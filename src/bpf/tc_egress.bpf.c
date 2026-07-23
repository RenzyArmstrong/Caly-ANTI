/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - XDP/eBPF DDoS mitigation suite
 * src/bpf/tc_egress.bpf.c - clsact egress conntrack-lite learner.
 *
 * PURPOSE
 *   XDP (and the tc ingress program) only see inbound packets, so an
 *   outbound-initiated flow - a DNS query, an NTP sync, a package download -
 *   has no inbound handshake to learn from. When the reply comes back it
 *   arrives with a SOURCE port that the reflection filter treats as a known
 *   amplifier (53 DNS, 123 NTP, ...), and it would be dropped.
 *
 *   This program closes that gap. It runs on the clsact EGRESS hook and, for
 *   every locally-originated flow, inserts a conntrack-lite entry so the reply
 *   hits the conntrack short-circuit (step 5) and never reaches the
 *   amplification filter (step 6). THIS is what makes the anti-amplification
 *   filter safe to enable.
 *
 * ORIENTATION - the one thing to get right
 *   conn_key is ALWAYS stored ingress-relative: saddr/sport is the REMOTE
 *   peer, daddr/dport is US. An egress packet is the mirror image, so the
 *   tuple is SWAPPED before insertion:
 *
 *       conn_key.saddr = egress ip.daddr   (remote)
 *       conn_key.daddr = egress ip.saddr   (us)
 *       conn_key.sport = egress l4.dest    (remote port)
 *       conn_key.dport = egress l4.source  (our port)
 *
 *   The returning packet's ingress lookup then hits on its first try with no
 *   normalisation.
 *
 * SAFETY
 *   Egress NEVER drops: our own traffic must always leave. The verdict is
 *   unconditionally TC_ACT_OK. Every failure path is a silent TC_ACT_OK.
 *
 * L2 PRESENCE
 *   For locally-generated IP packets on an Ethernet device the L2 header is
 *   already attached by the time the clsact egress hook runs (the neighbour
 *   layer builds it in ip_finish_output2, before dev_queue_xmit). On virtual
 *   devices without a MAC header it is not. We therefore auto-detect: if the
 *   first 14 bytes look like an Ethernet frame carrying IP/IPv6/VLAN we parse
 *   from offset 14, otherwise we treat the buffer as starting at L3 and read
 *   the IP version nibble directly.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "compat.h"
#include "maps.h"
#include "checksum.h"
#include "parsing.h"

#define TCE_PULL_LEN       80u   /* eth + 2 vlan + ipv6 + tcp/udp head       */
#define TCE_TCP_OFF_FLAGS  13u

struct tce_vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/* What egress needs to know about the outbound packet. Addresses are already
 * in the egress orientation (src = us, dst = remote). */
struct tce_out {
	__u32 src[4];        /* us,     network order */
	__u32 dst[4];        /* remote, network order */
	__u32 family;
	__u32 proto;
	__u16 sport;         /* our port,    network order */
	__u16 dport;         /* remote port, network order */
	__u16 tcp_flags;
	__u32 pkt_len;       /* skb->len; u32 so GSO/TSO super-frames (>= 64 KiB)
			      * are not truncated to 0/16 bits before being added
			      * to the u64 conn_state.bytes_out */
};

static __always_inline void tce_stat(__u32 reason)
{
	__u64 *p;

	if (reason >= STAT_MAX)
		return;
	p = bpf_map_lookup_elem(&caly_stats, &reason);
	if (p)
		*p += 1;
}

/*
 * Locate the L3 header. Returns the byte offset of the IPv4/IPv6 header and
 * writes the detected ethertype family into *family, or -1 when the frame is
 * not IP and must be ignored. Handles both the L2-present and L2-absent cases.
 */
static __always_inline int tce_l3_off(void *data, void *data_end,
				      __u16 skb_proto, __u32 *family)
{
	__u32 off = 0;
	__u16 h_proto;
	int i;

	/* Peek at a possible Ethernet header. */
	if ((void *)((__u8 *)data + sizeof(struct ethhdr)) <= data_end) {
		struct ethhdr *eth = data;

		h_proto = eth->h_proto;
		if (h_proto == bpf_htons(CALY_ETH_P_IP)   ||
		    h_proto == bpf_htons(CALY_ETH_P_IPV6) ||
		    h_proto == bpf_htons(CALY_ETH_P_8021Q) ||
		    h_proto == bpf_htons(CALY_ETH_P_8021AD) ||
		    h_proto == bpf_htons(CALY_ETH_P_QINQ1)) {
			off = sizeof(struct ethhdr);

			CALY_UNROLL
			for (i = 0; i < (int)CALY_VLAN_MAX_DEPTH; i++) {
				struct tce_vlan_hdr *vh;

				if (h_proto != bpf_htons(CALY_ETH_P_8021Q) &&
				    h_proto != bpf_htons(CALY_ETH_P_8021AD) &&
				    h_proto != bpf_htons(CALY_ETH_P_QINQ1))
					break;
				vh = (void *)((__u8 *)data + off);
				if ((void *)(vh + 1) > data_end)
					return -1;
				h_proto = vh->h_vlan_encapsulated_proto;
				off += sizeof(*vh);
			}

			if (h_proto == bpf_htons(CALY_ETH_P_IP))
				*family = CALY_AF_INET;
			else if (h_proto == bpf_htons(CALY_ETH_P_IPV6))
				*family = CALY_AF_INET6;
			else
				return -1;
			return (int)off;
		}
	}

	/* No usable Ethernet header: the buffer starts at L3. Use skb->protocol
	 * when it is meaningful, else fall back to the IP version nibble. */
	if (skb_proto == bpf_htons(CALY_ETH_P_IP))
		*family = CALY_AF_INET;
	else if (skb_proto == bpf_htons(CALY_ETH_P_IPV6))
		*family = CALY_AF_INET6;
	else if ((void *)((__u8 *)data + 1) <= data_end) {
		__u8 v = (*(__u8 *)data) >> 4;

		if (v == 4)
			*family = CALY_AF_INET;
		else if (v == 6)
			*family = CALY_AF_INET6;
		else
			return -1;
	} else {
		return -1;
	}
	return 0;
}

/* Parse the outbound packet into o. Returns 0 on a TCP/UDP flow worth
 * learning, -1 otherwise. */
static __always_inline int tce_parse(struct __sk_buff *skb, struct tce_out *o)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u32 family = 0;
	int l3i;
	__u32 l3_off, l4_off;

	l3i = tce_l3_off(data, data_end, (__u16)skb->protocol, &family);
	if (l3i < 0)
		return -1;
	l3_off = (__u32)l3i;
	o->family = family;

	if (family == CALY_AF_INET) {
		struct iphdr *iph = (void *)((__u8 *)data + l3_off);

		if ((void *)(iph + 1) > data_end)
			return -1;
		if (iph->ihl < 5)
			return -1;
		/* Do not learn fragments: no reliable L4 ports. */
		if (iph->frag_off & bpf_htons(0x3FFF))
			return -1;
		o->proto  = iph->protocol;
		o->src[0] = iph->saddr;
		o->dst[0] = iph->daddr;
		l4_off = l3_off + (__u32)iph->ihl * 4u;
	} else {
		struct ipv6hdr *ip6h = (void *)((__u8 *)data + l3_off);

		if ((void *)(ip6h + 1) > data_end)
			return -1;
		/* Only the common no-extension-header case is learned; an
		 * outbound flow behind ext headers is rare and simply falls
		 * back to the reply being re-evaluated by policy. */
		o->proto  = ip6h->nexthdr;
		__builtin_memcpy(&o->src[0], &ip6h->saddr, 16);
		__builtin_memcpy(&o->dst[0], &ip6h->daddr, 16);
		l4_off = l3_off + sizeof(struct ipv6hdr);
	}

	if (o->proto == CALY_IPPROTO_TCP) {
		struct tcphdr *th = (void *)((__u8 *)data + l4_off);

		if ((void *)(th + 1) > data_end)
			return -1;
		o->sport = th->source;
		o->dport = th->dest;
		o->tcp_flags = *((__u8 *)th + TCE_TCP_OFF_FLAGS);
	} else if (o->proto == CALY_IPPROTO_UDP) {
		struct udphdr *uh = (void *)((__u8 *)data + l4_off);

		if ((void *)(uh + 1) > data_end)
			return -1;
		o->sport = uh->source;
		o->dport = uh->dest;
		o->tcp_flags = 0;
	} else {
		return -1;   /* only TCP/UDP flows are learned */
	}

	if (o->sport == 0 || o->dport == 0)
		return -1;

	return 0;
}

/* Build the ingress-oriented (SWAPPED) conntrack key from an egress packet. */
static __always_inline void tce_conn_key(struct conn_key *k,
					 const struct tce_out *o)
{
	__builtin_memset(k, 0, sizeof(*k));
	/* remote peer -> saddr/sport */
	k->saddr[0] = o->dst[0];
	k->saddr[1] = o->dst[1];
	k->saddr[2] = o->dst[2];
	k->saddr[3] = o->dst[3];
	/* us -> daddr/dport */
	k->daddr[0] = o->src[0];
	k->daddr[1] = o->src[1];
	k->daddr[2] = o->src[2];
	k->daddr[3] = o->src[3];
	k->sport    = o->dport;   /* remote port */
	k->dport    = o->sport;   /* our port    */
	k->proto    = (__u8)o->proto;
	k->family   = (__u8)o->family;
}

SEC("tc")
int caly_tc_egress(struct __sk_buff *skb)
{
	struct fw_config *cfg;
	struct tce_out o;
	struct conn_key k;
	struct conn_state cs, *existing;
	__u32 zero = 0, pull;
	__u64 now;
	int is_syn, is_rst, is_fin;

	cfg = bpf_map_lookup_elem(&caly_config, &zero);
	if (!cfg)
		return TC_ACT_OK;
	if (!(cfg->flags & CALY_F_ENABLED))
		return TC_ACT_OK;
	if (!(cfg->flags & CALY_F_CONNTRACK))
		return TC_ACT_OK;

	/* Make the header region linear before parsing. */
	pull = skb->len;
	if (pull > TCE_PULL_LEN)
		pull = TCE_PULL_LEN;
	bpf_skb_pull_data(skb, pull);

	__builtin_memset(&o, 0, sizeof(o));
	o.pkt_len = skb->len;

	if (tce_parse(skb, &o) < 0)
		return TC_ACT_OK;

	now = bpf_ktime_get_ns();

	is_syn = (o.proto == CALY_IPPROTO_TCP) &&
		 (o.tcp_flags & CALY_TCP_SYN) && !(o.tcp_flags & CALY_TCP_ACK);
	is_rst = (o.proto == CALY_IPPROTO_TCP) && (o.tcp_flags & CALY_TCP_RST);
	is_fin = (o.proto == CALY_IPPROTO_TCP) && (o.tcp_flags & CALY_TCP_FIN);

	tce_conn_key(&k, &o);

	existing = bpf_map_lookup_elem(&caly_conn, &k);
	if (existing) {
		/* Update the flow we (or the ingress hook) already know. */
		existing->last_seen_ns = now;
		existing->pkts_out++;
		existing->bytes_out += o.pkt_len;
		existing->flags |= CALY_CT_F_OUTBOUND;

		if (existing->state == CALY_CT_SYN_RECV ||
		    existing->state == CALY_CT_SYN_SENT)
			existing->state = CALY_CT_ESTABLISHED;
		if (existing->state == CALY_CT_ESTABLISHED)
			existing->flags |= CALY_CT_F_SEEN_REPLY;

		if (is_rst) {
			existing->state = CALY_CT_CLOSED;
			tce_stat(STAT_CT_CLOSED);
		} else if (is_fin) {
			existing->state = CALY_CT_FIN_WAIT;
		}
		tce_stat(STAT_CT_UPDATED);
		return TC_ACT_OK;
	}

	/*
	 * No entry yet. Learn a brand-new outbound flow so its reply is
	 * recognised. For TCP we only seed on the initial SYN (a mid-stream
	 * packet with no entry is ambiguous); for UDP every first packet
	 * establishes the flow, which is exactly the DNS/NTP reflection-safety
	 * case this program exists for.
	 */
	if (o.proto == CALY_IPPROTO_TCP && !is_syn)
		return TC_ACT_OK;
	if (is_rst)
		return TC_ACT_OK;

	__builtin_memset(&cs, 0, sizeof(cs));
	cs.created_ns   = now;
	cs.last_seen_ns = now;
	cs.pkts_out     = 1;
	cs.bytes_out    = o.pkt_len;
	cs.ifindex      = skb->ifindex;
	cs.flags        = CALY_CT_F_OUTBOUND;

	if (o.proto == CALY_IPPROTO_TCP)
		cs.state = CALY_CT_SYN_SENT;
	else
		cs.state = CALY_CT_ESTABLISHED;   /* UDP: no handshake */

	/* Flag management-port flows so the GC never reaps them. */
	if (o.proto == CALY_IPPROTO_TCP) {
		if (caly_is_mgmt_tcp(cfg, bpf_ntohs(o.sport)) ||
		    caly_is_mgmt_tcp(cfg, bpf_ntohs(o.dport)))
			cs.flags |= CALY_CT_F_MGMT;
	} else {
		if (caly_is_mgmt_udp(cfg, bpf_ntohs(o.sport)) ||
		    caly_is_mgmt_udp(cfg, bpf_ntohs(o.dport)))
			cs.flags |= CALY_CT_F_MGMT;
	}

	if (bpf_map_update_elem(&caly_conn, &k, &cs, BPF_ANY) == 0)
		tce_stat(STAT_CT_CREATED);
	else
		tce_stat(STAT_CT_FULL);

	return TC_ACT_OK;
}

#ifndef CALY_LICENSE_DEFINED
#define CALY_LICENSE_DEFINED
char _license[] SEC("license") = "Dual BSD/GPL";
#endif
