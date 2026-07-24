// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
/*
 * Caly Anti - XDP/eBPF DDoS mitigation suite
 * src/bpf/xdp_firewall.bpf.c - the main XDP dataplane program.
 *
 * ONE entry point, caly_xdp_main, built from __always_inline stages that run in
 * the order laid out in docs/ARCHITECTURE.md section 3:
 *
 *    0  prelude        config / scratch / interface zone      (fail OPEN)
 *    1  parse          eth -> VLAN x2 -> IPv4|IPv6 -> ext hdrs -> tunnel -> L4
 *    2  anomaly        malformed or physically impossible packets
 *    2b mandatory ICMP PMTUD + IPv6 neighbour discovery carve-out
 *    3  allowlist      LPM hit  => XDP_PASS   (the operator escape hatch)
 *    3b mgmt ports     TCP/22 & friends       (the anti-lockout guarantee)
 *    4  reputation     static blocklist + dynamic ban with expiry
 *    5  conntrack      established flow      => XDP_PASS (short circuit)
 *    5b lockdown       nothing else survives FW_MODE_LOCKDOWN
 *    6  amplification  UDP source port is a known reflector (WAN only)
 *    7  port policy    closed / open / rate limited, plus default deny
 *    8  rate limiting  six per-source token buckets, strikes, escalating bans
 *    9  portscan       512-bit Bloom over destination ports
 *   10  SYN handling   tail call to the SYN proxy, or the rate-limit fallback
 *   11  account        per-CPU stats on EVERY verdict + sampled perf events
 *
 * DESIGN RULES THIS FILE OBEYS - break one and something breaks quietly:
 *
 *  - Every read is preceded by an explicit (ptr + size > data_end) test. No
 *    length field from the wire is ever used to compute an unchecked offset.
 *  - Every loop has a compile-time constant bound and is #pragma unroll'd via
 *    CALY_UNROLL. No bpf_loop(), which is 5.17+.
 *  - Every helper is __always_inline. A real BPF-to-BPF call loses packet
 *    pointer range information on the 4.18 verifier.
 *  - Every bpf_map_lookup_elem() result is NULL-checked before use.
 *  - Every hash key is __builtin_memset() to zero before it is filled in.
 *    struct conn_key has explicit pad[2] and the kernel compares raw bytes.
 *  - Big structures live in the per-CPU caly_scratch map, never on the 512
 *    byte BPF stack.
 *  - Every internal failure fails OPEN (XDP_PASS + a counter). A firewall that
 *    black-holes traffic because a map lookup failed is worse than no firewall.
 *  - XDP_ABORTED is never returned. It fires the xdp_exception tracepoint and
 *    is an error signal, not a drop verdict.
 *  - The allowlist and the management-port list are checked before EVERY drop
 *    rule. TCP/22 survives every mode, including UNDER_ATTACK and LOCKDOWN.
 *
 * Kernel floor is 4.18 (RHEL 8). No bpf_loop, no bpf_map_lookup_percpu_elem,
 * no ringbuf, no bpf_xdp_adjust_tail growth, config in an ARRAY map rather
 * than .rodata, LPM tries created with BPF_F_NO_PREALLOC by the loader.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "compat.h"
#include "maps.h"

/* -------------------------------------------------------------------------
 * UAPI constants that are macros (not BTF types) in older kernels and are
 * therefore absent from a vmlinux.h generated on, say, RHEL 8. Guarded so the
 * object compiles against a vmlinux.h from any supported kernel.
 * ------------------------------------------------------------------------- */
#ifndef XDP_PASS
#define XDP_DROP  1
#define XDP_PASS  2
#define XDP_TX    3
#endif

#ifndef BPF_ANY
#define BPF_ANY 0
#endif
#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#endif
#ifndef BPF_EXIST
#define BPF_EXIST 2
#endif
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif
#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU 0xffffffffULL
#endif

/* -------------------------------------------------------------------------
 * Local packet header definitions.
 *
 * These are deliberately NOT taken from vmlinux.h. struct iphdr and friends
 * are only present in a BTF dump if the generating kernel happened to keep
 * them, they use bitfields for ihl/version (endian dependent and awkward for
 * the verifier), and their presence differs across the 4.18..6.12 range we
 * support. Fixed-width, bitfield-free local copies remove the whole class of
 * problem. Field order and offsets match the wire format exactly.
 * ------------------------------------------------------------------------- */

struct caly_ethhdr {
	__u8  h_dest[6];
	__u8  h_source[6];
	__u16 h_proto;            /* network byte order */
};                                /* 14 bytes */

struct caly_vlanhdr {
	__u16 tci;                /* pcp:3 dei:1 vid:12, network order */
	__u16 encap_proto;        /* network byte order */
};                                /* 4 bytes */

struct caly_iphdr {
	__u8  ver_ihl;            /* version:4 << 4 | ihl:4 */
	__u8  tos;
	__u16 tot_len;            /* network order */
	__u16 id;
	__u16 frag_off;           /* flags:3 | offset:13, network order */
	__u8  ttl;
	__u8  protocol;
	__u16 check;
	__u32 saddr;              /* network order, raw wire bytes */
	__u32 daddr;
};                                /* 20 bytes */

struct caly_ip6hdr {
	__u8  ver_tc;             /* version:4 << 4 | tclass high nibble */
	__u8  tc_fl;
	__u16 flow_lbl_lo;
	__u16 payload_len;        /* network order */
	__u8  nexthdr;
	__u8  hop_limit;
	__u8  saddr[16];          /* wire bytes, MSB first */
	__u8  daddr[16];
};                                /* 40 bytes */

struct caly_ip6_ext {
	__u8  nexthdr;
	__u8  hdrlen;             /* units differ per header type */
	__u8  data[6];
};                                /* 8 bytes: the minimum extension header */

struct caly_tcphdr {
	__u16 source;             /* network order */
	__u16 dest;
	__u32 seq;
	__u32 ack_seq;
	__u8  doff_res;           /* doff:4 << 4 | reserved:4 */
	__u8  flags;              /* CWR ECE URG ACK PSH RST SYN FIN */
	__u16 window;
	__u16 check;
	__u16 urg_ptr;
};                                /* 20 bytes */

struct caly_udphdr {
	__u16 source;
	__u16 dest;
	__u16 len;
	__u16 check;
};                                /* 8 bytes */

struct caly_icmphdr {
	__u8  type;
	__u8  code;
	__u16 cksum;
	__u32 rest;
};                                /* 8 bytes, ICMPv4 and ICMPv6 alike */

struct caly_grehdr {
	__u16 flags_ver;          /* C R K S s recur A flags ver */
	__u16 proto;              /* inner ethertype */
};                                /* 4 bytes */

/* GRE header bits we care about. */
#define CALY_GRE_F_CSUM     0x8000u
#define CALY_GRE_F_ROUTING  0x4000u
#define CALY_GRE_F_KEY      0x2000u
#define CALY_GRE_F_SEQ      0x1000u
#define CALY_GRE_F_SSR      0x0800u
#define CALY_GRE_VER_MASK   0x0007u

/* -------------------------------------------------------------------------
 * Local bounds and small helpers.
 * ------------------------------------------------------------------------- */

/* Hard ceiling on any header offset we will chase. Gives the verifier a tight
 * range for every `data + off` expression and stops a crafted chain of tiny
 * extension headers from walking us off into arithmetic it cannot bound. */
#define CALY_MAX_HDR_OFF     512u

/* Largest frame length we account for. Bounds the unknown scalar produced by
 * the (data_end - data) pointer subtraction. */
#define CALY_MAX_PKT_LEN     65535u

/* Return codes from the stage helpers. */
#define CALY_PARSE_OK        0u
#define CALY_PARSE_TUNNEL    0xFFFFFFFFu

/* Verdict accumulator values. */
#define CALY_ACT_PASS        0
#define CALY_ACT_DROP        1
#define CALY_ACT_TX          2

/*
 * caly_scratch.tmp[] slot assignment. The scratch map is a PERCPU_ARRAY, so
 * these survive between invocations on the same CPU and are never shared, and
 * therefore need no locking.
 */
#define CALY_TMP_EV_COUNT    0    /* 1-in-N event sampling counter          */
#define CALY_TMP_EV_WIN_NS   1    /* start of the current events/sec window */
#define CALY_TMP_EV_IN_WIN   2    /* events emitted inside that window      */

/*
 * The pre-5.15 global SYN cap needs one shared token bucket. Rather than add a
 * map for a single bucket we borrow caly_port_tb slot 0, which is TCP port 0.
 * Port 0 is not valid on the wire and packets carrying it are dropped by
 * STAT_DROP_L4_PORT_ZERO long before the port-policy stage, so the slot can
 * never be claimed by a real port rule.
 */
#define CALY_TB_GLOBAL_SYN   CALY_PORT_TB_IDX(0, 0)

/*
 * A port_rule read out of an all-zero array slot is indistinguishable from an
 * explicitly configured "closed" rule, because CALY_PORT_CLOSED is 0. Treating
 * an unconfigured slot as closed would silently make every port default deny,
 * so "configured" means "something in the record is non-zero".
 *
 * If a future ABI adds CALY_PORT_F_PRESENT this collapses to a flag test with
 * no other change; see the contract change request that ships with this file.
 */
#ifdef CALY_PORT_F_PRESENT
#define CALY_RULE_PRESENT(r)  (((r)->flags & CALY_PORT_F_PRESENT) != 0)
#else
#define CALY_RULE_PRESENT(r)  ((r)->mode != CALY_PORT_CLOSED || \
			       (r)->flags != 0 || (r)->rate != 0 || \
			       (r)->burst != 0)
#endif

/* Maps, the counter/gauge accessors, LPM-key helpers, ban-expiry and
 * event helpers all come from maps.h (included above): the single
 * declaration site every dataplane object shares, so no two objects can
 * disagree about a map's key/value type, flags or size. caly_stat() and
 * the accessors below therefore also come from maps.h; only the helpers
 * unique to this program (caly_gauge, the LPM key builders, the parsers
 * and caly_ban_install) are defined locally. */

/* -------------------------------------------------------------------------
 * Counter helpers.
 *
 * caly_stats / caly_stats_b / caly_global are PERCPU_ARRAYs, so the read-
 * modify-write below needs no atomics: XDP runs in softirq context on one CPU
 * and the map value is that CPU's private copy.
 * ------------------------------------------------------------------------- */

CALY_INLINE void caly_gauge(__u32 gauge, __u64 add)
{
	__u64 *v;
	__u32 key = gauge;

	if (key >= CALY_G_MAX)
		return;

	v = bpf_map_lookup_elem(&caly_global, &key);
	if (v)
		*v += add;
}

/* -------------------------------------------------------------------------
 * Prefix-trie lookup helpers. LPM keys carry prefixlen in HOST order first,
 * then the address bytes in NETWORK order, most significant byte first. The
 * whole key is memset before use because the kernel hashes/compares raw bytes.
 * ------------------------------------------------------------------------- */

CALY_INLINE void caly_lpm4_key(struct lpm_key_v4 *k, const __u32 *addr_words)
{
	__builtin_memset(k, 0, sizeof(*k));
	k->prefixlen = 32;
	__builtin_memcpy(k->addr, addr_words, 4);
}

CALY_INLINE void caly_lpm6_key(struct lpm_key_v6 *k, const __u32 *addr_words)
{
	__builtin_memset(k, 0, sizeof(*k));
	k->prefixlen = 128;
	__builtin_memcpy(k->addr, addr_words, 16);
}

/* -------------------------------------------------------------------------
 * Ban installation.
 *
 * Called from the rate-limit, port-scan and amplification stages. Returns the
 * TTL actually installed (0 when no ban was installed) so the caller can put
 * it in the event record.
 *
 * The ban record is built in the per-CPU scratch area, never on the stack:
 * struct ban_entry is 64 bytes and the stack budget is 512 for the whole
 * program.
 * ------------------------------------------------------------------------- */

CALY_INLINE __u64 caly_ban_install(struct caly_scratch *sc,
				   const struct fw_config *cfg,
				   int is_v4, __u32 *k4, struct in6_key *k6,
				   __u64 now, __u32 reason, __u64 ttl_override,
				   __u32 strikes, __u32 pkt_len)
{
	struct ban_entry *be, *nb;
	__u64 ttl;
	long err;

	if (!(cfg->flags & CALY_F_AUTOBAN))
		return 0;

	if (is_v4)
		be = bpf_map_lookup_elem(&caly_ban4, k4);
	else
		be = bpf_map_lookup_elem(&caly_ban6, k6);

	if (be) {
		if (be->expiry_ns > now && !(be->flags & CALY_BAN_F_PERMANENT)) {
			/* Still serving an active ban: refresh the deadline so
			 * a source that keeps hammering stays out, but do not
			 * escalate on every packet. */
			ttl = be->cur_ttl_ns;
			if (ttl == 0)
				ttl = cfg->ban_ttl_base_ns;
			if (ttl_override > ttl)
				ttl = ttl_override;
			if (ttl == 0)
				return 0;
			be->expiry_ns = now + ttl;
			be->last_hit_ns = now;
			caly_stat(STAT_BAN_REFRESHED, pkt_len);
			return ttl;
		}

		/* Expired record for a repeat offender: escalate. */
		if (ttl_override)
			ttl = ttl_override;
		else
			ttl = caly_ban_next_ttl(be->cur_ttl_ns,
						cfg->ban_ttl_base_ns,
						cfg->ban_ttl_max_ns,
						cfg->ban_escalate_num,
						cfg->ban_escalate_den);
		if (ttl == 0)
			return 0;

		be->expiry_ns = now + ttl;
		be->last_hit_ns = now;
		be->cur_ttl_ns = ttl;
		be->reason = reason;
		be->strikes = strikes;
		be->offences += 1;
		be->flags |= CALY_BAN_F_AUTO | CALY_BAN_F_ESCALATED;
		caly_stat(STAT_BAN_ESCALATED, pkt_len);
		return ttl;
	}

	ttl = ttl_override ? ttl_override : cfg->ban_ttl_base_ns;
	if (ttl == 0)
		return 0;                       /* banning disabled by config */
	if (cfg->ban_ttl_max_ns && ttl > cfg->ban_ttl_max_ns)
		ttl = cfg->ban_ttl_max_ns;

	nb = &sc->ban;
	__builtin_memset(nb, 0, sizeof(*nb));
	nb->expiry_ns = now + ttl;
	nb->first_seen_ns = now;
	nb->last_hit_ns = now;
	nb->cur_ttl_ns = ttl;
	nb->reason = reason;
	nb->strikes = strikes;
	nb->offences = 1;
	nb->flags = CALY_BAN_F_AUTO;

	if (is_v4)
		err = bpf_map_update_elem(&caly_ban4, k4, nb, BPF_ANY);
	else
		err = bpf_map_update_elem(&caly_ban6, k6, nb, BPF_ANY);

	if (err) {
		caly_stat(STAT_BAN_FULL, pkt_len);
		return 0;
	}

	caly_stat(STAT_BAN_ADDED, pkt_len);
	return ttl;
}

/* -------------------------------------------------------------------------
 * Stage 1 - parsing.
 *
 * caly_parse_l3() handles one L3 header: IPv4 or IPv6, its extension headers,
 * and the L4 header that follows. If it finds a tunnel it fills *inner_off /
 * *inner_proto and returns CALY_PARSE_TUNNEL; the caller re-invokes it once,
 * which is how "one level of IPIP / IP6IP6 / GRE" is implemented without a
 * recursive call or an unbounded loop.
 *
 * Returns CALY_PARSE_OK, CALY_PARSE_TUNNEL, or the stat_reason to drop on.
 * ------------------------------------------------------------------------- */

CALY_INLINE int caly_ip6_is_ext(__u8 nh)
{
	return nh == CALY_IPPROTO_HOPOPTS  || nh == CALY_IPPROTO_ROUTING ||
	       nh == CALY_IPPROTO_FRAGMENT || nh == CALY_IPPROTO_DSTOPTS ||
	       nh == CALY_IPPROTO_AH       || nh == CALY_IPPROTO_MH;
}

CALY_INLINE int caly_is_tunnel_proto(__u8 proto)
{
	return proto == CALY_IPPROTO_IPIP || proto == CALY_IPPROTO_IPV6 ||
	       proto == CALY_IPPROTO_GRE;
}

/*
 * Parse the L4 header at pkt->l4_off. Fills sport/dport/tcp_flags/payload_off
 * and, for ICMP, *icmp_tc = (type << 8) | code.
 *
 * MITIGATES: truncated-header attacks - a packet that claims TCP but carries
 * fewer bytes than a TCP header would otherwise be read past the frame.
 */
CALY_INLINE __u32 caly_parse_l4(struct xdp_md *ctx, struct pkt_ctx *pkt,
				const struct fw_config *cfg, __u32 *icmp_tc)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 off = pkt->l4_off;
	__u32 doff;

	if (off > CALY_MAX_HDR_OFF)
		return STAT_DROP_L4_TRUNC;

	/* A non-first fragment carries no transport header at all. Mark it and
	 * let the policy stages skip anything port based. */
	if ((pkt->flags & CALY_PKT_F_FRAG) && pkt->frag_off != 0) {
		pkt->flags |= CALY_PKT_F_L4_TRUNC;
		pkt->payload_off = off;
		return CALY_PARSE_OK;
	}

	if (pkt->proto == CALY_IPPROTO_TCP) {
		struct caly_tcphdr *th = data + off;

		if ((void *)(th + 1) > data_end)
			return STAT_DROP_L4_TRUNC;

		pkt->sport = th->source;
		pkt->dport = th->dest;
		pkt->tcp_flags = th->flags;

		doff = (__u32)(th->doff_res >> 4);
		if (cfg->flags & CALY_F_ANOMALY_CHECKS) {
			__u32 min_doff = cfg->tcp_min_doff;

			if (min_doff < 5 || min_doff > 15)
				min_doff = 5;
			if (doff < min_doff)
				return STAT_DROP_TCP_DOFF;
			if (off + doff * 4 > pkt->pkt_len)
				return STAT_DROP_TCP_DOFF;
		}
		if (doff < 5)
			doff = 5;
		pkt->payload_off = off + doff * 4;
		return CALY_PARSE_OK;
	}

	if (pkt->proto == CALY_IPPROTO_UDP) {
		struct caly_udphdr *uh = data + off;

		if ((void *)(uh + 1) > data_end)
			return STAT_DROP_L4_TRUNC;

		pkt->sport = uh->source;
		pkt->dport = uh->dest;
		pkt->payload_off = off + sizeof(*uh);
		return CALY_PARSE_OK;
	}

	if (pkt->proto == CALY_IPPROTO_ICMP ||
	    pkt->proto == CALY_IPPROTO_ICMPV6) {
		struct caly_icmphdr *ih = data + off;

		if ((void *)(ih + 1) > data_end)
			return STAT_DROP_L4_TRUNC;

		*icmp_tc = ((__u32)ih->type << 8) | (__u32)ih->code;
		pkt->payload_off = off + sizeof(*ih);
		return CALY_PARSE_OK;
	}

	/* Anything else (ESP, AH, SCTP, OSPF, ...) has no ports we understand.
	 * The verdict is taken by the caller: pass unless default deny. */
	pkt->payload_off = off;
	return CALY_PARSE_OK;
}

/*
 * Parse one IPv4 or IPv6 header (plus extension headers) at l3_off.
 *
 * MITIGATES: header-length lies (ihl < 5, tot_len < ihl*4, ext header chains
 * that run off the end of the frame), RH0 amplification, hop-limit games and
 * fragment-overlap evasion.
 */
CALY_INLINE __u32 caly_parse_l3(struct xdp_md *ctx, struct pkt_ctx *pkt,
				const struct fw_config *cfg, __u32 l3_off,
				__u16 l3_proto, int allow_tunnel, int is_inner,
				__u32 *inner_off, __u16 *inner_proto,
				__u32 *icmp_tc)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 flags = cfg->flags;
	__u32 trunc_reason = is_inner ? STAT_DROP_TUNNEL_TRUNC
				      : STAT_DROP_IP4_TRUNC;
	__u32 off;
	__u8 proto;

	if (l3_off > CALY_MAX_HDR_OFF)
		return trunc_reason;

	pkt->l3_off = l3_off;

	/* Addresses are rewritten by every pass, so clear them first: an inner
	 * IPv4 header inside an outer IPv6 one must not leave stale high words
	 * behind. Words 1..3 being zero for IPv4 is load bearing - conn_key
	 * lookups compare all 16 bytes. */
	__builtin_memset(pkt->saddr, 0, sizeof(pkt->saddr));
	__builtin_memset(pkt->daddr, 0, sizeof(pkt->daddr));
	pkt->sport = 0;
	pkt->dport = 0;
	pkt->tcp_flags = 0;
	pkt->frag_off = 0;
	pkt->flags &= (__u32)~(CALY_PKT_F_FRAG | CALY_PKT_F_FRAG_FIRST |
			       CALY_PKT_F_L4_TRUNC);

	if (l3_proto == CALY_ETH_P_IP) {
		struct caly_iphdr *ip = data + l3_off;
		__u32 ihl, tot_len, raw_frag, frag_off, l4_total;

		if ((void *)(ip + 1) > data_end)
			return trunc_reason;

		if ((ip->ver_ihl >> 4) != 4)
			return STAT_DROP_L3_UNKNOWN;

		ihl = (__u32)(ip->ver_ihl & 0x0F);
		if (ihl < 5)
			return STAT_DROP_IP4_IHL;

		tot_len = (__u32)bpf_ntohs(ip->tot_len);
		if (tot_len < ihl * 4)
			return STAT_DROP_IP4_TOTLEN;

		if (flags & CALY_F_ANOMALY_CHECKS) {
			/* The frame may be longer than tot_len (Ethernet pads
			 * runts) but never shorter: that is truncation. */
			if (l3_off + tot_len > pkt->pkt_len)
				return STAT_DROP_IP4_TOTLEN;
		}

		if (ihl > 5 && (flags & CALY_F_DROP_IP4_OPTIONS))
			return STAT_DROP_IP4_OPTIONS;

		if (ip->ttl == 0)
			return STAT_DROP_TTL_ZERO;
		if ((flags & CALY_F_TTL_CHECK) && cfg->ip_min_ttl &&
		    (__u32)ip->ttl < cfg->ip_min_ttl)
			return STAT_DROP_TTL_LOW;

		pkt->family = CALY_AF_INET;
		pkt->saddr[0] = ip->saddr;      /* raw wire bytes, unswapped */
		pkt->daddr[0] = ip->daddr;
		proto = ip->protocol;

		raw_frag = (__u32)bpf_ntohs(ip->frag_off);
		frag_off = raw_frag & 0x1FFFu;
		if (frag_off || (raw_frag & 0x2000u)) {
			pkt->flags |= CALY_PKT_F_FRAG;
			pkt->frag_off = frag_off;
			if (frag_off == 0)
				pkt->flags |= CALY_PKT_F_FRAG_FIRST;

			if (flags & CALY_F_DROP_ALL_FRAGS)
				return STAT_DROP_FRAG_POLICY;

			if (flags & CALY_F_FRAG_CHECKS) {
				/* offset 1 means the second fragment starts 8
				 * bytes in, overlapping the transport header:
				 * the classic inspection-evasion trick. */
				if (frag_off == 1)
					return STAT_DROP_FRAG_OFF_ONE;
				/* A non-final fragment too small to carry a
				 * complete transport header exists only to
				 * confuse a reassembler. */
				if ((raw_frag & 0x2000u) && cfg->frag_min_bytes &&
				    tot_len - ihl * 4 < cfg->frag_min_bytes)
					return STAT_DROP_FRAG_TINY;
			}
		}

		l4_total = tot_len - ihl * 4;
		pkt->l4_len = (__u16)(l4_total > 0xFFFFu ? 0xFFFFu : l4_total);
		off = l3_off + ihl * 4;
	} else if (l3_proto == CALY_ETH_P_IPV6) {
		struct caly_ip6hdr *ip6 = data + l3_off;
		__u32 plen, hdr_bytes, ext_max, i;
		__u8 nh;

		trunc_reason = is_inner ? STAT_DROP_TUNNEL_TRUNC
					: STAT_DROP_IP6_TRUNC;

		if ((void *)(ip6 + 1) > data_end)
			return trunc_reason;

		if ((ip6->ver_tc >> 4) != 6)
			return STAT_DROP_L3_UNKNOWN;

		if (ip6->hop_limit == 0)
			return STAT_DROP_TTL_ZERO;
		if ((flags & CALY_F_TTL_CHECK) && cfg->ip_min_ttl &&
		    (__u32)ip6->hop_limit < cfg->ip_min_ttl)
			return STAT_DROP_TTL_LOW;

		plen = (__u32)bpf_ntohs(ip6->payload_len);
		if ((flags & CALY_F_ANOMALY_CHECKS) && plen != 0) {
			if (l3_off + 40 + plen > pkt->pkt_len)
				return trunc_reason;
		}

		pkt->family = CALY_AF_INET6;
		__builtin_memcpy(pkt->saddr, ip6->saddr, 16);
		__builtin_memcpy(pkt->daddr, ip6->daddr, 16);

		nh = ip6->nexthdr;
		off = l3_off + 40;

		ext_max = cfg->ip6_ext_max;
		if (ext_max > CALY_IP6_EXT_MAX)
			ext_max = CALY_IP6_EXT_MAX;

		/* Bounded extension-header walk. Compile-time bound of
		 * CALY_IP6_EXT_MAX, runtime bound from the config, so a
		 * crafted chain cannot spin the CPU. */
		CALY_UNROLL
		for (i = 0; i < CALY_IP6_EXT_MAX; i++) {
			struct caly_ip6_ext *eh;

			if (i >= ext_max)
				break;
			if (!caly_ip6_is_ext(nh))
				break;
			if (off > CALY_MAX_HDR_OFF)
				return STAT_DROP_IP6_EXT_DEPTH;

			eh = data + off;
			if ((void *)(eh + 1) > data_end)
				return STAT_DROP_IP6_EXT_TRUNC;

			if (nh == CALY_IPPROTO_ROUTING) {
				/* eh->data[0] is the routing type. RH0 was
				 * deprecated by RFC 5095 precisely because it
				 * is a traffic amplification primitive. */
				if ((flags & CALY_F_DROP_RH0) && eh->data[0] == 0)
					return STAT_DROP_IP6_RH0;
				hdr_bytes = ((__u32)eh->hdrlen + 1) * 8;
			} else if (nh == CALY_IPPROTO_FRAGMENT) {
				__u32 fo = ((__u32)eh->data[0] << 8) |
					   (__u32)eh->data[1];

				pkt->flags |= CALY_PKT_F_FRAG;
				pkt->frag_off = fo >> 3;
				if (pkt->frag_off == 0)
					pkt->flags |= CALY_PKT_F_FRAG_FIRST;

				if (flags & CALY_F_DROP_ALL_FRAGS)
					return STAT_DROP_FRAG_POLICY;
				if ((flags & CALY_F_FRAG_CHECKS) &&
				    pkt->frag_off == 1)
					return STAT_DROP_FRAG_OFF_ONE;

				hdr_bytes = 8;
			} else if (nh == CALY_IPPROTO_AH) {
				hdr_bytes = ((__u32)eh->hdrlen + 2) * 4;
			} else {
				hdr_bytes = ((__u32)eh->hdrlen + 1) * 8;
			}

			if (hdr_bytes < 8)
				hdr_bytes = 8;

			nh = eh->nexthdr;
			off += hdr_bytes;

			if (nh == CALY_IPPROTO_NONE)
				break;
		}

		if (caly_ip6_is_ext(nh))
			return STAT_DROP_IP6_EXT_DEPTH;
		if (off > CALY_MAX_HDR_OFF)
			return STAT_DROP_IP6_EXT_DEPTH;

		proto = nh;

		if (plen != 0 && off >= l3_off + 40 &&
		    plen + 40 > (off - l3_off)) {
			__u32 l4_total = plen + 40 - (off - l3_off);

			pkt->l4_len = (__u16)(l4_total > 0xFFFFu ? 0xFFFFu
							         : l4_total);
		} else {
			pkt->l4_len = 0;
		}
	} else {
		return STAT_DROP_L3_UNKNOWN;
	}

	pkt->l4_off = off;
	pkt->proto = proto;

	/* One level of IPIP / IP6IP6 / GRE, if the operator asked for it. The
	 * inner header is what policy should see; the wrapper is just paper. */
	if (caly_is_tunnel_proto(proto) && allow_tunnel) {
		if (proto == CALY_IPPROTO_IPIP) {
			*inner_off = off;
			*inner_proto = CALY_ETH_P_IP;
			return CALY_PARSE_TUNNEL;
		}
		if (proto == CALY_IPPROTO_IPV6) {
			*inner_off = off;
			*inner_proto = CALY_ETH_P_IPV6;
			return CALY_PARSE_TUNNEL;
		}
		if (proto == CALY_IPPROTO_GRE) {
			struct caly_grehdr *gre = data + off;
			__u32 gflags, glen, ethp;

			if (off > CALY_MAX_HDR_OFF)
				return STAT_DROP_TUNNEL_TRUNC;
			if ((void *)(gre + 1) > data_end)
				return STAT_DROP_TUNNEL_TRUNC;

			gflags = (__u32)bpf_ntohs(gre->flags_ver);

			/* Source-routed GRE is deprecated and is an attack
			 * primitive; refuse to parse it rather than guess at
			 * the variable-length routing field. */
			if (gflags & (CALY_GRE_F_ROUTING | CALY_GRE_F_SSR))
				return STAT_DROP_GRE_MALFORMED;

			if ((gflags & CALY_GRE_VER_MASK) != 0) {
				/* GREv1 is PPTP, not IP-in-IP. Leave it as an
				 * opaque L4 protocol rather than dropping a
				 * working VPN. */
				goto no_tunnel;
			}

			glen = 4;
			if (gflags & CALY_GRE_F_CSUM)
				glen += 4;
			if (gflags & CALY_GRE_F_KEY)
				glen += 4;
			if (gflags & CALY_GRE_F_SEQ)
				glen += 4;

			ethp = (__u32)bpf_ntohs(gre->proto);
			if (ethp != CALY_ETH_P_IP && ethp != CALY_ETH_P_IPV6)
				goto no_tunnel;   /* transparent bridging etc */

			*inner_off = off + glen;
			*inner_proto = (__u16)ethp;
			return CALY_PARSE_TUNNEL;
		}
	}

no_tunnel:
	return caly_parse_l4(ctx, pkt, cfg, icmp_tc);
}

/* -------------------------------------------------------------------------
 * The program.
 * ------------------------------------------------------------------------- */

SEC("xdp")
int caly_xdp_main(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct fw_config *cfg;
	struct caly_scratch *sc;
	struct pkt_ctx *pkt;
	struct iface_config *ifc;

	/* One reusable temporary big enough for the largest value we ever have
	 * to build before inserting it into a map. Their lifetimes never
	 * overlap, so a union keeps the stack far below the 512 byte limit. */
	union {
		struct rate_state rs;
		struct scan_state sn;
		struct src_stats  ts;
	} tv;

	struct in6_key skey6;
	__u32 skey4 = 0;

	__u64 flags, now, if_flags = 0, ban_ttl = 0, evval = 0;
	__u32 zero = 0, key32;
	__u32 reason = STAT_PASS_DEFAULT;
	__u32 pkt_len, mode;
	__u32 icmp_tc = 0;
	__u32 eth_proto = 0;
	__u32 rc;
	__u16 cur_proto;
	__u32 cur_off;
	__u32 i;
	int act = CALY_ACT_PASS;
	int is_wan = 0, if_monitor = 0, is_v4 = 1;
	int ct_missed = 0;
	int is_syn = 0, is_icmp = 0, want_event = 0;
	long err;

	/* (data_end - data) is the only pointer subtraction in the program.
	 * The verifier turns it into an unbounded scalar, so clamp it before
	 * it is ever used as a byte count. */
	pkt_len = (__u32)(data_end - data);
	if (pkt_len > CALY_MAX_PKT_LEN)
		pkt_len = CALY_MAX_PKT_LEN;

	/* ---- Stage 0: prelude. Everything here fails OPEN. ---- */

	cfg = bpf_map_lookup_elem(&caly_config, &zero);
	if (!cfg) {
		caly_stat(STAT_PKT_TOTAL, pkt_len);
		caly_stat(STAT_CONFIG_MISSING, pkt_len);
		caly_stat(STAT_PASS_TOTAL, pkt_len);
		return XDP_PASS;
	}

	sc = bpf_map_lookup_elem(&caly_scratch, &zero);
	if (!sc) {
		caly_stat(STAT_PKT_TOTAL, pkt_len);
		caly_stat(STAT_SCRATCH_FAIL, pkt_len);
		caly_stat(STAT_PASS_TOTAL, pkt_len);
		return XDP_PASS;
	}

	flags = cfg->flags;
	mode = cfg->mode;
	now = bpf_ktime_get_ns();

	/* Source hash keys are initialised here, unconditionally, so that
	 * EVERY path to the verdict block - including the ones that goto out
	 * before the parse fills them (mandatory ICMP, anomaly drops) - reads
	 * a fully defined key. A hash key with uninitialised padding is both a
	 * verifier error on 4.18 and a silent lookup miss. skey4 is already 0. */
	__builtin_memset(&skey6, 0, sizeof(skey6));

	pkt = &sc->pkt;
	__builtin_memset(pkt, 0, sizeof(*pkt));
	pkt->ts_ns = now;
	pkt->pkt_len = pkt_len;
	pkt->ifindex = ctx->ingress_ifindex;

	if (!(flags & CALY_F_ENABLED)) {
		reason = STAT_PASS_DISABLED;
		goto verdict;
	}

	/* Per-interface overrides. A miss means "use fw_config.default_zone
	 * and no per-interface flags", which is why the map is allowed to be
	 * empty on a fresh install. */
	key32 = pkt->ifindex;
	ifc = bpf_map_lookup_elem(&caly_iface, &key32);
	{
		__u32 zone = cfg->default_zone;

		if (ifc) {
			if_flags = ifc->flags;
			if (ifc->zone != CALY_ZONE_UNSPEC)
				zone = ifc->zone;
		}

		if (if_flags & CALY_IF_F_DISABLED) {
			reason = STAT_PASS_DISABLED;
			goto verdict;
		}

		if_monitor = (if_flags & CALY_IF_F_MONITOR) ? 1 : 0;
		/* Only WAN interfaces get martian filtering and the reflection
		 * filter; applying either to a LAN port drops your own internal
		 * traffic. See calyanti.conf [interfaces]. */
		is_wan = (zone == CALY_ZONE_WAN) ||
			 ((if_flags & CALY_IF_F_WAN) != 0);
		if (is_wan)
			pkt->flags |= CALY_PKT_F_WAN;
	}

	/* ---- Stage 1: parse ---- */

	{
		struct caly_ethhdr *eth = data;
		__u32 vlan_max, off = 0;

		if ((void *)(eth + 1) > data_end) {
			reason = STAT_DROP_ETH_TRUNC;
			act = CALY_ACT_DROP;
			goto verdict;
		}

		eth_proto = (__u32)bpf_ntohs(eth->h_proto);
		off = sizeof(*eth);

		vlan_max = (flags & CALY_F_VLAN_INSPECT) ? cfg->vlan_max_depth : 0;
		if (vlan_max > CALY_VLAN_MAX_DEPTH)
			vlan_max = CALY_VLAN_MAX_DEPTH;

		/* 802.1Q / 802.1ad / legacy vendor QinQ. Bounded at two tags:
		 * a stack of tags is a parser-exhaustion attack, not traffic. */
		CALY_UNROLL
		for (i = 0; i < CALY_VLAN_MAX_DEPTH; i++) {
			struct caly_vlanhdr *vh;

			if (i >= vlan_max)
				break;
			if (eth_proto != CALY_ETH_P_8021Q &&
			    eth_proto != CALY_ETH_P_8021AD &&
			    eth_proto != CALY_ETH_P_QINQ1 &&
			    eth_proto != CALY_ETH_P_QINQ2 &&
			    eth_proto != CALY_ETH_P_QINQ3)
				break;

			vh = data + off;
			if ((void *)(vh + 1) > data_end) {
				reason = STAT_DROP_VLAN_TRUNC;
				act = CALY_ACT_DROP;
				goto verdict;
			}

			eth_proto = (__u32)bpf_ntohs(vh->encap_proto);
			off += sizeof(*vh);
			pkt->vlan_depth += 1;
			pkt->flags |= CALY_PKT_F_VLAN;
		}

		if (eth_proto == CALY_ETH_P_8021Q ||
		    eth_proto == CALY_ETH_P_8021AD ||
		    eth_proto == CALY_ETH_P_QINQ1 ||
		    eth_proto == CALY_ETH_P_QINQ2 ||
		    eth_proto == CALY_ETH_P_QINQ3) {
			/* Tagged deeper than we are willing to walk. With VLAN
			 * inspection off this is simply "not a frame we parse". */
			if (flags & CALY_F_VLAN_INSPECT) {
				reason = STAT_DROP_VLAN_DEPTH;
				act = CALY_ACT_DROP;
			} else if (flags & CALY_F_DROP_UNKNOWN_L3) {
				reason = STAT_DROP_L3_UNKNOWN;
				act = CALY_ACT_DROP;
			} else {
				reason = STAT_PASS_NOT_IP;
			}
			goto verdict;
		}

		pkt->eth_proto = (__u16)eth_proto;
		cur_off = off;
		cur_proto = (__u16)eth_proto;
	}

	if (eth_proto == CALY_ETH_P_ARP) {
		/* ARP is never dropped by ethertype policy: without it the box
		 * cannot reach its own default gateway. */
		reason = STAT_PASS_NOT_IP;
		goto verdict;
	}

	if (eth_proto == CALY_ETH_P_IP) {
		if (!(flags & CALY_F_IPV4)) {
			reason = STAT_PASS_NOT_IP;
			goto verdict;
		}
	} else if (eth_proto == CALY_ETH_P_IPV6) {
		if (!(flags & CALY_F_IPV6) || (if_flags & CALY_IF_F_NO_IPV6)) {
			reason = STAT_DROP_IP6_DISABLED;
			act = CALY_ACT_DROP;
			goto verdict;
		}
	} else {
		if (flags & CALY_F_DROP_UNKNOWN_L3) {
			reason = STAT_DROP_L3_UNKNOWN;
			act = CALY_ACT_DROP;
		} else {
			reason = STAT_PASS_NOT_IP;
		}
		goto verdict;
	}

	/* L3 + L4. Iteration 0 parses the outer header; if it reports a tunnel
	 * iteration 1 parses the inner one and policy sees the inner header.
	 * CALY_TUNNEL_MAX_DEPTH is 1, so this is exactly two unrolled passes
	 * and never a loop the verifier has to reason about. */
	rc = CALY_PARSE_OK;
	CALY_UNROLL
	for (i = 0; i < CALY_TUNNEL_MAX_DEPTH + 1u; i++) {
		__u32 nxt_off = 0;
		__u16 nxt_proto = 0;
		__u32 tun_max = cfg->tunnel_max_depth;
		int allow_tun;

		if (tun_max > CALY_TUNNEL_MAX_DEPTH)
			tun_max = CALY_TUNNEL_MAX_DEPTH;
		allow_tun = (flags & CALY_F_TUNNEL_INSPECT) && (i < tun_max);

		rc = caly_parse_l3(ctx, pkt, cfg, cur_off, cur_proto,
				   allow_tun, i > 0, &nxt_off, &nxt_proto,
				   &icmp_tc);
		if (rc != CALY_PARSE_TUNNEL)
			break;

		cur_off = nxt_off;
		cur_proto = nxt_proto;
		pkt->tunnel_depth = i + 1;
		pkt->flags |= CALY_PKT_F_TUNNELED;
	}

	if (rc == CALY_PARSE_TUNNEL)
		rc = STAT_DROP_TUNNEL_DEPTH;   /* cannot happen; belt and braces */

	if (rc != CALY_PARSE_OK) {
		reason = rc;
		act = CALY_ACT_DROP;
		goto verdict;
	}

	sc->carry_icmp_tc = icmp_tc;
	sc->carry_is_wan = (__u8)is_wan;
	sc->carry_if_monitor = (__u8)if_monitor;
	sc->carry_if_flags = if_flags;

	/* Stage 2 onward lives in caly_xdp_policy, reached by this tail call.
	 * Splitting parse from policy is what keeps each half inside the verifier
	 * complexity budget on RHEL 9 / 5.14 (the monolith failed to load, -E2BIG).
	 * The parsed packet is already in sc->pkt and survives the tail call
	 * (per-CPU scratch, same CPU, same packet). We only fall through when the
	 * tail call could not happen (slot empty or the call limit was hit): fail
	 * OPEN into the shared verdict block, never drop a parsed packet because
	 * our own plumbing was missing. */
	bpf_tail_call(ctx, &caly_progs, CALY_PROG_IDX_POLICY);
	caly_stat(STAT_TAILCALL_FAIL, pkt_len);
	reason = STAT_PASS_DEFAULT;
	act = CALY_ACT_PASS;
	goto verdict;

	/* ---- Stage 11: accounting and verdict. Single exit point: every
	 * packet is charged exactly one specific reason plus the aggregates,
	 * and no path can return without doing so. ---- */
verdict:
	{
		__u32 verdict_code;
		int action;

		/* Monitor mode rewrites the verdict but keeps the reason, so
		 * `calyanti-cli stats` shows exactly what WOULD have been
		 * dropped before the operator commits to dropping it. */
		if (act == CALY_ACT_DROP &&
		    ((flags & CALY_F_MONITOR_ONLY) ||
		     mode == FW_MODE_MONITOR_ONLY || if_monitor)) {
			caly_stat(STAT_MONITOR_WOULD_DROP, pkt_len);
			act = CALY_ACT_PASS;
			verdict_code = CALY_VERDICT_MONITOR;
			want_event = 1;
		} else if (act == CALY_ACT_DROP) {
			verdict_code = CALY_VERDICT_DROP;
			want_event = 1;
		} else if (act == CALY_ACT_TX) {
			verdict_code = CALY_VERDICT_TX;
			want_event = 1;
		} else {
			verdict_code = CALY_VERDICT_PASS;
		}

		caly_stat(STAT_PKT_TOTAL, pkt_len);
		if (reason != STAT_PKT_TOTAL)
			caly_stat(reason, pkt_len);

		if (act == CALY_ACT_DROP) {
			caly_stat(STAT_DROP_TOTAL, pkt_len);
			caly_gauge(CALY_G_DROPS, 1);
			action = XDP_DROP;
		} else if (act == CALY_ACT_TX) {
			caly_stat(STAT_TX_TOTAL, pkt_len);
			action = XDP_TX;
		} else {
			caly_stat(STAT_PASS_TOTAL, pkt_len);
			action = XDP_PASS;
		}

		caly_gauge(CALY_G_PKTS, 1);
		caly_gauge(CALY_G_BYTES, pkt_len);
		if (is_syn)
			caly_gauge(CALY_G_SYN, 1);
		/* New-flow gauge tracks new inbound TCP connections, matching
		 * the newconn bucket and the global_newconn escalation
		 * thresholds; see the rate-limit stage for why UDP/ICMP misses
		 * are excluded. */
		if (is_syn && ct_missed)
			caly_gauge(CALY_G_NEWCONN, 1);
		if (pkt->proto == CALY_IPPROTO_UDP)
			caly_gauge(CALY_G_UDP, 1);
		if (is_icmp)
			caly_gauge(CALY_G_ICMP, 1);
		if (pkt->flags & CALY_PKT_F_FRAG)
			caly_gauge(CALY_G_FRAG, 1);

		/* Top-talker accounting. Reporting only; nothing in the drop
		 * path ever reads it. */
		if ((flags & CALY_F_SRC_STATS) && pkt->family) {
			struct src_stats *ss;

			if (is_v4)
				ss = bpf_map_lookup_elem(&caly_top4, &skey4);
			else
				ss = bpf_map_lookup_elem(&caly_top6, &skey6);

			if (ss) {
				ss->packets += 1;
				ss->bytes += pkt_len;
				ss->last_seen_ns = now;
				if (verdict_code == CALY_VERDICT_DROP ||
				    verdict_code == CALY_VERDICT_MONITOR) {
					ss->drops += 1;
					ss->drop_bytes += pkt_len;
					ss->last_reason = reason;
				}
			} else {
				__builtin_memset(&tv.ts, 0, sizeof(tv.ts));
				tv.ts.packets = 1;
				tv.ts.bytes = pkt_len;
				tv.ts.first_seen_ns = now;
				tv.ts.last_seen_ns = now;
				tv.ts.last_reason = reason;
				if (verdict_code == CALY_VERDICT_DROP ||
				    verdict_code == CALY_VERDICT_MONITOR) {
					tv.ts.drops = 1;
					tv.ts.drop_bytes = pkt_len;
				}

				if (is_v4)
					err = bpf_map_update_elem(&caly_top4,
								  &skey4,
								  &tv.ts,
								  BPF_ANY);
				else
					err = bpf_map_update_elem(&caly_top6,
								  &skey6,
								  &tv.ts,
								  BPF_ANY);
				if (err)
					caly_stat(STAT_MAP_FULL_SRCSTAT, pkt_len);
			}
		}

		/* Sampled events. Never emitted for an ordinary pass: at line
		 * rate that would cost more CPU than the filtering does. */
		if (want_event && (flags & CALY_F_LOG_EVENTS) &&
		    cfg->log_sample_rate) {
			struct event *ev = &sc->ev;
			int emit = 1;

			sc->tmp[CALY_TMP_EV_COUNT] += 1;
			if (sc->tmp[CALY_TMP_EV_COUNT] < cfg->log_sample_rate) {
				caly_stat(STAT_EVENT_SAMPLED_OUT, pkt_len);
				emit = 0;
			} else {
				sc->tmp[CALY_TMP_EV_COUNT] = 0;
			}

			/* Hard events/sec ceiling, counted per CPU. */
			if (emit && cfg->log_max_pps) {
				__u64 ws = sc->tmp[CALY_TMP_EV_WIN_NS];

				if (now < ws || now - ws >= CALY_NSEC_PER_SEC) {
					sc->tmp[CALY_TMP_EV_WIN_NS] = now;
					sc->tmp[CALY_TMP_EV_IN_WIN] = 0;
				}
				if (sc->tmp[CALY_TMP_EV_IN_WIN] >=
				    cfg->log_max_pps) {
					caly_stat(STAT_EVENT_SAMPLED_OUT,
						  pkt_len);
					emit = 0;
				} else {
					sc->tmp[CALY_TMP_EV_IN_WIN] += 1;
				}
			}

			if (emit) {
				__builtin_memset(ev, 0, sizeof(*ev));
				ev->ts_ns = now;
				ev->ban_ttl_ns = ban_ttl;
				ev->value = evval;
				__builtin_memcpy(ev->saddr, pkt->saddr,
						 sizeof(ev->saddr));
				__builtin_memcpy(ev->daddr, pkt->daddr,
						 sizeof(ev->daddr));
				ev->ifindex = pkt->ifindex;
				ev->reason = reason;
				ev->verdict = verdict_code;
				ev->proto = pkt->proto;
				ev->pkt_len = pkt_len;
				ev->family = pkt->family;
				ev->sport = pkt->sport;
				ev->dport = pkt->dport;
				ev->tcp_flags = (__u16)pkt->tcp_flags;
				ev->mode = (__u8)mode;
				ev->version = (__u8)CALY_ABI_VERSION_MAJOR;

				err = bpf_perf_event_output(ctx, &caly_events,
							    BPF_F_CURRENT_CPU,
							    ev, sizeof(*ev));
				if (err) {
					caly_stat(STAT_EVENT_LOST, pkt_len);
					caly_gauge(CALY_G_EVENTS_LOST, 1);
				} else {
					caly_stat(STAT_EVENT_EMITTED, pkt_len);
					caly_gauge(CALY_G_EVENTS, 1);
				}
			}
		}

		return action;
	}
}
SEC("xdp")
int caly_xdp_policy(struct xdp_md *ctx)
{
	struct fw_config *cfg;
	struct caly_scratch *sc;
	struct pkt_ctx *pkt;
	struct port_rule *prule = NULL;
	struct conn_state *cs;

	/* One reusable temporary big enough for the largest value we ever have
	 * to build before inserting it into a map. Their lifetimes never
	 * overlap, so a union keeps the stack far below the 512 byte limit. */
	union {
		struct rate_state rs;
		struct scan_state sn;
		struct src_stats  ts;
	} tv;

	struct lpm_key_v4 lk4;
	struct lpm_key_v6 lk6;
	struct in6_key skey6;
	__u32 skey4 = 0;

	__u64 flags, now, if_flags = 0, ban_ttl = 0, evval = 0;
	__u32 zero = 0, key32;
	__u32 reason = STAT_PASS_DEFAULT;
	__u32 pkt_len, mode;
	__u32 icmp_tc = 0;
	__u32 icmp_policy = CALY_ICMP_PASS;
	__u32 i;
	int act = CALY_ACT_PASS;
	int is_wan = 0, if_monitor = 0, is_v4 = 1;
	int ct_hit = 0, ct_missed = 0, ct_key_valid = 0;
	int is_syn = 0, is_icmp = 0, want_event = 0;
	int ban_deferred = 0;
	long err;

	/* Second half of the dataplane. caly_xdp_main parsed the frame into the
	 * per-CPU scratch map and tail-called us; we re-establish the policy
	 * inputs from sc->pkt and the carried values and run stage 2 (anomalies)
	 * through the verdict. Starting from a clean verifier state - with no
	 * packet-pointer range baggage from the parser - is what makes this half
	 * fit the complexity budget. Nothing here reads the frame bytes. */

	cfg = bpf_map_lookup_elem(&caly_config, &zero);
	if (!cfg) {
		caly_stat(STAT_PKT_TOTAL, 0);
		caly_stat(STAT_CONFIG_MISSING, 0);
		caly_stat(STAT_PASS_TOTAL, 0);
		return XDP_PASS;
	}

	sc = bpf_map_lookup_elem(&caly_scratch, &zero);
	if (!sc) {
		caly_stat(STAT_PKT_TOTAL, 0);
		caly_stat(STAT_SCRATCH_FAIL, 0);
		caly_stat(STAT_PASS_TOTAL, 0);
		return XDP_PASS;
	}

	pkt = &sc->pkt;
	flags = cfg->flags;
	mode = cfg->mode;
	now = pkt->ts_ns;
	pkt_len = pkt->pkt_len;

	/* Values computed in the parser half that policy still needs and that are
	 * not reconstructible from sc->pkt. */
	icmp_tc = sc->carry_icmp_tc;
	is_wan = sc->carry_is_wan;
	if_monitor = sc->carry_if_monitor;
	if_flags = sc->carry_if_flags;

	/* skey6 must be fully zeroed before use: for IPv4 only skey4 carries the
	 * address and skey6 stays zero, and a hash key with uninitialised padding
	 * is both a verifier error on 4.18 and a silent lookup miss. */
	__builtin_memset(&skey6, 0, sizeof(skey6));

	/* is_v4/is_icmp/is_syn and the per-source keys are derived here from the
	 * already-parsed sc->pkt, exactly as the monolith did after parsing. */
	is_v4 = (pkt->family == CALY_AF_INET);
	is_icmp = (pkt->proto == CALY_IPPROTO_ICMP ||
		   pkt->proto == CALY_IPPROTO_ICMPV6);
	is_syn = (pkt->proto == CALY_IPPROTO_TCP) &&
		 ((pkt->tcp_flags & CALY_TCP_SYN) != 0) &&
		 ((pkt->tcp_flags & CALY_TCP_ACK) == 0);

	/* Per-source map key, built once now that the source address is known
	 * and reused by every per-source lookup below. For IPv4 only saddr[0]
	 * carries the address and skey6 stays zero; for IPv6 skey4 stays zero.
	 * skey6 was already zeroed in the prelude. */
	if (is_v4)
		skey4 = pkt->saddr[0];
	else
		__builtin_memcpy(skey6.a, pkt->saddr, sizeof(skey6.a));

	/* ---- Stage 2: anomalies. No map lookups, cheapest and highest
	 * confidence checks first. ---- */

	/* LAND: a packet whose source equals its destination is impossible on
	 * the wire and crashes naive stacks. */
	if (flags & CALY_F_LAND_CHECK) {
		if (pkt->saddr[0] == pkt->daddr[0] &&
		    pkt->saddr[1] == pkt->daddr[1] &&
		    pkt->saddr[2] == pkt->daddr[2] &&
		    pkt->saddr[3] == pkt->daddr[3]) {
			reason = STAT_DROP_LAND;
			act = CALY_ACT_DROP;
			goto verdict;
		}
	}

	if (pkt->proto == CALY_IPPROTO_TCP &&
	    !(pkt->flags & CALY_PKT_F_L4_TRUNC)) {
		if (flags & CALY_F_TCP_FLAG_CHECKS) {
			/* Null / FIN-only / SYN+FIN / SYN+RST / FIN+RST / xmas
			 * / all-flags are OS-fingerprinting and stealth-scan
			 * probes; no stack ever emits them. ECE and CWR are
			 * legitimate ECN and are masked out inside the helper. */
			__u32 bad = caly_tcp_flags_illegal((__u8)pkt->tcp_flags);

			if (bad != STAT_PKT_TOTAL) {
				reason = bad;
				act = CALY_ACT_DROP;
				goto verdict;
			}
		}
		if ((flags & CALY_F_ANOMALY_CHECKS) &&
		    (pkt->sport == 0 || pkt->dport == 0)) {
			reason = STAT_DROP_L4_PORT_ZERO;
			act = CALY_ACT_DROP;
			goto verdict;
		}
	}

	if (pkt->proto == CALY_IPPROTO_UDP &&
	    !(pkt->flags & CALY_PKT_F_L4_TRUNC)) {
		if ((flags & CALY_F_ANOMALY_CHECKS) &&
		    (pkt->sport == 0 || pkt->dport == 0)) {
			reason = STAT_DROP_L4_PORT_ZERO;
			act = CALY_ACT_DROP;
			goto verdict;
		}
	}

	/* ICMP sanity and per-type policy. */
	if (is_icmp) {
		__u32 itype = (icmp_tc >> 8) & 0xFFu;
		__u32 *pol;
		__u32 payload;
		__u32 maxpay;
		int mandatory = 0;

		/* Fragmented ICMP has no legitimate use and is a reassembly
		 * attack in every implementation that ever had one. */
		if ((flags & CALY_F_FRAG_CHECKS) &&
		    (pkt->flags & CALY_PKT_F_FRAG)) {
			reason = STAT_DROP_FRAG_ICMP;
			act = CALY_ACT_DROP;
			goto verdict;
		}

		payload = pkt->l4_len >= sizeof(struct caly_icmphdr)
			? (__u32)pkt->l4_len - (__u32)sizeof(struct caly_icmphdr)
			: 0;
		maxpay = is_v4 ? cfg->icmp_max_payload : cfg->icmp6_max_payload;
		if (maxpay && payload > maxpay) {
			reason = is_v4 ? STAT_DROP_ICMP_OVERSIZE
				       : STAT_DROP_ICMP6_OVERSIZE;
			act = CALY_ACT_DROP;
			goto verdict;
		}

		/* The types below can NEVER be dropped. The loader refuses a
		 * config that tries; this is the second, independent guard.
		 *   IPv4 type 3  - Destination Unreachable, code 4 is
		 *                  Fragmentation Needed. Drop it and PMTUD
		 *                  black-holes: TCP connects, then hangs.
		 *   IPv6 type 2  - Packet Too Big, the ONLY PMTUD mechanism
		 *                  IPv6 has, because routers never fragment.
		 *   IPv6 133-136 - router and neighbour discovery. IPv6 has no
		 *                  ARP; dropping these disconnects the host. */
		if (is_v4) {
			mandatory = (itype == CALY_ICMP4_DEST_UNREACH);
		} else {
			mandatory = (itype == CALY_ICMP6_PKT_TOOBIG ||
				     itype == CALY_ICMP6_ROUTER_SOL ||
				     itype == CALY_ICMP6_ROUTER_ADV ||
				     itype == CALY_ICMP6_NEIGH_SOL ||
				     itype == CALY_ICMP6_NEIGH_ADV);
		}

		key32 = itype;
		if (is_v4)
			pol = bpf_map_lookup_elem(&caly_icmp4_pol, &key32);
		else
			pol = bpf_map_lookup_elem(&caly_icmp6_pol, &key32);

		icmp_policy = pol ? *pol : CALY_ICMP_PASS;
		if (mandatory)
			icmp_policy = CALY_ICMP_PASS;

		if (mandatory) {
			/* Short-circuit out of the whole ladder. Neighbour
			 * discovery arrives from fe80::/10, which the martian
			 * filter would otherwise reject on a WAN interface,
			 * and a PMTUD message may well come from a source that
			 * is banned or rate limited. Losing either strands the
			 * host far more effectively than any attack. */
			if (is_v4)
				reason = STAT_PASS_ICMP4_PMTUD;
			else if (itype == CALY_ICMP6_PKT_TOOBIG)
				reason = STAT_PASS_ICMP6_PMTUD;
			else
				reason = STAT_PASS_ICMP6_ND;
			goto verdict;
		}

		if ((flags & CALY_F_ICMP_FILTER) &&
		    icmp_policy == CALY_ICMP_DROP) {
			reason = is_v4 ? STAT_DROP_ICMP_TYPE
				       : STAT_DROP_ICMP6_TYPE;
			act = CALY_ACT_DROP;
			goto verdict;
		}
	}

	/* Bogons and martians. WAN zone only: on a LAN port every one of these
	 * tests would fire on legitimate internal traffic. */
	if ((flags & CALY_F_BOGON_FILTER) && is_wan) {
		int drop_private = ((flags & CALY_F_WAN_DROP_PRIVATE) != 0) ||
				   ((if_flags & CALY_IF_F_DROP_PRIVATE) != 0);
		__u32 bog;

		if (is_v4)
			bog = caly_v4_src_bogon((const __u8 *)&pkt->saddr[0],
						drop_private);
		else
			bog = caly_v6_src_bogon((const __u8 *)&pkt->saddr[0],
						drop_private);

		if (bog != STAT_PKT_TOTAL) {
			reason = bog;
			act = CALY_ACT_DROP;
			goto verdict;
		}

		/* A packet arriving from outside carrying one of our own
		 * prefixes as its source is spoofed by definition. */
		if (is_v4) {
			caly_lpm4_key(&lk4, pkt->saddr);
			if (bpf_map_lookup_elem(&caly_local4, &lk4)) {
				reason = STAT_DROP_SRC_SELF;
				act = CALY_ACT_DROP;
				goto verdict;
			}
		} else {
			caly_lpm6_key(&lk6, pkt->saddr);
			if (bpf_map_lookup_elem(&caly_local6, &lk6)) {
				reason = STAT_DROP_SRC_SELF;
				act = CALY_ACT_DROP;
				goto verdict;
			}
		}
	}

	/* ---- Stage 3: allowlist. THE escape hatch, checked before every
	 * drop rule below it. ---- */

	if (flags & CALY_F_ALLOWLIST) {
		struct rule_meta *rm;

		if (is_v4) {
			caly_lpm4_key(&lk4, pkt->saddr);
			rm = bpf_map_lookup_elem(&caly_allow4, &lk4);
		} else {
			caly_lpm6_key(&lk6, pkt->saddr);
			rm = bpf_map_lookup_elem(&caly_allow6, &lk6);
		}
		if (rm) {
			rm->hits += 1;
			pkt->flags |= CALY_PKT_F_ALLOWLIST;
			if (rm->flags & CALY_RULE_F_LOG)
				want_event = 1;
			reason = STAT_PASS_ALLOWLIST;
			goto verdict;
		}
	}

	/* ---- Stage 3b: management ports. The anti-lockout guarantee.
	 * TCP/22 is forced into this list by the loader in every mode; a
	 * config that would remove it is rejected outright. ---- */

	if (!(pkt->flags & CALY_PKT_F_L4_TRUNC)) {
		int mgmt = 0;

		if (pkt->proto == CALY_IPPROTO_TCP)
			mgmt = caly_is_mgmt_tcp(cfg, bpf_ntohs(pkt->dport));
		else if (pkt->proto == CALY_IPPROTO_UDP)
			mgmt = caly_is_mgmt_udp(cfg, bpf_ntohs(pkt->dport));

		if (mgmt) {
			pkt->flags |= CALY_PKT_F_MGMT;
			/* With MGMT_BYPASS_ALL (the default) a management port
			 * skips everything, rate limits included. Without it,
			 * reputation and port policy are still skipped - being
			 * banned must never cost you the ability to log in -
			 * but the per-source buckets below still apply. */
			if (flags & CALY_F_MGMT_BYPASS_ALL) {
				reason = STAT_PASS_MGMT_PORT;
				goto verdict;
			}
		}
	}

	/* ---- Stage 4: reputation ---- */

	if (!(pkt->flags & CALY_PKT_F_MGMT)) {
		if (flags & CALY_F_BLOCKLIST) {
			struct rule_meta *rm;

			if (is_v4) {
				caly_lpm4_key(&lk4, pkt->saddr);
				rm = bpf_map_lookup_elem(&caly_block4, &lk4);
			} else {
				caly_lpm6_key(&lk6, pkt->saddr);
				rm = bpf_map_lookup_elem(&caly_block6, &lk6);
			}
			if (rm) {
				rm->hits += 1;
				reason = STAT_DROP_BLOCKLIST;
				act = CALY_ACT_DROP;
				goto verdict;
			}
		}

		{
			struct ban_entry *be;

			if (is_v4)
				be = bpf_map_lookup_elem(&caly_ban4, &skey4);
			else
				be = bpf_map_lookup_elem(&caly_ban6, &skey6);

			if (be) {
				int active = (be->flags & CALY_BAN_F_PERMANENT) ||
					     be->expiry_ns > now;

				if (active) {
					/* Operator-, feed- and permanent bans
					 * are deliberate and enforced here,
					 * ahead of conntrack. A ban that is ONLY
					 * auto-installed may have been induced by
					 * spoofable connectionless traffic that
					 * carried a forged source, so enforcement
					 * is deferred until after the conntrack
					 * short-circuit below - a reply to one of
					 * the box's own outbound flows must never
					 * be black-holed by a spoof-induced ban. */
					if (be->flags & (CALY_BAN_F_MANUAL |
							 CALY_BAN_F_FEED |
							 CALY_BAN_F_PERMANENT)) {
						be->last_hit_ns = now;
						be->hit_pkts += 1;
						be->hit_bytes += pkt_len;
						evval = be->expiry_ns > now
							? be->expiry_ns - now
							: 0;
						ban_ttl = be->cur_ttl_ns;
						reason = STAT_DROP_BAN_ACTIVE;
						act = CALY_ACT_DROP;
						goto verdict;
					}
					ban_deferred = 1;
				}
				/* Expired: treat as a miss. Userspace garbage
				 * collects; deleting here would cost a map
				 * operation in the hot path for no gain. */
			}
		}
	}

	/* ---- Stage 5: conntrack-lite ----
	 *
	 * An established flow short-circuits every rule below. This is what
	 * makes inbound default-deny survivable: replies to your own outbound
	 * connections never meet the port policy at all.
	 *
	 * ORIENTATION: the key is always ingress relative - saddr is the
	 * remote peer, daddr is us. The tc egress program swaps the tuple
	 * before inserting an outbound flow so the reply hits first time. */

	if ((flags & CALY_F_CONNTRACK) && !(pkt->flags & CALY_PKT_F_L4_TRUNC)) {
		struct conn_key *ck = &sc->ck;

		__builtin_memset(ck, 0, sizeof(*ck));
		__builtin_memcpy(ck->saddr, pkt->saddr, sizeof(ck->saddr));
		__builtin_memcpy(ck->daddr, pkt->daddr, sizeof(ck->daddr));
		ck->sport = pkt->sport;
		ck->dport = pkt->dport;
		ck->proto = (__u8)pkt->proto;
		ck->family = (__u8)pkt->family;
		ct_key_valid = 1;

		cs = bpf_map_lookup_elem(&caly_conn, ck);
		if (cs) {
			__u64 idle = now >= cs->last_seen_ns
				   ? now - cs->last_seen_ns : 0;
			__u64 timeout;

			if (pkt->proto == CALY_IPPROTO_TCP) {
				if (cs->state == CALY_CT_ESTABLISHED)
					timeout = cfg->ct_tcp_est_ns;
				else if (cs->state == CALY_CT_FIN_WAIT ||
					 cs->state == CALY_CT_CLOSED)
					timeout = cfg->ct_tcp_fin_ns;
				else
					timeout = cfg->ct_tcp_syn_ns;
			} else if (pkt->proto == CALY_IPPROTO_UDP) {
				timeout = (cs->flags & CALY_CT_F_SEEN_REPLY)
					? cfg->ct_udp_stream_ns
					: cfg->ct_udp_ns;
			} else if (is_icmp) {
				timeout = cfg->ct_icmp_ns;
			} else {
				timeout = cfg->ct_generic_ns;
			}

			if (timeout != 0 && idle > timeout) {
				/* Stale entry: fall through to policy and let
				 * the accept path overwrite it. */
				ct_missed = 1;
				caly_stat(STAT_CT_MISS, pkt_len);
			} else {
				cs->last_seen_ns = now;
				cs->pkts_in += 1;
				cs->bytes_in += pkt_len;

				if (pkt->proto == CALY_IPPROTO_TCP) {
					if (pkt->tcp_flags & CALY_TCP_RST) {
						cs->state = CALY_CT_CLOSED;
						caly_stat(STAT_CT_CLOSED, pkt_len);
					} else if (pkt->tcp_flags & CALY_TCP_FIN) {
						cs->state = CALY_CT_FIN_WAIT;
					} else if ((pkt->tcp_flags & CALY_TCP_ACK) &&
						   (cs->state == CALY_CT_SYN_RECV ||
						    cs->state == CALY_CT_SYN_SENT ||
						    cs->state == CALY_CT_NEW)) {
						cs->state = CALY_CT_ESTABLISHED;
						cs->flags |= CALY_CT_F_SEEN_REPLY;
					}
				} else if (cs->state == CALY_CT_NEW) {
					cs->state = CALY_CT_ESTABLISHED;
					cs->flags |= CALY_CT_F_SEEN_REPLY;
				}

				caly_stat(STAT_CT_UPDATED, pkt_len);

				if (cs->state != CALY_CT_CLOSED) {
					ct_hit = 1;
					pkt->flags |= CALY_PKT_F_CT_HIT;
					caly_stat(STAT_CT_HIT, pkt_len);
					reason = STAT_PASS_CONNTRACK;
					goto verdict;
				}
				/* CLOSED entries do not short-circuit: a RST
				 * must not open the door for the next packet. */
				ct_missed = 1;
			}
		} else {
			ct_missed = 1;
			caly_stat(STAT_CT_MISS, pkt_len);
		}
	}

	/* ---- Deferred AUTO-ban enforcement ----
	 *
	 * A purely auto-installed ban may have been induced by spoofable
	 * connectionless traffic - a UDP/ICMP flood carrying a forged source -
	 * so it is enforced only now, AFTER the conntrack short-circuit. A reply
	 * to one of the box's own outbound flows matches egress-learned state and
	 * has already returned via STAT_PASS_CONNTRACK above; anything still
	 * executing here is unsolicited, so the ban applies. Operator, feed and
	 * permanent bans were already enforced in stage 4. */
	if (ban_deferred) {
		struct ban_entry *be;

		if (is_v4)
			be = bpf_map_lookup_elem(&caly_ban4, &skey4);
		else
			be = bpf_map_lookup_elem(&caly_ban6, &skey6);

		if (be && ((be->flags & CALY_BAN_F_PERMANENT) ||
			   be->expiry_ns > now)) {
			be->last_hit_ns = now;
			be->hit_pkts += 1;
			be->hit_bytes += pkt_len;
			evval = be->expiry_ns > now ? be->expiry_ns - now : 0;
			ban_ttl = be->cur_ttl_ns;
			reason = STAT_DROP_BAN_ACTIVE;
			act = CALY_ACT_DROP;
			goto verdict;
		}
	}

	/* An inbound SYN|ACK with no matching outbound SYN is either a
	 * reflection attack against a spoofed victim or a stray. It can only
	 * be judged when the egress hook is present to learn outbound flows;
	 * without it, dropping this would kill every outbound connection. */
	if ((flags & CALY_F_CAP_TC_EGRESS) && ct_missed &&
	    pkt->proto == CALY_IPPROTO_TCP &&
	    (pkt->tcp_flags & (CALY_TCP_SYN | CALY_TCP_ACK)) ==
	    (CALY_TCP_SYN | CALY_TCP_ACK) &&
	    !(pkt->flags & CALY_PKT_F_MGMT)) {
		reason = STAT_DROP_TCP_SYNACK_UNSOL;
		act = CALY_ACT_DROP;
		goto verdict;
	}

	/* ---- Stage 5b: lockdown ----
	 * Allowlist, management ports and established flows have all had their
	 * chance above. Nothing else gets through. */

	if (mode == FW_MODE_LOCKDOWN && !(pkt->flags & CALY_PKT_F_MGMT)) {
		if ((flags & CALY_F_LOCKDOWN_ICMP) && is_icmp &&
		    icmp_policy != CALY_ICMP_DROP) {
			reason = STAT_PASS_ICMP_POLICY;
			goto verdict;
		}
		reason = STAT_DROP_LOCKDOWN;
		act = CALY_ACT_DROP;
		goto verdict;
	}

	/* ---- Stage 6: reflection / amplification ----
	 *
	 * UDP whose SOURCE port is a known amplifier is the signature of being
	 * used as a reflection target. Our own DNS and NTP queries create
	 * outbound conntrack state (learned by the tc egress hook) and their
	 * replies short-circuit via ct_hit above; unsolicited traffic claiming
	 * to come from port 53 does not.
	 *
	 * That exemption exists ONLY when the egress learner is present, so the
	 * filter is gated on CALY_F_CAP_TC_EGRESS. On an XDP-only box, or when
	 * the clsact egress attach failed, there is no outbound UDP state, every
	 * solicited reply would look unsolicited, and running the filter would
	 * silently break NTP/DNS clients (source port 123/53). Fail open instead.
	 *
	 * The packet is DROPPED but the source is NEVER banned here: the source
	 * of reflected traffic is attacker-chosen - a spoofed victim, or a real
	 * reflector being abused - so a ban from this single, trivially forged
	 * signal black-holes the wrong host. WAN only, for the same reason as
	 * the martian filter; the operator can clear CALY_PORT_F_AMPLIFIER per
	 * port to allowlist a reflective service they legitimately consume. */

	if ((flags & CALY_F_ANTI_AMPLIFY) && (flags & CALY_F_CAP_TC_EGRESS) &&
	    is_wan && !ct_hit && pkt->proto == CALY_IPPROTO_UDP &&
	    !(pkt->flags & (CALY_PKT_F_L4_TRUNC | CALY_PKT_F_MGMT))) {
		struct port_rule *sr;

		key32 = (__u32)bpf_ntohs(pkt->sport);
		sr = bpf_map_lookup_elem(&caly_port_udp, &key32);
		if (sr && (sr->flags & CALY_PORT_F_AMPLIFIER)) {
			evval = key32;
			reason = STAT_DROP_AMP_SRCPORT;
			act = CALY_ACT_DROP;
			goto verdict;
		}
	}

	/* ---- Stage 7: port policy ----
	 * Per-protocol 65536-entry arrays indexed by the host-order
	 * destination port. Inbound default-deny is possible without breaking
	 * outbound replies precisely because conntrack ran first. */

	if ((flags & CALY_F_PORT_POLICY) &&
	    !(pkt->flags & (CALY_PKT_F_L4_TRUNC | CALY_PKT_F_MGMT)) &&
	    (pkt->proto == CALY_IPPROTO_TCP || pkt->proto == CALY_IPPROTO_UDP)) {
		int is_udp = (pkt->proto == CALY_IPPROTO_UDP);

		key32 = (__u32)bpf_ntohs(pkt->dport);
		if (is_udp)
			prule = bpf_map_lookup_elem(&caly_port_udp, &key32);
		else
			prule = bpf_map_lookup_elem(&caly_port_tcp, &key32);

		if (prule && CALY_RULE_PRESENT(prule)) {
			if (prule->flags & CALY_PORT_F_LOG)
				want_event = 1;

			if (prule->flags & CALY_PORT_F_MGMT) {
				pkt->flags |= CALY_PKT_F_MGMT;
				reason = STAT_PASS_MGMT_PORT;
				goto verdict;
			}

			if (prule->mode == CALY_PORT_CLOSED) {
				reason = STAT_DROP_PORT_CLOSED;
				act = CALY_ACT_DROP;
				goto verdict;
			}

			if (prule->mode == CALY_PORT_RATELIMIT) {
				struct caly_token_bucket *tb;
				__u32 tbi = CALY_PORT_TB_IDX(is_udp, key32);

				tb = bpf_map_lookup_elem(&caly_port_tb, &tbi);
				if (tb && !caly_tb_consume(tb, now, prule->rate,
							   prule->burst, 1)) {
					evval = prule->rate;
					reason = STAT_DROP_PORT_RATE;
					act = CALY_ACT_DROP;
					goto verdict;
				}
				reason = STAT_PASS_PORT_RATE_OK;
			} else {
				reason = STAT_PASS_PORT_OPEN;
			}
		} else if (flags & CALY_F_DEFAULT_DENY) {
			reason = STAT_DROP_DEFAULT_DENY;
			act = CALY_ACT_DROP;
			goto verdict;
		}
	} else if ((flags & CALY_F_DEFAULT_DENY) &&
		   !(pkt->flags & CALY_PKT_F_MGMT) && !is_icmp &&
		   pkt->proto != CALY_IPPROTO_TCP &&
		   pkt->proto != CALY_IPPROTO_UDP &&
		   !(pkt->flags & CALY_PKT_F_L4_TRUNC)) {
		/* ESP, AH, SCTP, OSPF, an un-inspected tunnel ... default deny
		 * means deny. With it off these pass, which is why VPNs keep
		 * working out of the box. */
		reason = caly_is_tunnel_proto((__u8)pkt->proto) &&
			 pkt->tunnel_depth ? STAT_DROP_TUNNEL_DEPTH
					   : STAT_DROP_L4_UNKNOWN;
		act = CALY_ACT_DROP;
		goto verdict;
	}

	/* ---- Stage 8: per-source token buckets ----
	 *
	 * Six nanosecond-refill integer buckets per source address. Exceeding
	 * one drops the packet and costs the source a strike; strike_limit
	 * strikes inside strike_window installs a ban whose TTL escalates on
	 * repeat offences.
	 *
	 * The map is a shared (NOT per-CPU) LRU: a per-CPU bucket would
	 * multiply the effective limit by the CPU count while RSS spread one
	 * attacker across every queue. The read-modify-write race that costs
	 * is benign - at worst a couple of extra packets get through. */

	if ((flags & CALY_F_RATE_LIMIT) && !(pkt->flags & CALY_PKT_F_ALLOWLIST)) {
		struct rate_state *rs;
		__u32 hit = STAT_PKT_TOTAL;
		__u32 want_bytes = pkt_len;
		int is_udp = (pkt->proto == CALY_IPPROTO_UDP);
		/* "New connection" is an inbound TCP SYN that missed conntrack:
		 * the one unambiguous new-flow signal XDP has on ingress, and
		 * the only event that creates state. Charging every unsolicited
		 * UDP/ICMP miss here instead would over-count an ongoing UDP
		 * stream and false-positive-ban it against the shipped default
		 * (500/s), which is sized for new TCP connections; UDP volume is
		 * governed by the dedicated UDP bucket. */
		int newconn = is_syn && ct_missed;

		if (is_v4)
			rs = bpf_map_lookup_elem(&caly_rate4, &skey4);
		else
			rs = bpf_map_lookup_elem(&caly_rate6, &skey6);

		if (!rs) {
			/* First packet from this source. A freshly seeded
			 * bucket is full, so this packet conforms by
			 * construction; seed, charge it, and insert. Doing it
			 * this way keeps a single pointer type on the path the
			 * verifier has to walk afterwards. */
			__builtin_memset(&tv.rs, 0, sizeof(tv.rs));
			tv.rs.flags = CALY_RS_F_SEEDED;
			tv.rs.window_start_ns = now;
			tv.rs.last_seen_ns = now;

			CALY_UNROLL
			for (i = 0; i < CALY_TB_MAX; i++)
				caly_tb_init(&tv.rs.tb[i], now, cfg->tb_burst[i]);

			caly_tb_consume(&tv.rs.tb[CALY_TB_PPS], now,
					cfg->tb_rate[CALY_TB_PPS],
					cfg->tb_burst[CALY_TB_PPS], 1);
			caly_tb_consume(&tv.rs.tb[CALY_TB_BPS], now,
					cfg->tb_rate[CALY_TB_BPS],
					cfg->tb_burst[CALY_TB_BPS], want_bytes);
			if (is_syn)
				caly_tb_consume(&tv.rs.tb[CALY_TB_SYN], now,
						cfg->tb_rate[CALY_TB_SYN],
						cfg->tb_burst[CALY_TB_SYN], 1);
			if (is_udp)
				caly_tb_consume(&tv.rs.tb[CALY_TB_UDP], now,
						cfg->tb_rate[CALY_TB_UDP],
						cfg->tb_burst[CALY_TB_UDP], 1);
			if (is_icmp)
				caly_tb_consume(&tv.rs.tb[CALY_TB_ICMP], now,
						cfg->tb_rate[CALY_TB_ICMP],
						cfg->tb_burst[CALY_TB_ICMP], 1);
			if (newconn)
				caly_tb_consume(&tv.rs.tb[CALY_TB_NEWCONN], now,
						cfg->tb_rate[CALY_TB_NEWCONN],
						cfg->tb_burst[CALY_TB_NEWCONN], 1);

			if (is_v4)
				err = bpf_map_update_elem(&caly_rate4, &skey4,
							  &tv.rs, BPF_ANY);
			else
				err = bpf_map_update_elem(&caly_rate6, &skey6,
							  &tv.rs, BPF_ANY);
			if (err)
				caly_stat(STAT_MAP_FULL_RATE, pkt_len);
		} else {
			rs->last_seen_ns = now;

			if (!caly_tb_consume(&rs->tb[CALY_TB_PPS], now,
					     cfg->tb_rate[CALY_TB_PPS],
					     cfg->tb_burst[CALY_TB_PPS], 1)) {
				hit = STAT_DROP_RATE_PPS;
				evval = cfg->tb_rate[CALY_TB_PPS];
			} else if (!caly_tb_consume(&rs->tb[CALY_TB_BPS], now,
						    cfg->tb_rate[CALY_TB_BPS],
						    cfg->tb_burst[CALY_TB_BPS],
						    want_bytes)) {
				hit = STAT_DROP_RATE_BPS;
				evval = cfg->tb_rate[CALY_TB_BPS];
			} else if (is_syn &&
				   !caly_tb_consume(&rs->tb[CALY_TB_SYN], now,
						    cfg->tb_rate[CALY_TB_SYN],
						    cfg->tb_burst[CALY_TB_SYN],
						    1)) {
				hit = STAT_DROP_RATE_SYN;
				evval = cfg->tb_rate[CALY_TB_SYN];
			} else if (is_udp &&
				   !caly_tb_consume(&rs->tb[CALY_TB_UDP], now,
						    cfg->tb_rate[CALY_TB_UDP],
						    cfg->tb_burst[CALY_TB_UDP],
						    1)) {
				hit = STAT_DROP_RATE_UDP;
				evval = cfg->tb_rate[CALY_TB_UDP];
			} else if (is_icmp &&
				   !caly_tb_consume(&rs->tb[CALY_TB_ICMP], now,
						    cfg->tb_rate[CALY_TB_ICMP],
						    cfg->tb_burst[CALY_TB_ICMP],
						    1)) {
				hit = STAT_DROP_RATE_ICMP;
				evval = cfg->tb_rate[CALY_TB_ICMP];
			} else if (newconn &&
				   !caly_tb_consume(&rs->tb[CALY_TB_NEWCONN], now,
						    cfg->tb_rate[CALY_TB_NEWCONN],
						    cfg->tb_burst[CALY_TB_NEWCONN],
						    1)) {
				hit = STAT_DROP_RATE_NEWCONN;
				evval = cfg->tb_rate[CALY_TB_NEWCONN];
			}

			if (hit != STAT_PKT_TOTAL) {
				__u64 win = cfg->strike_window_ns;

				if (win == 0)
					win = 60ULL * CALY_NSEC_PER_SEC;
				if (now < rs->window_start_ns ||
				    now - rs->window_start_ns > win) {
					rs->window_start_ns = now;
					rs->strikes = 0;
				}
				if (rs->strikes < 0xFFFFFFFFu)
					rs->strikes += 1;
				rs->last_reason = hit;
				rs->flags |= CALY_RS_F_STRIKING;
				caly_stat(STAT_STRIKE_ADDED, pkt_len);

				/* Persistent IP-level bans are withheld from
				 * connectionless UDP/ICMP strikes: those carry
				 * an unauthenticated, trivially spoofed source,
				 * so a flood forging a legitimate peer's address
				 * must not get that peer banned. The packet is
				 * still dropped and a strike recorded; only the
				 * ban map mutation is skipped. Any spoof-induced
				 * ban that still lands (e.g. from TCP) can no
				 * longer black-hole the box's own solicited
				 * replies - they short-circuit on conntrack
				 * ahead of the deferred ban check. */
				if ((flags & CALY_F_AUTOBAN) &&
				    cfg->strike_limit && !is_udp && !is_icmp &&
				    rs->strikes >= cfg->strike_limit) {
					ban_ttl = caly_ban_install(sc, cfg,
								   is_v4,
								   &skey4,
								   &skey6, now,
								   hit, 0,
								   rs->strikes,
								   pkt_len);
					if (ban_ttl) {
						rs->offences += 1;
						rs->strikes = 0;
						rs->window_start_ns = now;
					}
				}

				reason = hit;
				act = CALY_ACT_DROP;
				goto verdict;
			}
		}
	}

	/* ---- Stage 9: port-scan detection ----
	 *
	 * A 512-bit Bloom filter over the destination ports a source touched
	 * inside the current window. Collisions make the distinct estimate
	 * LOW, which biases towards not banning - the safe direction. Only
	 * conntrack misses reach here, so an established flow chatting to one
	 * port never accumulates. */

	if ((flags & CALY_F_PORTSCAN_DETECT) &&
	    !(pkt->flags & (CALY_PKT_F_L4_TRUNC | CALY_PKT_F_ALLOWLIST)) &&
	    (pkt->proto == CALY_IPPROTO_TCP || pkt->proto == CALY_IPPROTO_UDP)) {
		struct scan_state *st;
		__u32 dport_h = (__u32)bpf_ntohs(pkt->dport);
		__u64 win = cfg->scan_window_ns;

		if (win == 0)
			win = 30ULL * CALY_NSEC_PER_SEC;

		if (is_v4)
			st = bpf_map_lookup_elem(&caly_scan4, &skey4);
		else
			st = bpf_map_lookup_elem(&caly_scan6, &skey6);

		if (!st) {
			__builtin_memset(&tv.sn, 0, sizeof(tv.sn));
			caly_scan_reset(&tv.sn, now);
			tv.sn.last_seen_ns = now;
			tv.sn.hits = 1;
			caly_scan_mark(&tv.sn, (__u16)dport_h);
			tv.sn.last_port = dport_h;

			if (is_v4)
				err = bpf_map_update_elem(&caly_scan4, &skey4,
							  &tv.sn, BPF_ANY);
			else
				err = bpf_map_update_elem(&caly_scan6, &skey6,
							  &tv.sn, BPF_ANY);
			if (err)
				caly_stat(STAT_MAP_FULL_SCAN, pkt_len);
		} else {
			if (now < st->window_start_ns ||
			    now - st->window_start_ns > win)
				caly_scan_reset(st, now);

			st->last_seen_ns = now;
			if (st->hits < 0xFFFFFFFFu)
				st->hits += 1;

			/* Dedupe consecutive probes to the same port so a
			 * chatty single-port client is never mistaken for a
			 * scanner. */
			if (st->last_port != dport_h) {
				caly_scan_mark(st, (__u16)dport_h);
				st->last_port = dport_h;
			}

			if (cfg->scan_port_threshold &&
			    st->distinct > cfg->scan_port_threshold) {
				evval = st->distinct;
				ban_ttl = caly_ban_install(sc, cfg, is_v4,
							   &skey4, &skey6, now,
							   STAT_DROP_PORTSCAN,
							   cfg->ban_ttl_scan_ns,
							   st->distinct,
							   pkt_len);
				caly_scan_reset(st, now);
				reason = STAT_DROP_PORTSCAN;
				act = CALY_ACT_DROP;
				goto verdict;
			}
		}
	}

	/* ---- Stage 10: SYN handling ----
	 *
	 * The SYN proxy answers inbound SYNs from XDP with a kernel-generated
	 * cookie so a spoofed flood never reaches the TCP stack. It lives in a
	 * separate program behind a tail call because the raw syncookie
	 * helpers are 5.15+: on an older kernel the loader marks it
	 * autoload=false, the prog-array slot stays empty, bpf_tail_call()
	 * simply returns, and we land on the rate-limit fallback below. An
	 * inline call would fail verification for the whole object on every
	 * pre-5.15 kernel.
	 *
	 * CALY_F_CAP_SYNPROXY is tested first so the fallback is chosen
	 * without paying for a failed tail call on every packet. */

	if (is_syn) {
		if ((flags & CALY_F_SYNPROXY) && (flags & CALY_F_CAP_SYNPROXY) &&
		    mode == FW_MODE_UNDER_ATTACK) {
			struct port_rule *spr = prule;

			/* The port-policy stage may not have run (master toggle
			 * off) or this may be a UDP-derived prule, so re-read
			 * the TCP destination-port rule if we do not already
			 * have it. caly_port_tcp is an ARRAY, so the lookup is
			 * a single bounds-checked index that never returns
			 * NULL for an in-range port. */
			if (!spr) {
				key32 = (__u32)bpf_ntohs(pkt->dport);
				spr = bpf_map_lookup_elem(&caly_port_tcp, &key32);
			}

			if (spr && (spr->flags & CALY_PORT_F_SYNPROXY)) {
				bpf_tail_call(ctx, &caly_progs,
					      CALY_PROG_IDX_SYNPROXY);
				/* Only reached when the slot is empty or the
				 * tail call limit was hit. Fail open into the
				 * fallback; never drop a legitimate SYN
				 * because our own plumbing was missing. */
				caly_stat(STAT_TAILCALL_FAIL, pkt_len);
				caly_stat(STAT_SYNPROXY_UNAVAIL, pkt_len);
			} else {
				caly_stat(STAT_SYNPROXY_SKIPPED, pkt_len);
			}
		}

		/* Pre-5.15 fallback: a hard global cap on inbound SYNs per
		 * second, on top of the per-source rate_syn bucket already
		 * charged above. Shares caly_port_tb slot 0 (TCP port 0),
		 * which no real rule can ever occupy. */
		if (!(flags & CALY_F_CAP_SYNPROXY) && cfg->syn_fallback_pps) {
			struct caly_token_bucket *gb;

			key32 = CALY_TB_GLOBAL_SYN;
			gb = bpf_map_lookup_elem(&caly_port_tb, &key32);
			if (gb && !caly_tb_consume(gb, now, cfg->syn_fallback_pps,
						   cfg->syn_fallback_pps, 1)) {
				evval = cfg->syn_fallback_pps;
				reason = STAT_DROP_RATE_GLOBAL_SYN;
				act = CALY_ACT_DROP;
				goto verdict;
			}
		}
	}

	/* ---- Accepted. Learn the flow so its replies short-circuit. ----
	 *
	 * XDP sees ingress only. The ONLY inbound event that legitimately
	 * creates state is a policy-permitted TCP SYN (-> SYN_RECV, promoted to
	 * ESTABLISHED when the matching ACK arrives). Outbound-initiated flows
	 * (UDP, ICMP, and our own outbound TCP) are learned by the tc egress
	 * program, which inserts the tuple already swapped into ingress
	 * orientation so the reply hits on its first lookup.
	 *
	 * Deliberately NOT learning inbound UDP or ICMP is a security property,
	 * not an omission: an inbound flow entry would short-circuit stage 8,
	 * so a single-source UDP or ICMP flood to an open port would create one
	 * entry and then sail past the per-source rate buckets for every packet
	 * after the first. Making unsolicited UDP/ICMP re-run the full ladder
	 * every time is exactly what keeps the per-source limiter effective. */

	if ((flags & CALY_F_CONNTRACK) && ct_key_valid && ct_missed && is_syn &&
	    pkt->proto == CALY_IPPROTO_TCP &&
	    !(prule && (prule->flags & CALY_PORT_F_NO_CT))) {
		cs = &sc->cs;
		__builtin_memset(cs, 0, sizeof(*cs));
		cs->created_ns = now;
		cs->last_seen_ns = now;
		cs->pkts_in = 1;
		cs->bytes_in = pkt_len;
		cs->ifindex = pkt->ifindex;
		cs->state = CALY_CT_SYN_RECV;
		if (pkt->flags & CALY_PKT_F_MGMT)
			cs->flags |= CALY_CT_F_MGMT;
		if (pkt->flags & CALY_PKT_F_ALLOWLIST)
			cs->flags |= CALY_CT_F_ALLOWLIST;

		err = bpf_map_update_elem(&caly_conn, &sc->ck, cs, BPF_ANY);
		if (err)
			caly_stat(STAT_CT_FULL, pkt_len);
		else
			caly_stat(STAT_CT_CREATED, pkt_len);
	}

	if (reason == STAT_PASS_DEFAULT && !is_wan)
		reason = STAT_PASS_LAN_IFACE;

	/* ---- Stage 11: accounting and verdict. Single exit point: every
	 * packet is charged exactly one specific reason plus the aggregates,
	 * and no path can return without doing so. ---- */
verdict:
	{
		__u32 verdict_code;
		int action;

		/* Monitor mode rewrites the verdict but keeps the reason, so
		 * `calyanti-cli stats` shows exactly what WOULD have been
		 * dropped before the operator commits to dropping it. */
		if (act == CALY_ACT_DROP &&
		    ((flags & CALY_F_MONITOR_ONLY) ||
		     mode == FW_MODE_MONITOR_ONLY || if_monitor)) {
			caly_stat(STAT_MONITOR_WOULD_DROP, pkt_len);
			act = CALY_ACT_PASS;
			verdict_code = CALY_VERDICT_MONITOR;
			want_event = 1;
		} else if (act == CALY_ACT_DROP) {
			verdict_code = CALY_VERDICT_DROP;
			want_event = 1;
		} else if (act == CALY_ACT_TX) {
			verdict_code = CALY_VERDICT_TX;
			want_event = 1;
		} else {
			verdict_code = CALY_VERDICT_PASS;
		}

		caly_stat(STAT_PKT_TOTAL, pkt_len);
		if (reason != STAT_PKT_TOTAL)
			caly_stat(reason, pkt_len);

		if (act == CALY_ACT_DROP) {
			caly_stat(STAT_DROP_TOTAL, pkt_len);
			caly_gauge(CALY_G_DROPS, 1);
			action = XDP_DROP;
		} else if (act == CALY_ACT_TX) {
			caly_stat(STAT_TX_TOTAL, pkt_len);
			action = XDP_TX;
		} else {
			caly_stat(STAT_PASS_TOTAL, pkt_len);
			action = XDP_PASS;
		}

		caly_gauge(CALY_G_PKTS, 1);
		caly_gauge(CALY_G_BYTES, pkt_len);
		if (is_syn)
			caly_gauge(CALY_G_SYN, 1);
		/* New-flow gauge tracks new inbound TCP connections, matching
		 * the newconn bucket and the global_newconn escalation
		 * thresholds; see the rate-limit stage for why UDP/ICMP misses
		 * are excluded. */
		if (is_syn && ct_missed)
			caly_gauge(CALY_G_NEWCONN, 1);
		if (pkt->proto == CALY_IPPROTO_UDP)
			caly_gauge(CALY_G_UDP, 1);
		if (is_icmp)
			caly_gauge(CALY_G_ICMP, 1);
		if (pkt->flags & CALY_PKT_F_FRAG)
			caly_gauge(CALY_G_FRAG, 1);

		/* Top-talker accounting. Reporting only; nothing in the drop
		 * path ever reads it. */
		if ((flags & CALY_F_SRC_STATS) && pkt->family) {
			struct src_stats *ss;

			if (is_v4)
				ss = bpf_map_lookup_elem(&caly_top4, &skey4);
			else
				ss = bpf_map_lookup_elem(&caly_top6, &skey6);

			if (ss) {
				ss->packets += 1;
				ss->bytes += pkt_len;
				ss->last_seen_ns = now;
				if (verdict_code == CALY_VERDICT_DROP ||
				    verdict_code == CALY_VERDICT_MONITOR) {
					ss->drops += 1;
					ss->drop_bytes += pkt_len;
					ss->last_reason = reason;
				}
			} else {
				__builtin_memset(&tv.ts, 0, sizeof(tv.ts));
				tv.ts.packets = 1;
				tv.ts.bytes = pkt_len;
				tv.ts.first_seen_ns = now;
				tv.ts.last_seen_ns = now;
				tv.ts.last_reason = reason;
				if (verdict_code == CALY_VERDICT_DROP ||
				    verdict_code == CALY_VERDICT_MONITOR) {
					tv.ts.drops = 1;
					tv.ts.drop_bytes = pkt_len;
				}

				if (is_v4)
					err = bpf_map_update_elem(&caly_top4,
								  &skey4,
								  &tv.ts,
								  BPF_ANY);
				else
					err = bpf_map_update_elem(&caly_top6,
								  &skey6,
								  &tv.ts,
								  BPF_ANY);
				if (err)
					caly_stat(STAT_MAP_FULL_SRCSTAT, pkt_len);
			}
		}

		/* Sampled events. Never emitted for an ordinary pass: at line
		 * rate that would cost more CPU than the filtering does. */
		if (want_event && (flags & CALY_F_LOG_EVENTS) &&
		    cfg->log_sample_rate) {
			struct event *ev = &sc->ev;
			int emit = 1;

			sc->tmp[CALY_TMP_EV_COUNT] += 1;
			if (sc->tmp[CALY_TMP_EV_COUNT] < cfg->log_sample_rate) {
				caly_stat(STAT_EVENT_SAMPLED_OUT, pkt_len);
				emit = 0;
			} else {
				sc->tmp[CALY_TMP_EV_COUNT] = 0;
			}

			/* Hard events/sec ceiling, counted per CPU. */
			if (emit && cfg->log_max_pps) {
				__u64 ws = sc->tmp[CALY_TMP_EV_WIN_NS];

				if (now < ws || now - ws >= CALY_NSEC_PER_SEC) {
					sc->tmp[CALY_TMP_EV_WIN_NS] = now;
					sc->tmp[CALY_TMP_EV_IN_WIN] = 0;
				}
				if (sc->tmp[CALY_TMP_EV_IN_WIN] >=
				    cfg->log_max_pps) {
					caly_stat(STAT_EVENT_SAMPLED_OUT,
						  pkt_len);
					emit = 0;
				} else {
					sc->tmp[CALY_TMP_EV_IN_WIN] += 1;
				}
			}

			if (emit) {
				__builtin_memset(ev, 0, sizeof(*ev));
				ev->ts_ns = now;
				ev->ban_ttl_ns = ban_ttl;
				ev->value = evval;
				__builtin_memcpy(ev->saddr, pkt->saddr,
						 sizeof(ev->saddr));
				__builtin_memcpy(ev->daddr, pkt->daddr,
						 sizeof(ev->daddr));
				ev->ifindex = pkt->ifindex;
				ev->reason = reason;
				ev->verdict = verdict_code;
				ev->proto = pkt->proto;
				ev->pkt_len = pkt_len;
				ev->family = pkt->family;
				ev->sport = pkt->sport;
				ev->dport = pkt->dport;
				ev->tcp_flags = (__u16)pkt->tcp_flags;
				ev->mode = (__u8)mode;
				ev->version = (__u8)CALY_ABI_VERSION_MAJOR;

				err = bpf_perf_event_output(ctx, &caly_events,
							    BPF_F_CURRENT_CPU,
							    ev, sizeof(*ev));
				if (err) {
					caly_stat(STAT_EVENT_LOST, pkt_len);
					caly_gauge(CALY_G_EVENTS_LOST, 1);
				} else {
					caly_stat(STAT_EVENT_EMITTED, pkt_len);
					caly_gauge(CALY_G_EVENTS, 1);
				}
			}
		}

		return action;
	}
}

/*
 * GPL-only helpers (bpf_perf_event_output among them) require a GPL-compatible
 * license string. "Dual BSD/GPL" satisfies the kernel check while keeping the
 * source dual licensed.
 */
#ifndef CALY_LICENSE_DEFINED
#define CALY_LICENSE_DEFINED
char _license[] SEC("license") = "Dual BSD/GPL";
#endif
