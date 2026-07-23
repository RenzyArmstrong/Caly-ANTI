/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - XDP/eBPF DDoS mitigation suite
 * src/bpf/xdp_synproxy.bpf.c - the tail-called SYN proxy.
 *
 * REACHED VIA:  bpf_tail_call(ctx, &caly_progs, CALY_PROG_IDX_SYNPROXY)
 *
 * This program is a SEPARATE BPF object program on purpose. It calls the
 * kernel 5.15+ raw syncookie helpers:
 *
 *     bpf_tcp_raw_gen_syncookie_ipv4()   bpf_tcp_raw_gen_syncookie_ipv6()
 *     bpf_tcp_raw_check_syncookie_ipv4() bpf_tcp_raw_check_syncookie_ipv6()
 *
 * On a kernel that lacks them the loader calls
 * bpf_program__set_autoload(prog, false), the verifier never sees this
 * program, the caly_progs slot stays empty, and the caller's bpf_tail_call()
 * simply returns so the main program falls through to its rate-limit
 * fallback. That is the entire reason the SYN proxy lives behind a tail call:
 * an inline call would fail verification for the WHOLE object on every
 * pre-5.15 kernel.
 *
 * THE COOKIE IS NEVER HAND-ROLLED. The helpers use the kernel's own SYN
 * cookie secret; a cookie we invented could not be validated by the TCP stack
 * when the client's ACK arrives, so the connection would die silently and the
 * service would become permanently unreachable rather than merely undefended.
 *
 * FLOW
 *   inbound SYN  -> gen cookie -> rewrite IN PLACE into a SYN-ACK
 *                   (swap MACs, swap IPs, swap ports, seq = cookie,
 *                    ack_seq = client_seq + 1, flags = SYN|ACK, MSS option
 *                    from the helper, recompute IP + TCP checksums) -> XDP_TX
 *   inbound bare ACK -> check cookie -> valid: XDP_PASS (the stack
 *                   materialises the socket, requires tcp_syncookies=2)
 *                                    -> invalid: XDP_DROP
 *
 * The frame is never grown: no bpf_xdp_adjust_tail(), no bpf_xdp_adjust_head().
 * The SYN-ACK reuses the client's own option space, so a SYN that arrived with
 * no options simply gets a SYN-ACK with no options (client falls back to the
 * default MSS, which is correct, if suboptimal).
 *
 * SAFETY
 *   - The allowlist and the management port list are honoured BEFORE any drop.
 *   - MONITOR_ONLY never rewrites and never drops.
 *   - Every internal failure (missing config, unparsable frame, helper error)
 *     fails OPEN with XDP_PASS plus a counter.
 *   - XDP_ABORTED is never returned.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "compat.h"
#include "maps.h"
#include "checksum.h"
#include "parsing.h"

/*
 * Local, file-private helpers.
 *
 * They are deliberately prefixed sp_ and defined here rather than pulled from
 * checksum.h / parse.h so this translation unit is correct on its own and can
 * never collide with a differently spelled shared helper. A later integration
 * pass may fold them into the shared headers; the arithmetic is identical.
 */

#define SP_TCP_MIN_DOFF        5u
#define SP_TCP_MAX_HDR         60u          /* doff == 15                     */
#define SP_TCP_MAX_WORDS       30u          /* SP_TCP_MAX_HDR / 2             */
#define SP_TCP_MAX_OPT         40u          /* SP_TCP_MAX_HDR - 20            */
#define SP_TCP_OFF_DOFF        12u
#define SP_TCP_OFF_FLAGS       13u
#define SP_TCP_OFF_CHECK       16u
#define SP_SYNACK_WINDOW       65535u
#define SP_SYNACK_TTL          64u
#define SP_IP4_DF              0x4000u

/* 802.1Q / 802.1ad tag. struct vlan_hdr lives in include/linux/if_vlan.h and
 * is not guaranteed to appear in vmlinux.h (the 8021q module may not be built
 * in), so we spell it ourselves. */
struct sp_vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/* Everything the accounting and event paths need, so the deep helpers do not
 * have to re-derive it from the (possibly rewritten) packet. */
struct sp_flow {
	__u32 saddr[4];
	__u32 daddr[4];
	__u32 ifindex;
	__u32 family;
	__u32 pkt_len;
	__u32 tcp_flags;
	__u16 sport;
	__u16 dport;
};

/* ------------------------------------------------------------------------- */
/* Accounting                                                                */
/* ------------------------------------------------------------------------- */

static __always_inline void sp_stat(__u32 reason, __u32 bytes)
{
	__u64 *p;

	if (reason >= STAT_MAX)
		return;

	p = bpf_map_lookup_elem(&caly_stats, &reason);
	if (p)
		*p += 1;
	p = bpf_map_lookup_elem(&caly_stats_b, &reason);
	if (p)
		*p += bytes;
}

static __always_inline void sp_gauge(__u32 gauge, __u64 add)
{
	__u64 *p;

	if (gauge >= CALY_G_MAX)
		return;

	p = bpf_map_lookup_elem(&caly_global, &gauge);
	if (p)
		*p += add;
}

/*
 * Final accounting for the packet. The tail call never returns to the caller,
 * so this program owns the whole "step 11" accounting for the packets it
 * handles: the totals, the gauges and the specific reason.
 */
static __always_inline int sp_finish(__u32 reason, __u32 verdict, __u32 pkt_len)
{
	sp_stat(STAT_PKT_TOTAL, pkt_len);
	sp_gauge(CALY_G_PKTS, 1);
	sp_gauge(CALY_G_BYTES, pkt_len);

	if (reason != STAT_PKT_TOTAL)
		sp_stat(reason, pkt_len);

	if (verdict == CALY_VERDICT_DROP) {
		sp_stat(STAT_DROP_TOTAL, pkt_len);
		sp_gauge(CALY_G_DROPS, 1);
		return XDP_DROP;
	}
	if (verdict == CALY_VERDICT_TX) {
		sp_stat(STAT_TX_TOTAL, pkt_len);
		sp_gauge(CALY_G_SYNPROXY_TX, 1);
		return XDP_TX;
	}
	if (verdict == CALY_VERDICT_MONITOR)
		sp_stat(STAT_MONITOR_WOULD_DROP, pkt_len);

	sp_stat(STAT_PASS_TOTAL, pkt_len);
	return XDP_PASS;
}

static __always_inline void sp_event(struct xdp_md *ctx,
				     const struct fw_config *cfg,
				     const struct sp_flow *f,
				     __u32 reason, __u32 verdict, __u64 value)
{
	struct event ev;
	long rc;

	if (!(cfg->flags & CALY_F_LOG_EVENTS))
		return;
	if (cfg->log_sample_rate == 0)
		return;
	if (cfg->log_sample_rate > 1 &&
	    (bpf_get_prandom_u32() % cfg->log_sample_rate) != 0) {
		sp_stat(STAT_EVENT_SAMPLED_OUT, 0);
		return;
	}

	__builtin_memset(&ev, 0, sizeof(ev));
	ev.ts_ns     = bpf_ktime_get_ns();
	ev.value     = value;
	ev.saddr[0]  = f->saddr[0];
	ev.saddr[1]  = f->saddr[1];
	ev.saddr[2]  = f->saddr[2];
	ev.saddr[3]  = f->saddr[3];
	ev.daddr[0]  = f->daddr[0];
	ev.daddr[1]  = f->daddr[1];
	ev.daddr[2]  = f->daddr[2];
	ev.daddr[3]  = f->daddr[3];
	ev.ifindex   = f->ifindex;
	ev.reason    = reason;
	ev.verdict   = verdict;
	ev.proto     = CALY_IPPROTO_TCP;
	ev.pkt_len   = f->pkt_len;
	ev.family    = f->family;
	ev.sport     = f->sport;
	ev.dport     = f->dport;
	ev.tcp_flags = (__u16)f->tcp_flags;
	ev.mode      = (__u8)cfg->mode;
	ev.version   = (__u8)CALY_ABI_VERSION_MAJOR;

	rc = bpf_perf_event_output(ctx, &caly_events, BPF_F_CURRENT_CPU,
				   &ev, sizeof(ev));
	if (rc < 0) {
		sp_stat(STAT_EVENT_LOST, 0);
		sp_gauge(CALY_G_EVENTS_LOST, 1);
	} else {
		sp_stat(STAT_EVENT_EMITTED, 0);
		sp_gauge(CALY_G_EVENTS, 1);
	}
}

/* ------------------------------------------------------------------------- */
/* Checksums                                                                 */
/*                                                                           */
/* The Internet checksum is byte-order independent (RFC 1071 s2), so the      */
/* 16-bit words are summed exactly as they sit on the wire and the folded     */
/* result is stored back without any conversion.                             */
/* ------------------------------------------------------------------------- */

static __always_inline __u16 sp_csum_fold(__u32 sum)
{
	sum = (sum & 0xFFFFu) + (sum >> 16);
	sum = (sum & 0xFFFFu) + (sum >> 16);
	return (__u16)(~sum);
}

/* Recompute the 20-byte IPv4 header checksum in place. The caller has already
 * proven that iph + 20 <= data_end and that ihl == 5. */
static __always_inline void sp_ip4_csum(struct iphdr *iph)
{
	__u16 *w = (__u16 *)iph;
	__u32 sum = 0;
	int i;

	iph->check = 0;

	CALY_UNROLL
	for (i = 0; i < 10; i++)
		sum += w[i];

	iph->check = sp_csum_fold(sum);
}

/*
 * Recompute the TCP checksum in place over [th, th + tcp_len). psum is the
 * pseudo-header partial sum, already accumulated in wire-word space.
 *
 * The caller has proven th + tcp_len <= data_end, so the per-iteration bound
 * check below can never fire; it is there because the verifier will not take
 * our word for a variable-length walk.
 *
 * Returns 0 on success, -1 if a bound check unexpectedly failed.
 */
static __always_inline int sp_tcp_csum(void *data_end, void *th,
				       __u32 tcp_len, __u32 psum)
{
	__u16 *w = (__u16 *)th;
	__u32 sum = psum;
	int i;

	/* Zero the checksum field (offset 16) before summing. */
	*(__u16 *)((__u8 *)th + SP_TCP_OFF_CHECK) = 0;

	CALY_UNROLL
	for (i = 0; i < (int)SP_TCP_MAX_WORDS; i++) {
		if ((__u32)(i * 2) >= tcp_len)
			break;
		if ((void *)((__u8 *)th + i * 2 + 2) > data_end)
			return -1;
		sum += w[i];
	}

	*(__u16 *)((__u8 *)th + SP_TCP_OFF_CHECK) = sp_csum_fold(sum);
	return 0;
}

/* ------------------------------------------------------------------------- */
/* Policy shortcuts that must precede every drop                             */
/* ------------------------------------------------------------------------- */

static __always_inline int sp_allowlisted_v4(__be32 saddr)
{
	struct lpm_key_v4 k;

	__builtin_memset(&k, 0, sizeof(k));
	k.prefixlen = 32;
	__builtin_memcpy(k.addr, &saddr, 4);

	return bpf_map_lookup_elem(&caly_allow4, &k) != NULL;
}

static __always_inline int sp_allowlisted_v6(const void *saddr)
{
	struct lpm_key_v6 k;

	__builtin_memset(&k, 0, sizeof(k));
	k.prefixlen = 128;
	__builtin_memcpy(k.addr, saddr, 16);

	return bpf_map_lookup_elem(&caly_allow6, &k) != NULL;
}

/* Build the ingress-oriented conntrack key: saddr/sport is the REMOTE peer,
 * daddr/dport is us. The memset is mandatory - BPF hash lookups compare the
 * raw key bytes including pad[]. */
static __always_inline void sp_conn_key(struct conn_key *k,
					const struct sp_flow *f)
{
	__builtin_memset(k, 0, sizeof(*k));
	k->saddr[0] = f->saddr[0];
	k->saddr[1] = f->saddr[1];
	k->saddr[2] = f->saddr[2];
	k->saddr[3] = f->saddr[3];
	k->daddr[0] = f->daddr[0];
	k->daddr[1] = f->daddr[1];
	k->daddr[2] = f->daddr[2];
	k->daddr[3] = f->daddr[3];
	k->sport    = f->sport;
	k->dport    = f->dport;
	k->proto    = CALY_IPPROTO_TCP;
	k->family   = (__u8)f->family;
}

/* An established (or half-established) conntrack entry means the main program
 * already blessed this flow; a spliced connection must never be re-cookied. */
static __always_inline int sp_conn_known(const struct sp_flow *f)
{
	struct conn_key k;
	struct conn_state *cs;

	sp_conn_key(&k, f);
	cs = bpf_map_lookup_elem(&caly_conn, &k);
	if (!cs)
		return 0;
	if (cs->state == CALY_CT_CLOSED)
		return 0;
	return 1;
}

/* Record the spliced flow so the rest of the connection short-circuits in the
 * main program instead of coming back through here. */
static __always_inline void sp_conn_create(const struct sp_flow *f, __u64 now)
{
	struct conn_key k;
	struct conn_state cs;

	sp_conn_key(&k, f);

	__builtin_memset(&cs, 0, sizeof(cs));
	cs.created_ns   = now;
	cs.last_seen_ns = now;
	cs.pkts_in      = 1;
	cs.bytes_in     = f->pkt_len;
	cs.state        = CALY_CT_ESTABLISHED;
	cs.flags        = CALY_CT_F_SYNPROXIED | CALY_CT_F_SEEN_REPLY;
	cs.ifindex      = f->ifindex;

	if (bpf_map_update_elem(&caly_conn, &k, &cs, BPF_ANY) == 0)
		sp_stat(STAT_CT_CREATED, 0);
	else
		sp_stat(STAT_CT_FULL, 0);
}

/* ------------------------------------------------------------------------- */
/* SYN-ACK construction                                                      */
/* ------------------------------------------------------------------------- */

/*
 * Overwrite the client's TCP option area with a single MSS option followed by
 * NOPs. doff is left untouched so the frame length never changes.
 *
 * optlen is always a multiple of 4 (tcp_len is doff * 4), so the "< 4" case is
 * exactly "the client sent no options at all".
 */
static __always_inline void sp_write_mss(void *data_end, __u8 *opt,
					 __u32 optlen, __u16 mss)
{
	int i;

	if (optlen < 4)
		return;
	if ((void *)(opt + 4) > data_end)
		return;

	opt[0] = 2;                       /* kind: MSS       */
	opt[1] = 4;                       /* length          */
	opt[2] = (__u8)(mss >> 8);
	opt[3] = (__u8)(mss & 0xFFu);

	CALY_UNROLL
	for (i = 4; i < (int)SP_TCP_MAX_OPT; i++) {
		if ((__u32)i >= optlen)
			break;
		if ((void *)(opt + i + 1) > data_end)
			break;
		opt[i] = 1;               /* NOP             */
	}
}

/* Swap the Ethernet source and destination in place. */
static __always_inline void sp_swap_mac(struct ethhdr *eth)
{
	__u8 tmp[6];

	__builtin_memcpy(tmp, eth->h_dest, 6);
	__builtin_memcpy(eth->h_dest, eth->h_source, 6);
	__builtin_memcpy(eth->h_source, tmp, 6);
}

/*
 * Turn the inbound SYN into the outbound SYN-ACK. Everything below this point
 * mutates the frame, so the caller must have finished all of its validation
 * first: once we start writing there is no way back to XDP_PASS with an
 * unmodified packet.
 */
static __always_inline void sp_make_synack_tcp(void *th, __u32 tcp_len,
					       __u32 cookie, __u32 client_seq,
					       __u16 mss, void *data_end)
{
	struct tcphdr *t = th;
	__be16 sport = t->source;

	t->source  = t->dest;
	t->dest    = sport;
	t->seq     = bpf_htonl(cookie);
	t->ack_seq = bpf_htonl(client_seq + 1);
	t->window  = bpf_htons(SP_SYNACK_WINDOW);
	t->urg_ptr = 0;

	/* Byte 13 carries the flags. Written as a raw byte so the result does
	 * not depend on the bitfield layout recorded in vmlinux.h. */
	*((__u8 *)th + SP_TCP_OFF_FLAGS) = (__u8)(CALY_TCP_SYN | CALY_TCP_ACK);

	sp_write_mss(data_end, (__u8 *)th + 20, tcp_len - 20, mss);
}

/* ------------------------------------------------------------------------- */
/* IPv4                                                                      */
/* ------------------------------------------------------------------------- */

static __always_inline int sp_syn_v4(struct xdp_md *ctx,
				     const struct fw_config *cfg,
				     struct sp_flow *f,
				     void *data_end, struct ethhdr *eth,
				     struct iphdr *iph, void *th, __u32 tcp_len)
{
	struct tcphdr *t = th;
	__u16 *w;
	__u32 psum = 0;
	__u32 client_seq, cookie;
	__be32 tmp_addr;
	__u16 mss;
	__s64 value;
	int i;

	/* The helper rejects options-bearing IPv4 headers outright. */
	if (iph->ihl != 5)
		return sp_finish(STAT_SYNPROXY_SKIPPED, CALY_VERDICT_PASS,
				 f->pkt_len);

	/* A SYN that carries payload (TCP Fast Open) is not something we can
	 * splice without growing/shrinking the frame, and re-emitting the
	 * payload as ours would be wrong. Hand it back to the main policy. */
	if (bpf_ntohs(iph->tot_len) != 20u + tcp_len)
		return sp_finish(STAT_SYNPROXY_SKIPPED, CALY_VERDICT_PASS,
				 f->pkt_len);

	value = bpf_tcp_raw_gen_syncookie_ipv4(iph, th, tcp_len);
	if (value < 0) {
		sp_stat(STAT_SYNPROXY_GEN_FAIL, 0);
		sp_event(ctx, cfg, f, STAT_SYNPROXY_GEN_FAIL,
			 CALY_VERDICT_PASS, (__u64)(-value));
		return sp_finish(STAT_PKT_TOTAL, CALY_VERDICT_PASS,
				 f->pkt_len);
	}

	cookie = (__u32)value;
	mss    = (__u16)((__u64)value >> 32);
	sp_stat(STAT_SYNPROXY_GEN_OK, 0);

	client_seq = bpf_ntohl(t->seq);

	/* ---- from here on the frame is being rewritten ---- */
	sp_swap_mac(eth);

	tmp_addr    = iph->saddr;
	iph->saddr  = iph->daddr;
	iph->daddr  = tmp_addr;
	iph->ttl    = SP_SYNACK_TTL;
	iph->id     = 0;
	iph->frag_off = bpf_htons(SP_IP4_DF);
	sp_ip4_csum(iph);

	sp_make_synack_tcp(th, tcp_len, cookie, client_seq, mss, data_end);

	/* Pseudo header: swapped saddr, swapped daddr, zero, proto, tcp_len. */
	w = (__u16 *)&iph->saddr;
	CALY_UNROLL
	for (i = 0; i < 4; i++)
		psum += w[i];
	psum += bpf_htons(CALY_IPPROTO_TCP);
	psum += bpf_htons((__u16)tcp_len);

	if (sp_tcp_csum(data_end, th, tcp_len, psum) < 0) {
		/* Unreachable: tcp_len was bounds-checked above. Fail open. */
		sp_stat(STAT_SYNPROXY_TX_FAIL, 0);
		return sp_finish(STAT_PKT_TOTAL, CALY_VERDICT_PASS,
				 f->pkt_len);
	}

	sp_stat(STAT_SYNPROXY_TX, 0);
	sp_event(ctx, cfg, f, STAT_SYNPROXY_TX, CALY_VERDICT_TX, cookie);
	return sp_finish(STAT_PKT_TOTAL, CALY_VERDICT_TX, f->pkt_len);
}

static __always_inline int sp_ack_v4(struct xdp_md *ctx,
				     const struct fw_config *cfg,
				     struct sp_flow *f,
				     struct iphdr *iph, void *th, __u64 now)
{
	if (bpf_tcp_raw_check_syncookie_ipv4(iph, th) == 0) {
		sp_stat(STAT_SYNPROXY_CHECK_OK, 0);
		sp_conn_create(f, now);
		return sp_finish(STAT_PASS_SYNCOOKIE_OK, CALY_VERDICT_PASS,
				 f->pkt_len);
	}

	/*
	 * The cookie did not validate. That is either a spoofed / replayed ACK
	 * or - much more rarely - a genuine established flow whose conntrack
	 * entry was evicted from the LRU. Dropping the latter would break a
	 * live connection, so the drop is only armed when the operator has
	 * declared the box to be under attack.
	 */
	if (cfg->mode == FW_MODE_UNDER_ATTACK || cfg->mode == FW_MODE_LOCKDOWN) {
		sp_event(ctx, cfg, f, STAT_DROP_SYNCOOKIE_BAD,
			 CALY_VERDICT_DROP, 0);
		return sp_finish(STAT_DROP_SYNCOOKIE_BAD, CALY_VERDICT_DROP,
				 f->pkt_len);
	}

	sp_stat(STAT_DROP_SYNCOOKIE_BAD, 0);
	sp_event(ctx, cfg, f, STAT_DROP_SYNCOOKIE_BAD, CALY_VERDICT_MONITOR, 0);
	return sp_finish(STAT_PKT_TOTAL, CALY_VERDICT_MONITOR, f->pkt_len);
}

/* ------------------------------------------------------------------------- */
/* IPv6                                                                      */
/* ------------------------------------------------------------------------- */

static __always_inline int sp_syn_v6(struct xdp_md *ctx,
				     const struct fw_config *cfg,
				     struct sp_flow *f,
				     void *data_end, struct ethhdr *eth,
				     struct ipv6hdr *ip6h, void *th,
				     __u32 tcp_len)
{
	struct tcphdr *t = th;
	__u32 tmp[4];
	__u16 *w;
	__u32 psum = 0;
	__u32 client_seq, cookie;
	__u16 mss;
	__s64 value;
	int i;

	if (bpf_ntohs(ip6h->payload_len) != tcp_len)
		return sp_finish(STAT_SYNPROXY_SKIPPED, CALY_VERDICT_PASS,
				 f->pkt_len);

	value = bpf_tcp_raw_gen_syncookie_ipv6(ip6h, th, tcp_len);
	if (value < 0) {
		sp_stat(STAT_SYNPROXY_GEN_FAIL, 0);
		sp_event(ctx, cfg, f, STAT_SYNPROXY_GEN_FAIL,
			 CALY_VERDICT_PASS, (__u64)(-value));
		return sp_finish(STAT_PKT_TOTAL, CALY_VERDICT_PASS,
				 f->pkt_len);
	}

	cookie = (__u32)value;
	mss    = (__u16)((__u64)value >> 32);
	sp_stat(STAT_SYNPROXY_GEN_OK, 0);

	client_seq = bpf_ntohl(t->seq);

	/* ---- from here on the frame is being rewritten ---- */
	sp_swap_mac(eth);

	__builtin_memcpy(tmp, &ip6h->saddr, 16);
	__builtin_memcpy(&ip6h->saddr, &ip6h->daddr, 16);
	__builtin_memcpy(&ip6h->daddr, tmp, 16);
	ip6h->hop_limit = SP_SYNACK_TTL;

	sp_make_synack_tcp(th, tcp_len, cookie, client_seq, mss, data_end);

	/* Pseudo header: 16-byte src, 16-byte dst, 32-bit length, next hdr. */
	w = (__u16 *)&ip6h->saddr;
	CALY_UNROLL
	for (i = 0; i < 16; i++)
		psum += w[i];
	psum += bpf_htons((__u16)tcp_len);
	psum += bpf_htons(CALY_IPPROTO_TCP);

	if (sp_tcp_csum(data_end, th, tcp_len, psum) < 0) {
		sp_stat(STAT_SYNPROXY_TX_FAIL, 0);
		return sp_finish(STAT_PKT_TOTAL, CALY_VERDICT_PASS,
				 f->pkt_len);
	}

	sp_stat(STAT_SYNPROXY_TX, 0);
	sp_event(ctx, cfg, f, STAT_SYNPROXY_TX, CALY_VERDICT_TX, cookie);
	return sp_finish(STAT_PKT_TOTAL, CALY_VERDICT_TX, f->pkt_len);
}

static __always_inline int sp_ack_v6(struct xdp_md *ctx,
				     const struct fw_config *cfg,
				     struct sp_flow *f,
				     struct ipv6hdr *ip6h, void *th, __u64 now)
{
	if (bpf_tcp_raw_check_syncookie_ipv6(ip6h, th) == 0) {
		sp_stat(STAT_SYNPROXY_CHECK_OK, 0);
		sp_conn_create(f, now);
		return sp_finish(STAT_PASS_SYNCOOKIE_OK, CALY_VERDICT_PASS,
				 f->pkt_len);
	}

	if (cfg->mode == FW_MODE_UNDER_ATTACK || cfg->mode == FW_MODE_LOCKDOWN) {
		sp_event(ctx, cfg, f, STAT_DROP_SYNCOOKIE_BAD,
			 CALY_VERDICT_DROP, 0);
		return sp_finish(STAT_DROP_SYNCOOKIE_BAD, CALY_VERDICT_DROP,
				 f->pkt_len);
	}

	sp_stat(STAT_DROP_SYNCOOKIE_BAD, 0);
	sp_event(ctx, cfg, f, STAT_DROP_SYNCOOKIE_BAD, CALY_VERDICT_MONITOR, 0);
	return sp_finish(STAT_PKT_TOTAL, CALY_VERDICT_MONITOR, f->pkt_len);
}

/* ------------------------------------------------------------------------- */
/* Entry point                                                               */
/* ------------------------------------------------------------------------- */

SEC("xdp")
int caly_xdp_synproxy(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct fw_config *cfg;
	struct iphdr *iph = NULL;
	struct ipv6hdr *ip6h = NULL;
	struct tcphdr *th;
	struct port_rule *pr;
	struct sp_flow f;
	__u32 cfg_key = 0;
	__u32 nh_off = sizeof(struct ethhdr);
	__u32 l4_off, tcp_len, port_key;
	__u16 h_proto;
	__u8 tcp_flags, doff_byte;
	__u64 now;
	int i, is_syn, is_ack, monitor;

	__builtin_memset(&f, 0, sizeof(f));
	f.pkt_len = (__u32)((long)data_end - (long)data);
	f.ifindex = ctx->ingress_ifindex;

	cfg = bpf_map_lookup_elem(&caly_config, &cfg_key);
	if (!cfg)
		return sp_finish(STAT_CONFIG_MISSING, CALY_VERDICT_PASS,
				 f.pkt_len);

	/* ---- Ethernet + up to two VLAN tags ---- */
	if ((void *)(eth + 1) > data_end)
		return sp_finish(STAT_DROP_ETH_TRUNC, CALY_VERDICT_PASS,
				 f.pkt_len);
	h_proto = eth->h_proto;

	CALY_UNROLL
	for (i = 0; i < (int)CALY_VLAN_MAX_DEPTH; i++) {
		struct sp_vlan_hdr *vh;

		if (h_proto != bpf_htons(CALY_ETH_P_8021Q) &&
		    h_proto != bpf_htons(CALY_ETH_P_8021AD) &&
		    h_proto != bpf_htons(CALY_ETH_P_QINQ1))
			break;

		vh = data + nh_off;
		if ((void *)(vh + 1) > data_end)
			return sp_finish(STAT_DROP_VLAN_TRUNC,
					 CALY_VERDICT_PASS, f.pkt_len);
		h_proto = vh->h_vlan_encapsulated_proto;
		nh_off += sizeof(*vh);
	}

	/* ---- L3 ---- */
	if (h_proto == bpf_htons(CALY_ETH_P_IP)) {
		iph = data + nh_off;
		if ((void *)(iph + 1) > data_end)
			return sp_finish(STAT_DROP_IP4_TRUNC,
					 CALY_VERDICT_PASS, f.pkt_len);
		if (iph->protocol != CALY_IPPROTO_TCP)
			return sp_finish(STAT_SYNPROXY_SKIPPED,
					 CALY_VERDICT_PASS, f.pkt_len);
		if (iph->ihl < 5)
			return sp_finish(STAT_DROP_IP4_IHL, CALY_VERDICT_PASS,
					 f.pkt_len);
		/* Fragments never carry a complete, cookie-able handshake. */
		if (iph->frag_off & bpf_htons(0x3FFF))
			return sp_finish(STAT_SYNPROXY_SKIPPED,
					 CALY_VERDICT_PASS, f.pkt_len);

		l4_off      = nh_off + (__u32)iph->ihl * 4;
		f.family    = CALY_AF_INET;
		f.saddr[0]  = iph->saddr;
		f.daddr[0]  = iph->daddr;
	} else if (h_proto == bpf_htons(CALY_ETH_P_IPV6)) {
		ip6h = data + nh_off;
		if ((void *)(ip6h + 1) > data_end)
			return sp_finish(STAT_DROP_IP6_TRUNC,
					 CALY_VERDICT_PASS, f.pkt_len);
		/* The raw helpers take the fixed IPv6 header and assume TCP
		 * follows it directly. A SYN behind extension headers is
		 * exotic; hand it back to the main policy rather than guess. */
		if (ip6h->nexthdr != CALY_IPPROTO_TCP)
			return sp_finish(STAT_SYNPROXY_SKIPPED,
					 CALY_VERDICT_PASS, f.pkt_len);

		l4_off      = nh_off + sizeof(struct ipv6hdr);
		f.family    = CALY_AF_INET6;
		__builtin_memcpy(&f.saddr[0], &ip6h->saddr, 16);
		__builtin_memcpy(&f.daddr[0], &ip6h->daddr, 16);
	} else {
		return sp_finish(STAT_SYNPROXY_SKIPPED, CALY_VERDICT_PASS,
				 f.pkt_len);
	}

	/* ---- TCP ---- */
	th = data + l4_off;
	if ((void *)(th + 1) > data_end)
		return sp_finish(STAT_DROP_L4_TRUNC, CALY_VERDICT_PASS,
				 f.pkt_len);

	f.sport = th->source;
	f.dport = th->dest;

	if (f.sport == 0 || f.dport == 0)
		return sp_finish(STAT_DROP_L4_PORT_ZERO, CALY_VERDICT_PASS,
				 f.pkt_len);

	doff_byte = *((__u8 *)th + SP_TCP_OFF_DOFF);
	tcp_len   = (__u32)(doff_byte >> 4) * 4u;
	tcp_flags = *((__u8 *)th + SP_TCP_OFF_FLAGS);
	f.tcp_flags = tcp_flags;

	if (tcp_len < 20u || tcp_len > SP_TCP_MAX_HDR)
		return sp_finish(STAT_DROP_TCP_DOFF, CALY_VERDICT_PASS,
				 f.pkt_len);
	if ((void *)((__u8 *)th + tcp_len) > data_end)
		return sp_finish(STAT_DROP_L4_TRUNC, CALY_VERDICT_PASS,
				 f.pkt_len);

	is_syn = (tcp_flags & CALY_TCP_SYN) &&
		 !(tcp_flags & (CALY_TCP_ACK | CALY_TCP_RST | CALY_TCP_FIN));
	is_ack = (tcp_flags & CALY_TCP_ACK) &&
		 !(tcp_flags & (CALY_TCP_SYN | CALY_TCP_RST | CALY_TCP_FIN));

	if (!is_syn && !is_ack)
		return sp_finish(STAT_SYNPROXY_SKIPPED, CALY_VERDICT_PASS,
				 f.pkt_len);

	/*
	 * MONITOR_ONLY must not alter a single byte on the wire and must not
	 * drop. Everything below either rewrites or drops, so stop here.
	 */
	monitor = (cfg->flags & CALY_F_MONITOR_ONLY) ||
		  cfg->mode == FW_MODE_MONITOR_ONLY;
	if (monitor)
		return sp_finish(STAT_SYNPROXY_SKIPPED, CALY_VERDICT_PASS,
				 f.pkt_len);

	/* ---- the escape hatches, ahead of every drop and every rewrite ---- */
	if (caly_is_mgmt_tcp(cfg, bpf_ntohs(f.dport)))
		return sp_finish(STAT_PASS_MGMT_PORT, CALY_VERDICT_PASS,
				 f.pkt_len);

	if (cfg->flags & CALY_F_ALLOWLIST) {
		int hit = 0;

		if (f.family == CALY_AF_INET && iph)
			hit = sp_allowlisted_v4(iph->saddr);
		else if (ip6h)
			hit = sp_allowlisted_v6(&ip6h->saddr);
		if (hit)
			return sp_finish(STAT_PASS_ALLOWLIST,
					 CALY_VERDICT_PASS, f.pkt_len);
	}

	/* A port the operator has explicitly closed gets no cookies: the main
	 * program's port policy owns that verdict. */
	port_key = bpf_ntohs(f.dport);
	pr = bpf_map_lookup_elem(&caly_port_tcp, &port_key);
	if (pr && pr->mode == CALY_PORT_CLOSED &&
	    !(pr->flags & CALY_PORT_F_SYNPROXY))
		return sp_finish(STAT_SYNPROXY_SKIPPED, CALY_VERDICT_PASS,
				 f.pkt_len);

	/* Already-known flows never get re-cookied. */
	if ((cfg->flags & CALY_F_CONNTRACK) && sp_conn_known(&f))
		return sp_finish(STAT_PASS_CONNTRACK, CALY_VERDICT_PASS,
				 f.pkt_len);

	now = bpf_ktime_get_ns();

	if (is_syn) {
		if (f.family == CALY_AF_INET) {
			if (!iph)
				return sp_finish(STAT_SYNPROXY_SKIPPED,
						 CALY_VERDICT_PASS, f.pkt_len);
			return sp_syn_v4(ctx, cfg, &f, data_end, eth, iph, th,
					 tcp_len);
		}
		if (!ip6h)
			return sp_finish(STAT_SYNPROXY_SKIPPED,
					 CALY_VERDICT_PASS, f.pkt_len);
		return sp_syn_v6(ctx, cfg, &f, data_end, eth, ip6h, th,
				 tcp_len);
	}

	if (f.family == CALY_AF_INET) {
		if (!iph)
			return sp_finish(STAT_SYNPROXY_SKIPPED,
					 CALY_VERDICT_PASS, f.pkt_len);
		return sp_ack_v4(ctx, cfg, &f, iph, th, now);
	}
	if (!ip6h)
		return sp_finish(STAT_SYNPROXY_SKIPPED, CALY_VERDICT_PASS,
				 f.pkt_len);
	return sp_ack_v6(ctx, cfg, &f, ip6h, th, now);
}

char _license[] SEC("license") = "Dual BSD/GPL";
