/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - XDP/eBPF DDoS mitigation suite
 * src/bpf/tc_ingress.bpf.c - clsact ingress dataplane.
 *
 * This is the rung-3 fallback for NICs that cannot run XDP (OpenVZ/LXC, some
 * virtio setups without multiqueue, drivers with no XDP support). It runs the
 * SAME policy engine as the XDP main program, reads the SAME pinned maps, and
 * agrees with it bit-for-bit because both sides share the pure-arithmetic
 * helpers in common.h.
 *
 * Differences from XDP that this file has to cope with:
 *   - The verdict is TC_ACT_SHOT (drop) / TC_ACT_OK (pass), never XDP_*.
 *   - skb metadata (skb->ifindex, skb->len) is available.
 *   - data / data_end still need explicit bounds checks before every read.
 *   - The skb may be non-linear, so bpf_skb_pull_data() is called up front to
 *     make the header region readable before any deep parse.
 *   - There is no XDP_TX, so the SYN proxy is NOT reachable from here; the SYN
 *     defence degrades to the per-source SYN token bucket (CALY_TB_SYN) plus
 *     the kernel's own tcp_syncookies=1 backstop, exactly as documented for
 *     the pre-5.15 fallback.
 *
 * SAFETY INVARIANTS honoured (identical to the XDP path):
 *   - Allowlist and management-port checks precede EVERY drop rule.
 *   - TCP/22 (and every other configured mgmt port) is never dropped.
 *   - ICMP types that keep the host reachable (v4 type 3; v6 2/133/134/135/136)
 *     are never dropped here regardless of the policy map.
 *   - Every internal failure fails OPEN (TC_ACT_OK) plus a counter.
 *   - MONITOR_ONLY / per-iface monitor rewrites every drop to a pass.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "compat.h"
#include "maps.h"
#include "checksum.h"
#include "parsing.h"

/* How many bytes of header we insist are linear before parsing. Covers
 * Ethernet(14) + 2 VLAN tags(8) + IPv6(40) + 8 ext-header words + TCP(60). */
#define TCI_PULL_LEN    128u

#define TCI_TCP_OFF_DOFF   12u
#define TCI_TCP_OFF_FLAGS  13u

struct tci_vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/* Generic IPv6 extension / TLV header (uniquely named so it never collides
 * with vmlinux.h's struct ipv6_opt_hdr, whose presence in BTF is not
 * guaranteed on every target). */
struct tci_ext_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
};

/* Parsed-packet descriptor kept on the stack (small on purpose). */
struct tci_pkt {
	__u32 saddr[4];      /* network order                                 */
	__u32 daddr[4];      /* network order                                 */
	__u32 family;        /* CALY_AF_INET / CALY_AF_INET6                  */
	__u32 proto;         /* final L4 protocol                             */
	__u32 l3_off;
	__u32 l4_off;
	__u32 pkt_len;
	__u32 ifindex;
	__u32 pkt_flags;     /* CALY_PKT_F_*                                  */
	__u32 icmp_type;
	__u16 sport;         /* network order                                 */
	__u16 dport;         /* network order                                 */
	__u16 tcp_flags;
	__u16 frag_units;    /* IPv4 fragment offset in 8-byte units          */
	__u8  ttl;
	__u8  is_wan;
	__u8  is_syn;        /* SYN and not ACK/RST/FIN                        */
	__u8  drop_private;
};

/* ------------------------------------------------------------------------- */
/* Accounting                                                                */
/* ------------------------------------------------------------------------- */

static __always_inline void tci_stat(__u32 reason, __u32 bytes)
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

static __always_inline void tci_gauge(__u32 gauge, __u64 add)
{
	__u64 *p;

	if (gauge >= CALY_G_MAX)
		return;
	p = bpf_map_lookup_elem(&caly_global, &gauge);
	if (p)
		*p += add;
}

static __always_inline void tci_srcstats(const struct tci_pkt *p,
					 const struct fw_config *cfg,
					 __u32 reason, int dropped, __u64 now)
{
	struct src_stats *ss, init;

	if (!(cfg->flags & CALY_F_SRC_STATS))
		return;
	if (p->family != CALY_AF_INET && p->family != CALY_AF_INET6)
		return;   /* no parsed source to attribute stats to */

	if (p->family == CALY_AF_INET) {
		__u32 key = p->saddr[0];

		ss = bpf_map_lookup_elem(&caly_top4, &key);
		if (!ss) {
			__builtin_memset(&init, 0, sizeof(init));
			init.first_seen_ns = now;
			bpf_map_update_elem(&caly_top4, &key, &init, BPF_ANY);
			ss = bpf_map_lookup_elem(&caly_top4, &key);
		}
	} else {
		struct in6_key key;

		__builtin_memset(&key, 0, sizeof(key));
		key.a[0] = p->saddr[0];
		key.a[1] = p->saddr[1];
		key.a[2] = p->saddr[2];
		key.a[3] = p->saddr[3];
		ss = bpf_map_lookup_elem(&caly_top6, &key);
		if (!ss) {
			__builtin_memset(&init, 0, sizeof(init));
			init.first_seen_ns = now;
			bpf_map_update_elem(&caly_top6, &key, &init, BPF_ANY);
			ss = bpf_map_lookup_elem(&caly_top6, &key);
		}
	}

	if (!ss) {
		tci_stat(STAT_MAP_FULL_SRCSTAT, 0);
		return;
	}
	ss->packets++;
	ss->bytes += p->pkt_len;
	ss->last_seen_ns = now;
	ss->last_reason = reason;
	if (dropped) {
		ss->drops++;
		ss->drop_bytes += p->pkt_len;
	}
}

static __always_inline void tci_event(struct __sk_buff *skb,
				      struct caly_scratch *scr,
				      const struct fw_config *cfg,
				      const struct tci_pkt *p,
				      __u32 reason, __u32 verdict,
				      __u64 ban_ttl, __u64 value, __u64 now)
{
	struct event *ev = &scr->ev;
	long rc;

	if (!(cfg->flags & CALY_F_LOG_EVENTS))
		return;
	if (cfg->log_sample_rate == 0)
		return;
	if (cfg->log_sample_rate > 1 &&
	    (bpf_get_prandom_u32() % cfg->log_sample_rate) != 0) {
		tci_stat(STAT_EVENT_SAMPLED_OUT, 0);
		return;
	}

	__builtin_memset(ev, 0, sizeof(*ev));
	ev->ts_ns      = now;
	ev->ban_ttl_ns = ban_ttl;
	ev->value      = value;
	ev->saddr[0]   = p->saddr[0];
	ev->saddr[1]   = p->saddr[1];
	ev->saddr[2]   = p->saddr[2];
	ev->saddr[3]   = p->saddr[3];
	ev->daddr[0]   = p->daddr[0];
	ev->daddr[1]   = p->daddr[1];
	ev->daddr[2]   = p->daddr[2];
	ev->daddr[3]   = p->daddr[3];
	ev->ifindex    = p->ifindex;
	ev->reason     = reason;
	ev->verdict    = verdict;
	ev->proto      = p->proto;
	ev->pkt_len    = p->pkt_len;
	ev->family     = p->family;
	ev->sport      = p->sport;
	ev->dport      = p->dport;
	ev->tcp_flags  = p->tcp_flags;
	ev->mode       = (__u8)cfg->mode;
	ev->version    = (__u8)CALY_ABI_VERSION_MAJOR;

	rc = bpf_perf_event_output(skb, &caly_events, BPF_F_CURRENT_CPU,
				   ev, sizeof(*ev));
	if (rc < 0) {
		tci_stat(STAT_EVENT_LOST, 0);
		tci_gauge(CALY_G_EVENTS_LOST, 1);
	} else {
		tci_stat(STAT_EVENT_EMITTED, 0);
		tci_gauge(CALY_G_EVENTS, 1);
	}
}

/*
 * Single exit point. Applies the monitor-mode rewrite, charges the aggregate
 * and specific counters, updates the global gauges and top-talker stats, and
 * returns the TC verdict.
 */
static __always_inline int tci_finish(struct __sk_buff *skb,
				      struct caly_scratch *scr,
				      const struct fw_config *cfg,
				      const struct tci_pkt *p,
				      __u32 reason, __u32 verdict, int monitor,
				      __u64 now)
{
	int dropped;

	/* A would-be drop becomes a pass under monitor. */
	if (verdict == CALY_VERDICT_DROP && monitor) {
		tci_stat(STAT_MONITOR_WOULD_DROP, p->pkt_len);
		verdict = CALY_VERDICT_MONITOR;
	}

	tci_stat(STAT_PKT_TOTAL, p->pkt_len);
	tci_gauge(CALY_G_PKTS, 1);
	tci_gauge(CALY_G_BYTES, p->pkt_len);
	if (p->proto == CALY_IPPROTO_UDP)
		tci_gauge(CALY_G_UDP, 1);
	else if (p->proto == CALY_IPPROTO_ICMP ||
		 p->proto == CALY_IPPROTO_ICMPV6)
		tci_gauge(CALY_G_ICMP, 1);
	if (p->pkt_flags & CALY_PKT_F_FRAG)
		tci_gauge(CALY_G_FRAG, 1);

	if (reason != STAT_PKT_TOTAL)
		tci_stat(reason, p->pkt_len);

	dropped = (verdict == CALY_VERDICT_DROP);

	if (dropped) {
		tci_stat(STAT_DROP_TOTAL, p->pkt_len);
		tci_gauge(CALY_G_DROPS, 1);
	} else {
		tci_stat(STAT_PASS_TOTAL, p->pkt_len);
	}

	tci_srcstats(p, cfg, reason, dropped, now);

	return dropped ? TC_ACT_SHOT : TC_ACT_OK;
}

/* ------------------------------------------------------------------------- */
/* Reputation: blocklist, local-prefix (anti-spoof), dynamic ban             */
/* ------------------------------------------------------------------------- */

static __always_inline int tci_blocklisted(const struct tci_pkt *p)
{
	if (p->family == CALY_AF_INET) {
		struct lpm_key_v4 k;

		__builtin_memset(&k, 0, sizeof(k));
		k.prefixlen = 32;
		__builtin_memcpy(k.addr, &p->saddr[0], 4);
		return bpf_map_lookup_elem(&caly_block4, &k) != NULL;
	} else {
		struct lpm_key_v6 k;

		__builtin_memset(&k, 0, sizeof(k));
		k.prefixlen = 128;
		__builtin_memcpy(k.addr, &p->saddr[0], 16);
		return bpf_map_lookup_elem(&caly_block6, &k) != NULL;
	}
}

/* Source claims to be one of our own prefixes: spoofing us. */
static __always_inline int tci_src_is_local(const struct tci_pkt *p)
{
	if (p->family == CALY_AF_INET) {
		struct lpm_key_v4 k;

		__builtin_memset(&k, 0, sizeof(k));
		k.prefixlen = 32;
		__builtin_memcpy(k.addr, &p->saddr[0], 4);
		return bpf_map_lookup_elem(&caly_local4, &k) != NULL;
	} else {
		struct lpm_key_v6 k;

		__builtin_memset(&k, 0, sizeof(k));
		k.prefixlen = 128;
		__builtin_memcpy(k.addr, &p->saddr[0], 16);
		return bpf_map_lookup_elem(&caly_local6, &k) != NULL;
	}
}

static __always_inline int tci_allowlisted(const struct tci_pkt *p,
					   __u32 *rule_flags)
{
	struct rule_meta *rm;

	*rule_flags = 0;
	if (p->family == CALY_AF_INET) {
		struct lpm_key_v4 k;

		__builtin_memset(&k, 0, sizeof(k));
		k.prefixlen = 32;
		__builtin_memcpy(k.addr, &p->saddr[0], 4);
		rm = bpf_map_lookup_elem(&caly_allow4, &k);
	} else {
		struct lpm_key_v6 k;

		__builtin_memset(&k, 0, sizeof(k));
		k.prefixlen = 128;
		__builtin_memcpy(k.addr, &p->saddr[0], 16);
		rm = bpf_map_lookup_elem(&caly_allow6, &k);
	}
	if (!rm)
		return 0;
	*rule_flags = rm->flags;
	return 1;
}

/* Returns 1 (and updates hit counters) when the source is under an active
 * ban, 0 when there is no ban or it has expired. */
static __always_inline int tci_ban_active(const struct tci_pkt *p, __u64 now)
{
	struct ban_entry *b;

	if (p->family == CALY_AF_INET) {
		__u32 key = p->saddr[0];

		b = bpf_map_lookup_elem(&caly_ban4, &key);
	} else {
		struct in6_key key;

		__builtin_memset(&key, 0, sizeof(key));
		key.a[0] = p->saddr[0];
		key.a[1] = p->saddr[1];
		key.a[2] = p->saddr[2];
		key.a[3] = p->saddr[3];
		b = bpf_map_lookup_elem(&caly_ban6, &key);
	}
	if (!b)
		return 0;

	if (!(b->flags & CALY_BAN_F_PERMANENT) && b->expiry_ns <= now)
		return 0;   /* expired; userspace GC reclaims it */

	b->last_hit_ns = now;
	b->hit_pkts++;
	b->hit_bytes += p->pkt_len;
	return 1;
}

/*
 * Install or refresh a ban for the source. base_ttl seeds a brand-new ban;
 * an existing one is escalated through caly_ban_next_ttl(). All timestamps
 * come from the caller so userspace can reproduce the decision.
 */
static __always_inline __u64 tci_ban_apply(struct caly_scratch *scr,
					   const struct fw_config *cfg,
					   const struct tci_pkt *p,
					   __u32 reason, __u64 base_ttl,
					   __u32 strikes, __u64 now)
{
	struct ban_entry *b = &scr->ban;
	__u64 ttl;
	void *existing;
	__u32 key4 = p->saddr[0];
	struct in6_key key6;

	__builtin_memset(&key6, 0, sizeof(key6));
	key6.a[0] = p->saddr[0];
	key6.a[1] = p->saddr[1];
	key6.a[2] = p->saddr[2];
	key6.a[3] = p->saddr[3];

	if (p->family == CALY_AF_INET)
		existing = bpf_map_lookup_elem(&caly_ban4, &key4);
	else
		existing = bpf_map_lookup_elem(&caly_ban6, &key6);

	if (existing) {
		struct ban_entry *e = existing;

		ttl = caly_ban_next_ttl(e->cur_ttl_ns, cfg->ban_ttl_base_ns,
					cfg->ban_ttl_max_ns,
					cfg->ban_escalate_num,
					cfg->ban_escalate_den);
		e->expiry_ns  = now + ttl;
		e->cur_ttl_ns = ttl;
		e->last_hit_ns = now;
		e->reason     = reason;
		e->strikes    = strikes;
		e->offences++;
		e->flags |= CALY_BAN_F_AUTO | CALY_BAN_F_ESCALATED;
		tci_stat(STAT_BAN_ESCALATED, 0);
		return ttl;
	}

	if (base_ttl == 0)
		base_ttl = cfg->ban_ttl_base_ns;
	ttl = base_ttl;

	__builtin_memset(b, 0, sizeof(*b));
	b->expiry_ns     = now + ttl;
	b->first_seen_ns = now;
	b->last_hit_ns   = now;
	b->cur_ttl_ns    = ttl;
	b->reason        = reason;
	b->strikes       = strikes;
	b->offences      = 1;
	b->flags         = CALY_BAN_F_AUTO;

	if (p->family == CALY_AF_INET) {
		if (bpf_map_update_elem(&caly_ban4, &key4, b, BPF_ANY) == 0)
			tci_stat(STAT_BAN_ADDED, 0);
		else
			tci_stat(STAT_BAN_FULL, 0);
	} else {
		if (bpf_map_update_elem(&caly_ban6, &key6, b, BPF_ANY) == 0)
			tci_stat(STAT_BAN_ADDED, 0);
		else
			tci_stat(STAT_BAN_FULL, 0);
	}
	return ttl;
}

/* ------------------------------------------------------------------------- */
/* Conntrack-lite                                                            */
/* ------------------------------------------------------------------------- */

static __always_inline void tci_conn_key(struct conn_key *k,
					 const struct tci_pkt *p)
{
	__builtin_memset(k, 0, sizeof(*k));
	k->saddr[0] = p->saddr[0];
	k->saddr[1] = p->saddr[1];
	k->saddr[2] = p->saddr[2];
	k->saddr[3] = p->saddr[3];
	k->daddr[0] = p->daddr[0];
	k->daddr[1] = p->daddr[1];
	k->daddr[2] = p->daddr[2];
	k->daddr[3] = p->daddr[3];
	k->sport    = p->sport;
	k->dport    = p->dport;
	k->proto    = (__u8)p->proto;
	k->family   = (__u8)p->family;
}

/* Result of a conntrack lookup in tci_conn_hit(). */
#define TCI_CT_MISS        0  /* no live entry: treat as a brand-new flow      */
#define TCI_CT_UNCONFIRMED 1  /* entry exists but is not reply/egress confirmed */
#define TCI_CT_CONFIRMED   2  /* solicited / bidirectional: safe to fast-path   */

/*
 * Look up the flow for this packet, update its state, and classify it.
 *
 * A flow is only allowed to SKIP the per-source token buckets (TCI_CT_CONFIRMED)
 * once it is provably solicited: either the tc egress hook has seen our side
 * transmit (CALY_CT_F_OUTBOUND) or traffic has been observed in both directions
 * (CALY_CT_F_SEEN_REPLY). Unsolicited inbound traffic that merely created its
 * own entry - a single UDP/ICMP packet, or a half-open inbound SYN - stays
 * TCI_CT_UNCONFIRMED so it keeps flowing through the rate limiters; otherwise a
 * lone source could self-establish a fast path and then flood unthrottled.
 * Also promotes SYN_RECV -> ESTABLISHED on the matching inbound ACK.
 */
static __always_inline int tci_conn_hit(struct caly_scratch *scr,
					const struct tci_pkt *p, __u64 now)
{
	struct conn_key *k = &scr->ck;
	struct conn_state *cs;

	tci_conn_key(k, p);
	cs = bpf_map_lookup_elem(&caly_conn, k);
	if (!cs) {
		tci_stat(STAT_CT_MISS, 0);
		return TCI_CT_MISS;
	}

	cs->last_seen_ns = now;
	cs->pkts_in++;
	cs->bytes_in += p->pkt_len;

	if (cs->state == CALY_CT_CLOSED) {
		tci_stat(STAT_CT_MISS, 0);
		return TCI_CT_MISS;
	}

	/* Complete the handshake we learned on an inbound SYN. */
	if (cs->state == CALY_CT_SYN_RECV && p->proto == CALY_IPPROTO_TCP &&
	    (p->tcp_flags & CALY_TCP_ACK) && !(p->tcp_flags & CALY_TCP_SYN)) {
		cs->state = CALY_CT_ESTABLISHED;
		cs->flags |= CALY_CT_F_SEEN_REPLY;
		tci_stat(STAT_CT_UPDATED, 0);
	}

	if (p->proto == CALY_IPPROTO_TCP && (p->tcp_flags & CALY_TCP_RST)) {
		cs->state = CALY_CT_CLOSED;
		tci_stat(STAT_CT_CLOSED, 0);
	} else if (p->proto == CALY_IPPROTO_TCP &&
		   (p->tcp_flags & CALY_TCP_FIN)) {
		cs->state = CALY_CT_FIN_WAIT;
	}

	tci_stat(STAT_CT_HIT, 0);

	if (cs->flags & (CALY_CT_F_SEEN_REPLY | CALY_CT_F_OUTBOUND))
		return TCI_CT_CONFIRMED;
	return TCI_CT_UNCONFIRMED;
}

/* Create ingress-oriented state for a permitted new inbound flow. */
static __always_inline void tci_conn_create(struct caly_scratch *scr,
					    const struct tci_pkt *p,
					    __u32 rule_flags, __u64 now)
{
	struct conn_key *k = &scr->ck;
	struct conn_state *cs = &scr->cs;

	tci_conn_key(k, p);

	__builtin_memset(cs, 0, sizeof(*cs));
	cs->created_ns   = now;
	cs->last_seen_ns = now;
	cs->pkts_in      = 1;
	cs->bytes_in     = p->pkt_len;
	cs->ifindex      = p->ifindex;

	if (p->proto == CALY_IPPROTO_TCP) {
		if (p->is_syn)
			cs->state = CALY_CT_SYN_RECV;
		else
			cs->state = CALY_CT_NEW;
	} else {
		/*
		 * Unsolicited inbound UDP/ICMP has no handshake and no proof the
		 * source is genuine, so it is NOT established: leave it NEW.
		 * tci_conn_hit() only fast-paths a flow once the tc egress hook
		 * has confirmed our side replied (CALY_CT_F_OUTBOUND) or traffic
		 * has been seen both ways (CALY_CT_F_SEEN_REPLY). Until then the
		 * per-source token buckets keep throttling it, so a single UDP
		 * or ICMP packet can no longer buy a rate-limit-free fast path.
		 */
		cs->state = CALY_CT_NEW;
	}
	if (rule_flags)
		cs->flags |= CALY_CT_F_ALLOWLIST;

	if (bpf_map_update_elem(&caly_conn, k, cs, BPF_ANY) == 0)
		tci_stat(STAT_CT_CREATED, 0);
	else
		tci_stat(STAT_CT_FULL, 0);
}

/* ------------------------------------------------------------------------- */
/* Per-source token buckets                                                  */
/* ------------------------------------------------------------------------- */

/* Fetch or create the per-source rate_state. NULL only on true map failure. */
static __always_inline struct rate_state *tci_rate_state(const struct tci_pkt *p)
{
	struct rate_state *rs;
	struct rate_state init;
	__u32 key4 = p->saddr[0];
	struct in6_key key6;

	if (p->family == CALY_AF_INET)
		rs = bpf_map_lookup_elem(&caly_rate4, &key4);
	else {
		__builtin_memset(&key6, 0, sizeof(key6));
		key6.a[0] = p->saddr[0];
		key6.a[1] = p->saddr[1];
		key6.a[2] = p->saddr[2];
		key6.a[3] = p->saddr[3];
		rs = bpf_map_lookup_elem(&caly_rate6, &key6);
	}
	if (rs)
		return rs;

	/* A fully-zeroed rate_state is a valid fresh state: caly_tb_consume()
	 * seeds each bucket to a full burst on its first call (last_refill_ns
	 * == 0), and tci_strike() treats window_start_ns == 0 as "open a new
	 * window". No per-field seeding is needed. */
	__builtin_memset(&init, 0, sizeof(init));
	init.flags = CALY_RS_F_SEEDED;

	if (p->family == CALY_AF_INET) {
		bpf_map_update_elem(&caly_rate4, &key4, &init, BPF_ANY);
		rs = bpf_map_lookup_elem(&caly_rate4, &key4);
	} else {
		bpf_map_update_elem(&caly_rate6, &key6, &init, BPF_ANY);
		rs = bpf_map_lookup_elem(&caly_rate6, &key6);
	}
	return rs;
}

/*
 * Run every applicable per-source bucket. Returns the stat_reason to charge
 * when a bucket is exhausted (the packet is dropped), or STAT_PKT_TOTAL (0)
 * when the source is conforming. ct_miss says whether this is a new flow, so
 * the NEWCONN bucket is only charged on genuine connection attempts.
 */
static __always_inline __u32 tci_rate_check(struct rate_state *rs,
					    const struct fw_config *cfg,
					    const struct tci_pkt *p,
					    int ct_miss, __u64 now)
{
	__u32 reason = STAT_PKT_TOTAL;

	rs->last_seen_ns = now;

	if (!caly_tb_consume(&rs->tb[CALY_TB_PPS], now,
			     cfg->tb_rate[CALY_TB_PPS],
			     cfg->tb_burst[CALY_TB_PPS], 1))
		reason = STAT_DROP_RATE_PPS;

	if (reason == STAT_PKT_TOTAL &&
	    !caly_tb_consume(&rs->tb[CALY_TB_BPS], now,
			     cfg->tb_rate[CALY_TB_BPS],
			     cfg->tb_burst[CALY_TB_BPS], p->pkt_len))
		reason = STAT_DROP_RATE_BPS;

	if (reason == STAT_PKT_TOTAL && p->is_syn &&
	    !caly_tb_consume(&rs->tb[CALY_TB_SYN], now,
			     cfg->tb_rate[CALY_TB_SYN],
			     cfg->tb_burst[CALY_TB_SYN], 1))
		reason = STAT_DROP_RATE_SYN;

	if (reason == STAT_PKT_TOTAL && p->proto == CALY_IPPROTO_UDP &&
	    !caly_tb_consume(&rs->tb[CALY_TB_UDP], now,
			     cfg->tb_rate[CALY_TB_UDP],
			     cfg->tb_burst[CALY_TB_UDP], 1))
		reason = STAT_DROP_RATE_UDP;

	if (reason == STAT_PKT_TOTAL &&
	    (p->proto == CALY_IPPROTO_ICMP || p->proto == CALY_IPPROTO_ICMPV6) &&
	    !caly_tb_consume(&rs->tb[CALY_TB_ICMP], now,
			     cfg->tb_rate[CALY_TB_ICMP],
			     cfg->tb_burst[CALY_TB_ICMP], 1))
		reason = STAT_DROP_RATE_ICMP;

	if (reason == STAT_PKT_TOTAL && ct_miss &&
	    (p->is_syn || p->proto == CALY_IPPROTO_UDP ||
	     p->proto == CALY_IPPROTO_ICMP || p->proto == CALY_IPPROTO_ICMPV6) &&
	    !caly_tb_consume(&rs->tb[CALY_TB_NEWCONN], now,
			     cfg->tb_rate[CALY_TB_NEWCONN],
			     cfg->tb_burst[CALY_TB_NEWCONN], 1))
		reason = STAT_DROP_RATE_NEWCONN;

	return reason;
}

/* Record a strike; returns 1 when the strike total crossed the ban threshold
 * inside the window. */
static __always_inline int tci_strike(struct rate_state *rs,
				      const struct fw_config *cfg,
				      __u32 reason, __u64 now)
{
	if (rs->window_start_ns == 0 ||
	    now - rs->window_start_ns > cfg->strike_window_ns) {
		rs->window_start_ns = now;
		rs->strikes = 0;
	}
	if (rs->strikes < 0xFFFFFFFFu)
		rs->strikes++;
	rs->last_reason = reason;
	rs->flags |= CALY_RS_F_STRIKING;
	tci_stat(STAT_STRIKE_ADDED, 0);

	return cfg->strike_limit > 0 && rs->strikes >= cfg->strike_limit;
}

/* ------------------------------------------------------------------------- */
/* Port-scan detection                                                       */
/* ------------------------------------------------------------------------- */

/* Returns 1 when the distinct-destination-port estimate crossed the scan
 * threshold this window (caller then bans). */
static __always_inline int tci_scan(const struct tci_pkt *p,
				    const struct fw_config *cfg, __u64 now)
{
	struct scan_state *st, init;
	__u16 dport_h = bpf_ntohs(p->dport);
	__u32 key4 = p->saddr[0];
	struct in6_key key6;

	__builtin_memset(&key6, 0, sizeof(key6));
	key6.a[0] = p->saddr[0];
	key6.a[1] = p->saddr[1];
	key6.a[2] = p->saddr[2];
	key6.a[3] = p->saddr[3];

	if (p->family == CALY_AF_INET)
		st = bpf_map_lookup_elem(&caly_scan4, &key4);
	else
		st = bpf_map_lookup_elem(&caly_scan6, &key6);

	if (!st) {
		__builtin_memset(&init, 0, sizeof(init));
		caly_scan_reset(&init, now);
		if (p->family == CALY_AF_INET) {
			bpf_map_update_elem(&caly_scan4, &key4, &init, BPF_ANY);
			st = bpf_map_lookup_elem(&caly_scan4, &key4);
		} else {
			bpf_map_update_elem(&caly_scan6, &key6, &init, BPF_ANY);
			st = bpf_map_lookup_elem(&caly_scan6, &key6);
		}
		if (!st) {
			tci_stat(STAT_MAP_FULL_SCAN, 0);
			return 0;
		}
	}

	if (now - st->window_start_ns > cfg->scan_window_ns)
		caly_scan_reset(st, now);

	st->last_seen_ns = now;
	st->hits++;

	/* Dedupe consecutive probes to the same port so a chatty single-port
	 * flow does not inflate the distinct estimate. */
	if (dport_h == st->last_port)
		return 0;
	st->last_port = dport_h;

	caly_scan_mark(st, dport_h);

	return cfg->scan_port_threshold > 0 &&
	       st->distinct > cfg->scan_port_threshold;
}

/* ------------------------------------------------------------------------- */
/* ICMP policy                                                               */
/* ------------------------------------------------------------------------- */

static __always_inline int tci_icmp4_mandatory(__u32 type)
{
	return type == CALY_ICMP4_DEST_UNREACH;   /* carries Frag-Needed */
}

static __always_inline int tci_icmp6_mandatory(__u32 type)
{
	return type == CALY_ICMP6_PKT_TOOBIG   || type == CALY_ICMP6_ROUTER_SOL ||
	       type == CALY_ICMP6_ROUTER_ADV   || type == CALY_ICMP6_NEIGH_SOL  ||
	       type == CALY_ICMP6_NEIGH_ADV;
}

/* ------------------------------------------------------------------------- */
/* Parse                                                                     */
/* ------------------------------------------------------------------------- */

/*
 * Fill tp from the skb. Returns STAT_PKT_TOTAL (0) on a fully-parsed IP packet
 * that policy should evaluate, a positive stat_reason on a parse/anomaly drop,
 * or the sentinel TCI_PASS_NONIP when the frame is not IP and should be passed.
 */
#define TCI_PASS_NONIP  0xFFFFFFFFu

static __always_inline __u32 tci_parse(struct __sk_buff *skb,
				       struct tci_pkt *tp,
				       const struct fw_config *cfg,
				       __u64 iface_flags)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	__u32 nh_off = sizeof(struct ethhdr);
	__u16 h_proto;
	int i;
	int frag_no_l4 = 0;   /* set for a non-first fragment: no L4 header present */

	if ((void *)(eth + 1) > data_end)
		return STAT_DROP_ETH_TRUNC;
	h_proto = eth->h_proto;

	CALY_UNROLL
	for (i = 0; i < (int)CALY_VLAN_MAX_DEPTH; i++) {
		struct tci_vlan_hdr *vh;

		if (h_proto != bpf_htons(CALY_ETH_P_8021Q) &&
		    h_proto != bpf_htons(CALY_ETH_P_8021AD) &&
		    h_proto != bpf_htons(CALY_ETH_P_QINQ1) &&
		    h_proto != bpf_htons(CALY_ETH_P_QINQ2) &&
		    h_proto != bpf_htons(CALY_ETH_P_QINQ3))
			break;
		vh = data + nh_off;
		if ((void *)(vh + 1) > data_end)
			return STAT_DROP_VLAN_TRUNC;
		h_proto = vh->h_vlan_encapsulated_proto;
		nh_off += sizeof(*vh);
		tp->pkt_flags |= CALY_PKT_F_VLAN;
	}

	/* Still a VLAN tag after the max depth: refuse it. */
	if (h_proto == bpf_htons(CALY_ETH_P_8021Q) ||
	    h_proto == bpf_htons(CALY_ETH_P_8021AD) ||
	    h_proto == bpf_htons(CALY_ETH_P_QINQ1) ||
	    h_proto == bpf_htons(CALY_ETH_P_QINQ2) ||
	    h_proto == bpf_htons(CALY_ETH_P_QINQ3))
		return STAT_DROP_VLAN_DEPTH;

	if (h_proto == bpf_htons(CALY_ETH_P_IP)) {
		struct iphdr *iph = data + nh_off;
		__u32 ihl_bytes;
		__u16 frag;

		if ((void *)(iph + 1) > data_end)
			return STAT_DROP_IP4_TRUNC;
		if (iph->ihl < 5)
			return STAT_DROP_IP4_IHL;

		ihl_bytes = (__u32)iph->ihl * 4u;
		if (bpf_ntohs(iph->tot_len) < ihl_bytes)
			return STAT_DROP_IP4_TOTLEN;
		if ((cfg->flags & CALY_F_DROP_IP4_OPTIONS) && iph->ihl > 5)
			return STAT_DROP_IP4_OPTIONS;

		tp->family   = CALY_AF_INET;
		tp->l3_off   = nh_off;
		tp->l4_off   = nh_off + ihl_bytes;
		tp->proto    = iph->protocol;
		tp->ttl      = iph->ttl;
		tp->saddr[0] = iph->saddr;
		tp->daddr[0] = iph->daddr;

		frag = bpf_ntohs(iph->frag_off);
		tp->frag_units = frag & 0x1FFFu;
		if (frag & 0x3FFFu) {
			tp->pkt_flags |= CALY_PKT_F_FRAG;
			if ((frag & 0x2000u) && tp->frag_units == 0)
				tp->pkt_flags |= CALY_PKT_F_FRAG_FIRST;
		}
		/* A non-first fragment (offset != 0) carries no L4 header: the
		 * bytes at l4_off are datagram payload, not TCP/UDP ports. */
		if (tp->frag_units != 0)
			frag_no_l4 = 1;
	} else if (h_proto == bpf_htons(CALY_ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = data + nh_off;
		__u32 off = nh_off + sizeof(struct ipv6hdr);
		__u8 nexthdr;

		if ((void *)(ip6h + 1) > data_end)
			return STAT_DROP_IP6_TRUNC;
		if (!(cfg->flags & CALY_F_IPV6) ||
		    (iface_flags & CALY_IF_F_NO_IPV6))
			return STAT_DROP_IP6_DISABLED;

		tp->family   = CALY_AF_INET6;
		tp->l3_off   = nh_off;
		tp->ttl      = ip6h->hop_limit;
		__builtin_memcpy(&tp->saddr[0], &ip6h->saddr, 16);
		__builtin_memcpy(&tp->daddr[0], &ip6h->daddr, 16);
		nexthdr = ip6h->nexthdr;

		/* Walk a bounded number of extension headers. */
		CALY_UNROLL
		for (i = 0; i < (int)CALY_IP6_EXT_MAX; i++) {
			struct tci_ext_hdr *eh;

			if (nexthdr == CALY_IPPROTO_TCP ||
			    nexthdr == CALY_IPPROTO_UDP ||
			    nexthdr == CALY_IPPROTO_ICMPV6)
				break;
			/* Keep the running offset bounded so the verifier can
			 * prove every subsequent packet read stays in range;
			 * anything deeper than the pulled header region is
			 * treated as truncated. */
			if (off > TCI_PULL_LEN)
				return STAT_DROP_IP6_EXT_TRUNC;
			if (nexthdr == CALY_IPPROTO_FRAGMENT) {
				__u8 fo_hi = 0, fo_lo = 0;

				tp->pkt_flags |= CALY_PKT_F_FRAG;
				eh = data + off;
				if ((void *)(eh + 1) > data_end)
					return STAT_DROP_IP6_EXT_TRUNC;
				/* The fragment offset is the high 13 bits of the
				 * 16-bit field at bytes 2..3 of the fixed 8-byte
				 * fragment header. A non-zero offset means a
				 * non-first fragment, which has no L4 header. */
				if ((void *)((__u8 *)eh + 4) <= data_end) {
					fo_hi = *((__u8 *)eh + 2);
					fo_lo = *((__u8 *)eh + 3);
				}
				if (((((__u16)fo_hi << 8) | fo_lo) >> 3) != 0)
					frag_no_l4 = 1;
				else
					tp->pkt_flags |= CALY_PKT_F_FRAG_FIRST;
				nexthdr = eh->nexthdr;
				off += 8;      /* fragment hdr is fixed 8 */
				continue;
			}
			if (nexthdr == CALY_IPPROTO_HOPOPTS  ||
			    nexthdr == CALY_IPPROTO_ROUTING  ||
			    nexthdr == CALY_IPPROTO_DSTOPTS  ||
			    nexthdr == CALY_IPPROTO_AH       ||
			    nexthdr == CALY_IPPROTO_MH) {
				eh = data + off;
				if ((void *)(eh + 1) > data_end)
					return STAT_DROP_IP6_EXT_TRUNC;
				if ((cfg->flags & CALY_F_DROP_RH0) &&
				    nexthdr == CALY_IPPROTO_ROUTING) {
					/* Routing header, segments-left != 0
					 * type 0 is refused (RFC 5095). */
					__u8 rtype = 0, segs = 0;

					if ((void *)((__u8 *)eh + 4) <= data_end) {
						rtype = *((__u8 *)eh + 2);
						segs  = *((__u8 *)eh + 3);
					}
					if (rtype == 0 && segs != 0)
						return STAT_DROP_IP6_RH0;
				}
				if (nexthdr == CALY_IPPROTO_AH)
					off += ((__u32)eh->hdrlen + 2u) * 4u;
				else
					off += ((__u32)eh->hdrlen + 1u) * 8u;
				nexthdr = eh->nexthdr;
				continue;
			}
			/* Unknown/none: stop walking, treat as L4 unknown. */
			break;
		}

		tp->proto  = nexthdr;
		tp->l4_off = off;
	} else {
		return TCI_PASS_NONIP;
	}

	/* ---- L4 ---- */
	/*
	 * A non-first fragment has no L4 header at l4_off - those bytes are
	 * datagram payload. Mirror parsing.h's frag_no_l4 handling: leave the
	 * ports zero, flag the packet CALY_PKT_F_L4_TRUNC, and let the caller
	 * evaluate it as a portless packet. Reading TCP/UDP ports here would
	 * pull garbage payload bytes and drop legitimate fragmented UDP under
	 * the port-zero / port-policy / default-deny stages, so the datagram
	 * could never be reassembled.
	 */
	if (frag_no_l4) {
		tp->pkt_flags |= CALY_PKT_F_L4_TRUNC;
		return STAT_PKT_TOTAL;
	}

	if (tp->proto == CALY_IPPROTO_TCP) {
		struct tcphdr *th = data + tp->l4_off;
		__u32 doff;

		if ((void *)(th + 1) > data_end) {
			tp->pkt_flags |= CALY_PKT_F_L4_TRUNC;
			return STAT_DROP_L4_TRUNC;
		}
		tp->sport = th->source;
		tp->dport = th->dest;
		doff = (__u32)(*((__u8 *)th + TCI_TCP_OFF_DOFF) >> 4);
		tp->tcp_flags = *((__u8 *)th + TCI_TCP_OFF_FLAGS);
		if (doff < 5)
			return STAT_DROP_TCP_DOFF;
		tp->is_syn = (tp->tcp_flags & CALY_TCP_SYN) &&
			     !(tp->tcp_flags & (CALY_TCP_ACK | CALY_TCP_RST |
						CALY_TCP_FIN));
	} else if (tp->proto == CALY_IPPROTO_UDP) {
		struct udphdr *uh = data + tp->l4_off;

		if ((void *)(uh + 1) > data_end) {
			tp->pkt_flags |= CALY_PKT_F_L4_TRUNC;
			return STAT_DROP_L4_TRUNC;
		}
		tp->sport = uh->source;
		tp->dport = uh->dest;
	} else if (tp->proto == CALY_IPPROTO_ICMP ||
		   tp->proto == CALY_IPPROTO_ICMPV6) {
		__u8 *icmp = (__u8 *)data + tp->l4_off;

		/* type(1) + code(1) + checksum(2): 4 bytes minimum. */
		if ((void *)(icmp + 4) > data_end) {
			tp->pkt_flags |= CALY_PKT_F_L4_TRUNC;
			return STAT_DROP_L4_TRUNC;
		}
		tp->icmp_type = icmp[0];
	}
	/*
	 * Any other L4 protocol (ESP/AH IPsec, GRE, SCTP, ...) is left with its
	 * proto set and ports zero. It is NOT dropped here: silently black-
	 * holing IPsec or GRE would break VPNs. Such packets still pass through
	 * the allowlist, blocklist, ban and per-source pps/bps limiters in the
	 * caller, then default-allow. The caller skips the TCP/UDP/ICMP-specific
	 * stages for them.
	 */

	return STAT_PKT_TOTAL;
}

/* ------------------------------------------------------------------------- */
/* Entry point                                                               */
/* ------------------------------------------------------------------------- */

SEC("tc")
int caly_tc_ingress(struct __sk_buff *skb)
{
	struct fw_config *cfg;
	struct iface_config *ic;
	struct caly_scratch *scr;
	struct tci_pkt tp;
	struct rate_state *rs;
	struct port_rule *pr;
	__u32 zero = 0, ifkey, reason, rule_flags = 0;
	__u32 pull;
	__u64 now, iface_flags = 0;
	int monitor, ct_miss;

	/* Make the header region linear before any deep read. */
	pull = skb->len;
	if (pull > TCI_PULL_LEN)
		pull = TCI_PULL_LEN;
	bpf_skb_pull_data(skb, pull);

	cfg = bpf_map_lookup_elem(&caly_config, &zero);
	if (!cfg) {
		/* Fail OPEN: without config we never drop. */
		__u32 r = STAT_CONFIG_MISSING;
		__u64 *p = bpf_map_lookup_elem(&caly_stats, &r);

		if (p)
			*p += 1;
		return TC_ACT_OK;
	}

	scr = bpf_map_lookup_elem(&caly_scratch, &zero);
	if (!scr) {
		__u32 r = STAT_SCRATCH_FAIL;
		__u64 *p = bpf_map_lookup_elem(&caly_stats, &r);

		if (p)
			*p += 1;
		return TC_ACT_OK;
	}

	__builtin_memset(&tp, 0, sizeof(tp));
	tp.pkt_len = skb->len;
	tp.ifindex = skb->ifindex;

	if (!(cfg->flags & CALY_F_ENABLED))
		return tci_finish(skb, scr, cfg, &tp, STAT_PASS_DISABLED,
				  CALY_VERDICT_PASS, 0, 0);

	/* Per-interface overrides. */
	ifkey = skb->ifindex;
	ic = bpf_map_lookup_elem(&caly_iface, &ifkey);
	if (ic) {
		iface_flags = ic->flags;
		if (iface_flags & CALY_IF_F_DISABLED)
			return tci_finish(skb, scr, cfg, &tp, STAT_PASS_DISABLED,
					  CALY_VERDICT_PASS, 0, 0);
		if (ic->zone == CALY_ZONE_LAN || ic->zone == CALY_ZONE_DMZ)
			return tci_finish(skb, scr, cfg, &tp,
					  STAT_PASS_LAN_IFACE,
					  CALY_VERDICT_PASS, 0, 0);
		if (iface_flags & CALY_IF_F_WAN)
			tp.is_wan = 1;
	} else if (cfg->default_zone == CALY_ZONE_WAN) {
		tp.is_wan = 1;
	}

	monitor = (cfg->flags & CALY_F_MONITOR_ONLY) ||
		  cfg->mode == FW_MODE_MONITOR_ONLY ||
		  (iface_flags & CALY_IF_F_MONITOR);

	now = bpf_ktime_get_ns();

	/* ---- parse ---- */
	reason = tci_parse(skb, &tp, cfg, iface_flags);
	if (reason == TCI_PASS_NONIP)
		return tci_finish(skb, scr, cfg, &tp, STAT_PASS_NOT_IP,
				  CALY_VERDICT_PASS, 0, 0);
	if (reason != STAT_PKT_TOTAL)
		return tci_finish(skb, scr, cfg, &tp, reason,
				  CALY_VERDICT_DROP, monitor, now);

	int is_tcp  = (tp.proto == CALY_IPPROTO_TCP);
	int is_udp  = (tp.proto == CALY_IPPROTO_UDP);
	int is_icmp = (tp.proto == CALY_IPPROTO_ICMP ||
		       tp.proto == CALY_IPPROTO_ICMPV6);

	/* Port 0 is illegal for TCP/UDP only; ICMP and other L4s carry no
	 * ports and legitimately present as 0. A non-first fragment (flagged
	 * CALY_PKT_F_L4_TRUNC by the parser) also carries no ports and must not
	 * be judged on them: dropping it here would make the whole datagram
	 * unreassemblable. */
	if ((is_tcp || is_udp) && !(tp.pkt_flags & CALY_PKT_F_L4_TRUNC) &&
	    (tp.sport == 0 || tp.dport == 0))
		return tci_finish(skb, scr, cfg, &tp, STAT_DROP_L4_PORT_ZERO,
				  CALY_VERDICT_DROP, monitor, now);

	/* ================= ANOMALY (no map lookups) ================= */

	if (cfg->flags & CALY_F_LAND_CHECK) {
		if (tp.saddr[0] == tp.daddr[0] && tp.saddr[1] == tp.daddr[1] &&
		    tp.saddr[2] == tp.daddr[2] && tp.saddr[3] == tp.daddr[3] &&
		    tp.sport == tp.dport)
			return tci_finish(skb, scr, cfg, &tp, STAT_DROP_LAND,
					  CALY_VERDICT_DROP, monitor, now);
	}

	/* TTL / hop-limit. */
	if (tp.ttl == 0)
		return tci_finish(skb, scr, cfg, &tp, STAT_DROP_TTL_ZERO,
				  CALY_VERDICT_DROP, monitor, now);
	if ((cfg->flags & CALY_F_TTL_CHECK) && cfg->ip_min_ttl > 0 &&
	    tp.ttl < cfg->ip_min_ttl)
		return tci_finish(skb, scr, cfg, &tp, STAT_DROP_TTL_LOW,
				  CALY_VERDICT_DROP, monitor, now);

	/* Bogon / martian source, WAN only. */
	if ((cfg->flags & CALY_F_BOGON_FILTER) && tp.is_wan) {
		__u32 br;

		tp.drop_private = (cfg->flags & CALY_F_WAN_DROP_PRIVATE) ||
				  (iface_flags & CALY_IF_F_DROP_PRIVATE);
		if (tp.family == CALY_AF_INET)
			br = caly_v4_src_bogon((const __u8 *)&tp.saddr[0],
					       tp.drop_private);
		else
			br = caly_v6_src_bogon((const __u8 *)&tp.saddr[0],
					       tp.drop_private);
		if (br != STAT_PKT_TOTAL)
			return tci_finish(skb, scr, cfg, &tp, br,
					  CALY_VERDICT_DROP, monitor, now);

		if (tci_src_is_local(&tp))
			return tci_finish(skb, scr, cfg, &tp,
					  STAT_DROP_SRC_SELF,
					  CALY_VERDICT_DROP, monitor, now);
	}

	/* TCP illegal flag combinations. */
	if ((cfg->flags & CALY_F_TCP_FLAG_CHECKS) &&
	    tp.proto == CALY_IPPROTO_TCP) {
		__u32 fr = caly_tcp_flags_illegal((__u8)tp.tcp_flags);

		if (fr != STAT_PKT_TOTAL)
			return tci_finish(skb, scr, cfg, &tp, fr,
					  CALY_VERDICT_DROP, monitor, now);
	}

	/* Fragmentation policy. */
	if ((cfg->flags & CALY_F_FRAG_CHECKS) &&
	    (tp.pkt_flags & CALY_PKT_F_FRAG)) {
		if (tp.proto == CALY_IPPROTO_ICMP ||
		    tp.proto == CALY_IPPROTO_ICMPV6)
			return tci_finish(skb, scr, cfg, &tp,
					  STAT_DROP_FRAG_ICMP,
					  CALY_VERDICT_DROP, monitor, now);
		if (tp.frag_units == 1)
			return tci_finish(skb, scr, cfg, &tp,
					  STAT_DROP_FRAG_OFF_ONE,
					  CALY_VERDICT_DROP, monitor, now);
		if ((cfg->flags & CALY_F_DROP_ALL_FRAGS))
			return tci_finish(skb, scr, cfg, &tp,
					  STAT_DROP_FRAG_POLICY,
					  CALY_VERDICT_DROP, monitor, now);
		if ((tp.pkt_flags & CALY_PKT_F_FRAG_FIRST) &&
		    cfg->frag_min_bytes > 0 && tp.pkt_len < cfg->frag_min_bytes)
			return tci_finish(skb, scr, cfg, &tp,
					  STAT_DROP_FRAG_TINY,
					  CALY_VERDICT_DROP, monitor, now);
	}

	/* ICMP oversize + per-type policy (mandatory types can never drop). */
	if ((cfg->flags & CALY_F_ICMP_FILTER) && is_icmp) {
		int v6 = (tp.proto == CALY_IPPROTO_ICMPV6);
		__u32 type = tp.icmp_type & 0xFFu;
		__u32 *pol;

		/* Types that keep the host reachable are passed unconditionally,
		 * ahead of every drop, and are never rate limited. */
		if (v6 && tci_icmp6_mandatory(type))
			return tci_finish(skb, scr, cfg, &tp,
					  type == CALY_ICMP6_PKT_TOOBIG
						? STAT_PASS_ICMP6_PMTUD
						: STAT_PASS_ICMP6_ND,
					  CALY_VERDICT_PASS, 0, now);
		if (!v6 && tci_icmp4_mandatory(type))
			return tci_finish(skb, scr, cfg, &tp,
					  STAT_PASS_ICMP4_PMTUD,
					  CALY_VERDICT_PASS, 0, now);

		{
			__u32 maxp = v6 ? cfg->icmp6_max_payload
					: cfg->icmp_max_payload;
			__u32 payload = tp.pkt_len > (tp.l4_off + 8u)
					? tp.pkt_len - (tp.l4_off + 8u) : 0;

			if (maxp > 0 && payload > maxp)
				return tci_finish(skb, scr, cfg, &tp,
						  v6 ? STAT_DROP_ICMP6_OVERSIZE
						     : STAT_DROP_ICMP_OVERSIZE,
						  CALY_VERDICT_DROP, monitor, now);
		}

		pol = v6 ? bpf_map_lookup_elem(&caly_icmp6_pol, &type)
			 : bpf_map_lookup_elem(&caly_icmp4_pol, &type);
		if (pol && *pol == CALY_ICMP_DROP)
			return tci_finish(skb, scr, cfg, &tp,
					  v6 ? STAT_DROP_ICMP6_TYPE
					     : STAT_DROP_ICMP_TYPE,
					  CALY_VERDICT_DROP, monitor, now);
		/* PASS / RATELIMIT policy: fall through to the per-source
		 * ICMP token bucket below. */
	}

	/* ================= ESCAPE HATCHES (before every drop) ============ */

	if (cfg->flags & CALY_F_ALLOWLIST) {
		if (tci_allowlisted(&tp, &rule_flags)) {
			tp.pkt_flags |= CALY_PKT_F_ALLOWLIST;
			return tci_finish(skb, scr, cfg, &tp,
					  STAT_PASS_ALLOWLIST,
					  CALY_VERDICT_PASS, 0, now);
		}
	}

	/* Management ports (dport), HOST order. TCP/22 is always here. */
	if (tp.proto == CALY_IPPROTO_TCP &&
	    caly_is_mgmt_tcp(cfg, bpf_ntohs(tp.dport))) {
		tp.pkt_flags |= CALY_PKT_F_MGMT;
		return tci_finish(skb, scr, cfg, &tp, STAT_PASS_MGMT_PORT,
				  CALY_VERDICT_PASS, 0, now);
	}
	if (tp.proto == CALY_IPPROTO_UDP &&
	    caly_is_mgmt_udp(cfg, bpf_ntohs(tp.dport))) {
		tp.pkt_flags |= CALY_PKT_F_MGMT;
		return tci_finish(skb, scr, cfg, &tp, STAT_PASS_MGMT_PORT,
				  CALY_VERDICT_PASS, 0, now);
	}

	/* ================= REPUTATION ================= */

	if (cfg->flags & CALY_F_BLOCKLIST) {
		if (tci_blocklisted(&tp))
			return tci_finish(skb, scr, cfg, &tp,
					  STAT_DROP_BLOCKLIST,
					  CALY_VERDICT_DROP, monitor, now);
	}

	if (tci_ban_active(&tp, now))
		return tci_finish(skb, scr, cfg, &tp, STAT_DROP_BAN_ACTIVE,
				  CALY_VERDICT_DROP, monitor, now);

	/* ================= CONNTRACK short-circuit ================= */

	ct_miss = 1;
	if (cfg->flags & CALY_F_CONNTRACK) {
		int ch = tci_conn_hit(scr, &tp, now);

		if (ch == TCI_CT_CONFIRMED) {
			tp.pkt_flags |= CALY_PKT_F_CT_HIT;
			return tci_finish(skb, scr, cfg, &tp,
					  STAT_PASS_CONNTRACK,
					  CALY_VERDICT_PASS, 0, now);
		}
		/*
		 * An unconfirmed hit (the entry exists but the flow is not yet
		 * solicited/bidirectional) is deliberately NOT fast-pathed: it
		 * keeps flowing through the per-source token buckets below so a
		 * single source cannot self-establish an entry and bypass its
		 * rate caps. The entry already exists, so do not relearn it.
		 */
		if (ch == TCI_CT_UNCONFIRMED)
			ct_miss = 0;
	}

	/* ================= LOCKDOWN ================= */
	/* Nothing matched allowlist/mgmt/conntrack: in LOCKDOWN drop it. */
	if (cfg->mode == FW_MODE_LOCKDOWN)
		return tci_finish(skb, scr, cfg, &tp, STAT_DROP_LOCKDOWN,
				  CALY_VERDICT_DROP, monitor, now);

	/* ================= REFLECTION / AMPLIFICATION ================= */

	if ((cfg->flags & CALY_F_ANTI_AMPLIFY) &&
	    tp.proto == CALY_IPPROTO_UDP) {
		__u32 sport_h = bpf_ntohs(tp.sport);

		pr = bpf_map_lookup_elem(&caly_port_udp, &sport_h);
		if (pr && (pr->flags & CALY_PORT_F_AMPLIFIER)) {
			/*
			 * Drop the reflected packet, but do NOT ban its source.
			 * A UDP source address is trivially spoofable, so banning
			 * it lets a single crafted packet (sport=53/123/161/...)
			 * blackhole any resolver, NTP server or load balancer the
			 * operator depends on: tci_ban_active() precedes the
			 * conntrack short-circuit, so even our own solicited
			 * replies from that peer would then be dropped. Traffic we
			 * actually solicited has already short-circuited at the
			 * conntrack stage above; everything reaching here is
			 * unsolicited reflection and dropping it is the mitigation.
			 */
			tci_event(skb, scr, cfg, &tp, STAT_DROP_AMP_SRCPORT,
				  monitor ? CALY_VERDICT_MONITOR
					  : CALY_VERDICT_DROP,
				  0, sport_h, now);
			return tci_finish(skb, scr, cfg, &tp,
					  STAT_DROP_AMP_SRCPORT,
					  CALY_VERDICT_DROP, monitor, now);
		}
	}

	/* ================= PORT POLICY (TCP/UDP only) ================= */

	if ((cfg->flags & CALY_F_PORT_POLICY) && (is_tcp || is_udp) &&
	    !(tp.pkt_flags & CALY_PKT_F_L4_TRUNC)) {
		__u32 dport_h = bpf_ntohs(tp.dport);

		if (is_tcp)
			pr = bpf_map_lookup_elem(&caly_port_tcp, &dport_h);
		else
			pr = bpf_map_lookup_elem(&caly_port_udp, &dport_h);

		if (pr) {
			if (pr->mode == CALY_PORT_RATELIMIT) {
				__u32 idx = CALY_PORT_TB_IDX(is_udp, dport_h);
				struct caly_token_bucket *tb =
					bpf_map_lookup_elem(&caly_port_tb, &idx);

				if (tb && !caly_tb_consume(tb, now, pr->rate,
							   pr->burst, 1))
					return tci_finish(skb, scr, cfg, &tp,
							  STAT_DROP_PORT_RATE,
							  CALY_VERDICT_DROP,
							  monitor, now);
			} else if (pr->mode == CALY_PORT_CLOSED) {
				/* A zeroed (unconfigured) entry is CLOSED; it
				 * only drops when default-deny is engaged. An
				 * explicitly opened port has mode OPEN. */
				if (cfg->flags & CALY_F_DEFAULT_DENY)
					return tci_finish(skb, scr, cfg, &tp,
							  STAT_DROP_DEFAULT_DENY,
							  CALY_VERDICT_DROP,
							  monitor, now);
			}
			/* CALY_PORT_OPEN falls through to rate limiting. */
		} else if (cfg->flags & CALY_F_DEFAULT_DENY) {
			return tci_finish(skb, scr, cfg, &tp,
					  STAT_DROP_DEFAULT_DENY,
					  CALY_VERDICT_DROP, monitor, now);
		}
	}

	/* ================= PER-SOURCE TOKEN BUCKETS ================= */

	if ((cfg->flags & CALY_F_RATE_LIMIT) &&
	    !(rule_flags & CALY_RULE_F_BYPASS_RATE)) {
		rs = tci_rate_state(&tp);
		if (!rs) {
			tci_stat(STAT_MAP_FULL_RATE, 0);
			/* Fail OPEN on map pressure. */
		} else {
			__u32 rr = tci_rate_check(rs, cfg, &tp, ct_miss, now);

			if (rr != STAT_PKT_TOTAL) {
				/*
				 * Escalate a rate-limit drop to a ban only for
				 * connection-oriented (TCP) traffic. A UDP/ICMP (or
				 * other connectionless) source address is trivially
				 * spoofable, so a flood spoofing a victim's IP must
				 * not be able to accumulate strikes and install a
				 * ban on that victim - which would blackhole every
				 * resolver, NTP peer or LB the operator depends on.
				 * The token-bucket drop already throttles the flood
				 * without banning an arbitrary third party.
				 */
				if ((cfg->flags & CALY_F_AUTOBAN) && is_tcp &&
				    tci_strike(rs, cfg, rr, now)) {
					__u64 ttl = tci_ban_apply(scr, cfg, &tp,
							rr, cfg->ban_ttl_base_ns,
							rs->strikes, now);

					rs->offences++;
					tci_event(skb, scr, cfg, &tp, rr,
						  monitor ? CALY_VERDICT_MONITOR
							  : CALY_VERDICT_DROP,
						  ttl, rs->strikes, now);
				}
				return tci_finish(skb, scr, cfg, &tp, rr,
						  CALY_VERDICT_DROP,
						  monitor, now);
			}
		}
	}

	/* ================= PORT-SCAN DETECTION ================= */

	if ((cfg->flags & CALY_F_PORTSCAN_DETECT) &&
	    (tp.proto == CALY_IPPROTO_TCP || tp.proto == CALY_IPPROTO_UDP)) {
		if (tci_scan(&tp, cfg, now)) {
			__u64 ttl;

			if (cfg->flags & CALY_F_AUTOBAN) {
				ttl = tci_ban_apply(scr, cfg, &tp,
						    STAT_DROP_PORTSCAN,
						    cfg->ban_ttl_scan_ns,
						    0, now);
				tci_event(skb, scr, cfg, &tp, STAT_DROP_PORTSCAN,
					  monitor ? CALY_VERDICT_MONITOR
						  : CALY_VERDICT_DROP,
					  ttl, 0, now);
				return tci_finish(skb, scr, cfg, &tp,
						  STAT_DROP_PORTSCAN,
						  CALY_VERDICT_DROP,
						  monitor, now);
			}
		}
	}

	/* ================= SYN FALLBACK (no XDP_TX here) ================= */
	/*
	 * There is no SYN proxy on the tc path (XDP_TX is unavailable), so the
	 * SYN defence is purely the per-source CALY_TB_SYN bucket handled
	 * above plus the kernel's tcp_syncookies=1 backstop the installer
	 * enables. We still feed the global SYN gauge so the daemon can
	 * escalate the mode.
	 */
	if (tp.is_syn)
		tci_gauge(CALY_G_SYN, 1);

	/* ================= CONNTRACK LEARNING ================= */

	if ((cfg->flags & CALY_F_CONNTRACK) && ct_miss) {
		int learn = tp.is_syn ||
			    tp.proto == CALY_IPPROTO_UDP ||
			    tp.proto == CALY_IPPROTO_ICMP ||
			    tp.proto == CALY_IPPROTO_ICMPV6;

		/* Do not track flows for ports that asked to be untracked. */
		if (learn) {
			__u32 dport_h = bpf_ntohs(tp.dport);
			struct port_rule *dpr = NULL;

			if (tp.proto == CALY_IPPROTO_TCP)
				dpr = bpf_map_lookup_elem(&caly_port_tcp,
							  &dport_h);
			else if (tp.proto == CALY_IPPROTO_UDP)
				dpr = bpf_map_lookup_elem(&caly_port_udp,
							  &dport_h);
			if (!(dpr && (dpr->flags & CALY_PORT_F_NO_CT))) {
				tci_gauge(CALY_G_NEWCONN, 1);
				tci_conn_create(scr, &tp, rule_flags, now);
			}
		}
	}

	/* ================= DEFAULT ALLOW ================= */
	return tci_finish(skb, scr, cfg, &tp, STAT_PASS_DEFAULT,
			  CALY_VERDICT_PASS, 0, now);
}

char _license[] SEC("license") = "Dual BSD/GPL";
