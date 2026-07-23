/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - XDP/eBPF DDoS mitigation suite
 * src/bpf/ratelimit.h - token buckets, sliding windows, strike/ban escalation.
 *
 * PREREQUISITE INCLUDES:
 *     #include "vmlinux.h"     (BPF)  or  <linux/types.h> (userspace)
 *     #include "common.h"
 *     #include "compat.h"
 *     #include "ratelimit.h"
 *
 * Every function here is pure arithmetic over caller-supplied pointers. It
 * calls NO kernel helper and touches NO map, which is deliberate: the daemon's
 * "would this have been dropped" simulator links the exact same code and must
 * agree with the dataplane bit for bit. The map lookups that fetch the
 * rate_state / scan_state / ban_entry live in the caller.
 *
 * The core bucket primitives - caly_tb_init, caly_tb_consume - and the ban TTL
 * escalation - caly_ban_next_ttl - and the scan Bloom - caly_scan_mark,
 * caly_scan_reset - all live in common.h so both sides share one definition.
 * This file adds the non-consuming peek, the per-source multi-bucket driver,
 * the sliding-window strike machine, and the ban-record builders on top.
 *
 * OVERFLOW AND CLOCK SAFETY (inherited and extended)
 * --------------------------------------------------
 *   - caly_tb_consume clamps rate to CALY_TB_RATE_MAX and elapsed to 1 s, so
 *     elapsed*rate <= 4e18 < U64_MAX. It snaps the refill anchor forward before
 *     measuring, so a long idle gap can never be "spent twice".
 *   - It treats last_refill_ns == 0 (fresh LRU entry) or last_refill_ns > now
 *     (clock regression, or a timestamp captured on a CPU that ran ahead) as a
 *     reseed to a full bucket. That is the monotonic-regression safety net.
 *   - The sliding-window helpers here use caly_age_ns(), which returns 0 rather
 *     than a ~1.8e19 "age" when the stored timestamp is in the future, so a
 *     regressed clock re-opens the window instead of never expiring it.
 */

#ifndef __CALY_ANTI_RATELIMIT_H
#define __CALY_ANTI_RATELIMIT_H

/* -------------------------------------------------------------------------
 * Non-consuming peek.
 *
 * Answers "would `want` units conform right now?" WITHOUT mutating the bucket,
 * by refilling a stack copy. Reuses caly_tb_consume verbatim so the peek and
 * the real consume can never diverge. Used by the simulator and by paths that
 * must test one bucket before deciding whether to charge several.
 * ------------------------------------------------------------------------- */
CALY_INLINE int caly_tb_peek(const struct caly_token_bucket *tb, __u64 now_ns,
			     __u64 rate, __u64 burst, __u64 want)
{
	struct caly_token_bucket tmp = *tb;

	return caly_tb_consume(&tmp, now_ns, rate, burst, want);
}

/* Tokens available after refilling a copy, for reporting the depth an event
 * fired at. Never used to make a drop decision. */
CALY_INLINE __u64 caly_tb_avail(const struct caly_token_bucket *tb, __u64 now_ns,
				__u64 rate, __u64 burst)
{
	struct caly_token_bucket tmp = *tb;

	if (rate == 0 || burst == 0)
		return burst;
	/* Consume zero: refills the copy, subtracts nothing, leaves tokens. */
	(void)caly_tb_consume(&tmp, now_ns, rate, burst, 0);
	return tmp.tokens;
}

/* -------------------------------------------------------------------------
 * rate_state lifecycle.
 * ------------------------------------------------------------------------- */

/*
 * Seed a freshly created rate_state. caly_tb_consume self-heals an all-zero
 * bucket (last_refill_ns == 0 reseeds to a full burst on first use), so this
 * is not strictly required for correctness - but stamping the buckets and the
 * flag makes the first-packet behaviour explicit and lets the GC distinguish a
 * seeded-but-idle entry from a never-touched one.
 */
CALY_INLINE void caly_rate_seed(struct rate_state *rs,
				const struct fw_config *cfg, __u64 now_ns)
{
	unsigned int i;

	CALY_UNROLL
	for (i = 0; i < CALY_TB_MAX; i++)
		caly_tb_init(&rs->tb[i], now_ns, cfg->tb_burst[i]);

	rs->window_start_ns = now_ns;
	rs->last_seen_ns    = now_ns;
	rs->strikes         = 0;
	rs->last_reason     = 0;
	rs->flags          |= CALY_RS_F_SEEDED;
}

CALY_INLINE void caly_rate_touch(struct rate_state *rs, __u64 now_ns)
{
	rs->last_seen_ns = now_ns;
}

/* -------------------------------------------------------------------------
 * The per-source multi-bucket driver.
 *
 * Charges every bucket that applies to this packet and returns the
 * stat_reason of the FIRST one that was exhausted, or STAT_PKT_TOTAL (0) when
 * the packet conforms to all of them. The buckets are checked cheapest-signal
 * first: total pps, then total bps, then the protocol-specific bucket, then
 * new-connection. A disabled bucket (rate or burst 0) always conforms, which
 * is enforced inside caly_tb_consume - a misconfigured limiter must never
 * black-hole traffic.
 *
 * `want_bytes` is the on-wire length charged to the bps bucket. The SYN / UDP
 * / ICMP / newconn booleans are computed by the caller from the parsed packet;
 * exactly the buckets whose boolean is set are charged, in addition to pps and
 * bps which are always charged.
 *
 * Charging semantics: on the first exhausted bucket we STOP and return. The
 * packet is going to be dropped, so charging the remaining buckets would only
 * deplete them against a packet that never made it through - which would let a
 * burst on one dimension unfairly exhaust the others. This mirrors how a real
 * policer shortcuts.
 */
CALY_INLINE __u32 caly_rate_check(struct rate_state *rs,
				  const struct fw_config *cfg, __u64 now_ns,
				  __u32 want_bytes, int is_syn, int is_udp,
				  int is_icmp, int is_newconn)
{
	const __u64 *rate = cfg->tb_rate;
	const __u64 *burst = cfg->tb_burst;

	if (!(rs->flags & CALY_RS_F_SEEDED))
		caly_rate_seed(rs, cfg, now_ns);

	if (!caly_tb_consume(&rs->tb[CALY_TB_PPS], now_ns,
			     rate[CALY_TB_PPS], burst[CALY_TB_PPS], 1))
		return STAT_DROP_RATE_PPS;

	if (!caly_tb_consume(&rs->tb[CALY_TB_BPS], now_ns,
			     rate[CALY_TB_BPS], burst[CALY_TB_BPS],
			     (__u64)want_bytes))
		return STAT_DROP_RATE_BPS;

	if (is_syn &&
	    !caly_tb_consume(&rs->tb[CALY_TB_SYN], now_ns,
			     rate[CALY_TB_SYN], burst[CALY_TB_SYN], 1))
		return STAT_DROP_RATE_SYN;

	if (is_udp &&
	    !caly_tb_consume(&rs->tb[CALY_TB_UDP], now_ns,
			     rate[CALY_TB_UDP], burst[CALY_TB_UDP], 1))
		return STAT_DROP_RATE_UDP;

	if (is_icmp &&
	    !caly_tb_consume(&rs->tb[CALY_TB_ICMP], now_ns,
			     rate[CALY_TB_ICMP], burst[CALY_TB_ICMP], 1))
		return STAT_DROP_RATE_ICMP;

	if (is_newconn &&
	    !caly_tb_consume(&rs->tb[CALY_TB_NEWCONN], now_ns,
			     rate[CALY_TB_NEWCONN], burst[CALY_TB_NEWCONN], 1))
		return STAT_DROP_RATE_NEWCONN;

	return STAT_PKT_TOTAL;
}

/*
 * Charge just the SYN bucket. Used by the SYN-flood fallback path (pre-5.15,
 * no raw syncookie helper) where the main driver has already run but the SYN
 * bucket needs an independent, possibly stricter, decision.
 */
CALY_INLINE int caly_rate_syn_ok(struct rate_state *rs,
				 const struct fw_config *cfg, __u64 now_ns)
{
	if (!(rs->flags & CALY_RS_F_SEEDED))
		caly_rate_seed(rs, cfg, now_ns);

	return caly_tb_consume(&rs->tb[CALY_TB_SYN], now_ns,
			       cfg->tb_rate[CALY_TB_SYN],
			       cfg->tb_burst[CALY_TB_SYN], 1);
}

/* -------------------------------------------------------------------------
 * Global SYN fallback cap.
 *
 * The pre-5.15 path also enforces cfg.syn_fallback_pps as a single shared cap
 * across all sources, catching a distributed spoofed-SYN flood that stays
 * under every per-source limit. There is no dedicated map for it in the ABI,
 * so the caller supplies the caly_token_bucket (a slot it owns - e.g. a reserved
 * caly_port_tb index, or a per-CPU scratch word). rate 0 disables it.
 *
 * Returns 1 to permit, 0 to drop (charge STAT_DROP_RATE_GLOBAL_SYN).
 */
CALY_INLINE int caly_syn_global_ok(struct caly_token_bucket *tb, __u64 now_ns,
				   __u64 fallback_pps)
{
	__u64 burst;

	if (fallback_pps == 0)
		return 1;

	/* A one-second burst ceiling: enough to absorb legitimate connection
	 * spikes without letting a flood bank an unbounded reserve. */
	burst = fallback_pps;
	if (burst < 1)
		burst = 1;

	return caly_tb_consume(tb, now_ns, fallback_pps, burst, 1);
}

/* -------------------------------------------------------------------------
 * Per-port rate limiting.
 *
 * Ties a port_rule to its caly_token_bucket. CLOSED and OPEN modes never consult
 * the bucket (CLOSED is handled by the caller as a drop; OPEN passes). Only
 * RATELIMIT draws a token. Returns 1 to permit, 0 to drop
 * (charge STAT_DROP_PORT_RATE).
 * ------------------------------------------------------------------------- */
CALY_INLINE int caly_port_rate_ok(struct caly_token_bucket *tb,
				  const struct port_rule *pr, __u64 now_ns)
{
	if (!pr || pr->mode != CALY_PORT_RATELIMIT)
		return 1;
	if (!tb)
		return 1;      /* fail open: bucket slot missing */

	return caly_tb_consume(tb, now_ns, pr->rate, pr->burst, 1);
}

/* -------------------------------------------------------------------------
 * Sliding-window strike machine.
 *
 * A source that trips ANY rate bucket earns a strike. strike_limit strikes
 * inside strike_window trigger a ban. The window slides: a strike arriving
 * after the window has elapsed opens a fresh window rather than accumulating
 * against stale ones, so an attacker cannot bank strikes across quiet periods
 * to force a ban on the daemon's schedule rather than its own behaviour.
 *
 * Returns 1 when this strike reaches the ban threshold, 0 otherwise. The
 * caller charges STAT_STRIKE_ADDED on every call that returns via *striked,
 * and installs the ban when the function returns 1.
 * ------------------------------------------------------------------------- */
CALY_INLINE int caly_strike_register(struct rate_state *rs,
				     const struct fw_config *cfg, __u64 now_ns,
				     __u32 reason)
{
	__u32 limit = cfg->strike_limit;
	__u64 window = cfg->strike_window_ns;

	/* A zero window or zero limit means "ban on the first strike": there is
	 * no window to accumulate within. Guard both so a misconfiguration
	 * cannot make the strike counter run away without ever banning. */
	if (window == 0 || limit == 0) {
		rs->last_reason = reason;
		rs->strikes = caly_add_sat_u32(rs->strikes, 1);
		rs->flags |= CALY_RS_F_STRIKING;
		return 1;
	}

	/* Window rolled over (or clock regressed): start a fresh window. */
	if (!(rs->flags & CALY_RS_F_STRIKING) ||
	    caly_age_ns(now_ns, rs->window_start_ns) > window) {
		rs->window_start_ns = now_ns;
		rs->strikes = 0;
		rs->flags |= CALY_RS_F_STRIKING;
	}

	rs->strikes = caly_add_sat_u32(rs->strikes, 1);
	rs->last_reason = reason;

	if (rs->strikes >= limit) {
		/* Close the window so the next offence opens a new one and the
		 * escalation counter advances per ban, not per packet. */
		rs->flags &= ~CALY_RS_F_STRIKING;
		return 1;
	}
	return 0;
}

/* Reset the strike window without banning, e.g. when the operator manually
 * clears a source or when a long-lived conntrack flow proves the source is
 * legitimate. */
CALY_INLINE void caly_strike_clear(struct rate_state *rs)
{
	rs->strikes = 0;
	rs->flags &= ~CALY_RS_F_STRIKING;
}

/* -------------------------------------------------------------------------
 * Port-scan window.
 *
 * Wraps the common.h Bloom primitives with the window-rollover bookkeeping.
 * Records a destination port and reports whether the distinct-port estimate
 * has crossed the configured threshold this window, which is the scan-ban
 * trigger. Consecutive probes to the SAME port are deduped by last_port so a
 * single flow retransmitting does not inflate the estimate.
 *
 * Returns 1 when the threshold is crossed (install a scan ban), 0 otherwise.
 * ------------------------------------------------------------------------- */
CALY_INLINE int caly_scan_register(struct scan_state *st,
				   const struct fw_config *cfg, __u64 now_ns,
				   __u16 dport_host)
{
	__u64 window = cfg->scan_window_ns;
	__u32 threshold = cfg->scan_port_threshold;

	if (threshold == 0)
		return 0;      /* scan detection disabled by config */

	/* Fresh entry or window elapsed (or clock regressed): reset. */
	if (st->window_start_ns == 0 ||
	    (window != 0 && caly_age_ns(now_ns, st->window_start_ns) > window))
		caly_scan_reset(st, now_ns);

	st->last_seen_ns = now_ns;
	st->hits = caly_add_sat_u32(st->hits, 1);

	/* Dedupe consecutive identical probes. last_port stores port+1 so that
	 * 0 unambiguously means "no previous port" (port 0 is illegal anyway,
	 * but the +1 keeps the sentinel clean). */
	if (st->last_port == (__u32)dport_host + 1u)
		return 0;
	st->last_port = (__u32)dport_host + 1u;

	caly_scan_mark(st, dport_host);

	return st->distinct > threshold;
}

/* -------------------------------------------------------------------------
 * Ban-record construction and escalation.
 * ------------------------------------------------------------------------- */

/*
 * Fill a fresh ban_entry. `base_ttl_ns` is the base TTL for this class of ban
 * (cfg->ban_ttl_base_ns for a rate ban, ban_ttl_scan_ns for a scan ban,
 * ban_ttl_amp_ns for an amplifier ban). The escalation multiplier is applied
 * from `prev_ttl_ns` / `offences` supplied by the caller after it has looked
 * up any existing ban - see caly_ban_refresh for the update-in-place case.
 */
CALY_INLINE void caly_ban_fill(struct ban_entry *b, __u32 reason, __u64 now_ns,
			       const struct fw_config *cfg, __u64 base_ttl_ns,
			       __u32 strikes)
{
	__u64 ttl;

	if (base_ttl_ns == 0)
		base_ttl_ns = cfg->ban_ttl_base_ns;

	ttl = base_ttl_ns;
	if (cfg->ban_ttl_max_ns && ttl > cfg->ban_ttl_max_ns)
		ttl = cfg->ban_ttl_max_ns;

	__builtin_memset(b, 0, sizeof(*b));
	b->expiry_ns     = now_ns + ttl;
	b->first_seen_ns = now_ns;
	b->last_hit_ns   = now_ns;
	b->cur_ttl_ns    = ttl;
	b->hit_pkts      = 0;
	b->hit_bytes     = 0;
	b->reason        = reason;
	b->strikes       = strikes;
	b->offences      = 1;
	b->flags         = CALY_BAN_F_AUTO;
}

/*
 * Refresh an EXISTING ban that has just been hit again while still active, or
 * re-ban a source whose previous ban has expired. Escalates the TTL via
 * caly_ban_next_ttl (ttl * num / den clamped to [base, max]) so a repeat
 * offender is held longer each time. Returns the new TTL so the caller can put
 * it in the event.
 *
 * `expired` distinguishes the two cases: an expired-then-reoffended source has
 * its offence count bumped and TTL escalated; a still-active ban that merely
 * absorbed another packet only advances its hit counters and, optionally, its
 * expiry (a sliding ban that resets its clock on every hit, which is what
 * keeps a persistent attacker banned for as long as it keeps trying).
 */
CALY_INLINE __u64 caly_ban_refresh(struct ban_entry *b,
				   const struct fw_config *cfg, __u64 now_ns,
				   __u32 reason, __u32 pkt_len, int expired)
{
	__u64 ttl;

	b->last_hit_ns = now_ns;
	b->hit_pkts    = caly_add_sat_u64(b->hit_pkts, 1);
	b->hit_bytes   = caly_add_sat_u64(b->hit_bytes, pkt_len);

	if (expired) {
		/* Re-offence after expiry: escalate. */
		ttl = caly_ban_next_ttl(b->cur_ttl_ns, cfg->ban_ttl_base_ns,
					cfg->ban_ttl_max_ns,
					cfg->ban_escalate_num,
					cfg->ban_escalate_den);
		b->cur_ttl_ns = ttl;
		b->expiry_ns  = now_ns + ttl;
		b->offences   = caly_add_sat_u32(b->offences, 1);
		b->reason     = reason;
		b->flags     |= CALY_BAN_F_ESCALATED;
		if (b->first_seen_ns == 0)
			b->first_seen_ns = now_ns;
		return ttl;
	}

	/* Still active: slide the expiry out to keep a persistent attacker
	 * blocked, but do not escalate the base TTL on every packet. */
	if (b->flags & CALY_BAN_F_PERMANENT)
		return b->cur_ttl_ns;

	ttl = b->cur_ttl_ns;
	if (ttl == 0)
		ttl = cfg->ban_ttl_base_ns;
	if (cfg->ban_ttl_max_ns && ttl > cfg->ban_ttl_max_ns)
		ttl = cfg->ban_ttl_max_ns;
	b->expiry_ns = now_ns + ttl;
	return ttl;
}

/*
 * Account a packet dropped by an ALREADY-active ban (the common case: a source
 * is banned and keeps sending). Advances hit counters and slides the expiry.
 * Cheaper than caly_ban_refresh's full branch and used on the hot ban-hit
 * path. Returns the (unchanged) current TTL.
 */
CALY_INLINE __u64 caly_ban_hit(struct ban_entry *b, __u64 now_ns,
			       __u32 pkt_len)
{
	b->last_hit_ns = now_ns;
	b->hit_pkts    = caly_add_sat_u64(b->hit_pkts, 1);
	b->hit_bytes   = caly_add_sat_u64(b->hit_bytes, pkt_len);
	return b->cur_ttl_ns;
}

/* Pick the base TTL for a ban class from the reason that triggered it. Keeps
 * the mapping in one place so the three ban classes cannot drift. */
CALY_INLINE __u64 caly_ban_base_ttl(const struct fw_config *cfg, __u32 reason)
{
	switch (reason) {
	case STAT_DROP_PORTSCAN:
		return cfg->ban_ttl_scan_ns ? cfg->ban_ttl_scan_ns
					    : cfg->ban_ttl_base_ns;
	case STAT_DROP_AMP_SRCPORT:
		return cfg->ban_ttl_amp_ns ? cfg->ban_ttl_amp_ns
					   : cfg->ban_ttl_base_ns;
	default:
		return cfg->ban_ttl_base_ns;
	}
}

/* -------------------------------------------------------------------------
 * Compile-time sanity: the driver indexes rate_state.tb[] by enum caly_tb_kind
 * and must stay within the array the ABI declares.
 * ------------------------------------------------------------------------- */
CALY_ASSERT(CALY_TB_MAX == 6, ratelimit_tb_kinds);
CALY_ASSERT(sizeof(((struct rate_state *)0)->tb) ==
	    CALY_TB_MAX * sizeof(struct caly_token_bucket), ratelimit_tb_span);

#endif /* __CALY_ANTI_RATELIMIT_H */
