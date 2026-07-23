/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/events.c
 *
 * Perf-buffer / ring-buffer consumer for struct event, with validation,
 * bounded aggregation and rate-limited summary logging.
 *
 * libbpf ABI NOTE
 *   perf_buffer__new() changed shape in libbpf 0.6:
 *
 *     <= 0.5 :  perf_buffer__new(fd, pages, opts)
 *               with sample_cb / lost_cb / ctx inside struct perf_buffer_opts
 *     >= 0.6 :  perf_buffer__new(fd, pages, sample_cb, lost_cb, ctx, opts)
 *               with struct perf_buffer_opts reduced to { size_t sz; }
 *
 *   0.6 through 0.8 keep both behind the ___libbpf_overload() macro, so the
 *   six argument call compiles there too; 1.x removed the legacy form
 *   entirely. Selection is therefore purely "is this libbpf >= 0.6", which is
 *   exactly what the presence and contents of <bpf/libbpf_version.h> tell us
 *   (that header itself was added in 0.6). The build may override the
 *   decision with -DCALY_PB_MODERN=0/1.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#if defined(__has_include)
#  if __has_include(<bpf/libbpf_version.h>)
#    include <bpf/libbpf_version.h>
#  endif
#endif

#include "events.h"

#ifndef CALY_PB_MODERN
#  if defined(LIBBPF_MAJOR_VERSION) &&                                        \
      (LIBBPF_MAJOR_VERSION > 0 ||                                            \
       (LIBBPF_MAJOR_VERSION == 0 && LIBBPF_MINOR_VERSION >= 6))
#    define CALY_PB_MODERN 1
#  else
#    define CALY_PB_MODERN 0
#  endif
#endif

/* BPF_MAP_TYPE_RINGBUF and the ring_buffer__* API arrived together in
 * libbpf 0.0.9 / kernel 5.8. Every distro this suite targets ships at least
 * that, but the build can compile the path out with -DCALY_HAVE_RINGBUF=0 if
 * it ever links against something older. */
#ifndef CALY_HAVE_RINGBUF
#define CALY_HAVE_RINGBUF 1
#endif

#define EV_LINE_MAX      512u
#define EV_ADDR_MAX       64u
#define EV_PROBE_MAX      12u   /* linear probes before we use the spill slot */
#define EV_WORK_BUDGET  262144u /* slots * top_report ceiling per flush        */

/* -------------------------------------------------------------------------
 * Aggregation bucket
 * ------------------------------------------------------------------------- */

struct ev_agg {
	__u32 saddr[4];
	__u32 daddr[4];
	__u64 count;
	__u64 bytes;
	__u64 value_max;
	__u64 ban_ttl_max;
	__u64 first_ns;
	__u64 last_ns;
	__u32 family;
	__u32 reason;
	__u32 verdict;
	__u32 proto;
	__u32 ifindex;
	__u32 mode;
	__u32 dport_changes;  /* cheap scan indicator, not an exact distinct */
	__u32 used;
	__u16 sport;
	__u16 dport;
	__u16 tcp_flags;
	__u16 emitted;
};

struct events_ctx {
	int backend;

	struct perf_buffer *pb;
#if CALY_HAVE_RINGBUF
	struct ring_buffer *rb;
#endif
	/* When both transports are live, an epoll instance that watches both
	 * of their epoll fds so the daemon can still sleep on ONE descriptor.
	 * -1 when not built (single transport, or a libbpf too old to expose
	 * the per-buffer epoll fds). */
	int epfd;

	struct ev_agg *agg;
	unsigned int agg_slots;        /* power of two                       */
	unsigned int agg_mask;
	unsigned int agg_live;
	struct ev_agg spill;

	struct ev_agg *sel;            /* top_report selection scratch       */
	unsigned int top_report;
	int flushing;                  /* guards c->sel against re-entry     */

	__u64 flush_period_ns;
	__u64 next_flush_ns;
	__u64 window_start_ns;

	struct caly_token_bucket log_tb;
	__u64 log_rate;
	__u64 log_burst;
	__u64 lost_reported;           /* c->st.lost already accounted for   */

	int min_level;

	caly_log_fn log;
	void *log_user;
	events_cb cb;
	void *user;

	struct events_stats st;

	unsigned int consumed;         /* records seen in the current poll   */

	pthread_mutex_t lock;
	int lock_ready;
};

/* -------------------------------------------------------------------------
 * Small internals
 * ------------------------------------------------------------------------- */

static void ev_lock(struct events_ctx *c)
{
	if (c->lock_ready)
		(void)pthread_mutex_lock(&c->lock);
}

static void ev_unlock(struct events_ctx *c)
{
	if (c->lock_ready)
		(void)pthread_mutex_unlock(&c->lock);
}

/* Emits a finished line. Never called with the context lock held. */
static void ev_log(struct events_ctx *c, int level, const char *fmt, ...)
{
	char buf[EV_LINE_MAX];
	va_list ap;

	if (!c || !c->log || level > c->min_level)
		return;

	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	buf[sizeof(buf) - 1] = '\0';
	c->log(c->log_user, level, buf);
}

static unsigned int ev_pow2_ceil(unsigned int v, unsigned int max)
{
	unsigned int p = 1;

	if (v == 0)
		return 1;
	while (p < v && p < max)
		p <<= 1;
	return p > max ? max : p;
}

static void ev_addr_str(char *buf, size_t cap, __u32 family, const __u32 *a)
{
	if (cap == 0)
		return;
	buf[0] = '\0';

	if (family == CALY_AF_INET) {
		struct in_addr in;

		memset(&in, 0, sizeof(in));
		in.s_addr = a[0];
		if (!inet_ntop(AF_INET, &in, buf, (socklen_t)cap))
			(void)snprintf(buf, cap, "0.0.0.0");
	} else if (family == CALY_AF_INET6) {
		struct in6_addr in6;

		memset(&in6, 0, sizeof(in6));
		memcpy(&in6, a, 16);
		if (!inet_ntop(AF_INET6, &in6, buf, (socklen_t)cap))
			(void)snprintf(buf, cap, "::");
	} else {
		(void)snprintf(buf, cap, "?");
	}
	buf[cap - 1] = '\0';
}

static const char *ev_proto_str(__u32 proto)
{
	switch (proto) {
	case CALY_IPPROTO_ICMP:   return "icmp";
	case CALY_IPPROTO_TCP:    return "tcp";
	case CALY_IPPROTO_UDP:    return "udp";
	case CALY_IPPROTO_ICMPV6: return "icmp6";
	case CALY_IPPROTO_GRE:    return "gre";
	case CALY_IPPROTO_ESP:    return "esp";
	case CALY_IPPROTO_AH:     return "ah";
	case CALY_IPPROTO_SCTP:   return "sctp";
	case CALY_IPPROTO_IPIP:   return "ipip";
	case CALY_IPPROTO_IPV6:   return "ip6ip";
	default:                  return "proto";
	}
}

/* Severity of a (reason, verdict) pair on the CALY_LOG_* ladder. */
static int ev_level_of(__u32 reason, __u32 verdict)
{
	switch (reason) {
	case STAT_BAN_ADDED:
	case STAT_BAN_ESCALATED:
	case STAT_BAN_FULL:
	case STAT_CT_FULL:
	case STAT_MAP_FULL_RATE:
	case STAT_MAP_FULL_SCAN:
	case STAT_MAP_FULL_SRCSTAT:
	case STAT_EVENT_LOST:
	case STAT_TAILCALL_FAIL:
	case STAT_SCRATCH_FAIL:
	case STAT_CONFIG_MISSING:
		return CALY_LOG_WARN;
	default:
		break;
	}
	if (verdict == CALY_VERDICT_DROP || verdict == CALY_VERDICT_MONITOR)
		return CALY_LOG_INFO;
	return CALY_LOG_DEBUG;
}

/* -------------------------------------------------------------------------
 * Validation
 * ------------------------------------------------------------------------- */

int events_validate(const void *data, __u32 size, struct event *out)
{
	struct event ev;

	if (!data || !out)
		return -EINVAL;

	/* A record shorter than the fixed 88-byte layout is truncated. A
	 * longer one would come from a newer dataplane whose extra fields we
	 * do not understand, which the version check below rejects anyway. */
	if (size < (__u32)sizeof(ev))
		return -EBADMSG;

	memcpy(&ev, data, sizeof(ev));

	if (ev.version != (__u8)CALY_ABI_VERSION_MAJOR)
		return -EPROTO;

	if (ev.reason >= (__u32)STAT_MAX)
		return -EINVAL;
	if (ev.verdict >= (__u32)CALY_VERDICT_MAX)
		return -EINVAL;
	if (ev.family != CALY_AF_INET && ev.family != CALY_AF_INET6)
		return -EINVAL;
	if (ev.mode >= (__u8)FW_MODE_MAX)
		return -EINVAL;

	/* An IPv4 event must not carry stale words in the upper 96 bits: the
	 * dataplane zeroes them, so anything else means we are decoding a
	 * record that was not produced by a matching object. */
	if (ev.family == CALY_AF_INET &&
	    (ev.saddr[1] | ev.saddr[2] | ev.saddr[3] |
	     ev.daddr[1] | ev.daddr[2] | ev.daddr[3]) != 0)
		return -EINVAL;

	*out = ev;
	return 0;
}

/* -------------------------------------------------------------------------
 * Formatting
 * ------------------------------------------------------------------------- */

int events_format(const struct event *ev, char *buf, size_t cap)
{
	char s[EV_ADDR_MAX], d[EV_ADDR_MAX], ttl[40];
	int n;

	if (!ev || !buf || cap == 0)
		return -EINVAL;

	ev_addr_str(s, sizeof(s), ev->family, ev->saddr);
	ev_addr_str(d, sizeof(d), ev->family, ev->daddr);

	ttl[0] = '\0';
	if (ev->ban_ttl_ns)
		(void)snprintf(ttl, sizeof(ttl), " ban_ttl=%llus",
			       (unsigned long long)(ev->ban_ttl_ns /
						    CALY_NSEC_PER_SEC));

	n = snprintf(buf, cap,
		     "%s %s %s:%u -> %s:%u %s len=%u flags=0x%02x val=%llu"
		     "%s if=%u mode=%s",
		     caly_verdict_str(ev->verdict),
		     stat_reason_str(ev->reason),
		     s, (unsigned int)ntohs(ev->sport),
		     d, (unsigned int)ntohs(ev->dport),
		     ev_proto_str(ev->proto),
		     (unsigned int)ev->pkt_len,
		     (unsigned int)(ev->tcp_flags & 0xFFu),
		     (unsigned long long)ev->value,
		     ttl,
		     (unsigned int)ev->ifindex,
		     fw_mode_str(ev->mode));

	if (n < 0) {
		buf[0] = '\0';
		return -EIO;
	}
	if ((size_t)n >= cap) {
		buf[cap - 1] = '\0';
		return (int)(cap - 1);
	}
	return n;
}

/* -------------------------------------------------------------------------
 * Aggregation table
 * ------------------------------------------------------------------------- */

static __u32 ev_hash(const struct event *ev)
{
	__u32 h;

	h = caly_mix32(ev->saddr[0], 0x9E3779B9u);
	h ^= caly_mix32(ev->saddr[1] ^ ev->saddr[2] ^ ev->saddr[3],
			0x85EBCA6Bu);
	h ^= caly_mix32(ev->reason ^ (ev->family << 16), 0xC2B2AE35u);
	return h;
}

static int ev_agg_match(const struct ev_agg *a, const struct event *ev)
{
	return a->used && a->family == ev->family && a->reason == ev->reason &&
	       a->saddr[0] == ev->saddr[0] && a->saddr[1] == ev->saddr[1] &&
	       a->saddr[2] == ev->saddr[2] && a->saddr[3] == ev->saddr[3];
}

static void ev_agg_fold(struct ev_agg *a, const struct event *ev, __u64 now)
{
	if (!a->used) {
		memset(a, 0, sizeof(*a));
		a->used    = 1;
		a->family  = ev->family;
		a->reason  = ev->reason;
		a->verdict = ev->verdict;
		a->proto   = ev->proto;
		a->ifindex = ev->ifindex;
		a->sport   = ev->sport;
		a->dport   = ev->dport;
		a->first_ns = now;
		memcpy(a->saddr, ev->saddr, sizeof(a->saddr));
		memcpy(a->daddr, ev->daddr, sizeof(a->daddr));
	} else if (a->dport != ev->dport) {
		a->dport = ev->dport;
		if (a->dport_changes < 0xFFFFFFFFu)
			a->dport_changes++;
	}

	a->count++;
	a->bytes += ev->pkt_len;
	a->last_ns = now;
	a->mode = ev->mode;
	a->tcp_flags = ev->tcp_flags;
	if (ev->value > a->value_max)
		a->value_max = ev->value;
	if (ev->ban_ttl_ns > a->ban_ttl_max)
		a->ban_ttl_max = ev->ban_ttl_ns;
	/* A drop verdict outranks a pass in the summary. */
	if (ev->verdict == CALY_VERDICT_DROP)
		a->verdict = CALY_VERDICT_DROP;
}

/* Caller holds the lock. */
static void ev_agg_add(struct events_ctx *c, const struct event *ev, __u64 now)
{
	unsigned int idx = ev_hash(ev) & c->agg_mask;
	unsigned int i;

	for (i = 0; i < EV_PROBE_MAX; i++) {
		struct ev_agg *a = &c->agg[(idx + i) & c->agg_mask];

		if (ev_agg_match(a, ev)) {
			ev_agg_fold(a, ev, now);
			return;
		}
		if (!a->used) {
			ev_agg_fold(a, ev, now);
			c->agg_live++;
			return;
		}
	}

	/* Congested neighbourhood. Fold into the spill slot rather than
	 * evicting somebody or growing the table: the totals stay honest
	 * while only the per-source detail degrades. */
	c->st.agg_overflow++;
	ev_agg_fold(&c->spill, ev, now);
}

/*
 * Copy the `want` highest-count buckets into c->sel. Caller holds the lock.
 * Returns how many were selected.
 */
static unsigned int ev_agg_select(struct events_ctx *c, unsigned int want)
{
	unsigned int got = 0;
	unsigned int i, k;

	for (k = 0; k < want; k++) {
		struct ev_agg *best = NULL;

		for (i = 0; i < c->agg_slots; i++) {
			struct ev_agg *a = &c->agg[i];

			if (!a->used || a->emitted)
				continue;
			if (!best || a->count > best->count)
				best = a;
		}
		if (!best)
			break;
		best->emitted = 1;
		c->sel[got++] = *best;
	}
	return got;
}

/* -------------------------------------------------------------------------
 * Flush
 * ------------------------------------------------------------------------- */

static void ev_flush(struct events_ctx *c, __u64 now)
{
	struct ev_agg spill;
	char extra[160];
	__u64 total = 0, window_ns, lost_delta = 0, suppressed = 0;
	unsigned int sources, n = 0, i;

	ev_lock(c);

	if (c->flushing) {
		/* Another caller owns c->sel; skip rather than corrupt it. */
		ev_unlock(c);
		return;
	}
	c->flushing = 1;

	sources = c->agg_live;
	for (i = 0; i < c->agg_slots; i++)
		if (c->agg[i].used)
			total += c->agg[i].count;
	spill = c->spill;
	total += spill.count;

	window_ns = (now > c->window_start_ns) ? now - c->window_start_ns : 0;

	if (c->st.lost > c->lost_reported) {
		lost_delta = c->st.lost - c->lost_reported;
		c->lost_reported = c->st.lost;
	}

	if (total)
		n = ev_agg_select(c, c->top_report);

	/* Charge the rate limiter for the lines we are about to print. */
	for (i = 0; i < n; i++) {
		if (!caly_tb_consume(&c->log_tb, now, c->log_rate,
				     c->log_burst, 1)) {
			suppressed = (__u64)(n - i);
			n = i;
			break;
		}
	}
	c->st.suppressed += suppressed;
	c->st.logged += n;
	c->st.flushes++;
	c->st.last_flush_ns = now;

	/* Reset the window before dropping the lock so intake can continue
	 * while we format. */
	memset(c->agg, 0, (size_t)c->agg_slots * sizeof(*c->agg));
	memset(&c->spill, 0, sizeof(c->spill));
	c->agg_live = 0;
	c->window_start_ns = now;
	c->next_flush_ns = now + c->flush_period_ns;

	ev_unlock(c);

	if (total == 0)
		goto done;

	extra[0] = '\0';
	if (suppressed || lost_delta || spill.count)
		(void)snprintf(extra, sizeof(extra),
			       " (suppressed=%llu lost=%llu overflow=%llu)",
			       (unsigned long long)suppressed,
			       (unsigned long long)lost_delta,
			       (unsigned long long)spill.count);

	ev_log(c, CALY_LOG_INFO,
	       "events: %llu in %llu.%03llus from %u source(s), reported %u%s",
	       (unsigned long long)total,
	       (unsigned long long)(window_ns / CALY_NSEC_PER_SEC),
	       (unsigned long long)((window_ns % CALY_NSEC_PER_SEC) /
				    CALY_NSEC_PER_MSEC),
	       sources, n, extra);

	for (i = 0; i < n; i++) {
		const struct ev_agg *a = &c->sel[i];
		char s[EV_ADDR_MAX], d[EV_ADDR_MAX], ttl[40];

		ev_addr_str(s, sizeof(s), a->family, a->saddr);
		ev_addr_str(d, sizeof(d), a->family, a->daddr);

		ttl[0] = '\0';
		if (a->ban_ttl_max)
			(void)snprintf(ttl, sizeof(ttl), " ban_ttl=%llus",
				       (unsigned long long)(a->ban_ttl_max /
							    CALY_NSEC_PER_SEC));

		ev_log(c, ev_level_of(a->reason, a->verdict),
		       "  %s %s %s -> %s %s dport=%u n=%llu bytes=%llu "
		       "peak=%llu dport_changes=%u if=%u mode=%s%s",
		       caly_verdict_str(a->verdict),
		       stat_reason_str(a->reason), s, d,
		       ev_proto_str(a->proto),
		       (unsigned int)ntohs(a->dport),
		       (unsigned long long)a->count,
		       (unsigned long long)a->bytes,
		       (unsigned long long)a->value_max,
		       a->dport_changes,
		       (unsigned int)a->ifindex,
		       fw_mode_str(a->mode), ttl);
	}

done:
	ev_lock(c);
	c->flushing = 0;
	ev_unlock(c);
}

/* -------------------------------------------------------------------------
 * Record intake
 * ------------------------------------------------------------------------- */

static void ev_record(struct events_ctx *c, const void *data, __u32 size)
{
	struct event ev;
	__u64 now;
	int rc;

	rc = events_validate(data, size, &ev);

	ev_lock(c);
	c->st.received++;
	if (rc != 0) {
		if (rc == -EBADMSG)
			c->st.invalid_size++;
		else if (rc == -EPROTO)
			c->st.invalid_version++;
		else
			c->st.invalid_field++;
		ev_unlock(c);
		return;
	}
	ev_unlock(c);

	now = caly_mono_ns();

	ev_lock(c);
	c->st.accepted++;
	c->st.by_reason[ev.reason]++;
	c->st.by_verdict[ev.verdict]++;
	c->st.last_event_ts_ns = ev.ts_ns;
	ev_agg_add(c, &ev, now);
	c->st.agg_live = c->agg_live;
	ev_unlock(c);

	c->consumed++;

	/* The hook runs outside the lock so a slow consumer cannot stall the
	 * exporter, and so it may safely call events_stats_get(). */
	if (c->cb)
		c->cb(c->user, &ev);
}

static void ev_perf_sample(void *ctx, int cpu, void *data, __u32 size)
{
	(void)cpu;
	ev_record((struct events_ctx *)ctx, data, size);
}

static void ev_perf_lost(void *ctx, int cpu, __u64 cnt)
{
	struct events_ctx *c = ctx;

	(void)cpu;
	ev_lock(c);
	c->st.lost += cnt;
	ev_unlock(c);
}

#if CALY_HAVE_RINGBUF
static int ev_rb_sample(void *ctx, void *data, size_t size)
{
	if (size > 0xFFFFFFFFull)
		return 0;
	ev_record((struct events_ctx *)ctx, data, (__u32)size);
	return 0;
}
#endif

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

int events_init(struct events_ctx **out, const struct events_cfg *cfg)
{
	struct events_ctx *c;
	unsigned int slots, pages, top, flush_ms;
	__u64 now;
	int err;

	if (!out || !cfg)
		return -EINVAL;
	*out = NULL;

	if (cfg->rb_fd < 0 && cfg->perf_fd < 0)
		return -EINVAL;

	slots = cfg->agg_slots ? cfg->agg_slots : EVENTS_AGG_SLOTS_DEFAULT;
	slots = ev_pow2_ceil(slots, EVENTS_AGG_SLOTS_MAX);

	pages = cfg->pages ? cfg->pages : EVENTS_PAGES_DEFAULT;
	pages = ev_pow2_ceil(pages, EVENTS_PAGES_MAX);

	top = cfg->top_report ? cfg->top_report : EVENTS_TOP_REPORT_DEFAULT;
	if (top > EVENTS_TOP_REPORT_MAX)
		top = EVENTS_TOP_REPORT_MAX;
	/* Selection is O(slots * top); keep the per-flush work bounded. */
	while (top > 1 && (unsigned long)top * (unsigned long)slots >
			  (unsigned long)EV_WORK_BUDGET)
		top--;

	flush_ms = cfg->flush_ms ? cfg->flush_ms : EVENTS_FLUSH_MS_DEFAULT;
	if (flush_ms < EVENTS_FLUSH_MS_MIN)
		flush_ms = EVENTS_FLUSH_MS_MIN;
	if (flush_ms > EVENTS_FLUSH_MS_MAX)
		flush_ms = EVENTS_FLUSH_MS_MAX;

	c = calloc(1, sizeof(*c));
	if (!c)
		return -ENOMEM;

	c->epfd = -1;
	c->agg_slots  = slots;
	c->agg_mask   = slots - 1u;
	c->top_report = top;
	c->flush_period_ns = (__u64)flush_ms * CALY_NSEC_PER_MSEC;
	c->min_level = (cfg->min_level < 0) ? CALY_LOG_INFO : cfg->min_level;
	if (c->min_level > CALY_LOG_TRACE)
		c->min_level = CALY_LOG_TRACE;
	c->log      = cfg->log;
	c->log_user = cfg->log_user;
	c->cb       = cfg->on_event;
	c->user     = cfg->user;

	/* rate 0 means "no ceiling": caly_tb_consume() treats a zero rate as a
	 * disabled bucket and always reports conforming. */
	c->log_rate  = (__u64)cfg->max_log_pps;
	c->log_burst = c->log_rate < 4 ? 4 : c->log_rate;

	c->agg = calloc(slots, sizeof(*c->agg));
	c->sel = calloc(top, sizeof(*c->sel));
	if (!c->agg || !c->sel) {
		free(c->agg);
		free(c->sel);
		free(c);
		return -ENOMEM;
	}

	if (pthread_mutex_init(&c->lock, NULL) == 0)
		c->lock_ready = 1;

	now = caly_mono_ns();
	c->window_start_ns = now;
	c->next_flush_ns = now + c->flush_period_ns;
	caly_tb_init(&c->log_tb, now, c->log_burst);

	errno = 0;

	/* Open every transport the caller handed us. The ring buffer and the
	 * perf array are consumed CONCURRENTLY, not as alternatives: the
	 * dataplane's tail-called SYN-proxy and tc programs emit their events
	 * only to the perf array, so a ring-only reader would silently miss
	 * them. Both callbacks funnel through ev_record(), so aggregation,
	 * rate limiting and events_stats stay unified across the two sinks. */
#if CALY_HAVE_RINGBUF
	if (cfg->rb_fd >= 0) {
		c->rb = ring_buffer__new(cfg->rb_fd, ev_rb_sample, c, NULL);
		if (!c->rb || libbpf_get_error(c->rb))
			c->rb = NULL;
	}
#endif

	if (cfg->perf_fd >= 0) {
#if CALY_PB_MODERN
		c->pb = perf_buffer__new(cfg->perf_fd, pages, ev_perf_sample,
					 ev_perf_lost, c, NULL);
#else
		{
			struct perf_buffer_opts pbo;

			memset(&pbo, 0, sizeof(pbo));
			pbo.sample_cb = ev_perf_sample;
			pbo.lost_cb   = ev_perf_lost;
			pbo.ctx       = c;
			c->pb = perf_buffer__new(cfg->perf_fd, pages, &pbo);
		}
#endif
		if (!c->pb || libbpf_get_error(c->pb))
			c->pb = NULL;
	}

#if CALY_HAVE_RINGBUF
	if (c->rb && c->pb)
		c->backend = EVENTS_BACKEND_BOTH;
	else if (c->rb)
		c->backend = EVENTS_BACKEND_RINGBUF;
	else
#endif
	if (c->pb)
		c->backend = EVENTS_BACKEND_PERF;

	if (c->backend == EVENTS_BACKEND_NONE) {
		err = errno ? -errno : -ENOTSUP;
		events_free(c);
		return err;
	}

#if CALY_PB_MODERN && CALY_HAVE_RINGBUF
	/* Both transports live: fold their epoll fds into one epoll instance so
	 * events_pollfd() can still hand the daemon a single descriptor to
	 * sleep on that wakes for EITHER sink. If any step fails we leave
	 * c->epfd == -1; events_pollfd() then reports -1 and the caller falls
	 * back to timeout-driven events_poll(), which is already a supported
	 * mode (see events.h). */
	if (c->rb && c->pb) {
		int rfd = ring_buffer__epoll_fd(c->rb);
		int pfd = perf_buffer__epoll_fd(c->pb);

		if (rfd >= 0 && pfd >= 0) {
			c->epfd = epoll_create1(EPOLL_CLOEXEC);
			if (c->epfd >= 0) {
				struct epoll_event ee;
				int ok = 1;

				memset(&ee, 0, sizeof(ee));
				ee.events = EPOLLIN;
				ee.data.fd = rfd;
				if (epoll_ctl(c->epfd, EPOLL_CTL_ADD, rfd,
					      &ee) != 0)
					ok = 0;
				ee.data.fd = pfd;
				if (ok && epoll_ctl(c->epfd, EPOLL_CTL_ADD, pfd,
						    &ee) != 0)
					ok = 0;
				if (!ok) {
					(void)close(c->epfd);
					c->epfd = -1;
				}
			}
		}
	}
#endif

	c->st.backend = (__u32)c->backend;
	*out = c;
	return 0;
}

void events_free(struct events_ctx *c)
{
	if (!c)
		return;
	if (c->epfd >= 0)
		(void)close(c->epfd);
#if CALY_HAVE_RINGBUF
	if (c->rb)
		ring_buffer__free(c->rb);
#endif
	if (c->pb)
		perf_buffer__free(c->pb);
	if (c->lock_ready)
		(void)pthread_mutex_destroy(&c->lock);
	free(c->agg);
	free(c->sel);
	free(c);
}

int events_backend(const struct events_ctx *c)
{
	return c ? c->backend : EVENTS_BACKEND_NONE;
}

const char *events_backend_str(const struct events_ctx *c)
{
	switch (events_backend(c)) {
	case EVENTS_BACKEND_PERF:    return "perf";
	case EVENTS_BACKEND_RINGBUF: return "ringbuf";
	case EVENTS_BACKEND_BOTH:    return "ringbuf+perf";
	default:                     return "none";
	}
}

int events_pollfd(const struct events_ctx *c)
{
	if (!c)
		return -1;
#if CALY_PB_MODERN
#if CALY_HAVE_RINGBUF
	/* Both transports live: the combined epoll fd wakes for either sink.
	 * It is -1 when it could not be built, which correctly tells the caller
	 * to poll on a timeout instead of sleeping on a descriptor. */
	if (c->rb && c->pb)
		return c->epfd;
	if (c->rb)
		return ring_buffer__epoll_fd(c->rb);
#endif
	if (c->pb)
		return perf_buffer__epoll_fd(c->pb);
#endif
	/* libbpf too old to expose the epoll fd: the caller must use
	 * events_poll() with a timeout instead of sleeping on an fd. */
	return -1;
}

/* -------------------------------------------------------------------------
 * Polling
 * ------------------------------------------------------------------------- */

void events_flush(struct events_ctx *c)
{
	if (!c)
		return;
	ev_flush(c, caly_mono_ns());
}

void events_tick(struct events_ctx *c)
{
	__u64 now;
	int due;

	if (!c)
		return;

	now = caly_mono_ns();
	ev_lock(c);
	due = (now >= c->next_flush_ns);
	ev_unlock(c);

	if (due)
		ev_flush(c, now);
}

int events_poll(struct events_ctx *c, int timeout_ms)
{
	int rc;

	if (!c)
		return -EINVAL;
	if (timeout_ms < 0)
		timeout_ms = 0;

	c->consumed = 0;

#if CALY_HAVE_RINGBUF
	if (c->rb && c->pb) {
		/* Both transports live. Drain each into ev_record(); c->consumed
		 * (bumped there) is the unified record count, so only the SIGN
		 * of rc matters below. */
		int rrb, rpb;

#if CALY_PB_MODERN
		if (c->epfd >= 0 && timeout_ms > 0) {
			/* Block on the combined epoll so we wake for whichever
			 * sink has data, then drain both without blocking. */
			struct epoll_event evs[2];
			int nfd;

			do {
				nfd = epoll_wait(c->epfd, evs,
						 (int)(sizeof(evs) /
						       sizeof(evs[0])),
						 timeout_ms);
			} while (nfd < 0 && errno == EINTR);

			rrb = ring_buffer__poll(c->rb, 0);
			rpb = perf_buffer__poll(c->pb, 0);
		} else
#endif
		{
			/* No combined epoll (old libbpf, or it could not be
			 * built): give the ring buffer the blocking wait and
			 * drain the perf array without blocking. */
			rrb = ring_buffer__poll(c->rb, timeout_ms);
			rpb = perf_buffer__poll(c->pb, 0);
		}
		rc = (rrb < 0) ? rrb : rpb;
	} else if (c->rb) {
		rc = ring_buffer__poll(c->rb, timeout_ms);
	} else
#endif
	if (c->pb)
		rc = perf_buffer__poll(c->pb, timeout_ms);
	else
		return -ENOTSUP;

	events_tick(c);

	if (rc < 0) {
		/* A signal during the wait is normal in a daemon that handles
		 * SIGTERM/SIGHUP; it is not an event-pipeline failure. */
		if (rc == -EINTR)
			return (int)c->consumed;
		return rc;
	}
	return (int)c->consumed;
}

int events_next_timeout_ms(struct events_ctx *c)
{
	__u64 now, next, period;
	unsigned long long ms;

	if (!c)
		return 1000;

	now = caly_mono_ns();
	ev_lock(c);
	next = c->next_flush_ns;
	period = c->flush_period_ns;
	ev_unlock(c);

	if (next <= now)
		return 0;

	ms = (unsigned long long)((next - now) / CALY_NSEC_PER_MSEC);
	if (ms > period / CALY_NSEC_PER_MSEC)
		ms = period / CALY_NSEC_PER_MSEC;
	if (ms > 60000ull)
		ms = 60000ull;
	return (int)ms;
}

/* -------------------------------------------------------------------------
 * Statistics
 * ------------------------------------------------------------------------- */

int events_stats_get(struct events_ctx *c, struct events_stats *out)
{
	if (!c || !out)
		return -EINVAL;
	ev_lock(c);
	c->st.agg_live = c->agg_live;
	c->st.backend = (__u32)c->backend;
	*out = c->st;
	ev_unlock(c);
	return 0;
}

void events_stats_reset(struct events_ctx *c)
{
	if (!c)
		return;
	ev_lock(c);
	memset(&c->st, 0, sizeof(c->st));
	c->st.backend = (__u32)c->backend;
	c->lost_reported = 0;
	ev_unlock(c);
}
