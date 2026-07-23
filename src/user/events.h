/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/events.h
 *
 * Consumer for struct event records produced by the dataplane.
 *
 * TRANSPORT
 *   Two back ends, chosen at RUNTIME by which map fd the loader hands over:
 *
 *     caly_events_rb  (BPF_MAP_TYPE_RINGBUF, 5.8+)  - enabled when the loader
 *         set CALY_F_CAP_RINGBUF. One shared buffer, no per-CPU duplication,
 *         lower latency.
 *
 *     caly_events     (BPF_MAP_TYPE_PERF_EVENT_ARRAY)  - the always-present
 *         channel. Works on every kernel this suite targets, including the
 *         RHEL 8 4.18 backports.
 *
 *   These are NOT alternatives to pick between. The dataplane's tail-called
 *   SYN-proxy XDP program and the tc_ingress/tc_egress programs emit their
 *   struct event records ONLY to the perf array caly_events, never to the
 *   ring buffer, even when CALY_F_CAP_RINGBUF is set. So whenever both fds
 *   are valid this consumer opens and drains BOTH transports concurrently
 *   and folds their records into one aggregation / rate-limit / stats
 *   pipeline; binding to just the ring buffer would silently drop every
 *   synproxy and tc event -- exactly the traffic that appears under attack.
 *   Pass rb_fd = -1 (or perf_fd = -1) to run a single transport on purpose.
 *
 *   The perf path copes with BOTH libbpf ABIs: the 1.x six argument
 *   perf_buffer__new() and the 0.x three argument form whose callbacks live
 *   inside struct perf_buffer_opts. The selection is a compile-time decision
 *   driven by <bpf/libbpf_version.h>.
 *
 * POLICY
 *   Raw events are firehose material: one packet per event under a flood
 *   would turn the log into the denial of service. Every record is therefore
 *   validated, folded into a bounded aggregation table keyed by
 *   (family, source address, reason), and only summarised lines are emitted,
 *   at most `max_log_pps` of them per second. Nothing here allocates per
 *   event and nothing grows without a compile-time or config-time bound.
 */

#ifndef CALY_USER_EVENTS_H
#define CALY_USER_EVENTS_H

#if defined(__CALY_ANTI_COMMON_H) && !defined(CALY_USERSPACE)
#error "common.h included without CALY_USERSPACE; include a src/user/*.h first"
#endif

#ifndef CALY_USERSPACE
#define CALY_USERSPACE 1
#endif

#include <stddef.h>
#include <time.h>
#include <linux/types.h>

#include "../bpf/common.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CALY_LOG_FN_DEFINED
#define CALY_LOG_FN_DEFINED

#define CALY_LOG_ERR    0
#define CALY_LOG_WARN   1
#define CALY_LOG_INFO   2
#define CALY_LOG_DEBUG  3
#define CALY_LOG_TRACE  4

typedef void (*caly_log_fn)(void *user, int level, const char *msg);

#endif /* CALY_LOG_FN_DEFINED */

#ifndef CALY_TIME_HELPERS_DEFINED
#define CALY_TIME_HELPERS_DEFINED

static inline __u64 caly_mono_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (__u64)ts.tv_sec * CALY_NSEC_PER_SEC + (__u64)ts.tv_nsec;
}

static inline __u64 caly_wall_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return 0;
	return (__u64)ts.tv_sec * CALY_NSEC_PER_SEC + (__u64)ts.tv_nsec;
}

#endif /* CALY_TIME_HELPERS_DEFINED */

/* -------------------------------------------------------------------------
 * Configuration
 * ------------------------------------------------------------------------- */

#define EVENTS_PAGES_DEFAULT       8u      /* per CPU, power of two          */
#define EVENTS_PAGES_MAX         512u
#define EVENTS_AGG_SLOTS_DEFAULT 1024u     /* rounded up to a power of two   */
#define EVENTS_AGG_SLOTS_MAX    65536u
#define EVENTS_FLUSH_MS_DEFAULT  1000u
#define EVENTS_FLUSH_MS_MIN       100u
#define EVENTS_FLUSH_MS_MAX     60000u
#define EVENTS_LOG_PPS_DEFAULT     20u
#define EVENTS_TOP_REPORT_DEFAULT  10u
#define EVENTS_TOP_REPORT_MAX     128u

#define EVENTS_BACKEND_NONE    0
#define EVENTS_BACKEND_PERF    1
#define EVENTS_BACKEND_RINGBUF 2
#define EVENTS_BACKEND_BOTH    3   /* ring buffer AND perf array, drained together */

/*
 * Optional per-record hook, invoked for every event that passes validation,
 * BEFORE aggregation. The daemon uses it to react to STAT_BAN_ADDED and
 * friends (mirror the ban into a threat feed, bump a gauge, ...).
 *
 * It runs inside the poll callback, so it must not block and must not call
 * back into this module.
 */
typedef void (*events_cb)(void *user, const struct event *ev);

struct events_cfg {
	int perf_fd;                   /* caly_events fd, -1 if unavailable  */
	int rb_fd;                     /* caly_events_rb fd, -1 to disable   */
	unsigned int pages;            /* perf pages per CPU; 0 -> default   */
	unsigned int agg_slots;        /* 0 -> EVENTS_AGG_SLOTS_DEFAULT      */
	unsigned int flush_ms;         /* aggregation window                 */
	unsigned int max_log_pps;      /* hard ceiling on emitted lines/sec  */
	unsigned int top_report;       /* buckets reported per flush         */
	/* Highest CALY_LOG_* level still emitted; lines above it are dropped
	 * before they reach the sink. Use -1 for the default (CALY_LOG_INFO);
	 * 0 restricts the module to errors only. */
	int min_level;
	caly_log_fn log;
	void *log_user;
	events_cb on_event;            /* may be NULL                        */
	void *user;
};

/* -------------------------------------------------------------------------
 * Observability
 * ------------------------------------------------------------------------- */

struct events_stats {
	__u64 received;                /* records handed over by the ring    */
	__u64 accepted;                /* passed every validation check      */
	__u64 invalid_size;
	__u64 invalid_version;         /* ABI major mismatch                 */
	__u64 invalid_field;           /* reason/verdict/family/mode garbage */
	__u64 lost;                    /* reported by the ring buffer        */
	__u64 logged;                  /* summary lines actually emitted     */
	__u64 suppressed;              /* lines dropped by the rate limiter  */
	__u64 agg_overflow;            /* events folded into the spill slot  */
	__u64 flushes;
	__u64 last_event_ts_ns;        /* bpf_ktime_get_ns of the last event */
	__u64 last_flush_ns;           /* CLOCK_MONOTONIC                    */
	__u64 by_reason[STAT_MAX];
	__u64 by_verdict[CALY_VERDICT_MAX];
	__u32 backend;                 /* EVENTS_BACKEND_*                   */
	__u32 agg_live;                /* buckets in use right now           */
};

struct events_ctx;                 /* opaque */

/*
 * Create the consumer. Returns 0, or -errno. Requires at least one of
 * cfg->rb_fd / cfg->perf_fd to be a valid fd. When both are valid both
 * transports are opened and drained together (backend EVENTS_BACKEND_BOTH);
 * see the TRANSPORT note above for why binding to only one loses events.
 */
int  events_init(struct events_ctx **out, const struct events_cfg *cfg);
void events_free(struct events_ctx *ctx);

/* EVENTS_BACKEND_* actually in use. */
int  events_backend(const struct events_ctx *ctx);
const char *events_backend_str(const struct events_ctx *ctx);

/*
 * Epoll fd suitable for the daemon's own poll()/epoll loop, or -1 when the
 * linked libbpf is too old to expose one. When it is -1 the daemon must call
 * events_poll() with a timeout instead of sleeping on the fd.
 */
int  events_pollfd(const struct events_ctx *ctx);

/*
 * Consume whatever is ready. timeout_ms == 0 drains without blocking.
 * Returns the number of records consumed (>= 0) or -errno. Also runs the
 * aggregation flush when the window has elapsed.
 */
int  events_poll(struct events_ctx *ctx, int timeout_ms);

/* Run only the periodic work (flush if due). Cheap; safe to call often. */
void events_tick(struct events_ctx *ctx);

/* Force an immediate aggregation flush, e.g. on SIGTERM before exit. */
void events_flush(struct events_ctx *ctx);

/* Milliseconds until the next flush is due; for the daemon's poll timeout. */
int  events_next_timeout_ms(struct events_ctx *ctx);

int  events_stats_get(struct events_ctx *ctx, struct events_stats *out);
void events_stats_reset(struct events_ctx *ctx);

/*
 * Render one event as a single human-readable line, e.g.
 *   "drop rate_pps 203.0.113.9:41234 -> 198.51.100.1:443 proto=6 len=1500"
 * Always NUL terminates. Returns the number of bytes written (excluding the
 * NUL) or a negative errno.
 */
int  events_format(const struct event *ev, char *buf, size_t cap);

/*
 * Validate a raw record exactly the way the consumer does. Exposed so the
 * control socket and the test harness apply identical rules.
 * Returns 0 when acceptable, or a negative errno (-EBADMSG on a short
 * record, -EPROTO on an ABI mismatch, -EINVAL on a field out of range).
 */
int  events_validate(const void *data, __u32 size, struct event *out);

#ifdef __cplusplus
}
#endif

#endif /* CALY_USER_EVENTS_H */
