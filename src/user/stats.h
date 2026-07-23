/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/stats.h
 *
 * Periodic sampling of the per-CPU statistics arrays (caly_stats,
 * caly_stats_b, caly_global) into absolute snapshots and per-interval
 * deltas, a bounded ring of recent deltas for trend detection, and a
 * human-readable dump.
 *
 * DESIGN NOTES
 *
 *  - The three maps are BPF_MAP_TYPE_PERCPU_ARRAY of __u64. A lookup returns
 *    one __u64 per *possible* CPU, so the read buffer is sized from
 *    libbpf_num_possible_cpus(), never from the online CPU count.
 *
 *  - Rates are computed from the measured wall interval between two
 *    successive samples, not from the nominal stats_interval_ms, because the
 *    daemon's loop is allowed to be late under load and a nominal divisor
 *    would then over-report.
 *
 *  - Timestamps are CLOCK_MONOTONIC, which is the same clock the dataplane's
 *    bpf_ktime_get_ns() reads. Ban expiry deadlines produced by the dataplane
 *    are therefore directly comparable to caly_mono_ns() here. Do NOT use
 *    CLOCK_BOOTTIME or CLOCK_REALTIME for that comparison.
 *
 *  - Everything is bounded: the ring depth is fixed at init, no per-sample
 *    allocation happens, and no accessor can allocate.
 *
 * THREADING
 *  All entry points are serialised by an internal mutex, so the daemon may
 *  sample from its main loop while the Prometheus exporter or the control
 *  socket reads from another thread. Only mutex operations are used (no
 *  pthread_create), which resolves out of libc on both glibc and musl even
 *  when the link line omits -pthread.
 */

#ifndef CALY_USER_STATS_H
#define CALY_USER_STATS_H

/*
 * common.h compiles a different (smaller) surface when CALY_USERSPACE is not
 * defined. If some translation unit pulled it in first without the define,
 * the string helpers this module needs are simply absent and the failure mode
 * is a confusing link error much later. Catch it here instead.
 */
#if defined(__CALY_ANTI_COMMON_H) && !defined(CALY_USERSPACE)
#error "common.h included without CALY_USERSPACE; include a src/user/*.h first"
#endif

#ifndef CALY_USERSPACE
#define CALY_USERSPACE 1
#endif

#include <stddef.h>
#include <stdio.h>
#include <time.h>
#include <linux/types.h>

#include "../bpf/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Shared userspace primitives.
 *
 * These are duplicated (identically, behind one-shot guards) in every
 * src/user/*.h that needs them so that no header in this component depends on
 * another. Including any two of them in either order is well defined.
 * ------------------------------------------------------------------------- */

#ifndef CALY_LOG_FN_DEFINED
#define CALY_LOG_FN_DEFINED

/* Levels match fw_config.log_level: 0 = err .. 4 = trace. */
#define CALY_LOG_ERR    0
#define CALY_LOG_WARN   1
#define CALY_LOG_INFO   2
#define CALY_LOG_DEBUG  3
#define CALY_LOG_TRACE  4

/*
 * Logging sink. Deliberately NOT variadic: the caller formats into a bounded
 * stack buffer and hands over a finished NUL-terminated line, so a sink
 * implemented on top of syslog(), journald or a file cannot be handed a
 * format string that came from the network.
 */
typedef void (*caly_log_fn)(void *user, int level, const char *msg);

#endif /* CALY_LOG_FN_DEFINED */

#ifndef CALY_TIME_HELPERS_DEFINED
#define CALY_TIME_HELPERS_DEFINED

/* CLOCK_MONOTONIC: the same base as bpf_ktime_get_ns(). */
static inline __u64 caly_mono_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (__u64)ts.tv_sec * CALY_NSEC_PER_SEC + (__u64)ts.tv_nsec;
}

/* CLOCK_REALTIME: for human-facing timestamps only. Never for expiry math. */
static inline __u64 caly_wall_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
		return 0;
	return (__u64)ts.tv_sec * CALY_NSEC_PER_SEC + (__u64)ts.tv_nsec;
}

#endif /* CALY_TIME_HELPERS_DEFINED */

/* -------------------------------------------------------------------------
 * Sampling
 * ------------------------------------------------------------------------- */

#define STATS_RING_DEFAULT   64u
#define STATS_RING_MIN        2u
#define STATS_RING_MAX     1024u
#define STATS_EWMA_SHIFT_DEFAULT 3u   /* alpha = 1/8 */
#define STATS_EWMA_SHIFT_MAX     12u

/* Absolute counters as read from the maps at one instant. */
struct stats_snapshot {
	__u64 mono_ns;                 /* CLOCK_MONOTONIC at read time      */
	__u64 wall_ns;                 /* CLOCK_REALTIME at read time       */
	__u64 pkts[STAT_MAX];          /* caly_stats,   summed over CPUs    */
	__u64 bytes[STAT_MAX];         /* caly_stats_b, summed over CPUs    */
	__u64 gauges[CALY_G_MAX];      /* caly_global,  summed over CPUs    */
};

/* Difference between two successive snapshots. */
struct stats_delta {
	__u64 mono_ns;                 /* end of the interval               */
	__u64 wall_ns;
	__u64 interval_ns;             /* > 0 for every delta in the ring   */
	__u64 pkts[STAT_MAX];
	__u64 bytes[STAT_MAX];
	__u64 gauges[CALY_G_MAX];
};

/* Bookkeeping about the sampler itself; exported as metrics. */
struct stats_meta {
	__u64 samples_taken;
	__u64 read_errors;             /* map lookups that failed           */
	__u64 counter_resets;          /* counter went backwards (reload)   */
	__u64 last_mono_ns;
	__u64 last_wall_ns;
	__u64 last_interval_ns;
	__u32 ncpu;
	__u32 ring_depth;
	__u32 ring_count;
	__u32 have_baseline;
};

/* Which series a trend query refers to. */
#define STATS_SERIES_PKTS    0
#define STATS_SERIES_BYTES   1
#define STATS_SERIES_GAUGE   2

#define STATS_TREND_F_RISING   (1u << 0)
#define STATS_TREND_F_FALLING  (1u << 1)
#define STATS_TREND_F_SPIKE    (1u << 2)  /* cur >= 4x the window mean  */
#define STATS_TREND_F_QUIET    (1u << 3)  /* the whole window is zero   */

struct stats_trend {
	__u64 cur;                     /* most recent rate, units/sec       */
	__u64 avg;
	__u64 min;
	__u64 max;
	__u64 ewma;
	__s64 slope;                   /* units/sec, per second             */
	__u32 samples;                 /* samples actually considered       */
	__u32 flags;                   /* STATS_TREND_F_*                   */
};

struct stats_cfg {
	int fd_pkts;                   /* caly_stats   fd, -1 to skip       */
	int fd_bytes;                  /* caly_stats_b fd, -1 to skip       */
	int fd_global;                 /* caly_global  fd, -1 to skip       */
	unsigned int ring_depth;       /* 0 -> STATS_RING_DEFAULT           */
	unsigned int ewma_shift;       /* 0 -> STATS_EWMA_SHIFT_DEFAULT     */
	caly_log_fn log;               /* may be NULL                       */
	void *log_user;
};

struct stats_ctx;                  /* opaque */

/*
 * Create the sampler. Map fds are borrowed, never closed by this module: the
 * loader owns them and may pin/replace them across a reload (see
 * stats_set_fds()).
 *
 * Returns 0 on success, -errno on failure. *out is only written on success.
 */
int  stats_init(struct stats_ctx **out, const struct stats_cfg *cfg);
void stats_free(struct stats_ctx *ctx);

/*
 * Swap in a new set of map fds after a reload. The accumulated history is
 * kept but the baseline is dropped, so the first sample after the swap
 * produces no delta rather than a fabricated spike.
 */
void stats_set_fds(struct stats_ctx *ctx, int fd_pkts, int fd_bytes,
		   int fd_global);
void stats_set_log(struct stats_ctx *ctx, caly_log_fn log, void *log_user);

/*
 * Read all three maps, store the absolute snapshot, and push one delta into
 * the ring. The very first call establishes the baseline and pushes nothing.
 *
 * Returns 1 when a delta was produced, 0 when only a baseline was taken, and
 * -errno when the maps could not be read at all.
 */
int  stats_sample(struct stats_ctx *ctx);

/* Copy out the most recent absolute snapshot. -ENODATA before the first
 * successful stats_sample(). */
int  stats_latest(struct stats_ctx *ctx, struct stats_snapshot *out);

/* Copy out the most recent delta. -ENODATA until two samples exist. */
int  stats_latest_delta(struct stats_ctx *ctx, struct stats_delta *out);

/* back == 0 is the newest delta, back == 1 the one before it, and so on.
 * -ENODATA when fewer than back+1 deltas have been recorded. */
int  stats_history(struct stats_ctx *ctx, unsigned int back,
		   struct stats_delta *out);

int  stats_meta_get(struct stats_ctx *ctx, struct stats_meta *out);

/* Rate helpers. Pure functions over a delta; safe with interval_ns == 0. */
__u64 stats_rate_pkts(const struct stats_delta *d, __u32 reason);
__u64 stats_rate_bytes(const struct stats_delta *d, __u32 reason);
__u64 stats_rate_gauge(const struct stats_delta *d, __u32 gauge);

/*
 * Trend over the last `window` deltas (0 == the whole ring). `series` is one
 * of STATS_SERIES_*, `index` is an enum stat_reason or an enum caly_gauge.
 * Returns 0 on success, -EINVAL on a bad selector, -ENODATA when the ring is
 * empty.
 */
int  stats_trend_get(struct stats_ctx *ctx, int series, __u32 index,
		     unsigned int window, struct stats_trend *out);

/* -------------------------------------------------------------------------
 * Human-readable dump
 * ------------------------------------------------------------------------- */

#define STATS_DUMP_ZEROS      (1u << 0)  /* include all-zero rows         */
#define STATS_DUMP_NO_GAUGES  (1u << 1)
#define STATS_DUMP_DROPS_ONLY (1u << 2)  /* only stat_reason_is_drop()    */
#define STATS_DUMP_NO_HEADER  (1u << 3)
#define STATS_DUMP_TREND      (1u << 4)  /* append a short trend section  */

/*
 * Line sink for the dump. `line` is NUL terminated and includes its trailing
 * newline; `len` is strlen(line). Return non-zero to abort the dump early
 * (the return value is propagated).
 */
typedef int (*stats_line_fn)(void *user, const char *line, size_t len);

int  stats_dump_lines(struct stats_ctx *ctx, unsigned int flags,
		      stats_line_fn fn, void *user);
int  stats_dump(struct stats_ctx *ctx, FILE *f, unsigned int flags);

/*
 * Render into a caller-supplied buffer. Always NUL terminates when cap > 0.
 * Returns the number of bytes written excluding the NUL, or -E2BIG when the
 * output was truncated (the buffer still holds a valid, whole-line prefix).
 */
long stats_dump_buf(struct stats_ctx *ctx, unsigned int flags,
		    char *buf, size_t cap);

/*
 * Name of an enum caly_gauge value ("pkts", "bytes", "syn", ...). common.h
 * deliberately carries no gauge string table, so this is the single
 * definition every consumer (dump, Prometheus, control socket) shares.
 * Returns "unknown" for an out-of-range index; never NULL.
 */
const char *stats_gauge_str(__u32 gauge);

/* Format a byte count as e.g. "1.4G". `buf` must be at least 16 bytes. */
const char *stats_fmt_bytes(char *buf, size_t cap, __u64 v);
/* Format a plain count as e.g. "12.3k". `buf` must be at least 16 bytes. */
const char *stats_fmt_count(char *buf, size_t cap, __u64 v);

#ifdef __cplusplus
}
#endif

#endif /* CALY_USER_STATS_H */
