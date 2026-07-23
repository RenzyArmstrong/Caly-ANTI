/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/stats.c
 *
 * Per-CPU statistics sampler, delta ring and human-readable dump.
 * See stats.h for the contract.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "stats.h"

#define STATS_LINE_MAX   256u
#define STATS_U64_MAX    0xFFFFFFFFFFFFFFFFULL

struct stats_ctx {
	int fd_pkts;
	int fd_bytes;
	int fd_global;

	int ncpu;
	__u64 *cpubuf;                 /* ncpu entries, 8 bytes each        */

	unsigned int ring_depth;
	unsigned int ring_head;        /* next slot to write                */
	unsigned int ring_count;
	struct stats_delta *ring;

	struct stats_snapshot cur;     /* last absolute read                */
	struct stats_snapshot scratch; /* staging for the read in progress  */
	int have_baseline;

	unsigned int ewma_shift;
	__u64 *ewma_pkts;              /* STAT_MAX rates, units/sec         */
	__u64 *ewma_bytes;             /* STAT_MAX rates                    */
	__u64 *ewma_gauge;             /* CALY_G_MAX rates                  */

	__u64 samples_taken;
	__u64 read_errors;
	__u64 counter_resets;

	caly_log_fn log;
	void *log_user;

	pthread_mutex_t lock;
	int lock_ready;
};

/* -------------------------------------------------------------------------
 * Small internals
 * ------------------------------------------------------------------------- */

static void st_lock(struct stats_ctx *c)
{
	if (c->lock_ready)
		(void)pthread_mutex_lock(&c->lock);
}

static void st_unlock(struct stats_ctx *c)
{
	if (c->lock_ready)
		(void)pthread_mutex_unlock(&c->lock);
}

static void st_log(struct stats_ctx *c, int level, const char *fmt, ...)
{
	char buf[STATS_LINE_MAX];
	va_list ap;

	if (!c || !c->log)
		return;

	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	buf[sizeof(buf) - 1] = '\0';
	c->log(c->log_user, level, buf);
}

/* rate = v * 1e9 / ns, without overflowing __u64 for large v. */
static __u64 st_rate(__u64 v, __u64 ns)
{
	if (ns == 0 || v == 0)
		return 0;
	if (v <= STATS_U64_MAX / CALY_NSEC_PER_SEC)
		return (v * CALY_NSEC_PER_SEC) / ns;
	return (v / ns) * CALY_NSEC_PER_SEC;
}

static __u64 st_ewma(__u64 old, __u64 nv, unsigned int shift)
{
	if (old == 0)
		return nv;
	if (nv >= old)
		return old + ((nv - old) >> shift);
	return old - ((old - nv) >> shift);
}

/* Newest delta is back == 0. Returns NULL when out of range. */
static const struct stats_delta *st_ring_at(const struct stats_ctx *c,
					    unsigned int back)
{
	unsigned int idx;

	if (back >= c->ring_count)
		return NULL;
	/* head is one past the newest entry, modulo depth. */
	idx = (c->ring_head + c->ring_depth - 1u - back) % c->ring_depth;
	return &c->ring[idx];
}

static __u64 st_delta_val(const struct stats_delta *d, int series, __u32 idx)
{
	switch (series) {
	case STATS_SERIES_PKTS:
		return idx < (__u32)STAT_MAX ? d->pkts[idx] : 0;
	case STATS_SERIES_BYTES:
		return idx < (__u32)STAT_MAX ? d->bytes[idx] : 0;
	case STATS_SERIES_GAUGE:
		return idx < (__u32)CALY_G_MAX ? d->gauges[idx] : 0;
	default:
		return 0;
	}
}

/*
 * Sum one per-CPU __u64 across all possible CPUs.
 *
 * Returns 0 on success (including "key absent", which is reported as zero),
 * -1 when the lookup failed for another reason. On failure *out is untouched
 * so the caller can carry the previous value forward: fabricating a zero
 * would turn the next interval into a bogus multi-billion-packet spike.
 */
static int st_read_percpu(struct stats_ctx *c, int fd, __u32 key, __u64 *out)
{
	__u64 sum = 0;
	int i;

	if (fd < 0) {
		*out = 0;
		return 0;
	}
	if (bpf_map_lookup_elem(fd, &key, c->cpubuf) != 0) {
		if (errno == ENOENT) {
			*out = 0;
			return 0;
		}
		return -1;
	}
	for (i = 0; i < c->ncpu; i++)
		sum += c->cpubuf[i];
	*out = sum;
	return 0;
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

int stats_init(struct stats_ctx **out, const struct stats_cfg *cfg)
{
	struct stats_ctx *c;
	unsigned int depth, shift;
	int ncpu;

	if (!out || !cfg)
		return -EINVAL;
	*out = NULL;

	if (cfg->fd_pkts < 0 && cfg->fd_bytes < 0 && cfg->fd_global < 0)
		return -EINVAL;

	ncpu = libbpf_num_possible_cpus();
	if (ncpu <= 0)
		return ncpu < 0 ? ncpu : -EINVAL;
	/* Sanity bound: a bogus value here would size a huge allocation. */
	if (ncpu > 4096)
		return -ERANGE;

	depth = cfg->ring_depth ? cfg->ring_depth : STATS_RING_DEFAULT;
	if (depth < STATS_RING_MIN)
		depth = STATS_RING_MIN;
	if (depth > STATS_RING_MAX)
		depth = STATS_RING_MAX;

	shift = cfg->ewma_shift ? cfg->ewma_shift : STATS_EWMA_SHIFT_DEFAULT;
	if (shift > STATS_EWMA_SHIFT_MAX)
		shift = STATS_EWMA_SHIFT_MAX;

	c = calloc(1, sizeof(*c));
	if (!c)
		return -ENOMEM;

	c->fd_pkts     = cfg->fd_pkts;
	c->fd_bytes    = cfg->fd_bytes;
	c->fd_global   = cfg->fd_global;
	c->ncpu        = ncpu;
	c->ring_depth  = depth;
	c->ewma_shift  = shift;
	c->log         = cfg->log;
	c->log_user    = cfg->log_user;

	c->cpubuf     = calloc((size_t)ncpu, sizeof(__u64));
	c->ring       = calloc(depth, sizeof(*c->ring));
	c->ewma_pkts  = calloc((size_t)STAT_MAX, sizeof(__u64));
	c->ewma_bytes = calloc((size_t)STAT_MAX, sizeof(__u64));
	c->ewma_gauge = calloc((size_t)CALY_G_MAX, sizeof(__u64));

	if (!c->cpubuf || !c->ring || !c->ewma_pkts || !c->ewma_bytes ||
	    !c->ewma_gauge) {
		stats_free(c);
		return -ENOMEM;
	}

	if (pthread_mutex_init(&c->lock, NULL) == 0)
		c->lock_ready = 1;

	*out = c;
	return 0;
}

void stats_free(struct stats_ctx *c)
{
	if (!c)
		return;
	if (c->lock_ready)
		(void)pthread_mutex_destroy(&c->lock);
	free(c->cpubuf);
	free(c->ring);
	free(c->ewma_pkts);
	free(c->ewma_bytes);
	free(c->ewma_gauge);
	free(c);
}

void stats_set_fds(struct stats_ctx *c, int fd_pkts, int fd_bytes,
		   int fd_global)
{
	if (!c)
		return;
	st_lock(c);
	c->fd_pkts  = fd_pkts;
	c->fd_bytes = fd_bytes;
	c->fd_global = fd_global;
	/* New maps start at zero; drop the baseline so the next sample does
	 * not synthesise a delta against the old object's counters. */
	c->have_baseline = 0;
	memset(&c->cur, 0, sizeof(c->cur));
	st_unlock(c);
}

void stats_set_log(struct stats_ctx *c, caly_log_fn log, void *log_user)
{
	if (!c)
		return;
	st_lock(c);
	c->log = log;
	c->log_user = log_user;
	st_unlock(c);
}

/* -------------------------------------------------------------------------
 * Sampling
 * ------------------------------------------------------------------------- */

static int st_read_all(struct stats_ctx *c, struct stats_snapshot *s,
		       const struct stats_snapshot *fallback)
{
	__u32 i;
	int fails = 0;
	int total = 0;

	s->mono_ns = caly_mono_ns();
	s->wall_ns = caly_wall_ns();

	for (i = 0; i < (__u32)STAT_MAX; i++) {
		total++;
		if (st_read_percpu(c, c->fd_pkts, i, &s->pkts[i]) != 0) {
			s->pkts[i] = fallback ? fallback->pkts[i] : 0;
			fails++;
		}
		total++;
		if (st_read_percpu(c, c->fd_bytes, i, &s->bytes[i]) != 0) {
			s->bytes[i] = fallback ? fallback->bytes[i] : 0;
			fails++;
		}
	}
	for (i = 0; i < (__u32)CALY_G_MAX; i++) {
		total++;
		if (st_read_percpu(c, c->fd_global, i, &s->gauges[i]) != 0) {
			s->gauges[i] = fallback ? fallback->gauges[i] : 0;
			fails++;
		}
	}

	if (fails)
		c->read_errors += (__u64)fails;

	/* Every single lookup failed: the maps are gone (object unloaded or
	 * fds closed under us). Report it rather than emitting a flat zero
	 * series that looks like "the attack stopped". */
	return (fails == total) ? -EIO : 0;
}

static __u64 st_sub(struct stats_ctx *c, __u64 now, __u64 then)
{
	if (now >= then)
		return now - then;
	/* Counters only move forward. A decrease means the map (or the whole
	 * BPF object) was replaced; treat the interval as empty. */
	c->counter_resets++;
	return 0;
}

int stats_sample(struct stats_ctx *c)
{
	struct stats_delta *d;
	struct stats_snapshot *s;
	__u64 interval;
	__u32 i;
	int rc;

	if (!c)
		return -EINVAL;

	st_lock(c);

	s = &c->scratch;
	memset(s, 0, sizeof(*s));

	rc = st_read_all(c, s, c->have_baseline ? &c->cur : NULL);
	if (rc != 0) {
		st_log(c, CALY_LOG_ERR,
		       "stats: all map reads failed (%s); sampler stalled",
		       strerror(errno ? errno : EIO));
		st_unlock(c);
		return rc;
	}

	c->samples_taken++;

	if (!c->have_baseline) {
		c->cur = *s;
		c->have_baseline = 1;
		st_unlock(c);
		return 0;
	}

	interval = (s->mono_ns > c->cur.mono_ns) ? s->mono_ns - c->cur.mono_ns
						 : 0;
	if (interval == 0) {
		/* Two samples inside the same nanosecond, or a clock that did
		 * not move. Refresh the absolute view, publish no delta. */
		c->cur = *s;
		st_unlock(c);
		return 0;
	}

	d = &c->ring[c->ring_head];
	memset(d, 0, sizeof(*d));
	d->mono_ns     = s->mono_ns;
	d->wall_ns     = s->wall_ns;
	d->interval_ns = interval;

	for (i = 0; i < (__u32)STAT_MAX; i++) {
		d->pkts[i]  = st_sub(c, s->pkts[i],  c->cur.pkts[i]);
		d->bytes[i] = st_sub(c, s->bytes[i], c->cur.bytes[i]);
		c->ewma_pkts[i]  = st_ewma(c->ewma_pkts[i],
					   st_rate(d->pkts[i], interval),
					   c->ewma_shift);
		c->ewma_bytes[i] = st_ewma(c->ewma_bytes[i],
					   st_rate(d->bytes[i], interval),
					   c->ewma_shift);
	}
	for (i = 0; i < (__u32)CALY_G_MAX; i++) {
		d->gauges[i] = st_sub(c, s->gauges[i], c->cur.gauges[i]);
		c->ewma_gauge[i] = st_ewma(c->ewma_gauge[i],
					   st_rate(d->gauges[i], interval),
					   c->ewma_shift);
	}

	c->ring_head = (c->ring_head + 1u) % c->ring_depth;
	if (c->ring_count < c->ring_depth)
		c->ring_count++;

	c->cur = *s;

	st_unlock(c);
	return 1;
}

/* -------------------------------------------------------------------------
 * Accessors
 * ------------------------------------------------------------------------- */

int stats_latest(struct stats_ctx *c, struct stats_snapshot *out)
{
	int rc = 0;

	if (!c || !out)
		return -EINVAL;
	st_lock(c);
	if (!c->have_baseline)
		rc = -ENODATA;
	else
		*out = c->cur;
	st_unlock(c);
	return rc;
}

int stats_latest_delta(struct stats_ctx *c, struct stats_delta *out)
{
	return stats_history(c, 0, out);
}

int stats_history(struct stats_ctx *c, unsigned int back,
		  struct stats_delta *out)
{
	const struct stats_delta *d;
	int rc = 0;

	if (!c || !out)
		return -EINVAL;
	st_lock(c);
	d = st_ring_at(c, back);
	if (!d)
		rc = -ENODATA;
	else
		*out = *d;
	st_unlock(c);
	return rc;
}

int stats_meta_get(struct stats_ctx *c, struct stats_meta *out)
{
	const struct stats_delta *d;

	if (!c || !out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	st_lock(c);
	out->samples_taken   = c->samples_taken;
	out->read_errors     = c->read_errors;
	out->counter_resets  = c->counter_resets;
	out->last_mono_ns    = c->cur.mono_ns;
	out->last_wall_ns    = c->cur.wall_ns;
	out->ncpu            = (__u32)c->ncpu;
	out->ring_depth      = c->ring_depth;
	out->ring_count      = c->ring_count;
	out->have_baseline   = (__u32)(c->have_baseline ? 1 : 0);
	d = st_ring_at(c, 0);
	out->last_interval_ns = d ? d->interval_ns : 0;
	st_unlock(c);
	return 0;
}

__u64 stats_rate_pkts(const struct stats_delta *d, __u32 reason)
{
	if (!d || reason >= (__u32)STAT_MAX)
		return 0;
	return st_rate(d->pkts[reason], d->interval_ns);
}

__u64 stats_rate_bytes(const struct stats_delta *d, __u32 reason)
{
	if (!d || reason >= (__u32)STAT_MAX)
		return 0;
	return st_rate(d->bytes[reason], d->interval_ns);
}

__u64 stats_rate_gauge(const struct stats_delta *d, __u32 gauge)
{
	if (!d || gauge >= (__u32)CALY_G_MAX)
		return 0;
	return st_rate(d->gauges[gauge], d->interval_ns);
}

/* -------------------------------------------------------------------------
 * Trend detection
 * ------------------------------------------------------------------------- */

int stats_trend_get(struct stats_ctx *c, int series, __u32 index,
		    unsigned int window, struct stats_trend *out)
{
	const struct stats_delta *d;
	double sx = 0.0, sy = 0.0, sxx = 0.0, sxy = 0.0;
	__u64 sum = 0, mn = STATS_U64_MAX, mx = 0, cur = 0;
	unsigned int n = 0, i;
	__u64 t_newest = 0;
	int rc = 0;

	if (!c || !out)
		return -EINVAL;
	if (series != STATS_SERIES_PKTS && series != STATS_SERIES_BYTES &&
	    series != STATS_SERIES_GAUGE)
		return -EINVAL;
	if (series == STATS_SERIES_GAUGE) {
		if (index >= (__u32)CALY_G_MAX)
			return -EINVAL;
	} else if (index >= (__u32)STAT_MAX) {
		return -EINVAL;
	}

	memset(out, 0, sizeof(*out));

	st_lock(c);

	if (c->ring_count == 0) {
		st_unlock(c);
		return -ENODATA;
	}
	if (window == 0 || window > c->ring_count)
		window = c->ring_count;

	d = st_ring_at(c, 0);
	t_newest = d ? d->mono_ns : 0;

	for (i = 0; i < window; i++) {
		__u64 rate;
		double x, y;

		d = st_ring_at(c, i);
		if (!d)
			break;

		rate = st_rate(st_delta_val(d, series, index), d->interval_ns);
		if (i == 0)
			cur = rate;
		sum += rate;
		if (rate < mn)
			mn = rate;
		if (rate > mx)
			mx = rate;

		/* x is seconds BEFORE the newest sample, negated so that a
		 * positive slope means "growing towards now". */
		x = -((double)(t_newest - d->mono_ns) / 1e9);
		y = (double)rate;
		sx  += x;
		sy  += y;
		sxx += x * x;
		sxy += x * y;
		n++;
	}

	if (n == 0) {
		st_unlock(c);
		return -ENODATA;
	}
	if (mn == STATS_U64_MAX)
		mn = 0;

	out->cur     = cur;
	out->avg     = sum / n;
	out->min     = mn;
	out->max     = mx;
	out->samples = n;

	switch (series) {
	case STATS_SERIES_PKTS:
		out->ewma = c->ewma_pkts[index];
		break;
	case STATS_SERIES_BYTES:
		out->ewma = c->ewma_bytes[index];
		break;
	default:
		out->ewma = c->ewma_gauge[index];
		break;
	}

	if (n >= 2) {
		double denom = (double)n * sxx - sx * sx;

		if (denom > 1e-9 || denom < -1e-9) {
			double slope = ((double)n * sxy - sx * sy) / denom;

			if (slope > 9.0e18)
				slope = 9.0e18;
			else if (slope < -9.0e18)
				slope = -9.0e18;
			out->slope = (__s64)slope;
		}
	}

	if (mx == 0)
		out->flags |= STATS_TREND_F_QUIET;
	if (out->slope > 0 && out->cur > out->avg)
		out->flags |= STATS_TREND_F_RISING;
	if (out->slope < 0 && out->cur < out->avg)
		out->flags |= STATS_TREND_F_FALLING;
	if (out->avg > 0 && out->cur >= out->avg * 4)
		out->flags |= STATS_TREND_F_SPIKE;

	st_unlock(c);
	return rc;
}

/* -------------------------------------------------------------------------
 * Formatting helpers
 * ------------------------------------------------------------------------- */

const char *stats_gauge_str(__u32 gauge)
{
	switch (gauge) {
	case CALY_G_PKTS:        return "pkts";
	case CALY_G_BYTES:       return "bytes";
	case CALY_G_SYN:         return "syn";
	case CALY_G_NEWCONN:     return "newconn";
	case CALY_G_DROPS:       return "drops";
	case CALY_G_UDP:         return "udp";
	case CALY_G_ICMP:        return "icmp";
	case CALY_G_FRAG:        return "frag";
	case CALY_G_SYNPROXY_TX: return "synproxy_tx";
	case CALY_G_EVENTS:      return "events";
	case CALY_G_EVENTS_LOST: return "events_lost";
	default:                 return "unknown";
	}
}

static const char *st_scale(char *buf, size_t cap, __u64 v, int binary)
{
	static const char units[] = { ' ', 'k', 'M', 'G', 'T', 'P', 'E' };
	__u64 div = binary ? 1024ULL : 1000ULL;
	__u64 whole = v, rem = 0;
	unsigned int u = 0;

	if (cap == 0)
		return buf;

	while (whole >= div && u + 1 < sizeof(units) / sizeof(units[0])) {
		rem = whole % div;
		whole /= div;
		u++;
	}

	if (u == 0)
		(void)snprintf(buf, cap, "%llu", (unsigned long long)v);
	else
		(void)snprintf(buf, cap, "%llu.%llu%c",
			       (unsigned long long)whole,
			       (unsigned long long)((rem * 10ULL) / div),
			       units[u]);
	buf[cap - 1] = '\0';
	return buf;
}

const char *stats_fmt_bytes(char *buf, size_t cap, __u64 v)
{
	return st_scale(buf, cap, v, 1);
}

const char *stats_fmt_count(char *buf, size_t cap, __u64 v)
{
	return st_scale(buf, cap, v, 0);
}

/* -------------------------------------------------------------------------
 * Dump
 * ------------------------------------------------------------------------- */

struct st_emit {
	stats_line_fn fn;
	void *user;
	int rc;
};

static int st_emitf(struct st_emit *e, const char *fmt, ...)
{
	char line[STATS_LINE_MAX];
	va_list ap;
	int n;

	if (e->rc)
		return e->rc;

	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	if (n < 0)
		return 0;
	if ((size_t)n >= sizeof(line))
		n = (int)sizeof(line) - 1;
	line[n] = '\0';

	e->rc = e->fn(e->user, line, (size_t)n);
	return e->rc;
}

int stats_dump_lines(struct stats_ctx *c, unsigned int flags,
		     stats_line_fn fn, void *user)
{
	struct stats_snapshot *snap = NULL;
	struct stats_delta *delta = NULL;
	struct st_emit e;
	char b1[16], b2[16], b3[16], b4[16];
	__u32 i;
	int have_delta = 0;
	int rc = 0;

	if (!c || !fn)
		return -EINVAL;

	snap = calloc(1, sizeof(*snap));
	delta = calloc(1, sizeof(*delta));
	if (!snap || !delta) {
		free(snap);
		free(delta);
		return -ENOMEM;
	}

	if (stats_latest(c, snap) != 0) {
		free(snap);
		free(delta);
		return -ENODATA;
	}
	have_delta = (stats_latest_delta(c, delta) == 0);

	memset(&e, 0, sizeof(e));
	e.fn = fn;
	e.user = user;

	if (!(flags & STATS_DUMP_NO_HEADER)) {
		struct stats_meta meta;

		(void)stats_meta_get(c, &meta);
		st_emitf(&e,
			 "caly-anti statistics: samples=%llu cpus=%u "
			 "interval=%llu.%03llus errors=%llu resets=%llu\n",
			 (unsigned long long)meta.samples_taken, meta.ncpu,
			 (unsigned long long)(meta.last_interval_ns /
					      CALY_NSEC_PER_SEC),
			 (unsigned long long)((meta.last_interval_ns %
					       CALY_NSEC_PER_SEC) /
					      CALY_NSEC_PER_MSEC),
			 (unsigned long long)meta.read_errors,
			 (unsigned long long)meta.counter_resets);
		st_emitf(&e, "%-26s %12s %12s %12s %12s\n",
			 "reason", "packets", "bytes", "pps", "bps");
		st_emitf(&e,
			 "-------------------------------------"
			 "-------------------------------------\n");
	}

	for (i = 0; i < (__u32)STAT_MAX && !e.rc; i++) {
		__u64 pps, bps;

		if ((flags & STATS_DUMP_DROPS_ONLY) && !stat_reason_is_drop(i))
			continue;

		pps = have_delta ? stats_rate_pkts(delta, i) : 0;
		bps = have_delta ? stats_rate_bytes(delta, i) : 0;

		if (!(flags & STATS_DUMP_ZEROS) && snap->pkts[i] == 0 &&
		    snap->bytes[i] == 0 && pps == 0 && bps == 0)
			continue;

		st_emitf(&e, "%-26s %12s %12s %12s %12s\n",
			 stat_reason_str(i),
			 stats_fmt_count(b1, sizeof(b1), snap->pkts[i]),
			 stats_fmt_bytes(b2, sizeof(b2), snap->bytes[i]),
			 stats_fmt_count(b3, sizeof(b3), pps),
			 stats_fmt_bytes(b4, sizeof(b4), bps));
	}

	if (!(flags & STATS_DUMP_NO_GAUGES) && !e.rc) {
		st_emitf(&e, "\n%-26s %12s %12s\n",
			 "gauge", "total", "per-sec");
		for (i = 0; i < (__u32)CALY_G_MAX && !e.rc; i++) {
			__u64 rate = have_delta ? stats_rate_gauge(delta, i) : 0;

			if (!(flags & STATS_DUMP_ZEROS) &&
			    snap->gauges[i] == 0 && rate == 0)
				continue;
			st_emitf(&e, "%-26s %12s %12s\n", stats_gauge_str(i),
				 stats_fmt_count(b1, sizeof(b1),
						 snap->gauges[i]),
				 stats_fmt_count(b2, sizeof(b2), rate));
		}
	}

	if ((flags & STATS_DUMP_TREND) && !e.rc) {
		static const __u32 watch[] = {
			STAT_PKT_TOTAL, STAT_DROP_TOTAL, STAT_DROP_RATE_PPS,
			STAT_DROP_RATE_SYN, STAT_DROP_BAN_ACTIVE,
			STAT_DROP_AMP_SRCPORT, STAT_DROP_PORTSCAN
		};
		unsigned int w;

		st_emitf(&e, "\n%-26s %12s %12s %12s %10s\n",
			 "trend (pps)", "current", "mean", "peak", "slope/s");
		for (w = 0; w < sizeof(watch) / sizeof(watch[0]) && !e.rc; w++) {
			struct stats_trend t;

			if (stats_trend_get(c, STATS_SERIES_PKTS, watch[w], 0,
					    &t) != 0)
				continue;
			if (!(flags & STATS_DUMP_ZEROS) &&
			    (t.flags & STATS_TREND_F_QUIET))
				continue;
			st_emitf(&e, "%-26s %12s %12s %12s %10lld%s\n",
				 stat_reason_str(watch[w]),
				 stats_fmt_count(b1, sizeof(b1), t.cur),
				 stats_fmt_count(b2, sizeof(b2), t.avg),
				 stats_fmt_count(b3, sizeof(b3), t.max),
				 (long long)t.slope,
				 (t.flags & STATS_TREND_F_SPIKE) ? "  SPIKE" :
				 (t.flags & STATS_TREND_F_RISING) ? "  rising" :
				 "");
		}
	}

	rc = e.rc;
	free(snap);
	free(delta);
	return rc;
}

struct st_file_sink {
	FILE *f;
};

static int st_file_line(void *user, const char *line, size_t len)
{
	struct st_file_sink *s = user;

	if (fwrite(line, 1, len, s->f) != len)
		return -EIO;
	return 0;
}

int stats_dump(struct stats_ctx *c, FILE *f, unsigned int flags)
{
	struct st_file_sink sink;

	if (!f)
		return -EINVAL;
	sink.f = f;
	return stats_dump_lines(c, flags, st_file_line, &sink);
}

struct st_buf_sink {
	char *buf;
	size_t cap;
	size_t len;
	int truncated;
};

static int st_buf_line(void *user, const char *line, size_t len)
{
	struct st_buf_sink *s = user;

	/* Keep one byte for the NUL and never split a line. */
	if (s->len + len + 1u > s->cap) {
		s->truncated = 1;
		return 1;              /* stop the dump */
	}
	memcpy(s->buf + s->len, line, len);
	s->len += len;
	s->buf[s->len] = '\0';
	return 0;
}

long stats_dump_buf(struct stats_ctx *c, unsigned int flags, char *buf,
		    size_t cap)
{
	struct st_buf_sink sink;
	int rc;

	if (!buf || cap == 0)
		return -EINVAL;

	memset(&sink, 0, sizeof(sink));
	sink.buf = buf;
	sink.cap = cap;
	buf[0] = '\0';

	rc = stats_dump_lines(c, flags, st_buf_line, &sink);
	if (sink.truncated)
		return -E2BIG;
	if (rc < 0)
		return rc;
	return (long)sink.len;
}
