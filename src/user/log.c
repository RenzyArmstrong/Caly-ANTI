/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/log.c
 *
 * The rate limiter reuses caly_tb_consume() from common.h rather than
 * reimplementing one.  That helper is the same nanosecond token bucket the
 * dataplane uses: integer only, remainder carried in last_refill_ns, and
 * inert (always conforming) when rate or burst is zero.  Reusing it means
 * there is exactly one token-bucket implementation in the tree to get right.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "log.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <linux/types.h>

#ifndef CALY_USERSPACE
#define CALY_USERSPACE 1
#endif
#if defined(__has_include)
#  if __has_include("common.h")
#    include "common.h"
#  else
#    include "../bpf/common.h"
#  endif
#else
#  include "../bpf/common.h"
#endif

/* Longest single log line.  Anything longer is truncated with a marker; no
 * log message in this tree is anywhere near this. */
#define CALY_LOG_LINE_MAX   1024

/* Number of independent keyed limiters.  A small power of two: the table is
 * probed linearly and collisions merely share a bucket, which is harmless -
 * two unrelated messages sharing a limiter is a slightly stricter limit, not
 * a correctness problem. */
#define CALY_LOG_KEY_SLOTS  64

/* How often the "N messages suppressed" summary may be emitted. */
#define CALY_LOG_SUMMARY_INTERVAL_NS  (5ULL * CALY_NSEC_PER_SEC)

#define CALY_LOG_DEFAULT_RATE   500u
#define CALY_LOG_DEFAULT_BURST  1000u

/* Per-key allowance: three in the first second, one per second after. */
#define CALY_LOG_KEY_RATE   1u
#define CALY_LOG_KEY_BURST  3u

struct caly_log_key_slot {
	__u32              hash;
	int                used;
	struct token_bucket tb;
	unsigned long long suppressed;
	char               key[24];
};

static struct {
	int  level;
	int  stderr_on;
	int  syslog_on;
	int  syslog_open;
	int  initialised;
	char ident[32];

	struct token_bucket tb;
	__u64 rate;
	__u64 burst;

	unsigned long long suppressed_pending;
	unsigned long long suppressed_total;
	__u64 last_summary_ns;

	struct caly_log_key_slot keys[CALY_LOG_KEY_SLOTS];
} lg = {
	.level = CALY_LL_INFO,
	.stderr_on = 1,
	.syslog_on = 0,
	.syslog_open = 0,
	.initialised = 0,
	.ident = "calyanti",
	.rate = CALY_LOG_DEFAULT_RATE,
	.burst = CALY_LOG_DEFAULT_BURST,
};

static const char *const caly_level_names[CALY_LL_MAX] = {
	"error", "warn", "info", "debug", "trace"
};

static const char *const caly_level_tags[CALY_LL_MAX] = {
	"ERR ", "WARN", "INFO", "DBG ", "TRC "
};

static int caly_level_to_syslog(int level)
{
	switch (level) {
	case CALY_LL_ERR:   return LOG_ERR;
	case CALY_LL_WARN:  return LOG_WARNING;
	case CALY_LL_INFO:  return LOG_INFO;
	case CALY_LL_DEBUG: return LOG_DEBUG;
	case CALY_LL_TRACE: return LOG_DEBUG;
	default:            return LOG_INFO;
	}
}

static int caly_clamp_level(int level)
{
	if (level < CALY_LL_ERR)
		return CALY_LL_ERR;
	if (level > CALY_LL_TRACE)
		return CALY_LL_TRACE;
	return level;
}

void caly_log_init(const char *ident, int level, int stderr_on, int syslog_on)
{
	__u64 now = caly_now_ns();

	if (ident != NULL && ident[0] != '\0')
		(void)caly_strlcpy(lg.ident, ident, sizeof(lg.ident));

	lg.level = caly_clamp_level(level);
	lg.stderr_on = stderr_on ? 1 : 0;

	caly_tb_init(&lg.tb, now, lg.burst);
	lg.last_summary_ns = now;
	memset(lg.keys, 0, sizeof(lg.keys));

	caly_log_set_syslog(syslog_on);
	lg.initialised = 1;
}

void caly_log_fini(void)
{
	caly_log_flush_suppressed();
	if (lg.syslog_open) {
		closelog();
		lg.syslog_open = 0;
	}
	lg.syslog_on = 0;
	lg.initialised = 0;
}

void caly_log_set_level(int level)
{
	lg.level = caly_clamp_level(level);
}

int caly_log_get_level(void)
{
	return lg.level;
}

void caly_log_set_stderr(int on)
{
	lg.stderr_on = on ? 1 : 0;
}

void caly_log_set_syslog(int on)
{
	if (on) {
		if (!lg.syslog_open) {
			openlog(lg.ident, LOG_PID | LOG_NDELAY, LOG_DAEMON);
			lg.syslog_open = 1;
		}
		lg.syslog_on = 1;
	} else {
		if (lg.syslog_open) {
			closelog();
			lg.syslog_open = 0;
		}
		lg.syslog_on = 0;
	}
}

void caly_log_set_rate(unsigned int per_sec, unsigned int burst)
{
	lg.rate = per_sec;
	lg.burst = burst;
	caly_tb_init(&lg.tb, caly_now_ns(), lg.burst);
}

int caly_log_level_from_string(const char *s)
{
	int i;
	__u32 v;

	if (s == NULL || s[0] == '\0')
		return -1;

	if (caly_strcaseeq(s, "err") || caly_strcaseeq(s, "error") ||
	    caly_strcaseeq(s, "fatal"))
		return CALY_LL_ERR;
	if (caly_strcaseeq(s, "warn") || caly_strcaseeq(s, "warning"))
		return CALY_LL_WARN;
	if (caly_strcaseeq(s, "info") || caly_strcaseeq(s, "notice"))
		return CALY_LL_INFO;
	if (caly_strcaseeq(s, "debug"))
		return CALY_LL_DEBUG;
	if (caly_strcaseeq(s, "trace"))
		return CALY_LL_TRACE;

	for (i = 0; i < CALY_LL_MAX; i++) {
		if (caly_strcaseeq(s, caly_level_names[i]))
			return i;
	}

	if (caly_parse_u32(s, &v) == 0 && v < (__u32)CALY_LL_MAX)
		return (int)v;

	return -1;
}

const char *caly_log_level_name(int level)
{
	if (level < 0 || level >= CALY_LL_MAX)
		return "unknown";
	return caly_level_names[level];
}

int caly_log_enabled(int level)
{
	return level <= lg.level;
}

/* Write one already-formatted line to the enabled sinks.  Never rate limited:
 * callers decide.  `msg` must not contain a trailing newline. */
static void caly_log_emit(int level, const char *msg)
{
	if (lg.stderr_on) {
		char ts[32];
		char frac[8];
		__u64 wall = caly_wall_ns();

		if (caly_fmt_wallclock(wall, ts, sizeof(ts)) != 0)
			(void)caly_strlcpy(ts, "--------- --:--:--",
					   sizeof(ts));
		if (caly_snprintf(frac, sizeof(frac), "%03u",
				  (unsigned int)((wall / 1000000ULL) %
						 1000ULL)) < 0)
			(void)caly_strlcpy(frac, "000", sizeof(frac));

		/* One fprintf so the line cannot be interleaved by another
		 * writer sharing the fd. */
		(void)fprintf(stderr, "%s.%s [%s] %s\n", ts, frac,
			      caly_level_tags[caly_clamp_level(level)], msg);
		(void)fflush(stderr);
	}

	if (lg.syslog_on && lg.syslog_open)
		syslog(caly_level_to_syslog(level), "%s", msg);
}

/* Take one token from the global bucket.  Returns 1 when the message may be
 * emitted, 0 when it must be suppressed (and accounts the suppression). */
static int caly_log_admit(void)
{
	if (caly_tb_consume(&lg.tb, caly_now_ns(), lg.rate, lg.burst, 1))
		return 1;

	lg.suppressed_pending++;
	lg.suppressed_total++;
	return 0;
}

void caly_log_flush_suppressed(void)
{
	__u64 now;
	char msg[128];

	if (lg.suppressed_pending == 0)
		return;

	now = caly_now_ns();
	if (now - lg.last_summary_ns < CALY_LOG_SUMMARY_INTERVAL_NS)
		return;

	lg.last_summary_ns = now;

	if (caly_snprintf(msg, sizeof(msg),
			  "%llu log message(s) suppressed by the rate limiter "
			  "(%llu total since start)",
			  lg.suppressed_pending, lg.suppressed_total) >= 0) {
		/* Deliberately bypasses the bucket: a gap in the log must
		 * always be visible as a gap. */
		caly_log_emit(CALY_LL_WARN, msg);
	}
	lg.suppressed_pending = 0;
}

unsigned long long caly_log_suppressed_total(void)
{
	return lg.suppressed_total;
}

void caly_log_v(int level, const char *fmt, va_list ap)
{
	char msg[CALY_LOG_LINE_MAX];
	int n;

	if (fmt == NULL)
		return;
	if (level > lg.level)
		return;
	if (!caly_log_admit())
		return;

	n = caly_vsnprintf(msg, sizeof(msg), fmt, ap);
	if (n < 0) {
		/* Truncated or a formatting error.  msg is still NUL
		 * terminated by caly_vsnprintf; mark it rather than dropping
		 * the message. */
		size_t len = strlen(msg);

		if (len + 4 < sizeof(msg))
			(void)caly_strlcat(msg, "...", sizeof(msg));
		if (len == 0)
			return;
	}
	caly_log_emit(level, msg);
}

void caly_log_at(int level, const char *fmt, ...)
{
	va_list ap;

	if (level > lg.level)
		return;

	va_start(ap, fmt);
	caly_log_v(level, fmt, ap);
	va_end(ap);
}

/* FNV-1a, 32 bit.  Only used to bucket keys in a 64-slot table. */
static __u32 caly_log_hash(const char *s)
{
	__u32 h = 2166136261u;

	while (*s != '\0') {
		h ^= (__u32)(unsigned char)*s++;
		h *= 16777619u;
	}
	return h;
}

/*
 * Find (or claim) the limiter slot for `key`.  Linear probing over a fixed
 * table; when the table is full the oldest-looking slot is recycled.  There is
 * no allocation and no unbounded growth: an attacker cannot make the daemon
 * consume memory by causing new distinct log keys, because keys are string
 * literals chosen by us, never attacker-controlled data.
 */
static struct caly_log_key_slot *caly_log_key_slot(const char *key)
{
	__u32 h = caly_log_hash(key);
	unsigned int start = (unsigned int)(h % CALY_LOG_KEY_SLOTS);
	unsigned int i;
	struct caly_log_key_slot *victim = NULL;

	for (i = 0; i < CALY_LOG_KEY_SLOTS; i++) {
		struct caly_log_key_slot *s =
			&lg.keys[(start + i) % CALY_LOG_KEY_SLOTS];

		if (!s->used) {
			s->used = 1;
			s->hash = h;
			s->suppressed = 0;
			(void)caly_strlcpy(s->key, key, sizeof(s->key));
			caly_tb_init(&s->tb, caly_now_ns(), CALY_LOG_KEY_BURST);
			return s;
		}
		if (s->hash == h && strncmp(s->key, key, sizeof(s->key)) == 0)
			return s;
		if (victim == NULL ||
		    s->tb.last_refill_ns < victim->tb.last_refill_ns)
			victim = s;
	}

	/* Table full: recycle the least recently used slot. */
	victim->hash = h;
	victim->suppressed = 0;
	(void)caly_strlcpy(victim->key, key, sizeof(victim->key));
	caly_tb_init(&victim->tb, caly_now_ns(), CALY_LOG_KEY_BURST);
	return victim;
}

void caly_log_key(int level, const char *key, const char *fmt, ...)
{
	struct caly_log_key_slot *slot;
	unsigned long long missed;
	char msg[CALY_LOG_LINE_MAX];
	va_list ap;
	int n;

	if (fmt == NULL || key == NULL)
		return;
	if (level > lg.level)
		return;

	slot = caly_log_key_slot(key);
	if (!caly_tb_consume(&slot->tb, caly_now_ns(), CALY_LOG_KEY_RATE,
			     CALY_LOG_KEY_BURST, 1)) {
		slot->suppressed++;
		lg.suppressed_total++;
		return;
	}

	/* The keyed limiter has already thinned the stream; still take a
	 * global token so that many distinct keys cannot add up to a flood. */
	if (!caly_log_admit())
		return;

	va_start(ap, fmt);
	n = caly_vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	if (n < 0 && msg[0] == '\0')
		return;

	missed = slot->suppressed;
	slot->suppressed = 0;

	if (missed > 0) {
		char full[CALY_LOG_LINE_MAX];

		if (caly_snprintf(full, sizeof(full),
				  "%s [+%llu similar suppressed]",
				  msg, missed) >= 0) {
			caly_log_emit(level, full);
			return;
		}
	}
	caly_log_emit(level, msg);
}
