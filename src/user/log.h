/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/log.h
 *
 * Leveled logging to stderr and/or syslog, rate limited so that a log flood
 * cannot itself become the denial of service.
 *
 * WHY THE RATE LIMIT MATTERS HERE MORE THAN USUAL
 * -----------------------------------------------
 * This daemon reads a perf/ring buffer that a packet flood fills.  One log
 * line per event during a 4 Mpps attack is an unbounded write() storm into
 * journald, which fsyncs, which blocks, which stalls the event loop, which
 * makes the daemon stop draining the ring, which makes the dataplane count
 * STAT_EVENT_LOST forever.  The limiter below is therefore not a nicety: it
 * is what keeps the control plane responsive while the data plane is under
 * load.
 *
 * The limiter never silences the daemon completely.  Suppressed messages are
 * counted and a single summary line ("N messages suppressed") is emitted
 * outside the limit, so a gap in the log is always visible as a gap.
 *
 * THREADING: the daemon is single threaded and installs signal handlers via
 * signalfd, never as real handlers, so no logging call is ever reentered from
 * a signal context.  These functions are consequently not async-signal-safe
 * and do not need to be.
 */

#ifndef CALY_LOG_H
#define CALY_LOG_H

#include <stdarg.h>
#include <stddef.h>

/* Matches fw_config.log_level: 0 = error .. 4 = trace. */
enum caly_log_level {
	CALY_LL_ERR   = 0,
	CALY_LL_WARN  = 1,
	CALY_LL_INFO  = 2,
	CALY_LL_DEBUG = 3,
	CALY_LL_TRACE = 4,
	CALY_LL_MAX   = 5
};

/*
 * ident   - syslog identity, e.g. "calyanti". Copied, not retained.
 * level   - initial verbosity (enum caly_log_level), clamped into range.
 * stderr_on / syslog_on - sinks to enable. Both may be on.
 */
void caly_log_init(const char *ident, int level, int stderr_on, int syslog_on);
void caly_log_fini(void);

void caly_log_set_level(int level);
int  caly_log_get_level(void);
void caly_log_set_stderr(int on);
void caly_log_set_syslog(int on);

/* Emit at most `per_sec` messages per second with a bucket depth of `burst`.
 * Passing 0 for either disables limiting entirely (matching the semantics of
 * caly_tb_consume() in common.h, where a zero rate or burst means "inert").
 * Defaults: 500/s, burst 1000. */
void caly_log_set_rate(unsigned int per_sec, unsigned int burst);

/* "err"/"error", "warn"/"warning", "info", "debug", "trace", or "0".."4".
 * Returns the level, or -1 when the string is not recognised. */
int         caly_log_level_from_string(const char *s);
const char *caly_log_level_name(int level);

/* 1 when a message at `level` would be emitted (before rate limiting).  Use
 * it to skip expensive formatting on hot paths. */
int caly_log_enabled(int level);

void caly_log_v(int level, const char *fmt, va_list ap);
void caly_log_at(int level, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/*
 * Keyed rate limiting: at most a few messages per second per distinct `key`,
 * independent of the global bucket.  Use it for anything that is per-packet,
 * per-source or per-event so that one pathological input cannot crowd out
 * every other message.  `key` must be a short stable string literal such as
 * "event-decode" or "ct-full".
 */
void caly_log_key(int level, const char *key, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

/* Emit the "N messages suppressed" summary if anything was dropped and enough
 * time has passed.  Call it once per event-loop tick; it is cheap and does
 * nothing when nothing was suppressed. */
void caly_log_flush_suppressed(void);

/* Total messages dropped by the limiter since startup. */
unsigned long long caly_log_suppressed_total(void);

#define caly_err(...)    caly_log_at(CALY_LL_ERR,   __VA_ARGS__)
#define caly_warn(...)   caly_log_at(CALY_LL_WARN,  __VA_ARGS__)
#define caly_info(...)   caly_log_at(CALY_LL_INFO,  __VA_ARGS__)
#define caly_debug(...)  caly_log_at(CALY_LL_DEBUG, __VA_ARGS__)
#define caly_trace(...)  caly_log_at(CALY_LL_TRACE, __VA_ARGS__)

#endif /* CALY_LOG_H */
