/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/autotune.c
 *
 * Adaptive attack detection, classification and mitigation escalation.
 * See autotune.h for the contract, the safety invariants and the required
 * shape of struct at_ops.
 *
 * Design rules obeyed throughout this file:
 *
 *   1. Integer arithmetic only. No floating point anywhere: this code has to
 *      agree with a dataplane that has none, and a rounding difference between
 *      the two would be a bug that only shows up under load.
 *
 *   2. Every candidate configuration is rebuilt from the operator BASELINE.
 *      Escalation therefore cannot ratchet and de-escalation restores the
 *      operator's numbers exactly, byte for byte.
 *
 *   3. Nothing here can lock the operator out. The mgmt port list is copied
 *      verbatim from the baseline and repaired if TCP/22 is missing; every
 *      token bucket has an absolute floor; LOCKDOWN forces the allowlist,
 *      mgmt bypass, conntrack and PMTUD-preserving ICMP flags ON.
 *
 *   4. Attacker-derived data never reaches a shell and never reaches argv.
 *      Alert JSON is written to the hook's stdin. argv is built exclusively
 *      from compile-time string tables and integers.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "autotune.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#define AT_ARRAY_SIZE(a)   (sizeof(a) / sizeof((a)[0]))
#define AT_SRCMEM_PROBE    8u
#define AT_SRCMEM_MIN      256u
#define AT_SRCMEM_MAX      262144u
#define AT_CHILD_MAXFD     4096
#define AT_HOOK_ARGV_MAX   16

/* Absolute-threshold bits (fw_config.global_*_hi crossed this tick). */
#define AT_ABS_PPS         (1u << 0)
#define AT_ABS_BPS         (1u << 1)
#define AT_ABS_SYN         (1u << 2)
#define AT_ABS_NEWCONN     (1u << 3)

/* -------------------------------------------------------------------------
 * Name tables
 * ------------------------------------------------------------------------- */

static const char *const at_metric_names[AT_M_MAX] = {
	"pps", "bps", "syn_pps", "newconn_pps", "udp_pps", "icmp_pps",
	"frag_pps", "tcp_pps", "drop_pps", "uniq_src_ps", "conn_level",
	"pkt_size"
};

static const char *const at_class_names[AT_C_MAX] = {
	"syn_flood", "ack_flood", "udp_flood", "amplification", "icmp_flood",
	"fragment_flood", "conn_exhaustion", "slowloris", "portscan",
	"volumetric"
};

static const char *const at_event_names[AT_EV_MAX] = {
	"mode_escalate", "mode_deescalate", "attack", "clear", "ban",
	"heartbeat", "error"
};

const char *at_metric_str(__u32 metric)
{
	return metric < AT_M_MAX ? at_metric_names[metric] : "unknown";
}

const char *at_class_str(__u32 class_index)
{
	return class_index < AT_C_MAX ? at_class_names[class_index] : "unknown";
}

const char *at_event_str(__u32 kind)
{
	return kind < AT_EV_MAX ? at_event_names[kind] : "unknown";
}

/* -------------------------------------------------------------------------
 * Small integer helpers
 * ------------------------------------------------------------------------- */

__u64 autotune_now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (__u64)ts.tv_sec * CALY_NSEC_PER_SEC + (__u64)ts.tv_nsec;
}

/*
 * (a * b) / c without overflow. Every target architecture in this project is
 * 64-bit and both gcc and clang provide __uint128_t there; the shift-based
 * fallback exists so the file still compiles (with slightly coarser results)
 * anywhere else.
 */
static __u64 at_mul_div(__u64 a, __u64 b, __u64 c)
{
	if (c == 0)
		return 0;
#if defined(__SIZEOF_INT128__)
	return (__u64)(((__uint128_t)a * (__uint128_t)b) / (__uint128_t)c);
#else
	while (b != 0 && a > (~(__u64)0) / b) {
		b >>= 1;
		c >>= 1;
		if (c == 0)
			return a;
	}
	if (b == 0)
		return 0;
	return (a * b) / c;
#endif
}

static __u64 at_per_sec(__u64 delta, __u64 dt_ns)
{
	if (dt_ns == 0)
		return 0;
	return at_mul_div(delta, CALY_NSEC_PER_SEC, dt_ns);
}

static __u64 at_min64(__u64 a, __u64 b) { return a < b ? a : b; }

static __u32 at_clamp32(__u32 v, __u32 lo, __u32 hi)
{
	if (v < lo)
		return lo;
	if (v > hi)
		return hi;
	return v;
}

/*
 * Irregular-interval EWMA in integer arithmetic:
 *
 *     new = cur + (sample - cur) * dt / (tau + dt)
 *
 * dt >= tau collapses to "take the sample", which is exactly right: more than
 * a time constant has elapsed, the old value carries no information.
 */
static __u64 at_ewma_step(__u64 cur, __u64 sample, __u64 dt_ns, __u64 tau_ns)
{
	__u64 den, d;

	if (tau_ns == 0 || dt_ns >= tau_ns)
		return sample;
	den = tau_ns + dt_ns;
	if (sample >= cur) {
		d = sample - cur;
		return cur + at_mul_div(d, dt_ns, den);
	}
	d = cur - sample;
	return cur - at_mul_div(d, dt_ns, den);
}

static void at_track_update(struct at_track *t, __u64 v, __u64 dt_ns,
			    const __u64 *win, int freeze_long)
{
	t->cur = v;
	if (v > t->peak)
		t->peak = v;

	if (t->samples == 0) {
		t->ewma[AT_W_SHORT] = v;
		t->ewma[AT_W_MED]   = v;
		t->ewma[AT_W_LONG]  = v;
	} else {
		t->ewma[AT_W_SHORT] = at_ewma_step(t->ewma[AT_W_SHORT], v,
						   dt_ns, win[AT_W_SHORT]);
		t->ewma[AT_W_MED]   = at_ewma_step(t->ewma[AT_W_MED], v,
						   dt_ns, win[AT_W_MED]);
		/* The long window is the BASELINE. Freezing it while an anomaly
		 * is in progress is what stops a sustained flood from slowly
		 * redefining "normal" and disarming the detector. */
		if (!freeze_long)
			t->ewma[AT_W_LONG] = at_ewma_step(t->ewma[AT_W_LONG], v,
							  dt_ns,
							  win[AT_W_LONG]);
	}
	if (t->samples != 0xFFFFFFFFu)
		t->samples++;
}

/* -------------------------------------------------------------------------
 * Logging
 * ------------------------------------------------------------------------- */

#if defined(__GNUC__)
static void at_log(struct autotune *at, int level, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));
#endif

static void at_log(struct autotune *at, int level, const char *fmt, ...)
{
	char buf[512];
	va_list ap;

	if (!at || !at->ops.log)
		return;
	va_start(ap, fmt);
	if (vsnprintf(buf, sizeof(buf), fmt, ap) < 0)
		buf[0] = '\0';
	va_end(ap);
	buf[sizeof(buf) - 1] = '\0';
	at->ops.log(at->ops.ctx, level, "%s", buf);
}

/* -------------------------------------------------------------------------
 * Bounded string builder + JSON escaping
 * ------------------------------------------------------------------------- */

struct at_buf {
	char  *p;
	size_t cap;
	size_t len;
	int    ovf;
};

static void at_binit(struct at_buf *b, char *p, size_t cap)
{
	b->p = p;
	b->cap = cap;
	b->len = 0;
	b->ovf = (cap == 0);
	if (cap)
		p[0] = '\0';
}

static void at_bputc(struct at_buf *b, char c)
{
	if (b->ovf || b->len + 1 >= b->cap) {
		b->ovf = 1;
		return;
	}
	b->p[b->len++] = c;
	b->p[b->len] = '\0';
}

static void at_bputs(struct at_buf *b, const char *s)
{
	if (!s)
		return;
	while (*s && !b->ovf)
		at_bputc(b, *s++);
}

#if defined(__GNUC__)
static void at_bprintf(struct at_buf *b, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
#endif

static void at_bprintf(struct at_buf *b, const char *fmt, ...)
{
	va_list ap;
	int n;
	size_t room;

	if (b->ovf || b->len + 1 >= b->cap) {
		b->ovf = 1;
		return;
	}
	room = b->cap - b->len;
	va_start(ap, fmt);
	n = vsnprintf(b->p + b->len, room, fmt, ap);
	va_end(ap);
	if (n < 0) {
		b->ovf = 1;
		b->p[b->len] = '\0';
		return;
	}
	if ((size_t)n >= room) {
		b->ovf = 1;
		b->p[b->len] = '\0';
		return;
	}
	b->len += (size_t)n;
}

/*
 * Emit a JSON string literal, quotes included. Everything outside printable
 * 7-bit ASCII becomes \u00XX. All of our strings come from internal tables or
 * from inet_ntop, so this is belt and braces - but it is the belt that stops a
 * hostile hostname or tag from ever breaking out of the JSON envelope, and
 * therefore out of a log-ingestion pipeline.
 */
static void at_bjson_str(struct at_buf *b, const char *s)
{
	const unsigned char *u = (const unsigned char *)s;

	at_bputc(b, '"');
	if (u) {
		for (; *u && !b->ovf; u++) {
			unsigned char c = *u;

			if (c == '"' || c == '\\') {
				at_bputc(b, '\\');
				at_bputc(b, (char)c);
			} else if (c >= 0x20 && c < 0x7F) {
				at_bputc(b, (char)c);
			} else {
				at_bprintf(b, "\\u%04x", (unsigned int)c);
			}
		}
	}
	at_bputc(b, '"');
}

static void at_bjson_u64(struct at_buf *b, const char *key, __u64 v)
{
	at_bjson_str(b, key);
	at_bprintf(b, ":%llu", (unsigned long long)v);
}

static void at_bjson_kstr(struct at_buf *b, const char *key, const char *v)
{
	at_bjson_str(b, key);
	at_bputc(b, ':');
	at_bjson_str(b, v);
}

static void at_bjson_bool(struct at_buf *b, const char *key, int v)
{
	at_bjson_str(b, key);
	at_bputs(b, v ? ":true" : ":false");
}

/* -------------------------------------------------------------------------
 * Address helpers
 * ------------------------------------------------------------------------- */

static int at_addr_valid(const struct at_addr *a)
{
	if (!a)
		return 0;
	if (a->family == CALY_AF_INET)
		return a->a[0] != 0;
	if (a->family == CALY_AF_INET6)
		return (a->a[0] | a->a[1] | a->a[2] | a->a[3]) != 0;
	return 0;
}

static void at_fmt_addr(const struct at_addr *a, char *buf, size_t len)
{
	if (!buf || len == 0)
		return;
	buf[0] = '\0';
	if (!a) {
		snprintf(buf, len, "invalid");
		return;
	}
	if (a->family == CALY_AF_INET) {
		struct in_addr in;

		memset(&in, 0, sizeof(in));
		memcpy(&in.s_addr, &a->a[0], sizeof(in.s_addr));
		if (!inet_ntop(AF_INET, &in, buf, (socklen_t)len))
			snprintf(buf, len, "0.0.0.0");
	} else if (a->family == CALY_AF_INET6) {
		struct in6_addr in6;

		memset(&in6, 0, sizeof(in6));
		memcpy(&in6, a->a, sizeof(a->a) < sizeof(in6) ?
		       sizeof(a->a) : sizeof(in6));
		if (!inet_ntop(AF_INET6, &in6, buf, (socklen_t)len))
			snprintf(buf, len, "::");
	} else {
		snprintf(buf, len, "invalid");
	}
	buf[len - 1] = '\0';
}

/* -------------------------------------------------------------------------
 * Per-source memory (previous counters + ban escalation history)
 * ------------------------------------------------------------------------- */

static __u32 at_srcmem_hash(const struct at_addr *a)
{
	__u32 h;

	h = caly_mix32(a->a[0], 0x51ED270Bu);
	h = caly_mix32(h ^ a->a[1], 0x2F1B3C5Du);
	h = caly_mix32(h ^ a->a[2], 0x7A1E9C3Fu);
	h = caly_mix32(h ^ a->a[3], 0x1B873593u);
	h = caly_mix32(h ^ a->family, 0x9E3779B9u);
	return h;
}

static struct at_srcmem *at_srcmem_get(struct autotune *at,
				       const struct at_addr *a, __u64 now_ns,
				       int *created)
{
	struct at_srcmem *e, *victim;
	__u32 mask, idx, i, victim_i;
	__u64 oldest;

	if (created)
		*created = 0;

	if (!at->srcmem || at->srcmem_cap == 0 || !at_addr_valid(a))
		return NULL;

	mask = at->srcmem_cap - 1u;
	idx = at_srcmem_hash(a) & mask;
	victim_i = idx;
	oldest = ~(__u64)0;

	for (i = 0; i < AT_SRCMEM_PROBE; i++) {
		__u32 slot = (idx + i) & mask;

		e = &at->srcmem[slot];
		if (e->family == 0) {
			memset(e, 0, sizeof(*e));
			e->family = a->family;
			memcpy(e->a, a->a, sizeof(e->a));
			e->last_seen_ns = now_ns;
			at->srcmem_used++;
			if (created)
				*created = 1;
			return e;
		}
		if (e->family == a->family &&
		    memcmp(e->a, a->a, sizeof(e->a)) == 0) {
			e->last_seen_ns = now_ns;
			return e;
		}
		if (e->last_seen_ns <= oldest) {
			oldest = e->last_seen_ns;
			victim_i = slot;
		}
	}

	/* Table pressure: recycle the coldest slot in the probe window. This is
	 * a cache, not a ledger; losing an escalation history costs one shorter
	 * ban, never a missed one. A recycled slot has no prior baseline for
	 * this source, so it is reported as newly created: the caller must seed
	 * it and observe, never differentiate a lifetime total as one interval. */
	victim = &at->srcmem[victim_i];
	memset(victim, 0, sizeof(*victim));
	victim->family = a->family;
	memcpy(victim->a, a->a, sizeof(victim->a));
	victim->last_seen_ns = now_ns;
	if (created)
		*created = 1;
	return victim;
}

/* -------------------------------------------------------------------------
 * Defaults
 * ------------------------------------------------------------------------- */

void autotune_tunables_default(struct at_tunables *t)
{
	if (!t)
		return;
	memset(t, 0, sizeof(*t));

	t->win_ns[AT_W_SHORT] = 10ULL  * CALY_NSEC_PER_SEC;
	t->win_ns[AT_W_MED]   = 60ULL  * CALY_NSEC_PER_SEC;
	t->win_ns[AT_W_LONG]  = 900ULL * CALY_NSEC_PER_SEC;

	t->min_tick_ns             = 250ULL * CALY_NSEC_PER_MSEC;
	t->warmup_ns               = 60ULL  * CALY_NSEC_PER_SEC;
	t->heartbeat_ns            = 60ULL  * CALY_NSEC_PER_SEC;
	t->hook_min_interval_ns    = 5ULL   * CALY_NSEC_PER_SEC;
	t->lockdown_extra_dwell_ns = 300ULL * CALY_NSEC_PER_SEC;
	t->ban_interval_ns         = 2ULL   * CALY_NSEC_PER_SEC;

	/* Multiples are in TENTHS. Floors are absolute and are what keeps a
	 * quiet server from tripping on a backup job or a package update. */
	t->metric_mult[AT_M_PPS]         = 40;
	t->metric_floor[AT_M_PPS]        = 50000;
	t->metric_mult[AT_M_BPS]         = 40;
	t->metric_floor[AT_M_BPS]        = 12500000ULL;   /* 100 Mbit/s */
	t->metric_mult[AT_M_SYN_PPS]     = 50;
	t->metric_floor[AT_M_SYN_PPS]    = 2000;
	t->metric_mult[AT_M_NEWCONN_PPS] = 50;
	t->metric_floor[AT_M_NEWCONN_PPS] = 2000;
	t->metric_mult[AT_M_UDP_PPS]     = 50;
	t->metric_floor[AT_M_UDP_PPS]    = 20000;
	t->metric_mult[AT_M_ICMP_PPS]    = 60;
	t->metric_floor[AT_M_ICMP_PPS]   = 1000;
	t->metric_mult[AT_M_FRAG_PPS]    = 60;
	t->metric_floor[AT_M_FRAG_PPS]   = 1000;
	t->metric_mult[AT_M_TCP_PPS]     = 40;
	t->metric_floor[AT_M_TCP_PPS]    = 50000;
	t->metric_mult[AT_M_DROP_PPS]    = 60;
	t->metric_floor[AT_M_DROP_PPS]   = 5000;
	t->metric_mult[AT_M_UNIQ_SRC]    = 60;
	t->metric_floor[AT_M_UNIQ_SRC]   = 5000;
	t->metric_mult[AT_M_CONN_LEVEL]  = 25;
	t->metric_floor[AT_M_CONN_LEVEL] = 20000;
	/* Mean packet size is a classification input, not an anomaly signal. */
	t->metric_mult[AT_M_PKT_SIZE]    = 0;
	t->metric_floor[AT_M_PKT_SIZE]   = 0;

	t->confirm_up   = 3;
	t->confirm_down = 10;

	t->sev_elevate  = 20;
	t->sev_attack   = 50;
	t->sev_lockdown = 85;

	t->max_bans_per_tick = 32;
	t->ban_min_drops     = 1000;
	t->ban_min_share_pct = 2;
	t->srcmem_entries    = 4096;

	t->allow_lockdown        = 0;   /* operator state, per calyanti.conf */
	t->allow_synproxy        = 1;
	t->allow_amp_override    = 1;
	t->allow_portscan_enable = 1;
	t->allow_drop_all_frags  = 0;
	t->allow_icmp_policy     = 1;
	t->allow_autoban         = 1;

	t->dry_run        = 0;
	t->alerts_enabled = 1;
	t->hook_timeout_s = 10;

	t->alert_file[0]     = '\0';
	t->hook_path[0]      = '\0';
	t->webhook_url[0]    = '\0';
	t->webhook_client[0] = '\0';
	snprintf(t->node_id, sizeof(t->node_id), "%s", "calyanti");
}

/* -------------------------------------------------------------------------
 * Alert sinks: file, exec hook, webhook
 * ------------------------------------------------------------------------- */

static char *const at_hook_envp[] = {
	(char *)"PATH=/usr/sbin:/usr/bin:/sbin:/bin",
	(char *)"LC_ALL=C",
	(char *)"CALYANTI=1",
	NULL
};

/* An absolute path to a regular, executable, non-world-writable file. */
static int at_execpath_ok(const char *p)
{
	struct stat sb;

	if (!p || p[0] != '/')
		return 0;
	if (strlen(p) >= 250)
		return 0;
	if (strstr(p, "/../") != NULL)
		return 0;
	if (stat(p, &sb) != 0)
		return 0;
	if (!S_ISREG(sb.st_mode))
		return 0;
	if (sb.st_mode & S_IWOTH)
		return 0;
	if (access(p, X_OK) != 0)
		return 0;
	return 1;
}

/*
 * A URL we are willing to hand to an external HTTP client as a bare argv
 * entry. The scheme check is load bearing: it guarantees the string cannot be
 * mistaken for an option by the client's argument parser.
 */
static int at_url_ok(const char *u)
{
	static const char allowed[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
		"0123456789-._~:/?#[]@!$&'()*+,;=%";
	size_t i, n;

	if (!u || !*u)
		return 0;
	n = strlen(u);
	if (n < 8 || n >= 1000)
		return 0;
	if (strncmp(u, "http://", 7) != 0 && strncmp(u, "https://", 8) != 0)
		return 0;
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)u[i];

		if (c <= 0x20 || c >= 0x7F)
			return 0;
		if (!memchr(allowed, (int)c, sizeof(allowed) - 1))
			return 0;
	}
	return 1;
}

/* Executed in the grandchild, between fork() and execve(). Only
 * async-signal-safe calls are permitted here. */
static void at_child_exec(const char *path, char *const argv[],
			  int rfd, unsigned int timeout_s)
{
	sigset_t empty;
	int devnull;
	int i;

	setsid();

	sigemptyset(&empty);
	sigprocmask(SIG_SETMASK, &empty, NULL);
	for (i = 1; i < 32; i++) {
		if (i == SIGKILL || i == SIGSTOP)
			continue;
		signal(i, SIG_DFL);
	}

	if (rfd != 0) {
		if (dup2(rfd, 0) < 0)
			_exit(127);
	}
	devnull = open("/dev/null", O_RDWR);
	if (devnull >= 0) {
		dup2(devnull, 1);
		dup2(devnull, 2);
	}
	for (i = 3; i < AT_CHILD_MAXFD; i++)
		close(i);

	alarm(timeout_s ? timeout_s : 10);
	execve(path, argv, at_hook_envp);
	_exit(127);
}

/*
 * Push the payload into the child's stdin without ever blocking the daemon.
 * Non-blocking writes, a bounded poll loop, and SIGPIPE neutralised for the
 * duration (single-threaded daemon; see the threading note in autotune.h).
 */
static void at_write_payload(int fd, const char *buf, size_t len)
{
	struct sigaction ign, old;
	int have_old = 0;
	size_t off = 0;
	int fl, tries;

	if (fd < 0 || !buf || len == 0)
		return;

	memset(&ign, 0, sizeof(ign));
	ign.sa_handler = SIG_IGN;
	sigemptyset(&ign.sa_mask);
	if (sigaction(SIGPIPE, &ign, &old) == 0)
		have_old = 1;

	fl = fcntl(fd, F_GETFL, 0);
	if (fl >= 0)
		(void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);

	for (tries = 0; off < len && tries < 40; tries++) {
		ssize_t n = write(fd, buf + off, len - off);

		if (n > 0) {
			off += (size_t)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			struct pollfd pf;

			pf.fd = fd;
			pf.events = POLLOUT;
			pf.revents = 0;
			(void)poll(&pf, 1, 25);
			continue;
		}
		break;   /* EPIPE: the child is gone. Nothing to be done. */
	}

	if (have_old)
		(void)sigaction(SIGPIPE, &old, NULL);
}

/*
 * fork -> fork -> execve. The intermediate child is reaped immediately so the
 * daemon never accumulates zombies and never needs a SIGCHLD handler; the
 * grandchild is reparented to init and self-limits with alarm().
 */
static int at_spawn(struct autotune *at, const char *path, char *const argv[],
		    const char *payload, size_t plen)
{
	int pfd[2];
	pid_t p1;
	int st = 0;

	if (pipe(pfd) != 0)
		return -errno;

	p1 = fork();
	if (p1 < 0) {
		int e = errno;

		close(pfd[0]);
		close(pfd[1]);
		return -e;
	}
	if (p1 == 0) {
		pid_t p2 = fork();

		if (p2 == 0)
			at_child_exec(path, argv, pfd[0],
				      at->cfg.hook_timeout_s);
		_exit(p2 < 0 ? 127 : 0);
	}

	close(pfd[0]);
	while (waitpid(p1, &st, 0) < 0 && errno == EINTR)
		;
	at_write_payload(pfd[1], payload, plen);
	close(pfd[1]);
	return 0;
}

static void at_hook_fire(struct autotune *at, __u32 kind, __u64 now_ns,
			 const char *json, size_t jlen)
{
	char sevbuf[16];
	char *argv[AT_HOOK_ARGV_MAX];
	int n;

	if (!at->cfg.alerts_enabled)
		return;
	if (at->cfg.hook_path[0] == '\0' && at->cfg.webhook_url[0] == '\0')
		return;
	if (at->last_hook_ns != 0 &&
	    now_ns - at->last_hook_ns < at->cfg.hook_min_interval_ns)
		return;
	at->last_hook_ns = now_ns;

	snprintf(sevbuf, sizeof(sevbuf), "%u", (unsigned int)at->severity);

	/* Every argv element below is either a compile-time literal, an entry
	 * from a fixed name table, or a locally formatted integer. No packet
	 * data, no configuration string, no shell. */
	if (at->cfg.hook_path[0] != '\0') {
		if (!at_execpath_ok(at->cfg.hook_path)) {
			at->alerts_failed++;
			at_log(at, AT_LOG_WARN,
			       "autotune: alert hook '%s' is not a safe executable, skipped",
			       at->cfg.hook_path);
		} else {
			n = 0;
			argv[n++] = at->cfg.hook_path;
			argv[n++] = (char *)"--event";
			argv[n++] = (char *)at_event_str(kind);
			argv[n++] = (char *)"--mode";
			argv[n++] = (char *)fw_mode_str(at->mode);
			argv[n++] = (char *)"--class";
			argv[n++] = (char *)(at->class_mask ?
					     at_class_str(at->primary_class) :
					     "none");
			argv[n++] = (char *)"--severity";
			argv[n++] = sevbuf;
			argv[n] = NULL;
			if (at_spawn(at, at->cfg.hook_path, argv, json,
				     jlen) != 0) {
				at->alerts_failed++;
				at_log(at, AT_LOG_WARN,
				       "autotune: failed to spawn alert hook");
			}
		}
	}

	if (at->webhook_ok && at->cfg.webhook_url[0] != '\0') {
		char tmo[16];

		snprintf(tmo, sizeof(tmo), "%u",
			 (unsigned int)(at->cfg.hook_timeout_s ?
					at->cfg.hook_timeout_s : 10));
		n = 0;
		argv[n++] = at->webhook_client;
		argv[n++] = (char *)"-sS";
		argv[n++] = (char *)"--max-time";
		argv[n++] = tmo;
		argv[n++] = (char *)"-X";
		argv[n++] = (char *)"POST";
		argv[n++] = (char *)"-H";
		argv[n++] = (char *)"Content-Type: application/json";
		argv[n++] = (char *)"--data-binary";
		argv[n++] = (char *)"@-";
		argv[n++] = at->cfg.webhook_url;
		argv[n] = NULL;
		if (at_spawn(at, at->webhook_client, argv, json, jlen) != 0) {
			at->alerts_failed++;
			at_log(at, AT_LOG_WARN,
			       "autotune: failed to spawn webhook client");
		}
	}
}

static void at_alert_sink_open(struct autotune *at)
{
	at->alert_fd = -1;
	at->alert_fd_owned = 0;

	if (!at->cfg.alerts_enabled || at->cfg.alert_file[0] == '\0')
		return;

	if (strcmp(at->cfg.alert_file, "-") == 0) {
		at->alert_fd = 2;   /* stderr, borrowed */
		return;
	}
	if (at->cfg.alert_file[0] != '/') {
		at_log(at, AT_LOG_WARN,
		       "autotune: alert_file must be an absolute path, disabled");
		return;
	}
	at->alert_fd = open(at->cfg.alert_file,
			    O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
	if (at->alert_fd < 0) {
		at->alert_fd = -1;
		at_log(at, AT_LOG_WARN,
		       "autotune: cannot open alert file '%s': %s",
		       at->cfg.alert_file, strerror(errno));
		return;
	}
	at->alert_fd_owned = 1;
}

static void at_webhook_probe(struct autotune *at)
{
	static const char *const candidates[] = {
		"/usr/bin/curl", "/bin/curl", "/usr/local/bin/curl"
	};
	size_t i;

	at->webhook_ok = 0;
	at->webhook_client[0] = '\0';

	if (!at->cfg.alerts_enabled || at->cfg.webhook_url[0] == '\0')
		return;

	if (!at_url_ok(at->cfg.webhook_url)) {
		at_log(at, AT_LOG_ERR,
		       "autotune: webhook_url rejected (must be http:// or https:// and free of control characters), webhook disabled");
		return;
	}

	if (at->cfg.webhook_client[0] != '\0') {
		if (at_execpath_ok(at->cfg.webhook_client)) {
			snprintf(at->webhook_client, sizeof(at->webhook_client),
				 "%s", at->cfg.webhook_client);
			at->webhook_ok = 1;
		} else {
			at_log(at, AT_LOG_ERR,
			       "autotune: webhook_client '%s' is not a safe executable, webhook disabled",
			       at->cfg.webhook_client);
		}
		return;
	}

	for (i = 0; i < AT_ARRAY_SIZE(candidates); i++) {
		if (at_execpath_ok(candidates[i])) {
			snprintf(at->webhook_client, sizeof(at->webhook_client),
				 "%s", candidates[i]);
			at->webhook_ok = 1;
			return;
		}
	}
	at_log(at, AT_LOG_WARN,
	       "autotune: no curl-compatible client found for webhook_url; use hook_path instead. Webhook disabled.");
}

/* -------------------------------------------------------------------------
 * Alert construction
 * ------------------------------------------------------------------------- */

struct at_banrec {
	struct at_addr addr;
	__u64 ttl_ns;
	__u64 drops;
	__u32 offences;
	__u32 reason;
};

static void at_json_metrics(struct autotune *at, struct at_buf *b);
static __u64 at_threshold(const struct autotune *at, __u32 m);

static void at_json_time(struct at_buf *b)
{
	struct timespec rt;
	struct tm tmv;
	char iso[40];

	memset(&tmv, 0, sizeof(tmv));
	iso[0] = '\0';
	if (clock_gettime(CLOCK_REALTIME, &rt) == 0) {
		time_t secs = (time_t)rt.tv_sec;

		if (gmtime_r(&secs, &tmv) != NULL) {
			if (strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%SZ",
				     &tmv) == 0)
				iso[0] = '\0';
		}
		at_bjson_kstr(b, "ts", iso[0] ? iso : "unknown");
		at_bputc(b, ',');
		at_bjson_u64(b, "ts_unix", (__u64)rt.tv_sec);
	} else {
		at_bjson_kstr(b, "ts", "unknown");
		at_bputc(b, ',');
		at_bjson_u64(b, "ts_unix", 0);
	}
}

static void at_json_classes(struct autotune *at, struct at_buf *b)
{
	__u32 i, first = 1;

	at_bjson_str(b, "classes");
	at_bputs(b, ":[");
	for (i = 0; i < AT_C_MAX; i++) {
		if (!(at->class_mask & AT_CLS_BIT(i)))
			continue;
		if (!first)
			at_bputc(b, ',');
		first = 0;
		at_bjson_str(b, at_class_str(i));
	}
	at_bputc(b, ']');
}

static void at_json_top_reasons(struct autotune *at, struct at_buf *b)
{
	__u32 idx[6];
	__u64 val[6];
	__u32 n = 0, i, j;

	memset(idx, 0, sizeof(idx));
	memset(val, 0, sizeof(val));

	for (i = 0; i < STAT_MAX; i++) {
		__u64 r = at->rtrack[i].rate;

		if (r == 0 || !stat_reason_is_drop(i))
			continue;
		if (n < AT_ARRAY_SIZE(val)) {
			idx[n] = i;
			val[n] = r;
			n++;
		} else {
			__u32 minj = 0;

			for (j = 1; j < AT_ARRAY_SIZE(val); j++)
				if (val[j] < val[minj])
					minj = j;
			if (r > val[minj]) {
				val[minj] = r;
				idx[minj] = i;
			}
		}
	}
	/* Descending, insertion sort over at most six entries. */
	for (i = 1; i < n; i++) {
		__u64 tv = val[i];
		__u32 ti = idx[i];

		j = i;
		while (j > 0 && val[j - 1] < tv) {
			val[j] = val[j - 1];
			idx[j] = idx[j - 1];
			j--;
		}
		val[j] = tv;
		idx[j] = ti;
	}

	at_bjson_str(b, "top_drop_reasons");
	at_bputs(b, ":[");
	for (i = 0; i < n; i++) {
		if (i)
			at_bputc(b, ',');
		at_bputc(b, '{');
		at_bjson_kstr(b, "reason", stat_reason_str(idx[i]));
		at_bputc(b, ',');
		at_bjson_u64(b, "pps", val[i]);
		at_bputc(b, '}');
	}
	at_bputc(b, ']');
}

static void at_json_bans(struct at_buf *b, const struct at_banrec *bans,
			 __u32 n)
{
	char ip[INET6_ADDRSTRLEN + 4];
	__u32 i;

	at_bjson_str(b, "bans");
	at_bputs(b, ":[");
	for (i = 0; i < n && i < AT_ALERT_BANS_MAX; i++) {
		if (i)
			at_bputc(b, ',');
		at_fmt_addr(&bans[i].addr, ip, sizeof(ip));
		at_bputc(b, '{');
		at_bjson_kstr(b, "ip", ip);
		at_bputc(b, ',');
		at_bjson_u64(b, "family",
			     bans[i].addr.family == CALY_AF_INET6 ? 6 : 4);
		at_bputc(b, ',');
		at_bjson_u64(b, "ttl_ms", bans[i].ttl_ns / CALY_NSEC_PER_MSEC);
		at_bputc(b, ',');
		at_bjson_u64(b, "drops", bans[i].drops);
		at_bputc(b, ',');
		at_bjson_u64(b, "offences", bans[i].offences);
		at_bputc(b, ',');
		at_bjson_kstr(b, "reason", stat_reason_str(bans[i].reason));
		at_bputc(b, '}');
	}
	at_bputc(b, ']');
}

static void at_emit_alert(struct autotune *at, __u32 kind, __u64 now_ns,
			  __u32 prev_mode, const struct at_banrec *bans,
			  __u32 nbans, const char *detail)
{
	char json[AT_JSON_MAX];
	struct at_buf b;

	if (!at->cfg.alerts_enabled)
		return;

	at_binit(&b, json, sizeof(json) - 2);

	at_bputc(&b, '{');
	at_json_time(&b);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "ts_mono_ns", now_ns);
	at_bputc(&b, ',');
	at_bjson_kstr(&b, "node", at->cfg.node_id);
	at_bputc(&b, ',');
	at_bjson_kstr(&b, "product", "calyanti");
	at_bputc(&b, ',');
	at_bjson_u64(&b, "abi", CALY_ABI_VERSION);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "logic", AT_LOGIC_VERSION);
	at_bputc(&b, ',');
	at_bjson_kstr(&b, "event", at_event_str(kind));
	at_bputc(&b, ',');
	at_bjson_kstr(&b, "mode", fw_mode_str(at->mode));
	at_bputc(&b, ',');
	at_bjson_kstr(&b, "prev_mode", fw_mode_str(prev_mode));
	at_bputc(&b, ',');
	at_bjson_bool(&b, "pinned", at->pinned != 0);
	at_bputc(&b, ',');
	at_bjson_bool(&b, "dry_run", at->cfg.dry_run != 0);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "severity", at->severity);
	at_bputc(&b, ',');
	at_json_classes(at, &b);
	at_bputc(&b, ',');
	at_bjson_kstr(&b, "primary_class",
		      at->class_mask ? at_class_str(at->primary_class) : "none");
	at_bputc(&b, ',');
	at_bjson_u64(&b, "attack_since_ns", at->attack_since_ns);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "mode_since_ns", at->mode_since_ns);
	at_bputc(&b, ',');
	at_json_metrics(at, &b);
	at_bputc(&b, ',');
	at_json_top_reasons(at, &b);
	at_bputc(&b, ',');
	at_json_bans(&b, bans, nbans);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "bans_total", at->bans_issued);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "config_pushes", at->config_pushes);
	if (detail && *detail) {
		at_bputc(&b, ',');
		at_bjson_kstr(&b, "detail", detail);
	}
	at_bputc(&b, '}');

	/* at_binit reserved two bytes so the newline always fits. */
	b.p[b.len] = '\n';
	b.len++;
	b.p[b.len] = '\0';

	if (b.ovf)
		at_log(at, AT_LOG_WARN,
		       "autotune: alert JSON truncated (%u bytes)",
		       (unsigned int)b.len);

	if (at->alert_fd >= 0) {
		size_t off = 0;

		while (off < b.len) {
			ssize_t w = write(at->alert_fd, b.p + off, b.len - off);

			if (w > 0) {
				off += (size_t)w;
				continue;
			}
			if (w < 0 && errno == EINTR)
				continue;
			at->alerts_failed++;
			break;
		}
	}

	at_hook_fire(at, kind, now_ns, b.p, b.len);
	at->alerts_emitted++;
}

/* -------------------------------------------------------------------------
 * Sampling and differentiation
 * ------------------------------------------------------------------------- */

static __u64 at_gauge_delta(struct autotune *at, const __u64 *cur, __u32 idx)
{
	__u64 d = 0;

	if (at->have_prev_gauge && cur[idx] >= at->prev_gauge[idx])
		d = cur[idx] - at->prev_gauge[idx];
	return d;
}

static void at_compute_rates(struct autotune *at, const struct at_sample *s,
			     __u64 dt_ns)
{
	__u64 d_pkts, d_bytes, d_syn, d_newconn, d_drops, d_udp, d_icmp, d_frag;
	__u64 pps, udp, icmp;
	__u32 i;

	d_pkts    = at_gauge_delta(at, s->gauge, CALY_G_PKTS);
	d_bytes   = at_gauge_delta(at, s->gauge, CALY_G_BYTES);
	d_syn     = at_gauge_delta(at, s->gauge, CALY_G_SYN);
	d_newconn = at_gauge_delta(at, s->gauge, CALY_G_NEWCONN);
	d_drops   = at_gauge_delta(at, s->gauge, CALY_G_DROPS);
	d_udp     = at_gauge_delta(at, s->gauge, CALY_G_UDP);
	d_icmp    = at_gauge_delta(at, s->gauge, CALY_G_ICMP);
	d_frag    = at_gauge_delta(at, s->gauge, CALY_G_FRAG);

	at->last_drop_delta = d_drops;

	pps  = at_per_sec(d_pkts, dt_ns);
	udp  = at_per_sec(d_udp, dt_ns);
	icmp = at_per_sec(d_icmp, dt_ns);

	at->rate[AT_M_PPS]         = pps;
	at->rate[AT_M_BPS]         = at_per_sec(d_bytes, dt_ns);
	at->rate[AT_M_SYN_PPS]     = at_per_sec(d_syn, dt_ns);
	at->rate[AT_M_NEWCONN_PPS] = at_per_sec(d_newconn, dt_ns);
	at->rate[AT_M_UDP_PPS]     = udp;
	at->rate[AT_M_ICMP_PPS]    = icmp;
	at->rate[AT_M_FRAG_PPS]    = at_per_sec(d_frag, dt_ns);
	at->rate[AT_M_DROP_PPS]    = at_per_sec(d_drops, dt_ns);

	/* Derived: everything that is neither UDP nor ICMP. Dominated by TCP on
	 * any real host, and the only signal that separates an ACK flood from a
	 * SYN flood. */
	at->rate[AT_M_TCP_PPS] = (pps > udp + icmp) ? pps - udp - icmp : 0;

	at->rate[AT_M_UNIQ_SRC] = s->have_uniq ?
		at_per_sec(s->uniq_sources, dt_ns) :
		at->rate[AT_M_UNIQ_SRC];
	at->rate[AT_M_CONN_LEVEL] = s->have_conn ? s->conn_entries :
		at->rate[AT_M_CONN_LEVEL];
	at->rate[AT_M_PKT_SIZE] = d_pkts ? (d_bytes / d_pkts) : 0;

	for (i = 0; i < CALY_G_MAX; i++)
		at->prev_gauge[i] = s->gauge[i];
	at->have_prev_gauge = 1;
}

static void at_compute_reason_rates(struct autotune *at,
				    const struct at_sample *s, __u64 dt_ns,
				    int freeze_long)
{
	__u32 i;

	if (!s->have_stat)
		return;

	for (i = 0; i < STAT_MAX; i++) {
		struct at_rtrack *r = &at->rtrack[i];
		__u64 d = 0;

		if (at->have_prev_stat && s->stat[i] >= r->prev)
			d = s->stat[i] - r->prev;
		r->prev = s->stat[i];
		r->rate = at_per_sec(d, dt_ns);

		if (!at->have_prev_stat) {
			r->ewma_short = r->rate;
			r->ewma_long = r->rate;
			continue;
		}
		r->ewma_short = at_ewma_step(r->ewma_short, r->rate, dt_ns,
					     at->cfg.win_ns[AT_W_SHORT]);
		if (!freeze_long)
			r->ewma_long = at_ewma_step(r->ewma_long, r->rate,
						    dt_ns,
						    at->cfg.win_ns[AT_W_LONG]);
	}
	at->have_prev_stat = 1;
}

__u64 autotune_reason_rate(const struct autotune *at, __u32 reason)
{
	if (!at || reason >= STAT_MAX)
		return 0;
	return at->rtrack[reason].rate;
}

/* -------------------------------------------------------------------------
 * Anomaly detection
 * ------------------------------------------------------------------------- */

static __u64 at_threshold(const struct autotune *at, __u32 m)
{
	__u64 rel, flr;

	if (m >= AT_M_MAX || at->cfg.metric_mult[m] == 0)
		return 0;
	rel = at_mul_div(at->track[m].ewma[AT_W_LONG],
			 at->cfg.metric_mult[m], 10);
	flr = at->cfg.metric_floor[m];
	return rel > flr ? rel : flr;
}

static void at_detect(struct autotune *at, const struct fw_config *live)
{
	__u32 m, n_anom = 0, sev = 0;

	at->anom_mask = 0;
	at->abs_hi_mask = 0;

	for (m = 0; m < AT_M_MAX; m++) {
		__u64 thr = at_threshold(at, m);
		__u64 cur = at->rate[m];
		__u64 over_pct;
		__u32 s;

		at->track[m].anomalous = 0;
		if (thr == 0 || cur <= thr)
			continue;

		at->track[m].anomalous = 1;
		at->anom_mask |= (1u << m);
		n_anom++;

		/* 100% over the threshold -> 25, 400% over -> 100. */
		over_pct = at_min64(at_mul_div(cur, 100, thr), 100000ULL);
		if (over_pct <= 100)
			continue;
		s = (__u32)at_min64((over_pct - 100) / 4, 100);
		if (s > sev)
			sev = s;
	}

	/* Multiple simultaneous anomalies are much less likely to be a
	 * legitimate burst. */
	if (n_anom > 1) {
		__u32 bonus = (n_anom - 1) * 8;

		sev = (sev + bonus > 100) ? 100 : sev + bonus;
	}

	/* Operator-set absolute thresholds. These are unconditional: crossing
	 * one demands UNDER_ATTACK regardless of what the adaptive baseline
	 * thinks, because the operator has told us the box cannot serve that
	 * much traffic legitimately. */
	if (live->global_pps_hi && at->rate[AT_M_PPS] > live->global_pps_hi)
		at->abs_hi_mask |= AT_ABS_PPS;
	if (live->global_bps_hi && at->rate[AT_M_BPS] > live->global_bps_hi)
		at->abs_hi_mask |= AT_ABS_BPS;
	if (live->global_syn_pps_hi &&
	    at->rate[AT_M_SYN_PPS] > live->global_syn_pps_hi)
		at->abs_hi_mask |= AT_ABS_SYN;
	if (live->global_newconn_pps_hi &&
	    at->rate[AT_M_NEWCONN_PPS] > live->global_newconn_pps_hi)
		at->abs_hi_mask |= AT_ABS_NEWCONN;

	if (at->abs_hi_mask && sev < at->cfg.sev_attack)
		sev = at->cfg.sev_attack;

	at->severity = sev > 100 ? 100 : sev;
}

/* All operator low-water marks satisfied? Required before any de-escalation. */
static int at_below_all_lo(const struct autotune *at,
			   const struct fw_config *live)
{
	if (live->global_pps_lo && at->rate[AT_M_PPS] >= live->global_pps_lo)
		return 0;
	if (live->global_bps_lo && at->rate[AT_M_BPS] >= live->global_bps_lo)
		return 0;
	if (live->global_syn_pps_lo &&
	    at->rate[AT_M_SYN_PPS] >= live->global_syn_pps_lo)
		return 0;
	if (live->global_newconn_pps_lo &&
	    at->rate[AT_M_NEWCONN_PPS] >= live->global_newconn_pps_lo)
		return 0;
	return 1;
}

/* -------------------------------------------------------------------------
 * Classification
 * ------------------------------------------------------------------------- */

static __u64 at_reason_sum(const struct autotune *at, __u32 from, __u32 to)
{
	__u64 sum = 0;
	__u32 i;

	for (i = from; i <= to && i < STAT_MAX; i++)
		sum += at->rtrack[i].rate;
	return sum;
}

static int at_anom(const struct autotune *at, __u32 m)
{
	return (at->anom_mask & (1u << m)) != 0;
}

/* Percentage of `total` that `part` represents, saturating and division-safe. */
static __u32 at_share(__u64 part, __u64 total)
{
	if (total == 0)
		return 0;
	return (__u32)at_min64(at_mul_div(part, 100, total), 100);
}

static void at_classify(struct autotune *at, const struct fw_config *live)
{
	__u64 pps      = at->rate[AT_M_PPS];
	__u64 syn      = at->rate[AT_M_SYN_PPS];
	__u64 udp      = at->rate[AT_M_UDP_PPS];
	__u64 icmp     = at->rate[AT_M_ICMP_PPS];
	__u64 tcp      = at->rate[AT_M_TCP_PPS];
	__u64 conns    = at->rate[AT_M_CONN_LEVEL];
	__u64 psize    = at->rate[AT_M_PKT_SIZE];
	__u64 amp_drop = at->rtrack[STAT_DROP_AMP_SRCPORT].rate;
	__u64 scan_drop = at->rtrack[STAT_DROP_PORTSCAN].rate;
	__u64 frag_drop = at_reason_sum(at, STAT_DROP_FRAG_TINY,
					STAT_DROP_FRAG_ICMP);
	__u64 tcpflag_drop = at_reason_sum(at, STAT_DROP_TCP_NULL,
					   STAT_DROP_TCP_SYNACK_UNSOL);
	__u64 syn_drop  = at->rtrack[STAT_DROP_RATE_SYN].rate +
			  at->rtrack[STAT_DROP_RATE_GLOBAL_SYN].rate;
	__u64 ct_full   = at->rtrack[STAT_CT_FULL].rate;
	__u64 ct_miss   = at->rtrack[STAT_CT_MISS].rate;
	__u64 conn_cap  = live->max_conn_entries;
	__u32 sc[AT_C_MAX];
	__u32 i, best = AT_C_VOLUMETRIC, best_score = 0;

	memset(sc, 0, sizeof(sc));

	/* --- SYN flood ------------------------------------------------- */
	if (at_anom(at, AT_M_SYN_PPS) || (at->abs_hi_mask & AT_ABS_SYN))
		sc[AT_C_SYN] += 60;
	if (pps && at_share(syn, pps) >= 40)
		sc[AT_C_SYN] += 25;
	if (syn_drop > 0)
		sc[AT_C_SYN] += 15;

	/* --- ACK / PSH-ACK / RST flood ---------------------------------- *
	 * TCP volume up, handshake volume flat. That is traffic pretending to
	 * belong to sessions that were never established. */
	if (at_anom(at, AT_M_TCP_PPS) && !at_anom(at, AT_M_SYN_PPS)) {
		sc[AT_C_ACK] += 50;
		if (!at_anom(at, AT_M_NEWCONN_PPS))
			sc[AT_C_ACK] += 15;
		if (tcpflag_drop > 0 && pps && at_share(tcpflag_drop, pps) >= 5)
			sc[AT_C_ACK] += 15;
		if (ct_miss > 0 && tcp && at_share(ct_miss, tcp) >= 50)
			sc[AT_C_ACK] += 10;
	}

	/* --- UDP flood --------------------------------------------------- */
	if (at_anom(at, AT_M_UDP_PPS))
		sc[AT_C_UDP] += 60;
	if (pps && at_share(udp, pps) >= 50)
		sc[AT_C_UDP] += 20;

	/* --- Reflection / amplification ---------------------------------- *
	 * The tell is not volume, it is provenance: UDP arriving FROM a known
	 * reflector source port, in large packets. */
	if (amp_drop > 0) {
		sc[AT_C_AMP] += 50;
		if (udp && at_share(amp_drop, udp) >= 5)
			sc[AT_C_AMP] += 15;
	}
	if (psize >= 512 && at_anom(at, AT_M_UDP_PPS))
		sc[AT_C_AMP] += 25;
	if (psize >= 1200 && at_anom(at, AT_M_BPS))
		sc[AT_C_AMP] += 10;

	/* --- ICMP flood --------------------------------------------------- */
	if (at_anom(at, AT_M_ICMP_PPS))
		sc[AT_C_ICMP] += 70;
	if (pps && at_share(icmp, pps) >= 20)
		sc[AT_C_ICMP] += 20;

	/* --- Fragment flood ---------------------------------------------- */
	if (at_anom(at, AT_M_FRAG_PPS))
		sc[AT_C_FRAG] += 60;
	if (frag_drop > 0 && pps && at_share(frag_drop, pps) >= 2)
		sc[AT_C_FRAG] += 25;

	/* --- Connection-table exhaustion --------------------------------- */
	if (at_anom(at, AT_M_NEWCONN_PPS) ||
	    (at->abs_hi_mask & AT_ABS_NEWCONN))
		sc[AT_C_CONN_EXH] += 60;
	if (conn_cap && at_share(conns, conn_cap) >= 80)
		sc[AT_C_CONN_EXH] += 30;
	if (ct_full > 0)
		sc[AT_C_CONN_EXH] += 20;

	/* --- Slow-loris-like --------------------------------------------- *
	 * Lots of connections, almost no packets. The inverse signature of
	 * every volumetric class above, and the reason conn_level is tracked
	 * as a level rather than a rate. */
	if (conn_cap && at_share(conns, conn_cap) >= 60 &&
	    !at_anom(at, AT_M_PPS) && !at_anom(at, AT_M_BPS)) {
		sc[AT_C_SLOWLORIS] += 60;
		if (at_anom(at, AT_M_CONN_LEVEL))
			sc[AT_C_SLOWLORIS] += 20;
		if (!at_anom(at, AT_M_NEWCONN_PPS))
			sc[AT_C_SLOWLORIS] += 10;
	}

	/* --- Port scan ---------------------------------------------------- */
	if (scan_drop > 0)
		sc[AT_C_PORTSCAN] += 50;
	if (at->rtrack[STAT_DROP_PORTSCAN].ewma_long &&
	    scan_drop > at->rtrack[STAT_DROP_PORTSCAN].ewma_long * 4)
		sc[AT_C_PORTSCAN] += 30;
	else if (scan_drop > 100)
		sc[AT_C_PORTSCAN] += 30;

	/* --- Generic volumetric ------------------------------------------ */
	if (at_anom(at, AT_M_PPS) || at_anom(at, AT_M_BPS) ||
	    (at->abs_hi_mask & (AT_ABS_PPS | AT_ABS_BPS)))
		sc[AT_C_VOLUMETRIC] += 45;
	if (at_anom(at, AT_M_PPS) && at_anom(at, AT_M_BPS))
		sc[AT_C_VOLUMETRIC] += 15;

	at->class_mask = 0;
	for (i = 0; i < AT_C_MAX; i++) {
		at->class_score[i] = sc[i] > 100 ? 100 : sc[i];
		if (at->class_score[i] >= AT_CLASS_MIN_SCORE)
			at->class_mask |= AT_CLS_BIT(i);
		if (at->class_score[i] > best_score) {
			best_score = at->class_score[i];
			best = i;
		}
	}

	/* Something is clearly wrong but nothing matched a signature: call it
	 * volumetric so the generic response (pps/bps tightening + bans) still
	 * engages. Never leave an escalation without a class. */
	if (at->class_mask == 0 && at->severity >= at->cfg.sev_elevate) {
		at->class_mask = AT_CLS_VOLUMETRIC;
		best = AT_C_VOLUMETRIC;
	}
	at->primary_class = best;
}

/* -------------------------------------------------------------------------
 * Configuration synthesis
 * ------------------------------------------------------------------------- */

/* Percentage of the operator's configured limit that each mode allows. */
static const __u32 at_mode_pct[FW_MODE_MAX] = {
	100,  /* NORMAL       */
	50,   /* ELEVATED     */
	25,   /* UNDER_ATTACK */
	10,   /* LOCKDOWN     */
	100   /* MONITOR_ONLY */
};

/* Absolute floors. No escalation path may take a bucket below these: a
 * limiter that reaches zero is a black hole, and a black hole is an outage we
 * caused ourselves. */
static const __u64 at_tb_rate_floor[CALY_TB_MAX] = {
	2000,        /* PPS     */
	2000000,     /* BPS  ~16 Mbit/s */
	100,         /* SYN     */
	1000,        /* UDP     */
	20,          /* ICMP    */
	50           /* NEWCONN */
};

static const __u64 at_tb_burst_floor[CALY_TB_MAX] = {
	2000, 2000000, 100, 1000, 20, 50
};

/* Extra pressure applied to one bucket when a class is asserted. */
struct at_press {
	__u32 cls_bit;
	__u32 kind;
	__u32 pct;
};

static const struct at_press at_press_tab[] = {
	{ AT_CLS_SYN,        CALY_TB_SYN,     50 },
	{ AT_CLS_ACK,        CALY_TB_PPS,     50 },
	{ AT_CLS_UDP,        CALY_TB_UDP,     50 },
	{ AT_CLS_UDP,        CALY_TB_BPS,     50 },
	{ AT_CLS_AMP,        CALY_TB_UDP,     70 },
	{ AT_CLS_ICMP,       CALY_TB_ICMP,    25 },
	{ AT_CLS_FRAG,       CALY_TB_PPS,     75 },
	{ AT_CLS_CONN_EXH,   CALY_TB_NEWCONN, 40 },
	{ AT_CLS_SLOWLORIS,  CALY_TB_NEWCONN, 60 },
	{ AT_CLS_VOLUMETRIC, CALY_TB_PPS,     60 },
	{ AT_CLS_VOLUMETRIC, CALY_TB_BPS,     60 }
};

static __u64 at_scale_down(__u64 v, __u32 pct, __u64 floor_v)
{
	__u64 r;

	if (v == 0)
		return 0;              /* disabled stays disabled */
	if (pct >= 100)
		return v;
	r = at_mul_div(v, pct, 100);
	if (r < floor_v)
		r = floor_v;
	if (r > v)
		r = v;                 /* a floor above the operator's value
					* must never LOOSEN the limiter */
	if (r == 0)
		r = 1;
	return r;
}

static __u64 at_scale_up(__u64 v, __u32 pct, __u64 cap)
{
	__u64 r;

	if (v == 0)
		return 0;
	if (pct <= 100)
		return v;
	r = at_mul_div(v, pct, 100);
	if (cap && r > cap)
		r = cap;
	if (r < v)
		r = v;
	return r;
}

static __u32 at_kind_pct(__u32 mode_pct, __u32 cls_mask, __u32 kind)
{
	__u32 pct = mode_pct;
	size_t i;

	for (i = 0; i < AT_ARRAY_SIZE(at_press_tab); i++) {
		__u32 c;

		if (at_press_tab[i].kind != kind)
			continue;
		if (!(cls_mask & at_press_tab[i].cls_bit))
			continue;
		c = (mode_pct * at_press_tab[i].pct) / 100u;
		if (c < pct)
			pct = c;       /* strongest single press wins; presses
					* do not compound into zero */
	}
	return pct;
}

/*
 * TCP/22 is not negotiable. The loader enforces this too; enforcing it again
 * here means no code path in this module - not a bug, not a bad tunable, not a
 * corrupted baseline - can produce a configuration that locks the operator out
 * of a machine that is under attack.
 */
static int at_enforce_mgmt(struct fw_config *c)
{
	__u32 n = c->mgmt_tcp_count;
	__u32 i;
	int repaired = 0;

	if (n > CALY_MGMT_PORTS_MAX) {
		n = CALY_MGMT_PORTS_MAX;
		repaired = 1;
	}
	for (i = 0; i < n; i++)
		if (c->mgmt_tcp_ports[i] == 22)
			break;
	if (i == n) {
		if (n < CALY_MGMT_PORTS_MAX) {
			c->mgmt_tcp_ports[n] = 22;
			n++;
		} else {
			c->mgmt_tcp_ports[CALY_MGMT_PORTS_MAX - 1] = 22;
		}
		repaired = 1;
	}
	if (n == 0) {
		c->mgmt_tcp_ports[0] = 22;
		n = 1;
		repaired = 1;
	}
	c->mgmt_tcp_count = n;
	if (c->mgmt_udp_count > CALY_MGMT_PORTS_MAX) {
		c->mgmt_udp_count = CALY_MGMT_PORTS_MAX;
		repaired = 1;
	}
	return repaired;
}

/* Last gate before a map write. A failure here abandons the push; the
 * previously applied configuration keeps running. */
static int at_config_sane(struct autotune *at, const struct fw_config *c)
{
	__u32 i;
	int found22 = 0;

	if ((c->abi_version >> 16) != CALY_ABI_VERSION_MAJOR) {
		at_log(at, AT_LOG_ERR,
		       "autotune: refusing config push, ABI major %llu != %u",
		       (unsigned long long)(c->abi_version >> 16),
		       (unsigned int)CALY_ABI_VERSION_MAJOR);
		return 0;
	}
	if (c->mode >= FW_MODE_MAX) {
		at_log(at, AT_LOG_ERR,
		       "autotune: refusing config push, invalid mode %u",
		       (unsigned int)c->mode);
		return 0;
	}
	if (c->mgmt_tcp_count == 0 || c->mgmt_tcp_count > CALY_MGMT_PORTS_MAX)
		return 0;
	for (i = 0; i < c->mgmt_tcp_count; i++)
		if (c->mgmt_tcp_ports[i] == 22)
			found22 = 1;
	if (!found22) {
		at_log(at, AT_LOG_ERR,
		       "autotune: refusing config push, TCP/22 missing from mgmt list");
		return 0;
	}
	if ((c->flags & CALY_F_ENABLED) != (at->base.flags & CALY_F_ENABLED)) {
		at_log(at, AT_LOG_ERR,
		       "autotune: refusing config push, CALY_F_ENABLED changed");
		return 0;
	}
	if ((at->base.flags & CALY_F_ALLOWLIST) &&
	    !(c->flags & CALY_F_ALLOWLIST)) {
		at_log(at, AT_LOG_ERR,
		       "autotune: refusing config push, allowlist would be disabled");
		return 0;
	}
	if (c->mode == FW_MODE_LOCKDOWN &&
	    !(c->flags & (CALY_F_ALLOWLIST | CALY_F_MGMT_BYPASS_ALL))) {
		at_log(at, AT_LOG_ERR,
		       "autotune: refusing lockdown without allowlist/mgmt bypass");
		return 0;
	}
	/* Map sizing and verifier bounds are load-time properties. Changing
	 * them at runtime does nothing useful and desynchronises the daemon's
	 * view of the maps it already created. */
	if (c->max_ban_entries    != at->base.max_ban_entries    ||
	    c->max_conn_entries   != at->base.max_conn_entries   ||
	    c->max_rate_entries   != at->base.max_rate_entries   ||
	    c->max_scan_entries   != at->base.max_scan_entries   ||
	    c->max_srcstat_entries != at->base.max_srcstat_entries ||
	    c->max_allow_entries  != at->base.max_allow_entries  ||
	    c->max_block_entries  != at->base.max_block_entries  ||
	    c->max_iface_entries  != at->base.max_iface_entries  ||
	    c->vlan_max_depth     != at->base.vlan_max_depth     ||
	    c->ip6_ext_max        != at->base.ip6_ext_max        ||
	    c->tunnel_max_depth   != at->base.tunnel_max_depth) {
		at_log(at, AT_LOG_ERR,
		       "autotune: refusing config push, load-time sizing changed");
		return 0;
	}
	return 1;
}

static void at_build_config(struct autotune *at, const struct fw_config *live,
			    __u32 mode, __u32 cls, struct fw_config *out)
{
	__u32 mode_pct;
	__u32 k;
	__u64 f;

	*out = at->base;

	if (mode >= FW_MODE_MAX)
		mode = FW_MODE_NORMAL;
	mode_pct = at_mode_pct[mode];
	out->mode = mode;

	/* Identity: keep the loader's ABI stamp and the loader-probed
	 * capability bits, which are read-only to policy. */
	out->abi_version = live->abi_version ? live->abi_version :
					       CALY_ABI_VERSION;
	f = (at->base.flags & CALY_F_OPERATOR_MASK) |
	    (live->flags & CALY_F_CAP_MASK);

	/* ---- per-source token buckets ---- */
	for (k = 0; k < CALY_TB_MAX; k++) {
		__u32 pct = at_kind_pct(mode_pct, cls, k);

		out->tb_rate[k]  = at_scale_down(at->base.tb_rate[k], pct,
						 at_tb_rate_floor[k]);
		out->tb_burst[k] = at_scale_down(at->base.tb_burst[k], pct,
						 at_tb_burst_floor[k]);
	}

	/* ---- pre-5.15 global SYN cap ---- */
	out->syn_fallback_pps = at_scale_down(at->base.syn_fallback_pps,
					      at_kind_pct(mode_pct, cls,
							  CALY_TB_SYN),
					      5000);

	/* ---- banning gets harsher as the mode rises ---- */
	if (mode == FW_MODE_UNDER_ATTACK)
		out->ban_ttl_base_ns = at_scale_up(at->base.ban_ttl_base_ns,
						   200,
						   at->base.ban_ttl_max_ns);
	else if (mode == FW_MODE_LOCKDOWN)
		out->ban_ttl_base_ns = at_scale_up(at->base.ban_ttl_base_ns,
						   400,
						   at->base.ban_ttl_max_ns);

	if (at->base.strike_limit > 2) {
		if (mode == FW_MODE_UNDER_ATTACK)
			out->strike_limit = at_clamp32(
				at->base.strike_limit / 2, 2,
				at->base.strike_limit);
		else if (mode == FW_MODE_LOCKDOWN)
			out->strike_limit = at_clamp32(
				at->base.strike_limit / 4, 2,
				at->base.strike_limit);
	}

	/* ---- class-specific knobs ---- */
	if ((cls & AT_CLS_PORTSCAN) && mode >= FW_MODE_ELEVATED &&
	    mode <= FW_MODE_LOCKDOWN)
		out->scan_port_threshold = (__u32)at_scale_down(
			at->base.scan_port_threshold, mode_pct, 8);

	if ((cls & (AT_CLS_CONN_EXH | AT_CLS_SLOWLORIS)) &&
	    mode >= FW_MODE_ELEVATED && mode <= FW_MODE_LOCKDOWN) {
		/* Reclaim table slots faster: half-open and idle-established
		 * entries are exactly what both attacks hoard. */
		out->ct_tcp_syn_ns = at_scale_down(at->base.ct_tcp_syn_ns,
						   mode_pct,
						   2ULL * CALY_NSEC_PER_SEC);
		out->ct_tcp_est_ns = at_scale_down(at->base.ct_tcp_est_ns,
						   mode_pct,
						   60ULL * CALY_NSEC_PER_SEC);
	}

	/* ---- telemetry cost control ---- */
	if (at->base.log_sample_rate != 0) {
		__u32 up = 100;

		if (mode == FW_MODE_ELEVATED)
			up = 200;
		else if (mode == FW_MODE_UNDER_ATTACK)
			up = 400;
		else if (mode == FW_MODE_LOCKDOWN)
			up = 800;
		out->log_sample_rate = (__u32)at_scale_up(
			at->base.log_sample_rate, up, 1000000);
	}

	/* ---- policy flags ----
	 * Only the bits explicitly authorised by at_tunables may be turned ON
	 * here, and no operator bit is ever turned OFF. */
	if (mode >= FW_MODE_ELEVATED && mode <= FW_MODE_LOCKDOWN) {
		if ((cls & AT_CLS_SYN) && at->cfg.allow_synproxy &&
		    (live->flags & CALY_F_CAP_SYNPROXY))
			f |= CALY_F_SYNPROXY;
		if ((cls & AT_CLS_AMP) && at->cfg.allow_amp_override)
			f |= CALY_F_ANTI_AMPLIFY;
		if ((cls & AT_CLS_PORTSCAN) && at->cfg.allow_portscan_enable)
			f |= CALY_F_PORTSCAN_DETECT;
	}

	if (mode == FW_MODE_LOCKDOWN) {
		/* Forced ON, never off: without these, LOCKDOWN is an outage
		 * rather than a defence. */
		f |= CALY_F_ALLOWLIST;
		f |= CALY_F_MGMT_BYPASS_ALL;
		f |= CALY_F_LOCKDOWN_ICMP;
		f |= CALY_F_CONNTRACK;
		f |= CALY_F_DEFAULT_DENY;
		if ((cls & AT_CLS_FRAG) && at->cfg.allow_drop_all_frags)
			f |= CALY_F_DROP_ALL_FRAGS;
	}

	out->flags = f;
	out->config_gen = live->config_gen;

	at_enforce_mgmt(out);
}

/* Equality ignoring config_gen, which we bump on every push by definition. */
static int at_config_equal(const struct fw_config *a, const struct fw_config *b)
{
	struct fw_config tmp = *a;

	tmp.config_gen = b->config_gen;
	return memcmp(&tmp, b, sizeof(tmp)) == 0;
}

static int at_push_config(struct autotune *at, const struct fw_config *live,
			  __u32 mode, __u32 cls)
{
	struct fw_config cand;
	int rc;

	at_build_config(at, live, mode, cls, &cand);

	if (!at_config_sane(at, &cand)) {
		at->config_rejected++;
		return -EINVAL;
	}
	if (at->have_applied && at_config_equal(&cand, &at->applied))
		return 0;

	cand.config_gen = live->config_gen + 1;

	if (at->cfg.dry_run) {
		at->applied = cand;
		at->have_applied = 1;
		at->config_pushes++;
		at_log(at, AT_LOG_INFO,
		       "autotune: [dry-run] would push config gen %llu mode %s",
		       (unsigned long long)cand.config_gen,
		       fw_mode_str(cand.mode));
		return 0;
	}
	if (!at->ops.config_write) {
		at->config_rejected++;
		return -ENOSYS;
	}
	rc = at->ops.config_write(at->ops.ctx, &cand);
	if (rc != 0) {
		at->config_rejected++;
		at_log(at, AT_LOG_ERR,
		       "autotune: config write failed (%d); previous configuration keeps running",
		       rc);
		return rc;
	}
	at->applied = cand;
	at->have_applied = 1;
	at->config_pushes++;
	at_log(at, AT_LOG_INFO,
	       "autotune: config gen %llu applied, mode=%s pps=%llu syn=%llu udp=%llu newconn=%llu",
	       (unsigned long long)cand.config_gen, fw_mode_str(cand.mode),
	       (unsigned long long)cand.tb_rate[CALY_TB_PPS],
	       (unsigned long long)cand.tb_rate[CALY_TB_SYN],
	       (unsigned long long)cand.tb_rate[CALY_TB_UDP],
	       (unsigned long long)cand.tb_rate[CALY_TB_NEWCONN]);
	return 0;
}

/* -------------------------------------------------------------------------
 * Side policy that does not live in fw_config: amplifier source ports and
 * ICMP echo policy. Both are applied only when we can read the previous value
 * first, so de-escalation restores the operator's configuration exactly.
 * ------------------------------------------------------------------------- */

static void at_amp_apply(struct autotune *at, int engage)
{
	static const __u16 amp_ports[CALY_AMP_PORTS_COUNT] = CALY_AMP_PORTS_INIT;
	struct port_rule pr;
	__u32 i;

	if (!at->cfg.allow_amp_override)
		return;
	if (!at->ops.port_rule_get || !at->ops.port_rule_set)
		return;

	if (engage) {
		if (at->amp_touched_n != 0)
			return;   /* already engaged */
		for (i = 0; i < CALY_AMP_PORTS_COUNT; i++) {
			memset(&pr, 0, sizeof(pr));
			if (at->ops.port_rule_get(at->ops.ctx, 1, amp_ports[i],
						  &pr) != 0)
				continue;
			if (pr.flags & CALY_PORT_F_AMPLIFIER)
				continue;   /* operator already has it on */
			if (pr.flags & CALY_PORT_F_MGMT)
				continue;   /* never touch a mgmt port */
			pr.flags |= CALY_PORT_F_AMPLIFIER;
			if (at->cfg.dry_run ||
			    at->ops.port_rule_set(at->ops.ctx, 1, amp_ports[i],
						  &pr) == 0) {
				if (at->amp_touched_n <
				    CALY_AMP_PORTS_COUNT)
					at->amp_touched[at->amp_touched_n++] =
						amp_ports[i];
			}
		}
		if (at->amp_touched_n)
			at_log(at, AT_LOG_INFO,
			       "autotune: reflection filter re-asserted on %u UDP source ports",
			       (unsigned int)at->amp_touched_n);
	} else {
		for (i = 0; i < at->amp_touched_n; i++) {
			memset(&pr, 0, sizeof(pr));
			if (at->ops.port_rule_get(at->ops.ctx, 1,
						  at->amp_touched[i],
						  &pr) != 0)
				continue;
			pr.flags &= ~(__u32)CALY_PORT_F_AMPLIFIER;
			if (!at->cfg.dry_run)
				(void)at->ops.port_rule_set(at->ops.ctx, 1,
							    at->amp_touched[i],
							    &pr);
		}
		if (at->amp_touched_n)
			at_log(at, AT_LOG_INFO,
			       "autotune: reflection filter restored on %u UDP source ports",
			       (unsigned int)at->amp_touched_n);
		at->amp_touched_n = 0;
	}
}

static void at_icmp_apply(struct autotune *at, int engage)
{
	__u32 pol;

	if (!at->cfg.allow_icmp_policy)
		return;
	if (!at->ops.icmp_pol_get || !at->ops.icmp_pol_set)
		return;

	if (engage) {
		if (!at->icmp4_echo_changed &&
		    at->ops.icmp_pol_get(at->ops.ctx, 0, CALY_ICMP4_ECHO,
					 &pol) == 0) {
			if (pol == CALY_ICMP_PASS) {
				at->icmp4_echo_saved = pol;
				if (at->cfg.dry_run ||
				    at->ops.icmp_pol_set(at->ops.ctx, 0,
							 CALY_ICMP4_ECHO,
							 CALY_ICMP_RATELIMIT)
				    == 0)
					at->icmp4_echo_changed = 1;
			}
		}
		if (!at->icmp6_echo_changed &&
		    at->ops.icmp_pol_get(at->ops.ctx, 1,
					 CALY_ICMP6_ECHO_REQUEST, &pol) == 0) {
			if (pol == CALY_ICMP_PASS) {
				at->icmp6_echo_saved = pol;
				if (at->cfg.dry_run ||
				    at->ops.icmp_pol_set(at->ops.ctx, 1,
							 CALY_ICMP6_ECHO_REQUEST,
							 CALY_ICMP_RATELIMIT)
				    == 0)
					at->icmp6_echo_changed = 1;
			}
		}
	} else {
		if (at->icmp4_echo_changed) {
			if (!at->cfg.dry_run)
				(void)at->ops.icmp_pol_set(at->ops.ctx, 0,
							   CALY_ICMP4_ECHO,
							   at->icmp4_echo_saved);
			at->icmp4_echo_changed = 0;
		}
		if (at->icmp6_echo_changed) {
			if (!at->cfg.dry_run)
				(void)at->ops.icmp_pol_set(at->ops.ctx, 1,
							   CALY_ICMP6_ECHO_REQUEST,
							   at->icmp6_echo_saved);
			at->icmp6_echo_changed = 0;
		}
	}
	/* NOTE: the mandatory types (ICMPv4 type 3; ICMPv6 2/133/134/135/136)
	 * are never touched by any path in this module. PMTUD and IPv6
	 * neighbour discovery survive every escalation. */
}

static void at_side_policy(struct autotune *at, __u32 mode, __u32 cls)
{
	int active = (mode >= FW_MODE_ELEVATED && mode <= FW_MODE_LOCKDOWN);

	at_amp_apply(at, active && (cls & AT_CLS_AMP) != 0);
	at_icmp_apply(at, active && (cls & AT_CLS_ICMP) != 0);
}

/* -------------------------------------------------------------------------
 * Mode state machine
 * ------------------------------------------------------------------------- */

static __u32 at_target_mode(struct autotune *at, const struct fw_config *live,
			    __u64 now_ns)
{
	__u32 adaptive = FW_MODE_NORMAL;
	__u32 absolute = FW_MODE_NORMAL;
	__u32 target;
	int warmed;

	(void)live;

	warmed = (at->sample_count >= 8) &&
		 (at->first_ts_ns != 0) &&
		 (now_ns - at->first_ts_ns >= at->cfg.warmup_ns);

	if (warmed) {
		if (at->severity >= at->cfg.sev_lockdown)
			adaptive = FW_MODE_LOCKDOWN;
		else if (at->severity >= at->cfg.sev_attack)
			adaptive = FW_MODE_UNDER_ATTACK;
		else if (at->severity >= at->cfg.sev_elevate)
			adaptive = FW_MODE_ELEVATED;
	}

	/* Absolute operator thresholds apply from the first sample; a box that
	 * boots into an ongoing flood has no usable baseline and must not have
	 * to wait out the warm-up before defending itself. */
	if (at->abs_hi_mask)
		absolute = FW_MODE_UNDER_ATTACK;

	target = adaptive > absolute ? adaptive : absolute;

	if (target == FW_MODE_LOCKDOWN && !at->cfg.allow_lockdown)
		target = FW_MODE_UNDER_ATTACK;

	return target;
}

/*
 * One rung per decision, in both directions. Escalation needs confirm_up
 * consecutive confirming samples; de-escalation needs confirm_down consecutive
 * quiet samples AND the operator's attack_dwell to have elapsed since the mode
 * last changed. Together these are what stop an attacker from making the box
 * oscillate by probing just above and just below the threshold.
 */
static __u32 at_step_mode(struct autotune *at, const struct fw_config *live,
			  __u64 now_ns)
{
	__u32 target = at_target_mode(at, live, now_ns);
	__u64 dwell;

	at->target_mode = target;

	if (at->pinned)
		return at->mode;

	/* MONITOR_ONLY as a mode is an operator state; if we somehow find
	 * ourselves in it without being pinned, treat it as NORMAL for the
	 * purposes of stepping. */
	if (at->mode >= FW_MODE_MONITOR_ONLY)
		return at->mode;

	if (target > at->mode) {
		at->down_count = 0;
		if (at->up_count < 0xFFFFFFFFu)
			at->up_count++;
		if (at->up_count >= at->cfg.confirm_up) {
			at->up_count = 0;
			return at->mode + 1;
		}
		return at->mode;
	}

	if (target < at->mode) {
		at->up_count = 0;

		if (!at_below_all_lo(at, live)) {
			at->down_count = 0;
			return at->mode;
		}
		dwell = live->attack_dwell_ns;
		if (at->mode == FW_MODE_LOCKDOWN)
			dwell += at->cfg.lockdown_extra_dwell_ns;
		if (at->mode_since_ns != 0 &&
		    now_ns - at->mode_since_ns < dwell) {
			/* Keep counting quiet samples but do not act yet. */
			if (at->down_count < 0xFFFFFFFFu)
				at->down_count++;
			return at->mode;
		}
		if (at->down_count < 0xFFFFFFFFu)
			at->down_count++;
		if (at->down_count >= at->cfg.confirm_down) {
			at->down_count = 0;
			return at->mode - 1;
		}
		return at->mode;
	}

	at->up_count = 0;
	at->down_count = 0;
	return at->mode;
}

/* -------------------------------------------------------------------------
 * Auto-ban
 * ------------------------------------------------------------------------- */

static void at_sort_offenders(struct at_offender *o, __u32 n)
{
	__u32 i, j;

	for (i = 1; i < n; i++) {
		struct at_offender tmp = o[i];

		j = i;
		while (j > 0 && o[j - 1].drops_delta < tmp.drops_delta) {
			o[j] = o[j - 1];
			j--;
		}
		o[j] = tmp;
	}
}

static __u32 at_ban_reason(const struct autotune *at)
{
	if (!at->class_mask)
		return STAT_DROP_RATE_PPS;
	switch (at->primary_class) {
	case AT_C_SYN:       return STAT_DROP_RATE_SYN;
	case AT_C_ACK:       return STAT_DROP_RATE_PPS;
	case AT_C_UDP:       return STAT_DROP_RATE_UDP;
	case AT_C_AMP:       return STAT_DROP_AMP_SRCPORT;
	case AT_C_ICMP:      return STAT_DROP_RATE_ICMP;
	case AT_C_FRAG:      return STAT_DROP_FRAG_POLICY;
	case AT_C_CONN_EXH:  return STAT_DROP_RATE_NEWCONN;
	case AT_C_SLOWLORIS: return STAT_DROP_RATE_NEWCONN;
	case AT_C_PORTSCAN:  return STAT_DROP_PORTSCAN;
	default:             return STAT_DROP_RATE_PPS;
	}
}

static __u64 at_ban_base_ttl(const struct autotune *at,
			     const struct fw_config *live)
{
	__u64 ttl;

	if (at->class_mask & AT_CLS_AMP)
		ttl = live->ban_ttl_amp_ns;
	else if (at->class_mask & AT_CLS_PORTSCAN)
		ttl = live->ban_ttl_scan_ns;
	else
		ttl = live->ban_ttl_base_ns;

	if (ttl == 0)
		ttl = live->ban_ttl_base_ns;
	if (ttl == 0)
		ttl = 60ULL * CALY_NSEC_PER_SEC;
	return ttl;
}

static __u32 at_autoban(struct autotune *at, const struct fw_config *live,
			__u64 now_ns, struct at_banrec *recs, __u32 rec_max)
{
	struct at_offender top[AT_TOP_MAX];
	struct at_banrec local[AT_TOP_MAX];
	__u32 nrec = 0;
	__u64 base_ttl, max_ttl;
	__u64 cur_g_drops, interval_g_drops;
	__u32 reason;
	int n, i;
	__u32 banned = 0;

	if (!at->cfg.allow_autoban || !at->ops.top_offenders ||
	    !at->ops.ban_add)
		return 0;
	if (!(at->base.flags & CALY_F_AUTOBAN))
		return 0;
	/* Banning in monitor-only would fill the ban LRU with entries the
	 * dataplane will never act on. Observe and report instead. */
	if (at->base.flags & CALY_F_MONITOR_ONLY)
		return 0;
	if (at->mode < FW_MODE_ELEVATED || at->mode > FW_MODE_LOCKDOWN)
		return 0;
	if (at->last_ban_pass_ns != 0 &&
	    now_ns - at->last_ban_pass_ns < at->cfg.ban_interval_ns)
		return 0;
	at->last_ban_pass_ns = now_ns;

	/* Global drop count accumulated over THIS ban-pass interval. Each
	 * source's drops_delta below is likewise measured over the interval
	 * between consecutive ban passes, so dividing one by the other yields a
	 * true per-interval share. Reusing at->last_drop_delta here (a single
	 * tick's global delta) would divide an interval numerator by a per-tick
	 * denominator and inflate every source's share, defeating the
	 * ban_min_share_pct floor. prev_gauge[CALY_G_DROPS] is the cumulative
	 * value from the sample at_compute_rates just processed this step. */
	cur_g_drops = at->prev_gauge[CALY_G_DROPS];
	interval_g_drops = (cur_g_drops >= at->last_ban_pass_drops) ?
			   cur_g_drops - at->last_ban_pass_drops : 0;
	at->last_ban_pass_drops = cur_g_drops;

	memset(top, 0, sizeof(top));
	n = at->ops.top_offenders(at->ops.ctx, top, AT_TOP_MAX);
	if (n <= 0)
		return 0;
	if ((__u32)n > AT_TOP_MAX)
		n = (int)AT_TOP_MAX;

	/* Differentiate each source's cumulative drop count against our own
	 * memory of it, so maps.c does not have to keep a previous-sample
	 * table and a long-lived heavy talker is not banned for history. */
	for (i = 0; i < n; i++) {
		struct at_srcmem *m;
		int created = 0;

		if (!at_addr_valid(&top[i].addr)) {
			top[i].drops_delta = 0;
			continue;
		}
		m = at_srcmem_get(at, &top[i].addr, now_ns, &created);
		if (!m || created) {
			/* No prior baseline for this source: either we have no
			 * per-source memory at all, or this is the first time we
			 * have seen it (a fresh or recycled slot). src_stats.drops
			 * is a pinned, restart-surviving LIFETIME total; treating
			 * it as one interval's worth would ban a long-lived heavy
			 * talker for its history. Seed the baseline if we can and
			 * observe only this pass. */
			if (m) {
				m->prev_drops = top[i].st.drops;
				m->prev_pkts = top[i].st.packets;
			}
			top[i].drops_delta = 0;
			top[i].pkts_delta = 0;
			top[i].share_pct = 0;
			continue;
		}
		top[i].drops_delta = (top[i].st.drops >= m->prev_drops) ?
			top[i].st.drops - m->prev_drops : top[i].st.drops;
		top[i].pkts_delta = (top[i].st.packets >= m->prev_pkts) ?
			top[i].st.packets - m->prev_pkts : top[i].st.packets;
		m->prev_drops = top[i].st.drops;
		m->prev_pkts = top[i].st.packets;
		top[i].share_pct = at_share(top[i].drops_delta,
					    interval_g_drops);
	}

	at_sort_offenders(top, (__u32)n);

	base_ttl = at_ban_base_ttl(at, live);
	max_ttl = live->ban_ttl_max_ns ? live->ban_ttl_max_ns :
					 base_ttl * 16;
	reason = at_ban_reason(at);

	for (i = 0; i < n && banned < at->cfg.max_bans_per_tick; i++) {
		struct at_srcmem *m;
		struct ban_entry be;
		struct ban_entry old;
		__u64 ttl;
		int have_old = 0;

		if (!at_addr_valid(&top[i].addr))
			continue;
		if (top[i].drops_delta < at->cfg.ban_min_drops)
			continue;
		if (interval_g_drops &&
		    top[i].share_pct < at->cfg.ban_min_share_pct)
			continue;

		/* The dataplane checks the allowlist before the ban map, so an
		 * allowlisted source could never be dropped anyway; skipping
		 * here just keeps the ban table honest. */
		if (at->ops.is_allowlisted &&
		    at->ops.is_allowlisted(at->ops.ctx, &top[i].addr) == 1) {
			at->bans_suppressed++;
			continue;
		}

		m = at_srcmem_get(at, &top[i].addr, now_ns, NULL);

		memset(&old, 0, sizeof(old));
		if (at->ops.ban_lookup &&
		    at->ops.ban_lookup(at->ops.ctx, &top[i].addr, &old) == 0)
			have_old = 1;

		/* Escalation source of truth, best first: the live ban entry,
		 * then our own memory, then the base TTL. */
		if (have_old && old.cur_ttl_ns) {
			ttl = caly_ban_next_ttl(old.cur_ttl_ns, base_ttl,
						max_ttl,
						live->ban_escalate_num,
						live->ban_escalate_den);
		} else if (m && m->cur_ttl_ns &&
			   now_ns < m->ban_expires_ns + max_ttl) {
			ttl = caly_ban_next_ttl(m->cur_ttl_ns, base_ttl,
						max_ttl,
						live->ban_escalate_num,
						live->ban_escalate_den);
		} else {
			ttl = base_ttl;
		}
		if (ttl > max_ttl)
			ttl = max_ttl;
		if (ttl == 0)
			ttl = base_ttl;

		/* Already banned for at least as long: leave it alone rather
		 * than churning the LRU. */
		if (have_old && !(old.flags & CALY_BAN_F_PERMANENT) &&
		    old.expiry_ns > now_ns + ttl) {
			at->bans_suppressed++;
			continue;
		}
		/* Never touch a ban we do not own. This module only ever writes
		 * finite CALY_BAN_F_AUTO entries; MANUAL (operator/CLI),
		 * PERMANENT (operator) and FEED (threat feed) bans belong to
		 * someone else. Overwriting one would silently downgrade a
		 * permanent block to a finite auto-ban and erase its provenance,
		 * making the source reachable again once the TTL expires. */
		if (have_old && (old.flags & (CALY_BAN_F_MANUAL |
					      CALY_BAN_F_PERMANENT |
					      CALY_BAN_F_FEED))) {
			at->bans_suppressed++;
			continue;
		}

		memset(&be, 0, sizeof(be));
		be.expiry_ns     = now_ns + ttl;
		be.first_seen_ns = (have_old && old.first_seen_ns) ?
				   old.first_seen_ns : now_ns;
		be.last_hit_ns   = have_old ? old.last_hit_ns : 0;
		be.cur_ttl_ns    = ttl;
		be.hit_pkts      = have_old ? old.hit_pkts : 0;
		be.hit_bytes     = have_old ? old.hit_bytes : 0;
		be.reason        = reason;
		be.strikes       = have_old ? old.strikes : 0;
		be.offences      = (have_old ? old.offences : (m ? m->offences : 0)) + 1;
		be.flags         = CALY_BAN_F_AUTO;
		if (ttl > base_ttl)
			be.flags |= CALY_BAN_F_ESCALATED;
		/* INVARIANT: this module never issues a permanent ban.
		 * CALY_BAN_F_PERMANENT belongs to the operator alone, and every
		 * entry we write carries a finite expiry the dataplane and the
		 * GC sweep both honour. */

		if (!at->cfg.dry_run) {
			if (at->ops.ban_add(at->ops.ctx, &top[i].addr,
					    &be) != 0) {
				at->bans_suppressed++;
				continue;
			}
		}

		if (m) {
			m->cur_ttl_ns = ttl;
			m->last_ban_ns = now_ns;
			m->ban_expires_ns = be.expiry_ns;
			m->offences = be.offences;
		}
		at->bans_issued++;
		banned++;

		if (nrec < AT_ARRAY_SIZE(local)) {
			local[nrec].addr = top[i].addr;
			local[nrec].ttl_ns = ttl;
			local[nrec].drops = top[i].drops_delta;
			local[nrec].offences = be.offences;
			local[nrec].reason = reason;
			nrec++;
		}
	}

	if (recs && rec_max) {
		__u32 copy = nrec < rec_max ? nrec : rec_max;

		memcpy(recs, local, copy * sizeof(local[0]));
		return copy;
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * JSON metrics block (shared by alerts and the status report)
 * ------------------------------------------------------------------------- */

static void at_json_metrics(struct autotune *at, struct at_buf *b)
{
	__u32 m;

	at_bjson_str(b, "metrics");
	at_bputc(b, ':');
	at_bputc(b, '{');
	for (m = 0; m < AT_M_MAX; m++) {
		if (m)
			at_bputc(b, ',');
		at_bjson_str(b, at_metric_str(m));
		at_bputs(b, ":{");
		at_bjson_u64(b, "cur", at->rate[m]);
		at_bputc(b, ',');
		at_bjson_u64(b, "s10", at->track[m].ewma[AT_W_SHORT]);
		at_bputc(b, ',');
		at_bjson_u64(b, "m60", at->track[m].ewma[AT_W_MED]);
		at_bputc(b, ',');
		at_bjson_u64(b, "l900", at->track[m].ewma[AT_W_LONG]);
		at_bputc(b, ',');
		at_bjson_u64(b, "thr", at_threshold(at, m));
		at_bputc(b, ',');
		at_bjson_bool(b, "anom", at->track[m].anomalous != 0);
		at_bputc(b, '}');
	}
	at_bputc(b, '}');
}

/* -------------------------------------------------------------------------
 * Init / fini
 * ------------------------------------------------------------------------- */

static __u32 at_round_pow2(__u32 v, __u32 lo, __u32 hi)
{
	__u32 p = lo;

	if (v < lo)
		v = lo;
	if (v > hi)
		v = hi;
	while (p < v && p < hi)
		p <<= 1;
	return p;
}

static void at_sanitise_tunables(struct autotune *at)
{
	__u32 i;

	for (i = 0; i < AT_W_MAX; i++)
		if (at->cfg.win_ns[i] == 0)
			at->cfg.win_ns[i] = (i == AT_W_SHORT) ?
				10ULL * CALY_NSEC_PER_SEC :
				(i == AT_W_MED ? 60ULL * CALY_NSEC_PER_SEC :
						 900ULL * CALY_NSEC_PER_SEC);

	if (at->cfg.min_tick_ns == 0)
		at->cfg.min_tick_ns = 100ULL * CALY_NSEC_PER_MSEC;
	if (at->cfg.heartbeat_ns == 0)
		at->cfg.heartbeat_ns = 60ULL * CALY_NSEC_PER_SEC;
	if (at->cfg.ban_interval_ns == 0)
		at->cfg.ban_interval_ns = CALY_NSEC_PER_SEC;

	at->cfg.confirm_up   = at_clamp32(at->cfg.confirm_up, 1, 1000);
	at->cfg.confirm_down = at_clamp32(at->cfg.confirm_down, 1, 10000);
	at->cfg.sev_elevate  = at_clamp32(at->cfg.sev_elevate, 1, 100);
	at->cfg.sev_attack   = at_clamp32(at->cfg.sev_attack,
					  at->cfg.sev_elevate, 100);
	at->cfg.sev_lockdown = at_clamp32(at->cfg.sev_lockdown,
					  at->cfg.sev_attack, 100);
	at->cfg.max_bans_per_tick = at_clamp32(at->cfg.max_bans_per_tick, 0,
					       AT_TOP_MAX);
	at->cfg.ban_min_share_pct = at_clamp32(at->cfg.ban_min_share_pct, 0,
					       100);
	at->cfg.hook_timeout_s = at_clamp32(at->cfg.hook_timeout_s, 1, 300);

	at->cfg.alert_file[sizeof(at->cfg.alert_file) - 1] = '\0';
	at->cfg.hook_path[sizeof(at->cfg.hook_path) - 1] = '\0';
	at->cfg.webhook_url[sizeof(at->cfg.webhook_url) - 1] = '\0';
	at->cfg.webhook_client[sizeof(at->cfg.webhook_client) - 1] = '\0';
	at->cfg.node_id[sizeof(at->cfg.node_id) - 1] = '\0';
	if (at->cfg.node_id[0] == '\0')
		snprintf(at->cfg.node_id, sizeof(at->cfg.node_id), "calyanti");
}

int autotune_init(struct autotune *at, const struct at_ops *ops,
		  const struct at_tunables *cfg)
{
	struct fw_config live;
	int rc;

	if (!at || !ops || !ops->config_read || !ops->gauges_read)
		return -EINVAL;

	memset(at, 0, sizeof(*at));
	at->ops = *ops;
	at->alert_fd = -1;

	if (cfg)
		at->cfg = *cfg;
	else
		autotune_tunables_default(&at->cfg);
	at_sanitise_tunables(at);

	memset(&live, 0, sizeof(live));
	rc = at->ops.config_read(at->ops.ctx, &live);
	if (rc != 0) {
		at_log(at, AT_LOG_ERR,
		       "autotune: cannot read the live configuration (%d)", rc);
		return rc;
	}
	if (live.abi_version == 0)
		live.abi_version = CALY_ABI_VERSION;
	if ((live.abi_version >> 16) != CALY_ABI_VERSION_MAJOR) {
		at_log(at, AT_LOG_ERR,
		       "autotune: ABI major mismatch (map %llu, built %u); refusing to drive this dataplane",
		       (unsigned long long)(live.abi_version >> 16),
		       (unsigned int)CALY_ABI_VERSION_MAJOR);
		return -EPROTO;
	}

	at->base = live;
	at_enforce_mgmt(&at->base);
	at->have_base = 1;
	at->applied = live;
	at->have_applied = 1;

	at->mode = live.mode < FW_MODE_MAX ? live.mode : FW_MODE_NORMAL;
	at->applied_mode = at->mode;
	at->pinned = (at->mode == FW_MODE_LOCKDOWN ||
		      at->mode == FW_MODE_MONITOR_ONLY) ? 1 : 0;

	at->srcmem_cap = at_round_pow2(at->cfg.srcmem_entries ?
				       at->cfg.srcmem_entries : 4096,
				       AT_SRCMEM_MIN, AT_SRCMEM_MAX);
	at->srcmem = (struct at_srcmem *)calloc(at->srcmem_cap,
						sizeof(struct at_srcmem));
	if (!at->srcmem) {
		at->srcmem_cap = 0;
		at_log(at, AT_LOG_WARN,
		       "autotune: per-source memory allocation failed; ban TTLs will not escalate");
	}

	at_alert_sink_open(at);
	at_webhook_probe(at);

	if (!at->ops.stats_read)
		at_log(at, AT_LOG_WARN,
		       "autotune: no stats_read op; classification will use gauges only");
	if (!at->ops.top_offenders || !at->ops.ban_add)
		at_log(at, AT_LOG_WARN,
		       "autotune: no top_offenders/ban_add op; userspace auto-banning disabled");
	if (!at->ops.config_write)
		at_log(at, AT_LOG_WARN,
		       "autotune: no config_write op; running in observe-only mode");

	at->init_done = 1;
	at_log(at, AT_LOG_INFO,
	       "autotune: ready, mode=%s pinned=%u dry_run=%u windows=%llu/%llu/%llu s",
	       fw_mode_str(at->mode), (unsigned int)at->pinned,
	       (unsigned int)at->cfg.dry_run,
	       (unsigned long long)(at->cfg.win_ns[AT_W_SHORT] /
				    CALY_NSEC_PER_SEC),
	       (unsigned long long)(at->cfg.win_ns[AT_W_MED] /
				    CALY_NSEC_PER_SEC),
	       (unsigned long long)(at->cfg.win_ns[AT_W_LONG] /
				    CALY_NSEC_PER_SEC));
	return 0;
}

void autotune_fini(struct autotune *at)
{
	if (!at)
		return;
	if (at->init_done) {
		/* Put the box back the way the operator left it. */
		at_amp_apply(at, 0);
		at_icmp_apply(at, 0);
	}
	if (at->alert_fd >= 0 && at->alert_fd_owned)
		close(at->alert_fd);
	at->alert_fd = -1;
	at->alert_fd_owned = 0;
	free(at->srcmem);
	at->srcmem = NULL;
	at->srcmem_cap = 0;
	at->init_done = 0;
}

int autotune_set_base_config(struct autotune *at, const struct fw_config *cfg)
{
	struct fw_config live;

	if (!at || !cfg)
		return -EINVAL;
	if ((cfg->abi_version >> 16) != CALY_ABI_VERSION_MAJOR &&
	    cfg->abi_version != 0)
		return -EPROTO;

	at->base = *cfg;
	if (at->base.abi_version == 0)
		at->base.abi_version = CALY_ABI_VERSION;
	at_enforce_mgmt(&at->base);
	at->have_base = 1;

	/* A reload is the operator speaking. If the new baseline names an
	 * automatic mode, automatic control resumes from there. */
	if (at->base.mode == FW_MODE_LOCKDOWN ||
	    at->base.mode == FW_MODE_MONITOR_ONLY) {
		at->pinned = 1;
		at->mode = at->base.mode;
	} else {
		at->pinned = 0;
		if (at->base.mode < FW_MODE_MAX)
			at->mode = at->base.mode;
	}
	at->up_count = 0;
	at->down_count = 0;
	at->mode_since_ns = at->last_ts_ns;

	memset(&live, 0, sizeof(live));
	if (at->ops.config_read &&
	    at->ops.config_read(at->ops.ctx, &live) == 0) {
		if (live.abi_version == 0)
			live.abi_version = CALY_ABI_VERSION;
	} else {
		live = at->base;
	}

	at->have_applied = 0;   /* force a push of the new effective config */
	at_side_policy(at, at->mode, at->class_mask);
	return at_push_config(at, &live, at->mode, at->class_mask);
}

/* -------------------------------------------------------------------------
 * Public entry points
 * ------------------------------------------------------------------------- */

void autotune_note_event(struct autotune *at, const struct event *ev)
{
	if (!at || !ev)
		return;
	if (ev->reason < STAT_MAX)
		at->ev_reason[ev->reason]++;
}

int autotune_force_mode(struct autotune *at, __u32 mode, __u64 now_ns)
{
	struct fw_config live;
	__u32 prev;

	if (!at || mode >= FW_MODE_MAX)
		return -EINVAL;

	prev = at->mode;
	at->mode = mode;
	at->mode_since_ns = now_ns;
	at->up_count = 0;
	at->down_count = 0;
	at->pinned = (mode == FW_MODE_LOCKDOWN ||
		      mode == FW_MODE_MONITOR_ONLY) ? 1 : 0;

	memset(&live, 0, sizeof(live));
	if (at->ops.config_read &&
	    at->ops.config_read(at->ops.ctx, &live) == 0) {
		if (live.abi_version == 0)
			live.abi_version = CALY_ABI_VERSION;
	} else {
		live = at->base;
	}

	at_side_policy(at, at->mode, at->class_mask);
	at_emit_alert(at, mode > prev ? AT_EV_MODE_UP : AT_EV_MODE_DOWN,
		      now_ns, prev, NULL, 0, "operator override");
	return at_push_config(at, &live, at->mode, at->class_mask);
}

void autotune_unpin(struct autotune *at, __u64 now_ns)
{
	if (!at)
		return;
	at->pinned = 0;
	at->up_count = 0;
	at->down_count = 0;
	at->mode_since_ns = now_ns;
	if (at->mode >= FW_MODE_MONITOR_ONLY)
		at->mode = FW_MODE_NORMAL;
}

int autotune_step(struct autotune *at, __u64 now_ns, const struct at_sample *s)
{
	struct fw_config live;
	struct at_banrec bans[AT_ALERT_BANS_MAX];
	__u64 dt;
	__u32 prev_mode, prev_class, new_mode;
	__u32 nbans = 0;
	__u32 m;
	int freeze_long;

	if (!at || !s || !at->init_done)
		return -EINVAL;

	if (s->have_live)
		live = s->live;
	else if (at->ops.config_read &&
		 at->ops.config_read(at->ops.ctx, &live) == 0)
		;
	else
		live = at->base;

	if (live.abi_version == 0)
		live.abi_version = CALY_ABI_VERSION;
	if ((live.abi_version >> 16) != CALY_ABI_VERSION_MAJOR) {
		if (!at->abi_warned) {
			at->abi_warned = 1;
			at_log(at, AT_LOG_ERR,
			       "autotune: live config ABI major %llu != %u; halting all writes",
			       (unsigned long long)(live.abi_version >> 16),
			       (unsigned int)CALY_ABI_VERSION_MAJOR);
			at_emit_alert(at, AT_EV_ERROR, now_ns, at->mode, NULL,
				      0, "abi major mismatch, writes halted");
		}
		return -EPROTO;
	}

	/* Someone else moved the mode. Adopt it; if it is one of the two
	 * operator states, stop driving until told otherwise. */
	if (at->have_applied && live.mode != at->applied.mode &&
	    live.mode < FW_MODE_MAX) {
		at_log(at, AT_LOG_INFO,
		       "autotune: external mode change %s -> %s",
		       fw_mode_str(at->applied.mode), fw_mode_str(live.mode));
		at->mode = live.mode;
		at->mode_since_ns = now_ns;
		at->up_count = 0;
		at->down_count = 0;
		at->pinned = (live.mode == FW_MODE_LOCKDOWN ||
			      live.mode == FW_MODE_MONITOR_ONLY) ? 1 : 0;
		at->applied = live;
	}

	/* ---- timing ---- */
	if (at->last_ts_ns == 0 || now_ns < at->last_ts_ns) {
		at->first_ts_ns = now_ns;
		at->last_ts_ns = now_ns;
		at->mode_since_ns = now_ns;
		memcpy(at->prev_gauge, s->gauge, sizeof(at->prev_gauge));
		at->have_prev_gauge = 1;
		if (s->have_stat) {
			for (m = 0; m < STAT_MAX; m++)
				at->rtrack[m].prev = s->stat[m];
			at->have_prev_stat = 1;
		}
		return 0;
	}
	dt = now_ns - at->last_ts_ns;
	if (dt < at->cfg.min_tick_ns)
		return 1;
	at->last_ts_ns = now_ns;
	at->last_dt_ns = dt;
	at->sample_count++;

	prev_mode = at->mode;
	prev_class = at->class_mask;

	/* ---- rates, detection, classification ----
	 * Detection runs against the baselines as they were BEFORE this
	 * sample, so a single tick can never move the baseline far enough to
	 * hide itself. */
	at_compute_rates(at, s, dt);
	at_detect(at, &live);
	freeze_long = (at->anom_mask != 0) ||
		      (at->mode >= FW_MODE_ELEVATED &&
		       at->mode <= FW_MODE_LOCKDOWN);
	at_compute_reason_rates(at, s, dt, freeze_long);
	at_classify(at, &live);

	for (m = 0; m < AT_M_MAX; m++)
		at_track_update(&at->track[m], at->rate[m], dt,
				at->cfg.win_ns, freeze_long);

	/* ---- mode machine ---- */
	new_mode = at_step_mode(at, &live, now_ns);
	if (new_mode != at->mode) {
		at->mode = new_mode;
		at->mode_since_ns = now_ns;
		if (new_mode > prev_mode && at->attack_since_ns == 0)
			at->attack_since_ns = now_ns;
		if (new_mode == FW_MODE_NORMAL)
			at->attack_since_ns = 0;
	}

	/* ---- act ---- */
	if (!at->pinned) {
		if (at->mode != at->applied_mode ||
		    at->class_mask != at->applied_class_mask ||
		    !at->have_applied) {
			at_side_policy(at, at->mode, at->class_mask);
			(void)at_push_config(at, &live, at->mode,
					     at->class_mask);
			at->applied_mode = at->mode;
			at->applied_class_mask = at->class_mask;
		}
	}

	nbans = at_autoban(at, &live, now_ns, bans, AT_ALERT_BANS_MAX);

	/* ---- alerts ---- */
	if (at->mode != prev_mode) {
		at_emit_alert(at,
			      at->mode > prev_mode ? AT_EV_MODE_UP :
						     AT_EV_MODE_DOWN,
			      now_ns, prev_mode, bans, nbans, NULL);
		at->last_heartbeat_ns = now_ns;
		if (at->mode == FW_MODE_NORMAL && prev_mode != FW_MODE_NORMAL)
			at_emit_alert(at, AT_EV_CLEAR, now_ns, prev_mode, NULL,
				      0, NULL);
	} else if (at->class_mask != prev_class && at->class_mask != 0) {
		at_emit_alert(at, AT_EV_ATTACK, now_ns, prev_mode, bans, nbans,
			      NULL);
		at->last_heartbeat_ns = now_ns;
	} else if (nbans > 0) {
		at_emit_alert(at, AT_EV_BAN, now_ns, prev_mode, bans, nbans,
			      NULL);
	} else if (at->mode >= FW_MODE_ELEVATED &&
		   at->mode <= FW_MODE_LOCKDOWN &&
		   (at->last_heartbeat_ns == 0 ||
		    now_ns - at->last_heartbeat_ns >= at->cfg.heartbeat_ns)) {
		at_emit_alert(at, AT_EV_HEARTBEAT, now_ns, prev_mode, NULL, 0,
			      NULL);
		at->last_heartbeat_ns = now_ns;
	}

	return 0;
}

int autotune_tick(struct autotune *at, __u64 now_ns)
{
	struct at_sample s;
	int rc;

	if (!at || !at->init_done)
		return -EINVAL;
	if (!at->ops.gauges_read || !at->ops.config_read)
		return -ENOSYS;

	memset(&s, 0, sizeof(s));

	rc = at->ops.config_read(at->ops.ctx, &s.live);
	if (rc == 0)
		s.have_live = 1;

	rc = at->ops.gauges_read(at->ops.ctx, s.gauge, CALY_G_MAX);
	if (rc != 0) {
		at_log(at, AT_LOG_WARN,
		       "autotune: gauge read failed (%d), skipping this tick",
		       rc);
		return rc;
	}

	if (at->ops.stats_read &&
	    at->ops.stats_read(at->ops.ctx, s.stat, STAT_MAX) == 0)
		s.have_stat = 1;

	if (at->ops.conn_count &&
	    at->ops.conn_count(at->ops.ctx, &s.conn_entries) == 0)
		s.have_conn = 1;

	if (at->ops.unique_sources &&
	    at->ops.unique_sources(at->ops.ctx, &s.uniq_sources) == 0)
		s.have_uniq = 1;

	return autotune_step(at, now_ns, &s);
}

/* -------------------------------------------------------------------------
 * Status reporting
 * ------------------------------------------------------------------------- */

void autotune_status(const struct autotune *at, struct at_status *out)
{
	__u32 m;
	__u64 dwell;

	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	if (!at)
		return;

	out->mode          = at->mode;
	out->pinned        = at->pinned;
	out->severity      = at->severity;
	out->class_mask    = at->class_mask;
	out->primary_class = at->primary_class;
	out->anom_mask     = at->anom_mask;
	out->up_count      = at->up_count;
	out->down_count    = at->down_count;
	out->mode_since_ns = at->mode_since_ns;
	out->attack_since_ns = at->attack_since_ns;
	out->samples       = at->sample_count;
	out->bans_issued   = at->bans_issued;
	out->bans_suppressed = at->bans_suppressed;
	out->alerts_emitted = at->alerts_emitted;
	out->alerts_failed = at->alerts_failed;
	out->config_pushes = at->config_pushes;
	out->config_rejected = at->config_rejected;
	out->last_tick_ns  = at->last_ts_ns;

	out->warmed_up = (at->sample_count >= 8 && at->first_ts_ns != 0 &&
			  at->last_ts_ns - at->first_ts_ns >=
			  at->cfg.warmup_ns) ? 1 : 0;

	dwell = at->applied.attack_dwell_ns;
	if (at->mode == FW_MODE_LOCKDOWN)
		dwell += at->cfg.lockdown_extra_dwell_ns;
	if (at->mode_since_ns && at->last_ts_ns > at->mode_since_ns) {
		__u64 elapsed = at->last_ts_ns - at->mode_since_ns;

		out->dwell_remaining_ns = elapsed >= dwell ? 0 : dwell - elapsed;
	} else {
		out->dwell_remaining_ns = dwell;
	}

	for (m = 0; m < AT_M_MAX; m++) {
		out->rate[m]       = at->rate[m];
		out->base[m]       = at->track[m].ewma[AT_W_LONG];
		out->ewma_short[m] = at->track[m].ewma[AT_W_SHORT];
		out->ewma_med[m]   = at->track[m].ewma[AT_W_MED];
		out->thr[m]        = at_threshold(at, m);
	}
}

int autotune_status_json(const struct autotune *at, char *buf, size_t len)
{
	struct at_buf b;
	struct autotune *mut = (struct autotune *)at;   /* builders take non-const */
	struct at_status st;

	if (!buf || len == 0)
		return -EINVAL;
	at_binit(&b, buf, len);
	if (!at) {
		at_bputs(&b, "{}");
		return (int)b.len;
	}

	autotune_status(at, &st);

	at_bputc(&b, '{');
	at_json_time(&b);
	at_bputc(&b, ',');
	at_bjson_kstr(&b, "node", at->cfg.node_id);
	at_bputc(&b, ',');
	at_bjson_kstr(&b, "mode", fw_mode_str(st.mode));
	at_bputc(&b, ',');
	at_bjson_bool(&b, "pinned", st.pinned != 0);
	at_bputc(&b, ',');
	at_bjson_bool(&b, "warmed_up", st.warmed_up != 0);
	at_bputc(&b, ',');
	at_bjson_bool(&b, "dry_run", at->cfg.dry_run != 0);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "severity", st.severity);
	at_bputc(&b, ',');
	at_json_classes(mut, &b);
	at_bputc(&b, ',');
	at_bjson_kstr(&b, "primary_class",
		      st.class_mask ? at_class_str(st.primary_class) : "none");
	at_bputc(&b, ',');
	at_bjson_u64(&b, "target_mode", at->target_mode);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "confirm_up_count", st.up_count);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "confirm_down_count", st.down_count);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "dwell_remaining_ms",
		     st.dwell_remaining_ns / CALY_NSEC_PER_MSEC);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "samples", st.samples);
	at_bputc(&b, ',');
	at_json_metrics(mut, &b);
	at_bputc(&b, ',');
	at_json_top_reasons(mut, &b);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "bans_issued", st.bans_issued);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "bans_suppressed", st.bans_suppressed);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "alerts_emitted", st.alerts_emitted);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "alerts_failed", st.alerts_failed);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "config_pushes", st.config_pushes);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "config_rejected", st.config_rejected);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "srcmem_used", at->srcmem_used);
	at_bputc(&b, ',');
	at_bjson_u64(&b, "srcmem_cap", at->srcmem_cap);
	at_bputc(&b, '}');

	if (b.ovf)
		return (int)len;   /* signal truncation, snprintf style */
	return (int)b.len;
}
