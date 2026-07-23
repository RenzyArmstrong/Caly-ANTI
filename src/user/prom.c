/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/prom.c
 *
 * Minimal, dependency-free HTTP/1.1 server exposing /metrics and /healthz.
 * See prom.h for the threat model this implementation is written against.
 *
 * Not internally locked: drive it from a single thread (the daemon's event
 * loop). The stats and events modules it reads ARE internally locked, so the
 * sampler may run on another thread.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "prom.h"
#include "stats.h"
#include "events.h"

/* EAGAIN and EWOULDBLOCK are the same value on Linux; testing both would
 * trip -Wlogical-op on GCC. */
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
#define PC_WOULDBLOCK(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#else
#define PC_WOULDBLOCK(e) ((e) == EAGAIN)
#endif

#define PC_ST_FREE   0
#define PC_ST_READ   1
#define PC_ST_WRITE  2

#define PC_PATH_MAX      128u
#define PC_HDR_MAX       320u
#define PC_ACCEPT_BURST   16
#define PC_LOG_MAX       256u

#define PC_CT_METRICS "text/plain; version=0.0.4; charset=utf-8"
#define PC_CT_PLAIN   "text/plain; charset=utf-8"

struct prom_conn {
	int fd;
	unsigned char state;
	unsigned char head_only;
	__u64 start_ns;
	__u64 last_ns;
	unsigned int in_len;
	char in[PROM_REQ_MAX];
	char *out;
	size_t out_cap;
	size_t out_len;
	size_t out_off;
};

struct prom_ctx {
	int lfd;
	int own_lfd;

	unsigned int max_conns;
	unsigned int timeout_ms;
	size_t body_cap;
	int emit_zero_rates;
	char ns[PROM_NS_MAX];

	struct prom_conn *conns;

	char *render_store;
	struct prom_buf render;

	struct stats_ctx *stats;
	struct events_ctx *events;

	prom_extra_fn extra;
	prom_health_fn health;
	void *user;

	caly_log_fn log;
	void *log_user;

	struct prom_server_stats st;

	/* Scratch for a scrape; heap-allocated so the stack stays small. */
	struct stats_snapshot *snap;
	struct stats_delta *delta;
	struct events_stats *evst;
};

/* -------------------------------------------------------------------------
 * Logging
 * ------------------------------------------------------------------------- */

static void pc_log(struct prom_ctx *c, int level, const char *fmt, ...)
{
	char buf[PC_LOG_MAX];
	va_list ap;

	if (!c || !c->log)
		return;
	va_start(ap, fmt);
	(void)vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	buf[sizeof(buf) - 1] = '\0';
	c->log(c->log_user, level, buf);
}

/* -------------------------------------------------------------------------
 * prom_buf
 * ------------------------------------------------------------------------- */

void prom_buf_init(struct prom_buf *pb, char *storage, size_t cap)
{
	if (!pb)
		return;
	pb->buf = storage;
	pb->cap = cap;
	pb->len = 0;
	pb->truncated = 0;
	if (storage && cap)
		storage[0] = '\0';
}

void prom_buf_reset(struct prom_buf *pb)
{
	if (!pb)
		return;
	pb->len = 0;
	pb->truncated = 0;
	if (pb->buf && pb->cap)
		pb->buf[0] = '\0';
}

int prom_buf_add(struct prom_buf *pb, const char *s, size_t n)
{
	if (!pb || !pb->buf || !s)
		return -EINVAL;
	if (pb->len + n + 1u > pb->cap) {
		pb->truncated = 1;
		return -ENOSPC;
	}
	memcpy(pb->buf + pb->len, s, n);
	pb->len += n;
	pb->buf[pb->len] = '\0';
	return 0;
}

int prom_buf_addf(struct prom_buf *pb, const char *fmt, ...)
{
	va_list ap;
	size_t avail;
	int n;

	if (!pb || !pb->buf || pb->cap == 0)
		return -EINVAL;
	if (pb->len >= pb->cap) {
		pb->truncated = 1;
		return -ENOSPC;
	}

	avail = pb->cap - pb->len;
	va_start(ap, fmt);
	n = vsnprintf(pb->buf + pb->len, avail, fmt, ap);
	va_end(ap);

	if (n < 0)
		return -EIO;
	if ((size_t)n >= avail) {
		/* Discard the partial write so the buffer never ends mid-line
		 * and the exposition stays parseable. */
		pb->buf[pb->len] = '\0';
		pb->truncated = 1;
		return -ENOSPC;
	}
	pb->len += (size_t)n;
	return 0;
}

/* Prometheus label values escape backslash, double quote and newline. */
static void pc_escape(char *dst, size_t cap, const char *src)
{
	size_t i = 0;

	if (!dst || cap == 0)
		return;
	if (!src)
		src = "";

	while (*src && i + 2u < cap) {
		unsigned char ch = (unsigned char)*src++;

		if (ch == '\\' || ch == '"') {
			dst[i++] = '\\';
			dst[i++] = (char)ch;
		} else if (ch == '\n') {
			dst[i++] = '\\';
			dst[i++] = 'n';
		} else if (ch < 0x20u || ch == 0x7Fu) {
			dst[i++] = '_';
		} else {
			dst[i++] = (char)ch;
		}
	}
	dst[i] = '\0';
}

void prom_buf_family(struct prom_buf *pb, const char *name, const char *type,
		     const char *help)
{
	char esc[192];

	pc_escape(esc, sizeof(esc), help ? help : "");
	(void)prom_buf_addf(pb, "# HELP %s %s\n# TYPE %s %s\n",
			    name, esc, name, type ? type : "gauge");
}

void prom_buf_u64(struct prom_buf *pb, const char *name, __u64 v)
{
	(void)prom_buf_addf(pb, "%s %llu\n", name, (unsigned long long)v);
}

void prom_buf_i64(struct prom_buf *pb, const char *name, __s64 v)
{
	(void)prom_buf_addf(pb, "%s %lld\n", name, (long long)v);
}

void prom_buf_f64(struct prom_buf *pb, const char *name, double v)
{
	(void)prom_buf_addf(pb, "%s %.6f\n", name, v);
}

void prom_buf_u64_l(struct prom_buf *pb, const char *name, const char *lname,
		    const char *lval, __u64 v)
{
	char esc[128];

	pc_escape(esc, sizeof(esc), lval);
	(void)prom_buf_addf(pb, "%s{%s=\"%s\"} %llu\n", name, lname, esc,
			    (unsigned long long)v);
}

void prom_buf_f64_l(struct prom_buf *pb, const char *name, const char *lname,
		    const char *lval, double v)
{
	char esc[128];

	pc_escape(esc, sizeof(esc), lval);
	(void)prom_buf_addf(pb, "%s{%s=\"%s\"} %.6f\n", name, lname, esc, v);
}

void prom_buf_u64_l2(struct prom_buf *pb, const char *name,
		     const char *l1name, const char *l1val,
		     const char *l2name, const char *l2val, __u64 v)
{
	char e1[96], e2[96];

	pc_escape(e1, sizeof(e1), l1val);
	pc_escape(e2, sizeof(e2), l2val);
	(void)prom_buf_addf(pb, "%s{%s=\"%s\",%s=\"%s\"} %llu\n", name,
			    l1name, e1, l2name, e2, (unsigned long long)v);
}

/* -------------------------------------------------------------------------
 * Metric rendering
 * ------------------------------------------------------------------------- */

static void pc_ns_sanitise(char *dst, size_t cap, const char *src)
{
	size_t i = 0;

	if (!src || !*src)
		src = "calyanti";

	while (*src && i + 1u < cap) {
		char ch = *src++;

		if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
		    ch == '_' || (i > 0 && ch >= '0' && ch <= '9'))
			dst[i++] = ch;
	}
	dst[i] = '\0';
	if (i == 0)
		(void)snprintf(dst, cap, "calyanti");
}

int prom_render(struct prom_ctx *c, struct prom_buf *pb)
{
	char nm[128];
	const char *ns;
	__u64 t0, now;
	__u32 i;
	int have_snap = 0, have_delta = 0, have_meta = 0;
	struct stats_meta meta;

	if (!c || !pb || !pb->buf)
		return -EINVAL;

	t0 = caly_mono_ns();
	ns = c->ns;
	memset(&meta, 0, sizeof(meta));

	prom_buf_reset(pb);

	(void)snprintf(nm, sizeof(nm), "%s_build_info", ns);
	prom_buf_family(pb, nm, "gauge",
			"Caly Anti build and ABI identification.");
	(void)prom_buf_addf(pb,
			    "%s{abi_major=\"%u\",abi_minor=\"%u\","
			    "backend=\"%s\"} 1\n",
			    nm, (unsigned int)CALY_ABI_VERSION_MAJOR,
			    (unsigned int)CALY_ABI_VERSION_MINOR,
			    events_backend_str(c->events));

	(void)snprintf(nm, sizeof(nm), "%s_up", ns);
	prom_buf_family(pb, nm, "gauge",
			"1 when the exporter is serving requests.");
	prom_buf_u64(pb, nm, 1);

	if (c->stats) {
		have_snap  = (stats_latest(c->stats, c->snap) == 0);
		have_delta = (stats_latest_delta(c->stats, c->delta) == 0);
		have_meta  = (stats_meta_get(c->stats, &meta) == 0);
	}

	(void)snprintf(nm, sizeof(nm), "%s_stats_available", ns);
	prom_buf_family(pb, nm, "gauge",
			"1 when at least one statistics sample has been taken.");
	prom_buf_u64(pb, nm, have_snap ? 1 : 0);

	if (have_snap) {
		(void)snprintf(nm, sizeof(nm), "%s_packets_total", ns);
		prom_buf_family(pb, nm, "counter",
				"Packets accounted by the dataplane, by reason "
				"code.");
		for (i = 0; i < (__u32)STAT_MAX; i++)
			prom_buf_u64_l(pb, nm, "reason", stat_reason_str(i),
				       c->snap->pkts[i]);

		(void)snprintf(nm, sizeof(nm), "%s_bytes_total", ns);
		prom_buf_family(pb, nm, "counter",
				"Bytes accounted by the dataplane, by reason "
				"code.");
		for (i = 0; i < (__u32)STAT_MAX; i++)
			prom_buf_u64_l(pb, nm, "reason", stat_reason_str(i),
				       c->snap->bytes[i]);

		(void)snprintf(nm, sizeof(nm), "%s_global_total", ns);
		prom_buf_family(pb, nm, "counter",
				"Global dataplane gauges, cumulative.");
		for (i = 0; i < (__u32)CALY_G_MAX; i++)
			prom_buf_u64_l(pb, nm, "gauge", stats_gauge_str(i),
				       c->snap->gauges[i]);
	}

	if (have_delta) {
		(void)snprintf(nm, sizeof(nm), "%s_packets_per_second", ns);
		prom_buf_family(pb, nm, "gauge",
				"Packet rate over the last sampling interval, "
				"by reason code.");
		for (i = 0; i < (__u32)STAT_MAX; i++) {
			__u64 v = stats_rate_pkts(c->delta, i);

			if (v || c->emit_zero_rates)
				prom_buf_u64_l(pb, nm, "reason",
					       stat_reason_str(i), v);
		}

		(void)snprintf(nm, sizeof(nm), "%s_bytes_per_second", ns);
		prom_buf_family(pb, nm, "gauge",
				"Byte rate over the last sampling interval, by "
				"reason code.");
		for (i = 0; i < (__u32)STAT_MAX; i++) {
			__u64 v = stats_rate_bytes(c->delta, i);

			if (v || c->emit_zero_rates)
				prom_buf_u64_l(pb, nm, "reason",
					       stat_reason_str(i), v);
		}

		(void)snprintf(nm, sizeof(nm), "%s_global_per_second", ns);
		prom_buf_family(pb, nm, "gauge",
				"Global dataplane gauge rates.");
		for (i = 0; i < (__u32)CALY_G_MAX; i++)
			prom_buf_u64_l(pb, nm, "gauge", stats_gauge_str(i),
				       stats_rate_gauge(c->delta, i));
	}

	if (have_meta) {
		now = caly_mono_ns();

		(void)snprintf(nm, sizeof(nm), "%s_samples_total", ns);
		prom_buf_family(pb, nm, "counter",
				"Statistics sampling passes completed.");
		prom_buf_u64(pb, nm, meta.samples_taken);

		(void)snprintf(nm, sizeof(nm), "%s_sample_errors_total", ns);
		prom_buf_family(pb, nm, "counter",
				"Failed per-CPU map lookups during sampling.");
		prom_buf_u64(pb, nm, meta.read_errors);

		(void)snprintf(nm, sizeof(nm), "%s_counter_resets_total", ns);
		prom_buf_family(pb, nm, "counter",
				"Times a dataplane counter moved backwards, "
				"which means the BPF object was replaced.");
		prom_buf_u64(pb, nm, meta.counter_resets);

		(void)snprintf(nm, sizeof(nm), "%s_sample_interval_seconds",
			       ns);
		prom_buf_family(pb, nm, "gauge",
				"Measured interval covered by the last delta.");
		prom_buf_f64(pb, nm,
			     (double)meta.last_interval_ns / 1e9);

		(void)snprintf(nm, sizeof(nm), "%s_sample_age_seconds", ns);
		prom_buf_family(pb, nm, "gauge",
				"Age of the most recent statistics sample.");
		prom_buf_f64(pb, nm,
			     meta.last_mono_ns && now > meta.last_mono_ns
				     ? (double)(now - meta.last_mono_ns) / 1e9
				     : 0.0);

		(void)snprintf(nm, sizeof(nm), "%s_possible_cpus", ns);
		prom_buf_family(pb, nm, "gauge",
				"Possible CPUs summed for every per-CPU map.");
		prom_buf_u64(pb, nm, meta.ncpu);
	}

	if (c->events && c->evst &&
	    events_stats_get(c->events, c->evst) == 0) {
		(void)snprintf(nm, sizeof(nm), "%s_events_total", ns);
		prom_buf_family(pb, nm, "counter",
				"Dataplane event records handled by the "
				"consumer, by outcome.");
		prom_buf_u64_l(pb, nm, "outcome", "received",
			       c->evst->received);
		prom_buf_u64_l(pb, nm, "outcome", "accepted",
			       c->evst->accepted);
		prom_buf_u64_l(pb, nm, "outcome", "invalid_size",
			       c->evst->invalid_size);
		prom_buf_u64_l(pb, nm, "outcome", "invalid_version",
			       c->evst->invalid_version);
		prom_buf_u64_l(pb, nm, "outcome", "invalid_field",
			       c->evst->invalid_field);
		prom_buf_u64_l(pb, nm, "outcome", "lost", c->evst->lost);
		prom_buf_u64_l(pb, nm, "outcome", "logged", c->evst->logged);
		prom_buf_u64_l(pb, nm, "outcome", "suppressed",
			       c->evst->suppressed);
		prom_buf_u64_l(pb, nm, "outcome", "agg_overflow",
			       c->evst->agg_overflow);

		(void)snprintf(nm, sizeof(nm), "%s_events_by_reason_total", ns);
		prom_buf_family(pb, nm, "counter",
				"Accepted event records by reason code.");
		for (i = 0; i < (__u32)STAT_MAX; i++)
			if (c->evst->by_reason[i] || c->emit_zero_rates)
				prom_buf_u64_l(pb, nm, "reason",
					       stat_reason_str(i),
					       c->evst->by_reason[i]);

		(void)snprintf(nm, sizeof(nm), "%s_events_by_verdict_total",
			       ns);
		prom_buf_family(pb, nm, "counter",
				"Accepted event records by verdict.");
		for (i = 0; i < (__u32)CALY_VERDICT_MAX; i++)
			prom_buf_u64_l(pb, nm, "verdict", caly_verdict_str(i),
				       c->evst->by_verdict[i]);

		(void)snprintf(nm, sizeof(nm), "%s_event_agg_buckets", ns);
		prom_buf_family(pb, nm, "gauge",
				"Aggregation buckets in use in the current "
				"window.");
		prom_buf_u64(pb, nm, c->evst->agg_live);
	}

	/* Exporter self-telemetry: a scrape that silently fails to serve is
	 * indistinguishable from a quiet network unless we say so. */
	(void)snprintf(nm, sizeof(nm), "%s_http_connections", ns);
	prom_buf_family(pb, nm, "gauge",
			"HTTP connections currently open on the exporter.");
	prom_buf_u64(pb, nm, (__u64)c->st.conns_open);

	(void)snprintf(nm, sizeof(nm), "%s_http_connections_max", ns);
	prom_buf_family(pb, nm, "gauge",
			"Configured concurrent connection ceiling.");
	prom_buf_u64(pb, nm, (__u64)c->max_conns);

	(void)snprintf(nm, sizeof(nm), "%s_http_requests_total", ns);
	prom_buf_family(pb, nm, "counter",
			"HTTP requests answered, by response class.");
	prom_buf_u64_l(pb, nm, "class", "2xx", c->st.responses_2xx);
	prom_buf_u64_l(pb, nm, "class", "4xx", c->st.responses_4xx);
	prom_buf_u64_l(pb, nm, "class", "5xx", c->st.responses_5xx);

	(void)snprintf(nm, sizeof(nm), "%s_http_rejected_total", ns);
	prom_buf_family(pb, nm, "counter",
			"Connections and requests refused by the exporter.");
	prom_buf_u64_l(pb, nm, "reason", "conn_cap", c->st.rejected_cap);
	prom_buf_u64_l(pb, nm, "reason", "evicted", c->st.evicted);
	prom_buf_u64_l(pb, nm, "reason", "timeout", c->st.timeouts);
	prom_buf_u64_l(pb, nm, "reason", "oversize", c->st.oversize);
	prom_buf_u64_l(pb, nm, "reason", "bad_request", c->st.bad_request);
	prom_buf_u64_l(pb, nm, "reason", "accept_error", c->st.accept_errors);

	(void)snprintf(nm, sizeof(nm), "%s_http_bytes_sent_total", ns);
	prom_buf_family(pb, nm, "counter", "Response bytes written.");
	prom_buf_u64(pb, nm, c->st.bytes_sent);

	(void)snprintf(nm, sizeof(nm), "%s_render_truncated_total", ns);
	prom_buf_family(pb, nm, "counter",
			"Scrapes truncated because the render buffer was too "
			"small; raise metrics_body_cap.");
	prom_buf_u64(pb, nm, c->st.render_truncated);

	if (c->extra)
		c->extra(c->user, pb, ns);

	(void)snprintf(nm, sizeof(nm), "%s_scrape_duration_seconds", ns);
	prom_buf_family(pb, nm, "gauge",
			"Time spent rendering this exposition.");
	now = caly_mono_ns();
	prom_buf_f64(pb, nm, now > t0 ? (double)(now - t0) / 1e9 : 0.0);

	if (pb->truncated)
		c->st.render_truncated++;

	return 0;
}

const char *prom_namespace(const struct prom_ctx *c)
{
	return c ? c->ns : "calyanti";
}

/* -------------------------------------------------------------------------
 * Connection plumbing
 * ------------------------------------------------------------------------- */

static void pc_close(struct prom_ctx *c, struct prom_conn *cn)
{
	if (cn->state == PC_ST_FREE)
		return;
	if (cn->fd >= 0)
		(void)close(cn->fd);
	cn->fd = -1;
	cn->state = PC_ST_FREE;
	cn->in_len = 0;
	cn->out_len = 0;
	cn->out_off = 0;
	cn->head_only = 0;
	if (c->st.conns_open)
		c->st.conns_open--;
	/* cn->out stays allocated: reusing it keeps total memory at
	 * O(max_conns * body_cap) with no per-request churn. */
}

static struct prom_conn *pc_slot(struct prom_ctx *c)
{
	unsigned int i;

	for (i = 0; i < c->max_conns; i++)
		if (c->conns[i].state == PC_ST_FREE)
			return &c->conns[i];
	return NULL;
}

static void pc_evict_oldest(struct prom_ctx *c)
{
	struct prom_conn *victim = NULL;
	unsigned int i;

	for (i = 0; i < c->max_conns; i++) {
		struct prom_conn *cn = &c->conns[i];

		if (cn->state == PC_ST_FREE)
			continue;
		if (!victim || cn->start_ns < victim->start_ns)
			victim = cn;
	}
	if (victim) {
		c->st.evicted++;
		pc_close(c, victim);
	}
}

static int pc_out_reserve(struct prom_ctx *c, struct prom_conn *cn,
			  size_t need)
{
	size_t cap;
	size_t limit = c->body_cap + PC_HDR_MAX + 64u;
	char *nb;

	if (cn->out_cap >= need)
		return 0;
	if (need > limit)
		return -E2BIG;

	cap = cn->out_cap ? cn->out_cap : 4096u;
	while (cap < need)
		cap <<= 1;
	if (cap > limit)
		cap = limit;

	nb = realloc(cn->out, cap);
	if (!nb)
		return -ENOMEM;
	cn->out = nb;
	cn->out_cap = cap;
	return 0;
}

static void pc_flush(struct prom_ctx *c, struct prom_conn *cn)
{
	while (cn->out_off < cn->out_len) {
		ssize_t n = send(cn->fd, cn->out + cn->out_off,
				 cn->out_len - cn->out_off, MSG_NOSIGNAL);

		if (n > 0) {
			cn->out_off += (size_t)n;
			c->st.bytes_sent += (__u64)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && PC_WOULDBLOCK(errno)) {
			cn->last_ns = caly_mono_ns();
			return;
		}
		pc_close(c, cn);
		return;
	}
	/* Connection: close - we never keep alive. */
	pc_close(c, cn);
}

static void pc_respond(struct prom_ctx *c, struct prom_conn *cn, int code,
		       const char *reason, const char *ctype,
		       const char *body, size_t blen)
{
	char hdr[PC_HDR_MAX];
	int hlen;
	size_t need;

	if (code >= 200 && code < 300)
		c->st.responses_2xx++;
	else if (code >= 400 && code < 500)
		c->st.responses_4xx++;
	else if (code >= 500)
		c->st.responses_5xx++;
	c->st.requests++;

	hlen = snprintf(hdr, sizeof(hdr),
			"HTTP/1.1 %d %s\r\n"
			"Content-Type: %s\r\n"
			"Content-Length: %llu\r\n"
			"Connection: close\r\n"
			"Cache-Control: no-store\r\n"
			"X-Content-Type-Options: nosniff\r\n"
			"\r\n",
			code, reason, ctype, (unsigned long long)blen);
	if (hlen < 0 || (size_t)hlen >= sizeof(hdr)) {
		pc_close(c, cn);
		return;
	}

	need = (size_t)hlen + (cn->head_only ? 0u : blen);
	if (pc_out_reserve(c, cn, need ? need : 1u) != 0) {
		static const char oom[] =
			"HTTP/1.1 500 Internal Server Error\r\n"
			"Content-Length: 0\r\n"
			"Connection: close\r\n\r\n";
		ssize_t ignored;

		c->st.responses_5xx++;
		ignored = send(cn->fd, oom, sizeof(oom) - 1u, MSG_NOSIGNAL);
		(void)ignored;
		pc_close(c, cn);
		return;
	}

	memcpy(cn->out, hdr, (size_t)hlen);
	if (!cn->head_only && blen && body)
		memcpy(cn->out + hlen, body, blen);
	cn->out_len = need;
	cn->out_off = 0;
	cn->state = PC_ST_WRITE;
	cn->last_ns = caly_mono_ns();

	pc_flush(c, cn);
}

static void pc_respond_text(struct prom_ctx *c, struct prom_conn *cn, int code,
			    const char *reason, const char *text)
{
	pc_respond(c, cn, code, reason, PC_CT_PLAIN, text, strlen(text));
}

/* -------------------------------------------------------------------------
 * Request parsing
 * ------------------------------------------------------------------------- */

/* Returns the offset just past the header terminator, or 0 when incomplete. */
static size_t pc_header_end(const char *buf, size_t len)
{
	size_t i;

	for (i = 0; i + 3u < len; i++)
		if (buf[i] == '\r' && buf[i + 1] == '\n' &&
		    buf[i + 2] == '\r' && buf[i + 3] == '\n')
			return i + 4u;
	/* Tolerate bare-LF request framing from hand-typed probes. */
	for (i = 0; i + 1u < len; i++)
		if (buf[i] == '\n' && buf[i + 1] == '\n')
			return i + 2u;
	return 0;
}

#define PC_PARSE_OK        0
#define PC_PARSE_BAD      -1
#define PC_PARSE_METHOD   -2
#define PC_PARSE_URI_LONG -3

static int pc_parse_request(const char *buf, size_t len, int *head_only,
			    char *path, size_t pcap)
{
	size_t i = 0, mstart, mlen, tstart, tlen, j;

	/* Method. */
	mstart = i;
	while (i < len && buf[i] != ' ' && buf[i] != '\r' && buf[i] != '\n')
		i++;
	if (i >= len || buf[i] != ' ')
		return PC_PARSE_BAD;
	mlen = i - mstart;

	if (mlen == 3 && memcmp(buf + mstart, "GET", 3) == 0) {
		*head_only = 0;
	} else if (mlen == 4 && memcmp(buf + mstart, "HEAD", 4) == 0) {
		*head_only = 1;
	} else {
		return PC_PARSE_METHOD;
	}

	while (i < len && buf[i] == ' ')
		i++;

	/* Request target. */
	tstart = i;
	while (i < len && buf[i] != ' ' && buf[i] != '\r' && buf[i] != '\n')
		i++;
	tlen = i - tstart;
	if (tlen == 0)
		return PC_PARSE_BAD;

	/* Strip the query string and any fragment. */
	for (j = 0; j < tlen; j++)
		if (buf[tstart + j] == '?' || buf[tstart + j] == '#')
			break;
	tlen = j;
	if (tlen == 0 || tlen + 1u > pcap)
		return tlen + 1u > pcap ? PC_PARSE_URI_LONG : PC_PARSE_BAD;

	for (j = 0; j < tlen; j++) {
		unsigned char ch = (unsigned char)buf[tstart + j];

		/* Nothing we serve needs escapes, so refuse anything outside
		 * a conservative set instead of implementing percent-decoding
		 * (and its traversal bugs). */
		if (ch <= 0x20u || ch >= 0x7Fu || ch == '"' || ch == '\\' ||
		    ch == '%')
			return PC_PARSE_BAD;
		path[j] = (char)ch;
	}
	path[tlen] = '\0';

	if (path[0] != '/')
		return PC_PARSE_BAD;

	/* The version token is optional (HTTP/0.9-style probes) but if present
	 * it must look like HTTP/1.x; we answer 1.1 regardless. */
	while (i < len && buf[i] == ' ')
		i++;
	if (i < len && buf[i] != '\r' && buf[i] != '\n') {
		if (len - i < 7u || memcmp(buf + i, "HTTP/1.", 7) != 0)
			return PC_PARSE_BAD;
	}

	return PC_PARSE_OK;
}

static int pc_path_is(const char *path, const char *want)
{
	size_t n = strlen(want);

	if (strncmp(path, want, n) != 0)
		return 0;
	/* Accept an optional single trailing slash. */
	return path[n] == '\0' || (path[n] == '/' && path[n + 1] == '\0');
}

static void pc_serve_health(struct prom_ctx *c, struct prom_conn *cn)
{
	char detail[192];
	char body[224];
	size_t i;
	int rc = 0;

	detail[0] = '\0';
	if (c->health)
		rc = c->health(c->user, detail, sizeof(detail));
	detail[sizeof(detail) - 1] = '\0';

	if (detail[0] == '\0')
		(void)snprintf(detail, sizeof(detail), "%s",
			       rc ? "unhealthy" : "ok");

	for (i = 0; detail[i]; i++) {
		unsigned char ch = (unsigned char)detail[i];

		if (ch < 0x20u || ch == 0x7Fu)
			detail[i] = ' ';
	}

	(void)snprintf(body, sizeof(body), "%s\n", detail);
	pc_respond(c, cn, rc ? 503 : 200,
		   rc ? "Service Unavailable" : "OK", PC_CT_PLAIN,
		   body, strlen(body));
}

static void pc_serve_metrics(struct prom_ctx *c, struct prom_conn *cn)
{
	if (prom_render(c, &c->render) != 0) {
		pc_respond_text(c, cn, 500, "Internal Server Error",
				"render failed\n");
		return;
	}
	pc_respond(c, cn, 200, "OK", PC_CT_METRICS, c->render.buf,
		   c->render.len);
}

static void pc_handle_request(struct prom_ctx *c, struct prom_conn *cn)
{
	char path[PC_PATH_MAX];
	int head_only = 0;
	int rc;

	rc = pc_parse_request(cn->in, cn->in_len, &head_only, path,
			      sizeof(path));
	cn->head_only = (unsigned char)(head_only ? 1 : 0);

	if (rc == PC_PARSE_METHOD) {
		c->st.bad_request++;
		pc_respond_text(c, cn, 405, "Method Not Allowed",
				"only GET and HEAD are supported\n");
		return;
	}
	if (rc == PC_PARSE_URI_LONG) {
		c->st.bad_request++;
		pc_respond_text(c, cn, 414, "URI Too Long", "uri too long\n");
		return;
	}
	if (rc != PC_PARSE_OK) {
		c->st.bad_request++;
		pc_respond_text(c, cn, 400, "Bad Request", "bad request\n");
		return;
	}

	if (pc_path_is(path, "/metrics")) {
		pc_serve_metrics(c, cn);
		return;
	}
	if (pc_path_is(path, "/healthz") || pc_path_is(path, "/health")) {
		pc_serve_health(c, cn);
		return;
	}
	if (strcmp(path, "/") == 0) {
		pc_respond_text(c, cn, 200, "OK",
				"caly-anti exporter\n"
				"endpoints: /metrics /healthz\n");
		return;
	}

	c->st.bad_request++;
	pc_respond_text(c, cn, 404, "Not Found", "not found\n");
}

static void pc_read(struct prom_ctx *c, struct prom_conn *cn)
{
	for (;;) {
		size_t space = sizeof(cn->in) - cn->in_len;
		ssize_t n;

		if (space == 0) {
			c->st.oversize++;
			cn->head_only = 0;
			pc_respond_text(c, cn, 431,
					"Request Header Fields Too Large",
					"request header too large\n");
			return;
		}

		n = recv(cn->fd, cn->in + cn->in_len, space, 0);
		if (n > 0) {
			cn->in_len += (unsigned int)n;
			cn->last_ns = caly_mono_ns();
			if (pc_header_end(cn->in, cn->in_len)) {
				pc_handle_request(c, cn);
				return;
			}
			continue;
		}
		if (n == 0) {
			pc_close(c, cn);
			return;
		}
		if (errno == EINTR)
			continue;
		if (PC_WOULDBLOCK(errno))
			return;
		pc_close(c, cn);
		return;
	}
}

static void pc_accept(struct prom_ctx *c)
{
	int i;

	for (i = 0; i < PC_ACCEPT_BURST; i++) {
		struct prom_conn *cn;
		int fd, one = 1;

		fd = accept4(c->lfd, NULL, NULL,
			     SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			if (PC_WOULDBLOCK(errno))
				return;
			c->st.accept_errors++;
			if (errno == EMFILE || errno == ENFILE) {
				/* Without freeing a descriptor the listener
				 * stays permanently readable and the daemon
				 * spins. Give up one connection instead. */
				pc_evict_oldest(c);
			}
			return;
		}

		cn = pc_slot(c);
		if (!cn) {
			/* Every slot is busy. Honour the documented guarantee
			 * (prom.h: "the oldest connection is evicted rather than
			 * letting the accept backlog or the fd table run dry") by
			 * reclaiming the oldest slot so a fresh scrape can always
			 * land, instead of black-holing it behind slow or idle
			 * clients that are holding every slot. */
			pc_evict_oldest(c);
			cn = pc_slot(c);
		}
		if (!cn) {
			/* Eviction freed nothing (should not happen while any
			 * slot is in use): accept-and-close rather than leave it
			 * in the backlog, which would keep the listener readable
			 * forever. */
			c->st.rejected_cap++;
			(void)close(fd);
			continue;
		}

		(void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one,
				 sizeof(one));

		cn->fd = fd;
		cn->state = PC_ST_READ;
		cn->head_only = 0;
		cn->in_len = 0;
		cn->out_len = 0;
		cn->out_off = 0;
		cn->start_ns = caly_mono_ns();
		cn->last_ns = cn->start_ns;

		c->st.accepted++;
		c->st.conns_open++;

		/* Opportunistic first read: most scrapes arrive in one
		 * segment and this saves a poll round trip. */
		pc_read(c, cn);
	}
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

static int pc_bind(const char *addr, __u16 port, int *out_fd)
{
	struct addrinfo hints, *res = NULL, *ai;
	char portstr[8];
	int rc, saved = EADDRNOTAVAIL;
	int fd = -1;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;

	(void)snprintf(portstr, sizeof(portstr), "%u", (unsigned int)port);

	rc = getaddrinfo(addr, portstr, &hints, &res);
	if (rc != 0 || !res)
		return -EINVAL;

	for (ai = res; ai; ai = ai->ai_next) {
		int one = 1;

		fd = socket(ai->ai_family,
			    ai->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC,
			    ai->ai_protocol);
		if (fd < 0) {
			saved = errno;
			continue;
		}
		(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one,
				 sizeof(one));
#ifdef IPV6_V6ONLY
		if (ai->ai_family == AF_INET6)
			(void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one,
					 sizeof(one));
#endif
		if (bind(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
			saved = errno;
			(void)close(fd);
			fd = -1;
			continue;
		}
		if (listen(fd, PROM_BACKLOG) != 0) {
			saved = errno;
			(void)close(fd);
			fd = -1;
			continue;
		}
		break;
	}

	freeaddrinfo(res);

	if (fd < 0)
		return -saved;
	*out_fd = fd;
	return 0;
}

static int pc_is_loopback(const char *addr)
{
	if (!addr)
		return 1;
	if (strncmp(addr, "127.", 4) == 0)
		return 1;
	if (strcmp(addr, "::1") == 0)
		return 1;
	return 0;
}

int prom_init(struct prom_ctx **out, const struct prom_cfg *cfg)
{
	struct prom_ctx *c;
	const char *addr;
	unsigned int i;
	__u16 port;
	int rc;

	if (!out || !cfg)
		return -EINVAL;
	*out = NULL;

	c = calloc(1, sizeof(*c));
	if (!c)
		return -ENOMEM;

	c->lfd = -1;
	c->max_conns = cfg->max_conns ? cfg->max_conns
				      : PROM_MAX_CONNS_DEFAULT;
	if (c->max_conns > PROM_MAX_CONNS_LIMIT)
		c->max_conns = PROM_MAX_CONNS_LIMIT;

	c->timeout_ms = cfg->req_timeout_ms ? cfg->req_timeout_ms
					    : PROM_TIMEOUT_MS_DEFAULT;
	if (c->timeout_ms > PROM_TIMEOUT_MS_MAX)
		c->timeout_ms = PROM_TIMEOUT_MS_MAX;

	c->body_cap = cfg->body_cap ? cfg->body_cap : PROM_BODY_CAP_DEFAULT;
	if (c->body_cap < PROM_BODY_CAP_MIN)
		c->body_cap = PROM_BODY_CAP_MIN;
	if (c->body_cap > PROM_BODY_CAP_MAX)
		c->body_cap = PROM_BODY_CAP_MAX;

	c->emit_zero_rates = cfg->emit_zero_rates;
	c->stats  = cfg->stats;
	c->events = cfg->events;
	c->extra  = cfg->extra;
	c->health = cfg->health;
	c->user   = cfg->user;
	c->log    = cfg->log;
	c->log_user = cfg->log_user;

	pc_ns_sanitise(c->ns, sizeof(c->ns), cfg->ns);

	c->conns = calloc(c->max_conns, sizeof(*c->conns));
	c->render_store = malloc(c->body_cap);
	c->snap = calloc(1, sizeof(*c->snap));
	c->delta = calloc(1, sizeof(*c->delta));
	c->evst = calloc(1, sizeof(*c->evst));
	if (!c->conns || !c->render_store || !c->snap || !c->delta ||
	    !c->evst) {
		prom_free(c);
		return -ENOMEM;
	}

	prom_buf_init(&c->render, c->render_store, c->body_cap);

	for (i = 0; i < c->max_conns; i++) {
		c->conns[i].fd = -1;
		c->conns[i].state = PC_ST_FREE;
	}
	c->st.conns_max = c->max_conns;

	if (cfg->listen_fd >= 0) {
		c->lfd = cfg->listen_fd;
		c->own_lfd = 0;
	} else {
		addr = cfg->bind_addr ? cfg->bind_addr : PROM_ADDR_DEFAULT;
		port = cfg->port ? cfg->port : PROM_PORT_DEFAULT;

		rc = pc_bind(addr, port, &c->lfd);
		if (rc != 0) {
			pc_log(c, CALY_LOG_ERR,
			       "prom: cannot bind %s:%u: %s", addr,
			       (unsigned int)port, strerror(-rc));
			prom_free(c);
			return rc;
		}
		c->own_lfd = 1;

		if (!pc_is_loopback(addr))
			pc_log(c, CALY_LOG_WARN,
			       "prom: listening on %s:%u, which is NOT "
			       "loopback; the metrics endpoint is an attack "
			       "surface and should be firewalled or bound to "
			       "127.0.0.1", addr, (unsigned int)port);
		else
			pc_log(c, CALY_LOG_INFO,
			       "prom: listening on %s:%u (/metrics /healthz)",
			       addr, (unsigned int)port);
	}

	*out = c;
	return 0;
}

void prom_free(struct prom_ctx *c)
{
	unsigned int i;

	if (!c)
		return;

	if (c->conns) {
		for (i = 0; i < c->max_conns; i++) {
			if (c->conns[i].state != PC_ST_FREE &&
			    c->conns[i].fd >= 0)
				(void)close(c->conns[i].fd);
			free(c->conns[i].out);
		}
		free(c->conns);
	}
	if (c->own_lfd && c->lfd >= 0)
		(void)close(c->lfd);

	free(c->render_store);
	free(c->snap);
	free(c->delta);
	free(c->evst);
	free(c);
}

int prom_listen_fd(const struct prom_ctx *c)
{
	return c ? c->lfd : -1;
}

/* -------------------------------------------------------------------------
 * Event loop integration
 * ------------------------------------------------------------------------- */

int prom_pollfd_count(const struct prom_ctx *c)
{
	unsigned int i, n = 0;

	if (!c)
		return 0;
	for (i = 0; i < c->max_conns; i++)
		if (c->conns[i].state != PC_ST_FREE)
			n++;
	return (int)n + (c->lfd >= 0 ? 1 : 0);
}

int prom_fill_pollfds(struct prom_ctx *c, struct pollfd *fds, int max)
{
	unsigned int i;
	int n = 0;

	if (!c || !fds || max <= 0)
		return -EINVAL;

	if (c->lfd >= 0) {
		fds[n].fd = c->lfd;
		fds[n].events = POLLIN;
		fds[n].revents = 0;
		n++;
	}

	for (i = 0; i < c->max_conns && n < max; i++) {
		struct prom_conn *cn = &c->conns[i];

		if (cn->state == PC_ST_FREE || cn->fd < 0)
			continue;
		fds[n].fd = cn->fd;
		fds[n].events = (cn->state == PC_ST_WRITE) ? POLLOUT : POLLIN;
		fds[n].revents = 0;
		n++;
	}
	return n;
}

static struct prom_conn *pc_by_fd(struct prom_ctx *c, int fd)
{
	unsigned int i;

	for (i = 0; i < c->max_conns; i++)
		if (c->conns[i].state != PC_ST_FREE && c->conns[i].fd == fd)
			return &c->conns[i];
	return NULL;
}

void prom_handle_pollfds(struct prom_ctx *c, const struct pollfd *fds, int n)
{
	int i;
	int listener_ready = 0;

	if (!c || !fds || n <= 0)
		return;

	/* Connections first, listener last: servicing the listener can reuse
	 * a descriptor number freed in this same pass, and handling that new
	 * connection with the old entry's revents would be wrong. */
	for (i = 0; i < n; i++) {
		struct prom_conn *cn;
		short re = fds[i].revents;

		if (fds[i].fd < 0 || re == 0)
			continue;
		if (c->lfd >= 0 && fds[i].fd == c->lfd) {
			if (re & (POLLIN | POLLERR | POLLHUP))
				listener_ready = 1;
			continue;
		}

		cn = pc_by_fd(c, fds[i].fd);
		if (!cn)
			continue;

		if (re & (POLLNVAL | POLLERR)) {
			pc_close(c, cn);
			continue;
		}
		if (cn->state == PC_ST_WRITE) {
			if (re & (POLLOUT | POLLHUP))
				pc_flush(c, cn);
			continue;
		}
		if (re & POLLIN)
			pc_read(c, cn);
		else if (re & POLLHUP)
			pc_close(c, cn);
	}

	if (listener_ready)
		pc_accept(c);
}

int prom_step(struct prom_ctx *c, int timeout_ms)
{
	struct pollfd fds[PROM_MAX_CONNS_LIMIT + 1];
	int n, rc;

	if (!c)
		return -EINVAL;

	n = prom_fill_pollfds(c, fds, (int)(sizeof(fds) / sizeof(fds[0])));
	if (n <= 0)
		return n;

	rc = poll(fds, (nfds_t)n, timeout_ms);
	if (rc < 0) {
		if (errno == EINTR) {
			prom_sweep(c);
			return 0;
		}
		return -errno;
	}
	if (rc > 0)
		prom_handle_pollfds(c, fds, n);
	prom_sweep(c);
	return rc;
}

void prom_sweep(struct prom_ctx *c)
{
	__u64 now, limit;
	unsigned int i;

	if (!c)
		return;

	now = caly_mono_ns();
	limit = (__u64)c->timeout_ms * CALY_NSEC_PER_MSEC;

	for (i = 0; i < c->max_conns; i++) {
		struct prom_conn *cn = &c->conns[i];

		if (cn->state == PC_ST_FREE)
			continue;
		/* Idle timeout: no I/O progress within the window. */
		if (now > cn->last_ns && now - cn->last_ns > limit) {
			c->st.timeouts++;
			pc_close(c, cn);
			continue;
		}
		/* Header-completion deadline. A client still reading its request
		 * must finish within req_timeout_ms of connecting. pc_read()
		 * refreshes last_ns on every byte received, so a trickle of one
		 * byte per interval would otherwise keep the idle check above
		 * from ever firing and hold the slot indefinitely (slowloris).
		 * start_ns is set once at accept and never refreshed, so this
		 * bound cannot be reset by dribbling bytes. */
		if (cn->state == PC_ST_READ && now > cn->start_ns &&
		    now - cn->start_ns > limit) {
			c->st.timeouts++;
			pc_close(c, cn);
		}
	}
}

int prom_next_timeout_ms(const struct prom_ctx *c)
{
	__u64 now, oldest = 0;
	unsigned int i;
	int any = 0;

	if (!c)
		return -1;

	now = caly_mono_ns();
	for (i = 0; i < c->max_conns; i++) {
		const struct prom_conn *cn = &c->conns[i];
		__u64 ref;

		if (cn->state == PC_ST_FREE)
			continue;
		/* A read-phase connection is also bound by start_ns (see
		 * prom_sweep); start_ns <= last_ns, so it governs the earlier
		 * deadline and must drive the wake-up. */
		ref = (cn->state == PC_ST_READ) ? cn->start_ns : cn->last_ns;
		if (!any || ref < oldest) {
			oldest = ref;
			any = 1;
		}
	}
	if (!any)
		return -1;             /* nothing pending: sleep freely */

	if (now >= oldest + (__u64)c->timeout_ms * CALY_NSEC_PER_MSEC)
		return 0;
	return (int)((oldest + (__u64)c->timeout_ms * CALY_NSEC_PER_MSEC -
		      now) / CALY_NSEC_PER_MSEC);
}

int prom_stats_get(const struct prom_ctx *c, struct prom_server_stats *out)
{
	unsigned int i, open = 0;

	if (!c || !out)
		return -EINVAL;

	*out = c->st;
	for (i = 0; i < c->max_conns; i++)
		if (c->conns[i].state != PC_ST_FREE)
			open++;
	out->conns_open = open;
	out->conns_max = c->max_conns;
	return 0;
}
