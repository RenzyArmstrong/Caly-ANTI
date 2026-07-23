/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/prom.h
 *
 * A deliberately tiny, dependency-free HTTP/1.1 endpoint exposing
 *   GET /metrics   Prometheus text exposition format 0.0.4
 *   GET /healthz   liveness probe
 *
 * THREAT MODEL
 *   This listener is itself an attack surface, so it is built to the same
 *   standard as the dataplane:
 *
 *     - binds 127.0.0.1 by default; a non-loopback bind is logged as a
 *       warning at startup, never silently accepted as normal;
 *     - every socket is non-blocking, so one stalled client cannot hold the
 *       daemon's event loop;
 *     - concurrent connections are hard-capped (prom_cfg.max_conns) and the
 *       oldest connection is evicted rather than letting the accept backlog
 *       or the fd table run dry;
 *     - the request buffer is a fixed per-connection array; a request that
 *       does not terminate within it gets 431 and the connection is closed;
 *     - a connection that makes no progress within req_timeout_ms is closed;
 *     - responses are rendered into one bounded, pre-allocated buffer and
 *       copied into a per-connection output buffer whose capacity is capped,
 *       so total memory is O(max_conns * body_cap) and nothing grows with
 *       request volume;
 *     - only GET and HEAD are accepted, only two paths are served, keep-alive
 *       is refused (Connection: close), and no request content is ever
 *       reflected into the response.
 *
 * INTEGRATION
 *   Either drive it from the daemon's own poll loop with
 *   prom_fill_pollfds() / prom_handle_pollfds(), or call prom_step(ctx, 0)
 *   once per loop iteration and let it poll internally. Both are supported;
 *   the fill/handle pair is preferred because it lets the daemon block.
 */

#ifndef CALY_USER_PROM_H
#define CALY_USER_PROM_H

#if defined(__CALY_ANTI_COMMON_H) && !defined(CALY_USERSPACE)
#error "common.h included without CALY_USERSPACE; include a src/user/*.h first"
#endif

#ifndef CALY_USERSPACE
#define CALY_USERSPACE 1
#endif

#include <stdarg.h>
#include <stddef.h>
#include <time.h>
#include <poll.h>
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

/* Owned by other translation units in this component. */
struct stats_ctx;
struct events_ctx;

/* -------------------------------------------------------------------------
 * Bounded text builder
 *
 * Exposed because the daemon's extra-metrics callback appends through it.
 * Every append is all-or-nothing, so the buffer never ends mid-line: on
 * overflow the append is discarded and `truncated` is latched, which keeps
 * the exposition parseable by Prometheus instead of poisoning a scrape.
 * ------------------------------------------------------------------------- */
struct prom_buf {
	char  *buf;
	size_t cap;
	size_t len;
	int    truncated;
};

void prom_buf_init(struct prom_buf *pb, char *storage, size_t cap);
void prom_buf_reset(struct prom_buf *pb);
int  prom_buf_add(struct prom_buf *pb, const char *s, size_t n);
int  prom_buf_addf(struct prom_buf *pb, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

/* "# HELP <name> <help>\n# TYPE <name> <type>\n" */
void prom_buf_family(struct prom_buf *pb, const char *name, const char *type,
		     const char *help);

void prom_buf_u64(struct prom_buf *pb, const char *name, __u64 v);
void prom_buf_i64(struct prom_buf *pb, const char *name, __s64 v);
void prom_buf_f64(struct prom_buf *pb, const char *name, double v);

/* Label values are escaped (backslash, double quote, newline) before use. */
void prom_buf_u64_l(struct prom_buf *pb, const char *name, const char *lname,
		    const char *lval, __u64 v);
void prom_buf_f64_l(struct prom_buf *pb, const char *name, const char *lname,
		    const char *lval, double v);
void prom_buf_u64_l2(struct prom_buf *pb, const char *name,
		     const char *l1name, const char *l1val,
		     const char *l2name, const char *l2val, __u64 v);

/* -------------------------------------------------------------------------
 * Callbacks
 * ------------------------------------------------------------------------- */

/*
 * Append daemon-owned metrics (mode, config generation, map occupancy,
 * interface list, ...). `ns` is the sanitised metric namespace so the caller
 * can build "<ns>_something". Called once per /metrics scrape, in the
 * daemon's own thread of control, with no locks held by this module.
 */
typedef void (*prom_extra_fn)(void *user, struct prom_buf *pb, const char *ns);

/*
 * Liveness. Return 0 for healthy (200) or non-zero for unhealthy (503), and
 * optionally write a one-line explanation into `detail`. When no callback is
 * supplied the endpoint always answers 200: a metrics probe that flaps a
 * supervisor into restarting a firewall under attack would be worse than no
 * probe at all.
 */
typedef int (*prom_health_fn)(void *user, char *detail, size_t cap);

/* -------------------------------------------------------------------------
 * Configuration
 * ------------------------------------------------------------------------- */

#define PROM_ADDR_DEFAULT      "127.0.0.1"
#define PROM_PORT_DEFAULT      9101
#define PROM_MAX_CONNS_DEFAULT     8u
#define PROM_MAX_CONNS_LIMIT     128u
#define PROM_REQ_MAX            8192u   /* request bytes accepted per conn  */
#define PROM_TIMEOUT_MS_DEFAULT 3000u
#define PROM_TIMEOUT_MS_MAX    60000u
#define PROM_BODY_CAP_DEFAULT (256u * 1024u)
#define PROM_BODY_CAP_MIN     (16u * 1024u)
#define PROM_BODY_CAP_MAX     (4u * 1024u * 1024u)
#define PROM_NS_MAX               32u
#define PROM_BACKLOG              16

struct prom_cfg {
	const char *bind_addr;         /* NULL -> PROM_ADDR_DEFAULT          */
	__u16 port;                    /* 0 -> PROM_PORT_DEFAULT             */
	int listen_fd;                 /* pre-opened socket (socket
					* activation); -1 to bind ourselves */
	unsigned int max_conns;        /* 0 -> PROM_MAX_CONNS_DEFAULT        */
	unsigned int req_timeout_ms;   /* 0 -> PROM_TIMEOUT_MS_DEFAULT       */
	unsigned int body_cap;         /* 0 -> PROM_BODY_CAP_DEFAULT         */
	const char *ns;                /* metric prefix; NULL -> "calyanti"  */
	int emit_zero_rates;           /* also export all-zero rate series   */

	struct stats_ctx  *stats;      /* may be NULL                        */
	struct events_ctx *events;     /* may be NULL                        */

	prom_extra_fn extra;
	prom_health_fn health;
	void *user;

	caly_log_fn log;
	void *log_user;
};

/* -------------------------------------------------------------------------
 * Server statistics (also exported through /metrics itself)
 * ------------------------------------------------------------------------- */
struct prom_server_stats {
	__u64 accepted;
	__u64 rejected_cap;            /* refused: connection cap reached    */
	__u64 evicted;                 /* oldest connection closed for room  */
	__u64 requests;
	__u64 responses_2xx;
	__u64 responses_4xx;
	__u64 responses_5xx;
	__u64 timeouts;
	__u64 oversize;                /* request exceeded PROM_REQ_MAX      */
	__u64 bad_request;
	__u64 bytes_sent;
	__u64 render_truncated;
	__u64 accept_errors;
	__u32 conns_open;
	__u32 conns_max;
};

struct prom_ctx;                   /* opaque */

/*
 * Bind (or adopt cfg->listen_fd) and start serving. Returns 0 or -errno; on
 * failure nothing is left listening and *out is untouched.
 */
int  prom_init(struct prom_ctx **out, const struct prom_cfg *cfg);
void prom_free(struct prom_ctx *ctx);

int  prom_listen_fd(const struct prom_ctx *ctx);

/*
 * Number of pollfd slots this module needs right now (listener plus live
 * connections): at most max_conns + 1.
 */
int  prom_pollfd_count(const struct prom_ctx *ctx);

/* Fill up to `max` entries; returns how many were written, or -errno. */
int  prom_fill_pollfds(struct prom_ctx *ctx, struct pollfd *fds, int max);

/*
 * Process the revents produced for the descriptors this module contributed.
 * Entries belonging to other subsystems are ignored (matched by fd), so the
 * daemon may pass its whole array.
 */
void prom_handle_pollfds(struct prom_ctx *ctx, const struct pollfd *fds,
			 int n);

/* Self-contained variant: poll our own descriptors and service them. */
int  prom_step(struct prom_ctx *ctx, int timeout_ms);

/* Close connections that have exceeded req_timeout_ms. Idempotent. */
void prom_sweep(struct prom_ctx *ctx);

/* Suggested poll timeout so prom_sweep() runs on time. */
int  prom_next_timeout_ms(const struct prom_ctx *ctx);

int  prom_stats_get(const struct prom_ctx *ctx, struct prom_server_stats *out);

/*
 * Render the exposition into `pb` exactly as GET /metrics would. Useful for
 * "calyctl metrics" and for tests without going through a socket.
 */
int  prom_render(struct prom_ctx *ctx, struct prom_buf *pb);

/* The sanitised namespace actually in use. */
const char *prom_namespace(const struct prom_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* CALY_USER_PROM_H */
