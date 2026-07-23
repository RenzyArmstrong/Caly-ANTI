/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/ipc.c
 *
 * SOCK_SEQPACKET control socket: server (daemon) and client (calyctl) halves.
 * See ipc.h for the wire protocol and the security model.
 *
 * The server is single-threaded: drive it from the daemon's poll loop with
 * ipc_fill_pollfds()/ipc_handle_pollfds(), or call ipc_step(). One request
 * per connection; the connection is closed once its response has drained,
 * which keeps the state machine to READ -> WRITE -> closed and removes any
 * possibility of request pipelining being abused.
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "ipc.h"
#include "stats.h"
#include "events.h"

#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
#define IC_WOULDBLOCK(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#else
#define IC_WOULDBLOCK(e) ((e) == EAGAIN)
#endif

#define IC_ST_FREE   0
#define IC_ST_READ   1
#define IC_ST_WRITE  2

#define IC_LOG_MAX   256u
#define IC_UNKNOWN32 0xFFFFFFFFu

struct ipc_frame {
	size_t off;
	size_t len;
};

struct ipc_conn {
	int fd;
	unsigned char state;
	__u64 start_ns;
	__u64 last_ns;

	char  *out;
	size_t out_cap;
	size_t out_len;

	struct ipc_frame *frames;
	size_t frames_cap;
	size_t frames_n;
	size_t frames_w;
};

struct ipc_ctx {
	int lfd;
	int own_lfd;
	char path[108];
	int path_owned;                /* we created the socket node         */

	unsigned int max_conns;
	unsigned int timeout_ms;
	__u32 allow_uid;
	int allow_uid_set;

	struct ipc_conn *conns;

	unsigned char *rx;             /* IPC_MSG_MAX receive scratch        */

	const struct ipc_handlers *h;
	void *user;
	struct stats_ctx *stats;
	struct events_ctx *events;

	caly_log_fn log;
	void *log_user;

	struct ipc_server_stats st;
};

/* -------------------------------------------------------------------------
 * Logging
 * ------------------------------------------------------------------------- */

static void ic_log(struct ipc_ctx *c, int level, const char *fmt, ...)
{
	char buf[IC_LOG_MAX];
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
 * String tables
 * ------------------------------------------------------------------------- */

const char *ipc_status_str(__u32 code)
{
	switch (code) {
	case IPC_OK:        return "ok";
	case IPC_EPROTO:    return "protocol error";
	case IPC_EPERM:     return "permission denied";
	case IPC_EINVAL:    return "invalid argument";
	case IPC_ENOSYS:    return "not implemented";
	case IPC_ENOENT:    return "not found";
	case IPC_EBUSY:     return "busy, try again";
	case IPC_EIO:       return "kernel operation failed";
	case IPC_ENOSPC:    return "map full";
	case IPC_ETOOBIG:   return "response too large";
	case IPC_EINTERNAL: return "internal error";
	default:            return "unknown";
	}
}

const char *ipc_type_str(__u32 type)
{
	switch (type) {
	case IPC_REQ_PING:           return "ping";
	case IPC_REQ_STATUS:         return "status";
	case IPC_REQ_STATS:          return "stats";
	case IPC_REQ_BAN:            return "ban";
	case IPC_REQ_UNBAN:          return "unban";
	case IPC_REQ_ALLOW_ADD:      return "allow-add";
	case IPC_REQ_ALLOW_DEL:      return "allow-del";
	case IPC_REQ_BLOCK_ADD:      return "block-add";
	case IPC_REQ_BLOCK_DEL:      return "block-del";
	case IPC_REQ_SET_MODE:       return "set-mode";
	case IPC_REQ_RELOAD:         return "reload";
	case IPC_REQ_DUMP_CONNTRACK: return "dump-conntrack";
	case IPC_REQ_DUMP_TOP:       return "dump-top";
	case IPC_REQ_DUMP_BANS:      return "dump-bans";
	case IPC_REQ_EVENTS_STATS:   return "events-stats";
	case IPC_RESP_OK:            return "ok";
	case IPC_RESP_ERR:           return "err";
	case IPC_RESP_DATA:          return "data";
	case IPC_RESP_STATUS:        return "status-reply";
	case IPC_RESP_PONG:          return "pong";
	case IPC_RESP_EVENTS_STATS:  return "events-stats-reply";
	default:                     return "unknown";
	}
}

static __u32 ic_errno_to_status(int neg_errno)
{
	int e = neg_errno < 0 ? -neg_errno : neg_errno;

	switch (e) {
	case 0:       return IPC_OK;
	case EPERM:
	case EACCES:  return IPC_EPERM;
	case EINVAL:  return IPC_EINVAL;
	case ENOSYS:  return IPC_ENOSYS;
	case ENOENT:  return IPC_ENOENT;
	case EBUSY:
	case EAGAIN:  return IPC_EBUSY;
	case EIO:     return IPC_EIO;
	case ENOSPC:  return IPC_ENOSPC;
	case E2BIG:   return IPC_ETOOBIG;
	default:      return IPC_EINTERNAL;
	}
}

/* -------------------------------------------------------------------------
 * Output framing
 * ------------------------------------------------------------------------- */

static void conn_out_clear(struct ipc_conn *cn)
{
	cn->out_len = 0;
	cn->frames_n = 0;
	cn->frames_w = 0;
}

static int conn_out_reserve(struct ipc_conn *cn, size_t need)
{
	size_t cap;
	char *nb;
	/* Absolute ceiling on one connection's queued output. */
	size_t limit = (size_t)IPC_RESP_BYTES_MAX + IPC_MSG_MAX;

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

static int conn_frame_reserve(struct ipc_conn *cn)
{
	size_t cap;
	struct ipc_frame *nf;

	if (cn->frames_n < cn->frames_cap)
		return 0;
	cap = cn->frames_cap ? cn->frames_cap * 2u : 8u;
	nf = realloc(cn->frames, cap * sizeof(*nf));
	if (!nf)
		return -ENOMEM;
	cn->frames = nf;
	cn->frames_cap = cap;
	return 0;
}

static int conn_enq(struct ipc_conn *cn, __u32 type, __u32 seq, __u32 status,
		    __u32 flags, const void *payload, __u32 len)
{
	struct ipc_hdr hdr;
	size_t framelen;
	int rc;

	if (len > IPC_PAYLOAD_MAX)
		return -E2BIG;

	framelen = sizeof(hdr) + len;

	rc = conn_out_reserve(cn, cn->out_len + framelen);
	if (rc != 0)
		return rc;
	rc = conn_frame_reserve(cn);
	if (rc != 0)
		return rc;

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic   = IPC_MAGIC;
	hdr.version = (__u16)IPC_VERSION;
	hdr.type    = (__u16)type;
	hdr.seq     = seq;
	hdr.status  = status;
	hdr.flags   = flags;
	hdr.length  = len;

	memcpy(cn->out + cn->out_len, &hdr, sizeof(hdr));
	if (len && payload)
		memcpy(cn->out + cn->out_len + sizeof(hdr), payload, len);

	cn->frames[cn->frames_n].off = cn->out_len;
	cn->frames[cn->frames_n].len = framelen;
	cn->frames_n++;
	cn->out_len += framelen;
	return 0;
}

/* -------------------------------------------------------------------------
 * Streaming sink
 * ------------------------------------------------------------------------- */

struct ipc_stream {
	struct ipc_conn *cn;
	__u32 seq;
	char chunk[IPC_CHUNK_PAYLOAD];
	size_t chunk_len;
	size_t total;
	int truncated;
	int err;               /* first negative errno from conn_enq        */
};

static int stream_emit(struct ipc_stream *s, int more)
{
	int rc;

	rc = conn_enq(s->cn, IPC_RESP_DATA, s->seq, IPC_OK,
		      IPC_F_TEXT | (more ? IPC_F_MORE : 0u),
		      s->chunk, (__u32)s->chunk_len);
	s->chunk_len = 0;
	if (rc != 0 && s->err == 0)
		s->err = rc;
	return rc;
}

static int ipc_stream_line(void *sink, const char *line, size_t len)
{
	struct ipc_stream *s = sink;

	if (s->err || s->truncated)
		return 1;

	while (len > 0) {
		size_t room;

		if (s->total >= IPC_RESP_BYTES_MAX) {
			s->truncated = 1;
			return 1;
		}
		room = sizeof(s->chunk) - s->chunk_len;
		if (room > IPC_RESP_BYTES_MAX - s->total)
			room = IPC_RESP_BYTES_MAX - s->total;
		if (room > len)
			room = len;

		memcpy(s->chunk + s->chunk_len, line, room);
		s->chunk_len += room;
		s->total += room;
		line += room;
		len -= room;

		if (s->chunk_len == sizeof(s->chunk)) {
			if (stream_emit(s, 1) != 0)
				return 1;
		}
	}
	return 0;
}

/* Flush the trailing chunk as the terminal (non-MORE) frame. */
static int stream_finish(struct ipc_stream *s, __u32 status)
{
	if (s->err)
		return s->err;

	if (s->truncated) {
		static const char note[] = "\n# response truncated\n";
		size_t nlen = sizeof(note) - 1u;

		if (s->chunk_len + nlen <= sizeof(s->chunk)) {
			memcpy(s->chunk + s->chunk_len, note, nlen);
			s->chunk_len += nlen;
		}
		status = IPC_ETOOBIG;
	}

	return conn_enq(s->cn, IPC_RESP_DATA, s->seq, status, IPC_F_TEXT,
			s->chunk, (__u32)s->chunk_len);
}

/* -------------------------------------------------------------------------
 * Fixed responses
 * ------------------------------------------------------------------------- */

static void reply_err(struct ipc_ctx *c, struct ipc_conn *cn, __u32 seq,
		      __u32 status, const char *msg)
{
	const char *m = msg ? msg : ipc_status_str(status);

	conn_out_clear(cn);
	(void)conn_enq(cn, IPC_RESP_ERR, seq, status, IPC_F_TEXT,
		       m, (__u32)strlen(m));
	c->st.responses_err++;
}

static void reply_ok(struct ipc_ctx *c, struct ipc_conn *cn, __u32 seq,
		     const char *msg)
{
	conn_out_clear(cn);
	if (msg && *msg)
		(void)conn_enq(cn, IPC_RESP_OK, seq, IPC_OK, IPC_F_TEXT,
			       msg, (__u32)strlen(msg));
	else
		(void)conn_enq(cn, IPC_RESP_OK, seq, IPC_OK, 0, NULL, 0);
	c->st.responses_ok++;
}

/* -------------------------------------------------------------------------
 * Request validation
 * ------------------------------------------------------------------------- */

static int ic_check_addr(const struct ipc_addr *a)
{
	if (a->pad[0] != 0 || a->pad[1] != 0)
		return -EINVAL;
	if (a->family == CALY_AF_INET) {
		if (a->prefixlen > 32u)
			return -EINVAL;
	} else if (a->family == CALY_AF_INET6) {
		if (a->prefixlen > 128u)
			return -EINVAL;
	} else {
		return -EINVAL;
	}
	return 0;
}

/* -------------------------------------------------------------------------
 * Telemetry helpers for the status reply
 * ------------------------------------------------------------------------- */

static void ic_fill_status_telemetry(struct ipc_ctx *c, struct ipc_status *st)
{
	struct stats_snapshot *snap;
	struct stats_delta *delta;
	struct stats_meta meta;
	__u64 now;

	st->ncpu = 0;
	st->events_backend = (__u32)events_backend(c->events);

	if (!c->stats)
		return;

	snap = calloc(1, sizeof(*snap));
	delta = calloc(1, sizeof(*delta));
	if (!snap || !delta) {
		free(snap);
		free(delta);
		return;
	}

	if (stats_latest(c->stats, snap) == 0) {
		st->pkts_total  = snap->pkts[STAT_PKT_TOTAL];
		st->bytes_total = snap->bytes[STAT_PKT_TOTAL];
		st->drops_total = snap->pkts[STAT_DROP_TOTAL];
	}
	if (stats_latest_delta(c->stats, delta) == 0) {
		st->pps      = stats_rate_pkts(delta, STAT_PKT_TOTAL);
		st->bps      = stats_rate_bytes(delta, STAT_PKT_TOTAL);
		st->drop_pps = stats_rate_pkts(delta, STAT_DROP_TOTAL);
		st->syn_pps  = stats_rate_gauge(delta, CALY_G_SYN);
	}
	if (stats_meta_get(c->stats, &meta) == 0) {
		st->ncpu = meta.ncpu;
		now = caly_mono_ns();
		if (meta.last_mono_ns && now > meta.last_mono_ns)
			st->sample_age_ns = now - meta.last_mono_ns;
	}

	free(snap);
	free(delta);
}

/* -------------------------------------------------------------------------
 * Dispatch
 * ------------------------------------------------------------------------- */

static void handle_status(struct ipc_ctx *c, struct ipc_conn *cn, __u32 seq)
{
	struct ipc_status st;

	memset(&st, 0, sizeof(st));
	st.abi_version = CALY_ABI_VERSION;
	st.mode        = FW_MODE_MAX;      /* "unknown" until a handler sets it */
	st.conn_count  = IC_UNKNOWN32;
	st.conn_max    = IC_UNKNOWN32;
	st.ban_count   = IC_UNKNOWN32;
	st.rate_count  = IC_UNKNOWN32;
	st.scan_count  = IC_UNKNOWN32;
	st.iface_count = IC_UNKNOWN32;

	if (c->h && c->h->status) {
		int rc = c->h->status(c->user, &st);

		if (rc < 0) {
			reply_err(c, cn, seq, ic_errno_to_status(rc), NULL);
			return;
		}
	}

	/* IPC owns the live telemetry block, always fresh. */
	ic_fill_status_telemetry(c, &st);

	conn_out_clear(cn);
	(void)conn_enq(cn, IPC_RESP_STATUS, seq, IPC_OK, 0, &st, sizeof(st));
	c->st.responses_ok++;
}

static void handle_events_stats(struct ipc_ctx *c, struct ipc_conn *cn,
				__u32 seq)
{
	struct ipc_events_summary sum;
	struct events_stats *es;

	if (!c->events) {
		reply_err(c, cn, seq, IPC_ENOSYS, "no event pipeline");
		return;
	}

	es = calloc(1, sizeof(*es));
	if (!es) {
		reply_err(c, cn, seq, IPC_EINTERNAL, NULL);
		return;
	}
	if (events_stats_get(c->events, es) != 0) {
		free(es);
		reply_err(c, cn, seq, IPC_EINTERNAL, NULL);
		return;
	}

	memset(&sum, 0, sizeof(sum));
	sum.received     = es->received;
	sum.accepted     = es->accepted;
	sum.invalid      = es->invalid_size + es->invalid_version +
			   es->invalid_field;
	sum.lost         = es->lost;
	sum.logged       = es->logged;
	sum.suppressed   = es->suppressed;
	sum.agg_overflow = es->agg_overflow;
	sum.flushes      = es->flushes;
	sum.backend      = es->backend;
	sum.agg_live     = es->agg_live;
	free(es);

	conn_out_clear(cn);
	(void)conn_enq(cn, IPC_RESP_EVENTS_STATS, seq, IPC_OK, 0, &sum,
		       sizeof(sum));
	c->st.responses_ok++;
}

typedef int (*ic_dump_fn)(void *user, __u32 flags, ipc_line_fn sink,
			  void *sink_arg);

static void handle_stream(struct ipc_ctx *c, struct ipc_conn *cn, __u32 seq,
			  __u32 flags, ic_dump_fn fn)
{
	struct ipc_stream *s;
	__u32 status = IPC_OK;
	int rc;

	if (!fn) {
		reply_err(c, cn, seq, IPC_ENOSYS, NULL);
		return;
	}

	s = calloc(1, sizeof(*s));
	if (!s) {
		reply_err(c, cn, seq, IPC_EINTERNAL, NULL);
		return;
	}
	s->cn = cn;
	s->seq = seq;

	conn_out_clear(cn);

	rc = fn(c->user, flags, ipc_stream_line, s);
	if (rc < 0)
		status = ic_errno_to_status(rc);

	if (s->err == -ENOMEM) {
		/* Ran out of memory mid-dump: discard the partial frames and
		 * answer with a clean error rather than a half response. */
		free(s);
		reply_err(c, cn, seq, IPC_EINTERNAL, NULL);
		return;
	}
	if (s->truncated) {
		status = IPC_ETOOBIG;
		c->st.truncated_out++;
	}

	if (stream_finish(s, status) != 0) {
		free(s);
		reply_err(c, cn, seq, IPC_EINTERNAL, NULL);
		return;
	}
	free(s);

	if (status == IPC_OK)
		c->st.responses_ok++;
	else
		c->st.responses_err++;
}

/*
 * IPC_REQ_STATS: prefer the daemon's dump_stats handler, but if none is
 * registered and a stats context was supplied, serve the dump ourselves.
 * stats_line_fn and ipc_line_fn are the same shape, so the stream sink drops
 * straight into stats_dump_lines().
 */
static void handle_stats(struct ipc_ctx *c, struct ipc_conn *cn, __u32 seq,
			 __u32 req_flags)
{
	struct ipc_stream *s;
	unsigned int dflags = 0;
	__u32 status = IPC_OK;
	int rc;

	if (c->h && c->h->dump_stats) {
		handle_stream(c, cn, seq, req_flags, c->h->dump_stats);
		return;
	}
	if (!c->stats) {
		reply_err(c, cn, seq, IPC_ENOSYS, NULL);
		return;
	}

	if (req_flags & IPC_DUMP_F_ZEROS)
		dflags |= STATS_DUMP_ZEROS;
	if (req_flags & IPC_DUMP_F_DROPS_ONLY)
		dflags |= STATS_DUMP_DROPS_ONLY;
	if (req_flags & IPC_DUMP_F_TREND)
		dflags |= STATS_DUMP_TREND;

	s = calloc(1, sizeof(*s));
	if (!s) {
		reply_err(c, cn, seq, IPC_EINTERNAL, NULL);
		return;
	}
	s->cn = cn;
	s->seq = seq;

	conn_out_clear(cn);

	rc = stats_dump_lines(c->stats, dflags, ipc_stream_line, s);
	if (rc < 0 && rc != -ENODATA)
		status = ic_errno_to_status(rc);

	if (s->err == -ENOMEM) {
		free(s);
		reply_err(c, cn, seq, IPC_EINTERNAL, NULL);
		return;
	}
	if (s->truncated) {
		status = IPC_ETOOBIG;
		c->st.truncated_out++;
	}
	if (stream_finish(s, status) != 0) {
		free(s);
		reply_err(c, cn, seq, IPC_EINTERNAL, NULL);
		return;
	}
	free(s);

	if (status == IPC_OK)
		c->st.responses_ok++;
	else
		c->st.responses_err++;
}

static void handle_ban(struct ipc_ctx *c, struct ipc_conn *cn, __u32 seq,
		       const void *payload, __u32 len, __u32 req_flags)
{
	struct ipc_ban_req req;
	char msg[96], addr[80];
	int rc;

	if (len != sizeof(req)) {
		reply_err(c, cn, seq, IPC_EPROTO, "bad ban payload size");
		return;
	}
	memcpy(&req, payload, sizeof(req));

	rc = ic_check_addr(&req.addr);
	if (rc != 0) {
		reply_err(c, cn, seq, IPC_EINVAL, "bad address");
		return;
	}
	if (req.reason >= (__u32)STAT_MAX)
		req.reason = STAT_BAN_ADDED;

	/* Sanitise flags: the operator may only request PERMANENT or FEED; the
	 * server stamps MANUAL and strips dataplane-only bits. */
	req.flags &= (CALY_BAN_F_PERMANENT | CALY_BAN_F_FEED);
	req.flags |= CALY_BAN_F_MANUAL;

	if (req_flags & IPC_F_DRYRUN) {
		reply_ok(c, cn, seq, "dry-run ok");
		return;
	}
	if (!c->h || !c->h->ban) {
		reply_err(c, cn, seq, IPC_ENOSYS, NULL);
		return;
	}

	rc = c->h->ban(c->user, &req);
	if (rc < 0) {
		reply_err(c, cn, seq, ic_errno_to_status(rc), NULL);
		return;
	}

	(void)ipc_addr_str(&req.addr, addr, sizeof(addr));
	(void)snprintf(msg, sizeof(msg), "banned %s", addr);
	reply_ok(c, cn, seq, msg);
}

static void handle_addr_op(struct ipc_ctx *c, struct ipc_conn *cn, __u32 seq,
			   const void *payload, __u32 len, __u32 req_flags,
			   int (*fn)(void *, const struct ipc_addr *),
			   const char *verb)
{
	struct ipc_addr addr;
	char msg[96], as[80];
	int rc;

	if (len != sizeof(addr)) {
		reply_err(c, cn, seq, IPC_EPROTO, "bad address payload size");
		return;
	}
	memcpy(&addr, payload, sizeof(addr));

	if (ic_check_addr(&addr) != 0) {
		reply_err(c, cn, seq, IPC_EINVAL, "bad address");
		return;
	}
	if (req_flags & IPC_F_DRYRUN) {
		reply_ok(c, cn, seq, "dry-run ok");
		return;
	}
	if (!fn) {
		reply_err(c, cn, seq, IPC_ENOSYS, NULL);
		return;
	}

	rc = fn(c->user, &addr);
	if (rc < 0) {
		reply_err(c, cn, seq, ic_errno_to_status(rc), NULL);
		return;
	}

	(void)ipc_addr_str(&addr, as, sizeof(as));
	(void)snprintf(msg, sizeof(msg), "%s %s", verb, as);
	reply_ok(c, cn, seq, msg);
}

static void handle_rule_add(struct ipc_ctx *c, struct ipc_conn *cn, __u32 seq,
			    const void *payload, __u32 len, __u32 req_flags,
			    int (*fn)(void *, const struct ipc_rule_req *),
			    __u32 force_flag, __u32 allow_mask,
			    const char *verb)
{
	struct ipc_rule_req req;
	char msg[96], as[80];
	int rc;

	if (len != sizeof(req)) {
		reply_err(c, cn, seq, IPC_EPROTO, "bad rule payload size");
		return;
	}
	memcpy(&req, payload, sizeof(req));

	if (ic_check_addr(&req.addr) != 0) {
		reply_err(c, cn, seq, IPC_EINVAL, "bad address");
		return;
	}
	req.flags &= allow_mask;
	req.flags |= force_flag;

	if (req_flags & IPC_F_DRYRUN) {
		reply_ok(c, cn, seq, "dry-run ok");
		return;
	}
	if (!fn) {
		reply_err(c, cn, seq, IPC_ENOSYS, NULL);
		return;
	}

	rc = fn(c->user, &req);
	if (rc < 0) {
		reply_err(c, cn, seq, ic_errno_to_status(rc), NULL);
		return;
	}

	(void)ipc_addr_str(&req.addr, as, sizeof(as));
	(void)snprintf(msg, sizeof(msg), "%s %s", verb, as);
	reply_ok(c, cn, seq, msg);
}

static void handle_set_mode(struct ipc_ctx *c, struct ipc_conn *cn, __u32 seq,
			    const void *payload, __u32 len, __u32 req_flags)
{
	struct ipc_mode_req req;
	char msg[64];
	int rc;

	if (len != sizeof(req)) {
		reply_err(c, cn, seq, IPC_EPROTO, "bad mode payload size");
		return;
	}
	memcpy(&req, payload, sizeof(req));

	if (req.mode >= (__u32)FW_MODE_MAX) {
		reply_err(c, cn, seq, IPC_EINVAL, "bad mode");
		return;
	}
	if (req_flags & IPC_F_DRYRUN) {
		reply_ok(c, cn, seq, "dry-run ok");
		return;
	}
	if (!c->h || !c->h->set_mode) {
		reply_err(c, cn, seq, IPC_ENOSYS, NULL);
		return;
	}

	rc = c->h->set_mode(c->user, req.mode);
	if (rc < 0) {
		reply_err(c, cn, seq, ic_errno_to_status(rc), NULL);
		return;
	}

	(void)snprintf(msg, sizeof(msg), "mode %s", fw_mode_str(req.mode));
	reply_ok(c, cn, seq, msg);
}

static void handle_reload(struct ipc_ctx *c, struct ipc_conn *cn, __u32 seq,
			  __u32 req_flags)
{
	int rc;

	if (req_flags & IPC_F_DRYRUN) {
		reply_ok(c, cn, seq, "dry-run ok");
		return;
	}
	if (!c->h || !c->h->reload) {
		reply_err(c, cn, seq, IPC_ENOSYS, NULL);
		return;
	}
	rc = c->h->reload(c->user);
	if (rc < 0) {
		reply_err(c, cn, seq, ic_errno_to_status(rc), NULL);
		return;
	}
	reply_ok(c, cn, seq, "reloaded");
}

static void ic_dispatch(struct ipc_ctx *c, struct ipc_conn *cn,
			const struct ipc_hdr *hdr, const void *payload)
{
	const struct ipc_handlers *h = c->h;

	c->st.requests++;

	switch (hdr->type) {
	case IPC_REQ_PING:
		conn_out_clear(cn);
		(void)conn_enq(cn, IPC_RESP_PONG, hdr->seq, IPC_OK, 0, NULL, 0);
		c->st.responses_ok++;
		break;
	case IPC_REQ_STATUS:
		handle_status(c, cn, hdr->seq);
		break;
	case IPC_REQ_EVENTS_STATS:
		handle_events_stats(c, cn, hdr->seq);
		break;
	case IPC_REQ_STATS:
		handle_stats(c, cn, hdr->seq, hdr->flags);
		break;
	case IPC_REQ_DUMP_CONNTRACK:
		handle_stream(c, cn, hdr->seq, hdr->flags,
			      h ? h->dump_conntrack : NULL);
		break;
	case IPC_REQ_DUMP_TOP:
		handle_stream(c, cn, hdr->seq, hdr->flags,
			      h ? h->dump_top : NULL);
		break;
	case IPC_REQ_DUMP_BANS:
		handle_stream(c, cn, hdr->seq, hdr->flags,
			      h ? h->dump_bans : NULL);
		break;
	case IPC_REQ_BAN:
		handle_ban(c, cn, hdr->seq, payload, hdr->length, hdr->flags);
		break;
	case IPC_REQ_UNBAN:
		handle_addr_op(c, cn, hdr->seq, payload, hdr->length,
			       hdr->flags, h ? h->unban : NULL, "unbanned");
		break;
	case IPC_REQ_ALLOW_ADD:
		handle_rule_add(c, cn, hdr->seq, payload, hdr->length,
				hdr->flags, h ? h->allow_add : NULL,
				CALY_RULE_F_ALLOW,
				CALY_RULE_F_ALLOW | CALY_RULE_F_BYPASS_RATE |
				CALY_RULE_F_LOG, "allowed");
		break;
	case IPC_REQ_ALLOW_DEL:
		handle_addr_op(c, cn, hdr->seq, payload, hdr->length,
			       hdr->flags, h ? h->allow_del : NULL,
			       "allow-removed");
		break;
	case IPC_REQ_BLOCK_ADD:
		handle_rule_add(c, cn, hdr->seq, payload, hdr->length,
				hdr->flags, h ? h->block_add : NULL,
				CALY_RULE_F_BLOCK,
				CALY_RULE_F_BLOCK | CALY_RULE_F_LOG,
				"blocked");
		break;
	case IPC_REQ_BLOCK_DEL:
		handle_addr_op(c, cn, hdr->seq, payload, hdr->length,
			       hdr->flags, h ? h->block_del : NULL,
			       "block-removed");
		break;
	case IPC_REQ_SET_MODE:
		handle_set_mode(c, cn, hdr->seq, payload, hdr->length,
				hdr->flags);
		break;
	case IPC_REQ_RELOAD:
		handle_reload(c, cn, hdr->seq, hdr->flags);
		break;
	default:
		reply_err(c, cn, hdr->seq, IPC_EPROTO, "unknown request type");
		break;
	}
}

/* -------------------------------------------------------------------------
 * Connection I/O
 * ------------------------------------------------------------------------- */

static void ic_close(struct ipc_ctx *c, struct ipc_conn *cn)
{
	if (cn->state == IC_ST_FREE)
		return;
	if (cn->fd >= 0)
		(void)close(cn->fd);
	cn->fd = -1;
	cn->state = IC_ST_FREE;
	conn_out_clear(cn);
	if (c->st.conns_open)
		c->st.conns_open--;
}

static struct ipc_conn *ic_slot(struct ipc_ctx *c)
{
	unsigned int i;

	for (i = 0; i < c->max_conns; i++)
		if (c->conns[i].state == IC_ST_FREE)
			return &c->conns[i];
	return NULL;
}

static void ic_drain(struct ipc_ctx *c, struct ipc_conn *cn)
{
	while (cn->frames_w < cn->frames_n) {
		struct ipc_frame *f = &cn->frames[cn->frames_w];
		ssize_t n = send(cn->fd, cn->out + f->off, f->len,
				 MSG_NOSIGNAL);

		if (n == (ssize_t)f->len) {
			cn->frames_w++;
			cn->last_ns = caly_mono_ns();
			c->st.bytes_sent += (__u64)n;
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0 && IC_WOULDBLOCK(errno)) {
			cn->last_ns = caly_mono_ns();
			return;                 /* wait for POLLOUT */
		}
		/* A SEQPACKET send is atomic; a short count or a hard error
		 * both mean this connection is unusable. */
		ic_close(c, cn);
		return;
	}
	/* Response fully delivered; one request per connection. */
	ic_close(c, cn);
}

static void ic_read(struct ipc_ctx *c, struct ipc_conn *cn)
{
	struct ipc_hdr hdr;
	ssize_t n;

	/* SEQPACKET: exactly one datagram per recv. MSG_TRUNC makes recv
	 * report the true length so an oversized datagram is detected rather
	 * than silently clipped. */
	n = recv(cn->fd, c->rx, IPC_MSG_MAX, MSG_TRUNC);
	if (n == 0) {
		ic_close(c, cn);
		return;
	}
	if (n < 0) {
		if (errno == EINTR || IC_WOULDBLOCK(errno))
			return;
		ic_close(c, cn);
		return;
	}
	c->st.bytes_recv += (__u64)n;

	if ((size_t)n > IPC_MSG_MAX || (size_t)n < sizeof(hdr)) {
		c->st.bad_frame++;
		reply_err(c, cn, 0, IPC_EPROTO, "malformed frame");
		cn->state = IC_ST_WRITE;
		ic_drain(c, cn);
		return;
	}

	memcpy(&hdr, c->rx, sizeof(hdr));

	if (hdr.magic != IPC_MAGIC || hdr.version != (__u16)IPC_VERSION) {
		c->st.bad_frame++;
		reply_err(c, cn, hdr.seq, IPC_EPROTO, "bad magic or version");
		cn->state = IC_ST_WRITE;
		ic_drain(c, cn);
		return;
	}
	if (hdr.length > IPC_PAYLOAD_MAX ||
	    (size_t)hdr.length + sizeof(hdr) != (size_t)n) {
		c->st.bad_frame++;
		reply_err(c, cn, hdr.seq, IPC_EPROTO, "length mismatch");
		cn->state = IC_ST_WRITE;
		ic_drain(c, cn);
		return;
	}

	ic_dispatch(c, cn, &hdr, c->rx + sizeof(hdr));

	if (cn->frames_n == 0) {
		/* A handler must always produce at least one frame; if none
		 * did, do not leave the peer hanging. */
		reply_err(c, cn, hdr.seq, IPC_EINTERNAL, NULL);
	}
	cn->state = IC_ST_WRITE;
	ic_drain(c, cn);
}

static int ic_check_peer(struct ipc_ctx *c, int fd)
{
	struct ucred cred;
	socklen_t clen = sizeof(cred);

	memset(&cred, 0, sizeof(cred));
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) != 0)
		return -EPERM;
	if (clen != sizeof(cred))
		return -EPERM;

	if (cred.uid == 0)
		return 0;
	if (c->allow_uid_set && cred.uid == c->allow_uid)
		return 0;

	ic_log(c, CALY_LOG_WARN,
	       "ipc: refused control connection from uid=%u pid=%ld",
	       (unsigned int)cred.uid, (long)cred.pid);
	return -EPERM;
}

static void ic_accept(struct ipc_ctx *c)
{
	int i;

	for (i = 0; i < 16; i++) {
		struct ipc_conn *cn;
		int fd;

		fd = accept4(c->lfd, NULL, NULL,
			     SOCK_NONBLOCK | SOCK_CLOEXEC);
		if (fd < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				continue;
			if (IC_WOULDBLOCK(errno))
				return;
			if (errno == EMFILE || errno == ENFILE)
				return;
			return;
		}

		if (ic_check_peer(c, fd) != 0) {
			struct ipc_hdr h;
			const char *m = ipc_status_str(IPC_EPERM);

			c->st.rejected_cred++;
			/* Best-effort refusal message, then close. */
			memset(&h, 0, sizeof(h));
			h.magic = IPC_MAGIC;
			h.version = (__u16)IPC_VERSION;
			h.type = (__u16)IPC_RESP_ERR;
			h.status = IPC_EPERM;
			h.flags = IPC_F_TEXT;
			h.length = (__u32)strlen(m);
			{
				unsigned char tmp[sizeof(h) + 32];

				memcpy(tmp, &h, sizeof(h));
				memcpy(tmp + sizeof(h), m, h.length);
				(void)send(fd, tmp, sizeof(h) + h.length,
					   MSG_NOSIGNAL | MSG_DONTWAIT);
			}
			(void)close(fd);
			continue;
		}

		cn = ic_slot(c);
		if (!cn) {
			c->st.rejected_cap++;
			(void)close(fd);
			continue;
		}

		cn->fd = fd;
		cn->state = IC_ST_READ;
		conn_out_clear(cn);
		cn->start_ns = caly_mono_ns();
		cn->last_ns = cn->start_ns;

		c->st.accepted++;
		c->st.conns_open++;

		/* Opportunistic read: the request is usually already queued. */
		ic_read(c, cn);
	}
}

/* -------------------------------------------------------------------------
 * Socket setup
 * ------------------------------------------------------------------------- */

static int ic_bind(struct ipc_ctx *c, const char *path)
{
	struct sockaddr_un sa;
	struct stat stbuf;
	mode_t old_umask;
	int fd, rc;

	if (strlen(path) + 1u > sizeof(sa.sun_path))
		return -ENAMETOOLONG;

	/* Ensure /run/calyanti exists and is only reachable by root. */
	if (mkdir(CALY_RUN_DIR, 0750) != 0 && errno != EEXIST)
		return -errno;
	(void)chmod(CALY_RUN_DIR, 0750);

	/* Refuse to clobber anything that is not our own stale socket. */
	if (lstat(path, &stbuf) == 0) {
		if (!S_ISSOCK(stbuf.st_mode))
			return -EEXIST;
		if (unlink(path) != 0 && errno != ENOENT)
			return -errno;
	} else if (errno != ENOENT) {
		return -errno;
	}

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	memcpy(sa.sun_path, path, strlen(path));

	old_umask = umask(0177);        /* node is created 0600 before chmod */
	rc = bind(fd, (struct sockaddr *)&sa, sizeof(sa));
	(void)umask(old_umask);
	if (rc != 0) {
		rc = -errno;
		(void)close(fd);
		return rc;
	}

	c->path_owned = 1;
	(void)chmod(path, 0600);
	(void)chown(path, 0, 0);        /* best effort; we are typically root */

	if (listen(fd, 16) != 0) {
		rc = -errno;
		(void)close(fd);
		(void)unlink(path);
		c->path_owned = 0;
		return rc;
	}

	c->lfd = fd;
	c->own_lfd = 1;
	return 0;
}

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

int ipc_init(struct ipc_ctx **out, const struct ipc_cfg *cfg)
{
	struct ipc_ctx *c;
	const char *path;
	unsigned int i;
	int rc;

	if (!out || !cfg)
		return -EINVAL;
	*out = NULL;

	c = calloc(1, sizeof(*c));
	if (!c)
		return -ENOMEM;

	c->lfd = -1;
	c->max_conns = cfg->max_conns ? cfg->max_conns : IPC_MAX_CONNS_DEFAULT;
	if (c->max_conns > IPC_MAX_CONNS_LIMIT)
		c->max_conns = IPC_MAX_CONNS_LIMIT;
	c->timeout_ms = cfg->timeout_ms ? cfg->timeout_ms
					: IPC_TIMEOUT_MS_DEFAULT;
	if (c->timeout_ms > IPC_TIMEOUT_MS_MAX)
		c->timeout_ms = IPC_TIMEOUT_MS_MAX;
	c->allow_uid = cfg->allow_uid;
	c->allow_uid_set = cfg->allow_uid_set;
	c->h = cfg->handlers;
	c->user = cfg->user;
	c->stats = cfg->stats;
	c->events = cfg->events;
	c->log = cfg->log;
	c->log_user = cfg->log_user;

	path = cfg->path ? cfg->path : CALY_CTRL_SOCK_PATH;
	(void)snprintf(c->path, sizeof(c->path), "%s", path);

	c->conns = calloc(c->max_conns, sizeof(*c->conns));
	c->rx = malloc(IPC_MSG_MAX);
	if (!c->conns || !c->rx) {
		ipc_free(c);
		return -ENOMEM;
	}
	for (i = 0; i < c->max_conns; i++) {
		c->conns[i].fd = -1;
		c->conns[i].state = IC_ST_FREE;
	}
	c->st.conns_max = c->max_conns;

	if (cfg->listen_fd >= 0) {
		c->lfd = cfg->listen_fd;
		c->own_lfd = 0;
		c->path_owned = 0;
	} else {
		rc = ic_bind(c, c->path);
		if (rc != 0) {
			ic_log(c, CALY_LOG_ERR,
			       "ipc: cannot bind %s: %s", c->path,
			       strerror(-rc));
			ipc_free(c);
			return rc;
		}
		ic_log(c, CALY_LOG_INFO, "ipc: control socket at %s (0600)",
		       c->path);
	}

	*out = c;
	return 0;
}

void ipc_free(struct ipc_ctx *c)
{
	unsigned int i;

	if (!c)
		return;

	if (c->conns) {
		for (i = 0; i < c->max_conns; i++) {
			if (c->conns[i].state != IC_ST_FREE &&
			    c->conns[i].fd >= 0)
				(void)close(c->conns[i].fd);
			free(c->conns[i].out);
			free(c->conns[i].frames);
		}
		free(c->conns);
	}
	if (c->own_lfd && c->lfd >= 0)
		(void)close(c->lfd);
	if (c->path_owned && c->path[0])
		(void)unlink(c->path);

	free(c->rx);
	free(c);
}

int ipc_listen_fd(const struct ipc_ctx *c)
{
	return c ? c->lfd : -1;
}

/* -------------------------------------------------------------------------
 * Event loop integration
 * ------------------------------------------------------------------------- */

int ipc_pollfd_count(const struct ipc_ctx *c)
{
	unsigned int i, n = 0;

	if (!c)
		return 0;
	for (i = 0; i < c->max_conns; i++)
		if (c->conns[i].state != IC_ST_FREE)
			n++;
	return (int)n + (c->lfd >= 0 ? 1 : 0);
}

int ipc_fill_pollfds(struct ipc_ctx *c, struct pollfd *fds, int max)
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
		struct ipc_conn *cn = &c->conns[i];

		if (cn->state == IC_ST_FREE || cn->fd < 0)
			continue;
		fds[n].fd = cn->fd;
		fds[n].events = (cn->state == IC_ST_WRITE) ? POLLOUT : POLLIN;
		fds[n].revents = 0;
		n++;
	}
	return n;
}

static struct ipc_conn *ic_by_fd(struct ipc_ctx *c, int fd)
{
	unsigned int i;

	for (i = 0; i < c->max_conns; i++)
		if (c->conns[i].state != IC_ST_FREE && c->conns[i].fd == fd)
			return &c->conns[i];
	return NULL;
}

void ipc_handle_pollfds(struct ipc_ctx *c, const struct pollfd *fds, int n)
{
	int i;
	int listener_ready = 0;

	if (!c || !fds || n <= 0)
		return;

	for (i = 0; i < n; i++) {
		struct ipc_conn *cn;
		short re = fds[i].revents;

		if (fds[i].fd < 0 || re == 0)
			continue;
		if (c->lfd >= 0 && fds[i].fd == c->lfd) {
			if (re & (POLLIN | POLLERR | POLLHUP))
				listener_ready = 1;
			continue;
		}

		cn = ic_by_fd(c, fds[i].fd);
		if (!cn)
			continue;

		if (re & (POLLNVAL | POLLERR)) {
			ic_close(c, cn);
			continue;
		}
		if (cn->state == IC_ST_WRITE) {
			if (re & (POLLOUT | POLLHUP))
				ic_drain(c, cn);
			continue;
		}
		if (re & POLLIN)
			ic_read(c, cn);
		else if (re & POLLHUP)
			ic_close(c, cn);
	}

	if (listener_ready)
		ic_accept(c);
}

int ipc_step(struct ipc_ctx *c, int timeout_ms)
{
	struct pollfd fds[IPC_MAX_CONNS_LIMIT + 1];
	int n, rc;

	if (!c)
		return -EINVAL;

	n = ipc_fill_pollfds(c, fds, (int)(sizeof(fds) / sizeof(fds[0])));
	if (n <= 0)
		return n;

	rc = poll(fds, (nfds_t)n, timeout_ms);
	if (rc < 0) {
		if (errno == EINTR) {
			ipc_sweep(c);
			return 0;
		}
		return -errno;
	}
	if (rc > 0)
		ipc_handle_pollfds(c, fds, n);
	ipc_sweep(c);
	return rc;
}

void ipc_sweep(struct ipc_ctx *c)
{
	__u64 now, limit;
	unsigned int i;

	if (!c)
		return;

	now = caly_mono_ns();
	limit = (__u64)c->timeout_ms * CALY_NSEC_PER_MSEC;

	for (i = 0; i < c->max_conns; i++) {
		struct ipc_conn *cn = &c->conns[i];

		if (cn->state == IC_ST_FREE)
			continue;
		if (now > cn->last_ns && now - cn->last_ns > limit) {
			c->st.timeouts++;
			ic_close(c, cn);
		}
	}
}

int ipc_next_timeout_ms(const struct ipc_ctx *c)
{
	__u64 now, oldest = 0;
	unsigned int i;
	int any = 0;

	if (!c)
		return -1;

	now = caly_mono_ns();
	for (i = 0; i < c->max_conns; i++) {
		const struct ipc_conn *cn = &c->conns[i];

		if (cn->state == IC_ST_FREE)
			continue;
		if (!any || cn->last_ns < oldest) {
			oldest = cn->last_ns;
			any = 1;
		}
	}
	if (!any)
		return -1;

	if (now >= oldest + (__u64)c->timeout_ms * CALY_NSEC_PER_MSEC)
		return 0;
	return (int)((oldest + (__u64)c->timeout_ms * CALY_NSEC_PER_MSEC -
		      now) / CALY_NSEC_PER_MSEC);
}

int ipc_stats_get(const struct ipc_ctx *c, struct ipc_server_stats *out)
{
	unsigned int i, open = 0;

	if (!c || !out)
		return -EINVAL;
	*out = c->st;
	for (i = 0; i < c->max_conns; i++)
		if (c->conns[i].state != IC_ST_FREE)
			open++;
	out->conns_open = open;
	out->conns_max = c->max_conns;
	return 0;
}

/* -------------------------------------------------------------------------
 * Address parsing / formatting
 * ------------------------------------------------------------------------- */

int ipc_addr_parse(const char *text, struct ipc_addr *out)
{
	char work[128];
	char *slash;
	unsigned long plen;
	int family;
	size_t n;

	if (!text || !out)
		return -EINVAL;
	n = strlen(text);
	if (n == 0 || n >= sizeof(work))
		return -EINVAL;
	memcpy(work, text, n + 1u);

	memset(out, 0, sizeof(*out));

	slash = strchr(work, '/');
	if (slash)
		*slash = '\0';

	if (strchr(work, ':')) {
		family = CALY_AF_INET6;
		if (inet_pton(AF_INET6, work, out->addr) != 1)
			return -EINVAL;
	} else {
		family = CALY_AF_INET;
		if (inet_pton(AF_INET, work, out->addr) != 1)
			return -EINVAL;
	}
	out->family = (__u8)family;

	if (slash) {
		char *end = NULL;

		errno = 0;
		plen = strtoul(slash + 1, &end, 10);
		if (errno != 0 || !end || *end != '\0' || end == slash + 1)
			return -EINVAL;
	} else {
		plen = (family == CALY_AF_INET6) ? 128u : 32u;
	}

	if (family == CALY_AF_INET6) {
		if (plen > 128u)
			return -EINVAL;
	} else if (plen > 32u) {
		return -EINVAL;
	}
	out->prefixlen = (__u8)plen;
	return 0;
}

const char *ipc_addr_str(const struct ipc_addr *a, char *buf, size_t cap)
{
	char ip[64];
	int af;

	if (!buf || cap == 0)
		return buf;
	if (!a) {
		(void)snprintf(buf, cap, "(null)");
		return buf;
	}

	af = (a->family == CALY_AF_INET6) ? AF_INET6 : AF_INET;
	if (!inet_ntop(af, a->addr, ip, sizeof(ip)))
		(void)snprintf(ip, sizeof(ip), "?");
	(void)snprintf(buf, cap, "%s/%u", ip, (unsigned int)a->prefixlen);
	return buf;
}

/* -------------------------------------------------------------------------
 * Client
 * ------------------------------------------------------------------------- */

int ipc_client_connect(const char *path)
{
	struct sockaddr_un sa;
	const char *p = path ? path : CALY_CTRL_SOCK_PATH;
	int fd;

	if (strlen(p) + 1u > sizeof(sa.sun_path))
		return -ENAMETOOLONG;

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	memcpy(sa.sun_path, p, strlen(p));

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		int rc = -errno;

		(void)close(fd);
		return rc;
	}
	return fd;
}

int ipc_client_send(int fd, __u32 type, __u32 seq, __u32 flags,
		    const void *payload, __u32 len)
{
	struct ipc_hdr hdr;
	unsigned char *buf;
	ssize_t n;
	size_t total;

	if (fd < 0)
		return -EINVAL;
	if (len > IPC_PAYLOAD_MAX)
		return -E2BIG;
	if (len && !payload)
		return -EINVAL;

	total = sizeof(hdr) + len;
	buf = malloc(total);
	if (!buf)
		return -ENOMEM;

	memset(&hdr, 0, sizeof(hdr));
	hdr.magic = IPC_MAGIC;
	hdr.version = (__u16)IPC_VERSION;
	hdr.type = (__u16)type;
	hdr.seq = seq;
	hdr.status = 0;
	hdr.flags = flags;
	hdr.length = len;

	memcpy(buf, &hdr, sizeof(hdr));
	if (len)
		memcpy(buf + sizeof(hdr), payload, len);

	for (;;) {
		n = send(fd, buf, total, MSG_NOSIGNAL);
		if (n == (ssize_t)total) {
			free(buf);
			return 0;
		}
		if (n < 0 && errno == EINTR)
			continue;
		break;
	}
	free(buf);
	return n < 0 ? -errno : -EIO;
}

long ipc_client_recv(int fd, struct ipc_hdr *hdr, void *buf, size_t cap)
{
	unsigned char hbuf[sizeof(struct ipc_hdr)];
	struct iovec iov[2];
	struct msghdr msg;
	ssize_t n;

	if (fd < 0 || !hdr || (!buf && cap))
		return -EINVAL;

	/* Read the header and payload in one recvmsg so message boundaries are
	 * preserved and MSG_TRUNC flags an oversized datagram. */
	iov[0].iov_base = hbuf;
	iov[0].iov_len = sizeof(hbuf);
	iov[1].iov_base = buf;
	iov[1].iov_len = cap;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.msg_iovlen = 2;

	for (;;) {
		n = recvmsg(fd, &msg, 0);
		if (n >= 0)
			break;
		if (errno == EINTR)
			continue;
		return -errno;
	}

	if (n == 0)
		return -ECONNRESET;
	if ((size_t)n < sizeof(hbuf))
		return -EBADMSG;
	if (msg.msg_flags & MSG_TRUNC)
		return -EBADMSG;

	memcpy(hdr, hbuf, sizeof(*hdr));
	if (hdr->magic != IPC_MAGIC || hdr->version != (__u16)IPC_VERSION)
		return -EBADMSG;
	if ((size_t)hdr->length + sizeof(hbuf) != (size_t)n)
		return -EBADMSG;
	if (hdr->length > cap)
		return -EBADMSG;

	return (long)hdr->length;
}

int ipc_client_request(int fd, __u32 type, __u32 flags, const void *payload,
		       __u32 len, ipc_line_fn sink, void *sink_arg)
{
	unsigned char *buf;
	__u32 seq = (__u32)(caly_mono_ns() & 0xFFFFFFFFu);
	int final = IPC_EINTERNAL;
	int rc;

	if (fd < 0)
		return -EINVAL;

	rc = ipc_client_send(fd, type, seq, flags, payload, len);
	if (rc != 0)
		return rc;

	buf = malloc(IPC_PAYLOAD_MAX + 1u);
	if (!buf)
		return -ENOMEM;

	for (;;) {
		struct ipc_hdr hdr;
		long plen = ipc_client_recv(fd, &hdr, buf, IPC_PAYLOAD_MAX);

		if (plen < 0) {
			free(buf);
			return (int)plen;
		}
		if (hdr.seq != seq) {
			/* Stale datagram from an aborted exchange: ignore. */
			continue;
		}

		if (sink && plen > 0 && (hdr.flags & IPC_F_TEXT))
			(void)sink(sink_arg, (const char *)buf, (size_t)plen);

		final = (int)hdr.status;

		if (!(hdr.flags & IPC_F_MORE))
			break;
	}

	free(buf);
	return final;
}
