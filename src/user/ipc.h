/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/ipc.h
 *
 * SOCK_SEQPACKET unix-domain control socket at /run/calyanti/control.sock.
 * The daemon runs the server side; calyctl is the client. This header is the
 * single authoritative definition of the wire protocol so the two cannot
 * drift apart.
 *
 * WHY SEQPACKET
 *   It preserves message boundaries and connection semantics at once. Every
 *   request is exactly one datagram, so the server never has to reassemble a
 *   stream or guess where a message ends - a class of framing bug simply
 *   cannot occur. Responses may span several datagrams (a conntrack dump does
 *   not fit in one), chained by the IPC_F_MORE flag.
 *
 * SECURITY
 *   The socket is created 0600, root-owned, inside a 0750 /run/calyanti.
 *   Belt and braces, the server ALSO reads SO_PEERCRED on every connection
 *   and refuses any peer whose uid is neither 0 nor cfg->allow_uid. The
 *   payload of every request is treated as hostile: each field is range
 *   checked before a handler ever sees it, exactly as the dataplane checks
 *   every packet field. A control socket that trusts its input is a local
 *   root escalation waiting to happen.
 *
 * BYTE ORDER
 *   Both peers are the same machine and are built from this very header, so
 *   the framing header and the fixed request/response structs are HOST byte
 *   order. IP ADDRESSES inside requests are NETWORK byte order, because they
 *   are copied verbatim into BPF map keys which are defined network order.
 */

#ifndef CALY_USER_IPC_H
#define CALY_USER_IPC_H

#if defined(__CALY_ANTI_COMMON_H) && !defined(CALY_USERSPACE)
#error "common.h included without CALY_USERSPACE; include a src/user/*.h first"
#endif

#ifndef CALY_USERSPACE
#define CALY_USERSPACE 1
#endif

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

/* -------------------------------------------------------------------------
 * Wire protocol
 * ------------------------------------------------------------------------- */

/* The path lives in common.h as CALY_CTL_SOCK (the single source of truth
 * shared with the daemon, calyctl and calywatch). Kept as an alias so existing
 * ipc.c call sites need no change. */
#define CALY_CTRL_SOCK_PATH  CALY_CTL_SOCK

#define IPC_MAGIC            0xCA17A011u   /* "caly ... 011" */
#define IPC_VERSION          1u

/* Largest single datagram either side will send or accept. */
#define IPC_MSG_MAX          65536u
#define IPC_PAYLOAD_MAX      (IPC_MSG_MAX - (__u32)sizeof(struct ipc_hdr))
/* Payload bytes packed into one streamed data frame. */
#define IPC_CHUNK_PAYLOAD    8192u
/* Ceiling on a whole streamed response, so a dump can never exhaust memory. */
#define IPC_RESP_BYTES_MAX   (4u * 1024u * 1024u)

/* Message types. Requests are client->server, responses server->client.
 * Values are frozen: never renumber, append only. */
enum ipc_type {
	IPC_REQ_PING            = 1,
	IPC_REQ_STATUS          = 2,
	IPC_REQ_STATS           = 3,   /* text stream                       */
	IPC_REQ_BAN             = 4,
	IPC_REQ_UNBAN           = 5,
	IPC_REQ_ALLOW_ADD       = 6,
	IPC_REQ_ALLOW_DEL       = 7,
	IPC_REQ_BLOCK_ADD       = 8,
	IPC_REQ_BLOCK_DEL       = 9,
	IPC_REQ_SET_MODE        = 10,
	IPC_REQ_RELOAD          = 11,
	IPC_REQ_DUMP_CONNTRACK  = 12,  /* text stream                       */
	IPC_REQ_DUMP_TOP        = 13,  /* text stream                       */
	IPC_REQ_DUMP_BANS       = 14,  /* text stream                       */
	IPC_REQ_EVENTS_STATS    = 15,  /* binary struct events_stats-ish    */
	IPC_REQ_MAX,

	IPC_RESP_OK             = 0x1000,  /* success, optional payload      */
	IPC_RESP_ERR            = 0x1001,  /* status != 0, message payload   */
	IPC_RESP_DATA           = 0x1002,  /* stream chunk; IPC_F_MORE while
					    * more chunks follow             */
	IPC_RESP_STATUS         = 0x1003,  /* struct ipc_status payload      */
	IPC_RESP_PONG           = 0x1004,
	IPC_RESP_EVENTS_STATS   = 0x1005   /* struct ipc_events_summary      */
};

/* hdr.flags: bits 0..2 are transport flags reserved by the framing layer. */
#define IPC_F_MORE     (1u << 0)   /* another response datagram follows  */
#define IPC_F_TEXT     (1u << 1)   /* payload is human-readable text     */
#define IPC_F_DRYRUN   (1u << 2)   /* request: validate, do not apply    */

/*
 * Dump-request options live in bits 8+ so they never collide with the
 * transport flags above. They are passed through verbatim to the daemon's
 * dump_* handlers, and are also honoured by the IPC layer's own self-served
 * stats dump.
 */
#define IPC_DUMP_F_ZEROS      (1u << 8)   /* include all-zero rows        */
#define IPC_DUMP_F_DROPS_ONLY (1u << 9)   /* drop reasons only           */
#define IPC_DUMP_F_TREND      (1u << 10)  /* append a trend section      */

/* hdr.status: 0 on success, otherwise a positive errno-like code. */
enum ipc_status_code {
	IPC_OK          = 0,
	IPC_EPROTO      = 1,   /* malformed frame / bad magic / version     */
	IPC_EPERM       = 2,   /* peer credential check failed              */
	IPC_EINVAL      = 3,   /* a request field is out of range           */
	IPC_ENOSYS      = 4,   /* no handler registered for this request    */
	IPC_ENOENT      = 5,   /* target not found (unban of an absent ban) */
	IPC_EBUSY       = 6,   /* transient; caller may retry               */
	IPC_EIO         = 7,   /* map update / kernel operation failed      */
	IPC_ENOSPC      = 8,   /* a map was full                            */
	IPC_ETOOBIG     = 9,   /* response exceeded IPC_RESP_BYTES_MAX      */
	IPC_EINTERNAL   = 10
};

/* 24 bytes, naturally aligned, no implicit padding. */
struct ipc_hdr {
	__u32 magic;
	__u16 version;
	__u16 type;        /* enum ipc_type                                 */
	__u32 seq;         /* echoed from request into its responses        */
	__u32 status;      /* enum ipc_status_code (responses)              */
	__u32 flags;       /* IPC_F_*                                       */
	__u32 length;      /* payload bytes following this header           */
};

/* An address + prefix, as it will be turned into an LPM / hash key. 20 B. */
struct ipc_addr {
	__u8 family;       /* CALY_AF_INET / CALY_AF_INET6                  */
	__u8 prefixlen;    /* 0..32 (v4) or 0..128 (v6)                     */
	__u8 pad[2];       /* MUST be zero                                  */
	__u8 addr[16];     /* network byte order; v4 uses the first 4 bytes */
};

struct ipc_ban_req {
	struct ipc_addr addr;
	__u64 ttl_ns;      /* 0 with IPC_BAN_PERMANENT set => never expires */
	__u32 reason;      /* enum stat_reason, informational               */
	__u32 flags;       /* CALY_BAN_F_* (server forces MANUAL)           */
};

struct ipc_rule_req {
	struct ipc_addr addr;
	__u32 flags;       /* CALY_RULE_F_*                                 */
	__u32 tag;         /* free-form operator/feed tag                   */
};

struct ipc_mode_req {
	__u32 mode;        /* enum fw_mode                                  */
	__u32 pad;
};

/*
 * Status reply. Fields split by owner:
 *   - the daemon's status handler fills the policy/identity/map-count block;
 *   - the IPC layer overwrites the telemetry block (pkts.., pps.., ncpu,
 *     events_backend) from the stats/events contexts it was given, so those
 *     numbers are always live even if the handler is cheap.
 */
struct ipc_status {
	/* identity / policy (handler-owned) */
	__u64 abi_version;
	__u64 config_gen;
	__u64 uptime_ns;
	__u64 flags;           /* fw_config.flags snapshot                  */
	__u32 mode;            /* enum fw_mode                              */
	__u32 dataplane;       /* enum caly_dataplane actually attached     */
	__u32 xdp_mode;        /* enum caly_xdp_mode                        */
	__u32 monitor_only;    /* effective monitor-only (0/1)              */

	/* map occupancy (handler-owned; UINT32_MAX means "unknown") */
	__u32 conn_count;
	__u32 conn_max;
	__u32 ban_count;
	__u32 rate_count;
	__u32 scan_count;
	__u32 iface_count;

	/* telemetry (IPC-owned) */
	__u32 ncpu;
	__u32 events_backend;  /* EVENTS_BACKEND_* mirror                   */
	__u64 pkts_total;
	__u64 bytes_total;
	__u64 drops_total;
	__u64 pps;
	__u64 bps;
	__u64 drop_pps;
	__u64 syn_pps;
	__u64 sample_age_ns;

	__u64 reserved[4];
};

/* Compact event-pipeline summary for IPC_REQ_EVENTS_STATS. */
struct ipc_events_summary {
	__u64 received;
	__u64 accepted;
	__u64 invalid;         /* size + version + field, summed            */
	__u64 lost;
	__u64 logged;
	__u64 suppressed;
	__u64 agg_overflow;
	__u64 flushes;
	__u32 backend;
	__u32 agg_live;
};

/* -------------------------------------------------------------------------
 * Server side
 * ------------------------------------------------------------------------- */

/*
 * Line sink handed to the streaming dump handlers. `line` need not be NUL
 * terminated; `len` is authoritative. Returns 0 to continue or non-zero to
 * abort the dump (the IPC layer stops asking for more lines and finalises
 * the response). The handler MUST route every line through this and MUST NOT
 * touch the socket directly.
 */
typedef int (*ipc_line_fn)(void *sink, const char *line, size_t len);

/*
 * Handlers the daemon registers. Any may be NULL, in which case the matching
 * request is answered IPC_ENOSYS (except STATS, which the IPC layer can serve
 * itself from stats_ctx when no dump_stats handler is set).
 *
 * Every handler runs in the daemon's own thread inside a request dispatch,
 * with all arguments already validated. Return 0 on success or a NEGATIVE
 * errno; the IPC layer maps it onto enum ipc_status_code. `user` is
 * ipc_cfg.user.
 */
struct ipc_handlers {
	int (*status)(void *user, struct ipc_status *out);
	int (*ban)(void *user, const struct ipc_ban_req *req);
	int (*unban)(void *user, const struct ipc_addr *addr);
	int (*allow_add)(void *user, const struct ipc_rule_req *req);
	int (*allow_del)(void *user, const struct ipc_addr *addr);
	int (*block_add)(void *user, const struct ipc_rule_req *req);
	int (*block_del)(void *user, const struct ipc_addr *addr);
	int (*set_mode)(void *user, __u32 mode);
	int (*reload)(void *user);

	int (*dump_stats)(void *user, __u32 flags, ipc_line_fn sink,
			  void *sink_arg);
	int (*dump_conntrack)(void *user, __u32 flags, ipc_line_fn sink,
			      void *sink_arg);
	int (*dump_top)(void *user, __u32 flags, ipc_line_fn sink,
			void *sink_arg);
	int (*dump_bans)(void *user, __u32 flags, ipc_line_fn sink,
			 void *sink_arg);
};

#define IPC_MAX_CONNS_DEFAULT   8u
#define IPC_MAX_CONNS_LIMIT    64u
#define IPC_TIMEOUT_MS_DEFAULT 5000u
#define IPC_TIMEOUT_MS_MAX    60000u

struct ipc_cfg {
	const char *path;          /* NULL -> CALY_CTRL_SOCK_PATH           */
	int listen_fd;             /* pre-bound (socket activation); -1 else */
	unsigned int max_conns;    /* 0 -> IPC_MAX_CONNS_DEFAULT            */
	unsigned int timeout_ms;   /* slow-client deadline                  */
	__u32 allow_uid;           /* extra non-root uid permitted; 0 = none */
	int allow_uid_set;         /* honour allow_uid only when set        */

	const struct ipc_handlers *handlers;
	void *user;

	/* Optional read-only contexts the IPC layer may serve directly. */
	struct stats_ctx  *stats;
	struct events_ctx *events;

	caly_log_fn log;
	void *log_user;
};

struct ipc_server_stats {
	__u64 accepted;
	__u64 rejected_cap;
	__u64 rejected_cred;
	__u64 requests;
	__u64 responses_ok;
	__u64 responses_err;
	__u64 bad_frame;
	__u64 timeouts;
	__u64 truncated_out;       /* dumps clipped at IPC_RESP_BYTES_MAX   */
	__u64 bytes_sent;
	__u64 bytes_recv;
	__u32 conns_open;
	__u32 conns_max;
};

struct ipc_ctx;                    /* opaque */

int  ipc_init(struct ipc_ctx **out, const struct ipc_cfg *cfg);
void ipc_free(struct ipc_ctx *ctx);

int  ipc_listen_fd(const struct ipc_ctx *ctx);
int  ipc_pollfd_count(const struct ipc_ctx *ctx);
int  ipc_fill_pollfds(struct ipc_ctx *ctx, struct pollfd *fds, int max);
void ipc_handle_pollfds(struct ipc_ctx *ctx, const struct pollfd *fds, int n);
int  ipc_step(struct ipc_ctx *ctx, int timeout_ms);
void ipc_sweep(struct ipc_ctx *ctx);
int  ipc_next_timeout_ms(const struct ipc_ctx *ctx);

int  ipc_stats_get(const struct ipc_ctx *ctx, struct ipc_server_stats *out);

/* -------------------------------------------------------------------------
 * Client side (used by calyctl; pure protocol, no daemon state)
 * ------------------------------------------------------------------------- */

/*
 * Connect to the control socket. Returns a connected fd (>= 0) or -errno.
 * `path` NULL uses CALY_CTRL_SOCK_PATH. The fd is blocking, which is what a
 * short-lived CLI wants.
 */
int  ipc_client_connect(const char *path);

/*
 * Send one request datagram: header (magic/version/type/seq/flags/length)
 * followed by `payload`. Returns 0 or -errno.
 */
int  ipc_client_send(int fd, __u32 type, __u32 seq, __u32 flags,
		     const void *payload, __u32 len);

/*
 * Receive one response datagram into `buf`. On success writes the parsed
 * header into *hdr and returns the payload length (>= 0); the payload sits at
 * the front of `buf`. Returns -errno on error, -EBADMSG on a malformed or
 * oversized datagram. `*hdr` still carries IPC_F_MORE when more datagrams are
 * expected.
 */
long ipc_client_recv(int fd, struct ipc_hdr *hdr, void *buf, size_t cap);

/*
 * Convenience: send a request and stream every response datagram to `sink`
 * until a datagram without IPC_F_MORE arrives. Text payloads are passed
 * through as-is. Returns the final IPC status code (>= 0, enum
 * ipc_status_code) or -errno on a transport failure.
 */
int  ipc_client_request(int fd, __u32 type, __u32 flags, const void *payload,
			__u32 len, ipc_line_fn sink, void *sink_arg);

/* Parse "1.2.3.4/24" or "2001:db8::/32" (or a bare address, prefix implied
 * full) into an ipc_addr. Returns 0 or -EINVAL. */
int  ipc_addr_parse(const char *text, struct ipc_addr *out);
/* Render an ipc_addr as "addr/prefix". Returns `buf`. */
const char *ipc_addr_str(const struct ipc_addr *a, char *buf, size_t cap);

const char *ipc_status_str(__u32 code);
const char *ipc_type_str(__u32 type);

#ifdef __cplusplus
}
#endif

#endif /* CALY_USER_IPC_H */
