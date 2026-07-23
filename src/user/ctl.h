/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/ctl.h
 *
 * The daemon-side of the operator control protocol.  This is the missing half
 * that lets calyctl and calywatch actually talk to the running daemon: they
 * speak newline-delimited JSON over the SOCK_STREAM control socket, and this
 * module parses a request, executes it against the live maps, and writes the
 * single JSON response line the clients expect.
 *
 * WIRE PROTOCOL (must stay byte-compatible with cli/calyctl and
 * watcher/calywatch.py - the CLI header documents it authoritatively):
 *
 *   Request   : {"id": <int>, "cmd": "<name>", "args": {...}}
 *   Response  : {"id": <int>, "ok": true,  "data": {...}}
 *               {"id": <int>, "ok": false, "error": "<text>",
 *                "code": "<machine token>"}
 *   Stream    : {"stream":"events","event":{...}}   (unsolicited, after
 *               a successful "subscribe")
 *
 * Every request is answered with exactly one response line and the request id
 * is echoed.  Unknown commands answer ok=false code="unknown_command", which
 * the CLI treats as "fall back to the direct backend" rather than an error, so
 * the protocol is forward compatible.
 *
 * This module owns ZERO long-lived state: it is a pure function of the request
 * and the environment handed in by main.c.  main.c owns the socket lifecycle
 * and the subscriber list; this module only formats event lines for it.
 */

#ifndef CALY_USER_CTL_H
#define CALY_USER_CTL_H

#include <sys/types.h>
#include <linux/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct caly_maps;
struct caly_bpf;
struct fw_config;
struct caly_link;
struct event;

/*
 * Everything a request handler may touch.  main.c fills this in once (all
 * pointers reference the daemon's own fields) and passes the same env to every
 * dispatch call.  Nothing here is copied or freed by the ctl module.
 */
struct caly_ctl_env {
	struct caly_bpf        *bpf;     /* the loaded object: maps + config   */
	struct fw_config       *cfg;     /* the daemon's authoritative config  */

	__u32                  *base_mode;   /* operator-selected base mode    */
	__u32                  *cur_mode;    /* current (maybe escalated) mode */
	int                    *reload_pending;

	const char             *version;
	__u64                   start_wall_ns;   /* CLOCK_REALTIME at startup  */
	long                    pid;
	__u64                  *events_seen;
	__u64                  *events_lost;

	const struct caly_link *links;
	int                     nlink;

	int                     synproxy_loaded;
	int                     ringbuf_active;
};

/* What the caller should do with the connection after a request line. */
enum caly_ctl_action {
	CALY_CTL_CONTINUE = 0,   /* response written; keep reading the socket */
	CALY_CTL_SUBSCRIBE,      /* client subscribed; caller must adopt the fd
				  * into the event subscriber set (do NOT close) */
	CALY_CTL_CLOSE           /* fatal protocol error; close the connection */
};

/*
 * Execute one request.  `line`/`len` is a single request (a trailing newline,
 * if present, is ignored).  Exactly one response line - terminated by '\n' -
 * is written to `fd`.  The return value tells main.c what to do next.
 */
enum caly_ctl_action caly_ctl_dispatch(const struct caly_ctl_env *env, int fd,
				       const char *line, size_t len);

/*
 * Format one subscribed event as a complete JSON stream line (including the
 * trailing '\n').  Returns the byte length written, or -1 if it would not fit.
 * main.c calls this from its event callback and fans the result out to every
 * subscriber fd.
 */
int caly_ctl_format_event(const struct event *ev, char *buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* CALY_USER_CTL_H */
