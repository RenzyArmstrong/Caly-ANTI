/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - XDP/eBPF DDoS mitigation suite
 * src/user/config.h - configuration parser for /etc/calyanti/calyanti.conf
 *
 * The parser turns the INI-style configuration file into
 *
 *   - one fully populated `struct fw_config` (copied verbatim into the
 *     caly_config BPF array map), plus
 *   - the list-valued directives that cannot live in a fixed-size struct
 *     (CIDRs, per-port rules, ICMP type policy, interface overrides), which
 *     src/user/maps.c programs into the corresponding BPF maps.
 *
 * Everything here is pure userspace. The ABI itself lives in
 * src/bpf/common.h and is included below; this header never redefines a
 * boundary-crossing type.
 *
 * VALIDATION PHILOSOPHY
 * ---------------------
 * The parser is deliberately hostile. A configuration that could lock the
 * operator out of the machine is REJECTED, and the caller keeps running the
 * previous configuration. Specifically:
 *
 *   - TCP/22 is forced into fw_config.mgmt_tcp_ports[0] in every mode,
 *     including UNDER_ATTACK and LOCKDOWN. It cannot be removed.
 *   - ICMPv4 type 3 and ICMPv6 types 2/133/134/135/136 may never be set to
 *     drop; a config that tries is refused outright.
 *   - When an administrative session is detectable (SSH_CONNECTION, or an
 *     established socket on a management port in /proc/net/tcp{,6}), a
 *     configuration that would drop that peer is refused.
 *   - default_deny without conntrack is refused: it breaks every
 *     outbound-initiated flow on the box.
 *
 * ERROR CONVENTION
 * ----------------
 * Every function returns 0 on success or a NEGATIVE errno on failure, and
 * fills the caller's `err` buffer with a human-readable, file:line qualified
 * message. Non-fatal problems are accumulated as warnings on the config
 * object (see caly_conf_warning_count / caly_conf_warning).
 */

#ifndef CALY_USER_CONFIG_H
#define CALY_USER_CONFIG_H

#include <stddef.h>
#include <stdio.h>
#include <signal.h>
#include <linux/types.h>
#include <net/if.h>

#ifndef CALY_USERSPACE
#define CALY_USERSPACE 1
#endif

#include "../bpf/common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Sizing
 * ------------------------------------------------------------------------- */

#define CALY_CONF_ERRSZ        512u
#define CALY_CONF_WARNSZ       224u
#define CALY_CONF_MAX_WARN     64u
#define CALY_CONF_PATHSZ       4096u
#define CALY_CONF_MAX_ADMIN    16u

/* rule_meta.tag namespaces (CALY_TAG_CONF/AUTO/CLI/ADMIN/FEED_BASE) are the
 * shared contract and now live in src/bpf/common.h, included above, so the
 * daemon, the CLI and the threat-feed loader cannot drift. A reload flushes
 * only CALY_TAG_CONF (and CALY_TAG_AUTO for caly_local*), so threat-feed and
 * CLI entries survive. */

/* -------------------------------------------------------------------------
 * List-valued directives
 * ------------------------------------------------------------------------- */

/* One CIDR, host bits already masked to zero, address in NETWORK byte order
 * exactly as an LPM trie key wants it. */
struct caly_cidr {
	__u8  family;      /* CALY_AF_INET | CALY_AF_INET6                   */
	__u8  prefixlen;   /* 0..32 for v4, 0..128 for v6                    */
	__u8  pad[2];
	__u8  addr[16];    /* network byte order, MSB first, masked          */
	__u32 flags;       /* CALY_RULE_F_*                                  */
	__u32 tag;         /* CALY_TAG_*                                     */
};

/* A closed port interval, used for synproxy_port / amp_exempt / amp_extra. */
struct caly_range {
	__u32 lo;
	__u32 hi;
};

/* One `tcp_port =` / `udp_port =` directive, already expanded to a range. */
struct caly_portspec {
	__u32 lo;
	__u32 hi;
	__u32 proto;       /* CALY_IPPROTO_TCP | CALY_IPPROTO_UDP            */
	__u32 mode;        /* enum caly_port_mode                            */
	__u32 flags;       /* CALY_PORT_F_* the operator asked for           */
	__u32 pad;
	__u64 rate;        /* packets/sec, CALY_PORT_RATELIMIT only          */
	__u64 burst;       /* bucket depth in packets                        */
};

/* One `icmp4_type =` / `icmp6_type =` directive. */
struct caly_icmpspec {
	__u32 family;      /* CALY_AF_INET | CALY_AF_INET6                   */
	__u32 lo;          /* first ICMP type, 0..255                        */
	__u32 hi;          /* last ICMP type, 0..255                         */
	__u32 policy;      /* enum caly_icmp_policy                          */
};

/* One `interface =` directive. */
struct caly_ifspec {
	char  name[IF_NAMESIZE];
	__u32 zone;        /* enum caly_zone                                 */
	__u32 pad;
	__u64 flags;       /* CALY_IF_F_*                                    */
};

/* An administrative peer we detected talking to a management port. Used only
 * to refuse configurations that would cut it off. */
struct caly_admin_peer {
	struct caly_cidr addr;   /* /32 or /128 host route                   */
	__u32 local_port;        /* our side of the connection, host order   */
	__u32 source;            /* CALY_ADMIN_SRC_*                         */
};

#define CALY_ADMIN_SRC_ENV   1u   /* $SSH_CONNECTION / $SSH_CLIENT        */
#define CALY_ADMIN_SRC_PROC  2u   /* established socket in /proc/net/tcp  */

/* -------------------------------------------------------------------------
 * The parsed configuration
 * ------------------------------------------------------------------------- */

struct caly_conf {
	/* Copied verbatim into caly_config. */
	struct fw_config fw;

	/* [allowlist] / [blocklist] / [local] */
	struct caly_cidr     *allow;
	size_t                n_allow, c_allow;
	struct caly_cidr     *block;
	size_t                n_block, c_block;
	struct caly_cidr     *local;
	size_t                n_local, c_local;

	/* [ports] */
	struct caly_portspec *ports;
	size_t                n_ports, c_ports;

	/* [icmp] */
	struct caly_icmpspec *icmp;
	size_t                n_icmp, c_icmp;

	/* [interfaces] */
	struct caly_ifspec   *ifaces;
	size_t                n_ifaces, c_ifaces;

	/* [amplification] */
	struct caly_range    *amp_exempt;
	size_t                n_amp_exempt, c_amp_exempt;
	struct caly_range    *amp_extra;
	size_t                n_amp_extra, c_amp_extra;

	/* [synproxy] */
	struct caly_range    *synproxy_ports;
	size_t                n_synproxy, c_synproxy;

	/* Raw management port lists as written by the operator; finalisation
	 * folds them into fw.mgmt_*_ports with TCP/22 forced into slot 0. */
	__u16                 mgmt_tcp[CALY_MGMT_PORTS_MAX * 2];
	size_t                n_mgmt_tcp;
	__u16                 mgmt_udp[CALY_MGMT_PORTS_MAX * 2];
	size_t                n_mgmt_udp;

	/* Behaviour switches that are not fw_config fields. */
	int                   allow_bypass_rate;  /* allowlist_bypass_ratelimit */
	int                   strict;             /* unknown key => fatal       */
	int                   finalized;

	/* Detected administrative sessions (best effort, may be empty). */
	struct caly_admin_peer admin[CALY_CONF_MAX_ADMIN];
	size_t                 n_admin;

	/* Provenance and diagnostics. */
	char                  path[CALY_CONF_PATHSZ];
	size_t                n_warn;
	char                  warn[CALY_CONF_MAX_WARN][CALY_CONF_WARNSZ];
};

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

/* Allocate a config object pre-loaded with the shipped defaults. NULL on OOM.*/
struct caly_conf *caly_conf_alloc(void);

/* Release everything owned by `c`, including `c` itself. NULL-safe. */
void caly_conf_free(struct caly_conf *c);

/* Reset `c` to the shipped defaults (the same values documented in
 * config/calyanti.conf), discarding every list. */
void caly_conf_set_defaults(struct caly_conf *c);

/* Parse `path` into `c`, appending to whatever lists are already present.
 * Does NOT validate; call caly_conf_finalize() afterwards, or use
 * caly_conf_load() which does both. */
int caly_conf_parse_file(struct caly_conf *c, const char *path,
			 char *err, size_t errsz);

/* Same, from an in-memory buffer. `origin` is used in error messages. */
int caly_conf_parse_string(struct caly_conf *c, const char *text,
			   const char *origin, char *err, size_t errsz);

/* Apply the forced safety invariants, clamp out-of-range knobs, run every
 * lockout check and mark the object usable. Idempotent. */
int caly_conf_finalize(struct caly_conf *c, char *err, size_t errsz);

/* alloc + defaults + parse + finalize. On success *out owns the result. */
int caly_conf_load(const char *path, struct caly_conf **out,
		   char *err, size_t errsz);

/* -------------------------------------------------------------------------
 * Reload
 * -------------------------------------------------------------------------
 * caly_conf_reload() re-reads (*cur)->path, validates it in full and, only if
 * it is safe, pushes it into the BPF maps and swaps *cur. On ANY failure the
 * previous configuration stays installed and *cur is untouched: a typo in the
 * config file can never disarm or wedge a running dataplane.
 */

struct caly_maps;   /* src/user/maps.h */

int caly_conf_reload(struct caly_maps *maps, struct caly_conf **cur,
		     char *err, size_t errsz);

/* SIGHUP plumbing. The handler only sets a flag; the daemon calls
 * caly_conf_reload_pending_take() from its main loop. */
extern volatile sig_atomic_t caly_reload_pending;

int caly_conf_install_sighup(void);
int caly_conf_reload_pending_take(void);   /* test-and-clear, returns 0/1 */

/* -------------------------------------------------------------------------
 * Value parsers (exported: the CLI accepts the same syntax)
 * -------------------------------------------------------------------------
 *   bool      yes/no/true/false/on/off/1/0/enable(d)/disable(d)
 *   duration  <int>[ns|us|ms|s|m|h|d]; bare integer == SECONDS; -> ns
 *   rate      <int>[k|m|g][pps|bps]; k/m/g are 1e3/1e6/1e9; byte rates are
 *             BYTES per second, never bits
 *   size      <int>[k|m|g|ki|mi|gi][b]; k/m/g decimal, ki/mi/gi binary
 *   cidr      a.b.c.d[/len] or v6[/len]; bare address implies /32 or /128
 * ------------------------------------------------------------------------- */

int caly_parse_bool(const char *s, int *out);
int caly_parse_duration_ns(const char *s, __u64 *out);
int caly_parse_rate(const char *s, __u64 *out);
int caly_parse_size(const char *s, __u64 *out);
int caly_parse_cidr(const char *s, struct caly_cidr *out);
int caly_parse_port_range(const char *s, __u32 *lo, __u32 *hi);
int caly_parse_fw_mode(const char *s, __u32 *out);
int caly_parse_zone(const char *s, __u32 *out);
int caly_parse_dataplane(const char *s, __u32 *out);
int caly_parse_xdp_mode(const char *s, __u32 *out);
int caly_parse_port_mode(const char *s, __u32 *out);
int caly_parse_icmp_policy(const char *s, __u32 *out);

/* Render a CIDR as "a.b.c.d/len" / "v6/len". Returns buf. */
const char *caly_cidr_str(const struct caly_cidr *c, char *buf, size_t sz);

/* Longest-prefix containment test: does network `net` cover host `h`? */
int caly_cidr_contains(const struct caly_cidr *net, const struct caly_cidr *h);

/* Build a /32 or /128 host CIDR from raw network-order address bytes. */
void caly_cidr_from_addr(struct caly_cidr *out, __u8 family, const __u8 *addr);

/* -------------------------------------------------------------------------
 * Diagnostics
 * ------------------------------------------------------------------------- */

size_t      caly_conf_warning_count(const struct caly_conf *c);
const char *caly_conf_warning(const struct caly_conf *c, size_t i);
void        caly_conf_print(const struct caly_conf *c, FILE *f);

/* Best-effort detection of administrative peers. `ports` is the management
 * TCP port list (host order); an established inbound connection to one of
 * them, or $SSH_CONNECTION, identifies a session we must not cut off.
 * Never fails hard: an unreadable /proc simply yields zero peers. */
int caly_detect_admin_peers(const __u16 *ports, size_t nports,
			    struct caly_admin_peer *out, size_t max,
			    size_t *n);

#ifdef __cplusplus
}
#endif

#endif /* CALY_USER_CONFIG_H */
