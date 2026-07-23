/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/main.c
 *
 * The daemon entry point: argument parsing, privilege and RLIMIT_MEMLOCK
 * handling, configuration file parsing, load/seed/attach orchestration,
 * signal handling (via signalfd, so no work happens in async-signal context),
 * a small line-oriented control socket, and the single-threaded event loop
 * that drains the event buffer, samples the gauges to drive mode escalation,
 * and sweeps the LRU maps.
 *
 * All libbpf contact is behind loader.h; this file includes no BPF headers.
 *
 * ON CONFIGURATION PARSING
 * ------------------------
 * The scalar knobs are parsed straight into struct fw_config; the list-valued
 * directives (allow/block/local prefixes, per-port rules, per-type ICMP
 * policy, interfaces, amplifier exemptions, syn-proxy ports) are buffered and
 * applied to the maps after load, because the map sizes (max_*_entries) must
 * be known before the maps are created.  Every parser is file-static so this
 * translation unit cannot collide with any other component's symbols.
 *
 * THE ONE INVARIANT THAT OUTRANKS EVERYTHING
 * ------------------------------------------
 * caly_config_sanitize() forces TCP/22 into the management list and refuses a
 * configuration that cannot keep SSH reachable.  A reload that fails sanitise
 * keeps the previous configuration running.  Locking the operator out of a
 * machine that is under attack is worse than the attack.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "loader.h"
#include "log.h"
#include "util.h"
#include "ctl.h"

/* Maximum live "subscribe" connections streaming events at once. Bounded so a
 * flood of subscribers cannot exhaust descriptors; the control socket is
 * root-only, so this is belt-and-braces rather than a real threat surface. */
#define CALY_CTL_MAX_SUBS  32

/* struct caly_daemon is defined further down; the two forward declarations
 * below reference it by pointer, so it must be an announced (incomplete) tag
 * before them or the parameter type binds to the wrong scope. */
struct caly_daemon;

/* Defined with the control-socket code below; caly_on_event() (above it) needs
 * to be able to evict a subscriber whose socket has died mid-write. */
static void caly_ctl_subscribe_remove(struct caly_daemon *d, int fd);

/* Defined further down with the event loop, but the control-socket subscriber
 * code (above its definition) registers fds through it. */
static int caly_epoll_add(int epfd, int fd, __u32 events);

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/un.h>

/* XDP attach-mode bits, for interpreting caly_xdp_iface_status() in --status.
 * Stable UAPI; spelled locally to avoid the <linux/if_link.h> vs <net/if.h>
 * collision on musl. */
#define CALY_XDPF_SKB  (1U << 1)
#define CALY_XDPF_DRV  (1U << 2)
#define CALY_XDPF_HW   (1U << 3)

/* ================================================================== *
 * State
 * ================================================================== */

struct caly_iface_spec {
	char  name[IF_NAMESIZE];
	__u32 zone;         /* enum caly_zone */
	__u64 flags;        /* CALY_IF_F_* */
	int   have_zone;
	int   attach;       /* attach the XDP program here */
};

struct caly_pending_cidr {
	struct caly_cidr cidr;
	int   map_id;       /* CALY_MID_ALLOW4 ... resolved at apply time */
	__u32 flags;        /* CALY_RULE_F_* */
	__u32 tag;
};

struct caly_pending_port {
	int   is_udp;
	__u32 lo, hi;
	__u32 mode;         /* enum caly_port_mode, or 0xFFFFFFFF = keep */
	__u64 rate, burst;
	__u32 set_flags;    /* CALY_PORT_F_* to OR in */
	__u32 clr_flags;    /* CALY_PORT_F_* to clear */
};

struct caly_pending_icmp {
	__u32 family;
	__u32 type;
	__u32 policy;
};

struct caly_vec {
	void  *data;
	int    count;
	int    cap;
	size_t elemsz;
};

struct caly_daemon {
	struct fw_config cfg;
	struct caly_bpf  bpf;

	char config_path[PATH_MAX_SAFE];
	char obj_path[PATH_MAX_SAFE];
	char pin_dir[PATH_MAX_SAFE];
	char pidfile[PATH_MAX_SAFE];
	char ctl_path[PATH_MAX_SAFE];

	struct caly_iface_spec ifaces[CALY_MAX_IFACES];
	int   niface;

	struct caly_link links[CALY_MAX_IFACES];
	int   nlink;

	struct caly_vec cidrs;   /* struct caly_pending_cidr */
	struct caly_vec ports;   /* struct caly_pending_port */
	struct caly_vec icmps;   /* struct caly_pending_icmp */

	int allow_bypass_rate;   /* allowlist_bypass_ratelimit */

	/* runtime options */
	int foreground;
	int dry_run;
	int force;
	int use_syslog;
	int log_level_cli;       /* -1 when unset */
	int mode_cli;            /* -1 when unset */

	/* descriptors */
	int pidfd;
	int ctl_fd;
	int sigfd;
	int timerfd;
	int epfd;
	int notify_fd;           /* daemonize readiness pipe, -1 when none */

	struct caly_event_src *events;

	/* escalation / periodic work */
	__u64 prev_gauges[CALY_G_MAX];
	__u64 prev_sample_ns;
	__u64 last_stats_ns;
	__u64 last_gc_ns;
	__u64 last_hi_ns;
	__u32 base_mode;
	__u32 cur_mode;
	int   have_prev_sample;

	__u64 events_seen;
	__u64 events_lost;

	/* control-socket JSON plane (see ctl.c) */
	int   sub_fds[CALY_CTL_MAX_SUBS];  /* live event subscribers          */
	int   nsub;
	__u64 start_wall_ns;          /* CLOCK_REALTIME at startup, for uptime */

	volatile sig_atomic_t stop;
	int reload_pending;
};

static struct caly_daemon g_daemon;

/* ================================================================== *
 * Tiny growable vector (checked, never an unchecked malloc)
 * ================================================================== */

static void caly_vec_init(struct caly_vec *v, size_t elemsz)
{
	v->data = NULL;
	v->count = 0;
	v->cap = 0;
	v->elemsz = elemsz;
}

static int caly_vec_push(struct caly_vec *v, const void *elem)
{
	if (v->count == v->cap) {
		int ncap = v->cap ? v->cap * 2 : 16;
		void *nd;

		if (ncap > 1 << 20) {           /* runaway guard */
			errno = ENOSPC;
			return -1;
		}
		nd = realloc(v->data, (size_t)ncap * v->elemsz);
		if (nd == NULL)
			return -1;
		v->data = nd;
		v->cap = ncap;
	}
	memcpy((char *)v->data + (size_t)v->count * v->elemsz, elem,
	       v->elemsz);
	v->count++;
	return 0;
}

static void caly_vec_free(struct caly_vec *v)
{
	free(v->data);
	v->data = NULL;
	v->count = 0;
	v->cap = 0;
}

/* ================================================================== *
 * Interface list management
 * ================================================================== */

static struct caly_iface_spec *caly_iface_find(struct caly_daemon *d,
					       const char *name)
{
	int i;

	for (i = 0; i < d->niface; i++) {
		if (caly_streq(d->ifaces[i].name, name))
			return &d->ifaces[i];
	}
	return NULL;
}

static struct caly_iface_spec *caly_iface_add(struct caly_daemon *d,
					      const char *name)
{
	struct caly_iface_spec *s = caly_iface_find(d, name);

	if (s != NULL)
		return s;
	if (d->niface >= CALY_MAX_IFACES) {
		caly_err("too many interfaces (max %d)", CALY_MAX_IFACES);
		return NULL;
	}
	s = &d->ifaces[d->niface++];
	memset(s, 0, sizeof(*s));
	if (caly_strlcpy(s->name, name, sizeof(s->name)) >= sizeof(s->name)) {
		caly_err("interface name '%s' is too long", name);
		d->niface--;
		return NULL;
	}
	s->zone = CALY_ZONE_UNSPEC;
	s->attach = 1;
	return s;
}

/* ================================================================== *
 * Configuration parsing
 * ================================================================== */

static int caly_cfg_bool(struct caly_daemon *d, const char *val, __u64 bit,
			 int lineno)
{
	int b;

	if (caly_parse_bool(val, &b) != 0) {
		caly_err("config line %d: '%s' is not a boolean", lineno, val);
		return -1;
	}
	if (b)
		d->cfg.flags |= bit;
	else
		d->cfg.flags &= ~bit;
	return 0;
}

static int caly_cfg_u32(const char *val, __u32 *out, int lineno,
			const char *key)
{
	if (caly_parse_u32(val, out) != 0) {
		caly_err("config line %d: %s expects an integer, got '%s'",
			 lineno, key, val);
		return -1;
	}
	return 0;
}

static int caly_cfg_dur_ns(const char *val, __u64 *out, int lineno,
			   const char *key)
{
	if (caly_parse_duration_ns(val, out) != 0) {
		caly_err("config line %d: %s expects a duration, got '%s'",
			 lineno, key, val);
		return -1;
	}
	return 0;
}

static int caly_cfg_dur_ms(const char *val, __u32 *out, int lineno,
			   const char *key)
{
	__u64 ns;

	if (caly_parse_duration_ns(val, &ns) != 0) {
		caly_err("config line %d: %s expects a duration, got '%s'",
			 lineno, key, val);
		return -1;
	}
	ns /= CALY_NSEC_PER_MSEC;
	if (ns > 0xFFFFFFFFULL)
		ns = 0xFFFFFFFFULL;
	*out = (__u32)ns;
	return 0;
}

static int caly_cfg_rate(const char *val, __u64 *out, int lineno,
			 const char *key)
{
	if (caly_parse_rate(val, out) != 0) {
		caly_err("config line %d: %s expects a rate, got '%s'",
			 lineno, key, val);
		return -1;
	}
	return 0;
}

static __u32 caly_zone_from_str(const char *s)
{
	if (caly_strcaseeq(s, "wan"))
		return CALY_ZONE_WAN;
	if (caly_strcaseeq(s, "lan"))
		return CALY_ZONE_LAN;
	if (caly_strcaseeq(s, "dmz"))
		return CALY_ZONE_DMZ;
	return CALY_ZONE_UNSPEC;
}

static int caly_mode_from_str(const char *s, __u32 *out)
{
	if (caly_strcaseeq(s, "normal"))
		*out = FW_MODE_NORMAL;
	else if (caly_strcaseeq(s, "elevated"))
		*out = FW_MODE_ELEVATED;
	else if (caly_strcaseeq(s, "under-attack") ||
		 caly_strcaseeq(s, "under_attack") ||
		 caly_strcaseeq(s, "attack"))
		*out = FW_MODE_UNDER_ATTACK;
	else if (caly_strcaseeq(s, "lockdown"))
		*out = FW_MODE_LOCKDOWN;
	else if (caly_strcaseeq(s, "monitor-only") ||
		 caly_strcaseeq(s, "monitor_only") ||
		 caly_strcaseeq(s, "monitor"))
		*out = FW_MODE_MONITOR_ONLY;
	else
		return -1;
	return 0;
}

static __u32 caly_dataplane_from_str(const char *s)
{
	if (caly_strcaseeq(s, "auto"))
		return CALY_DP_AUTO;
	if (caly_strcaseeq(s, "xdp-native") || caly_strcaseeq(s, "native"))
		return CALY_DP_XDP_NATIVE;
	if (caly_strcaseeq(s, "xdp-generic") || caly_strcaseeq(s, "generic"))
		return CALY_DP_XDP_GENERIC;
	if (caly_strcaseeq(s, "tc-bpf") || caly_strcaseeq(s, "tc"))
		return CALY_DP_TC;
	if (caly_strcaseeq(s, "nftables") || caly_strcaseeq(s, "nft"))
		return CALY_DP_NFTABLES;
	if (caly_strcaseeq(s, "iptables"))
		return CALY_DP_IPTABLES;
	return CALY_DP_AUTO;
}

static __u32 caly_xdpmode_from_str(const char *s)
{
	if (caly_strcaseeq(s, "auto"))
		return CALY_XDP_AUTO;
	if (caly_strcaseeq(s, "native"))
		return CALY_XDP_NATIVE;
	if (caly_strcaseeq(s, "generic"))
		return CALY_XDP_GENERIC;
	if (caly_strcaseeq(s, "offload"))
		return CALY_XDP_OFFLOAD;
	return CALY_XDP_AUTO;
}

/* Add a CIDR (or comma/space separated list of them) to a pending trie. */
static int caly_cfg_add_cidrs(struct caly_daemon *d, char *val, int map4,
			      int map6, __u32 flags, int lineno)
{
	char *tok[64];
	int n, i;

	n = caly_str_split(val, ", \t", tok, 64);
	for (i = 0; i < n; i++) {
		struct caly_pending_cidr pc;

		memset(&pc, 0, sizeof(pc));
		if (caly_parse_cidr(tok[i], &pc.cidr) != 0) {
			caly_err("config line %d: '%s' is not a valid CIDR",
				 lineno, tok[i]);
			return -1;
		}
		pc.map_id = (pc.cidr.family == CALY_AF_INET6) ? map6 : map4;
		pc.flags = flags;
		pc.tag = 0;
		if (caly_vec_push(&d->cidrs, &pc) != 0) {
			caly_err("out of memory buffering prefix '%s'",
				 tok[i]);
			return -1;
		}
	}
	return 0;
}

/* Add a comma/space separated list of ports as a pending port directive that
 * only sets/clears flags (used by amp_exempt, amp_extra, synproxy_port). */
static int caly_cfg_flag_ports(struct caly_daemon *d, char *val, int is_udp,
			       __u32 set_flags, __u32 clr_flags, int lineno)
{
	char *tok[128];
	int n, i;

	n = caly_str_split(val, ", \t", tok, 128);
	for (i = 0; i < n; i++) {
		struct caly_pending_port pp;
		__u32 lo, hi;

		if (caly_parse_port_range(tok[i], &lo, &hi) != 0) {
			caly_err("config line %d: '%s' is not a valid port or "
				 "range", lineno, tok[i]);
			return -1;
		}
		memset(&pp, 0, sizeof(pp));
		pp.is_udp = is_udp;
		pp.lo = lo;
		pp.hi = hi;
		pp.mode = 0xFFFFFFFFu;   /* keep the existing mode */
		pp.set_flags = set_flags;
		pp.clr_flags = clr_flags;
		if (caly_vec_push(&d->ports, &pp) != 0) {
			caly_err("out of memory buffering port '%s'", tok[i]);
			return -1;
		}
	}
	return 0;
}

/* "22 open", "80 ratelimit 10k 20k", "1000-2000 closed" */
static int caly_cfg_port_rule(struct caly_daemon *d, int is_udp, char *val,
			      int lineno)
{
	char *tok[8];
	struct caly_pending_port pp;
	int n;

	n = caly_str_split(val, " \t", tok, 8);
	if (n < 2) {
		caly_err("config line %d: %s_port needs '<port> "
			 "<open|closed|ratelimit>'", lineno,
			 is_udp ? "udp" : "tcp");
		return -1;
	}

	memset(&pp, 0, sizeof(pp));
	pp.is_udp = is_udp;
	if (caly_parse_port_range(tok[0], &pp.lo, &pp.hi) != 0) {
		caly_err("config line %d: '%s' is not a valid port or range",
			 lineno, tok[0]);
		return -1;
	}

	if (caly_strcaseeq(tok[1], "open")) {
		pp.mode = CALY_PORT_OPEN;
	} else if (caly_strcaseeq(tok[1], "closed") ||
		   caly_strcaseeq(tok[1], "close")) {
		pp.mode = CALY_PORT_CLOSED;
	} else if (caly_strcaseeq(tok[1], "ratelimit") ||
		   caly_strcaseeq(tok[1], "rate")) {
		pp.mode = CALY_PORT_RATELIMIT;
		if (n >= 3 && caly_parse_rate(tok[2], &pp.rate) != 0) {
			caly_err("config line %d: '%s' is not a valid rate",
				 lineno, tok[2]);
			return -1;
		}
		if (n >= 4 && caly_parse_rate(tok[3], &pp.burst) != 0) {
			caly_err("config line %d: '%s' is not a valid burst",
				 lineno, tok[3]);
			return -1;
		}
		if (pp.burst == 0)
			pp.burst = pp.rate * 2;
	} else {
		caly_err("config line %d: unknown port mode '%s'", lineno,
			 tok[1]);
		return -1;
	}

	if (caly_vec_push(&d->ports, &pp) != 0) {
		caly_err("out of memory buffering a port rule");
		return -1;
	}
	return 0;
}

static int caly_cfg_icmp_rule(struct caly_daemon *d, __u32 family, char *val,
			      int lineno)
{
	char *tok[4];
	struct caly_pending_icmp pi;
	__u32 type;
	int n;

	n = caly_str_split(val, " \t", tok, 4);
	if (n < 2) {
		caly_err("config line %d: icmp type needs '<type> "
			 "<drop|pass|ratelimit>'", lineno);
		return -1;
	}
	if (caly_parse_u32(tok[0], &type) != 0 || type > 255) {
		caly_err("config line %d: '%s' is not a valid ICMP type",
			 lineno, tok[0]);
		return -1;
	}

	memset(&pi, 0, sizeof(pi));
	pi.family = family;
	pi.type = type;
	if (caly_strcaseeq(tok[1], "drop"))
		pi.policy = CALY_ICMP_DROP;
	else if (caly_strcaseeq(tok[1], "pass"))
		pi.policy = CALY_ICMP_PASS;
	else if (caly_strcaseeq(tok[1], "ratelimit") ||
		 caly_strcaseeq(tok[1], "rate"))
		pi.policy = CALY_ICMP_RATELIMIT;
	else {
		caly_err("config line %d: unknown ICMP policy '%s'", lineno,
			 tok[1]);
		return -1;
	}

	/* Refuse a mandatory-type drop at parse time so the operator sees the
	 * line number, not just a runtime rejection. */
	if (pi.policy == CALY_ICMP_DROP &&
	    caly_icmp_type_is_mandatory(family, type)) {
		caly_err("config line %d: ICMPv%u type %u may never be "
			 "dropped; it is mandatory for connectivity",
			 lineno, family == CALY_AF_INET6 ? 6u : 4u, type);
		return -1;
	}

	if (caly_vec_push(&d->icmps, &pi) != 0) {
		caly_err("out of memory buffering an ICMP rule");
		return -1;
	}
	return 0;
}

static int caly_cfg_mgmt_ports(struct caly_daemon *d, char *val, int is_udp,
			       int lineno)
{
	char *tok[CALY_MGMT_PORTS_MAX + 8];
	__u16 *arr = is_udp ? d->cfg.mgmt_udp_ports : d->cfg.mgmt_tcp_ports;
	__u32 *cnt = is_udp ? &d->cfg.mgmt_udp_count : &d->cfg.mgmt_tcp_count;
	int n, i;

	n = caly_str_split(val, ", \t", tok, CALY_MGMT_PORTS_MAX + 8);

	*cnt = 0;
	memset(arr, 0, sizeof(__u16) * CALY_MGMT_PORTS_MAX);

	for (i = 0; i < n; i++) {
		__u16 p;

		if (*cnt >= CALY_MGMT_PORTS_MAX) {
			caly_warn("config line %d: more than %u management "
				  "ports; ignoring the rest", lineno,
				  CALY_MGMT_PORTS_MAX);
			break;
		}
		if (caly_parse_u16(tok[i], &p) != 0 || p == 0) {
			caly_err("config line %d: '%s' is not a valid port",
				 lineno, tok[i]);
			return -1;
		}
		arr[(*cnt)++] = p;
	}
	/* TCP/22 enforcement happens in caly_config_sanitize(). */
	return 0;
}

static int caly_cfg_interface(struct caly_daemon *d, char *val, int lineno)
{
	char *tok[8];
	struct caly_iface_spec *s;
	int n, i;

	n = caly_str_split(val, " \t", tok, 8);
	if (n < 1) {
		caly_err("config line %d: interface needs a name", lineno);
		return -1;
	}

	s = caly_iface_add(d, tok[0]);
	if (s == NULL)
		return -1;

	for (i = 1; i < n; i++) {
		if (caly_str_startswith(tok[i], "zone=")) {
			s->zone = caly_zone_from_str(tok[i] + 5);
			s->have_zone = 1;
			if (s->zone == CALY_ZONE_WAN)
				s->flags |= CALY_IF_F_WAN;
		} else if (caly_streq(tok[i], "monitor")) {
			s->flags |= CALY_IF_F_MONITOR;
		} else if (caly_streq(tok[i], "disabled")) {
			s->flags |= CALY_IF_F_DISABLED;
		} else if (caly_streq(tok[i], "drop-private")) {
			s->flags |= CALY_IF_F_DROP_PRIVATE;
		} else if (caly_streq(tok[i], "no-ipv6")) {
			s->flags |= CALY_IF_F_NO_IPV6;
		} else if (caly_streq(tok[i], "trust-vlan")) {
			s->flags |= CALY_IF_F_TRUST_VLAN;
		} else {
			caly_warn("config line %d: unknown interface flag "
				  "'%s'", lineno, tok[i]);
		}
	}
	return 0;
}

/*
 * Apply one key = value pair.  Returns 0 on success, -1 on a hard error.
 * Unknown keys are warned about but not fatal, so a config written for a newer
 * minor ABI still starts on an older daemon.
 */
static int caly_cfg_apply(struct caly_daemon *d, const char *key, char *val,
			  int lineno)
{
	struct fw_config *c = &d->cfg;

#define KBOOL(k, bit) \
	if (caly_streq(key, (k))) return caly_cfg_bool(d, val, (bit), lineno)
#define KU32(k, field) \
	if (caly_streq(key, (k))) return caly_cfg_u32(val, &c->field, \
						      lineno, (k))
#define KDUR_NS(k, field) \
	if (caly_streq(key, (k))) return caly_cfg_dur_ns(val, &c->field, \
							 lineno, (k))
#define KDUR_MS(k, field) \
	if (caly_streq(key, (k))) return caly_cfg_dur_ms(val, &c->field, \
							 lineno, (k))
#define KRATE(k, field) \
	if (caly_streq(key, (k))) return caly_cfg_rate(val, &c->field, \
						       lineno, (k))

	/* [general] */
	KBOOL("enabled", CALY_F_ENABLED);
	KBOOL("monitor_only", CALY_F_MONITOR_ONLY);
	if (caly_streq(key, "mode")) {
		if (caly_mode_from_str(val, &c->mode) != 0) {
			caly_err("config line %d: unknown mode '%s'", lineno,
				 val);
			return -1;
		}
		return 0;
	}
	KBOOL("ipv4", CALY_F_IPV4);
	KBOOL("ipv6", CALY_F_IPV6);
	if (caly_streq(key, "log_level")) {
		int lv = caly_log_level_from_string(val);

		if (lv < 0) {
			caly_err("config line %d: bad log_level '%s'", lineno,
				 val);
			return -1;
		}
		c->log_level = (__u32)lv;
		return 0;
	}
	KDUR_MS("poll_interval", poll_interval_ms);
	KDUR_MS("stats_interval", stats_interval_ms);
	KDUR_MS("gc_interval", gc_interval_ms);
	KU32("gc_batch", gc_batch);

	/* [dataplane] */
	if (caly_streq(key, "dataplane")) {
		c->dataplane_pref = caly_dataplane_from_str(val);
		return 0;
	}
	if (caly_streq(key, "xdp_mode")) {
		c->xdp_attach_pref = caly_xdpmode_from_str(val);
		return 0;
	}
	KU32("event_pages", event_pages);

	/* [interfaces] */
	if (caly_streq(key, "interface"))
		return caly_cfg_interface(d, val, lineno);
	if (caly_streq(key, "default_zone")) {
		c->default_zone = caly_zone_from_str(val);
		return 0;
	}

	/* [management] */
	if (caly_streq(key, "mgmt_tcp_ports"))
		return caly_cfg_mgmt_ports(d, val, 0, lineno);
	if (caly_streq(key, "mgmt_udp_ports"))
		return caly_cfg_mgmt_ports(d, val, 1, lineno);
	KBOOL("mgmt_bypass_ratelimit", CALY_F_MGMT_BYPASS_ALL);

	/* [allowlist] */
	if (caly_streq(key, "allow")) {
		__u32 f = CALY_RULE_F_ALLOW;

		if (d->allow_bypass_rate)
			f |= CALY_RULE_F_BYPASS_RATE;
		return caly_cfg_add_cidrs(d, val, CALY_MID_ALLOW4,
					  CALY_MID_ALLOW6, f, lineno);
	}
	if (caly_streq(key, "allowlist_bypass_ratelimit")) {
		int b;

		if (caly_parse_bool(val, &b) != 0)
			return -1;
		d->allow_bypass_rate = b;
		return 0;
	}
	KBOOL("allowlist_enabled", CALY_F_ALLOWLIST);
	if (caly_streq(key, "local"))
		return caly_cfg_add_cidrs(d, val, CALY_MID_LOCAL4,
					  CALY_MID_LOCAL6, CALY_RULE_F_LOCAL,
					  lineno);

	/* [blocklist] */
	if (caly_streq(key, "block"))
		return caly_cfg_add_cidrs(d, val, CALY_MID_BLOCK4,
					  CALY_MID_BLOCK6, CALY_RULE_F_BLOCK,
					  lineno);
	KBOOL("blocklist_enabled", CALY_F_BLOCKLIST);

	/* [anomaly] */
	KBOOL("anomaly_checks", CALY_F_ANOMALY_CHECKS);
	KBOOL("land_check", CALY_F_LAND_CHECK);
	KBOOL("bogon_filter", CALY_F_BOGON_FILTER);
	KBOOL("wan_drop_private", CALY_F_WAN_DROP_PRIVATE);
	KBOOL("tcp_flag_checks", CALY_F_TCP_FLAG_CHECKS);
	KBOOL("frag_checks", CALY_F_FRAG_CHECKS);
	if (caly_streq(key, "frag_min_size")) {
		__u64 v;

		if (caly_parse_size(val, &v) != 0) {
			caly_err("config line %d: bad frag_min_size '%s'",
				 lineno, val);
			return -1;
		}
		c->frag_min_bytes = (v > 0xFFFFFFFFULL) ? 0xFFFFFFFFu
							: (__u32)v;
		return 0;
	}
	KBOOL("drop_all_fragments", CALY_F_DROP_ALL_FRAGS);
	KBOOL("drop_ip4_options", CALY_F_DROP_IP4_OPTIONS);
	KBOOL("drop_ipv6_rh0", CALY_F_DROP_RH0);
	if (caly_streq(key, "min_ttl")) {
		if (caly_cfg_u32(val, &c->ip_min_ttl, lineno, "min_ttl") != 0)
			return -1;
		if (c->ip_min_ttl > 0)
			c->flags |= CALY_F_TTL_CHECK;
		else
			c->flags &= ~CALY_F_TTL_CHECK;
		return 0;
	}
	KBOOL("drop_unknown_ethertype", CALY_F_DROP_UNKNOWN_L3);
	KU32("vlan_max_depth", vlan_max_depth);
	KU32("ipv6_ext_max", ip6_ext_max);
	KU32("tunnel_max_depth", tunnel_max_depth);
	KBOOL("vlan_inspect", CALY_F_VLAN_INSPECT);
	KBOOL("tunnel_inspect", CALY_F_TUNNEL_INSPECT);
	KU32("tcp_min_doff", tcp_min_doff);

	/* [icmp] */
	KBOOL("icmp_filter", CALY_F_ICMP_FILTER);
	KU32("icmp_max_payload", icmp_max_payload);
	KU32("icmp6_max_payload", icmp6_max_payload);
	if (caly_streq(key, "icmp4_type"))
		return caly_cfg_icmp_rule(d, CALY_AF_INET, val, lineno);
	if (caly_streq(key, "icmp6_type"))
		return caly_cfg_icmp_rule(d, CALY_AF_INET6, val, lineno);

	/* [ratelimit] */
	KBOOL("ratelimit_enabled", CALY_F_RATE_LIMIT);
	KRATE("rate_pps", tb_rate[CALY_TB_PPS]);
	KRATE("rate_pps_burst", tb_burst[CALY_TB_PPS]);
	KRATE("rate_bps", tb_rate[CALY_TB_BPS]);
	KRATE("rate_bps_burst", tb_burst[CALY_TB_BPS]);
	KRATE("rate_syn", tb_rate[CALY_TB_SYN]);
	KRATE("rate_syn_burst", tb_burst[CALY_TB_SYN]);
	KRATE("rate_udp", tb_rate[CALY_TB_UDP]);
	KRATE("rate_udp_burst", tb_burst[CALY_TB_UDP]);
	KRATE("rate_icmp", tb_rate[CALY_TB_ICMP]);
	KRATE("rate_icmp_burst", tb_burst[CALY_TB_ICMP]);
	KRATE("rate_newconn", tb_rate[CALY_TB_NEWCONN]);
	KRATE("rate_newconn_burst", tb_burst[CALY_TB_NEWCONN]);
	KU32("max_rate_entries", max_rate_entries);
	KDUR_NS("rate_idle_timeout", rate_idle_ns);

	/* [autoban] */
	KBOOL("autoban", CALY_F_AUTOBAN);
	KU32("strike_limit", strike_limit);
	KDUR_NS("strike_window", strike_window_ns);
	KDUR_NS("ban_ttl_base", ban_ttl_base_ns);
	KDUR_NS("ban_ttl_max", ban_ttl_max_ns);
	KU32("ban_escalate_num", ban_escalate_num);
	KU32("ban_escalate_den", ban_escalate_den);
	KDUR_NS("ban_ttl_scan", ban_ttl_scan_ns);
	KDUR_NS("ban_ttl_amp", ban_ttl_amp_ns);
	KU32("max_ban_entries", max_ban_entries);
	KU32("max_block_entries", max_block_entries);
	KU32("max_allow_entries", max_allow_entries);
	KU32("max_iface_entries", max_iface_entries);

	/* [amplification] */
	KBOOL("anti_amplification", CALY_F_ANTI_AMPLIFY);
	if (caly_streq(key, "amp_exempt"))
		return caly_cfg_flag_ports(d, val, 1, 0,
					   CALY_PORT_F_AMPLIFIER, lineno);
	if (caly_streq(key, "amp_extra"))
		return caly_cfg_flag_ports(d, val, 1, CALY_PORT_F_AMPLIFIER,
					   0, lineno);

	/* [ports] */
	KBOOL("default_deny", CALY_F_DEFAULT_DENY);
	KBOOL("port_policy", CALY_F_PORT_POLICY);
	if (caly_streq(key, "tcp_port"))
		return caly_cfg_port_rule(d, 0, val, lineno);
	if (caly_streq(key, "udp_port"))
		return caly_cfg_port_rule(d, 1, val, lineno);

	/* [conntrack] */
	KBOOL("conntrack", CALY_F_CONNTRACK);
	KDUR_NS("ct_tcp_syn", ct_tcp_syn_ns);
	KDUR_NS("ct_tcp_established", ct_tcp_est_ns);
	KDUR_NS("ct_tcp_fin", ct_tcp_fin_ns);
	KDUR_NS("ct_udp", ct_udp_ns);
	KDUR_NS("ct_udp_stream", ct_udp_stream_ns);
	KDUR_NS("ct_icmp", ct_icmp_ns);
	KDUR_NS("ct_generic", ct_generic_ns);
	KU32("max_conn_entries", max_conn_entries);

	/* [portscan] */
	KBOOL("portscan_detect", CALY_F_PORTSCAN_DETECT);
	KU32("scan_port_threshold", scan_port_threshold);
	KDUR_NS("scan_window", scan_window_ns);
	KU32("max_scan_entries", max_scan_entries);
	KDUR_NS("scan_idle_timeout", scan_idle_ns);

	/* [synproxy] / [attack] */
	KBOOL("synproxy", CALY_F_SYNPROXY);
	if (caly_streq(key, "synproxy_port"))
		return caly_cfg_flag_ports(d, val, 0, CALY_PORT_F_SYNPROXY,
					   0, lineno);
	KRATE("global_syn_pps_high", global_syn_pps_hi);
	KRATE("global_syn_pps_low", global_syn_pps_lo);
	KRATE("syn_fallback_pps", syn_fallback_pps);
	KRATE("global_pps_high", global_pps_hi);
	KRATE("global_pps_low", global_pps_lo);
	KRATE("global_bps_high", global_bps_hi);
	KRATE("global_bps_low", global_bps_lo);
	KRATE("global_newconn_pps_high", global_newconn_pps_hi);
	KRATE("global_newconn_pps_low", global_newconn_pps_lo);
	KDUR_NS("attack_dwell", attack_dwell_ns);
	KBOOL("lockdown_allow_icmp", CALY_F_LOCKDOWN_ICMP);

	/* [logging] */
	KBOOL("log_events", CALY_F_LOG_EVENTS);
	KU32("log_sample_rate", log_sample_rate);
	KU32("log_max_pps", log_max_pps);
	KBOOL("src_stats", CALY_F_SRC_STATS);
	KU32("max_srcstat_entries", max_srcstat_entries);
	KDUR_NS("srcstat_idle_timeout", srcstat_idle_ns);

#undef KBOOL
#undef KU32
#undef KDUR_NS
#undef KDUR_MS
#undef KRATE

	caly_warn("config line %d: unknown key '%s' (ignored)", lineno, key);
	return 0;
}

/*
 * Parse the whole file into d->cfg (which must already hold the defaults) and
 * the pending buffers.  Section headers are skipped: keys are globally unique,
 * so dispatch is by key name alone, which also means a key in the "wrong"
 * section still works.
 */
static int caly_config_parse_file(struct caly_daemon *d, const char *path)
{
	FILE *f;
	char line[2048];
	int lineno = 0;
	int errors = 0;

	f = fopen(path, "re");
	if (f == NULL) {
		caly_err("cannot open the configuration file %s: %s", path,
			 strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), f) != NULL) {
		char *s, *eq, *key, *val;
		char *hash;

		lineno++;

		/* Strip a comment.  '#' inside a value is not expected in this
		 * grammar, so a leading-or-later '#' always starts a comment. */
		hash = strchr(line, '#');
		if (hash != NULL)
			*hash = '\0';

		s = caly_trim(line);
		if (s[0] == '\0')
			continue;
		if (s[0] == '[')          /* section header */
			continue;

		eq = strchr(s, '=');
		if (eq == NULL) {
			caly_warn("config line %d: no '=', ignoring: %s",
				  lineno, s);
			continue;
		}
		*eq = '\0';
		key = caly_trim(s);
		val = caly_trim(eq + 1);

		if (caly_cfg_apply(d, key, val, lineno) != 0)
			errors++;
	}

	if (ferror(f)) {
		caly_err("error reading %s: %s", path, strerror(errno));
		(void)fclose(f);
		return -1;
	}
	(void)fclose(f);

	if (errors > 0) {
		caly_err("%d configuration error(s) in %s", errors, path);
		return -1;
	}
	return 0;
}

/* ================================================================== *
 * Applying the buffered list directives to the maps (post-load)
 * ================================================================== */

static int caly_apply_pending(struct caly_daemon *d)
{
	int i;
	int rc = 0;

	/* Prefixes: allow, block, local. */
	for (i = 0; i < d->cidrs.count; i++) {
		struct caly_pending_cidr *pc =
			(struct caly_pending_cidr *)d->cidrs.data + i;

		if (caly_lpm_insert(&d->bpf, pc->map_id, &pc->cidr, pc->flags,
				    pc->tag) != 0) {
			char buf[CALY_CIDR_STRLEN];

			(void)caly_format_cidr(&pc->cidr, buf, sizeof(buf));
			caly_warn("cannot insert prefix %s: %s", buf,
				  strerror(errno));
			rc = -1;
		}
	}

	/* Port rules and flag adjustments. */
	for (i = 0; i < d->ports.count; i++) {
		struct caly_pending_port *pp =
			(struct caly_pending_port *)d->ports.data + i;
		__u32 p;

		for (p = pp->lo; p <= pp->hi; p++) {
			struct port_rule r;

			if (caly_port_rule_get(&d->bpf, pp->is_udp, p, &r)
			    != 0)
				memset(&r, 0, sizeof(r));

			if (pp->mode != 0xFFFFFFFFu) {
				r.mode = pp->mode;
				if (pp->mode == CALY_PORT_RATELIMIT) {
					r.rate = pp->rate;
					r.burst = pp->burst;
				}
			}
			r.flags |= pp->set_flags;
			r.flags &= ~pp->clr_flags;

			if (caly_port_rule_set(&d->bpf, pp->is_udp, p, &r)
			    != 0) {
				caly_warn("cannot set %s port %u: %s",
					  pp->is_udp ? "udp" : "tcp", p,
					  strerror(errno));
				rc = -1;
				break;
			}
		}
	}

	/* ICMP type policies (mandatory drops already rejected at parse). */
	for (i = 0; i < d->icmps.count; i++) {
		struct caly_pending_icmp *pi =
			(struct caly_pending_icmp *)d->icmps.data + i;

		if (caly_icmp_policy_set(&d->bpf, pi->family, pi->type,
					 pi->policy) != 0) {
			caly_warn("cannot set ICMPv%u type %u policy: %s",
				  pi->family == CALY_AF_INET6 ? 6u : 4u,
				  pi->type, strerror(errno));
			rc = -1;
		}
	}

	/* Interface config entries. */
	for (i = 0; i < d->niface; i++) {
		struct caly_iface_spec *s = &d->ifaces[i];
		struct iface_config ic;
		unsigned int idx = caly_if_index(s->name);

		if (idx == 0) {
			caly_warn("interface '%s' does not exist; skipping "
				  "its zone/flags", s->name);
			continue;
		}
		memset(&ic, 0, sizeof(ic));
		ic.ifindex = idx;
		ic.zone = s->have_zone ? s->zone : CALY_ZONE_UNSPEC;
		ic.flags = s->flags;
		if (s->zone == CALY_ZONE_WAN)
			ic.flags |= CALY_IF_F_WAN;

		if (caly_iface_config_set(&d->bpf, &ic) != 0) {
			caly_warn("cannot set the interface config for %s: %s",
				  s->name, strerror(errno));
			rc = -1;
		}
	}

	return rc;
}

/* ================================================================== *
 * Event decoding
 * ================================================================== */

static void caly_on_event(void *ctx, const void *data, __u32 size)
{
	struct caly_daemon *d = ctx;
	const struct event *ev = data;
	char src[CALY_ADDR_STRLEN];
	char dst[CALY_ADDR_STRLEN];

	d->events_seen++;

	if (size < sizeof(*ev)) {
		caly_log_key(CALY_LL_WARN, "ev-trunc",
			     "dropped a truncated event record (%u < %zu "
			     "bytes)", size, sizeof(*ev));
		return;
	}
	if (ev->version != CALY_ABI_VERSION_MAJOR) {
		caly_log_key(CALY_LL_WARN, "ev-abi",
			     "event with ABI major %u, expected %u; ignoring",
			     ev->version, CALY_ABI_VERSION_MAJOR);
		return;
	}

	/* Fan the event out to any live "subscribe" connections. This happens
	 * before the log-level gate so the live dashboard sees events even when
	 * the daemon's own logging is quiet. Writes are non-blocking: a slow
	 * subscriber simply misses this event, and a dead one is evicted. */
	if (d->nsub > 0) {
		char line[1024];
		int  len = caly_ctl_format_event(ev, line, sizeof(line));

		if (len > 0) {
			int i = 0;

			while (i < d->nsub) {
				ssize_t w = send(d->sub_fds[i], line,
						 (size_t)len,
						 MSG_NOSIGNAL | MSG_DONTWAIT);

				if (w < 0 && errno != EAGAIN &&
				    errno != EWOULDBLOCK)
					caly_ctl_subscribe_remove(d,
								  d->sub_fds[i]);
				else
					i++;   /* delivered, or transiently full */
			}
		}
	}

	if (!caly_log_enabled(CALY_LL_INFO))
		return;

	if (caly_format_addr_words(ev->family, ev->saddr, src,
				   sizeof(src)) != 0)
		(void)caly_strlcpy(src, "?", sizeof(src));
	if (caly_format_addr_words(ev->family, ev->daddr, dst,
				   sizeof(dst)) != 0)
		(void)caly_strlcpy(dst, "?", sizeof(dst));

	/* Keyed on the reason so one hot reason cannot crowd out the others.
	 * Ports are network order on the wire; ntohs() is endian-correct. */
	caly_log_key(CALY_LL_INFO, stat_reason_str(ev->reason),
		     "%s: %s:%u -> %s:%u proto=%u %s value=%llu%s",
		     caly_verdict_str(ev->verdict), src,
		     (unsigned int)ntohs(ev->sport), dst,
		     (unsigned int)ntohs(ev->dport),
		     ev->proto, stat_reason_str(ev->reason),
		     (unsigned long long)ev->value,
		     ev->ban_ttl_ns ? " (banned)" : "");
}

static void caly_on_lost(void *ctx, int cpu, __u64 count)
{
	struct caly_daemon *d = ctx;

	d->events_lost += count;
	caly_log_key(CALY_LL_WARN, "ev-lost",
		     "lost %llu event(s) on cpu %d (the buffer filled; "
		     "filtering is unaffected, only telemetry)",
		     (unsigned long long)count, cpu);
}

/* ================================================================== *
 * Mode escalation from the gauges
 * ================================================================== */

static __u64 caly_rate_of(const __u64 *cur, const __u64 *prev, unsigned int g,
			  __u64 elapsed_ns)
{
	__u64 delta;

	if (elapsed_ns == 0 || cur[g] < prev[g])
		return 0;
	delta = cur[g] - prev[g];
	/* delta * 1e9 could overflow only past ~1.8e10 events/interval, which
	 * a per-CPU counter will not reach in a sub-second tick; guard anyway. */
	if (delta > 0xFFFFFFFFFFFFFFFFULL / CALY_NSEC_PER_SEC)
		return 0xFFFFFFFFFFFFFFFFULL / elapsed_ns;
	return (delta * CALY_NSEC_PER_SEC) / elapsed_ns;
}

static void caly_maybe_escalate(struct caly_daemon *d, __u64 now)
{
	__u64 g[CALY_G_MAX];
	__u64 elapsed;
	__u64 pps, bps, syn, newconn;
	__u32 want;
	const struct fw_config *c = &d->cfg;

	/* LOCKDOWN and MONITOR_ONLY are explicit operator states; never
	 * auto-manage them. */
	if (d->base_mode == FW_MODE_LOCKDOWN ||
	    d->base_mode == FW_MODE_MONITOR_ONLY)
		return;

	if (caly_bpf_read_gauges(&d->bpf, g, CALY_G_MAX) != 0)
		return;

	if (!d->have_prev_sample) {
		memcpy(d->prev_gauges, g, sizeof(g));
		d->prev_sample_ns = now;
		d->have_prev_sample = 1;
		return;
	}

	elapsed = now - d->prev_sample_ns;
	if (elapsed < CALY_NSEC_PER_MSEC)
		return;

	pps     = caly_rate_of(g, d->prev_gauges, CALY_G_PKTS, elapsed);
	bps     = caly_rate_of(g, d->prev_gauges, CALY_G_BYTES, elapsed);
	syn     = caly_rate_of(g, d->prev_gauges, CALY_G_SYN, elapsed);
	newconn = caly_rate_of(g, d->prev_gauges, CALY_G_NEWCONN, elapsed);

	memcpy(d->prev_gauges, g, sizeof(g));
	d->prev_sample_ns = now;

	/* A zero hi threshold disables that metric as an escalation trigger. */
	{
		int hi = 0, above_lo = 0;

		if (c->global_pps_hi && pps > c->global_pps_hi)
			hi = 1;
		if (c->global_bps_hi && bps > c->global_bps_hi)
			hi = 1;
		if (c->global_syn_pps_hi && syn > c->global_syn_pps_hi)
			hi = 1;
		if (c->global_newconn_pps_hi && newconn > c->global_newconn_pps_hi)
			hi = 1;

		if (pps > c->global_pps_lo || bps > c->global_bps_lo ||
		    syn > c->global_syn_pps_lo ||
		    newconn > c->global_newconn_pps_lo)
			above_lo = 1;

		if (hi) {
			want = FW_MODE_UNDER_ATTACK;
			d->last_hi_ns = now;
		} else if (above_lo) {
			want = FW_MODE_ELEVATED;
		} else {
			want = FW_MODE_NORMAL;
		}
	}

	/* Dwell: do not leave UNDER_ATTACK until the attack has been quiet for
	 * attack_dwell_ns, so a bursty flood cannot make the mode oscillate. */
	if (d->cur_mode == FW_MODE_UNDER_ATTACK &&
	    want != FW_MODE_UNDER_ATTACK) {
		__u64 dwell = c->attack_dwell_ns ? c->attack_dwell_ns
						 : (2ULL * 60 *
						    CALY_NSEC_PER_SEC);

		if (now - d->last_hi_ns < dwell)
			return;   /* stay under attack a while longer */
	}

	if (want == d->cur_mode)
		return;

	caly_info("mode %s -> %s (pps=%llu bps=%llu syn=%llu newconn=%llu)",
		  fw_mode_str(d->cur_mode), fw_mode_str(want),
		  (unsigned long long)pps, (unsigned long long)bps,
		  (unsigned long long)syn, (unsigned long long)newconn);

	d->cur_mode = want;
	d->cfg.mode = want;
	if (caly_bpf_config_write(&d->bpf, &d->cfg) != 0)
		caly_warn("cannot push the new mode to the dataplane");
	else if (want == FW_MODE_UNDER_ATTACK && d->bpf.synproxy_loaded)
		caly_info("SYN proxy is now engaged for flagged ports");
}

/* ================================================================== *
 * Periodic statistics dump (SIGUSR1 and the control socket)
 * ================================================================== */

static void caly_dump_stats(struct caly_daemon *d, int fd)
{
	__u64 g[CALY_G_MAX];
	__u64 *pkts;
	char linebuf[256];
	unsigned int i;

	if (caly_bpf_read_gauges(&d->bpf, g, CALY_G_MAX) == 0) {
		for (i = 0; i < CALY_G_MAX; i++) {
			int n = caly_snprintf(linebuf, sizeof(linebuf),
					      "gauge %-12s %llu\n",
					      caly_gauge_name(i),
					      (unsigned long long)g[i]);
			if (n < 0)
				continue;
			if (fd >= 0)
				(void)caly_write_all(fd, linebuf, (size_t)n);
			else
				caly_info("%s", caly_trim(linebuf));
		}
	}

	pkts = calloc(STAT_MAX, sizeof(__u64));
	if (pkts == NULL)
		return;

	if (caly_bpf_read_stats(&d->bpf, pkts, NULL, STAT_MAX) == 0) {
		for (i = 0; i < STAT_MAX; i++) {
			int n;

			if (pkts[i] == 0)
				continue;
			n = caly_snprintf(linebuf, sizeof(linebuf),
					  "stat %-24s %llu\n",
					  stat_reason_str(i),
					  (unsigned long long)pkts[i]);
			if (n < 0)
				continue;
			if (fd >= 0)
				(void)caly_write_all(fd, linebuf, (size_t)n);
			else
				caly_info("%s", caly_trim(linebuf));
		}
	}
	free(pkts);
}

/* ================================================================== *
 * Control socket
 * ================================================================== */

static int caly_ctl_open(struct caly_daemon *d)
{
	struct sockaddr_un addr;
	int fd;

	if (caly_mkdir_p(CALY_RUN_DIR, 0755) != 0)
		caly_warn("cannot create %s: %s", CALY_RUN_DIR,
			  strerror(errno));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		caly_warn("cannot create the control socket: %s",
			  strerror(errno));
		return -1;
	}
	(void)caly_set_cloexec(fd);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	if (caly_strlcpy(addr.sun_path, d->ctl_path, sizeof(addr.sun_path)) >=
	    sizeof(addr.sun_path)) {
		caly_warn("control socket path is too long: %s", d->ctl_path);
		(void)close(fd);
		return -1;
	}

	(void)unlink(d->ctl_path);   /* a stale socket from a dead instance */

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
		caly_warn("cannot bind the control socket %s: %s",
			  d->ctl_path, strerror(errno));
		(void)close(fd);
		return -1;
	}
	if (chmod(d->ctl_path, 0600) != 0)
		caly_debug("cannot chmod %s: %s", d->ctl_path,
			   strerror(errno));
	if (listen(fd, 8) != 0) {
		caly_warn("cannot listen on the control socket: %s",
			  strerror(errno));
		(void)close(fd);
		(void)unlink(d->ctl_path);
		return -1;
	}
	(void)caly_set_nonblock(fd);

	d->ctl_fd = fd;
	return 0;
}

/*
 * Fill in the control-plane environment. ctl.c reaches the maps through the
 * loader's caly_bpf handle (raw libbpf), so nothing to adopt here.
 */
static void caly_ctl_build_env(struct caly_daemon *d, struct caly_ctl_env *env)
{
	memset(env, 0, sizeof(*env));
	env->bpf            = &d->bpf;
	env->cfg            = &d->cfg;
	env->base_mode      = &d->base_mode;
	env->cur_mode       = &d->cur_mode;
	env->reload_pending = &d->reload_pending;
	env->version        = CALY_VERSION;
	env->start_wall_ns  = d->start_wall_ns;
	env->pid            = (long)getpid();
	env->events_seen    = &d->events_seen;
	env->events_lost    = &d->events_lost;
	env->links          = d->links;
	env->nlink          = d->nlink;
	env->synproxy_loaded = d->bpf.synproxy_loaded;
	env->ringbuf_active  = caly_events_is_ring(d->events);
}

static int caly_ctl_subscribe_add(struct caly_daemon *d, int fd)
{
	if (d->nsub >= CALY_CTL_MAX_SUBS)
		return -1;
	if (caly_set_nonblock(fd) != 0)
		return -1;
	if (caly_epoll_add(d->epfd, fd, EPOLLIN | EPOLLRDHUP) != 0)
		return -1;
	d->sub_fds[d->nsub++] = fd;
	return 0;
}

static void caly_ctl_subscribe_remove(struct caly_daemon *d, int fd)
{
	int i;

	for (i = 0; i < d->nsub; i++) {
		if (d->sub_fds[i] != fd)
			continue;
		(void)epoll_ctl(d->epfd, EPOLL_CTL_DEL, fd, NULL);
		(void)close(fd);
		d->sub_fds[i] = d->sub_fds[--d->nsub];
		return;
	}
}

static int caly_ctl_is_sub(const struct caly_daemon *d, int fd)
{
	int i;

	for (i = 0; i < d->nsub; i++)
		if (d->sub_fds[i] == fd)
			return 1;
	return 0;
}

/*
 * Handle one accepted control connection. The client speaks newline-delimited
 * JSON and may pipeline several requests over one connection (calyctl's
 * dashboard reuses the socket), so we loop until it closes, times out, or
 * overflows the line buffer. A "subscribe" request promotes the fd into the
 * epoll-managed event-subscriber set: we return 1 and the caller does NOT close
 * it. Otherwise we return 0 and the caller closes.
 */
static int caly_ctl_handle(struct caly_daemon *d, int cfd)
{
	struct caly_ctl_env env;
	char   buf[65536];
	size_t used = 0;
	struct timeval tv;

	tv.tv_sec = 5;
	tv.tv_usec = 0;
	(void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	(void)setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

	caly_ctl_build_env(d, &env);

	for (;;) {
		char  *nl = memchr(buf, '\n', used);
		size_t linelen, rem;
		enum caly_ctl_action act;

		if (!nl) {
			ssize_t n;

			if (used == sizeof(buf))
				return 0;   /* one oversized line: give up */
			n = read(cfd, buf + used, sizeof(buf) - used);
			if (n <= 0)
				return 0;   /* EOF, timeout or error */
			used += (size_t)n;
			continue;
		}

		linelen = (size_t)(nl - buf);
		act = caly_ctl_dispatch(&env, cfd, buf, linelen);

		rem = used - (linelen + 1);
		memmove(buf, nl + 1, rem);
		used = rem;

		if (act == CALY_CTL_SUBSCRIBE) {
			if (caly_ctl_subscribe_add(d, cfd) == 0)
				return 1;   /* adopted; caller keeps it open */
			return 0;
		}
		if (act == CALY_CTL_CLOSE)
			return 0;
	}
}

static void caly_ctl_accept(struct caly_daemon *d)
{
	for (;;) {
		int cfd = accept(d->ctl_fd, NULL, NULL);
		int promoted;

		if (cfd < 0) {
			if (errno == EINTR)
				continue;
			/* EAGAIN: drained the backlog. */
			break;
		}
		(void)caly_set_cloexec(cfd);
		if (d->bpf.obj == NULL && d->bpf.map_fd[CALY_MID_CONFIG] < 0) {
			/* not loaded yet; nothing the control plane can do */
			(void)close(cfd);
			continue;
		}
		promoted = caly_ctl_handle(d, cfd);
		if (!promoted)
			(void)close(cfd);
	}
}

/* ================================================================== *
 * Reload
 * ================================================================== */

static int caly_reload(struct caly_daemon *d)
{
	struct fw_config newcfg;
	struct caly_daemon tmp;
	char err[256];
	unsigned int warnings = 0;

	if (d->config_path[0] == '\0') {
		caly_warn("SIGHUP/reload requested but no configuration file "
			  "was given; nothing to reload");
		return 0;
	}

	caly_info("reloading configuration from %s", d->config_path);

	/*
	 * Parse into a scratch daemon so a parse error leaves the running
	 * configuration completely untouched.  The pending buffers are part
	 * of that scratch state.
	 */
	memset(&tmp, 0, sizeof(tmp));
	caly_config_defaults(&tmp.cfg);
	caly_vec_init(&tmp.cidrs, sizeof(struct caly_pending_cidr));
	caly_vec_init(&tmp.ports, sizeof(struct caly_pending_port));
	caly_vec_init(&tmp.icmps, sizeof(struct caly_pending_icmp));
	tmp.bpf = d->bpf;   /* map fds only; not re-loaded */

	if (caly_config_parse_file(&tmp, d->config_path) != 0) {
		caly_err("reload aborted: keeping the running configuration");
		caly_vec_free(&tmp.cidrs);
		caly_vec_free(&tmp.ports);
		caly_vec_free(&tmp.icmps);
		return -1;
	}

	newcfg = tmp.cfg;

	/* Preserve the runtime-managed mode across a reload unless the file
	 * explicitly pins one other than normal. */
	if (newcfg.mode == FW_MODE_NORMAL)
		newcfg.mode = d->cur_mode;

	if (caly_config_sanitize(&newcfg, err, sizeof(err), &warnings) != 0) {
		caly_err("reload rejected: %s. Keeping the running "
			 "configuration.", err);
		caly_vec_free(&tmp.cidrs);
		caly_vec_free(&tmp.ports);
		caly_vec_free(&tmp.icmps);
		return -1;
	}

	/* Commit. */
	d->cfg = newcfg;
	d->base_mode = (newcfg.mode == FW_MODE_LOCKDOWN ||
			newcfg.mode == FW_MODE_MONITOR_ONLY)
		? newcfg.mode : FW_MODE_NORMAL;
	d->cur_mode = newcfg.mode;

	/* Swap the pending buffers in. */
	caly_vec_free(&d->cidrs);
	caly_vec_free(&d->ports);
	caly_vec_free(&d->icmps);
	d->cidrs = tmp.cidrs;
	d->ports = tmp.ports;
	d->icmps = tmp.icmps;
	d->allow_bypass_rate = tmp.allow_bypass_rate;
	/* Interface zones may have changed; copy the specs. */
	memcpy(d->ifaces, tmp.ifaces, sizeof(d->ifaces));
	d->niface = tmp.niface;

	/*
	 * Re-apply the loader-discovered capability bits.  caly_config_sanitize()
	 * unconditionally clears the whole CALY_F_CAP_MASK, and unlike startup
	 * (main.c: apply_caps runs AFTER sanitize) nothing else restores them on a
	 * reload.  Without this, a routine SIGHUP would strip CALY_F_CAP_SYNPROXY,
	 * CALY_F_CAP_RINGBUF and the XDP_* caps out of the config we push to the
	 * dataplane, silently disabling the SYN proxy and XDP_TX and moving events
	 * off the ring buffer - precisely when an operator under attack reloads.
	 */
	caly_config_apply_caps(&d->cfg, &d->bpf.feat);
	{
		int i;
		__u64 add = 0;

		/* CALY_F_CAP_XDP_NATIVE / XDP_TX / TC_EGRESS only become known at
		 * attach time; re-derive them from the live links, exactly as the
		 * startup path does after attaching the interfaces. */
		for (i = 0; i < d->nlink; i++) {
			if (d->links[i].dataplane == CALY_DP_XDP_NATIVE)
				add |= CALY_F_CAP_XDP_NATIVE | CALY_F_CAP_XDP_TX;
			if (d->links[i].tc_attached)
				add |= CALY_F_CAP_TC_EGRESS;
		}
		d->cfg.flags |= add;
	}

	if (caly_bpf_config_write(&d->bpf, &d->cfg) != 0)
		caly_warn("cannot write the reloaded configuration");
	if (caly_bpf_seed_maps(&d->bpf, &d->cfg) != 0)
		caly_warn("cannot re-seed the policy maps on reload");
	if (caly_apply_pending(d) != 0)
		caly_warn("some list directives could not be re-applied");

	caly_log_set_level((int)d->cfg.log_level);

	caly_info("reload complete (%u value(s) corrected)", warnings);
	return 0;
}

/* ================================================================== *
 * Signals, pidfile, privileges, RLIMIT_MEMLOCK
 * ================================================================== */

static int caly_signalfd_open(void)
{
	sigset_t mask;
	int fd;

	sigemptyset(&mask);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGUSR1);

	/* Block them so they are delivered through the fd, never as an async
	 * handler that could reenter non-async-signal-safe logging. */
	if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0)
		return -1;

	fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	if (fd < 0)
		return -1;

	/* SIGPIPE would otherwise kill us when a control-socket peer hangs
	 * up mid-write. */
	signal(SIGPIPE, SIG_IGN);
	return fd;
}

static int caly_raise_memlock(void)
{
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };

	if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0)
		return 0;

	/* On 5.11+ BPF memory is memcg-accounted and this bump is unnecessary,
	 * so a failure here is not fatal; on older kernels it matters and the
	 * subsequent map creation will fail loudly if the limit was the
	 * problem. */
	caly_warn("cannot raise RLIMIT_MEMLOCK to unlimited: %s. Harmless on "
		  "kernels >= 5.11 (BPF memory is memcg-accounted there); on "
		  "older kernels map creation may fail.", strerror(errno));
	return -1;
}

static int caly_check_privilege(void)
{
	if (caly_have_capability(CALY_CAP_SYS_ADMIN))
		return 0;
	if (caly_have_capability(CALY_CAP_BPF) &&
	    caly_have_capability(CALY_CAP_NET_ADMIN))
		return 0;

	caly_err("insufficient privilege: loading XDP needs CAP_SYS_ADMIN, or "
		 "CAP_BPF together with CAP_NET_ADMIN. Run as root or grant "
		 "the capabilities.");
	return -1;
}

/* ================================================================== *
 * Daemonize with a readiness pipe (systemd Type=forking friendly)
 * ================================================================== */

static int caly_daemonize(int *notify_out)
{
	int p[2];
	pid_t pid;

	*notify_out = -1;

	if (pipe(p) != 0)
		return -1;
	(void)caly_set_cloexec(p[0]);
	(void)caly_set_cloexec(p[1]);

	pid = fork();
	if (pid < 0) {
		(void)close(p[0]);
		(void)close(p[1]);
		return -1;
	}
	if (pid > 0) {
		/* Original parent: wait for the grandchild to report. */
		char status = 1;
		ssize_t n;

		(void)close(p[1]);
		n = caly_read_all(p[0], &status, 1);
		(void)close(p[0]);
		_exit(n == 1 ? (int)status : 1);
	}

	/* First child. */
	(void)close(p[0]);
	if (setsid() < 0) {
		char c = 1;

		(void)caly_write_all(p[1], &c, 1);
		_exit(1);
	}

	pid = fork();
	if (pid < 0) {
		char c = 1;

		(void)caly_write_all(p[1], &c, 1);
		_exit(1);
	}
	if (pid > 0)
		_exit(0);   /* intermediate child */

	/* Grandchild: the real daemon. */
	if (chdir("/") != 0)
		caly_warn("cannot chdir to /: %s", strerror(errno));
	umask(022);

	*notify_out = p[1];
	return 0;
}

/* Report readiness to the waiting parent and detach stdio.  status 0 = ok. */
static void caly_notify_ready(int *notify_fd, int status, int detach_stdio)
{
	char c = (char)status;

	if (*notify_fd >= 0) {
		(void)caly_write_all(*notify_fd, &c, 1);
		caly_close_fd(notify_fd);
	}

	if (detach_stdio && status == 0) {
		int nul = open("/dev/null", O_RDWR | O_CLOEXEC);

		if (nul >= 0) {
			(void)dup2(nul, STDIN_FILENO);
			(void)dup2(nul, STDOUT_FILENO);
			(void)dup2(nul, STDERR_FILENO);
			if (nul > STDERR_FILENO)
				(void)close(nul);
		}
		/* stderr is gone: logging must go to syslog from here on. */
		caly_log_set_stderr(0);
		caly_log_set_syslog(1);
	}
}

/* ================================================================== *
 * Teardown
 * ================================================================== */

static void caly_detach_all(struct caly_daemon *d)
{
	int i;

	for (i = d->nlink - 1; i >= 0; i--)
		(void)caly_bpf_detach_link(&d->links[i], d->force);
	d->nlink = 0;
}

static void caly_teardown(struct caly_daemon *d, int do_unpin)
{
	int i;

	caly_detach_all(d);

	/* Close every live event subscriber. */
	for (i = 0; i < d->nsub; i++)
		(void)close(d->sub_fds[i]);
	d->nsub = 0;

	if (d->events != NULL) {
		caly_events_close(d->events);
		d->events = NULL;
	}

	caly_bpf_close(&d->bpf);

	if (do_unpin)
		(void)caly_unpin_all(d->pin_dir);

	if (d->ctl_fd >= 0) {
		caly_close_fd(&d->ctl_fd);
		(void)unlink(d->ctl_path);
	}
	caly_close_fd(&d->timerfd);
	caly_close_fd(&d->sigfd);
	caly_close_fd(&d->epfd);

	if (d->pidfd >= 0) {
		caly_pidfile_release(d->pidfd, d->pidfile);
		d->pidfd = -1;
	}

	caly_vec_free(&d->cidrs);
	caly_vec_free(&d->ports);
	caly_vec_free(&d->icmps);
}

/* ================================================================== *
 * Event loop
 * ================================================================== */

static int caly_epoll_add(int epfd, int fd, __u32 events)
{
	struct epoll_event ev;

	if (fd < 0)
		return 0;
	memset(&ev, 0, sizeof(ev));
	ev.events = events;
	ev.data.fd = fd;
	return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
}

static void caly_handle_signal(struct caly_daemon *d)
{
	struct signalfd_siginfo si;
	ssize_t n;

	while ((n = read(d->sigfd, &si, sizeof(si))) == (ssize_t)sizeof(si)) {
		switch (si.ssi_signo) {
		case SIGTERM:
		case SIGINT:
			caly_info("received %s, shutting down",
				  si.ssi_signo == SIGTERM ? "SIGTERM"
							  : "SIGINT");
			d->stop = 1;
			break;
		case SIGHUP:
			d->reload_pending = 1;
			break;
		case SIGUSR1:
			caly_info("--- statistics (SIGUSR1) ---");
			caly_dump_stats(d, -1);
			break;
		default:
			break;
		}
	}
}

static void caly_periodic(struct caly_daemon *d)
{
	__u64 now = caly_now_ns();

	caly_log_flush_suppressed();

	if (d->cfg.stats_interval_ms > 0 &&
	    now - d->last_stats_ns >=
	    (__u64)d->cfg.stats_interval_ms * CALY_NSEC_PER_MSEC) {
		caly_maybe_escalate(d, now);
		d->last_stats_ns = now;
	}

	if (d->cfg.gc_interval_ms > 0 &&
	    now - d->last_gc_ns >=
	    (__u64)d->cfg.gc_interval_ms * CALY_NSEC_PER_MSEC) {
		struct caly_gc_stats gc;

		if (caly_bpf_gc(&d->bpf, &d->cfg, now, &gc) == 0 &&
		    (gc.bans_removed || gc.rate_removed || gc.scan_removed ||
		     gc.top_removed || gc.conn_removed)) {
			caly_debug("gc: bans=%llu rate=%llu scan=%llu "
				   "top=%llu conn=%llu (examined %llu)",
				   (unsigned long long)gc.bans_removed,
				   (unsigned long long)gc.rate_removed,
				   (unsigned long long)gc.scan_removed,
				   (unsigned long long)gc.top_removed,
				   (unsigned long long)gc.conn_removed,
				   (unsigned long long)gc.examined);
		}
		d->last_gc_ns = now;
	}
}

static int caly_run_loop(struct caly_daemon *d)
{
	struct epoll_event evs[8];
	int ev_epoll_fd;
	struct itimerspec its;
	unsigned int tick_ms;

	d->epfd = epoll_create1(EPOLL_CLOEXEC);
	if (d->epfd < 0) {
		caly_err("epoll_create1 failed: %s", strerror(errno));
		return -1;
	}

	d->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK |
						     TFD_CLOEXEC);
	if (d->timerfd < 0) {
		caly_err("timerfd_create failed: %s", strerror(errno));
		return -1;
	}

	/* Base tick: the smallest of poll/stats/gc, clamped to [50ms, 1s]. */
	tick_ms = d->cfg.poll_interval_ms ? d->cfg.poll_interval_ms : 200;
	if (d->cfg.stats_interval_ms && d->cfg.stats_interval_ms < tick_ms)
		tick_ms = d->cfg.stats_interval_ms;
	if (tick_ms < 50)
		tick_ms = 50;
	if (tick_ms > 1000)
		tick_ms = 1000;

	memset(&its, 0, sizeof(its));
	its.it_interval.tv_sec = tick_ms / 1000;
	its.it_interval.tv_nsec = (long)(tick_ms % 1000) * 1000000L;
	its.it_value = its.it_interval;
	if (timerfd_settime(d->timerfd, 0, &its, NULL) != 0) {
		caly_err("timerfd_settime failed: %s", strerror(errno));
		return -1;
	}

	ev_epoll_fd = caly_events_epoll_fd(d->events);

	if (caly_epoll_add(d->epfd, d->sigfd, EPOLLIN) != 0 ||
	    caly_epoll_add(d->epfd, d->timerfd, EPOLLIN) != 0 ||
	    caly_epoll_add(d->epfd, ev_epoll_fd, EPOLLIN) != 0 ||
	    caly_epoll_add(d->epfd, d->ctl_fd, EPOLLIN) != 0) {
		caly_err("epoll_ctl failed: %s", strerror(errno));
		return -1;
	}

	caly_info("Caly Anti is running (%d interface(s), mode %s). SIGTERM to "
		  "stop, SIGHUP to reload, SIGUSR1 to dump stats.",
		  d->nlink, fw_mode_str(d->cur_mode));

	while (!d->stop) {
		int n = epoll_wait(d->epfd, evs,
				   (int)(sizeof(evs) / sizeof(evs[0])), -1);
		int i;

		if (n < 0) {
			if (errno == EINTR)
				continue;
			caly_err("epoll_wait failed: %s", strerror(errno));
			break;
		}

		for (i = 0; i < n; i++) {
			int fd = evs[i].data.fd;

			if (fd == d->sigfd) {
				caly_handle_signal(d);
			} else if (fd == d->timerfd) {
				__u64 exp;

				(void)caly_read_all(d->timerfd, &exp,
						    sizeof(exp));
				caly_periodic(d);
			} else if (fd == ev_epoll_fd) {
				if (caly_events_consume(d->events) < 0)
					caly_log_key(CALY_LL_WARN,
						     "ev-consume",
						     "event consume error: %s",
						     strerror(errno));
			} else if (fd == d->ctl_fd) {
				caly_ctl_accept(d);
			} else if (caly_ctl_is_sub(d, fd)) {
				/* Subscribers only ever cause an event here by
				 * closing (or, rarely, sending junk). Either way
				 * the connection is done: drain and evict. */
				char tmp[256];
				ssize_t n = recv(fd, tmp, sizeof(tmp),
						 MSG_DONTWAIT);

				if (!(n < 0 && (errno == EAGAIN ||
						errno == EWOULDBLOCK)))
					caly_ctl_subscribe_remove(d, fd);
			}
		}

		if (d->reload_pending) {
			d->reload_pending = 0;
			(void)caly_reload(d);
		}
	}

	caly_info("event loop exited");
	return 0;
}

/* ================================================================== *
 * syncookies sysctl
 * ================================================================== */

static void caly_apply_syncookie_sysctl(struct caly_daemon *d)
{
	long cur = -1;

	(void)caly_sysctl_read_int("net.ipv4.tcp_syncookies", &cur);

	if (d->bpf.synproxy_loaded) {
		/* The raw-cookie SYN proxy REQUIRES 2 (unconditional). At 1
		 * the kernel only honours cookies once the accept queue
		 * overflows, so the handshakes this program completes on
		 * behalf of the stack would be rejected. */
		if (cur != 2) {
			if (caly_sysctl_write("net.ipv4.tcp_syncookies",
					      "2") == 0)
				caly_info("set net.ipv4.tcp_syncookies=2 "
					  "(required by the SYN proxy)");
			else
				caly_warn("cannot set "
					  "net.ipv4.tcp_syncookies=2: %s. The "
					  "SYN proxy needs it; the installer "
					  "normally writes "
					  "/etc/sysctl.d/98-calyanti.conf.",
					  strerror(errno));
		}
	} else if (cur >= 0 && cur < 1) {
		/* Fallback path: at least enable classic syncookies. */
		if (caly_sysctl_write("net.ipv4.tcp_syncookies", "1") == 0)
			caly_info("set net.ipv4.tcp_syncookies=1 (SYN "
				  "rate-limit fallback; the raw-cookie SYN "
				  "proxy needs kernel 6.0+)");
	}
}

/* ================================================================== *
 * Bring-up
 * ================================================================== */

static int caly_attach_interfaces(struct caly_daemon *d)
{
	int i;
	int attached = 0;

	for (i = 0; i < d->niface; i++) {
		struct caly_iface_spec *s = &d->ifaces[i];
		struct caly_link *link;

		if (!s->attach)
			continue;
		if (d->nlink >= CALY_MAX_IFACES)
			break;

		link = &d->links[d->nlink];

		if (caly_bpf_attach(&d->bpf, s->name, d->cfg.xdp_attach_pref,
				    d->force, link) != 0) {
			caly_err("cannot attach to %s", s->name);
			/* Roll back the interfaces already attached so we do
			 * not leave a half-installed dataplane behind. */
			caly_detach_all(d);
			return -1;
		}
		d->nlink++;
		attached++;

		/* The egress hook is best-effort: without it, outbound UDP
		 * (DNS/NTP/QUIC) replies fall through to the port policy, but
		 * the daemon runs fine. */
		if (d->cfg.flags & CALY_F_CONNTRACK)
			(void)caly_bpf_attach_tc_egress(&d->bpf, link);
	}

	if (attached == 0) {
		caly_err("no interfaces were attached");
		return -1;
	}
	return 0;
}

static int caly_startup(struct caly_daemon *d)
{
	struct caly_features feat;
	struct caly_load_opts opts;
	char err[256];
	unsigned int warnings = 0;

	if (caly_bpf_probe_features(&feat) != 0) {
		caly_err("feature probing failed");
		return -1;
	}
	caly_features_log(&feat);
	d->bpf.feat = feat;

	if (!feat.have_btf) {
		caly_err("this kernel exposes no BTF (/sys/kernel/btf/vmlinux "
			 "is absent), so the CO-RE XDP dataplane cannot load. "
			 "The installer's documented fallback is the nftables "
			 "dataplane (ladder rung 4). This daemon loads only "
			 "the eBPF rungs; run the installer to select a "
			 "fallback.");
		return -1;
	}

	caly_config_apply_caps(&d->cfg, &feat);

	if (caly_config_sanitize(&d->cfg, err, sizeof(err), &warnings) != 0) {
		caly_err("configuration rejected: %s", err);
		return -1;
	}
	if (warnings > 0)
		caly_info("%u configuration value(s) were corrected", warnings);

	d->base_mode = (d->cfg.mode == FW_MODE_LOCKDOWN ||
			d->cfg.mode == FW_MODE_MONITOR_ONLY)
		? d->cfg.mode : FW_MODE_NORMAL;
	d->cur_mode = d->cfg.mode;

	if (caly_bpffs_ensure(CALY_BPFFS_ROOT, d->pin_dir) != 0)
		return -1;

	memset(&opts, 0, sizeof(opts));
	opts.obj_path = d->obj_path[0] ? d->obj_path : NULL;
	opts.pin_dir = d->pin_dir;
	opts.reuse_pins = 1;
	opts.want_synproxy = (d->cfg.flags & CALY_F_SYNPROXY) ? 1 : 0;
	opts.want_ringbuf = 1;
	opts.verbose_libbpf = (d->cfg.log_level >= CALY_LL_DEBUG);

	if (caly_bpf_load(&d->bpf, &opts, &d->cfg) != 0)
		return -1;

	/* Capabilities are now realised; refresh and re-push the config. */
	caly_config_apply_caps(&d->cfg, &d->bpf.feat);
	if (caly_bpf_config_write(&d->bpf, &d->cfg) != 0) {
		caly_err("cannot write the initial configuration");
		return -1;
	}
	if (caly_bpf_seed_maps(&d->bpf, &d->cfg) != 0) {
		caly_err("cannot seed the policy maps");
		return -1;
	}

	if (caly_apply_pending(d) != 0)
		caly_warn("some configuration list directives could not be "
			  "applied; continuing");

	d->events = caly_events_open(&d->bpf, &d->cfg, caly_on_event,
				     caly_on_lost, d);
	if (d->events == NULL) {
		caly_err("cannot open the event source");
		return -1;
	}

	if (caly_attach_interfaces(d) != 0)
		return -1;

	/*
	 * Report the capabilities that only become known once an interface has
	 * actually accepted the program.  The dataplane reads these to decide
	 * whether the SYN proxy may XDP_TX: it is disabled on generic/skb mode
	 * because XDP_TX there is slow, so CALY_F_CAP_XDP_TX is set only for a
	 * native attach.
	 */
	{
		int i;
		__u64 add = 0;

		for (i = 0; i < d->nlink; i++) {
			if (d->links[i].dataplane == CALY_DP_XDP_NATIVE)
				add |= CALY_F_CAP_XDP_NATIVE |
				       CALY_F_CAP_XDP_TX;
			if (d->links[i].tc_attached)
				add |= CALY_F_CAP_TC_EGRESS;
		}
		if (add != 0 && (d->cfg.flags & add) != add) {
			d->cfg.flags |= add;
			if (caly_bpf_config_write(&d->bpf, &d->cfg) != 0)
				caly_warn("cannot push the realised "
					  "capabilities to the dataplane");
		}
	}

	caly_apply_syncookie_sysctl(d);

	if (caly_ctl_open(d) != 0)
		caly_warn("running without a control socket; calyctl will not "
			  "be able to reach this daemon");

	return 0;
}

/* ================================================================== *
 * Sub-commands that do not run the daemon
 * ================================================================== */

static const char *caly_xdpmode_word(__u32 mode)
{
	if (mode & CALY_XDPF_DRV)
		return "native";
	if (mode & CALY_XDPF_SKB)
		return "generic";
	if (mode & CALY_XDPF_HW)
		return "offload";
	return "attached";
}

static int caly_do_status(struct caly_daemon *d)
{
	struct caly_bpf b;
	struct fw_config cfg;
	struct caly_if_entry ifs[256];
	__u64 g[CALY_G_MAX];
	int n, i;

	if (caly_bpf_open_pinned(&b, d->pin_dir) != 0) {
		printf("caly-anti: not running (no pinned maps under %s)\n",
		       d->pin_dir);
		return 1;
	}

	printf("caly-anti %s\n", CALY_VERSION);
	printf("pin dir: %s\n", d->pin_dir);

	if (caly_bpf_config_read(&b, &cfg) == 0) {
		printf("mode: %s\n", fw_mode_str(cfg.mode));
		printf("enabled: %s\n",
		       (cfg.flags & CALY_F_ENABLED) ? "yes" : "no");
		printf("monitor-only: %s\n",
		       (cfg.flags & CALY_F_MONITOR_ONLY) ? "yes" : "no");
		printf("synproxy capable: %s\n",
		       (cfg.flags & CALY_F_CAP_SYNPROXY) ? "yes" : "no");
		printf("ringbuf: %s\n",
		       (cfg.flags & CALY_F_CAP_RINGBUF) ? "yes" : "no");
	}

	if (caly_bpf_read_gauges(&b, g, CALY_G_MAX) == 0) {
		printf("\ngauges:\n");
		for (i = 0; i < CALY_G_MAX; i++)
			printf("  %-12s %llu\n", caly_gauge_name(i),
			       (unsigned long long)g[i]);
	}

	printf("\nattached interfaces:\n");
	n = caly_if_enumerate(ifs, (int)(sizeof(ifs) / sizeof(ifs[0])));
	for (i = 0; i < n; i++) {
		__u32 pid = 0, mode = 0;
		int ours = 0;
		int r = caly_xdp_iface_status(ifs[i].name, &pid, &mode,
					      &ours);

		if (r == 1 && ours)
			printf("  %-16s prog id %-6u %s\n", ifs[i].name, pid,
			       caly_xdpmode_word(mode));
	}

	{
		long allow4 = caly_bpf_map_count(&b, CALY_MID_ALLOW4);
		long block4 = caly_bpf_map_count(&b, CALY_MID_BLOCK4);
		long ban4 = caly_bpf_map_count(&b, CALY_MID_BAN4);
		long conn = caly_bpf_map_count(&b, CALY_MID_CONN);

		printf("\nmap entries: allow4=%ld block4=%ld ban4=%ld "
		       "conn=%ld\n",
		       allow4, block4, ban4, conn);
	}

	caly_bpf_close(&b);
	return 0;
}

static int caly_do_dry_run(struct caly_daemon *d)
{
	struct caly_features feat;
	char err[256];
	unsigned int warnings = 0;
	int i;

	printf("caly-anti %s: configuration check (dry run)\n", CALY_VERSION);

	if (caly_bpf_probe_features(&feat) == 0) {
		printf("kernel %u.%u.%u, btf=%s ringbuf=%s synproxy=%s "
		       "virt=%s\n",
		       feat.kver_major, feat.kver_minor, feat.kver_patch,
		       feat.have_btf ? "yes" : "no",
		       feat.have_ringbuf ? "yes" : "no",
		       feat.have_synproxy ? "yes" : "no",
		       feat.virt[0] ? feat.virt : "none");
		caly_config_apply_caps(&d->cfg, &feat);
	}

	if (caly_config_sanitize(&d->cfg, err, sizeof(err), &warnings) != 0) {
		printf("INVALID: %s\n", err);
		return 1;
	}

	printf("configuration is valid (%u value(s) would be corrected)\n",
	       warnings);
	printf("mode: %s\n", fw_mode_str(d->cfg.mode));
	printf("mgmt tcp ports:");
	for (i = 0; i < (int)d->cfg.mgmt_tcp_count; i++)
		printf(" %u", d->cfg.mgmt_tcp_ports[i]);
	printf("\n");
	printf("interfaces to attach:");
	for (i = 0; i < d->niface; i++)
		printf(" %s", d->ifaces[i].name);
	if (d->niface == 0)
		printf(" (none - pass --iface or add interface= lines)");
	printf("\n");
	printf("pending: %d prefix(es), %d port rule(s), %d icmp rule(s)\n",
	       d->cidrs.count, d->ports.count, d->icmps.count);

	{
		char obj[PATH_MAX_SAFE];

		if (d->obj_path[0] != '\0')
			printf("bpf object: %s\n", d->obj_path);
		else if (caly_bpf_find_object(obj, sizeof(obj)) != NULL)
			printf("bpf object: %s\n", obj);
		else
			printf("bpf object: NOT FOUND (set CALY_BPF_OBJECT)\n");
	}

	return 0;
}

/* ================================================================== *
 * Usage / version
 * ================================================================== */

static void caly_usage(const char *argv0)
{
	printf(
"Usage: %s [options]\n"
"\n"
"Caly Anti - XDP/eBPF DDoS mitigation daemon.\n"
"\n"
"Options:\n"
"  -c, --config PATH      configuration file (default %s)\n"
"  -i, --iface NAME       attach to this interface (repeatable)\n"
"  -m, --mode MODE        normal|elevated|under-attack|lockdown|monitor-only\n"
"  -l, --log-level LEVEL  error|warn|info|debug|trace (or 0-4)\n"
"  -f, --foreground       do not daemonize; log to stderr\n"
"  -n, --dry-run          parse and validate the config, then exit\n"
"  -s, --status           report the running daemon's state and exit\n"
"  -u, --unload           detach every caly program and remove pins, then exit\n"
"      --obj PATH         path to the BPF object (default: search)\n"
"      --pin-dir PATH     bpffs pin directory (default %s)\n"
"      --force            replace a foreign XDP program / force unload\n"
"      --no-syslog        do not log to syslog when daemonized\n"
"  -V, --version          print the version and exit\n"
"  -h, --help             this help\n"
"\n"
"Signals: SIGTERM/SIGINT stop and detach, SIGHUP reload, SIGUSR1 dump stats.\n",
		argv0, CALY_CONF_PATH, CALY_PIN_DIR);
}

/* ================================================================== *
 * main
 * ================================================================== */

int main(int argc, char **argv)
{
	struct caly_daemon *d = &g_daemon;
	int action_status = 0, action_unload = 0, action_version = 0;
	int detach_stdio = 0;
	int c;
	int rc = 1;
	pid_t other = 0;

	enum {
		OPT_OBJ = 0x100,
		OPT_PIN_DIR,
		OPT_FORCE,
		OPT_NO_SYSLOG,
	};
	static const struct option longopts[] = {
		{ "config",     required_argument, NULL, 'c' },
		{ "iface",      required_argument, NULL, 'i' },
		{ "interface",  required_argument, NULL, 'i' },
		{ "mode",       required_argument, NULL, 'm' },
		{ "log-level",  required_argument, NULL, 'l' },
		{ "foreground", no_argument,       NULL, 'f' },
		{ "dry-run",    no_argument,       NULL, 'n' },
		{ "status",     no_argument,       NULL, 's' },
		{ "unload",     no_argument,       NULL, 'u' },
		{ "version",    no_argument,       NULL, 'V' },
		{ "help",       no_argument,       NULL, 'h' },
		{ "obj",        required_argument, NULL, OPT_OBJ },
		{ "pin-dir",    required_argument, NULL, OPT_PIN_DIR },
		{ "force",      no_argument,       NULL, OPT_FORCE },
		{ "no-syslog",  no_argument,       NULL, OPT_NO_SYSLOG },
		{ NULL, 0, NULL, 0 }
	};

	memset(d, 0, sizeof(*d));
	d->pidfd = -1;
	d->ctl_fd = -1;
	d->sigfd = -1;
	d->timerfd = -1;
	d->epfd = -1;
	d->notify_fd = -1;
	d->log_level_cli = -1;
	d->mode_cli = -1;
	d->use_syslog = 1;
	d->nsub = 0;
	d->start_wall_ns = caly_wall_ns();
	{
		int i;

		for (i = 0; i < CALY_MID_MAX; i++)
			d->bpf.map_fd[i] = -1;
	}

	caly_config_defaults(&d->cfg);
	caly_vec_init(&d->cidrs, sizeof(struct caly_pending_cidr));
	caly_vec_init(&d->ports, sizeof(struct caly_pending_port));
	caly_vec_init(&d->icmps, sizeof(struct caly_pending_icmp));

	(void)caly_strlcpy(d->config_path, "", sizeof(d->config_path));
	(void)caly_strlcpy(d->pin_dir, CALY_PIN_DIR, sizeof(d->pin_dir));
	(void)caly_strlcpy(d->pidfile, CALY_PIDFILE, sizeof(d->pidfile));
	(void)caly_strlcpy(d->ctl_path, CALY_CTL_SOCK, sizeof(d->ctl_path));

	/* Early minimal logging to stderr; reconfigured once options parsed. */
	caly_log_init("calyanti", CALY_LL_INFO, 1, 0);

	while ((c = getopt_long(argc, argv, "c:i:m:l:fnsuVh", longopts,
				NULL)) != -1) {
		switch (c) {
		case 'c':
			if (caly_strlcpy(d->config_path, optarg,
					 sizeof(d->config_path)) >=
			    sizeof(d->config_path)) {
				caly_err("--config path is too long");
				goto out;
			}
			break;
		case 'i':
			if (caly_iface_add(d, optarg) == NULL)
				goto out;
			break;
		case 'm': {
			__u32 m;

			if (caly_mode_from_str(optarg, &m) != 0) {
				caly_err("unknown mode '%s'", optarg);
				goto out;
			}
			d->mode_cli = (int)m;
			break;
		}
		case 'l': {
			int lv = caly_log_level_from_string(optarg);

			if (lv < 0) {
				caly_err("unknown log level '%s'", optarg);
				goto out;
			}
			d->log_level_cli = lv;
			break;
		}
		case 'f':
			d->foreground = 1;
			break;
		case 'n':
			d->dry_run = 1;
			break;
		case 's':
			action_status = 1;
			break;
		case 'u':
			action_unload = 1;
			break;
		case 'V':
			action_version = 1;
			break;
		case OPT_OBJ:
			if (caly_strlcpy(d->obj_path, optarg,
					 sizeof(d->obj_path)) >=
			    sizeof(d->obj_path)) {
				caly_err("--obj path is too long");
				goto out;
			}
			break;
		case OPT_PIN_DIR:
			if (caly_strlcpy(d->pin_dir, optarg,
					 sizeof(d->pin_dir)) >=
			    sizeof(d->pin_dir)) {
				caly_err("--pin-dir path is too long");
				goto out;
			}
			break;
		case OPT_FORCE:
			d->force = 1;
			break;
		case OPT_NO_SYSLOG:
			d->use_syslog = 0;
			break;
		case 'h':
			caly_usage(argv[0]);
			rc = 0;
			goto out;
		default:
			caly_usage(argv[0]);
			goto out;
		}
	}

	if (action_version) {
		printf("caly-anti %s (ABI %u.%u)\n", CALY_VERSION,
		       CALY_ABI_VERSION_MAJOR, CALY_ABI_VERSION_MINOR);
		rc = 0;
		goto out;
	}

	if (d->log_level_cli >= 0)
		caly_log_set_level(d->log_level_cli);

	/* --- read the config file if one was given or the default exists --- */
	if (d->config_path[0] == '\0' && caly_file_exists(CALY_CONF_PATH))
		(void)caly_strlcpy(d->config_path, CALY_CONF_PATH,
				   sizeof(d->config_path));

	if (d->config_path[0] != '\0') {
		if (caly_config_parse_file(d, d->config_path) != 0) {
			if (!action_status && !action_unload) {
				caly_err("configuration parsing failed");
				goto out;
			}
		}
	} else if (!action_status && !action_unload && !action_version) {
		caly_warn("no configuration file; using built-in safe "
			  "defaults");
	}

	/* CLI overrides win over the file. */
	if (d->log_level_cli >= 0)
		d->cfg.log_level = (__u32)d->log_level_cli;
	if (d->mode_cli >= 0)
		d->cfg.mode = (__u32)d->mode_cli;

	caly_log_set_level((int)d->cfg.log_level);

	/* --- sub-commands that do not run the daemon --- */
	if (action_unload) {
		if (caly_check_privilege() != 0)
			goto out;
		(void)caly_unload_everything(d->pin_dir, d->force);
		rc = 0;
		goto out;
	}
	if (action_status) {
		rc = caly_do_status(d);
		goto out;
	}
	if (d->dry_run) {
		rc = caly_do_dry_run(d);
		goto out;
	}

	/* --- real startup --- */
	if (caly_check_privilege() != 0)
		goto out;

	if (d->niface == 0)
		caly_warn("no interfaces specified; the daemon needs at least "
			  "one --iface or interface= line and will fail to "
			  "attach");

	(void)caly_raise_memlock();

	/* Daemonize before touching the kernel so load/attach errors are
	 * reported to the launching shell through the readiness pipe. */
	if (!d->foreground) {
		if (caly_daemonize(&d->notify_fd) != 0) {
			caly_err("cannot daemonize: %s", strerror(errno));
			goto out;
		}
		detach_stdio = 1;
		if (d->use_syslog)
			caly_log_set_syslog(1);
	}

	/* The runtime directory holds both the pidfile and the control socket;
	 * create it before either is opened. */
	if (caly_mkdir_p(CALY_RUN_DIR, 0755) != 0)
		caly_warn("cannot create %s: %s", CALY_RUN_DIR,
			  strerror(errno));

	/* Pidfile: flock-based, so a crashed previous instance leaves a stale
	 * file that we take over rather than refuse to start. */
	d->pidfd = caly_pidfile_acquire(d->pidfile, &other);
	if (d->pidfd < 0) {
		if (errno == EEXIST)
			caly_err("another instance is already running (pid "
				 "%ld); pidfile %s", (long)other, d->pidfile);
		else
			caly_err("cannot acquire the pidfile %s: %s",
				 d->pidfile, strerror(errno));
		caly_notify_ready(&d->notify_fd, 1, 0);
		goto out;
	}
	if (caly_pidfile_write(d->pidfd, getpid()) != 0)
		caly_warn("cannot write the pidfile %s: %s", d->pidfile,
			  strerror(errno));

	d->sigfd = caly_signalfd_open();
	if (d->sigfd < 0) {
		caly_err("cannot set up signal handling: %s", strerror(errno));
		caly_notify_ready(&d->notify_fd, 1, 0);
		goto out;
	}

	if (caly_startup(d) != 0) {
		caly_err("startup failed");
		caly_notify_ready(&d->notify_fd, 1, 0);
		caly_teardown(d, 1);
		goto out;
	}

	/* Ready: tell the parent to exit 0 and (when daemonized) detach the
	 * standard streams. */
	caly_notify_ready(&d->notify_fd, 0, detach_stdio);

	rc = caly_run_loop(d) == 0 ? 0 : 1;

	caly_info("shutting down: detaching programs and removing pins");
	caly_teardown(d, 1);

	caly_log_fini();
	return rc;

out:
	if (d->notify_fd >= 0)
		caly_notify_ready(&d->notify_fd, (rc == 0) ? 0 : 1, 0);
	caly_vec_free(&d->cidrs);
	caly_vec_free(&d->ports);
	caly_vec_free(&d->icmps);
	caly_log_fini();
	return rc;
}
