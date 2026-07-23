/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/loader.c
 *
 * The only file in the userspace tree that includes libbpf.
 *
 * LIBBPF COMPATIBILITY
 * --------------------
 * The floor is libbpf 0.8; the target is 1.x.  Three APIs were renamed at 1.0
 * and are shimmed below:
 *
 *   bpf_xdp_attach/detach/query_id   <-  bpf_set_link_xdp_fd/bpf_get_link_xdp_id
 *   LIBBPF_OPTS                      <-  DECLARE_LIBBPF_OPTS
 *   libbpf_probe_bpf_helper/map_type <-  kernel-version gate
 *
 * bpf_obj_get_info_by_fd() is used rather than bpf_prog_get_info_by_fd()
 * because the former exists in every version including 1.x, while the latter
 * only appeared at 1.0.
 *
 * XDP_FLAGS_* are spelled out below rather than pulled from <linux/if_link.h>:
 * that header collides with <net/if.h> on musl, and these are stable UAPI
 * values that have never changed.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "loader.h"
#include "log.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#if defined(__has_include)
#  if __has_include(<bpf/libbpf_version.h>)
#    include <bpf/libbpf_version.h>
#  endif
#endif

#ifndef LIBBPF_MAJOR_VERSION
#define LIBBPF_MAJOR_VERSION 0
#endif
#ifndef LIBBPF_MINOR_VERSION
#define LIBBPF_MINOR_VERSION 0
#endif

#define CALY_LIBBPF_AT_LEAST(maj, min)                       \
	(LIBBPF_MAJOR_VERSION > (maj) ||                     \
	 (LIBBPF_MAJOR_VERSION == (maj) &&                   \
	  LIBBPF_MINOR_VERSION >= (min)))

#ifndef LIBBPF_OPTS
#define LIBBPF_OPTS DECLARE_LIBBPF_OPTS
#endif

/* bpf_map__set_autocreate() is how the ring buffer map is skipped on kernels
 * that predate BPF_MAP_TYPE_RINGBUF (5.8).  Without it, an object containing
 * a ringbuf map cannot be loaded on such a kernel at all.  Overridable from
 * the build so a distro with an odd libbpf can correct the guess. */
#ifndef CALY_HAVE_MAP_AUTOCREATE
#  if CALY_LIBBPF_AT_LEAST(0, 8)
#    define CALY_HAVE_MAP_AUTOCREATE 1
#  else
#    define CALY_HAVE_MAP_AUTOCREATE 0
#  endif
#endif

/* XDP attach flags (uapi/linux/if_link.h). */
#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
#define XDP_FLAGS_UPDATE_IF_NOEXIST  (1U << 0)
#endif
#ifndef XDP_FLAGS_SKB_MODE
#define XDP_FLAGS_SKB_MODE           (1U << 1)
#endif
#ifndef XDP_FLAGS_DRV_MODE
#define XDP_FLAGS_DRV_MODE           (1U << 2)
#endif
#ifndef XDP_FLAGS_HW_MODE
#define XDP_FLAGS_HW_MODE            (1U << 3)
#endif

#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC  0xcafe4a11
#endif

/*
 * Kernel version at which the raw syncookie helpers are assumed present when
 * the build headers are too old to name BPF_FUNC_tcp_raw_gen_syncookie_ipv4
 * and therefore too old to probe for it.
 *
 * This is only ever a fallback.  When the headers do name the helper, the
 * runtime libbpf_probe_bpf_helper() result is authoritative and this constant
 * is not consulted, which is the correct ordering: probing the running kernel
 * beats guessing from a version number.
 */
#ifndef CALY_SYNPROXY_MIN_KVER_MAJOR
#define CALY_SYNPROXY_MIN_KVER_MAJOR 6
#endif
#ifndef CALY_SYNPROXY_MIN_KVER_MINOR
#define CALY_SYNPROXY_MIN_KVER_MINOR 0
#endif

/* Sanity bounds applied to every operator-supplied map size. */
#define CALY_MAP_ENTRIES_MIN     1024u
#define CALY_MAP_ENTRIES_MAX     16777216u
#define CALY_LOCAL_MAP_ENTRIES   4096u
#define CALY_RINGBUF_BYTES       (4u * 1024u * 1024u)

/* Batch size used when filling the two 65536-entry port arrays. */
#define CALY_SEED_BATCH          1024u

struct caly_map_desc {
	const char *name;
	int         optional;   /* absent from the object is not an error */
};

static const struct caly_map_desc caly_maps[CALY_MID_MAX] = {
	[CALY_MID_CONFIG]     = { CALY_MAP_CONFIG,      0 },
	[CALY_MID_STATS]      = { CALY_MAP_STATS,       0 },
	[CALY_MID_STATS_B]    = { CALY_MAP_STATS_BYTES, 0 },
	[CALY_MID_GLOBAL]     = { CALY_MAP_GLOBAL,      0 },
	[CALY_MID_ALLOW4]     = { CALY_MAP_ALLOW_V4,    0 },
	[CALY_MID_ALLOW6]     = { CALY_MAP_ALLOW_V6,    0 },
	[CALY_MID_BLOCK4]     = { CALY_MAP_BLOCK_V4,    0 },
	[CALY_MID_BLOCK6]     = { CALY_MAP_BLOCK_V6,    0 },
	[CALY_MID_LOCAL4]     = { CALY_MAP_LOCAL_V4,    0 },
	[CALY_MID_LOCAL6]     = { CALY_MAP_LOCAL_V6,    0 },
	[CALY_MID_BAN4]       = { CALY_MAP_BAN_V4,      0 },
	[CALY_MID_BAN6]       = { CALY_MAP_BAN_V6,      0 },
	[CALY_MID_RATE4]      = { CALY_MAP_RATE_V4,     0 },
	[CALY_MID_RATE6]      = { CALY_MAP_RATE_V6,     0 },
	[CALY_MID_CONN]       = { CALY_MAP_CONN,        0 },
	[CALY_MID_SCAN4]      = { CALY_MAP_SCAN_V4,     0 },
	[CALY_MID_SCAN6]      = { CALY_MAP_SCAN_V6,     0 },
	[CALY_MID_TOP4]       = { CALY_MAP_TOP_V4,      0 },
	[CALY_MID_TOP6]       = { CALY_MAP_TOP_V6,      0 },
	[CALY_MID_PORT_TCP]   = { CALY_MAP_PORT_TCP,    0 },
	[CALY_MID_PORT_UDP]   = { CALY_MAP_PORT_UDP,    0 },
	[CALY_MID_PORT_TB]    = { CALY_MAP_PORT_TB,     0 },
	[CALY_MID_ICMP4_POL]  = { CALY_MAP_ICMP4_POL,   0 },
	[CALY_MID_ICMP6_POL]  = { CALY_MAP_ICMP6_POL,   0 },
	[CALY_MID_IFACE]      = { CALY_MAP_IFACE,       0 },
	[CALY_MID_EVENTS]     = { CALY_MAP_EVENTS,      0 },
	[CALY_MID_EVENTS_RB]  = { CALY_MAP_EVENTS_RB,   1 },
	[CALY_MID_PROGS]      = { CALY_MAP_PROGS,       0 },
	[CALY_MID_SCRATCH]    = { CALY_MAP_SCRATCH,     0 },
};

const char *caly_map_name(int map_id)
{
	if (map_id < 0 || map_id >= CALY_MID_MAX)
		return "invalid";
	return caly_maps[map_id].name;
}

const char *caly_gauge_name(__u32 g)
{
	switch (g) {
	case CALY_G_PKTS:        return "pkts";
	case CALY_G_BYTES:       return "bytes";
	case CALY_G_SYN:         return "syn";
	case CALY_G_NEWCONN:     return "newconn";
	case CALY_G_DROPS:       return "drops";
	case CALY_G_UDP:         return "udp";
	case CALY_G_ICMP:        return "icmp";
	case CALY_G_FRAG:        return "frag";
	case CALY_G_SYNPROXY_TX: return "synproxy_tx";
	case CALY_G_EVENTS:      return "events";
	case CALY_G_EVENTS_LOST: return "events_lost";
	default:                 return "unknown";
	}
}

/* ================================================================== *
 * libbpf glue
 * ================================================================== */

static int caly_libbpf_print(enum libbpf_print_level level, const char *fmt,
			     va_list ap)
{
	int lvl;

	switch (level) {
	case LIBBPF_WARN:  lvl = CALY_LL_WARN;  break;
	case LIBBPF_INFO:  lvl = CALY_LL_DEBUG; break;
	case LIBBPF_DEBUG: lvl = CALY_LL_TRACE; break;
	default:           lvl = CALY_LL_DEBUG; break;
	}

	if (!caly_log_enabled(lvl))
		return 0;

	/* libbpf messages arrive with a trailing newline; the logger adds its
	 * own, so strip it into a local copy. */
	{
		char buf[1024];
		size_t len;
		int n = caly_vsnprintf(buf, sizeof(buf), fmt, ap);

		if (n < 0 && buf[0] == '\0')
			return 0;
		len = strlen(buf);
		while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
			buf[--len] = '\0';
		if (len == 0)
			return 0;
		caly_log_at(lvl, "libbpf: %s", buf);
	}
	return 0;
}

static void caly_libbpf_setup(int verbose)
{
	static int done;

	if (done)
		return;
	done = 1;
	(void)verbose;

#if LIBBPF_MAJOR_VERSION < 1
	/* Make 0.x behave like 1.0: no implicit RLIMIT_MEMLOCK bump (we do it
	 * ourselves and log it), strict section-name handling, and errors
	 * returned as negative values rather than through errno. */
	(void)libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
#endif
	/* Our print hook filters by log level internally, so verbosity is a
	 * property of the logger, not of whether the hook is installed. */
	libbpf_set_print(caly_libbpf_print);
}

static int caly_xdp_attach_compat(int ifindex, int prog_fd, __u32 flags)
{
#if CALY_LIBBPF_AT_LEAST(0, 7)
	return bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
#else
	return bpf_set_link_xdp_fd(ifindex, prog_fd, flags);
#endif
}

static int caly_xdp_detach_compat(int ifindex, __u32 flags)
{
#if CALY_LIBBPF_AT_LEAST(0, 7)
	return bpf_xdp_detach(ifindex, flags, NULL);
#else
	return bpf_set_link_xdp_fd(ifindex, -1, flags);
#endif
}

static int caly_xdp_query_compat(int ifindex, __u32 flags, __u32 *prog_id)
{
#if CALY_LIBBPF_AT_LEAST(0, 7)
	return bpf_xdp_query_id(ifindex, (int)flags, prog_id);
#else
	return bpf_get_link_xdp_id(ifindex, prog_id, flags);
#endif
}

/* ================================================================== *
 * Feature probing
 * ================================================================== */

static int caly_probe_ringbuf(const struct caly_features *f)
{
#if CALY_LIBBPF_AT_LEAST(0, 7)
	int r = libbpf_probe_bpf_map_type(BPF_MAP_TYPE_RINGBUF, NULL);

	if (r >= 0)
		return r > 0 ? 1 : 0;
	caly_debug("ringbuf map probe failed (%d), falling back to a version "
		   "check", r);
#endif
	return f->kver_code >= caly_kver_code(5, 8, 0) ? 1 : 0;
}

/*
 * Probe for the raw syncookie helpers.
 *
 * We deliberately refuse to hardcode the helper's numeric id.  If the build
 * headers are new enough to name BPF_FUNC_tcp_raw_gen_syncookie_ipv4 we probe
 * the running kernel and that answer is final.  If they are not, we fall back
 * to a kernel-version gate and record that the answer is a guess, so that
 * caly_bpf_load() knows it must be prepared to reload with the program
 * disabled.
 */
static int caly_probe_synproxy(struct caly_features *f)
{
	f->synproxy_probe_conclusive = 0;

#if defined(BPF_FUNC_tcp_raw_gen_syncookie_ipv4) && CALY_LIBBPF_AT_LEAST(0, 7)
	{
		int r = libbpf_probe_bpf_helper(
				BPF_PROG_TYPE_XDP,
				BPF_FUNC_tcp_raw_gen_syncookie_ipv4, NULL);

		if (r >= 0) {
			f->synproxy_probe_conclusive = 1;
			return r > 0 ? 1 : 0;
		}
		caly_debug("syncookie helper probe failed (%d), falling back "
			   "to a version check", r);
	}
#endif
	return f->kver_code >= caly_kver_code(CALY_SYNPROXY_MIN_KVER_MAJOR,
					      CALY_SYNPROXY_MIN_KVER_MINOR, 0)
		? 1 : 0;
}

/* BPF_MAP_LOOKUP_BATCH and friends are 5.6+.  There is no libbpf probe for a
 * syscall command, so this is a version gate; getting it wrong only costs a
 * slower seeding loop, never correctness. */
static int caly_probe_batch_ops(const struct caly_features *f)
{
	return f->kver_code >= caly_kver_code(5, 6, 0) ? 1 : 0;
}

int caly_bpf_probe_features(struct caly_features *f)
{
	if (f == NULL)
		return -1;

	memset(f, 0, sizeof(*f));

	f->libbpf_major = LIBBPF_MAJOR_VERSION;
	f->libbpf_minor = LIBBPF_MINOR_VERSION;

	if (caly_kernel_version(&f->kver_major, &f->kver_minor,
				&f->kver_patch) != 0) {
		caly_warn("cannot determine the kernel version; assuming the "
			  "oldest supported feature set");
		f->kver_major = 4;
		f->kver_minor = 18;
		f->kver_patch = 0;
	}
	f->kver_code = caly_kver_code(f->kver_major, f->kver_minor,
				      f->kver_patch);

	f->have_btf = caly_have_btf();
	f->have_ringbuf = caly_probe_ringbuf(f);
	f->have_synproxy = caly_probe_synproxy(f);
	f->have_batch_ops = caly_probe_batch_ops(f);

	/* The libbpf TC API is 0.6+; clsact itself is ancient. */
	f->have_tc_bpf = CALY_LIBBPF_AT_LEAST(0, 6) ? 1 : 0;

	f->is_container = caly_is_container();
	f->is_virt = caly_detect_virt(f->virt, sizeof(f->virt));

	return 0;
}

void caly_features_log(const struct caly_features *f)
{
	if (f == NULL)
		return;

	caly_info("kernel %u.%u.%u, libbpf %u.%u, virt=%s%s",
		  f->kver_major, f->kver_minor, f->kver_patch,
		  f->libbpf_major, f->libbpf_minor,
		  f->virt[0] != '\0' ? f->virt : "none",
		  f->is_container ? " (container)" : "");
	caly_info("features: btf=%s ringbuf=%s synproxy=%s%s batch=%s tc=%s",
		  f->have_btf ? "yes" : "no",
		  f->have_ringbuf ? "yes" : "no",
		  f->have_synproxy ? "yes" : "no",
		  f->synproxy_probe_conclusive ? "" : " (assumed)",
		  f->have_batch_ops ? "yes" : "no",
		  f->have_tc_bpf ? "yes" : "no");

	if (!f->have_btf)
		caly_warn("/sys/kernel/btf/vmlinux is absent: CO-RE cannot "
			  "work on this kernel. This is a documented fallback "
			  "to the nftables dataplane (ladder rung 4), not an "
			  "install failure.");
	if (f->is_container)
		caly_warn("running inside a container: XDP is usually "
			  "unavailable or restricted here, expect a fallback "
			  "to generic mode or to tc");
}

/* ================================================================== *
 * bpffs
 * ================================================================== */

static int caly_is_bpffs(const char *path)
{
	struct statfs st;

	if (statfs(path, &st) != 0)
		return 0;
	/* f_type is __fsword_t (glibc, signed long) or unsigned (musl); on a
	 * 64-bit target both hold BPF_FS_MAGIC without sign trouble.  Compare
	 * as unsigned long long rather than through typeof to stay portable. */
	return (unsigned long long)st.f_type ==
	       (unsigned long long)(unsigned int)BPF_FS_MAGIC ? 1 : 0;
}

int caly_bpffs_ensure(const char *bpffs_root, const char *pin_dir)
{
	if (bpffs_root == NULL)
		bpffs_root = CALY_BPFFS_ROOT;
	if (pin_dir == NULL)
		pin_dir = CALY_PIN_DIR;

	if (!caly_is_dir(bpffs_root)) {
		if (caly_mkdir_p(bpffs_root, 0755) != 0) {
			caly_err("cannot create %s: %s", bpffs_root,
				 strerror(errno));
			return -1;
		}
	}

	if (!caly_is_bpffs(bpffs_root)) {
		caly_info("mounting bpffs at %s", bpffs_root);
		if (mount("bpf", bpffs_root, "bpf", 0, NULL) != 0) {
			caly_err("cannot mount bpffs at %s: %s. Mount it "
				 "manually or add it to /etc/fstab.",
				 bpffs_root, strerror(errno));
			return -1;
		}
		if (!caly_is_bpffs(bpffs_root)) {
			caly_err("%s is still not a bpffs after mounting",
				 bpffs_root);
			return -1;
		}
	}

	if (caly_mkdir_p(pin_dir, 0700) != 0) {
		caly_err("cannot create the pin directory %s: %s", pin_dir,
			 strerror(errno));
		return -1;
	}
	return 0;
}

/* ================================================================== *
 * Locating the BPF object
 * ================================================================== */

const char *caly_bpf_find_object(char *buf, size_t len)
{
	static const char *const dirs[] = {
		"/usr/lib/calyanti",
		"/usr/libexec/calyanti",
		"/usr/local/lib/calyanti",
		"/lib/calyanti",
		"/opt/calyanti",
		".",
		"./src/bpf",
		"./build",
		NULL
	};
	const char *env;
	char exe[PATH_MAX_SAFE];
	ssize_t n;
	int i;

	if (buf == NULL || len == 0)
		return NULL;
	buf[0] = '\0';

	env = getenv("CALY_BPF_OBJECT");
	if (env != NULL && env[0] != '\0') {
		if (caly_strlcpy(buf, env, len) >= len)
			return NULL;
		if (caly_file_exists(buf))
			return buf;
		caly_warn("CALY_BPF_OBJECT=%s does not exist, continuing the "
			  "search", env);
	}

	/* Alongside the running binary: the layout of an uninstalled build. */
	n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	if (n > 0) {
		char *slash;

		exe[n] = '\0';
		slash = strrchr(exe, '/');
		if (slash != NULL) {
			*slash = '\0';
			if (caly_snprintf(buf, len, "%s/%s", exe,
					  CALY_BPF_OBJ_NAME) >= 0 &&
			    caly_file_exists(buf))
				return buf;
			if (caly_snprintf(buf, len, "%s/bpf/%s", exe,
					  CALY_BPF_OBJ_NAME) >= 0 &&
			    caly_file_exists(buf))
				return buf;
		}
	}

	for (i = 0; dirs[i] != NULL; i++) {
		/* Directly in the directory... */
		if (caly_snprintf(buf, len, "%s/%s", dirs[i],
				  CALY_BPF_OBJ_NAME) >= 0 &&
		    caly_file_exists(buf))
			return buf;
		/* ...or in its bpf/ subdirectory, which is where the installer
		 * places it (BPFOBJDIR = <libdir>/bpf). */
		if (caly_snprintf(buf, len, "%s/bpf/%s", dirs[i],
				  CALY_BPF_OBJ_NAME) >= 0 &&
		    caly_file_exists(buf))
			return buf;
	}

	buf[0] = '\0';
	return NULL;
}

/* ================================================================== *
 * Configuration defaults, sanitising, capability bits
 * ================================================================== */

#define CALY_SEC   (1000000000ULL)
#define CALY_MIN   (60ULL * CALY_SEC)
#define CALY_HOUR  (3600ULL * CALY_SEC)

void caly_config_defaults(struct fw_config *cfg)
{
	if (cfg == NULL)
		return;

	memset(cfg, 0, sizeof(*cfg));

	cfg->abi_version = CALY_ABI_VERSION;
	cfg->config_gen  = 1;

	/* Mirrors the shipped config/calyanti.conf.  Safe, not tight: a
	 * firewall whose defaults silently do nothing is a worse default than
	 * one that filters only the unambiguously hostile. */
	cfg->flags = CALY_F_ENABLED | CALY_F_IPV4 | CALY_F_IPV6 |
		     CALY_F_VLAN_INSPECT | CALY_F_TUNNEL_INSPECT |
		     CALY_F_ANOMALY_CHECKS | CALY_F_LAND_CHECK |
		     CALY_F_BOGON_FILTER | CALY_F_TCP_FLAG_CHECKS |
		     CALY_F_FRAG_CHECKS | CALY_F_ICMP_FILTER |
		     CALY_F_DROP_RH0 | CALY_F_ALLOWLIST | CALY_F_BLOCKLIST |
		     CALY_F_AUTOBAN | CALY_F_RATE_LIMIT |
		     CALY_F_ANTI_AMPLIFY | CALY_F_PORT_POLICY |
		     CALY_F_CONNTRACK | CALY_F_PORTSCAN_DETECT |
		     CALY_F_SYNPROXY | CALY_F_SRC_STATS | CALY_F_LOG_EVENTS |
		     CALY_F_MGMT_BYPASS_ALL | CALY_F_LOCKDOWN_ICMP;
	/* Deliberately clear: MONITOR_ONLY, WAN_DROP_PRIVATE, DEFAULT_DENY,
	 * DROP_ALL_FRAGS, DROP_IP4_OPTIONS, TTL_CHECK, DROP_UNKNOWN_L3. */

	cfg->tb_rate[CALY_TB_PPS]      = 200000ULL;
	cfg->tb_burst[CALY_TB_PPS]     = 400000ULL;
	cfg->tb_rate[CALY_TB_BPS]      = 250000000ULL;   /* 2 Gbit/s */
	cfg->tb_burst[CALY_TB_BPS]     = 500000000ULL;
	cfg->tb_rate[CALY_TB_SYN]      = 2000ULL;
	cfg->tb_burst[CALY_TB_SYN]     = 4000ULL;
	cfg->tb_rate[CALY_TB_UDP]      = 50000ULL;
	cfg->tb_burst[CALY_TB_UDP]     = 100000ULL;
	cfg->tb_rate[CALY_TB_ICMP]     = 200ULL;
	cfg->tb_burst[CALY_TB_ICMP]    = 400ULL;
	cfg->tb_rate[CALY_TB_NEWCONN]  = 500ULL;
	cfg->tb_burst[CALY_TB_NEWCONN] = 1000ULL;

	cfg->global_pps_hi          = 4000000ULL;
	cfg->global_pps_lo          = 2000000ULL;
	cfg->global_bps_hi          = 1250000000ULL;    /* 10 Gbit/s */
	cfg->global_bps_lo          = 800000000ULL;
	cfg->global_syn_pps_hi      = 40000ULL;
	cfg->global_syn_pps_lo      = 15000ULL;
	cfg->global_newconn_pps_hi  = 100000ULL;
	cfg->global_newconn_pps_lo  = 50000ULL;
	cfg->attack_dwell_ns        = 2ULL * CALY_MIN;
	cfg->syn_fallback_pps       = 100000ULL;

	cfg->ban_ttl_base_ns  = 10ULL * CALY_MIN;
	cfg->ban_ttl_max_ns   = 24ULL * CALY_HOUR;
	cfg->ban_ttl_scan_ns  = 1ULL * CALY_HOUR;
	cfg->ban_ttl_amp_ns   = 6ULL * CALY_HOUR;
	cfg->strike_window_ns = 60ULL * CALY_SEC;

	cfg->scan_window_ns = 30ULL * CALY_SEC;

	cfg->ct_tcp_syn_ns    = 60ULL * CALY_SEC;
	cfg->ct_tcp_est_ns    = 4ULL * CALY_HOUR;
	cfg->ct_tcp_fin_ns    = 30ULL * CALY_SEC;
	cfg->ct_udp_ns        = 30ULL * CALY_SEC;
	cfg->ct_udp_stream_ns = 180ULL * CALY_SEC;
	cfg->ct_icmp_ns       = 30ULL * CALY_SEC;
	cfg->ct_generic_ns    = 60ULL * CALY_SEC;

	cfg->rate_idle_ns    = 5ULL * CALY_MIN;
	cfg->scan_idle_ns    = 5ULL * CALY_MIN;
	cfg->srcstat_idle_ns = 10ULL * CALY_MIN;

	cfg->mode         = FW_MODE_NORMAL;
	cfg->default_zone = CALY_ZONE_LAN;

	cfg->strike_limit        = 10;
	cfg->ban_escalate_num    = 2;
	cfg->ban_escalate_den    = 1;
	cfg->scan_port_threshold = 60;

	cfg->icmp_max_payload  = 1472;
	cfg->icmp6_max_payload = 1472;
	cfg->frag_min_bytes    = 128;
	cfg->ip_min_ttl        = 0;

	cfg->vlan_max_depth   = CALY_VLAN_MAX_DEPTH;
	cfg->ip6_ext_max      = CALY_IP6_EXT_MAX;
	cfg->tunnel_max_depth = CALY_TUNNEL_MAX_DEPTH;
	cfg->tcp_min_doff     = 5;

	cfg->log_sample_rate = 100;
	cfg->log_max_pps     = 1000;
	cfg->log_level       = CALY_LL_INFO;
	cfg->event_pages     = 16;

	cfg->max_ban_entries     = 262144;
	cfg->max_conn_entries    = 262144;
	cfg->max_rate_entries    = 524288;
	cfg->max_scan_entries    = 131072;
	cfg->max_srcstat_entries = 131072;
	cfg->max_allow_entries   = 65536;
	cfg->max_block_entries   = 262144;
	cfg->max_iface_entries   = 64;

	cfg->dataplane_pref   = CALY_DP_AUTO;
	cfg->xdp_attach_pref  = CALY_XDP_AUTO;
	cfg->poll_interval_ms = 200;
	cfg->stats_interval_ms = 1000;
	cfg->gc_interval_ms   = 5000;
	cfg->gc_batch         = 4096;

	/* THE lockout-prevention default. */
	cfg->mgmt_tcp_ports[0] = 22;
	cfg->mgmt_tcp_count    = 1;
	cfg->mgmt_udp_count    = 0;
}

static __u32 caly_clamp_u32(__u32 v, __u32 lo, __u32 hi, const char *what,
			    unsigned int *warnings)
{
	if (v < lo || v > hi) {
		__u32 nv = (v < lo) ? lo : hi;

		caly_warn("config: %s = %u is out of range [%u, %u], "
			  "clamped to %u", what, v, lo, hi, nv);
		if (warnings != NULL)
			(*warnings)++;
		return nv;
	}
	return v;
}

int caly_config_sanitize(struct fw_config *cfg, char *err, size_t errlen,
			 unsigned int *warnings)
{
	unsigned int i;
	int have_ssh = 0;

	if (err != NULL && errlen > 0)
		err[0] = '\0';
	if (cfg == NULL) {
		if (err != NULL)
			(void)caly_strlcpy(err, "no configuration", errlen);
		return -1;
	}

	/* ABI: the major must match what this binary was compiled against.
	 * A minor difference is additive and therefore safe. */
	if ((cfg->abi_version >> 16) != CALY_ABI_VERSION_MAJOR) {
		if (cfg->abi_version != 0) {
			if (err != NULL)
				(void)caly_snprintf(err, errlen,
					"ABI major mismatch: configuration is "
					"%llu.%llu, this build is %u.%u",
					(unsigned long long)
						(cfg->abi_version >> 16),
					(unsigned long long)
						(cfg->abi_version & 0xFFFF),
					CALY_ABI_VERSION_MAJOR,
					CALY_ABI_VERSION_MINOR);
			return -1;
		}
	}
	cfg->abi_version = CALY_ABI_VERSION;

	/* Capability bits are discovered, never configured.  Clearing them
	 * here means an operator cannot claim a SYN proxy the kernel does not
	 * have and thereby send every SYN into an empty tail-call slot. */
	cfg->flags &= ~CALY_F_CAP_MASK;

	cfg->mode = caly_clamp_u32(cfg->mode, 0, FW_MODE_MAX - 1, "mode",
				   warnings);
	cfg->default_zone = caly_clamp_u32(cfg->default_zone, 0,
					   CALY_ZONE_MAX - 1, "default_zone",
					   warnings);
	cfg->dataplane_pref = caly_clamp_u32(cfg->dataplane_pref, 0,
					     CALY_DP_MAX - 1, "dataplane",
					     warnings);
	cfg->xdp_attach_pref = caly_clamp_u32(cfg->xdp_attach_pref, 0,
					      CALY_XDP_MODE_MAX - 1,
					      "xdp_mode", warnings);

	/* Parse depths may only LOWER the compile-time bounds: the dataplane
	 * loops are unrolled against the constants, so a larger value is not
	 * merely ignored, it is meaningless. */
	if (cfg->vlan_max_depth > CALY_VLAN_MAX_DEPTH) {
		caly_warn("config: vlan_max_depth %u exceeds the compiled "
			  "bound %u, clamped", cfg->vlan_max_depth,
			  CALY_VLAN_MAX_DEPTH);
		cfg->vlan_max_depth = CALY_VLAN_MAX_DEPTH;
		if (warnings != NULL)
			(*warnings)++;
	}
	if (cfg->ip6_ext_max > CALY_IP6_EXT_MAX) {
		caly_warn("config: ipv6_ext_max %u exceeds the compiled bound "
			  "%u, clamped", cfg->ip6_ext_max, CALY_IP6_EXT_MAX);
		cfg->ip6_ext_max = CALY_IP6_EXT_MAX;
		if (warnings != NULL)
			(*warnings)++;
	}
	if (cfg->tunnel_max_depth > CALY_TUNNEL_MAX_DEPTH) {
		caly_warn("config: tunnel_max_depth %u exceeds the compiled "
			  "bound %u, clamped", cfg->tunnel_max_depth,
			  CALY_TUNNEL_MAX_DEPTH);
		cfg->tunnel_max_depth = CALY_TUNNEL_MAX_DEPTH;
		if (warnings != NULL)
			(*warnings)++;
	}

	cfg->tcp_min_doff = caly_clamp_u32(cfg->tcp_min_doff, 5, 15,
					   "tcp_min_doff", warnings);
	cfg->ip_min_ttl = caly_clamp_u32(cfg->ip_min_ttl, 0, 255, "min_ttl",
					 warnings);
	cfg->log_level = caly_clamp_u32(cfg->log_level, 0, CALY_LL_MAX - 1,
					"log_level", warnings);

	if (cfg->ban_escalate_den == 0) {
		caly_warn("config: ban_escalate_den is 0, forcing 1");
		cfg->ban_escalate_den = 1;
		if (warnings != NULL)
			(*warnings)++;
	}
	if (cfg->strike_limit == 0) {
		/* 0 would ban on the first bucket overrun. */
		caly_warn("config: strike_limit is 0, forcing 1");
		cfg->strike_limit = 1;
		if (warnings != NULL)
			(*warnings)++;
	}
	if (cfg->ban_ttl_max_ns < cfg->ban_ttl_base_ns)
		cfg->ban_ttl_max_ns = cfg->ban_ttl_base_ns;

	/* Hysteresis pairs must not be inverted or the daemon will oscillate
	 * between modes on every tick. */
	if (cfg->global_pps_lo > cfg->global_pps_hi)
		cfg->global_pps_lo = cfg->global_pps_hi;
	if (cfg->global_bps_lo > cfg->global_bps_hi)
		cfg->global_bps_lo = cfg->global_bps_hi;
	if (cfg->global_syn_pps_lo > cfg->global_syn_pps_hi)
		cfg->global_syn_pps_lo = cfg->global_syn_pps_hi;
	if (cfg->global_newconn_pps_lo > cfg->global_newconn_pps_hi)
		cfg->global_newconn_pps_lo = cfg->global_newconn_pps_hi;

	/* event_pages must be a power of two: it becomes the perf ring size
	 * in pages, and the kernel rejects anything else. */
	if (cfg->event_pages == 0 ||
	    (cfg->event_pages & (cfg->event_pages - 1)) != 0) {
		caly_warn("config: event_pages = %u is not a power of two, "
			  "using 16", cfg->event_pages);
		cfg->event_pages = 16;
		if (warnings != NULL)
			(*warnings)++;
	}
	cfg->event_pages = caly_clamp_u32(cfg->event_pages, 1, 1024,
					  "event_pages", warnings);

	cfg->poll_interval_ms = caly_clamp_u32(cfg->poll_interval_ms, 10,
					       60000, "poll_interval",
					       warnings);
	cfg->stats_interval_ms = caly_clamp_u32(cfg->stats_interval_ms, 100,
						600000, "stats_interval",
						warnings);
	cfg->gc_interval_ms = caly_clamp_u32(cfg->gc_interval_ms, 100,
					     3600000, "gc_interval", warnings);
	cfg->gc_batch = caly_clamp_u32(cfg->gc_batch, 16, 1048576, "gc_batch",
				       warnings);

	cfg->max_ban_entries = caly_clamp_u32(cfg->max_ban_entries,
					      CALY_MAP_ENTRIES_MIN,
					      CALY_MAP_ENTRIES_MAX,
					      "max_ban_entries", warnings);
	cfg->max_conn_entries = caly_clamp_u32(cfg->max_conn_entries,
					       CALY_MAP_ENTRIES_MIN,
					       CALY_MAP_ENTRIES_MAX,
					       "max_conn_entries", warnings);
	cfg->max_rate_entries = caly_clamp_u32(cfg->max_rate_entries,
					       CALY_MAP_ENTRIES_MIN,
					       CALY_MAP_ENTRIES_MAX,
					       "max_rate_entries", warnings);
	cfg->max_scan_entries = caly_clamp_u32(cfg->max_scan_entries,
					       CALY_MAP_ENTRIES_MIN,
					       CALY_MAP_ENTRIES_MAX,
					       "max_scan_entries", warnings);
	cfg->max_srcstat_entries = caly_clamp_u32(cfg->max_srcstat_entries,
						  CALY_MAP_ENTRIES_MIN,
						  CALY_MAP_ENTRIES_MAX,
						  "max_srcstat_entries",
						  warnings);
	cfg->max_allow_entries = caly_clamp_u32(cfg->max_allow_entries,
						64, CALY_MAP_ENTRIES_MAX,
						"max_allow_entries", warnings);
	cfg->max_block_entries = caly_clamp_u32(cfg->max_block_entries,
						64, CALY_MAP_ENTRIES_MAX,
						"max_block_entries", warnings);
	cfg->max_iface_entries = caly_clamp_u32(cfg->max_iface_entries,
						4, 4096, "max_iface_entries",
						warnings);

	/* ---- management port list: the lockout-prevention invariant ---- */
	if (cfg->mgmt_tcp_count > CALY_MGMT_PORTS_MAX)
		cfg->mgmt_tcp_count = CALY_MGMT_PORTS_MAX;
	if (cfg->mgmt_udp_count > CALY_MGMT_PORTS_MAX)
		cfg->mgmt_udp_count = CALY_MGMT_PORTS_MAX;

	/* Entries past the count are stale; zero them so a later reader that
	 * trusts the array rather than the count cannot see a ghost port. */
	for (i = cfg->mgmt_tcp_count; i < CALY_MGMT_PORTS_MAX; i++)
		cfg->mgmt_tcp_ports[i] = 0;
	for (i = cfg->mgmt_udp_count; i < CALY_MGMT_PORTS_MAX; i++)
		cfg->mgmt_udp_ports[i] = 0;

	for (i = 0; i < cfg->mgmt_tcp_count; i++) {
		if (cfg->mgmt_tcp_ports[i] == 22)
			have_ssh = 1;
	}

	if (!have_ssh) {
		if (cfg->mgmt_tcp_count < CALY_MGMT_PORTS_MAX) {
			cfg->mgmt_tcp_ports[cfg->mgmt_tcp_count++] = 22;
			caly_warn("config: TCP/22 was not in the management "
				  "port list; it has been added. Locking "
				  "yourself out of a machine that is under "
				  "attack is worse than the attack.");
			if (warnings != NULL)
				(*warnings)++;
		} else {
			/* All 16 slots hold other ports.  We will not silently
			 * evict one of the operator's choices, and we will not
			 * run without SSH reachable. */
			if (err != NULL)
				(void)caly_snprintf(err, errlen,
					"all %u management TCP slots are in "
					"use and none of them is 22; refusing "
					"a configuration that cannot keep SSH "
					"reachable",
					CALY_MGMT_PORTS_MAX);
			return -1;
		}
	}

	return 0;
}

void caly_config_apply_caps(struct fw_config *cfg,
			    const struct caly_features *f)
{
	if (cfg == NULL || f == NULL)
		return;

	cfg->flags &= ~CALY_F_CAP_MASK;

	if (f->have_synproxy)
		cfg->flags |= CALY_F_CAP_SYNPROXY;
	if (f->have_ringbuf)
		cfg->flags |= CALY_F_CAP_RINGBUF;
	if (f->have_btf)
		cfg->flags |= CALY_F_CAP_BTF;
	if (f->have_batch_ops)
		cfg->flags |= CALY_F_CAP_BATCH_OPS;
	/* CALY_F_CAP_XDP_NATIVE, CALY_F_CAP_XDP_TX and CALY_F_CAP_TC_EGRESS
	 * are set by caly_bpf_attach()/caly_bpf_attach_tc_egress() once an
	 * interface has actually accepted the program: they describe a
	 * realised attachment, not a prediction. */
}

/* ================================================================== *
 * Map sizing and loading
 * ================================================================== */

static int caly_set_max_entries(struct bpf_map *m, __u32 n)
{
#if CALY_LIBBPF_AT_LEAST(0, 6)
	return bpf_map__set_max_entries(m, n);
#else
	return bpf_map__resize(m, n);
#endif
}

static struct bpf_map *caly_find_map(struct bpf_object *obj, const char *name)
{
	return bpf_object__find_map_by_name(obj, name);
}

static int caly_size_maps(struct bpf_object *obj, const struct fw_config *cfg)
{
	static const struct {
		const char *name;
		size_t      off;      /* offset of the __u32 in fw_config */
		__u32       fallback;
	} sized[] = {
		{ CALY_MAP_BAN_V4,   offsetof(struct fw_config,
					      max_ban_entries),     262144 },
		{ CALY_MAP_BAN_V6,   offsetof(struct fw_config,
					      max_ban_entries),     262144 },
		{ CALY_MAP_RATE_V4,  offsetof(struct fw_config,
					      max_rate_entries),    524288 },
		{ CALY_MAP_RATE_V6,  offsetof(struct fw_config,
					      max_rate_entries),    524288 },
		{ CALY_MAP_CONN,     offsetof(struct fw_config,
					      max_conn_entries),    262144 },
		{ CALY_MAP_SCAN_V4,  offsetof(struct fw_config,
					      max_scan_entries),    131072 },
		{ CALY_MAP_SCAN_V6,  offsetof(struct fw_config,
					      max_scan_entries),    131072 },
		{ CALY_MAP_TOP_V4,   offsetof(struct fw_config,
					      max_srcstat_entries), 131072 },
		{ CALY_MAP_TOP_V6,   offsetof(struct fw_config,
					      max_srcstat_entries), 131072 },
		{ CALY_MAP_ALLOW_V4, offsetof(struct fw_config,
					      max_allow_entries),    65536 },
		{ CALY_MAP_ALLOW_V6, offsetof(struct fw_config,
					      max_allow_entries),    65536 },
		{ CALY_MAP_BLOCK_V4, offsetof(struct fw_config,
					      max_block_entries),   262144 },
		{ CALY_MAP_BLOCK_V6, offsetof(struct fw_config,
					      max_block_entries),   262144 },
		{ CALY_MAP_IFACE,    offsetof(struct fw_config,
					      max_iface_entries),       64 },
	};
	unsigned int i;

	for (i = 0; i < sizeof(sized) / sizeof(sized[0]); i++) {
		struct bpf_map *m = caly_find_map(obj, sized[i].name);
		__u32 n;
		int err;

		if (m == NULL) {
			caly_err("BPF object is missing the map '%s'",
				 sized[i].name);
			return -1;
		}

		n = (cfg != NULL)
			? *(const __u32 *)((const char *)cfg + sized[i].off)
			: sized[i].fallback;
		if (n == 0)
			n = sized[i].fallback;

		err = caly_set_max_entries(m, n);
		if (err) {
			caly_err("cannot size map '%s' to %u entries: %s",
				 sized[i].name, n, strerror(-err > 0 ? -err
							    : errno));
			return -1;
		}
	}

	/* The two "our own prefixes" tries are small and fixed. */
	{
		const char *fixed[] = { CALY_MAP_LOCAL_V4, CALY_MAP_LOCAL_V6 };

		for (i = 0; i < 2; i++) {
			struct bpf_map *m = caly_find_map(obj, fixed[i]);

			if (m == NULL) {
				caly_err("BPF object is missing the map '%s'",
					 fixed[i]);
				return -1;
			}
			if (caly_set_max_entries(m, CALY_LOCAL_MAP_ENTRIES)) {
				caly_err("cannot size map '%s'", fixed[i]);
				return -1;
			}
		}
	}
	return 0;
}

/* Verify the LPM tries carry BPF_F_NO_PREALLOC.  A trie without it fails
 * creation with a bare -EINVAL, which is one of the least informative errors
 * in the whole BPF surface; catching it here turns it into a sentence. */
static int caly_check_lpm_flags(struct bpf_object *obj)
{
	static const char *const tries[] = {
		CALY_MAP_ALLOW_V4, CALY_MAP_ALLOW_V6,
		CALY_MAP_BLOCK_V4, CALY_MAP_BLOCK_V6,
		CALY_MAP_LOCAL_V4, CALY_MAP_LOCAL_V6,
	};
	unsigned int i;
	int bad = 0;

	for (i = 0; i < sizeof(tries) / sizeof(tries[0]); i++) {
		struct bpf_map *m = caly_find_map(obj, tries[i]);
		__u32 flags;

		if (m == NULL)
			continue;
		flags = bpf_map__map_flags(m);
		if ((flags & BPF_F_NO_PREALLOC) == 0) {
			caly_err("map '%s' is an LPM trie without "
				 "BPF_F_NO_PREALLOC; the kernel will reject "
				 "it with -EINVAL. Fix the map definition in "
				 "the BPF object.", tries[i]);
			bad = 1;
		}
	}
	return bad ? -1 : 0;
}

static int caly_set_pin_paths(struct bpf_object *obj, const char *pin_dir)
{
	int i;

	for (i = 0; i < CALY_MID_MAX; i++) {
		struct bpf_map *m = caly_find_map(obj, caly_maps[i].name);
		char path[PATH_MAX_SAFE];
		int err;

		if (m == NULL) {
			if (caly_maps[i].optional)
				continue;
			caly_err("BPF object is missing the map '%s'",
				 caly_maps[i].name);
			return -1;
		}

		if (caly_snprintf(path, sizeof(path), "%s/%s", pin_dir,
				  caly_maps[i].name) < 0) {
			caly_err("pin path for '%s' is too long",
				 caly_maps[i].name);
			return -1;
		}

		err = bpf_map__set_pin_path(m, path);
		if (err) {
			caly_err("cannot set the pin path for '%s': %s",
				 caly_maps[i].name, strerror(-err));
			return -1;
		}
	}
	return 0;
}

static int caly_collect_map_fds(struct caly_bpf *b)
{
	int i;

	for (i = 0; i < CALY_MID_MAX; i++) {
		struct bpf_map *m = caly_find_map(b->obj, caly_maps[i].name);

		b->map_fd[i] = -1;
		if (m == NULL) {
			if (caly_maps[i].optional)
				continue;
			caly_err("map '%s' vanished after load",
				 caly_maps[i].name);
			return -1;
		}
		b->map_fd[i] = bpf_map__fd(m);
		if (b->map_fd[i] < 0 && !caly_maps[i].optional) {
			caly_err("map '%s' has no descriptor after load",
				 caly_maps[i].name);
			return -1;
		}
	}
	return 0;
}

/* Populate caly_progs.  Slots we cannot fill are DELETED rather than left
 * alone: when a pinned prog array is reused across a restart, a stale entry
 * would tail-call into the previous generation's program. */
static int caly_fill_prog_array(struct caly_bpf *b)
{
	int progs_fd = b->map_fd[CALY_MID_PROGS];
	__u32 idx;

	if (progs_fd < 0) {
		caly_err("the tail-call program array is not available");
		return -1;
	}

	for (idx = 0; idx < CALY_PROG_IDX_MAX; idx++) {
		int fd = -1;

		if (idx == CALY_PROG_IDX_SYNPROXY)
			fd = b->prog_fd_synproxy;
		else if (idx == CALY_PROG_IDX_IPV6)
			fd = b->prog_fd_ipv6;

		if (fd >= 0) {
			if (bpf_map_update_elem(progs_fd, &idx, &fd,
						BPF_ANY) != 0) {
				caly_err("cannot install tail-call slot %u: "
					 "%s", idx, strerror(errno));
				return -1;
			}
			caly_debug("tail-call slot %u installed", idx);
		} else {
			/* An empty slot makes bpf_tail_call() fall through to
			 * the caller's fallback, which is exactly the
			 * behaviour the SYN proxy design depends on. */
			if (bpf_map_delete_elem(progs_fd, &idx) != 0 &&
			    errno != ENOENT)
				caly_debug("could not clear tail-call slot "
					   "%u: %s", idx, strerror(errno));
		}
	}
	return 0;
}

/*
 * One load attempt.  `enable_synproxy` and `enable_ringbuf` let the caller
 * retry with features removed after a verifier rejection.
 */
static int caly_load_attempt(struct caly_bpf *b,
			     const struct caly_load_opts *opts,
			     const struct fw_config *cfg,
			     int enable_synproxy, int enable_ringbuf)
{
	LIBBPF_OPTS(bpf_object_open_opts, oo);
	struct bpf_object *obj = NULL;
	struct bpf_program *p;
	int err;

	b->obj = NULL;
	b->prog_fd_main = -1;
	b->prog_fd_synproxy = -1;
	b->prog_fd_ipv6 = -1;
	b->prog_fd_tc_egress = -1;
	b->prog_fd_tc_ingress = -1;
	b->synproxy_loaded = 0;
	b->ringbuf_active = 0;

	oo.object_name = "calyanti";

	obj = bpf_object__open_file(b->obj_path, &oo);
	if (obj == NULL || libbpf_get_error(obj) != 0) {
		long e = obj != NULL ? libbpf_get_error(obj) : -errno;

		caly_err("cannot open the BPF object %s: %s", b->obj_path,
			 strerror((int)(e < 0 ? -e : e)));
		return -1;
	}
	b->obj = obj;

	/* ---- programs: decide autoload BEFORE load ---- */
	p = bpf_object__find_program_by_name(obj, CALY_PROG_XDP_MAIN);
	if (p == NULL) {
		caly_err("BPF object has no program named '%s'",
			 CALY_PROG_XDP_MAIN);
		goto fail;
	}

	p = bpf_object__find_program_by_name(obj, CALY_PROG_XDP_SYNPROXY);
	if (p != NULL) {
		if (!enable_synproxy) {
			/* The verifier never sees a program that calls a
			 * helper this kernel does not implement.  An inline
			 * call would fail verification for the ENTIRE object
			 * on every kernel without the helper. */
			if (bpf_program__set_autoload(p, false) != 0)
				caly_warn("cannot disable autoload for '%s'",
					  CALY_PROG_XDP_SYNPROXY);
			caly_info("SYN proxy program disabled: falling back "
				  "to per-source SYN rate limiting "
				  "(net.ipv4.tcp_syncookies=1)");
		}
	} else if (enable_synproxy) {
		caly_warn("BPF object has no '%s' program; the SYN proxy will "
			  "not be available", CALY_PROG_XDP_SYNPROXY);
	}

	/* ---- ring buffer map ---- */
	{
		struct bpf_map *rb = caly_find_map(obj, CALY_MAP_EVENTS_RB);

		if (rb != NULL) {
			if (enable_ringbuf) {
				__u32 sz = CALY_RINGBUF_BYTES;

				if (caly_set_max_entries(rb, sz) != 0)
					caly_warn("cannot size the ring "
						  "buffer, using the object "
						  "default");
				b->ringbuf_active = 1;
			} else {
#if CALY_HAVE_MAP_AUTOCREATE
				if (bpf_map__set_autocreate(rb, false) != 0) {
					caly_err("cannot disable the ring "
						 "buffer map");
					goto fail;
				}
				caly_info("ring buffer disabled; events go "
					  "through the perf event array");
#else
				caly_err("this kernel cannot provide "
					 "BPF_MAP_TYPE_RINGBUF and this "
					 "libbpf (%u.%u) has no "
					 "bpf_map__set_autocreate(), so the "
					 "map cannot be skipped. Rebuild "
					 "against libbpf >= 0.8, or install "
					 "on a kernel >= 5.8.",
					 (unsigned int)LIBBPF_MAJOR_VERSION,
					 (unsigned int)LIBBPF_MINOR_VERSION);
				goto fail;
#endif
			}
		} else if (enable_ringbuf) {
			caly_debug("BPF object has no ring buffer map; using "
				   "the perf event array");
		}
	}

	if (caly_size_maps(obj, cfg) != 0)
		goto fail;
	if (caly_check_lpm_flags(obj) != 0)
		goto fail;

	if (opts->reuse_pins) {
		if (caly_set_pin_paths(obj, b->pin_dir) != 0)
			goto fail;
	}

	err = bpf_object__load(obj);
	if (err) {
		caly_debug("bpf_object__load failed: %s", strerror(-err));
		errno = -err;
		goto fail;
	}

	/* ---- collect descriptors ---- */
	if (caly_collect_map_fds(b) != 0)
		goto fail;

	p = bpf_object__find_program_by_name(obj, CALY_PROG_XDP_MAIN);
	b->prog_fd_main = (p != NULL) ? bpf_program__fd(p) : -1;
	if (b->prog_fd_main < 0) {
		caly_err("'%s' did not load", CALY_PROG_XDP_MAIN);
		goto fail;
	}

	p = bpf_object__find_program_by_name(obj, CALY_PROG_XDP_SYNPROXY);
	if (p != NULL && enable_synproxy) {
		b->prog_fd_synproxy = bpf_program__fd(p);
		b->synproxy_loaded = b->prog_fd_synproxy >= 0;
	}

	p = bpf_object__find_program_by_name(obj, CALY_PROG_XDP_IPV6);
	if (p != NULL)
		b->prog_fd_ipv6 = bpf_program__fd(p);

	p = bpf_object__find_program_by_name(obj, CALY_PROG_TC_EGRESS);
	if (p != NULL)
		b->prog_fd_tc_egress = bpf_program__fd(p);

	/* Attached directly at clsact ingress (rung 3), never tail-called, so it
	 * has a program-name macro but no CALY_PROG_IDX_* slot. Used only if the
	 * BPF object happens to provide it. */
	p = bpf_object__find_program_by_name(obj, CALY_PROG_TC_INGRESS);
	if (p != NULL)
		b->prog_fd_tc_ingress = bpf_program__fd(p);

	if (caly_fill_prog_array(b) != 0)
		goto fail;

	return 0;

fail:
	if (b->obj != NULL) {
		bpf_object__close(b->obj);
		b->obj = NULL;
	}
	return -1;
}

int caly_bpf_load(struct caly_bpf *b, const struct caly_load_opts *opts,
		  const struct fw_config *cfg)
{
	struct caly_load_opts defaults;
	struct caly_features feat;
	int want_syn, want_rb;
	int i;

	if (b == NULL)
		return -1;

	if (opts == NULL) {
		memset(&defaults, 0, sizeof(defaults));
		defaults.reuse_pins = 1;
		defaults.want_synproxy = 1;
		defaults.want_ringbuf = 1;
		opts = &defaults;
	}

	feat = b->feat;
	if (feat.kver_code == 0 && caly_bpf_probe_features(&feat) != 0)
		return -1;

	memset(b->map_fd, 0, sizeof(b->map_fd));
	for (i = 0; i < CALY_MID_MAX; i++)
		b->map_fd[i] = -1;
	b->obj = NULL;
	b->pinned_only = 0;
	b->feat = feat;

	(void)caly_strlcpy(b->pin_dir,
			   opts->pin_dir != NULL ? opts->pin_dir
						 : CALY_PIN_DIR,
			   sizeof(b->pin_dir));

	if (opts->obj_path != NULL && opts->obj_path[0] != '\0') {
		if (caly_strlcpy(b->obj_path, opts->obj_path,
				 sizeof(b->obj_path)) >=
		    sizeof(b->obj_path)) {
			caly_err("BPF object path is too long");
			return -1;
		}
		if (!caly_file_exists(b->obj_path)) {
			caly_err("BPF object %s does not exist", b->obj_path);
			return -1;
		}
	} else if (caly_bpf_find_object(b->obj_path,
					sizeof(b->obj_path)) == NULL) {
		caly_err("cannot find %s. Set CALY_BPF_OBJECT or pass --obj.",
			 CALY_BPF_OBJ_NAME);
		return -1;
	}

	caly_libbpf_setup(opts->verbose_libbpf);

	want_syn = opts->want_synproxy && feat.have_synproxy;
	want_rb = opts->want_ringbuf && feat.have_ringbuf;

	caly_info("loading %s (synproxy=%s, ringbuf=%s)", b->obj_path,
		  want_syn ? "on" : "off", want_rb ? "on" : "off");

	if (caly_load_attempt(b, opts, cfg, want_syn, want_rb) == 0)
		goto loaded;

	/*
	 * Degrade rather than abort.  The first retry drops the SYN proxy,
	 * which is the only program that can be rejected purely because of a
	 * missing helper; the second drops the ring buffer, which is the only
	 * map that can be rejected purely because of a missing map type.
	 */
	if (want_syn) {
		caly_warn("load failed with the SYN proxy enabled; retrying "
			  "without it. The per-source SYN token bucket and "
			  "net.ipv4.tcp_syncookies=1 remain in effect.");
		want_syn = 0;
		if (caly_load_attempt(b, opts, cfg, want_syn, want_rb) == 0)
			goto loaded;
	}

	if (want_rb) {
		caly_warn("load failed with the ring buffer enabled; retrying "
			  "with the perf event array only");
		want_rb = 0;
		if (caly_load_attempt(b, opts, cfg, want_syn, want_rb) == 0)
			goto loaded;
	}

	/*
	 * Last resort: a pinned map from a previous generation with different
	 * dimensions makes reuse fail.  Drop the pins and try once more with
	 * a clean slate; state is lost but the daemon starts.
	 */
	if (opts->reuse_pins) {
		struct caly_load_opts nopin = *opts;

		caly_warn("load failed while reusing pinned maps in %s; "
			  "removing the stale pins and retrying. Existing "
			  "bans and conntrack state will be lost.",
			  b->pin_dir);
		nopin.reuse_pins = 0;
		if (caly_unpin_all(b->pin_dir) == 0 &&
		    caly_load_attempt(b, &nopin, cfg, want_syn, want_rb) == 0) {
			/* Re-pin explicitly since the pin paths were not set
			 * before load on this attempt. */
			for (i = 0; i < CALY_MID_MAX; i++) {
				struct bpf_map *m;
				char path[PATH_MAX_SAFE];

				m = caly_find_map(b->obj, caly_maps[i].name);
				if (m == NULL || bpf_map__fd(m) < 0)
					continue;
				if (caly_snprintf(path, sizeof(path), "%s/%s",
						  b->pin_dir,
						  caly_maps[i].name) < 0)
					continue;
				if (bpf_map__pin(m, path) != 0)
					caly_warn("cannot pin '%s': %s",
						  caly_maps[i].name,
						  strerror(errno));
			}
			goto loaded;
		}
	}

	caly_err("all load attempts failed for %s", b->obj_path);
	memset(b, 0, sizeof(*b));
	for (i = 0; i < CALY_MID_MAX; i++)
		b->map_fd[i] = -1;
	return -1;

loaded:
	/* Report the capabilities that were actually realised, not merely
	 * requested, so caly_config_apply_caps() sets CALY_F_CAP_SYNPROXY only
	 * when the program is really there (otherwise the main program pays for
	 * a failed tail call per SYN) and CALY_F_CAP_RINGBUF only when the ring
	 * buffer map is really active (otherwise the dataplane would write
	 * events into a map that does not exist). */
	b->feat.have_synproxy = b->synproxy_loaded ? 1 : 0;
	b->feat.have_ringbuf = b->ringbuf_active ? 1 : 0;

	caly_info("BPF object loaded; maps pinned under %s", b->pin_dir);
	if (b->synproxy_loaded)
		caly_info("SYN proxy active. It REQUIRES "
			  "net.ipv4.tcp_syncookies=2 (unconditional); at 1 "
			  "the kernel only honours cookies once the accept "
			  "queue overflows and the handshakes this program "
			  "completes will be rejected.");
	return 0;
}

int caly_bpf_open_pinned(struct caly_bpf *b, const char *pin_dir)
{
	int i;
	int found = 0;

	if (b == NULL)
		return -1;

	memset(b, 0, sizeof(*b));
	for (i = 0; i < CALY_MID_MAX; i++)
		b->map_fd[i] = -1;
	b->prog_fd_main = -1;
	b->prog_fd_synproxy = -1;
	b->prog_fd_ipv6 = -1;
	b->prog_fd_tc_egress = -1;
	b->prog_fd_tc_ingress = -1;
	b->pinned_only = 1;

	(void)caly_strlcpy(b->pin_dir, pin_dir != NULL ? pin_dir
						       : CALY_PIN_DIR,
			   sizeof(b->pin_dir));

	for (i = 0; i < CALY_MID_MAX; i++) {
		char path[PATH_MAX_SAFE];
		int fd;

		if (caly_snprintf(path, sizeof(path), "%s/%s", b->pin_dir,
				  caly_maps[i].name) < 0)
			continue;
		if (!caly_file_exists(path))
			continue;

		fd = bpf_obj_get(path);
		if (fd < 0) {
			caly_debug("cannot open the pin %s: %s", path,
				   strerror(errno));
			continue;
		}
		b->map_fd[i] = fd;
		found++;
	}

	if (found == 0) {
		caly_err("no pinned maps under %s: is the daemon running?",
			 b->pin_dir);
		return -1;
	}
	return 0;
}

void caly_bpf_close(struct caly_bpf *b)
{
	int i;

	if (b == NULL)
		return;

	if (b->pinned_only) {
		for (i = 0; i < CALY_MID_MAX; i++)
			caly_close_fd(&b->map_fd[i]);
	} else if (b->obj != NULL) {
		/* bpf_object__close() owns every map and program descriptor
		 * it handed us; closing them here would be a double close. */
		bpf_object__close(b->obj);
		b->obj = NULL;
		for (i = 0; i < CALY_MID_MAX; i++)
			b->map_fd[i] = -1;
	}

	b->prog_fd_main = -1;
	b->prog_fd_synproxy = -1;
	b->prog_fd_ipv6 = -1;
	b->prog_fd_tc_egress = -1;
	b->prog_fd_tc_ingress = -1;
}

int caly_bpf_map_fd(const struct caly_bpf *b, int map_id)
{
	if (b == NULL || map_id < 0 || map_id >= CALY_MID_MAX)
		return -1;
	return b->map_fd[map_id];
}

/* ================================================================== *
 * Config map access
 * ================================================================== */

int caly_bpf_config_write(const struct caly_bpf *b,
			  const struct fw_config *cfg)
{
	__u32 key = 0;
	int fd;

	if (b == NULL || cfg == NULL)
		return -1;

	fd = caly_bpf_map_fd(b, CALY_MID_CONFIG);
	if (fd < 0) {
		caly_err("the configuration map is not available");
		return -1;
	}

	/* One whole-struct update.  It is not atomic with respect to a
	 * concurrent dataplane read, so a handful of packets may observe a
	 * mixture of old and new thresholds.  That is a deliberate trade:
	 * every field is independently safe, and the alternative (a second
	 * config slot plus a generation pointer) costs a lookup per packet. */
	if (bpf_map_update_elem(fd, &key, cfg, BPF_ANY) != 0) {
		caly_err("cannot write the configuration map: %s",
			 strerror(errno));
		return -1;
	}
	return 0;
}

int caly_bpf_config_read(const struct caly_bpf *b, struct fw_config *cfg)
{
	__u32 key = 0;
	int fd;

	if (b == NULL || cfg == NULL)
		return -1;

	fd = caly_bpf_map_fd(b, CALY_MID_CONFIG);
	if (fd < 0)
		return -1;

	if (bpf_map_lookup_elem(fd, &key, cfg) != 0) {
		caly_err("cannot read the configuration map: %s",
			 strerror(errno));
		return -1;
	}
	return 0;
}

/* ================================================================== *
 * Seeding
 * ================================================================== */

int caly_icmp_type_is_mandatory(__u32 family, __u32 type)
{
	static const __u32 v6[CALY_ICMP6_MANDATORY_COUNT] =
		CALY_ICMP6_MANDATORY_INIT;
	static const __u32 v4[CALY_ICMP4_MANDATORY_COUNT] =
		CALY_ICMP4_MANDATORY_INIT;
	unsigned int i;

	if (family == CALY_AF_INET6) {
		for (i = 0; i < CALY_ICMP6_MANDATORY_COUNT; i++) {
			if (v6[i] == type)
				return 1;
		}
	} else if (family == CALY_AF_INET) {
		for (i = 0; i < CALY_ICMP4_MANDATORY_COUNT; i++) {
			if (v4[i] == type)
				return 1;
		}
	}
	return 0;
}

int caly_icmp_policy_set(const struct caly_bpf *b, __u32 family, __u32 type,
			 __u32 policy)
{
	int fd;
	__u32 key = type;
	__u32 val = policy;

	if (b == NULL || type > 255u) {
		errno = EINVAL;
		return -1;
	}
	if (policy >= CALY_ICMP_POL_MAX) {
		errno = EINVAL;
		return -1;
	}

	if (policy == CALY_ICMP_DROP && caly_icmp_type_is_mandatory(family,
								    type)) {
		caly_err("refusing to drop ICMPv%u type %u: it is mandatory. "
			 "%s",
			 family == CALY_AF_INET6 ? 6u : 4u, type,
			 family == CALY_AF_INET6
				? "IPv6 has no ARP - neighbour and router "
				  "discovery ARE ICMPv6, and type 2 is the "
				  "only PMTUD mechanism IPv6 has."
				: "Type 3 code 4 is Fragmentation Needed; "
				  "dropping it black-holes PMTUD and produces "
				  "the classic 'SSH connects then hangs'.");
		errno = EPERM;
		return -1;
	}

	fd = caly_bpf_map_fd(b, family == CALY_AF_INET6 ? CALY_MID_ICMP6_POL
							: CALY_MID_ICMP4_POL);
	if (fd < 0) {
		errno = ENOENT;
		return -1;
	}

	if (bpf_map_update_elem(fd, &key, &val, BPF_ANY) != 0) {
		caly_err("cannot set the ICMPv%u type %u policy: %s",
			 family == CALY_AF_INET6 ? 6u : 4u, type,
			 strerror(errno));
		return -1;
	}
	return 0;
}

int caly_port_rule_set(const struct caly_bpf *b, int is_udp, __u32 port,
		       const struct port_rule *rule)
{
	int fd;

	if (b == NULL || rule == NULL || port > 65535u) {
		errno = EINVAL;
		return -1;
	}

	fd = caly_bpf_map_fd(b, is_udp ? CALY_MID_PORT_UDP
				       : CALY_MID_PORT_TCP);
	if (fd < 0) {
		errno = ENOENT;
		return -1;
	}
	if (bpf_map_update_elem(fd, &port, rule, BPF_ANY) != 0) {
		caly_err("cannot set the %s/%u port rule: %s",
			 is_udp ? "udp" : "tcp", port, strerror(errno));
		return -1;
	}
	return 0;
}

int caly_port_rule_get(const struct caly_bpf *b, int is_udp, __u32 port,
		       struct port_rule *out)
{
	int fd;

	if (b == NULL || out == NULL || port > 65535u) {
		errno = EINVAL;
		return -1;
	}
	fd = caly_bpf_map_fd(b, is_udp ? CALY_MID_PORT_UDP
				       : CALY_MID_PORT_TCP);
	if (fd < 0) {
		errno = ENOENT;
		return -1;
	}
	return bpf_map_lookup_elem(fd, &port, out) == 0 ? 0 : -1;
}

int caly_iface_config_set(const struct caly_bpf *b,
			  const struct iface_config *ic)
{
	int fd;
	__u32 key;

	if (b == NULL || ic == NULL || ic->ifindex == 0) {
		errno = EINVAL;
		return -1;
	}

	fd = caly_bpf_map_fd(b, CALY_MID_IFACE);
	if (fd < 0) {
		errno = ENOENT;
		return -1;
	}

	key = ic->ifindex;
	if (bpf_map_update_elem(fd, &key, ic, BPF_ANY) != 0) {
		caly_err("cannot set the interface configuration for ifindex "
			 "%u: %s", ic->ifindex, strerror(errno));
		return -1;
	}
	return 0;
}

/*
 * Fill an ARRAY map's whole index space with one value.
 *
 * The 65536-entry port arrays are zero-filled by the kernel at creation, and
 * a zeroed struct port_rule has mode == CALY_PORT_CLOSED (0).  That is
 * indistinguishable from an explicit "closed" rule, so leaving the array
 * untouched would make every unconfigured port closed regardless of
 * CALY_F_DEFAULT_DENY.  Seeding the baseline explicitly removes the
 * ambiguity: after this call, "no rule" means whatever the operator's
 * default_deny setting says it means.
 */
static int caly_array_fill(int fd, __u32 entries, const void *value,
			   __u32 value_size, int use_batch)
{
	__u32 i;

	if (fd < 0)
		return -1;

#if CALY_LIBBPF_AT_LEAST(0, 2)
	if (use_batch) {
		__u32 *keys = calloc(CALY_SEED_BATCH, sizeof(__u32));
		char  *vals = calloc(CALY_SEED_BATCH, value_size);
		int ok = 1;

		if (keys == NULL || vals == NULL) {
			free(keys);
			free(vals);
			caly_warn("out of memory seeding an array map; "
				  "falling back to single updates");
		} else {
			for (i = 0; i < entries && ok; i += CALY_SEED_BATCH) {
				__u32 n = entries - i;
				__u32 j;

				if (n > CALY_SEED_BATCH)
					n = CALY_SEED_BATCH;
				for (j = 0; j < n; j++) {
					keys[j] = i + j;
					memcpy(vals + (size_t)j * value_size,
					       value, value_size);
				}
				if (bpf_map_update_batch(fd, keys, vals, &n,
							 NULL) != 0)
					ok = 0;
			}
			free(keys);
			free(vals);
			if (ok)
				return 0;
			caly_debug("batch update unsupported here (%s); "
				   "falling back to single updates",
				   strerror(errno));
		}
	}
#else
	(void)use_batch;
#endif

	for (i = 0; i < entries; i++) {
		if (bpf_map_update_elem(fd, &i, value, BPF_ANY) != 0) {
			caly_err("cannot seed array entry %u: %s", i,
				 strerror(errno));
			return -1;
		}
	}
	return 0;
}

/* The shipped ICMP policy from config/calyanti.conf.  Types not listed
 * default to DROP when CALY_F_ICMP_FILTER is set, matching the documented
 * behaviour "unlisted types default to drop when icmp_filter is on". */
struct caly_icmp_seed {
	__u32 type;
	__u32 policy;
};

static const struct caly_icmp_seed caly_icmp4_seed[] = {
	{ 0,  CALY_ICMP_PASS },       /* echo reply                     */
	{ 3,  CALY_ICMP_PASS },       /* dest unreachable - MANDATORY   */
	{ 8,  CALY_ICMP_RATELIMIT },  /* echo request                   */
	{ 11, CALY_ICMP_PASS },       /* time exceeded (traceroute)     */
	{ 12, CALY_ICMP_PASS },       /* parameter problem              */
};

static const struct caly_icmp_seed caly_icmp6_seed[] = {
	{ 1,   CALY_ICMP_PASS },
	{ 2,   CALY_ICMP_PASS },      /* packet too big - MANDATORY     */
	{ 3,   CALY_ICMP_PASS },
	{ 4,   CALY_ICMP_PASS },
	{ 128, CALY_ICMP_RATELIMIT },
	{ 129, CALY_ICMP_PASS },
	{ 130, CALY_ICMP_PASS },
	{ 131, CALY_ICMP_PASS },
	{ 132, CALY_ICMP_PASS },
	{ 133, CALY_ICMP_PASS },      /* router solicit  - MANDATORY    */
	{ 134, CALY_ICMP_PASS },      /* router advert   - MANDATORY    */
	{ 135, CALY_ICMP_PASS },      /* neighbour sol   - MANDATORY    */
	{ 136, CALY_ICMP_PASS },      /* neighbour advert- MANDATORY    */
	{ 137, CALY_ICMP_DROP },      /* redirect                       */
	{ 143, CALY_ICMP_PASS },      /* MLDv2 report                   */
};

static int caly_seed_icmp(const struct caly_bpf *b, const struct fw_config *cfg)
{
	static const __u32 mand6[CALY_ICMP6_MANDATORY_COUNT] =
		CALY_ICMP6_MANDATORY_INIT;
	static const __u32 mand4[CALY_ICMP4_MANDATORY_COUNT] =
		CALY_ICMP4_MANDATORY_INIT;
	__u32 base = (cfg->flags & CALY_F_ICMP_FILTER) ? CALY_ICMP_DROP
						       : CALY_ICMP_PASS;
	int fd4 = caly_bpf_map_fd(b, CALY_MID_ICMP4_POL);
	int fd6 = caly_bpf_map_fd(b, CALY_MID_ICMP6_POL);
	unsigned int i;

	if (fd4 < 0 || fd6 < 0) {
		caly_err("the ICMP policy maps are not available");
		return -1;
	}

	if (caly_array_fill(fd4, 256, &base, sizeof(base),
			    b->feat.have_batch_ops) != 0)
		return -1;
	if (caly_array_fill(fd6, 256, &base, sizeof(base),
			    b->feat.have_batch_ops) != 0)
		return -1;

	for (i = 0; i < sizeof(caly_icmp4_seed) / sizeof(caly_icmp4_seed[0]);
	     i++) {
		if (caly_icmp_policy_set(b, CALY_AF_INET,
					 caly_icmp4_seed[i].type,
					 caly_icmp4_seed[i].policy) != 0)
			return -1;
	}
	for (i = 0; i < sizeof(caly_icmp6_seed) / sizeof(caly_icmp6_seed[0]);
	     i++) {
		if (caly_icmp_policy_set(b, CALY_AF_INET6,
					 caly_icmp6_seed[i].type,
					 caly_icmp6_seed[i].policy) != 0)
			return -1;
	}

	/* Belt and braces: whatever the seed table says, the mandatory types
	 * end up permitted.  This is the last line of defence before the
	 * dataplane starts reading these maps. */
	for (i = 0; i < CALY_ICMP4_MANDATORY_COUNT; i++) {
		__u32 k = mand4[i], v = CALY_ICMP_PASS;

		if (bpf_map_update_elem(fd4, &k, &v, BPF_ANY) != 0) {
			caly_err("cannot force ICMPv4 type %u to pass: %s", k,
				 strerror(errno));
			return -1;
		}
	}
	for (i = 0; i < CALY_ICMP6_MANDATORY_COUNT; i++) {
		__u32 k = mand6[i], v = CALY_ICMP_PASS;

		if (bpf_map_update_elem(fd6, &k, &v, BPF_ANY) != 0) {
			caly_err("cannot force ICMPv6 type %u to pass: %s", k,
				 strerror(errno));
			return -1;
		}
	}
	return 0;
}

static int caly_seed_ports(const struct caly_bpf *b,
			   const struct fw_config *cfg)
{
	static const __u16 amp[CALY_AMP_PORTS_COUNT] = CALY_AMP_PORTS_INIT;
	struct port_rule base;
	struct port_rule r;
	int fd_tcp = caly_bpf_map_fd(b, CALY_MID_PORT_TCP);
	int fd_udp = caly_bpf_map_fd(b, CALY_MID_PORT_UDP);
	unsigned int i;

	if (fd_tcp < 0 || fd_udp < 0) {
		caly_err("the port policy maps are not available");
		return -1;
	}

	memset(&base, 0, sizeof(base));
	base.mode = (cfg->flags & CALY_F_DEFAULT_DENY) ? CALY_PORT_CLOSED
						       : CALY_PORT_OPEN;
	base.flags = 0;
	base.rate = 0;
	base.burst = 0;

	if (caly_array_fill(fd_tcp, 65536, &base, sizeof(base),
			    b->feat.have_batch_ops) != 0)
		return -1;
	if (caly_array_fill(fd_udp, 65536, &base, sizeof(base),
			    b->feat.have_batch_ops) != 0)
		return -1;

	/* Reflection sources.  The DESTINATION port drives mode; the SOURCE
	 * port is looked up in the same array for CALY_PORT_F_AMPLIFIER.  The
	 * two uses read different fields, which is what lets a real DNS server
	 * (dport 53, mode OPEN) coexist with the reflection filter (sport 53,
	 * amplifier flag). */
	if (cfg->flags & CALY_F_ANTI_AMPLIFY) {
		for (i = 0; i < CALY_AMP_PORTS_COUNT; i++) {
			__u32 p = amp[i];

			r = base;
			if (caly_port_rule_get(b, 1, p, &r) != 0)
				r = base;
			r.flags |= CALY_PORT_F_AMPLIFIER;
			if (caly_port_rule_set(b, 1, p, &r) != 0)
				return -1;
		}
		caly_debug("%u amplifier source ports flagged in %s",
			   CALY_AMP_PORTS_COUNT, CALY_MAP_PORT_UDP);
	}

	/* Management ports: open, flagged, never dropped.  Seeded AFTER the
	 * bulk fill so the baseline cannot overwrite them. */
	for (i = 0; i < cfg->mgmt_tcp_count && i < CALY_MGMT_PORTS_MAX; i++) {
		__u32 p = cfg->mgmt_tcp_ports[i];

		if (p == 0 || p > 65535u)
			continue;
		r = base;
		if (caly_port_rule_get(b, 0, p, &r) != 0)
			r = base;
		r.mode = CALY_PORT_OPEN;
		r.flags |= CALY_PORT_F_MGMT;
		if (caly_port_rule_set(b, 0, p, &r) != 0)
			return -1;
	}
	for (i = 0; i < cfg->mgmt_udp_count && i < CALY_MGMT_PORTS_MAX; i++) {
		__u32 p = cfg->mgmt_udp_ports[i];

		if (p == 0 || p > 65535u)
			continue;
		r = base;
		if (caly_port_rule_get(b, 1, p, &r) != 0)
			r = base;
		r.mode = CALY_PORT_OPEN;
		r.flags |= CALY_PORT_F_MGMT;
		if (caly_port_rule_set(b, 1, p, &r) != 0)
			return -1;
	}

	return 0;
}

int caly_bpf_seed_maps(const struct caly_bpf *b, const struct fw_config *cfg)
{
	if (b == NULL || cfg == NULL)
		return -1;

	if (caly_seed_ports(b, cfg) != 0)
		return -1;
	if (caly_seed_icmp(b, cfg) != 0)
		return -1;
	return 0;
}

/* ================================================================== *
 * Attach / detach
 * ================================================================== */

/* Resolve a program id to its kernel object name.  Returns 0 on success. */
static int caly_prog_name_by_id(__u32 prog_id, char *name, size_t len)
{
	struct bpf_prog_info info;
	__u32 info_len = sizeof(info);
	int fd;
	int rc = -1;

	if (name == NULL || len == 0)
		return -1;
	name[0] = '\0';

	fd = bpf_prog_get_fd_by_id(prog_id);
	if (fd < 0)
		return -1;

	memset(&info, 0, sizeof(info));
	if (bpf_obj_get_info_by_fd(fd, &info, &info_len) == 0) {
		char tmp[BPF_OBJ_NAME_LEN + 1];

		memcpy(tmp, info.name, BPF_OBJ_NAME_LEN);
		tmp[BPF_OBJ_NAME_LEN] = '\0';
		rc = (caly_strlcpy(name, tmp, len) >= len) ? -1 : 0;
	}
	(void)close(fd);
	return rc;
}

/*
 * Is the program currently attached one of ours?
 *
 * Program names are truncated by the kernel to BPF_OBJ_NAME_LEN-1 = 15
 * characters, so "caly_xdp_synproxy" is stored as "caly_xdp_synpro".  Testing
 * the "caly_" prefix is therefore both necessary and sufficient.
 */
static int caly_prog_is_ours(__u32 prog_id, char *name, size_t len)
{
	char tmp[BPF_OBJ_NAME_LEN + 1];

	if (caly_prog_name_by_id(prog_id, tmp, sizeof(tmp)) != 0)
		return -1;
	if (name != NULL && len > 0)
		(void)caly_strlcpy(name, tmp, len);
	return caly_str_startswith(tmp, "caly_") ? 1 : 0;
}

/* Which XDP mode is the program on `ifindex` attached in?  Returns the
 * XDP_FLAGS_* mode bit, or 0 when nothing is attached. */
static __u32 caly_xdp_current_mode(int ifindex, __u32 *prog_id_out)
{
	static const __u32 modes[] = {
		XDP_FLAGS_DRV_MODE, XDP_FLAGS_SKB_MODE, XDP_FLAGS_HW_MODE
	};
	unsigned int i;
	__u32 id = 0;

	if (prog_id_out != NULL)
		*prog_id_out = 0;

	for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
		id = 0;
		if (caly_xdp_query_compat(ifindex, modes[i], &id) == 0 &&
		    id != 0) {
			if (prog_id_out != NULL)
				*prog_id_out = id;
			return modes[i];
		}
	}

	/* Attached, but the mode query did not say which. */
	id = 0;
	if (caly_xdp_query_compat(ifindex, 0, &id) == 0 && id != 0) {
		if (prog_id_out != NULL)
			*prog_id_out = id;
		return 0;
	}
	return 0;
}

static const char *caly_xdp_mode_str(__u32 flags)
{
	if (flags & XDP_FLAGS_DRV_MODE)
		return "native";
	if (flags & XDP_FLAGS_SKB_MODE)
		return "generic";
	if (flags & XDP_FLAGS_HW_MODE)
		return "offload";
	return "unspecified";
}

/*
 * Attach a SCHED_CLS program at a clsact hook (ingress or egress).  Shared by
 * the tc-ingress dataplane fallback and the egress conntrack hook.  Returns 0
 * on success, -1 otherwise (errno meaningful).
 */
#if CALY_LIBBPF_AT_LEAST(0, 6)
static int caly_tc_attach_point(unsigned int ifindex, const char *ifname,
				int prog_fd, int is_ingress)
{
	LIBBPF_OPTS(bpf_tc_hook, hook);
	LIBBPF_OPTS(bpf_tc_opts, tcopts);
	int err;

	if (prog_fd < 0) {
		errno = ENOENT;
		return -1;
	}

	hook.ifindex = (int)ifindex;
	hook.attach_point = is_ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS;

	err = bpf_tc_hook_create(&hook);
	if (err != 0 && err != -EEXIST) {
		caly_warn("cannot create the clsact %s hook on %s: %s",
			  is_ingress ? "ingress" : "egress",
			  ifname != NULL ? ifname : "?", strerror(-err));
		errno = -err;
		return -1;
	}

	tcopts.prog_fd = prog_fd;
	tcopts.handle = 1;
	tcopts.priority = 1;

	err = bpf_tc_attach(&hook, &tcopts);
	if (err != 0) {
		caly_warn("cannot attach to the %s %s hook: %s",
			  ifname != NULL ? ifname : "?",
			  is_ingress ? "ingress" : "egress", strerror(-err));
		errno = -err;
		return -1;
	}
	return 0;
}
#endif

/*
 * Rung-3 fallback: when XDP cannot attach in any mode (typically a container
 * or an OpenVZ/LXC guest where XDP is unavailable), attach the SCHED_CLS
 * ingress program at the clsact hook instead.  Requires the BPF object to
 * provide a 'caly_tc_ingress' program; if it does not, XDP failure stays
 * fatal for that interface.  Returns 0 on success.
 */
static int caly_attach_tc_ingress_fallback(struct caly_bpf *b,
					   unsigned int ifindex,
					   const char *ifname,
					   struct caly_link *out)
{
#if CALY_LIBBPF_AT_LEAST(0, 6)
	if (b->prog_fd_tc_ingress < 0)
		return -1;

	if (caly_tc_attach_point(ifindex, ifname, b->prog_fd_tc_ingress,
				 1) != 0)
		return -1;

	out->tc_attached = 1;
	out->active = 1;
	out->dataplane = CALY_DP_TC;
	caly_info("XDP is unavailable on %s; attached the tc/clsact ingress "
		  "dataplane instead (ladder rung 3)", ifname);
	return 0;
#else
	(void)b;
	(void)ifindex;
	(void)ifname;
	(void)out;
	return -1;
#endif
}

int caly_bpf_attach(struct caly_bpf *b, const char *ifname, __u32 xdp_pref,
		    int force, struct caly_link *out)
{
	__u32 try_flags[3];
	unsigned int ntry = 0, i;
	unsigned int ifindex;
	__u32 existing_id = 0;
	__u32 existing_mode;

	if (b == NULL || ifname == NULL || out == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (b->prog_fd_main < 0) {
		caly_err("no main XDP program is loaded");
		errno = ENOENT;
		return -1;
	}

	ifindex = caly_if_index(ifname);
	if (ifindex == 0) {
		caly_err("interface '%s' does not exist", ifname);
		errno = ENODEV;
		return -1;
	}

	memset(out, 0, sizeof(*out));
	out->ifindex = ifindex;
	(void)caly_strlcpy(out->ifname, ifname, sizeof(out->ifname));

	/* ---- deal with anything already attached ---- */
	existing_mode = caly_xdp_current_mode((int)ifindex, &existing_id);
	if (existing_id != 0) {
		char name[BPF_OBJ_NAME_LEN + 1];
		int ours = caly_prog_is_ours(existing_id, name, sizeof(name));

		if (ours == 1) {
			caly_info("replacing our own XDP program (id %u, %s) "
				  "on %s", existing_id,
				  caly_xdp_mode_str(existing_mode), ifname);
		} else if (force) {
			caly_warn("forcibly replacing the XDP program '%s' "
				  "(id %u) on %s", name[0] ? name : "?",
				  existing_id, ifname);
		} else {
			caly_err("a foreign XDP program '%s' (id %u) is "
				 "attached to %s; refusing to replace it. "
				 "Pass --force if that is what you want.",
				 name[0] ? name : "?", existing_id, ifname);
			errno = EBUSY;
			return -1;
		}

		if (caly_xdp_detach_compat((int)ifindex, existing_mode) != 0) {
			/* Retry with unspecified flags: some drivers report a
			 * mode on query that they will not accept on detach. */
			if (caly_xdp_detach_compat((int)ifindex, 0) != 0) {
				caly_err("cannot detach the existing XDP "
					 "program from %s: %s", ifname,
					 strerror(errno));
				return -1;
			}
		}
	}

	/* ---- build the attach-mode preference list ---- */
	switch (xdp_pref) {
	case CALY_XDP_NATIVE:
		try_flags[ntry++] = XDP_FLAGS_DRV_MODE;
		break;
	case CALY_XDP_GENERIC:
		try_flags[ntry++] = XDP_FLAGS_SKB_MODE;
		break;
	case CALY_XDP_OFFLOAD:
		try_flags[ntry++] = XDP_FLAGS_HW_MODE;
		break;
	case CALY_XDP_AUTO:
	default:
		try_flags[ntry++] = XDP_FLAGS_DRV_MODE;
		try_flags[ntry++] = XDP_FLAGS_SKB_MODE;
		break;
	}

	for (i = 0; i < ntry; i++) {
		int err = caly_xdp_attach_compat((int)ifindex, b->prog_fd_main,
						 try_flags[i]);

		if (err == 0) {
			__u32 id = 0;

			out->xdp_flags = try_flags[i];
			out->xdp_attached = 1;
			out->active = 1;
			(void)caly_xdp_query_compat((int)ifindex,
						    try_flags[i], &id);
			out->prog_id = id;

			if (try_flags[i] & XDP_FLAGS_DRV_MODE) {
				out->dataplane = CALY_DP_XDP_NATIVE;
			} else if (try_flags[i] & XDP_FLAGS_HW_MODE) {
				out->dataplane = CALY_DP_XDP_NATIVE;
			} else {
				out->dataplane = CALY_DP_XDP_GENERIC;
			}

			caly_info("attached to %s in %s mode (prog id %u)",
				  ifname, caly_xdp_mode_str(try_flags[i]), id);

			if (out->dataplane == CALY_DP_XDP_GENERIC)
				caly_warn("%s is running XDP in generic "
					  "(skb) mode: roughly 5x slower than "
					  "native, and XDP_TX is slow enough "
					  "that the SYN proxy is better left "
					  "off on this interface", ifname);
			return 0;
		}

		caly_debug("attach to %s in %s mode failed: %s", ifname,
			   caly_xdp_mode_str(try_flags[i]),
			   strerror(err < 0 ? -err : errno));
	}

	if (xdp_pref != CALY_XDP_AUTO) {
		char drv[64];

		if (caly_if_driver(ifname, drv, sizeof(drv)) != 0)
			(void)caly_strlcpy(drv, "unknown", sizeof(drv));
		caly_err("cannot attach to %s in the requested %s mode "
			 "(driver '%s'). Pinning to a rung the NIC cannot "
			 "provide is a fatal error by design: silently "
			 "running a weaker dataplane than you asked for is "
			 "worse than refusing to start.",
			 ifname, caly_xdp_mode_str(try_flags[0]), drv);
		errno = EOPNOTSUPP;
		return -1;
	}

	/* AUTO: XDP failed in every mode. Descend the ladder to tc/clsact
	 * ingress if the object carries a SCHED_CLS program for it. */
	caly_warn("XDP would not attach to %s in any mode; trying the "
		  "tc/clsact fallback", ifname);
	if (caly_attach_tc_ingress_fallback(b, ifindex, ifname, out) == 0)
		return 0;

	caly_err("cannot attach any eBPF dataplane to %s. If this host is a "
		 "container or OpenVZ/LXC guest, XDP and tc-BPF may both be "
		 "unavailable; the installer's documented fallback is "
		 "nftables (ladder rung 4).", ifname);
	errno = EOPNOTSUPP;
	return -1;
}

int caly_bpf_attach_tc_egress(struct caly_bpf *b, struct caly_link *link)
{
#if CALY_LIBBPF_AT_LEAST(0, 6)
	if (b == NULL || link == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (b->prog_fd_tc_egress < 0) {
		caly_debug("no '%s' program in the object; outbound flows "
			   "will not be learned by the egress hook",
			   CALY_PROG_TC_EGRESS);
		return -1;
	}

	if (caly_tc_attach_point(link->ifindex, link->ifname,
				 b->prog_fd_tc_egress, 0) != 0) {
		/* Leave the qdisc in place: another filter may be using it. */
		return -1;
	}

	link->tc_attached = 1;
	caly_info("clsact egress hook attached on %s; outbound-initiated "
		  "flows will be learned into conntrack", link->ifname);
	return 0;
#else
	(void)b;
	caly_warn("this libbpf (%u.%u) has no TC API; the clsact egress hook "
		  "is unavailable and outbound-initiated UDP replies will "
		  "fall through to the port policy",
		  (unsigned int)LIBBPF_MAJOR_VERSION,
		  (unsigned int)LIBBPF_MINOR_VERSION);
	if (link != NULL)
		link->tc_attached = 0;
	errno = ENOTSUP;
	return -1;
#endif
}

static int caly_tc_detach(unsigned int ifindex, const char *ifname)
{
#if CALY_LIBBPF_AT_LEAST(0, 6)
	/* Remove both hooks we might have installed: the egress conntrack hook
	 * and, when XDP was unavailable, the ingress dataplane fallback.
	 * Removing a hook that is not present returns -ENOENT/-EINVAL, which
	 * is not an error here. */
	static const int points[2] = { BPF_TC_EGRESS, BPF_TC_INGRESS };
	int rc = 0;
	int i;

	for (i = 0; i < 2; i++) {
		LIBBPF_OPTS(bpf_tc_hook, hook);
		LIBBPF_OPTS(bpf_tc_opts, tcopts);
		int err;

		hook.ifindex = (int)ifindex;
		hook.attach_point = points[i];

		tcopts.handle = 1;
		tcopts.priority = 1;
		tcopts.prog_fd = 0;
		tcopts.prog_id = 0;
		tcopts.flags = 0;

		err = bpf_tc_detach(&hook, &tcopts);
		if (err != 0 && err != -ENOENT && err != -EINVAL) {
			caly_debug("cannot detach the tc %s filter from %s: %s",
				   points[i] == BPF_TC_INGRESS ? "ingress"
							       : "egress",
				   ifname != NULL ? ifname : "?",
				   strerror(-err));
			rc = -1;
		}
	}
	return rc;
#else
	(void)ifindex;
	(void)ifname;
	return 0;
#endif
}

int caly_bpf_detach_link(struct caly_link *link, int force)
{
	int rc = 0;

	if (link == NULL)
		return -1;
	if (!link->active && !link->xdp_attached && !link->tc_attached)
		return 0;

	if (link->tc_attached) {
		if (caly_tc_detach(link->ifindex, link->ifname) == 0)
			link->tc_attached = 0;
		else
			rc = -1;
	}

	if (link->xdp_attached) {
		__u32 id = 0;
		int ours;

		/* Only detach if what is attached is still ours: between
		 * attach and shutdown, an operator may have replaced it. */
		(void)caly_xdp_query_compat((int)link->ifindex,
					    link->xdp_flags, &id);
		if (id == 0) {
			link->xdp_attached = 0;
		} else {
			ours = caly_prog_is_ours(id, NULL, 0);
			if (ours == 1 || force || id == link->prog_id) {
				if (caly_xdp_detach_compat((int)link->ifindex,
							   link->xdp_flags)
				    != 0 &&
				    caly_xdp_detach_compat((int)link->ifindex,
							   0) != 0) {
					caly_warn("cannot detach XDP from "
						  "%s: %s", link->ifname,
						  strerror(errno));
					rc = -1;
				} else {
					caly_info("detached from %s",
						  link->ifname);
					link->xdp_attached = 0;
				}
			} else {
				caly_warn("%s now carries a foreign XDP "
					  "program (id %u); leaving it alone",
					  link->ifname, id);
				link->xdp_attached = 0;
			}
		}
	}

	link->active = 0;
	return rc;
}

int caly_bpf_detach_iface(const char *ifname, int force)
{
	struct caly_link link;
	unsigned int ifindex;
	__u32 id = 0;
	__u32 mode;
	int ours;

	if (ifname == NULL)
		return -1;

	ifindex = caly_if_index(ifname);
	if (ifindex == 0)
		return -1;

	mode = caly_xdp_current_mode((int)ifindex, &id);
	if (id == 0) {
		/* Nothing attached; still try to clear a stale tc filter. */
		(void)caly_tc_detach(ifindex, ifname);
		return 0;
	}

	ours = caly_prog_is_ours(id, NULL, 0);
	if (ours != 1 && !force) {
		caly_debug("%s carries a foreign XDP program (id %u); leaving "
			   "it alone", ifname, id);
		return 0;
	}

	memset(&link, 0, sizeof(link));
	link.ifindex = ifindex;
	(void)caly_strlcpy(link.ifname, ifname, sizeof(link.ifname));
	link.xdp_flags = mode;
	link.prog_id = id;
	link.xdp_attached = 1;
	link.tc_attached = 1;
	link.active = 1;

	if (caly_bpf_detach_link(&link, force) != 0)
		return -1;
	return 1;
}

int caly_xdp_iface_status(const char *ifname, __u32 *prog_id, __u32 *mode,
			  int *is_ours)
{
	unsigned int ifindex;
	__u32 id = 0;
	__u32 m;

	if (prog_id != NULL)
		*prog_id = 0;
	if (mode != NULL)
		*mode = 0;
	if (is_ours != NULL)
		*is_ours = 0;

	if (ifname == NULL)
		return -1;
	ifindex = caly_if_index(ifname);
	if (ifindex == 0)
		return -1;

	m = caly_xdp_current_mode((int)ifindex, &id);
	if (id == 0)
		return 0;

	if (prog_id != NULL)
		*prog_id = id;
	if (mode != NULL)
		*mode = m;
	if (is_ours != NULL)
		*is_ours = caly_prog_is_ours(id, NULL, 0) == 1 ? 1 : 0;
	return 1;
}

int caly_unpin_all(const char *pin_dir)
{
	int i;
	int rc = 0;

	if (pin_dir == NULL)
		pin_dir = CALY_PIN_DIR;

	for (i = 0; i < CALY_MID_MAX; i++) {
		char path[PATH_MAX_SAFE];

		if (caly_snprintf(path, sizeof(path), "%s/%s", pin_dir,
				  caly_maps[i].name) < 0)
			continue;
		if (unlink(path) != 0 && errno != ENOENT) {
			caly_warn("cannot remove the pin %s: %s", path,
				  strerror(errno));
			rc = -1;
		}
	}

	if (rmdir(pin_dir) != 0 && errno != ENOENT && errno != ENOTEMPTY)
		caly_debug("cannot remove %s: %s", pin_dir, strerror(errno));

	return rc;
}

int caly_unload_everything(const char *pin_dir, int force)
{
	struct caly_if_entry ifs[256];
	int n, i;
	int cleaned = 0;

	n = caly_if_enumerate(ifs, (int)(sizeof(ifs) / sizeof(ifs[0])));
	if (n < 0) {
		caly_err("cannot enumerate interfaces: %s", strerror(errno));
		n = 0;
	}

	/*
	 * Discovering attachments from the kernel rather than from a state
	 * file is what makes this survive a crashed previous instance: there
	 * is no file to be stale.
	 */
	for (i = 0; i < n; i++) {
		int r = caly_bpf_detach_iface(ifs[i].name, force);

		if (r > 0)
			cleaned++;
	}

	if (caly_unpin_all(pin_dir) != 0)
		caly_warn("some pins under %s could not be removed",
			  pin_dir != NULL ? pin_dir : CALY_PIN_DIR);

	caly_info("unload complete: %d interface(s) cleaned", cleaned);
	return cleaned;
}

/* ================================================================== *
 * Counters
 * ================================================================== */

/* Per-CPU map values are padded to 8 bytes per CPU by the kernel; for a __u64
 * value that is exactly sizeof(__u64), but the rounding is spelled out so the
 * buffer stays correct if the value type ever changes. */
static size_t caly_percpu_stride(size_t value_size)
{
	return (value_size + 7u) & ~(size_t)7u;
}

static int caly_percpu_sum(int fd, __u32 key, __u64 *out, long ncpus,
			   void *scratch)
{
	size_t stride = caly_percpu_stride(sizeof(__u64));
	long c;
	__u64 sum = 0;

	if (fd < 0 || out == NULL || scratch == NULL)
		return -1;

	if (bpf_map_lookup_elem(fd, &key, scratch) != 0) {
		if (errno == ENOENT) {
			*out = 0;
			return 0;
		}
		return -1;
	}

	for (c = 0; c < ncpus; c++) {
		__u64 v;

		memcpy(&v, (char *)scratch + (size_t)c * stride, sizeof(v));
		sum += v;
	}
	*out = sum;
	return 0;
}

int caly_bpf_read_gauges(const struct caly_bpf *b, __u64 *out, unsigned int n)
{
	long ncpus;
	void *scratch;
	unsigned int i;
	int fd;
	int rc = 0;

	if (b == NULL || out == NULL || n == 0)
		return -1;

	fd = caly_bpf_map_fd(b, CALY_MID_GLOBAL);
	if (fd < 0)
		return -1;

	ncpus = libbpf_num_possible_cpus();
	if (ncpus <= 0)
		ncpus = caly_num_possible_cpus();
	if (ncpus <= 0)
		return -1;

	scratch = calloc((size_t)ncpus, caly_percpu_stride(sizeof(__u64)));
	if (scratch == NULL) {
		caly_err("out of memory reading the gauge map");
		return -1;
	}

	for (i = 0; i < n && i < CALY_G_MAX; i++) {
		if (caly_percpu_sum(fd, i, &out[i], ncpus, scratch) != 0) {
			out[i] = 0;
			rc = -1;
		}
	}
	for (; i < n; i++)
		out[i] = 0;

	free(scratch);
	return rc;
}

int caly_bpf_read_stats(const struct caly_bpf *b, __u64 *pkts, __u64 *bytes,
			unsigned int n)
{
	long ncpus;
	void *scratch;
	unsigned int i;
	int fd_p, fd_b;
	int rc = 0;

	if (b == NULL || n == 0)
		return -1;
	if (pkts == NULL && bytes == NULL)
		return -1;

	fd_p = caly_bpf_map_fd(b, CALY_MID_STATS);
	fd_b = caly_bpf_map_fd(b, CALY_MID_STATS_B);

	ncpus = libbpf_num_possible_cpus();
	if (ncpus <= 0)
		ncpus = caly_num_possible_cpus();
	if (ncpus <= 0)
		return -1;

	scratch = calloc((size_t)ncpus, caly_percpu_stride(sizeof(__u64)));
	if (scratch == NULL) {
		caly_err("out of memory reading the statistics maps");
		return -1;
	}

	for (i = 0; i < n; i++) {
		if (pkts != NULL) {
			if (fd_p < 0 ||
			    caly_percpu_sum(fd_p, i, &pkts[i], ncpus,
					    scratch) != 0) {
				pkts[i] = 0;
				rc = -1;
			}
		}
		if (bytes != NULL) {
			if (fd_b < 0 ||
			    caly_percpu_sum(fd_b, i, &bytes[i], ncpus,
					    scratch) != 0) {
				bytes[i] = 0;
				rc = -1;
			}
		}
	}

	free(scratch);
	return rc;
}

/* ================================================================== *
 * Event source
 * ================================================================== */

struct caly_event_src {
	struct perf_buffer *pb;
	struct ring_buffer *rb;
	int   epoll_fd;       /* fd the daemon adds to its own epoll set     */
	int   own_epoll_fd;   /* >=0 when we created epoll_fd and must close */
	int   use_ring;       /* 1 when the ring buffer is the primary xport */
	caly_event_fn on_event;
	caly_lost_fn  on_lost;
	void *ctx;
};

static void caly_pb_sample(void *ctx, int cpu, void *data, __u32 size)
{
	struct caly_event_src *src = ctx;

	(void)cpu;
	if (src != NULL && src->on_event != NULL)
		src->on_event(src->ctx, data, size);
}

static void caly_pb_lost(void *ctx, int cpu, __u64 cnt)
{
	struct caly_event_src *src = ctx;

	if (src != NULL && src->on_lost != NULL)
		src->on_lost(src->ctx, cpu, cnt);
}

#if CALY_LIBBPF_AT_LEAST(0, 8)
static int caly_rb_sample(void *ctx, void *data, size_t size)
{
	struct caly_event_src *src = ctx;

	if (src != NULL && src->on_event != NULL)
		src->on_event(src->ctx, data, (__u32)size);
	return 0;
}
#endif

struct caly_event_src *caly_events_open(const struct caly_bpf *b,
					const struct fw_config *cfg,
					caly_event_fn on_event,
					caly_lost_fn on_lost, void *ctx)
{
	struct caly_event_src *src;
	int rb_fd, pb_fd;
	int rb_epoll = -1, pb_epoll = -1;
	size_t pages;

	if (b == NULL || on_event == NULL)
		return NULL;

	src = calloc(1, sizeof(*src));
	if (src == NULL) {
		caly_err("out of memory opening the event source");
		return NULL;
	}
	src->epoll_fd = -1;
	src->own_epoll_fd = -1;
	src->on_event = on_event;
	src->on_lost = on_lost;
	src->ctx = ctx;

	rb_fd = caly_bpf_map_fd(b, CALY_MID_EVENTS_RB);
	pb_fd = caly_bpf_map_fd(b, CALY_MID_EVENTS);
	pages = (cfg != NULL && cfg->event_pages > 0) ? cfg->event_pages : 16;

#if CALY_LIBBPF_AT_LEAST(0, 8)
	if (b->ringbuf_active && rb_fd >= 0) {
		src->rb = ring_buffer__new(rb_fd, caly_rb_sample, src, NULL);
		if (src->rb != NULL) {
			src->use_ring = 1;
			rb_epoll = ring_buffer__epoll_fd(src->rb);
		} else {
			caly_warn("cannot open the ring buffer (%s); using the "
				  "perf event array only", strerror(errno));
		}
	}
#else
	(void)rb_fd;
#endif

	/*
	 * ALWAYS open the perf event array as well, even when the ring buffer
	 * is active.  The main XDP program emits to whichever transport loaded,
	 * but the SYN-proxy tail call and the tc ingress/egress programs emit
	 * ONLY to caly_events (the perf array) on every kernel.  If the ring
	 * buffer were the sole reader, every synproxy/tc event would be silently
	 * dropped on kernels >= 5.8 - exactly under a SYN flood.  A given event
	 * is written to one map only, so draining both never double-delivers.
	 */
	if (pb_fd >= 0) {
#if CALY_LIBBPF_AT_LEAST(0, 6)
		src->pb = perf_buffer__new(pb_fd, pages, caly_pb_sample,
					   caly_pb_lost, src, NULL);
#else
		{
			struct perf_buffer_opts pbo;

			memset(&pbo, 0, sizeof(pbo));
			pbo.sample_cb = caly_pb_sample;
			pbo.lost_cb = caly_pb_lost;
			pbo.ctx = src;
			src->pb = perf_buffer__new(pb_fd, pages, &pbo);
		}
#endif
		if (src->pb == NULL || libbpf_get_error(src->pb) != 0) {
			src->pb = NULL;   /* may be an ERR_PTR; do not free it */
			if (src->rb == NULL) {
				caly_err("cannot open the perf event buffer: %s",
					 strerror(errno));
				caly_events_close(src);
				return NULL;
			}
			caly_warn("cannot open the perf event buffer (%s); "
				  "synproxy/tc events will not be visible",
				  strerror(errno));
		} else {
			pb_epoll = perf_buffer__epoll_fd(src->pb);
		}
	}

	if (src->rb == NULL && src->pb == NULL) {
		caly_err("neither event transport is available");
		caly_events_close(src);
		return NULL;
	}

	/*
	 * Hand the daemon a single epoll fd and a single consume entry point.
	 * When both transports are open we own an epoll set that watches both
	 * underlying fds, so the caller's one-fd/one-consume abstraction still
	 * holds while caly_events_consume() drains both.
	 */
	if (rb_epoll >= 0 && pb_epoll >= 0) {
		struct epoll_event ee;
		int ep = epoll_create1(EPOLL_CLOEXEC);

		if (ep < 0) {
			caly_err("cannot create the combined event epoll: %s",
				 strerror(errno));
			caly_events_close(src);
			return NULL;
		}
		memset(&ee, 0, sizeof(ee));
		ee.events = EPOLLIN;
		ee.data.fd = rb_epoll;
		if (epoll_ctl(ep, EPOLL_CTL_ADD, rb_epoll, &ee) != 0) {
			caly_err("cannot watch the ring buffer fd: %s",
				 strerror(errno));
			close(ep);
			caly_events_close(src);
			return NULL;
		}
		ee.data.fd = pb_epoll;
		if (epoll_ctl(ep, EPOLL_CTL_ADD, pb_epoll, &ee) != 0) {
			caly_err("cannot watch the perf event fd: %s",
				 strerror(errno));
			close(ep);
			caly_events_close(src);
			return NULL;
		}
		src->epoll_fd = ep;
		src->own_epoll_fd = ep;
		caly_info("event source: ring buffer + perf event array "
			  "(%zu pages/CPU)", pages);
	} else if (rb_epoll >= 0) {
		src->epoll_fd = rb_epoll;
		caly_info("event source: ring buffer");
	} else {
		src->epoll_fd = pb_epoll;
		caly_info("event source: perf event array (%zu pages/CPU)",
			  pages);
	}

	return src;
}

int caly_events_epoll_fd(const struct caly_event_src *src)
{
	return src != NULL ? src->epoll_fd : -1;
}

int caly_events_is_ring(const struct caly_event_src *src)
{
	return src != NULL ? src->use_ring : 0;
}

int caly_events_consume(struct caly_event_src *src)
{
	int total = 0;
	int got = 0;
	int r;

	if (src == NULL)
		return -1;

	/* Drain BOTH transports: the ring buffer carries the main program's
	 * events while the perf array carries the synproxy/tc events (and is
	 * the compat path).  Either fd may have woken us. */
#if CALY_LIBBPF_AT_LEAST(0, 8)
	if (src->rb != NULL) {
		r = ring_buffer__consume(src->rb);
		if (r >= 0) {
			total += r;
			got = 1;
		}
	}
#endif
	if (src->pb != NULL) {
		r = perf_buffer__consume(src->pb);
		if (r >= 0) {
			total += r;
			got = 1;
		}
	}
	return got ? total : -1;
}

void caly_events_close(struct caly_event_src *src)
{
	if (src == NULL)
		return;
#if CALY_LIBBPF_AT_LEAST(0, 8)
	if (src->rb != NULL)
		ring_buffer__free(src->rb);
#endif
	if (src->pb != NULL)
		perf_buffer__free(src->pb);
	if (src->own_epoll_fd >= 0)
		close(src->own_epoll_fd);
	free(src);
}

/* ================================================================== *
 * LPM insert and map counting
 * ================================================================== */

int caly_lpm_insert(const struct caly_bpf *b, int map_id,
		    const struct caly_cidr *cidr, __u32 flags, __u32 tag)
{
	struct rule_meta meta;
	struct caly_cidr c;
	int fd;

	if (b == NULL || cidr == NULL) {
		errno = EINVAL;
		return -1;
	}

	c = *cidr;
	if (caly_cidr_apply_mask(&c) != 0) {
		errno = EINVAL;
		return -1;
	}

	fd = caly_bpf_map_fd(b, map_id);
	if (fd < 0) {
		errno = ENOENT;
		return -1;
	}

	memset(&meta, 0, sizeof(meta));
	meta.added_ns = 0;             /* 0 == boot-time configuration */
	meta.hits = 0;
	meta.flags = flags;
	meta.tag = tag;

	if (c.family == CALY_AF_INET) {
		struct lpm_key_v4 key;

		memset(&key, 0, sizeof(key));
		key.prefixlen = c.prefixlen;
		memcpy(key.addr, c.addr, 4);
		if (bpf_map_update_elem(fd, &key, &meta, BPF_ANY) != 0)
			return -1;
	} else if (c.family == CALY_AF_INET6) {
		struct lpm_key_v6 key;

		memset(&key, 0, sizeof(key));
		key.prefixlen = c.prefixlen;
		memcpy(key.addr, c.addr, 16);
		if (bpf_map_update_elem(fd, &key, &meta, BPF_ANY) != 0)
			return -1;
	} else {
		errno = EINVAL;
		return -1;
	}
	return 0;
}

long caly_bpf_map_count(const struct caly_bpf *b, int map_id)
{
	int fd = caly_bpf_map_fd(b, map_id);
	unsigned char key[64], next[64];
	long count = 0;
	int have = 0;

	if (fd < 0)
		return -1;

	memset(key, 0, sizeof(key));
	while (bpf_map_get_next_key(fd, have ? key : NULL, next) == 0) {
		count++;
		memcpy(key, next, sizeof(key));
		have = 1;
		if (count > (long)CALY_MAP_ENTRIES_MAX)
			break;   /* runaway guard */
	}
	return count;
}

/* ================================================================== *
 * Garbage collection
 * ================================================================== */

enum caly_gc_kind {
	CALY_GC_BAN,
	CALY_GC_RATE,
	CALY_GC_SCAN,
	CALY_GC_TOP,
	CALY_GC_CONN,
};

/* Decide whether one entry has aged out of policy.  Most kinds read only the
 * value; the conntrack kind also reads the key, because the per-proto timeout
 * knobs are selected on the L4 protocol, which lives in conn_key, not
 * conn_state. */
static int caly_gc_expired(enum caly_gc_kind kind, const void *key,
			   const void *val, __u64 now,
			   const struct fw_config *cfg)
{
	switch (kind) {
	case CALY_GC_BAN: {
		const struct ban_entry *e = val;

		if (e->flags & CALY_BAN_F_PERMANENT)
			return 0;
		return e->expiry_ns != 0 && e->expiry_ns <= now;
	}
	case CALY_GC_RATE: {
		const struct rate_state *e = val;
		__u64 idle = cfg->rate_idle_ns ? cfg->rate_idle_ns
					       : (5ULL * 60 * CALY_NSEC_PER_SEC);

		return e->last_seen_ns != 0 &&
		       now > e->last_seen_ns &&
		       (now - e->last_seen_ns) > idle;
	}
	case CALY_GC_SCAN: {
		const struct scan_state *e = val;
		__u64 idle = cfg->scan_idle_ns ? cfg->scan_idle_ns
					       : (5ULL * 60 * CALY_NSEC_PER_SEC);

		return e->last_seen_ns != 0 &&
		       now > e->last_seen_ns &&
		       (now - e->last_seen_ns) > idle;
	}
	case CALY_GC_TOP: {
		const struct src_stats *e = val;
		__u64 idle = cfg->srcstat_idle_ns
				? cfg->srcstat_idle_ns
				: (10ULL * 60 * CALY_NSEC_PER_SEC);

		return e->last_seen_ns != 0 &&
		       now > e->last_seen_ns &&
		       (now - e->last_seen_ns) > idle;
	}
	case CALY_GC_CONN: {
		const struct conn_state *e = val;
		const struct conn_key *k = key;
		unsigned int proto = k != NULL ? k->proto
					       : CALY_IPPROTO_TCP;
		__u64 to;

		/*
		 * Honour the per-protocol timeout knobs, selecting on the L4
		 * protocol in the key and, for TCP, the handshake state - the
		 * same selection maps.c makes.  A conntrack hit short-circuits
		 * the per-source rate limiters and the amplifier filter, so an
		 * entry retained past its configured timeout keeps granting
		 * that bypass; bounding the sweep to the operator-set seconds
		 * is the whole point of this GC.
		 */
		switch (proto) {
		case CALY_IPPROTO_TCP:
			if (e->state == CALY_CT_ESTABLISHED)
				to = cfg->ct_tcp_est_ns ? cfg->ct_tcp_est_ns
					: (4ULL * 3600 * CALY_NSEC_PER_SEC);
			else if (e->state == CALY_CT_FIN_WAIT ||
				 e->state == CALY_CT_CLOSED)
				to = cfg->ct_tcp_fin_ns ? cfg->ct_tcp_fin_ns
					: (30ULL * CALY_NSEC_PER_SEC);
			else
				to = cfg->ct_tcp_syn_ns ? cfg->ct_tcp_syn_ns
					: (60ULL * CALY_NSEC_PER_SEC);
			break;
		case CALY_IPPROTO_UDP:
			to = (e->flags & CALY_CT_F_SEEN_REPLY)
				? (cfg->ct_udp_stream_ns
					? cfg->ct_udp_stream_ns
					: (180ULL * CALY_NSEC_PER_SEC))
				: (cfg->ct_udp_ns
					? cfg->ct_udp_ns
					: (30ULL * CALY_NSEC_PER_SEC));
			break;
		case CALY_IPPROTO_ICMP:
		case CALY_IPPROTO_ICMPV6:
			to = cfg->ct_icmp_ns ? cfg->ct_icmp_ns
					     : (30ULL * CALY_NSEC_PER_SEC);
			break;
		default:
			to = cfg->ct_generic_ns ? cfg->ct_generic_ns
						: (60ULL * CALY_NSEC_PER_SEC);
			break;
		}
		/* Never GC a management flow out from under the operator. */
		if (e->flags & CALY_CT_F_MGMT)
			to = to * 4;
		return e->last_seen_ns != 0 &&
		       now > e->last_seen_ns &&
		       (now - e->last_seen_ns) > to;
	}
	}
	return 0;
}

/*
 * Sweep one map.  Uses the delete-after-advance idiom: the current key is
 * copied into `prev` before it is deleted, so bpf_map_get_next_key(prev)
 * still resolves to the following key even though prev now names a deleted
 * entry (the kernel walks from prev's hash position).  Bounded by `budget`
 * keys examined.
 */
static __u64 caly_gc_sweep(int fd, size_t keysz, size_t valsz,
			   enum caly_gc_kind kind, __u64 now,
			   const struct fw_config *cfg, __u32 budget,
			   __u64 *examined)
{
	unsigned char prev[64], cur[64], val[128];
	__u64 removed = 0;
	__u32 seen = 0;
	int have_prev = 0;

	if (fd < 0 || keysz > sizeof(prev) || valsz > sizeof(val))
		return 0;

	while (seen < budget) {
		if (bpf_map_get_next_key(fd, have_prev ? prev : NULL,
					 cur) != 0)
			break;
		seen++;

		/* Advance the cursor before any delete. */
		memcpy(prev, cur, keysz);
		have_prev = 1;

		if (bpf_map_lookup_elem(fd, cur, val) != 0)
			continue;   /* evicted from under us; fine */

		if (caly_gc_expired(kind, cur, val, now, cfg)) {
			if (bpf_map_delete_elem(fd, cur) == 0)
				removed++;
		}
	}

	if (examined != NULL)
		*examined += seen;
	return removed;
}

int caly_bpf_gc(const struct caly_bpf *b, const struct fw_config *cfg,
		__u64 now_ns, struct caly_gc_stats *out)
{
	struct caly_gc_stats st;
	__u32 budget;

	if (b == NULL || cfg == NULL)
		return -1;

	memset(&st, 0, sizeof(st));
	budget = cfg->gc_batch ? cfg->gc_batch : 4096;

	st.bans_removed +=
		caly_gc_sweep(caly_bpf_map_fd(b, CALY_MID_BAN4),
			      sizeof(__u32), sizeof(struct ban_entry),
			      CALY_GC_BAN, now_ns, cfg, budget, &st.examined);
	st.bans_removed +=
		caly_gc_sweep(caly_bpf_map_fd(b, CALY_MID_BAN6),
			      sizeof(struct in6_key), sizeof(struct ban_entry),
			      CALY_GC_BAN, now_ns, cfg, budget, &st.examined);

	st.rate_removed +=
		caly_gc_sweep(caly_bpf_map_fd(b, CALY_MID_RATE4),
			      sizeof(__u32), sizeof(struct rate_state),
			      CALY_GC_RATE, now_ns, cfg, budget, &st.examined);
	st.rate_removed +=
		caly_gc_sweep(caly_bpf_map_fd(b, CALY_MID_RATE6),
			      sizeof(struct in6_key),
			      sizeof(struct rate_state),
			      CALY_GC_RATE, now_ns, cfg, budget, &st.examined);

	st.scan_removed +=
		caly_gc_sweep(caly_bpf_map_fd(b, CALY_MID_SCAN4),
			      sizeof(__u32), sizeof(struct scan_state),
			      CALY_GC_SCAN, now_ns, cfg, budget, &st.examined);
	st.scan_removed +=
		caly_gc_sweep(caly_bpf_map_fd(b, CALY_MID_SCAN6),
			      sizeof(struct in6_key),
			      sizeof(struct scan_state),
			      CALY_GC_SCAN, now_ns, cfg, budget, &st.examined);

	st.top_removed +=
		caly_gc_sweep(caly_bpf_map_fd(b, CALY_MID_TOP4),
			      sizeof(__u32), sizeof(struct src_stats),
			      CALY_GC_TOP, now_ns, cfg, budget, &st.examined);
	st.top_removed +=
		caly_gc_sweep(caly_bpf_map_fd(b, CALY_MID_TOP6),
			      sizeof(struct in6_key),
			      sizeof(struct src_stats),
			      CALY_GC_TOP, now_ns, cfg, budget, &st.examined);

	st.conn_removed +=
		caly_gc_sweep(caly_bpf_map_fd(b, CALY_MID_CONN),
			      sizeof(struct conn_key),
			      sizeof(struct conn_state),
			      CALY_GC_CONN, now_ns, cfg, budget, &st.examined);

	if (out != NULL)
		*out = st;
	return 0;
}
