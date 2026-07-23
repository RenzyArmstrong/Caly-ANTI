/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/loader.h
 *
 * BPF object lifecycle: probe -> open -> size -> load -> pin -> seed ->
 * attach, and the inverse.  Everything that talks to libbpf lives behind this
 * interface so that the rest of the daemon never includes libbpf headers and
 * never sees a libbpf version difference.
 *
 * DESIGN NOTES THAT ARE EASY TO GET WRONG
 * ---------------------------------------
 * 1. max_*_entries are read from struct fw_config BEFORE map creation and
 *    applied with bpf_map__set_max_entries().  Once loaded, a map cannot be
 *    resized; changing those knobs requires a restart, and caly_bpf_load()
 *    is the only place they are honoured.
 *
 * 2. All six LPM tries are declared BPF_F_NO_PREALLOC in the BPF object.  The
 *    loader does not add the flag; it verifies it, because a trie without it
 *    fails creation with -EINVAL and the resulting message is opaque.
 *
 * 3. The SYN proxy program is autoloaded only when the raw syncookie helpers
 *    are present.  If probing is impossible (build headers too old to even
 *    name the helper) the loader still tries, and falls back to reloading the
 *    object with the program disabled.  The verifier never sees a helper the
 *    kernel lacks, which is the entire reason the SYN proxy is a separate
 *    program reached by tail call.
 *
 * 4. Attach never blindly replaces a foreign XDP program.  It reads the
 *    installed program's id, resolves its name, and only replaces programs
 *    whose name starts with "caly_" unless the caller passes force.  This is
 *    what makes unload idempotent and safe after a crash.
 *
 * 5. TCP/22 is forced into fw_config.mgmt_tcp_ports by caly_config_sanitize()
 *    in every mode.  Nothing else in the tree may write that array without
 *    running it through sanitize first.
 */

#ifndef CALY_LOADER_H
#define CALY_LOADER_H

#include <stddef.h>
#include <net/if.h>
#include <linux/types.h>

#include "util.h"       /* PATH_MAX_SAFE, struct caly_cidr, helpers */

#ifndef CALY_USERSPACE
#define CALY_USERSPACE 1
#endif
#if defined(__has_include)
#  if __has_include("common.h")
#    include "common.h"
#  else
#    include "../bpf/common.h"
#  endif
#else
#  include "../bpf/common.h"
#endif

/* Opaque to every consumer of this header. */
struct bpf_object;

#ifndef CALY_VERSION
#define CALY_VERSION "1.0.0"
#endif

/* Default locations.  CALY_PIN_DIR, CALY_RUN_DIR, CALY_BPFFS_ROOT,
 * CALY_CONF_PATH and CALY_CTL_SOCK (the control socket) all come from common.h,
 * which is the single source of truth for paths shared with the CLI/watcher. */
#ifndef CALY_BPF_OBJ_NAME
#define CALY_BPF_OBJ_NAME  "calyanti.bpf.o"
#endif

#define CALY_PIDFILE   CALY_RUN_DIR "/calyanti.pid"

/* Maximum interfaces the daemon will attach to in one run. */
#define CALY_MAX_IFACES  32

/*
 * Map identifiers.  The order here is the order maps are opened, pinned and
 * reported in; it has no ABI significance (names in common.h do).
 */
enum caly_map_id {
	CALY_MID_CONFIG = 0,
	CALY_MID_STATS,
	CALY_MID_STATS_B,
	CALY_MID_GLOBAL,
	CALY_MID_ALLOW4,
	CALY_MID_ALLOW6,
	CALY_MID_BLOCK4,
	CALY_MID_BLOCK6,
	CALY_MID_LOCAL4,
	CALY_MID_LOCAL6,
	CALY_MID_BAN4,
	CALY_MID_BAN6,
	CALY_MID_RATE4,
	CALY_MID_RATE6,
	CALY_MID_CONN,
	CALY_MID_SCAN4,
	CALY_MID_SCAN6,
	CALY_MID_TOP4,
	CALY_MID_TOP6,
	CALY_MID_PORT_TCP,
	CALY_MID_PORT_UDP,
	CALY_MID_PORT_TB,
	CALY_MID_ICMP4_POL,
	CALY_MID_ICMP6_POL,
	CALY_MID_IFACE,
	CALY_MID_EVENTS,
	CALY_MID_EVENTS_RB,
	CALY_MID_PROGS,
	CALY_MID_SCRATCH,
	CALY_MID_MAX
};

/* Everything discovered about the running system before we load anything. */
struct caly_features {
	unsigned int kver_major;
	unsigned int kver_minor;
	unsigned int kver_patch;
	__u32        kver_code;          /* caly_kver_code() form            */

	int have_btf;                    /* /sys/kernel/btf/vmlinux readable */
	int have_ringbuf;                /* BPF_MAP_TYPE_RINGBUF usable      */
	int have_synproxy;               /* raw syncookie helpers usable     */
	int have_batch_ops;              /* BPF_MAP_*_BATCH syscalls (5.6+)  */
	int have_tc_bpf;                 /* libbpf TC API + clsact usable    */
	int synproxy_probe_conclusive;   /* 0 => have_synproxy is a guess    */

	int is_container;
	int is_virt;
	char virt[32];

	unsigned int libbpf_major;
	unsigned int libbpf_minor;
};

/* Per-interface attachment record. */
struct caly_link {
	unsigned int ifindex;
	char         ifname[IF_NAMESIZE];
	__u32        xdp_flags;      /* flags the program is attached with   */
	__u32        prog_id;        /* kernel id of our attached program    */
	__u32        dataplane;      /* enum caly_dataplane rung achieved    */
	int          xdp_attached;
	int          tc_attached;    /* clsact egress hook holds caly_tc_egr */
	int          active;
};

struct caly_bpf {
	struct bpf_object *obj;
	int   map_fd[CALY_MID_MAX];

	int   prog_fd_main;
	int   prog_fd_synproxy;
	int   prog_fd_ipv6;
	int   prog_fd_tc_egress;
	int   prog_fd_tc_ingress;    /* optional, only if the object has one */

	int   synproxy_loaded;
	int   ringbuf_active;
	int   pinned_only;           /* opened from pins, obj == NULL        */

	char  pin_dir[PATH_MAX_SAFE];
	char  obj_path[PATH_MAX_SAFE];

	struct caly_features feat;
};

struct caly_load_opts {
	const char *obj_path;    /* NULL => search the standard locations    */
	const char *pin_dir;     /* NULL => CALY_PIN_DIR                     */
	int reuse_pins;          /* 1 => adopt compatible existing pinned maps */
	int want_synproxy;       /* operator asked for it (CALY_F_SYNPROXY)  */
	int want_ringbuf;        /* operator wants ringbuf events if possible */
	int verbose_libbpf;      /* route libbpf debug output into the log   */
};

/* ------------------------------------------------------------------ *
 * Probing and environment
 * ------------------------------------------------------------------ */

/* Fills `f`.  Never fails hard: an unprobeable feature is reported as absent,
 * which always selects the more conservative code path. */
int  caly_bpf_probe_features(struct caly_features *f);
void caly_features_log(const struct caly_features *f);

/* Ensure bpffs is mounted at `bpffs_root` and `pin_dir` exists (mode 0700).
 * Mounts bpffs when it is missing.  Returns 0 or -1. */
int  caly_bpffs_ensure(const char *bpffs_root, const char *pin_dir);

/* Locate the BPF object file.  Searches, in order: $CALY_BPF_OBJECT, the
 * directory of /proc/self/exe, ./, ./src/bpf/, /usr/lib/calyanti/,
 * /usr/libexec/calyanti/, /usr/local/lib/calyanti/, /lib/calyanti/.
 * Returns buf on success, NULL when nothing was found. */
const char *caly_bpf_find_object(char *buf, size_t len);

const char *caly_map_name(int map_id);

/* ------------------------------------------------------------------ *
 * Configuration
 * ------------------------------------------------------------------ */

/* The shipped defaults from config/calyanti.conf, byte for byte.  Safe, not
 * tight: monitor_only off, default_deny off, wan_drop_private off, generous
 * buckets.  A daemon started with no config file at all runs exactly this. */
void caly_config_defaults(struct fw_config *cfg);

/*
 * Clamp, validate and make safe.  Always run this on anything that came from
 * a file, a CLI flag or the control socket before it reaches the config map.
 *
 * Guarantees on return 0:
 *   - abi_version is ours,
 *   - mode, zones and enum-valued fields are in range,
 *   - vlan/ip6-ext/tunnel depths are <= their compile-time bounds,
 *   - mgmt_tcp_count/mgmt_udp_count are <= CALY_MGMT_PORTS_MAX,
 *   - TCP/22 is present in mgmt_tcp_ports,
 *   - no capability bit is set from operator input.
 *
 * Returns -1 only when the configuration cannot be made safe (currently: the
 * management list is full of 16 other ports so SSH cannot be inserted).  The
 * caller must then keep the previously running configuration.  `err` receives
 * a human-readable reason.  `warnings`, when non-NULL, is incremented once per
 * value that had to be corrected.
 */
int  caly_config_sanitize(struct fw_config *cfg, char *err, size_t errlen,
			  unsigned int *warnings);

/* Write the loader-discovered capability bits (CALY_F_CAP_*) into cfg->flags,
 * clearing any the operator tried to set by hand. */
void caly_config_apply_caps(struct fw_config *cfg,
			    const struct caly_features *f);

/* Whole-struct copy in and out of caly_config[0]. */
int  caly_bpf_config_write(const struct caly_bpf *b,
			   const struct fw_config *cfg);
int  caly_bpf_config_read(const struct caly_bpf *b, struct fw_config *cfg);

/* ------------------------------------------------------------------ *
 * Load / unload
 * ------------------------------------------------------------------ */

/*
 * Open, size, load and pin.  On failure the object is fully cleaned up and
 * `b` is left zeroed, so the caller may retry with different options.
 *
 * Retries internally: if the first load fails and the SYN proxy program was
 * enabled it retries with it disabled, and if that fails and the ring buffer
 * map was enabled it retries with the ring buffer disabled.  A verifier
 * rejection caused by a missing helper therefore degrades instead of
 * aborting.
 */
int  caly_bpf_load(struct caly_bpf *b, const struct caly_load_opts *opts,
		   const struct fw_config *cfg);

/* Open an existing pinned map set without loading anything.  Used by
 * --status and by any tool that wants to read state from a running daemon.
 * Maps that are not pinned are reported as fd -1 rather than as an error. */
int  caly_bpf_open_pinned(struct caly_bpf *b, const char *pin_dir);

/* Close every descriptor and free the object.  Does NOT detach programs and
 * does NOT remove pins: teardown order is the caller's decision. */
void caly_bpf_close(struct caly_bpf *b);

/* -1 when the map was not opened. */
int  caly_bpf_map_fd(const struct caly_bpf *b, int map_id);

/* ------------------------------------------------------------------ *
 * Seeding
 * ------------------------------------------------------------------ */

/*
 * Populate the maps that have a defined initial state:
 *   - caly_port_tcp / caly_port_udp filled with the baseline port mode,
 *   - CALY_PORT_F_AMPLIFIER set on the 21 reflection source ports,
 *   - mgmt ports marked OPEN + CALY_PORT_F_MGMT,
 *   - caly_icmp4_pol / caly_icmp6_pol seeded with the shipped policy, with
 *     the mandatory types forced to PASS,
 *   - caly_progs tail-call slots reset and repopulated.
 *
 * Idempotent: safe to call again after a configuration reload.
 */
int  caly_bpf_seed_maps(const struct caly_bpf *b, const struct fw_config *cfg);

/*
 * Set one ICMP type policy.  family is CALY_AF_INET or CALY_AF_INET6.
 * REFUSES to set CALY_ICMP_DROP on a mandatory type (v4: 3; v6: 2, 133, 134,
 * 135, 136) and returns -1 with errno EPERM, because dropping those does not
 * harden the host, it disconnects it.  Every writer of these maps - config
 * parser, CLI, control socket - must go through this function.
 */
int  caly_icmp_policy_set(const struct caly_bpf *b, __u32 family, __u32 type,
			  __u32 policy);

/* 1 when the type may never be dropped for that family. */
int  caly_icmp_type_is_mandatory(__u32 family, __u32 type);

int  caly_port_rule_set(const struct caly_bpf *b, int is_udp, __u32 port,
			const struct port_rule *rule);
int  caly_port_rule_get(const struct caly_bpf *b, int is_udp, __u32 port,
			struct port_rule *out);
int  caly_iface_config_set(const struct caly_bpf *b,
			   const struct iface_config *ic);

/* ------------------------------------------------------------------ *
 * Attach / detach
 * ------------------------------------------------------------------ */

/*
 * Attach the main XDP program to `ifname`, honouring xdp_pref
 * (enum caly_xdp_mode).  With CALY_XDP_AUTO it tries driver mode first and
 * falls back to generic; with an explicit mode it tries only that mode, so
 * that pinning to a rung the hardware cannot provide is a loud failure rather
 * than a silent downgrade.
 *
 * An XDP program already attached to the interface is replaced only when it
 * is one of ours (kernel object name begins with "caly_") or `force` is set;
 * otherwise the call fails with errno EBUSY and the foreign program is left
 * alone.
 */
int  caly_bpf_attach(struct caly_bpf *b, const char *ifname, __u32 xdp_pref,
		     int force, struct caly_link *out);

/*
 * Attach caly_tc_egress at the clsact egress hook.  This is what teaches
 * conntrack about outbound-initiated flows, and it is the reason an
 * outbound DNS query gets its reply back under inbound default-deny.
 * Not fatal when it fails: the daemon logs and continues without it.
 */
int  caly_bpf_attach_tc_egress(struct caly_bpf *b, struct caly_link *link);

/* Detach whatever we attached, in the reverse order.  Idempotent. */
int  caly_bpf_detach_link(struct caly_link *link, int force);

/* Detach by name without holding a link record: used by --unload and by
 * recovery after a crash.  Returns 1 if something was detached, 0 if there
 * was nothing of ours attached, -1 on error. */
int  caly_bpf_detach_iface(const char *ifname, int force);

/* Read-only: what XDP program, if any, is on `ifname`.  Returns 1 when a
 * program is attached (filling prog_id, the XDP_FLAGS_* mode, and whether the
 * program name begins with "caly_"), 0 when nothing is attached, -1 on error.
 * Any of the out pointers may be NULL. */
int  caly_xdp_iface_status(const char *ifname, __u32 *prog_id, __u32 *mode,
			   int *is_ours);

/*
 * Sweep every interface on the system, detach every "caly_" XDP program and
 * clsact filter found, and remove the pin directory.  Survives a crashed
 * previous instance because it discovers state from the kernel rather than
 * from any file the dead process might have left behind.
 * Returns the number of interfaces cleaned, or -1.
 */
int  caly_unload_everything(const char *pin_dir, int force);

/* Remove the pinned map directory only.  Returns 0 even when it did not
 * exist. */
int  caly_unpin_all(const char *pin_dir);

/* ------------------------------------------------------------------ *
 * Reading counters
 * ------------------------------------------------------------------ */

/* Sum the per-CPU gauge array into out[CALY_G_MAX]. */
int  caly_bpf_read_gauges(const struct caly_bpf *b, __u64 *out,
			  unsigned int n);

/* Sum the per-CPU statistics arrays.  pkts and bytes may each be NULL.
 * `n` entries are read, normally STAT_MAX. */
int  caly_bpf_read_stats(const struct caly_bpf *b, __u64 *pkts, __u64 *bytes,
			 unsigned int n);

/* Human-readable name for enum caly_gauge. */
const char *caly_gauge_name(__u32 g);

/* ------------------------------------------------------------------ *
 * Event source (perf event array or ring buffer)
 *
 * A thin wrapper that hides which of the two transports is in use so the
 * daemon's event loop just polls one fd and calls one consume function.  The
 * ring buffer is used when the object loaded with it (5.8+); otherwise the
 * always-present perf event array is used.
 * ------------------------------------------------------------------ */

struct caly_event_src;   /* opaque */

/* Delivered once per record.  `data`/`size` are the raw bytes from the map;
 * the callee validates size >= sizeof(struct event) before dereferencing. */
typedef void (*caly_event_fn)(void *ctx, const void *data, __u32 size);

/* Delivered when the transport dropped records (perf ring overrun). */
typedef void (*caly_lost_fn)(void *ctx, int cpu, __u64 count);

/* Open over whichever transport the object loaded with.  `cfg->event_pages`
 * sizes the per-CPU perf ring.  Returns NULL on failure. */
struct caly_event_src *caly_events_open(const struct caly_bpf *b,
					const struct fw_config *cfg,
					caly_event_fn on_event,
					caly_lost_fn on_lost, void *ctx);

/* An epoll-able fd that becomes readable when records are waiting. */
int  caly_events_epoll_fd(const struct caly_event_src *src);

/* Drain everything currently ready, invoking the callbacks.  Returns the
 * number of records consumed, or -1. */
int  caly_events_consume(struct caly_event_src *src);

/* 1 ring buffer, 0 perf event array. */
int  caly_events_is_ring(const struct caly_event_src *src);

void caly_events_close(struct caly_event_src *src);

/* ------------------------------------------------------------------ *
 * Garbage collection
 *
 * Userspace owns eviction of the LRU state maps: expired bans, idle rate and
 * scan state, stale top-talker rows and dead conntrack entries.  The LRU
 * mechanism keeps the maps from ever failing an insert, but it evicts by
 * age-of-use, not by policy, so a ban whose TTL passed would otherwise linger
 * until pressure reclaims it.  This sweep enforces the policy timeouts.
 *
 * `now_ns` must be CLOCK_MONOTONIC (the same clock the dataplane stamps with).
 * At most cfg->gc_batch keys are examined per map per call, so the sweep is
 * bounded regardless of map size.  Returns the number of entries removed.
 */
struct caly_gc_stats {
	__u64 bans_removed;
	__u64 rate_removed;
	__u64 scan_removed;
	__u64 top_removed;
	__u64 conn_removed;
	__u64 examined;
};

int  caly_bpf_gc(const struct caly_bpf *b, const struct fw_config *cfg,
		 __u64 now_ns, struct caly_gc_stats *out);

/* ------------------------------------------------------------------ *
 * LPM / list helpers used when applying configuration to the maps
 * ------------------------------------------------------------------ */

/* Insert one prefix into the allow, block or local trie (chosen by map_id:
 * CALY_MID_ALLOW4/6, CALY_MID_BLOCK4/6, CALY_MID_LOCAL4/6).  The prefix is
 * masked to its length first so two spellings of the same network cannot both
 * exist.  `flags` are CALY_RULE_F_*, `tag` is a free-form operator tag. */
int  caly_lpm_insert(const struct caly_bpf *b, int map_id,
		     const struct caly_cidr *cidr, __u32 flags, __u32 tag);

/* Count the entries in a map by walking it.  Used by --status and the control
 * socket.  Returns the count or -1. */
long caly_bpf_map_count(const struct caly_bpf *b, int map_id);

#endif /* CALY_LOADER_H */
