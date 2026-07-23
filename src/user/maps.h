/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - XDP/eBPF DDoS mitigation suite
 * src/user/maps.h - typed userspace wrappers over every map in the ABI.
 *
 * Nothing in this file spells a map name inline: the CALY_MAP_* string
 * constants in src/bpf/common.h are the only source of truth, and this header
 * indexes them through enum caly_map_id.
 *
 * ERROR CONVENTION
 * ----------------
 * 0 on success, NEGATIVE errno on failure. libbpf changed its low-level
 * return convention at 1.0 (-1 plus errno before, -errno after); every call
 * here is normalised so callers never have to care.
 *
 * THINGS THAT ARE EASY TO GET WRONG AND ARE HANDLED HERE
 * -----------------------------------------------------
 *  - PERCPU maps need a value buffer of libbpf_num_possible_cpus() entries,
 *    each rounded UP to 8 bytes. Sizing it from sizeof(value) alone smashes
 *    the stack on every machine with more than one CPU.
 *  - LPM trie keys are prefixlen-first in HOST order followed by the address
 *    in NETWORK order, and the host bits MUST be masked to zero or the trie
 *    stores a prefix that can never match.
 *  - struct conn_key contains explicit padding and BPF hash lookups compare
 *    raw bytes: every key is memset to 0 before it is filled in.
 *  - bpf_map_get_next_key() on an LPM trie only exists from kernel 4.20.
 *    Every LPM operation therefore also maintains an in-process shadow list
 *    so flush and dump keep working on RHEL 8 era kernels.
 *  - Batch syscalls (4.20/5.6+) are used where available and every one of
 *    them falls back to a per-entry loop on any error.
 */

#ifndef CALY_USER_MAPS_H
#define CALY_USER_MAPS_H

#include <stddef.h>
#include <linux/types.h>

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct bpf_object;   /* libbpf, forward declared so callers need no headers */

/* -------------------------------------------------------------------------
 * "This port carries an explicit operator rule".
 *
 * struct port_rule.mode == CALY_PORT_CLOSED is 0, which is also the value of
 * a never-written array slot, so mode alone cannot distinguish "explicitly
 * closed" from "no rule at all". caly_maps_apply_ports() resolves this
 * without needing the dataplane to know anything: unlisted ports are filled
 * with CALY_PORT_OPEN when default_deny is off and CALY_PORT_CLOSED when it
 * is on, which is exactly the semantics the packet path wants.
 *
 * This flag is set in addition, purely so the dataplane can charge
 * STAT_DROP_DEFAULT_DENY rather than STAT_DROP_PORT_CLOSED if it wants to
 * tell the two apart. Bit 5 is unused in common.h; a dataplane that does not
 * know about it simply ignores it. See contract_change_requests.
 * ------------------------------------------------------------------------- */
#ifndef CALY_PORT_F_PRESENT
#define CALY_PORT_F_PRESENT   (1u << 5)
#endif

/* -------------------------------------------------------------------------
 * Map identity
 * ------------------------------------------------------------------------- */

enum caly_map_id {
	CALY_MAP_ID_CONFIG = 0,
	CALY_MAP_ID_STATS,
	CALY_MAP_ID_STATS_B,
	CALY_MAP_ID_GLOBAL,
	CALY_MAP_ID_ALLOW4,
	CALY_MAP_ID_ALLOW6,
	CALY_MAP_ID_BLOCK4,
	CALY_MAP_ID_BLOCK6,
	CALY_MAP_ID_LOCAL4,
	CALY_MAP_ID_LOCAL6,
	CALY_MAP_ID_BAN4,
	CALY_MAP_ID_BAN6,
	CALY_MAP_ID_RATE4,
	CALY_MAP_ID_RATE6,
	CALY_MAP_ID_CONN,
	CALY_MAP_ID_SCAN4,
	CALY_MAP_ID_SCAN6,
	CALY_MAP_ID_TOP4,
	CALY_MAP_ID_TOP6,
	CALY_MAP_ID_PORT_TCP,
	CALY_MAP_ID_PORT_UDP,
	CALY_MAP_ID_PORT_TB,
	CALY_MAP_ID_ICMP4_POL,
	CALY_MAP_ID_ICMP6_POL,
	CALY_MAP_ID_IFACE,
	CALY_MAP_ID_EVENTS,
	CALY_MAP_ID_EVENTS_RB,
	CALY_MAP_ID_PROGS,
	CALY_MAP_ID_SCRATCH,
	CALY_MAP_ID_MAX
};

/* Which LPM set a CIDR belongs to. Family picks v4 or v6 automatically. */
enum caly_set {
	CALY_SET_ALLOW = 0,
	CALY_SET_BLOCK = 1,
	CALY_SET_LOCAL = 2,
	CALY_SET_MAX   = 3
};

/* Family selector for the dump/flush helpers. */
#define CALY_FAM_ANY  0u
#define CALY_FAM_V4   CALY_AF_INET
#define CALY_FAM_V6   CALY_AF_INET6

/* -------------------------------------------------------------------------
 * Handle
 * ------------------------------------------------------------------------- */

struct caly_cidr_vec {
	struct caly_cidr *v;
	size_t            n;
	size_t            cap;
};

struct caly_maps {
	int    fd[CALY_MAP_ID_MAX];
	int    owned[CALY_MAP_ID_MAX];   /* close() on caly_maps_close()     */

	int    ncpu;                     /* libbpf_num_possible_cpus()       */
	int    have_batch;               /* batch syscalls usable at all     */
	int    batch_broken[CALY_MAP_ID_MAX];

	/* Shadow of the last programmed port tables, so a reload only writes
	 * the entries that actually changed. NULL until the first apply. */
	struct port_rule *shadow_tcp;
	struct port_rule *shadow_udp;

	/* Shadow of every prefix we inserted, indexed [set][0=v4,1=v6].
	 * Used for flush/dump when the kernel has no trie_get_next_key. */
	struct caly_cidr_vec lpm_shadow[CALY_SET_MAX][2];
	int    lpm_shadow_enabled;

	/* Set when the caller created the maps in this process and knows they
	 * are still zeroed; lets the first port-table write be a diff. */
	int    fresh;
};

/* -------------------------------------------------------------------------
 * Dump record types
 * ------------------------------------------------------------------------- */

struct caly_rule_dump {
	struct caly_cidr cidr;
	struct rule_meta meta;
};

struct caly_ban_dump {
	struct caly_cidr addr;
	struct ban_entry entry;
};

struct caly_conn_dump {
	struct conn_key   key;
	struct conn_state state;
};

struct caly_top_entry {
	struct caly_cidr addr;
	struct src_stats stats;
};

struct caly_iface_dump {
	__u32               ifindex;
	char                name[IF_NAMESIZE];
	struct iface_config cfg;
};

enum caly_top_sort {
	CALY_TOP_BY_PKTS = 0,
	CALY_TOP_BY_BYTES,
	CALY_TOP_BY_DROPS,
	CALY_TOP_BY_DROP_BYTES,
	CALY_TOP_BY_LAST_SEEN
};

struct caly_gc_stats {
	size_t bans_expired;
	size_t rate_idle;
	size_t scan_idle;
	size_t srcstat_idle;
	size_t conn_expired;
};

/* -------------------------------------------------------------------------
 * Lifecycle
 * ------------------------------------------------------------------------- */

void        caly_maps_init(struct caly_maps *m);
void        caly_maps_close(struct caly_maps *m);
const char *caly_map_name(int id);
int         caly_maps_fd(const struct caly_maps *m, int id);

/* Adopt an already-open fd. `owned` != 0 hands ownership to caly_maps_close.*/
int caly_maps_set_fd(struct caly_maps *m, int id, int fd, int owned);

/* Resolve every map out of a loaded bpf_object. fds stay owned by libbpf. */
int caly_maps_bind_object(struct caly_maps *m, struct bpf_object *obj,
			  char *err, size_t errsz);

/* Open every map from its pin under `pin_dir` (default CALY_PIN_DIR). The
 * optional maps (ringbuf, prog array) are allowed to be absent. */
int caly_maps_open_pinned(struct caly_maps *m, const char *pin_dir,
			  char *err, size_t errsz);

/* Tell the wrappers the maps were just created and are still all-zero. */
void caly_maps_mark_fresh(struct caly_maps *m);

/* Probe whether BPF_MAP_*_BATCH works here. Returns 1 yes, 0 no. */
int caly_maps_probe_batch(struct caly_maps *m);

/* Monotonic nanoseconds on the same clock as bpf_ktime_get_ns(). */
__u64 caly_now_ns(void);

/* max_entries of a live map, or -errno. */
int caly_map_max_entries(const struct caly_maps *m, int id, __u32 *out);

/* -------------------------------------------------------------------------
 * caly_config
 * ------------------------------------------------------------------------- */

int caly_map_config_get(const struct caly_maps *m, struct fw_config *out);

/* Verbatim write of the 720-byte config. Does not preserve capability bits;
 * use caly_map_config_install() unless you know you own them. */
int caly_map_config_set(const struct caly_maps *m, const struct fw_config *in);

/* Read-modify-write that keeps CALY_F_CAP_* discovered by the loader, keeps
 * config_gen monotonic, refuses an ABI major mismatch, and refuses any image
 * whose management list has lost TCP/22. */
int caly_map_config_install(const struct caly_maps *m, struct fw_config *in,
			    char *err, size_t errsz);

/* Flip just the mode (escalation path; does not touch anything else). */
int caly_map_config_set_mode(const struct caly_maps *m, __u32 mode);

/* OR / AND-NOT capability bits, for the loader's probe results. */
int caly_map_config_set_caps(const struct caly_maps *m, __u64 set, __u64 clear);

/* -------------------------------------------------------------------------
 * Allowlist / blocklist / local prefixes (LPM tries)
 * ------------------------------------------------------------------------- */

int caly_set_add(struct caly_maps *m, int set, const struct caly_cidr *c);
int caly_set_del(struct caly_maps *m, int set, const struct caly_cidr *c);
int caly_set_lookup(const struct caly_maps *m, int set,
		    const struct caly_cidr *c, struct rule_meta *out);

/* Bulk import. Uses BPF_MAP_UPDATE_BATCH when available. `added` may be
 * NULL. Never aborts the whole import because of one duplicate. */
int caly_set_add_many(struct caly_maps *m, int set,
		      const struct caly_cidr *arr, size_t n, size_t *added);

/* Remove every entry (family == CALY_FAM_ANY for both). When by_tag != 0
 * only entries whose rule_meta.tag equals `tag` are removed, which is how a
 * threat-feed refresh avoids clobbering manual entries. */
int caly_set_flush(struct caly_maps *m, int set, __u32 family,
		   int by_tag, __u32 tag, size_t *removed);

/* Caller frees *out with free(). */
int caly_set_dump(struct caly_maps *m, int set, __u32 family,
		  struct caly_rule_dump **out, size_t *n);

/* -------------------------------------------------------------------------
 * Dynamic bans (LRU hash)
 * ------------------------------------------------------------------------- */

/* `addr` must be a host address (/32 or /128). ttl_ns == 0 with
 * CALY_BAN_F_PERMANENT means "until removed". */
int caly_ban_add(const struct caly_maps *m, const struct caly_cidr *addr,
		 __u64 ttl_ns, __u32 reason, __u32 flags);
int caly_ban_del(struct caly_maps *m, const struct caly_cidr *addr);
int caly_ban_get(const struct caly_maps *m, const struct caly_cidr *addr,
		 struct ban_entry *out);
int caly_ban_flush(struct caly_maps *m, __u32 family, size_t *removed);
int caly_ban_dump(struct caly_maps *m, __u32 family,
		  struct caly_ban_dump **out, size_t *n);

/* Evict expired bans. `budget` caps the number of entries examined per call
 * so a 262144-entry table never stalls the daemon loop; 0 means unlimited. */
int caly_ban_sweep(struct caly_maps *m, __u64 now_ns, __u32 budget,
		   size_t *removed);

/* -------------------------------------------------------------------------
 * Conntrack-lite
 * ------------------------------------------------------------------------- */

int caly_conn_dump(struct caly_maps *m, struct caly_conn_dump **out, size_t *n);
int caly_conn_del(const struct caly_maps *m, const struct conn_key *k);
int caly_conn_flush(struct caly_maps *m, size_t *removed);
int caly_conn_sweep(struct caly_maps *m, const struct fw_config *cfg,
		    __u64 now_ns, __u32 budget, size_t *removed);
int caly_conn_count(struct caly_maps *m, size_t *n);

/* -------------------------------------------------------------------------
 * Statistics (PERCPU: summed across every possible CPU)
 * ------------------------------------------------------------------------- */

/* pkts and bytes must each have room for `n` entries; pass STAT_MAX. Either
 * pointer may be NULL if that half is not wanted. */
int caly_stats_read(struct caly_maps *m, __u64 *pkts, __u64 *bytes, size_t n);
int caly_gauges_read(struct caly_maps *m, __u64 *g, size_t n);
int caly_stats_reset(struct caly_maps *m);
int caly_gauges_reset(struct caly_maps *m);

/* -------------------------------------------------------------------------
 * Top talkers
 * ------------------------------------------------------------------------- */

/* Sorted descending by `sort`, truncated to `limit` (0 = everything).
 * Caller frees *out with free(). */
int caly_top_query(struct caly_maps *m, __u32 family, int sort, size_t limit,
		   struct caly_top_entry **out, size_t *n);
int caly_top_flush(struct caly_maps *m, __u32 family, size_t *removed);

/* -------------------------------------------------------------------------
 * Per-source state garbage collection
 * ------------------------------------------------------------------------- */

int caly_rate_sweep(struct caly_maps *m, __u64 now_ns, __u64 idle_ns,
		    __u32 budget, size_t *removed);
int caly_scan_sweep(struct caly_maps *m, __u64 now_ns, __u64 idle_ns,
		    __u32 budget, size_t *removed);
int caly_srcstat_sweep(struct caly_maps *m, __u64 now_ns, __u64 idle_ns,
		       __u32 budget, size_t *removed);

/* One pass over everything the config says should be swept. */
int caly_maps_gc(struct caly_maps *m, const struct fw_config *cfg,
		 __u64 now_ns, struct caly_gc_stats *out);

/* -------------------------------------------------------------------------
 * Port policy / ICMP policy / interfaces
 * ------------------------------------------------------------------------- */

int caly_port_get(const struct caly_maps *m, int is_udp, __u32 port,
		  struct port_rule *out);
int caly_port_set(struct caly_maps *m, int is_udp, __u32 port,
		  const struct port_rule *in);
int caly_port_tb_reset(const struct caly_maps *m, int is_udp, __u32 port);

int caly_icmp_policy_get(const struct caly_maps *m, __u32 family, __u32 type,
			 __u32 *out);
int caly_icmp_policy_set(const struct caly_maps *m, __u32 family, __u32 type,
			 __u32 policy);

int caly_iface_set(const struct caly_maps *m, __u32 ifindex, __u32 zone,
		   __u64 flags);
int caly_iface_get(const struct caly_maps *m, __u32 ifindex,
		   struct iface_config *out);
int caly_iface_del(const struct caly_maps *m, __u32 ifindex);
int caly_iface_dump(struct caly_maps *m, struct caly_iface_dump **out,
		    size_t *n);

/* -------------------------------------------------------------------------
 * Programming the whole policy from a parsed configuration
 * ------------------------------------------------------------------------- */

int caly_maps_apply_sets(struct caly_maps *m, const struct caly_conf *c,
			 char *err, size_t errsz);
int caly_maps_apply_ports(struct caly_maps *m, const struct caly_conf *c,
			  char *err, size_t errsz);
int caly_maps_apply_icmp(struct caly_maps *m, const struct caly_conf *c,
			 char *err, size_t errsz);
int caly_maps_apply_ifaces(struct caly_maps *m, const struct caly_conf *c,
			   char *err, size_t errsz);

/* Insert this host's own addresses into caly_local4/6 as /32 and /128 host
 * routes, tagged CALY_TAG_AUTO. Safe to call repeatedly. */
int caly_maps_populate_local(struct caly_maps *m, size_t *added);

/*
 * The whole policy, in the only safe order: every table the dataplane
 * consults is written BEFORE the config that switches the corresponding
 * feature on, and the allowlist is written first of all.
 */
int caly_maps_apply_config(struct caly_maps *m, struct caly_conf *c,
			   char *err, size_t errsz);

#ifdef __cplusplus
}
#endif

#endif /* CALY_USER_MAPS_H */
