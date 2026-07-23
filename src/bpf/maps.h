/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - XDP/eBPF DDoS mitigation suite
 * src/bpf/maps.h - every BPF map, defined exactly once.
 *
 * All dataplane objects (xdp_firewall.bpf.c, the SYN proxy, the optional IPv6
 * split, the tc egress program) include THIS file and nothing else declares a
 * map. That is the only way separate objects can be guaranteed to agree on
 * key/value types, flags and sizes.
 *
 * PREREQUISITE INCLUDES:
 *     #include "vmlinux.h"
 *     #include <bpf/bpf_helpers.h>
 *     #include "common.h"
 *     #include "compat.h"
 *     #include "maps.h"
 *
 * SIZING
 * ------
 * The max_entries below are DEFAULTS. fw_config.max_*_entries is read by the
 * loader from calyanti.conf BEFORE bpf_object__load(), and applied with
 * bpf_map__set_max_entries(). Changing a number here changes only what a
 * hand-loaded object (bpftool prog load) gets.
 *
 * PINNING
 * -------
 * Off by default: the loader calls bpf_map__set_pin_path() explicitly so it
 * can decide, per map, whether a stale pin from a previous daemon generation
 * with different sizing should be reused or unlinked. Build with
 * -DCALY_PIN_MAPS=1 to have libbpf do it declaratively instead (requires
 * bpf_object_open_opts.pin_root_path = CALY_PIN_DIR).
 *
 * WHAT IS AND IS NOT PER-CPU
 * --------------------------
 * PERCPU: caly_stats, caly_stats_b, caly_global, caly_scratch.
 *   Counters must be exact and scratch must be lock free.
 * SHARED: caly_rate4/6, caly_port_tb, and every LRU/LPM map.
 *   A per-CPU token bucket multiplies the effective limit by nr_cpus, and RSS
 *   spreads one attacker across every queue - a 64-core box would enforce 64x
 *   the configured rate. The read-modify-write race on a shared bucket is
 *   benign: at worst a couple of extra packets conform. bpf_spin_lock is
 *   deliberately not used (5.1+, unreliable on RHEL 8 backports).
 */

#ifndef __CALY_ANTI_MAPS_H
#define __CALY_ANTI_MAPS_H

/* -------------------------------------------------------------------------
 * Default sizing. Every one is overridable from the Makefile.
 * ------------------------------------------------------------------------- */

#ifndef CALY_MAX_ALLOW_ENTRIES
#define CALY_MAX_ALLOW_ENTRIES     65536
#endif
#ifndef CALY_MAX_BLOCK_ENTRIES
#define CALY_MAX_BLOCK_ENTRIES     262144
#endif
#ifndef CALY_MAX_LOCAL_ENTRIES
#define CALY_MAX_LOCAL_ENTRIES     4096
#endif
#ifndef CALY_MAX_BAN_ENTRIES
#define CALY_MAX_BAN_ENTRIES       262144
#endif
#ifndef CALY_MAX_RATE_ENTRIES
#define CALY_MAX_RATE_ENTRIES      524288
#endif
#ifndef CALY_MAX_CONN_ENTRIES
#define CALY_MAX_CONN_ENTRIES      262144
#endif
#ifndef CALY_MAX_SCAN_ENTRIES
#define CALY_MAX_SCAN_ENTRIES      131072
#endif
#ifndef CALY_MAX_SRCSTAT_ENTRIES
#define CALY_MAX_SRCSTAT_ENTRIES   131072
#endif
#ifndef CALY_MAX_IFACE_ENTRIES
#define CALY_MAX_IFACE_ENTRIES     64
#endif
#ifndef CALY_RINGBUF_BYTES
#define CALY_RINGBUF_BYTES         (4 * 1024 * 1024)   /* must be 2^n * PAGE */
#endif

#define CALY_PORT_TABLE_ENTRIES    65536
#define CALY_ICMP_TABLE_ENTRIES    256

/* -------------------------------------------------------------------------
 * Pinning control.
 * ------------------------------------------------------------------------- */

#ifndef CALY_PIN_MAPS
#define CALY_PIN_MAPS 0
#endif

#if CALY_PIN_MAPS
#ifndef LIBBPF_PIN_BY_NAME
#define LIBBPF_PIN_BY_NAME 1
#endif
#define CALY_MAP_PIN __uint(pinning, LIBBPF_PIN_BY_NAME);
#else
#define CALY_MAP_PIN
#endif

/* BPF_F_NO_PREALLOC is mandatory for LPM tries; the kernel returns -EINVAL
 * without it. Redefined here so a reduced vmlinux.h cannot break the build. */
#ifndef BPF_F_NO_PREALLOC
#define BPF_F_NO_PREALLOC (1U << 0)
#endif

/* -------------------------------------------------------------------------
 * 1. caly_config - the single runtime configuration record.
 *
 * An ARRAY, not .rodata: global-variable relocation is unreliable on 4.18-era
 * backports, and .rodata cannot be updated after load, which would make every
 * knob load-time-only.
 * ------------------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct fw_config);
	__uint(max_entries, 1);
	CALY_MAP_PIN
} caly_config SEC(".maps");

/* -------------------------------------------------------------------------
 * 2-4. Statistics and gauges. PERCPU because they must be exact.
 * ------------------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);            /* enum stat_reason */
	__type(value, __u64);
	__uint(max_entries, STAT_MAX);
	CALY_MAP_PIN
} caly_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);            /* enum stat_reason */
	__type(value, __u64);
	__uint(max_entries, STAT_MAX);
	CALY_MAP_PIN
} caly_stats_b SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);            /* enum caly_gauge */
	__type(value, __u64);
	__uint(max_entries, CALY_G_MAX);
	CALY_MAP_PIN
} caly_global SEC(".maps");

/* -------------------------------------------------------------------------
 * 5-10. Reputation and topology LPM tries.
 *
 * Key layout is dictated by the kernel: __u32 prefixlen in HOST order first,
 * then the match bytes in NETWORK order, most significant byte first.
 * ------------------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key_v4);
	__type(value, struct rule_meta);
	__uint(max_entries, CALY_MAX_ALLOW_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	CALY_MAP_PIN
} caly_allow4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key_v6);
	__type(value, struct rule_meta);
	__uint(max_entries, CALY_MAX_ALLOW_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	CALY_MAP_PIN
} caly_allow6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key_v4);
	__type(value, struct rule_meta);
	__uint(max_entries, CALY_MAX_BLOCK_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	CALY_MAP_PIN
} caly_block4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key_v6);
	__type(value, struct rule_meta);
	__uint(max_entries, CALY_MAX_BLOCK_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	CALY_MAP_PIN
} caly_block6 SEC(".maps");

/* Our own prefixes: anti-spoofing (a source inside caly_local4 arriving on a
 * WAN interface is forged) and direction inference for conntrack. */
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key_v4);
	__type(value, struct rule_meta);
	__uint(max_entries, CALY_MAX_LOCAL_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	CALY_MAP_PIN
} caly_local4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_key_v6);
	__type(value, struct rule_meta);
	__uint(max_entries, CALY_MAX_LOCAL_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	CALY_MAP_PIN
} caly_local6 SEC(".maps");

/* -------------------------------------------------------------------------
 * 11-12. Dynamic bans. LRU so a flood of distinct sources evicts old entries
 * instead of failing inserts - a full ban table must never stop us banning.
 * ------------------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);            /* IPv4, network byte order */
	__type(value, struct ban_entry);
	__uint(max_entries, CALY_MAX_BAN_ENTRIES);
	CALY_MAP_PIN
} caly_ban4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct in6_key);
	__type(value, struct ban_entry);
	__uint(max_entries, CALY_MAX_BAN_ENTRIES);
	CALY_MAP_PIN
} caly_ban6 SEC(".maps");

/* -------------------------------------------------------------------------
 * 13-14. Per-source token buckets. SHARED, never PERCPU. See the header note.
 * ------------------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);            /* IPv4, network byte order */
	__type(value, struct rate_state);
	__uint(max_entries, CALY_MAX_RATE_ENTRIES);
	CALY_MAP_PIN
} caly_rate4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct in6_key);
	__type(value, struct rate_state);
	__uint(max_entries, CALY_MAX_RATE_ENTRIES);
	CALY_MAP_PIN
} caly_rate6 SEC(".maps");

/* -------------------------------------------------------------------------
 * 15. Conntrack-lite.
 *
 * struct conn_key carries explicit pad[2] and BPF hash lookups compare the raw
 * key bytes INCLUDING padding. Every consumer must __builtin_memset() the key
 * before filling it in; caly_conn_key_v4/v6() in parsing.h do that for you.
 * ------------------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct conn_key);
	__type(value, struct conn_state);
	__uint(max_entries, CALY_MAX_CONN_ENTRIES);
	CALY_MAP_PIN
} caly_conn SEC(".maps");

/* -------------------------------------------------------------------------
 * 16-17. Port-scan detection state (512-bit Bloom over destination ports).
 * ------------------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct scan_state);
	__uint(max_entries, CALY_MAX_SCAN_ENTRIES);
	CALY_MAP_PIN
} caly_scan4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct in6_key);
	__type(value, struct scan_state);
	__uint(max_entries, CALY_MAX_SCAN_ENTRIES);
	CALY_MAP_PIN
} caly_scan6 SEC(".maps");

/* -------------------------------------------------------------------------
 * 18-19. Top-talker accounting. Reporting only; nothing in the drop path
 * reads these, so a failed update is never a reason to change a verdict.
 * ------------------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct src_stats);
	__uint(max_entries, CALY_MAX_SRCSTAT_ENTRIES);
	CALY_MAP_PIN
} caly_top4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct in6_key);
	__type(value, struct src_stats);
	__uint(max_entries, CALY_MAX_SRCSTAT_ENTRIES);
	CALY_MAP_PIN
} caly_top6 SEC(".maps");

/* -------------------------------------------------------------------------
 * 20-22. Port policy.
 *
 * Plain 65536-entry arrays indexed by the HOST byte order port, so a lookup is
 * one bounds-checked array access with no hashing.
 *
 * caly_port_udp is consulted TWICE with different meanings: by DESTINATION
 * port for port_rule.mode, and by SOURCE port for CALY_PORT_F_AMPLIFIER. The
 * two read different fields and never collide, which is exactly what lets a
 * real DNS server coexist with the reflection filter.
 * ------------------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);            /* TCP port, HOST byte order */
	__type(value, struct port_rule);
	__uint(max_entries, CALY_PORT_TABLE_ENTRIES);
	CALY_MAP_PIN
} caly_port_tcp SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);            /* UDP port, HOST byte order */
	__type(value, struct port_rule);
	__uint(max_entries, CALY_PORT_TABLE_ENTRIES);
	CALY_MAP_PIN
} caly_port_udp SEC(".maps");

/* Per-port bucket STATE. Shared, not per-CPU, for the same reason as
 * caly_rate4/6. Indexed by CALY_PORT_TB_IDX(is_udp, host_port). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct token_bucket);
	__uint(max_entries, CALY_PORT_TB_ENTRIES);
	CALY_MAP_PIN
} caly_port_tb SEC(".maps");

/* -------------------------------------------------------------------------
 * 23-24. ICMP / ICMPv6 per-type policy.
 *
 * The loader refuses a configuration that sets ICMPv4 type 3 or ICMPv6 types
 * 2/133/134/135/136 to CALY_ICMP_DROP. Dropping those breaks PMTUD and IPv6
 * neighbour discovery, which disconnects the host rather than hardening it.
 * ------------------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);            /* ICMP type 0..255 */
	__type(value, __u32);          /* enum caly_icmp_policy */
	__uint(max_entries, CALY_ICMP_TABLE_ENTRIES);
	CALY_MAP_PIN
} caly_icmp4_pol SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);            /* ICMPv6 type 0..255 */
	__type(value, __u32);          /* enum caly_icmp_policy */
	__uint(max_entries, CALY_ICMP_TABLE_ENTRIES);
	CALY_MAP_PIN
} caly_icmp6_pol SEC(".maps");

/* -------------------------------------------------------------------------
 * 25. Per-interface overrides. A miss means "use fw_config.default_zone and
 * no per-interface flags", which is why this is a HASH and not an array
 * indexed by ifindex: ifindex is unbounded and mostly sparse.
 * ------------------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);            /* ifindex */
	__type(value, struct iface_config);
	__uint(max_entries, CALY_MAX_IFACE_ENTRIES);
	CALY_MAP_PIN
} caly_iface SEC(".maps");

/* -------------------------------------------------------------------------
 * 26-27. Event channels.
 *
 * caly_events (PERF_EVENT_ARRAY) is ALWAYS present: it works on every
 * supported kernel and is the compat path. caly_events_rb (RINGBUF, 5.8+) is
 * preferred when the loader sets CALY_F_CAP_RINGBUF; below 5.8 the loader
 * calls bpf_map__set_autocreate(caly_events_rb, false) and the map is never
 * created, or the whole declaration is compiled out with
 * -DCALY_HAVE_RINGBUF=0 for a pre-0.8 libbpf that lacks set_autocreate.
 *
 * max_entries 0 on the perf array asks libbpf to substitute the possible-CPU
 * count at load time. The loader also sets it explicitly, because relying on
 * that substitution across every shipped libbpf version is not a bet worth
 * taking when the failure mode is "events silently stop on CPU 8+".
 * ------------------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 0);
	CALY_MAP_PIN
} caly_events SEC(".maps");

#if CALY_HAVE_RINGBUF
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, CALY_RINGBUF_BYTES);
	CALY_MAP_PIN
} caly_events_rb SEC(".maps");
#endif

/* -------------------------------------------------------------------------
 * 28. Tail-call table.
 *
 * Slot 0 (SYN proxy) is populated only after the loader has confirmed the
 * 5.15+ raw syncookie helpers exist. An empty slot makes bpf_tail_call() a
 * no-op that returns to the caller, which is the entire reason the SYN proxy
 * lives behind a tail call: on a pre-5.15 kernel the program is never
 * autoloaded, so the verifier never sees a helper the kernel lacks.
 *
 * Slot 1 (IPv6 split) is optional and normally empty.
 * ------------------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, CALY_PROG_IDX_MAX);
	CALY_MAP_PIN
} caly_progs SEC(".maps");

/* -------------------------------------------------------------------------
 * 29. Per-CPU scratch.
 *
 * XDP programs get 512 bytes of stack. struct event alone is 88 and pkt_ctx is
 * 96, so anything non-trivial lives here. One entry, key 0, PERCPU so there is
 * no locking and no cross-CPU aliasing.
 * ------------------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct caly_scratch);
	__uint(max_entries, 1);
	CALY_MAP_PIN
} caly_scratch SEC(".maps");

/* -------------------------------------------------------------------------
 * Accessors.
 *
 * Every one of these bounds-checks its index before the lookup even though
 * array maps already reject out-of-range keys: an explicit check keeps the
 * verifier's range tracking simple and documents the bound at the call site.
 *
 * NOTE the fail-open discipline: a NULL return from any of these means "we
 * could not evaluate this rule", and the caller must PASS, never drop.
 * ------------------------------------------------------------------------- */

CALY_INLINE struct fw_config *caly_cfg_get(void)
{
	__u32 k = 0;

	return bpf_map_lookup_elem(&caly_config, &k);
}

CALY_INLINE struct caly_scratch *caly_scratch_get(void)
{
	__u32 k = 0;

	return bpf_map_lookup_elem(&caly_scratch, &k);
}

/* Charge one packet and its bytes to a stat_reason. Called exactly once per
 * packet per reason, immediately before returning a verdict. */
CALY_INLINE void caly_stat(__u32 reason, __u64 bytes)
{
	__u64 *pkts, *octets;

	if (reason >= STAT_MAX)
		return;

	pkts = bpf_map_lookup_elem(&caly_stats, &reason);
	if (pkts)
		*pkts += 1;

	octets = bpf_map_lookup_elem(&caly_stats_b, &reason);
	if (octets)
		*octets += bytes;
}

/* Packet-only counter, for reasons that are events rather than packet
 * dispositions (STAT_BAN_ADDED, STAT_CT_CREATED, STAT_TAILCALL_FAIL, ...). */
CALY_INLINE void caly_stat_ev(__u32 reason)
{
	__u64 *pkts;

	if (reason >= STAT_MAX)
		return;

	pkts = bpf_map_lookup_elem(&caly_stats, &reason);
	if (pkts)
		*pkts += 1;
}

CALY_INLINE void caly_gauge_add(__u32 gauge, __u64 v)
{
	__u64 *g;

	if (gauge >= CALY_G_MAX)
		return;

	g = bpf_map_lookup_elem(&caly_global, &gauge);
	if (g)
		*g += v;
}

/* Destination-port policy. `port` is HOST byte order. */
CALY_INLINE struct port_rule *caly_port_rule(int is_udp, __u16 port)
{
	__u32 k = (__u32)port;

	if (k >= CALY_PORT_TABLE_ENTRIES)
		return 0;

	return is_udp ? bpf_map_lookup_elem(&caly_port_udp, &k)
		      : bpf_map_lookup_elem(&caly_port_tcp, &k);
}

/* Per-port token bucket state. `port` is HOST byte order. */
CALY_INLINE struct token_bucket *caly_port_bucket(int is_udp, __u16 port)
{
	__u32 k = CALY_PORT_TB_IDX(is_udp, (__u32)port);

	if (k >= CALY_PORT_TB_ENTRIES)
		return 0;

	return bpf_map_lookup_elem(&caly_port_tb, &k);
}

/*
 * ICMP type policy. Returns the policy value; a missing entry is reported as
 * CALY_ICMP_PASS, because a lookup failure must never turn into a drop.
 *
 * The mandatory types are re-asserted HERE as well as in the loader. Two
 * independent enforcement points is not redundancy for its own sake: a
 * hand-edited pinned map, a partially applied config update, or a future
 * loader bug must not be able to black-hole PMTUD or IPv6 ND.
 */
CALY_INLINE __u32 caly_icmp4_policy(__u8 type)
{
	__u32 k = (__u32)type;
	__u32 *p;

	if (type == CALY_ICMP4_DEST_UNREACH)
		return CALY_ICMP_PASS;      /* code 4 is Fragmentation Needed */

	if (k >= CALY_ICMP_TABLE_ENTRIES)
		return CALY_ICMP_PASS;

	p = bpf_map_lookup_elem(&caly_icmp4_pol, &k);
	if (!p)
		return CALY_ICMP_PASS;
	if (*p >= CALY_ICMP_POL_MAX)
		return CALY_ICMP_PASS;
	return *p;
}

CALY_INLINE __u32 caly_icmp6_policy(__u8 type)
{
	__u32 k = (__u32)type;
	__u32 *p;

	/* PMTUD, RS, RA, NS, NA. IPv6 has no ARP; dropping these disconnects
	 * the host rather than hardening it. */
	if (type == CALY_ICMP6_PKT_TOOBIG || type == CALY_ICMP6_ROUTER_SOL ||
	    type == CALY_ICMP6_ROUTER_ADV || type == CALY_ICMP6_NEIGH_SOL ||
	    type == CALY_ICMP6_NEIGH_ADV)
		return CALY_ICMP_PASS;

	if (k >= CALY_ICMP_TABLE_ENTRIES)
		return CALY_ICMP_PASS;

	p = bpf_map_lookup_elem(&caly_icmp6_pol, &k);
	if (!p)
		return CALY_ICMP_PASS;
	if (*p >= CALY_ICMP_POL_MAX)
		return CALY_ICMP_PASS;
	return *p;
}

CALY_INLINE struct iface_config *caly_iface_get(__u32 ifindex)
{
	return bpf_map_lookup_elem(&caly_iface, &ifindex);
}

/* -------------------------------------------------------------------------
 * Address-keyed lookups.
 *
 * The v4 key is the raw network-order __u32 straight from the header; the v6
 * key is struct in6_key, which must be fully initialised (it has no padding,
 * but a partially filled key is still a guaranteed miss).
 * ------------------------------------------------------------------------- */

CALY_INLINE void caly_in6_key_set(struct in6_key *k, const __u32 *addr)
{
	k->a[0] = addr[0];
	k->a[1] = addr[1];
	k->a[2] = addr[2];
	k->a[3] = addr[3];
}

CALY_INLINE void caly_lpm4_key_set(struct lpm_key_v4 *k, __u32 addr_net)
{
	const __u8 *b = (const __u8 *)&addr_net;

	k->prefixlen = 32;      /* HOST order, per the LPM trie ABI */
	k->addr[0] = b[0];      /* NETWORK order, MSB first */
	k->addr[1] = b[1];
	k->addr[2] = b[2];
	k->addr[3] = b[3];
}

CALY_INLINE void caly_lpm6_key_set(struct lpm_key_v6 *k, const __u32 *addr)
{
	const __u8 *b = (const __u8 *)addr;
	unsigned int i;

	k->prefixlen = 128;
	CALY_UNROLL
	for (i = 0; i < 16u; i++)
		k->addr[i] = b[i];
}

/* -------------------------------------------------------------------------
 * Ban expiry.
 *
 * An expired entry is treated as a MISS and left for the userspace GC to
 * reap; deleting from the dataplane would serialise against every other CPU
 * touching the LRU for no benefit. CALY_BAN_F_PERMANENT ignores expiry_ns.
 * ------------------------------------------------------------------------- */
CALY_INLINE int caly_ban_active(const struct ban_entry *b, __u64 now_ns)
{
	if (!b)
		return 0;
	if (b->flags & CALY_BAN_F_PERMANENT)
		return 1;
	if (b->expiry_ns == 0)
		return 0;
	return b->expiry_ns > now_ns;
}

/* -------------------------------------------------------------------------
 * Event emission.
 *
 * Ring buffer when the loader probed it (5.8+), perf event array otherwise.
 * The perf array is the compat path and is always present.
 *
 * Losing an event is NEVER a reason to change a verdict: a full ring means we
 * are under load, which is exactly when dropping legitimate traffic because
 * we could not log about it would be worst. Both paths count the loss and
 * return; the caller ignores the return value in the drop path.
 * ------------------------------------------------------------------------- */
CALY_INLINE int caly_event_emit(void *ctx, const struct fw_config *cfg,
				struct event *ev)
{
	long err;

	ev->version = (__u8)CALY_ABI_VERSION_MAJOR;

#if CALY_HAVE_RINGBUF
	if (CALY_CAN_RINGBUF(cfg)) {
		struct event *slot;

		slot = bpf_ringbuf_reserve(&caly_events_rb,
					   sizeof(struct event), 0);
		if (!slot) {
			caly_stat_ev(STAT_EVENT_LOST);
			caly_gauge_add(CALY_G_EVENTS_LOST, 1);
			return -1;
		}
		__builtin_memcpy(slot, ev, sizeof(struct event));
		bpf_ringbuf_submit(slot, 0);
		caly_stat_ev(STAT_EVENT_EMITTED);
		caly_gauge_add(CALY_G_EVENTS, 1);
		return 0;
	}
#else
	(void)cfg;
#endif

	err = bpf_perf_event_output(ctx, &caly_events, BPF_F_CURRENT_CPU,
				    ev, sizeof(struct event));
	if (err) {
		caly_stat_ev(STAT_EVENT_LOST);
		caly_gauge_add(CALY_G_EVENTS_LOST, 1);
		return -1;
	}
	caly_stat_ev(STAT_EVENT_EMITTED);
	caly_gauge_add(CALY_G_EVENTS, 1);
	return 0;
}

/*
 * Sampling decision for events. log_sample_rate is "emit 1 in N"; 0 means
 * never. Uses bpf_get_prandom_u32() rather than a counter so that a periodic
 * attack pattern cannot phase-lock with the sampler and become invisible.
 * CALY_PORT_F_LOG on a port and a ban insertion bypass sampling entirely -
 * those are decisions the operator asked to see every time.
 */
CALY_INLINE int caly_event_sampled(const struct fw_config *cfg, int force)
{
	__u32 n;

	if (!cfg)
		return 0;
	if (!(cfg->flags & CALY_F_LOG_EVENTS))
		return 0;
	if (force)
		return 1;

	n = cfg->log_sample_rate;
	if (n == 0)
		return 0;
	if (n == 1)
		return 1;

	return (bpf_get_prandom_u32() % n) == 0;
}

#endif /* __CALY_ANTI_MAPS_H */
