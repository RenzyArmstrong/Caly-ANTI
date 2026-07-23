/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - XDP/eBPF DDoS mitigation suite
 * src/bpf/common.h - THE authoritative ABI contract.
 *
 * This header is included VERBATIM by:
 *   - the BPF dataplane objects  (src/bpf/*.bpf.c)
 *   - the userspace loader/daemon (src/user/*.c)
 *   - the CLI / stats reporter
 *
 * Everything that crosses the kernel/userspace boundary is defined here and
 * ONLY here. If you need a new knob, add it to the reserved[] headroom of
 * struct fw_config and bump CALY_ABI_VERSION. Never reorder, never resize,
 * never insert a field in the middle: struct fw_config is memcpy()'d verbatim
 * into a BPF_MAP_TYPE_ARRAY and a single byte of layout skew silently
 * corrupts every threshold in the dataplane.
 *
 * PREREQUISITE INCLUDES (this header intentionally includes nothing):
 *   BPF side:        #include "vmlinux.h"     (CO-RE, generated from BTF)
 *   userspace side:  #include <linux/types.h> (or <stdint.h> + typedefs)
 *                    #define CALY_USERSPACE 1   before including this file
 *                    to get the string-table helpers compiled in.
 *
 * RULES OF THE ROAD (violate these and the build or the box breaks):
 *   1. Fixed-width types only. No int, no long, no size_t, no enums as
 *      struct members, no bitfields, no pointers.
 *   2. Every struct that crosses the boundary is 8-byte aligned with
 *      EXPLICIT padding. Compile-time assertions at the bottom enforce it.
 *   3. All multi-byte packet-derived fields (addresses, ports in conn_key,
 *      event, pkt_ctx) are stored in NETWORK byte order, exactly as seen on
 *      the wire. All configuration fields (fw_config.mgmt_*_ports, port map
 *      indices) are HOST byte order. Convert once, at the boundary.
 *   4. BPF hash map keys MUST be fully initialised before lookup/update.
 *      __builtin_memset(&key, 0, sizeof(key)) FIRST, always. Stack garbage
 *      in the padding bytes turns every lookup into a miss.
 *   5. Kernel object-name limit is 16 bytes including NUL, so every map name
 *      constant below is <= 15 characters. Do not lengthen them.
 */

#ifndef __CALY_ANTI_COMMON_H
#define __CALY_ANTI_COMMON_H

/* -------------------------------------------------------------------------
 * ABI identity
 * ------------------------------------------------------------------------- */

/* Bump the minor on additive changes that consume reserved[] headroom.
 * Bump the major on ANY layout change; the loader refuses to attach when the
 * major it was compiled with differs from the major in a pinned config map. */
#define CALY_ABI_VERSION_MAJOR  1u
#define CALY_ABI_VERSION_MINOR  1u
#define CALY_ABI_VERSION        ((CALY_ABI_VERSION_MAJOR << 16) | \
                                 CALY_ABI_VERSION_MINOR)

#ifndef CALY_INLINE
#define CALY_INLINE static inline __attribute__((always_inline))
#endif

/* `#pragma unroll` is a clang extension. GCC (which builds the userspace
 * side) warns about the unknown pragma and would fail a -Werror build, so it
 * is spelled through _Pragma and compiled out for non-clang. */
#if defined(__clang__)
#define CALY_UNROLL _Pragma("unroll")
#else
#define CALY_UNROLL
#endif

/* -------------------------------------------------------------------------
 * Compile-time constants (shared sizing / bounds)
 *
 * Every one of these is also a hard verifier bound: loops in the dataplane
 * are #pragma unroll'd against these constants, never against a config value.
 * The matching fw_config fields are runtime knobs that may only LOWER the
 * effective bound, never raise it above the constant.
 * ------------------------------------------------------------------------- */

#define CALY_VLAN_MAX_DEPTH     2u    /* 802.1Q + 802.1ad QinQ                */
#define CALY_IP6_EXT_MAX        8u    /* IPv6 extension headers walked        */
#define CALY_TUNNEL_MAX_DEPTH   1u    /* one level of IPIP/IP6IP6/GRE         */
#define CALY_MGMT_PORTS_MAX     16u   /* mgmt allowlist slots, per protocol   */
#define CALY_CFG_RESERVED       24u   /* fw_config future-proofing headroom   */

#define CALY_SCAN_BITMAP_WORDS  8u
#define CALY_SCAN_BITMAP_BITS   (CALY_SCAN_BITMAP_WORDS * 64u)  /* 512 bits   */
#define CALY_SCAN_BITMAP_MASK   (CALY_SCAN_BITMAP_BITS - 1u)

#define CALY_NSEC_PER_SEC       1000000000ULL
#define CALY_NSEC_PER_MSEC      1000000ULL

/* Token-bucket arithmetic bounds. rate is in units/sec (packets/sec or
 * bytes/sec); the refill window is clamped so that elapsed_ns * rate can
 * never overflow __u64:  1e9 * 4e9 = 4e18 < 1.8e19 (U64_MAX). */
#define CALY_TB_RATE_MAX        4000000000ULL   /* 4 Gpps or 32 Gbit/s        */
#define CALY_TB_MAX_ELAPSED_NS  CALY_NSEC_PER_SEC

/* Ethertypes / protocol numbers. Redefining these locally rather than relying
 * on vmlinux.h keeps the header self-contained on both sides of the boundary
 * (vmlinux.h carries types, not the ETH_P_*/IPPROTO_* macros). */
#define CALY_ETH_P_IP           0x0800
#define CALY_ETH_P_IPV6         0x86DD
#define CALY_ETH_P_ARP          0x0806
#define CALY_ETH_P_8021Q        0x8100
#define CALY_ETH_P_8021AD       0x88A8
#define CALY_ETH_P_QINQ1        0x9100  /* legacy vendor QinQ tags */
#define CALY_ETH_P_QINQ2        0x9200
#define CALY_ETH_P_QINQ3        0x9300

#define CALY_IPPROTO_HOPOPTS    0
#define CALY_IPPROTO_ICMP       1
#define CALY_IPPROTO_IPIP       4
#define CALY_IPPROTO_TCP        6
#define CALY_IPPROTO_UDP        17
#define CALY_IPPROTO_IPV6       41    /* 6in4 / IP6IP6 */
#define CALY_IPPROTO_ROUTING    43
#define CALY_IPPROTO_FRAGMENT   44
#define CALY_IPPROTO_GRE        47
#define CALY_IPPROTO_ESP        50
#define CALY_IPPROTO_AH         51
#define CALY_IPPROTO_ICMPV6     58
#define CALY_IPPROTO_NONE       59
#define CALY_IPPROTO_DSTOPTS    60
#define CALY_IPPROTO_MH         135
#define CALY_IPPROTO_SCTP       132

/* TCP flag bits, as laid out in the 13th byte of the TCP header. */
#define CALY_TCP_FIN            0x01
#define CALY_TCP_SYN            0x02
#define CALY_TCP_RST            0x04
#define CALY_TCP_PSH            0x08
#define CALY_TCP_ACK            0x10
#define CALY_TCP_URG            0x20
#define CALY_TCP_ECE            0x40
#define CALY_TCP_CWR            0x80
#define CALY_TCP_FLAG_MASK      0x3F  /* FIN..URG, ignore ECN negotiation     */
#define CALY_TCP_ALL_FLAGS      0xFF

/* Address families. Deliberately NOT the libc AF_INET values: they differ
 * across libcs and we store this in a hash key. */
#define CALY_AF_INET            4u
#define CALY_AF_INET6           6u

/* -------------------------------------------------------------------------
 * Map names. Kernel BPF_OBJ_NAME_LEN is 16 (15 chars + NUL). Userspace looks
 * maps up by these constants only; never spell a map name inline.
 * ------------------------------------------------------------------------- */

#define CALY_MAP_CONFIG         "caly_config"     /* ARRAY, 1x fw_config      */
#define CALY_MAP_STATS          "caly_stats"      /* PERCPU_ARRAY pkt counts  */
#define CALY_MAP_STATS_BYTES    "caly_stats_b"    /* PERCPU_ARRAY byte counts */
#define CALY_MAP_GLOBAL         "caly_global"     /* PERCPU_ARRAY gauges      */
#define CALY_MAP_ALLOW_V4       "caly_allow4"     /* LPM_TRIE                 */
#define CALY_MAP_ALLOW_V6       "caly_allow6"     /* LPM_TRIE                 */
#define CALY_MAP_BLOCK_V4       "caly_block4"     /* LPM_TRIE                 */
#define CALY_MAP_BLOCK_V6       "caly_block6"     /* LPM_TRIE                 */
#define CALY_MAP_LOCAL_V4       "caly_local4"     /* LPM_TRIE, our prefixes   */
#define CALY_MAP_LOCAL_V6       "caly_local6"     /* LPM_TRIE, our prefixes   */
#define CALY_MAP_BAN_V4         "caly_ban4"       /* LRU_HASH                 */
#define CALY_MAP_BAN_V6         "caly_ban6"       /* LRU_HASH                 */
#define CALY_MAP_RATE_V4        "caly_rate4"      /* LRU_HASH                 */
#define CALY_MAP_RATE_V6        "caly_rate6"      /* LRU_HASH                 */
#define CALY_MAP_CONN           "caly_conn"       /* LRU_HASH conntrack-lite  */
#define CALY_MAP_SCAN_V4        "caly_scan4"      /* LRU_HASH                 */
#define CALY_MAP_SCAN_V6        "caly_scan6"      /* LRU_HASH                 */
#define CALY_MAP_TOP_V4         "caly_top4"       /* LRU_HASH src_stats       */
#define CALY_MAP_TOP_V6         "caly_top6"       /* LRU_HASH src_stats       */
#define CALY_MAP_PORT_TCP       "caly_port_tcp"   /* ARRAY 65536x port_rule   */
#define CALY_MAP_PORT_UDP       "caly_port_udp"   /* ARRAY 65536x port_rule   */
#define CALY_MAP_PORT_TB        "caly_port_tb"    /* ARRAY 131072x bucket     */
#define CALY_MAP_ICMP4_POL      "caly_icmp4_pol"  /* ARRAY 256x __u32         */
#define CALY_MAP_ICMP6_POL      "caly_icmp6_pol"  /* ARRAY 256x __u32         */
#define CALY_MAP_IFACE          "caly_iface"      /* HASH ifindex->iface_cfg  */
#define CALY_MAP_EVENTS         "caly_events"     /* PERF_EVENT_ARRAY         */
#define CALY_MAP_EVENTS_RB      "caly_events_rb"  /* RINGBUF (5.8+, optional) */
#define CALY_MAP_PROGS          "caly_progs"      /* PROG_ARRAY tail calls    */
#define CALY_MAP_SCRATCH        "caly_scratch"    /* PERCPU_ARRAY 1x scratch  */

/* BPF program (C function) names, for bpf_object__find_program_by_name(). */
#define CALY_PROG_XDP_MAIN      "caly_xdp_main"
#define CALY_PROG_XDP_SYNPROXY  "caly_xdp_synproxy"
#define CALY_PROG_XDP_IPV6      "caly_xdp_ipv6"
#define CALY_PROG_TC_INGRESS    "caly_tc_ingress"  /* clsact ingress, rung 3 */
#define CALY_PROG_TC_EGRESS     "caly_tc_egress"

/* Pin locations. The daemon pins everything so the CLI can attach without
 * being the loader, and so maps survive a daemon restart. */
#define CALY_BPFFS_ROOT         "/sys/fs/bpf"
#define CALY_PIN_DIR            "/sys/fs/bpf/calyanti"
#define CALY_RUN_DIR            "/run/calyanti"
#define CALY_CONF_PATH          "/etc/calyanti/calyanti.conf"

/* THE control socket. Single source of truth: the daemon binds this path and
 * every client (calyctl, calywatch) connects to it. src/user/ipc.h aliases
 * CALY_CTRL_SOCK_PATH to this; do not spell the path anywhere else. */
#define CALY_CTL_SOCK           CALY_RUN_DIR "/control.sock"

/* -------------------------------------------------------------------------
 * Enumerations. NONE of these may be used as a struct member type; store them
 * in a __u32 field. They exist to name constants, not to define layout.
 * ------------------------------------------------------------------------- */

/* Operating mode. Written by the daemon into fw_config.mode; the dataplane
 * only ever reads it. Escalation/de-escalation is a userspace decision made
 * from the global gauges, never from inside XDP. */
enum fw_mode {
	FW_MODE_NORMAL       = 0,  /* full policy, generous thresholds          */
	FW_MODE_ELEVATED     = 1,  /* thresholds scaled down, events sampled up */
	FW_MODE_UNDER_ATTACK = 2,  /* aggressive: synproxy on, strict buckets   */
	FW_MODE_LOCKDOWN     = 3,  /* allowlist + mgmt ports + conntrack ONLY   */
	FW_MODE_MONITOR_ONLY = 4,  /* evaluate everything, drop nothing         */
	FW_MODE_MAX          = 5,
};

/* Verdict recorded in struct event. Maps 1:1 onto XDP actions except for
 * CALY_VERDICT_MONITOR, which means "this WOULD have been dropped but the
 * configuration says observe only". XDP_ABORTED is deliberately absent: it is
 * an error tracepoint, not a drop, and must never appear in a production
 * return path. */
enum caly_verdict {
	CALY_VERDICT_PASS    = 0,
	CALY_VERDICT_DROP    = 1,
	CALY_VERDICT_TX      = 2,
	CALY_VERDICT_MONITOR = 3,
	CALY_VERDICT_MAX     = 4,
};

/* Per-source token buckets. rate_state.tb[] is indexed by this enum, and so
 * are fw_config.tb_rate[] / fw_config.tb_burst[]. Keep the three in lockstep. */
enum caly_tb_kind {
	CALY_TB_PPS     = 0,  /* all packets from this source, packets/sec      */
	CALY_TB_BPS     = 1,  /* all bytes from this source,   bytes/sec        */
	CALY_TB_SYN     = 2,  /* TCP SYN (no ACK) packets/sec                   */
	CALY_TB_UDP     = 3,  /* UDP packets/sec                                */
	CALY_TB_ICMP    = 4,  /* ICMP + ICMPv6 packets/sec                      */
	CALY_TB_NEWCONN = 5,  /* conntrack misses (new flows) per sec           */
	CALY_TB_MAX     = 6,
};

/* Global per-CPU gauges. Userspace sums across CPUs each tick, differentiates
 * against the previous sample to get a rate, and compares to the hi/lo
 * thresholds in fw_config to drive mode escalation. */
enum caly_gauge {
	CALY_G_PKTS        = 0,
	CALY_G_BYTES       = 1,
	CALY_G_SYN         = 2,
	CALY_G_NEWCONN     = 3,
	CALY_G_DROPS       = 4,
	CALY_G_UDP         = 5,
	CALY_G_ICMP        = 6,
	CALY_G_FRAG        = 7,
	CALY_G_SYNPROXY_TX = 8,
	CALY_G_EVENTS      = 9,
	CALY_G_EVENTS_LOST = 10,
	CALY_G_MAX         = 11,
};

/* Port policy modes, stored in port_rule.mode. */
enum caly_port_mode {
	CALY_PORT_CLOSED    = 0,  /* inbound drop unless conntrack/allowlist    */
	CALY_PORT_OPEN      = 1,  /* inbound permitted, still rate limited      */
	CALY_PORT_RATELIMIT = 2,  /* inbound permitted up to rate/burst         */
	CALY_PORT_MODE_MAX  = 3,
};

/* ICMP / ICMPv6 per-type policy, stored as __u32 in caly_icmp4_pol and
 * caly_icmp6_pol indexed by ICMP type (0..255). */
enum caly_icmp_policy {
	CALY_ICMP_DROP      = 0,
	CALY_ICMP_PASS      = 1,
	CALY_ICMP_RATELIMIT = 2,
	CALY_ICMP_POL_MAX   = 3,
};

/* Interface zone, stored in iface_config.zone. CALY_ZONE_UNSPEC means "use
 * fw_config.default_zone". */
enum caly_zone {
	CALY_ZONE_UNSPEC = 0,
	CALY_ZONE_WAN    = 1,
	CALY_ZONE_LAN    = 2,
	CALY_ZONE_DMZ    = 3,
	CALY_ZONE_MAX    = 4,
};

/* Degradation ladder, best first. fw_config.dataplane_pref pins the installer
 * to one rung; CALY_DP_AUTO probes downward from the top. */
enum caly_dataplane {
	CALY_DP_AUTO         = 0,
	CALY_DP_XDP_NATIVE   = 1,
	CALY_DP_XDP_GENERIC  = 2,
	CALY_DP_TC           = 3,
	CALY_DP_NFTABLES     = 4,
	CALY_DP_IPTABLES     = 5,
	CALY_DP_MAX          = 6,
};

/* XDP attach mode preference, fw_config.xdp_attach_pref. */
enum caly_xdp_mode {
	CALY_XDP_AUTO    = 0,
	CALY_XDP_NATIVE  = 1,   /* XDP_FLAGS_DRV_MODE  */
	CALY_XDP_GENERIC = 2,   /* XDP_FLAGS_SKB_MODE  */
	CALY_XDP_OFFLOAD = 3,   /* XDP_FLAGS_HW_MODE   */
	CALY_XDP_MODE_MAX = 4,
};

/* Tail-call slots in caly_progs (BPF_MAP_TYPE_PROG_ARRAY).
 *
 * CALY_PROG_SYNPROXY is populated ONLY when the loader has confirmed via
 * libbpf_probe_bpf_helper(BPF_PROG_TYPE_XDP, BPF_FUNC_tcp_raw_gen_syncookie_ipv4)
 * that the 5.15+ helpers exist. On older kernels the program is marked
 * autoload=false, the slot stays empty, and bpf_tail_call() simply returns
 * (falling through to the SYN rate-limit fallback in the caller). That
 * fall-through is the entire reason the SYN proxy lives behind a tail call.
 *
 * CALY_PROG_IPV6 is OPTIONAL. It exists so the IPv6 path can be split out
 * when the verifier's instruction budget is tight (notably on RHEL 8 era
 * 4.18 backports). If the main program handles IPv6 inline, leave the slot
 * empty; the tail call fails and execution continues in the caller. */
enum caly_prog_idx {
	CALY_PROG_IDX_SYNPROXY = 0,
	CALY_PROG_IDX_IPV6     = 1,
	CALY_PROG_IDX_RSVD2    = 2,
	CALY_PROG_IDX_RSVD3    = 3,
	CALY_PROG_IDX_MAX      = 4,
};

/* Reason why a ban was installed / how it was installed. ban_entry.flags. */
#define CALY_BAN_F_AUTO         (1u << 0)  /* inserted by the dataplane      */
#define CALY_BAN_F_MANUAL       (1u << 1)  /* inserted by the operator/CLI   */
#define CALY_BAN_F_PERMANENT    (1u << 2)  /* expiry_ns ignored              */
#define CALY_BAN_F_ESCALATED    (1u << 3)  /* TTL has been escalated >= once */
#define CALY_BAN_F_FEED         (1u << 4)  /* came from a threat feed        */

/* rate_state.flags */
#define CALY_RS_F_SEEDED        (1u << 0)  /* buckets initialised            */
#define CALY_RS_F_STRIKING      (1u << 1)  /* inside an active strike window */

/* conn_state.state - conntrack-lite state machine. */
#define CALY_CT_NEW             0u  /* created, no handshake evidence yet    */
#define CALY_CT_SYN_RECV        1u  /* inbound SYN accepted by policy        */
#define CALY_CT_SYN_SENT        2u  /* outbound SYN seen by the tc egress hk */
#define CALY_CT_ESTABLISHED     3u  /* handshake completed / bidirectional   */
#define CALY_CT_FIN_WAIT        4u  /* FIN seen in either direction          */
#define CALY_CT_CLOSED          5u  /* RST or both FINs                      */
#define CALY_CT_STATE_MAX       6u

/* conn_state.flags */
#define CALY_CT_F_OUTBOUND      (1u << 0)  /* we initiated the flow          */
#define CALY_CT_F_SYNPROXIED    (1u << 1)  /* spliced through the SYN proxy  */
#define CALY_CT_F_MGMT          (1u << 2)  /* touches a mgmt port; never GC  */
#define CALY_CT_F_ALLOWLIST     (1u << 3)  /* peer is allowlisted            */
#define CALY_CT_F_SEEN_REPLY    (1u << 4)  /* traffic seen in both dirs      */

/* port_rule.flags */
#define CALY_PORT_F_AMPLIFIER   (1u << 0)  /* drop pkts whose SOURCE port is
                                            * this port (reflection filter)  */
#define CALY_PORT_F_MGMT        (1u << 1)  /* management port: never dropped */
#define CALY_PORT_F_SYNPROXY    (1u << 2)  /* SYN-proxy inbound SYNs here    */
#define CALY_PORT_F_NO_CT       (1u << 3)  /* do not create conntrack state  */
#define CALY_PORT_F_LOG         (1u << 4)  /* emit an event on every verdict */
#define CALY_PORT_F_PRESENT     (1u << 5)  /* rule was explicitly configured;
                                            * distinguishes an operator-set
                                            * mode==CLOSED (byte-identical to
                                            * an all-zero slot) from a
                                            * never-written array entry, so
                                            * the dataplane can charge
                                            * STAT_DROP_PORT_CLOSED vs
                                            * STAT_DROP_DEFAULT_DENY. Set by
                                            * maps.c on every rule it writes. */

/* iface_config.flags */
#define CALY_IF_F_WAN           (1u << 0)  /* apply bogon/martian filtering  */
#define CALY_IF_F_MONITOR       (1u << 1)  /* per-iface monitor-only          */
#define CALY_IF_F_DISABLED      (1u << 2)  /* bypass entirely (XDP_PASS)      */
#define CALY_IF_F_DROP_PRIVATE  (1u << 3)  /* RFC1918 source is a martian    */
#define CALY_IF_F_NO_IPV6       (1u << 4)  /* drop all IPv6 on this iface    */
#define CALY_IF_F_TRUST_VLAN    (1u << 5)  /* accept tagged frames           */

/* rule_meta.flags (allow / block / local LPM tries) */
#define CALY_RULE_F_ALLOW       (1u << 0)
#define CALY_RULE_F_BLOCK       (1u << 1)
#define CALY_RULE_F_LOCAL       (1u << 2)
#define CALY_RULE_F_BYPASS_RATE (1u << 3)  /* allowlist: skip token buckets  */
#define CALY_RULE_F_LOG         (1u << 4)

/* rule_meta.tag namespaces. Blessed here so the daemon (config.c/maps.c), the
 * CLI and the threat-feed loader cannot disagree: a reload flushes only
 * CALY_TAG_CONF (plus CALY_TAG_AUTO for caly_local*), so feed- and CLI-added
 * prefixes survive a config reload. tag is a free-form __u32, so this is not an
 * ABI/layout change - only a shared numbering convention. */
#define CALY_TAG_CONF           0u        /* came from calyanti.conf         */
#define CALY_TAG_AUTO           1u        /* auto-discovered (interface addrs)*/
#define CALY_TAG_CLI            2u        /* added at runtime by the CLI      */
#define CALY_TAG_ADMIN          3u        /* detected administrative peer     */
#define CALY_TAG_FEED_BASE      1000u     /* threat feeds: 1000 + feed id     */

/* -------------------------------------------------------------------------
 * fw_config.flags - master feature toggles.
 *
 * flags is __u64, so use the ULL suffix. Bits 0..31 are policy, 32..47 are
 * loader-discovered capabilities (written by the daemon after probing, never
 * by the operator), 48..63 are reserved.
 * ------------------------------------------------------------------------- */

#define CALY_F_ENABLED           (1ULL << 0)  /* master switch                */
#define CALY_F_MONITOR_ONLY      (1ULL << 1)  /* evaluate, never drop         */
#define CALY_F_IPV4              (1ULL << 2)
#define CALY_F_IPV6              (1ULL << 3)
#define CALY_F_VLAN_INSPECT      (1ULL << 4)
#define CALY_F_TUNNEL_INSPECT    (1ULL << 5)
#define CALY_F_ANOMALY_CHECKS    (1ULL << 6)  /* truncation/ihl/totlen/doff   */
#define CALY_F_LAND_CHECK        (1ULL << 7)
#define CALY_F_BOGON_FILTER      (1ULL << 8)  /* 0/8 127/8 169.254/16 224/4.. */
#define CALY_F_WAN_DROP_PRIVATE  (1ULL << 9)  /* RFC1918 source on a WAN port */
#define CALY_F_TCP_FLAG_CHECKS   (1ULL << 10)
#define CALY_F_FRAG_CHECKS       (1ULL << 11) /* tiny frags, frag_off == 1    */
#define CALY_F_DROP_ALL_FRAGS    (1ULL << 12) /* paranoid: no fragments at all*/
#define CALY_F_ICMP_FILTER       (1ULL << 13)
#define CALY_F_DROP_IP4_OPTIONS  (1ULL << 14) /* ihl > 5 (source routing etc.)*/
#define CALY_F_DROP_RH0          (1ULL << 15) /* IPv6 routing header type 0   */
#define CALY_F_TTL_CHECK         (1ULL << 16) /* enforce ip_min_ttl           */
#define CALY_F_ALLOWLIST         (1ULL << 17)
#define CALY_F_BLOCKLIST         (1ULL << 18)
#define CALY_F_AUTOBAN           (1ULL << 19)
#define CALY_F_RATE_LIMIT        (1ULL << 20) /* per-source token buckets     */
#define CALY_F_ANTI_AMPLIFY      (1ULL << 21) /* reflection source-port filter*/
#define CALY_F_PORT_POLICY       (1ULL << 22)
#define CALY_F_DEFAULT_DENY      (1ULL << 23) /* unlisted port == closed      */
#define CALY_F_CONNTRACK         (1ULL << 24)
#define CALY_F_PORTSCAN_DETECT   (1ULL << 25)
#define CALY_F_SYNPROXY          (1ULL << 26) /* operator wants the SYN proxy */
#define CALY_F_SRC_STATS         (1ULL << 27) /* top-talker accounting        */
#define CALY_F_LOG_EVENTS        (1ULL << 28)
#define CALY_F_MGMT_BYPASS_ALL   (1ULL << 29) /* mgmt ports skip rate limits  */
#define CALY_F_LOCKDOWN_ICMP     (1ULL << 30) /* keep PMTUD alive in LOCKDOWN */
#define CALY_F_DROP_UNKNOWN_L3   (1ULL << 31) /* non-IP, non-ARP ethertypes   */

/* --- loader-discovered capabilities: read-only for the operator --- */
#define CALY_F_CAP_SYNPROXY      (1ULL << 32) /* 5.15+ raw syncookie helpers  */
#define CALY_F_CAP_RINGBUF       (1ULL << 33) /* 5.8+ BPF_MAP_TYPE_RINGBUF    */
#define CALY_F_CAP_XDP_NATIVE    (1ULL << 34) /* driver supports XDP_FLAGS_DRV*/
#define CALY_F_CAP_TC_EGRESS     (1ULL << 35) /* clsact egress hook attached  */
#define CALY_F_CAP_BTF           (1ULL << 36) /* /sys/kernel/btf/vmlinux ok   */
#define CALY_F_CAP_XDP_TX        (1ULL << 37) /* XDP_TX usable on this driver */
#define CALY_F_CAP_LRU_PERCPU    (1ULL << 38) /* reserved capability bit      */
#define CALY_F_CAP_BATCH_OPS     (1ULL << 39) /* 5.6+ map batch syscalls      */

/* Convenience masks. */
#define CALY_F_DEFAULT_POLICY \
	(CALY_F_ENABLED | CALY_F_IPV4 | CALY_F_IPV6 | CALY_F_VLAN_INSPECT | \
	 CALY_F_ANOMALY_CHECKS | CALY_F_LAND_CHECK | CALY_F_BOGON_FILTER | \
	 CALY_F_TCP_FLAG_CHECKS | CALY_F_FRAG_CHECKS | CALY_F_ICMP_FILTER | \
	 CALY_F_ALLOWLIST | CALY_F_BLOCKLIST | CALY_F_AUTOBAN | \
	 CALY_F_RATE_LIMIT | CALY_F_ANTI_AMPLIFY | CALY_F_CONNTRACK | \
	 CALY_F_PORTSCAN_DETECT | CALY_F_SRC_STATS | CALY_F_LOG_EVENTS | \
	 CALY_F_MGMT_BYPASS_ALL | CALY_F_LOCKDOWN_ICMP)

#define CALY_F_OPERATOR_MASK     0x00000000FFFFFFFFULL  /* settable from conf */
#define CALY_F_CAP_MASK          0x0000FFFF00000000ULL  /* probed by loader   */

/* -------------------------------------------------------------------------
 * enum stat_reason - the index space of the per-CPU statistics arrays.
 *
 * EVERY distinct decision in the dataplane has exactly one code here. The
 * dataplane increments caly_stats[reason] (packets) and caly_stats_b[reason]
 * (bytes) on every packet, exactly once, immediately before returning its
 * verdict. STAT_MAX is the map's max_entries; it is not a valid index.
 *
 * Codes are append-only. Inserting a code in the middle renumbers the wire
 * format of struct event.reason and invalidates every historical metric.
 * ------------------------------------------------------------------------- */
enum stat_reason {
	/* ---- aggregates: incremented in addition to the specific reason ---- */
	STAT_PKT_TOTAL = 0,
	STAT_PASS_TOTAL,
	STAT_DROP_TOTAL,
	STAT_TX_TOTAL,
	STAT_MONITOR_WOULD_DROP,

	/* ---- explicit pass reasons ---- */
	STAT_PASS_NOT_IP,             /* ARP and friends, policy says forward   */
	STAT_PASS_LAN_IFACE,          /* iface zone is LAN/DMZ, bypass          */
	STAT_PASS_DISABLED,           /* CALY_F_ENABLED clear, or iface disabled*/
	STAT_PASS_ALLOWLIST,          /* LPM allowlist hit: the escape hatch    */
	STAT_PASS_MGMT_PORT,          /* SSH / configured mgmt port             */
	STAT_PASS_CONNTRACK,          /* established flow short-circuit         */
	STAT_PASS_PORT_OPEN,          /* port policy said open                  */
	STAT_PASS_PORT_RATE_OK,       /* port policy rate limit, conforming     */
	STAT_PASS_ICMP_POLICY,        /* ICMP type explicitly permitted         */
	STAT_PASS_ICMP6_ND,           /* NS/NA/RS/RA (133-136), mandatory       */
	STAT_PASS_ICMP6_PMTUD,        /* Packet Too Big (type 2), mandatory     */
	STAT_PASS_ICMP4_PMTUD,        /* Dest Unreach / Frag Needed (3/4)       */
	STAT_PASS_SYNCOOKIE_OK,       /* raw cookie validated, splice to stack  */
	STAT_PASS_DEFAULT,            /* nothing matched, default policy allow  */

	/* ---- parse / truncation / malformed ---- */
	STAT_DROP_ETH_TRUNC,
	STAT_DROP_VLAN_TRUNC,
	STAT_DROP_VLAN_DEPTH,         /* more tags than CALY_VLAN_MAX_DEPTH     */
	STAT_DROP_L3_UNKNOWN,         /* unhandled ethertype, default deny      */
	STAT_DROP_IP4_TRUNC,
	STAT_DROP_IP4_IHL,            /* ihl < 5                                */
	STAT_DROP_IP4_TOTLEN,         /* tot_len < ihl*4, or > frame            */
	STAT_DROP_IP4_OPTIONS,        /* ihl > 5 and options are refused        */
	STAT_DROP_IP6_TRUNC,
	STAT_DROP_IP6_EXT_DEPTH,      /* more than CALY_IP6_EXT_MAX ext headers */
	STAT_DROP_IP6_EXT_TRUNC,
	STAT_DROP_IP6_RH0,            /* routing header type 0 (RFC 5095)       */
	STAT_DROP_IP6_DISABLED,       /* IPv6 off globally or per interface     */
	STAT_DROP_TTL_ZERO,           /* ttl / hop_limit == 0                   */
	STAT_DROP_TTL_LOW,            /* below fw_config.ip_min_ttl             */
	STAT_DROP_TUNNEL_TRUNC,
	STAT_DROP_TUNNEL_DEPTH,       /* nested beyond CALY_TUNNEL_MAX_DEPTH    */
	STAT_DROP_TUNNEL_PROTO,       /* tunnel type not permitted              */
	STAT_DROP_GRE_MALFORMED,      /* GRE version/flags we refuse to parse   */
	STAT_DROP_L4_TRUNC,           /* TCP/UDP/ICMP header past data_end      */
	STAT_DROP_L4_UNKNOWN,         /* protocol not TCP/UDP/ICMP, default deny*/
	STAT_DROP_L4_PORT_ZERO,       /* source or destination port 0           */

	/* ---- address anomalies ---- */
	STAT_DROP_LAND,               /* src == dst (LAND attack)               */
	STAT_DROP_BOGON_SRC,          /* 0/8 127/8 169.254/16 240/4 etc.        */
	STAT_DROP_PRIVATE_SRC,        /* RFC1918 arriving on a WAN interface    */
	STAT_DROP_MCAST_SRC,          /* 224/4 or ff00::/8 used as a source     */
	STAT_DROP_BCAST_SRC,          /* 255.255.255.255 as a source            */
	STAT_DROP_IP6_SRC_UNSPEC,     /* ::                                     */
	STAT_DROP_IP6_SRC_LOOPBACK,   /* ::1                                    */
	STAT_DROP_SRC_SELF,           /* source is one of our own prefixes      */

	/* ---- fragmentation ---- */
	STAT_DROP_FRAG_TINY,          /* first fragment smaller than the min    */
	STAT_DROP_FRAG_OFF_ONE,       /* frag_off == 1, classic overlap evasion */
	STAT_DROP_FRAG_POLICY,        /* CALY_F_DROP_ALL_FRAGS                  */
	STAT_DROP_FRAG_ICMP,          /* fragmented ICMP is always hostile      */

	/* ---- TCP flag combinations ---- */
	STAT_DROP_TCP_NULL,           /* no flags at all                        */
	STAT_DROP_TCP_FIN_ONLY,       /* FIN with no ACK                        */
	STAT_DROP_TCP_SYN_FIN,
	STAT_DROP_TCP_SYN_RST,
	STAT_DROP_TCP_FIN_RST,
	STAT_DROP_TCP_XMAS,           /* FIN|PSH|URG                            */
	STAT_DROP_TCP_ALL_FLAGS,      /* every flag set                         */
	STAT_DROP_TCP_DOFF,           /* data offset < 5 or past the frame      */
	STAT_DROP_TCP_SYNACK_UNSOL,   /* SYN|ACK with no matching outbound SYN  */

	/* ---- ICMP ---- */
	STAT_DROP_ICMP_TYPE,          /* type policy is DROP                    */
	STAT_DROP_ICMP_OVERSIZE,      /* payload > icmp_max_payload (ping death)*/
	STAT_DROP_ICMP6_TYPE,
	STAT_DROP_ICMP6_OVERSIZE,

	/* ---- reputation lists ---- */
	STAT_DROP_BLOCKLIST,          /* static LPM blocklist                   */
	STAT_DROP_BAN_ACTIVE,         /* dynamic ban, not yet expired           */
	STAT_DROP_LOCKDOWN,           /* LOCKDOWN mode, nothing else matched    */

	/* ---- reflection / amplification ---- */
	STAT_DROP_AMP_SRCPORT,        /* UDP source port is a known amplifier   */

	/* ---- port policy ---- */
	STAT_DROP_PORT_CLOSED,
	STAT_DROP_PORT_RATE,          /* per-port token bucket exhausted        */
	STAT_DROP_DEFAULT_DENY,       /* no rule and CALY_F_DEFAULT_DENY        */

	/* ---- per-source token buckets ---- */
	STAT_DROP_RATE_PPS,
	STAT_DROP_RATE_BPS,
	STAT_DROP_RATE_SYN,
	STAT_DROP_RATE_UDP,
	STAT_DROP_RATE_ICMP,
	STAT_DROP_RATE_NEWCONN,
	STAT_DROP_RATE_GLOBAL_SYN,    /* pre-5.15 global SYN cap fallback       */

	/* ---- scan detection ---- */
	STAT_DROP_PORTSCAN,

	/* ---- SYN proxy ---- */
	STAT_SYNPROXY_GEN_OK,         /* cookie generated                       */
	STAT_SYNPROXY_GEN_FAIL,       /* helper refused (bad MSS, no room)      */
	STAT_SYNPROXY_TX,             /* SYN-ACK rewritten and XDP_TX'd         */
	STAT_SYNPROXY_TX_FAIL,
	STAT_SYNPROXY_CHECK_OK,
	STAT_DROP_SYNCOOKIE_BAD,      /* bare ACK with an invalid cookie        */
	STAT_SYNPROXY_UNAVAIL,        /* wanted, but helper/tail call missing   */
	STAT_SYNPROXY_SKIPPED,        /* not enabled for this port              */

	/* ---- conntrack-lite ---- */
	STAT_CT_CREATED,
	STAT_CT_HIT,
	STAT_CT_MISS,
	STAT_CT_UPDATED,
	STAT_CT_FULL,                 /* insert failed, LRU under pressure      */
	STAT_CT_CLOSED,

	/* ---- bans ---- */
	STAT_BAN_ADDED,
	STAT_BAN_ESCALATED,
	STAT_BAN_REFRESHED,
	STAT_BAN_FULL,
	STAT_STRIKE_ADDED,

	/* ---- infrastructure / self-diagnostics ---- */
	STAT_MAP_FULL_RATE,
	STAT_MAP_FULL_SCAN,
	STAT_MAP_FULL_SRCSTAT,
	STAT_EVENT_EMITTED,
	STAT_EVENT_SAMPLED_OUT,
	STAT_EVENT_LOST,              /* perf/ring buffer full                  */
	STAT_TAILCALL_FAIL,
	STAT_SCRATCH_FAIL,            /* per-CPU scratch lookup returned NULL   */
	STAT_CONFIG_MISSING,          /* config map empty: fail OPEN, not shut  */

	STAT_MAX
};

/* -------------------------------------------------------------------------
 * Structures.
 * ------------------------------------------------------------------------- */

/*
 * LPM trie keys. BPF_MAP_TYPE_LPM_TRIE mandates that the key begins with a
 * __u32 prefix length in HOST byte order, followed by the match data in
 * NETWORK byte order, most significant byte first. Tries MUST be created with
 * BPF_F_NO_PREALLOC or the kernel rejects them (-EINVAL).
 */
struct lpm_key_v4 {
	__u32 prefixlen;   /* 0..32                                           */
	__u8  addr[4];     /* network byte order                              */
};

struct lpm_key_v6 {
	__u32 prefixlen;   /* 0..128                                          */
	__u8  addr[16];    /* network byte order                              */
};

/* Value type of caly_allow{4,6}, caly_block{4,6}, caly_local{4,6}. */
struct rule_meta {
	__u64 added_ns;    /* bpf_ktime_get_ns() at insertion (0 = boot conf) */
	__u64 hits;        /* userspace-maintained; dataplane may bump it     */
	__u32 flags;       /* CALY_RULE_F_*                                   */
	__u32 tag;         /* free-form operator tag / feed id                */
};

/* IPv6 hash key. Wrapped in a struct so it can be a map key type directly. */
struct in6_key {
	__u32 a[4];        /* network byte order, a[0] is the high word       */
};

/*
 * Dynamic ban record. Key is __u32 (IPv4, network order) in caly_ban4 or
 * struct in6_key in caly_ban6. Stored in an LRU hash so that a flood of
 * distinct sources evicts old bans instead of failing inserts.
 */
struct ban_entry {
	__u64 expiry_ns;      /* absolute bpf_ktime_get_ns() deadline         */
	__u64 first_seen_ns;  /* when this source was first banned            */
	__u64 last_hit_ns;    /* last packet dropped by this ban              */
	__u64 cur_ttl_ns;     /* TTL used for this ban, input to escalation   */
	__u64 hit_pkts;       /* packets dropped while banned                 */
	__u64 hit_bytes;
	__u32 reason;         /* enum stat_reason that triggered the ban      */
	__u32 strikes;        /* strike count at ban time                     */
	__u32 offences;       /* how many times this source has been banned   */
	__u32 flags;          /* CALY_BAN_F_*                                 */
};

/*
 * One token bucket. tokens is an integral count of units (packets or bytes);
 * there is no scaling factor and no floating point anywhere. Refill is exact
 * to the nanosecond because the remainder is carried in last_refill_ns.
 */
struct token_bucket {
	__u64 tokens;
	__u64 last_refill_ns;
};

/*
 * Per-source rate limiting state. Key is __u32 / struct in6_key. Lives in an
 * LRU hash: under a spoofed-source flood the LRU evicts, it never fails.
 *
 * NOTE: this map is deliberately NOT per-CPU. A per-CPU token bucket would
 * multiply the effective limit by the CPU count and RSS would spread one
 * attacker across every queue. Concurrent read-modify-write of a bucket is a
 * benign race that can, at worst, let a couple of extra packets through.
 * Statistics counters, which must be exact, live in PERCPU maps instead.
 */
struct rate_state {
	struct token_bucket tb[CALY_TB_MAX];  /* indexed by enum caly_tb_kind */
	__u64 window_start_ns;                /* strike window opened at      */
	__u64 last_seen_ns;
	__u32 strikes;                        /* strikes inside the window    */
	__u32 last_reason;                    /* enum stat_reason of last hit */
	__u32 offences;                       /* lifetime ban count           */
	__u32 flags;                          /* CALY_RS_F_*                  */
};

/*
 * Conntrack-lite 5-tuple key.
 *
 * ORIENTATION: always stored as seen at XDP ingress, i.e. saddr/sport is the
 * REMOTE peer and daddr/dport is US. The optional tc egress program therefore
 * has to SWAP the tuple before inserting an outbound flow, so that the reply
 * packet hits on its first lookup.
 *
 * IPv4 uses index 0 of saddr/daddr only; indices 1..3 MUST be zero.
 *
 * CRITICAL: BPF hash lookups compare the raw key bytes INCLUDING pad[]. Every
 * consumer MUST zero the whole struct before filling it in:
 *
 *     struct conn_key k;
 *     __builtin_memset(&k, 0, sizeof(k));
 *
 * Skipping the memset leaves uninitialised stack in pad[] and turns every
 * lookup into a miss, which silently disables the conntrack fast path.
 */
struct conn_key {
	__u32 saddr[4];    /* network byte order, remote                      */
	__u32 daddr[4];    /* network byte order, local                       */
	__u16 sport;       /* network byte order                              */
	__u16 dport;       /* network byte order                              */
	__u8  proto;       /* CALY_IPPROTO_*                                  */
	__u8  family;      /* CALY_AF_INET / CALY_AF_INET6                    */
	__u8  pad[2];      /* MUST be zero                                    */
};

struct conn_state {
	__u64 created_ns;
	__u64 last_seen_ns;
	__u64 pkts_in;
	__u64 bytes_in;
	__u64 pkts_out;
	__u64 bytes_out;
	__u32 state;       /* CALY_CT_*                                       */
	__u32 flags;       /* CALY_CT_F_*                                     */
	__u32 ifindex;     /* interface the flow was learned on               */
	__u32 mark;        /* free-form, reserved for policy tagging          */
};

/*
 * Per-port policy. caly_port_tcp and caly_port_udp are plain 65536-entry
 * ARRAYs indexed by the HOST byte order port number, so lookup is a single
 * bounds-checked array access with no hashing.
 *
 * The DESTINATION port drives mode (closed/open/ratelimited). The SOURCE port
 * of a UDP packet is looked up in the SAME map to test CALY_PORT_F_AMPLIFIER;
 * the two uses never collide because they read different fields. Running a
 * real DNS server therefore still works: inbound queries hit dport 53 with
 * mode=OPEN, while spoofed reflection traffic arrives with sport 53 and is
 * dropped by the amplifier flag. Clearing CALY_PORT_F_AMPLIFIER on a port is
 * how the operator allowlists a reflective service they legitimately consume.
 *
 * The rate/burst pair is the per-port bucket configuration; the bucket STATE
 * lives in caly_port_tb, indexed by CALY_PORT_TB_IDX().
 */
struct port_rule {
	__u64 rate;        /* packets/sec when mode == CALY_PORT_RATELIMIT    */
	__u64 burst;       /* bucket depth in packets                         */
	__u32 mode;        /* enum caly_port_mode                             */
	__u32 flags;       /* CALY_PORT_F_*                                   */
};

/* Index into caly_port_tb (ARRAY of struct token_bucket, 2*65536 entries). */
#define CALY_PORT_TB_TCP_BASE   0u
#define CALY_PORT_TB_UDP_BASE   65536u
#define CALY_PORT_TB_ENTRIES    131072u
#define CALY_PORT_TB_IDX(is_udp, port) \
	(((is_udp) ? CALY_PORT_TB_UDP_BASE : CALY_PORT_TB_TCP_BASE) + \
	 ((port) & 0xFFFFu))

/*
 * Port-scan detection state, per source. A 512-bit Bloom filter over the
 * destination ports touched inside the current window. Two hash functions;
 * false positives merely make the distinct-port estimate slightly low, which
 * biases towards NOT banning - the safe direction.
 */
struct scan_state {
	__u64 window_start_ns;
	__u64 last_seen_ns;
	__u64 bitmap[CALY_SCAN_BITMAP_WORDS];
	__u32 distinct;    /* estimated distinct destination ports this window*/
	__u32 hits;        /* packets accounted this window                   */
	__u32 last_port;   /* dedupe consecutive probes to the same port      */
	__u32 flags;
};

/* Top-talker accounting, per source. Best-effort, sampled, purely for
 * reporting: nothing in the drop path reads it. */
struct src_stats {
	__u64 packets;
	__u64 bytes;
	__u64 drops;
	__u64 drop_bytes;
	__u64 first_seen_ns;
	__u64 last_seen_ns;
	__u32 last_reason; /* enum stat_reason                                */
	__u32 flags;
};

/*
 * Event pushed to userspace through caly_events (PERF_EVENT_ARRAY, works on
 * every supported kernel) or caly_events_rb (RINGBUF, 5.8+, preferred when
 * CALY_F_CAP_RINGBUF is set). Fixed 88-byte record, no variable payload, so
 * the reader can validate the size and reject truncated samples.
 */
struct event {
	__u64 ts_ns;       /* bpf_ktime_get_ns()                              */
	__u64 ban_ttl_ns;  /* TTL of the ban this event installed, else 0     */
	__u64 value;       /* rate/strike/distinct-port value that triggered  */
	__u32 saddr[4];    /* network byte order                              */
	__u32 daddr[4];    /* network byte order                              */
	__u32 ifindex;
	__u32 reason;      /* enum stat_reason                                */
	__u32 verdict;     /* enum caly_verdict                               */
	__u32 proto;       /* CALY_IPPROTO_*                                  */
	__u32 pkt_len;
	__u32 family;      /* CALY_AF_INET / CALY_AF_INET6                    */
	__u16 sport;       /* network byte order                              */
	__u16 dport;       /* network byte order                              */
	__u16 tcp_flags;
	__u8  mode;        /* enum fw_mode at the time of the verdict         */
	__u8  version;     /* CALY_ABI_VERSION_MAJOR                          */
};

/* Per-interface overrides. caly_iface is a HASH keyed by __u32 ifindex. A
 * miss means "use fw_config.default_zone and no per-iface flags". */
struct iface_config {
	__u64 flags;       /* CALY_IF_F_*                                     */
	__u32 ifindex;
	__u32 zone;        /* enum caly_zone                                  */
	__u64 reserved[2];
};

/*
 * Parsed packet descriptor handed from the main XDP program to a tail-called
 * program through the per-CPU scratch map. Offsets are byte offsets from
 * ctx->data. The callee still has to re-validate every offset against
 * data_end - the verifier will not take our word for it and neither should
 * you, because the packet may have been re-read.
 */
struct pkt_ctx {
	__u64 ts_ns;
	__u32 saddr[4];       /* network byte order                          */
	__u32 daddr[4];       /* network byte order                          */
	__u32 l3_off;         /* offset of the IPv4/IPv6 header              */
	__u32 l4_off;         /* offset of the TCP/UDP/ICMP header           */
	__u32 payload_off;    /* offset of the L4 payload                    */
	__u32 pkt_len;        /* data_end - data                             */
	__u32 ifindex;
	__u32 family;         /* CALY_AF_INET / CALY_AF_INET6                */
	__u32 proto;          /* final L4 protocol                           */
	__u32 vlan_depth;
	__u32 tunnel_depth;
	__u32 frag_off;       /* host order, 0 when not fragmented           */
	__u32 tcp_flags;
	__u32 flags;          /* CALY_PKT_F_*                                */
	__u16 sport;          /* network byte order                          */
	__u16 dport;          /* network byte order                          */
	__u16 eth_proto;      /* host order ethertype after VLAN unwrapping  */
	__u16 l4_len;         /* L4 header + payload length                  */
};

#define CALY_PKT_F_FRAG        (1u << 0)  /* any fragment                    */
#define CALY_PKT_F_FRAG_FIRST  (1u << 1)  /* offset 0 with MF set            */
#define CALY_PKT_F_TUNNELED    (1u << 2)  /* fields describe the INNER hdr   */
#define CALY_PKT_F_VLAN        (1u << 3)
#define CALY_PKT_F_WAN         (1u << 4)  /* arrived on a WAN-zone interface */
#define CALY_PKT_F_ALLOWLIST   (1u << 5)
#define CALY_PKT_F_MGMT        (1u << 6)
#define CALY_PKT_F_CT_HIT      (1u << 7)
#define CALY_PKT_F_L4_TRUNC    (1u << 8)  /* L4 header not fully present     */

/*
 * Per-CPU scratch. XDP programs get 512 bytes of stack; struct event alone is
 * 88 bytes and pkt_ctx is 96, so anything non-trivial has to live here. One
 * entry, key 0, BPF_MAP_TYPE_PERCPU_ARRAY, so there is no locking.
 */
struct caly_scratch {
	struct pkt_ctx    pkt;
	struct event      ev;
	struct conn_key   ck;
	struct conn_state cs;
	struct ban_entry  ban;
	__u64             tmp[8];
};

/* -------------------------------------------------------------------------
 * struct fw_config
 *
 * ONE entry in caly_config (BPF_MAP_TYPE_ARRAY, key 0). Copied verbatim
 * between userspace and the kernel, so the layout below is load bearing:
 *
 *   - every 64-bit field comes first, in one block, so nothing is padded;
 *   - the 32-bit block has an EVEN number of members, keeping the following
 *     __u16 arrays 8-byte aligned;
 *   - the two __u16[16] arrays are 32 bytes each, preserving alignment;
 *   - reserved[] closes the struct on an 8-byte boundary.
 *
 * There are no bitfields, no enums, no __u8 scalars and no implicit padding
 * anywhere. Static assertions at the bottom of this header prove it.
 *
 * All *_ns fields are nanoseconds. All rate fields are units per second. All
 * port fields are HOST byte order.
 * ------------------------------------------------------------------------- */
struct fw_config {
	/* ---- identity ---- */
	__u64 abi_version;          /* CALY_ABI_VERSION, written by the loader */
	__u64 config_gen;           /* bumped on every successful update       */
	__u64 flags;                /* CALY_F_*                                */

	/* ---- per-source token buckets, indexed by enum caly_tb_kind ---- */
	__u64 tb_rate[CALY_TB_MAX];   /* units/sec; 0 disables that bucket     */
	__u64 tb_burst[CALY_TB_MAX];  /* bucket depth; 0 disables that bucket  */

	/* ---- global gauges: mode escalation thresholds (hysteresis pairs) --- */
	__u64 global_pps_hi;        /* cross upward  -> escalate               */
	__u64 global_pps_lo;        /* fall below    -> de-escalate            */
	__u64 global_bps_hi;
	__u64 global_bps_lo;
	__u64 global_syn_pps_hi;    /* cross upward  -> engage the SYN proxy   */
	__u64 global_syn_pps_lo;
	__u64 global_newconn_pps_hi;
	__u64 global_newconn_pps_lo;
	__u64 attack_dwell_ns;      /* minimum time to stay escalated          */
	__u64 syn_fallback_pps;     /* pre-5.15 global SYN cap (0 = unlimited) */

	/* ---- banning ---- */
	__u64 ban_ttl_base_ns;      /* first offence                           */
	__u64 ban_ttl_max_ns;       /* escalation ceiling                      */
	__u64 ban_ttl_scan_ns;      /* port-scan ban TTL                       */
	__u64 ban_ttl_amp_ns;       /* amplification-source ban TTL            */
	__u64 strike_window_ns;     /* strikes must land inside this window    */

	/* ---- scan detection ---- */
	__u64 scan_window_ns;       /* sliding window for distinct dst ports   */

	/* ---- conntrack-lite timeouts ---- */
	__u64 ct_tcp_syn_ns;
	__u64 ct_tcp_est_ns;
	__u64 ct_tcp_fin_ns;
	__u64 ct_udp_ns;            /* unidirectional UDP                      */
	__u64 ct_udp_stream_ns;     /* UDP with traffic seen both ways         */
	__u64 ct_icmp_ns;
	__u64 ct_generic_ns;

	/* ---- userspace garbage collection thresholds ---- */
	__u64 rate_idle_ns;         /* evict rate_state idle longer than this  */
	__u64 scan_idle_ns;
	__u64 srcstat_idle_ns;

	/* ---- 32-bit knobs (EVEN count: 34) ---- */
	__u32 mode;                 /* enum fw_mode                            */
	__u32 default_zone;         /* enum caly_zone for unlisted interfaces  */

	__u32 strike_limit;         /* strikes in a window before a ban        */
	__u32 ban_escalate_num;     /* next_ttl = ttl * num / den              */
	__u32 ban_escalate_den;
	__u32 scan_port_threshold;  /* distinct dst ports before a scan ban    */

	__u32 icmp_max_payload;     /* bytes after the ICMP header             */
	__u32 icmp6_max_payload;
	__u32 frag_min_bytes;       /* non-final fragments smaller -> drop     */
	__u32 ip_min_ttl;           /* 0 disables the check                    */

	__u32 vlan_max_depth;       /* clamped to CALY_VLAN_MAX_DEPTH          */
	__u32 ip6_ext_max;          /* clamped to CALY_IP6_EXT_MAX             */
	__u32 tunnel_max_depth;     /* clamped to CALY_TUNNEL_MAX_DEPTH        */
	__u32 tcp_min_doff;         /* normally 5                              */

	__u32 log_sample_rate;      /* emit 1 event in N; 0 = never            */
	__u32 log_max_pps;          /* hard ceiling on events/sec              */
	__u32 log_level;            /* daemon verbosity, 0=err .. 4=trace      */
	__u32 event_pages;          /* perf ring pages per CPU (power of two)  */

	__u32 max_ban_entries;      /* map sizing, read before map creation    */
	__u32 max_conn_entries;
	__u32 max_rate_entries;
	__u32 max_scan_entries;
	__u32 max_srcstat_entries;
	__u32 max_allow_entries;
	__u32 max_block_entries;
	__u32 max_iface_entries;

	__u32 dataplane_pref;       /* enum caly_dataplane                     */
	__u32 xdp_attach_pref;      /* enum caly_xdp_mode                      */
	__u32 poll_interval_ms;     /* daemon event poll timeout               */
	__u32 stats_interval_ms;    /* gauge sampling period                   */
	__u32 gc_interval_ms;       /* map sweep period                        */
	__u32 gc_batch;             /* entries examined per sweep              */
	__u32 mgmt_tcp_count;       /* valid entries in mgmt_tcp_ports         */
	__u32 mgmt_udp_count;       /* valid entries in mgmt_udp_ports         */

	/* ---- management allowlist, HOST byte order ---- */
	/* INVARIANT: the loader ALWAYS forces TCP/22 into this list, in every
	 * mode including LOCKDOWN and UNDER_ATTACK, and refuses a configuration
	 * that would remove it. Locking the operator out of a machine that is
	 * under attack is worse than the attack. */
	__u16 mgmt_tcp_ports[CALY_MGMT_PORTS_MAX];
	__u16 mgmt_udp_ports[CALY_MGMT_PORTS_MAX];

	/* ---- ABI headroom: new knobs consume these, never grow the struct -- */
	__u64 reserved[CALY_CFG_RESERVED];
};

/* Size is asserted below. Kept here for readers: 41*8 + 34*4 + 2*32 + 24*8. */
#define CALY_FW_CONFIG_SIZE  720u

/* -------------------------------------------------------------------------
 * The amplifier source-port table.
 *
 * The loader seeds CALY_PORT_F_AMPLIFIER on each of these ports in
 * caly_port_udp at startup. Keeping the list here means the daemon, the CLI
 * and the documentation cannot drift apart.
 * ------------------------------------------------------------------------- */
#define CALY_AMP_PORTS_COUNT  21u
#define CALY_AMP_PORTS_INIT { \
	   19,  /* chargen        */ \
	   17,  /* qotd           */ \
	   53,  /* DNS            */ \
	   69,  /* TFTP           */ \
	  111,  /* portmap/rpcbind*/ \
	  123,  /* NTP            */ \
	  137,  /* NetBIOS-NS     */ \
	  161,  /* SNMP           */ \
	  389,  /* CLDAP          */ \
	  520,  /* RIP            */ \
	  623,  /* IPMI/RMCP      */ \
	 1434,  /* MSSQL Browser  */ \
	 1900,  /* SSDP           */ \
	 3283,  /* Apple ARD      */ \
	 5093,  /* Sentinel LM    */ \
	 5351,  /* NAT-PMP        */ \
	 5353,  /* mDNS           */ \
	11211,  /* memcached      */ \
	27015,  /* Steam / SRCDS  */ \
	30718,  /* Lantronix      */ \
	37810   /* DVR / DHCPDiscover */ \
}

/*
 * ICMPv6 types that MUST remain CALY_ICMP_PASS. Dropping any of these breaks
 * IPv6 outright: no PMTUD (2), no neighbour discovery (135/136), no router
 * discovery (133/134). The loader rejects a configuration that sets any of
 * them to CALY_ICMP_DROP.
 */
#define CALY_ICMP6_MANDATORY_COUNT  5u
#define CALY_ICMP6_MANDATORY_INIT { 2, 133, 134, 135, 136 }

/*
 * ICMPv4 types that MUST remain permitted. Type 3 carries Fragmentation
 * Needed (code 4); dropping it black-holes PMTUD and produces the classic
 * "SSH connects then hangs" failure.
 */
#define CALY_ICMP4_MANDATORY_COUNT  1u
#define CALY_ICMP4_MANDATORY_INIT { 3 }

/* ICMP type numbers referenced by the dataplane. */
#define CALY_ICMP4_ECHOREPLY     0
#define CALY_ICMP4_DEST_UNREACH  3
#define CALY_ICMP4_ECHO          8
#define CALY_ICMP4_TIME_EXCEEDED 11
#define CALY_ICMP4_PARAMPROB     12

#define CALY_ICMP6_DEST_UNREACH  1
#define CALY_ICMP6_PKT_TOOBIG    2
#define CALY_ICMP6_TIME_EXCEED   3
#define CALY_ICMP6_PARAMPROB     4
#define CALY_ICMP6_ECHO_REQUEST  128
#define CALY_ICMP6_ECHO_REPLY    129
#define CALY_ICMP6_MLD_QUERY     130
#define CALY_ICMP6_MLD_REPORT    131
#define CALY_ICMP6_MLD_DONE      132
#define CALY_ICMP6_ROUTER_SOL    133
#define CALY_ICMP6_ROUTER_ADV    134
#define CALY_ICMP6_NEIGH_SOL     135
#define CALY_ICMP6_NEIGH_ADV     136
#define CALY_ICMP6_REDIRECT      137
#define CALY_ICMP6_MLD2_REPORT   143

/* -------------------------------------------------------------------------
 * Shared pure-arithmetic helpers.
 *
 * These compile identically in the BPF object and in userspace, which is the
 * point: the daemon's "would this have been dropped" simulator and the
 * dataplane must agree bit for bit. They call no kernel helper and touch no
 * global state; the caller supplies the timestamp.
 * ------------------------------------------------------------------------- */

CALY_INLINE void caly_tb_init(struct token_bucket *tb, __u64 now_ns, __u64 burst)
{
	tb->tokens = burst;
	tb->last_refill_ns = now_ns;
}

/*
 * Refill and try to consume `want` units.
 * Returns 1 when the packet conforms (tokens were available), 0 when the
 * bucket is exhausted. A rate or burst of 0 disables the bucket entirely and
 * always returns 1 - a misconfigured limiter must never black-hole traffic.
 */
CALY_INLINE int caly_tb_consume(struct token_bucket *tb, __u64 now_ns,
				__u64 rate, __u64 burst, __u64 want)
{
	__u64 elapsed, add, consumed_ns;

	if (rate == 0 || burst == 0)
		return 1;

	if (rate > CALY_TB_RATE_MAX)
		rate = CALY_TB_RATE_MAX;

	/* Fresh or recycled LRU entry, or a clock that went backwards. */
	if (tb->last_refill_ns == 0 || tb->last_refill_ns > now_ns) {
		tb->last_refill_ns = now_ns;
		tb->tokens = burst;
	}

	/* Snap the refill anchor forward before measuring so that a long idle
	 * period can never be spent twice, and so elapsed * rate cannot
	 * overflow (<= 1e9 * 4e9 = 4e18). */
	if (now_ns - tb->last_refill_ns > CALY_TB_MAX_ELAPSED_NS)
		tb->last_refill_ns = now_ns - CALY_TB_MAX_ELAPSED_NS;

	elapsed = now_ns - tb->last_refill_ns;
	add = (elapsed * rate) / CALY_NSEC_PER_SEC;

	if (add > 0) {
		/* Carry the sub-token remainder in last_refill_ns instead of
		 * discarding it, so slow rates stay exact over time. */
		consumed_ns = (add * CALY_NSEC_PER_SEC) / rate;
		tb->last_refill_ns += consumed_ns;

		if (tb->tokens + add < tb->tokens || tb->tokens + add > burst)
			tb->tokens = burst;
		else
			tb->tokens += add;
	}

	if (tb->tokens >= want) {
		tb->tokens -= want;
		return 1;
	}
	return 0;
}

/* Escalating ban TTL: ttl * num / den, clamped to [base, max]. */
CALY_INLINE __u64 caly_ban_next_ttl(__u64 cur_ttl_ns, __u64 base_ns,
				    __u64 max_ns, __u32 num, __u32 den)
{
	__u64 next;

	if (base_ns == 0)
		base_ns = 1;
	if (max_ns < base_ns)
		max_ns = base_ns;
	if (cur_ttl_ns < base_ns)
		return base_ns;
	if (den == 0 || num <= den)
		return cur_ttl_ns > max_ns ? max_ns : cur_ttl_ns;

	/* Clamp before multiplying so num/den cannot overflow __u64. */
	if (cur_ttl_ns > max_ns)
		return max_ns;
	next = (cur_ttl_ns / den) * num;
	if (next < cur_ttl_ns)      /* division underflow on tiny TTLs */
		next = cur_ttl_ns;
	return next > max_ns ? max_ns : next;
}

/* 32-bit mixer used by the port-scan Bloom filter. Deterministic and
 * identical on both sides so userspace can reproduce the estimate. */
CALY_INLINE __u32 caly_mix32(__u32 x, __u32 seed)
{
	x ^= seed;
	x *= 0x2545F491u;
	x ^= x >> 15;
	x *= 0x85EBCA6Bu;
	x ^= x >> 13;
	x *= 0xC2B2AE35u;
	x ^= x >> 16;
	return x;
}

/*
 * Record a destination port in the scan bitmap. Returns 1 if the port looks
 * new inside this window (both Bloom bits were not already set), 0 otherwise.
 * Callers reset window_start_ns/bitmap/distinct when the window rolls over.
 */
CALY_INLINE int caly_scan_mark(struct scan_state *st, __u16 port)
{
	__u32 h1 = caly_mix32((__u32)port, 0x9E3779B9u) & CALY_SCAN_BITMAP_MASK;
	__u32 h2 = caly_mix32((__u32)port, 0x7F4A7C15u) & CALY_SCAN_BITMAP_MASK;
	__u32 w1 = h1 >> 6, w2 = h2 >> 6;
	__u64 m1 = 1ULL << (h1 & 63u), m2 = 1ULL << (h2 & 63u);
	int fresh;

	/* Redundant given the mask above, but the verifier wants it spelled
	 * out and it costs two compare instructions. */
	if (w1 >= CALY_SCAN_BITMAP_WORDS || w2 >= CALY_SCAN_BITMAP_WORDS)
		return 0;

	fresh = !((st->bitmap[w1] & m1) && (st->bitmap[w2] & m2));
	st->bitmap[w1] |= m1;
	st->bitmap[w2] |= m2;

	if (fresh && st->distinct < 0xFFFFFFFFu)
		st->distinct++;
	return fresh;
}

CALY_INLINE void caly_scan_reset(struct scan_state *st, __u64 now_ns)
{
	unsigned int i;

	st->window_start_ns = now_ns;
	st->distinct = 0;
	st->hits = 0;
	st->last_port = 0;
	CALY_UNROLL
	for (i = 0; i < CALY_SCAN_BITMAP_WORDS; i++)
		st->bitmap[i] = 0;
}

/* Is `port` (HOST byte order) in the management allowlist? Checked before
 * every drop decision so the operator can always get back in. */
CALY_INLINE int caly_is_mgmt_tcp(const struct fw_config *cfg, __u16 port)
{
	unsigned int i;
	__u32 n = cfg->mgmt_tcp_count;

	if (n > CALY_MGMT_PORTS_MAX)
		n = CALY_MGMT_PORTS_MAX;
	CALY_UNROLL
	for (i = 0; i < CALY_MGMT_PORTS_MAX; i++) {
		if (i >= n)
			break;
		if (cfg->mgmt_tcp_ports[i] == port)
			return 1;
	}
	return 0;
}

CALY_INLINE int caly_is_mgmt_udp(const struct fw_config *cfg, __u16 port)
{
	unsigned int i;
	__u32 n = cfg->mgmt_udp_count;

	if (n > CALY_MGMT_PORTS_MAX)
		n = CALY_MGMT_PORTS_MAX;
	CALY_UNROLL
	for (i = 0; i < CALY_MGMT_PORTS_MAX; i++) {
		if (i >= n)
			break;
		if (cfg->mgmt_udp_ports[i] == port)
			return 1;
	}
	return 0;
}

/*
 * IPv4 bogon / martian source classification.
 *
 * `a` points at the four ADDRESS BYTES exactly as they sit in the IPv4
 * header, i.e. a[0] is the first octet. Taking bytes rather than a __u32
 * keeps this endian-neutral: a word load of a big-endian address places the
 * first octet in the low byte on x86_64/aarch64 but in the high byte on a
 * big-endian target, and a helper that silently assumes one of those is a
 * latent "the filter does nothing" bug.
 *
 * Callers pass a pointer to their own copy (pkt_ctx.saddr, conn_key.saddr,
 * ...) after the packet bounds check, never a raw ctx->data pointer:
 *
 *     reason = caly_v4_src_bogon((const __u8 *)&pkt->saddr[0], drop_private);
 *
 * Returns the stat_reason to charge, or STAT_PKT_TOTAL (0) when the address
 * is acceptable. drop_private selects RFC1918/CGNAT rejection, which is only
 * correct on a WAN-zone interface.
 */
CALY_INLINE __u32 caly_v4_src_bogon(const __u8 *a, int drop_private)
{
	if (a[0] == 0u)                                  /* 0.0.0.0/8      */
		return STAT_DROP_BOGON_SRC;
	if (a[0] == 127u)                                /* 127.0.0.0/8    */
		return STAT_DROP_BOGON_SRC;
	if (a[0] == 169u && a[1] == 254u)                /* 169.254.0.0/16 */
		return STAT_DROP_BOGON_SRC;
	if ((a[0] & 0xF0u) == 0xE0u)                     /* 224.0.0.0/4    */
		return STAT_DROP_MCAST_SRC;
	if ((a[0] & 0xF0u) == 0xF0u) {                   /* 240.0.0.0/4    */
		if (a[0] == 255u && a[1] == 255u &&
		    a[2] == 255u && a[3] == 255u)        /* limited bcast  */
			return STAT_DROP_BCAST_SRC;
		return STAT_DROP_BOGON_SRC;
	}
	if (a[0] == 192u && a[1] == 0u && a[2] == 2u)    /* 192.0.2.0/24   */
		return STAT_DROP_BOGON_SRC;
	if (a[0] == 198u && a[1] == 51u && a[2] == 100u) /* 198.51.100.0/24*/
		return STAT_DROP_BOGON_SRC;
	if (a[0] == 203u && a[1] == 0u && a[2] == 113u)  /* 203.0.113.0/24 */
		return STAT_DROP_BOGON_SRC;
	if (a[0] == 198u && (a[1] & 0xFEu) == 18u)       /* 198.18.0.0/15  */
		return STAT_DROP_BOGON_SRC;

	if (drop_private) {
		if (a[0] == 10u)                             /* 10/8      */
			return STAT_DROP_PRIVATE_SRC;
		if (a[0] == 172u && (a[1] & 0xF0u) == 16u)   /* 172.16/12 */
			return STAT_DROP_PRIVATE_SRC;
		if (a[0] == 192u && a[1] == 168u)            /* 192.168/16*/
			return STAT_DROP_PRIVATE_SRC;
		if (a[0] == 100u && (a[1] & 0xC0u) == 64u)   /* 100.64/10 */
			return STAT_DROP_PRIVATE_SRC;
	}
	return STAT_PKT_TOTAL;   /* 0 == acceptable */
}

/*
 * IPv6 source classification. `a` points at the sixteen ADDRESS BYTES as they
 * sit in the IPv6 header. Endian-neutral for the same reason as the IPv4
 * variant above.
 */
CALY_INLINE __u32 caly_v6_src_bogon(const __u8 *a, int drop_private)
{
	unsigned int i;
	__u8 acc = 0;

	if (a[0] == 0xFFu)                       /* ff00::/8 multicast    */
		return STAT_DROP_MCAST_SRC;

	CALY_UNROLL
	for (i = 0; i < 15u; i++)
		acc = (__u8)(acc | a[i]);

	if (acc == 0u) {
		if (a[15] == 0u)                 /* ::                    */
			return STAT_DROP_IP6_SRC_UNSPEC;
		if (a[15] == 1u)                 /* ::1                   */
			return STAT_DROP_IP6_SRC_LOOPBACK;
	}

	/* 0100::/64, the RFC 6666 discard-only prefix. */
	if (a[0] == 0x01u && a[1] == 0x00u && a[2] == 0u && a[3] == 0u &&
	    a[4] == 0u && a[5] == 0u && a[6] == 0u && a[7] == 0u)
		return STAT_DROP_BOGON_SRC;

	if (drop_private) {
		if ((a[0] & 0xFEu) == 0xFCu)                 /* fc00::/7  */
			return STAT_DROP_PRIVATE_SRC;
		if (a[0] == 0xFEu && (a[1] & 0xC0u) == 0x80u)/* fe80::/10 */
			return STAT_DROP_PRIVATE_SRC;
	}
	return STAT_PKT_TOTAL;
}

/*
 * Illegal TCP flag combinations. Returns the stat_reason to charge, or 0 when
 * the combination is legal. Only the low six bits matter; ECE/CWR are
 * legitimate and must not be treated as an anomaly.
 */
CALY_INLINE __u32 caly_tcp_flags_illegal(__u8 flags)
{
	__u8 f = (__u8)(flags & CALY_TCP_FLAG_MASK);

	if (flags == CALY_TCP_ALL_FLAGS)
		return STAT_DROP_TCP_ALL_FLAGS;
	if (f == 0)
		return STAT_DROP_TCP_NULL;
	if ((f & (CALY_TCP_SYN | CALY_TCP_FIN)) ==
	    (CALY_TCP_SYN | CALY_TCP_FIN))
		return STAT_DROP_TCP_SYN_FIN;
	if ((f & (CALY_TCP_SYN | CALY_TCP_RST)) ==
	    (CALY_TCP_SYN | CALY_TCP_RST))
		return STAT_DROP_TCP_SYN_RST;
	if ((f & (CALY_TCP_FIN | CALY_TCP_RST)) ==
	    (CALY_TCP_FIN | CALY_TCP_RST))
		return STAT_DROP_TCP_FIN_RST;
	if ((f & (CALY_TCP_FIN | CALY_TCP_PSH | CALY_TCP_URG)) ==
	    (CALY_TCP_FIN | CALY_TCP_PSH | CALY_TCP_URG))
		return STAT_DROP_TCP_XMAS;
	if (f == CALY_TCP_FIN)
		return STAT_DROP_TCP_FIN_ONLY;
	return STAT_PKT_TOTAL;
}

/* -------------------------------------------------------------------------
 * Userspace-only helpers.
 *
 * Guarded so the BPF object never compiles a 100-arm switch it cannot use.
 * Define CALY_USERSPACE before including this header from the daemon or CLI.
 * ------------------------------------------------------------------------- */
#ifdef CALY_USERSPACE

CALY_INLINE const char *stat_reason_str(__u32 r)
{
	switch (r) {
	case STAT_PKT_TOTAL:            return "pkt_total";
	case STAT_PASS_TOTAL:           return "pass_total";
	case STAT_DROP_TOTAL:           return "drop_total";
	case STAT_TX_TOTAL:             return "tx_total";
	case STAT_MONITOR_WOULD_DROP:   return "monitor_would_drop";

	case STAT_PASS_NOT_IP:          return "pass_not_ip";
	case STAT_PASS_LAN_IFACE:       return "pass_lan_iface";
	case STAT_PASS_DISABLED:        return "pass_disabled";
	case STAT_PASS_ALLOWLIST:       return "pass_allowlist";
	case STAT_PASS_MGMT_PORT:       return "pass_mgmt_port";
	case STAT_PASS_CONNTRACK:       return "pass_conntrack";
	case STAT_PASS_PORT_OPEN:       return "pass_port_open";
	case STAT_PASS_PORT_RATE_OK:    return "pass_port_rate_ok";
	case STAT_PASS_ICMP_POLICY:     return "pass_icmp_policy";
	case STAT_PASS_ICMP6_ND:        return "pass_icmp6_nd";
	case STAT_PASS_ICMP6_PMTUD:     return "pass_icmp6_pmtud";
	case STAT_PASS_ICMP4_PMTUD:     return "pass_icmp4_pmtud";
	case STAT_PASS_SYNCOOKIE_OK:    return "pass_syncookie_ok";
	case STAT_PASS_DEFAULT:         return "pass_default";

	case STAT_DROP_ETH_TRUNC:       return "drop_eth_trunc";
	case STAT_DROP_VLAN_TRUNC:      return "drop_vlan_trunc";
	case STAT_DROP_VLAN_DEPTH:      return "drop_vlan_depth";
	case STAT_DROP_L3_UNKNOWN:      return "drop_l3_unknown";
	case STAT_DROP_IP4_TRUNC:       return "drop_ip4_trunc";
	case STAT_DROP_IP4_IHL:         return "drop_ip4_ihl";
	case STAT_DROP_IP4_TOTLEN:      return "drop_ip4_totlen";
	case STAT_DROP_IP4_OPTIONS:     return "drop_ip4_options";
	case STAT_DROP_IP6_TRUNC:       return "drop_ip6_trunc";
	case STAT_DROP_IP6_EXT_DEPTH:   return "drop_ip6_ext_depth";
	case STAT_DROP_IP6_EXT_TRUNC:   return "drop_ip6_ext_trunc";
	case STAT_DROP_IP6_RH0:         return "drop_ip6_rh0";
	case STAT_DROP_IP6_DISABLED:    return "drop_ip6_disabled";
	case STAT_DROP_TTL_ZERO:        return "drop_ttl_zero";
	case STAT_DROP_TTL_LOW:         return "drop_ttl_low";
	case STAT_DROP_TUNNEL_TRUNC:    return "drop_tunnel_trunc";
	case STAT_DROP_TUNNEL_DEPTH:    return "drop_tunnel_depth";
	case STAT_DROP_TUNNEL_PROTO:    return "drop_tunnel_proto";
	case STAT_DROP_GRE_MALFORMED:   return "drop_gre_malformed";
	case STAT_DROP_L4_TRUNC:        return "drop_l4_trunc";
	case STAT_DROP_L4_UNKNOWN:      return "drop_l4_unknown";
	case STAT_DROP_L4_PORT_ZERO:    return "drop_l4_port_zero";

	case STAT_DROP_LAND:            return "drop_land";
	case STAT_DROP_BOGON_SRC:       return "drop_bogon_src";
	case STAT_DROP_PRIVATE_SRC:     return "drop_private_src";
	case STAT_DROP_MCAST_SRC:       return "drop_mcast_src";
	case STAT_DROP_BCAST_SRC:       return "drop_bcast_src";
	case STAT_DROP_IP6_SRC_UNSPEC:  return "drop_ip6_src_unspec";
	case STAT_DROP_IP6_SRC_LOOPBACK:return "drop_ip6_src_loopback";
	case STAT_DROP_SRC_SELF:        return "drop_src_self";

	case STAT_DROP_FRAG_TINY:       return "drop_frag_tiny";
	case STAT_DROP_FRAG_OFF_ONE:    return "drop_frag_off_one";
	case STAT_DROP_FRAG_POLICY:     return "drop_frag_policy";
	case STAT_DROP_FRAG_ICMP:       return "drop_frag_icmp";

	case STAT_DROP_TCP_NULL:        return "drop_tcp_null";
	case STAT_DROP_TCP_FIN_ONLY:    return "drop_tcp_fin_only";
	case STAT_DROP_TCP_SYN_FIN:     return "drop_tcp_syn_fin";
	case STAT_DROP_TCP_SYN_RST:     return "drop_tcp_syn_rst";
	case STAT_DROP_TCP_FIN_RST:     return "drop_tcp_fin_rst";
	case STAT_DROP_TCP_XMAS:        return "drop_tcp_xmas";
	case STAT_DROP_TCP_ALL_FLAGS:   return "drop_tcp_all_flags";
	case STAT_DROP_TCP_DOFF:        return "drop_tcp_doff";
	case STAT_DROP_TCP_SYNACK_UNSOL:return "drop_tcp_synack_unsolicited";

	case STAT_DROP_ICMP_TYPE:       return "drop_icmp_type";
	case STAT_DROP_ICMP_OVERSIZE:   return "drop_icmp_oversize";
	case STAT_DROP_ICMP6_TYPE:      return "drop_icmp6_type";
	case STAT_DROP_ICMP6_OVERSIZE:  return "drop_icmp6_oversize";

	case STAT_DROP_BLOCKLIST:       return "drop_blocklist";
	case STAT_DROP_BAN_ACTIVE:      return "drop_ban_active";
	case STAT_DROP_LOCKDOWN:        return "drop_lockdown";

	case STAT_DROP_AMP_SRCPORT:     return "drop_amp_srcport";

	case STAT_DROP_PORT_CLOSED:     return "drop_port_closed";
	case STAT_DROP_PORT_RATE:       return "drop_port_rate";
	case STAT_DROP_DEFAULT_DENY:    return "drop_default_deny";

	case STAT_DROP_RATE_PPS:        return "drop_rate_pps";
	case STAT_DROP_RATE_BPS:        return "drop_rate_bps";
	case STAT_DROP_RATE_SYN:        return "drop_rate_syn";
	case STAT_DROP_RATE_UDP:        return "drop_rate_udp";
	case STAT_DROP_RATE_ICMP:       return "drop_rate_icmp";
	case STAT_DROP_RATE_NEWCONN:    return "drop_rate_newconn";
	case STAT_DROP_RATE_GLOBAL_SYN: return "drop_rate_global_syn";

	case STAT_DROP_PORTSCAN:        return "drop_portscan";

	case STAT_SYNPROXY_GEN_OK:      return "synproxy_gen_ok";
	case STAT_SYNPROXY_GEN_FAIL:    return "synproxy_gen_fail";
	case STAT_SYNPROXY_TX:          return "synproxy_tx";
	case STAT_SYNPROXY_TX_FAIL:     return "synproxy_tx_fail";
	case STAT_SYNPROXY_CHECK_OK:    return "synproxy_check_ok";
	case STAT_DROP_SYNCOOKIE_BAD:   return "drop_syncookie_bad";
	case STAT_SYNPROXY_UNAVAIL:     return "synproxy_unavailable";
	case STAT_SYNPROXY_SKIPPED:     return "synproxy_skipped";

	case STAT_CT_CREATED:           return "ct_created";
	case STAT_CT_HIT:               return "ct_hit";
	case STAT_CT_MISS:              return "ct_miss";
	case STAT_CT_UPDATED:           return "ct_updated";
	case STAT_CT_FULL:              return "ct_full";
	case STAT_CT_CLOSED:            return "ct_closed";

	case STAT_BAN_ADDED:            return "ban_added";
	case STAT_BAN_ESCALATED:        return "ban_escalated";
	case STAT_BAN_REFRESHED:        return "ban_refreshed";
	case STAT_BAN_FULL:             return "ban_full";
	case STAT_STRIKE_ADDED:         return "strike_added";

	case STAT_MAP_FULL_RATE:        return "map_full_rate";
	case STAT_MAP_FULL_SCAN:        return "map_full_scan";
	case STAT_MAP_FULL_SRCSTAT:     return "map_full_srcstat";
	case STAT_EVENT_EMITTED:        return "event_emitted";
	case STAT_EVENT_SAMPLED_OUT:    return "event_sampled_out";
	case STAT_EVENT_LOST:           return "event_lost";
	case STAT_TAILCALL_FAIL:        return "tailcall_fail";
	case STAT_SCRATCH_FAIL:         return "scratch_fail";
	case STAT_CONFIG_MISSING:       return "config_missing";

	default:                        return "unknown";
	}
}

CALY_INLINE const char *fw_mode_str(__u32 m)
{
	switch (m) {
	case FW_MODE_NORMAL:       return "normal";
	case FW_MODE_ELEVATED:     return "elevated";
	case FW_MODE_UNDER_ATTACK: return "under-attack";
	case FW_MODE_LOCKDOWN:     return "lockdown";
	case FW_MODE_MONITOR_ONLY: return "monitor-only";
	default:                   return "unknown";
	}
}

CALY_INLINE const char *caly_verdict_str(__u32 v)
{
	switch (v) {
	case CALY_VERDICT_PASS:    return "pass";
	case CALY_VERDICT_DROP:    return "drop";
	case CALY_VERDICT_TX:      return "tx";
	case CALY_VERDICT_MONITOR: return "monitor";
	default:                   return "unknown";
	}
}

CALY_INLINE const char *caly_dataplane_str(__u32 d)
{
	switch (d) {
	case CALY_DP_AUTO:        return "auto";
	case CALY_DP_XDP_NATIVE:  return "xdp-native";
	case CALY_DP_XDP_GENERIC: return "xdp-generic";
	case CALY_DP_TC:          return "tc-bpf";
	case CALY_DP_NFTABLES:    return "nftables";
	case CALY_DP_IPTABLES:    return "iptables+ipset";
	default:                  return "unknown";
	}
}

/* True when the reason denotes a drop rather than a pass or a counter. Used
 * by the reporter to build the drop breakdown without a second table. */
CALY_INLINE int stat_reason_is_drop(__u32 r)
{
	return (r >= STAT_DROP_ETH_TRUNC && r <= STAT_DROP_PORTSCAN) ||
	       r == STAT_DROP_SYNCOOKIE_BAD;
}

#endif /* CALY_USERSPACE */

/* -------------------------------------------------------------------------
 * Compile-time layout assertions.
 *
 * These fire at compile time on BOTH sides. If one of them trips, the ABI has
 * drifted and the fix is to correct the struct, never to edit the expected
 * number. The negative-array idiom is used instead of _Static_assert so the
 * header works with pre-C11 compilers and with clang's BPF target alike.
 * ------------------------------------------------------------------------- */
#define CALY_ASSERT(cond, tag) \
	typedef char caly_static_assert_##tag[(cond) ? 1 : -1]

CALY_ASSERT(sizeof(struct lpm_key_v4) == 8,            lpm_key_v4_size);
CALY_ASSERT(sizeof(struct lpm_key_v6) == 20,           lpm_key_v6_size);
CALY_ASSERT(sizeof(struct in6_key) == 16,              in6_key_size);
CALY_ASSERT(sizeof(struct rule_meta) == 24,            rule_meta_size);
CALY_ASSERT(sizeof(struct ban_entry) == 64,            ban_entry_size);
CALY_ASSERT(sizeof(struct token_bucket) == 16,         token_bucket_size);
CALY_ASSERT(sizeof(struct rate_state) == 128,          rate_state_size);
CALY_ASSERT(sizeof(struct conn_key) == 40,             conn_key_size);
CALY_ASSERT(sizeof(struct conn_state) == 64,           conn_state_size);
CALY_ASSERT(sizeof(struct port_rule) == 24,            port_rule_size);
CALY_ASSERT(sizeof(struct scan_state) == 96,           scan_state_size);
CALY_ASSERT(sizeof(struct src_stats) == 56,            src_stats_size);
CALY_ASSERT(sizeof(struct event) == 88,                event_size);
CALY_ASSERT(sizeof(struct iface_config) == 32,         iface_config_size);
CALY_ASSERT(sizeof(struct pkt_ctx) == 96,              pkt_ctx_size);
CALY_ASSERT(sizeof(struct caly_scratch) == 416,        caly_scratch_size);
CALY_ASSERT(sizeof(struct fw_config) == CALY_FW_CONFIG_SIZE, fw_config_size);

/* The scratch area exists precisely because these do not fit on the 512-byte
 * BPF stack together. If it ever shrinks below the stack limit something has
 * been dropped from it by mistake. */
CALY_ASSERT(sizeof(struct caly_scratch) > 256,         caly_scratch_purpose);

/* Alignment of every boundary-crossing struct must be 8 so that the same
 * layout is produced on x86_64 and aarch64, and by clang-BPF and gcc alike. */
CALY_ASSERT(sizeof(struct fw_config) % 8 == 0,         fw_config_align);
CALY_ASSERT(sizeof(struct rate_state) % 8 == 0,        rate_state_align);
CALY_ASSERT(sizeof(struct event) % 8 == 0,             event_align);
CALY_ASSERT(sizeof(struct scan_state) % 8 == 0,        scan_state_align);
CALY_ASSERT(sizeof(struct pkt_ctx) % 8 == 0,           pkt_ctx_align);

/* Critical offsets inside fw_config. If any of these moves, every deployed
 * daemon disagrees with every deployed BPF object. */
CALY_ASSERT(__builtin_offsetof(struct fw_config, abi_version) == 0,
	    fw_config_off_abi);
CALY_ASSERT(__builtin_offsetof(struct fw_config, flags) == 16,
	    fw_config_off_flags);
CALY_ASSERT(__builtin_offsetof(struct fw_config, tb_rate) == 24,
	    fw_config_off_tb_rate);
CALY_ASSERT(__builtin_offsetof(struct fw_config, tb_burst) == 72,
	    fw_config_off_tb_burst);
CALY_ASSERT(__builtin_offsetof(struct fw_config, mode) == 328,
	    fw_config_off_mode);
CALY_ASSERT(__builtin_offsetof(struct fw_config, mgmt_tcp_ports) == 464,
	    fw_config_off_mgmt_tcp);
CALY_ASSERT(__builtin_offsetof(struct fw_config, mgmt_udp_ports) == 496,
	    fw_config_off_mgmt_udp);
CALY_ASSERT(__builtin_offsetof(struct fw_config, reserved) == 528,
	    fw_config_off_reserved);

/* LPM trie keys must be prefixlen-first; the kernel reads the first four
 * bytes as the prefix length regardless of what we name them. */
CALY_ASSERT(__builtin_offsetof(struct lpm_key_v4, prefixlen) == 0,
	    lpm_v4_prefix_first);
CALY_ASSERT(__builtin_offsetof(struct lpm_key_v6, prefixlen) == 0,
	    lpm_v6_prefix_first);

/* conn_key must have no implicit tail padding: 16+16+2+2+1+1+2 == 40. */
CALY_ASSERT(__builtin_offsetof(struct conn_key, pad) == 38, conn_key_pad_off);

/* The bucket array and the config rate arrays must stay index-compatible. */
CALY_ASSERT(sizeof(((struct rate_state *)0)->tb) ==
	    CALY_TB_MAX * sizeof(struct token_bucket), rate_state_tb_len);

/* The statistics enum must fit in the __u32 that carries it in struct event
 * and must leave room to grow inside a sanely sized per-CPU array. */
CALY_ASSERT(STAT_MAX > 0 && STAT_MAX < 1024,           stat_max_bounds);

#endif /* __CALY_ANTI_COMMON_H */
