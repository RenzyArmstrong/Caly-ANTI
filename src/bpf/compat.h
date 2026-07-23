/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - XDP/eBPF DDoS mitigation suite
 * src/bpf/compat.h - kernel feature gating and safe shims.
 *
 * ONE source tree has to build a single BPF object that loads on kernels from
 * 4.18 (RHEL 8) to 6.12+, on x86_64 and aarch64, with wildly different BTF and
 * helper availability. This header is where every such difference is named,
 * so that no other file in the tree contains a bare kernel-version test.
 *
 * PREREQUISITE INCLUDES (BPF side):
 *     #include "vmlinux.h"
 *     #include <bpf/bpf_helpers.h>
 *     #include <bpf/bpf_endian.h>
 *     #include "common.h"
 *     #include "compat.h"
 *
 * THE CALY_HAVE_* SCHEME
 * ----------------------
 * Every optional kernel capability has:
 *
 *   1. a COMPILE-TIME macro, CALY_HAVE_<FEATURE>, which is 1 when the headers
 *      we were built against can even express the feature. This gates whether
 *      the instruction is emitted at all.
 *
 *   2. a RUNTIME capability bit in fw_config.flags, CALY_F_CAP_<FEATURE>,
 *      written by the loader after probing the running kernel. This gates
 *      whether the emitted instruction is executed.
 *
 * Both are required. Compile-time alone is wrong because a distro kernel's
 * BTF may advertise a helper prototype that the running kernel refuses.
 * Runtime alone is impossible because the verifier rejects an unknown helper
 * ID at load time, before any config can be read.
 *
 * The loader mirrors this table exactly:
 *
 *   CALY_HAVE_SYNCOOKIE_RAW  <-> CALY_F_CAP_SYNPROXY   (5.15+)
 *   CALY_HAVE_RINGBUF        <-> CALY_F_CAP_RINGBUF    (5.8+)
 *   CALY_HAVE_XDP_TX         <-> CALY_F_CAP_XDP_TX     (driver dependent)
 *   CALY_HAVE_TC_EGRESS      <-> CALY_F_CAP_TC_EGRESS  (clsact present)
 *   (BTF)                    <-> CALY_F_CAP_BTF
 *
 * FORBIDDEN HELPERS (do not add shims for these, do not use them):
 *   bpf_loop()                    5.17+  - all loops are CALY_UNROLL bounded
 *   bpf_map_lookup_percpu_elem()  5.20+  - userspace sums per-CPU values
 *   bpf_xdp_adjust_tail() GROWTH  5.8+   - the SYN proxy rewrites in place
 *   bpf_spin_lock()               5.1+   - unreliable on RHEL8 backports
 *   bpf_ktime_get_boot_ns()       5.7+   - bpf_ktime_get_ns() everywhere
 */

#ifndef __CALY_ANTI_COMPAT_H
#define __CALY_ANTI_COMPAT_H

/* -------------------------------------------------------------------------
 * Toolchain sanity
 * ------------------------------------------------------------------------- */

#ifndef __section
#define __section(NAME) __attribute__((section(NAME), used))
#endif

#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

/* barrier_var() forces the verifier to forget what it thinks it knows about a
 * scalar, which is how you stop LLVM hoisting a bounds check above the load it
 * protects. Cheap (no instruction is emitted), and load bearing in the parsers.
 */
#ifndef caly_barrier_var
#define caly_barrier_var(x) asm volatile("" : "+r"(x))
#endif

#ifndef caly_barrier
#define caly_barrier() asm volatile("" ::: "memory")
#endif

/* CALY_ARRAY_SIZE is only ever applied to real arrays, never to a pointer. */
#define CALY_ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

/* -------------------------------------------------------------------------
 * Compile-time feature detection.
 *
 * Every macro may be overridden from the Makefile with -DCALY_HAVE_x=0/1 so a
 * distribution build can force a conservative object without editing sources.
 * ------------------------------------------------------------------------- */

/* --- CO-RE / BTF ------------------------------------------------------- */
#ifndef CALY_HAVE_CORE
#if defined(__has_builtin)
#if __has_builtin(__builtin_preserve_access_index)
#define CALY_HAVE_CORE 1
#else
#define CALY_HAVE_CORE 0
#endif
#else
#define CALY_HAVE_CORE 0
#endif
#endif /* CALY_HAVE_CORE */

/* bpf_core_field_exists() and friends come from bpf_core_read.h. libbpf has
 * shipped them since 0.2; we only claim them when CO-RE builtins exist. */
#ifndef CALY_HAVE_CORE_FIELD_EXISTS
#if CALY_HAVE_CORE && defined(bpf_core_field_exists)
#define CALY_HAVE_CORE_FIELD_EXISTS 1
#else
#define CALY_HAVE_CORE_FIELD_EXISTS 0
#endif
#endif

/*
 * CALY_FIELD_EXISTS(type, field)
 *
 * 1 when the RUNNING kernel's BTF has that field, resolved by libbpf at load
 * time. Falls back to the compile-time answer (1, since vmlinux.h declared it)
 * when CO-RE is unavailable. Use this - never a LINUX_VERSION_CODE test - when
 * you need to know whether a struct member is present.
 */
#if CALY_HAVE_CORE_FIELD_EXISTS
#define CALY_FIELD_EXISTS(type, field) bpf_core_field_exists(type, field)
#else
#define CALY_FIELD_EXISTS(type, field) 1
#endif

/*
 * CALY_ENUM_VALUE_EXISTS(enum_type, value)
 *
 * Guards enumerators that appeared late (e.g. BPF_FIB_LKUP_RET_*). Same
 * fallback discipline as CALY_FIELD_EXISTS.
 */
#if CALY_HAVE_CORE && defined(bpf_core_enum_value_exists)
#define CALY_ENUM_VALUE_EXISTS(t, v) bpf_core_enum_value_exists(t, v)
#else
#define CALY_ENUM_VALUE_EXISTS(t, v) 1
#endif

/* --- raw SYN cookie helpers (5.15+) ------------------------------------ */
/*
 * These four are the ONLY sanctioned way to build the SYN proxy. When the
 * prototypes are absent from bpf_helper_defs.h the whole synproxy program is
 * compiled out; when they are present the loader still has to confirm the
 * running kernel implements them (libbpf_probe_bpf_helper) and set
 * CALY_F_CAP_SYNPROXY before the main program will tail call into it.
 */
#ifndef CALY_HAVE_SYNCOOKIE_RAW
#if defined(BPF_FUNC_tcp_raw_gen_syncookie_ipv4) || \
    defined(bpf_tcp_raw_gen_syncookie_ipv4)
#define CALY_HAVE_SYNCOOKIE_RAW 1
#else
/* libbpf exposes the helpers as static inline pointers in bpf_helper_defs.h
 * rather than macros, so the macro test above misses on most toolchains.
 * __builtin_preserve_enum_value is not usable here (helper IDs are not an
 * enum in vmlinux.h), so default to 1 on any clang new enough to have the
 * BPF target features the rest of this tree needs, and let the Makefile's
 * feature probe override with -DCALY_HAVE_SYNCOOKIE_RAW=0 when the compile
 * test fails. That probe is authoritative; this is only its default. */
#if defined(__clang_major__) && __clang_major__ >= 12
#define CALY_HAVE_SYNCOOKIE_RAW 1
#else
#define CALY_HAVE_SYNCOOKIE_RAW 0
#endif
#endif
#endif /* CALY_HAVE_SYNCOOKIE_RAW */

/* --- BPF ring buffer (5.8+) -------------------------------------------- */
#ifndef CALY_HAVE_RINGBUF
#if defined(BPF_MAP_TYPE_RINGBUF) || defined(__CALY_FORCE_RINGBUF)
#define CALY_HAVE_RINGBUF 1
#else
#define CALY_HAVE_RINGBUF 0
#endif
#endif

/*
 * The ringbuf MAP may be declared even on old kernels because the loader calls
 * bpf_map__set_autocreate(caly_events_rb, false) when the probe fails, and the
 * verifier then rewrites the (unreachable, config-gated) helper calls against
 * a map that is never created. bpf_map__set_autocreate() is libbpf 0.8+; on
 * older libbpf the build must define CALY_HAVE_RINGBUF=0 so the map is not
 * declared at all. The Makefile probes for it.
 */
#ifndef CALY_HAVE_MAP_AUTOCREATE
#define CALY_HAVE_MAP_AUTOCREATE CALY_HAVE_RINGBUF
#endif

/* --- XDP_TX ------------------------------------------------------------- */
/*
 * XDP_TX is in the ABI since 4.8, so it always compiles. Whether the DRIVER
 * can transmit on the RX queue is a runtime property; in generic/skb mode it
 * works but is slow. Hence the runtime bit only.
 */
#ifndef CALY_HAVE_XDP_TX
#define CALY_HAVE_XDP_TX 1
#endif

/* --- tc/clsact BPF ------------------------------------------------------ */
#ifndef CALY_HAVE_TC_EGRESS
#define CALY_HAVE_TC_EGRESS 1
#endif

/* --- VLAN metadata in struct xdp_md ------------------------------------- */
/*
 * xdp_md has no vlan_tci field on any kernel; hardware VLAN offload strips the
 * tag before XDP sees it on some drivers. We therefore ALWAYS parse tags from
 * the frame and never consult metadata. Named here so nobody adds it later.
 */
#define CALY_HAVE_XDP_VLAN_META 0

/* --- bpf_ktime_get_boot_ns (5.7+) --------------------------------------- */
/*
 * Deliberately NOT used. Every timestamp in the ABI (ban_entry.expiry_ns,
 * token_bucket.last_refill_ns, ...) is bpf_ktime_get_ns(). Mixing the two
 * clocks would make bans expire at boot-time offsets. Userspace reads
 * CLOCK_MONOTONIC to stay in the same time base.
 */
#define CALY_HAVE_KTIME_BOOT 0

/* -------------------------------------------------------------------------
 * Runtime capability tests.
 *
 * Always pair the compile-time macro with the runtime bit. The && short
 * circuits at compile time when the feature is not built in, so the config
 * load is elided entirely in that case.
 * ------------------------------------------------------------------------- */

#define caly_cap(cfg, bit)  (((cfg) != 0) && (((cfg)->flags & (bit)) != 0))

#define CALY_CAN_SYNPROXY(cfg) \
	(CALY_HAVE_SYNCOOKIE_RAW && caly_cap((cfg), CALY_F_CAP_SYNPROXY))

#define CALY_CAN_RINGBUF(cfg) \
	(CALY_HAVE_RINGBUF && caly_cap((cfg), CALY_F_CAP_RINGBUF))

#define CALY_CAN_XDP_TX(cfg) \
	(CALY_HAVE_XDP_TX && caly_cap((cfg), CALY_F_CAP_XDP_TX))

/* -------------------------------------------------------------------------
 * XDP action constants.
 *
 * vmlinux.h supplies enum xdp_action, but a BTF-less or reduced vmlinux.h can
 * miss it and the numbers are ABI-frozen anyway. XDP_ABORTED is defined for
 * completeness and then poisoned: it fires the xdp_exception tracepoint and is
 * an error path, not a drop verdict. It must never appear in this tree.
 * ------------------------------------------------------------------------- */

#ifndef XDP_ABORTED
#define XDP_ABORTED   0
#define XDP_DROP      1
#define XDP_PASS      2
#define XDP_TX        3
#define XDP_REDIRECT  4
#endif

/* Perf-event-output flags. These are UAPI #defines from <linux/bpf.h>, not
 * types or enumerators, so vmlinux.h (which carries only types) does not
 * supply them. Define them if absent so bpf_perf_event_output() compiles
 * against a pure vmlinux.h build. */
#ifndef BPF_F_INDEX_MASK
#define BPF_F_INDEX_MASK   0xffffffffULL
#endif
#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU  BPF_F_INDEX_MASK
#endif

/* tc/clsact return codes (linux/pkt_cls.h), redefined so the tc program does
 * not have to include a UAPI header that clashes with vmlinux.h. */
#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC   (-1)
#endif
#ifndef TC_ACT_OK
#define TC_ACT_OK       0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT     2
#endif

/* -------------------------------------------------------------------------
 * Error codes returned by the parsers in parsing.h.
 *
 * Negative, small, and disjoint from any errno the helpers return, so a caller
 * can propagate either without ambiguity. Every one maps to exactly one
 * enum stat_reason; caly_parse_err_reason() below does the translation so the
 * mapping lives in one place.
 * ------------------------------------------------------------------------- */

#define CALY_OK                  0
#define CALY_ERR_TRUNC          (-1)   /* read would pass data_end          */
#define CALY_ERR_ETH_TRUNC      (-2)
#define CALY_ERR_VLAN_TRUNC     (-3)
#define CALY_ERR_VLAN_DEPTH     (-4)
#define CALY_ERR_L3_UNKNOWN     (-5)
#define CALY_ERR_IP4_TRUNC      (-6)
#define CALY_ERR_IP4_IHL        (-7)
#define CALY_ERR_IP4_TOTLEN     (-8)
#define CALY_ERR_IP4_OPTIONS    (-9)
#define CALY_ERR_IP6_TRUNC      (-10)
#define CALY_ERR_IP6_EXT_DEPTH  (-11)
#define CALY_ERR_IP6_EXT_TRUNC  (-12)
#define CALY_ERR_IP6_RH0        (-13)
#define CALY_ERR_TUNNEL_TRUNC   (-14)
#define CALY_ERR_TUNNEL_DEPTH   (-15)
#define CALY_ERR_TUNNEL_PROTO   (-16)
#define CALY_ERR_GRE_MALFORMED  (-17)
#define CALY_ERR_L4_TRUNC       (-18)
#define CALY_ERR_L4_UNKNOWN     (-19)
#define CALY_ERR_TCP_DOFF       (-20)
#define CALY_ERR_L4_PORT_ZERO   (-21)
#define CALY_ERR_ENCRYPTED      (-22)  /* ESP: no L4 to inspect, not an error */
#define CALY_ERR_NO_NEXT        (-23)  /* IPPROTO_NONE: nothing follows       */
#define CALY_ERR_FRAG_NO_L4     (-24)  /* non-first fragment, no L4 header    */
#define CALY_ERR_INVAL          (-25)  /* bad argument from the caller        */

/*
 * Translate a parser error into the stat_reason to charge. Unknown/benign
 * codes fall back to STAT_DROP_L4_TRUNC only for genuine truncation; the three
 * "not an error" codes (ESP, NONE, non-first fragment) return STAT_PKT_TOTAL
 * so the caller can tell "cannot inspect" from "must drop".
 */
CALY_INLINE __u32 caly_parse_err_reason(int err)
{
	switch (err) {
	case CALY_ERR_ETH_TRUNC:     return STAT_DROP_ETH_TRUNC;
	case CALY_ERR_VLAN_TRUNC:    return STAT_DROP_VLAN_TRUNC;
	case CALY_ERR_VLAN_DEPTH:    return STAT_DROP_VLAN_DEPTH;
	case CALY_ERR_L3_UNKNOWN:    return STAT_DROP_L3_UNKNOWN;
	case CALY_ERR_IP4_TRUNC:     return STAT_DROP_IP4_TRUNC;
	case CALY_ERR_IP4_IHL:       return STAT_DROP_IP4_IHL;
	case CALY_ERR_IP4_TOTLEN:    return STAT_DROP_IP4_TOTLEN;
	case CALY_ERR_IP4_OPTIONS:   return STAT_DROP_IP4_OPTIONS;
	case CALY_ERR_IP6_TRUNC:     return STAT_DROP_IP6_TRUNC;
	case CALY_ERR_IP6_EXT_DEPTH: return STAT_DROP_IP6_EXT_DEPTH;
	case CALY_ERR_IP6_EXT_TRUNC: return STAT_DROP_IP6_EXT_TRUNC;
	case CALY_ERR_IP6_RH0:       return STAT_DROP_IP6_RH0;
	case CALY_ERR_TUNNEL_TRUNC:  return STAT_DROP_TUNNEL_TRUNC;
	case CALY_ERR_TUNNEL_DEPTH:  return STAT_DROP_TUNNEL_DEPTH;
	case CALY_ERR_TUNNEL_PROTO:  return STAT_DROP_TUNNEL_PROTO;
	case CALY_ERR_GRE_MALFORMED: return STAT_DROP_GRE_MALFORMED;
	case CALY_ERR_L4_TRUNC:      return STAT_DROP_L4_TRUNC;
	case CALY_ERR_L4_UNKNOWN:    return STAT_DROP_L4_UNKNOWN;
	case CALY_ERR_TCP_DOFF:      return STAT_DROP_TCP_DOFF;
	case CALY_ERR_L4_PORT_ZERO:  return STAT_DROP_L4_PORT_ZERO;
	case CALY_ERR_TRUNC:         return STAT_DROP_L4_TRUNC;
	/* Not failures: the packet is well formed, we simply cannot see L4. */
	case CALY_ERR_ENCRYPTED:     return STAT_PKT_TOTAL;
	case CALY_ERR_NO_NEXT:       return STAT_PKT_TOTAL;
	case CALY_ERR_FRAG_NO_L4:    return STAT_PKT_TOTAL;
	case CALY_ERR_INVAL:         return STAT_PKT_TOTAL;
	default:                     return STAT_PKT_TOTAL;
	}
}

/*
 * A parse result that is "cannot inspect further" rather than "malformed".
 * These must never turn into a drop on their own: an ESP packet or a trailing
 * fragment is legitimate traffic that simply has no ports to police.
 */
CALY_INLINE int caly_parse_err_benign(int err)
{
	return err == CALY_ERR_ENCRYPTED || err == CALY_ERR_NO_NEXT ||
	       err == CALY_ERR_FRAG_NO_L4;
}

/* -------------------------------------------------------------------------
 * Byte order.
 *
 * bpf_htons/bpf_ntohs come from <bpf/bpf_endian.h> and are compile-time
 * constant folded. These wrappers exist so a file that (legitimately) does not
 * include bpf_endian.h - the userspace simulator, for instance - still builds.
 * ------------------------------------------------------------------------- */

#ifndef caly_htons
#if defined(bpf_htons)
#define caly_htons(x) bpf_htons(x)
#define caly_ntohs(x) bpf_ntohs(x)
#define caly_htonl(x) bpf_htonl(x)
#define caly_ntohl(x) bpf_ntohl(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
      __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define caly_htons(x) ((__u16)__builtin_bswap16((__u16)(x)))
#define caly_ntohs(x) ((__u16)__builtin_bswap16((__u16)(x)))
#define caly_htonl(x) ((__u32)__builtin_bswap32((__u32)(x)))
#define caly_ntohl(x) ((__u32)__builtin_bswap32((__u32)(x)))
#else
#define caly_htons(x) ((__u16)(x))
#define caly_ntohs(x) ((__u16)(x))
#define caly_htonl(x) ((__u32)(x))
#define caly_ntohl(x) ((__u32)(x))
#endif
#endif /* caly_htons */

/* -------------------------------------------------------------------------
 * Small arithmetic shims used across the dataplane.
 * ------------------------------------------------------------------------- */

CALY_INLINE __u64 caly_min_u64(__u64 a, __u64 b) { return a < b ? a : b; }
CALY_INLINE __u64 caly_max_u64(__u64 a, __u64 b) { return a > b ? a : b; }
CALY_INLINE __u32 caly_min_u32(__u32 a, __u32 b) { return a < b ? a : b; }
CALY_INLINE __u32 caly_max_u32(__u32 a, __u32 b) { return a > b ? a : b; }

/* Saturating add: counters must never wrap into a small number, because a
 * wrapped strike counter reads as "no strikes" and disables the ban path. */
CALY_INLINE __u64 caly_add_sat_u64(__u64 a, __u64 b)
{
	__u64 s = a + b;

	return s < a ? ~0ULL : s;
}

CALY_INLINE __u32 caly_add_sat_u32(__u32 a, __u32 b)
{
	__u32 s = a + b;

	return s < a ? ~0u : s;
}

/*
 * Monotonic-clock delta that is safe against a timestamp captured on another
 * CPU whose bpf_ktime_get_ns() ran a few nanoseconds ahead. Returns 0 rather
 * than a ~1.8e19 nanosecond "age" when `then` is in the future, which is what
 * a naive subtraction produces and what makes idle-timeout logic misfire.
 */
CALY_INLINE __u64 caly_age_ns(__u64 now_ns, __u64 then_ns)
{
	return now_ns > then_ns ? now_ns - then_ns : 0;
}

/* -------------------------------------------------------------------------
 * Clamping of runtime knobs to their compile-time verifier bounds.
 *
 * Loop bounds in the dataplane are ALWAYS the CALY_*_MAX constants, never a
 * config value; the config may only lower the effective bound. These helpers
 * enforce that in one place so no caller has to remember it.
 * ------------------------------------------------------------------------- */

CALY_INLINE __u32 caly_clamp_vlan_depth(__u32 v)
{
	if (v == 0 || v > CALY_VLAN_MAX_DEPTH)
		return CALY_VLAN_MAX_DEPTH;
	return v;
}

CALY_INLINE __u32 caly_clamp_ip6_ext(__u32 v)
{
	if (v == 0 || v > CALY_IP6_EXT_MAX)
		return CALY_IP6_EXT_MAX;
	return v;
}

CALY_INLINE __u32 caly_clamp_tunnel_depth(__u32 v)
{
	if (v > CALY_TUNNEL_MAX_DEPTH)
		return CALY_TUNNEL_MAX_DEPTH;
	return v;
}

/* -------------------------------------------------------------------------
 * Fail-open discipline.
 *
 * EVERY internal failure - config missing, scratch NULL, tail call failed, LRU
 * full, event ring full - results in XDP_PASS plus a counter. Never a drop.
 * These two macros exist so that intent is greppable and so a reviewer can
 * verify the invariant by searching for the macro rather than reading every
 * return statement.
 * ------------------------------------------------------------------------- */

#define CALY_FAIL_OPEN      XDP_PASS
#define CALY_FAIL_OPEN_TC   TC_ACT_OK

/*
 * Poison XDP_ABORTED. Any accidental use in this tree becomes a compile error
 * with a message pointing at the reason, instead of a silent production bug
 * that fires xdp_exception under load. The definition above is kept so that
 * arithmetic on enum xdp_action still works; only the identifier is poisoned,
 * and only after every legitimate use (there are none).
 */
#if defined(__clang__) && !defined(CALY_ALLOW_XDP_ABORTED)
/* #pragma GCC poison would also reject the #define above, so the check is a
 * static one instead: XDP_ABORTED must be 0 and must never be RETURNED. The
 * build system greps for "return XDP_ABORTED" as a belt-and-braces check. */
typedef char caly_xdp_aborted_is_zero[(XDP_ABORTED == 0) ? 1 : -1];
#endif

/* -------------------------------------------------------------------------
 * Verifier budget hints.
 *
 * 4.18-era verifiers cap complexity at 96k instructions analysed (1M from
 * 5.2). The IPv6 path can be split into caly_progs[CALY_PROG_IDX_IPV6] when a
 * build overruns; CALY_SPLIT_IPV6 selects that. Default off - the main program
 * fits comfortably - but the Makefile can turn it on for a constrained target
 * without touching the dataplane source.
 * ------------------------------------------------------------------------- */

#ifndef CALY_SPLIT_IPV6
#define CALY_SPLIT_IPV6 0
#endif

/* Instruction budget assumed by the unroll bounds. Purely documentary. */
#define CALY_VERIFIER_BUDGET_OLD   96000u
#define CALY_VERIFIER_BUDGET_NEW   1000000u

/* -------------------------------------------------------------------------
 * License. Placed here so every object in the tree spells it identically:
 * GPL-only helpers (bpf_perf_event_output on some kernels, the syncookie
 * helpers) refuse to link against a non-GPL-compatible string.
 * ------------------------------------------------------------------------- */
#define CALY_BPF_LICENSE "Dual BSD/GPL"

#endif /* __CALY_ANTI_COMPAT_H */
