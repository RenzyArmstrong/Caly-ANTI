/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/autotune.h
 *
 * Adaptive attack detection, classification and mitigation escalation.
 *
 * WHAT THIS MODULE IS
 * -------------------
 * The dataplane never decides anything about the *global* state of the box.
 * It counts, it enforces, and it reads fw_config.mode. This module is the
 * closed loop around it:
 *
 *     sample gauges  ->  differentiate into rates  ->  EWMA baselines
 *         ->  anomaly detection (multiple-of-baseline + absolute floor)
 *         ->  debounce / hysteresis
 *         ->  attack classification
 *         ->  per-class response plan
 *         ->  fw_mode state machine + fw_config synthesis
 *         ->  map writes (through struct at_ops, i.e. maps.c)
 *         ->  auto-bans with escalating TTLs
 *         ->  structured JSON alerts + fork/exec hook + webhook
 *
 * WHAT THIS MODULE IS NOT
 * -----------------------
 * It contains no map plumbing whatsoever. Every read and every write goes
 * through the function-pointer table `struct at_ops`, which the daemon fills
 * in with the maps.c implementations. That keeps the decision logic testable
 * (feed it a synthetic sample, assert the plan) and keeps exactly one copy of
 * the bpf(2) syscall wrappers in the tree.
 *
 * TIME DOMAIN - READ THIS
 * -----------------------
 * Every `now_ns` handed to this module MUST come from
 * clock_gettime(CLOCK_MONOTONIC), because that is the same clock as
 * bpf_ktime_get_ns() in the dataplane. ban_entry.expiry_ns is compared against
 * bpf_ktime_get_ns() inside XDP; computing it from CLOCK_REALTIME would make
 * every ban either instantly expired or effectively permanent. Use
 * autotune_now_ns() and there is nothing to get wrong.
 *
 * SAFETY INVARIANTS THIS MODULE UPHOLDS
 * -------------------------------------
 *  - It never removes TCP/22 (or any operator mgmt port) from fw_config. If a
 *    candidate configuration would lack TCP/22 it is repaired before the push,
 *    and if it still fails validation the push is abandoned and the previously
 *    running configuration keeps running.
 *  - It never clears CALY_F_ENABLED, CALY_F_ALLOWLIST, CALY_F_MGMT_BYPASS_ALL
 *    or CALY_F_LOCKDOWN_ICMP; in LOCKDOWN it forces all four ON.
 *  - It never sets a token-bucket rate below a hard floor, so no escalation
 *    path can strangle legitimate traffic to zero.
 *  - It never issues a permanent ban. CALY_BAN_F_PERMANENT is reserved for the
 *    operator; every ban this module installs carries a finite expiry_ns.
 *  - Every candidate configuration is rebuilt from the operator baseline, not
 *    from the previously tightened configuration, so de-escalation restores
 *    the operator's values exactly and escalation never ratchets.
 *  - LOCKDOWN is opt-in (at_tunables.allow_lockdown) and matches the shipped
 *    config's documented behaviour: lockdown and monitor-only are operator
 *    states; if the operator pins one, this module observes and alerts but
 *    stops driving the mode.
 *  - Attacker-derived data never reaches a shell. Hook argv entries come from
 *    fixed internal string tables and integers only; the JSON payload (which
 *    does contain attacker-chosen source addresses, rendered by inet_ntop from
 *    binary) is delivered on the child's stdin, never as an argument.
 *
 * THREADING
 * ---------
 * Single-threaded. One `struct autotune` is driven by one thread (the daemon
 * main loop). The alert hook temporarily changes the SIGPIPE disposition while
 * writing to the child's stdin, which is only safe in a single-threaded
 * process; the daemon may also just install SIG_IGN for SIGPIPE at startup, in
 * which case the save/restore is a no-op.
 *
 * PREREQUISITE: this header includes common.h, so the build must be able to
 * find src/bpf/common.h (either -Isrc/bpf, or the ../bpf relative fallback
 * below, which works when this header is compiled from src/user/).
 */

#ifndef CALY_ANTI_AUTOTUNE_H
#define CALY_ANTI_AUTOTUNE_H

#include <stdarg.h>
#include <stddef.h>
#include <linux/types.h>

#ifndef CALY_USERSPACE
#define CALY_USERSPACE 1
#endif

#if defined(__has_include)
#  if __has_include("common.h")
#    include "common.h"
#  elif __has_include("../bpf/common.h")
#    include "../bpf/common.h"
#  else
#    include <common.h>
#  endif
#else
#  include "common.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Version of the autotune decision logic. Bumped when the meaning of a
 * tunable changes; emitted in every JSON alert so a log archive can be read
 * years later without guessing.
 * ------------------------------------------------------------------------- */
#define AT_LOGIC_VERSION        1u

/* Daemon log levels; identical numbering to fw_config.log_level. */
#define AT_LOG_ERR              0
#define AT_LOG_WARN             1
#define AT_LOG_INFO             2
#define AT_LOG_DEBUG            3
#define AT_LOG_TRACE            4

/* -------------------------------------------------------------------------
 * Metrics.
 *
 * PPS/BPS/SYN/NEWCONN/UDP/ICMP/FRAG/TCP/DROP are RATES, differentiated from
 * the cumulative per-CPU gauges. UNIQ_SRC is a rate too (distinct sources per
 * second). CONN_LEVEL and PKT_SIZE are LEVELS, not rates - a level is compared
 * against its own baseline exactly the same way, it is just not differentiated
 * on the way in.
 *
 * AT_M_TCP_PPS is derived (pps - udp - icmp, floored at zero). It is not
 * exact - SCTP, ESP and friends are folded into it - but it is precisely the
 * signal needed to separate an ACK/PSH-ACK flood (TCP up, SYN flat) from a SYN
 * flood (TCP up, SYN up).
 * ------------------------------------------------------------------------- */
enum at_metric {
	AT_M_PPS         = 0,   /* total packets/sec                           */
	AT_M_BPS         = 1,   /* total bytes/sec                             */
	AT_M_SYN_PPS     = 2,   /* TCP SYN (no ACK) packets/sec                */
	AT_M_NEWCONN_PPS = 3,   /* conntrack misses / new flows per sec        */
	AT_M_UDP_PPS     = 4,
	AT_M_ICMP_PPS    = 5,
	AT_M_FRAG_PPS    = 6,
	AT_M_TCP_PPS     = 7,   /* derived: pps - udp - icmp                   */
	AT_M_DROP_PPS    = 8,
	AT_M_UNIQ_SRC    = 9,   /* distinct source addresses per second        */
	AT_M_CONN_LEVEL  = 10,  /* conntrack table occupancy (a level)         */
	AT_M_PKT_SIZE    = 11,  /* mean packet size in bytes (a level)         */
	AT_M_MAX         = 12
};

/* EWMA window set. Short reacts, medium contextualises, long is the baseline
 * that anomaly thresholds are multiples of. */
enum at_window {
	AT_W_SHORT = 0,   /* default 10s  */
	AT_W_MED   = 1,   /* default 1m   */
	AT_W_LONG  = 2,   /* default 15m  */
	AT_W_MAX   = 3
};

/* -------------------------------------------------------------------------
 * Attack classification. Attacks are frequently mixed, so classification
 * produces a BITMASK plus a single highest-scoring primary class.
 * ------------------------------------------------------------------------- */
enum at_class {
	AT_C_SYN        = 0,   /* spoofed / non-spoofed SYN flood             */
	AT_C_ACK        = 1,   /* ACK, PSH-ACK, RST flood (no handshake)      */
	AT_C_UDP        = 2,   /* plain UDP flood                             */
	AT_C_AMP        = 3,   /* reflection / amplification                  */
	AT_C_ICMP       = 4,
	AT_C_FRAG       = 5,   /* fragment flood                              */
	AT_C_CONN_EXH   = 6,   /* connection-table exhaustion                 */
	AT_C_SLOWLORIS  = 7,   /* many connections, little traffic            */
	AT_C_PORTSCAN   = 8,
	AT_C_VOLUMETRIC = 9,   /* generic: big, but not otherwise classified  */
	AT_C_MAX        = 10
};

#define AT_CLS_BIT(i)      (1u << (i))
#define AT_CLS_SYN         AT_CLS_BIT(AT_C_SYN)
#define AT_CLS_ACK         AT_CLS_BIT(AT_C_ACK)
#define AT_CLS_UDP         AT_CLS_BIT(AT_C_UDP)
#define AT_CLS_AMP         AT_CLS_BIT(AT_C_AMP)
#define AT_CLS_ICMP        AT_CLS_BIT(AT_C_ICMP)
#define AT_CLS_FRAG        AT_CLS_BIT(AT_C_FRAG)
#define AT_CLS_CONN_EXH    AT_CLS_BIT(AT_C_CONN_EXH)
#define AT_CLS_SLOWLORIS   AT_CLS_BIT(AT_C_SLOWLORIS)
#define AT_CLS_PORTSCAN    AT_CLS_BIT(AT_C_PORTSCAN)
#define AT_CLS_VOLUMETRIC  AT_CLS_BIT(AT_C_VOLUMETRIC)
#define AT_CLS_NONE        0u

/* A class is asserted when its evidence score reaches this. */
#define AT_CLASS_MIN_SCORE 50u

/* Alert kinds. */
enum at_event_kind {
	AT_EV_MODE_UP     = 0,
	AT_EV_MODE_DOWN   = 1,
	AT_EV_ATTACK      = 2,   /* attack detected / classification changed  */
	AT_EV_CLEAR       = 3,   /* back to NORMAL                            */
	AT_EV_BAN         = 4,
	AT_EV_HEARTBEAT   = 5,
	AT_EV_ERROR       = 6,
	AT_EV_MAX         = 7
};

/* Upper bound on offenders considered per tick. */
#define AT_TOP_MAX          64u
/* Offenders listed inside one JSON alert. */
#define AT_ALERT_BANS_MAX   16u
/* Largest JSON alert we will ever emit, including the trailing newline. */
#define AT_JSON_MAX         8192u

/* -------------------------------------------------------------------------
 * Addresses
 * ------------------------------------------------------------------------- */
struct at_addr {
	__u32 family;    /* CALY_AF_INET or CALY_AF_INET6                    */
	__u32 a[4];      /* NETWORK byte order. IPv4 uses a[0]; a[1..3] == 0 */
};

/* One candidate offender, as returned by at_ops.top_offenders(). The op fills
 * `addr` and `st` (the raw cumulative struct src_stats read out of caly_top4 /
 * caly_top6). autotune fills the delta fields from its own per-source memory,
 * so maps.c does not have to keep a previous-sample table. */
struct at_offender {
	struct at_addr   addr;
	struct src_stats st;
	__u64            drops_delta;   /* filled by autotune */
	__u64            pkts_delta;    /* filled by autotune */
	__u32            share_pct;     /* filled by autotune */
	__u32            pad;
};

/* -------------------------------------------------------------------------
 * struct at_ops - the ONLY way this module touches the kernel.
 *
 * ctx is passed back verbatim; the daemon typically points it at its
 * `struct caly_maps`. Every entry except config_read and gauges_read may be
 * NULL: a NULL op disables exactly the feature that needs it, is logged once
 * at init, and never causes a crash or a wrong decision. Return 0 on success
 * and a negative errno on failure unless stated otherwise.
 *
 * IMPLEMENTATION NOTES FOR maps.c
 *   config_read    - read caly_config key 0 into *out.
 *   config_write   - write *in to caly_config key 0 (BPF_ANY). The caller has
 *                    already validated it; do not second-guess the contents,
 *                    but DO reject a write whose abi_version major differs
 *                    from CALY_ABI_VERSION_MAJOR.
 *   gauges_read    - read caly_global, SUMMING each index across all CPUs,
 *                    into out[0..n-1] where n == CALY_G_MAX. Values are
 *                    cumulative counters, never rates.
 *   stats_read     - same for caly_stats (packet counts), n == STAT_MAX.
 *   conn_count     - number of live entries in caly_conn. An exact count needs
 *                    a full walk; a cached count maintained by the GC sweep is
 *                    perfectly adequate and is what this module expects.
 *   unique_sources - number of DISTINCT source addresses observed since the
 *                    previous call to this op (typically counted by the GC
 *                    sweep over caly_rate4/caly_rate6). Consumed as a rate.
 *   top_offenders  - up to `max` entries from caly_top4 + caly_top6, largest
 *                    st.drops first. Fewer is fine. Returns the count, or a
 *                    negative errno.
 *   ban_lookup     - caly_ban4 / caly_ban6 lookup; 0 on hit, -ENOENT on miss.
 *   ban_add        - caly_ban4 / caly_ban6 update (BPF_ANY). LRU maps never
 *                    fail on capacity, they evict.
 *   is_allowlisted - longest-prefix match of the address in caly_allow4 /
 *                    caly_allow6. 1 = allowlisted, 0 = not, negative = error.
 *   port_rule_get  - caly_port_tcp / caly_port_udp lookup by HOST-order port.
 *   port_rule_set  - the matching update. Used only to raise or lower
 *                    CALY_PORT_F_AMPLIFIER on the standard reflector ports.
 *   icmp_pol_get   - caly_icmp4_pol / caly_icmp6_pol lookup by type.
 *   icmp_pol_set   - the matching update. NEVER called with CALY_ICMP_DROP for
 *                    a mandatory type; this module only ever writes
 *                    CALY_ICMP_RATELIMIT to ICMPv4 type 8 / ICMPv6 type 128,
 *                    and only when it was able to read the previous value
 *                    first so that it can be restored on de-escalation.
 *   log            - printf-style daemon logger. May be NULL.
 * ------------------------------------------------------------------------- */
typedef void (*at_log_fn)(void *ctx, int level, const char *fmt, ...)
#if defined(__GNUC__)
	__attribute__((format(printf, 3, 4)))
#endif
	;

struct at_ops {
	void *ctx;

	int (*config_read)(void *ctx, struct fw_config *out);
	int (*config_write)(void *ctx, const struct fw_config *in);

	int (*gauges_read)(void *ctx, __u64 *out, __u32 n);
	int (*stats_read)(void *ctx, __u64 *out, __u32 n);
	int (*conn_count)(void *ctx, __u64 *out);
	int (*unique_sources)(void *ctx, __u64 *out);

	int (*top_offenders)(void *ctx, struct at_offender *out, __u32 max);

	int (*ban_lookup)(void *ctx, const struct at_addr *a,
			  struct ban_entry *out);
	int (*ban_add)(void *ctx, const struct at_addr *a,
		       const struct ban_entry *e);
	int (*is_allowlisted)(void *ctx, const struct at_addr *a);

	int (*port_rule_get)(void *ctx, int is_udp, __u16 port,
			     struct port_rule *out);
	int (*port_rule_set)(void *ctx, int is_udp, __u16 port,
			     const struct port_rule *in);

	int (*icmp_pol_get)(void *ctx, int v6, __u8 type, __u32 *out);
	int (*icmp_pol_set)(void *ctx, int v6, __u8 type, __u32 pol);

	at_log_fn log;
};

/* -------------------------------------------------------------------------
 * Tunables. autotune_tunables_default() fills every field with a value that
 * is safe on an untuned box; the daemon then overrides from calyanti.conf.
 * ------------------------------------------------------------------------- */
struct at_tunables {
	/* EWMA time constants, indexed by enum at_window. */
	__u64 win_ns[AT_W_MAX];

	/* Ignore ticks closer together than this (a burst of SIGALRMs must not
	 * turn into a burst of escalation decisions). Default 250ms. */
	__u64 min_tick_ns;

	/* Adaptive (baseline-relative) escalation is suppressed until the
	 * baselines have had this long to form. Absolute thresholds from
	 * fw_config (global_*_hi) remain active throughout, so a box that boots
	 * into an ongoing flood still reacts. Default 60s. */
	__u64 warmup_ns;

	/* Repeat the "still under attack" alert this often. Default 60s. */
	__u64 heartbeat_ns;

	/* Minimum spacing between hook/webhook executions. Default 5s. */
	__u64 hook_min_interval_ns;

	/* Extra dwell required before leaving LOCKDOWN, on top of
	 * fw_config.attack_dwell_ns. Default 5m. */
	__u64 lockdown_extra_dwell_ns;

	/* Minimum interval between auto-ban passes. Default 2s. */
	__u64 ban_interval_ns;

	/* Anomaly rule per metric: anomalous when
	 *     rate > max(metric_floor[m], baseline_long * metric_mult[m] / 10)
	 * metric_mult is in TENTHS (40 == 4.0x). A mult of 0 removes the metric
	 * from anomaly detection entirely (it is still tracked and reported). */
	__u64 metric_floor[AT_M_MAX];
	__u32 metric_mult[AT_M_MAX];

	/* Debounce / hysteresis, in consecutive samples. */
	__u32 confirm_up;      /* default 3  */
	__u32 confirm_down;    /* default 10 */

	/* Severity (0..100) required for each rung. */
	__u32 sev_elevate;     /* default 20 */
	__u32 sev_attack;      /* default 50 */
	__u32 sev_lockdown;    /* default 85 */

	/* Auto-ban policy. */
	__u32 max_bans_per_tick;  /* default 32 */
	__u64 ban_min_drops;      /* per interval, default 1000 */
	__u32 ban_min_share_pct;  /* of all drops this interval, default 2 */
	__u32 srcmem_entries;     /* per-source memory slots, default 4096 */

	/* Capability gates. Each one authorises this module to turn a policy
	 * bit ON that the operator left OFF. Nothing here can turn an operator
	 * bit off. */
	__u32 allow_lockdown;        /* auto-escalate to LOCKDOWN. default 0  */
	__u32 allow_synproxy;        /* set CALY_F_SYNPROXY.       default 1  */
	__u32 allow_amp_override;    /* set CALY_F_ANTI_AMPLIFY and re-assert
				      * CALY_PORT_F_AMPLIFIER.     default 1  */
	__u32 allow_portscan_enable; /* set CALY_F_PORTSCAN_DETECT default 1  */
	__u32 allow_drop_all_frags;  /* LOCKDOWN only.             default 0  */
	__u32 allow_icmp_policy;     /* rate-limit echo types.     default 1  */
	__u32 allow_autoban;         /* userspace auto-bans.       default 1  */

	/* Decide and alert, but never write a map. The operator's dry run. */
	__u32 dry_run;

	__u32 alerts_enabled;     /* default 1 */
	__u32 hook_timeout_s;     /* child SIGALRM budget, default 10 */

	/* Alert sinks. Empty string disables that sink.
	 *   alert_file   - path to append JSON Lines to. "-" means stderr.
	 *   hook_path    - absolute path to an executable. Invoked as
	 *                  hook --event E --mode M --class C --severity N
	 *                  with the JSON alert on stdin.
	 *   webhook_url  - http:// or https:// endpoint. POSTed with the
	 *                  external client below; the JSON goes on stdin, never
	 *                  into argv.
	 *   webhook_client - absolute path to a curl-compatible client. Empty
	 *                  means probe /usr/bin/curl, /bin/curl,
	 *                  /usr/local/bin/curl at init. If none is found the
	 *                  webhook sink is disabled with a warning; use
	 *                  hook_path instead. */
	char  alert_file[256];
	char  hook_path[256];
	char  webhook_url[1024];
	char  webhook_client[256];

	/* Free-form identity stamped into every alert. */
	char  node_id[64];
};

/* -------------------------------------------------------------------------
 * Internal state (exposed so the daemon can embed the struct; treat the
 * fields as read-only outside this module).
 * ------------------------------------------------------------------------- */
struct at_track {
	__u64 ewma[AT_W_MAX];
	__u64 cur;
	__u64 peak;
	__u32 samples;
	__u32 anomalous;
};

struct at_rtrack {          /* per stat_reason */
	__u64 prev;
	__u64 rate;
	__u64 ewma_short;
	__u64 ewma_long;
};

/* Per-source memory: previous cumulative counters (so we can differentiate a
 * source's drop count without maps.c keeping a table) plus the ban escalation
 * history that makes TTLs grow across repeat offences. */
struct at_srcmem {
	__u32 a[4];
	__u32 family;          /* 0 == empty slot */
	__u32 offences;
	__u64 prev_drops;
	__u64 prev_pkts;
	__u64 cur_ttl_ns;
	__u64 last_ban_ns;
	__u64 last_seen_ns;
	__u64 ban_expires_ns;
};

/* One observation handed to autotune_step(). autotune_tick() builds this from
 * the ops table; tests build it by hand. */
struct at_sample {
	__u64 gauge[CALY_G_MAX];
	__u64 stat[STAT_MAX];
	__u64 conn_entries;
	__u64 uniq_sources;
	struct fw_config live;
	__u32 have_stat;
	__u32 have_conn;
	__u32 have_uniq;
	__u32 have_live;
};

struct at_status {
	__u32 mode;
	__u32 pinned;
	__u32 severity;
	__u32 class_mask;
	__u32 primary_class;
	__u32 anom_mask;
	__u32 warmed_up;
	__u32 up_count;
	__u32 down_count;
	__u32 pad0;
	__u64 mode_since_ns;
	__u64 attack_since_ns;
	__u64 dwell_remaining_ns;
	__u64 rate[AT_M_MAX];
	__u64 base[AT_M_MAX];
	__u64 ewma_short[AT_M_MAX];
	__u64 ewma_med[AT_M_MAX];
	__u64 thr[AT_M_MAX];
	__u64 samples;
	__u64 bans_issued;
	__u64 bans_suppressed;
	__u64 alerts_emitted;
	__u64 alerts_failed;
	__u64 config_pushes;
	__u64 config_rejected;
	__u64 last_tick_ns;
};

struct autotune {
	struct at_ops      ops;
	struct at_tunables cfg;

	/* Operator baseline. Every candidate configuration is built from this,
	 * never from the previously applied one. */
	struct fw_config   base;
	struct fw_config   applied;
	__u32              have_base;
	__u32              have_applied;

	/* sampling */
	__u64 first_ts_ns;
	__u64 last_ts_ns;
	__u64 prev_gauge[CALY_G_MAX];
	__u32 have_prev_gauge;
	__u32 have_prev_stat;
	__u64 sample_count;
	__u64 last_drop_delta;
	__u64 last_dt_ns;

	__u64 rate[AT_M_MAX];
	struct at_track  track[AT_M_MAX];
	struct at_rtrack rtrack[STAT_MAX];

	/* detection / classification */
	__u32 anom_mask;
	__u32 severity;
	__u32 class_mask;
	__u32 primary_class;
	__u32 class_score[AT_C_MAX];
	__u32 abs_hi_mask;      /* which fw_config global_*_hi are crossed */

	/* mode machine */
	__u32 mode;
	__u32 target_mode;
	__u32 pinned;
	__u32 up_count;
	__u32 down_count;
	__u64 mode_since_ns;
	__u64 attack_since_ns;

	/* applied side policy, for exact restoration */
	__u32 applied_class_mask;
	__u32 applied_mode;
	__u16 amp_touched[CALY_AMP_PORTS_COUNT];
	__u32 amp_touched_n;
	__u32 icmp4_echo_saved;
	__u32 icmp6_echo_saved;
	__u32 icmp4_echo_changed;
	__u32 icmp6_echo_changed;

	/* per-source memory */
	struct at_srcmem *srcmem;
	__u32 srcmem_cap;       /* power of two */
	__u32 srcmem_used;

	/* alerting */
	int   alert_fd;
	int   alert_fd_owned;
	int   webhook_ok;
	char  webhook_client[256];
	__u64 last_hook_ns;
	__u64 last_heartbeat_ns;
	__u64 last_ban_pass_ns;
	__u64 last_ban_pass_drops;   /* cumulative CALY_G_DROPS at prev pass */

	/* counters */
	__u64 bans_issued;
	__u64 bans_suppressed;
	__u64 alerts_emitted;
	__u64 alerts_failed;
	__u64 config_pushes;
	__u64 config_rejected;
	__u64 ev_reason[STAT_MAX];   /* fed by autotune_note_event() */

	__u32 abi_warned;
	__u32 init_done;
};

/* -------------------------------------------------------------------------
 * API
 * ------------------------------------------------------------------------- */

/* CLOCK_MONOTONIC nanoseconds - the same domain as bpf_ktime_get_ns(). */
__u64 autotune_now_ns(void);

/* Fill *t with the shipped defaults. Never fails. */
void autotune_tunables_default(struct at_tunables *t);

/*
 * Initialise. `ops` must provide at least config_read and gauges_read; `cfg`
 * may be NULL, in which case the defaults are used. Reads the live config as
 * the operator baseline, allocates the per-source memory table, opens the
 * alert file and probes the webhook client.
 *
 * Returns 0, or a negative errno. On failure nothing is allocated and the
 * struct is safe to discard.
 */
int autotune_init(struct autotune *at, const struct at_ops *ops,
		  const struct at_tunables *cfg);

/* Release everything. Safe on a zeroed or already-finalised struct. */
void autotune_fini(struct autotune *at);

/*
 * Adopt a new operator baseline - call this after a SIGHUP config reload, with
 * the configuration as parsed from calyanti.conf (NOT the currently applied,
 * possibly tightened, one). Clears the pinned state if the new baseline mode
 * is an automatic one. Immediately re-derives and re-pushes the effective
 * configuration for the current mode.
 */
int autotune_set_base_config(struct autotune *at, const struct fw_config *cfg);

/*
 * One control-loop iteration: sample through the ops table, then decide and
 * act. Call it every fw_config.stats_interval_ms. `now_ns` must be
 * CLOCK_MONOTONIC (see autotune_now_ns).
 *
 * Returns 0 on a completed iteration, 1 when the tick was skipped because it
 * arrived sooner than min_tick_ns, or a negative errno when sampling failed.
 * A sampling failure is never fatal: the previous configuration keeps running
 * and the next tick tries again.
 */
int autotune_tick(struct autotune *at, __u64 now_ns);

/*
 * The same decision pass over a caller-supplied observation. autotune_tick()
 * is exactly gather + this. Exposed for the simulator and the unit tests.
 */
int autotune_step(struct autotune *at, __u64 now_ns, const struct at_sample *s);

/*
 * Operator override from the CLI. FW_MODE_LOCKDOWN and FW_MODE_MONITOR_ONLY
 * pin the machine: this module keeps observing, classifying, alerting and
 * banning, but stops driving fw_config.mode until autotune_unpin() is called
 * or a non-pinning mode is forced. Any other mode is adopted as the current
 * rung and automatic control continues from there.
 */
int autotune_force_mode(struct autotune *at, __u32 mode, __u64 now_ns);

/* Resume automatic mode control from the current rung. */
void autotune_unpin(struct autotune *at, __u64 now_ns);

/*
 * Optional: feed a dataplane event (from the ring/perf reader) so the module
 * can account per-reason event counts for the status report. Cheap, allocation
 * free, and never changes a decision on its own.
 */
void autotune_note_event(struct autotune *at, const struct event *ev);

/* Snapshot for `calyanti-cli status`. */
void autotune_status(const struct autotune *at, struct at_status *out);

/*
 * Render the current status as one line of JSON (no trailing newline).
 * Returns the number of bytes that would have been written, exactly like
 * snprintf, so a truncated result is detectable.
 */
int autotune_status_json(const struct autotune *at, char *buf, size_t len);

/* Current per-second rate for a stat_reason, 0 if out of range or unsampled. */
__u64 autotune_reason_rate(const struct autotune *at, __u32 reason);

/* Name tables. Always return a non-NULL, static, printable string. */
const char *at_metric_str(__u32 metric);
const char *at_class_str(__u32 class_index);
const char *at_event_str(__u32 kind);

#ifdef __cplusplus
}
#endif

#endif /* CALY_ANTI_AUTOTUNE_H */
