# Caly Anti — Architecture

XDP/eBPF DDoS mitigation for Linux 4.18 → 6.12+, x86_64 and aarch64.

This document is the design contract. `src/bpf/common.h` is the *executable*
version of it: where the two disagree, the header wins and this file is wrong.

---

## 1. Design principles

**Cheapest check first, single pass, no unbounded loops.** A packet is parsed
once. Every subsequent decision reads from that one parse. There is no second
pass, no re-walk of extension headers, and no loop whose bound is not a
compile-time constant.

**Never wedge the operator.** The management port list (which always contains
TCP/22, enforced by the loader) and the allowlist are checked *before every
drop rule*, in every mode, including `UNDER_ATTACK` and `LOCKDOWN`. A machine
under attack is exactly when you most need to be able to log in. Every code
path in the dataplane is auditable against this: if a drop can be reached
without first testing the allowlist and the mgmt ports, it is a bug.

**Fail open, never closed.** A missing config map, a NULL scratch lookup, a
failed tail call, a full LRU — every one of these results in `XDP_PASS` and a
counter, never a drop. A firewall that black-holes traffic because it failed
internally is worse than no firewall at all, because the failure is invisible.

**`XDP_ABORTED` is never returned.** It is an error tracepoint that fires
`xdp_exception`, not a drop verdict. Production paths return only `XDP_PASS`,
`XDP_DROP` or `XDP_TX`.

**Statistics are exact; policy state is approximate.** Counters live in
`PERCPU` maps and are therefore race-free. Token buckets and conntrack live in
shared LRU hashes and are updated non-atomically on purpose — see §5.

---

## 2. Degradation ladder

The installer probes downward and uses the best rung the system can actually
provide. Each rung is a complete, working dataplane; there is no "partially
installed" state.

```
   ┌─────────────────────────────────────────────────────────────────────┐
 1 │ XDP NATIVE      driver-level, before skb allocation                 │
   │                 ~20-40 Mpps/core drop rate                          │
   │ needs: BTF, XDP-capable driver, kernel >= 4.18                      │
   └───────────────────────────────┬─────────────────────────────────────┘
                                   │ driver lacks ndo_bpf / XDP_SETUP_PROG
   ┌───────────────────────────────▼─────────────────────────────────────┐
 2 │ XDP GENERIC     skb-mode, after allocation                          │
   │                 ~2-5 Mpps, roughly 5x slower than native            │
   │ needs: BTF, kernel >= 4.18. Works on virtio without multiqueue.     │
   └───────────────────────────────┬─────────────────────────────────────┘
                                   │ XDP unavailable (OpenVZ, some LXC)
   ┌───────────────────────────────▼─────────────────────────────────────┐
 3 │ tc / clsact eBPF    ingress hook, full skb available                │
   │ needs: BTF, kernel >= 4.18, CONFIG_NET_CLS_BPF                      │
   │ same policy engine, ~1-2 Mpps                                       │
   └───────────────────────────────┬─────────────────────────────────────┘
                                   │ no BTF, or eBPF unavailable entirely
   ┌───────────────────────────────▼─────────────────────────────────────┐
 4 │ nftables        sets + flowtables + limit/meter                     │
   │ needs: nft binary, kernel >= 3.13                                   │
   │ static rules only: no per-source token buckets, no scan detection   │
   └───────────────────────────────┬─────────────────────────────────────┘
                                   │ no nftables (very old / minimal distro)
   ┌───────────────────────────────▼─────────────────────────────────────┐
 5 │ iptables + ipset    hashlimit, recent, ipset timeouts               │
   │ last resort; correctness preserved, throughput is not               │
   └─────────────────────────────────────────────────────────────────────┘
```

### Detection inputs

| Input | Source | Effect |
|---|---|---|
| Kernel version | `uname -r`, `LINUX_VERSION_CODE` | gates 5.15+ SYN proxy, 5.8+ ringbuf |
| BTF present | `/sys/kernel/btf/vmlinux` | **absent ⇒ drop to rung 4.** CO-RE cannot work without it |
| Driver XDP support | `ethtool -i`, probe `XDP_FLAGS_DRV_MODE` attach | native vs generic |
| Virtualisation | `systemd-detect-virt`, `/proc/1/environ`, `/proc/user_beancounters` | OpenVZ/LXC ⇒ XDP unavailable, drop to rung 3 |
| virtio multiqueue | `ethtool -l` channel count vs `nproc` | insufficient queues ⇒ generic, not native |
| `CONFIG_NET_CLS_BPF` | `/proc/config.gz`, `/boot/config-$(uname -r)` | gates rung 3 |
| Helper availability | `libbpf_probe_bpf_helper()` | gates SYN proxy program autoload |
| Map type availability | `libbpf_probe_bpf_map_type()` | gates ringbuf, falls back to perf array |

`bpftool` is *not* required at runtime. `vmlinux.h` is generated at build time
where BTF is available and shipped in the package; the runtime check is only
whether the *running* kernel exposes BTF for CO-RE relocation.

**BTF absence is not a failure.** It is a documented fallback to rung 4. The
installer must never abort because a kernel lacks BTF.

---

## 3. Packet path

Every step is bounds-checked against `data_end` before any read. Length fields
in the packet are never trusted — they are validated *against* the actual
frame extent, never used to compute a read offset that has not been checked.

```
                                 ┌──────────────┐
   NIC ─── XDP hook ────────────▶│  caly_xdp_   │
                                 │    main      │
                                 └──────┬───────┘
                                        │
   ╔════════════════════════════════════▼════════════════════════════════════╗
   ║ 0. PRELUDE                                                              ║
   ║    cfg = caly_config[0]         ── NULL ⇒ PASS  (STAT_CONFIG_MISSING)   ║
   ║    !CALY_F_ENABLED              ── ⇒ PASS       (STAT_PASS_DISABLED)    ║
   ║    iface = caly_iface[ifindex]  ── zone LAN/DMZ ⇒ PASS                  ║
   ║    now   = bpf_ktime_get_ns()                                           ║
   ╚════════════════════════════════════┬════════════════════════════════════╝
                                        │
   ╔════════════════════════════════════▼════════════════════════════════════╗
   ║ 1. PARSE  (single pass, all bounds explicit, all loops const-bounded)   ║
   ║                                                                         ║
   ║    Ethernet ──▶ VLAN 802.1Q/802.1ad ──▶ IPv4 ────▶ ext hdrs ──▶ L4      ║
   ║                 (max 2, QinQ)          or IPv6     (max 8)              ║
   ║                                          │                              ║
   ║                                          ├─▶ IPIP / IP6IP6 / GRE        ║
   ║                                          │   (max 1 level, then         ║
   ║                                          │    re-parse inner as L3)     ║
   ║                                          ▼                              ║
   ║                                    TCP / UDP / ICMP / ICMPv6            ║
   ║                                                                         ║
   ║    result ⇒ struct pkt_ctx in caly_scratch (per-CPU, 512B stack limit)  ║
   ╚════════════════════════════════════┬════════════════════════════════════╝
                                        │
   ╔════════════════════════════════════▼════════════════════════════════════╗
   ║ 2. ANOMALY  — malformed or physically impossible. Highest confidence,   ║
   ║              cheapest, evaluated first, no map lookups at all.          ║
   ║                                                                         ║
   ║   truncated hdr · ihl<5 · tot_len<ihl*4 · doff<5 · LAND (src==dst)      ║
   ║   bogon/martian src on WAN · RFC1918 src (if wan_drop_private)          ║
   ║   IPv6 src ::, ::1, multicast · RH0 · TTL/hop-limit 0                   ║
   ║   TCP null/FIN-only/SYN+FIN/SYN+RST/FIN+RST/xmas/all-flags              ║
   ║   tiny fragment · frag_off==1 · fragmented ICMP · ICMP oversize         ║
   ║   ICMPv6 type policy ── types 2,133,134,135,136 CAN NEVER BE DROPPED    ║
   ╚════════════════════════════════════┬════════════════════════════════════╝
                                        │  survives
   ╔════════════════════════════════════▼════════════════════════════════════╗
   ║ 3. ALLOWLIST     caly_allow4/6  (LPM)                                   ║
   ║                                                                         ║
   ║    HIT ═══════════════════════════════════════════════▶ XDP_PASS        ║
   ║                                              (STAT_PASS_ALLOWLIST)      ║
   ║    THE ESCAPE HATCH. Checked before every drop rule below.              ║
   ╚════════════════════════════════════┬════════════════════════════════════╝
                                        │
   ╔════════════════════════════════════▼════════════════════════════════════╗
   ║ 3b. MGMT PORTS   cfg.mgmt_tcp_ports[] / mgmt_udp_ports[]                ║
   ║     dport is a mgmt port ══════════════════════════════▶ XDP_PASS       ║
   ║     TCP/22 is ALWAYS in this list. Enforced by the loader.              ║
   ╚════════════════════════════════════┬════════════════════════════════════╝
                                        │
   ╔════════════════════════════════════▼════════════════════════════════════╗
   ║ 4. REPUTATION                                                           ║
   ║    caly_block4/6 (LPM, static)  ────────────────────▶ XDP_DROP          ║
   ║    caly_ban4/6   (LRU, dynamic) ── expiry_ns > now ─▶ XDP_DROP          ║
   ║                                └─ expired ⇒ treat as miss, GC later     ║
   ╚════════════════════════════════════┬════════════════════════════════════╝
                                        │
   ╔════════════════════════════════════▼════════════════════════════════════╗
   ║ 5. CONNTRACK-LITE       caly_conn (LRU, 5-tuple)                        ║
   ║                                                                         ║
   ║    ESTABLISHED hit ════════════════════════════════════▶ XDP_PASS       ║
   ║                        (STAT_PASS_CONNTRACK) — short-circuits ALL       ║
   ║                        of steps 6-9. This is what makes inbound         ║
   ║                        default-deny survivable.                         ║
   ╚════════════════════════════════════┬════════════════════════════════════╝
                                        │ miss / not established
   ╔════════════════════════════════════▼════════════════════════════════════╗
   ║ 6. REFLECTION / AMPLIFICATION     (UDP only)                            ║
   ║    caly_port_udp[sport].flags & CALY_PORT_F_AMPLIFIER                   ║
   ║      ⇒ XDP_DROP + ban(ban_ttl_amp)          (STAT_DROP_AMP_SRCPORT)     ║
   ║                                                                         ║
   ║    Exempt: conntrack hit (step 5 already passed us — we asked for it)   ║
   ║            or the operator cleared the flag for that service.           ║
   ╚════════════════════════════════════┬════════════════════════════════════╝
                                        │
   ╔════════════════════════════════════▼════════════════════════════════════╗
   ║ 7. PORT POLICY    caly_port_tcp[dport] / caly_port_udp[dport]           ║
   ║       CLOSED    ⇒ XDP_DROP                                              ║
   ║       OPEN      ⇒ continue                                              ║
   ║       RATELIMIT ⇒ caly_port_tb[idx] token bucket ⇒ drop or continue     ║
   ║       no rule + CALY_F_DEFAULT_DENY ⇒ XDP_DROP                          ║
   ╚════════════════════════════════════┬════════════════════════════════════╝
                                        │
   ╔════════════════════════════════════▼════════════════════════════════════╗
   ║ 8. PER-SOURCE TOKEN BUCKETS   caly_rate4/6 → rate_state.tb[6]           ║
   ║    pps · bps · syn · udp · icmp · newconn                               ║
   ║    ns refill, integer only, remainder carried in last_refill_ns         ║
   ║                                                                         ║
   ║    exceeded ⇒ strike++ ; strikes >= strike_limit within strike_window   ║
   ║              ⇒ insert ban, TTL = base, escalating base*num/den → max    ║
   ╚════════════════════════════════════┬════════════════════════════════════╝
                                        │
   ╔════════════════════════════════════▼════════════════════════════════════╗
   ║ 9. PORT-SCAN DETECTION    caly_scan4/6 → 512-bit Bloom over dports      ║
   ║    distinct > scan_port_threshold within scan_window                    ║
   ║      ⇒ ban(ban_ttl_scan)                     (STAT_DROP_PORTSCAN)       ║
   ╚════════════════════════════════════┬════════════════════════════════════╝
                                        │
   ╔════════════════════════════════════▼════════════════════════════════════╗
   ║ 10. SYN HANDLING                                                        ║
   ║                                                                         ║
   ║   TCP SYN, cfg.mode == UNDER_ATTACK, CALY_F_SYNPROXY,                   ║
   ║   CALY_F_CAP_SYNPROXY, port flagged CALY_PORT_F_SYNPROXY                ║
   ║        │                                                                ║
   ║        └──▶ bpf_tail_call(caly_progs, CALY_PROG_IDX_SYNPROXY)           ║
   ║                    │                                                    ║
   ║                    ├─ tail call succeeds ──▶ see §4                     ║
   ║                    └─ slot empty (kernel < 5.15) ──▶ falls through      ║
   ║                       to per-source rate_syn bucket + syn_fallback_pps  ║
   ╚════════════════════════════════════┬════════════════════════════════════╝
                                        │
   ╔════════════════════════════════════▼════════════════════════════════════╗
   ║ 11. ACCOUNT + VERDICT                                                   ║
   ║   caly_stats[reason]++     (PERCPU, exact)                              ║
   ║   caly_stats_b[reason] += len                                           ║
   ║   caly_global[gauge] += ...                                             ║
   ║   caly_top4/6[src] update  (if CALY_F_SRC_STATS)                        ║
   ║   sampled event → ringbuf (5.8+) or perf array (fallback)               ║
   ║                                                                         ║
   ║   MONITOR_ONLY / iface monitor ⇒ verdict rewritten PASS,                ║
   ║                                  STAT_MONITOR_WOULD_DROP charged        ║
   ║                                                                         ║
   ║        ══▶ XDP_PASS   ║   XDP_DROP   ║   XDP_TX      (never ABORTED)    ║
   ╚═════════════════════════════════════════════════════════════════════════╝
```

### Conntrack entry creation

XDP sees ingress only, which constrains how state is learned:

- **Inbound SYN** permitted by policy → entry in `CALY_CT_SYN_RECV`.
- **Inbound ACK** matching a `SYN_RECV` entry → promoted to
  `CALY_CT_ESTABLISHED`.
- **Outbound flows** are learned by the optional `caly_tc_egress` clsact
  program. It inserts the tuple **swapped** — `conn_key` is always stored in
  *ingress orientation* (`saddr` = remote peer, `daddr` = us) so the reply
  packet hits on its first lookup with no normalisation.

Without the egress hook, outbound-initiated UDP (DNS, NTP, QUIC) has no
inbound handshake to learn from and its replies fall through to the port
policy. The installer attaches the egress hook wherever clsact exists, so this
is a fallback concern only on very old kernels.

---

## 4. SYN proxy

### The constraint that defines the design

The SYN proxy uses **only** these helpers:

```
bpf_tcp_raw_gen_syncookie_ipv4()     bpf_tcp_raw_gen_syncookie_ipv6()
bpf_tcp_raw_check_syncookie_ipv4()   bpf_tcp_raw_check_syncookie_ipv6()
```

They are **kernel 5.15 or newer**, and they use the kernel's *own* SYN cookie
secret.

That last point is the whole design. A hand-rolled cookie hash cannot be
validated by the TCP stack. The client would complete the handshake, the ACK
would arrive, the kernel would reject the cookie it never issued, and the
connection would die silently — a SYN proxy that makes the service
*permanently unreachable* rather than merely undefended. **Do not implement a
custom cookie under any circumstances.** If the helpers are absent, rate limit
instead.

### Flow

```
   client                        Caly Anti (XDP)                    kernel
     │                                 │                              │
     │────── SYN ─────────────────────▶│                              │
     │                                 │ gen_syncookie() → cookie     │
     │                                 │ rewrite IN PLACE:            │
     │                                 │   swap MAC src/dst           │
     │                                 │   swap IP  src/dst           │
     │                                 │   swap TCP sport/dport       │
     │                                 │   seq     = cookie           │
     │                                 │   ack_seq = client_seq + 1   │
     │                                 │   flags   = SYN|ACK          │
     │                                 │   MSS option from helper     │
     │                                 │   recompute IP + TCP csum    │
     │◀───── SYN-ACK ──────── XDP_TX ──│         (kernel never saw it)│
     │                                 │                              │
     │────── ACK (bare) ──────────────▶│                              │
     │                                 │ check_syncookie()            │
     │                                 │   valid   → XDP_PASS ────────▶ socket
     │                                 │   invalid → XDP_DROP         │  materialised
     │                                 │                              │  by the stack
```

No half-open socket is ever created for a spoofed SYN. The cost of a spoofed
SYN flood becomes one `XDP_TX` per packet and **zero kernel memory**.

### Mandatory sysctl

```
net.ipv4.tcp_syncookies = 2
```

**2 (unconditional), not 1.** At `1` the kernel only issues and accepts
cookies once the accept queue actually overflows — so the cookies our XDP
program already handed out are not recognised when the ACK comes back. The
installer writes this to `/etc/sysctl.d/98-calyanti.conf`.

### Loading and the tail call

The SYN proxy lives in a **separate BPF program**, reached by
`bpf_tail_call()` through `caly_progs[CALY_PROG_IDX_SYNPROXY]`:

1. Loader calls `libbpf_probe_bpf_helper(BPF_PROG_TYPE_XDP,
   BPF_FUNC_tcp_raw_gen_syncookie_ipv4, NULL)`.
2. If unsupported → `bpf_program__set_autoload(prog, false)`. **The verifier
   never sees the program**, so it never sees a helper the kernel does not
   have. This is why it must be a separate program: an inline call would fail
   verification for the entire object on every pre-5.15 kernel.
3. The prog-array slot stays empty. `bpf_tail_call()` on an empty slot simply
   returns and execution continues in the caller.
4. Fallback on < 5.15: per-source `rate_syn` token bucket +
   `cfg.syn_fallback_pps` global cap + `net.ipv4.tcp_syncookies = 1`.

The main program also needs `CALY_F_CAP_SYNPROXY` in `cfg.flags` (set by the
loader after probing) before it attempts the tail call, so the fallback path
is chosen without paying for a failed tail call per packet.

`XDP_TX` requires the driver to support transmit on the RX queue. The loader
probes this and sets `CALY_F_CAP_XDP_TX`; in generic/skb mode `XDP_TX` works
but is slow, so the SYN proxy is disabled by default on rung 2 and the rate
limit fallback is used instead.

---

## 5. Map layout

All maps are pinned under `/sys/fs/bpf/calyanti/` so the CLI can attach
without being the loader and state survives a daemon restart.

**Kernel object names are limited to 15 characters + NUL.** Every name below
respects that; do not lengthen them.

| # | Name | Type | Key | Value | Max entries | Flags / notes |
|--:|------|------|-----|-------|-------------|---------------|
| 1 | `caly_config` | `ARRAY` | `__u32` (always 0) | `struct fw_config` (720 B) | 1 | Runtime config. **Not `.rodata`** — see §6 |
| 2 | `caly_stats` | `PERCPU_ARRAY` | `__u32` = `enum stat_reason` | `__u64` | `STAT_MAX` (109) | Packet counters, exact |
| 3 | `caly_stats_b` | `PERCPU_ARRAY` | `__u32` = `enum stat_reason` | `__u64` | `STAT_MAX` (109) | Byte counters, exact |
| 4 | `caly_global` | `PERCPU_ARRAY` | `__u32` = `enum caly_gauge` | `__u64` | `CALY_G_MAX` (11) | Gauges driving mode escalation |
| 5 | `caly_allow4` | `LPM_TRIE` | `struct lpm_key_v4` (8 B) | `struct rule_meta` (24 B) | `cfg.max_allow_entries` (65536) | **`BPF_F_NO_PREALLOC`** |
| 6 | `caly_allow6` | `LPM_TRIE` | `struct lpm_key_v6` (20 B) | `struct rule_meta` | 65536 | **`BPF_F_NO_PREALLOC`** |
| 7 | `caly_block4` | `LPM_TRIE` | `struct lpm_key_v4` | `struct rule_meta` | `cfg.max_block_entries` (262144) | **`BPF_F_NO_PREALLOC`** |
| 8 | `caly_block6` | `LPM_TRIE` | `struct lpm_key_v6` | `struct rule_meta` | 262144 | **`BPF_F_NO_PREALLOC`** |
| 9 | `caly_local4` | `LPM_TRIE` | `struct lpm_key_v4` | `struct rule_meta` | 4096 | Our own prefixes; anti-spoof + direction |
| 10 | `caly_local6` | `LPM_TRIE` | `struct lpm_key_v6` | `struct rule_meta` | 4096 | **`BPF_F_NO_PREALLOC`** |
| 11 | `caly_ban4` | `LRU_HASH` | `__u32` (v4, network order) | `struct ban_entry` (64 B) | `cfg.max_ban_entries` (262144) | LRU: full ⇒ evict, never fail |
| 12 | `caly_ban6` | `LRU_HASH` | `struct in6_key` (16 B) | `struct ban_entry` | 262144 | |
| 13 | `caly_rate4` | `LRU_HASH` | `__u32` | `struct rate_state` (128 B) | `cfg.max_rate_entries` (524288) | Shared, not percpu — see below |
| 14 | `caly_rate6` | `LRU_HASH` | `struct in6_key` | `struct rate_state` | 524288 | |
| 15 | `caly_conn` | `LRU_HASH` | `struct conn_key` (40 B) | `struct conn_state` (64 B) | `cfg.max_conn_entries` (262144) | **memset the key** — see below |
| 16 | `caly_scan4` | `LRU_HASH` | `__u32` | `struct scan_state` (96 B) | `cfg.max_scan_entries` (131072) | 512-bit Bloom over dports |
| 17 | `caly_scan6` | `LRU_HASH` | `struct in6_key` | `struct scan_state` | 131072 | |
| 18 | `caly_top4` | `LRU_HASH` | `__u32` | `struct src_stats` (56 B) | `cfg.max_srcstat_entries` (131072) | Reporting only |
| 19 | `caly_top6` | `LRU_HASH` | `struct in6_key` | `struct src_stats` | 131072 | Reporting only |
| 20 | `caly_port_tcp` | `ARRAY` | `__u32` port, **host order** | `struct port_rule` (24 B) | 65536 | Dest-port policy |
| 21 | `caly_port_udp` | `ARRAY` | `__u32` port, **host order** | `struct port_rule` | 65536 | Dest-port policy **and** amplifier source-port flag |
| 22 | `caly_port_tb` | `ARRAY` | `__u32` = `CALY_PORT_TB_IDX()` | `struct token_bucket` (16 B) | 131072 | TCP 0–65535, UDP 65536–131071 |
| 23 | `caly_icmp4_pol` | `ARRAY` | `__u32` ICMP type | `__u32` = `enum caly_icmp_policy` | 256 | Type 3 can never be `DROP` |
| 24 | `caly_icmp6_pol` | `ARRAY` | `__u32` ICMPv6 type | `__u32` | 256 | Types 2,133,134,135,136 can never be `DROP` |
| 25 | `caly_iface` | `HASH` | `__u32` ifindex | `struct iface_config` (32 B) | `cfg.max_iface_entries` (64) | Miss ⇒ `cfg.default_zone` |
| 26 | `caly_events` | `PERF_EVENT_ARRAY` | `__u32` cpu | `__u32` | 0 (libbpf sets `nr_cpus`) | **Always present.** Works on every supported kernel |
| 27 | `caly_events_rb` | `RINGBUF` | — | — | 4194304 (4 MiB) | 5.8+. `set_autocreate(false)` below that |
| 28 | `caly_progs` | `PROG_ARRAY` | `__u32` = `enum caly_prog_idx` | prog fd | `CALY_PROG_IDX_MAX` (4) | Slot 0 SYN proxy, slot 1 optional IPv6 split |
| 29 | `caly_scratch` | `PERCPU_ARRAY` | `__u32` (always 0) | `struct caly_scratch` (416 B) | 1 | Escapes the 512-byte BPF stack limit |

### Why `caly_port_udp` serves two purposes

The **destination** port drives `port_rule.mode`. The **source** port of a UDP
packet is looked up in the *same* array to test `CALY_PORT_F_AMPLIFIER`. The
two uses read different fields and can never collide.

This is what lets you run a real DNS server behind the reflection filter:
inbound queries arrive at `dport 53` with `mode = OPEN`, while spoofed
reflection traffic arrives with `sport 53` and is dropped by the amplifier
flag. Clearing `CALY_PORT_F_AMPLIFIER` on a port is how an operator allowlists
a reflective service they legitimately consume.

### Why rate limiters are *not* per-CPU

`caly_stats`, `caly_stats_b` and `caly_global` are `PERCPU` because they are
counters and must be exact.

`caly_rate4/6` and `caly_port_tb` are **deliberately shared**. A per-CPU token
bucket would multiply the effective limit by the CPU count, and RSS spreads a
single attacker across every queue — a 64-core box would enforce 64× the
configured rate. Concurrent read-modify-write of a bucket is a benign race
that can, at worst, let a couple of extra packets through. `bpf_spin_lock` is
not used: it is 5.1+ and the RHEL 8 backport situation is not worth the risk
for a rate limiter that tolerates approximation.

### `conn_key` must be memset

BPF hash lookups compare the **raw key bytes, including padding**.
`struct conn_key` has an explicit `pad[2]`. Every consumer must do:

```c
struct conn_key k;
__builtin_memset(&k, 0, sizeof(k));
```

Skipping it leaves uninitialised stack in `pad[]`, turns every lookup into a
miss, and silently disables the conntrack fast path — with no error anywhere.
IPv4 uses `saddr[0]`/`daddr[0]` only; words 1–3 must be zero for the same
reason.

### Memory budget at defaults

Roughly 220 MB of locked kernel memory with the shipped defaults, dominated by
`caly_rate4/6` (524288 × ~160 B) and `caly_conn` (262144 × ~120 B). The
`max_*_entries` knobs in `calyanti.conf` are read *before* map creation. On a
small VPS, set `max_rate_entries = 65536` and `max_conn_entries = 65536` for
roughly 30 MB.

---

## 6. Kernel compatibility

These constraints are what make the object load on RHEL 8 (4.18) and
Ubuntu 20.04 as well as on 6.12.

| Rule | Why |
|---|---|
| **No `bpf_loop()`** | 5.17+. All loops are `#pragma unroll` with compile-time constant bounds |
| **No `bpf_map_lookup_percpu_elem()`** | 5.20+. Userspace sums per-CPU values via the map lookup syscall instead |
| **No `BPF_MAP_TYPE_RINGBUF` in the compat path** | 5.8+. Probed and preferred when present; `PERF_EVENT_ARRAY` is the always-present fallback |
| **No `bpf_xdp_adjust_tail()` growth** | Tail *growth* is 5.8+. The SYN proxy rewrites in place and never grows the frame |
| **Config in `BPF_MAP_TYPE_ARRAY`, not `.rodata`** | Global-variable relocation is unreliable on 4.18-era backports, and `.rodata` cannot be updated after load anyway — which would make every knob load-time-only |
| **LPM tries need `BPF_F_NO_PREALLOC`** | The kernel returns `-EINVAL` without it |
| **All loops compile-time bounded, `#pragma unroll`** | Older verifiers have no bounded-loop support at all |
| **CO-RE via `vmlinux.h`** | Generated from `/sys/kernel/btf/vmlinux`. Absent ⇒ installer falls back to nftables (rung 4), never fails |
| **License string `"Dual BSD/GPL"`** | GPL-only helpers are required; a non-GPL string fails the load |

`#pragma unroll` is a clang extension. `common.h` spells it through
`CALY_UNROLL` (a `_Pragma` guarded on `__clang__`) so the same header compiles
under GCC for the userspace side without tripping `-Werror=unknown-pragmas`.

### ABI safety

`struct fw_config` is copied **verbatim** between userspace and a BPF array
map. A single byte of layout skew silently corrupts every threshold. The
layout is therefore mechanical:

- all `__u64` fields first, in one block (41 of them, 328 B);
- then `__u32` fields, in an **even** count (34, 136 B) so what follows stays
  8-byte aligned;
- then two `__u16[16]` port arrays (32 B each — multiples of 8);
- then `__u64 reserved[24]` closing on an 8-byte boundary.

Total **720 bytes**, no implicit padding anywhere, no bitfields, no enums as
members, no `__u8` scalars. `common.h` proves all of this with compile-time
assertions on `sizeof` and `__builtin_offsetof` that fire on *both* sides of
the boundary.

New knobs consume `reserved[]`. They never grow the struct, never reorder it,
and never get inserted in the middle. `abi_version` is written by the loader
and checked before attach.

---

## 7. Threat model

### In scope

| Threat | Control |
|---|---|
| Volumetric UDP flood | per-source `bps`/`udp` buckets, global gauge → `UNDER_ATTACK` |
| Spoofed SYN flood | SYN proxy (§4); pre-5.15: `syn` bucket + `syn_fallback_pps` |
| Reflection / amplification (DNS, NTP, memcached, SSDP, CLDAP, …) | amplifier source-port filter, conntrack-exempted (§3 step 6) |
| ACK / RST / fragment floods | per-source `pps` bucket, fragment sanity rules |
| Slow port scanning / reconnaissance | Bloom-filter distinct-dport detector → ban |
| Malformed-packet DoS (LAND, ping of death, tiny frags, xmas) | anomaly stage, no map lookups, cheapest tier |
| Botnet HTTP/S connection floods | `newconn` bucket + per-port rate limits + escalating bans |
| Source-spoofed traffic claiming our own prefixes | `caly_local4/6` → `STAT_DROP_SRC_SELF` |
| Martian/bogon sources | bogon filter, WAN-zone only |
| IPv6 routing-header amplification | RH0 drop (RFC 5095) |
| Evasion via VLAN/QinQ or tunnel wrapping | 2 VLAN tags + 1 tunnel level parsed, policy applied to the inner header |

### Out of scope — and why

- **Link saturation upstream of the NIC.** If the flood fills your transit,
  nothing running on the host can help. XDP protects the *host*, not the
  *pipe*. You need upstream scrubbing or BGP flowspec.
- **Application-layer attacks** (Slowloris, HTTP request floods with valid
  handshakes, expensive queries). Every packet is legitimate at L3/L4. Use a
  WAF or application rate limiting. The `newconn` bucket and per-port limits
  blunt the crudest versions only.
- **Encrypted-payload inspection.** XDP sees bytes, not TLS sessions.
- **Stateful deep inspection.** `conn_key` is a 5-tuple with a small state
  machine, not a reassembling, sequence-validating conntrack. It cannot detect
  out-of-window RSTs or overlapping-segment attacks. Keep the kernel's real
  conntrack for that.
- **Attacks from allowlisted sources.** By construction. The allowlist is an
  unconditional bypass; keep it short.

### Assumptions

- The operator has out-of-band access (console, IPMI, cloud serial) — although
  every effort is made to ensure it is never needed.
- The host is not already compromised. Anything with `CAP_BPF`/`CAP_SYS_ADMIN`
  can unload this.
- Clock is monotonic. All timestamps come from `bpf_ktime_get_ns()`;
  `caly_tb_consume()` explicitly handles a backwards clock and recycled LRU
  entries by reseeding the bucket rather than trusting the delta.

### Failure modes and their blast radius

| Failure | Behaviour | Blast radius |
|---|---|---|
| `caly_config` empty / unreadable | `XDP_PASS`, `STAT_CONFIG_MISSING` | Unprotected, loudly counted |
| `caly_scratch` lookup NULL | `XDP_PASS`, `STAT_SCRATCH_FAIL` | Unprotected for that packet |
| Tail call to an empty slot | Falls through to the caller's fallback | Weaker SYN defence only |
| LRU map full | Coldest entry evicted | Oldest state lost, never a drop |
| Ban map full | `STAT_BAN_FULL`, packet still evaluated | Ban not recorded; rate limits still apply |
| Event ring full | `STAT_EVENT_LOST` | Telemetry gap only; filtering unaffected |
| Misconfigured bucket (rate or burst 0) | Bucket disabled, always conforms | Limiter inert — never a black hole |
| BTF absent at install | Falls back to nftables (rung 4) | Reduced throughput, policy preserved |

Every one of these fails **open**. There is no configuration and no internal
error in which Caly Anti drops management traffic.
