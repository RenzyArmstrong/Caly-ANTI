# Caly Anti

XDP/eBPF DDoS mitigation for Linux 4.18 through 6.12+, on x86_64 and aarch64.

Caly Anti filters hostile traffic in the NIC driver's receive path, before the
kernel allocates an `sk_buff`, before netfilter, before conntrack, before the
socket layer. A dropped packet costs tens of nanoseconds instead of the
microseconds an iptables drop costs, which is the difference between absorbing
a flood and falling over.

It is a **host** defence. It is not, and cannot be, a substitute for upstream
scrubbing. See [Limitations](#limitations) — that section is not boilerplate,
read it before you deploy.

---

## Table of contents

- [What it does](#what-it-does)
- [Threat model](#threat-model)
- [The degradation ladder](#the-degradation-ladder)
- [Quickstart](#quickstart)
- [Emergency: how to turn it all off](#emergency-how-to-turn-it-all-off)
- [Feature table](#feature-table)
- [Operating modes](#operating-modes)
- [Command surface](#command-surface)
- [Repository layout](#repository-layout)
- [Safety invariants](#safety-invariants)
- [Limitations](#limitations)
- [Documentation index](#documentation-index)
- [Licence](#licence)

---

## What it does

A single XDP program parses each frame once — Ethernet, up to two VLAN tags
(802.1Q and 802.1ad QinQ), IPv4 or IPv6 with up to eight extension headers,
optionally one level of IPIP/IP6IP6/GRE encapsulation, then TCP, UDP, ICMP or
ICMPv6 — and applies, in this order:

1. **Anomaly rules.** Malformed or physically impossible packets: truncated
   headers, `ihl < 5`, `tot_len < ihl*4`, `doff < 5`, LAND (source equals
   destination), bogon and martian sources on WAN interfaces, IPv6 `::`, `::1`
   and multicast used as a source, RH0, illegal TCP flag combinations, tiny
   fragments, `frag_off == 1`, fragmented ICMP, oversize ICMP. No map lookups,
   cheapest tier, highest confidence.
2. **Allowlist** (LPM trie). A hit is an unconditional `XDP_PASS`. This is the
   operator escape hatch and it is checked before every drop rule below.
3. **Management ports.** TCP/22 is forced into the list by the loader in every
   mode. See [Safety invariants](#safety-invariants).
4. **Reputation.** Static blocklist (LPM) and dynamic bans (LRU hash with
   expiry timestamps and escalating TTLs).
5. **Conntrack-lite.** An LRU hash on the 5-tuple. An established flow
   short-circuits straight to `XDP_PASS`. This is what makes inbound
   default-deny survivable.
6. **Reflection/amplification filter.** UDP whose *source* port is a known
   amplifier (DNS, NTP, memcached, SSDP, CLDAP, chargen, and 15 more) is
   dropped unless conntrack says we asked for it.
7. **Port policy.** Two 65536-entry arrays, one per protocol: closed, open, or
   rate-limited with a per-port token bucket.
8. **Per-source token buckets.** Six of them — total pps, total bps, SYN pps,
   UDP pps, ICMP pps, new-connection pps — with nanosecond refill and integer
   arithmetic. Overrunning a bucket costs a strike; enough strikes inside the
   window installs a ban.
9. **Port-scan detection.** A 512-bit Bloom filter over destination ports per
   source, sliding window.
10. **SYN handling.** Either the kernel-cookie SYN proxy (5.15+) or the
    per-source SYN bucket plus a global cap.

Statistics for all 109 distinct decisions land in per-CPU arrays, and a sampled
event stream goes to userspace over a ring buffer (5.8+) or a perf event array
(everywhere else).

---

## Threat model

### In scope

| Threat | Control |
|---|---|
| Volumetric UDP flood | per-source `bps` and `udp` buckets, global gauge escalation to `under-attack` |
| Spoofed SYN flood | SYN proxy using the kernel's own cookie secret; pre-5.15, the `syn` bucket plus `syn_fallback_pps` |
| Reflection/amplification (DNS, NTP, memcached, SSDP, CLDAP, chargen, ...) | amplifier source-port filter, exempted by conntrack |
| ACK, RST and fragment floods | per-source `pps` bucket plus fragment sanity rules |
| Port scanning and reconnaissance | Bloom-filter distinct-destination-port detector, ban on breach |
| Malformed-packet DoS (LAND, ping of death, tiny fragments, xmas scan) | anomaly stage, no map lookups |
| Botnet connection floods | `newconn` bucket, per-port rate limits, escalating bans |
| Source spoofing using our own prefixes | `caly_local4/6`, charged as `drop_src_self` |
| Martian and bogon sources | bogon filter, WAN zone only |
| IPv6 routing-header amplification | RH0 drop (RFC 5095) |
| Evasion by VLAN/QinQ or tunnel wrapping | two VLAN tags plus one tunnel level parsed; policy applies to the inner header |

### Explicitly out of scope

- **Link saturation.** If the flood fills your transit or your provider's edge,
  nothing running on the host matters. See [Limitations](#limitations).
- **Application-layer attacks.** Slowloris, HTTP request floods over completed
  TLS handshakes, expensive database queries. Every packet is legitimate at
  L3/L4. Use a WAF and application rate limiting.
- **Encrypted payload inspection.** XDP sees bytes on the wire, not TLS
  sessions. There is no decryption and there will not be.
- **Stateful deep inspection.** `conn_key` is a 5-tuple with a six-state
  machine, not a reassembling, sequence-validating conntrack. It cannot detect
  out-of-window RSTs or overlapping-segment attacks. Keep the kernel's real
  conntrack if you need that.
- **Attacks from allowlisted sources.** By construction. The allowlist is an
  unconditional bypass. Keep it short.

### Assumptions

- You have out-of-band access — serial console, IPMI, or a cloud serial
  console. Every effort is made to ensure you never need it. Have it anyway.
- The host is not already compromised. Anything holding `CAP_BPF` or
  `CAP_SYS_ADMIN` can unload this in one syscall.
- The clock is monotonic. All timestamps come from `bpf_ktime_get_ns()`, and
  the token bucket explicitly handles a backwards clock and recycled LRU
  entries by reseeding rather than trusting the delta.

---

## The degradation ladder

The installer probes downward and uses the best rung the system can actually
provide. Every rung is a complete, working dataplane. There is no
"partially installed" state.

| Rung | Dataplane | Requires | Throughput (order of magnitude) | What you lose |
|---:|---|---|---|---|
| 1 | XDP native (driver) | BTF, XDP-capable driver, 4.18+ | 20-40 Mpps/core drop | nothing |
| 2 | XDP generic (skb) | BTF, 4.18+ | 2-5 Mpps | ~5x throughput; `XDP_TX` is slow, so the SYN proxy defaults off |
| 3 | tc/clsact eBPF ingress | BTF, 4.18+, `CONFIG_NET_CLS_BPF` | 1-2 Mpps | runs after skb allocation, so a flood still costs memory |
| 4 | nftables | `nft`, 3.13+ | ~0.3-1 Mpps | per-source token buckets, scan detection, SYN proxy, conntrack-lite |
| 5 | iptables + ipset | `iptables`, `ipset` | ~0.1-0.3 Mpps | as above, plus rule-count scaling |

**Missing BTF is a documented fallback to rung 4, never an install failure.**
If `/sys/kernel/btf/vmlinux` does not exist, CO-RE cannot work, and the
installer says so and configures nftables instead of aborting.

Detection inputs, in the order they are evaluated:

| Input | Source | Effect |
|---|---|---|
| Kernel version | `uname -r` | gates the 5.15+ SYN proxy and the 5.8+ ring buffer |
| BTF present | `/sys/kernel/btf/vmlinux` | absent implies rung 4 |
| Driver XDP support | `ethtool -i`, trial `XDP_FLAGS_DRV_MODE` attach | native versus generic |
| Virtualisation | `systemd-detect-virt`, `/proc/user_beancounters` | OpenVZ and most LXC have no XDP at all |
| virtio queue count | `ethtool -l` versus `nproc` | too few queues implies generic, not native |
| `CONFIG_NET_CLS_BPF` | `/boot/config-$(uname -r)`, `/proc/config.gz` | gates rung 3 |
| Helper availability | `libbpf_probe_bpf_helper()` | gates SYN proxy program autoload |
| Map type availability | `libbpf_probe_bpf_map_type()` | gates the ring buffer; perf array otherwise |

Full detail, including a per-driver table and cloud-provider quirks, is in
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

---

## Quickstart

This sequence is deliberately conservative. It ends with a machine that is
protected; it does not start with one, because a firewall you have not
baselined is an outage waiting for a Tuesday.

### 1. Install

Pick your distro from [docs/INSTALL.md](docs/INSTALL.md). The short version on
a modern EL or Debian derivative:

```sh
sudo dnf install -y clang llvm libbpf-devel elfutils-libelf-devel zlib-devel \
                    bpftool make gcc     # EL9/EL10/Fedora/Amazon Linux 2023
# or
sudo apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
                    linux-tools-common linux-tools-generic make gcc pkg-config

git clone https://github.com/calyanti/caly-anti.git
cd caly-anti
make
sudo make install
```

### 2. Check the environment before you enable anything

```sh
sudo calyantid --probe
```

That prints the rung it would select, the driver, whether BTF is present,
whether the SYN cookie helpers exist, and whether `XDP_TX` is usable. It
changes nothing.

### 3. Tell it which interface faces the internet

Edit `/etc/calyanti/calyanti.conf`:

```ini
interface = eth0 zone=wan
```

Bogon filtering, RFC1918-source rejection and the reflection filter are inert
until an interface is in the WAN zone. This is the single most common
"installed it and nothing happened" cause.

### 4. Put your own networks in the allowlist

```ini
allow = 203.0.113.0/24        # office egress
allow = 198.51.100.10/32      # monitoring probe
```

An allowlist hit is an unconditional pass, checked before every drop rule.
A deployment with an empty allowlist is one automation mistake away from a
self-inflicted outage.

### 5. Run in monitor-only for a week

```ini
monitor_only = yes
```

```sh
sudo calyanti-cli check /etc/calyanti/calyanti.conf
sudo systemctl enable --now calyanti
calyanti-cli status
```

Every rule is evaluated, every verdict is recorded, nothing is dropped. What
*would* have been dropped is charged to `monitor_would_drop` and broken down by
reason.

### 6. Read what it saw

```sh
calyanti-cli stats --watch        # live counters by reason
calyanti-cli top -n 20            # busiest sources, with drop counts
calyanti-cli events --follow      # sampled per-packet verdicts
```

If anything in the would-drop breakdown is traffic you need, fix it now — while
it is still only a counter. [docs/TUNING.md](docs/TUNING.md) explains how to
read this and how to size every threshold from it.

### 7. Turn it on

```ini
monitor_only = no
```

```sh
sudo calyanti-cli reload
```

A reload rewrites `caly_config` and the policy maps in place. It never detaches
the XDP program, so there is no window in which the box is unprotected.

### 8. Then tighten

The shipped defaults are **safe, not tight**. Seven blocks in
`calyanti.conf` are marked `### TIGHTEN ###`. Work through them once you have
baseline data: set the real WAN interface, populate the allowlist, enumerate
your listening services and enable `default_deny`, enable `wan_drop_private`
if the host is genuinely public-facing, and resize the token buckets to roughly
four times your observed 99th-percentile per-source rates.

---

## Emergency: how to turn it all off

Print this. Keep it where you keep your console credentials.

```sh
# 1. Stop enforcing, keep everything loaded and counting (safest first step):
sudo calyanti-cli mode monitor-only

# 2. Stop the daemon; the XDP program stays attached and passes everything
#    if the config map is emptied, but the clean way is:
sudo systemctl stop calyanti

# 3. Detach XDP from an interface by hand, no daemon required:
sudo ip link set dev eth0 xdp off
sudo ip link set dev eth0 xdpgeneric off

# 4. Remove the tc hook if one was attached:
sudo tc qdisc del dev eth0 clsact

# 5. Remove every pin so nothing can be re-attached from state:
sudo rm -rf /sys/fs/bpf/calyanti

# 6. Prevent it from starting again on the next boot:
sudo systemctl disable --now calyanti
sudo systemctl mask calyanti
```

Steps 3 to 6 need no Caly Anti binary and no working config. They work from a
rescue initramfs and from a serial console. The full out-of-band procedure,
including what to do when the box is unreachable, is in
[docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

---

## Feature table

| Feature | Config key | Default | Notes |
|---|---|---|---|
| Master switch | `enabled` | yes | off still counts every packet, just passes it |
| Monitor only | `monitor_only` | no | evaluate everything, drop nothing |
| IPv4 / IPv6 | `ipv4`, `ipv6` | yes / yes | turning IPv6 off *drops* IPv6, it does not bypass it |
| VLAN and QinQ inspect | `vlan_inspect` | yes | up to 2 tags |
| Tunnel inspect | `tunnel_inspect` | yes | one level of IPIP/IP6IP6/GRE |
| Structural anomaly checks | `anomaly_checks` | yes | truncation, ihl, tot_len, doff |
| LAND attack | `land_check` | yes | source equals destination |
| Bogon/martian filter | `bogon_filter` | yes | WAN-zone interfaces only |
| RFC1918 source on WAN | `wan_drop_private` | **no** | wrong behind NAT, in a VPC, or on CGNAT. Read before enabling |
| Illegal TCP flags | `tcp_flag_checks` | yes | ECE/CWR are never treated as anomalies |
| Fragment sanity | `frag_checks`, `frag_min_size` | yes, 128 | tiny fragments, `frag_off == 1`, fragmented ICMP |
| Drop all fragments | `drop_all_fragments` | no | breaks large DNS/UDP and some VPNs |
| Drop IPv4 options | `drop_ip4_options` | no | source routing is the classic abuse |
| Drop IPv6 RH0 | `drop_ipv6_rh0` | yes | RFC 5095; no legitimate use |
| Minimum TTL | `min_ttl` | 0 (off) | blunt; rejects distant legitimate clients |
| ICMP type policy | `icmp4_type`, `icmp6_type` | see conf | types that break the network cannot be dropped |
| ICMP payload ceiling | `icmp_max_payload` | 1472 | ping of death / ICMP flood control |
| Allowlist | `allow`, `allowlist_enabled` | empty, yes | unconditional pass, before every drop rule |
| Blocklist | `block`, `blocklist_enabled` | empty, yes | static LPM, plus threat feeds |
| Per-source rate limits | `rate_*`, `ratelimit_enabled` | generous, yes | six buckets, nanosecond refill |
| Auto-ban | `autoban`, `strike_*`, `ban_ttl_*` | yes | escalating TTL, `/32` and `/128` only |
| Anti-amplification | `anti_amplification`, `amp_exempt` | yes | 21 source ports, conntrack-exempted |
| Port policy | `tcp_port`, `udp_port`, `port_policy` | yes | 65536-entry array per protocol |
| Inbound default deny | `default_deny` | **no** | the most valuable line in the config file |
| Conntrack-lite | `conntrack`, `ct_*` | yes | LRU 5-tuple, six states |
| Port-scan detection | `portscan_detect`, `scan_*` | yes, 60 ports / 30 s | 512-bit Bloom per source |
| SYN proxy | `synproxy`, `synproxy_port` | yes | 5.15+ only; automatic fallback below that |
| Management port bypass | `mgmt_tcp_ports`, `mgmt_bypass_ratelimit` | 22, yes | TCP/22 cannot be removed |
| Top-talker accounting | `src_stats` | yes | reporting only; nothing in the drop path reads it |
| Event stream | `log_events`, `log_sample_rate`, `log_max_pps` | yes, 1-in-100, 1000/s | ring buffer on 5.8+, perf array below |

Every scalar key in `config/calyanti.conf` carries a `-> fw_config.<field>`
comment naming the exact ABI field it writes. List-valued directives are marked
`-> map <name>`.

---

## Operating modes

`fw_config.mode` is written by the daemon and only read by the dataplane. The
dataplane never escalates on its own; escalation is a userspace decision made
from the global gauges.

| Mode | Meaning | Entered how |
|---|---|---|
| `normal` | Full policy, configured thresholds | default |
| `elevated` | Thresholds scaled down, event sampling raised | automatically, when a global gauge crosses its `_high` mark |
| `under-attack` | Aggressive: SYN proxy engaged, strict buckets | automatically, from the SYN or newconn gauges |
| `lockdown` | Allowlist, management ports and established conntrack only | manual |
| `monitor-only` | Everything evaluated, nothing dropped | manual |

Escalation is hysteretic: a gauge must cross `_high` to escalate and fall below
`_low` to de-escalate, and the daemon stays escalated for at least
`attack_dwell` afterwards, so an attacker cannot probe the threshold to make
your policy oscillate.

`lockdown` and `monitor-only` are manual states. The daemon will not move into
or out of them by itself.

---

## Command surface

`calyanti-cli --help` is authoritative; this is the shape of it.

| Command | What it does |
|---|---|
| `calyanti-cli status` | rung, attach mode, interfaces, mode, uptime, capability bits |
| `calyanti-cli stats [--watch] [--json] [--reset]` | all 109 counters, packets and bytes, by reason |
| `calyanti-cli top [-n N] [--json]` | busiest sources with packet, byte and drop counts |
| `calyanti-cli events [--follow] [--json]` | the sampled event stream |
| `calyanti-cli mode <mode>` | force a mode; `normal` returns control to the daemon |
| `calyanti-cli allow add\|del <cidr>` | edit the allowlist live |
| `calyanti-cli block add\|del <cidr>` | edit the static blocklist live |
| `calyanti-cli ban add <ip> [ttl]` / `ban del <ip>` / `ban list` | dynamic bans |
| `calyanti-cli conn list` | conntrack-lite table |
| `calyanti-cli feed load <url\|file>` | load a threat feed into the blocklist, tagged |
| `calyanti-cli check [file]` | validate a config file without applying it |
| `calyanti-cli reload` | apply config in place, no detach |
| `calyantid --probe` | print the detected ladder rung and capabilities, change nothing |
| `calyantid --foreground --config <path>` | run the daemon in the foreground |

---

## Repository layout

```
src/bpf/common.h          THE ABI contract. Read it before touching anything.
src/bpf/*.bpf.c           the dataplane: caly_xdp_main, caly_xdp_synproxy,
                          caly_xdp_ipv6, caly_tc_egress
src/user/                 loader, daemon, CLI
config/calyanti.conf      commented sample configuration, 113 keys
docs/ARCHITECTURE.md      design contract: ladder, maps, packet path, SYN proxy
docs/INSTALL.md           per-distro installation
docs/COMPATIBILITY.md     kernel, driver and cloud-provider matrices
docs/TUNING.md            sizing thresholds, reading stats, worked examples
docs/TROUBLESHOOTING.md   verifier logs, attach failures, recovery
docs/SECURITY.md          the attack surface of this tool
docs/BENCHMARKING.md      how to load-test without taking yourself down
```

`src/bpf/common.h` defines everything that crosses the kernel/userspace
boundary and nothing else does. It ends with 30 compile-time assertions on
`sizeof` and `__builtin_offsetof` that fire on both sides of the boundary. If
one of them ever trips, the fix is to correct the struct, never to edit the
expected number.

---

## Safety invariants

These are enforced by the loader, not by convention. A configuration that
violates one is rejected and the previously loaded configuration keeps running.

1. **TCP/22 is always a management port.** In every mode, including
   `under-attack` and `lockdown`. If you delete it from the config it is put
   back. If you moved SSH to 2222, add 2222 — you will end up with both, which
   is fine and intended.
2. **ICMPv6 types 2, 133, 134, 135 and 136 can never be set to drop.** IPv6 has
   no ARP; neighbour discovery *is* ICMPv6. Dropping those does not harden the
   host, it disconnects it. Type 2 is the only PMTUD mechanism IPv6 has.
3. **ICMPv4 type 3 can never be set to drop.** Code 4 is Fragmentation Needed.
   Drop it and you black-hole Path MTU Discovery, producing the most confusing
   failure in networking: TCP connects, small requests work, anything large
   hangs forever.
4. **The allowlist and the management-port check precede every drop rule.** If
   a drop can be reached without them, it is a bug — report it.
5. **Every internal failure fails open.** Missing config map, NULL scratch
   lookup, failed tail call, full LRU, full event ring: all of them produce
   `XDP_PASS` plus a counter. A firewall that black-holes traffic because it
   failed internally is worse than no firewall, because the failure is
   invisible.
6. **`XDP_ABORTED` is never returned.** It fires the `xdp_exception` tracepoint
   and is an error path, not a drop verdict. Production paths return only
   `XDP_PASS`, `XDP_DROP` or `XDP_TX`.
7. **Auto-bans are per-address only.** `/32` and `/128`. The dataplane never
   bans a prefix, so the collateral damage of a false positive is capped at one
   address.

---

## Limitations

Read this section twice. Most of the disappointment people have with XDP
firewalls comes from expecting one of these things to work.

**A 100 Gbps flood is won or lost upstream of your NIC.** If the attack
saturates your transit, your provider's edge, or the hypervisor's virtual
switch, the packets never reach the driver where this program runs. XDP can
drop 40 Mpps per core; it cannot create bandwidth. When the pipe is full, the
only controls that matter are your provider's scrubbing centre, BGP flowspec,
RTBH, or an anycast scrubbing service. Caly Anti protects the *host* so that it
survives what does arrive, and it keeps your CPU free so that the legitimate
fraction still gets served. It does not protect the *pipe* and no host-resident
software can.

**XDP cannot see egress.** The XDP hook is receive-only. Outbound flows are
learned by the optional `tc`/`clsact` egress program, which the installer
attaches wherever clsact exists. Without it, outbound-initiated UDP (DNS, NTP,
QUIC) has no inbound handshake to learn from, and its replies fall through to
the port policy instead of matching conntrack. That is a fallback concern only
on very old kernels — but if you pin the dataplane to nftables or iptables, you
lose the egress hook and therefore lose conntrack-lite entirely.

**It runs before the kernel's conntrack, not instead of it.** `conn_key` is a
5-tuple plus a six-state machine. It does not reassemble fragments, does not
validate sequence numbers, does not track TCP windows, and has no protocol
helpers. A packet that passes Caly Anti is still evaluated by netfilter and by
the real conntrack afterwards. Do not remove your existing firewall rules
because you installed this.

**It cannot decrypt TLS.** It sees IP headers, TCP/UDP headers and opaque
bytes. Slowloris, HTTP floods over completed handshakes, expensive GraphQL
queries and credential stuffing all look like perfectly legitimate traffic at
L3/L4, because they are. The `newconn` bucket and per-port limits blunt the
crudest versions and nothing more. Use a WAF.

**Source-IP-based auto-banning is dangerous for spoofable protocols.** UDP,
ICMP and non-handshake TCP source addresses are trivially forged. An attacker
who knows you auto-ban can send spoofed packets that appear to come from your
DNS resolver, your upstream gateway, your monitoring system or your payment
processor and get *you* to block *them*. The design mitigates this — allowlist
first, `/32` bans only, TTLs rather than permanent blocks, an LRU ban table
that evicts rather than fills, conntrack exemption, and bogon filtering that
removes the easiest forgeries — but the mitigation is not free and you must
understand it. [docs/SECURITY.md](docs/SECURITY.md) covers this properly, and
tells you when to turn `autoban` off.

**Fragment handling is by policy, not by reassembly.** XDP sees individual
fragments. Only the first fragment carries the L4 header, so port policy and
per-port rate limits cannot be applied to subsequent fragments. Caly Anti
applies sanity rules (minimum size, `frag_off == 1`, no fragmented ICMP) and
counts the rest against the per-source `pps` and `bps` buckets. If you need
strict fragment policy, `drop_all_fragments = yes` exists, and it will break
large DNS responses over UDP and some VPN encapsulations.

**Native XDP is unavailable in several common places.** OpenVZ and most LXC
containers have no XDP at all. virtio-net needs multiqueue with at least as
many queues as CPUs for native mode. Some cloud NIC drivers only do generic
mode, and generic mode is roughly five times slower and makes `XDP_TX` — and
therefore the SYN proxy — expensive enough that it is disabled by default.
[docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) has the driver-by-driver
picture.

**The SYN proxy needs kernel 5.15 or newer, and `net.ipv4.tcp_syncookies = 2`.**
It is built exclusively on `bpf_tcp_raw_gen_syncookie_ipv4/ipv6()` and
`bpf_tcp_raw_check_syncookie_ipv4/ipv6()`, because those use the kernel's own
cookie secret. A hand-rolled cookie cannot be validated by the TCP stack: the
client would complete the handshake, the kernel would reject a cookie it never
issued, and the connection would die silently — a SYN proxy that makes the
service permanently unreachable rather than merely undefended. On older kernels
the program is not loaded at all and the fallback is rate limiting, which is
meaningfully weaker. That fallback is also the reason this suite still runs on
RHEL 8.

**Anything with `CAP_BPF` or `CAP_SYS_ADMIN` can remove it.** This is a network
filter, not a kernel integrity mechanism. A root-level compromise beats it in
one syscall.

---

## Documentation index

| Document | Read it when |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | you want the design contract: ladder, maps, packet path, SYN proxy, threat model |
| [docs/INSTALL.md](docs/INSTALL.md) | installing, on any of thirteen distro families |
| [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md) | "will this work on my kernel / NIC / cloud?" |
| [docs/TUNING.md](docs/TUNING.md) | choosing thresholds; telling an attack from a launch day |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | it will not load, will not attach, or dropped something it should not have |
| [docs/SECURITY.md](docs/SECURITY.md) | before exposing the metrics endpoint or enabling the log watcher |
| [docs/BENCHMARKING.md](docs/BENCHMARKING.md) | before you point a packet generator at anything |

---

## Licence

The BPF objects carry the license string `"Dual BSD/GPL"`, which is required to
call GPL-restricted kernel helpers. `src/bpf/common.h` is
`BSD-2-Clause OR GPL-2.0`. See the per-file SPDX identifiers; where a file has
none, the repository default applies.
