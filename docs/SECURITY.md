# Caly Anti — Security

The attack surface of the *mitigation tool itself*, and how to reduce it.

A DDoS filter is a privileged process that consumes attacker-controlled input
on every packet. That makes it a target, and it makes it a lever: the most
efficient attack against a host running an auto-banning firewall is often to
make the firewall block the traffic you actually need.

This document covers what an attacker can do to Caly Anti, what Caly Anti can
be tricked into doing to you, and what the design does about both.

---

## Contents

- [1. Attack surface inventory](#1-attack-surface-inventory)
- [2. Auto-ban weaponisation](#2-auto-ban-weaponisation)
- [3. The control socket](#3-the-control-socket)
- [4. The metrics endpoint](#4-the-metrics-endpoint)
- [5. Log watchers and attacker-controlled input](#5-log-watchers-and-attacker-controlled-input)
- [6. Threat feeds](#6-threat-feeds)
- [7. The pinned maps in bpffs](#7-the-pinned-maps-in-bpffs)
- [8. The dataplane itself](#8-the-dataplane-itself)
- [9. Privilege model](#9-privilege-model)
- [10. Self-lockout, and the invariants that prevent it](#10-self-lockout-and-the-invariants-that-prevent-it)
- [11. Resource exhaustion against the tool](#11-resource-exhaustion-against-the-tool)
- [12. Telemetry contains personal data](#12-telemetry-contains-personal-data)
- [13. Supply chain](#13-supply-chain)
- [14. Hardening checklist](#14-hardening-checklist)
- [15. Reporting a vulnerability](#15-reporting-a-vulnerability)

---

## 1. Attack surface inventory

| Component | Input | Exposure | Worst case |
|---|---|---|---|
| XDP dataplane | every packet on the wire | **remote, unauthenticated, pre-firewall** | kernel crash or read of adjacent memory (mitigated by the verifier) |
| tc egress program | every outbound packet | local | same |
| BPF maps in bpffs | whatever can write to `/sys/fs/bpf/calyanti` | local, filesystem permissions | full policy rewrite: unban, allowlist, disable |
| Daemon config parser | `/etc/calyanti/calyanti.conf` | local, root-writable | memory corruption in a root process |
| Control socket | CLI commands | local, unix socket permissions | full policy control |
| Metrics endpoint | HTTP GET | **network, if you bind it wrongly** | information disclosure; DoS on the daemon |
| Threat feed loader | remote URLs | **network, attacker-influenceable content** | blocklisting your own prefixes |
| Log watcher | application log lines | **remote, attacker-controlled content** | banning arbitrary addresses; parser DoS |
| Event stream consumer | dataplane records | local | none (fixed 88-byte records, size-validated) |
| CLI | argv, socket replies | local | terminal escape injection from crafted data |

The two that deserve most of your attention are the **log watcher** and the
**auto-ban system**, because they are the only components that turn
attacker-supplied data into a policy change. Everything else requires local
access you have already lost the game without.

---

## 2. Auto-ban weaponisation

**This is the most important section in this document.**

### The problem

Source-IP-based automatic banning is only sound when the source address is
*expensive to forge*. That is true for TCP after a completed three-way
handshake — the attacker must receive the SYN-ACK to continue. It is false for:

- **all UDP**, unconditionally;
- **all ICMP**, unconditionally;
- **TCP SYN, RST and ACK floods**, because no handshake is completed;
- **anything at all** if the attacker sits on-path.

An attacker who knows you auto-ban does not need to attack you. They send a
modest volume of spoofed packets whose source address is something you need,
your firewall bans it, and you have DoSed yourself with the attacker's traffic
budget rather than theirs. Good targets for that game:

- your recursive DNS resolvers, or your upstream's;
- your default gateway or first-hop router;
- your monitoring and alerting systems;
- your payment processor, your identity provider, your CDN's edge nodes;
- the NTP servers you sync from;
- your own load balancers, if they appear as source addresses anywhere;
- a partner's API endpoint, to break an integration and blame you.

The amplification is enormous. A few thousand spoofed packets can remove an
address from your reach for the whole `ban_ttl`.

### What this design does about it

Eight mitigations, all active by default:

1. **The allowlist precedes every drop rule.** An allowlist hit is an
   unconditional `XDP_PASS` checked before the blocklist, before bans, before
   every rate limiter and before every anomaly rule. Nothing in the suite can
   drop a packet from an allowlisted source. This is the primary defence and
   it is why the config file nags you to populate it.
2. **Bans are `/32` and `/128` only.** The dataplane never bans a prefix, so
   the blast radius of one false positive is exactly one address. Prefix
   blocking is `block =`, a deliberate operator action.
3. **Bans have a TTL, and the first one is short.** `ban_ttl_base` defaults to
   10 minutes. Nothing is banned permanently by the dataplane;
   `CALY_BAN_F_PERMANENT` can only be set by the operator.
4. **Escalation is per-source and requires repeat offences.** A single spoofed
   burst produces a base-TTL ban, not a 24-hour one. The escalation ladder
   (`ttl * num / den`, clamped to `ban_ttl_max`) rewards persistence, and a
   spoofer who persists is spending real bandwidth.
5. **A ban requires `strike_limit` strikes inside `strike_window`.** One
   over-limit packet is not a ban. The attacker must sustain the forgery.
6. **The ban table is an LRU.** A flood of distinct spoofed sources evicts the
   *coldest* bans rather than filling the table and failing. It cannot be used
   to push out the bans that matter, only the oldest ones.
7. **Conntrack exempts solicited traffic.** Replies to flows you initiated
   short-circuit to `XDP_PASS` before the ban check is ever relevant to them,
   so an attacker cannot get your DNS resolver banned by forging its address in
   traffic that looks like an answer to a query you made.
8. **Bogon and martian filtering removes the cheapest forgeries** before they
   can accrue strikes, on WAN-zone interfaces.

### What you must do about it

**Populate the allowlist with your infrastructure.** Not "eventually" — before
you take `monitor_only` off.

```ini
allow = 198.51.100.10/32      # monitoring
allow = 198.51.100.11/32      # resolver 1
allow = 198.51.100.12/32      # resolver 2
allow = 203.0.113.0/24        # office / admin
allow = 192.0.2.1/32          # default gateway
# CDN, LB, payment provider, IdP, partner API, NTP pool members you pin
```

Then decide whether auto-banning is right for your exposure at all:

| Exposure | Recommendation |
|---|---|
| Predominantly TCP, clients complete handshakes | `autoban = yes`, defaults are fine |
| Predominantly UDP, no upstream BCP38 | **`autoban = no`** — rate limit instead |
| Clients arrive via CDN, corporate NAT or carrier CGNAT | **`autoban = no`**; ban the wrong shared address and you remove thousands of users |
| Game server | `autoban = yes` with a high `strike_limit` and a short TTL (2-5 min) |
| SMTP / SSH exposed to brute force | `autoban = yes`, low `strike_limit`, long TTL |

**Rate limiting degrades gracefully under spoofing; banning does not.** A
forged source burns its own token bucket and affects nothing else. A forged
source that earns a ban burns the *real owner's* connectivity. When in doubt,
limit rather than ban.

### Upstream anti-spoofing is the real fix

Ask your provider whether they implement BCP38 / RFC 2827 ingress filtering,
and enable uRPF where your topology allows it:

```sh
# Loose mode: drop only if the source has no route at all anywhere.
# Safe with asymmetric routing and multihoming.
sysctl -w net.ipv4.conf.all.rp_filter=2

# Strict mode: the reply must go out the interface the packet arrived on.
# Correct only on a single-homed host with symmetric routing.
sysctl -w net.ipv4.conf.all.rp_filter=1
```

The installer writes `rp_filter = 2` because strict mode breaks multihomed and
policy-routed hosts. If you are single-homed with symmetric routing, `1` is
strictly better; change it knowingly.

---

## 3. The control socket

The daemon listens on a unix domain socket under `CALY_RUN_DIR`
(`/run/calyanti/`). It carries full policy control: mode changes, allowlist and
blocklist edits, ban insertion and removal, reload.

**It is not a network socket and must never become one.** There is no TCP
listener, no authentication protocol, and none is planned — the unix socket's
filesystem permissions *are* the authentication.

Requirements the daemon enforces at startup, and which you should verify:

```sh
ls -ld /run/calyanti
ls -l  /run/calyanti/control.sock
```

| Property | Required |
|---|---|
| Directory mode | `0750`, owner `root`, group `calyanti` |
| Socket mode | `0660`, owner `root`, group `calyanti` |
| Socket type | `AF_UNIX`, `SOCK_SEQPACKET` |
| Peer identification | `SO_PEERCRED` — the daemon logs uid/gid/pid of every mutating command |

Anyone in the `calyanti` group can change your firewall policy. Treat group
membership as equivalent to root over the network path:

```sh
getent group calyanti          # audit this list
sudo gpasswd -d someuser calyanti
```

Commands that mutate policy are logged with the peer credentials, so
`journalctl -u calyanti | grep 'cli:'` is an audit trail. Ship it off the box
if it matters to you.

If you do not need CLI access at all, remove the group and leave the socket
root-only.

---

## 4. The metrics endpoint

If you enable a Prometheus-style metrics endpoint, it is the only part of this
system that can be network-reachable by design. Get it right.

**Bind to localhost.** Then scrape it through something that does
authentication and TLS — an nginx reverse proxy, a node_exporter sidecar, or a
WireGuard/Tailscale interface.

```ini
metrics_listen = 127.0.0.1:9433
```

Never:

```ini
metrics_listen = 0.0.0.0:9433      # DO NOT
```

Why it matters:

- **Information disclosure.** The metrics reveal your thresholds, your current
  mode, your ban count, your top talkers (i.e. client IP addresses), and
  exactly which of your controls are enabled. An attacker who can read them can
  size their attack to sit precisely under every limit, and can watch in real
  time whether they are being filtered — turning your own telemetry into their
  feedback loop.
- **It is a DoS vector.** An HTTP endpoint on a box under attack is one more
  thing consuming CPU and one more parser exposed.
- **It leaks your escalation state.** Knowing you are in `elevated` versus
  `under-attack` tells an attacker whether to push harder or back off and wait.

If you must expose it beyond localhost, put it on a management interface that
is *not* the WAN interface, and add the management port to `mgmt_tcp_ports` so
you do not filter your own monitoring — while remembering that management ports
bypass the drop rules, so keep the metrics port allowlisted to your monitoring
source rather than open to the world.

---

## 5. Log watchers and attacker-controlled input

If you run a component that tails application logs and asks Caly Anti to ban
what it finds, you have built a remote-controlled banning API for whoever can
write to those logs. Which is anyone who can send your web server a request.

This is worth being blunt about: **log-driven banning is the single most
common way an operator gets DoSed by their own tooling.**

### The failure modes

| Attack | Mechanism | Consequence |
|---|---|---|
| Header injection | The attacker sets `X-Forwarded-For: 8.8.8.8` and triggers a ban rule | you ban Google's resolver, or your gateway, or your CDN |
| Log injection | A newline or CR in a URL, User-Agent or username forges an entire extra log line | arbitrary address banned, with a plausible-looking reason |
| Escape sequences | ANSI/terminal escapes in a field | a `calyanti-cli ban list` on a real terminal executes attacker-influenced output rendering |
| Regex denial of service | A crafted field triggers catastrophic backtracking in the watcher's pattern | the watcher pegs a core; log processing stalls behind it |
| Log volume flood | Millions of failure lines per second | watcher CPU exhaustion, unbounded memory in the parser |
| Path traversal | `../` in a logged filename used to build a state path | file write outside the state directory |
| Unicode/encoding confusion | Homoglyphs or overlong UTF-8 in an address field | parser accepts something the validator did not |

### Rules for any log-driven banning

1. **Parse the address from a field the *server* controls, never one the
   *client* controls.** In nginx that is `$remote_addr`, not
   `$http_x_forwarded_for`. If you are genuinely behind a proxy, use
   `real_ip_header` with a `set_real_ip_from` list of *your* proxies, so nginx
   validates the chain before the address ever reaches the log.
2. **Validate strictly.** `inet_pton()` on an exact-match capture. Reject
   anything that is not a bare address. No regexes that accept surrounding
   text.
3. **Refuse to ban anything in the allowlist, in `caly_local4/6`, or in your
   own prefixes** — before calling the CLI, not after. The dataplane already
   enforces this, but a watcher that tries is a watcher with a bug.
4. **Never ban a private, loopback, link-local, multicast or CGNAT address**
   from a log rule. If those appear in your logs, your proxy configuration is
   wrong and banning is not the fix.
5. **Cap the rate.** No more than N bans per minute, whatever N is small enough
   that a runaway rule is a nuisance rather than an outage.
6. **Use anchored, linear-time patterns.** No nested quantifiers. Prefer a
   fixed field split over a regex.
7. **Bound every buffer and truncate every line.** A single log line can be
   megabytes if the attacker wants it to be.
8. **Sanitise before display.** Strip anything outside printable ASCII before a
   value reaches a terminal or an HTML dashboard.
9. **Log every ban decision with the raw source line**, so a bad rule is
   forensically obvious afterwards.
10. **Short TTLs.** A log-driven ban should expire in minutes. The whole class
    of mistake is self-limiting if nothing lasts long.

### The default position

Log-driven banning is **not enabled by default** and, on any host where the
client population arrives through shared addresses, it should stay off. The
per-source token buckets already limit what one address can do, and they do it
without trusting anything the attacker wrote.

---

## 6. Threat feeds

`calyanti-cli feed load <url|file>` inserts entries into the blocklist maps,
tagged so a feed refresh does not clobber manual entries.

Feeds are remote content that becomes firewall policy. Treat them accordingly:

| Risk | Control |
|---|---|
| Compromised or hijacked feed source | HTTPS with certificate verification, no plain HTTP, no `-k` |
| Feed content includes your own prefixes | the loader refuses any entry that overlaps `caly_local4/6` or the allowlist, and logs the refusal |
| Feed includes `0.0.0.0/0` or `::/0` | rejected outright; a default route in a blocklist is a self-DoS |
| Feed includes critical infrastructure (root servers, your gateway) | the allowlist wins over the blocklist, always. Populate it first |
| Feed grows without bound | capped by `max_block_entries`; the loader refuses an update that would exceed it rather than truncating silently |
| Feed source goes away | the previous contents remain; a failed refresh never empties the list |
| Malformed input | the parser validates every line and rejects the file if any line fails, rather than importing a partial list |

Verify what you loaded:

```sh
calyanti-cli block list --tag <feed-id> | head
calyanti-cli block list | wc -l
```

Pin the feed to a specific URL you control a mirror of, and verify a checksum
where the publisher provides one. Do not pipe a feed through `curl | sh`, and
do not point the loader at a URL from a source you cannot audit — the entire
value of a blocklist is that somebody trustworthy curated it.

---

## 7. The pinned maps in bpffs

Everything is pinned under `/sys/fs/bpf/calyanti/` so the CLI can attach
without being the loader and state survives a daemon restart.

**Anyone who can write to those pins can rewrite your policy** without going
through the daemon, the control socket, or any audit log: unban an address,
allowlist a prefix, set `mode` to a value that changes behaviour, or empty
`caly_config` (which fails open — everything passes).

```sh
ls -ld /sys/fs/bpf/calyanti
```

Required: mode `0700`, owner `root`, group `root`.

```sh
sudo chmod 0700 /sys/fs/bpf/calyanti
sudo chown root:root /sys/fs/bpf/calyanti
```

Note also that `bpftool map update` can modify any map by id, not just by pin,
so the real boundary is `CAP_BPF`/`CAP_SYS_ADMIN` rather than the directory
mode. The mode stops the accidental case; capabilities stop the deliberate one.

```sh
sysctl kernel.unprivileged_bpf_disabled      # should be 1 or 2
```

---

## 8. The dataplane itself

The XDP program processes remote, unauthenticated, attacker-controlled input
before any other kernel code sees it. Its safety rests on:

- **The verifier.** Every memory access is proven in-bounds at load time. Every
  loop has a compile-time constant bound. There is no dynamic allocation, no
  recursion, and no unbounded pointer arithmetic. A bug that would be an
  out-of-bounds read in a userspace parser is a load-time rejection here.
- **Explicit bounds checks before every read.** `(ptr + size > data_end)`
  precedes every access. Length fields in the packet are validated *against*
  the actual frame extent and are never used to compute an unchecked offset.
- **Constant parse depth.** Two VLAN tags, eight IPv6 extension headers, one
  tunnel level. An attacker cannot make the program do more work per packet by
  nesting headers, which is a real DoS against parsers that recurse.
- **Fail-open on every internal error.** Missing config, NULL scratch, failed
  tail call, full LRU: all `XDP_PASS` plus a counter. There is no internal
  state an attacker can corrupt into a drop-everything condition.
- **No `XDP_ABORTED`.** It fires the `xdp_exception` tracepoint, which is
  itself a cost an attacker could trigger deliberately.

Residual risks, honestly stated:

- **Verifier bugs are kernel bugs.** They have existed and will again. Keep the
  kernel patched; that is the only mitigation.
- **JIT spectre-class issues.** Mitigated by the kernel's own BPF hardening
  (`net.core.bpf_jit_harden`). On a multi-tenant host, consider setting it to
  `2`, at a performance cost.
- **Per-packet cost is an amplifier in itself.** Every check you enable is work
  an attacker gets you to do for free. The processing order — cheapest,
  no-map-lookup checks first — exists precisely to bound that.
- **Timing side channels** from map hit/miss latency are theoretically
  observable and practically useless: the information leaked is "is this
  address in the conntrack table", which the attacker already knows.

---

## 9. Privilege model

The daemon must load BPF programs, attach XDP, create pins and read per-CPU
maps. That requires:

| Kernel | Capability set |
|---|---|
| 5.8 and newer | `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON` (+ `CAP_SYS_RESOURCE` on < 5.11 for memlock) |
| Before 5.8 | `CAP_SYS_ADMIN` — there is no finer split available |

The systemd unit runs as root and drops everything else it can:

```ini
[Service]
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_PERFMON CAP_SYS_RESOURCE CAP_SYS_ADMIN
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/sys/fs/bpf /run/calyanti /var/lib/calyanti
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=no
SystemCallArchitectures=native
SystemCallFilter=@system-service @privileged
LimitMEMLOCK=infinity
```

`MemoryDenyWriteExecute=no` is required: the BPF JIT allocates executable
memory, and setting it to `yes` breaks program loading. That is a real,
unavoidable weakening of the sandbox, and it is worth knowing about rather than
discovering.

Check what you actually got:

```sh
systemd-analyze security calyanti.service
```

`calyanti-cli` is **not** setuid. It talks to the control socket and needs only
group membership.

---

## 10. Self-lockout, and the invariants that prevent it

The most likely security incident involving this tool is that it locks you out
of your own machine. Seven invariants exist to prevent that, and they are
enforced by the loader rather than by convention — a configuration that
violates one is rejected and the previous configuration keeps running.

1. **TCP/22 is forced into `mgmt_tcp_ports` in every mode**, including
   `under-attack` and `lockdown`. A config that would remove it is rejected.
2. **The allowlist and management-port checks precede every drop rule.**
3. **ICMPv6 types 2, 133, 134, 135, 136 can never be set to `drop`.** IPv6 has
   no ARP; neighbour discovery *is* ICMPv6. Dropping those disconnects the host
   rather than hardening it.
4. **ICMPv4 type 3 can never be set to `drop`.** Code 4 is Fragmentation
   Needed; dropping it black-holes PMTUD.
5. **Every internal failure fails open**, with a counter.
6. **`XDP_ABORTED` is never returned.**
7. **Auto-bans are single addresses only.**

The security consequence of invariant 1 deserves stating plainly: **port 22 is
never protected by this firewall.** Management ports bypass the drop rules by
design, which means the load-bearing control on SSH is SSH's own configuration.
Do the obvious things:

```sh
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 20
AllowGroups sshusers
```

and put your admin networks in the allowlist so that the port-policy layer can
close 22 to everyone else. That combination — mgmt bypass on, allowlist
populated, port closed to the world — is the configuration this design is built
around, and it is described in the `### TIGHTEN ###` block of the
`[management]` section in `calyanti.conf`.

---

## 11. Resource exhaustion against the tool

| Vector | Effect | Mitigation |
|---|---|---|
| Flood of distinct source addresses | fills `caly_rate4/6`, `caly_scan4/6`, `caly_top4/6` | all are LRU: the coldest entry is evicted, inserts never fail. `map_full_*` counters make it visible |
| Flood of distinct flows | fills `caly_conn` | LRU. Watch `ct_full` (counter 93); a non-zero value means live flows are being evicted |
| Event flood | daemon CPU, ring overflow | `log_sample_rate`, `log_max_pps`, and `event_sampled_out` distinguishes sampling from loss |
| Deeply nested headers | per-packet parse cost | hard constant bounds: 2 VLAN tags, 8 extension headers, 1 tunnel level |
| Tiny-packet flood | per-packet cost dominates | cheapest checks first, no map lookups in the anomaly stage |
| Ban table churn | evicting useful bans | LRU evicts coldest first; `max_ban_entries` sizes the table |
| Log flood into a watcher | watcher CPU, disk | rate-limit the watcher and the logs themselves; see section 5 |
| Metrics scrape flood | daemon CPU | bind to localhost; rate-limit at the reverse proxy |

The design principle throughout: **every table is an LRU or a fixed array, and
every failure is an eviction or a counter, never a refusal and never a drop.**
An attacker can degrade the *quality* of the state Caly Anti keeps. They cannot
make it fail closed, and they cannot make it fail silently.

---

## 12. Telemetry contains personal data

`struct event` carries source and destination addresses. `caly_top4/6` carries
per-source counters. `calyanti-cli stats`, `top` and `events`, the metrics
endpoint, and any diagnostic bundle all contain client IP addresses.

In the EU, UK and several other jurisdictions an IP address is personal data.
That has practical consequences:

- **Set a retention period** on the event stream wherever you ship it, and keep
  it short. Days, not years.
- **`log_sample_rate` is a privacy control as well as a performance one.**
  1-in-100 sampling is 1% of the personal data.
- **Redact diagnostic bundles before sharing them** with vendors, in bug
  reports, or in a public issue tracker.
- **Bans are a record of an individual's activity.** `/var/lib/calyanti/`
  persists them across restarts. Include it in your data inventory.
- **The metrics endpoint exposes top-talker addresses.** Another reason not to
  bind it publicly.

None of this is legal advice. It is a note that the file you are about to paste
into a support ticket has customer IP addresses in it.

---

## 13. Supply chain

- **The BPF object is compiled from source on the target**, or from a package
  built by your distro. There is no downloaded binary blob in the default
  install path.
- **`vmlinux.h` is generated from the running kernel's own BTF** at build time.
  It is not shipped pre-generated by default; when it is (for cross-builds),
  regenerate it and diff before trusting it.
- **The vendored libbpf** in `third_party/libbpf` is a pinned upstream commit.
  Verify it against upstream if you build from a tarball rather than from git.
- **Verify release artifacts** before installing: signature or checksum,
  published separately from the artifact.
- **Do not `curl | sh`.** Not for this, not for anything. Download, read,
  then run.
- **The `calyanti` group is a privilege boundary.** A compromised account in
  that group can rewrite firewall policy. Treat additions to it as you would
  additions to `wheel`.

---

## 14. Hardening checklist

Work through this before the box faces the internet.

**Configuration**

- [ ] Allowlist populated with gateway, resolvers, monitoring, admin networks,
      CDN/LB ranges, and any partner endpoint you cannot afford to ban
- [ ] `mgmt_tcp_ports` contains your real SSH port (22 will be there regardless)
- [ ] The internet-facing interface is `zone=wan`
- [ ] `autoban` decision made deliberately against your exposure (section 2)
- [ ] `default_deny = yes` after enumerating services with `ss -lntup`
- [ ] Buckets sized from a week of `monitor_only` data, not from the defaults
- [ ] `log_sample_rate` is not 1

**System**

- [ ] `net.ipv4.tcp_syncookies = 2` on 5.15+, `1` below that
- [ ] `sysctl kernel.unprivileged_bpf_disabled` is 1 or 2
- [ ] `/sys/fs/bpf/calyanti` is `0700 root:root`
- [ ] `/run/calyanti/control.sock` is `0660 root:calyanti`
- [ ] `getent group calyanti` contains only accounts that should control the
      firewall
- [ ] `/etc/calyanti/calyanti.conf` is `0640 root:root` — it contains your
      allowlist, which is a map of your admin infrastructure
- [ ] Metrics endpoint bound to `127.0.0.1` or a management interface only
- [ ] `systemd-analyze security calyanti.service` reviewed

**SSH, because the firewall deliberately does not protect it**

- [ ] Key-only authentication, `PermitRootLogin no`
- [ ] `AllowGroups` restricted
- [ ] Admin networks allowlisted and port 22 closed to everyone else at the
      port-policy layer

**Operations**

- [ ] Out-of-band console access tested, from a different network, *before* you
      need it
- [ ] The panic-button procedure from TROUBLESHOOTING §0 printed and reachable
      without the box
- [ ] Kernel patched — the verifier is your sandbox and it is kernel code
- [ ] Event retention period set
- [ ] Threat feeds pinned to auditable sources over HTTPS
- [ ] Log-driven banning off, or built to the rules in section 5

---

## 15. Reporting a vulnerability

Report privately first. Do not open a public issue for a vulnerability.

Include, where relevant:

- kernel version, distro, architecture, NIC driver;
- the ladder rung and attach mode from `calyanti-cli status`;
- `calyantid --probe` output;
- a minimal reproducer: a packet capture, a `bpftool prog run` invocation, or a
  configuration file;
- what you expected and what happened.

Classes of report that are especially valuable:

- **any path that reaches a drop without first checking the allowlist and the
  management ports** — that violates a stated invariant;
- **any way to make the dataplane return `XDP_ABORTED`**;
- **any internal failure that results in a drop rather than a pass**;
- **any way to get a legitimate address banned without sending traffic from
  it**;
- **any input to the config parser, feed loader or control socket that
  corrupts memory in the root daemon**;
- **any verifier-accepted out-of-bounds access** — that is a kernel bug and we
  will help you report it upstream.

Redact client addresses from anything you attach. See section 12.
