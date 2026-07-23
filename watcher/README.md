# calywatch — Caly Anti layer-7 log watcher

The XDP/eBPF dataplane in Caly Anti sees **packets**, not **sessions**. An HTTP
request flood over completed TCP handshakes, a WordPress login brute force,
slowloris, an SSH dictionary run — every packet in these attacks is perfectly
legitimate at L3/L4, so the dataplane cannot tell them apart from real traffic.
That is explicitly *out of scope* for the dataplane (see
`docs/ARCHITECTURE.md`, "Out of scope").

`calywatch` closes that gap. It tails logs, applies rule sets, and pushes the
offenders it finds **down into the XDP ban maps** (`caly_ban4` / `caly_ban6`),
where enforcement is effectively free. When the dataplane is not available it
degrades to `nft` or `ipset` on its own.

- **Language:** Python 3.6+ (works on RHEL 8's 3.6, Alpine/musl, and newer).
- **Dependencies:** the standard library only. No `pip`, no venv, no compiler.
- **Privileges:** root or `CAP_NET_ADMIN` for the `nft`/`ipset` backends and
  for active-session protection; the control-socket backend only needs access
  to the daemon socket.

---

## Contents

- [How it fits together](#how-it-fits-together)
- [Security model — logs are hostile input](#security-model--logs-are-hostile-input)
- [Quick start](#quick-start)
- [Configuration — `calywatch.conf`](#configuration--calywatchconf)
- [Rule file format](#rule-file-format)
- [Ban backends and the fallback chain](#ban-backends-and-the-fallback-chain)
- [Escalating bans and persisted state](#escalating-bans-and-persisted-state)
- [Management-session protection and the allowlist](#management-session-protection-and-the-allowlist)
- [X-Forwarded-For and trusted proxies](#x-forwarded-for-and-trusted-proxies)
- [journald input](#journald-input)
- [Command-line interface](#command-line-interface)
- [fail2ban integration](#fail2ban-integration)
- [Running under systemd / OpenRC](#running-under-systemd--openrc)
- [Shipped rule sets](#shipped-rule-sets)
- [Signals](#signals)
- [Troubleshooting](#troubleshooting)

---

## How it fits together

```
   access.log / secure / journald
              │  (tail, rotation-safe)
              ▼
   ┌──────────────────────┐        strict ipaddress validation
   │  rule sets (regex +   │        allowlist + active-session guard
   │  threshold + window)  │        per-minute ban cap
   └──────────┬───────────┘
              │ offender
              ▼
   ┌──────────────────────────────────────────────┐
   │  ban backend chain (best available first):    │
   │   1. control socket → caly_ban4/6 in XDP      │
   │   2. calyctl        → same maps via the CLI    │
   │   3. nft            → table inet calywatch      │
   │   4. ipset+iptables → set + CALYWATCH chain     │
   └──────────────────────────────────────────────┘
```

The TTL escalation arithmetic (`ttl * num / den`, clamped to `[base, max]`) is a
line-for-line port of `caly_ban_next_ttl()` from `src/bpf/common.h`, so a ban
`calywatch` installs and a ban the in-kernel autobanner installs **age
identically**.

---

## Security model — logs are hostile input

Every byte of a log line can be chosen by the attacker. A request for

```
GET /?x=9.9.9.9%20Failed%20password%20for%20root%20from%208.8.8.8 HTTP/1.1
```

lands verbatim in your access log. If a log watcher is naïve, that line makes it
ban `9.9.9.9` or `8.8.8.8` — addresses the attacker chose. `calywatch` is built
so that cannot happen:

- **No code execution.** There is no `eval`, `exec`, or `compile` of anything
  derived from a log line, anywhere.
- **No shell, ever.** Every subprocess (`nft`, `ipset`, `journalctl`, `calyctl`)
  is invoked with a literal `argv` list and `shell=False`. No value taken from a
  log line is placed in `argv` before it has been validated as an IP address.
- **Strict address parsing.** A regex capture is only a *candidate*. It becomes a
  ban target only after `ipaddress.ip_address()` accepts it. Leading-zero octets
  (`010.0.0.1`), zone IDs (`fe80::1%eth0`), CIDRs, and anything with whitespace
  are rejected. IPv4-mapped IPv6 is normalised to IPv4 so v4 and dual-stack logs
  produce the same target.
- **X-Forwarded-For is not trusted by default.** A forged `X-Forwarded-For` can
  never redirect a ban unless the **direct peer** is inside a configured
  `trusted_proxy` prefix (see below).
- **The allowlist is checked before every ban**, with no exceptions and no code
  path that can skip it.
- **A hard per-minute ban cap** (`max_bans_per_min`) bounds the blast radius of a
  log-injection flood: even if everything else were bypassed, the watcher cannot
  ban more than the configured number of *new* addresses per minute.
- **Output is sanitised too.** Attacker-controlled strings are stripped of
  non-printable bytes and truncated before they are written to *our* log, so the
  attacker cannot inject forged lines into it either.
- **ReDoS guard.** Rule regexes are sampled for runtime; one that repeatedly
  blows a per-line budget is auto-disabled rather than being allowed to stall
  the event loop.

---

## Quick start

```sh
# 1. Put the rule files somewhere calywatch searches (or point at them).
#    (`install -t` is GNU-only; this form also works with busybox on Alpine.)
sudo mkdir -p /etc/calyanti/rules
sudo install -m644 watcher/rules/*.rules /etc/calyanti/rules/

# 2. Install the program:
sudo install -Dm755 watcher/calywatch.py /usr/bin/calywatch

# 3. Write a minimal config:
sudo tee /etc/calyanti/calywatch.conf >/dev/null <<'EOF'
ban_backend = auto
allow       = 203.0.113.10           # your admin box — TIGHTEN this
[source /var/log/nginx/access.log]
rules = nginx
[source /var/log/nginx/error.log]
rules = nginx
[source journal:sshd]
journal = sshd.service
rules = sshd generic
EOF

# 4. Check it, then run in the foreground to watch it work:
calywatch -c /etc/calyanti/calywatch.conf test-config
calywatch -c /etc/calyanti/calywatch.conf -f --dry-run
```

Run with `--dry-run` for a few days first. It evaluates every rule and logs
exactly what it *would* ban, without touching a single backend. Tune thresholds
against your own traffic, then drop `--dry-run`.

---

## Configuration — `calywatch.conf`

Same syntax as the rule files: `#`/`;` comments, `key = value`, and
`[section]` headers. Keys before the first section are global; `[source ...]`
sections describe what to tail.

Values follow the same conventions as `calyanti.conf`:

- **booleans:** `yes/no`, `true/false`, `on/off`, `1/0`
- **durations:** `ns/us/ms/s/m/h/d/w`; a **bare integer is seconds**
  (so fail2ban's `600` and `-1` pass straight through)

### Global keys

| Key | Default | Meaning |
|---|---|---|
| `ban_backend` | `auto` | `auto`, `socket`, `calyctl`, `nft`, `ipset`, `dry-run`, `none` |
| `socket` | `/run/calyanti/calyanti.sock` | control socket path (repeatable) |
| `calyctl` | autodetected | path to `calyctl`/`calyanti-cli`/`calyanti` |
| `calyctl_ban` | `ban %a --ttl %ts --reason %r` | argv template; `%a` addr, `%t` secs, `%ts` secs, `%n` ns, `%r` reason, `%v` family |
| `calyctl_unban` | `unban %a` | argv template |
| `ban_ttl_base` | `15m` | first-offence ban TTL (rule `ttl` overrides per rule) |
| `ban_ttl_max` | `7d` | escalation ceiling |
| `ban_escalate_num` / `ban_escalate_den` | `3` / `2` | `next = ttl * num / den` |
| `max_bans_per_min` | `120` | hard cap on **new** bans/min (`0` = unlimited) |
| `ban_burst` | `240` | token-bucket burst for the cap |
| `refresh_min` | `60s` | minimum gap between re-asserting an active ban |
| `dry_run` | `no` | detect and log only, never call a backend |
| `protect_active_sessions` | `yes` | auto-allow peers of ESTABLISHED mgmt sessions |
| `mgmt_ports` | `22` | management ports; **22 is always included** |
| `never_ban_private` | `yes` | seed the allowlist with RFC1918/loopback/link-local |
| `allow` | *(empty)* | allowlist CIDRs/addresses (space or comma separated, repeatable) |
| `trusted_proxy` | *(empty)* | proxy CIDRs whose `X-Forwarded-For` may be believed |
| `state_path` | `/var/lib/calyanti/calywatch.state` | persisted offender state |
| `state_save` | `30s` | how often to flush state |
| `gc_interval` | `30s` | idle-tracker sweep period |
| `log_level` | `info` | `err`/`warn`/`info`/`debug` |
| `log_target` | `auto` | `auto`/`stderr`/`syslog`/`<path>` |
| `rules_dir` | see below | directories to search for named rule sets (comma separated) |

Rule-set search order: `rules_dir` entries, then `/etc/calyanti/rules`,
`/etc/calyanti/watcher/rules`, `/usr/share/calyanti/rules`,
`/usr/local/share/calyanti/rules`.

### `[source ...]` sections

The word after `source` is the file path (or a label if you use the `glob =` /
`journal =` keys):

```ini
# tail one file
[source /var/log/nginx/access.log]
rules = nginx

# a glob — new matching files are picked up automatically
[source vhosts]
glob  = /var/log/nginx/*access*.log
rules = nginx

# the systemd journal for one or more units
[source ssh]
journal = sshd.service,ssh.service
rules   = sshd generic

# start from the beginning of the file instead of tailing the end
[source /var/log/secure]
rules        = generic sshd
start_at_end = no
```

`rules =` names one or more rule sets (repeatable, and space/comma separated).
A source with no valid rule set is skipped with a warning; the rest keep
running.

You can also add allowlist/trusted-proxy entries in block form:

```ini
[allow]
198.51.100.0/24
2001:db8:1::/48

[trusted_proxy]
10.0.0.0/8
```

---

## Rule file format

A rule file is the same lexer as the config. Keys **before** the first
`[section]` are the file header (defaults inherited by every rule); each
`[name]` starts a rule.

### Rule properties

| Key | Default | Meaning |
|---|---|---|
| `desc` | — | free text |
| `enabled` | `yes` | set `no` to ship a rule off by default |
| `prefilter` | — | literal substring; if any is present the regexes are tried. Repeatable. Pure speed optimisation — a line failing every prefilter is skipped before any regex runs |
| `regex` | *(required)* | Python regex, repeatable (**any** may match). Must contain a named group for the address |
| `ip_group` | `ip` | name of the capture group holding the client address |
| `xff_group` | — | name of the group holding `X-Forwarded-For` (consulted only for trusted proxies) |
| `match` | — | `<group> <op> <value>`, repeatable, **all** must hold. Ops: `~ !~ == != >= <= > <  in  !in` |
| `distinct` | — | count **distinct** values of this group (tumbling window) instead of occurrences |
| `threshold` | `1` | occurrences (or distinct values) that trip the rule |
| `window` | `60s` | sliding window for occurrence counting |
| `weight` | `1` | each match counts this much toward the threshold |
| `cooldown` | = `window` | minimum gap between two firings for one key |
| `action` | `ban` | `ban` / `warn` / `count` / `ignore` |
| `ttl` | global base | base ban TTL for this rule |
| `reason` | rule name | short tag recorded with the ban (`[A-Za-z0-9_.:@-]`) |
| `severity` | `5` | 0–9, informational only |
| `max_tracked` | `65536` | hard cap on tracked source keys for this rule (LRU) |

### Actions

- **`ban`** — install a ban through the backend chain (allowlist + rate cap
  apply first).
- **`warn`** — log at WARNING when the threshold trips, but do **not** ban. Good
  for a new rule you are still calibrating.
- **`count`** — match and tally, take no action. Useful as a building block or
  for pure observation.
- **`ignore`** — a *positive* signal. When it matches, the source's counters are
  cleared across the whole rule set and the address is soft-allowed for `ttl`.
  This is how "a successful login forgives earlier failures" is expressed. All
  `ignore` rules are evaluated **before** the counting rules on every line.

### Match operators

| Op | True when |
|---|---|
| `~` / `!~` | the group value matches / does not match the regex |
| `==` / `!=` | the group value equals / differs from the literal string |
| `>= <= > <` | numeric comparison (value parsed as a float) |
| `in` / `!in` | the value is / is not in a comma-separated set |

A **missing** capture group makes a positive condition fail and a negative
condition pass — the conservative reading, which never manufactures a ban.

### Worked example

```ini
name   = nginx
window = 60s
action = ban

[nginx-4xx-storm]
desc      = 4xx error storm (enumeration / broken bot)
prefilter = "
regex     = ^(?P<ip>[0-9A-Fa-f:.]{3,45}) \S+ \S+ \[[^\]]+\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3})
match     = status ~ ^4(?:0[0-9]|1[0-8]|2[0-9])$
match     = status !~ ^40[18]$          # 401/408 are not enumeration
threshold = 80
window    = 60s
ttl       = 30m
reason    = http-4xx-storm
```

Test any line against every rule without touching the network:

```sh
calywatch test-line '1.2.3.4 - - [23/Jul/2026:20:02:13 +0000] "GET /.env HTTP/1.1" 404 5 "-" "-"'
```

### Sliding-window implementation

Occurrence counting is a `deque` of monotonic timestamps whose `maxlen` is the
threshold, so memory per key is bounded, the count can never exceed the
threshold, and there is **no per-line rescan**. Distinct counting uses a
tumbling window with a capped set, mirroring the dataplane's 512-bit Bloom
filter: it undercounts on eviction, and undercounting biases toward *not*
banning — the safe direction.

---

## Ban backends and the fallback chain

`ban_backend = auto` builds this chain and uses the best one that accepts each
ban; a backend that fails is skipped for a short cooldown and the next is tried,
so a daemon restart degrades to `nft` rather than losing the ban.

1. **`socket`** — an `AF_UNIX` control socket to the `calyanti` daemon, which
   programs `caly_ban4`/`caly_ban6` directly. Speaks a small newline-delimited
   JSON protocol, with a plain-text (`BAN <ip> <secs> <reason>`) fallback for a
   daemon that answers non-JSON.
2. **`calyctl`** — the project CLI (`calyctl` / `calyanti-cli` / `calyanti`),
   invoked with a configurable but shell-free argv template.
3. **`nft`** — a dedicated `table inet calywatch` with timeout-flagged sets and
   an **accept-first** rule for the management ports, so even a runaway watcher
   with an empty allowlist cannot lock SSH out. It never touches the table the
   nftables dataplane rung installs.
4. **`ipset` + `iptables`** — a timeout-enabled `hash:ip` set and a dedicated
   `CALYWATCH` chain that `RETURN`s the management ports before the set match.

`dry-run` logs would-be bans and touches nothing. `none` disables banning
entirely (detection-only).

The `nft` and `ipset` fallbacks program **their own** management-port bypass, so
they honour the same invariant the dataplane does: *TCP/22 (and any configured
`mgmt_ports`) always survives.*

---

## Escalating bans and persisted state

Each offender is remembered with an offence count. The first ban uses
`ban_ttl_base` (or the rule's `ttl`); each subsequent offence multiplies the TTL
by `ban_escalate_num / ban_escalate_den`, clamped to `ban_ttl_max` — the exact
arithmetic the kernel autobanner uses.

State is persisted as line-delimited JSON (atomic temp-file + rename, mode
`0600`). On restart, bans that are still valid are **re-asserted** to the backend
(so volatile `nft`/`ipset` sets survive a reboot), and expired ones are simply
forgotten — never re-applied. Long-idle, inactive records are pruned from the
file so it cannot grow without bound.

---

## Management-session protection and the allowlist

Two independent safety nets protect the operator:

1. **The allowlist** (`allow`), checked immediately before **every** ban. With
   `never_ban_private = yes` (the default) it is pre-seeded with RFC1918,
   loopback, CGNAT and link-local ranges.
2. **Active-session protection** (`protect_active_sessions = yes`). Every few
   seconds `calywatch` reads `/proc/net/tcp{,6}` and auto-allowlists the peer of
   every **ESTABLISHED** connection to a management port. The SSH session you
   are typing in therefore cannot be banned by the log noise it produces — even
   before you have written a single `allow` line.

Combined with the dataplane forcing TCP/22 into `fw_config.mgmt_tcp_ports` in
every mode, there is no configuration in which `calywatch` locks you out.

---

## X-Forwarded-For and trusted proxies

If you sit behind a load balancer or CDN, the direct peer is the proxy, not the
client. Two correct options:

- **Best:** make your web server log the real client (nginx `ngx_http_realip`,
  Apache `mod_remoteip`) so `%h`/`$remote_addr` is already the true address, and
  ignore XFF entirely here.
- **Otherwise:** log `X-Forwarded-For`, give the rule an `xff_group`, and list
  your proxy ranges in `trusted_proxy`. `calywatch` believes the forwarded chain
  **only** when the direct peer is a trusted proxy, and then bans the rightmost
  address in the chain that is *not itself* a trusted proxy — the last hop an
  attacker cannot forge past. Without trust, a forged `X-Forwarded-For` is
  ignored completely.

A `trusted_proxy` member is **never itself a ban target** — it is treated as
allowlisted, checked at the same choke point as `allow`. A shared proxy/CDN
egress address fronts *every* client behind it, so banning it would be a
self-inflicted outage for all of them. This matters because several web rules
(4xx storms, path scans, suspicious paths, bad user-agents, WordPress rules)
cannot carry an `xff_group` and so resolve their target to the direct peer,
which behind a proxy *is* the proxy: guarding `trusted_proxy` at the ban choke
point means those rules simply take no action behind a proxy rather than banning
it. Behind a proxy, prefer real-client logging (`ngx_http_realip` /
`mod_remoteip`) so every rule sees the true client and can act on it.

---

## journald input

Give a `[source]` a `journal =` key (one or more units, comma-separated) and
`calywatch` follows them with `journalctl -f -o short-iso`. `short-iso` (not
`cat`) is used so the `<timestamp> <host> <identifier>[pid]:` prefix is kept:
`cat` prints only the bare `MESSAGE` and drops the `sshd[123]:` / `vsftpd[123]:`
identifier, which rules that key on the daemon name need. All rule regexes are
unanchored, so the prefix changes nothing for content matches. Unit names are validated
against a conservative character class before they are ever placed in the argv,
so a hostile `journal =` value can contribute neither an option nor a shell
metacharacter. If `journalctl` exits, it is respawned with capped backoff.

```ini
[source ssh]
journal      = sshd.service
rules        = sshd
journal_args = _SYSTEMD_UNIT=sshd.service   # optional extra matchers
```

---

## Command-line interface

```
calywatch [global options] <command>

global: -c/--config PATH   -f/--foreground   --log-level L   --log-target T
        --state PATH        --dry-run          --backend B     --rules-dir DIR

commands:
  run                     tail and enforce (default)
  ban <ip> [--ttl T] [--reason R]   ban one address via the backend chain
  unban <ip>              remove one address from the ban maps
  test-config             parse config + rules and exit non-zero on error
  list-rules              print every loaded rule
  status                  probe backends, print a JSON status summary
  test-line <line...>     show which rules a literal line matches
  selftest                run internal self-tests (no privileges, no side effects)
  emit-fail2ban-action    print the fail2ban action.d/calyanti.conf
  emit-fail2ban-jail      print an example fail2ban jail snippet
```

`calywatch selftest` exercises the parsing, IP-validation, escalation,
rate-limit, rotation and persistence paths with no privileges and no side
effects — packagers can gate a build on it.

---

## fail2ban integration

Already running fail2ban? Route its bans into the XDP blocklist instead of
iptables, and keep your existing filters and jails:

```sh
calywatch emit-fail2ban-action | sudo tee /etc/fail2ban/action.d/calyanti.conf
calywatch emit-fail2ban-jail                     # example jail.local snippet
```

Then set `banaction = calyanti` (or `action = calyanti`) on any jail. fail2ban's
`actionban` calls `calywatch ban <ip> --ttl <bantime> --reason fail2ban-<name>`
as a literal argv; `calywatch` re-validates `<ip>` with `ipaddress` before it
touches any backend, so even a hostile value cannot become a shell fragment or
an unvalidated target. fail2ban and standalone `calywatch` coexide happily —
both ultimately call the same backend chain and de-duplicate in the ban map.

---

## Running under systemd / OpenRC

**systemd** (`/etc/systemd/system/calywatch.service`):

```ini
[Unit]
Description=Caly Anti layer-7 log watcher
After=network.target calyanti.service
Wants=calyanti.service

[Service]
Type=simple
ExecStart=/usr/bin/calywatch -c /etc/calyanti/calywatch.conf --foreground
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
# Least privilege: it needs to read logs, program nft/ipset, and read
# /proc/net/tcp. It does not need full root.
User=root
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/calyanti /run/calyanti
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Use `--foreground` under a service manager so logs go to the journal and the
process does not double-fork.

**OpenRC / Alpine** — run `/usr/bin/calywatch -c /etc/calyanti/calywatch.conf -f`
under `supervise-daemon`; there is no daemonisation flag to worry about.

---

## Shipped rule sets

| File | Point it at | Covers |
|---|---|---|
| `rules/nginx.rules` | nginx access **and** error logs | request floods, 4xx/5xx storms, slowloris (stock + `$request_time`), path scans, traversal/injection, WordPress `xmlrpc`/login/enum, bad user-agents, `limit_req`, TLS abuse |
| `rules/apache.rules` | Apache access **and** error logs | the same web attacks plus mod_auth brute force, `File does not exist` storms, malformed requests, the 2.4.49/2.4.50 traversal CVE |
| `rules/sshd.rules` | `auth.log` / `secure` / `journalctl -u sshd` | password brute force, invalid-user and distinct-username enumeration, MaxAuthTries, pre-auth key-scanning, bad-protocol probes, policy denials, PAM failures. Includes a success rule that clears strikes |
| `rules/generic.rules` | `auth.log` / `secure` / `maillog` / journald | PAM, Postfix SASL/RCPT, Dovecot, Exim, FTP (vsftpd/ProFTPD/Pure-FTPd), MySQL/PostgreSQL/Redis, OpenVPN/WireGuard, control panels, kernel martian/netfilter logs |

Several rules ship `enabled = no` because they need a non-default log format
(e.g. `$request_time`/`%D` for exact slowloris, martian logging for the kernel
rules). Blocks marked **### TIGHTEN ###** carry concrete guidance: the shipped
thresholds are deliberately *generous* so a busy site does not self-ban on day
one. Watch `--dry-run` output for a week, then set thresholds to roughly 4× your
observed per-client p99.

---

## Signals

| Signal | Effect |
|---|---|
| `SIGHUP` | reload every rule set (a file that fails to parse keeps its old copy; counters for surviving rules are preserved) |
| `SIGUSR1` | log a one-line stats summary immediately |
| `SIGTERM` / `SIGINT` | flush state and shut down cleanly |

---

## Troubleshooting

- **"no ban backend probed OK"** — none of socket/calyctl/nft/ipset were usable
  at startup. The chain is still retried on demand; check that the daemon socket
  exists or that `nft`/`ipset` are installed. `calywatch status` prints what was
  found.
- **A rule never fires** — run `calywatch test-line '<a real log line>'`. If it
  shows `matched-regex-but-condition-failed`, a `match =` clause is excluding it;
  if nothing matches, the `regex`/`prefilter` does not fit your log format.
- **"rule … disabled: regex too slow"** — a rule's regex repeatedly blew the
  per-line time budget (likely catastrophic backtracking). Simplify it; the
  auto-disable protects the event loop from a ReDoS in your own rules.
- **It banned something it should not have** — add the address/prefix to `allow`
  (or `[allow]`), then `calywatch unban <ip>`. Consider whether a `trusted_proxy`
  entry is missing and a real client IP is being read from a proxy hop.
- **Nothing is banned but detections are logged** — you are in `--dry-run` (or
  `dry_run = yes`, or `ban_backend = none`). That is the recommended way to
  calibrate; remove it when the thresholds look right.
```
