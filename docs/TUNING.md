# Caly Anti — Tuning

How to size thresholds for *your* server, how to read the counters, how to tell
an attack from a launch day, and three worked examples.

The shipped defaults are **safe, not tight**. They are sized so that a fresh
install on a machine nobody has profiled will not drop legitimate traffic. That
also means a small botnet will walk straight through them. Tuning is not
optional; it is the deployment.

The one rule that matters: **never tighten blind.** Every threshold in this
document is derived from a measurement you take on your own box.

---

## Contents

- [1. The tuning loop](#1-the-tuning-loop)
- [2. Reading the statistics](#2-reading-the-statistics)
- [3. Telling an attack from a traffic spike](#3-telling-an-attack-from-a-traffic-spike)
- [4. Sizing the per-source token buckets](#4-sizing-the-per-source-token-buckets)
- [5. Sizing the ban policy](#5-sizing-the-ban-policy)
- [6. Sizing port-scan detection](#6-sizing-port-scan-detection)
- [7. Sizing the global gauges and mode escalation](#7-sizing-the-global-gauges-and-mode-escalation)
- [8. Port policy and default deny](#8-port-policy-and-default-deny)
- [9. Conntrack timeouts](#9-conntrack-timeouts)
- [10. Memory and CPU](#10-memory-and-cpu)
- [11. Worked example: web server](#11-worked-example-web-server)
- [12. Worked example: game server](#12-worked-example-game-server)
- [13. Worked example: DNS resolver and authoritative server](#13-worked-example-dns-resolver-and-authoritative-server)
- [14. Things not to do](#14-things-not-to-do)

---

## 1. The tuning loop

```
  monitor_only = yes
        |
        v
  run for 7 days across a full weekly cycle  <---------------+
        |                                                    |
        v                                                    |
  calyanti-cli stats / top / events                          |
        |                                                    |
        v                                                    |
  is anything in the would-drop breakdown legitimate? --yes--+
        |                                                (fix the rule)
        no
        |
        v
  set thresholds to ~4x observed p99
        |
        v
  monitor_only = no ; reload
        |
        v
  watch drop_total for 48h; any legitimate drop -> loosen and repeat
```

Seven days, not one. A weekly cycle catches the Monday-morning login storm, the
Sunday-night backup window, and the cron job that only runs on the first of the
month — all of which look exactly like attacks to a limiter sized off a
Wednesday afternoon.

While `monitor_only = yes`:

- every rule is evaluated;
- the verdict that *would* have been returned is recorded;
- `monitor_would_drop` (stat code 4) is charged in addition to the specific
  reason code, so the per-reason breakdown is complete;
- nothing is dropped.

---

## 2. Reading the statistics

```sh
calyanti-cli stats            # snapshot, packets and bytes per reason
calyanti-cli stats --watch    # refreshed in place
calyanti-cli stats --json     # for your metrics pipeline
calyanti-cli top -n 20        # busiest sources
calyanti-cli events --follow  # sampled per-packet detail
```

### The counter space

There are 109 counters (`STAT_MAX`), each with a packet count in `caly_stats`
and a byte count in `caly_stats_b`, both per-CPU and therefore exact. The
counter is charged exactly once per packet, immediately before the verdict is
returned.

| Code range | Group | Meaning |
|---|---|---|
| 0-4 | aggregates | `pkt_total`, `pass_total`, `drop_total`, `tx_total`, `monitor_would_drop` |
| 5-18 | pass reasons | why a packet was explicitly allowed |
| 19-40 | parse and structure | truncation, `ihl`, `tot_len`, `doff`, tunnels, unknown L3/L4 |
| 41-48 | address anomalies | LAND, bogon, private, multicast/broadcast source, `src_self` |
| 49-52 | fragments | tiny, `frag_off == 1`, policy, fragmented ICMP |
| 53-61 | TCP flags | null, FIN-only, SYN+FIN, SYN+RST, FIN+RST, xmas, all-flags, `doff`, unsolicited SYN-ACK |
| 62-65 | ICMP | type policy and oversize, v4 and v6 |
| 66-68 | reputation | blocklist, active ban, lockdown |
| 69 | amplification | `drop_amp_srcport` |
| 70-72 | port policy | closed, per-port rate, default deny |
| 73-79 | per-source buckets | pps, bps, syn, udp, icmp, newconn, global-syn fallback |
| 80 | scan | `drop_portscan` |
| 81-88 | SYN proxy | cookie generation, TX, validation, `drop_syncookie_bad` |
| 89-94 | conntrack | created, hit, miss, updated, full, closed |
| 95-99 | bans | added, escalated, refreshed, full, strike added |
| 100-108 | self-diagnostics | map full, event emitted/sampled/lost, tail-call fail, scratch fail, config missing |

Drop reasons are codes **19-80 inclusive, plus 86** (`drop_syncookie_bad`).
Everything else is a pass, a transform, or an accounting counter. The CLI's
drop breakdown uses exactly that predicate.

### The five counters to alert on

| Counter | Normal | What a rise means |
|---|---|---|
| `drop_total` (2) | small fraction of `pkt_total` | the obvious one; always look at the breakdown beneath it |
| `ct_full` (93) | 0 | `max_conn_entries` too small, or a connection flood. LRU is evicting live flows |
| `event_lost` (105) | 0 | the event ring is overflowing. Raise `event_pages` or lower `log_sample_rate` |
| `scratch_fail` (107) | 0 | should be impossible. Packets are passing unfiltered. File a bug |
| `config_missing` (108) | 0 | the config map is empty and **everything is passing**. The daemon is not running or failed to populate |

`scratch_fail` and `config_missing` are fail-open paths. They mean you are
unprotected, and they are loud precisely so you notice.

### The self-diagnostic counters worth watching under load

| Counter | Meaning | Fix |
|---|---|---|
| `map_full_rate` (100) | `caly_rate4/6` insert pressure | raise `max_rate_entries`, or accept LRU eviction (which is the design) |
| `map_full_scan` (101) | scan-state pressure | raise `max_scan_entries` or `scan_idle_timeout` down |
| `ban_full` (98) | ban table under pressure | raise `max_ban_entries`; the LRU evicts the coldest ban |
| `tailcall_fail` (106) | tail call to an empty slot | expected on kernels < 5.15 with `synproxy = yes`; otherwise a bug |
| `synproxy_unavailable` (87) | wanted, but the helper is missing | expected below 5.15. Confirm with `calyanti-cli status` |
| `event_sampled_out` (104) | sampling or `log_max_pps` suppressed an event | normal under load; distinguishes sampling from `event_lost` |

### Converting counters to rates

The counters are monotonic. Rates are differences:

```sh
# crude but effective
A=$(calyanti-cli stats --json | jq '.counters.pkt_total.packets'); sleep 10
B=$(calyanti-cli stats --json | jq '.counters.pkt_total.packets')
echo "$(( (B - A) / 10 )) pps"
```

The daemon does this internally every `stats_interval` (default 1 s) to drive
mode escalation, and it is what `calyanti-cli stats --watch` displays.

### Reading `top`

```
SOURCE               PKTS      BYTES     DROPS   DROP%  LAST REASON       AGE
198.51.100.7      412,001    58.1 MB   401,552   97.5%  drop_rate_udp     4s
203.0.113.44       98,220    12.0 MB         0    0.0%  pass_conntrack    1s
```

`top` reads `caly_top4`/`caly_top6`, which is reporting-only — nothing in the
drop path reads it, so turning `src_stats = no` costs you visibility and buys
you one LRU update per packet.

A **high drop percentage on a single source** is a rate-limited attacker. A
**low drop percentage spread over thousands of sources** is either a botnet or
a real traffic event, and section 3 is how you tell them apart.

---

## 3. Telling an attack from a traffic spike

This is the judgement call that no threshold can make for you. The signals,
roughly in order of reliability:

| Signal | Attack | Legitimate spike |
|---|---|---|
| **Source cardinality vs. rate** | rate rises much faster than distinct sources (few sources, huge rate) or distinct sources explode with each doing tiny volume (spoofed) | both rise together, proportionally |
| **Source address distribution** | clustered in a handful of ASNs or hosting ranges, or uniformly random across the whole v4 space (spoofing) | matches your normal geographic and ASN mix |
| **`newconn` to `pkt_total` ratio** | close to 1 — every packet starts a new flow | low; real clients reuse connections |
| **`ct_hit` fraction** | collapses; almost nothing matches existing state | stays high |
| **Packet size distribution** | uniform, often exactly 64 B or exactly MTU | the usual bimodal mix |
| **Which reason codes fire** | anomaly codes (19-61) appear at all | anomaly codes stay near zero |
| **Time profile** | instantaneous step to a plateau, ends abruptly | ramps over minutes, follows a daily curve |
| **Port distribution** | one port, or thousands of ports | your actual services |
| **TTL distribution** | one or two distinct values | a wide spread from real internet paths |
| **Correlates with something** | nothing | a deploy, a campaign, a news mention, a partner's cron |
| **Application health** | backend fine, network saturated | backend latency rises with load |

The two decisive ones in practice:

1. **Anomaly counters are near-zero in legitimate traffic.** If
   `drop_tcp_null`, `drop_tcp_xmas`, `drop_land`, `drop_bogon_src`,
   `drop_frag_off_one` or `drop_ip6_src_unspec` are non-zero at any meaningful
   rate, somebody is generating packets by hand. Real stacks do not emit those.
2. **A real spike keeps `ct_hit` high.** Legitimate clients reuse connections
   and their replies match existing state. A flood has no state; every packet
   is a conntrack miss. Watch the ratio `ct_hit / (ct_hit + ct_miss)`.

```sh
# The single most useful one-liner during an incident:
calyanti-cli stats --json | jq -r '
  .counters | to_entries
  | map(select(.value.packets > 0))
  | sort_by(-.value.packets)[:15][]
  | "\(.value.packets)\t\(.key)"'
```

The top of that list tells you what is happening in one screen.

### When it is a legitimate spike

Do not tighten. Raise the affected limit, or move the traffic behind conntrack
by making sure the port is `open` rather than `ratelimit`, and note the new
observed peak for the next tuning round.

### When it is an attack

Let the daemon escalate — that is what the global gauges are for. If it has
not, and you are certain:

```sh
calyanti-cli mode under-attack
```

and when it is over:

```sh
calyanti-cli mode normal        # returns control to the automatic escalator
```

`lockdown` is the emergency stop: allowlist, management ports and established
conntrack only. It will drop legitimate new connections. Use it when the
alternative is the box falling over.

---

## 4. Sizing the per-source token buckets

Six buckets per source, indexed by `enum caly_tb_kind`. Each has a `rate`
(sustained units per second) and a `burst` (bucket depth). Refill is exact to
the nanosecond, integer only, with the sub-token remainder carried in
`last_refill_ns` so slow rates stay exact over hours.

| Bucket | Config keys | Unit | Default rate | Default burst |
|---|---|---|---|---|
| `CALY_TB_PPS` | `rate_pps`, `rate_pps_burst` | packets/s | 200k | 400k |
| `CALY_TB_BPS` | `rate_bps`, `rate_bps_burst` | **bytes**/s | 250m (2 Gbit/s) | 500m |
| `CALY_TB_SYN` | `rate_syn`, `rate_syn_burst` | packets/s | 2k | 4k |
| `CALY_TB_UDP` | `rate_udp`, `rate_udp_burst` | packets/s | 50k | 100k |
| `CALY_TB_ICMP` | `rate_icmp`, `rate_icmp_burst` | packets/s | 200 | 400 |
| `CALY_TB_NEWCONN` | `rate_newconn`, `rate_newconn_burst` | flows/s | 500 | 1k |

**Byte rates are bytes, not bits.** `125m` is 125 MB/s is 1 Gbit/s. This trips
people up constantly.

**Rate 0 or burst 0 disables that bucket** and it always conforms. A
misconfigured limiter must never black-hole traffic, so "0" means "off", not
"deny everything".

### The sizing method

1. Run `monitor_only = yes` for a week.
2. Take the **99th percentile per-source** rate for each bucket — not the mean,
   and not the maximum. The mean is dominated by the long tail of clients that
   send one request; the maximum is whichever scraper had a bad afternoon.
3. Set `rate = 4 x p99`.
4. Set `burst = 2 x rate`, i.e. two seconds of sustained traffic.

The 4x factor is empirical: it survives a legitimate client doubling its rate
twice over without a strike, while still catching an attacker who needs orders
of magnitude more to hurt you. If your traffic is unusually bursty (mobile
clients, CDN origin pulls, backup windows) use 8x for `pps` and `bps` and keep
4x for `syn`, `udp` and `newconn`.

Extracting p99 from the event stream:

```sh
# Collect an hour of sampled events, then find the per-source packet-rate p99.
calyanti-cli events --json --follow > /tmp/ev.jsonl &
sleep 3600; kill %1

jq -r '.saddr' /tmp/ev.jsonl | sort | uniq -c | sort -rn \
  | awk '{print $1}' | sort -n \
  | awk '{v[NR]=$1} END {print "p99 events/hr per source:", v[int(NR*0.99)]}'
```

Remember that events are sampled at `log_sample_rate` (default 1 in 100), so
multiply accordingly, and prefer `calyanti-cli top --json` for exact per-source
totals.

### What "burst" actually buys you

A source sending at rate `R` against a limit `L` with a bucket depth `B` runs
out of tokens after:

```
t = B / (R - L)      seconds        (only when R > L)
```

So the default `rate_pps = 200k`, `rate_pps_burst = 400k` lets a source
sending 400 kpps run for 400000/(400000-200000) = 2 seconds before it starts
taking strikes. With `strike_limit = 10`, it takes another handful of
over-limit packets to earn a ban — which happens in microseconds at that rate.

A source sending *below* the limit never takes a strike, no matter how long it
runs. That is the point of a token bucket and it is why bursts should be
generous: they absorb legitimate short spikes without ever touching a sustained
attacker.

### Why the limiters are not per-CPU

`caly_rate4/6` and `caly_port_tb` are shared LRU/array maps, deliberately. A
per-CPU token bucket would multiply the effective limit by the CPU count, and
RSS spreads one attacker across every queue — a 64-core box would enforce 64x
the configured rate. The cost is a benign read-modify-write race that can let a
couple of extra packets through. Statistics, which must be exact, live in
per-CPU maps instead.

Practical consequence: **do not divide your limits by core count.** The number
you configure is the number that is enforced.

### The management bypass

`mgmt_bypass_ratelimit = yes` (default) exempts management ports from all six
buckets. That is the safe answer: a rate-limit misconfiguration, or an attacker
deliberately burning your per-source budget, cannot throttle you out of your
own SSH session. The exposure is that SSH is then unprotected by Caly Anti;
mitigate with key-only authentication and by putting your admin networks in the
allowlist and closing 22 to everyone else at the port-policy level.

---

## 5. Sizing the ban policy

Exceeding a bucket does not drop the packet on its own. It costs the source a
**strike**. Accumulate `strike_limit` strikes inside `strike_window` and the
source is banned for `ban_ttl_base`, escalating on repeat offences.

```ini
strike_limit     = 10
strike_window    = 60s
ban_ttl_base     = 10m
ban_ttl_max      = 24h
ban_escalate_num = 2
ban_escalate_den = 1
ban_ttl_scan     = 1h
ban_ttl_amp      = 6h
```

Escalation is `next_ttl = ttl * num / den`, clamped to `[base, max]`:

| Offence | TTL with 2/1 | TTL with 3/2 | TTL with 1/1 |
|---|---|---|---|
| 1st | 10m | 10m | 10m |
| 2nd | 20m | 15m | 10m |
| 3rd | 40m | 22m | 10m |
| 4th | 80m | 33m | 10m |
| 5th | 160m | 50m | 10m |
| ... | capped at 24h | capped at 24h | flat |

Set `num = den` to disable escalation and use a flat `ban_ttl_base`.

### Choosing the numbers

| Situation | `strike_limit` | `ban_ttl_base` | Rationale |
|---|---|---|---|
| Public web/API, mixed clients | 10-20 | 5-10m | forgiving; NAT gateways share one address and one bad actor behind a corporate NAT should not ban the office |
| Behind a CDN (only CDN IPs reach you) | **autoban off** | n/a | banning a CDN edge is a self-inflicted outage. Allowlist the CDN ranges and rate limit at the CDN instead |
| Game server, session-based | 20-40 | 2-5m | legitimate clients burst hard; a long ban ruins a match |
| SMTP, SSH-facing, mail relays | 5 | 1h | brute-force sources have no legitimate use for a second chance |
| UDP-heavy service exposed to spoofing | **autoban off**, or 30+ with a 60 s TTL | 1m | see below |

### When to turn `autoban` off

Auto-banning by source IP is only sound when the source address is
**expensive to forge**. That is true for TCP after a completed handshake, and
essentially false for everything else.

Turn `autoban = no` (and rely on rate limiting, which is stateless with respect
to who you trust) when:

- your exposure is predominantly UDP and you have no upstream BCP38 filtering;
- your clients arrive through a small number of shared addresses — a CDN, a
  corporate NAT, a mobile carrier CGNAT — where one ban affects thousands;
- you feed bans from application logs that contain attacker-controlled headers
  (see [SECURITY.md](SECURITY.md), and do not do this).

Rate limiting degrades gracefully under spoofing: a forged source burns its own
bucket and nothing else. Banning does not: a forged source burns *the real
owner's* connectivity. [SECURITY.md](SECURITY.md#auto-ban-weaponisation) covers
the design mitigations in detail.

### Bans are always `/32` and `/128`

The dataplane never bans a prefix. The blast radius of a false positive is
exactly one address. If you want to block a prefix, that is `block =` in the
config, which is a deliberate operator action.

---

## 6. Sizing port-scan detection

```ini
portscan_detect     = yes
scan_port_threshold = 60
scan_window         = 30s
```

Per source, a 512-bit Bloom filter with two hash functions records the
destination ports touched inside the window. Two hashes and two word writes per
packet; no per-port table, no allocation.

### The Bloom filter has a hard ceiling, and you must respect it

With `m = 512` bits and `k = 2` hashes, the probability that a genuinely new
port is misread as already-seen is `(1 - e^(-kn/m))^k` after `n` distinct ports:

| Distinct ports seen | Chance a new port reads as "already seen" |
|---|---|
| 32 | 1.4% |
| 64 | 4.9% |
| 128 | 15.5% |
| 256 | 40% |
| 384 | 60% |

Collisions make the estimate **low**, which biases towards *not* banning — the
safe direction, by design. But it also means the `distinct` counter saturates:

**Do not set `scan_port_threshold` above about 150.** Above roughly 200 it
becomes very slow to reach and above 256 it may never be reached at all within
a window. Useful values are **40-80**.

### Tuning the window

| Value | Catches | Misses | False positives |
|---|---|---|---|
| `scan_window = 10s`, threshold 40 | fast `nmap -T4` sweeps | anything slower | rare |
| `scan_window = 30s`, threshold 60 (default) | most automated scanning | patient scanners | rare |
| `scan_window = 5m`, threshold 100 | slower sweeps | very slow scans | clients with many parallel connections to many ports |

A patient scanner at one port per minute is invisible to **any** windowed
detector, by construction. That is not a bug in this implementation; it is what
a sliding window is. If slow scanning matters to you, correlate in your SIEM
from the event stream, not in the dataplane.

Known false-positive sources: FTP in active mode, SIP/RTP media negotiation,
BitTorrent, some CDN health-check fleets, and any client that legitimately
opens connections to many high ports. Check `calyanti-cli top` for the banned
source before lowering the threshold.

---

## 7. Sizing the global gauges and mode escalation

The daemon samples the per-CPU gauges every `stats_interval`, differentiates
them into rates, and compares to these hysteresis pairs:

```ini
global_pps_high         = 4m
global_pps_low          = 2m
global_bps_high         = 1250m      # bytes/s = 10 Gbit/s
global_bps_low          = 800m
global_syn_pps_high     = 40k
global_syn_pps_low      = 15k
global_newconn_pps_high = 100k
global_newconn_pps_low  = 50k
attack_dwell            = 2m
```

Method:

1. Measure your normal peak for each gauge over a week
   (`calyanti-cli stats --watch`, or scrape the JSON into your metrics system).
2. `_high` = 3x normal peak. Below that you will escalate on Black Friday.
3. `_low` = 1.5x normal peak. **Keep a wide gap** between `_high` and `_low` or
   the policy will flap when the attack sits right on the threshold.
4. `attack_dwell` = the minimum time to stay escalated after the rates fall
   back. Two minutes is a good floor; it stops an attacker from probing the
   threshold to make you oscillate between policies.

`global_syn_pps_high` is the one that engages the SYN proxy. Size it off your
*normal* SYN rate, which for most services is a few hundred per second — 40k is
already three orders of magnitude above a small site. Bring it down.

What each mode changes:

| Mode | Effect |
|---|---|
| `normal` | configured thresholds |
| `elevated` | thresholds scaled down, event sampling raised so you get detail during the interesting part |
| `under-attack` | SYN proxy engaged on flagged ports, strict buckets |
| `lockdown` | allowlist, management ports and established conntrack only — everything else dropped |
| `monitor-only` | evaluate everything, drop nothing |

`lockdown` and `monitor-only` are manual. The daemon never enters or leaves
them on its own.

---

## 8. Port policy and default deny

Two 65536-entry arrays, one per protocol. A lookup is one bounds-checked index:
no hashing, no per-rule cost, so a thousand port rules cost exactly as much as
one.

```ini
tcp_port = 22    open
tcp_port = 443   ratelimit rate=50k burst=100k
udp_port = 443   ratelimit rate=50k burst=100k
tcp_port = 3389  closed
default_deny     = no
```

| Mode | Inbound behaviour |
|---|---|
| `closed` | dropped unless conntrack matches or the source is allowlisted |
| `open` | permitted, still subject to per-source buckets |
| `ratelimit` | permitted up to a **per-port** token bucket, independent of the per-source ones |

### Enabling `default_deny` safely

`default_deny = yes` is the single most valuable line in the config file, and
the one most likely to take your service down if you enable it carelessly.

```sh
# 1. Enumerate what actually listens:
ss -lntup | awk 'NR>1 {print $1, $5}' | sort -u

# 2. Write a rule for each one.
# 3. Run monitor_only for 24h and look for what you missed:
calyanti-cli stats --json | jq '.counters.drop_default_deny, .counters.drop_port_closed'
calyanti-cli events --follow | grep -E 'default_deny|port_closed'

# 4. Only then:
#    default_deny = yes ; calyanti-cli reload
```

Outbound-initiated traffic keeps working either way — that is exactly what
conntrack-lite is for — **provided the tc egress hook is attached**. Check:

```sh
calyanti-cli status | grep -o TC_EGRESS || echo "NO EGRESS HOOK: default_deny will break outbound UDP replies"
```

Without the egress hook, outbound-initiated UDP (DNS lookups, NTP syncs, QUIC)
has no inbound handshake to learn from, so its replies have no conntrack entry
and hit the closed-port rule. Either fix the egress hook, or leave the reply
paths open, or leave `default_deny = no`.

### The amplifier list and your own services

`caly_port_udp` is consulted twice, with different meanings:

- by **destination** port, for `port_rule.mode`;
- by **source** port, for `CALY_PORT_F_AMPLIFIER`.

They read different fields and never collide. That is what lets a real DNS
server coexist with the reflection filter: inbound queries arrive at `dport 53`
with `mode = open`, while spoofed reflection traffic arrives with `sport 53`
and is dropped.

You only need `amp_exempt` when you must accept **unsolicited** traffic *from*
one of those source ports — which is rare, because your own outbound queries
create conntrack state that exempts their replies automatically.

```ini
# You run an authoritative DNS server: NOT needed. dport 53 is what you serve.
# You have a legacy application that receives unsolicited UDP from source port
# 123 with no prior outbound packet: then, and only then:
amp_exempt = 123
```

---

## 9. Conntrack timeouts

```ini
ct_tcp_syn         = 60s
ct_tcp_established = 4h
ct_tcp_fin         = 30s
ct_udp             = 30s
ct_udp_stream      = 180s
ct_icmp            = 30s
ct_generic         = 60s
max_conn_entries   = 262144
```

An expired entry does not kill the session. Its next packet simply falls
through to the port policy. With `default_deny = off` that is a pass; with
`default_deny = on` it is a drop, so:

**If you run `default_deny = yes`, `ct_tcp_established` must exceed your
longest expected idle period.** A database connection pool that idles for six
hours behind a four-hour timeout will hang on the next query. Either raise the
timeout or keep the service port `open` rather than `closed`.

Sizing `max_conn_entries`: peak concurrent flows x 1.5. Watch `ct_full`
(counter 93); any non-zero value means the LRU is evicting live flows and the
table is too small. Each entry costs a 40-byte key plus a 64-byte value plus
hash overhead — call it 120 bytes.

`ct_udp_stream` applies once traffic has been seen in both directions; it is
longer than `ct_udp` because a one-way UDP burst deserves less state than a
real bidirectional session.

---

## 10. Memory and CPU

### Memory

Roughly **220 MB** of locked kernel memory at shipped defaults, dominated by
`caly_rate4/6` (524288 x ~160 B) and `caly_conn` (262144 x ~120 B).

| Knob | Default | Entry cost | Default footprint |
|---|---|---|---|
| `max_rate_entries` (x2 for v6) | 524288 | ~160 B | ~170 MB |
| `max_conn_entries` | 262144 | ~120 B | ~31 MB |
| `max_ban_entries` (x2) | 262144 | ~80 B | ~42 MB |
| `max_scan_entries` (x2) | 131072 | ~112 B | ~29 MB |
| `max_srcstat_entries` (x2) | 131072 | ~72 B | ~19 MB |
| `max_block_entries` (x2) | 262144 | ~40 B | ~21 MB |
| `caly_port_tcp/udp` | fixed 65536 each | 24 B | 3 MB |
| `caly_port_tb` | fixed 131072 | 16 B | 2 MB |

Those are ceilings, not allocations for the LRU maps in the sense that matters
to you — but they *are* preallocated by the kernel for hash maps without
`BPF_F_NO_PREALLOC`, so treat them as committed memory.

A small VPS profile, roughly 30 MB:

```ini
max_rate_entries    = 65536
max_conn_entries    = 65536
max_scan_entries    = 32768
max_srcstat_entries = 32768
max_ban_entries     = 65536
max_block_entries   = 65536
src_stats           = no
event_pages         = 4
```

`max_*_entries` are read **before map creation**. They take effect on daemon
restart, not on reload.

### CPU

Rough per-packet costs on a modern x86_64 core, native XDP:

| Path | Cost |
|---|---|
| Parse + anomaly checks, no map lookups | 15-30 ns |
| Plus allowlist LPM lookup | +30-60 ns |
| Plus conntrack hit | +40-80 ns |
| Full path with rate limiting and scan marking | 150-300 ns |
| Event emission (per emitted event) | +200-400 ns |

That is 3-7 Mpps per core for the full path. Measure it on your own hardware —
[BENCHMARKING.md](BENCHMARKING.md) shows how, using
`kernel.bpf_stats_enabled` and `bpftool prog show`.

The two knobs that buy the most CPU back:

1. `src_stats = no` — removes one LRU hash update per packet.
2. `log_sample_rate` — raise it. Under attack, `1` will cost you more CPU on
   logging than on filtering. `log_max_pps` is the hard ceiling that stops
   that; suppression is counted in `event_sampled_out` so you can tell it from
   loss.

---

## 11. Worked example: web server

nginx on 80/443, HTTP/3 on UDP/443, 5000 requests/s peak, behind no CDN, one
public interface.

**Measured baseline** (one week, `monitor_only = yes`):

| Metric | p50 | p99 | peak |
|---|---|---|---|
| per-source pps | 12 | 400 | 2,100 |
| per-source bps | 9 KB/s | 300 KB/s | 1.8 MB/s |
| per-source new connections/s | 1 | 25 | 90 |
| per-source SYN/s | 1 | 28 | 95 |
| global pps | — | — | 180k |
| global SYN/s | — | — | 5.2k |
| global newconn/s | — | — | 4.9k |

**Configuration:**

```ini
interface = eth0 zone=wan
default_zone = lan

allow = 203.0.113.0/24            # office
allow = 198.51.100.10/32          # monitoring

# 4x p99, burst = 2x rate
rate_pps           = 1600
rate_pps_burst     = 3200
rate_bps           = 1200k        # 1.2 MB/s ~ 4x the 300 KB/s p99
rate_bps_burst     = 2400k
rate_syn           = 120
rate_syn_burst     = 240
rate_udp           = 2000         # HTTP/3
rate_udp_burst     = 4000
rate_icmp          = 20
rate_icmp_burst    = 40
rate_newconn       = 100
rate_newconn_burst = 200

# Forgiving: a corporate NAT is one source address for a whole office.
strike_limit  = 20
strike_window = 60s
ban_ttl_base  = 5m
ban_ttl_max   = 6h

# 3x observed peak, 1.5x for the low mark
global_pps_high         = 540k
global_pps_low          = 270k
global_syn_pps_high     = 16k
global_syn_pps_low      = 8k
global_newconn_pps_high = 15k
global_newconn_pps_low  = 7k
attack_dwell            = 2m

tcp_port = 22   open
tcp_port = 80   ratelimit rate=200k burst=400k
tcp_port = 443  ratelimit rate=200k burst=400k
udp_port = 443  ratelimit rate=200k burst=400k     # QUIC
default_deny = yes

synproxy = yes
synproxy_port = 80
synproxy_port = 443

portscan_detect     = yes
scan_port_threshold = 50
scan_window         = 30s

ct_tcp_established = 4h
max_conn_entries   = 262144
```

**Why these choices:**

- The per-port rate limits (200k) are far above the per-source ones. They are a
  backstop against a distributed flood that stays under every individual
  source limit — exactly the case per-source limiting cannot catch.
- `synproxy_port` is restricted to 80 and 443 because SYN-proxying costs one
  extra round trip on every new connection. There is no reason to pay it on
  ports nothing floods.
- `strike_limit = 20` rather than 10: one address can be an entire office
  behind NAT.
- `default_deny = yes` is safe here because every listening service is
  enumerated and conntrack covers outbound-initiated flows.

**If you are behind a CDN**, invert this: allowlist the CDN's published ranges,
set `autoban = no`, and do the rate limiting at the CDN. Banning a CDN edge
node is a self-inflicted outage that will look like a CDN failure for the two
hours it takes you to find it.

---

## 12. Worked example: game server

A UDP game server: 32-128 players, 30-64 ticks/s, small packets, session-based,
extremely latency sensitive. Also the single most commonly attacked class of
host on the internet.

**Measured baseline:**

| Metric | p50 | p99 | peak |
|---|---|---|---|
| per-player pps (inbound) | 64 | 128 | 200 |
| per-player bps | 6 KB/s | 15 KB/s | 25 KB/s |
| players | — | — | 128 |
| global pps | — | — | 30k |

**Configuration:**

```ini
interface = eth0 zone=wan

udp_port = 27015 ratelimit rate=40k burst=80k     # game
tcp_port = 27015 ratelimit rate=1k  burst=2k      # rcon/query over TCP
tcp_port = 22    open
default_deny = yes

# 4x p99 with generous bursts: game clients are bursty on map load
rate_pps           = 512
rate_pps_burst     = 2048
rate_bps           = 60k
rate_bps_burst     = 240k
rate_udp           = 512
rate_udp_burst     = 2048
rate_newconn       = 20
rate_newconn_burst = 60
rate_icmp          = 10
rate_icmp_burst    = 20

# Very forgiving bans: a false positive drops a player mid-match.
autoban       = yes
strike_limit  = 40
strike_window = 30s
ban_ttl_base  = 2m
ban_ttl_max   = 1h

# 27015 is on the amplifier list because SRCDS query reflection is a real
# attack. You SERVE on dport 27015; the amplifier flag is about SOURCE port
# 27015, so leave it alone. Only exempt it if you consume another server's
# query responses unsolicited.
anti_amplification = yes

# Game clients open few ports; a scanning source is not a player.
portscan_detect     = yes
scan_port_threshold = 30
scan_window         = 60s

ct_udp        = 60s
ct_udp_stream = 300s          # a match lasts longer than 180s
max_conn_entries = 65536

global_pps_high = 90k
global_pps_low  = 45k
```

**Why these choices:**

- `ct_udp_stream = 300s`: a player who is alt-tabbed or spectating can go
  quiet for a couple of minutes. If the entry expires and `default_deny` is on,
  their next packet is dropped and they see a disconnect.
- `rate_pps_burst = 4 x rate`: map loads and round transitions produce a genuine
  burst. Sizing the burst tightly here is how you kick your own players.
- `strike_limit = 40` with a short TTL: the cost of a false positive (a player
  ejected mid-match, who then posts about it) is much higher than the cost of a
  few extra seconds of an attacker's traffic.
- Do **not** set `wan_drop_private = yes` if any of your players reach you over
  a CGNAT carrier — 100.64.0.0/10 is not private in the sense that matters.

**The honest caveat for game servers:** the attacks that actually take game
servers down are volumetric UDP floods measured in tens of Gbit/s, aimed at the
IP rather than the service. Those are won upstream. Caly Anti keeps the box
alive and the CPU free so that the game keeps running for whatever fraction of
the flood does not saturate your link; it does not create bandwidth. If your
host does not offer DDoS protection, that is the problem to solve first.

---

## 13. Worked example: DNS resolver and authoritative server

DNS is the trickiest case because port 53 is both the most abused amplifier and
a service you may legitimately run.

### Case A: authoritative server (you serve queries, you do not recurse)

Inbound queries arrive at **destination** port 53. Reflection traffic arrives
with **source** port 53. Those are different lookups in `caly_port_udp` and
they never collide, so:

```ini
interface = eth0 zone=wan

udp_port = 53 ratelimit rate=30k burst=60k
tcp_port = 53 ratelimit rate=5k  burst=10k     # TCP fallback and AXFR
tcp_port = 22 open
default_deny = yes

anti_amplification = yes
amp_exempt =                                    # LEAVE EMPTY. You serve
                                                # dport 53; you do not need
                                                # unsolicited sport 53.

# DNS clients send one or two queries. A source at 500 qps is a resolver farm
# or an attacker; 4x your measured p99 will be far below the port limit.
rate_udp       = 400
rate_udp_burst = 1600
rate_pps       = 500
rate_pps_burst = 2000

# Your own responses are what get reflected at victims. Rate limit responses
# per source so you are not the amplifier.
udp_port = 53 ratelimit rate=30k burst=60k

# Response Rate Limiting belongs in the DNS server too - this is not a
# substitute for BIND's RRL or Knot's rate limiting.
```

**Critically:** Caly Anti cannot stop *you* from being an amplifier. It filters
ingress. Configure Response Rate Limiting in the DNS server itself (BIND
`rate-limit`, Knot `mod-rrl`, NSD `rrl-ratelimit`) and refuse recursion from
the internet. The per-port ingress limit above caps how many queries reach the
daemon, which caps how many responses it can emit, but RRL is the correct
control and it is not optional.

### Case B: recursive resolver serving a known client population

```ini
interface = eth0 zone=wan
interface = eth1 zone=lan       # clients arrive here

# Only your networks may query.
allow = 10.0.0.0/8
allow = 2001:db8::/32

udp_port = 53 ratelimit rate=50k burst=100k
tcp_port = 53 ratelimit rate=10k burst=20k
default_deny = yes

# Your OUTBOUND queries to the internet create conntrack state, so the replies
# (which arrive with sport 53, i.e. matching the amplifier flag) are exempted
# automatically. This only works with the tc egress hook attached.
anti_amplification = yes
conntrack = yes
```

**This is the case that breaks if the egress hook is missing.** Your recursive
queries go out to the root and TLD servers, and the replies come back with
source port 53 — which is exactly the amplifier signature. They are exempted
because conntrack says you asked for them. Without the egress hook there is no
conntrack entry, and your own resolver's replies get dropped.

Check before enabling `anti_amplification` on a recursive resolver:

```sh
calyanti-cli status | grep -o TC_EGRESS \
  || echo "NO EGRESS HOOK - set amp_exempt = 53 or your recursion will break"
```

If you cannot get the egress hook (rung 4/5, or a kernel without clsact), then:

```ini
amp_exempt = 53
```

and accept that you have given up the DNS reflection filter on that host. That
is the honest trade; the alternative is a resolver that cannot resolve.

### Case C: you run neither, you are just a client

Leave everything at defaults. Your outbound lookups create conntrack state,
their replies match it, and unsolicited traffic claiming source port 53 gets
dropped. This is the case the defaults are built for.

---

## 14. Things not to do

- **Do not enable `default_deny` without enumerating your services first.**
  `ss -lntup`, then a rule per line, then 24 hours of `monitor_only`.
- **Do not enable `wan_drop_private` on a host behind NAT, in a cloud VPC with
  private addressing, or on a CGNAT provider network.** It will drop your own
  traffic. It ships off for that reason.
- **Do not set `min_ttl` unless you know every client is within N hops.** It is
  a blunt instrument that silently rejects distant but legitimate clients.
- **Do not set `log_sample_rate = 1` in production.** Under attack you will
  spend more CPU on logging than on filtering. `log_max_pps` limits the damage;
  do not rely on it.
- **Do not set `drop_all_fragments = yes` casually.** It breaks large DNS over
  UDP, some VPN encapsulation, and any path where PMTUD is already broken.
- **Do not divide your rate limits by core count.** The limiters are shared,
  not per-CPU. The number you configure is the number enforced.
- **Do not set `scan_port_threshold` above ~150.** The 512-bit Bloom filter
  saturates and the threshold becomes unreachable.
- **Do not remove TCP/22 from `mgmt_tcp_ports`.** The loader will put it back
  and reject the config that tried. If you moved SSH, *add* the new port.
- **Do not put a large network in the allowlist.** An allowlist hit bypasses
  every control in the suite. Keep it to the addresses you genuinely control.
- **Do not tune during an incident.** Escalate the mode, wait, then tune from
  the data afterwards. Threshold changes made at 3 a.m. under pressure are how
  outages become longer outages.
