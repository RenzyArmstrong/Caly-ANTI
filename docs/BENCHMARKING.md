# Caly Anti — Benchmarking

How to load-test the filter, measure per-packet cost, and generate attack
traffic **without taking yourself — or anyone else — down**.

Read [section 0](#0-rules-of-engagement) first. It is not optional and it is
not boilerplate. People melt production NICs and get abuse complaints filed
against their ASN because they pointed a packet generator at the wrong address.

---

## Contents

- [0. Rules of engagement](#0-rules-of-engagement)
- [1. Test topology](#1-test-topology)
- [2. What to measure](#2-what-to-measure)
- [3. Measuring per-packet cost in the dataplane](#3-measuring-per-packet-cost-in-the-dataplane)
- [4. Baseline line rate before you filter anything](#4-baseline-line-rate-before-you-filter-anything)
- [5. pktgen (in-kernel, highest packet rate)](#5-pktgen-in-kernel-highest-packet-rate)
- [6. trafgen (flexible, scriptable frames)](#6-trafgen-flexible-scriptable-frames)
- [7. hping3 (quick attack shapes)](#7-hping3-quick-attack-shapes)
- [8. MoonGen and TRex (line-rate, measured)](#8-moongen-and-trex-line-rate-measured)
- [9. Testing each control specifically](#9-testing-each-control-specifically)
- [10. Testing the SYN proxy](#10-testing-the-syn-proxy)
- [11. Reading the results](#11-reading-the-results)
- [12. Common mistakes that produce wrong numbers](#12-common-mistakes-that-produce-wrong-numbers)

---

## 0. Rules of engagement

1. **Test on an isolated network you own.** A lab VLAN, a crossover cable, a
   pair of VMs on a private bridge. Never on a shared segment and never across
   the public internet.
2. **Spoofed-source traffic must never leave your lab.** `--rand-source`,
   pktgen `flag IPSRC_RND`, and every spoofing feature in this document
   generate packets that will get your ASN reported for source-address forgery
   if they reach a real network. Test them air-gapped.
3. **A packet generator can saturate a NIC and its PCIe lane.** That affects
   every other function on the card and, on a shared host, every other tenant.
   Know your hardware's limit before you approach it.
4. **Get written authorisation for anything touching infrastructure you do not
   personally own** — including your cloud provider's network. Most providers'
   acceptable-use policies prohibit load testing that leaves your instance, and
   several will suspend the account first and ask later.
5. **Never point this at a production address, a third party, or "just to see".**
   There is no benign flood.
6. **Cloud instances have hypervisor-level shapers.** You will hit
   `bw_allowance_exceeded` / `pps_allowance_exceeded` long before you find the
   filter's limit, and the hypervisor's drops are invisible to XDP. Bare metal
   is the only place you can measure the dataplane's true ceiling.

If you cannot satisfy 1 and 2, stop. Use the `bpftool prog run` method in
[section 3](#3-measuring-per-packet-cost-in-the-dataplane) instead — it
measures per-packet cost with zero packets on any wire.

---

## 1. Test topology

Minimum viable, and safe:

```
  ┌────────────────────┐         ┌────────────────────┐
  │  GENERATOR (DUT-G)  │  ─────▶ │   TARGET (DUT-T)    │
  │  pktgen / TRex /    │  isolated│  Caly Anti + the   │
  │  MoonGen / hping3   │   link   │  service under test│
  │                     │  ◀───── │                    │
  └────────────────────┘         └────────────────────┘
        no other hosts on this segment; no uplink to anything real
```

- **Two physical machines, one cable** is ideal. The generator needs to be at
  least as capable as the target or you measure the generator, not the filter.
- **Two VMs on a private bridge** works for correctness testing (does the right
  rule fire?) but not for throughput — virtio and the host bridge cap you well
  below what the filter can do.
- A **third host** on the segment, running `tcpdump`/`tshark`, lets you confirm
  what actually crossed the wire versus what each side thinks it sent.

Record the fixed facts before the first run:

```sh
# On the target:
uname -r; ethtool -i eth0 | head -3; nproc
calyanti-cli status
ethtool -l eth0            # queue count - determines how many cores RSS uses
```

---

## 2. What to measure

| Metric | How | Why it matters |
|---|---|---|
| Drop rate (pps) sustained | generator TX vs target `drop_total` delta | the headline number |
| Per-packet CPU cost (ns) | `bpf_stats_enabled`, section 3 | scales to "how many Mpps per core" |
| Passed-traffic throughput under attack | a real client's goodput while the flood runs | the number that actually matters to users |
| CPU headroom at target rate | `mpstat -P ALL` softirq% | are you at the cliff or cruising |
| NIC-level drops | `ethtool -S` `rx_missed`/`no_buf` | packets that never reached XDP — not the filter's doing |
| Latency added to passed traffic | `ping`/`sockperf` with and without the program | the cost paid by legitimate traffic |
| Correct verdict | per-reason counters | did the *intended* rule fire, or a different one |

The mistake to avoid: reporting a drop-rate number without the
passed-throughput number beside it. A filter that drops 40 Mpps while also
dropping every legitimate packet is not a good filter; it is `ip link set down`
with extra steps.

---

## 3. Measuring per-packet cost in the dataplane

This is the most reproducible measurement and it needs **no traffic generator
at all**. Two methods.

### Method A: live stats counter (real traffic)

```sh
sudo sysctl -w kernel.bpf_stats_enabled=1

# Let traffic (real or generated) flow, then:
sudo bpftool prog show name caly_xdp_main
# run_time_ns 1234567890  run_cnt 9876543
#   -> average ns/packet = run_time_ns / run_cnt

sudo sysctl -w kernel.bpf_stats_enabled=0     # ~5% overhead; turn it back off
```

`run_time_ns / run_cnt` is the average nanoseconds the program spends per
packet. Invert it for the single-core packet rate: 200 ns/packet is 5 Mpps per
core.

Watch it live:

```sh
watch -n1 'sudo bpftool prog show name caly_xdp_main | \
  grep -oE "run_time_ns [0-9]+|run_cnt [0-9]+"'
```

### Method B: `bpftool prog run` (synthetic, zero packets on the wire)

Feed the program a crafted frame and have the kernel run it N times in a tight
loop, reporting the average. This isolates the program's cost from the driver,
RSS, IRQs and the generator entirely.

```sh
# Build a test frame - a TCP SYN to port 443 - however you like; scapy is easy:
python3 - <<'EOF'
from scapy.all import Ether, IP, TCP, raw
pkt = Ether()/IP(src="198.51.100.7", dst="203.0.113.1")/TCP(dport=443, flags="S")
open("/tmp/syn.bin","wb").write(raw(pkt))
EOF

sudo bpftool prog run name caly_xdp_main \
     data_in /tmp/syn.bin \
     repeat 10000000

# Output includes: "return value: 1 (XDP_DROP)  duration: 187ns"
```

`duration` is nanoseconds per invocation, averaged over `repeat`. This is the
cleanest single number you can get and it is what to quote when comparing two
builds or two configurations, because nothing external is in the measurement.

Compare configurations by changing the config map between runs:

```sh
# Cost with src_stats on vs off, everything else identical:
sudo bpftool prog run name caly_xdp_main data_in /tmp/syn.bin repeat 10000000
sudo sed -i 's/^src_stats.*/src_stats = no/' /etc/calyanti/calyanti.conf
sudo calyanti-cli reload
sudo bpftool prog run name caly_xdp_main data_in /tmp/syn.bin repeat 10000000
```

Build one test frame per path you care about — a conntrack hit, an allowlisted
source, a bogon source, a full-path rate-limited packet — and you have a
per-path cost table that is fully reproducible on any machine.

---

## 4. Baseline line rate before you filter anything

You cannot attribute a limit to the filter until you know the limit *without*
it. Measure the bare path first:

```sh
# Attach a program that does nothing but pass, measure the achievable rate,
# then attach Caly Anti and measure again. The difference is the filter.
cat > /tmp/xdp_pass.c <<'EOF'
#include <linux/bpf.h>
__attribute__((section("xdp"), used))
int pass(struct xdp_md *ctx) { return XDP_PASS; }
char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";
EOF
clang -O2 -g -target bpf -c /tmp/xdp_pass.c -o /tmp/xdp_pass.o
sudo ip link set dev eth0 xdp obj /tmp/xdp_pass.o sec xdp
# ... run the generator, record the rate ...
sudo ip link set dev eth0 xdp off
```

Also measure `XDP_DROP` line rate with a trivial drop-everything program: that
is the hardware-and-driver ceiling for dropping, and Caly Anti's full-path drop
rate will be some fraction of it. If the trivial drop tops out at 22 Mpps on
your NIC, the filter cannot exceed that no matter how cheap its logic is.

---

## 5. pktgen (in-kernel, highest packet rate)

`pktgen` runs in the kernel and hits far higher rates than any userspace tool
short of DPDK. It is the right tool for finding the drop ceiling.

```sh
sudo modprobe pktgen
```

Driver script for a single flow from one queue:

```sh
#!/bin/sh
# pktgen-single.sh - LAB ONLY. Generates traffic; do not run near production.
PGDEV=/proc/net/pktgen
DEV=eth0

pg() { echo "$1" > "$2"; }

# Reset
echo "reset" > $PGDEV/pgctrl

# Bind device to a kernel thread (kpktgend_0 = CPU 0)
pg "rem_device_all" $PGDEV/kpktgend_0
pg "add_device $DEV" $PGDEV/kpktgend_0

# Frame definition
pg "count 100000000"        $PGDEV/$DEV     # 0 = run until stopped
pg "clone_skb 1000"         $PGDEV/$DEV     # reuse skb: max rate
pg "pkt_size 64"            $PGDEV/$DEV     # smallest = highest pps
pg "dst 203.0.113.1"        $PGDEV/$DEV     # TARGET, in your lab range
pg "dst_mac 02:00:00:00:00:01" $PGDEV/$DEV  # target NIC MAC
pg "udp_src_min 1024"       $PGDEV/$DEV
pg "udp_src_max 65000"      $PGDEV/$DEV
pg "udp_dst_min 53"         $PGDEV/$DEV
pg "udp_dst_max 53"         $PGDEV/$DEV

# Start (blocks until count reached or you write "stop")
echo "start" > $PGDEV/pgctrl
```

Read the result out of the same procfs file:

```sh
cat /proc/net/pktgen/eth0
# ... look for "Result: OK: ... (pps NNNNNN) (Mb/sec ...)"
```

### Spoofed sources (the realistic case, LAB ONLY)

RSS spreads traffic across queues by hashing the 5-tuple, so a single-source
test lands entirely on one core and measures that core, not the box. To exercise
the filter the way a real distributed attack would — and to fill `caly_rate4/6`
the way a real flood does:

```sh
pg "flag IPSRC_RND"         $PGDEV/$DEV
pg "src_min 100.64.0.0"     $PGDEV/$DEV     # a range you own in the lab
pg "src_max 100.64.255.255" $PGDEV/$DEV
```

Multi-queue, one kernel thread per CPU, for maximum rate:

```sh
# Bind a queue to each CPU: kpktgend_0..N, add eth0@0..eth0@N
for cpu in $(seq 0 $(($(nproc)-1))); do
    echo "rem_device_all" > /proc/net/pktgen/kpktgend_$cpu
    echo "add_device eth0@$cpu" > /proc/net/pktgen/kpktgend_$cpu
done
```

Each `eth0@N` is configured independently under `/proc/net/pktgen/eth0@N`.

pktgen limits: it transmits, it does not receive replies, so it cannot complete
a TCP handshake and cannot test the conntrack established-flow path or validate
a SYN-ACK. For those, use [section 10](#10-testing-the-syn-proxy) tooling.

---

## 6. trafgen (flexible, scriptable frames)

`trafgen`, from the `netsniff-ng` toolkit, builds arbitrary frames with a
compact packet language and randomised fields. It is slower than pktgen but far
more expressive — the right tool for reproducing a specific malformed packet or
attack signature.

```sh
# Debian/Ubuntu: apt install netsniff-ng
# Fedora/EL:     dnf install netsniff-ng
# Arch:          pacman -S netsniff-ng
```

A randomised-source UDP flood to port 53 (reflection-shaped), LAB ONLY:

```
# udp-flood.cfg
{
  /* Ethernet */
  0x02,0x00,0x00,0x00,0x00,0x01,   # dst MAC (target)
  0x02,0x00,0x00,0x00,0x00,0x02,   # src MAC
  0x08,0x00,                        # ethertype IPv4

  /* IPv4 */
  0x45,0x00,
  const16(0x001c),                  # total length = 28
  drnd(2),                          # id: random
  0x00,0x00,
  0x40,0x11,                        # TTL 64, proto UDP
  csumip(14,33),                    # IP checksum over the header
  drnd(4),                          # SOURCE IP: random (LAB ONLY)
  0xcb,0x00,0x71,0x01,              # dst 203.0.113.1

  /* UDP */
  drnd(2),                          # src port random
  const16(53),                      # dst port 53
  const16(0x0008),                  # length 8
  const16(0x0000),                  # checksum 0 (v4 may omit)
}
```

```sh
sudo trafgen --cpp --dev eth0 --conf udp-flood.cfg --num 100000000 --cpus $(nproc)
```

`drnd(n)` is n random bytes; `dinc`/`ddec` step a field; `csumip`/`csumudp`
compute checksums over a byte range. This makes it straightforward to generate
a packet that trips one specific anomaly rule — set the TCP flags byte to
`0x00` for a null scan, `0x29` for xmas, source==dest for LAND — and confirm
the corresponding counter, and only that counter, increments.

---

## 7. hping3 (quick attack shapes)

Slow (userspace, one packet at a time-ish) but unbeatable for a quick,
readable reproduction of a named attack shape. Correctness testing, not
throughput.

```sh
# apt/dnf/pacman install hping3
```

| Attack shape | Command (LAB ONLY) |
|---|---|
| SYN flood, spoofed | `sudo hping3 -S -p 443 --flood --rand-source 203.0.113.1` |
| ACK flood | `sudo hping3 -A -p 443 --flood --rand-source 203.0.113.1` |
| RST flood | `sudo hping3 -R -p 443 --flood --rand-source 203.0.113.1` |
| UDP flood to a port | `sudo hping3 --udp -p 53 --flood --rand-source 203.0.113.1` |
| Reflection shape (src port 53) | `sudo hping3 --udp -s 53 -k -p 1024 --flood --rand-source 203.0.113.1` |
| Null scan | `sudo hping3 -p 443 --flood 203.0.113.1` (no flags) |
| Xmas | `sudo hping3 -FPU -p 443 --flood 203.0.113.1` |
| SYN+FIN | `sudo hping3 -SF -p 443 --flood 203.0.113.1` |
| LAND | `sudo hping3 -S -a 203.0.113.1 -p 443 --flood 203.0.113.1` (src = dst) |
| ICMP flood | `sudo hping3 --icmp --flood --rand-source 203.0.113.1` |
| Oversize ICMP | `sudo hping3 --icmp -d 2000 203.0.113.1` |
| Tiny fragment | `sudo hping3 --udp -p 53 -f -d 8 203.0.113.1` |
| Frag offset 1 | `sudo hping3 --udp -p 53 -g 1 203.0.113.1` |

After each, confirm the *intended* counter fired and nothing else did:

```sh
calyanti-cli stats --json | jq -r '.counters | to_entries
  | map(select(.value.packets>0)) | sort_by(-.value.packets)[:8][]
  | "\(.value.packets)\t\(.key)"'
```

A xmas flood should light up `drop_tcp_xmas` and `drop_total` and essentially
nothing else. If it also lights up `drop_rate_pps`, your buckets are tighter
than your anomaly checks are fast — which is fine, but know which rule caught
it.

---

## 8. MoonGen and TRex (line-rate, measured)

When you need **line rate with per-packet latency measurement** — the numbers
you would put in a report — pktgen and hping3 are not enough. Both of these
drive the NIC from userspace via DPDK and measure what comes back.

### TRex (Cisco)

Stateful and stateless L4-7 generator. The stateless API is what you want for
DDoS shapes.

```sh
# TRex ships as a self-contained tarball; it needs DPDK-bound NICs.
# https://trex-tgn.cisco.com/
cd /opt/trex/vX.XX
sudo ./t-rex-64 -i -c $(nproc)         # server, interactive DPDK mode
```

A stateless SYN-flood profile (Python API sketch, LAB ONLY):

```python
from trex_stl_lib.api import *

def create_stream():
    base = Ether()/IP(dst="203.0.113.1")/TCP(dport=443, flags="S")
    pad = max(0, 64 - len(base))
    pkt = STLPktBuilder(
        pkt=base/(b'\x00'*pad),
        vm=STLScVmRaw([                        # randomise the source IP
            STLVmFlowVar(name="src", min_value="100.64.0.1",
                         max_value="100.64.255.254", size=4, op="random"),
            STLVmWrFlowVar(fv_name="src", pkt_offset="IP.src"),
            STLVmFixIpv4(offset="IP"),
        ]))
    return STLStream(packet=pkt, mode=STLTXCont(pps=10_000_000))
```

TRex reports TX pps, RX pps, and latency histograms per stream, so you get the
drop rate (TX minus RX) and the latency added to whatever you let through, in
one run.

### MoonGen

Lua-scripted, DPDK-based, hardware-timestamped latency. The
`examples/l3-load-latency.lua` script measures exactly the two numbers that
matter — achievable rate and per-packet latency — and is easy to adapt to a
flood shape.

```sh
# https://github.com/emmericp/MoonGen
sudo ./build/MoonGen examples/l3-load-latency.lua 0 1 -r 10000000
```

Both need DPDK-compatible NICs bound away from the kernel driver on the
*generator*. Do not bind the target's NIC to DPDK — the target must keep its
kernel driver so XDP runs.

---

## 9. Testing each control specifically

The point of correctness testing is to prove that the rule you *think* is
firing is the rule that *is* firing. One control at a time, with everything
else in `monitor_only` or disabled so the counters are unambiguous.

| Control | Generate | Expect counter | Also check |
|---|---|---|---|
| Bogon filter | source `0.0.0.0`, `127.0.0.1`, `240.0.0.1` on a WAN iface | `drop_bogon_src` | inert unless the iface is `zone=wan` |
| Private-on-WAN | source `10.0.0.1` on a WAN iface, `wan_drop_private=yes` | `drop_private_src` | off by default |
| LAND | src == dst | `drop_land` | |
| TCP null/xmas/etc. | hping3 flag shapes (section 7) | the matching `drop_tcp_*` | one per shape |
| Amplifier filter | UDP `sport 53` with no prior outbound | `drop_amp_srcport` | must NOT fire if a conntrack entry exists |
| Port closed | SYN to an unlisted port, `default_deny=yes` | `drop_default_deny` | vs `drop_port_closed` for an explicit rule |
| Per-source pps | exceed `rate_pps` from one source | `drop_rate_pps` after strikes | `strike_added`, then `ban_added` |
| Per-source ban | sustain the overrun past `strike_limit` | `drop_ban_active` | `ban_added`, then `drop_ban_active` on subsequent packets |
| Port scan | many dports from one source in `scan_window` | `drop_portscan` | keep threshold ≤ 150 (Bloom saturates) |
| Blocklist | traffic from a `block =` prefix | `drop_blocklist` | allowlist entry for the same IP must override it |
| Allowlist override | same source in both allow and block | `pass_allowlist` | proves the escape hatch precedes the drop |
| Conntrack hit | complete a handshake, then send more | `pass_conntrack`, `ct_hit` | the follow-up must NOT hit any drop rule |
| ICMP oversize | `hping3 --icmp -d 2000` | `drop_icmp_oversize` | |
| Fragmented ICMP | fragmented ICMP echo | `drop_frag_icmp` | |

The two that catch people:

- **The amplifier filter must be conntrack-exempt.** Generate `sport 53` traffic
  *after* completing an outbound flow to that peer and confirm it passes
  (`pass_conntrack`), then from a fresh source with no state and confirm it drops
  (`drop_amp_srcport`). If the exempt case drops, the egress hook is missing —
  see COMPATIBILITY and TUNING.
- **The allowlist must win over the blocklist.** Put the same address in both,
  send traffic, and confirm `pass_allowlist` — not `drop_blocklist`. That is the
  invariant that keeps you from banning your own gateway via a bad feed.

---

## 10. Testing the SYN proxy

The SYN proxy is the one control you cannot validate with a fire-and-forget
generator, because it requires a returning ACK to be checked against the
kernel's cookie.

### Prerequisites

```sh
sysctl net.ipv4.tcp_syncookies            # MUST be 2
calyanti-cli status | grep -o SYNPROXY    # must be present (kernel 5.15+)
uname -r                                  # >= 5.15
```

If any of those is wrong, the proxy is not active and you are testing the rate
fallback instead — which is a valid thing to test, just a different thing.

### Drive it into the active state

The proxy engages in `under-attack` mode on flagged ports. Either force the
mode or drive the global SYN gauge past `global_syn_pps_high`:

```sh
calyanti-cli mode under-attack
```

### Generate the flood, and a real connection through it

```sh
# From the generator, LAB ONLY: a spoofed SYN flood.
sudo hping3 -S -p 443 --flood --rand-source 203.0.113.1

# Simultaneously, from a NON-spoofed lab host, complete a real handshake:
curl -m 5 http://203.0.113.1/  ;  echo "exit=$?"
# or:
hping3 -S -p 443 -c 1 203.0.113.1     # then watch for the SYN-ACK
```

### What proves it works

```sh
watch -n1 'calyanti-cli stats | grep -E "synproxy|syncookie"'
```

| Counter | Meaning during the test |
|---|---|
| `synproxy_gen_ok` | cookies generated for inbound SYNs |
| `synproxy_tx` | SYN-ACKs rewritten and `XDP_TX`'d back |
| `synproxy_check_ok` | a returning ACK carried a valid cookie — the real connection |
| `drop_syncookie_bad` | bare ACKs with invalid cookies — the flood's forged ACKs, if any |

And, decisively, on the target:

```sh
ss -s                                       # half-open count stays LOW
nstat -az | grep -i -E 'TcpExtSyncookies|ListenOverflow|ListenDrop'
```

The whole point is that `ss -s` shows the accept queue *not* filling: a spoofed
SYN flood costs one `XDP_TX` per packet and **zero** half-open sockets, while
the legitimate `curl` still completes. If the real connection fails while the
flood runs, check the sysctl first — `tcp_syncookies = 1` instead of `2` is the
cause nine times out of ten, because the kernel then rejects the cookie the XDP
program already issued.

### Testing the pre-5.15 fallback

On an older kernel there is no proxy; the defence is the per-source `rate_syn`
bucket plus `syn_fallback_pps`. Confirm:

```sh
calyanti-cli stats | grep -E 'synproxy_unavailable|drop_rate_syn|drop_rate_global_syn'
```

`synproxy_unavailable` climbing is expected and correct on those kernels.

---

## 11. Reading the results

### Turning counters into a rate

Counters are monotonic; take deltas over a known interval:

```sh
A=$(calyanti-cli stats --json | jq -r '.counters.drop_total.packets')
sleep 10
B=$(calyanti-cli stats --json | jq -r '.counters.drop_total.packets')
echo "$(( (B - A) / 10 )) drops/sec"
```

### The report worth writing

For each configuration tested, record:

| Field | From |
|---|---|
| Hardware, kernel, driver, queue count | `uname -r`, `ethtool -i`, `ethtool -l` |
| Attach mode (native/generic) | `calyanti-cli status` |
| Offered load (pps, bps) | the generator |
| Sustained drop rate (pps) | `drop_total` delta |
| Passed goodput under load | a real client's measured throughput |
| Per-packet cost (ns) | `bpftool prog run`, section 3 |
| CPU at that rate (softirq%) | `mpstat -P ALL 1` |
| NIC drops | `ethtool -S \| grep -Ei 'miss\|no_buf'` |

A result without the hardware line and the passed-goodput line is not
reproducible and not meaningful.

### Sanity anchors

Order-of-magnitude expectations on a modern x86_64 core, native XDP, so you can
tell a real result from a broken measurement:

| Path | ns/packet | per-core Mpps |
|---|---|---|
| Trivial `XDP_DROP` (driver ceiling) | 10-20 | 50-100 |
| Parse + anomaly, no map lookups | 15-30 | 33-66 |
| Full path with rate limiting + scan | 150-300 | 3-7 |
| Per emitted event | +200-400 | — |

If you measure 50 Mpps through the *full* path, you are measuring the generator
or a counter that is not incrementing — the full path cannot be that cheap. If
you measure 0.2 Mpps on native XDP, something is forcing generic mode or the
CPU governor is in `powersave`.

---

## 12. Common mistakes that produce wrong numbers

| Mistake | Symptom | Fix |
|---|---|---|
| Single source, so RSS uses one core | rate plateaus at one core's limit | `--rand-source` / `IPSRC_RND` / TRex flow var |
| Testing on a cloud instance | plateau far below the filter's limit | it is the hypervisor shaper (`bw_allowance_exceeded`); use bare metal |
| CPU governor in `powersave` | 20-30% low, inconsistent | `cpupower frequency-set -g performance` |
| Generic XDP without noticing | 5x low | `calyanti-cli status` shows `SKB_MODE`; fix the native attach |
| Generator is the bottleneck | target CPU is idle at "max" rate | use a faster generator (pktgen/TRex) or a second generator host |
| Measuring TX, not drops | numbers look great, box is melting | measure `drop_total` on the target, not pps on the generator |
| `bpf_stats_enabled` left on | everything 5% slow | it has overhead; turn it off after measuring |
| No passed-traffic measurement | "40 Mpps!" but real clients time out | always measure goodput through the flood |
| virtio LRO on | XDP sees coalesced frames, counts look wrong | `ethtool -K eth0 lro off gro off` |
| NIC ring too small | `rx_no_buffer` climbing, packets never reach XDP | `ethtool -G eth0 rx 4096` |
| Comparing across different `pkt_size` | pps differs for a trivial reason | fix the frame size; smaller = higher pps at the same bps |
| Spoofed traffic escaping the lab | abuse report from your provider | it never leaves an isolated segment. Section 0 |

The single most common one is the first: RSS hashes the 5-tuple to a queue, so
a single-source flood lands on one core and you measure that core, not the box.
Every serious throughput number in this document uses randomised sources for
exactly that reason.
