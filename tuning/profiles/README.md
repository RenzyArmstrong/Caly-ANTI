# Caly Anti tuning profiles

This directory holds optional **NIC tuning profiles** for `nic-tuning.sh`, plus
the reasoning behind the shipped defaults. A profile is a small `KEY=VALUE`
file that presets the script's options, so a fleet can be tuned identically
without a wrapper full of flags.

> The **sysctl** side has no profile files. It is one commented file,
> `../99-calyanti-sysctl.conf`, applied by `../apply-sysctl.sh`. The knobs that
> are unsafe on some workloads are marked `#OPT` inside it and are opted into
> with `apply-sysctl.sh --optional`. See the top of that file.

---

## How a profile is used

```sh
# NIC tuning with a profile:
sudo ../nic-tuning.sh --profile ./10G-server.conf --iface eth0

# A flag on the command line overrides the same key from the profile,
# because the profile is parsed first and the flags are parsed after.
sudo ../nic-tuning.sh --profile ./10G-server.conf --iface eth0 --rfs on
```

A profile is **parsed, never sourced**. It is data. `nic-tuning.sh` reads it
line by line and accepts only the whitelisted keys listed below; anything else
is warned about and ignored. Do not put shell code in it — it will not run, by
design. (A config file that a root script `.`-sources is a root shell waiting
for the wrong `$(...)`.)

### File format

```
# comment; blank lines ignored
KEY = value          # trailing comments allowed
KEY=value            # whitespace around = is optional
```

---

## Recognised keys (NIC)

Every key maps to the identically named `nic-tuning.sh` option. The script's
`--help` is the authoritative description; this is the summary.

| Key | Values | Default | What it does |
|-----|--------|---------|--------------|
| `IFACES` | names | *(auto)* | Interfaces to tune; repeatable/comma-listed. |
| `CHANNELS` | N \| `max` \| `skip` | `min(nproc, hw max)` | Combined queue count. Never lowered. |
| `RX_RING` | N \| `max` | `max` | RX descriptors, up to the hardware maximum. |
| `TX_RING` | N \| `max` | `min(hw max, 4096)` | TX descriptors. |
| `COALESCE` | `adaptive` \| `fixed` \| `skip` | `adaptive` | Interrupt moderation strategy. |
| `RX_USECS` | N | `32` | Fixed-mode RX interrupt delay (µs). |
| `RX_FRAMES` | N | `64` | Fixed-mode RX frame budget. |
| `LRO` | `off` \| `keep` | `off` | **Must be off for XDP.** |
| `GRO` | `auto` \| `on` \| `off` \| `keep` | `auto` | `auto` = off under XDP generic mode. |
| `VLAN_OFFLOAD` | `keep` \| `off` | `keep` | `off` lets XDP see 802.1Q tags. |
| `PAUSE` | `off` \| `on` \| `keep` | `off` | Ethernet flow control. |
| `RPS` | `auto` \| `on` \| `off` \| `skip` | `auto` | Software RX steering. |
| `RFS` | `on` \| `off` | `off` | Flow-aware steering. Off on a DDoS filter. |
| `RFS_ENTRIES` | N | `32768` | Global RFS table size (power of two). |
| `XPS` | `on` \| `off` \| `skip` | `on` | Transmit steering. |
| `IRQ_AFFINITY` | `on` \| `off` | `on` | Pin queue IRQs round-robin to NUMA-local CPUs. |
| `XDP_MODE` | `auto` \| `native` \| `generic` \| `offload` \| `none` | `auto` | Override attach-mode detection. |

---

## Why the defaults are what they are

These four choices surprise people, so they are justified here rather than
buried in the script.

### RFS defaults to OFF

Receive Flow Steering sends a packet to the CPU where the socket that owns its
flow last ran, using a global flow table. On a general server that improves
cache locality. **On a DDoS filter it is usually a net loss:** a spoofed-source
flood presents a brand-new flow on almost every packet, so the flow table
churns constantly and you pay the hash-and-insert cost for traffic XDP is about
to drop. Turn RFS on only when the box mostly serves *real*, long-lived
connections and you have measured the benefit. `RFS=on`.

### RPS defaults to AUTO (usually off)

With a multi-queue NIC, RSS already spreads packets across CPUs in hardware and
RPS is pure overhead. RPS earns its keep in exactly two situations, and the
`auto` logic enables it only then:

* **Single-queue NICs** — virtio without multiqueue, many small cloud shapes.
  One hardware queue means one CPU takes every interrupt unless RPS fans the
  work out in software.
* **XDP generic/skb mode** — the program runs *after* the RPS handoff, so RPS
  is the only way to get the filtering onto more than one core.

In **XDP native mode**, a dropped packet never reaches RPS, which is the entire
point of the native rung of the degradation ladder. `auto` accounts for this.

### Transmit offloads (TSO/GSO/checksum) are LEFT ALONE

A widespread hardening myth says to disable every offload before loading XDP.
TSO, GSO and checksum offload are **transmit-side** and have nothing to do with
XDP ingress. Disabling them costs 30–70% of egress throughput and defends
nothing. `nic-tuning.sh` touches only the offloads that actually interfere with
the XDP receive path:

* **LRO — off (required).** LRO merges received segments into one super-frame
  in the NIC. XDP would see a frame that never existed on the wire; most
  drivers refuse the attach while LRO is on.
* **GRO — off only in generic mode.** GRO merges in software inside
  `netif_receive_skb`. In XDP native mode the program runs first, so GRO is
  fine. In generic mode the program runs *after* GRO and would see one merged
  pseudo-packet, breaking per-packet rate limiting and every length check.
* **Hardware GRO (`rx-gro-hw`) — off under any XDP mode**, because the merge
  happens in the NIC before the program runs regardless of attach mode.
* **RX VLAN offload — left on by default.** Set `VLAN_OFFLOAD=off` if you rely
  on the dataplane's 802.1Q/QinQ parsing; with hardware stripping the tag is
  gone before XDP sees the frame (L3 filtering still works; per-VLAN policy
  does not).

### Ring and channel changes are skipped while XDP is attached

Resizing rings or channels reallocates every queue buffer, which can detach a
live XDP program or wedge a queue. The script **skips both** when it detects an
attached program, unless you pass `--force`. The correct order is: **tune the
NIC, then attach the dataplane.** The `--print-unit` output wires this ordering
into systemd with `Before=calyanti.service`.

Every ring/channel change that *is* made waits for the link to come back and
**rolls itself back** if the link does not return within ten seconds — a bad
ring size must not cost you the box.

---

## Example profiles

Copy one, edit it, point `--profile` at it. None of these are installed
automatically.

### `10G-server.conf` — bare-metal 10/25G, public-facing

```
# Multi-queue NIC (ixgbe/i40e/ice/mlx5), one RX queue per CPU already.
CHANNELS = max
RX_RING = max
TX_RING = 4096
COALESCE = adaptive
LRO = off
GRO = auto
PAUSE = off
RPS = auto          # auto -> off, RSS already covers every CPU
RFS = off
XPS = on
IRQ_AFFINITY = on
```

Run once at boot, before the dataplane, and stop irqbalance so the pinning
sticks:

```sh
sudo ./nic-tuning.sh --profile 10G-server.conf --iface eth0 --stop-irqbalance
```

### `cloud-vm.conf` — virtio/ENA/gVNIC guest

```
# Small cloud instance. Queue count is set by the hypervisor; do not fight it.
CHANNELS = skip
RX_RING = max        # ENA/virtio still let you grow the ring
COALESCE = adaptive
LRO = off
GRO = auto
RPS = auto           # single-queue shapes -> auto turns RPS on
RFS = off
XPS = on
IRQ_AFFINITY = on
```

Notes per driver:

* **virtio_net** — `ethtool -L` works only on a *multiqueue* device. Give the
  guest `<driver name='vhost' queues='N'/>` (libvirt) or the equivalent, or the
  channel step is correctly skipped. Native XDP wants roughly twice as many
  queues as vCPUs; short of that the kernel uses generic mode.
* **ENA (AWS)** — no `ethtool -A` (pause) and limited coalescing; those steps
  skip cleanly. Rings resize.
* **gVNIC (GCP)** — supports native XDP; RX ring resize is supported.

### `edge-router.conf` — forwarding host, asymmetric paths

```
# This box FORWARDS. Be conservative.
CHANNELS = max
RX_RING = max
TX_RING = max        # a forwarder needs TX depth as much as RX
COALESCE = adaptive
LRO = off
GRO = off            # never coalesce on a forwarder; it corrupts flow boundaries
PAUSE = keep         # some transit links negotiate pause deliberately
RPS = auto
RFS = off
XPS = on
IRQ_AFFINITY = on
```

Pair this with `rp_filter` care in the sysctl profile: strict reverse-path
filtering (value 1) **breaks asymmetric forwarding**, which is exactly what an
edge router does. The sysctl profile ships loose (2) for this reason.

### `container-host.conf` — Docker/Kubernetes node

```
# Tune the PHYSICAL uplink only. Do NOT run this inside a container: net.*
# sysctls are per namespace and most sysfs queue knobs are read-only there.
CHANNELS = max
RX_RING = max
COALESCE = adaptive
LRO = off
GRO = auto
RPS = auto
RFS = off            # pod churn already stresses conntrack; do not add RFS churn
XPS = on
IRQ_AFFINITY = on
```

The container runtime installs its own netfilter/conntrack rules, so read
section 12 of the sysctl profile: size `nf_conntrack_max` for the pod count and
keep the timeouts short.

---

## Persistence

None of these settings survive a reboot, a driver reload (`modprobe -r`), or a
NIC hotplug. Generate the boilerplate to reapply them:

```sh
./nic-tuning.sh --print-unit
```

That prints:

* a templated systemd unit `calyanti-nic-tune@.service`, ordered
  `Before=calyanti.service` so the NIC is tuned before the dataplane attaches
  (which is what keeps the ring/channel steps from being skipped);
* a udev rule that re-runs it when an interface appears;
* an OpenRC `/etc/local.d` snippet for Alpine.

`apply-sysctl.sh --install` persists the **sysctl** side into
`/etc/sysctl.d/99-calyanti-sysctl.conf` (and the conntrack hash size into
`/etc/modprobe.d/`, because that key is read-only after the module loads on
some kernels).

---

## Verifying, and the four numbers that tell you whether it worked

Tuning without measurement is superstition. After applying, watch these for a
few days under real traffic; anything that stays at zero did not need a bigger
number.

```sh
# 1. NIC-level loss. The reason ring/coalescing tuning exists.
ethtool -S eth0 | grep -iE 'drop|miss|err|no_buf|fifo|overrun'

# 2. Kernel backlog drops (col 2) and softirq time-squeezes (col 3).
awk 'NR>1 {print NR-1": drops="$2" squeeze="$3}' /proc/net/softnet_stat

# 3. Per-queue interrupt spread. Even columns = RSS/affinity are working.
grep -E 'eth0|mlx|ena|virtio' /proc/interrupts

# 4. Conntrack occupancy vs the ceiling you set in the sysctl profile.
sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max
```

Cross-check against the dataplane's own view, which counts what XDP dropped
*before* any of the above:

```sh
calyanti-cli stats        # drop breakdown by reason
calyanti-cli top          # top talkers (caly_top4 / caly_top6)
```

If `ethtool -S` shows RX drops climbing while `calyanti-cli stats` shows the
XDP program is barely working, the loss is happening *below* XDP — grow the RX
ring and the channel count first, then netdev_max_backlog and netdev_budget in
the sysctl profile. If XDP is dropping hard and NIC drops are zero, the
dataplane is doing its job and you are tuning the wrong layer.

---

## See also

* `../99-calyanti-sysctl.conf` — the kernel sysctl profile, fully commented.
* `../apply-sysctl.sh` — applies it safely (backup, verify, `--revert`).
* `../nic-tuning.sh` — the tool these profiles feed; `--help`, `--show`,
  `--print-unit`, `--revert`.
* `../../docs/ARCHITECTURE.md` — the degradation ladder and where XDP native vs
  generic mode changes what NIC tuning can achieve.
