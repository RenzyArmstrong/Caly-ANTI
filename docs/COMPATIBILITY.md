# Caly Anti — Compatibility

What works where, and what silently degrades. Three matrices: kernel features,
NIC drivers, and cloud providers.

The loader **probes** rather than parsing `uname`. That matters: RHEL 9's
"5.14" carries backported helpers that upstream 5.14 does not have, and
Ubuntu's 5.4 carries backports that Debian's 5.10 does not. Version numbers in
this document tell you what to *expect*; `calyantid --probe` tells you what you
actually have.

```sh
calyantid --probe
```

---

## Contents

- [1. Kernel feature matrix](#1-kernel-feature-matrix)
- [2. What each missing feature costs you](#2-what-each-missing-feature-costs-you)
- [3. Distro kernel matrix](#3-distro-kernel-matrix)
- [4. libbpf version matrix](#4-libbpf-version-matrix)
- [5. NIC driver XDP support](#5-nic-driver-xdp-support)
- [6. Cloud provider notes](#6-cloud-provider-notes)
- [7. Virtualisation and containers](#7-virtualisation-and-containers)
- [8. Architecture notes](#8-architecture-notes)
- [9. Interacting with other XDP users](#9-interacting-with-other-xdp-users)
- [10. Probing anything yourself](#10-probing-anything-yourself)

---

## 1. Kernel feature matrix

| Feature | Upstream since | Used by | If absent |
|---|---|---|---|
| XDP generic (`XDP_FLAGS_SKB_MODE`) | 4.12 | rung 2 | rung 3 |
| XDP native (`XDP_FLAGS_DRV_MODE`) | 4.8 (driver dependent) | rung 1 | rung 2 |
| XDP hardware offload (`XDP_FLAGS_HW_MODE`) | 4.16 | `xdp_mode = offload` | native |
| `XDP_TX` | with XDP | SYN proxy | SYN rate limiting |
| `BPF_MAP_TYPE_LPM_TRIE` | 4.11 | allow/block/local lists | **hard requirement** |
| `BPF_MAP_TYPE_LRU_HASH` | 4.10 | bans, rates, conntrack, scan, top | **hard requirement** |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | 4.6 | stats, gauges, scratch | **hard requirement** |
| `BPF_MAP_TYPE_PROG_ARRAY` + `bpf_tail_call` | 4.2 | SYN proxy dispatch | inline only, no SYN proxy |
| `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | 4.3 | event stream | no events |
| CO-RE / BTF (`/sys/kernel/btf/vmlinux`) | 5.2 upstream, backported to 4.18 by EL8 | everything on rungs 1-3 | **rung 4** |
| BTF func info / `bpf_program__set_autoload` | libbpf 0.6 | SYN proxy autoload gating | vendored libbpf |
| tc/clsact BPF (`CONFIG_NET_CLS_BPF`) | 4.1 | rung 3, egress conntrack learning | no outbound flow learning |
| `bpf_ktime_get_ns` | 4.1 | everything | **hard requirement** |
| `bpf_xdp_adjust_head` | 4.10 | not used | n/a |
| `bpf_xdp_adjust_tail` (shrink) | 4.18 | not used | n/a |
| `bpf_xdp_adjust_tail` (grow) | 5.8 | **deliberately not used** | n/a |
| `BPF_MAP_TYPE_RINGBUF` | 5.8 | preferred event transport | perf event array |
| Map batch syscalls (`BPF_MAP_LOOKUP_BATCH`) | 5.6 | fast GC sweeps | per-key syscalls |
| `bpf_tcp_raw_gen_syncookie_ipv4/ipv6` | **5.15** | SYN proxy | SYN bucket + `syn_fallback_pps` |
| `bpf_tcp_raw_check_syncookie_ipv4/ipv6` | **5.15** | SYN proxy | as above |
| `bpf_loop` | 5.17 | **deliberately not used** | n/a |
| `bpf_map_lookup_percpu_elem` | 5.20 | **deliberately not used** | n/a |
| XDP multi-buffer (`xdp_frags`) | 5.18 | not used | n/a — the program refuses jumbo frags rather than depending on it |
| BPF token / `CAP_BPF` split | 5.8 | privilege separation | needs `CAP_SYS_ADMIN` |
| BPF memory in cgroup accounting | 5.11 | memory sizing | `RLIMIT_MEMLOCK` applies |
| `bpf_link` XDP attach (`BPF_LINK_CREATE`) | 5.9 | safe attach/detach ownership | netlink attach with `XDP_FLAGS_REPLACE` |
| `XDP_FLAGS_REPLACE` | 5.6 | atomic program swap | detach-then-attach window |

Everything marked "deliberately not used" is a design decision recorded in
`docs/ARCHITECTURE.md` §6, made so that a single object file loads on 4.18 and
on 6.12 alike.

### The 4.18 floor

4.18 is the floor because it is the RHEL 8 kernel and because it is the first
release where all of the map types above coexist with reliable XDP driver
support. Two 4.18-era constraints shape the code:

- **Program size.** Upstream limits a single program to 4096 instructions until
  5.2, which raised it to 1M for privileged loads. RHEL 8 backported the higher
  limit. If you hit `BPF program is too large`, that is what
  `CALY_PROG_IDX_IPV6` exists for: the IPv6 path can be split into a
  tail-called program and the main program shrinks accordingly.
- **No bounded loops.** Verifier loop support arrived in 5.3. Every loop in the
  dataplane is `#pragma unroll` with a compile-time constant bound
  (`CALY_VLAN_MAX_DEPTH` 2, `CALY_IP6_EXT_MAX` 8, `CALY_TUNNEL_MAX_DEPTH` 1,
  `CALY_MGMT_PORTS_MAX` 16, `CALY_SCAN_BITMAP_WORDS` 8). The `vlan_max_depth`,
  `ipv6_ext_max` and `tunnel_max_depth` config knobs may only *lower* those
  bounds; raising them above the constant is clamped, not honoured.

---

## 2. What each missing feature costs you

| Missing | Observable symptom | Behaviour | Severity |
|---|---|---|---|
| BTF | `calyantid --probe` says `dataplane: nftables` | rung 4: static rules, no per-source buckets, no scan detection, no conntrack-lite, no SYN proxy | high — but supported |
| 5.15 syncookie helpers | `capabilities:` line has no `SYNPROXY`; `synproxy_unavailable` counter climbs | per-source `rate_syn` bucket + `syn_fallback_pps` + `tcp_syncookies = 1` | medium |
| Ring buffer (< 5.8) | no `RINGBUF` capability | perf event array; slightly higher CPU per event, identical records | negligible |
| Batch map ops (< 5.6) | none visible | GC sweeps use one syscall per key; raise `gc_interval` if the daemon shows up in `top` | negligible |
| Native XDP (driver) | `attach: SKB_MODE` | generic XDP, ~5x slower, `XDP_TX` on the slow path | medium |
| `XDP_TX` | no `XDP_TX` capability | SYN proxy disabled even on 5.15+ | medium |
| clsact / tc BPF | no `TC_EGRESS` capability | outbound flows are not learned; outbound-initiated UDP replies fall through to port policy instead of matching conntrack | medium, and it interacts badly with `default_deny = yes` |
| `bpf_link` (< 5.9) | none visible | attach via netlink; a crashed daemon can leave a program attached — see TROUBLESHOOTING | low |

The one combination to watch for: **no `TC_EGRESS` together with
`default_deny = yes`**. Outbound-initiated UDP (DNS, NTP, QUIC) has no inbound
handshake to learn from, so its replies have no conntrack entry and hit the
closed-port rule. Either keep `default_deny = no`, or explicitly open the reply
paths you need, or fix the missing clsact support. `calyanti-cli status` warns
about this combination at startup.

---

## 3. Distro kernel matrix

| Distro | Kernel | BTF | XDP native | SYN proxy (5.15+ helpers) | Ring buffer | Notes |
|---|---|---|---|---|---|---|
| RHEL/Alma/Rocky/Oracle 8 (RHCK) | 4.18 | yes, 4.18.0-193+ | yes | **no** | no | the reference "oldest supported" target |
| Oracle Linux 8 (UEK7) | 5.15 | yes | yes | yes | yes | check which kernel you booted |
| RHEL/Alma/Rocky 9, CentOS Stream 9 | 5.14 | yes | yes | **yes** (backported) | yes | version number understates it; probe decides |
| RHEL/Alma/Rocky 10, Stream 10 | 6.12 | yes | yes | yes | yes | |
| Fedora 38+ | 6.2+ | yes | yes | yes | yes | |
| Amazon Linux 2 (4.14) | 4.14 | no | partial | no | no | **below the 4.18 floor**; use the 5.10 extras kernel or rung 4 |
| Amazon Linux 2 (5.10 extras) | 5.10 | yes | yes | no | yes | |
| Amazon Linux 2023 | 6.1 | yes | yes | yes | yes | |
| Ubuntu 20.04 GA | 5.4 | yes | yes | **no** | no | |
| Ubuntu 20.04 HWE | 5.15 | yes | yes | yes | yes | `linux-generic-hwe-20.04` |
| Ubuntu 22.04 | 5.15 | yes | yes | yes | yes | |
| Ubuntu 24.04 | 6.8 | yes | yes | yes | yes | |
| Debian 11 | 5.10 | **verify** | yes | no | yes | some point releases lack `CONFIG_DEBUG_INFO_BTF`; check `/sys/kernel/btf/vmlinux` |
| Debian 12 | 6.1 | yes | yes | yes | yes | |
| Debian 13 | 6.12 | yes | yes | yes | yes | |
| Arch | rolling | yes | yes | yes | yes | |
| openSUSE Leap 15.5 | 5.14 | yes | yes | probe | yes | SLE backports; probe decides |
| openSUSE Leap 15.6 | 6.4 | yes | yes | yes | yes | |
| Tumbleweed | mainline | yes | yes | yes | yes | |
| SLES 15 SP5/SP6 | 5.14 / 6.4 | yes | yes | probe | yes | needs the development-tools module to build |
| Alpine 3.18+ (`linux-lts`) | 6.1+ | yes | yes | yes | yes | musl; OpenRC |

"probe" means the version number does not settle it and
`libbpf_probe_bpf_helper()` is the only reliable answer.

---

## 4. libbpf version matrix

The loader needs `bpf_program__set_autoload()` (libbpf 0.6),
`libbpf_probe_bpf_helper()` and `libbpf_probe_bpf_map_type()` (libbpf 0.7), and
`bpf_map__set_autocreate()` (libbpf 0.8) — the last one is what lets the
ring-buffer map be skipped entirely on pre-5.8 kernels instead of failing map
creation.

| libbpf | Ships with | Usable |
|---|---|---|
| 0.1 | Ubuntu 20.04 | no — vendor |
| 0.3 | Debian 11 | no — vendor |
| 0.4-0.5 | RHEL 8.6+, Ubuntu 22.04 | no — vendor |
| 0.8 | — | yes, minimum |
| 1.0-1.1 | RHEL 9.2+, Debian 12 | yes |
| 1.2+ | Ubuntu 24.04, Fedora, Arch, Alpine, AL2023, Debian 13 | yes |

`make LIBBPF=bundled` builds and statically links the vendored copy; that is
selected automatically when the system library is too old. There is no runtime
libbpf dependency in that configuration, which is also the easiest way to ship
one binary across EL8 and EL9.

---

## 5. NIC driver XDP support

"Native" means the driver implements `ndo_bpf`/`XDP_SETUP_PROG` and the program
runs before `sk_buff` allocation. "Generic" is the kernel's skb-mode fallback,
available on **every** netdev, roughly five times slower.

| Driver | Hardware | Native XDP since | `XDP_TX` | AF_XDP zero-copy | Notes and gotchas |
|---|---|---|---|---|---|
| `ixgbe` | Intel 82599, X520, X540, X550 | 4.12 | yes | 5.x | Attaching **reallocates the rings**: a brief link-local disruption. MTU in XDP mode is limited (no multi-buffer); frames above ~3 KB are refused. Needs `combined` queue count ≤ half the CPUs for XDP TX rings. |
| `ixgbevf` | SR-IOV VF of the above | 4.17 | yes | no | Some hypervisors block it. |
| `i40e` | Intel X710, XL710, XXV710 | 4.13 | yes | 5.x | Same TX-ring reservation as ixgbe. Firmware ≥ 6.01 recommended; older firmware has XDP-related RX corruption. |
| `iavf` | i40e/ice VF | 6.5 | yes | 6.5 | Older kernels: generic only. |
| `ice` | Intel E810 | 5.5 | yes | 5.5 | Multi-buffer 6.3+. Attach fails if `combined` queues exceed half of available. |
| `mlx4_en` | Mellanox ConnectX-3 | 4.8 | yes | no | Reserves one TX ring per core for XDP; needs free rings or attach returns `-ENOSPC`. |
| `mlx5_core` | Mellanox/NVIDIA ConnectX-4/5/6/7 | 4.9 | yes | 5.5 | The best-behaved implementation. Multi-buffer 6.3+. Striding RQ interacts with XDP: the driver switches RQ mode on attach, causing a short reset. `ethtool --set-priv-flags` `rx_striding_rq` may need to be off on some firmware. |
| `bnxt_en` | Broadcom NetXtreme-C/E | 4.12 | yes | 5.x | Page-per-packet mode on attach, so RX memory roughly doubles. MTU ≤ 3 KB in XDP mode on older firmware. |
| `nfp` | Netronome Agilio | 4.10 | yes | no | The only driver with real **hardware offload** (`XDP_FLAGS_HW_MODE`). Offloaded programs cannot use every map type; if `xdp_mode = offload` fails, the loader falls back to native. |
| `qede` | Marvell/QLogic FastLinQ | 4.10 | yes | no | |
| `thunderx` (`nicvf`) | Cavium ThunderX | 4.12 | yes | no | aarch64. |
| `netsec` | Socionext | 5.3 | yes | no | aarch64. |
| `dpaa2-eth` | NXP LS2 | 5.0 | yes | no | aarch64. |
| `mvneta` / `mvpp2` | Marvell Armada | 5.3 / 5.9 | yes | no | aarch64, common on ARM edge boxes. |
| `stmmac` | Synopsys DesignWare | 5.13 | yes | 5.13 | Very common on ARM SoCs. |
| `virtio_net` | KVM/QEMU, most VPS | 4.10 | yes | 5.x | **Needs `combined` queues ≥ CPU count** (`ethtool -L eth0 combined $(nproc)`) and LRO off (`ethtool -K eth0 lro off`). MTU must fit one page minus headroom (~3500). Single-queue instances get generic mode only. |
| `veth` | container/netns pairs | 4.19 | yes | 5.x (with peer) | Both ends matter; a program on one end sees what the peer transmits. XDP on veth is mostly useful for testing. |
| `tun` / `tap` | VPNs, QEMU userspace net | 4.14 | yes | no | Only meaningful with vhost; a userspace VPN process reading `/dev/net/tun` bypasses it. |
| `ena` | AWS Nitro | 5.6 | yes | no | See [AWS ENA](#aws-ena). |
| `gve` | Google Compute Engine | 6.4 (DQO) | yes | no | See [GCP gVNIC](#gcp-gvnic). |
| `hv_netvsc` | Azure / Hyper-V | 4.20 | yes (slow path) | no | See [Azure](#azure-hv_netvsc--accelerated-networking). |
| `xen-netfront` | Xen PV guests | none | n/a | n/a | Generic mode only. |
| `bonding` | bond0 etc. | 5.15 | yes | inherits | Below 5.15, attach to the **slaves**, not the bond. Above it, attaching to the bond propagates to slaves. |
| `team` | teamd | none | n/a | n/a | Attach to the members. |
| `bridge`, `vlan`, `macvlan`, `vxlan`, `wireguard`, `ipip`, `gre` | virtual | none | n/a | n/a | Attach to the **physical** device underneath. XDP runs before VLAN stripping, which is why the parser handles up to two tags itself. |
| everything else | | none | n/a | n/a | Generic mode. Works, but 2-5 Mpps, not 20-40. |

### Reading this table in practice

```sh
ethtool -i eth0 | head -3
```

If the `driver` line is not in the table above, assume generic mode and set:

```ini
xdp_mode = generic
```

Or leave `xdp_mode = auto` and let the loader try native first and fall back —
which is the default, and which is why `attach:` in `calyanti-cli status` is
worth reading after every kernel upgrade.

### VLAN interfaces

If your traffic arrives on `eth0.100`, attach to **`eth0`**, not to
`eth0.100`. XDP runs before the VLAN tag is stripped, so:

- the program on `eth0` sees the tagged frame and parses the tag itself
  (`vlan_inspect = yes`, up to two tags including QinQ);
- a program on `eth0.100` would never run at all, because that netdev has no
  native XDP hook.

Zone configuration follows the physical interface:

```ini
interface = eth0 zone=wan trust-vlan
```

### Bonded interfaces

On kernel 5.15+ attach to `bond0` and the kernel propagates to the slaves.
Below 5.15:

```ini
interface = eth0 zone=wan
interface = eth1 zone=wan
```

Attach to each slave. Per-source rate-limiter state is shared (the maps are
global), so a source arriving on either slave hits the same bucket. That is the
correct behaviour and it is why the maps are not per-interface.

---

## 6. Cloud provider notes

### AWS ENA

The `ena` driver supports native XDP from kernel 5.6, which means Amazon
Linux 2023 (6.1), Ubuntu 20.04+ and any EL9 AMI. Constraints:

- **Queue splitting.** ENA reserves TX queues for XDP. The driver refuses the
  attach if the configured `combined` channel count is more than half of the
  maximum. Check and halve:

  ```sh
  ethtool -l eth0
  sudo ethtool -L eth0 combined $(( $(nproc) / 2 ))
  ```

- **MTU ceiling.** ENA refuses XDP when the interface MTU exceeds roughly 3500
  bytes. If you enabled jumbo frames (9001 is the AWS default inside a VPC on
  many instance types), XDP will not attach:

  ```sh
  ip link show eth0 | grep mtu
  sudo ip link set dev eth0 mtu 1500     # if you can accept it
  ```

  If you need jumbo frames, use generic mode (`xdp_mode = generic`).
- **Enhanced networking must be on.** It is on by default on all Nitro
  instances. `ethtool -i eth0` printing `driver: ena` confirms it.
- **`ena` on older kernels** (Amazon Linux 2 with the 4.14 kernel) has no XDP
  at all — generic mode only, and 4.14 is below the supported floor anyway.
- Elastic Network Adapter statistics worth watching under test:
  `ethtool -S eth0 | grep -E 'bw_in_allowance_exceeded|pps_allowance_exceeded'`.
  **Those counters are the instance-level shaper, not you.** If they climb, the
  hypervisor is dropping packets before your NIC sees them and no host-side
  filter can help; you need a bigger instance or upstream scrubbing.

### GCP gVNIC

- `gve` gained native XDP support relatively late (the DQO queue format,
  kernel 6.4+). Below that, generic mode.
- Older GCE machine types present `virtio_net` instead of `gve`; the virtio
  rules apply (queues, LRO off, MTU).
- gVNIC requires the guest image to advertise the `GVNIC` guest OS feature;
  instances created from images without it get virtio.
- GCE's per-VM egress caps are enforced in the hypervisor. As with AWS, a
  volumetric attack that exceeds your instance's ingress allowance is dropped
  above you and is invisible to XDP.

```sh
ethtool -i eth0            # driver: gve or virtio_net
uname -r                   # >= 6.4 for gve native XDP
```

### Azure hv_netvsc + accelerated networking

This is the one that produces a working-looking install that filters nothing.
Read it carefully.

With accelerated networking enabled, an Azure VM has **two** netdevs:

- the **synthetic** device, `eth0`, driver `hv_netvsc`;
- the **VF**, typically `enP1s2` or similar, driver `mlx4_en` or `mlx5_core`,
  which is enslaved to the synthetic device.

Almost all traffic flows through the VF, bypassing the synthetic device.

**Attach XDP to the synthetic device (`eth0`), never to the VF.** `hv_netvsc`
propagates the XDP program to the VF for you and re-applies it across the
VF hot-remove/hot-add cycles that Azure performs during host maintenance and
live migration. If you attach directly to the VF:

- the program disappears the next time Azure detaches the VF, silently;
- traffic that transiently falls back to the synthetic path is unfiltered.

```sh
ip -br link                    # find the synthetic device and its VF
ethtool -i eth0                # driver: hv_netvsc
ethtool -i enP1s2              # driver: mlx5_core
```

Configure the synthetic device only:

```ini
interface = eth0 zone=wan
```

Other Azure notes:

- `XDP_TX` on `hv_netvsc` goes through the slow path. The SYN proxy works but
  costs more than it does on bare metal; measure before enabling it under load.
- Azure's VF hot-remove during maintenance produces a brief window where the
  program is re-attached. `calyantid` watches netlink for this and re-attaches;
  the gap is milliseconds.
- Accelerated networking is not available on every VM size. Without it there is
  only the synthetic device and `hv_netvsc`'s own XDP path, which is generic-
  speed.

### Other providers

| Provider | Typical driver | Native XDP | Notes |
|---|---|---|---|
| Hetzner Cloud | `virtio_net` | with multiqueue | `ethtool -l` first |
| Hetzner dedicated | `igb`, `ixgbe`, `i40e`, `r8169` | yes except `r8169` | Realtek: generic only |
| DigitalOcean | `virtio_net` | usually single queue | generic mode in practice |
| Linode/Akamai | `virtio_net` | with multiqueue | |
| Vultr | `virtio_net` | with multiqueue | |
| OVH / SoYouStart | `ixgbe`, `i40e`, `bnxt_en`, `virtio_net` | yes | OVH's own anti-DDoS runs upstream of you and will null-route during a large attack; test accordingly |
| Oracle Cloud | `virtio_net`, `mlx5_core` | yes | bare-metal shapes get mlx5 |
| Scaleway | `virtio_net` | with multiqueue | |
| Proxmox guest | `virtio_net` | with multiqueue | set queues in the VM's NIC config, not just in the guest |
| VMware guest | `vmxnet3` | **no** | generic only |
| VirtualBox | `e1000`, `virtio_net` | e1000 no, virtio maybe | development only |

---

## 7. Virtualisation and containers

| Environment | Detection | XDP | Recommended rung |
|---|---|---|---|
| Bare metal | `systemd-detect-virt` says `none` | native | 1 |
| KVM/QEMU | `kvm` | native with multiqueue virtio | 1 or 2 |
| Xen HVM | `xen` | depends on driver | 2 |
| Xen PV | `xen` + `xen-netfront` | generic only | 2 |
| Hyper-V / Azure | `microsoft` | native via `hv_netvsc` | 1 |
| VMware | `vmware` | generic only (`vmxnet3`) | 2 |
| OpenVZ / Virtuozzo | `/proc/user_beancounters` exists | **none** | 4 (or install on the host) |
| LXC/LXD unprivileged | `lxc` | **none** | run on the host |
| LXC/LXD privileged | `lxc` | generic on veth, if `CAP_BPF` + `CAP_NET_ADMIN` | 2/3, limited value |
| Docker / Podman | `docker`, `podman` | **none** by default | run on the host |
| systemd-nspawn | `systemd-nspawn` | none | run on the host |
| WSL2 | `wsl` | generic on `eth0` | development only |

**The rule: XDP belongs on the machine that owns the NIC.** Filtering on a veth
inside a container happens after the host has already received, routed and
copied the packet. That is not mitigation, it is bookkeeping.

Detection commands the installer uses, in case you want to run them yourself:

```sh
systemd-detect-virt            # none | kvm | xen | microsoft | vmware | lxc | docker | openvz
test -e /proc/user_beancounters && echo openvz
test -e /proc/vz && echo openvz-host-or-guest
grep -q container=lxc /proc/1/environ 2>/dev/null && echo lxc
cat /sys/class/dmi/id/sys_vendor 2>/dev/null
```

---

## 8. Architecture notes

Both **x86_64** and **aarch64** are first-class targets. Everything crossing
the ABI boundary is fixed-width, explicitly padded and 8-byte aligned, and
`common.h` proves it with 30 compile-time assertions that fire on both sides,
so a config written by an aarch64 daemon has the same layout as one written by
an x86_64 daemon.

| Concern | x86_64 | aarch64 |
|---|---|---|
| JIT | mature | mature since 4.x, `bpf_jit_enable` on by default on most distros |
| Unaligned access | tolerated | the verifier enforces alignment unless `CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS` is set (it is, on arm64) |
| Common NICs | ixgbe, i40e, ice, mlx5, bnxt | mlx5, thunderx, dpaa2-eth, mvneta, mvpp2, stmmac, ena (Graviton) |
| AWS Graviton | n/a | `ena`, full native XDP |
| Page size | 4 KB | 4 KB, but **64 KB on some RHEL/SLES arm64 kernels** |

The 64 KB page size on some aarch64 kernels matters for one thing: drivers that
size their XDP buffers off `PAGE_SIZE` (virtio in particular) behave
differently. If native attach fails on a 64 KB-page arm64 kernel, check
`getconf PAGESIZE` before assuming a driver bug.

Big-endian architectures (s390x, some MIPS) are **not tested**. The byte-order
discipline in the code is explicit — `caly_v4_src_bogon()` and
`caly_v6_src_bogon()` take a `const __u8 *` to the address bytes precisely so
that a word load's endianness cannot silently disable the filter — but nothing
in CI runs on a big-endian host, so treat it as unsupported rather than broken.

---

## 9. Interacting with other XDP users

Only **one** XDP program can be attached to an interface at a time, unless
every participant uses `libxdp`'s dispatcher. Things that already attach XDP
programs:

| Software | What it attaches | Coexistence |
|---|---|---|
| Cilium | XDP accel on the native device | **conflicts**; do not run both on the same NIC |
| Calico with XDP | XDP on host interfaces | **conflicts** |
| Katran | XDP L4 load balancer | **conflicts** |
| `xdp-tools` / `xdp-filter` | libxdp dispatcher | can coexist via the dispatcher |
| systemd `.link` with `BPFProgram=` | XDP | conflicts |
| some cloud agents | XDP telemetry | check |

Find out what is already there:

```sh
ip -d link show dev eth0 | grep -A3 xdp
bpftool net show
bpftool prog show
```

If something else owns the hook, the attach fails with `-EBUSY`:

```
libbpf: Kernel error message: XDP program already attached
```

Your options: remove the other program, move Caly Anti to the tc rung
(`dataplane = tc-bpf`, which uses clsact and composes fine with an XDP program
above it), or use a different interface.

The daemon attaches with `bpf_link` on kernel 5.9+, which gives it exclusive,
refcounted ownership — a crashed daemon's link is released by the kernel and
the program detaches cleanly. On older kernels it uses netlink attach with
`XDP_FLAGS_REPLACE` where available (5.6+) and a plain attach below that; in
the plain case a `SIGKILL`ed daemon leaves the program attached, and the manual
detach in [TROUBLESHOOTING.md](TROUBLESHOOTING.md) is how you clear it.

---

## 10. Probing anything yourself

```sh
# Ladder rung, capabilities, driver, attach mode - changes nothing:
calyantid --probe

# Does the kernel have the SYN cookie helpers?
bpftool feature probe kernel | grep -i syncookie

# Which map types can this kernel create?
bpftool feature probe kernel | grep -i 'map_type.*ringbuf\|lpm_trie\|lru'

# Which helpers are available to XDP programs specifically?
bpftool feature probe kernel | sed -n '/eBPF helpers supported for program type xdp/,/^$/p'

# Is the tc/clsact classifier compiled in?
grep -E 'CONFIG_NET_CLS_BPF|CONFIG_NET_ACT_BPF|CONFIG_BPF_SYSCALL|CONFIG_XDP_SOCKETS' \
    /boot/config-$(uname -r) 2>/dev/null || zgrep -E 'CONFIG_NET_CLS_BPF' /proc/config.gz

# Will a trivial program attach in native mode on this driver?
cat > /tmp/xdp_pass.c <<'EOF'
#include <linux/bpf.h>
__attribute__((section("xdp"), used))
int pass(struct xdp_md *ctx) { return XDP_PASS; }
char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";
EOF
clang -O2 -g -target bpf -c /tmp/xdp_pass.c -o /tmp/xdp_pass.o
sudo ip link set dev eth0 xdp obj /tmp/xdp_pass.o sec xdp && \
    echo "native XDP OK" && sudo ip link set dev eth0 xdp off
```

That last one is the only test that is not a guess. If it succeeds, rung 1 is
available on that interface; if it fails with `-EOPNOTSUPP`, the driver has no
native XDP and you are on rung 2.
