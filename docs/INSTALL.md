# Caly Anti — Installation

Per-distro installation, from build dependencies to a running daemon.

If you only read one section, read [Pre-flight](#1-pre-flight-run-this-first)
and [First-run configuration](#6-first-run-configuration). Everything else is
package names.

---

## Contents

- [0. What gets installed where](#0-what-gets-installed-where)
- [1. Pre-flight: run this first](#1-pre-flight-run-this-first)
- [2. Build dependencies per distro](#2-build-dependencies-per-distro)
  - [AlmaLinux / Rocky / RHEL / Oracle Linux 8](#almalinux--rocky--rhel--oracle-linux-8)
  - [AlmaLinux / Rocky / RHEL / Oracle Linux 9 and 10, CentOS Stream 9 and 10](#almalinux--rocky--rhel--oracle-linux-9-and-10-centos-stream-9-and-10)
  - [Fedora 38+](#fedora-38)
  - [Amazon Linux 2023](#amazon-linux-2023)
  - [Ubuntu 20.04 LTS](#ubuntu-2004-lts)
  - [Ubuntu 22.04 LTS](#ubuntu-2204-lts)
  - [Ubuntu 24.04 LTS](#ubuntu-2404-lts)
  - [Debian 11 (bullseye)](#debian-11-bullseye)
  - [Debian 12 (bookworm) and 13 (trixie)](#debian-12-bookworm-and-13-trixie)
  - [Arch Linux](#arch-linux)
  - [openSUSE Leap 15.5+ / Tumbleweed / SLES 15](#opensuse-leap-155--tumbleweed--sles-15)
  - [Alpine Linux 3.18+](#alpine-linux-318)
- [3. Build and install](#3-build-and-install)
- [4. The sysctl file](#4-the-sysctl-file)
- [5. Service management](#5-service-management)
- [6. First-run configuration](#6-first-run-configuration)
- [7. Verifying the installation](#7-verifying-the-installation)
- [8. Containers, VPS and anywhere XDP is unavailable](#8-containers-vps-and-anywhere-xdp-is-unavailable)
- [9. Upgrading](#9-upgrading)
- [10. Uninstalling](#10-uninstalling)

---

## 0. What gets installed where

| Path | Contents |
|---|---|
| `/usr/sbin/calyantid` | the loader/daemon |
| `/usr/bin/calyanti-cli` | the CLI |
| `/usr/lib/calyanti/caly_xdp.bpf.o` | the compiled BPF object |
| `/usr/lib/calyanti/caly_tc.bpf.o` | the tc/clsact egress object |
| `/usr/lib/calyanti/nftables.d/` | rung-4 rule templates |
| `/etc/calyanti/calyanti.conf` | configuration (never overwritten by an upgrade) |
| `/etc/sysctl.d/98-calyanti.conf` | `tcp_syncookies` and friends |
| `/etc/logrotate.d/calyanti` | log rotation |
| `/usr/lib/systemd/system/calyanti.service` | unit file (systemd distros) |
| `/etc/init.d/calyanti` | OpenRC script (Alpine) |
| `/sys/fs/bpf/calyanti/` | pinned maps and programs, created at runtime |
| `/run/calyanti/` | control socket and pid file, created at runtime |
| `/var/lib/calyanti/` | persisted bans and feed state |

The pin directory and the run directory are named in `src/bpf/common.h` as
`CALY_PIN_DIR` and `CALY_RUN_DIR`. The config path is `CALY_CONF_PATH`. Those
constants are the authority; if this table ever disagrees with the header, the
header wins.

---

## 1. Pre-flight: run this first

Four checks. Run them before you install anything. They take ten seconds and
they tell you which rung of the ladder you are going to land on.

```sh
# 1. Kernel version. 4.18 is the floor. 5.15+ unlocks the SYN proxy.
uname -r

# 2. BTF. Present means CO-RE works and rungs 1-3 are available.
#    Absent means rung 4 (nftables), and that is a supported outcome.
ls -l /sys/kernel/btf/vmlinux

# 3. Which driver is behind your internet-facing interface.
ip -br link
ethtool -i eth0 | grep -E '^(driver|version)'

# 4. Are you in a container or a VM that cannot do XDP at all?
systemd-detect-virt || true
test -e /proc/user_beancounters && echo "OpenVZ: XDP unavailable"
```

Interpretation:

| Observation | Consequence |
|---|---|
| Kernel < 4.18 | Not supported for eBPF rungs. Rung 4 or 5 only. |
| `/sys/kernel/btf/vmlinux` missing | Rung 4 (nftables). Not an error. See [BTF is missing](#btf-is-missing). |
| `systemd-detect-virt` says `openvz`, `lxc`, `lxc-libvirt` | No XDP. Rung 3 if the container has `CAP_BPF` and `CAP_NET_ADMIN`, otherwise rung 4. |
| Driver is `virtio_net` | Native XDP needs multiqueue; see [COMPATIBILITY.md](COMPATIBILITY.md). |
| Kernel >= 5.15 | SYN proxy available. Set `net.ipv4.tcp_syncookies = 2`. |

### BTF is missing

Some distro kernels are built without `CONFIG_DEBUG_INFO_BTF`. Your options, in
order of preference:

1. Install a kernel that has it. On EL8 that means 4.18.0-193 or newer
   (RHEL 8.2+). On Debian 11, a `bullseye-backports` kernel. On Ubuntu 20.04,
   the HWE kernel: `apt install linux-generic-hwe-20.04`.
2. Generate a BTF blob for your running kernel with
   [`pahole`](https://git.kernel.org/pub/scm/devel/pahole/pahole.git) against a
   vmlinux with DWARF, and point the loader at it. This is a specialist
   operation and only worth it on a kernel you build yourself.
3. Accept rung 4. `calyantid` will configure nftables, the policy is preserved,
   and you lose per-source token buckets, scan detection, conntrack-lite and
   the SYN proxy. Say so explicitly in the config so nobody is surprised:

   ```ini
   dataplane = nftables
   ```

**Do not** let a missing BTF turn into a failed install. It is a documented,
supported outcome.

---

## 2. Build dependencies per distro

Every command below assumes you are root or using `sudo`.

Common requirements, whatever the distro:

| Requirement | Minimum | Why |
|---|---|---|
| `clang` | 10 | BPF CO-RE relocations (`-target bpf -g`) need clang 10+ |
| `llvm` (`llvm-strip`) | matching clang | stripping DWARF from the BPF object |
| `libbpf` | 0.8 (1.0+ preferred) | `bpf_program__set_autoload()`, `libbpf_probe_bpf_helper()`, `libbpf_probe_bpf_map_type()` |
| `libelf`, `zlib` | any | libbpf link dependencies |
| `bpftool` | any | generating `vmlinux.h`, and diagnostics |
| C compiler + make | any | the userspace side |

When the distro's `libbpf` is older than 0.8 the build uses the bundled copy in
`third_party/libbpf` and links it statically. That is decided automatically;
you can force it either way:

```sh
make LIBBPF=bundled      # always build and statically link the vendored copy
make LIBBPF=system       # fail rather than vendoring
```

The **Vendored libbpf** column below says which distros need it.

| Distro | clang | libbpf pkg | Vendored libbpf | bpftool pkg |
|---|---|---|---|---|
| RHEL/Alma/Rocky/Oracle 8 | `clang` (AppStream) | `libbpf-devel` (0.4-0.5) | yes | `bpftool` |
| RHEL/Alma/Rocky/Oracle 9, Stream 9 | `clang` | `libbpf-devel` (1.x on 9.2+) | on 9.0/9.1 | `bpftool` |
| RHEL/Alma/Rocky 10, Stream 10 | `clang` | `libbpf-devel` (1.5+) | no | `bpftool` |
| Fedora 38+ | `clang` | `libbpf-devel` (1.x) | no | `bpftool` |
| Amazon Linux 2023 | `clang` | `libbpf-devel` (1.x) | no | `bpftool` |
| Ubuntu 20.04 | `clang-12` | `libbpf-dev` (0.1) | yes | `linux-tools-$(uname -r)` |
| Ubuntu 22.04 | `clang-14` | `libbpf-dev` (0.5) | yes | `linux-tools-$(uname -r)` |
| Ubuntu 24.04 | `clang-18` | `libbpf-dev` (1.3) | no | `linux-tools-$(uname -r)` |
| Debian 11 | `clang-13` | `libbpf-dev` (0.3) | yes | `bpftool` |
| Debian 12 | `clang-14` | `libbpf-dev` (1.1) | no | `bpftool` |
| Debian 13 | `clang-19` | `libbpf-dev` (1.5) | no | `bpftool` |
| Arch | `clang` | `libbpf` | no | `bpf` |
| openSUSE Leap 15.5+ | `clang` | `libbpf-devel` | no | `bpftool` |
| Tumbleweed | `clang` | `libbpf-devel` | no | `bpftool` |
| Alpine 3.18+ | `clang` | `libbpf-dev` | no | `bpftool` |

---

### AlmaLinux / Rocky / RHEL / Oracle Linux 8

Kernel 4.18 (RHCK). No SYN cookie helpers, no ring buffer — the fallbacks are
automatic. Oracle's UEK7 is 5.15 and *does* have both; check with
`uname -r` which kernel you actually booted.

```sh
dnf install -y \
    clang llvm llvm-devel \
    libbpf-devel elfutils-libelf-devel zlib-devel \
    bpftool make gcc pkgconf-pkg-config \
    kernel-headers kernel-devel
```

RHEL 8 only, to get the entitlement for CodeReady Builder (Alma/Rocky have this
enabled already):

```sh
subscription-manager repos --enable codeready-builder-for-rhel-8-$(arch)-rpms
```

Alma/Rocky/Oracle 8 equivalent, if `llvm-devel` is not found:

```sh
dnf config-manager --set-enabled powertools   # Rocky/Alma 8
dnf config-manager --set-enabled ol8_codeready_builder   # Oracle 8
```

EL8's `libbpf` is too old for the loader's probe APIs, so the build vendors it:

```sh
make LIBBPF=bundled
```

BTF check on EL8: present since 4.18.0-193 (RHEL 8.2). If
`/sys/kernel/btf/vmlinux` is missing, update the kernel.

---

### AlmaLinux / Rocky / RHEL / Oracle Linux 9 and 10, CentOS Stream 9 and 10

Kernel 5.14 on EL9 and 6.12 on EL10. EL9's 5.14 is heavily backported and
**does** carry the raw syncookie helpers despite the version number — the
loader probes for them rather than checking `uname`, which is why this works.

```sh
dnf install -y \
    clang llvm libbpf-devel elfutils-libelf-devel zlib-devel \
    bpftool make gcc pkgconf-pkg-config kernel-headers

# RHEL 9/10 only:
subscription-manager repos --enable codeready-builder-for-rhel-9-$(arch)-rpms
# Alma/Rocky 9/10:
dnf config-manager --set-enabled crb
# Oracle 9:
dnf config-manager --set-enabled ol9_codeready_builder
```

```sh
make && make install
```

---

### Fedora 38+

```sh
dnf install -y clang llvm libbpf-devel elfutils-libelf-devel zlib-devel \
               bpftool make gcc pkgconf-pkg-config kernel-headers
make && make install
```

---

### Amazon Linux 2023

Kernel 6.1, BTF present, everything available including the SYN proxy.

```sh
dnf install -y clang llvm libbpf-devel elfutils-libelf-devel zlib-devel \
               bpftool make gcc kernel-headers
make && make install
```

**Amazon Linux 2** (kernel 4.14/5.10 depending on the `amazon-linux-extras`
kernel you selected) is *not* supported on rungs 1-3 with the 4.14 kernel; the
floor is 4.18. On AL2 with the 5.10 kernel from `extras`, it works. Check with
`uname -r`.

The ENA driver has XDP constraints; see
[COMPATIBILITY.md](COMPATIBILITY.md#aws-ena).

---

### Ubuntu 20.04 LTS

GA kernel is 5.4; the HWE kernel is 5.15 and unlocks the SYN proxy. Use HWE if
you can.

```sh
apt update
apt install -y \
    clang-12 llvm-12 \
    libbpf-dev libelf-dev zlib1g-dev \
    linux-tools-common linux-tools-generic linux-tools-$(uname -r) \
    make gcc pkg-config linux-headers-$(uname -r)

# Optional but recommended: 5.15 kernel, which brings the SYN proxy.
apt install -y linux-generic-hwe-20.04 && reboot
```

`clang` is not a default alternative on 20.04, so point the build at the
versioned binary, and vendor libbpf (the packaged 0.1.0 is far too old):

```sh
make CLANG=clang-12 LLVM_STRIP=llvm-strip-12 LIBBPF=bundled
make install
```

---

### Ubuntu 22.04 LTS

Kernel 5.15. Everything is available.

```sh
apt update
apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
               linux-tools-common linux-tools-$(uname -r) \
               make gcc pkg-config linux-headers-$(uname -r)
make LIBBPF=bundled     # packaged libbpf is 0.5, below the 0.8 floor
make install
```

---

### Ubuntu 24.04 LTS

Kernel 6.8, libbpf 1.3, clang 18. Nothing special.

```sh
apt update
apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
               linux-tools-common linux-tools-$(uname -r) \
               make gcc pkg-config linux-headers-$(uname -r)
make && make install
```

---

### Debian 11 (bullseye)

Kernel 5.10. No SYN proxy (helpers are 5.15+); the SYN rate-limit fallback is
selected automatically.

```sh
apt update
apt install -y clang-13 llvm-13 libbpf-dev libelf-dev zlib1g-dev \
               bpftool make gcc pkg-config linux-headers-$(uname -r)
make CLANG=clang-13 LLVM_STRIP=llvm-strip-13 LIBBPF=bundled
make install
```

**Check BTF explicitly on bullseye.** Some point-release kernels were built
without `CONFIG_DEBUG_INFO_BTF`:

```sh
ls -l /sys/kernel/btf/vmlinux || echo "no BTF: use backports kernel or rung 4"
```

A backports kernel fixes it:

```sh
echo 'deb http://deb.debian.org/debian bullseye-backports main' \
    > /etc/apt/sources.list.d/backports.list
apt update
apt -t bullseye-backports install -y linux-image-amd64
reboot
```

---

### Debian 12 (bookworm) and 13 (trixie)

Kernel 6.1 and 6.12. Everything available.

```sh
apt update
apt install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
               bpftool make gcc pkg-config linux-headers-$(uname -r)
make && make install
```

---

### Arch Linux

`bpftool` lives in the `bpf` package, not `bpftool`.

```sh
pacman -S --needed clang llvm libbpf bpf zlib base-devel linux-headers
make && make install
```

---

### openSUSE Leap 15.5+ / Tumbleweed / SLES 15

```sh
zypper install -y clang llvm libbpf-devel libelf-devel zlib-devel \
                  bpftool make gcc pkg-config kernel-devel
make && make install
```

On **SLES 15** the toolchain lives behind a module that must be activated
first:

```sh
SUSEConnect -p sle-module-development-tools/15.5/$(uname -m)
zypper refresh
```

Leap 15.5 ships kernel 5.14 (SLE backports; probe decides on SYN proxy
availability), Leap 15.6 ships 6.4, Tumbleweed tracks mainline.

---

### Alpine Linux 3.18+

musl libc and OpenRC. Alpine's kernel (`linux-lts`) has BTF enabled.

```sh
apk add --no-cache \
    clang llvm libbpf-dev elfutils-dev zlib-dev bpftool \
    build-base linux-headers musl-dev bsd-compat-headers pkgconf \
    argp-standalone
make && make install
```

Notes for musl:

- `argp-standalone` is needed because musl does not provide `argp.h`. If your
  build does not use argp it is harmless.
- `bsd-compat-headers` provides `sys/queue.h`, which libbpf uses.
- Alpine's `linux-lts` is the kernel to use. `linux-virt` also has BTF; the
  `linux-edge` package tracks mainline.
- OpenRC, not systemd — see [Service management](#5-service-management).

If you run Alpine as a **container** rather than as the host OS, you are almost
certainly on rung 4 or 5; see
[section 8](#8-containers-vps-and-anywhere-xdp-is-unavailable).

---

## 3. Build and install

```sh
git clone https://github.com/calyanti/caly-anti.git
cd caly-anti

make                      # builds vmlinux.h from the running kernel's BTF,
                          # compiles the BPF objects and the userspace binaries
sudo make install         # installs to the paths in section 0
```

Useful build variables:

| Variable | Default | Purpose |
|---|---|---|
| `CLANG` | `clang` | path to clang (use `clang-12` etc. on old Ubuntu/Debian) |
| `LLVM_STRIP` | `llvm-strip` | must match the clang version |
| `LIBBPF` | `auto` | `system`, `bundled`, or `auto` |
| `PREFIX` | `/usr` | install prefix |
| `SYSCONFDIR` | `/etc` | config prefix |
| `ARCH` | autodetected | `x86_64` or `arm64` |
| `VMLINUX_BTF` | `/sys/kernel/btf/vmlinux` | source for `vmlinux.h` |
| `DEBUG` | unset | build with `-O1 -g` and verbose verifier logs |

### Cross-building, and building where the target has no BTF

`vmlinux.h` is generated at **build** time from BTF and the object is CO-RE
relocatable, so it does not have to match the target kernel exactly. To build
on a machine whose BTF differs from the target's:

```sh
# On any machine with the target kernel's BTF blob:
bpftool btf dump file /path/to/target/vmlinux format c > src/bpf/vmlinux.h
make VMLINUX_H=src/bpf/vmlinux.h
```

The *runtime* check is only whether the running kernel exposes BTF for CO-RE
relocation. `bpftool` is not required at runtime.

---

## 4. The sysctl file

`make install` writes `/etc/sysctl.d/98-calyanti.conf`:

```ini
# Caly Anti - required and recommended kernel tunables.

# MANDATORY when the XDP SYN proxy is active (kernel 5.15+).
# 2 = issue and accept cookies unconditionally.
# At 1 the kernel only honours cookies once the accept queue overflows, so the
# cookies our XDP program already handed out are not recognised when the ACK
# comes back, and every proxied connection dies silently.
net.ipv4.tcp_syncookies = 2

# Do not send ICMP redirects; do not accept them.
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Do not accept source-routed packets.
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Reverse-path filtering in loose mode. Strict (1) breaks asymmetric routing
# and multihoming; loose (2) still stops the crudest spoofing.
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2

# Larger backlogs so a burst that survives XDP does not die at the socket.
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_max_syn_backlog = 8192
net.core.somaxconn = 4096

# Ignore broadcast pings (smurf).
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
```

Apply without rebooting:

```sh
sudo sysctl --system
sysctl net.ipv4.tcp_syncookies      # must print 2 for the SYN proxy
```

**On Alpine** `sysctl` is the busybox applet, which has no `--system` option
and would apply nothing. Load the drop-in explicitly, or use the OpenRC service
(both read `/etc/sysctl.d/*.conf`):

```sh
sudo sysctl -p /etc/sysctl.d/98-calyanti.conf   # or: sudo rc-service sysctl restart
sysctl net.ipv4.tcp_syncookies      # must print 2 for the SYN proxy
```

**If you are on a kernel older than 5.15**, the SYN proxy is not loaded and
`net.ipv4.tcp_syncookies = 1` is the correct value — the kernel's own cookie
mechanism is then your SYN defence, alongside the per-source `rate_syn` bucket
and `syn_fallback_pps`. `calyantid --probe` tells you which case you are in and
the installer writes the matching value.

**`rp_filter = 2` is a deliberate choice.** Strict mode (1) drops legitimate
traffic on any host with asymmetric routing or more than one uplink. If you
have a single uplink and no policy routing, `1` is strictly better; change it
knowingly.

---

## 5. Service management

### systemd (everything except Alpine)

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now calyanti
systemctl status calyanti
journalctl -u calyanti -f
```

Reload configuration without detaching the dataplane:

```sh
sudo systemctl reload calyanti      # or: sudo calyanti-cli reload
```

A reload rewrites `caly_config` and the policy maps in place. The XDP program
is never detached, so there is no window in which the box is unprotected.

The unit runs as root because loading BPF programs, attaching XDP and creating
pins all require it. On kernel 5.8+ the necessary capability set is
`CAP_BPF CAP_NET_ADMIN CAP_PERFMON` plus `CAP_SYS_RESOURCE` for the memlock
limit; before 5.8 it is `CAP_SYS_ADMIN`. See
[SECURITY.md](SECURITY.md#privilege-model).

### OpenRC (Alpine)

```sh
rc-update add calyanti default
rc-service calyanti start
rc-service calyanti status
tail -f /var/log/calyanti.log
```

Reload:

```sh
rc-service calyanti reload
```

Alpine's OpenRC script sources `/etc/conf.d/calyanti` for daemon flags:

```sh
# /etc/conf.d/calyanti
CALYANTI_OPTS="--config /etc/calyanti/calyanti.conf"
```

### Memory lock limit

BPF maps at the shipped defaults need roughly **220 MB** of locked kernel
memory, dominated by `caly_rate4/6` (524288 entries of ~160 B) and `caly_conn`
(262144 of ~120 B).

On kernel **5.11 and newer** BPF memory is charged to the cgroup memory
controller and `RLIMIT_MEMLOCK` is irrelevant. On **older kernels** the limit
applies and the default (64 KB) is nowhere near enough. The unit file sets:

```ini
LimitMEMLOCK=infinity
```

If you run the daemon by hand on a pre-5.11 kernel:

```sh
ulimit -l unlimited
```

On a small VPS, cut the memory instead of raising the limit:

```ini
max_rate_entries = 65536
max_conn_entries = 65536
max_scan_entries = 32768
max_srcstat_entries = 32768
max_ban_entries = 65536
```

That is roughly 30 MB. These knobs are read **before** map creation, so they
take effect on daemon restart, not on reload.

### bpffs

Pins live in `/sys/fs/bpf`. systemd mounts it automatically. If it is missing:

```sh
mount | grep bpf || sudo mount -t bpf bpffs /sys/fs/bpf
```

To make it permanent on a system without systemd's automount:

```sh
echo 'bpffs /sys/fs/bpf bpf defaults 0 0' | sudo tee -a /etc/fstab
```

---

## 6. First-run configuration

Four edits to `/etc/calyanti/calyanti.conf`, in this order. Do not skip the
first one.

### a. Management ports

```ini
mgmt_tcp_ports = 22
# If you moved SSH:
# mgmt_tcp_ports = 22, 2222
```

TCP/22 is forced into this list by the loader in every mode, including
`under-attack` and `lockdown`. A config that would remove it is rejected and
the previous config keeps running. If you moved SSH, **add** your real port —
do not assume removing 22 works, because it will be put back and you will end
up with both. That is intended.

### b. Interface zones

```ini
interface = eth0 zone=wan
interface = eth1 zone=lan
default_zone = lan
```

Bogon filtering, RFC1918-source rejection and the reflection filter apply on
**WAN-zone interfaces only**. Until you set this, the most valuable checks in
the suite are inert. This is the single most common "I installed it and nothing
happened" cause.

Available per-interface flags: `monitor`, `disabled`, `drop-private`,
`no-ipv6`, `trust-vlan`.

### c. Allowlist

```ini
allow = 203.0.113.0/24        # office egress
allow = 198.51.100.10/32      # monitoring
allow = 2001:db8:1234::/48    # office IPv6
```

An allowlist hit returns `XDP_PASS` immediately, before the blocklist, before
bans, before every rate limiter and before every anomaly rule. Put your admin
networks, monitoring probes, load balancers and backup servers here. Keep it
short: an allowlisted source that gets compromised walks past every control.

### d. Monitor mode for the first week

```ini
monitor_only = yes
```

Then validate and start:

```sh
sudo calyanti-cli check /etc/calyanti/calyanti.conf
sudo systemctl enable --now calyanti
```

`check` parses the file, applies every loader invariant (management port
present, mandatory ICMP types not dropped, thresholds in range) and prints what
it would change — without touching the running configuration.

Read [TUNING.md](TUNING.md) before turning `monitor_only` off.

---

## 7. Verifying the installation

```sh
calyanti-cli status
```

Expected shape:

```
Caly Anti 1.0 (ABI 1.0)   mode: monitor-only   uptime: 00:04:11
dataplane: xdp-native     attach: DRV_MODE
interfaces: eth0 (wan, ifindex 2), eth1 (lan, ifindex 3)
capabilities: BTF SYNPROXY RINGBUF XDP_NATIVE XDP_TX TC_EGRESS BATCH_OPS
config generation: 1   pinned at /sys/fs/bpf/calyanti
```

The `capabilities` line is the loader's probe result, mirrored into
`fw_config.flags` bits 32-39. Missing `SYNPROXY` means kernel < 5.15 (or the
helper probe failed) and the rate-limit fallback is in use. Missing `RINGBUF`
means kernel < 5.8 and events go over the perf event array. Both are normal.

Cross-check with the kernel's own view:

```sh
# XDP program attached?
ip -d link show dev eth0 | grep -A2 xdp
bpftool net show

# Programs and maps loaded?
bpftool prog show | grep caly
bpftool map show | grep caly

# Pins in place?
ls -l /sys/fs/bpf/calyanti/
```

Confirm packets are actually being seen:

```sh
calyanti-cli stats | head -20
```

`pkt_total` should be climbing. If it is zero while traffic is flowing, the
program is attached to the wrong interface, or the interface is in a zone that
bypasses (`pass_lan_iface`), or the master switch is off (`pass_disabled`).
`calyanti-cli stats` names the reason directly.

Finally, prove you have not locked yourself out — from a **second** terminal,
while the first is still connected:

```sh
ssh -o ConnectTimeout=5 you@thishost true && echo "SSH still works"
```

---

## 8. Containers, VPS and anywhere XDP is unavailable

### Where XDP does not exist at all

| Environment | XDP | What to do |
|---|---|---|
| OpenVZ / Virtuozzo container | none | rung 4/5, on the **host** if you control it |
| LXC / LXD unprivileged container | none | run on the host, not in the container |
| LXC privileged with `CAP_BPF` + `CAP_NET_ADMIN` | generic on veth only | rung 2 or 3, limited value |
| Docker/Podman container | none by default | run the daemon on the host |
| systemd-nspawn | none | run on the host |
| KVM/QEMU guest with virtio_net | yes, native with multiqueue | see below |
| Xen PV (`xen-netfront`) | generic only | rung 2 |
| Hyper-V (`hv_netvsc`) | yes, attach to the synthetic device | see COMPATIBILITY.md |
| Bare metal | yes | rung 1 |

**The rule for containers is simple: XDP belongs on the host.** A container
does not own the NIC. Filtering at the veth inside the container happens after
the host has already paid the cost of receiving, routing and copying the
packet, which defeats the point.

If you genuinely cannot run on the host — a managed container platform, for
example — pin the dataplane to nftables and accept a static policy:

```ini
dataplane = nftables
```

### virtio_net (most VPS providers: Hetzner, DigitalOcean, Linode, Vultr, OVH)

Native XDP on virtio-net needs as many queues as CPUs, and needs guest
offloads that XDP cannot handle to be off.

```sh
# How many queues does the device offer, and how many are configured?
ethtool -l eth0

# Raise combined queues to the CPU count (must be <= "Pre-set maximums"):
sudo ethtool -L eth0 combined $(nproc)

# XDP cannot process LRO-coalesced frames:
sudo ethtool -K eth0 lro off gro off
```

If `Pre-set maximums: Combined: 1`, the hypervisor gave you a single queue and
native XDP is not available. Generic mode still works:

```ini
xdp_mode = generic
```

Generic mode is roughly five times slower than native and `XDP_TX` goes through
the slow path, which is why the SYN proxy is disabled by default on rung 2.
That is a deliberate default, not an oversight: a slow `XDP_TX` under a SYN
flood costs more than it saves.

Also note the MTU limit: native XDP on virtio requires the frame to fit in one
page minus headroom, so an MTU above roughly 3500 disables it.

### Very small VPS instances

On a 1 GB / 1 vCPU box, the default maps alone will not fit. Set:

```ini
max_rate_entries    = 65536
max_conn_entries    = 65536
max_scan_entries    = 32768
max_srcstat_entries = 32768
max_ban_entries     = 65536
max_block_entries   = 65536
src_stats           = no        # saves one LRU update per packet
event_pages         = 4         # 16 KiB per CPU instead of 64 KiB
```

That brings locked memory to roughly 30 MB. These are read before map creation,
so restart the daemon rather than reloading.

### Cloud provider specifics

AWS ENA, GCP gVNIC and Azure accelerated networking each have their own
constraints — queue splitting, MTU ceilings, and which netdev to attach to.
They are documented in
[COMPATIBILITY.md](COMPATIBILITY.md#cloud-provider-notes). Read that section
before your first attach on a cloud instance; attaching to the wrong device on
Azure in particular produces a working-looking install that filters nothing.

---

## 9. Upgrading

```sh
cd caly-anti
git pull
make
sudo make install         # does NOT overwrite /etc/calyanti/calyanti.conf
sudo systemctl restart calyanti
```

A **restart** (not a reload) is required when the BPF object changes, because
maps are re-created with sizes read from `max_*_entries`. State that does not
survive a restart: conntrack-lite entries, rate-limiter state, scan windows,
top-talker counters. State that does survive: anything persisted in
`/var/lib/calyanti/` — bans and feed contents are re-inserted after the new
maps come up.

### ABI major version changes

`CALY_ABI_VERSION` is `(major << 16) | minor`, currently `1.0`. The loader
refuses to attach when the major version it was compiled with differs from the
major in a pinned config map. If you see:

```
calyantid: pinned config has ABI major 1, this build is major 2 - refusing
```

remove the stale pins and restart:

```sh
sudo systemctl stop calyanti
sudo rm -rf /sys/fs/bpf/calyanti
sudo systemctl start calyanti
```

Minor version bumps are additive (new knobs consume `fw_config.reserved[]`) and
need no intervention.

---

## 10. Uninstalling

```sh
sudo systemctl disable --now calyanti     # or: rc-update del calyanti default
sudo make uninstall
```

Then confirm nothing is left attached:

```sh
ip link show | grep -E 'xdp|prog'
bpftool net show
ls /sys/fs/bpf/calyanti 2>/dev/null
```

If anything survives — for example because the daemon was killed with
`SIGKILL` before it could clean up:

```sh
for i in $(ls /sys/class/net); do
    sudo ip link set dev "$i" xdp off        2>/dev/null
    sudo ip link set dev "$i" xdpgeneric off 2>/dev/null
    sudo tc qdisc del dev "$i" clsact        2>/dev/null
done
sudo rm -rf /sys/fs/bpf/calyanti
```

Programs and maps are refcounted: once the last pin and the last attachment are
gone, the kernel frees them. `bpftool prog show` confirms it.

Configuration and state are left in place deliberately. Remove them explicitly
if you want them gone:

```sh
sudo rm -rf /etc/calyanti /var/lib/calyanti /etc/sysctl.d/98-calyanti.conf
sudo sysctl --system      # revert the sysctls to distro defaults
```
