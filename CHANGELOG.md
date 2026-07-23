# Changelog

All notable changes to Caly Anti are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-07-23

Initial release.

### Added

- **eBPF/XDP dataplane** (`src/bpf/`): a CO-RE XDP program with bounds-safe
  parsers for Ethernet, VLAN (QinQ), IPv4/IPv6 with extension headers, and
  one level of IPIP/GRE; per-source token buckets; a conntrack-lite fast path;
  allow/block/dynamic-ban LPM lookups; per-CPU counters and sampled events.
- **SYN handling**: kernel-cookie SYN proxy via the raw syncookie helpers on
  kernels that provide them (5.15+), with SYN rate limiting as the fallback.
- **tc/clsact programs**: an ingress policy program and an egress program that
  records locally originated flows, so replies to our own traffic are never
  mistaken for reflected traffic.
- **Loader/daemon** (`calyd`): libbpf loader with feature probing, per-interface
  attach with native/generic/tc fallback, pinned maps, adaptive escalation, a
  Prometheus endpoint, and a JSON control socket.
- **Control CLI/TUI** (`calyctl`): status, live dashboard, stats, top talkers,
  allow/block/ban management, per-port policy, conntrack view, mode switching,
  config reload, environment `doctor`, and self-test. Python 3.6+, stdlib only.
- **Layer-7 watcher** (`calywatch`): tails web/SSH logs and feeds offenders to
  the ban maps through the control socket, with strict input validation and a
  per-minute ban cap. Ships nginx/apache/sshd/generic rule sets.
- **Non-eBPF fallbacks**: a self-contained nftables table, plus iptables+ipset
  rulesets, for kernels and containers where XDP and tc-BPF are unavailable.
- **Kernel & NIC tuning**: a documented sysctl profile with a backup/restore
  path, and NIC queue/offload tuning compatible with XDP.
- **Universal installer**: distro/package-manager/init/libc/kernel/BTF/NIC
  detection, a best-available dataplane ladder, systemd and OpenRC integration,
  and a monitor-only default so a fresh install never drops the operator.
- **Documentation** (`docs/`): architecture, installation per distro, a
  compatibility matrix, tuning, troubleshooting, security notes, and
  benchmarking guidance.

[1.0.0]: https://example.com/calyanti/releases/tag/v1.0.0
