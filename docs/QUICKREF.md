# Caly Anti - Operator Quick Reference

A one-page cheat sheet. Every command below matches the real `calyctl`
subcommands and installer flags.

## Emergency: turn everything off

If the box becomes unreachable or filtering misbehaves, remove all mitigation:

```sh
sudo /usr/sbin/calyanti-panic      # installed helper
# or, from the source tree:
sudo sh scripts/panic.sh
```

This detaches the XDP program from every interface, clears the tc, nftables,
iptables and ipset rules, unpins the maps, and restores sysctl. Traffic is then
completely unfiltered. It needs only coreutils + `ip` + `nft`/`iptables`.

If even that is unavailable (rescue/serial console), the minimum by hand:

```sh
for i in /sys/class/net/*; do ip link set dev "$(basename "$i")" xdp off; done
nft delete table inet calyanti 2>/dev/null
systemctl stop calyanti calyanti-watch 2>/dev/null
```

## Status and monitoring

```sh
calyctl status              # daemon, interfaces, dataplane, mode, counts
calyctl dashboard           # live TUI: pps/bps, top talkers, mode, events
calyctl stats               # per-reason packet/byte counters
calyctl stats --watch       # refreshing plain-text stats
calyctl top --n 20          # noisiest sources
calyctl conntrack           # active flows
calyctl doctor              # environment diagnosis (kernel, BTF, driver, sysctl)
```

## Modes

```sh
calyctl mode monitor        # evaluate everything, drop nothing (safe default)
calyctl mode normal         # full policy, generous thresholds
calyctl mode elevated       # tighter thresholds
calyctl mode under-attack   # aggressive: SYN proxy on, strict buckets
calyctl mode lockdown       # allowlist + management ports + conntrack only
```

Management ports (SSH/22 and anything configured) always pass, in every mode.

## Lists

```sh
calyctl allow   <cidr>      # never touch this prefix (escape hatch)
calyctl unallow <cidr>
calyctl block   <cidr>      # static blocklist
calyctl unblock <cidr>
calyctl ban     <ip> [--ttl 1h] [--reason note]
calyctl unban   <ip>
calyctl list    allow|block|local|bans
calyctl import  <file> --allow|--block
calyctl export
```

Banning a prefix that contains your own SSH client IP requires `--force`.

## Per-port policy

```sh
calyctl port open  tcp/443
calyctl port close udp/0-65535
calyctl port limit tcp/80 --rate 5000 --burst 10000
```

## Service management

```sh
# systemd
systemctl {status,restart,stop} calyanti
systemctl {enable,start} calyanti-watch     # layer-7 log watcher (optional)
journalctl -u calyanti -n 50 --no-pager

# OpenRC (Alpine)
rc-service calyanti {status,restart,stop}
rc-service calyanti-watch start
```

## Config

```sh
$EDITOR /etc/calyanti/calyanti.conf         # main config
$EDITOR /etc/calyanti/calywatch.conf        # watcher config
calyctl reload                              # apply without restart (SIGHUP)
```

## Install / remove

```sh
sudo scripts/install.sh                      # monitor-only by default
sudo scripts/install.sh --dataplane=auto --enable-watch
sudo scripts/install.sh --uninstall          # or: calyanti-uninstall
```

After install the dataplane starts in monitor-only. Confirm reachability, then
`calyctl mode normal` to begin enforcing.

## Files and paths

| Path | What |
|------|------|
| `/usr/sbin/calyd` | daemon |
| `/usr/sbin/calyctl` | CLI |
| `/usr/sbin/calywatch` | layer-7 log watcher |
| `/etc/calyanti/calyanti.conf` | main config |
| `/etc/calyanti/calywatch.conf` | watcher config |
| `/etc/calyanti/rules/` | watcher rule sets |
| `/run/calyanti/control.sock` | control socket |
| `/sys/fs/bpf/calyanti/` | pinned maps |
| `/var/lib/calyanti/` | state |
