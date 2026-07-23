# Caly Anti — Troubleshooting

Start with [section 0](#0-the-panic-button) if traffic has stopped. Everything
else can wait until the box is reachable again.

---

## Contents

- [0. The panic button](#0-the-panic-button)
- [1. Out-of-band recovery](#1-out-of-band-recovery)
- [2. "Traffic stopped entirely"](#2-traffic-stopped-entirely)
- [3. Legitimate traffic is being dropped](#3-legitimate-traffic-is-being-dropped)
- [4. Nothing is being dropped](#4-nothing-is-being-dropped)
- [5. The BPF program will not load: reading verifier logs](#5-the-bpf-program-will-not-load-reading-verifier-logs)
- [6. XDP will not attach](#6-xdp-will-not-attach)
- [7. Conflicting XDP programs](#7-conflicting-xdp-programs)
- [8. BTF is missing](#8-btf-is-missing)
- [9. bpffs is not mounted](#9-bpffs-is-not-mounted)
- [10. Map creation and memory failures](#10-map-creation-and-memory-failures)
- [11. Events are missing or lost](#11-events-are-missing-or-lost)
- [12. The SYN proxy is not working](#12-the-syn-proxy-is-not-working)
- [13. Performance problems](#13-performance-problems)
- [14. PMTUD, IPv6 and "it connects then hangs"](#14-pmtud-ipv6-and-it-connects-then-hangs)
- [15. Collecting a diagnostic bundle](#15-collecting-a-diagnostic-bundle)

---

## 0. The panic button

Four escalating steps. Try them in order; stop as soon as the box is healthy.

```sh
# 1. Stop enforcing. Everything stays loaded and keeps counting.
sudo calyanti-cli mode monitor-only

# 2. Stop the daemon and clean up its attachments.
sudo systemctl stop calyanti

# 3. Detach XDP by hand. Needs no Caly Anti binary and no working config.
sudo ip link set dev eth0 xdp off
sudo ip link set dev eth0 xdpgeneric off
sudo tc qdisc del dev eth0 clsact

# 4. Remove every pin so nothing can be reloaded from state, and stop it
#    coming back on the next boot.
sudo rm -rf /sys/fs/bpf/calyanti
sudo systemctl disable --now calyanti
sudo systemctl mask calyanti
```

For every interface at once, when you do not know which one is the problem:

```sh
for i in $(ls /sys/class/net); do
    sudo ip link set dev "$i" xdp off        2>/dev/null
    sudo ip link set dev "$i" xdpgeneric off 2>/dev/null
    sudo tc qdisc del dev "$i" clsact        2>/dev/null
done
```

Verify nothing is left:

```sh
ip -d link show | grep -i xdp
bpftool net show
bpftool prog show | grep caly
```

Programs and maps are refcounted. Once the last pin and the last attachment are
gone, the kernel frees them.

---

## 1. Out-of-band recovery

You cannot reach the box over the network. This is what the console is for.

### Getting a console

| Environment | How |
|---|---|
| Bare metal with IPMI/iDRAC/iLO | SOL: `ipmitool -I lanplus -H bmc -U admin sol activate` |
| AWS EC2 | EC2 Serial Console (Nitro instances), or detach the volume and mount it elsewhere |
| GCP | `gcloud compute connect-to-serial-port INSTANCE` |
| Azure | Serial Console in the portal, or `az serial-console connect` |
| Hetzner | vKVM / Rescue System from Robot or Cloud Console |
| DigitalOcean / Linode / Vultr | Recovery Console in the panel |
| Proxmox / libvirt | `virsh console DOMAIN`, or the noVNC console |
| OVH | IPMI/KVM from the manager, or netboot to rescue |

If the serial console is not enabled on a cloud instance, enable it *now*, on
every host, before you need it. It is the difference between a five-minute fix
and a volume-detach-and-mount afternoon.

### From the console

```sh
# What is attached, and to what?
ip -d link show | grep -B3 -i xdp
bpftool net show

# Nuclear detach, per section 0 step 3-4.
for i in $(ls /sys/class/net); do
    ip link set dev "$i" xdp off        2>/dev/null
    ip link set dev "$i" xdpgeneric off 2>/dev/null
    tc qdisc del dev "$i" clsact        2>/dev/null
done
rm -rf /sys/fs/bpf/calyanti
systemctl mask calyanti
```

Then test connectivity from outside before you go any further.

### If the daemon starts before you can log in

Mask the unit from a rescue environment so it never runs:

```sh
# Booted into a rescue/live image with the root filesystem at /mnt:
ln -sf /dev/null /mnt/etc/systemd/system/calyanti.service
# Alpine/OpenRC:
rm -f /mnt/etc/runlevels/default/calyanti
```

Or add `systemd.mask=calyanti.service` to the kernel command line at the
bootloader prompt — press `e` at the GRUB menu, append it to the `linux` line,
`Ctrl-X` to boot. That is a one-shot change; it does not persist.

Belt and braces from the bootloader, if you suspect the network stack itself:

```
systemd.unit=rescue.target
```

### Why this should never be necessary

Six invariants exist specifically to prevent it:

1. TCP/22 is forced into the management port list in every mode, including
   `under-attack` and `lockdown`. A config that would remove it is rejected and
   the previous config keeps running.
2. The allowlist and the management-port check precede every drop rule.
3. ICMPv6 types 2, 133, 134, 135, 136 can never be set to drop.
4. ICMPv4 type 3 can never be set to drop, so PMTUD survives.
5. Every internal failure fails open: missing config, NULL scratch, failed tail
   call, full LRU, full event ring — all `XDP_PASS` plus a counter.
6. `XDP_ABORTED` is never returned.

If you needed this section, one of those was violated. That is a bug worth
reporting with the diagnostic bundle from
[section 15](#15-collecting-a-diagnostic-bundle).

---

## 2. "Traffic stopped entirely"

Work down this list. Each step tells you whether to continue.

### Step 1: is it Caly Anti at all?

```sh
sudo ip link set dev eth0 xdp off
sudo ip link set dev eth0 xdpgeneric off
```

If traffic returns, it is us. If not, stop reading this document and look at
routing, the link, the upstream, or the other firewall.

### Step 2: which counter is charged?

Re-attach and look at what the dataplane says it is doing:

```sh
sudo systemctl start calyanti
calyanti-cli stats --json | jq -r '
  .counters | to_entries | map(select(.value.packets > 0))
  | sort_by(-.value.packets)[:15][] | "\(.value.packets)\t\(.key)"'
```

The top drop reason is the answer. Common ones and what they mean:

| Reason | Cause | Fix |
|---|---|---|
| `drop_lockdown` | mode is `lockdown` | `calyanti-cli mode normal` |
| `drop_default_deny` | `default_deny = yes` with a service you did not list | add the `tcp_port`/`udp_port` rule, or set `default_deny = no` |
| `drop_port_closed` | an explicit `closed` rule | fix the rule |
| `drop_private_src` | `wan_drop_private = yes` behind NAT/VPC/CGNAT | set it to `no` |
| `drop_bogon_src` | a LAN interface is in the WAN zone | fix the `interface =` zone |
| `drop_ip6_disabled` | `ipv6 = no` — which **drops** IPv6, it does not bypass it | `ipv6 = yes` |
| `drop_ban_active` | your own address got auto-banned | `calyanti-cli ban del <ip>`, then allowlist it |
| `drop_blocklist` | a threat feed contains your prefix | `calyanti-cli block del <cidr>`; allowlist wins over blocklist |
| `drop_rate_*` | a bucket is far too tight | raise it; see TUNING.md |
| `drop_l4_unknown` | a protocol other than TCP/UDP/ICMP (ESP, SCTP, GRE) | those are refused by default; open them explicitly |
| `drop_l3_unknown` | `drop_unknown_ethertype = yes` killing PPPoE/LLDP/802.1X | set it to `no` |
| `drop_icmp6_type` | an ICMPv6 type you need is not permitted | check `icmp6_type` lines |

### Step 3: if `pass_*` dominates but traffic still does not work

The dataplane is passing and something downstream is dropping. Check in order:

```sh
# Real conntrack and netfilter:
sudo nft list ruleset | head -50
sudo iptables -L -n -v | head -50
conntrack -S 2>/dev/null | head

# Kernel-level drops:
ip -s link show dev eth0
ethtool -S eth0 | grep -Ei 'drop|discard|err|miss|no_buf'
nstat -az | grep -Ei 'drop|Listen|Overflow|Prune'
```

`ListenOverflows` and `ListenDrops` climbing means your accept queue is full,
which is an application problem, not a filter problem.

### Step 4: if `config_missing` is climbing

The config map is empty. The dataplane is passing **everything** — you are
unprotected, not blocked, so this is not the cause of a traffic stoppage. It
means the daemon died or never populated the map:

```sh
systemctl status calyanti
journalctl -u calyanti -n 100 --no-pager
```

---

## 3. Legitimate traffic is being dropped

### Find out exactly why

```sh
# Follow the event stream and filter for the affected address:
calyanti-cli events --follow --json | jq -r 'select(.saddr=="203.0.113.5")
  | "\(.ts) \(.reason) \(.verdict) \(.proto) \(.sport)->\(.dport) \(.pkt_len)B"'
```

Events are sampled at `log_sample_rate` (default 1 in 100). If the traffic is
low-volume you may see nothing; drop the sample rate temporarily:

```sh
sudo sed -i 's/^log_sample_rate.*/log_sample_rate = 1/' /etc/calyanti/calyanti.conf
sudo calyanti-cli reload
# ... reproduce ...
sudo sed -i 's/^log_sample_rate.*/log_sample_rate = 100/' /etc/calyanti/calyanti.conf
sudo calyanti-cli reload
```

Do not leave it at 1 under any real load.

### The immediate unblock

```sh
calyanti-cli ban list | grep 203.0.113.5      # is it banned?
calyanti-cli ban del 203.0.113.5              # unban
calyanti-cli allow add 203.0.113.5/32         # and make sure it cannot recur
```

The allowlist is checked before every drop rule, including the blocklist and
active bans, so an allowlist entry always wins.

### Then fix the root cause

Do not leave a growing allowlist as the fix. Find the rule:

| Reason | Root cause | Proper fix |
|---|---|---|
| `drop_rate_pps` / `drop_rate_bps` | bucket too tight for a legitimate heavy client | raise to 4x observed p99 (TUNING.md §4) |
| `drop_rate_newconn` | a client opening many short connections | raise `rate_newconn`, or enable connection reuse in the client |
| `drop_portscan` | a client legitimately touching many ports (FTP active, SIP, BitTorrent) | raise `scan_port_threshold`, or allowlist |
| `drop_amp_srcport` | you consume a reflective service without conntrack state | attach the tc egress hook, or `amp_exempt = <port>` |
| `drop_default_deny` | an unlisted service | add the port rule |
| `drop_tcp_synack_unsolicited` | asymmetric routing: the SYN went out another path | this host is not seeing both directions; fix routing or disable the check |
| `drop_frag_tiny` | a path with an unusual MTU producing small fragments | lower `frag_min_size`, or fix PMTUD |
| `drop_ttl_low` | `min_ttl` set too high for distant clients | set `min_ttl = 0` |

### The safest way to test a rule change

```sh
# Put the whole thing in monitor mode, make the change, watch, then re-enable.
calyanti-cli mode monitor-only
# ... edit config, calyanti-cli reload, observe monitor_would_drop ...
calyanti-cli mode normal
```

`monitor_would_drop` (counter 4) records what would have happened, broken down
by the same reason codes, so you can validate a change with zero risk.

---

## 4. Nothing is being dropped

In order of likelihood:

```sh
# 1. Master switch and monitor mode:
calyanti-cli status | grep -E 'mode|enabled'
grep -E '^(enabled|monitor_only)' /etc/calyanti/calyanti.conf

# 2. Is the interface in the WAN zone? Bogon filtering, RFC1918-source
#    rejection and the reflection filter are inert outside it.
grep -E '^(interface|default_zone)' /etc/calyanti/calyanti.conf
calyanti-cli status | grep -A5 interfaces

# 3. Is the program even seeing packets?
calyanti-cli stats | grep -E 'pkt_total|pass_lan_iface|pass_disabled'

# 4. Attached to the right device?
ip -d link show dev eth0 | grep -i xdp
```

| Symptom | Cause |
|---|---|
| `pkt_total` is 0 | attached to the wrong interface, or to a VLAN/bridge/bond child instead of the physical device |
| `pass_disabled` dominates | `enabled = no`, or the interface has the `disabled` flag |
| `pass_lan_iface` dominates | the interface zone is `lan` or `dmz`. Set `zone=wan` |
| `monitor_would_drop` climbs but `drop_total` does not | `monitor_only = yes` (working as intended) |
| everything is `pass_allowlist` | your allowlist is too broad. `0.0.0.0/0` in the allowlist disables the entire suite |
| `pass_conntrack` dominates | normal on an established-traffic-heavy host; new flows are still evaluated |

The single most common cause is number 2: no interface is in the WAN zone.

---

## 5. The BPF program will not load: reading verifier logs

### Getting the full log

```sh
# From the daemon:
sudo calyantid --foreground --verbose --verifier-log-level=2 --dry-run

# From libbpf directly:
sudo LIBBPF_LOG_LEVEL=debug calyantid --foreground --dry-run 2>&1 | tee /tmp/verifier.log

# From bpftool, with the object on disk:
sudo bpftool prog load /usr/lib/calyanti/caly_xdp.bpf.o /sys/fs/bpf/test \
     type xdp -d 2>&1 | tail -100
```

Verifier logs are long and the **last 20-30 lines before the error are the only
ones that matter**. The error message names the register and the instruction;
the preceding lines show how that register got its value.

### How to read one

```
; if (data + sizeof(*eth) > data_end)
44: (bf) r2 = r1
45: (07) r2 += 14
46: (2d) if r2 > r3 goto pc+120
...
78: (71) r4 = *(u8 *)(r1 +23)
invalid access to packet, off=23 size=1, R1(id=0,off=0,r=14)
R1 offset is outside of the packet
```

Read it backwards:

- `invalid access to packet, off=23 size=1` — a 1-byte read at offset 23.
- `R1(... r=14)` — `r=14` is the **proven** safe range for that pointer. Only
  14 bytes have been validated; the code is reading at 23.
- The fix is a bounds check that covers offset 23 before the read, on **that
  specific pointer**, in a path the verifier can follow.

### Common failures and their causes

| Message | Cause | Fix |
|---|---|---|
| `invalid access to packet, off=N size=M, R_(r=K)` | read beyond the last validated bound | add `if ((void *)(p + 1) > data_end) return XDP_PASS;` before the read |
| `R1 offset is outside of the packet` | pointer arithmetic escaped the validated window | re-derive the pointer from `ctx->data` after any revalidation |
| `R0 invalid mem access 'map_value_or_null'` | used a map lookup result without a NULL check | `if (!v) return ...;` immediately after `bpf_map_lookup_elem()` |
| `math between pkt pointer and register with unbounded min value` | added an unbounded value (a length field from the packet) to a pointer | mask or clamp the value first: `off &= 0xFF;` |
| `back-edge from insn X to Y` | a loop the verifier cannot unroll (pre-5.3 has no loop support at all) | `#pragma unroll` with a compile-time constant bound — spelled `CALY_UNROLL` in this codebase |
| `BPF program is too large. Processed 1000001 insn` | complexity limit | split the path into a tail-called program; that is what `CALY_PROG_IDX_IPV6` exists for |
| `unreachable insn` | dead code after an unconditional return, often from an over-aggressive optimiser | build with `-O2`, not `-O3` or `-Os` |
| `unknown func bpf_tcp_raw_gen_syncookie_ipv4#N` | the kernel lacks a 5.15+ helper and the program was autoloaded anyway | the loader's `libbpf_probe_bpf_helper()` gate failed; see [section 12](#12-the-syn-proxy-is-not-working) |
| `cannot call GPL-restricted function from non-GPL program` | wrong license string | must be exactly `"Dual BSD/GPL"` |
| `misaligned packet access off ...` | unaligned multi-byte load on an architecture without `CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS` | use byte loads or `__builtin_memcpy` into a local |
| `map 'caly_allow4': failed to create: Invalid argument (-22)` | LPM trie without `BPF_F_NO_PREALLOC` | the kernel requires that flag on LPM tries |
| `failed to load BTF from ...: Invalid argument` | `vmlinux.h` from an incompatible kernel, or a corrupt BTF blob | regenerate: `bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h` |
| `libbpf: failed to find BTF for extern` | CO-RE relocation against a type the running kernel does not have | that field is guarded with `bpf_core_field_exists()`; report it with your kernel version |
| `Permission denied (-1)` on load | not root, or missing `CAP_BPF`/`CAP_SYS_ADMIN`, or `kernel.unprivileged_bpf_disabled=1` with insufficient capabilities | run as root |
| `Operation not permitted` with lockdown | Secure Boot kernel lockdown mode blocks some BPF operations | check `cat /sys/kernel/security/lockdown`; `integrity` mode blocks tracing but permits XDP |

### If you are debugging your own change

```sh
make DEBUG=1                     # -O1 -g, verbose logs, no llvm-strip
sudo calyantid --foreground --dry-run --verifier-log-level=2
```

`--dry-run` loads and verifies the object and then exits without attaching
anything, which is the fastest edit-compile-verify loop.

---

## 6. XDP will not attach

The load succeeded (the verifier was happy) but the attach failed.

### Read the errno

| Error | Meaning | Action |
|---|---|---|
| `-EOPNOTSUPP` (95) | the driver has no native XDP | use `xdp_mode = generic` |
| `-EBUSY` (16) | another XDP program is attached | [section 7](#7-conflicting-xdp-programs) |
| `-EINVAL` (22) | bad flags, or MTU too large for the driver's XDP mode | lower the MTU, or use generic |
| `-ENOMEM` (12) | the driver cannot allocate its XDP rings | reduce ring size or queue count |
| `-ENOSPC` (28) | not enough free TX rings for XDP (mlx4, ixgbe, i40e, ice) | reduce `combined` channels |
| `-EPERM` (1) | not root / missing capability | run as root |

```sh
# The errno the daemon saw:
journalctl -u calyanti -n 50 --no-pager | grep -i 'attach\|xdp'
```

### Per-driver checklist

**virtio_net** — needs one queue per CPU and LRO off:

```sh
ethtool -l eth0                              # Pre-set maximums vs Current
sudo ethtool -L eth0 combined $(nproc)
sudo ethtool -K eth0 lro off gro off
ip link show eth0 | grep mtu                 # must be under ~3500
```

If `Pre-set maximums: Combined: 1`, the hypervisor gave you one queue and
native XDP is not available. Use `xdp_mode = generic`.

**ixgbe / i40e / ice** — XDP reserves a TX ring per core:

```sh
ethtool -l eth0
sudo ethtool -L eth0 combined $(( $(nproc) / 2 ))
```

Also: these drivers refuse XDP above roughly 3 KB MTU because they have no
multi-buffer support.

**mlx5_core** — usually just works. If it does not:

```sh
sudo ethtool --set-priv-flags eth0 rx_striding_rq off
ethtool -g eth0                              # ring sizes
```

**ena (AWS)** — halve the channels and check the MTU:

```sh
ethtool -l eth0
sudo ethtool -L eth0 combined $(( $(nproc) / 2 ))
ip link show eth0 | grep mtu                 # XDP refused above ~3500
sudo ip link set dev eth0 mtu 1500
```

**hv_netvsc (Azure)** — attach to the **synthetic** device (`eth0`), never to
the VF (`enP*`). See [COMPATIBILITY.md](COMPATIBILITY.md#azure-hv_netvsc--accelerated-networking).

**bonding** — on kernel < 5.15, attach to the slaves, not the bond.

**VLAN, bridge, macvlan, vxlan, wireguard** — no XDP hook. Attach to the
physical device underneath. The parser handles up to two VLAN tags itself,
which is why this works.

### Proving whether native XDP exists at all

```sh
cat > /tmp/xdp_pass.c <<'EOF'
#include <linux/bpf.h>
__attribute__((section("xdp"), used))
int pass(struct xdp_md *ctx) { return XDP_PASS; }
char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";
EOF
clang -O2 -g -target bpf -c /tmp/xdp_pass.c -o /tmp/xdp_pass.o
sudo ip link set dev eth0 xdp obj /tmp/xdp_pass.o sec xdp
echo "exit=$?"
sudo ip link set dev eth0 xdp off
```

If that fails, the driver has no native XDP and no amount of Caly Anti
configuration will change it.

### Attaching costs a link flap on some drivers

`ixgbe`, `i40e`, `ice`, `mlx4` and `bnxt_en` reconfigure their rings when an
XDP program is attached, which drops the link for a fraction of a second. On a
production box, expect a brief interruption on the first attach — but **not** on
a `calyanti-cli reload`, which rewrites maps in place and never detaches.

---

## 7. Conflicting XDP programs

Only one XDP program can own an interface, unless everyone uses libxdp's
dispatcher.

```sh
ip -d link show dev eth0 | grep -A3 -i xdp
bpftool net show
bpftool prog show
```

Output like this means something else is there:

```
eth0: prog/xdp id 47 tag a1b2c3d4e5f60718 jited
```

```sh
bpftool prog show id 47        # what is it, and who loaded it?
```

Known conflicting software: Cilium (XDP acceleration), Calico with XDP, Katran,
`xdp-filter`, systemd `.link` files with `BPFProgram=`, some cloud telemetry
agents.

Your options:

1. Remove the other program.
2. Move Caly Anti to the tc rung — `dataplane = tc-bpf` — which uses clsact and
   composes fine underneath somebody else's XDP program.
3. Use a different interface.

### A stale program from a crashed daemon

On kernel 5.9+ the daemon attaches with `bpf_link`, which the kernel releases
when the process dies. Below that it uses netlink attach, and a `SIGKILL`ed
daemon leaves the program attached:

```sh
sudo ip link set dev eth0 xdp off
sudo ip link set dev eth0 xdpgeneric off
sudo rm -rf /sys/fs/bpf/calyanti
sudo systemctl start calyanti
```

Note that `xdp off` and `xdpgeneric off` are different operations. A program
attached in generic mode is not removed by `xdp off` on some kernels. Run both.

---

## 8. BTF is missing

```sh
ls -l /sys/kernel/btf/vmlinux
```

If it does not exist, CO-RE cannot work and rungs 1-3 are unavailable. **This
is a supported outcome, not an install failure.** The installer configures
nftables (rung 4) instead.

Options, best first:

1. **Install a kernel with BTF.**

   ```sh
   grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
   ```

   | Distro | Get BTF by |
   |---|---|
   | EL8 | update to 4.18.0-193 or newer (RHEL 8.2+) |
   | Debian 11 | `apt -t bullseye-backports install linux-image-amd64` |
   | Ubuntu 20.04 | `apt install linux-generic-hwe-20.04` |
   | custom kernel | rebuild with `CONFIG_DEBUG_INFO_BTF=y` and `pahole` >= 1.16 installed |

2. **Accept rung 4** and say so explicitly, so nobody is surprised later:

   ```ini
   dataplane = nftables
   ```

3. **Supply BTF out of band** if you have a matching vmlinux with DWARF. This
   is a specialist operation and only worth it on a kernel you build yourself.

A related failure mode: BTF exists but `vmlinux.h` was generated from a
*different* kernel, and a CO-RE relocation fails at load time with
`failed to find BTF for extern` or `no BTF found for kernel version`.
Regenerate it:

```sh
bpftool btf dump file /sys/kernel/btf/vmlinux format c > src/bpf/vmlinux.h
make clean && make
```

---

## 9. bpffs is not mounted

Symptom:

```
calyantid: failed to pin map caly_config at /sys/fs/bpf/calyanti/caly_config:
           No such file or directory
```

```sh
mount | grep bpf
sudo mount -t bpf bpffs /sys/fs/bpf
```

Permanent:

```sh
echo 'bpffs /sys/fs/bpf bpf defaults 0 0' | sudo tee -a /etc/fstab
```

systemd normally handles this via `sys-fs-bpf.mount`; minimal containers,
Alpine without systemd, and some hardened images do not.

Related: if `/sys/fs/bpf/calyanti` exists but contains pins from an **older ABI
major version**, the loader refuses to attach rather than reinterpreting a
struct whose layout changed:

```
calyantid: pinned config has ABI major 1, this build is major 2 - refusing
```

```sh
sudo systemctl stop calyanti
sudo rm -rf /sys/fs/bpf/calyanti
sudo systemctl start calyanti
```

Permissions on the pin directory matter — anyone who can write there can
rewrite your policy. It should be `0700 root:root`. See
[SECURITY.md](SECURITY.md).

---

## 10. Map creation and memory failures

```
libbpf: map 'caly_rate4': failed to create: Operation not permitted (-1)
```

or

```
libbpf: Error in bpf_object__probe_loading(): Operation not permitted
```

### RLIMIT_MEMLOCK (kernels before 5.11)

BPF maps at shipped defaults need roughly 220 MB of locked memory; the default
limit is 64 KB.

```sh
ulimit -l                                     # in KB; 64 is the usual default
prlimit --pid $(pgrep calyantid) --memlock    # what the daemon actually has
```

The systemd unit sets `LimitMEMLOCK=infinity`. If you are running by hand:

```sh
sudo bash -c 'ulimit -l unlimited; calyantid --foreground'
```

On kernel **5.11 and newer** BPF memory is charged to the cgroup memory
controller and `RLIMIT_MEMLOCK` is irrelevant — so if you are on a modern
kernel and hitting an allocation failure, it is the **cgroup** limit:

```sh
systemctl show calyanti -p MemoryMax -p MemoryCurrent
cat /sys/fs/cgroup/system.slice/calyanti.service/memory.max
```

### Just use less memory

```ini
max_rate_entries    = 65536
max_conn_entries    = 65536
max_scan_entries    = 32768
max_srcstat_entries = 32768
max_ban_entries     = 65536
max_block_entries   = 65536
```

Roughly 30 MB. These are read **before** map creation, so a daemon **restart**
is required — a reload will not resize maps.

### `E2BIG` on map creation

A single map's `max_entries` multiplied by its value size exceeded what the
kernel will allocate. Lower the corresponding `max_*_entries`.

---

## 11. Events are missing or lost

| Counter | Meaning |
|---|---|
| `event_emitted` (103) | successfully pushed to userspace |
| `event_sampled_out` (104) | suppressed by `log_sample_rate` or `log_max_pps` — **not** a loss |
| `event_lost` (105) | the ring or perf buffer was full — a real loss |

```sh
calyanti-cli stats | grep -E 'event_'
```

`event_lost` climbing:

```ini
event_pages     = 64      # from 16; must be a power of two, per CPU
log_sample_rate = 500     # from 100
log_max_pps     = 500     # hard ceiling
```

`event_pages` needs a daemon restart (the buffer is sized at map creation);
`log_sample_rate` and `log_max_pps` take effect on reload.

No events at all:

```sh
grep -E '^(log_events|log_sample_rate)' /etc/calyanti/calyanti.conf
calyanti-cli status | grep -o RINGBUF
```

`log_sample_rate = 0` disables event emission entirely while leaving the
counters running. That is a legitimate configuration for a high-throughput box;
make sure it is not an accident.

Missing `RINGBUF` in the capability line just means kernel < 5.8 and the perf
event array is in use. The records are identical; only the transport differs.

---

## 12. The SYN proxy is not working

### Check whether it is even loaded

```sh
calyanti-cli status | grep -o SYNPROXY || echo "SYN proxy NOT available"
calyanti-cli stats | grep -E 'synproxy|syncookie'
```

| Counter | Meaning |
|---|---|
| `synproxy_unavailable` (87) | wanted, but the helper or the tail-call slot is missing. **Expected on kernels < 5.15** |
| `synproxy_skipped` (88) | not enabled for that port — check `synproxy_port` |
| `synproxy_gen_ok` (81) | cookie generated |
| `synproxy_tx` (83) | SYN-ACK rewritten and transmitted |
| `synproxy_gen_fail` (82) / `synproxy_tx_fail` (84) | helper refused, or the driver rejected `XDP_TX` |
| `synproxy_check_ok` (85) | a returning ACK carried a valid cookie |
| `drop_syncookie_bad` (86) | a bare ACK with an invalid cookie — either an attack or the sysctl problem below |

### The sysctl. This is the one that catches everybody.

```sh
sysctl net.ipv4.tcp_syncookies
```

It must be **2**, not 1.

At `1` the kernel only issues and accepts cookies once the accept queue
actually overflows — so the cookies our XDP program already handed out are not
recognised when the ACK comes back. The symptom is exactly the failure mode the
design is built to avoid: clients complete the handshake, the kernel rejects a
cookie it never issued, and connections die silently.

```sh
sudo sysctl -w net.ipv4.tcp_syncookies=2
grep -r tcp_syncookies /etc/sysctl.conf /etc/sysctl.d/
sudo sysctl --system
```

Check for something else overwriting it: cloud-init, a CIS hardening role, or
another sysctl drop-in with a higher-numbered filename than
`98-calyanti.conf`.

### Kernel too old

The helpers `bpf_tcp_raw_gen_syncookie_ipv4/ipv6()` and
`bpf_tcp_raw_check_syncookie_ipv4/ipv6()` are 5.15+.

```sh
bpftool feature probe kernel | grep -i syncookie
```

On older kernels the SYN proxy program is marked `autoload=false` so the
verifier never sees a helper the kernel lacks, the prog-array slot stays empty,
and `bpf_tail_call()` falls through to the fallback: the per-source `rate_syn`
bucket plus `syn_fallback_pps`, with `net.ipv4.tcp_syncookies = 1`. That is
meaningfully weaker and it is also why this suite still runs on RHEL 8. There
is no workaround short of a newer kernel.

**Never attempt a hand-rolled cookie.** The kernel validates the ACK against
its own secret; a cookie it did not issue can never be spliced into a socket,
so a custom cookie produces a service that is permanently unreachable rather
than merely undefended.

### `XDP_TX` unavailable or slow

```sh
calyanti-cli status | grep -o XDP_TX
```

In generic/skb mode `XDP_TX` works but goes through the slow path, so the SYN
proxy is disabled by default on rung 2. That is deliberate: a slow `XDP_TX`
under a SYN flood costs more than it saves. Fix the native attach
([section 6](#6-xdp-will-not-attach)) or accept the rate-limit fallback.

### Watching it work

```sh
# On the server, watch the counters:
watch -n1 'calyanti-cli stats | grep -E "synproxy|syncookie"'

# From a client, generate SYNs (LAB ONLY - see BENCHMARKING.md):
sudo hping3 -S -p 443 --flood --rand-source <server>

# On the server, confirm the kernel is not building half-open sockets:
ss -s
nstat -az | grep -i -E 'syncookies|TcpExtListen'
```

`synproxy_tx` should climb, and `netstat -s | grep -i cookie` should show
cookies being *sent* without the accept queue overflowing.

---

## 13. Performance problems

### Establish where the CPU is going

```sh
# Per-program cost:
sudo sysctl -w kernel.bpf_stats_enabled=1
sudo bpftool prog show | grep -A2 caly_xdp_main
# run_time_ns / run_cnt = average nanoseconds per packet
sudo sysctl -w kernel.bpf_stats_enabled=0     # ~5% overhead, turn it back off

# Where the softirq time goes:
sudo perf top -e cycles:k --sort comm,dso
mpstat -P ALL 1 5

# Is the NIC dropping before we see the packet?
ethtool -S eth0 | grep -Ei 'drop|miss|no_buf|discard'
ip -s link show dev eth0
```

If `rx_missed_errors` or `rx_no_buffer_count` is climbing, the packets never
reached XDP. That is a ring-size, IRQ-affinity or raw-bandwidth problem, not a
filter problem.

### Reduce per-packet cost

| Change | Saves | Costs |
|---|---|---|
| `src_stats = no` | one LRU hash update per packet | `calyanti-cli top` stops working |
| `log_sample_rate` up, or `log_events = no` | 200-400 ns per emitted event | visibility |
| `portscan_detect = no` | two hashes and two word writes per packet | scan detection |
| `tunnel_inspect = no` | one parse branch | policy applies to the outer header only |
| `vlan_max_depth = 1` | one unrolled iteration | QinQ is not parsed |
| Native instead of generic XDP | roughly 5x | requires driver support |

### The system-level items that matter more than any of the above

```sh
# Spread interrupts across cores:
sudo systemctl stop irqbalance
# ... then set /proc/irq/*/smp_affinity_list per queue, one queue per core.

# Enough RX queues:
ethtool -l eth0
sudo ethtool -L eth0 combined $(nproc)

# Bigger rings absorb bursts:
ethtool -g eth0
sudo ethtool -G eth0 rx 4096

# CPU frequency governor - this one is worth 20-30% on its own:
cpupower frequency-info
sudo cpupower frequency-set -g performance
```

### One source, one core

RSS hashes the 5-tuple to a queue. A single-source test therefore lands
entirely on one core and you will measure that core's limit, not the box's.
Under a real distributed attack the load spreads. Test with
`--rand-source`-style generators; see [BENCHMARKING.md](BENCHMARKING.md).

---

## 14. PMTUD, IPv6 and "it connects then hangs"

The classic symptom: TCP connects, small requests work, anything large hangs
forever. That is Path MTU Discovery being black-holed.

The loader will not let you cause it — ICMPv4 type 3 and ICMPv6 type 2 can
never be set to drop, and a config that tries is rejected — but something else
on the path can:

```sh
# Are we permitting them?
calyanti-cli stats | grep -E 'pass_icmp4_pmtud|pass_icmp6_pmtud|drop_icmp'

# Is something upstream eating them?
sudo tcpdump -ni eth0 'icmp[icmptype] == 3 or icmp6[icmp6type] == 2'

# Prove the MTU:
tracepath 8.8.8.8
ping -M do -s 1472 8.8.8.8       # 1472 + 28 = 1500
```

Check the rest of the stack:

```sh
sudo nft list ruleset | grep -i icmp
sudo iptables -L -n | grep -i icmp
```

### IPv6 stops working entirely

IPv6 has no ARP; neighbour discovery **is** ICMPv6. Types 133, 134, 135 and 136
can never be set to drop, and 2 is the only PMTUD mechanism IPv6 has.

```sh
calyanti-cli stats | grep -E 'icmp6|ip6'
ip -6 neigh show                    # empty or all FAILED means ND is broken
sudo tcpdump -ni eth0 icmp6
```

If `drop_icmp6_type` is climbing, look at which type:

```sh
calyanti-cli events --follow --json | jq -r 'select(.reason=="drop_icmp6_type")
  | "\(.saddr) proto=\(.proto) len=\(.pkt_len)"'
```

Also check `drop_ip6_disabled` — `ipv6 = no` **drops** IPv6, it does not bypass
it. That is deliberate, so that turning IPv6 "off" cannot silently leave an
unfiltered path open, but it surprises people.

---

## 15. Collecting a diagnostic bundle

Everything a bug report needs, in one paste:

```sh
#!/bin/sh
# calyanti-diag.sh - collect diagnostics. Review before sharing: the stats and
# event output contain client IP addresses.
set -x
uname -a
cat /etc/os-release
ls -l /sys/kernel/btf/vmlinux
sysctl net.ipv4.tcp_syncookies net.core.netdev_max_backlog
ip -br link
ip -d link show
for i in $(ls /sys/class/net); do ethtool -i "$i" 2>/dev/null; ethtool -l "$i" 2>/dev/null; done
bpftool net show
bpftool prog show
bpftool map show
ls -l /sys/fs/bpf/calyanti/ 2>/dev/null
calyantid --probe
calyanti-cli status
calyanti-cli stats
systemctl status calyanti --no-pager
journalctl -u calyanti -n 300 --no-pager
grep -vE '^[[:space:]]*(#|$)' /etc/calyanti/calyanti.conf
```

```sh
sudo sh calyanti-diag.sh > /tmp/calyanti-diag.txt 2>&1
```

**Redact before sharing.** `calyanti-cli stats`, `top` and `events` all contain
client IP addresses, and your config contains your allowlist — which is a map of
your admin infrastructure. See
[SECURITY.md](SECURITY.md#telemetry-contains-personal-data).

For a verifier failure, add the full log:

```sh
sudo LIBBPF_LOG_LEVEL=debug calyantid --foreground --dry-run \
     --verifier-log-level=2 > /tmp/verifier.log 2>&1
```

The last 100 lines of that file are the ones that matter.
