#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Caly Anti - XDP/eBPF DDoS mitigation suite
# tuning/nic-tuning.sh - NIC queue, offload, coalescing and IRQ tuning.
#
# WHAT THIS DOES, AND WHY THE ORDER MATTERS
#
#   1. Offloads first (cheap, no link flap). LRO must be off before XDP is
#      attached; most drivers refuse the attach otherwise, and the ones that
#      do not hand XDP a coalesced super-frame that is not a real packet.
#   2. Flow control (pause frames) off. Under a flood, pause frames turn your
#      problem into the whole switch's problem.
#   3. Channels and rings. These BOUNCE THE LINK. They are skipped while an
#      XDP program is attached unless --force, and every change is verified by
#      waiting for the link to come back - if it does not, the change is rolled
#      back automatically.
#   4. Interrupt coalescing.
#   5. RPS / RFS / XPS. Pure sysfs, no link impact.
#   6. IRQ affinity. Fights with irqbalance; see --stop-irqbalance.
#
# EVERY ethtool CALL IS ALLOWED TO FAIL. Virtio without multiqueue has no
# channels, most cloud NICs have no coalescing knobs, many have fixed
# offloads, and containers have no NIC at all. Unsupported is not an error;
# it is Tuesday.
#
# POSIX sh only: bash, dash and busybox ash all run this unmodified.
# `set -e` is deliberately not used - see above.

set -u

PROG="nic-tuning.sh"
VERSION="1.0"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

ACTION="apply"              # apply | show | revert | print-unit
IFACES=""
WANT_ALL="no"
DRY_RUN="no"
FORCE="no"
VERBOSE="no"

DO_RING="yes"
RX_RING=""                  # empty = hardware maximum
TX_RING=""                  # empty = min(hardware maximum, TX_RING_CAP)
TX_RING_CAP=4096

DO_CHANNELS="yes"
CHANNELS=""                 # empty = min(online CPUs, hardware maximum)

COALESCE="adaptive"         # adaptive | fixed | skip
RX_USECS=32
RX_FRAMES=64

LRO="off"                   # off | keep
GRO="auto"                  # auto | on | off | keep
VLAN_OFFLOAD="keep"         # keep | off
PAUSE="off"                 # off | on | keep

RPS="auto"                  # auto | on | off | skip
RFS="off"                   # on | off
RFS_ENTRIES=32768
XPS="on"                    # on | off | skip
IRQ_AFFINITY="on"           # on | off
STOP_IRQBALANCE="no"

XDP_MODE="auto"             # auto | native | generic | none

BACKUP_DIR="/var/lib/calyanti/nic"
BACKUP_DIR_FALLBACK="/var/tmp/calyanti-nic"
RESTORE_FILE=""
RESTORE_OUT=""
PROFILE=""

CALY_CONF="/etc/calyanti/calyanti.conf"

LINK_SETTLE_SECS=10

N_OK=0
N_SKIP=0
N_FAIL=0

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

C_R=""; C_G=""; C_Y=""; C_B=""; C_0=""
if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ] && [ "${TERM:-dumb}" != "dumb" ]; then
	C_R=$(printf '\033[31m'); C_G=$(printf '\033[32m')
	C_Y=$(printf '\033[33m'); C_B=$(printf '\033[1m')
	C_0=$(printf '\033[0m')
fi

say()  { printf '%s\n' "$*"; }
hdr()  { printf '\n%s%s%s\n' "$C_B" "$*" "$C_0"; }
ok()   { printf '  %sok%s      %s\n' "$C_G" "$C_0" "$*"; N_OK=$((N_OK + 1)); }
skip() { printf '  skip    %s\n' "$*"; N_SKIP=$((N_SKIP + 1)); }
bad()  { printf '  %sfail%s    %s\n' "$C_R" "$C_0" "$*"; N_FAIL=$((N_FAIL + 1)); }
note() { printf '  note    %s\n' "$*"; }
vrb()  { [ "$VERBOSE" = yes ] && printf '  ..      %s\n' "$*"; return 0; }
warn() { printf '%s%s: warning:%s %s\n' "$C_Y" "$PROG" "$C_0" "$*" >&2; }
err()  { printf '%s%s: error:%s %s\n' "$C_R" "$PROG" "$C_0" "$*" >&2; }
die()  { err "$*"; cleanup; exit 1; }

TMPD=""
cleanup() { [ -n "$TMPD" ] && [ -d "$TMPD" ] && rm -rf "$TMPD"; TMPD=""; }
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

have() { command -v "$1" >/dev/null 2>&1; }
oneline() { printf '%s' "$*" | tr '\n' ' ' | sed -e 's/  */ /g' -e 's/^ //' -e 's/ $//'; }

usage() {
	cat <<'EOF'
Caly Anti - NIC tuning for an XDP dataplane.

USAGE
    nic-tuning.sh [options]                tune the auto-detected interfaces
    nic-tuning.sh -i eth0 -i eth1          tune specific interfaces
    nic-tuning.sh --all                    tune every physical interface
    nic-tuning.sh --show                   report current state, change nothing
    nic-tuning.sh --revert [FILE]          undo a previous run
    nic-tuning.sh --print-unit             print a systemd unit + udev rule

INTERFACE SELECTION
    -i, --iface NAME    Add an interface. May be repeated.
        --all           Every interface that has a real device behind it
                        (excludes lo, veth, bridges, bonds and tunnels).
    With neither, the script uses, in order: interfaces named in
    /etc/calyanti/calyanti.conf, then whatever carries the default route.

QUEUES AND RINGS   (these bounce the link)
        --channels N|max|skip   Combined queue count. Default: min(nproc, hw max).
                                Never lowers an existing higher value.
        --rx-ring N|max         RX descriptors. Default: hardware maximum.
        --tx-ring N|max         TX descriptors. Default: min(hw max, 4096).
        --no-ring               Do not touch ring sizes.
    Both are SKIPPED when an XDP program is attached, unless --force: a
    reallocation under a live dataplane can detach the program or wedge the
    queue. Attach XDP after tuning, or accept the flap with --force.

OFFLOADS
        --lro off|keep          Default off. XDP requires LRO off.
        --gro auto|on|off|keep  Default auto: off when XDP is attached in
                                generic/skb mode, otherwise left alone.
        --vlan-offload keep|off Default keep. Set off if you need the XDP
                                program to see 802.1Q tags in the frame.
        --pause off|on|keep     Ethernet flow control. Default off.

COALESCING
        --coalesce adaptive|fixed|skip   Default adaptive, falling back to
                                fixed if the driver has no adaptive moderation.
        --rx-usecs N            Fixed mode RX delay. Default 32.
        --rx-frames N           Fixed mode RX frame budget. Default 64.

SOFTWARE STEERING
        --rps auto|on|off|skip  Default auto: enable only when the NIC has
                                fewer RX queues than the host has CPUs.
        --rfs on|off            Default off. Read the note in --help output
                                below before turning it on.
        --rfs-entries N         Global RFS table size. Default 32768.
        --xps on|off|skip       Default on.
        --irq-affinity on|off   Default on.
        --stop-irqbalance       Stop and disable irqbalance, which otherwise
                                undoes IRQ pinning within about ten seconds.

OTHER
        --xdp-mode auto|native|generic|none
                                Override XDP attach-mode detection.
        --profile FILE          Read KEY=VALUE defaults (see profiles/README.md).
        --backup-dir DIR        Default /var/lib/calyanti/nic
    -n, --dry-run               Print the commands, run none of them.
        --force                 Allow disruptive changes while XDP is attached.
    -v, --verbose
    -h, --help
    -V, --version

WHY RFS DEFAULTS TO OFF
    RFS steers a packet to the CPU where the owning socket last ran, using a
    global flow table. On a normal server that is a win. On a DDoS filter it
    is usually a loss: a spoofed-source flood inserts a new flow per packet,
    the table thrashes, and you pay the hash and the table write for traffic
    that XDP is about to drop anyway. Turn it on only if the box is primarily
    serving real connections and you have measured the cache-miss benefit.

WHY RPS IS "AUTO"
    RPS spreads packets across CPUs in software. With a multi-queue NIC and
    RSS already spreading in hardware, it is pure overhead. It matters in
    exactly two cases: a single-queue NIC (virtio without multiqueue, many
    small cloud instances), and XDP GENERIC mode - where XDP runs after the
    RPS handoff, so RPS is the only way to filter on more than one core.
    In XDP NATIVE mode a dropped packet never reaches RPS at all, which is the
    whole point of the native rung of the ladder.

EXIT STATUS
    0 everything applied or already correct; 1 fatal; 2 some steps failed.
EOF
}

# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

# try <label> <cmd> [args...] - run, tolerate failure, report.
try() {
	_lbl=$1
	shift
	if [ "$DRY_RUN" = yes ]; then
		printf '  would  %s   (%s)\n' "$_lbl" "$*"
		return 0
	fi
	_out=$("$@" 2>&1)
	_rc=$?
	if [ $_rc -eq 0 ]; then
		ok "$_lbl"
	else
		skip "$_lbl - not supported here: $(oneline "$_out")"
	fi
	return $_rc
}

# write_sysfs <path> <value> <label>
write_sysfs() {
	_p=$1; _v=$2; _l=$3
	if [ ! -e "$_p" ]; then
		vrb "$_l: $_p does not exist"
		return 3
	fi
	if [ "$DRY_RUN" = yes ]; then
		printf '  would  %s   (echo %s > %s)\n' "$_l" "$_v" "$_p"
		return 0
	fi
	if [ ! -w "$_p" ]; then
		skip "$_l - $_p is not writable"
		return 4
	fi
	if printf '%s\n' "$_v" > "$_p" 2>/dev/null; then
		vrb "$_l -> $_v"
		return 0
	fi
	skip "$_l - kernel refused $_v (managed by the driver?)"
	return 5
}

read_file() {
	[ -r "$1" ] || return 1
	cat "$1" 2>/dev/null
}

# ---------------------------------------------------------------------------
# CPU topology helpers
# ---------------------------------------------------------------------------

expand_cpulist() {
	# "0-3,8,10-11" -> "0 1 2 3 8 10 11"
	printf '%s' "$1" | awk -F, '
	{
		out = ""
		for (i = 1; i <= NF; i++) {
			n = split($i, r, "-")
			if (n == 2) {
				for (c = r[1] + 0; c <= r[2] + 0; c++)
					out = out (out == "" ? "" : " ") c
			} else if ($i != "") {
				out = out (out == "" ? "" : " ") ($i + 0)
			}
		}
		print out
	}'
}

online_cpus() {
	_l=$(read_file /sys/devices/system/cpu/online)
	if [ -n "$_l" ]; then
		expand_cpulist "$_l"
		return 0
	fi
	_n=$(nproc 2>/dev/null || echo 1)
	_i=0
	_o=""
	while [ "$_i" -lt "$_n" ]; do
		_o="$_o $_i"
		_i=$((_i + 1))
	done
	printf '%s\n' "${_o# }"
}

cpu_count() {
	set -- $(online_cpus)
	printf '%s\n' "$#"
}

# Build the comma-separated 32-bit hex mask sysfs wants ("00000000,0000000f").
# Built nibble by nibble on purpose: awk's %x conversion is not reliable above
# 2^31 across mawk/gawk/busybox awk, and a wrong mask silently steers nothing.
cpus_to_mask() {
	printf '%s\n' "$*" | awk '
	{
		hex = "0123456789abcdef"
		maxw = 0
		for (i = 1; i <= NF; i++) {
			c = $i + 0
			w = int(c / 32)
			b = c % 32
			set[w "," b] = 1
			if (w > maxw) maxw = w
		}
		out = ""
		for (w = maxw; w >= 0; w--) {
			s = ""
			for (n = 7; n >= 0; n--) {
				v = 0
				for (k = 0; k < 4; k++) {
					bb = n * 4 + k
					if ((w "," bb) in set) v += 2 ^ k
				}
				s = s substr(hex, v + 1, 1)
			}
			out = (out == "" ? s : out "," s)
		}
		if (out == "") out = "0"
		print out
	}'
}

iface_numa_cpus() {
	_if=$1
	_nn=$(read_file "/sys/class/net/$_if/device/numa_node")
	case "$_nn" in
	''|-1|*[!0-9-]*)
		online_cpus
		return 0
		;;
	esac
	_cl=$(read_file "/sys/devices/system/node/node$_nn/cpulist")
	if [ -n "$_cl" ]; then
		expand_cpulist "$_cl"
	else
		online_cpus
	fi
}

count_glob() {
	_n=0
	for _x in "$@"; do
		[ -e "$_x" ] && _n=$((_n + 1))
	done
	printf '%s\n' "$_n"
}

# ---------------------------------------------------------------------------
# Interface discovery
# ---------------------------------------------------------------------------

is_physical() {
	_if=$1
	[ "$_if" = lo ] && return 1
	[ -d "/sys/class/net/$_if" ] || return 1
	[ -e "/sys/class/net/$_if/device" ] || return 1
	# Exclude software constructs that happen to have a device link.
	[ -d "/sys/class/net/$_if/bridge" ] && return 1
	[ -d "/sys/class/net/$_if/bonding" ] && return 1
	return 0
}

conf_ifaces() {
	[ -r "$CALY_CONF" ] || return 0
	awk '
	/^[ \t]*interface[ \t]*=/ {
		sub(/^[ \t]*interface[ \t]*=[ \t]*/, "")
		sub(/#.*$/, "")
		if ($0 ~ /disabled/) next
		print $1
	}' "$CALY_CONF" 2>/dev/null
}

route_ifaces() {
	have ip || return 0
	{
		ip -4 route show default 2>/dev/null
		ip -6 route show default 2>/dev/null
	} | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1) }'
}

all_physical() {
	for _p in /sys/class/net/*; do
		[ -d "$_p" ] || continue
		_n=${_p##*/}
		is_physical "$_n" && printf '%s\n' "$_n"
	done
}

dedup_ifaces() {
	_seen=""
	for _i in $1; do
		[ -n "$_i" ] || continue
		case " $_seen " in
		*" $_i "*) continue ;;
		esac
		[ -d "/sys/class/net/$_i" ] || continue
		_seen="$_seen $_i"
	done
	printf '%s\n' "${_seen# }"
}

# ---------------------------------------------------------------------------
# ethtool output parsing
# ---------------------------------------------------------------------------

# eth_section_field <file> <max|cur> <label>
eth_section_field() {
	awk -v want="$2" -v lab="$3" '
	/^Pre-set maximums:/      { sec = "max"; next }
	/^Current hardware settings:/ { sec = "cur"; next }
	{
		if (sec != want) next
		i = index($0, ":")
		if (i == 0) next
		l = substr($0, 1, i - 1)
		v = substr($0, i + 1)
		gsub(/^[ \t]+/, "", l); gsub(/[ \t]+$/, "", l)
		gsub(/^[ \t]+/, "", v); gsub(/[ \t]+$/, "", v)
		if (l == lab && v != "") { print v; exit }
	}' "$1" 2>/dev/null
}

# eth_feature <file> <feature-name> -> "on" / "off" / "" ; sets FEATURE_FIXED
FEATURE_FIXED="no"
eth_feature() {
	FEATURE_FIXED="no"
	_line=$(awk -v f="$2" -F: '
		{
			k = $1
			gsub(/^[ \t]+/, "", k); gsub(/[ \t]+$/, "", k)
			if (k == f) { print $2; exit }
		}' "$1" 2>/dev/null)
	case "$_line" in
	*"[fixed]"*) FEATURE_FIXED="yes" ;;
	esac
	printf '%s' "$_line" | awk '{ print $1 }'
}

eth_dump() {
	# eth_dump <iface> <ethtool-args...> -> file path in $TMPD, or empty
	_if=$1
	shift
	_f="$TMPD/eth.$_if.$(printf '%s' "$*" | tr -c 'a-zA-Z0-9' '_')"
	if ethtool "$@" "$_if" > "$_f" 2>/dev/null; then
		printf '%s\n' "$_f"
		return 0
	fi
	rm -f "$_f" 2>/dev/null
	return 1
}

# ---------------------------------------------------------------------------
# XDP detection
# ---------------------------------------------------------------------------

# The attach-mode probe is a SAFETY INTERLOCK: the ring and channel steps read
# its result to decide whether reallocating queues under a live dataplane is
# safe. It must therefore never report "none" (safe to reallocate) when it in
# fact could not tell. busybox `ip` (Alpine and other minimal images) has no
# `-d`/details support and never prints XDP info, yet `have ip` is still true -
# so a program attached by libbpf would be invisible to `ip -d` alone. When the
# state cannot be positively established we return "unknown", and the callers
# treat "unknown" exactly like "attached".
_IP_KIND=""                 # cached: "" | iproute2 | busybox | none
_XDP_WARNED=no

ip_is_iproute2() {
	case "$_IP_KIND" in
	iproute2) return 0 ;;
	busybox|none) return 1 ;;
	esac
	if ! have ip; then _IP_KIND=none; return 1; fi
	# Real iproute2 answers `ip -V` with its own name; busybox ip does not know
	# the option and prints usage to stderr instead.
	if ip -V 2>/dev/null | grep -qi iproute2; then
		_IP_KIND=iproute2
		return 0
	fi
	_IP_KIND=busybox
	return 1
}

# Prints: none | generic | native | offload | unknown
detect_xdp_mode() {
	_if=$1
	if [ "$XDP_MODE" != auto ]; then
		printf '%s\n' "$XDP_MODE"
		return 0
	fi

	# Primary source: bpftool reads the attachment straight from the kernel and
	# does not care which `ip` is installed. `bpftool net show dev IF` lists the
	# interface under the "xdp:" section only when a program is attached, tagged
	# with the attach mode (generic / driver / offload).
	if have bpftool; then
		_b=$(bpftool net show dev "$_if" 2>/dev/null)
		_brc=$?
		if [ "$_brc" -eq 0 ] && [ -n "$_b" ]; then
			_x=$(printf '%s\n' "$_b" | awk '
				/^xdp:/     { inx = 1; next }
				/^[a-z_]+:/ { inx = 0 }
				inx && NF   { print }')
			case "$_x" in
			*generic*) printf 'generic\n'; return 0 ;;
			*offload*) printf 'offload\n'; return 0 ;;
			*driver*)  printf 'native\n';  return 0 ;;
			*"$_if"*)  printf 'native\n';  return 0 ;;
			esac
			printf 'none\n'
			return 0
		fi
	fi

	# Fallback: iproute2. Only a NEGATIVE result from the real iproute2 binary
	# is trustworthy; busybox ip cannot see XDP at all.
	if ip_is_iproute2; then
		_o=$(ip -d link show dev "$_if" 2>/dev/null)
		case "$_o" in
		*xdpgeneric*) printf 'generic\n'; return 0 ;;
		*xdpoffload*) printf 'offload\n'; return 0 ;;
		*xdpdrv*)     printf 'native\n';  return 0 ;;
		esac
		case "$_o" in
		*" xdp "*|*"xdp/id"*|*"prog/xdp"*) printf 'native\n'; return 0 ;;
		esac
		printf 'none\n'
		return 0
	fi

	# No bpftool and no real iproute2: we cannot prove the interface is clear.
	if [ "$_XDP_WARNED" = no ]; then
		warn "cannot positively determine XDP attach state on this host: no bpftool,"
		warn "and \`ip\` is missing or busybox (no \`ip -d\`). The ring/channel interlock"
		warn "fails SAFE - those steps are skipped as if a program were attached."
		warn "Install bpftool or iproute2, or pass --xdp-mode / --force explicitly."
		_XDP_WARNED=yes
	fi
	printf 'unknown\n'
}

# ---------------------------------------------------------------------------
# IRQ helpers
# ---------------------------------------------------------------------------

irq_name() {
	awk -v irq="$1:" '$1 == irq { s = ""; for (i = NF; i >= 2; i--) { if ($i ~ /^[0-9]+$/) break; s = $i " " s } print s; exit }' \
		/proc/interrupts 2>/dev/null
}

iface_irqs() {
	_if=$1
	_dev="/sys/class/net/$_if/device"
	_list=""
	if [ -d "$_dev/msi_irqs" ]; then
		for _q in "$_dev/msi_irqs"/*; do
			[ -e "$_q" ] || continue
			_list="$_list ${_q##*/}"
		done
	fi
	if [ -z "$_list" ] && [ -r "$_dev/irq" ]; then
		_list=$(read_file "$_dev/irq")
	fi
	if [ -z "$_list" ]; then
		# Legacy / virtio naming: match the interface name in the action column.
		_list=$(awk -v ifc="$_if" '
			$0 ~ ("(^| )" ifc "(-|$| )") {
				k = $1; sub(/:$/, "", k)
				if (k ~ /^[0-9]+$/) print k
			}' /proc/interrupts 2>/dev/null)
	fi
	# Drop control/async/command vectors: pinning them buys nothing and on
	# some drivers they are shared with other functions.
	for _i in $_list; do
		_n=$(irq_name "$_i")
		case "$_n" in
		*config*|*async*|*cmd*|*fw*|*ctrl*) continue ;;
		esac
		printf '%s\n' "$_i"
	done | sort -n 2>/dev/null
}

irqbalance_active() {
	if have systemctl; then
		systemctl is-active irqbalance >/dev/null 2>&1 && return 0
	fi
	if have rc-service; then
		rc-service irqbalance status >/dev/null 2>&1 && return 0
	fi
	if have pgrep; then
		pgrep -x irqbalance >/dev/null 2>&1 && return 0
	fi
	return 1
}

# ---------------------------------------------------------------------------
# Link safety
# ---------------------------------------------------------------------------

link_state() { read_file "/sys/class/net/$1/operstate"; }

# wait_link_up <iface> - returns 0 if the link is up within LINK_SETTLE_SECS.
wait_link_up() {
	_if=$1
	_t=0
	while [ "$_t" -lt "$LINK_SETTLE_SECS" ]; do
		case "$(link_state "$_if")" in
		up) return 0 ;;
		esac
		sleep 1
		_t=$((_t + 1))
	done
	case "$(link_state "$_if")" in
	up) return 0 ;;
	esac
	return 1
}

# ---------------------------------------------------------------------------
# Restore-script generation
# ---------------------------------------------------------------------------

# secure_path <path> - succeed only if <path> exists, is owned by root (uid 0),
# and is NOT world-writable nor writable by a non-root group. Used to refuse
# attacker-controlled files and directories under world-writable parents such
# as /var/tmp before we either execute a restore script or write backups into
# it. If ownership/mode cannot be read (no stat), we fail closed.
secure_path() {
	_sp=$1
	[ -e "$_sp" ] || return 1
	_meta=$(stat -c '%u %g %a' "$_sp" 2>/dev/null) || return 1
	[ -n "$_meta" ] || return 1
	printf '%s\n' "$_meta" | awk '
		{
			uid = $1; gid = $2; mode = $3
			if (uid != 0) exit 1                        # not root-owned
			n = length(mode)
			g = substr(mode, n - 1, 1) + 0              # group octal digit
			o = substr(mode, n, 1) + 0                  # other octal digit
			if (int(o / 2) % 2 == 1) exit 1             # world-writable
			if (int(g / 2) % 2 == 1 && gid != 0) exit 1 # non-root-group-writable
			exit 0
		}'
}

restore_begin() {
	_ts=$(date +%Y%m%d-%H%M%S 2>/dev/null || echo unknown)
	if ! mkdir -p "$BACKUP_DIR" 2>/dev/null || [ ! -w "$BACKUP_DIR" ]; then
		# /var/tmp is world-writable and sticky, so another user can pre-create
		# our subdirectory (or a symlink) and capture the root-written backups.
		# Create it ourselves under a tight umask; if it already exists it must
		# be a root-owned, non-world/non-foreign-group-writable directory or we
		# refuse it rather than write a restore script another user can swap.
		BACKUP_DIR="$BACKUP_DIR_FALLBACK"
		if (umask 077; mkdir "$BACKUP_DIR" 2>/dev/null); then
			:
		elif [ -d "$BACKUP_DIR" ] && secure_path "$BACKUP_DIR" && [ -w "$BACKUP_DIR" ]; then
			:
		else
			warn "no safe backup directory (refusing world-writable $BACKUP_DIR);"
			warn "continuing WITHOUT a restore script"
			RESTORE_OUT=""
			return 1
		fi
	fi
	RESTORE_OUT="$BACKUP_DIR/nic-restore-$_ts.sh"
	cat > "$RESTORE_OUT" <<EOF
#!/bin/sh
# Generated by Caly Anti $PROG $VERSION on $(date 2>/dev/null || echo unknown).
# Restores the NIC settings that were in effect before that run.
#
# Ring and channel restores bounce the link, exactly as the original change
# did. Lines whose original value could not be read are absent.
set -u
_rc=0
r() {
	printf '  %s\n' "\$*"
	"\$@" >/dev/null 2>&1 || { printf '    (failed, continuing)\n'; _rc=2; }
}
w() {
	[ -w "\$1" ] || { printf '  skip (ro) %s\n' "\$1"; return 0; }
	printf '  %s <- %s\n' "\$1" "\$2"
	printf '%s\n' "\$2" > "\$1" 2>/dev/null || { printf '    (failed, continuing)\n'; _rc=2; }
}

EOF
	chmod 0700 "$RESTORE_OUT" 2>/dev/null
	return 0
}

rec_cmd() {
	[ -n "$RESTORE_OUT" ] || return 0
	[ "$DRY_RUN" = yes ] && return 0
	printf 'r %s\n' "$*" >> "$RESTORE_OUT"
}

rec_write() {
	[ -n "$RESTORE_OUT" ] || return 0
	[ "$DRY_RUN" = yes ] && return 0
	printf "w '%s' '%s'\n" "$1" "$2" >> "$RESTORE_OUT"
}

rec_comment() {
	[ -n "$RESTORE_OUT" ] || return 0
	[ "$DRY_RUN" = yes ] && return 0
	printf '# %s\n' "$*" >> "$RESTORE_OUT"
}

restore_end() {
	[ -n "$RESTORE_OUT" ] || return 0
	[ "$DRY_RUN" = yes ] && return 0
	printf '\nexit "$_rc"\n' >> "$RESTORE_OUT"
	cp -f "$RESTORE_OUT" "$BACKUP_DIR/nic-restore-latest.sh" 2>/dev/null
	chmod 0700 "$BACKUP_DIR/nic-restore-latest.sh" 2>/dev/null
	say ""
	say "Restore script: $RESTORE_OUT"
	say "                $BACKUP_DIR/nic-restore-latest.sh  (used by --revert)"
}

# ---------------------------------------------------------------------------
# Profile file (KEY=VALUE, whitelisted - never sourced)
# ---------------------------------------------------------------------------

load_profile() {
	_f=$1
	[ -r "$_f" ] || die "profile '$_f' is not readable"
	# Parsed, not sourced: a tuning profile is data, and `.` on a data file is
	# how a config file becomes arbitrary code execution as root.
	# `|| [ -n "$_k" ]` processes a final line that lacks a trailing newline;
	# POSIX read returns non-zero at EOF for such a line, which would otherwise
	# silently drop the last key (common with printf/echo -n authored files).
	while IFS='=' read -r _k _v || [ -n "$_k" ]; do
		[ -n "$_k" ] || continue
		case "$_k" in \#*) continue ;; esac
		_k=$(printf '%s' "$_k" | tr -d ' \t')
		_v=$(printf '%s' "$_v" | sed -e 's/#.*$//' -e 's/^[ \t]*//' -e 's/[ \t]*$//')
		[ -n "$_v" ] || continue
		case "$_k" in
		CHANNELS)      CHANNELS=$_v ;;
		RX_RING)       RX_RING=$_v ;;
		TX_RING)       TX_RING=$_v ;;
		COALESCE)      COALESCE=$_v ;;
		RX_USECS)      RX_USECS=$_v ;;
		RX_FRAMES)     RX_FRAMES=$_v ;;
		LRO)           LRO=$_v ;;
		GRO)           GRO=$_v ;;
		VLAN_OFFLOAD)  VLAN_OFFLOAD=$_v ;;
		PAUSE)         PAUSE=$_v ;;
		RPS)           RPS=$_v ;;
		RFS)           RFS=$_v ;;
		RFS_ENTRIES)   RFS_ENTRIES=$_v ;;
		XPS)           XPS=$_v ;;
		IRQ_AFFINITY)  IRQ_AFFINITY=$_v ;;
		XDP_MODE)      XDP_MODE=$_v ;;
		IFACES)        IFACES="$IFACES $(printf '%s' "$_v" | tr ',' ' ')" ;;
		*) warn "profile: ignoring unknown key '$_k'" ;;
		esac
	done < "$_f"
}

# ---------------------------------------------------------------------------
# --print-unit
# ---------------------------------------------------------------------------

print_unit() {
	cat <<'EOF'
# NIC settings do not survive a reboot, a driver reload, or a NIC hotplug.
# Nothing below is installed by this script; copy what you need.
#
# ---------------------------------------------------------------------------
# /etc/systemd/system/calyanti-nic-tune@.service
# ---------------------------------------------------------------------------
[Unit]
Description=Caly Anti NIC tuning for %i
Documentation=file:/usr/share/calyanti/tuning/profiles/README.md
After=network-pre.target sys-subsystem-net-devices-%i.device
Wants=network-pre.target
BindsTo=sys-subsystem-net-devices-%i.device
# Tune BEFORE the dataplane attaches: ring and channel changes are skipped
# while an XDP program is loaded.
Before=calyanti.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/share/calyanti/tuning/nic-tuning.sh --iface %i
# Never let a tuning failure block the network coming up.
SuccessExitStatus=0 2

[Install]
WantedBy=multi-user.target

# Enable with:   systemctl enable calyanti-nic-tune@eth0.service
#
# ---------------------------------------------------------------------------
# /etc/udev/rules.d/70-calyanti-nic.rules   (re-tune on hotplug/driver reload)
# ---------------------------------------------------------------------------
ACTION=="add", SUBSYSTEM=="net", KERNEL=="eth*", \
  RUN+="/usr/bin/systemctl --no-block start calyanti-nic-tune@$name.service"

# ---------------------------------------------------------------------------
# OpenRC (Alpine): /etc/local.d/calyanti-nic.start, chmod +x
# ---------------------------------------------------------------------------
#!/bin/sh
/usr/share/calyanti/tuning/nic-tuning.sh --iface eth0 || true
EOF
}

# ---------------------------------------------------------------------------
# --show
# ---------------------------------------------------------------------------

show_iface() {
	_if=$1
	hdr "=== $_if ==="

	_drv="?"; _fw="?"; _bus="?"
	if _f=$(eth_dump "$_if" -i); then
		_drv=$(awk -F: '/^driver:/ { gsub(/^[ \t]+/, "", $2); print $2 }' "$_f")
		_fw=$(awk -F: '/^firmware-version:/ { gsub(/^[ \t]+/, "", $2); print $2 }' "$_f")
		_bus=$(awk -F: '/^bus-info:/ { gsub(/^[ \t]+/, "", $2); print $2 }' "$_f")
	fi
	_nn=$(read_file "/sys/class/net/$_if/device/numa_node")
	_mtu=$(read_file "/sys/class/net/$_if/mtu")
	_st=$(link_state "$_if")
	_nrx=$(count_glob "/sys/class/net/$_if/queues/rx-"*)
	_ntx=$(count_glob "/sys/class/net/$_if/queues/tx-"*)

	say "  driver          ${_drv:-?} (fw ${_fw:-?}, bus ${_bus:-?})"
	say "  link            ${_st:-?}, mtu ${_mtu:-?}, numa_node ${_nn:--1}"
	say "  queues          rx=$_nrx tx=$_ntx   host cpus=$(cpu_count)"
	say "  xdp             $(detect_xdp_mode "$_if")"

	if _f=$(eth_dump "$_if" -l); then
		say "  channels        combined $(eth_section_field "$_f" cur Combined)/$(eth_section_field "$_f" max Combined)  rx $(eth_section_field "$_f" cur RX)/$(eth_section_field "$_f" max RX)  tx $(eth_section_field "$_f" cur TX)/$(eth_section_field "$_f" max TX)"
	else
		say "  channels        not reported by this driver"
	fi

	if _f=$(eth_dump "$_if" -g); then
		say "  rings           rx $(eth_section_field "$_f" cur RX)/$(eth_section_field "$_f" max RX)  tx $(eth_section_field "$_f" cur TX)/$(eth_section_field "$_f" max TX)"
	else
		say "  rings           not reported by this driver"
	fi

	if _f=$(eth_dump "$_if" -c); then
		_arx=$(awk '/^Adaptive RX:/ { print $3 }' "$_f")
		_rxu=$(awk -F: '/^rx-usecs:/ { gsub(/[ \t]/, "", $2); print $2 }' "$_f")
		_rxf=$(awk -F: '/^rx-frames:/ { gsub(/[ \t]/, "", $2); print $2 }' "$_f")
		say "  coalesce        adaptive-rx=${_arx:-?} rx-usecs=${_rxu:-?} rx-frames=${_rxf:-?}"
	else
		say "  coalesce        not reported by this driver"
	fi

	if _f=$(eth_dump "$_if" -k); then
		_lro=$(eth_feature "$_f" large-receive-offload)
		_gro=$(eth_feature "$_f" generic-receive-offload)
		_gso=$(eth_feature "$_f" generic-segmentation-offload)
		_tso=$(eth_feature "$_f" tcp-segmentation-offload)
		_rxv=$(eth_feature "$_f" rx-vlan-offload)
		_grohw=$(eth_feature "$_f" rx-gro-hw)
		say "  offloads        lro=${_lro:-?} gro=${_gro:-?} gro-hw=${_grohw:-?} tso=${_tso:-?} gso=${_gso:-?} rxvlan=${_rxv:-?}"
	fi

	if _f=$(eth_dump "$_if" -a); then
		say "  flow control    $(oneline "$(awk 'NR>1' "$_f")")"
	fi

	_q=0
	while [ "$_q" -lt "$_nrx" ]; do
		_rc=$(read_file "/sys/class/net/$_if/queues/rx-$_q/rps_cpus")
		_fc=$(read_file "/sys/class/net/$_if/queues/rx-$_q/rps_flow_cnt")
		say "  rx-$_q            rps_cpus=${_rc:-n/a} rps_flow_cnt=${_fc:-n/a}"
		_q=$((_q + 1))
		[ "$_q" -ge 8 ] && { say "  (rx queues truncated at 8)"; break; }
	done
	_q=0
	while [ "$_q" -lt "$_ntx" ]; do
		_xc=$(read_file "/sys/class/net/$_if/queues/tx-$_q/xps_cpus")
		say "  tx-$_q            xps_cpus=${_xc:-n/a}"
		_q=$((_q + 1))
		[ "$_q" -ge 8 ] && { say "  (tx queues truncated at 8)"; break; }
	done

	say "  rps_sock_flow_entries $(read_file /proc/sys/net/core/rps_sock_flow_entries || echo n/a)"

	_irqs=$(iface_irqs "$_if")
	if [ -n "$_irqs" ]; then
		say "  irqs"
		for _i in $_irqs; do
			_al=$(read_file "/proc/irq/$_i/smp_affinity_list")
			printf '    %-6s cpu=%-10s %s\n' "$_i" "${_al:-?}" "$(irq_name "$_i")"
		done
	else
		say "  irqs            none found (virtual NIC, or shared legacy IRQ)"
	fi
	if irqbalance_active; then
		say "  irqbalance      RUNNING - it will overwrite manual IRQ pinning"
	fi

	if _f=$(eth_dump "$_if" -S); then
		_l=$(grep -iE 'drop|discard|miss|error|err|fifo|no_buf|overrun' "$_f" 2>/dev/null \
			| awk '{ gsub(/[ \t]+/, " "); if ($NF + 0 > 0) print "    " $0 }' | head -20)
		if [ -n "$_l" ]; then
			say "  non-zero loss counters (these are your tuning feedback):"
			printf '%s\n' "$_l"
		else
			say "  loss counters   all zero"
		fi
	fi

	say "  softnet         $(awk 'NR<=1{next} {d+=strtonum("0x" $2); s+=strtonum("0x" $3)} END{printf "backlog_drops=%d time_squeeze=%d", d, s}' /proc/net/softnet_stat 2>/dev/null || echo 'n/a (needs gawk)')"
}

# ---------------------------------------------------------------------------
# Tuning steps
# ---------------------------------------------------------------------------

tune_offloads() {
	_if=$1
	_xdp=$2

	_f=$(eth_dump "$_if" -k) || { skip "offloads - ethtool -k unsupported"; return 0; }

	# --- LRO: mandatory off for XDP ---------------------------------------
	if [ "$LRO" = off ]; then
		_cur=$(eth_feature "$_f" large-receive-offload)
		if [ "$FEATURE_FIXED" = yes ]; then
			vrb "lro is fixed at ${_cur:-?} in this driver"
		elif [ "$_cur" = on ]; then
			rec_cmd ethtool -K "$_if" lro on
			try "lro off (XDP cannot see coalesced frames)" \
				ethtool -K "$_if" lro off
		else
			vrb "lro already off"
		fi
	fi

	# --- GRO ---------------------------------------------------------------
	# In NATIVE mode XDP runs before GRO, so GRO is harmless and worth keeping
	# for the traffic that is passed. In GENERIC mode XDP runs inside
	# netif_receive_skb, AFTER GRO has already merged segments - the program
	# then sees one 64 KB pseudo-packet instead of 45 real ones, which breaks
	# per-packet rate limiting and every length check in the dataplane.
	_want_gro=""
	case "$GRO" in
	on)   _want_gro=on ;;
	off)  _want_gro=off ;;
	keep) _want_gro="" ;;
	auto)
		case "$_xdp" in
		generic) _want_gro=off ;;
		*)       _want_gro="" ;;
		esac
		;;
	esac
	if [ -n "$_want_gro" ]; then
		_cur=$(eth_feature "$_f" generic-receive-offload)
		if [ "$FEATURE_FIXED" = yes ]; then
			vrb "gro is fixed at ${_cur:-?}"
		elif [ "$_cur" != "$_want_gro" ]; then
			rec_cmd ethtool -K "$_if" gro "$_cur"
			try "gro $_want_gro (XDP generic sees post-GRO frames)" \
				ethtool -K "$_if" gro "$_want_gro"
		else
			vrb "gro already $_want_gro"
		fi
	fi

	# Hardware GRO is always wrong under XDP: the merge happens in the NIC,
	# before the program runs, in every attach mode.
	if [ "$_xdp" != none ]; then
		_cur=$(eth_feature "$_f" rx-gro-hw)
		if [ -n "$_cur" ] && [ "$FEATURE_FIXED" = no ] && [ "$_cur" = on ]; then
			rec_cmd ethtool -K "$_if" rx-gro-hw on
			try "rx-gro-hw off (merges frames before XDP sees them)" \
				ethtool -K "$_if" rx-gro-hw off
		fi
	fi

	# --- RX VLAN stripping -------------------------------------------------
	# With hardware stripping the tag is gone from the frame by the time XDP
	# runs, so the dataplane's 802.1Q/QinQ parsing never fires. Filtering still
	# works (L3 is parsed correctly); what you lose is per-VLAN policy.
	if [ "$VLAN_OFFLOAD" = off ]; then
		_cur=$(eth_feature "$_f" rx-vlan-offload)
		if [ "$FEATURE_FIXED" = yes ]; then
			vrb "rx-vlan-offload is fixed at ${_cur:-?}"
		elif [ "$_cur" = on ]; then
			rec_cmd ethtool -K "$_if" rxvlan on
			try "rxvlan off (so XDP sees 802.1Q tags in the frame)" \
				ethtool -K "$_if" rxvlan off
		fi
	fi

	# TSO/GSO/checksum offload are TRANSMIT-side and have nothing to do with
	# XDP ingress. Disabling them is a popular piece of cargo cult that costs
	# 30-70% of egress throughput and buys nothing. We never touch them.
	vrb "tso/gso/checksum offloads deliberately left alone (transmit side)"
	return 0
}

tune_pause() {
	_if=$1
	[ "$PAUSE" = keep ] && { vrb "flow control left alone"; return 0; }

	_f=$(eth_dump "$_if" -a) || { skip "flow control - ethtool -a unsupported"; return 0; }
	_rx=$(awk -F: '/^RX:/ { gsub(/[ \t]/, "", $2); print $2; exit }' "$_f")
	_tx=$(awk -F: '/^TX:/ { gsub(/[ \t]/, "", $2); print $2; exit }' "$_f")
	_auto=$(awk -F: '/^Autonegotiate:/ { gsub(/[ \t]/, "", $2); print $2; exit }' "$_f")

	if [ "$PAUSE" = off ]; then
		[ "${_rx:-off}" = off ] && [ "${_tx:-off}" = off ] && {
			vrb "flow control already off"
			return 0
		}
		rec_cmd ethtool -A "$_if" rx "${_rx:-on}" tx "${_tx:-on}" autoneg "${_auto:-on}"
		try "pause frames off (a flood must not pause the whole switch port)" \
			ethtool -A "$_if" rx off tx off
	else
		rec_cmd ethtool -A "$_if" rx "${_rx:-off}" tx "${_tx:-off}"
		try "pause frames on" ethtool -A "$_if" rx on tx on
	fi
	return 0
}

tune_channels() {
	_if=$1
	_xdp=$2
	[ "$DO_CHANNELS" = yes ] || return 0
	[ "$CHANNELS" = skip ] && { vrb "channels skipped by request"; return 0; }

	if [ "$_xdp" != none ] && [ "$FORCE" != yes ]; then
		if [ "$_xdp" = unknown ]; then
			skip "channels - XDP attach state is UNKNOWN; reallocating queues under"
			note "a live dataplane can detach it. Failing safe. Install bpftool or"
			note "iproute2 so the interlock can tell, pass --xdp-mode none if nothing"
			note "is attached, or re-run with --force."
		else
			skip "channels - an XDP program is attached ($_xdp); reallocating queues"
			note "under a live dataplane can detach it. Tune first, attach after,"
			note "or re-run with --force."
		fi
		return 0
	fi

	_f=$(eth_dump "$_if" -l) || { skip "channels - ethtool -l unsupported (virtio without multiqueue?)"; return 0; }
	_max=$(eth_section_field "$_f" max Combined)
	_cur=$(eth_section_field "$_f" cur Combined)
	case "${_max:-0}" in
	''|0|*[!0-9]*)
		# Some drivers expose separate RX/TX channels instead of combined.
		_maxrx=$(eth_section_field "$_f" max RX)
		_currx=$(eth_section_field "$_f" cur RX)
		case "${_maxrx:-0}" in
		''|0|*[!0-9]*) skip "channels - driver reports no adjustable channels"; return 0 ;;
		esac
		_want=$CHANNELS
		[ -z "$_want" ] || [ "$_want" = max ] && _want=$_maxrx
		[ "$_want" -gt "$_maxrx" ] 2>/dev/null && _want=$_maxrx
		if [ "${_currx:-0}" -ge "$_want" ] 2>/dev/null; then
			vrb "rx channels already $_currx (>= $_want)"
			return 0
		fi
		rec_cmd ethtool -L "$_if" rx "$_currx"
		try "rx channels $_currx -> $_want" ethtool -L "$_if" rx "$_want"
		return 0
		;;
	esac

	_ncpu=$(cpu_count)
	_want=$CHANNELS
	if [ -z "$_want" ]; then
		_want=$_ncpu
		[ "$_want" -gt "$_max" ] && _want=$_max
	elif [ "$_want" = max ]; then
		_want=$_max
	fi
	case "$_want" in
	''|*[!0-9]*) skip "channels - invalid target '$CHANNELS'"; return 0 ;;
	esac
	[ "$_want" -lt 1 ] && _want=1
	[ "$_want" -gt "$_max" ] && _want=$_max

	# Never REDUCE the queue count: fewer queues means less RSS spreading,
	# which is the opposite of what this script is for.
	if [ "${_cur:-0}" -ge "$_want" ] 2>/dev/null; then
		vrb "combined channels already $_cur (target $_want, max $_max)"
		return 0
	fi

	_pre=$(link_state "$_if")
	rec_cmd ethtool -L "$_if" combined "$_cur"
	if try "combined channels $_cur -> $_want (hw max $_max)" \
		ethtool -L "$_if" combined "$_want"; then
		if [ "$DRY_RUN" = no ] && [ "$_pre" = up ] && ! wait_link_up "$_if"; then
			bad "link did not come back after the channel change - rolling back"
			ethtool -L "$_if" combined "$_cur" >/dev/null 2>&1
			have ip && ip link set dev "$_if" up >/dev/null 2>&1
		fi
	fi
	return 0
}

tune_rings() {
	_if=$1
	_xdp=$2
	[ "$DO_RING" = yes ] || { vrb "ring sizing skipped by request"; return 0; }

	if [ "$_xdp" != none ] && [ "$FORCE" != yes ]; then
		if [ "$_xdp" = unknown ]; then
			skip "rings - XDP attach state is UNKNOWN; a ring resize reallocates every"
			note "buffer and can detach a live program. Failing safe. Install bpftool"
			note "or iproute2, pass --xdp-mode none if nothing is attached, or --force."
		else
			skip "rings - an XDP program is attached ($_xdp); a ring resize"
			note "reallocates every buffer. Tune first, attach after, or --force."
		fi
		return 0
	fi

	_f=$(eth_dump "$_if" -g) || { skip "rings - ethtool -g unsupported by this driver"; return 0; }
	_rxmax=$(eth_section_field "$_f" max RX)
	_txmax=$(eth_section_field "$_f" max TX)
	_rxcur=$(eth_section_field "$_f" cur RX)
	_txcur=$(eth_section_field "$_f" cur TX)

	case "${_rxmax:-0}${_txmax:-0}" in
	*[!0-9]*|0) skip "rings - driver reports no adjustable ring sizes"; return 0 ;;
	esac

	_rxw=$RX_RING
	[ -z "$_rxw" ] && _rxw=max
	[ "$_rxw" = max ] && _rxw=$_rxmax
	_txw=$TX_RING
	if [ -z "$_txw" ]; then
		_txw=$_txmax
		[ "$_txw" -gt "$TX_RING_CAP" ] 2>/dev/null && _txw=$TX_RING_CAP
	elif [ "$_txw" = max ]; then
		_txw=$_txmax
	fi
	case "$_rxw$_txw" in
	*[!0-9]*) skip "rings - invalid target rx='$RX_RING' tx='$TX_RING'"; return 0 ;;
	esac
	[ "$_rxw" -gt "$_rxmax" ] 2>/dev/null && _rxw=$_rxmax
	[ "$_txw" -gt "$_txmax" ] 2>/dev/null && _txw=$_txmax

	if [ "${_rxcur:-0}" = "$_rxw" ] && [ "${_txcur:-0}" = "$_txw" ]; then
		vrb "rings already rx=$_rxcur tx=$_txcur"
		return 0
	fi

	# Bigger RX rings absorb a burst that would otherwise overrun the ring
	# while the CPU is still in the previous softirq pass. The cost is memory
	# (rx_ring * 2 KB per queue) and latency: a full 8192-entry ring at 1 Gbit
	# is ~90 ms of buffered packets, which is bufferbloat in your NIC.
	_pre=$(link_state "$_if")
	rec_cmd ethtool -G "$_if" rx "$_rxcur" tx "$_txcur"
	if try "rings rx $_rxcur -> $_rxw, tx $_txcur -> $_txw (hw max $_rxmax/$_txmax)" \
		ethtool -G "$_if" rx "$_rxw" tx "$_txw"; then
		if [ "$DRY_RUN" = no ] && [ "$_pre" = up ] && ! wait_link_up "$_if"; then
			bad "link did not come back after the ring resize - rolling back"
			ethtool -G "$_if" rx "$_rxcur" tx "$_txcur" >/dev/null 2>&1
			have ip && ip link set dev "$_if" up >/dev/null 2>&1
		fi
	fi
	return 0
}

tune_coalesce() {
	_if=$1
	[ "$COALESCE" = skip ] && { vrb "coalescing skipped by request"; return 0; }

	_f=$(eth_dump "$_if" -c) || { skip "coalescing - ethtool -c unsupported"; return 0; }
	_arx=$(awk '/^Adaptive RX:/ { print $3 }' "$_f")
	_rxu=$(awk -F: '/^rx-usecs:/ { gsub(/[ \t]/, "", $2); print $2 }' "$_f")
	_rxf=$(awk -F: '/^rx-frames:/ { gsub(/[ \t]/, "", $2); print $2 }' "$_f")

	rec_cmd ethtool -C "$_if" adaptive-rx "${_arx:-off}" rx-usecs "${_rxu:-0}" rx-frames "${_rxf:-0}"

	if [ "$COALESCE" = adaptive ]; then
		if [ "$_arx" = on ]; then
			vrb "adaptive-rx already on"
			return 0
		fi
		# Adaptive moderation raises the interrupt rate when the load is light
		# (low latency) and lowers it under load (fewer interrupts, more work
		# per softirq pass) - which is exactly the profile a flood needs.
		if try "adaptive-rx on" ethtool -C "$_if" adaptive-rx on; then
			return 0
		fi
		note "no adaptive moderation in this driver; falling back to fixed"
	fi

	# Fixed moderation. Higher rx-usecs means fewer interrupts and more
	# packets per NAPI poll (better under flood), at the price of up to that
	# many microseconds of added latency on an idle link.
	if [ "${_rxu:-x}" = "$RX_USECS" ] && [ "${_rxf:-x}" = "$RX_FRAMES" ]; then
		vrb "coalescing already rx-usecs=$RX_USECS rx-frames=$RX_FRAMES"
		return 0
	fi
	if ! try "coalescing rx-usecs=$RX_USECS rx-frames=$RX_FRAMES (adds up to ${RX_USECS}us latency)" \
		ethtool -C "$_if" rx-usecs "$RX_USECS" rx-frames "$RX_FRAMES"; then
		# Several drivers accept rx-usecs but reject rx-frames.
		try "coalescing rx-usecs=$RX_USECS only" \
			ethtool -C "$_if" rx-usecs "$RX_USECS"
	fi
	return 0
}

tune_rps_rfs() {
	_if=$1
	_xdp=$2
	_nrx=$(count_glob "/sys/class/net/$_if/queues/rx-"*)
	_ncpu=$(cpu_count)
	[ "$_nrx" -gt 0 ] || { vrb "no rx queues in sysfs"; return 0; }

	_want_rps=$RPS
	if [ "$_want_rps" = auto ]; then
		if [ "$_nrx" -lt "$_ncpu" ]; then
			_want_rps=on
			note "RPS enabled: $_nrx rx queue(s) for $_ncpu CPUs, so RSS alone"
			note "cannot use the whole machine."
		else
			_want_rps=off
			vrb "RPS not needed: $_nrx rx queues for $_ncpu CPUs"
		fi
	fi
	[ "$_want_rps" = skip ] && return 0

	if [ "$_want_rps" = on ] && [ "$_xdp" = native ]; then
		note "XDP is attached in native mode: packets the program DROPS never"
		note "reach RPS. RPS only spreads the traffic that is passed."
	fi

	_cpus=$(iface_numa_cpus "$_if")
	_mask=$(cpus_to_mask "$_cpus")
	_zero=$(cpus_to_mask "")

	_q=0
	while [ "$_q" -lt "$_nrx" ]; do
		_p="/sys/class/net/$_if/queues/rx-$_q/rps_cpus"
		if [ -e "$_p" ]; then
			_old=$(read_file "$_p")
			rec_write "$_p" "${_old:-0}"
			if [ "$_want_rps" = on ]; then
				write_sysfs "$_p" "$_mask" "rps rx-$_q -> cpus $(oneline "$_cpus")" \
					&& [ "$_q" -eq 0 ] && ok "rps_cpus set on $_nrx queue(s) = $_mask"
			else
				write_sysfs "$_p" "$_zero" "rps rx-$_q off"
			fi
		fi

		# --- RFS ---------------------------------------------------------
		_pf="/sys/class/net/$_if/queues/rx-$_q/rps_flow_cnt"
		if [ -e "$_pf" ]; then
			_oldf=$(read_file "$_pf")
			rec_write "$_pf" "${_oldf:-0}"
			if [ "$RFS" = on ]; then
				_per=$((RFS_ENTRIES / _nrx))
				# rps_flow_cnt must be a power of two.
				_pow=1
				while [ $((_pow * 2)) -le "$_per" ]; do
					_pow=$((_pow * 2))
				done
				write_sysfs "$_pf" "$_pow" "rfs rx-$_q flow_cnt=$_pow"
			else
				write_sysfs "$_pf" 0 "rfs rx-$_q off"
			fi
		fi
		_q=$((_q + 1))
	done

	if [ "$RFS" = on ]; then
		_g=/proc/sys/net/core/rps_sock_flow_entries
		_oldg=$(read_file "$_g")
		rec_write "$_g" "${_oldg:-0}"
		write_sysfs "$_g" "$RFS_ENTRIES" "rfs global table = $RFS_ENTRIES" \
			&& ok "RFS enabled (global table $RFS_ENTRIES)"
		note "RFS thrashes under a spoofed-source flood: every packet is a new"
		note "flow, so the table churns and the locality benefit never lands."
	fi
	return 0
}

tune_xps() {
	_if=$1
	[ "$XPS" = skip ] || [ "$XPS" = off ] && {
		if [ "$XPS" = off ]; then
			_ntx=$(count_glob "/sys/class/net/$_if/queues/tx-"*)
			_q=0
			_zero=$(cpus_to_mask "")
			while [ "$_q" -lt "$_ntx" ]; do
				_p="/sys/class/net/$_if/queues/tx-$_q/xps_cpus"
				[ -e "$_p" ] && { rec_write "$_p" "$(read_file "$_p")"; write_sysfs "$_p" "$_zero" "xps tx-$_q off"; }
				_q=$((_q + 1))
			done
		fi
		return 0
	}

	_ntx=$(count_glob "/sys/class/net/$_if/queues/tx-"*)
	[ "$_ntx" -gt 0 ] || return 0
	_cpus=$(iface_numa_cpus "$_if")
	set -- $_cpus
	_ncpus=$#
	[ "$_ncpus" -gt 0 ] || return 0

	# CPU i transmits on queue (i mod ntx). Each queue therefore gets a
	# disjoint set of CPUs, which is what removes the lock contention.
	_q=0
	_done=0
	while [ "$_q" -lt "$_ntx" ]; do
		_sel=""
		_idx=0
		for _c in $_cpus; do
			if [ $((_idx % _ntx)) -eq "$_q" ]; then
				_sel="$_sel $_c"
			fi
			_idx=$((_idx + 1))
		done
		_p="/sys/class/net/$_if/queues/tx-$_q/xps_cpus"
		if [ -e "$_p" ] && [ -n "$_sel" ]; then
			rec_write "$_p" "$(read_file "$_p")"
			write_sysfs "$_p" "$(cpus_to_mask "$_sel")" "xps tx-$_q -> cpus$_sel" \
				&& _done=$((_done + 1))
		fi
		_q=$((_q + 1))
	done
	[ "$_done" -gt 0 ] && ok "xps_cpus set on $_done tx queue(s)"
	return 0
}

tune_irq_affinity() {
	_if=$1
	[ "$IRQ_AFFINITY" = on ] || { vrb "IRQ affinity left alone"; return 0; }

	_irqs=$(iface_irqs "$_if")
	if [ -z "$_irqs" ]; then
		skip "IRQ affinity - no per-queue IRQs found (virtual NIC or shared line)"
		return 0
	fi

	if irqbalance_active; then
		if [ "$STOP_IRQBALANCE" = yes ]; then
			if have systemctl; then
				try "stop irqbalance" systemctl stop irqbalance
				try "disable irqbalance" systemctl disable irqbalance
			elif have rc-service; then
				try "stop irqbalance" rc-service irqbalance stop
				try "disable irqbalance" rc-update del irqbalance default
			else
				warn "irqbalance is running and I cannot stop it here"
			fi
		else
			warn "irqbalance is RUNNING. It rebalances every ~10 seconds and will"
			warn "undo this pinning. Use --stop-irqbalance, or add the IRQs to"
			warn "IRQBALANCE_BANNED_CPULIST / --banirq in its config."
		fi
	fi

	_cpus=$(iface_numa_cpus "$_if")
	set -- $_cpus
	_n=$#
	[ "$_n" -gt 0 ] || return 0

	_i=0
	_set=0
	for _irq in $_irqs; do
		_cpu=$(printf '%s\n' "$_cpus" | awk -v k=$((_i % _n)) '{ print $(k + 1) }')
		_al="/proc/irq/$_irq/smp_affinity_list"
		_ah="/proc/irq/$_irq/smp_affinity"
		if [ -e "$_al" ]; then
			rec_write "$_al" "$(read_file "$_al")"
			write_sysfs "$_al" "$_cpu" "irq $_irq -> cpu $_cpu" && _set=$((_set + 1))
		elif [ -e "$_ah" ]; then
			rec_write "$_ah" "$(read_file "$_ah")"
			write_sysfs "$_ah" "$(cpus_to_mask "$_cpu")" "irq $_irq -> cpu $_cpu" \
				&& _set=$((_set + 1))
		fi
		_i=$((_i + 1))
	done
	if [ "$_set" -gt 0 ]; then
		ok "pinned $_set IRQ(s) round-robin across cpus $(oneline "$_cpus")"
	else
		skip "IRQ affinity - the kernel manages these vectors itself (nothing to do)"
	fi
	return 0
}

tune_iface() {
	_if=$1

	if [ ! -d "/sys/class/net/$_if" ]; then
		bad "$_if: no such interface"
		return 1
	fi

	_xdp=$(detect_xdp_mode "$_if")
	_drv="?"
	if _f=$(eth_dump "$_if" -i); then
		_drv=$(awk -F: '/^driver:/ { gsub(/^[ \t]+/, "", $2); print $2 }' "$_f")
	fi

	hdr "=== $_if (driver ${_drv:-?}, xdp $_xdp) ==="
	rec_comment "--- $_if ---"

	case "$_drv" in
	virtio_net)
		note "virtio_net: queue count is fixed by the hypervisor (-L needs a"
		note "multiqueue device). XDP native needs 2x queues vs CPUs on some"
		note "hosts; without them the kernel falls back to generic mode."
		;;
	veth|tun)
		note "$_drv is a virtual device; most of this will be unsupported."
		;;
	esac

	tune_offloads "$_if" "$_xdp"
	tune_pause "$_if"
	tune_channels "$_if" "$_xdp"
	tune_rings "$_if" "$_xdp"
	tune_coalesce "$_if"
	tune_rps_rfs "$_if" "$_xdp"
	tune_xps "$_if"
	tune_irq_affinity "$_if"
	return 0
}

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

# Load the profile BEFORE parsing the flags, so a flag on the command line
# overrides the same key from the profile (the documented precedence). --profile
# is itself a flag, so pre-scan for it here without consuming "$@"; the main loop
# below then re-reads the flags and its values win over the profile-supplied
# ones. (IFACES is additive: profile interfaces and -i interfaces are unioned.)
_pscan_prev=""
for _arg in "$@"; do
	[ "$_arg" = "--" ] && break
	case "$_arg" in
	--profile=*) PROFILE=${_arg#--profile=} ;;
	*) [ "$_pscan_prev" = "--profile" ] && PROFILE=$_arg ;;
	esac
	_pscan_prev=$_arg
done
[ -n "$PROFILE" ] && load_profile "$PROFILE"

while [ $# -gt 0 ]; do
	case "$1" in
	-i|--iface)     [ $# -ge 2 ] || die "--iface needs an argument"; IFACES="$IFACES $(printf '%s' "$2" | tr ',' ' ')"; shift 2 ;;
	--iface=*)      IFACES="$IFACES $(printf '%s' "${1#--iface=}" | tr ',' ' ')"; shift ;;
	--all)          WANT_ALL="yes"; shift ;;
	--show)         ACTION="show"; shift ;;
	--print-unit)   ACTION="print-unit"; shift ;;
	--revert)
		ACTION="revert"; shift
		if [ $# -gt 0 ]; then
			case "$1" in
			-*) : ;;
			*) RESTORE_FILE=$1; shift ;;
			esac
		fi
		;;
	--channels)     [ $# -ge 2 ] || die "--channels needs an argument"; CHANNELS=$2; shift 2 ;;
	--channels=*)   CHANNELS=${1#--channels=}; shift ;;
	--rx-ring)      [ $# -ge 2 ] || die "--rx-ring needs an argument"; RX_RING=$2; shift 2 ;;
	--rx-ring=*)    RX_RING=${1#--rx-ring=}; shift ;;
	--tx-ring)      [ $# -ge 2 ] || die "--tx-ring needs an argument"; TX_RING=$2; shift 2 ;;
	--tx-ring=*)    TX_RING=${1#--tx-ring=}; shift ;;
	--no-ring)      DO_RING="no"; shift ;;
	--coalesce)     [ $# -ge 2 ] || die "--coalesce needs an argument"; COALESCE=$2; shift 2 ;;
	--coalesce=*)   COALESCE=${1#--coalesce=}; shift ;;
	--rx-usecs)     [ $# -ge 2 ] || die "--rx-usecs needs an argument"; RX_USECS=$2; shift 2 ;;
	--rx-usecs=*)   RX_USECS=${1#--rx-usecs=}; shift ;;
	--rx-frames)    [ $# -ge 2 ] || die "--rx-frames needs an argument"; RX_FRAMES=$2; shift 2 ;;
	--rx-frames=*)  RX_FRAMES=${1#--rx-frames=}; shift ;;
	--lro)          [ $# -ge 2 ] || die "--lro needs an argument"; LRO=$2; shift 2 ;;
	--lro=*)        LRO=${1#--lro=}; shift ;;
	--gro)          [ $# -ge 2 ] || die "--gro needs an argument"; GRO=$2; shift 2 ;;
	--gro=*)        GRO=${1#--gro=}; shift ;;
	--vlan-offload) [ $# -ge 2 ] || die "--vlan-offload needs an argument"; VLAN_OFFLOAD=$2; shift 2 ;;
	--vlan-offload=*) VLAN_OFFLOAD=${1#--vlan-offload=}; shift ;;
	--pause)        [ $# -ge 2 ] || die "--pause needs an argument"; PAUSE=$2; shift 2 ;;
	--pause=*)      PAUSE=${1#--pause=}; shift ;;
	--rps)          [ $# -ge 2 ] || die "--rps needs an argument"; RPS=$2; shift 2 ;;
	--rps=*)        RPS=${1#--rps=}; shift ;;
	--rfs)          [ $# -ge 2 ] || die "--rfs needs an argument"; RFS=$2; shift 2 ;;
	--rfs=*)        RFS=${1#--rfs=}; shift ;;
	--rfs-entries)  [ $# -ge 2 ] || die "--rfs-entries needs an argument"; RFS_ENTRIES=$2; shift 2 ;;
	--rfs-entries=*) RFS_ENTRIES=${1#--rfs-entries=}; shift ;;
	--xps)          [ $# -ge 2 ] || die "--xps needs an argument"; XPS=$2; shift 2 ;;
	--xps=*)        XPS=${1#--xps=}; shift ;;
	--irq-affinity) [ $# -ge 2 ] || die "--irq-affinity needs an argument"; IRQ_AFFINITY=$2; shift 2 ;;
	--irq-affinity=*) IRQ_AFFINITY=${1#--irq-affinity=}; shift ;;
	--stop-irqbalance) STOP_IRQBALANCE="yes"; shift ;;
	--xdp-mode)     [ $# -ge 2 ] || die "--xdp-mode needs an argument"; XDP_MODE=$2; shift 2 ;;
	--xdp-mode=*)   XDP_MODE=${1#--xdp-mode=}; shift ;;
	--profile)      [ $# -ge 2 ] || die "--profile needs an argument"; PROFILE=$2; shift 2 ;;
	--profile=*)    PROFILE=${1#--profile=}; shift ;;
	--backup-dir)   [ $# -ge 2 ] || die "--backup-dir needs an argument"; BACKUP_DIR=$2; shift 2 ;;
	--backup-dir=*) BACKUP_DIR=${1#--backup-dir=}; shift ;;
	-n|--dry-run)   DRY_RUN="yes"; shift ;;
	--force)        FORCE="yes"; shift ;;
	-v|--verbose)   VERBOSE="yes"; shift ;;
	-h|--help)      usage; exit 0 ;;
	-V|--version)   printf '%s %s\n' "$PROG" "$VERSION"; exit 0 ;;
	--)             shift; break ;;
	*)              die "unknown option '$1' (try --help)" ;;
	esac
done

# The profile was already loaded before this loop (see the pre-scan above), so
# the flags just parsed take precedence over any key it set.

case "$COALESCE" in adaptive|fixed|skip) : ;; *) die "--coalesce must be adaptive, fixed or skip" ;; esac
case "$LRO" in off|keep) : ;; *) die "--lro must be off or keep" ;; esac
case "$GRO" in auto|on|off|keep) : ;; *) die "--gro must be auto, on, off or keep" ;; esac
case "$VLAN_OFFLOAD" in keep|off) : ;; *) die "--vlan-offload must be keep or off" ;; esac
case "$PAUSE" in on|off|keep) : ;; *) die "--pause must be on, off or keep" ;; esac
case "$RPS" in auto|on|off|skip) : ;; *) die "--rps must be auto, on, off or skip" ;; esac
case "$RFS" in on|off) : ;; *) die "--rfs must be on or off" ;; esac
case "$XPS" in on|off|skip) : ;; *) die "--xps must be on, off or skip" ;; esac
case "$IRQ_AFFINITY" in on|off) : ;; *) die "--irq-affinity must be on or off" ;; esac
case "$XDP_MODE" in auto|native|generic|offload|none) : ;; *) die "--xdp-mode must be auto, native, generic, offload or none" ;; esac

if [ "$ACTION" = print-unit ]; then
	print_unit
	exit 0
fi

# ---------------------------------------------------------------------------
# --revert
# ---------------------------------------------------------------------------

if [ "$ACTION" = revert ]; then
	[ "$(id -u 2>/dev/null || echo 1)" = "0" ] || die "--revert must run as root"
	if [ -z "$RESTORE_FILE" ]; then
		RESTORE_FILE="$BACKUP_DIR/nic-restore-latest.sh"
		[ -f "$RESTORE_FILE" ] || RESTORE_FILE="$BACKUP_DIR_FALLBACK/nic-restore-latest.sh"
	fi
	[ -f "$RESTORE_FILE" ] || die "no restore script found ($RESTORE_FILE). Pass one explicitly."
	# This script is executed as root. Refuse it unless the file and its parent
	# directory are root-owned and not world/foreign-group-writable, so a local
	# user cannot plant a payload under a world-writable path (e.g. /var/tmp).
	[ -L "$RESTORE_FILE" ] && die "restore script $RESTORE_FILE is a symlink; refusing to run it"
	_rdir=$(dirname "$RESTORE_FILE" 2>/dev/null) || _rdir=/
	if ! secure_path "$_rdir" || ! secure_path "$RESTORE_FILE"; then
		die "refusing to run $RESTORE_FILE: it or its directory is not root-owned or is
world/foreign-group-writable. Move it where only root can write and pass it explicitly."
	fi
	say "${C_B}Reverting from $RESTORE_FILE${C_0}"
	sh "$RESTORE_FILE"
	exit $?
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

if ! TMPD=$(mktemp -d 2>/dev/null) || [ -z "$TMPD" ]; then
	TMPD="${TMPDIR:-/tmp}/calyanti-nic.$$.$(date +%s 2>/dev/null || echo 0)"
	(umask 077; mkdir "$TMPD") 2>/dev/null || die "cannot create a temporary directory"
fi
chmod 0700 "$TMPD" 2>/dev/null
[ -d "$TMPD" ] || die "cannot create a temporary directory"

have ethtool || warn "ethtool is not installed: offload, ring, channel and
	coalescing tuning will all be skipped. Install it (ethtool package) and
	re-run. RPS/XPS/IRQ tuning still works without it."

if [ "$ACTION" = apply ] && [ "$DRY_RUN" = no ]; then
	[ "$(id -u 2>/dev/null || echo 1)" = "0" ] || die "must run as root (or use --dry-run / --show)"
fi

# ---------------------------------------------------------------------------
# Interface selection
# ---------------------------------------------------------------------------

if [ "$WANT_ALL" = yes ]; then
	IFACES="$IFACES $(all_physical | tr '\n' ' ')"
fi
if [ -z "$(printf '%s' "$IFACES" | tr -d ' \t')" ]; then
	IFACES="$(conf_ifaces | tr '\n' ' ') $(route_ifaces | tr '\n' ' ')"
	[ -n "$(printf '%s' "$IFACES" | tr -d ' \t')" ] || \
		IFACES="$(all_physical | tr '\n' ' ')"
	[ -n "$(printf '%s' "$IFACES" | tr -d ' \t')" ] && \
		say "auto-detected interfaces:$(printf ' %s' $IFACES)"
fi
IFACES=$(dedup_ifaces "$IFACES")
[ -n "$IFACES" ] || die "no interfaces to work on (try --iface NAME or --all)"

# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

if [ "$ACTION" = show ]; then
	for IF in $IFACES; do
		show_iface "$IF"
	done
	exit 0
fi

say "${C_B}Caly Anti NIC tuning${C_0}"
say "  interfaces:  $IFACES"
say "  cpus:        $(cpu_count)"
[ "$DRY_RUN" = yes ] && say "  mode:        DRY RUN, nothing will be changed"

[ "$DRY_RUN" = no ] && restore_begin

for IF in $IFACES; do
	tune_iface "$IF"
done

restore_end

hdr "Summary"
say "  applied:     $N_OK"
say "  skipped:     $N_SKIP  (unsupported by the driver, or already correct)"
say "  failed:      $N_FAIL"
say ""
say "NIC settings do NOT survive a reboot or a driver reload."
say "Run '$0 --print-unit' for a systemd unit and udev rule that reapply them."
say ""
say "Verify with:  $0 --show"
say "and watch:    ethtool -S <iface> | grep -iE 'drop|miss|err'"
say "              awk 'NR>1{print \$2, \$3}' /proc/net/softnet_stat"

[ "$N_FAIL" -gt 0 ] && exit 2
exit 0
