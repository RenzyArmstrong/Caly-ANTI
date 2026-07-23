#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Caly Anti - emergency disable / recovery.
#
# Removes every Caly Anti dataplane and restores defaults, so an operator can
# regain a clean network state from a console. Depends only on coreutils, ip,
# and (when present) tc / nft / iptables / ipset. Every step is guarded, so one
# failure never stops the rest. Safe to run more than once.
#
# Install path: /usr/sbin/calyanti-panic (symlink) or run: sh scripts/panic.sh
set -u

PIN_DIR="/sys/fs/bpf/calyanti"
SYSCTL_BACKUP_DIR="/var/lib/calyanti/sysctl"

if [ "$(id -u)" -ne 0 ]; then
	if command -v sudo >/dev/null 2>&1; then
		exec sudo -- "$0" "$@"
	fi
	echo "calyanti-panic: must run as root" >&2
	exit 1
fi

say() { printf '  - %s\n' "$*"; }

printf '== Caly Anti: emergency disable ==\n'

# 1. Detach the XDP program and the tc hook from every interface.
for _p in /sys/class/net/*; do
	[ -e "$_p" ] || continue
	_if=$(basename "$_p")
	[ "$_if" = "lo" ] && continue
	ip link set dev "$_if" xdp off        2>/dev/null || true
	ip link set dev "$_if" xdpgeneric off 2>/dev/null || true
	ip link set dev "$_if" xdpdrv off     2>/dev/null || true
	if command -v tc >/dev/null 2>&1; then
		tc qdisc del dev "$_if" clsact 2>/dev/null || true
	fi
done
say "interfaces cleared"

# 2. The project's own nftables table (never touches the base ruleset).
if command -v nft >/dev/null 2>&1; then
	nft delete table inet calyanti 2>/dev/null || true
	say "nftables table removed"
fi

# 3. The project's iptables/ip6tables chains, across legacy and nft backends.
_ipt_clear() {
	_ipt=$1
	command -v "$_ipt" >/dev/null 2>&1 || return 0
	# Unhook the jumps from the base chains first, then flush and delete.
	"$_ipt" -t mangle -D PREROUTING -j CALY_EARLY 2>/dev/null || true
	"$_ipt" -t filter -D INPUT      -j CALY_INPUT 2>/dev/null || true
	"$_ipt" -t filter -D FORWARD    -j CALY_FWD   2>/dev/null || true
	for _c in CALY_INPUT CALY_FWD CALY_DROP CALY_LOGDROP \
		  CALY_BUCKETS CALY_PORTS CALY_AMP CALY_SYNCEIL; do
		"$_ipt" -t filter -F "$_c" 2>/dev/null || true
		"$_ipt" -t filter -X "$_c" 2>/dev/null || true
	done
	"$_ipt" -t mangle -F CALY_EARLY 2>/dev/null || true
	"$_ipt" -t mangle -X CALY_EARLY 2>/dev/null || true
}
for _b in iptables ip6tables iptables-legacy ip6tables-legacy \
	  iptables-nft ip6tables-nft; do
	_ipt_clear "$_b"
done
say "iptables chains removed"

# 4. The project's ipset sets.
if command -v ipset >/dev/null 2>&1; then
	for _s in calyanti_allow4 calyanti_allow6 calyanti_block4 \
		  calyanti_block6 calyanti_ban4 calyanti_ban6; do
		ipset destroy "$_s" 2>/dev/null || true
	done
	say "ipset sets removed"
fi

# 5. Unpin the maps.
if [ -d "$PIN_DIR" ]; then
	rm -rf "$PIN_DIR" 2>/dev/null || true
	say "pinned maps removed"
fi

# 6. Restore sysctl from the backup the tuning step wrote.
_restored=0
for _cand in /usr/lib/calyanti/scripts/apply-sysctl.sh \
	     /usr/libexec/calyanti/apply-sysctl.sh \
	     ./tuning/apply-sysctl.sh; do
	if [ -x "$_cand" ]; then
		if "$_cand" --revert >/dev/null 2>&1; then
			_restored=1
			break
		fi
	fi
done
if [ "$_restored" -eq 0 ] && [ -d "$SYSCTL_BACKUP_DIR" ]; then
	_latest=$(ls -1t "$SYSCTL_BACKUP_DIR"/*.sh 2>/dev/null | head -n 1 || true)
	if [ -n "${_latest:-}" ] && [ -x "$_latest" ]; then
		"$_latest" >/dev/null 2>&1 && _restored=1
	fi
fi
if [ "$_restored" -eq 1 ]; then
	say "sysctl restored"
else
	say "sysctl restore skipped (no backup found)"
fi

# 7. Stop the services if an init system is managing them.
if command -v systemctl >/dev/null 2>&1; then
	systemctl stop calyanti-watch calyanti 2>/dev/null || true
elif command -v rc-service >/dev/null 2>&1; then
	rc-service calyanti-watch stop 2>/dev/null || true
	rc-service calyanti stop       2>/dev/null || true
fi
say "services stopped"

printf '== done. Network traffic is now unfiltered. ==\n'
exit 0
