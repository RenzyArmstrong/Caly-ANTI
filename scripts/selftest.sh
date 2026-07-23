#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Caly Anti - post-install self-test.
#
# Read-only validation, safe to run on a production host: it reconfigures
# nothing. It reports PASS / WARN / FAIL per check and exits non-zero only when
# a real FAIL is seen (a WARN is informational).
set -u

SBINDIR="${SBINDIR:-/usr/sbin}"
PIN_DIR="${PIN_DIR:-/sys/fs/bpf/calyanti}"
CTL_SOCK="${CTL_SOCK:-/run/calyanti/control.sock}"
CONF="${CONF:-/etc/calyanti/calyanti.conf}"

fails=0
warns=0

if [ -t 1 ] && command -v tput >/dev/null 2>&1 && [ -n "${TERM:-}" ]; then
	C_OK=$(tput setaf 2 2>/dev/null || echo ""); C_WARN=$(tput setaf 3 2>/dev/null || echo "")
	C_BAD=$(tput setaf 1 2>/dev/null || echo ""); C_OFF=$(tput sgr0 2>/dev/null || echo "")
else
	C_OK=""; C_WARN=""; C_BAD=""; C_OFF=""
fi

pass() { printf '  %sPASS%s  %s\n' "$C_OK"   "$C_OFF" "$*"; }
warn() { printf '  %sWARN%s  %s\n' "$C_WARN" "$C_OFF" "$*"; warns=$((warns + 1)); }
fail() { printf '  %sFAIL%s  %s\n' "$C_BAD"  "$C_OFF" "$*"; fails=$((fails + 1)); }

printf '== Caly Anti self-test ==\n'

# 1. Binaries.
if [ -x "${SBINDIR}/calyd" ] && "${SBINDIR}/calyd" --version >/dev/null 2>&1; then
	pass "daemon present and runnable (${SBINDIR}/calyd)"
elif [ -x "${SBINDIR}/calyd" ]; then
	warn "daemon present but --version failed"
else
	fail "no daemon at ${SBINDIR}/calyd"
fi

if [ -x "${SBINDIR}/calyctl" ]; then
	pass "CLI present (${SBINDIR}/calyctl)"
else
	warn "no CLI at ${SBINDIR}/calyctl"
fi

# 2. Configuration.
if [ -r "$CONF" ]; then
	pass "configuration present (${CONF})"
else
	warn "no configuration at ${CONF}"
fi

# 3. Program attached to at least one interface.
_attached=0
if command -v bpftool >/dev/null 2>&1; then
	if bpftool net show 2>/dev/null | grep -qi 'xdp\|caly'; then
		_attached=1
	fi
fi
if [ "$_attached" -eq 0 ] && command -v ip >/dev/null 2>&1; then
	if ip -details link show 2>/dev/null | grep -qi 'xdp'; then
		_attached=1
	fi
fi
if [ "$_attached" -eq 1 ]; then
	pass "a program is attached to the data path (xdp/tc)"
else
	warn "no attached xdp/tc program found (nftables/iptables fallback?)"
fi

# 4. Pinned maps.
if [ -d "$PIN_DIR" ] && [ -n "$(ls -A "$PIN_DIR" 2>/dev/null || true)" ]; then
	pass "maps pinned under ${PIN_DIR}"
else
	warn "no pinned maps under ${PIN_DIR} (expected for the nft/iptables path)"
fi

# 5. Daemon answers the control socket.
if [ -S "$CTL_SOCK" ]; then
	if [ -x "${SBINDIR}/calyctl" ] && "${SBINDIR}/calyctl" status >/dev/null 2>&1; then
		pass "daemon answers on the control socket"
	else
		warn "control socket exists but the daemon did not answer"
	fi
else
	warn "no control socket at ${CTL_SOCK} (daemon not running?)"
fi

# 6. SYN cookies sysctl (the SYN proxy design requires value 2).
if [ -r /proc/sys/net/ipv4/tcp_syncookies ]; then
	_sc=$(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || echo "?")
	if [ "$_sc" = "2" ]; then
		pass "net.ipv4.tcp_syncookies = 2"
	elif [ "$_sc" = "1" ]; then
		warn "net.ipv4.tcp_syncookies = 1 (SYN proxy needs 2; fallback active)"
	else
		warn "net.ipv4.tcp_syncookies = ${_sc}"
	fi
fi

# 7. Management port still reachable. This is the check that matters most.
_mgmt="${CALY_MGMT_PORTS:-22}"
_listen=""
if command -v ss >/dev/null 2>&1; then
	_listen=$(ss -H -ltn 2>/dev/null || true)
elif command -v netstat >/dev/null 2>&1; then
	_listen=$(netstat -ltn 2>/dev/null || true)
fi
if [ -n "$_listen" ]; then
	for _p in $_mgmt; do
		if printf '%s\n' "$_listen" | grep -Eq ":${_p}([[:space:]]|\$)"; then
			pass "management port ${_p} is listening"
		else
			warn "management port ${_p} not seen listening"
		fi
	done
else
	warn "cannot enumerate listening sockets (no ss/netstat)"
fi

printf '\n'
if [ "$fails" -gt 0 ]; then
	printf '%sself-test: %d failure(s), %d warning(s)%s\n' "$C_BAD" "$fails" "$warns" "$C_OFF"
	exit 1
fi
printf '%sself-test: OK%s (%d warning(s))\n' "$C_OK" "$C_OFF" "$warns"
exit 0
