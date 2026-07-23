#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Caly Anti - scripts/uninstall.sh
#
# Full, clean removal:
#   - stop and disable the services
#   - detach the XDP program from every interface, in every mode
#   - remove the tc/clsact filters
#   - flush and delete the nftables table and the iptables chains + ipsets
#   - unpin the maps and remove the pin directory
#   - revert the sysctl drop-in, restoring the pre-install values
#   - remove installed files, keeping configuration unless --purge
#
# The teardown order matters: detach the dataplane BEFORE removing the binary
# that knows how to detach it. Every step is best-effort and never aborts the
# rest, because a half-removed firewall that still drops packets is the worst
# possible outcome of an uninstall.
#
# POSIX sh. Runs under dash, busybox ash and bash.

set -u

CALY_VERSION="1.0.0"

caly_self=$0
case "$caly_self" in
*/*) caly_self_dir=${caly_self%/*} ;;
*)   caly_self_dir=. ;;
esac
SCRIPT_DIR=$(cd "$caly_self_dir" 2>/dev/null && pwd) || SCRIPT_DIR=$PWD
unset caly_self caly_self_dir

# Prefer the installed detect-env.sh so uninstall works after the source tree
# is gone; fall back to the one beside us.
if [ -r "/usr/lib/calyanti/scripts/detect-env.sh" ]; then
	# shellcheck source=scripts/detect-env.sh
	. "/usr/lib/calyanti/scripts/detect-env.sh"
elif [ -r "${SCRIPT_DIR}/detect-env.sh" ]; then
	# shellcheck source=scripts/detect-env.sh
	. "${SCRIPT_DIR}/detect-env.sh"
else
	echo "uninstall.sh: detect-env.sh not found; using built-in minimal helpers" >&2
	CALY_DRY_RUN=${CALY_DRY_RUN:-0}
	CALY_QUIET=${CALY_QUIET:-0}
	caly_info() { [ "${CALY_QUIET}" = 1 ] || printf '==> %s\n' "$*"; }
	caly_step() { [ "${CALY_QUIET}" = 1 ] || printf '  -> %s\n' "$*"; }
	caly_ok()   { [ "${CALY_QUIET}" = 1 ] || printf '  ok  %s\n' "$*"; }
	caly_warn() { printf 'warning: %s\n' "$*" >&2; }
	caly_err()  { printf 'error: %s\n' "$*" >&2; }
	caly_say()  { [ "${CALY_QUIET}" = 1 ] || printf '%s\n' "$*"; }
	caly_have() { command -v "$1" >/dev/null 2>&1; }
	caly_init_colors() { :; }
	caly_try() {
		if [ "${CALY_DRY_RUN}" = 1 ]; then printf '  [dry-run] %s\n' "$*"; return 0; fi
		"$@" >/dev/null 2>&1 || return 0
	}
	caly_run() {
		if [ "${CALY_DRY_RUN}" = 1 ]; then printf '  [dry-run] %s\n' "$*"; return 0; fi
		"$@"
	}
	CALY_C_RESET=''; CALY_C_BOLD=''; CALY_C_RED=''; CALY_C_GREEN=''
	CALY_C_YELLOW=''; CALY_C_BLUE=''; CALY_C_DIM=''
	CALY_MINIMAL=1
fi

# Paths (mirror install.sh; overridable for staged trees).
PREFIX="/usr"
SYSCONFDIR="/etc"
SBINDIR="${PREFIX}/sbin"
LIBDIR="${PREFIX}/lib/calyanti"
CONFDIR="${SYSCONFDIR}/calyanti"
DOCDIR="${PREFIX}/share/doc/calyanti"
STATEDIR="/var/lib/calyanti"
LOGDIR="/var/log/calyanti"
RUNDIR="/run/calyanti"
PINDIR="/sys/fs/bpf/calyanti"
SYSCTL_FILE="/etc/sysctl.d/98-calyanti.conf"

OPT_PURGE=0
OPT_KEEP_SYSCTL=0
OPT_IFACE=""
OPT_YES=0

usage() {
	cat <<'EOF'
Caly Anti uninstaller

Usage: uninstall.sh [OPTIONS]

  --purge            also remove /etc/calyanti (configuration and generated
                     rulesets) and /var/lib/calyanti (state). Without it the
                     configuration is kept so a later reinstall reuses it.
  --keep-sysctl      leave /etc/sysctl.d/98-calyanti.conf in place.
  --iface=NAME[,..]  extra interface(s) to detach, on top of what is
                     discovered automatically.
  -n, --dry-run      print every action, change nothing.
  -y, --yes          do not prompt for confirmation.
  -q, --quiet        less output.
  --no-color         disable colour.
  -h, --help         this text.

Removal is best-effort and ordered so the machine is never left with a
half-active filter: the dataplane is detached before its binary is removed.
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--purge)        OPT_PURGE=1 ;;
	--keep-sysctl)  OPT_KEEP_SYSCTL=1 ;;
	--iface=*)      OPT_IFACE=${1#--iface=} ;;
	--iface)        OPT_IFACE=${2:-}; shift ;;
	-n|--dry-run)   CALY_DRY_RUN=1 ;;
	-y|--yes)       OPT_YES=1 ;;
	-q|--quiet)     CALY_QUIET=1 ;;
	--no-color)     CALY_COLOR="never"; caly_init_colors ;;
	-h|--help)      usage; exit 0 ;;
	*)              caly_err "unknown option '$1'"; usage >&2; exit 2 ;;
	esac
	shift
done

if [ "$(id -u 2>/dev/null || echo 1)" != "0" ] && [ "${CALY_DRY_RUN:-0}" != "1" ]; then
	caly_err "must run as root"
	exit 1
fi

# Fill in detection variables the teardown uses, when the full library loaded.
if [ "${CALY_MINIMAL:-0}" != "1" ]; then
	caly_detect_all 2>/dev/null || true
fi
: "${CALY_INIT:=unknown}"
: "${CALY_HAVE_IP:=no}"
: "${CALY_HAVE_TC:=no}"
: "${CALY_HAVE_NFT:=no}"
: "${CALY_HAVE_IPTABLES:=no}"
: "${CALY_HAVE_IP6TABLES:=no}"
: "${CALY_HAVE_IPSET:=no}"
: "${CALY_NICS:=}"

confirm() {
	[ "$OPT_YES" = "1" ] && return 0
	[ "${CALY_DRY_RUN:-0}" = "1" ] && return 0
	if [ ! -t 0 ]; then
		caly_warn "not interactive and --yes not given; assuming YES for uninstall"
		return 0
	fi
	printf '%s [Y/n] ' "$1"
	read -r caly_cf_a || caly_cf_a="y"
	case "$caly_cf_a" in
	n|N|no|NO|No) unset caly_cf_a; return 1 ;;
	esac
	unset caly_cf_a
	return 0
}

# --------------------------------------------------------------------------
# 0. Cancel any pending rollback deadman so it cannot fire mid-uninstall.
# --------------------------------------------------------------------------
step_cancel_rollback() {
	if [ -f "${RUNDIR}/rollback.pid" ]; then
		caly_step "cancelling the armed rollback timer"
		caly_try mkdir -p "$RUNDIR"
		caly_try touch "${RUNDIR}/confirmed"
		caly_rb_pid=$(cat "${RUNDIR}/rollback.pid" 2>/dev/null || true)
		case "$caly_rb_pid" in
		[0-9]*) caly_try kill "$caly_rb_pid" ;;
		esac
		caly_try rm -f "${RUNDIR}/rollback.pid"
		unset caly_rb_pid
	fi
}

# --------------------------------------------------------------------------
# 1. Stop and disable the services.
# --------------------------------------------------------------------------
step_stop_services() {
	caly_info "Stopping services"
	case "$CALY_INIT" in
	systemd)
		for caly_ss_u in calyanti-watch.service calyanti.service \
		    calyanti-nft.service calyanti-iptables.service; do
			caly_try systemctl stop "$caly_ss_u"
			caly_try systemctl disable "$caly_ss_u"
		done
		unset caly_ss_u ;;
	openrc)
		for caly_ss_u in calyanti-watch calyanti; do
			caly_try rc-service "$caly_ss_u" stop
			caly_try rc-update del "$caly_ss_u" default
		done
		unset caly_ss_u ;;
	sysvinit|busybox)
		caly_try /etc/init.d/calyanti stop
		if caly_have update-rc.d; then
			caly_try update-rc.d -f calyanti remove
		elif caly_have chkconfig; then
			caly_try chkconfig --del calyanti
		fi ;;
	*)
		# Unknown init: kill by pidfile, then by name.
		if [ -f "${RUNDIR}/calyanti.pid" ]; then
			caly_rb_pid=$(cat "${RUNDIR}/calyanti.pid" 2>/dev/null || true)
			case "$caly_rb_pid" in
			[0-9]*) caly_try kill "$caly_rb_pid" ;;
			esac
			unset caly_rb_pid
		fi
		caly_have pkill && caly_try pkill -x calyd ;;
	esac
}

# --------------------------------------------------------------------------
# 2. Ask the daemon to detach, if it is still around and knows how. Cleanest
#    path: it removes exactly what it created.
# --------------------------------------------------------------------------
step_daemon_detach() {
	for caly_dd_c in "${SBINDIR}/calyctl" /usr/sbin/calyctl \
	    /usr/local/sbin/calyctl calyctl; do
		if caly_have "$caly_dd_c" || [ -x "$caly_dd_c" ]; then
			caly_step "asking ${caly_dd_c} to detach the dataplane"
			caly_try "$caly_dd_c" detach
			break
		fi
	done
	unset caly_dd_c
}

# --------------------------------------------------------------------------
# 3. Detach XDP and tc from every interface. Belt and braces: even if the
#    daemon already did it, doing it again is harmless, and if the daemon was
#    killed hard this is the only thing that removes the program.
# --------------------------------------------------------------------------
discover_attached_ifaces() {
	caly_di_list=""
	for caly_di_p in /sys/class/net/*; do
		[ -e "$caly_di_p" ] || continue
		caly_di_if=${caly_di_p##*/}
		[ "$caly_di_if" = "lo" ] && continue
		caly_di_list="${caly_di_list}${caly_di_list:+ }${caly_di_if}"
	done
	# Union with any operator-specified interfaces.
	for caly_di_if in $(printf '%s' "$OPT_IFACE" | tr ',' ' '); do
		case " $caly_di_list " in
		*" $caly_di_if "*) ;;
		*) caly_di_list="${caly_di_list}${caly_di_list:+ }${caly_di_if}" ;;
		esac
	done
	printf '%s' "$caly_di_list"
	unset caly_di_list caly_di_p caly_di_if
}

step_detach_dataplane() {
	caly_info "Detaching XDP and tc programs"
	caly_dp_ifaces=$(discover_attached_ifaces)

	for caly_dp_if in $caly_dp_ifaces; do
		if [ "$CALY_HAVE_IP" = "yes" ]; then
			# There is no harm in clearing a mode that was not set, so
			# clear all three spellings. Old iproute2 uses `xdp off`;
			# newer versions also accept the mode-specific forms.
			caly_try ip link set dev "$caly_dp_if" xdp off
			caly_try ip link set dev "$caly_dp_if" xdpgeneric off
			caly_try ip link set dev "$caly_dp_if" xdpdrv off
			caly_try ip link set dev "$caly_dp_if" xdpoffload off
		fi
		if [ "$CALY_HAVE_TC" = "yes" ]; then
			# Remove our clsact ingress filter. Deleting the qdisc takes
			# the filter with it, but only do that if it is a clsact
			# qdisc we are responsible for.
			caly_try tc filter del dev "$caly_dp_if" ingress
			caly_try tc filter del dev "$caly_dp_if" egress
			if tc qdisc show dev "$caly_dp_if" 2>/dev/null | \
			    grep -q 'clsact'; then
				caly_try tc qdisc del dev "$caly_dp_if" clsact
			fi
		fi
	done

	# bpftool can force-detach anything the above missed (e.g. an interface
	# that has since been renamed).
	if [ -n "${CALY_BPFTOOL:-}" ] || caly_have bpftool; then
		caly_bt=${CALY_BPFTOOL:-$(command -v bpftool 2>/dev/null || echo bpftool)}
		caly_try "$caly_bt" net detach xdp 2>/dev/null
	fi
	unset caly_dp_ifaces caly_dp_if caly_bt
}

# --------------------------------------------------------------------------
# 4. Unpin the maps and programs.
# --------------------------------------------------------------------------
step_unpin() {
	caly_info "Unpinning maps"
	if [ -d "$PINDIR" ]; then
		caly_step "removing ${PINDIR}"
		caly_try rm -rf "$PINDIR"
	fi
	# Older loaders may have pinned individual objects at the bpffs root.
	for caly_up_n in caly_config caly_stats caly_stats_b caly_global \
	    caly_allow4 caly_allow6 caly_block4 caly_block6 caly_local4 \
	    caly_local6 caly_ban4 caly_ban6 caly_rate4 caly_rate6 caly_conn \
	    caly_scan4 caly_scan6 caly_top4 caly_top6 caly_port_tcp caly_port_udp \
	    caly_port_tb caly_icmp4_pol caly_icmp6_pol caly_iface caly_events \
	    caly_events_rb caly_progs caly_scratch; do
		[ -e "/sys/fs/bpf/${caly_up_n}" ] && caly_try rm -f "/sys/fs/bpf/${caly_up_n}"
	done
	unset caly_up_n
}

# --------------------------------------------------------------------------
# 5. Remove the nftables ruleset.
# --------------------------------------------------------------------------
step_nftables() {
	[ "$CALY_HAVE_NFT" = "yes" ] || return 0
	if nft list table inet calyanti >/dev/null 2>&1; then
		caly_info "Removing the nftables table"
		caly_try nft delete table inet calyanti
	fi
	caly_try rm -f /etc/local.d/calyanti-nft.start
}

# --------------------------------------------------------------------------
# 6. Remove the iptables chains and ipsets.
# --------------------------------------------------------------------------
step_iptables() {
	[ "$CALY_HAVE_IPTABLES" = "yes" ] || [ "$CALY_HAVE_IP6TABLES" = "yes" ] || return 0
	caly_info "Removing the iptables chains and ipsets"

	for caly_ip_cmd in iptables ip6tables; do
		caly_have "$caly_ip_cmd" || continue
		# Unlink from INPUT first, then flush and delete the chain.
		caly_try "$caly_ip_cmd" -D INPUT -j CALYANTI
		caly_try "$caly_ip_cmd" -F CALYANTI
		caly_try "$caly_ip_cmd" -X CALYANTI
	done

	if [ "$CALY_HAVE_IPSET" = "yes" ]; then
		for caly_ip_s in caly_allow4 caly_block4 caly_ban4 \
		    caly_allow6 caly_block6 caly_ban6; do
			caly_try ipset flush "$caly_ip_s"
			caly_try ipset destroy "$caly_ip_s"
		done
		unset caly_ip_s
	fi
	caly_try rm -f /etc/local.d/calyanti-iptables.start
	unset caly_ip_cmd
}

# --------------------------------------------------------------------------
# 7. Revert sysctl, restoring the pre-install values where we saved them.
# --------------------------------------------------------------------------
step_sysctl() {
	[ "$OPT_KEEP_SYSCTL" = "1" ] && { caly_step "keeping ${SYSCTL_FILE} (--keep-sysctl)"; return 0; }
	if [ -f "$SYSCTL_FILE" ]; then
		caly_info "Reverting sysctl"
		caly_try rm -f "$SYSCTL_FILE"
		if [ -r "${STATEDIR}/sysctl-backup.conf" ] && caly_have sysctl; then
			caly_step "restoring the previous values from ${STATEDIR}/sysctl-backup.conf"
			# Apply the saved originals, then reload the rest of the system
			# so nothing we changed lingers.
			while IFS= read -r caly_sc_line || [ -n "$caly_sc_line" ]; do
				case "$caly_sc_line" in
				\#*|'') continue ;;
				esac
				caly_sc_k=${caly_sc_line%%=*}
				caly_sc_v=${caly_sc_line#*=}
				caly_sc_k=$(printf '%s' "$caly_sc_k" | tr -d ' 	')
				caly_sc_v=$(printf '%s' "$caly_sc_v" | sed 's/^[ 	]*//')
				[ -n "$caly_sc_k" ] || continue
				caly_try sysctl -w "${caly_sc_k}=${caly_sc_v}"
			done < "${STATEDIR}/sysctl-backup.conf"
			unset caly_sc_line caly_sc_k caly_sc_v
		fi
		if caly_have sysctl; then
			caly_try sysctl --system
		fi
	fi
}

# --------------------------------------------------------------------------
# 8. Remove the fstab bpffs line we may have added.
# --------------------------------------------------------------------------
step_fstab() {
	[ -f /etc/fstab ] || return 0
	if grep -q 'added by the Caly Anti installer' /etc/fstab 2>/dev/null; then
		caly_info "Removing our /etc/fstab bpffs entry"
		if [ "${CALY_DRY_RUN:-0}" != "1" ]; then
			awk '
				/added by the Caly Anti installer/ { skip = 1; next }
				skip && /\/sys\/fs\/bpf/ && $3 == "bpf" { skip = 0; next }
				{ skip = 0; print }
			' /etc/fstab > /etc/fstab.calytmp 2>/dev/null && \
			mv -f /etc/fstab.calytmp /etc/fstab || \
			caly_warn "could not edit /etc/fstab; remove the bpffs line by hand"
		else
			caly_step "[dry-run] would strip the bpffs line from /etc/fstab"
		fi
	fi
	# We do not unmount bpffs: other BPF tooling may be using it.
}

# --------------------------------------------------------------------------
# 9. Remove installed files. Configuration and state survive unless --purge.
# --------------------------------------------------------------------------
step_remove_files() {
	caly_info "Removing installed files"

	for caly_rf_f in \
	    "${SBINDIR}/calyd" \
	    "${SBINDIR}/calyctl" \
	    "${SBINDIR}/calyanti-cli" \
	    "${SBINDIR}/calywatch" \
	    "${SBINDIR}/calyanti-panic" \
	    "${SBINDIR}/calyanti-uninstall"; do
		[ -e "$caly_rf_f" ] || [ -L "$caly_rf_f" ] && caly_try rm -f "$caly_rf_f"
	done

	# systemd / openrc unit files
	for caly_rf_f in \
	    /usr/lib/systemd/system/calyanti.service \
	    /usr/lib/systemd/system/calyanti-watch.service \
	    /lib/systemd/system/calyanti.service \
	    /lib/systemd/system/calyanti-watch.service \
	    /etc/systemd/system/calyanti.service \
	    /etc/systemd/system/calyanti-watch.service \
	    /etc/systemd/system/calyanti-nft.service \
	    /etc/systemd/system/calyanti-iptables.service \
	    /etc/init.d/calyanti \
	    /etc/init.d/calyanti-watch \
	    /etc/conf.d/calyanti \
	    /etc/conf.d/calyanti-watch; do
		[ -e "$caly_rf_f" ] && caly_try rm -f "$caly_rf_f"
	done

	if [ "$CALY_INIT" = "systemd" ]; then
		caly_try systemctl daemon-reload
		caly_try systemctl reset-failed
	fi

	# The library tree and docs.
	[ -d "$LIBDIR" ] && caly_try rm -rf "$LIBDIR"
	[ -d "$DOCDIR" ] && caly_try rm -rf "$DOCDIR"
	[ -d "$LOGDIR" ] && caly_try rm -rf "$LOGDIR"
	[ -d "$RUNDIR" ] && caly_try rm -rf "$RUNDIR"

	if [ "$OPT_PURGE" = "1" ]; then
		caly_step "purging configuration and state"
		[ -d "$CONFDIR" ] && caly_try rm -rf "$CONFDIR"
		[ -d "$STATEDIR" ] && caly_try rm -rf "$STATEDIR"
	else
		caly_step "keeping ${CONFDIR} and ${STATEDIR} (use --purge to remove)"
		# Keep sysctl backup out of the way only on purge; otherwise a
		# reinstall can still find it.
	fi
	unset caly_rf_f
}

# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------
caly_say ""
caly_say "${CALY_C_BOLD}Caly Anti ${CALY_VERSION} uninstaller${CALY_C_RESET}"
caly_say ""
if ! confirm "Remove Caly Anti and detach the dataplane from all interfaces?"; then
	caly_say "Aborted; nothing was changed."
	exit 0
fi

step_cancel_rollback
step_stop_services
step_daemon_detach
step_detach_dataplane
step_unpin
step_nftables
step_iptables
step_sysctl
step_fstab
step_remove_files

caly_say ""
caly_ok "Caly Anti removed. The dataplane is detached and the host is unfiltered."
if [ "$OPT_PURGE" != "1" ]; then
	caly_say "  Configuration kept at ${CONFDIR}. Re-run with --purge to remove it."
fi
caly_say ""
exit 0
