#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Caly Anti - scripts/install.sh
#
# One-command installer for the XDP/eBPF DDoS mitigation suite.
#
#   ./scripts/install.sh                    detect, build, install, monitor only
#   ./scripts/install.sh --enforce          same, but start dropping immediately
#   ./scripts/install.sh --dry-run          print every action, change nothing
#   ./scripts/install.sh --dataplane=nft    pin a rung of the ladder
#   ./scripts/install.sh --iface=eth0       pin the WAN interface
#   ./scripts/install.sh --uninstall        hand over to uninstall.sh
#
# THE TWO RULES THIS SCRIPT EXISTS TO ENFORCE
#
#   1. It never leaves the machine unreachable. The install lands in
#      monitor-only mode: every rule is evaluated and counted, nothing is
#      dropped. Dropping starts only after an explicit `--enforce` or
#      `calyctl mode normal`. When --enforce is combined with an SSH session,
#      a rollback timer is armed that tears the dataplane back down unless you
#      confirm you are still connected.
#
#   2. It never fails because the machine is unusual. No BTF, no clang, no
#      bpftool, an OpenVZ container, a kernel from 2018 - each of those moves
#      the install down the degradation ladder (XDP native -> XDP generic ->
#      tc/clsact -> nftables -> iptables+ipset), it does not stop it.
#
# POSIX sh. Runs under dash, busybox ash, bash and ksh without modification.

set -eu

CALY_VERSION="1.0.0"

# --------------------------------------------------------------------------
# Locate ourselves and the source tree.
# --------------------------------------------------------------------------
caly_self=$0
case "$caly_self" in
*/*) caly_self_dir=${caly_self%/*} ;;
*)   caly_self_dir=. ;;
esac
SCRIPT_DIR=$(cd "$caly_self_dir" 2>/dev/null && pwd) || SCRIPT_DIR=$PWD
SRC_ROOT=$(cd "${SCRIPT_DIR}/.." 2>/dev/null && pwd) || SRC_ROOT=$SCRIPT_DIR
unset caly_self caly_self_dir

if [ ! -r "${SCRIPT_DIR}/detect-env.sh" ]; then
	echo "install.sh: detect-env.sh not found next to $0" >&2
	exit 1
fi
# shellcheck source=scripts/detect-env.sh
. "${SCRIPT_DIR}/detect-env.sh"

# --------------------------------------------------------------------------
# Installation layout. Everything is DESTDIR-aware so distribution packaging
# can call this script with --destdir and get a staged tree.
# --------------------------------------------------------------------------
DESTDIR=""
PREFIX="/usr"
SYSCONFDIR="/etc"
SBINDIR=""
LIBDIR=""
BPFOBJDIR=""
LIBEXEC_SCRIPTS=""
CONFDIR=""
DOCDIR=""
STATEDIR="/var/lib/calyanti"
LOGDIR="/var/log/calyanti"
RUNDIR="/run/calyanti"
PINDIR="/sys/fs/bpf/calyanti"
SYSCTL_FILE="/etc/sysctl.d/98-calyanti.conf"
CONF_NAME="calyanti.conf"
ENV_NAME="calyanti.env"

caly_set_paths() {
	SBINDIR="${PREFIX}/sbin"
	LIBDIR="${PREFIX}/lib/calyanti"
	BPFOBJDIR="${LIBDIR}/bpf"
	LIBEXEC_SCRIPTS="${LIBDIR}/scripts"
	CONFDIR="${SYSCONFDIR}/calyanti"
	DOCDIR="${PREFIX}/share/doc/calyanti"
}
caly_set_paths

# Path with the DESTDIR prefix applied.
d() { printf '%s%s' "${DESTDIR}" "$1"; }

# --------------------------------------------------------------------------
# Options
# --------------------------------------------------------------------------
OPT_DEPS=1
OPT_BUILD=1
OPT_SYSCTL=1
OPT_START=1
OPT_ENABLE=1
OPT_ENFORCE=0
OPT_SELFTEST=1
OPT_WATCH=0
OPT_DEGRADE=1
OPT_ROLLBACK=1
OPT_ROLLBACK_SECS=180
OPT_FORCE=0
OPT_YES=0
OPT_DATAPLANE="auto"
OPT_IFACE=""
OPT_MAKE_JOBS=""
OPT_CONFIG_SRC=""

# Resolved during the run.
CALY_IFACES=""
CALY_DP=""
CALY_XDP_MODE="auto"
CALY_STEP_NAME="startup"
CALY_DAEMON_BIN=""
CALY_CLI_BIN=""
CALY_BPF_OBJS=""
CALY_FRESH_CONFIG=0
CALY_SSH_PEER=""
CALY_IS_SSH="no"
CALY_MGMT_PORTS="22"
CALY_SELFTEST_FAIL=0
CALY_SELFTEST_WARN=0
CALY_INSTALLED_UNITS=""

usage() {
	cat <<'EOF'
Caly Anti installer

Usage: install.sh [OPTIONS]

Dataplane and interfaces
  --dataplane=VALUE   auto (default) | xdp | xdp-native | xdp-generic |
                      tc | nft | nftables | iptables
                      Pinning a rung the machine cannot provide is an error,
                      unless --force is also given.
  --iface=NAME[,NAME] interface(s) to protect and mark as WAN zone.
                      Default: the interface carrying the default route.

Safety
  (default)           install in MONITOR-ONLY mode: evaluate and count, drop
                      nothing. Switch on with `calyctl mode normal` when the
                      counters look right.
  --enforce           start dropping immediately. Over SSH this also arms a
                      rollback timer (see --rollback-secs).
  --no-rollback       do not arm the rollback timer with --enforce.
  --rollback-secs=N   rollback window in seconds (default 180).
  -y, --yes           assume yes for confirmation prompts.

What to do
  --no-deps           do not install distribution packages.
  --no-build          do not compile; use artifacts already in the tree.
  --no-sysctl         do not write /etc/sysctl.d/98-calyanti.conf.
  --no-start          install and enable, but do not start the service.
  --no-enable         do not enable the service at boot.
  --no-selftest       skip the post-install self-test.
  --no-degrade        fail instead of falling to a lower rung of the ladder.
  --enable-watch      also enable the event log watcher service.
  --config=PATH       install this file as the configuration instead of the
                      shipped sample (only when no config exists yet).
  --jobs=N            parallel build jobs (default: number of CPUs).

Paths
  --prefix=PATH       default /usr
  --sysconfdir=PATH   default /etc
  --destdir=PATH      staged install root, for packaging. Implies --no-start,
                      --no-enable, --no-sysctl.

Other
  -n, --dry-run       print every action, change nothing.
  --force             proceed past non-fatal safety checks.
  --uninstall         run scripts/uninstall.sh instead.
  -q, --quiet         less output.
  --debug             trace detail.
  --no-color          disable colour.
  -V, --version       print the version.
  -h, --help          this text.

Re-running the installer is safe: it upgrades binaries in place and never
overwrites an existing /etc/calyanti/calyanti.conf.
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--dataplane=*)  OPT_DATAPLANE=${1#--dataplane=} ;;
	--dataplane)    OPT_DATAPLANE=${2:-auto}; shift ;;
	--iface=*)      OPT_IFACE=${1#--iface=} ;;
	--iface|--interface) OPT_IFACE=${2:-}; shift ;;
	--interface=*)  OPT_IFACE=${1#--interface=} ;;
	--enforce)      OPT_ENFORCE=1 ;;
	--monitor|--monitor-only) OPT_ENFORCE=0 ;;
	--no-rollback)  OPT_ROLLBACK=0 ;;
	--rollback-secs=*) OPT_ROLLBACK_SECS=${1#--rollback-secs=} ;;
	--no-deps)      OPT_DEPS=0 ;;
	--no-build)     OPT_BUILD=0 ;;
	--no-sysctl)    OPT_SYSCTL=0 ;;
	--no-start)     OPT_START=0 ;;
	--no-enable)    OPT_ENABLE=0 ;;
	--no-selftest)  OPT_SELFTEST=0 ;;
	--no-degrade)   OPT_DEGRADE=0 ;;
	--enable-watch) OPT_WATCH=1 ;;
	--config=*)     OPT_CONFIG_SRC=${1#--config=} ;;
	--jobs=*)       OPT_MAKE_JOBS=${1#--jobs=} ;;
	-j)             OPT_MAKE_JOBS=${2:-}; shift ;;
	--prefix=*)     PREFIX=${1#--prefix=}; caly_set_paths ;;
	--sysconfdir=*) SYSCONFDIR=${1#--sysconfdir=}; caly_set_paths ;;
	--destdir=*)    DESTDIR=${1#--destdir=}
	                OPT_START=0; OPT_ENABLE=0; OPT_SYSCTL=0; OPT_SELFTEST=0 ;;
	-n|--dry-run)   CALY_DRY_RUN=1 ;;
	--force)        OPT_FORCE=1 ;;
	-y|--yes)       OPT_YES=1 ;;
	--uninstall)
		shift
		if [ -x "${SCRIPT_DIR}/uninstall.sh" ]; then
			exec "${SCRIPT_DIR}/uninstall.sh" "$@"
		elif [ -r "${SCRIPT_DIR}/uninstall.sh" ]; then
			exec /bin/sh "${SCRIPT_DIR}/uninstall.sh" "$@"
		fi
		caly_die "uninstall.sh not found next to $0" ;;
	-q|--quiet)     CALY_QUIET=1 ;;
	--debug)        CALY_DEBUG=1 ;;
	--no-color)     CALY_COLOR="never"; caly_init_colors ;;
	-V|--version)   printf 'calyanti installer %s\n' "$CALY_VERSION"; exit 0 ;;
	-h|--help)      usage; exit 0 ;;
	*)              caly_err "unknown option '$1'"; usage >&2; exit 2 ;;
	esac
	shift
done

case "$OPT_ROLLBACK_SECS" in
''|*[!0-9]*) caly_die "--rollback-secs needs a number" ;;
esac

# --------------------------------------------------------------------------
# Failure reporting. With `set -e` an unexpected non-zero status aborts the
# run; say where, and say what state the machine is in.
# --------------------------------------------------------------------------
caly_on_exit() {
	caly_oe_rc=$?
	if [ "$caly_oe_rc" -ne 0 ] && [ "${CALY_FINISHED:-0}" != "1" ]; then
		printf '\n%serror:%s installation failed during: %s (status %s)\n' \
			"${CALY_C_RED}" "${CALY_C_RESET}" "$CALY_STEP_NAME" \
			"$caly_oe_rc" >&2
		printf '  Nothing has been started in enforcing mode, so traffic is\n' >&2
		printf '  unaffected. Re-run with --debug for detail, or with\n' >&2
		printf '  --dataplane=nft to use the nftables fallback.\n' >&2
		printf '  Remove a partial install with: %s/uninstall.sh\n' \
			"$SCRIPT_DIR" >&2
	fi
	return 0
}
trap caly_on_exit EXIT

step() {
	CALY_STEP_NAME=$1
	caly_info "$1"
}

confirm() {
	# $1 = question. Returns 0 for yes.
	[ "$OPT_YES" = "1" ] && return 0
	[ "${CALY_DRY_RUN:-0}" = "1" ] && return 0
	if [ ! -t 0 ]; then
		caly_warn "not interactive and --yes not given; assuming NO"
		return 1
	fi
	printf '%s [y/N] ' "$1"
	read -r caly_cf_a || caly_cf_a=""
	case "$caly_cf_a" in
	y|Y|yes|YES|Yes) unset caly_cf_a; return 0 ;;
	esac
	unset caly_cf_a
	return 1
}

# Write stdin to a file, honouring --dry-run, atomically, with a mode.
write_file() {
	caly_wf_path=$1
	caly_wf_mode=${2:-0644}
	if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
		printf '%s  [dry-run]%s write %s (mode %s)\n' "${CALY_C_DIM}" \
			"${CALY_C_RESET}" "$caly_wf_path" "$caly_wf_mode"
		cat >/dev/null
		unset caly_wf_path caly_wf_mode
		return 0
	fi
	caly_wf_dir=${caly_wf_path%/*}
	[ -d "$caly_wf_dir" ] || mkdir -p "$caly_wf_dir"
	cat > "${caly_wf_path}.calytmp"
	mv -f "${caly_wf_path}.calytmp" "$caly_wf_path"
	chmod "$caly_wf_mode" "$caly_wf_path"
	unset caly_wf_path caly_wf_mode caly_wf_dir
	return 0
}

install_file() {
	# $1 src, $2 dst, $3 mode
	caly_if_src=$1
	caly_if_dst=$2
	caly_if_mode=${3:-0644}
	if [ ! -r "$caly_if_src" ]; then
		caly_warn "missing file, not installed: $caly_if_src"
		unset caly_if_src caly_if_dst caly_if_mode
		return 1
	fi
	caly_run mkdir -p "${caly_if_dst%/*}"
	if caly_have install; then
		caly_run install -m "$caly_if_mode" "$caly_if_src" "$caly_if_dst"
	else
		caly_run cp -f "$caly_if_src" "$caly_if_dst"
		caly_run chmod "$caly_if_mode" "$caly_if_dst"
	fi
	unset caly_if_src caly_if_dst caly_if_mode
	return 0
}

# --------------------------------------------------------------------------
# Configuration file editing.
#
# Replaces the first uncommented `key = ...` line. Commented example lines are
# never touched, so the documentation in the sample config survives.
# --------------------------------------------------------------------------
conf_set() {
	caly_cs_file=$1
	caly_cs_key=$2
	caly_cs_val=$3

	if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
		printf '%s  [dry-run]%s set %s = %s in %s\n' "${CALY_C_DIM}" \
			"${CALY_C_RESET}" "$caly_cs_key" "$caly_cs_val" "$caly_cs_file"
		unset caly_cs_file caly_cs_key caly_cs_val
		return 0
	fi
	[ -f "$caly_cs_file" ] || return 1

	awk -v key="$caly_cs_key" -v val="$caly_cs_val" '
		BEGIN { done = 0 }
		{
			if (!done && $0 ~ "^[ \t]*" key "[ \t]*=") {
				print key " = " val
				done = 1
				next
			}
			print
		}
		END { if (!done) print key " = " val }
	' "$caly_cs_file" > "${caly_cs_file}.calytmp"
	mv -f "${caly_cs_file}.calytmp" "$caly_cs_file"
	unset caly_cs_file caly_cs_key caly_cs_val
	return 0
}

# Append a list-valued directive inside a named [section]. List directives
# (allow, block, local, interface, tcp_port, ...) may appear many times, so
# they are inserted rather than replaced.
conf_add_in_section() {
	caly_ca_file=$1
	caly_ca_sect=$2
	caly_ca_line=$3

	if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
		printf '%s  [dry-run]%s add "%s" to [%s] in %s\n' "${CALY_C_DIM}" \
			"${CALY_C_RESET}" "$caly_ca_line" "$caly_ca_sect" "$caly_ca_file"
		unset caly_ca_file caly_ca_sect caly_ca_line
		return 0
	fi
	[ -f "$caly_ca_file" ] || return 1

	# Idempotency: never add the same directive twice.
	if grep -q "^[ 	]*${caly_ca_line}[ 	]*\$" "$caly_ca_file" 2>/dev/null; then
		unset caly_ca_file caly_ca_sect caly_ca_line
		return 0
	fi

	awk -v sect="[$caly_ca_sect]" -v line="$caly_ca_line" '
		BEGIN { done = 0 }
		{
			print
			if (!done && index($0, sect) == 1) {
				print line
				done = 1
			}
		}
		END { if (!done) print line }
	' "$caly_ca_file" > "${caly_ca_file}.calytmp"
	mv -f "${caly_ca_file}.calytmp" "$caly_ca_file"
	unset caly_ca_file caly_ca_sect caly_ca_line
	return 0
}

# --------------------------------------------------------------------------
# Detect whether we are being run from within an interactive SSH session and,
# if so, from which peer. This must survive `sudo`, whose default env_reset
# strips SSH_CONNECTION/SSH_CLIENT from the environment - so when those are
# gone we walk the process ancestry (sshd is still our forebear through sudo)
# and finally consult utmp via `who`. Sets:
#   CALY_IS_SSH   - "yes" if this looks like a remote login, else "no"
#   CALY_SSH_PEER - the peer IP if we could determine it, else ""
# The shell restores positional parameters on return, so the `set --` calls
# below do not disturb the caller's "$@".
# --------------------------------------------------------------------------
caly_detect_ssh() {
	CALY_IS_SSH="no"
	CALY_SSH_PEER=""

	# 1. Environment: present when run as root directly, or with `sudo -E`.
	if [ -n "${SSH_CONNECTION:-}" ]; then
		# shellcheck disable=SC2086
		set -- ${SSH_CONNECTION}
		CALY_IS_SSH="yes"; CALY_SSH_PEER=${1:-}
		return 0
	fi
	if [ -n "${SSH_CLIENT:-}" ]; then
		# shellcheck disable=SC2086
		set -- ${SSH_CLIENT}
		CALY_IS_SSH="yes"; CALY_SSH_PEER=${1:-}
		return 0
	fi

	# 2. Process ancestry: sudo resets the environment but not the parentage,
	#    so sshd remains reachable by walking ppid upward from us. Needs only
	#    /proc, so it works on musl/busybox where utmp may be absent.
	caly_ds_pid=$$
	caly_ds_n=0
	while [ "${caly_ds_pid:-0}" -gt 1 ] && [ "$caly_ds_n" -lt 24 ]; do
		caly_ds_n=$((caly_ds_n + 1))
		[ -r "/proc/${caly_ds_pid}/comm" ] || break
		caly_ds_comm=$(cat "/proc/${caly_ds_pid}/comm" 2>/dev/null || echo "")
		case "$caly_ds_comm" in
		sshd|sshd-session|dropbear) CALY_IS_SSH="yes"; break ;;
		esac
		# ppid follows comm in /proc/PID/stat, but comm may itself contain a
		# space or ')', so parse the fields after the final ')'.
		caly_ds_stat=$(cat "/proc/${caly_ds_pid}/stat" 2>/dev/null || echo "")
		[ -n "$caly_ds_stat" ] || break
		caly_ds_rest=${caly_ds_stat##*)}
		# shellcheck disable=SC2086
		set -- $caly_ds_rest
		caly_ds_pid=${2:-0}
		case "$caly_ds_pid" in
		''|*[!0-9]*) caly_ds_pid=0 ;;
		esac
	done

	# 3. utmp via `who`: a remote login shows its origin host in parentheses.
	#    Recovers the peer IP under sudo and, where the /proc walk found
	#    nothing, still flags the session remote. Silent (and harmless) where
	#    utmp is not maintained, which is why the ancestry check runs first.
	if caly_have who; then
		caly_ds_who=$(who am i 2>/dev/null || true)
		[ -n "$caly_ds_who" ] || caly_ds_who=$(who -m 2>/dev/null || true)
		caly_ds_host=""
		case "$caly_ds_who" in
		*\(*\)*) caly_ds_host=${caly_ds_who##*\(}; caly_ds_host=${caly_ds_host%%\)*} ;;
		esac
		case "$caly_ds_host" in
		''|:*|localhost|localhost.*) ;;
		*)
			CALY_IS_SSH="yes"
			# Record as the peer only when unambiguously an IP literal.
			case "$caly_ds_host" in
			*[!0-9A-Fa-f:.]*) ;;
			?*) [ -z "$CALY_SSH_PEER" ] && CALY_SSH_PEER=$caly_ds_host ;;
			esac ;;
		esac
	fi

	unset caly_ds_pid caly_ds_n caly_ds_comm caly_ds_stat caly_ds_rest caly_ds_who caly_ds_host
	return 0
}

# --------------------------------------------------------------------------
# Phase 1: preflight
# --------------------------------------------------------------------------
phase_preflight() {
	step "Preflight"

	if [ "$(uname -s 2>/dev/null || echo unknown)" != "Linux" ]; then
		caly_die "Caly Anti is Linux only (this is $(uname -s 2>/dev/null))"
	fi

	caly_detect_all

	if [ "$CALY_IS_ROOT" != "yes" ] && [ "${CALY_DRY_RUN:-0}" != "1" ] && \
	   [ -z "$DESTDIR" ]; then
		caly_die "must run as root (try: sudo $0 $*)"
	fi

	caly_say ""
	caly_say "  ${CALY_C_BOLD}Caly Anti ${CALY_VERSION}${CALY_C_RESET}"
	caly_say "  distribution   ${CALY_OS_PRETTY} (${CALY_OS_FAMILY}/${CALY_PKGMGR})"
	caly_say "  kernel         ${CALY_KERNEL_RELEASE} (${CALY_ARCH})"
	caly_say "  init           ${CALY_INIT} ${CALY_INIT_VERSION}"
	caly_say "  libc           ${CALY_LIBC} ${CALY_LIBC_VERSION}"
	caly_say "  virtualisation ${CALY_VIRT_TYPE}"
	caly_say "  BTF            ${CALY_HAVE_BTF}"
	caly_say "  best dataplane ${CALY_DATAPLANE_BEST}"
	caly_say ""

	# Record who is installing over SSH so we can allowlist them and, if
	# --enforce is used, verify that the session survived. Robust against sudo
	# stripping SSH_CONNECTION from the environment (see caly_detect_ssh).
	caly_detect_ssh
	if [ "$CALY_IS_SSH" = "yes" ]; then
		if [ -n "$CALY_SSH_PEER" ]; then
			caly_say "  This is an SSH session from ${CALY_C_BOLD}${CALY_SSH_PEER}${CALY_C_RESET};"
			caly_say "  it will be added to the allowlist and verified after start."
		else
			caly_say "  This looks like a remote (SSH) session; a rollback timer"
			caly_say "  will be armed if you enforce."
		fi
		caly_say ""
	fi

	if [ "$CALY_INIT" = "unknown" ]; then
		caly_warn "unrecognised init system; the service will be installed \
but not enabled. Start it by hand with: ${SBINDIR}/calyd --config ${CONFDIR}/${CONF_NAME}"
	fi
}

# --------------------------------------------------------------------------
# Phase 2: interface selection
# --------------------------------------------------------------------------
phase_pick_ifaces() {
	step "Selecting interfaces"

	if [ -n "$OPT_IFACE" ]; then
		CALY_IFACES=$(printf '%s' "$OPT_IFACE" | tr ',' ' ')
		for caly_pi_i in $CALY_IFACES; do
			if [ ! -e "/sys/class/net/${caly_pi_i}" ]; then
				if [ "$OPT_FORCE" = "1" ]; then
					caly_warn "interface ${caly_pi_i} does not exist (--force)"
				else
					caly_die "interface ${caly_pi_i} does not exist. \
Available: ${CALY_NICS:-none}"
				fi
			fi
		done
	else
		CALY_IFACES=$CALY_DEFAULT_IFACE
		if [ -z "$CALY_IFACES" ]; then
			caly_warn "could not determine the default-route interface. \
Pass --iface=NAME. Continuing so the rest of the install completes; the \
daemon will not attach anywhere until an interface is configured."
		fi
	fi

	for caly_pi_i in $CALY_IFACES; do
		caly_pi_d=$(caly_driver_of "$caly_pi_i")
		caly_pi_h=$(caly_xdp_hint_for_driver "$caly_pi_d")
		caly_step "${caly_pi_i}: driver ${caly_pi_d}, xdp hint ${caly_pi_h}"
	done
	unset caly_pi_i caly_pi_d caly_pi_h
}

# --------------------------------------------------------------------------
# Phase 3: choose the rung of the degradation ladder
# --------------------------------------------------------------------------
dp_is_bpf() {
	case "$1" in
	xdp-native|xdp-generic|tc) return 0 ;;
	esac
	return 1
}

phase_choose_dataplane() {
	step "Choosing the dataplane"

	case "$OPT_DATAPLANE" in
	auto)
		CALY_DP=$CALY_DATAPLANE_BEST
		caly_step "auto: ${CALY_DP} (${CALY_DATAPLANE_REASON:-supported})" ;;
	xdp)
		if [ "$CALY_XDP_MODE_BEST" = "native" ]; then
			CALY_DP="xdp-native"
		else
			CALY_DP="xdp-generic"
		fi ;;
	xdp-native|native) CALY_DP="xdp-native" ;;
	xdp-generic|generic|skb) CALY_DP="xdp-generic" ;;
	tc|tc-bpf|clsact) CALY_DP="tc" ;;
	nft|nftables) CALY_DP="nftables" ;;
	iptables|ipset|legacy) CALY_DP="iptables" ;;
	*) caly_die "unknown --dataplane value '${OPT_DATAPLANE}'" ;;
	esac

	if [ "$CALY_DP" = "none" ]; then
		caly_die "no usable dataplane on this system: ${CALY_DATAPLANE_REASON}.
Install nftables (or iptables and ipset) and re-run."
	fi

	# Validate an explicitly pinned rung. Silently running something weaker
	# than the operator asked for is worse than refusing.
	if [ "$OPT_DATAPLANE" != "auto" ]; then
		caly_cd_bad=""
		if dp_is_bpf "$CALY_DP"; then
			[ "$CALY_HAVE_BTF" = "yes" ] || \
				caly_cd_bad="no BTF at /sys/kernel/btf/vmlinux"
			[ "$CALY_HAVE_BPF_SYSCALL" != "no" ] || \
				caly_cd_bad="kernel has no CONFIG_BPF_SYSCALL"
		fi
		case "$CALY_DP" in
		xdp-native|xdp-generic)
			[ "$CALY_CONTAINER" = "no" ] || \
				caly_cd_bad="XDP inside a ${CALY_VIRT_TYPE} container" ;;
		nftables)
			[ "$CALY_HAVE_NFT" = "yes" ] || caly_cd_bad="nft is not installed" ;;
		iptables)
			[ "$CALY_HAVE_IPTABLES" = "yes" ] || \
				caly_cd_bad="iptables is not installed" ;;
		esac
		if [ -n "$caly_cd_bad" ]; then
			if [ "$OPT_FORCE" = "1" ]; then
				caly_warn "pinned dataplane ${CALY_DP} may not work: ${caly_cd_bad} (--force)"
			else
				caly_die "cannot use --dataplane=${OPT_DATAPLANE}: ${caly_cd_bad}.
Re-run with --dataplane=auto to pick the best available rung, or --force to try anyway."
			fi
		fi
		unset caly_cd_bad
	fi

	case "$CALY_DP" in
	xdp-native)  CALY_XDP_MODE="native" ;;
	xdp-generic) CALY_XDP_MODE="generic" ;;
	*)           CALY_XDP_MODE="auto" ;;
	esac

	# XDP_TX in generic/skb mode is slow enough that the SYN proxy is a net
	# loss; the architecture disables it there by default.
	if [ "$CALY_DP" = "xdp-generic" ]; then
		caly_step "generic/skb XDP: the SYN proxy stays off by default (XDP_TX is slow here)"
	fi

	caly_ok "dataplane: ${CALY_DP}"
}

# --------------------------------------------------------------------------
# Phase 4: dependencies
# --------------------------------------------------------------------------
phase_deps() {
	[ "$OPT_DEPS" = "1" ] || { caly_step "skipping dependency install (--no-deps)"; return 0; }
	dp_is_bpf "$CALY_DP" || [ "$OPT_BUILD" = "1" ] || return 0

	step "Installing dependencies"
	if [ ! -r "${SCRIPT_DIR}/deps.sh" ]; then
		caly_warn "deps.sh not found; skipping dependency install"
		return 0
	fi
	# shellcheck source=scripts/deps.sh
	. "${SCRIPT_DIR}/deps.sh"

	if dp_is_bpf "$CALY_DP"; then
		caly_install_deps all || \
			caly_warn "some dependencies could not be installed; \
the build may fail and fall back to a lower rung"
	else
		caly_install_deps runtime || \
			caly_warn "some runtime dependencies could not be installed"
	fi

	# Toolchain facts changed; re-detect so later phases see the truth.
	caly_detect_toolchain
	caly_detect_libbpf
	caly_detect_bpftool
	return 0
}

# --------------------------------------------------------------------------
# Phase 5: build
# --------------------------------------------------------------------------
degrade_to_legacy() {
	# $1 = reason
	if [ "$OPT_DEGRADE" != "1" ]; then
		caly_die "$1 (and --no-degrade was given)"
	fi
	if [ "$OPT_DATAPLANE" != "auto" ] && [ "$OPT_FORCE" != "1" ]; then
		caly_die "$1
You pinned --dataplane=${OPT_DATAPLANE}. Re-run with --dataplane=auto to fall
back automatically, or --force to ignore this check."
	fi
	if [ "$CALY_HAVE_NFT" = "yes" ]; then
		CALY_DP="nftables"
	elif [ "$CALY_HAVE_IPTABLES" = "yes" ]; then
		CALY_DP="iptables"
	else
		caly_die "$1
No nftables and no iptables either, so there is no fallback dataplane.
Install nftables and re-run."
	fi
	caly_warn "$1"
	caly_warn "falling back to the ${CALY_DP} dataplane (ladder rung $( \
		[ "$CALY_DP" = nftables ] && echo 4 || echo 5 ))"
	CALY_XDP_MODE="auto"
	return 0
}

phase_vmlinux() {
	dp_is_bpf "$CALY_DP" || return 0
	[ "$OPT_BUILD" = "1" ] || return 0
	step "Generating vmlinux.h"

	if [ ! -r "${SCRIPT_DIR}/gen-vmlinux.sh" ]; then
		caly_warn "gen-vmlinux.sh missing"
		degrade_to_legacy "cannot generate vmlinux.h"
		return 0
	fi

	caly_pv_rc=0
	if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
		caly_run /bin/sh "${SCRIPT_DIR}/gen-vmlinux.sh" \
			--output "${SRC_ROOT}/src/bpf/vmlinux.h"
	else
		/bin/sh "${SCRIPT_DIR}/gen-vmlinux.sh" \
			--output "${SRC_ROOT}/src/bpf/vmlinux.h" \
			${CALY_BPFTOOL:+--bpftool "$CALY_BPFTOOL"} || caly_pv_rc=$?
	fi

	if [ "$caly_pv_rc" -eq 2 ]; then
		degrade_to_legacy "no BTF on this kernel, so CO-RE and the eBPF dataplane are unavailable"
	elif [ "$caly_pv_rc" -ne 0 ]; then
		degrade_to_legacy "vmlinux.h generation failed (status ${caly_pv_rc})"
	else
		caly_ok "vmlinux.h ready"
	fi
	unset caly_pv_rc
	return 0
}

find_artifact() {
	# Print the first existing path from the candidate list.
	for caly_fa_c in "$@"; do
		if [ -f "$caly_fa_c" ]; then
			printf '%s' "$caly_fa_c"
			unset caly_fa_c
			return 0
		fi
	done
	unset caly_fa_c
	return 1
}

discover_artifacts() {
	CALY_DAEMON_BIN=$(find_artifact \
		"${SRC_ROOT}/build/calyd" \
		"${SRC_ROOT}/build/bin/calyd" \
		"${SRC_ROOT}/bin/calyd" \
		"${SRC_ROOT}/src/user/calyd" \
		"${SRC_ROOT}/calyd" \
		"${SRC_ROOT}/build/calyantid" \
		"${SRC_ROOT}/build/calyanti" || true)

	CALY_CLI_BIN=$(find_artifact \
		"${SRC_ROOT}/build/calyctl" \
		"${SRC_ROOT}/build/bin/calyctl" \
		"${SRC_ROOT}/bin/calyctl" \
		"${SRC_ROOT}/src/user/calyctl" \
		"${SRC_ROOT}/calyctl" \
		"${SRC_ROOT}/build/calyanti-cli" \
		"${SRC_ROOT}/src/user/calyanti-cli" || true)

	CALY_BPF_OBJS=""
	for caly_da_g in "${SRC_ROOT}/build"/*.bpf.o "${SRC_ROOT}/build/bpf"/*.bpf.o \
	    "${SRC_ROOT}/src/bpf"/*.bpf.o; do
		[ -f "$caly_da_g" ] || continue
		CALY_BPF_OBJS="${CALY_BPF_OBJS}${CALY_BPF_OBJS:+ }${caly_da_g}"
	done
	unset caly_da_g
	return 0
}

phase_build() {
	if [ "$OPT_BUILD" != "1" ]; then
		caly_step "skipping build (--no-build)"
		discover_artifacts
		return 0
	fi

	step "Building"

	if [ -z "$CALY_MAKE" ]; then
		caly_warn "make is not installed"
		if dp_is_bpf "$CALY_DP"; then
			degrade_to_legacy "cannot build without make"
		fi
		return 0
	fi
	if [ ! -f "${SRC_ROOT}/Makefile" ] && [ ! -f "${SRC_ROOT}/GNUmakefile" ]; then
		caly_warn "no Makefile in ${SRC_ROOT}"
		discover_artifacts
		if [ -z "$CALY_DAEMON_BIN" ] && dp_is_bpf "$CALY_DP"; then
			degrade_to_legacy "nothing to build and no prebuilt daemon found"
		fi
		return 0
	fi

	caly_pb_jobs=$OPT_MAKE_JOBS
	[ -n "$caly_pb_jobs" ] || caly_pb_jobs=$CALY_NPROC

	caly_pb_rc=0
	if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
		caly_run "$CALY_MAKE" -C "$SRC_ROOT" -j"$caly_pb_jobs"
	else
		caly_step "${CALY_MAKE} -C ${SRC_ROOT} -j${caly_pb_jobs}"
		# CLANG/BPFTOOL are passed as make variables. A Makefile that does
		# not use them ignores them; one that does gets the versioned
		# binaries we found rather than whatever is first in PATH.
		"$CALY_MAKE" -C "$SRC_ROOT" -j"$caly_pb_jobs" \
			${CALY_CLANG:+CLANG="$CALY_CLANG"} \
			${CALY_BPFTOOL:+BPFTOOL="$CALY_BPFTOOL"} \
			${CALY_LLVM_STRIP:+LLVM_STRIP="$CALY_LLVM_STRIP"} \
			|| caly_pb_rc=$?
	fi

	if [ "$caly_pb_rc" -ne 0 ]; then
		caly_warn "build failed (status ${caly_pb_rc})"
		if dp_is_bpf "$CALY_DP"; then
			degrade_to_legacy "the eBPF dataplane could not be built"
		fi
	fi

	discover_artifacts

	if [ -n "$CALY_DAEMON_BIN" ]; then
		caly_ok "daemon:  ${CALY_DAEMON_BIN}"
	else
		caly_warn "no daemon binary found after the build"
	fi
	if [ -n "$CALY_CLI_BIN" ]; then
		caly_ok "cli:     ${CALY_CLI_BIN}"
	fi
	if [ -n "$CALY_BPF_OBJS" ]; then
		caly_ok "bpf obj: ${CALY_BPF_OBJS}"
	elif dp_is_bpf "$CALY_DP"; then
		caly_warn "no *.bpf.o produced by the build"
		degrade_to_legacy "the BPF object is missing"
	fi

	unset caly_pb_jobs caly_pb_rc
	return 0
}

# --------------------------------------------------------------------------
# Phase 6: install files
# --------------------------------------------------------------------------
phase_install_files() {
	step "Installing files"

	caly_run mkdir -p "$(d "$SBINDIR")" "$(d "$LIBDIR")" "$(d "$BPFOBJDIR")" \
		"$(d "$LIBEXEC_SCRIPTS")" "$(d "$CONFDIR")" "$(d "$DOCDIR")" \
		"$(d "$STATEDIR")" "$(d "$LOGDIR")"
	caly_run chmod 0750 "$(d "$STATEDIR")" "$(d "$LOGDIR")" "$(d "$CONFDIR")"

	if [ -n "$CALY_DAEMON_BIN" ]; then
		install_file "$CALY_DAEMON_BIN" "$(d "${SBINDIR}/calyd")" 0755 || true
	else
		caly_warn "no daemon binary to install"
	fi

	if [ -n "$CALY_CLI_BIN" ]; then
		install_file "$CALY_CLI_BIN" "$(d "${SBINDIR}/calyctl")" 0755 || true
		# calyanti.conf documents the CLI as `calyanti-cli`; ship both
		# names so either spelling works and neither doc is wrong.
		caly_run ln -sf calyctl "$(d "${SBINDIR}/calyanti-cli")"
	else
		caly_warn "no CLI binary to install"
	fi

	# The layer-7 log watcher (calywatch). It is a stdlib-only Python 3 script
	# with no build step, installed alongside the CLI so calyanti-watch.service
	# works whenever it is enabled. It tails logs and feeds bans to the daemon
	# through the control socket.
	caly_watch_src=""
	for caly_ws in "${SRC_ROOT}/watcher/calywatch.py" \
	    "${SRC_ROOT}/build/calywatch" "${SRC_ROOT}/calywatch"; do
		[ -r "$caly_ws" ] || continue
		caly_watch_src="$caly_ws"
		break
	done
	if [ -n "$caly_watch_src" ]; then
		install_file "$caly_watch_src" "$(d "${SBINDIR}/calywatch")" 0755 || true
		# Rule sets go where calywatch searches by default: /etc/calyanti/rules.
		caly_run mkdir -p "$(d "${CONFDIR}/rules")"
		for caly_wr in "${SRC_ROOT}/watcher/rules"/*.rules; do
			[ -r "$caly_wr" ] || continue
			install_file "$caly_wr" \
				"$(d "${CONFDIR}/rules/${caly_wr##*/}")" 0644 || true
		done
		unset caly_wr
		# Sample watcher config: install if absent, else drop it in the docs
		# dir so an upgrade never clobbers an operator's edits.
		if [ -r "${SRC_ROOT}/config/calywatch.conf" ]; then
			if [ ! -f "$(d "${CONFDIR}/calywatch.conf")" ]; then
				install_file "${SRC_ROOT}/config/calywatch.conf" \
					"$(d "${CONFDIR}/calywatch.conf")" 0640 || true
			else
				install_file "${SRC_ROOT}/config/calywatch.conf" \
					"$(d "${DOCDIR}/calywatch.conf")" 0644 || true
			fi
		fi
	else
		caly_step "no calywatch.py in the tree; the log watcher will be unavailable"
	fi
	unset caly_watch_src caly_ws

	for caly_pf_o in $CALY_BPF_OBJS; do
		install_file "$caly_pf_o" "$(d "${BPFOBJDIR}/${caly_pf_o##*/}")" 0644 || true
	done
	unset caly_pf_o

	# The helper scripts go with the installation so uninstall.sh and
	# gen-vmlinux.sh work after the source tree is gone.
	for caly_pf_s in detect-env.sh deps.sh gen-vmlinux.sh uninstall.sh \
	    install.sh panic.sh selftest.sh; do
		[ -r "${SCRIPT_DIR}/${caly_pf_s}" ] || continue
		install_file "${SCRIPT_DIR}/${caly_pf_s}" \
			"$(d "${LIBEXEC_SCRIPTS}/${caly_pf_s}")" 0755 || true
	done
	unset caly_pf_s
	# The tuning helper is installed so panic.sh --revert and re-runs can find
	# it at a stable path.
	[ -r "${SRC_ROOT}/tuning/apply-sysctl.sh" ] && \
		install_file "${SRC_ROOT}/tuning/apply-sysctl.sh" \
			"$(d "${LIBEXEC_SCRIPTS}/apply-sysctl.sh")" 0755 || true
	caly_run ln -sf "${LIBEXEC_SCRIPTS}/uninstall.sh" \
		"$(d "${SBINDIR}/calyanti-uninstall")"
	# Emergency disable, reachable as a plain command from any console.
	[ -r "${SCRIPT_DIR}/panic.sh" ] && \
		caly_run ln -sf "${LIBEXEC_SCRIPTS}/panic.sh" \
			"$(d "${SBINDIR}/calyanti-panic")"

	[ -r "${SRC_ROOT}/docs/ARCHITECTURE.md" ] && \
		install_file "${SRC_ROOT}/docs/ARCHITECTURE.md" \
			"$(d "${DOCDIR}/ARCHITECTURE.md")" 0644
	[ -r "${SRC_ROOT}/config/calyanti.conf" ] && \
		install_file "${SRC_ROOT}/config/calyanti.conf" \
			"$(d "${DOCDIR}/calyanti.conf")" 0644
	[ -r "${SRC_ROOT}/README.md" ] && \
		install_file "${SRC_ROOT}/README.md" "$(d "${DOCDIR}/README.md")" 0644

	# Environment file: the supported way to pass extra flags to the daemon
	# without editing the unit or the init script.
	if [ ! -f "$(d "${CONFDIR}/${ENV_NAME}")" ]; then
		write_file "$(d "${CONFDIR}/${ENV_NAME}")" 0640 <<'EOF'
# /etc/calyanti/calyanti.env - extra options for the Caly Anti services.
#
# Read by calyanti.service, calyanti-watch.service and the OpenRC init
# scripts. Edit here rather than editing the unit files: an upgrade replaces
# the units but never this file.

# Extra flags for the daemon, e.g. --log-level=debug
CALYD_OPTS=""

# Extra flags for the event watcher.
CALYWATCH_OPTS=""
EOF
	fi

	caly_ok "files installed under ${SBINDIR}, ${LIBDIR} and ${CONFDIR}"
	return 0
}

# --------------------------------------------------------------------------
# Phase 7: configuration
# --------------------------------------------------------------------------
detect_ssh_ports() {
	# Everything sshd is configured to listen on, so a moved SSH port ends
	# up in the management allowlist automatically.
	caly_ds_ports="22"
	for caly_ds_f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
		[ -r "$caly_ds_f" ] || continue
		caly_ds_p=$(sed -n 's/^[ \t]*[Pp]ort[ \t][ \t]*\([0-9][0-9]*\).*/\1/p' \
			"$caly_ds_f" 2>/dev/null || true)
		for caly_ds_one in $caly_ds_p; do
			case " $caly_ds_ports " in
			*" $caly_ds_one "*) ;;
			*) caly_ds_ports="${caly_ds_ports} ${caly_ds_one}" ;;
			esac
		done
	done
	printf '%s' "$caly_ds_ports"
	unset caly_ds_ports caly_ds_f caly_ds_p caly_ds_one
}

phase_config() {
	step "Configuration"

	caly_pc_dst="$(d "${CONFDIR}/${CONF_NAME}")"
	caly_pc_src=$OPT_CONFIG_SRC
	[ -n "$caly_pc_src" ] || caly_pc_src="${SRC_ROOT}/config/calyanti.conf"

	if [ -f "$caly_pc_dst" ]; then
		CALY_FRESH_CONFIG=0
		caly_step "keeping the existing ${CONFDIR}/${CONF_NAME}"
		if [ -r "$caly_pc_src" ] && [ "${CALY_DRY_RUN:-0}" != "1" ]; then
			if ! cmp -s "$caly_pc_src" "$caly_pc_dst"; then
				install_file "$caly_pc_src" "${caly_pc_dst}.new" 0640 || true
				caly_step "shipped sample written to ${CONFDIR}/${CONF_NAME}.new for comparison"
			fi
		fi
	else
		if [ ! -r "$caly_pc_src" ]; then
			caly_die "no configuration to install: ${caly_pc_src} is missing"
		fi
		CALY_FRESH_CONFIG=1
		install_file "$caly_pc_src" "$caly_pc_dst" 0640
		caly_ok "installed ${CONFDIR}/${CONF_NAME}"
	fi

	# ---- safety edits -------------------------------------------------
	# Management ports first: this is the lockout-prevention invariant and
	# it is applied on every run, fresh config or not.
	CALY_MGMT_PORTS=$(detect_ssh_ports)
	caly_pc_mgmt=$(printf '%s' "$CALY_MGMT_PORTS" | tr ' ' ',' | sed 's/,/, /g')
	conf_set "$caly_pc_dst" "mgmt_tcp_ports" "$caly_pc_mgmt" || true
	caly_step "management TCP ports: ${caly_pc_mgmt} (22 is always forced by the loader)"

	if [ "$CALY_FRESH_CONFIG" = "1" ]; then
		# The interface the operator is protecting, in the WAN zone.
		for caly_pc_i in $CALY_IFACES; do
			conf_add_in_section "$caly_pc_dst" "interfaces" \
				"interface = ${caly_pc_i} zone=wan" || true
			caly_step "interface ${caly_pc_i} marked zone=wan"
		done
		# drop-private is deliberately NOT set: plenty of public hosts sit
		# behind a NAT or a cloud load balancer that legitimately sources
		# RFC1918 traffic. Enable it by hand once you have checked.

		if [ -n "$CALY_SSH_PEER" ]; then
			case "$CALY_SSH_PEER" in
			*:*) caly_pc_cidr="${CALY_SSH_PEER}/128" ;;
			*)   caly_pc_cidr="${CALY_SSH_PEER}/32" ;;
			esac
			conf_add_in_section "$caly_pc_dst" "allowlist" \
				"allow = ${caly_pc_cidr}" || true
			caly_ok "allowlisted your SSH client ${caly_pc_cidr}"
		fi
	fi

	# Dataplane and XDP mode always reflect what this run chose.
	case "$CALY_DP" in
	xdp-native)  conf_set "$caly_pc_dst" "dataplane" "xdp-native" || true ;;
	xdp-generic) conf_set "$caly_pc_dst" "dataplane" "xdp-generic" || true ;;
	tc)          conf_set "$caly_pc_dst" "dataplane" "tc-bpf" || true ;;
	nftables)    conf_set "$caly_pc_dst" "dataplane" "nftables" || true ;;
	iptables)    conf_set "$caly_pc_dst" "dataplane" "iptables" || true ;;
	esac
	conf_set "$caly_pc_dst" "xdp_mode" "$CALY_XDP_MODE" || true

	# ---- monitor-only vs enforcing ------------------------------------
	if [ "$OPT_ENFORCE" = "1" ]; then
		conf_set "$caly_pc_dst" "monitor_only" "no" || true
		conf_set "$caly_pc_dst" "mode" "normal" || true
		caly_warn "ENFORCING mode requested: packets matching a drop rule will be dropped"
	else
		conf_set "$caly_pc_dst" "monitor_only" "yes" || true
		caly_ok "monitor-only mode: every rule is evaluated and counted, nothing is dropped"
	fi

	# On a small machine the shipped map sizing (~220 MB locked) is more
	# than the box has. Shrink it rather than letting map creation fail.
	if [ "$CALY_MEM_TOTAL_KB" -gt 0 ] && [ "$CALY_MEM_TOTAL_KB" -lt 2097152 ] && \
	   [ "$CALY_FRESH_CONFIG" = "1" ]; then
		caly_step "less than 2 GiB of RAM: reducing map sizing to about 30 MB"
		conf_set "$caly_pc_dst" "max_rate_entries" "65536" || true
		conf_set "$caly_pc_dst" "max_conn_entries" "65536" || true
		conf_set "$caly_pc_dst" "max_scan_entries" "32768" || true
		conf_set "$caly_pc_dst" "max_srcstat_entries" "32768" || true
		conf_set "$caly_pc_dst" "max_ban_entries" "65536" || true
		conf_set "$caly_pc_dst" "max_block_entries" "65536" || true
	fi

	unset caly_pc_dst caly_pc_src caly_pc_mgmt caly_pc_i caly_pc_cidr
	return 0
}

# --------------------------------------------------------------------------
# Phase 8: sysctl
# --------------------------------------------------------------------------
phase_sysctl() {
	[ "$OPT_SYSCTL" = "1" ] || { caly_step "skipping sysctl (--no-sysctl)"; return 0; }
	step "Kernel tunables"

	# tcp_syncookies=2 is mandatory when the XDP SYN proxy is in play: at 1
	# the kernel only accepts cookies once the accept queue has overflowed,
	# so cookies our XDP program already issued are rejected when the ACK
	# comes back and the connection dies silently. At 2 they are always
	# accepted. Without the 5.15+ helpers we use the classic fallback, 1.
	caly_ps_sc=2
	caly_ps_why="unconditional: required by the XDP SYN proxy"
	if [ "${CALY_CAP_SYNPROXY}" = "no" ] || [ "${CALY_CAP_SYNPROXY}" = "unlikely" ] || \
	   ! dp_is_bpf "$CALY_DP"; then
		caly_ps_sc=1
		caly_ps_why="classic fallback: the raw syncookie helpers (5.15+) are unavailable here"
	fi

	# Save what we are about to change so uninstall.sh can put it back. Only on
	# the FIRST install: an upgrade re-run must not overwrite the genuine
	# pre-install snapshot with values we have already applied ourselves.
	if [ "${CALY_DRY_RUN:-0}" != "1" ] && [ -z "$DESTDIR" ] && \
	   [ ! -f "${STATEDIR}/sysctl-backup.conf" ]; then
		mkdir -p "$STATEDIR"
		{
			printf '# Caly Anti: values as they were before installation\n'
			for caly_ps_k in net.ipv4.tcp_syncookies net.core.bpf_jit_enable \
			    net.ipv4.tcp_max_syn_backlog net.core.netdev_max_backlog; do
				caly_ps_v=$(sysctl -n "$caly_ps_k" 2>/dev/null || echo "")
				[ -n "$caly_ps_v" ] && printf '%s = %s\n' "$caly_ps_k" "$caly_ps_v"
			done
		} > "${STATEDIR}/sysctl-backup.conf" 2>/dev/null || true
	fi

	write_file "$(d "$SYSCTL_FILE")" 0644 <<EOF
# /etc/sysctl.d/98-calyanti.conf
# Written by the Caly Anti installer. Remove this file and reload with
#   sysctl --system
# to revert (uninstall.sh does it for you and restores the previous values
# from ${STATEDIR}/sysctl-backup.conf).

# SYN cookies. ${caly_ps_why}
#
#   0  off
#   1  issue cookies only once the accept queue overflows
#   2  always issue and always accept cookies
#
# The XDP SYN proxy answers the client itself with a cookie generated by
# bpf_tcp_raw_gen_syncookie_ipv4(), which uses the KERNEL's own secret. When
# the client's ACK arrives, the stack has to accept that cookie to materialise
# the socket. At setting 1 it only does that while the accept queue is
# overflowing, so a proxied handshake completed during calm traffic would be
# dropped by our own kernel. 2 is not a tuning preference, it is a correctness
# requirement.
net.ipv4.tcp_syncookies = ${caly_ps_sc}

# JIT the BPF programs. Roughly an order of magnitude faster than the
# interpreter and enabled by default on most modern distributions anyway.
net.core.bpf_jit_enable = 1

# Deeper SYN and device backlogs so a burst absorbed by the dataplane is not
# then dropped by the stack behind it.
net.ipv4.tcp_max_syn_backlog = 8192
net.core.netdev_max_backlog = 5000

# Deliberately NOT set by this installer:
#   net.ipv4.conf.*.rp_filter    - breaks asymmetric routing and multihoming.
#   net.core.bpf_jit_harden      - lowering it would weaken an explicit
#                                  hardening decision made by your distro.
#   kernel.unprivileged_bpf_disabled - orthogonal to this suite and a
#                                  one-way switch on many kernels.
EOF

	if [ -z "$DESTDIR" ]; then
		if caly_have sysctl; then
			if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
				caly_run sysctl -p "$SYSCTL_FILE"
			else
				sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || \
					caly_warn "sysctl -p failed; values apply after the next reboot"
			fi
		else
			caly_warn "sysctl(8) not found; ${SYSCTL_FILE} applies at the next boot"
		fi
	fi

	caly_ok "wrote ${SYSCTL_FILE} (tcp_syncookies=${caly_ps_sc})"
	unset caly_ps_sc caly_ps_why caly_ps_k caly_ps_v
	return 0
}

# --------------------------------------------------------------------------
# Phase 9: bpffs
# --------------------------------------------------------------------------
phase_bpffs() {
	dp_is_bpf "$CALY_DP" || return 0
	[ -z "$DESTDIR" ] || return 0
	step "bpffs"

	if [ "$CALY_BPFFS_MOUNTED" != "yes" ]; then
		caly_step "mounting bpffs at /sys/fs/bpf"
		caly_run mkdir -p /sys/fs/bpf
		if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
			caly_run mount -t bpf bpffs /sys/fs/bpf
		else
			mount -t bpf bpffs /sys/fs/bpf 2>/dev/null || \
				mount -t bpf bpf /sys/fs/bpf 2>/dev/null || \
				caly_warn "could not mount bpffs; the daemon cannot pin maps"
		fi
	fi

	# Persist across reboots. systemd mounts bpffs itself since v238, but
	# OpenRC and older systemd do not.
	if [ -w /etc/fstab ] && [ "${CALY_DRY_RUN:-0}" != "1" ]; then
		if ! grep -q '[ 	]/sys/fs/bpf[ 	]' /etc/fstab 2>/dev/null; then
			caly_step "adding a bpffs entry to /etc/fstab"
			printf '%s\n' \
			  "# added by the Caly Anti installer" \
			  "bpffs /sys/fs/bpf bpf rw,nosuid,nodev,noexec,mode=700 0 0" \
			  >> /etc/fstab
		fi
	fi

	caly_run mkdir -p "$PINDIR"
	caly_run chmod 0700 "$PINDIR"
	caly_ok "pin directory ${PINDIR}"
	return 0
}

# --------------------------------------------------------------------------
# Phase 10: legacy dataplanes (ladder rungs 4 and 5)
#
# These are complete, standalone rulesets: they do not need the daemon to be
# running to protect the host. The daemon, when present, maintains the ban and
# allow sets inside them.
# --------------------------------------------------------------------------
AMP_PORTS_1="19,17,53,69,111,123,137,161,389,520,623"
AMP_PORTS_2="1434,1900,3283,5093,5351,5353,11211,27015,30718,37810"
BOGONS_V4="0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16, 192.0.2.0/24, \
198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15, 224.0.0.0/4, 240.0.0.0/4"

nft_ruleset() {
	# $1 = "drop" for enforcing, "" for monitor-only
	caly_nr_v=$1
	caly_nr_mgmt=$(printf '%s' "$CALY_MGMT_PORTS" | tr ' ' ',')
	caly_nr_wan=""
	for caly_nr_i in $CALY_IFACES; do
		caly_nr_wan="${caly_nr_wan}${caly_nr_wan:+, }\"${caly_nr_i}\""
	done
	[ -n "$caly_nr_wan" ] || caly_nr_wan="\"*\""

	cat <<EOF
#!/usr/sbin/nft -f
# /etc/calyanti/calyanti.nft
# Generated by the Caly Anti installer - ladder rung 4 (nftables).
#
# Regenerate with: install.sh --dataplane=nft
# Apply by hand with: nft -f /etc/calyanti/calyanti.nft
#
# Mode: $( [ -n "$caly_nr_v" ] && echo ENFORCING || echo "MONITOR ONLY (rules count, nothing is dropped)" )
#
# The chain policy is ACCEPT and every drop is an explicit rule. A partially
# loaded or flushed ruleset therefore fails open, exactly like the eBPF
# dataplane does.

table inet calyanti
delete table inet calyanti

table inet calyanti {
	set allow4 { type ipv4_addr; flags interval; auto-merge; }
	set allow6 { type ipv6_addr; flags interval; auto-merge; }
	set block4 { type ipv4_addr; flags interval; }
	set block6 { type ipv6_addr; flags interval; }
	set ban4   { type ipv4_addr; flags timeout; timeout 1h; size 262144; }
	set ban6   { type ipv6_addr; flags timeout; timeout 1h; size 262144; }
	set amp_src { type inet_service; elements = { ${AMP_PORTS_1}, ${AMP_PORTS_2} } }

	chain input {
		type filter hook input priority -10; policy accept;

		# ---- never wedge the operator ----------------------------
		iif lo accept
		ct state established,related accept
		tcp dport { ${caly_nr_mgmt} } accept
		ip saddr @allow4 accept
		ip6 saddr @allow6 accept

		# IPv6 without neighbour and router discovery is not IPv6, and
		# without Packet Too Big there is no PMTUD. These accepts come
		# before every drop rule, on purpose.
		icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert,
		              nd-router-solicit, nd-router-advert,
		              packet-too-big } accept
		# ICMP type 3 carries Fragmentation Needed; dropping it
		# black-holes PMTUD and produces "SSH connects then hangs".
		icmp type destination-unreachable accept

		# ---- reputation -----------------------------------------
		ip saddr @block4 counter ${caly_nr_v}
		ip6 saddr @block6 counter ${caly_nr_v}
		ip saddr @ban4 counter ${caly_nr_v}
		ip6 saddr @ban6 counter ${caly_nr_v}

		# ---- martians and bogons, WAN interfaces only -----------
		iifname { ${caly_nr_wan} } ip saddr { ${BOGONS_V4} } counter ${caly_nr_v}
		iifname { ${caly_nr_wan} } ip6 saddr { ::/128, ::1/128, ff00::/8 } counter ${caly_nr_v}

		# ---- malformed TCP ---------------------------------------
		tcp flags & (fin|syn|rst|psh|ack|urg) == 0 counter ${caly_nr_v}
		tcp flags & (fin|syn) == (fin|syn) counter ${caly_nr_v}
		tcp flags & (syn|rst) == (syn|rst) counter ${caly_nr_v}
		tcp flags & (fin|rst) == (fin|rst) counter ${caly_nr_v}
		tcp flags & (fin|psh|urg) == (fin|psh|urg) counter ${caly_nr_v}
		tcp flags & (fin|ack) == fin counter ${caly_nr_v}
		ct state invalid counter ${caly_nr_v}

		# ---- reflection / amplification --------------------------
		# Established replies were accepted above, so anything left
		# with an amplifier source port is unsolicited by definition.
		udp sport @amp_src counter ${caly_nr_v}

		# ---- rate limiting ---------------------------------------
		tcp flags syn / syn,ack meter caly_syn4 { ip saddr limit rate over 2000/second burst 4000 packets } counter ${caly_nr_v}
		tcp flags syn / syn,ack meter caly_syn6 { ip6 saddr limit rate over 2000/second burst 4000 packets } counter ${caly_nr_v}
		meter caly_pps4 { ip saddr limit rate over 200000/second burst 400000 packets } counter ${caly_nr_v}
		meter caly_pps6 { ip6 saddr limit rate over 200000/second burst 400000 packets } counter ${caly_nr_v}
		ip protocol icmp meter caly_icmp4 { ip saddr limit rate over 200/second burst 400 packets } counter ${caly_nr_v}
		icmpv6 type { echo-request, echo-reply } meter caly_icmp6 { ip6 saddr limit rate over 200/second burst 400 packets } counter ${caly_nr_v}
	}
}
EOF
	unset caly_nr_v caly_nr_mgmt caly_nr_wan caly_nr_i
}

nft_ruleset_minimal() {
	caly_nm_v=$1
	caly_nm_mgmt=$(printf '%s' "$CALY_MGMT_PORTS" | tr ' ' ',')
	cat <<EOF
#!/usr/sbin/nft -f
# /etc/calyanti/calyanti.nft (minimal variant)
# The full ruleset was rejected by this nft/kernel combination, most often
# because meters or a set flag are unsupported. This variant uses only
# syntax available since nftables 0.8.

table inet calyanti
delete table inet calyanti

table inet calyanti {
	set allow4 { type ipv4_addr; flags interval; }
	set allow6 { type ipv6_addr; flags interval; }
	set block4 { type ipv4_addr; flags interval; }
	set block6 { type ipv6_addr; flags interval; }
	set ban4   { type ipv4_addr; flags timeout; timeout 1h; }
	set ban6   { type ipv6_addr; flags timeout; timeout 1h; }

	chain input {
		type filter hook input priority -10; policy accept;

		iif lo accept
		ct state established,related accept
		tcp dport { ${caly_nm_mgmt} } accept
		ip saddr @allow4 accept
		ip6 saddr @allow6 accept
		icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert,
		              nd-router-solicit, nd-router-advert,
		              packet-too-big } accept
		icmp type destination-unreachable accept

		ip saddr @block4 counter ${caly_nm_v}
		ip6 saddr @block6 counter ${caly_nm_v}
		ip saddr @ban4 counter ${caly_nm_v}
		ip6 saddr @ban6 counter ${caly_nm_v}

		tcp flags & (fin|syn|rst|psh|ack|urg) == 0 counter ${caly_nm_v}
		tcp flags & (fin|syn) == (fin|syn) counter ${caly_nm_v}
		tcp flags & (syn|rst) == (syn|rst) counter ${caly_nm_v}
		tcp flags & (fin|rst) == (fin|rst) counter ${caly_nm_v}
		tcp flags & (fin|psh|urg) == (fin|psh|urg) counter ${caly_nm_v}
		ct state invalid counter ${caly_nm_v}
	}
}
EOF
	unset caly_nm_v caly_nm_mgmt
}

phase_nftables() {
	[ "$CALY_DP" = "nftables" ] || return 0
	step "Installing the nftables ruleset (ladder rung 4)"

	caly_pn_verdict=""
	[ "$OPT_ENFORCE" = "1" ] && caly_pn_verdict="drop"

	caly_pn_file="$(d "${CONFDIR}/calyanti.nft")"
	nft_ruleset "$caly_pn_verdict" | write_file "$caly_pn_file" 0640

	if [ -z "$DESTDIR" ] && [ "${CALY_DRY_RUN:-0}" != "1" ]; then
		if ! nft -c -f "$caly_pn_file" >/dev/null 2>&1; then
			caly_warn "this nftables version rejected the full ruleset; \
installing the minimal variant instead"
			nft_ruleset_minimal "$caly_pn_verdict" | \
				write_file "$caly_pn_file" 0640
			if ! nft -c -f "$caly_pn_file" >/dev/null 2>&1; then
				nft -c -f "$caly_pn_file" 2>&1 | sed -n '1,10p' >&2 || true
				caly_die "nftables rejected even the minimal ruleset (see above)"
			fi
		fi
		caly_step "loading the ruleset"
		nft -f "$caly_pn_file" || caly_die "nft -f failed"
	else
		caly_run nft -f "$caly_pn_file"
	fi

	# Boot persistence, independent of the daemon.
	if [ "$CALY_INIT" = "systemd" ] && [ -z "$DESTDIR" ]; then
		write_file "$(d "/etc/systemd/system/calyanti-nft.service")" 0644 <<EOF
[Unit]
Description=Caly Anti nftables ruleset
Documentation=file:${CONFDIR}/calyanti.nft
Wants=network-pre.target
Before=network-pre.target
After=nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'exec nft -f ${CONFDIR}/calyanti.nft'
ExecStop=/bin/sh -c 'nft delete table inet calyanti 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
EOF
		CALY_INSTALLED_UNITS="${CALY_INSTALLED_UNITS} calyanti-nft.service"
	elif [ "$CALY_INIT" = "openrc" ] && [ -z "$DESTDIR" ]; then
		write_file "$(d "/etc/local.d/calyanti-nft.start")" 0755 <<EOF
#!/bin/sh
# Caly Anti - load the nftables ruleset at boot.
exec nft -f ${CONFDIR}/calyanti.nft
EOF
	fi

	caly_ok "nftables ruleset active ($( [ -n "$caly_pn_verdict" ] && \
		echo enforcing || echo "monitor only, counters only" ))"
	unset caly_pn_verdict caly_pn_file
	return 0
}

iptables_script() {
	caly_is_v=$1     # "DROP" or "" (counter-only)
	caly_is_j=""
	[ -n "$caly_is_v" ] && caly_is_j="-j ${caly_is_v}"
	caly_is_mgmt=$(printf '%s' "$CALY_MGMT_PORTS" | tr ' ' ',')
	# WAN interfaces, mirrored into the emitted script so the bogon/martian
	# filter can be scoped to WAN only, exactly like the nft rung. Empty means
	# "every interface" (matches the nft "*" wildcard when no iface is known).
	caly_is_wan=$CALY_IFACES

	cat <<EOF
#!/bin/sh
# /etc/calyanti/calyanti-iptables.sh
# Generated by the Caly Anti installer - ladder rung 5 (iptables + ipset).
#
# Mode: $( [ -n "$caly_is_v" ] && echo ENFORCING || echo "MONITOR ONLY" )
#
# Every rule lands in the CALYANTI chain, which is jumped to from INPUT. The
# chain ends by falling through, so a partial ruleset fails open.
set -u

CHAIN=CALYANTI
# Interfaces the bogon/martian filter applies to; empty => every interface.
CALY_WAN_IFACES="${caly_is_wan}"
IPT=\$(command -v iptables 2>/dev/null || echo /sbin/iptables)
IP6T=\$(command -v ip6tables 2>/dev/null || true)
IPSET=\$(command -v ipset 2>/dev/null || true)

if [ -n "\$IPSET" ]; then
	\$IPSET create caly_allow4 hash:net family inet  -exist 2>/dev/null || true
	\$IPSET create caly_block4 hash:net family inet  -exist 2>/dev/null || true
	\$IPSET create caly_ban4   hash:ip  family inet  timeout 3600 -exist 2>/dev/null || true
	\$IPSET create caly_allow6 hash:net family inet6 -exist 2>/dev/null || true
	\$IPSET create caly_block6 hash:net family inet6 -exist 2>/dev/null || true
	\$IPSET create caly_ban6   hash:ip  family inet6 timeout 3600 -exist 2>/dev/null || true
fi

setup_v4() {
	\$IPT -N \$CHAIN 2>/dev/null || true
	\$IPT -F \$CHAIN
	\$IPT -C INPUT -j \$CHAIN 2>/dev/null || \$IPT -I INPUT 1 -j \$CHAIN

	# --- never wedge the operator ---
	\$IPT -A \$CHAIN -i lo -j RETURN
	\$IPT -A \$CHAIN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
	\$IPT -A \$CHAIN -p tcp -m multiport --dports ${caly_is_mgmt} -j RETURN
	# Fragmentation Needed keeps PMTUD alive.
	\$IPT -A \$CHAIN -p icmp --icmp-type fragmentation-needed -j RETURN
	if [ -n "\$IPSET" ]; then
		\$IPT -A \$CHAIN -m set --match-set caly_allow4 src -j RETURN
		\$IPT -A \$CHAIN -m set --match-set caly_block4 src ${caly_is_j}
		\$IPT -A \$CHAIN -m set --match-set caly_ban4 src ${caly_is_j}
	fi

	# --- martians / bogons, WAN interfaces only (mirrors the nft rung) ---
	for net in 0.0.0.0/8 127.0.0.0/8 169.254.0.0/16 192.0.2.0/24 \\
	           198.51.100.0/24 203.0.113.0/24 198.18.0.0/15 224.0.0.0/4 \\
	           240.0.0.0/4; do
		if [ -n "\$CALY_WAN_IFACES" ]; then
			for wanif in \$CALY_WAN_IFACES; do
				\$IPT -A \$CHAIN -i "\$wanif" -s "\$net" ${caly_is_j}
			done
		else
			\$IPT -A \$CHAIN -s "\$net" ${caly_is_j}
		fi
	done

	# --- malformed TCP ---
	\$IPT -A \$CHAIN -p tcp --tcp-flags ALL NONE ${caly_is_j}
	\$IPT -A \$CHAIN -p tcp --tcp-flags SYN,FIN SYN,FIN ${caly_is_j}
	\$IPT -A \$CHAIN -p tcp --tcp-flags SYN,RST SYN,RST ${caly_is_j}
	\$IPT -A \$CHAIN -p tcp --tcp-flags FIN,RST FIN,RST ${caly_is_j}
	\$IPT -A \$CHAIN -p tcp --tcp-flags FIN,PSH,URG FIN,PSH,URG ${caly_is_j}
	\$IPT -A \$CHAIN -p tcp --tcp-flags ACK,FIN FIN ${caly_is_j}
	\$IPT -A \$CHAIN -m conntrack --ctstate INVALID ${caly_is_j}

	# --- reflection / amplification (multiport takes at most 15 ports) ---
	\$IPT -A \$CHAIN -p udp -m multiport --sports ${AMP_PORTS_1} ${caly_is_j}
	\$IPT -A \$CHAIN -p udp -m multiport --sports ${AMP_PORTS_2} ${caly_is_j}

	# --- per-source rate limits ---
	\$IPT -A \$CHAIN -p tcp --syn -m hashlimit --hashlimit-above 2000/sec \\
		--hashlimit-burst 4000 --hashlimit-mode srcip \\
		--hashlimit-name calysyn4 ${caly_is_j}
	\$IPT -A \$CHAIN -p icmp -m hashlimit --hashlimit-above 200/sec \\
		--hashlimit-burst 400 --hashlimit-mode srcip \\
		--hashlimit-name calyicmp4 ${caly_is_j}
	\$IPT -A \$CHAIN -m hashlimit --hashlimit-above 200000/sec \\
		--hashlimit-burst 400000 --hashlimit-mode srcip \\
		--hashlimit-name calypps4 ${caly_is_j}
}

setup_v6() {
	[ -n "\$IP6T" ] || return 0
	\$IP6T -N \$CHAIN 2>/dev/null || true
	\$IP6T -F \$CHAIN
	\$IP6T -C INPUT -j \$CHAIN 2>/dev/null || \$IP6T -I INPUT 1 -j \$CHAIN

	\$IP6T -A \$CHAIN -i lo -j RETURN
	\$IP6T -A \$CHAIN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
	\$IP6T -A \$CHAIN -p tcp -m multiport --dports ${caly_is_mgmt} -j RETURN
	# ND and PMTUD are mandatory: without them IPv6 stops working.
	for t in packet-too-big neighbour-solicitation neighbour-advertisement \\
	         router-solicitation router-advertisement; do
		\$IP6T -A \$CHAIN -p icmpv6 --icmpv6-type "\$t" -j RETURN
	done
	if [ -n "\$IPSET" ]; then
		\$IP6T -A \$CHAIN -m set --match-set caly_allow6 src -j RETURN
		\$IP6T -A \$CHAIN -m set --match-set caly_block6 src ${caly_is_j}
		\$IP6T -A \$CHAIN -m set --match-set caly_ban6 src ${caly_is_j}
	fi

	\$IP6T -A \$CHAIN -p tcp --tcp-flags ALL NONE ${caly_is_j}
	\$IP6T -A \$CHAIN -p tcp --tcp-flags SYN,FIN SYN,FIN ${caly_is_j}
	\$IP6T -A \$CHAIN -p tcp --tcp-flags SYN,RST SYN,RST ${caly_is_j}
	\$IP6T -A \$CHAIN -p tcp --tcp-flags FIN,RST FIN,RST ${caly_is_j}
	\$IP6T -A \$CHAIN -m conntrack --ctstate INVALID ${caly_is_j}
	\$IP6T -A \$CHAIN -p udp -m multiport --sports ${AMP_PORTS_1} ${caly_is_j}
	\$IP6T -A \$CHAIN -p udp -m multiport --sports ${AMP_PORTS_2} ${caly_is_j}
	\$IP6T -A \$CHAIN -p tcp --syn -m hashlimit --hashlimit-above 2000/sec \\
		--hashlimit-burst 4000 --hashlimit-mode srcip \\
		--hashlimit-name calysyn6 ${caly_is_j}
}

# A failing individual rule (an unavailable match module, say) must not leave
# the chain half built, so failures are reported and the rest still loads.
setup_v4 || echo "calyanti: some IPv4 rules could not be installed" >&2
setup_v6 || echo "calyanti: some IPv6 rules could not be installed" >&2
exit 0
EOF
	unset caly_is_v caly_is_j caly_is_mgmt caly_is_wan
}

phase_iptables() {
	[ "$CALY_DP" = "iptables" ] || return 0
	step "Installing the iptables + ipset ruleset (ladder rung 5)"

	if [ "$CALY_HAVE_IPSET" != "yes" ]; then
		caly_warn "ipset is not installed: the allow/block/ban sets will be \
absent and only the static rules apply"
	fi

	caly_pi_verdict=""
	[ "$OPT_ENFORCE" = "1" ] && caly_pi_verdict="DROP"

	caly_pi_file="$(d "${CONFDIR}/calyanti-iptables.sh")"
	iptables_script "$caly_pi_verdict" | write_file "$caly_pi_file" 0750

	if [ -z "$DESTDIR" ]; then
		if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
			caly_run /bin/sh "$caly_pi_file"
		else
			/bin/sh "$caly_pi_file" || \
				caly_warn "the iptables ruleset did not load cleanly"
		fi
	fi

	if [ "$CALY_INIT" = "systemd" ] && [ -z "$DESTDIR" ]; then
		write_file "$(d "/etc/systemd/system/calyanti-iptables.service")" 0644 <<EOF
[Unit]
Description=Caly Anti iptables ruleset
Documentation=file:${CONFDIR}/calyanti-iptables.sh
Wants=network-pre.target
Before=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${CONFDIR}/calyanti-iptables.sh

[Install]
WantedBy=multi-user.target
EOF
		CALY_INSTALLED_UNITS="${CALY_INSTALLED_UNITS} calyanti-iptables.service"
	elif [ "$CALY_INIT" = "openrc" ] && [ -z "$DESTDIR" ]; then
		write_file "$(d "/etc/local.d/calyanti-iptables.start")" 0755 <<EOF
#!/bin/sh
# Caly Anti - load the iptables ruleset at boot.
exec ${CONFDIR}/calyanti-iptables.sh
EOF
	fi

	caly_ok "iptables ruleset active ($( [ -n "$caly_pi_verdict" ] && \
		echo enforcing || echo "monitor only, counters only" ))"
	unset caly_pi_verdict caly_pi_file
	return 0
}

# --------------------------------------------------------------------------
# Phase 11: init integration
# --------------------------------------------------------------------------
sysvinit_script() {
	cat <<EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          calyanti
# Required-Start:    \$local_fs \$remote_fs
# Required-Stop:     \$local_fs \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Caly Anti XDP/eBPF DDoS mitigation
### END INIT INFO
#
# Generated by the Caly Anti installer for a sysvinit system.

DAEMON=${SBINDIR}/calyd
CONF=${CONFDIR}/${CONF_NAME}
PIDFILE=${RUNDIR}/calyanti.pid
NAME=calyanti

[ -x "\$DAEMON" ] || exit 0
[ -r /etc/calyanti/calyanti.env ] && . /etc/calyanti/calyanti.env

case "\$1" in
start)
	echo "Starting \$NAME"
	mkdir -p ${RUNDIR}
	grep -q '[[:space:]]bpf[[:space:]]' /proc/mounts 2>/dev/null || \\
		mount -t bpf bpffs /sys/fs/bpf 2>/dev/null || true
	ulimit -l unlimited 2>/dev/null || true
	start-stop-daemon --start --quiet --background --make-pidfile \\
		--pidfile "\$PIDFILE" --exec "\$DAEMON" -- --config "\$CONF" \${CALYD_OPTS:-} ||
		{ "\$DAEMON" --config "\$CONF" \${CALYD_OPTS:-} & echo \$! > "\$PIDFILE"; }
	;;
stop)
	echo "Stopping \$NAME"
	if [ -f "\$PIDFILE" ]; then
		kill "\$(cat "\$PIDFILE")" 2>/dev/null || true
		rm -f "\$PIDFILE"
	fi
	;;
restart|force-reload)
	"\$0" stop
	sleep 1
	"\$0" start
	;;
reload)
	[ -f "\$PIDFILE" ] && kill -HUP "\$(cat "\$PIDFILE")" 2>/dev/null || true
	;;
status)
	if [ -f "\$PIDFILE" ] && kill -0 "\$(cat "\$PIDFILE")" 2>/dev/null; then
		echo "\$NAME is running"
		exit 0
	fi
	echo "\$NAME is not running"
	exit 3
	;;
*)
	echo "Usage: \$0 {start|stop|restart|reload|status}" >&2
	exit 2
	;;
esac
exit 0
EOF
}

phase_init() {
	step "Init integration (${CALY_INIT})"

	case "$CALY_INIT" in
	systemd)
		caly_pi_dir=${CALY_SYSTEMD_UNIT_DIR:-/usr/lib/systemd/system}
		caly_run mkdir -p "$(d "$caly_pi_dir")"
		install_file "${SRC_ROOT}/systemd/calyanti.service" \
			"$(d "${caly_pi_dir}/calyanti.service")" 0644 || \
			caly_warn "systemd/calyanti.service is missing from the source tree"
		install_file "${SRC_ROOT}/systemd/calyanti-watch.service" \
			"$(d "${caly_pi_dir}/calyanti-watch.service")" 0644 || true
		CALY_INSTALLED_UNITS="${CALY_INSTALLED_UNITS} calyanti.service"
		if [ -z "$DESTDIR" ]; then
			caly_run systemctl daemon-reload
		fi
		unset caly_pi_dir ;;
	openrc)
		install_file "${SRC_ROOT}/openrc/calyanti" \
			"$(d "/etc/init.d/calyanti")" 0755 || \
			caly_warn "openrc/calyanti is missing from the source tree"
		install_file "${SRC_ROOT}/openrc/calyanti-watch" \
			"$(d "/etc/init.d/calyanti-watch")" 0755 || true
		caly_run mkdir -p "$(d /etc/conf.d)"
		if [ ! -f "$(d /etc/conf.d/calyanti)" ]; then
			write_file "$(d /etc/conf.d/calyanti)" 0644 <<EOF
# /etc/conf.d/calyanti - OpenRC configuration for Caly Anti.
calyanti_config="${CONFDIR}/${CONF_NAME}"
CALYD_OPTS=""
EOF
		fi
		if [ ! -f "$(d /etc/conf.d/calyanti-watch)" ]; then
			write_file "$(d /etc/conf.d/calyanti-watch)" 0644 <<'EOF'
# /etc/conf.d/calyanti-watch - OpenRC configuration for the log watcher.
# Global options for calywatch (must precede its "run" subcommand), e.g.
# CALYWATCH_OPTS="--log-level debug". The config file lives at
# /etc/calyanti/calywatch.conf.
CALYWATCH_OPTS=""
EOF
		fi ;;
	sysvinit|busybox)
		sysvinit_script | write_file "$(d "/etc/init.d/calyanti")" 0755
		caly_step "generated a sysvinit script at /etc/init.d/calyanti" ;;
	*)
		caly_warn "init system '${CALY_INIT}' is not integrated. Start the \
daemon manually: ${SBINDIR}/calyd --config ${CONFDIR}/${CONF_NAME}" ;;
	esac
	return 0
}

phase_enable_start() {
	[ -z "$DESTDIR" ] || return 0
	[ -n "$CALY_DAEMON_BIN" ] || [ -x "$(d "${SBINDIR}/calyd")" ] || {
		caly_warn "no daemon installed; not enabling or starting the service"
		return 0
	}

	step "Enabling and starting"

	case "$CALY_INIT" in
	systemd)
		if [ "$OPT_ENABLE" = "1" ]; then
			caly_run systemctl enable calyanti.service || \
				caly_warn "systemctl enable failed"
			for caly_es_u in $CALY_INSTALLED_UNITS; do
				case "$caly_es_u" in
				calyanti-nft.service|calyanti-iptables.service)
					caly_run systemctl enable "$caly_es_u" || true ;;
				esac
			done
			[ "$OPT_WATCH" = "1" ] && \
				{ caly_run systemctl enable calyanti-watch.service || true; }
		fi
		if [ "$OPT_START" = "1" ]; then
			if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
				caly_run systemctl restart calyanti.service
			else
				systemctl restart calyanti.service || \
					caly_warn "the service did not start; see: \
journalctl -u calyanti -n 50 --no-pager"
			fi
			[ "$OPT_WATCH" = "1" ] && \
				{ systemctl restart calyanti-watch.service 2>/dev/null || true; }
		fi ;;
	openrc)
		if [ "$OPT_ENABLE" = "1" ]; then
			caly_run rc-update add calyanti default || \
				caly_warn "rc-update add failed"
			[ "$OPT_WATCH" = "1" ] && \
				{ caly_run rc-update add calyanti-watch default || true; }
		fi
		if [ "$OPT_START" = "1" ]; then
			if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
				caly_run rc-service calyanti restart
			else
				rc-service calyanti restart || \
					caly_warn "the service did not start; see /var/log/calyanti/"
			fi
			[ "$OPT_WATCH" = "1" ] && \
				{ rc-service calyanti-watch restart 2>/dev/null || true; }
		fi ;;
	sysvinit|busybox)
		if [ "$OPT_ENABLE" = "1" ]; then
			if caly_have update-rc.d; then
				caly_run update-rc.d calyanti defaults || true
			elif caly_have chkconfig; then
				caly_run chkconfig --add calyanti || true
			fi
		fi
		if [ "$OPT_START" = "1" ]; then
			caly_run /etc/init.d/calyanti restart || \
				caly_warn "the service did not start"
		fi ;;
	*)
		caly_warn "no init integration; start the daemon by hand" ;;
	esac
	unset caly_es_u
	return 0
}

# --------------------------------------------------------------------------
# Phase 12: rollback timer
#
# Only armed when the operator asked to enforce AND is connected over SSH.
# It is the difference between "I made a mistake" and "I need the console".
# --------------------------------------------------------------------------
phase_rollback_arm() {
	[ "$OPT_ENFORCE" = "1" ] || return 0
	[ "$OPT_ROLLBACK" = "1" ] || return 0
	[ -z "$DESTDIR" ] || return 0
	[ "${CALY_DRY_RUN:-0}" != "1" ] || return 0

	# The deadman only makes sense for a remote operator: arming it on a local
	# console would tear the dataplane down on someone sitting at the machine.
	# But staying silent when we cannot confirm a remote session is the
	# dangerous direction, so warn loudly rather than skip quietly.
	if [ "$CALY_IS_SSH" != "yes" ]; then
		caly_warn "--enforce with no rollback timer armed: this run does not \
look like a remote (SSH) login. If you ARE connected remotely, open a second \
session now and keep it open - a mistake in enforcing mode has no automatic \
revert."
		return 0
	fi

	step "Arming the rollback timer (${OPT_ROLLBACK_SECS}s)"

	caly_ra_script="${LIBDIR}/caly-rollback.sh"
	write_file "$caly_ra_script" 0755 <<EOF
#!/bin/sh
# Caly Anti deadman rollback. Generated by install.sh; safe to delete.
#
# Waits for ${RUNDIR}/confirmed to appear. If it does not, the dataplane is
# torn back down on the assumption that enforcing mode locked the operator out.
set -u
LOG=${LOGDIR}/rollback.log
i=0
while [ "\$i" -lt ${OPT_ROLLBACK_SECS} ]; do
	if [ -e "${RUNDIR}/confirmed" ]; then
		echo "\$(date): confirmed, rollback cancelled" >> "\$LOG" 2>/dev/null
		rm -f "${RUNDIR}/rollback.pid"
		exit 0
	fi
	sleep 1
	i=\$((i + 1))
done

echo "\$(date): NOT confirmed after ${OPT_ROLLBACK_SECS}s, rolling back" >> "\$LOG" 2>/dev/null

# 1. back to monitor-only so a restart cannot re-enforce
if [ -w ${CONFDIR}/${CONF_NAME} ]; then
	sed -i 's/^[ \t]*monitor_only[ \t]*=.*/monitor_only = yes/' \\
		${CONFDIR}/${CONF_NAME} 2>/dev/null || true
fi

# 2. stop the daemon
if command -v systemctl >/dev/null 2>&1; then
	systemctl stop calyanti.service 2>/dev/null || true
elif command -v rc-service >/dev/null 2>&1; then
	rc-service calyanti stop 2>/dev/null || true
elif [ -x /etc/init.d/calyanti ]; then
	/etc/init.d/calyanti stop 2>/dev/null || true
fi

# 3. detach anything left attached
for i in ${CALY_IFACES}; do
	ip link set dev "\$i" xdp off 2>/dev/null || true
	ip link set dev "\$i" xdpgeneric off 2>/dev/null || true
	ip link set dev "\$i" xdpdrv off 2>/dev/null || true
	tc filter del dev "\$i" ingress 2>/dev/null || true
done

# 4. remove the legacy rulesets
if command -v nft >/dev/null 2>&1; then
	nft delete table inet calyanti 2>/dev/null || true
fi
if command -v iptables >/dev/null 2>&1; then
	iptables -D INPUT -j CALYANTI 2>/dev/null || true
	iptables -F CALYANTI 2>/dev/null || true
fi

echo "\$(date): rollback complete, the host is unfiltered" >> "\$LOG" 2>/dev/null
rm -f "${RUNDIR}/rollback.pid"
exit 0
EOF

	mkdir -p "$RUNDIR" "$LOGDIR" 2>/dev/null || true
	rm -f "${RUNDIR}/confirmed"

	if caly_have setsid; then
		setsid /bin/sh "$caly_ra_script" >/dev/null 2>&1 &
	else
		nohup /bin/sh "$caly_ra_script" >/dev/null 2>&1 &
	fi
	printf '%s\n' "$!" > "${RUNDIR}/rollback.pid" 2>/dev/null || true

	caly_say ""
	caly_say "  ${CALY_C_YELLOW}${CALY_C_BOLD}ROLLBACK TIMER ARMED${CALY_C_RESET}"
	caly_say "  If you are still connected in ${OPT_ROLLBACK_SECS} seconds, confirm with:"
	caly_say ""
	caly_say "      ${CALY_C_BOLD}touch ${RUNDIR}/confirmed${CALY_C_RESET}"
	caly_say ""
	caly_say "  Otherwise the dataplane is torn down automatically and the host"
	caly_say "  is left unfiltered. Open a SECOND session now to test with."
	caly_say ""
	unset caly_ra_script
	return 0
}

# --------------------------------------------------------------------------
# Phase 13: self-test
# --------------------------------------------------------------------------
st_pass() { printf '  %s[ ok ]%s %s\n' "${CALY_C_GREEN}" "${CALY_C_RESET}" "$1"; }
st_warn() {
	printf '  %s[warn]%s %s\n' "${CALY_C_YELLOW}" "${CALY_C_RESET}" "$1"
	CALY_SELFTEST_WARN=$((CALY_SELFTEST_WARN + 1))
}
st_fail() {
	printf '  %s[fail]%s %s\n' "${CALY_C_RED}" "${CALY_C_RESET}" "$1"
	CALY_SELFTEST_FAIL=$((CALY_SELFTEST_FAIL + 1))
}
st_skip() { printf '  %s[skip]%s %s\n' "${CALY_C_DIM}" "${CALY_C_RESET}" "$1"; }

service_active() {
	case "$CALY_INIT" in
	systemd) systemctl is-active --quiet calyanti.service 2>/dev/null ;;
	openrc)  rc-service calyanti status >/dev/null 2>&1 ;;
	sysvinit|busybox) /etc/init.d/calyanti status >/dev/null 2>&1 ;;
	*) return 1 ;;
	esac
}

phase_selftest() {
	[ "$OPT_SELFTEST" = "1" ] || return 0
	[ -z "$DESTDIR" ] || return 0
	[ "${CALY_DRY_RUN:-0}" != "1" ] || return 0

	step "Self-test"

	# 1. binaries
	if [ -x "${SBINDIR}/calyd" ]; then
		st_pass "daemon installed at ${SBINDIR}/calyd"
	else
		st_fail "no daemon at ${SBINDIR}/calyd"
	fi
	if [ -x "${SBINDIR}/calyctl" ]; then
		st_pass "cli installed at ${SBINDIR}/calyctl"
	else
		st_warn "no cli at ${SBINDIR}/calyctl (status and mode changes unavailable)"
	fi

	# 2. configuration
	if [ -r "${CONFDIR}/${CONF_NAME}" ]; then
		st_pass "configuration at ${CONFDIR}/${CONF_NAME}"
		if [ -x "${SBINDIR}/calyd" ]; then
			if "${SBINDIR}/calyd" --check-config "${CONFDIR}/${CONF_NAME}" \
			    >/dev/null 2>&1; then
				st_pass "configuration parses"
			else
				st_skip "configuration check unavailable (calyd has no --check-config)"
			fi
		fi
	else
		st_fail "no configuration at ${CONFDIR}/${CONF_NAME}"
	fi

	# 3. management port survivability. This is the check that matters.
	caly_st_ok=0
	for caly_st_p in $CALY_MGMT_PORTS; do
		if [ "$CALY_HAVE_SS" = "yes" ]; then
			if ss -H -ltn 2>/dev/null | grep -Eq ":${caly_st_p}([[:space:]]|\$)"; then
				caly_st_ok=1
			fi
		elif caly_have netstat; then
			if netstat -ltn 2>/dev/null | grep -q ":${caly_st_p} "; then
				caly_st_ok=1
			fi
		fi
	done
	if [ "$caly_st_ok" = "1" ]; then
		st_pass "a management port (${CALY_MGMT_PORTS}) is still listening"
	else
		st_warn "could not confirm a listening management port; if you \
administer this box over SSH, verify from a second session before logging out"
	fi

	# 4. the session we are installing from
	if [ -n "$CALY_SSH_PEER" ] && [ "$CALY_HAVE_SS" = "yes" ]; then
		if ss -tn state established 2>/dev/null | grep -q "$CALY_SSH_PEER"; then
			st_pass "your SSH session from ${CALY_SSH_PEER} is still established"
		else
			st_warn "could not see your SSH session in ss output (harmless if \
you are behind NAT)"
		fi
	fi

	# 5. the service
	case "$CALY_INIT" in
	systemd|openrc|sysvinit|busybox)
		if [ "$OPT_START" != "1" ]; then
			st_skip "service not started (--no-start)"
		elif service_active; then
			st_pass "the calyanti service is running"
		else
			st_fail "the calyanti service is not running"
			case "$CALY_INIT" in
			systemd) printf '         journalctl -u calyanti -n 50 --no-pager\n' ;;
			openrc)  printf '         cat /var/log/calyanti/calyanti.err\n' ;;
			esac
		fi ;;
	*) st_skip "no init integration on this system" ;;
	esac

	# 6. the dataplane is actually attached
	case "$CALY_DP" in
	xdp-native|xdp-generic)
		caly_st_att=0
		for caly_st_i in $CALY_IFACES; do
			if [ "$CALY_HAVE_IP" = "yes" ] && \
			   ip -details link show dev "$caly_st_i" 2>/dev/null | \
			   grep -q 'xdp'; then
				st_pass "XDP program attached to ${caly_st_i}"
				caly_st_att=1
			fi
		done
		[ "$caly_st_att" = "1" ] || \
			st_warn "no XDP program visible on ${CALY_IFACES:-(no interface)} \
yet; the daemon may still be loading, check again with: ip -d link show" ;;
	tc)
		caly_st_att=0
		for caly_st_i in $CALY_IFACES; do
			if [ "$CALY_HAVE_TC" = "yes" ] && \
			   tc filter show dev "$caly_st_i" ingress 2>/dev/null | \
			   grep -q 'bpf'; then
				st_pass "tc/clsact filter attached to ${caly_st_i}"
				caly_st_att=1
			fi
		done
		[ "$caly_st_att" = "1" ] || st_warn "no tc BPF filter visible yet" ;;
	nftables)
		if nft list table inet calyanti >/dev/null 2>&1; then
			st_pass "nftables table inet calyanti is loaded"
		else
			st_fail "nftables table inet calyanti is missing"
		fi ;;
	iptables)
		if iptables -S CALYANTI >/dev/null 2>&1; then
			st_pass "iptables chain CALYANTI exists"
		else
			st_fail "iptables chain CALYANTI is missing"
		fi ;;
	esac

	# 7. pinned maps
	if dp_is_bpf "$CALY_DP"; then
		if [ -d "$PINDIR" ] && [ -n "$(ls -A "$PINDIR" 2>/dev/null || true)" ]; then
			st_pass "maps pinned under ${PINDIR}"
		else
			st_warn "${PINDIR} is empty; the daemon has not pinned its maps yet"
		fi
	fi

	# 8. sysctl actually took
	if [ "$OPT_SYSCTL" = "1" ] && caly_have sysctl; then
		caly_st_v=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || echo "?")
		if [ "$caly_st_v" = "2" ] || [ "$caly_st_v" = "1" ]; then
			st_pass "net.ipv4.tcp_syncookies = ${caly_st_v}"
		else
			st_warn "net.ipv4.tcp_syncookies is ${caly_st_v}; the SYN proxy \
needs 2 to splice proxied handshakes"
		fi
	fi

	# 9. monitor-only really is monitor-only
	if [ "$OPT_ENFORCE" != "1" ]; then
		if grep -Eq '^[[:space:]]*monitor_only[[:space:]]*=[[:space:]]*(yes|true|on|1)' \
		    "${CONFDIR}/${CONF_NAME}" 2>/dev/null; then
			st_pass "monitor-only is set: nothing will be dropped"
		else
			st_fail "monitor_only is not set in the configuration"
		fi
	fi

	printf '\n'
	if [ "$CALY_SELFTEST_FAIL" -gt 0 ]; then
		caly_warn "self-test: ${CALY_SELFTEST_FAIL} failure(s), \
${CALY_SELFTEST_WARN} warning(s)"
	elif [ "$CALY_SELFTEST_WARN" -gt 0 ]; then
		caly_ok "self-test passed with ${CALY_SELFTEST_WARN} warning(s)"
	else
		caly_ok "self-test passed"
	fi
	unset caly_st_ok caly_st_p caly_st_att caly_st_i caly_st_v
	return 0
}

# --------------------------------------------------------------------------
# Phase 14: summary
# --------------------------------------------------------------------------
phase_summary() {
	caly_say ""
	caly_say "${CALY_C_BOLD}Caly Anti ${CALY_VERSION} installed${CALY_C_RESET}"
	caly_say ""
	printf '  %-18s %s\n' "dataplane" "${CALY_DP}"
	printf '  %-18s %s\n' "interfaces" "${CALY_IFACES:-none configured}"
	printf '  %-18s %s\n' "mode" "$( [ "$OPT_ENFORCE" = 1 ] && \
		echo "ENFORCING (dropping)" || echo "monitor only (counting)" )"
	printf '  %-18s %s\n' "config" "${CONFDIR}/${CONF_NAME}"
	printf '  %-18s %s\n' "mgmt tcp ports" "${CALY_MGMT_PORTS}"
	if dp_is_bpf "$CALY_DP"; then
		printf '  %-18s %s\n' "pinned maps" "${PINDIR}"
		printf '  %-18s %s\n' "bpf objects" "${BPFOBJDIR}"
	fi
	caly_say ""
	caly_say "${CALY_C_BOLD}Next${CALY_C_RESET}"
	if [ "$OPT_ENFORCE" != "1" ]; then
		caly_say "  1. Leave it in monitor-only for a few days."
		caly_say "  2. Read the counters:      calyctl stats"
		caly_say "     and the top talkers:    calyctl top"
		caly_say "  3. Confirm the only would-be drops are traffic you are"
		caly_say "     happy to lose, then enforce:"
		caly_say ""
		caly_say "         ${CALY_C_BOLD}calyctl mode normal${CALY_C_RESET}"
		caly_say ""
		caly_say "     (or re-run this installer with --enforce)"
	else
		caly_say "  1. Verify from a SECOND session that you can still log in."
		if [ "$CALY_IS_SSH" = "yes" ] && [ "$OPT_ROLLBACK" = "1" ]; then
			caly_say "  2. Confirm within ${OPT_ROLLBACK_SECS}s:  touch ${RUNDIR}/confirmed"
			caly_say "  3. Watch the drops:       calyctl stats"
		else
			caly_say "  2. Watch the drops:       calyctl stats"
		fi
	fi
	caly_say ""
	caly_say "  service:    $( case "$CALY_INIT" in
		systemd) echo "systemctl status calyanti" ;;
		openrc)  echo "rc-service calyanti status" ;;
		*)       echo "/etc/init.d/calyanti status" ;;
		esac )"
	caly_say "  uninstall:  ${SBINDIR}/calyanti-uninstall"
	caly_say "  docs:       ${DOCDIR}/ARCHITECTURE.md"
	caly_say ""

	if [ "$CALY_DP" = "nftables" ] || [ "$CALY_DP" = "iptables" ]; then
		caly_say "  ${CALY_C_YELLOW}This machine is running ladder rung $( \
			[ "$CALY_DP" = nftables ] && echo 4 || echo 5 ) (${CALY_DP}).${CALY_C_RESET}"
		caly_say "  Reason: ${CALY_DATAPLANE_REASON:-explicitly requested}"
		caly_say "  Policy is preserved. What you do not get: per-source token"
		caly_say "  buckets, the port-scan detector, the SYN proxy and XDP-rate"
		caly_say "  packet processing."
		caly_say ""
	fi
	return 0
}

# --------------------------------------------------------------------------
# Run
# --------------------------------------------------------------------------
phase_preflight "$@"
phase_pick_ifaces
phase_choose_dataplane
phase_deps
phase_vmlinux
phase_build
phase_install_files
phase_config
phase_sysctl
phase_bpffs
phase_nftables
phase_iptables
phase_init
phase_enable_start
phase_rollback_arm
phase_selftest
phase_summary

CALY_FINISHED=1
if [ "$CALY_SELFTEST_FAIL" -gt 0 ]; then
	exit 1
fi
exit 0
