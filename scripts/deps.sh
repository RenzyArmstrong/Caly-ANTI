#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Caly Anti - scripts/deps.sh
#
# Build and runtime dependency installation, per distribution.
#
# Package names differ enormously between families and even between releases
# of the same family, so every list below is a set of CANDIDATES that is
# filtered against what the package manager actually offers before anything is
# installed. A name that does not exist on this release is skipped silently
# instead of aborting the whole install - that is the difference between an
# installer that works on eight distributions and one that works on one.
#
# POSIX sh only. Sourceable as a library or runnable directly:
#
#   ./deps.sh --list                 print what would be installed
#   ./deps.sh --build                build toolchain only
#   ./deps.sh --runtime              runtime libraries and tools only
#   ./deps.sh                        both (default)
#
# Nothing here is fatal by itself. If a dependency is missing afterwards the
# caller decides whether to degrade down the ladder (usually to nftables) or
# to stop.

if [ "${CALY_DEPS_LOADED:-0}" = "1" ]; then
	return 0 2>/dev/null || true
fi
CALY_DEPS_LOADED=1

# Locate and load detect-env.sh from the same directory.
caly_deps_self=$0
case "$caly_deps_self" in
*/*) caly_deps_dir=${caly_deps_self%/*} ;;
*)   caly_deps_dir=. ;;
esac
if [ "${CALY_DETECT_ENV_LOADED:-0}" != "1" ]; then
	if [ -r "${caly_deps_dir}/detect-env.sh" ]; then
		# shellcheck source=scripts/detect-env.sh
		. "${caly_deps_dir}/detect-env.sh"
	elif [ -r "${CALY_LIBEXEC_DIR:-/usr/lib/calyanti/scripts}/detect-env.sh" ]; then
		# shellcheck source=scripts/detect-env.sh
		. "${CALY_LIBEXEC_DIR:-/usr/lib/calyanti/scripts}/detect-env.sh"
	else
		echo "deps.sh: cannot find detect-env.sh next to $0" >&2
		exit 1
	fi
fi
unset caly_deps_self caly_deps_dir

# ---------------------------------------------------------------------------
# Package availability helpers
# ---------------------------------------------------------------------------

# caly_pkg_installed NAME -> 0 when already installed
caly_pkg_installed() {
	case "${CALY_PKGMGR}" in
	dnf|dnf5|yum|zypper) rpm -q "$1" >/dev/null 2>&1 ;;
	apt)  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | \
		grep -q '^install ok installed$' ;;
	pacman) pacman -Qq "$1" >/dev/null 2>&1 ;;
	apk)  apk info -e "$1" >/dev/null 2>&1 ;;
	xbps) xbps-query "$1" >/dev/null 2>&1 ;;
	emerge) qlist -I "$1" >/dev/null 2>&1 ;;
	*) return 1 ;;
	esac
}

# caly_pkg_available NAME -> 0 when the package manager can install it
caly_pkg_available() {
	case "${CALY_PKGMGR}" in
	dnf|dnf5)
		"${CALY_PKGMGR}" -q info "$1" >/dev/null 2>&1 ;;
	yum)
		yum -q info "$1" >/dev/null 2>&1 ;;
	apt)
		apt-cache show "$1" 2>/dev/null | grep -q '^Package:' ;;
	pacman)
		pacman -Si "$1" >/dev/null 2>&1 ;;
	zypper)
		zypper -n --no-refresh search --match-exact -t package "$1" \
			>/dev/null 2>&1 ;;
	apk)
		[ -n "$(apk search -x "$1" 2>/dev/null)" ] ;;
	xbps)
		xbps-query -R "$1" >/dev/null 2>&1 ;;
	emerge)
		emerge --pretend --quiet "$1" >/dev/null 2>&1 ;;
	*)
		return 1 ;;
	esac
}

# Filter a candidate list down to packages this system can actually install.
# Prints the surviving names, space separated. Already-installed packages are
# kept so that `--list` shows the complete dependency set; the package manager
# will simply report "nothing to do" for them.
caly_pkg_filter() {
	caly_pf_out=""
	for caly_pf_p in "$@"; do
		[ -n "$caly_pf_p" ] || continue
		if caly_pkg_installed "$caly_pf_p"; then
			caly_pf_out="${caly_pf_out}${caly_pf_out:+ }${caly_pf_p}"
			continue
		fi
		if caly_pkg_available "$caly_pf_p"; then
			caly_pf_out="${caly_pf_out}${caly_pf_out:+ }${caly_pf_p}"
		else
			caly_debug "package not available on this release: $caly_pf_p"
		fi
	done
	printf '%s' "$caly_pf_out"
	unset caly_pf_out caly_pf_p
}

# Remove already-installed packages from a list (what we actually hand to the
# package manager).
caly_pkg_missing() {
	caly_pm_out=""
	for caly_pm_p in "$@"; do
		[ -n "$caly_pm_p" ] || continue
		caly_pkg_installed "$caly_pm_p" && continue
		caly_pm_out="${caly_pm_out}${caly_pm_out:+ }${caly_pm_p}"
	done
	printf '%s' "$caly_pm_out"
	unset caly_pm_out caly_pm_p
}

caly_pkg_refresh() {
	[ "${CALY_DEPS_REFRESHED:-0}" = "1" ] && return 0
	CALY_DEPS_REFRESHED=1
	case "${CALY_PKGMGR}" in
	apt)
		caly_step "apt-get update"
		if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
			caly_run apt-get update
		else
			DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 || \
				caly_warn "apt-get update failed; using the cached index"
		fi ;;
	apk)
		caly_step "apk update"
		if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
			caly_run apk update
		else
			apk update >/dev/null 2>&1 || \
				caly_warn "apk update failed; using the cached index"
		fi ;;
	pacman)
		caly_step "pacman -Sy"
		if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
			caly_run pacman -Sy --noconfirm
		else
			pacman -Sy --noconfirm >/dev/null 2>&1 || \
				caly_warn "pacman -Sy failed; using the cached index"
		fi ;;
	zypper)
		caly_step "zypper refresh"
		if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
			caly_run zypper --non-interactive refresh
		else
			zypper --non-interactive refresh >/dev/null 2>&1 || \
				caly_warn "zypper refresh failed; using the cached index"
		fi ;;
	dnf|dnf5|yum)
		: ;;  # dnf refreshes on demand
	esac
	return 0
}

# Install a list of packages. Tries a single transaction first (fast, lets the
# solver work), then falls back to one-by-one so a single unsatisfiable name
# cannot take the whole set down with it.
caly_pkg_install() {
	[ $# -gt 0 ] || return 0
	caly_pi_list=$(caly_pkg_missing "$@")
	if [ -z "$caly_pi_list" ]; then
		caly_step "all packages already installed"
		return 0
	fi

	caly_step "installing: ${caly_pi_list}"

	if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
		# shellcheck disable=SC2086
		caly_run ${CALY_PKG_INSTALL} ${caly_pi_list}
		unset caly_pi_list
		return 0
	fi

	caly_pi_env=""
	[ "${CALY_PKGMGR}" = "apt" ] && caly_pi_env="DEBIAN_FRONTEND=noninteractive"

	# shellcheck disable=SC2086
	if env ${caly_pi_env} ${CALY_PKG_INSTALL} ${caly_pi_list} \
	    >"${CALY_DEPS_LOG:-/dev/null}" 2>&1; then
		unset caly_pi_list caly_pi_env
		return 0
	fi

	caly_warn "batch package install failed; retrying one package at a time"
	caly_pi_failed=""
	for caly_pi_p in $caly_pi_list; do
		# shellcheck disable=SC2086
		if ! env ${caly_pi_env} ${CALY_PKG_INSTALL} "$caly_pi_p" \
		    >"${CALY_DEPS_LOG:-/dev/null}" 2>&1; then
			caly_pi_failed="${caly_pi_failed}${caly_pi_failed:+ }${caly_pi_p}"
		fi
	done
	if [ -n "$caly_pi_failed" ]; then
		caly_warn "could not install: ${caly_pi_failed}"
		CALY_DEPS_FAILED="${CALY_DEPS_FAILED:-}${CALY_DEPS_FAILED:+ }${caly_pi_failed}"
		unset caly_pi_list caly_pi_env caly_pi_p caly_pi_failed
		return 1
	fi
	unset caly_pi_list caly_pi_env caly_pi_p caly_pi_failed
	return 0
}

# ---------------------------------------------------------------------------
# Extra repositories
#
# On the RHEL family, libbpf-devel and (on some releases) elfutils-libelf-devel
# live in PowerTools / CRB / CodeReady Builder, which is disabled by default.
# Enabling it is the single most common reason a "clang is installed but the
# build still fails" report exists.
# ---------------------------------------------------------------------------
caly_enable_extra_repos() {
	case "${CALY_OS_FAMILY}" in
	rhel) ;;
	*) return 0 ;;
	esac
	case "${CALY_PKGMGR}" in
	dnf|dnf5|yum) ;;
	*) return 0 ;;
	esac
	[ "${CALY_IS_ROOT}" = "yes" ] || return 0

	# Amazon Linux has no CRB and no dnf config-manager by default.
	case "${CALY_OS_ID}" in
	amzn) return 0 ;;
	esac

	caly_step "enabling the CodeReady Builder / PowerTools repository (if present)"

	# `config-manager` is a plugin; on a minimal image it is not installed.
	if ! "${CALY_PKGMGR}" config-manager --help >/dev/null 2>&1; then
		# shellcheck disable=SC2086
		caly_try ${CALY_PKG_INSTALL} dnf-plugins-core
	fi

	# Try every known name. All of these are expected to fail on releases
	# that do not have that particular repository id.
	for caly_er_r in crb powertools PowerTools \
	    "ol${CALY_OS_VERSION_MAJOR}_codeready_builder" \
	    "codeready-builder-for-rhel-${CALY_OS_VERSION_MAJOR}-${CALY_ARCH}-rpms"; do
		if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
			caly_run "${CALY_PKGMGR}" config-manager --set-enabled "$caly_er_r"
			continue
		fi
		"${CALY_PKGMGR}" config-manager --set-enabled "$caly_er_r" \
			>/dev/null 2>&1 && \
			caly_debug "enabled repo ${caly_er_r}"
	done

	# Subscribed RHEL proper needs subscription-manager rather than
	# config-manager for the CRB repository.
	if caly_have subscription-manager && [ "${CALY_OS_ID}" = "rhel" ]; then
		caly_try subscription-manager repos --enable \
			"codeready-builder-for-rhel-${CALY_OS_VERSION_MAJOR}-${CALY_ARCH}-rpms"
	fi
	unset caly_er_r
	return 0
}

# ---------------------------------------------------------------------------
# Dependency lists
#
# CALY_DEPS_BUILD    - needed to compile the BPF object and the daemon
# CALY_DEPS_RUNTIME  - needed to run it
# CALY_DEPS_OPTIONAL - nice to have; failure is never reported as an error
# ---------------------------------------------------------------------------
caly_deps_lists() {
	CALY_DEPS_BUILD=""
	CALY_DEPS_RUNTIME=""
	CALY_DEPS_OPTIONAL=""

	caly_dl_kver=${CALY_KERNEL_RELEASE}

	case "${CALY_OS_FAMILY}" in
	rhel)
		# clang+llvm: BPF target. bpftool: vmlinux.h generation.
		# libbpf-devel + elfutils-libelf-devel + zlib-devel: the loader.
		CALY_DEPS_BUILD="clang llvm make gcc \
libbpf libbpf-devel elfutils-libelf-devel zlib-devel \
pkgconf-pkg-config pkgconfig glibc-headers kernel-headers"
		CALY_DEPS_RUNTIME="libbpf elfutils-libelf zlib iproute ethtool \
iproute-tc"
		CALY_DEPS_OPTIONAL="bpftool llvm-toolset \
kernel-devel-${caly_dl_kver} kernel-devel nftables iptables iptables-nft \
ipset"
		;;
	debian)
		# linux-tools-$(uname -r) is where Ubuntu hides bpftool; Debian
		# 11+ has a standalone bpftool package. Both are candidates and
		# whichever exists wins.
		CALY_DEPS_BUILD="clang llvm make gcc \
libbpf-dev libelf-dev zlib1g-dev pkg-config libc6-dev"
		CALY_DEPS_RUNTIME="libelf1 zlib1g iproute2 ethtool"
		CALY_DEPS_OPTIONAL="bpftool linux-tools-common \
linux-tools-${caly_dl_kver} linux-tools-generic \
linux-headers-${caly_dl_kver} linux-headers-generic \
libbpf1 libbpf0 nftables iptables ipset"
		;;
	arch)
		# bpftool lives in the `bpf` package on Arch.
		CALY_DEPS_BUILD="clang llvm make gcc pkgconf libbpf elfutils zlib \
linux-api-headers"
		CALY_DEPS_RUNTIME="libbpf iproute2 ethtool elfutils zlib"
		CALY_DEPS_OPTIONAL="bpf linux-headers linux-lts-headers \
linux-zen-headers linux-hardened-headers nftables iptables-nft ipset"
		;;
	suse)
		CALY_DEPS_BUILD="clang llvm make gcc \
libbpf-devel libelf-devel zlib-devel pkg-config linux-glibc-devel"
		CALY_DEPS_RUNTIME="libbpf1 libbpf0 libelf1 iproute2 ethtool"
		CALY_DEPS_OPTIONAL="bpftool kernel-devel kernel-default-devel \
nftables iptables ipset"
		;;
	alpine)
		# musl-dev and linux-headers are mandatory on Alpine: the UAPI
		# headers do not come with the libc package the way they do with
		# glibc distributions.
		CALY_DEPS_BUILD="clang llvm make gcc musl-dev linux-headers \
libbpf-dev elfutils-dev zlib-dev pkgconf"
		CALY_DEPS_RUNTIME="libbpf iproute2 ethtool zlib"
		CALY_DEPS_OPTIONAL="bpftool clang-dev llvm-dev nftables \
iptables ipset"
		;;
	gentoo)
		CALY_DEPS_BUILD="sys-devel/clang sys-devel/llvm dev-libs/libbpf \
virtual/libelf sys-libs/zlib dev-util/pkgconf"
		CALY_DEPS_RUNTIME="dev-libs/libbpf sys-apps/iproute2 \
sys-apps/ethtool"
		CALY_DEPS_OPTIONAL="dev-util/bpftool net-firewall/nftables \
net-firewall/iptables net-firewall/ipset"
		;;
	void)
		CALY_DEPS_BUILD="clang llvm make gcc libbpf-devel elfutils-devel \
zlib-devel pkg-config"
		CALY_DEPS_RUNTIME="libbpf iproute2 ethtool"
		CALY_DEPS_OPTIONAL="bpftool nftables iptables ipset"
		;;
	*)
		caly_warn "unknown distribution family '${CALY_OS_FAMILY}'; \
install clang(>=10), llvm, libbpf(+headers), libelf(+headers), zlib(+headers), \
make, a C compiler, bpftool and iproute2 by hand"
		;;
	esac

	unset caly_dl_kver
}

# ---------------------------------------------------------------------------
# Post-install verification
# ---------------------------------------------------------------------------
caly_deps_verify() {
	CALY_DETECTED=0
	caly_detect_toolchain
	caly_detect_libbpf
	caly_detect_bpftool
	CALY_DETECTED=1

	caly_dv_missing=""

	if [ "${CALY_CLANG_OK}" != "yes" ]; then
		caly_dv_missing="${caly_dv_missing} clang>=10"
	fi
	if [ "${CALY_LIBBPF_DEVEL}" != "yes" ]; then
		caly_dv_missing="${caly_dv_missing} libbpf-headers"
	fi
	if [ "${CALY_LIBELF_DEVEL}" != "yes" ]; then
		caly_dv_missing="${caly_dv_missing} libelf-headers"
	fi
	if [ -z "${CALY_MAKE}" ]; then
		caly_dv_missing="${caly_dv_missing} make"
	fi
	if [ -z "${CALY_CC}" ]; then
		caly_dv_missing="${caly_dv_missing} cc"
	fi

	if [ -z "${CALY_BPFTOOL}" ]; then
		caly_warn "bpftool was not installed. vmlinux.h will be generated \
from a bundled per-architecture header if one is shipped, otherwise the \
install degrades to the nftables dataplane."
	fi

	if [ -n "$caly_dv_missing" ]; then
		caly_warn "still missing after dependency install:${caly_dv_missing}"
		unset caly_dv_missing
		return 1
	fi

	# libbpf older than 0.7 has no libbpf_probe_bpf_helper(), which the
	# loader uses to decide whether to autoload the SYN proxy program.
	caly_deps_check_libbpf_version
	unset caly_dv_missing
	return 0
}

caly_deps_check_libbpf_version() {
	CALY_LIBBPF_MODERN="unknown"
	[ -n "${CALY_LIBBPF_VERSION}" ] || return 0

	caly_lv_maj=${CALY_LIBBPF_VERSION%%.*}
	caly_lv_rest=${CALY_LIBBPF_VERSION#*.}
	caly_lv_min=${caly_lv_rest%%.*}
	caly_lv_maj=${caly_lv_maj%%[!0-9]*}
	caly_lv_min=${caly_lv_min%%[!0-9]*}
	[ -n "$caly_lv_maj" ] || caly_lv_maj=0
	[ -n "$caly_lv_min" ] || caly_lv_min=0

	if [ "$caly_lv_maj" -ge 1 ] || \
	   { [ "$caly_lv_maj" -eq 0 ] && [ "$caly_lv_min" -ge 7 ]; }; then
		CALY_LIBBPF_MODERN="yes"
	else
		CALY_LIBBPF_MODERN="no"
		caly_warn "system libbpf ${CALY_LIBBPF_VERSION} is older than 0.7: \
libbpf_probe_bpf_helper() is unavailable, so the loader cannot probe for the \
5.15+ raw syncookie helpers. Build against a vendored libbpf, or accept that \
the SYN proxy stays disabled and the SYN rate-limit fallback is used."
	fi
	export CALY_LIBBPF_MODERN
	unset caly_lv_maj caly_lv_min caly_lv_rest
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
# caly_install_deps [build|runtime|all]
caly_install_deps() {
	caly_id_what=${1:-all}

	caly_detect_all
	caly_deps_lists

	if [ "${CALY_PKGMGR}" = "unknown" ]; then
		caly_warn "no supported package manager found; skipping dependency \
installation. Install the toolchain by hand or re-run with --no-deps."
		return 1
	fi
	if [ "${CALY_IS_ROOT}" != "yes" ] && [ "${CALY_DRY_RUN:-0}" != "1" ]; then
		caly_warn "not running as root; skipping dependency installation"
		return 1
	fi

	caly_info "Installing dependencies with ${CALY_PKGMGR} (${CALY_OS_ID} \
${CALY_OS_VERSION_ID:-?}, family ${CALY_OS_FAMILY})"

	caly_enable_extra_repos
	caly_pkg_refresh

	caly_id_rc=0

	if [ "$caly_id_what" = "all" ] || [ "$caly_id_what" = "runtime" ]; then
		caly_id_rt=$(caly_pkg_filter ${CALY_DEPS_RUNTIME})
		if [ -n "$caly_id_rt" ]; then
			# shellcheck disable=SC2086
			caly_pkg_install $caly_id_rt || caly_id_rc=1
		fi
	fi

	if [ "$caly_id_what" = "all" ] || [ "$caly_id_what" = "build" ]; then
		caly_id_bd=$(caly_pkg_filter ${CALY_DEPS_BUILD})
		if [ -n "$caly_id_bd" ]; then
			# shellcheck disable=SC2086
			caly_pkg_install $caly_id_bd || caly_id_rc=1
		fi
	fi

	# Optional packages: never allowed to fail the run.
	caly_id_op=$(caly_pkg_filter ${CALY_DEPS_OPTIONAL})
	if [ -n "$caly_id_op" ]; then
		# shellcheck disable=SC2086
		caly_pkg_install $caly_id_op || \
			caly_debug "some optional packages were not installed"
	fi

	# Ubuntu hides bpftool inside linux-tools-<uname -r> without putting it
	# in PATH. Provide a symlink so gen-vmlinux.sh and the operator find it.
	caly_deps_link_bpftool

	if [ "${CALY_DRY_RUN:-0}" != "1" ]; then
		caly_deps_verify || caly_id_rc=1
	fi

	unset caly_id_what caly_id_rt caly_id_bd caly_id_op
	return $caly_id_rc
}

caly_deps_link_bpftool() {
	caly_have bpftool && return 0
	[ "${CALY_IS_ROOT}" = "yes" ] || return 0

	for caly_lb_c in \
	    "/usr/lib/linux-tools/${CALY_KERNEL_RELEASE}/bpftool" \
	    "/usr/lib/linux-tools-${CALY_KERNEL_RELEASE}/bpftool" \
	    /usr/lib/linux-tools/*/bpftool; do
		if [ -x "$caly_lb_c" ]; then
			caly_step "linking ${caly_lb_c} -> /usr/local/sbin/bpftool"
			caly_run mkdir -p /usr/local/sbin
			caly_run ln -sf "$caly_lb_c" /usr/local/sbin/bpftool
			CALY_BPFTOOL="/usr/local/sbin/bpftool"
			export CALY_BPFTOOL CALY_BPFTOOL_LINKED=1
			break
		fi
	done
	unset caly_lb_c
	return 0
}

caly_deps_print() {
	caly_detect_all
	caly_deps_lists
	printf 'distribution : %s %s (family %s)\n' "${CALY_OS_ID}" \
		"${CALY_OS_VERSION_ID:-?}" "${CALY_OS_FAMILY}"
	printf 'package mgr  : %s\n' "${CALY_PKGMGR}"
	printf 'install cmd  : %s\n' "${CALY_PKG_INSTALL}"
	printf '\nbuild        : %s\n' "${CALY_DEPS_BUILD:-none}"
	printf 'runtime      : %s\n' "${CALY_DEPS_RUNTIME:-none}"
	printf 'optional     : %s\n' "${CALY_DEPS_OPTIONAL:-none}"
	if [ "${CALY_PKGMGR}" != "unknown" ]; then
		printf '\nafter filtering against this release:\n'
		printf '  build      : %s\n' "$(caly_pkg_filter ${CALY_DEPS_BUILD})"
		printf '  runtime    : %s\n' "$(caly_pkg_filter ${CALY_DEPS_RUNTIME})"
		printf '  optional   : %s\n' "$(caly_pkg_filter ${CALY_DEPS_OPTIONAL})"
	fi
}

caly_deps_usage() {
	cat <<'EOF'
Usage: deps.sh [OPTION]

  --all           install build and runtime dependencies (default)
  --build         install build dependencies only
  --runtime       install runtime dependencies only
  --list          print the dependency sets and exit, install nothing
  --dry-run       show the commands without running them
  --quiet         less output
  --help          this text

Package names are resolved per distribution and filtered against what the
local package manager actually offers, so names absent on a given release are
skipped rather than aborting the run.
EOF
}

caly_deps_main() {
	caly_dm_what="all"
	while [ $# -gt 0 ]; do
		case "$1" in
		--all)     caly_dm_what="all" ;;
		--build)   caly_dm_what="build" ;;
		--runtime) caly_dm_what="runtime" ;;
		--list)    caly_dm_what="list" ;;
		--dry-run) CALY_DRY_RUN=1 ;;
		--quiet|-q) CALY_QUIET=1 ;;
		--debug)   CALY_DEBUG=1 ;;
		--no-color) CALY_COLOR="never"; caly_init_colors ;;
		-h|--help) caly_deps_usage; return 0 ;;
		*) caly_err "deps.sh: unknown option '$1'"; caly_deps_usage >&2
		   return 2 ;;
		esac
		shift
	done

	if [ "$caly_dm_what" = "list" ]; then
		caly_deps_print
		return 0
	fi
	caly_install_deps "$caly_dm_what"
}

case "${0##*/}" in
deps.sh)
	set -u
	caly_deps_main "$@"
	exit $?
	;;
esac
