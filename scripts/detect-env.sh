#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Caly Anti - scripts/detect-env.sh
#
# Sourceable environment-detection library. Everything the installer, the
# dependency installer and the uninstaller need to know about the machine is
# discovered here, exactly once, and exported as CALY_* variables.
#
# POSIX sh only. It must run under dash (Debian/Ubuntu), busybox ash (Alpine),
# bash (RHEL/Arch/SUSE) and ksh-ish shells without modification. No bashisms,
# no arrays, no [[ ]], no process substitution.
#
# Usage:
#
#   as a library
#       . /path/to/detect-env.sh
#       caly_detect_all
#       echo "$CALY_DATAPLANE_BEST"
#
#   standalone
#       ./detect-env.sh --report      human readable table (default)
#       ./detect-env.sh --export      CALY_x='y' lines, safe to eval
#       ./detect-env.sh --brief       one line summary
#       ./detect-env.sh --get VAR     print a single variable
#
# Detection is best effort and NEVER fatal: a missing tool sets a variable to
# "no"/"unknown" and the caller decides what that means. Nothing in here
# modifies the system.

# Guard against double sourcing (install.sh sources deps.sh which sources us).
if [ "${CALY_DETECT_ENV_LOADED:-0}" = "1" ]; then
	return 0 2>/dev/null || true
fi
CALY_DETECT_ENV_LOADED=1

# Version of this detection library, bumped when variables are added/removed.
CALY_DETECT_VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Output helpers. Shared by every script in the suite.
# ---------------------------------------------------------------------------

CALY_C_RESET=''
CALY_C_BOLD=''
CALY_C_RED=''
CALY_C_GREEN=''
CALY_C_YELLOW=''
CALY_C_BLUE=''
CALY_C_DIM=''

caly_init_colors() {
	CALY_C_RESET=''
	CALY_C_BOLD=''
	CALY_C_RED=''
	CALY_C_GREEN=''
	CALY_C_YELLOW=''
	CALY_C_BLUE=''
	CALY_C_DIM=''
	if [ "${CALY_COLOR:-auto}" = "never" ] || [ -n "${NO_COLOR:-}" ]; then
		return 0
	fi
	if [ "${CALY_COLOR:-auto}" != "always" ] && [ ! -t 1 ]; then
		return 0
	fi
	case "${TERM:-dumb}" in
	dumb|'') [ "${CALY_COLOR:-auto}" = "always" ] || return 0 ;;
	esac
	CALY_C_RESET=$(printf '\033[0m')
	CALY_C_BOLD=$(printf '\033[1m')
	CALY_C_RED=$(printf '\033[31m')
	CALY_C_GREEN=$(printf '\033[32m')
	CALY_C_YELLOW=$(printf '\033[33m')
	CALY_C_BLUE=$(printf '\033[36m')
	CALY_C_DIM=$(printf '\033[2m')
}
caly_init_colors

# caly_say  - always printed (unless --quiet)
# caly_info - progress chatter
# caly_warn - non fatal problem, goes to stderr
# caly_err  - fatal-ish problem, goes to stderr
# caly_die  - err + exit 1
caly_say() {
	[ "${CALY_QUIET:-0}" = "1" ] && return 0
	printf '%s\n' "$*"
}

caly_info() {
	[ "${CALY_QUIET:-0}" = "1" ] && return 0
	printf '%s==>%s %s\n' "${CALY_C_BLUE}" "${CALY_C_RESET}" "$*"
}

caly_step() {
	[ "${CALY_QUIET:-0}" = "1" ] && return 0
	printf '%s  ->%s %s\n' "${CALY_C_DIM}" "${CALY_C_RESET}" "$*"
}

caly_ok() {
	[ "${CALY_QUIET:-0}" = "1" ] && return 0
	printf '%s  ok%s  %s\n' "${CALY_C_GREEN}" "${CALY_C_RESET}" "$*"
}

caly_warn() {
	printf '%swarning:%s %s\n' "${CALY_C_YELLOW}" "${CALY_C_RESET}" "$*" >&2
	CALY_WARN_COUNT=$(( ${CALY_WARN_COUNT:-0} + 1 ))
}

caly_err() {
	printf '%serror:%s %s\n' "${CALY_C_RED}" "${CALY_C_RESET}" "$*" >&2
	CALY_ERR_COUNT=$(( ${CALY_ERR_COUNT:-0} + 1 ))
}

caly_die() {
	caly_err "$@"
	exit 1
}

caly_debug() {
	[ "${CALY_DEBUG:-0}" = "1" ] || return 0
	printf '%s[debug]%s %s\n' "${CALY_C_DIM}" "${CALY_C_RESET}" "$*" >&2
}

# Is a command available?
caly_have() {
	command -v "$1" >/dev/null 2>&1
}

# Print the absolute path of a command, or nothing.
caly_which() {
	command -v "$1" 2>/dev/null || true
}

# Run a command, honouring CALY_DRY_RUN. Used by install.sh/uninstall.sh; it
# lives here so every script gets identical dry-run semantics.
caly_run() {
	if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
		printf '%s  [dry-run]%s %s\n' "${CALY_C_DIM}" "${CALY_C_RESET}" "$*"
		return 0
	fi
	caly_debug "run: $*"
	"$@"
}

# Same, but failures are reported and swallowed. For teardown paths where a
# missing object is normal.
caly_try() {
	if [ "${CALY_DRY_RUN:-0}" = "1" ]; then
		printf '%s  [dry-run]%s %s\n' "${CALY_C_DIM}" "${CALY_C_RESET}" "$*"
		return 0
	fi
	caly_debug "try: $*"
	"$@" >/dev/null 2>&1 || return 0
}

# First line of a file, empty when unreadable.
caly_first_line() {
	[ -r "$1" ] || return 0
	while IFS= read -r caly_fl_line || [ -n "$caly_fl_line" ]; do
		printf '%s\n' "$caly_fl_line"
		break
	done < "$1"
	unset caly_fl_line
}

# Trim leading/trailing whitespace of $1.
caly_trim() {
	caly_tr_s=$1
	while :; do
		case "$caly_tr_s" in
		" "*|"	"*) caly_tr_s=${caly_tr_s#?} ;;
		*) break ;;
		esac
	done
	while :; do
		case "$caly_tr_s" in
		*" "|*"	") caly_tr_s=${caly_tr_s%?} ;;
		*) break ;;
		esac
	done
	printf '%s' "$caly_tr_s"
	unset caly_tr_s
}

# Strip surrounding single or double quotes.
caly_unquote() {
	caly_uq_s=$1
	case "$caly_uq_s" in
	\"*\") caly_uq_s=${caly_uq_s#\"}; caly_uq_s=${caly_uq_s%\"} ;;
	\'*\') caly_uq_s=${caly_uq_s#\'}; caly_uq_s=${caly_uq_s%\'} ;;
	esac
	printf '%s' "$caly_uq_s"
	unset caly_uq_s
}

# ---------------------------------------------------------------------------
# The variable inventory. Used by --export, --report and caly_export_all.
# Keep in sync with the setters below.
# ---------------------------------------------------------------------------
CALY_VARS="
CALY_DETECT_VERSION
CALY_OS_ID CALY_OS_ID_LIKE CALY_OS_NAME CALY_OS_PRETTY
CALY_OS_VERSION_ID CALY_OS_VERSION_MAJOR CALY_OS_FAMILY
CALY_PKGMGR CALY_PKG_INSTALL CALY_PKG_REFRESH CALY_PKG_QUERY
CALY_INIT CALY_INIT_VERSION CALY_SYSTEMD_UNIT_DIR
CALY_LIBC CALY_LIBC_VERSION
CALY_ARCH CALY_ARCH_BPF CALY_ARCH_TARGET CALY_NPROC CALY_MEM_TOTAL_KB
CALY_KERNEL_RELEASE CALY_KERNEL_MAJOR CALY_KERNEL_MINOR CALY_KERNEL_PATCH
CALY_KERNEL_CODE CALY_KERNEL_VENDOR
CALY_HAVE_BTF CALY_BTF_PATH CALY_BTF_SIZE
CALY_BPFFS CALY_BPFFS_MOUNTED
CALY_HAVE_BPF_SYSCALL CALY_HAVE_CLS_BPF CALY_HAVE_BPF_JIT CALY_KCONFIG
CALY_CLANG CALY_CLANG_VERSION CALY_CLANG_MAJOR CALY_CLANG_OK
CALY_LLVM_STRIP CALY_CC CALY_MAKE CALY_PKGCONFIG
CALY_LIBBPF CALY_LIBBPF_VERSION CALY_LIBBPF_DEVEL CALY_LIBELF_DEVEL
CALY_ZLIB_DEVEL CALY_KERNEL_HEADERS
CALY_BPFTOOL CALY_BPFTOOL_VERSION
CALY_VIRT CALY_VIRT_TYPE CALY_CONTAINER
CALY_NICS CALY_NIC_COUNT CALY_NIC_TABLE CALY_DEFAULT_IFACE CALY_DEFAULT_DRIVER
CALY_HAVE_NFT CALY_NFT_VERSION CALY_HAVE_IPTABLES CALY_HAVE_IP6TABLES
CALY_HAVE_IPSET CALY_HAVE_TC CALY_HAVE_IP CALY_HAVE_ETHTOOL CALY_HAVE_SS
CALY_XDP_OK CALY_XDP_MODE_BEST CALY_BPF_OK
CALY_CAP_SYNPROXY CALY_CAP_RINGBUF
CALY_DATAPLANE_BEST CALY_DATAPLANE_REASON
CALY_IS_ROOT CALY_SELINUX
"

caly_export_all() {
	for caly_ea_v in $CALY_VARS; do
		export "$caly_ea_v" 2>/dev/null || true
	done
	unset caly_ea_v
}

# ---------------------------------------------------------------------------
# 1. Operating system identity
# ---------------------------------------------------------------------------
caly_detect_os() {
	CALY_OS_ID="unknown"
	CALY_OS_ID_LIKE=""
	CALY_OS_NAME="unknown"
	CALY_OS_PRETTY="unknown"
	CALY_OS_VERSION_ID=""
	CALY_OS_VERSION_MAJOR=""
	CALY_OS_FAMILY="unknown"

	caly_os_file=""
	for caly_os_c in /etc/os-release /usr/lib/os-release /run/host/os-release; do
		if [ -r "$caly_os_c" ]; then
			caly_os_file=$caly_os_c
			break
		fi
	done

	if [ -n "$caly_os_file" ]; then
		# Parse by hand rather than sourcing: os-release is *mostly*
		# shell syntax but a hostile or broken file must not execute.
		while IFS= read -r caly_os_line || [ -n "$caly_os_line" ]; do
			case "$caly_os_line" in
			\#*|'') continue ;;
			esac
			caly_os_k=${caly_os_line%%=*}
			caly_os_v=${caly_os_line#*=}
			[ "$caly_os_k" = "$caly_os_line" ] && continue
			caly_os_v=$(caly_unquote "$caly_os_v")
			case "$caly_os_k" in
			ID)         CALY_OS_ID=$caly_os_v ;;
			ID_LIKE)    CALY_OS_ID_LIKE=$caly_os_v ;;
			NAME)       CALY_OS_NAME=$caly_os_v ;;
			PRETTY_NAME) CALY_OS_PRETTY=$caly_os_v ;;
			VERSION_ID) CALY_OS_VERSION_ID=$caly_os_v ;;
			esac
		done < "$caly_os_file"
	fi

	# Fallbacks for pre-os-release systems (RHEL 6 era, old SUSE, Slackware).
	if [ "$CALY_OS_ID" = "unknown" ]; then
		if [ -r /etc/redhat-release ]; then
			CALY_OS_PRETTY=$(caly_first_line /etc/redhat-release)
			case "$CALY_OS_PRETTY" in
			*CentOS*) CALY_OS_ID="centos" ;;
			*Rocky*)  CALY_OS_ID="rocky" ;;
			*Alma*)   CALY_OS_ID="almalinux" ;;
			*Fedora*) CALY_OS_ID="fedora" ;;
			*Oracle*) CALY_OS_ID="ol" ;;
			*)        CALY_OS_ID="rhel" ;;
			esac
			CALY_OS_VERSION_ID=$(printf '%s\n' "$CALY_OS_PRETTY" | \
				sed -n 's/.*release \([0-9][0-9.]*\).*/\1/p')
		elif [ -r /etc/debian_version ]; then
			CALY_OS_ID="debian"
			CALY_OS_VERSION_ID=$(caly_first_line /etc/debian_version)
			CALY_OS_PRETTY="Debian $CALY_OS_VERSION_ID"
		elif [ -r /etc/alpine-release ]; then
			CALY_OS_ID="alpine"
			CALY_OS_VERSION_ID=$(caly_first_line /etc/alpine-release)
			CALY_OS_PRETTY="Alpine Linux $CALY_OS_VERSION_ID"
		elif [ -r /etc/arch-release ]; then
			CALY_OS_ID="arch"
			CALY_OS_PRETTY="Arch Linux"
		elif [ -r /etc/SuSE-release ]; then
			CALY_OS_ID="suse"
			CALY_OS_PRETTY=$(caly_first_line /etc/SuSE-release)
		elif [ -r /etc/gentoo-release ]; then
			CALY_OS_ID="gentoo"
			CALY_OS_PRETTY=$(caly_first_line /etc/gentoo-release)
		fi
	fi

	[ "$CALY_OS_NAME" = "unknown" ] && [ "$CALY_OS_PRETTY" != "unknown" ] && \
		CALY_OS_NAME=$CALY_OS_PRETTY

	CALY_OS_VERSION_MAJOR=${CALY_OS_VERSION_ID%%.*}
	CALY_OS_VERSION_MAJOR=${CALY_OS_VERSION_MAJOR%%[!0-9]*}

	# Family drives package names, init defaults and path layout.
	case "$CALY_OS_ID" in
	rhel|centos|almalinux|rocky|fedora|ol|oraclelinux|amzn|scientific|\
	circle|eurolinux|navylinux|virtuozzo|cloudlinux|springdale)
		CALY_OS_FAMILY="rhel" ;;
	debian|ubuntu|linuxmint|pop|elementary|neon|raspbian|devuan|kali|\
	parrot|zorin|deepin|mx|tuxedo|pureos|trisquel)
		CALY_OS_FAMILY="debian" ;;
	arch|archarm|manjaro|endeavouros|artix|garuda|cachyos|arcolinux)
		CALY_OS_FAMILY="arch" ;;
	opensuse|opensuse-leap|opensuse-tumbleweed|opensuse-microos|sles|sled|\
	sle-micro|suse)
		CALY_OS_FAMILY="suse" ;;
	alpine|postmarketos)
		CALY_OS_FAMILY="alpine" ;;
	gentoo|funtoo|calculate)
		CALY_OS_FAMILY="gentoo" ;;
	void)
		CALY_OS_FAMILY="void" ;;
	*)
		# Derive from ID_LIKE when the distro is a derivative we do not
		# know by name. ID_LIKE is a space separated list, best first.
		for caly_os_l in $CALY_OS_ID_LIKE; do
			case "$caly_os_l" in
			rhel|fedora|centos) CALY_OS_FAMILY="rhel"; break ;;
			debian|ubuntu)      CALY_OS_FAMILY="debian"; break ;;
			arch)               CALY_OS_FAMILY="arch"; break ;;
			suse|opensuse)      CALY_OS_FAMILY="suse"; break ;;
			alpine)             CALY_OS_FAMILY="alpine"; break ;;
			gentoo)             CALY_OS_FAMILY="gentoo"; break ;;
			esac
		done ;;
	esac

	unset caly_os_file caly_os_c caly_os_line caly_os_k caly_os_v caly_os_l
}

# ---------------------------------------------------------------------------
# 2. Package manager
# ---------------------------------------------------------------------------
caly_detect_pkgmgr() {
	CALY_PKGMGR="unknown"
	CALY_PKG_INSTALL=""
	CALY_PKG_REFRESH=""
	CALY_PKG_QUERY=""

	# Probe by binary, ordered so the modern tool wins on systems that ship
	# both (dnf+yum on RHEL8, apt+apt-get everywhere Debian).
	if caly_have dnf5; then
		CALY_PKGMGR="dnf5"
		CALY_PKG_INSTALL="dnf5 install -y"
		CALY_PKG_REFRESH="dnf5 makecache"
		CALY_PKG_QUERY="rpm -q"
	elif caly_have dnf; then
		CALY_PKGMGR="dnf"
		CALY_PKG_INSTALL="dnf install -y"
		CALY_PKG_REFRESH="dnf makecache"
		CALY_PKG_QUERY="rpm -q"
	elif caly_have yum; then
		CALY_PKGMGR="yum"
		CALY_PKG_INSTALL="yum install -y"
		CALY_PKG_REFRESH="yum makecache"
		CALY_PKG_QUERY="rpm -q"
	elif caly_have apt-get; then
		CALY_PKGMGR="apt"
		CALY_PKG_INSTALL="apt-get install -y --no-install-recommends"
		CALY_PKG_REFRESH="apt-get update"
		CALY_PKG_QUERY="dpkg-query -W -f=\${Status}"
	elif caly_have pacman; then
		CALY_PKGMGR="pacman"
		CALY_PKG_INSTALL="pacman -S --needed --noconfirm"
		CALY_PKG_REFRESH="pacman -Sy"
		CALY_PKG_QUERY="pacman -Q"
	elif caly_have zypper; then
		CALY_PKGMGR="zypper"
		CALY_PKG_INSTALL="zypper --non-interactive install --no-recommends"
		CALY_PKG_REFRESH="zypper --non-interactive refresh"
		CALY_PKG_QUERY="rpm -q"
	elif caly_have apk; then
		CALY_PKGMGR="apk"
		CALY_PKG_INSTALL="apk add --no-cache"
		CALY_PKG_REFRESH="apk update"
		CALY_PKG_QUERY="apk info -e"
	elif caly_have emerge; then
		CALY_PKGMGR="emerge"
		CALY_PKG_INSTALL="emerge --noreplace"
		CALY_PKG_REFRESH="true"
		CALY_PKG_QUERY="qlist -I"
	elif caly_have xbps-install; then
		CALY_PKGMGR="xbps"
		CALY_PKG_INSTALL="xbps-install -y"
		CALY_PKG_REFRESH="xbps-install -S"
		CALY_PKG_QUERY="xbps-query"
	fi
}

# ---------------------------------------------------------------------------
# 3. Init system
# ---------------------------------------------------------------------------
caly_detect_init() {
	CALY_INIT="unknown"
	CALY_INIT_VERSION=""
	CALY_SYSTEMD_UNIT_DIR=""

	# PID 1 identity is authoritative; the presence of /usr/bin/systemctl in
	# a container that runs something else is not.
	caly_in_comm=""
	[ -r /proc/1/comm ] && caly_in_comm=$(caly_first_line /proc/1/comm)

	case "$caly_in_comm" in
	systemd)          CALY_INIT="systemd" ;;
	init)
		if [ -d /run/openrc ] || [ -x /sbin/openrc-run ] || \
		   [ -x /usr/bin/openrc-run ]; then
			CALY_INIT="openrc"
		else
			CALY_INIT="sysvinit"
		fi ;;
	openrc-init)      CALY_INIT="openrc" ;;
	runit|runsvdir)   CALY_INIT="runit" ;;
	s6-svscan)        CALY_INIT="s6" ;;
	dinit)            CALY_INIT="dinit" ;;
	busybox)          CALY_INIT="busybox" ;;
	esac

	if [ "$CALY_INIT" = "unknown" ]; then
		if [ -d /run/systemd/system ]; then
			CALY_INIT="systemd"
		elif [ -x /sbin/openrc-run ] || [ -x /usr/bin/openrc-run ] || \
		     [ -d /run/openrc ]; then
			CALY_INIT="openrc"
		elif [ -d /etc/init.d ]; then
			CALY_INIT="sysvinit"
		fi
	fi

	if [ "$CALY_INIT" = "systemd" ]; then
		if caly_have systemctl; then
			CALY_INIT_VERSION=$(systemctl --version 2>/dev/null | \
				sed -n '1s/^systemd \([0-9][0-9]*\).*/\1/p')
		fi
		if caly_have pkg-config; then
			CALY_SYSTEMD_UNIT_DIR=$(pkg-config --variable=systemdsystemunitdir \
				systemd 2>/dev/null || true)
		fi
		if [ -z "$CALY_SYSTEMD_UNIT_DIR" ]; then
			if [ -d /usr/lib/systemd/system ]; then
				CALY_SYSTEMD_UNIT_DIR="/usr/lib/systemd/system"
			elif [ -d /lib/systemd/system ]; then
				CALY_SYSTEMD_UNIT_DIR="/lib/systemd/system"
			else
				CALY_SYSTEMD_UNIT_DIR="/etc/systemd/system"
			fi
		fi
	elif [ "$CALY_INIT" = "openrc" ]; then
		if caly_have openrc; then
			CALY_INIT_VERSION=$(openrc --version 2>/dev/null | \
				sed -n '1s/.*openrc[^0-9]*\([0-9][0-9.]*\).*/\1/p')
		fi
	fi

	unset caly_in_comm
}

# ---------------------------------------------------------------------------
# 4. libc
# ---------------------------------------------------------------------------
caly_detect_libc() {
	CALY_LIBC="unknown"
	CALY_LIBC_VERSION=""

	if caly_have ldd; then
		caly_lc_out=$(ldd --version 2>&1 | sed -n '1p') || caly_lc_out=""
		case "$caly_lc_out" in
		*musl*)
			CALY_LIBC="musl" ;;
		*GNU*|*GLIBC*|*glibc*)
			CALY_LIBC="glibc"
			CALY_LIBC_VERSION=$(printf '%s\n' "$caly_lc_out" | \
				sed -n 's/.*[^0-9]\([0-9][0-9]*\.[0-9][0-9]*\)$/\1/p') ;;
		esac
		if [ "$CALY_LIBC" = "musl" ]; then
			CALY_LIBC_VERSION=$(ldd 2>&1 | \
				sed -n 's/^Version \([0-9][0-9.]*\)$/\1/p' | sed -n 1p)
		fi
	fi

	if [ "$CALY_LIBC" = "unknown" ]; then
		# musl ships /lib/ld-musl-<arch>.so.1; glibc ships libc.so.6.
		for caly_lc_f in /lib/ld-musl-*.so.1 /lib/libc.musl-*.so.1; do
			[ -e "$caly_lc_f" ] && { CALY_LIBC="musl"; break; }
		done
	fi
	if [ "$CALY_LIBC" = "unknown" ]; then
		for caly_lc_f in /lib64/libc.so.6 /lib/libc.so.6 \
		    /lib/*/libc.so.6; do
			[ -e "$caly_lc_f" ] && { CALY_LIBC="glibc"; break; }
		done
	fi
	# Alpine and postmarketOS are musl by definition.
	if [ "$CALY_LIBC" = "unknown" ] && [ "${CALY_OS_FAMILY:-}" = "alpine" ]; then
		CALY_LIBC="musl"
	fi

	unset caly_lc_out caly_lc_f
}

# ---------------------------------------------------------------------------
# 5. Architecture and machine size
# ---------------------------------------------------------------------------
caly_detect_arch() {
	CALY_ARCH=$(uname -m 2>/dev/null || echo unknown)

	# The directory name the kernel uses under arch/, which is also the
	# naming convention for bundled per-arch vmlinux.h files.
	case "$CALY_ARCH" in
	x86_64|amd64)      CALY_ARCH_BPF="x86";     CALY_ARCH_TARGET="x86_64" ;;
	i386|i486|i586|i686) CALY_ARCH_BPF="x86";   CALY_ARCH_TARGET="i386" ;;
	aarch64|arm64)     CALY_ARCH_BPF="arm64";   CALY_ARCH_TARGET="aarch64" ;;
	armv6l|armv7l|arm) CALY_ARCH_BPF="arm";     CALY_ARCH_TARGET="arm" ;;
	ppc64le|ppc64)     CALY_ARCH_BPF="powerpc"; CALY_ARCH_TARGET="powerpc64le" ;;
	s390x)             CALY_ARCH_BPF="s390";    CALY_ARCH_TARGET="s390x" ;;
	riscv64)           CALY_ARCH_BPF="riscv";   CALY_ARCH_TARGET="riscv64" ;;
	mips*)             CALY_ARCH_BPF="mips";    CALY_ARCH_TARGET="mips" ;;
	loongarch64)       CALY_ARCH_BPF="loongarch"; CALY_ARCH_TARGET="loongarch64" ;;
	*)                 CALY_ARCH_BPF="$CALY_ARCH"; CALY_ARCH_TARGET="$CALY_ARCH" ;;
	esac

	CALY_NPROC=1
	if caly_have nproc; then
		CALY_NPROC=$(nproc 2>/dev/null || echo 1)
	elif [ -r /proc/cpuinfo ]; then
		CALY_NPROC=$(grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo 1)
	fi
	case "$CALY_NPROC" in
	''|*[!0-9]*) CALY_NPROC=1 ;;
	esac

	CALY_MEM_TOTAL_KB=0
	if [ -r /proc/meminfo ]; then
		CALY_MEM_TOTAL_KB=$(sed -n 's/^MemTotal:[ \t]*\([0-9][0-9]*\) kB$/\1/p' \
			/proc/meminfo 2>/dev/null | sed -n 1p)
		case "$CALY_MEM_TOTAL_KB" in
		''|*[!0-9]*) CALY_MEM_TOTAL_KB=0 ;;
		esac
	fi

	CALY_IS_ROOT="no"
	if [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
		CALY_IS_ROOT="yes"
	fi

	CALY_SELINUX="no"
	if [ -d /sys/fs/selinux ] && caly_have getenforce; then
		CALY_SELINUX=$(getenforce 2>/dev/null | tr 'A-Z' 'a-z' || echo no)
	elif [ -r /sys/fs/selinux/enforce ]; then
		if [ "$(caly_first_line /sys/fs/selinux/enforce)" = "1" ]; then
			CALY_SELINUX="enforcing"
		else
			CALY_SELINUX="permissive"
		fi
	fi
}

# ---------------------------------------------------------------------------
# 6. Kernel version
#
# `uname -r` on a RHEL 8 box is 4.18.0-553.el8_10.x86_64. Everything after the
# first '-' is distro packaging, not upstream version. The parsed triple is a
# HINT only: RHEL backports 5.x features into 4.18 wholesale, so real feature
# gating is done by probing (BTF file, bpftool feature probe, libbpf helper
# probe in the loader), never by comparing to a version number alone.
# ---------------------------------------------------------------------------
caly_detect_kernel() {
	CALY_KERNEL_RELEASE=$(uname -r 2>/dev/null || echo 0.0.0)
	CALY_KERNEL_VENDOR="upstream"

	caly_kv_base=${CALY_KERNEL_RELEASE%%-*}

	caly_kv_maj=${caly_kv_base%%.*}
	caly_kv_rest=${caly_kv_base#*.}
	if [ "$caly_kv_rest" = "$caly_kv_base" ]; then
		caly_kv_min=0
		caly_kv_pat=0
	else
		caly_kv_min=${caly_kv_rest%%.*}
		caly_kv_p=${caly_kv_rest#*.}
		if [ "$caly_kv_p" = "$caly_kv_rest" ]; then
			caly_kv_pat=0
		else
			caly_kv_pat=$caly_kv_p
		fi
	fi

	# Strip any trailing non-digits (e.g. "0rc1", "10+").
	caly_kv_maj=${caly_kv_maj%%[!0-9]*}
	caly_kv_min=${caly_kv_min%%[!0-9]*}
	caly_kv_pat=${caly_kv_pat%%[!0-9]*}
	[ -n "$caly_kv_maj" ] || caly_kv_maj=0
	[ -n "$caly_kv_min" ] || caly_kv_min=0
	[ -n "$caly_kv_pat" ] || caly_kv_pat=0
	[ "$caly_kv_pat" -gt 255 ] 2>/dev/null && caly_kv_pat=255

	CALY_KERNEL_MAJOR=$caly_kv_maj
	CALY_KERNEL_MINOR=$caly_kv_min
	CALY_KERNEL_PATCH=$caly_kv_pat
	CALY_KERNEL_CODE=$(( caly_kv_maj * 65536 + caly_kv_min * 256 + caly_kv_pat ))

	case "$CALY_KERNEL_RELEASE" in
	*.el7*|*.el7.*)   CALY_KERNEL_VENDOR="rhel7" ;;
	*.el8*)           CALY_KERNEL_VENDOR="rhel8" ;;
	*.el9*)           CALY_KERNEL_VENDOR="rhel9" ;;
	*.el10*)          CALY_KERNEL_VENDOR="rhel10" ;;
	*.amzn2023*)      CALY_KERNEL_VENDOR="amzn2023" ;;
	*.amzn2*)         CALY_KERNEL_VENDOR="amzn2" ;;
	*-generic|*-aws|*-azure|*-gcp|*-oracle|*-kvm)
	                  CALY_KERNEL_VENDOR="ubuntu" ;;
	*-cloud-amd64|*-amd64|*-arm64|*-rt-amd64)
	                  CALY_KERNEL_VENDOR="debian" ;;
	*-lts|*-virt|*-rpi) CALY_KERNEL_VENDOR="alpine" ;;
	*-default|*-preempt) CALY_KERNEL_VENDOR="suse" ;;
	*-arch*|*-zen*|*-hardened*) CALY_KERNEL_VENDOR="arch" ;;
	esac

	unset caly_kv_base caly_kv_maj caly_kv_min caly_kv_pat caly_kv_rest caly_kv_p
}

# caly_kver_ge MAJOR MINOR -> 0 when the running kernel is at least MAJOR.MINOR
caly_kver_ge() {
	caly_kg_want=$(( $1 * 65536 + $2 * 256 ))
	[ "${CALY_KERNEL_CODE:-0}" -ge "$caly_kg_want" ]
}

# ---------------------------------------------------------------------------
# 7. BTF, bpffs and kernel config
# ---------------------------------------------------------------------------
caly_detect_btf() {
	CALY_HAVE_BTF="no"
	CALY_BTF_PATH=""
	CALY_BTF_SIZE=0

	if [ -r /sys/kernel/btf/vmlinux ]; then
		# Size via wc -c: sysfs BTF has no stat size on some kernels.
		CALY_BTF_SIZE=$(wc -c < /sys/kernel/btf/vmlinux 2>/dev/null || echo 0)
		case "$CALY_BTF_SIZE" in
		''|*[!0-9]*) CALY_BTF_SIZE=0 ;;
		esac
		if [ "$CALY_BTF_SIZE" -gt 4096 ]; then
			CALY_HAVE_BTF="yes"
			CALY_BTF_PATH="/sys/kernel/btf/vmlinux"
		fi
	fi

	if [ "$CALY_HAVE_BTF" = "no" ]; then
		# Split debug BTF shipped by some distros.
		for caly_bt_c in \
		    "/boot/vmlinux-${CALY_KERNEL_RELEASE}" \
		    "/lib/modules/${CALY_KERNEL_RELEASE}/vmlinux" \
		    "/lib/modules/${CALY_KERNEL_RELEASE}/build/vmlinux" \
		    "/usr/lib/debug/boot/vmlinux-${CALY_KERNEL_RELEASE}" \
		    "/usr/lib/debug/lib/modules/${CALY_KERNEL_RELEASE}/vmlinux"; do
			if [ -r "$caly_bt_c" ]; then
				CALY_BTF_PATH=$caly_bt_c
				CALY_HAVE_BTF="maybe"
				break
			fi
		done
	fi
	unset caly_bt_c
}

caly_detect_bpffs() {
	CALY_BPFFS="/sys/fs/bpf"
	CALY_BPFFS_MOUNTED="no"

	if [ -r /proc/mounts ]; then
		if awk '$3 == "bpf" { found=1 } END { exit !found }' \
		    /proc/mounts 2>/dev/null; then
			CALY_BPFFS=$(awk '$3 == "bpf" { print $2; exit }' \
				/proc/mounts 2>/dev/null)
			[ -n "$CALY_BPFFS" ] || CALY_BPFFS="/sys/fs/bpf"
			CALY_BPFFS_MOUNTED="yes"
		fi
	fi
}

caly_detect_kconfig() {
	CALY_KCONFIG=""
	CALY_HAVE_BPF_SYSCALL="unknown"
	CALY_HAVE_CLS_BPF="unknown"
	CALY_HAVE_BPF_JIT="unknown"

	caly_kc_reader=""
	if [ -r /proc/config.gz ] && caly_have zcat; then
		CALY_KCONFIG="/proc/config.gz"
		caly_kc_reader="zcat"
	else
		for caly_kc_c in \
		    "/boot/config-${CALY_KERNEL_RELEASE}" \
		    "/lib/modules/${CALY_KERNEL_RELEASE}/config" \
		    "/lib/modules/${CALY_KERNEL_RELEASE}/build/.config" \
		    "/usr/lib/kernel/config-${CALY_KERNEL_RELEASE}" \
		    /boot/config; do
			if [ -r "$caly_kc_c" ]; then
				CALY_KCONFIG=$caly_kc_c
				caly_kc_reader="cat"
				break
			fi
		done
	fi

	if [ -n "$caly_kc_reader" ] && [ -n "$CALY_KCONFIG" ]; then
		caly_kc_data=$($caly_kc_reader "$CALY_KCONFIG" 2>/dev/null || true)
		CALY_HAVE_BPF_SYSCALL="no"
		CALY_HAVE_CLS_BPF="no"
		CALY_HAVE_BPF_JIT="no"
		case "$caly_kc_data" in
		*"CONFIG_BPF_SYSCALL=y"*) CALY_HAVE_BPF_SYSCALL="yes" ;;
		esac
		case "$caly_kc_data" in
		*"CONFIG_NET_CLS_BPF=y"*|*"CONFIG_NET_CLS_BPF=m"*)
			CALY_HAVE_CLS_BPF="yes" ;;
		esac
		case "$caly_kc_data" in
		*"CONFIG_BPF_JIT=y"*) CALY_HAVE_BPF_JIT="yes" ;;
		esac
		unset caly_kc_data
	fi

	# A readable /sys/fs/bpf or a working bpftool is stronger evidence than
	# an absent kernel config file.
	if [ "$CALY_HAVE_BPF_SYSCALL" = "unknown" ]; then
		if [ -d /sys/fs/bpf ]; then
			CALY_HAVE_BPF_SYSCALL="yes"
		fi
	fi

	unset caly_kc_reader caly_kc_c
}

# ---------------------------------------------------------------------------
# 8. Build toolchain
# ---------------------------------------------------------------------------
caly_detect_toolchain() {
	CALY_CLANG=""
	CALY_CLANG_VERSION=""
	CALY_CLANG_MAJOR=0
	CALY_CLANG_OK="no"
	CALY_LLVM_STRIP=""
	CALY_CC=""
	CALY_MAKE=""
	CALY_PKGCONFIG=""

	# Prefer plain `clang`; if it is missing or too old, walk the versioned
	# names Debian/Ubuntu and Alpine install (clang-18, clang-17, ...).
	for caly_tc_c in clang clang-20 clang-19 clang-18 clang-17 clang-16 \
	    clang-15 clang-14 clang-13 clang-12 clang-11 clang-10; do
		caly_have "$caly_tc_c" || continue
		caly_tc_ver=$("$caly_tc_c" --version 2>/dev/null | \
			sed -n '1s/.*version \([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
		[ -n "$caly_tc_ver" ] || continue
		caly_tc_maj=${caly_tc_ver%%.*}
		case "$caly_tc_maj" in
		''|*[!0-9]*) continue ;;
		esac
		if [ "$caly_tc_maj" -gt "$CALY_CLANG_MAJOR" ]; then
			CALY_CLANG=$(caly_which "$caly_tc_c")
			CALY_CLANG_VERSION=$caly_tc_ver
			CALY_CLANG_MAJOR=$caly_tc_maj
		fi
	done

	if [ "$CALY_CLANG_MAJOR" -ge 10 ]; then
		CALY_CLANG_OK="yes"
	elif [ "$CALY_CLANG_MAJOR" -gt 0 ]; then
		CALY_CLANG_OK="too-old"
	fi

	for caly_tc_c in llvm-strip llvm-strip-20 llvm-strip-19 llvm-strip-18 \
	    llvm-strip-17 llvm-strip-16 llvm-strip-15 llvm-strip-14 \
	    llvm-strip-13 llvm-strip-12 llvm-strip-11 llvm-strip-10; do
		if caly_have "$caly_tc_c"; then
			CALY_LLVM_STRIP=$(caly_which "$caly_tc_c")
			break
		fi
	done

	for caly_tc_c in gcc cc clang; do
		if caly_have "$caly_tc_c"; then
			CALY_CC=$(caly_which "$caly_tc_c")
			break
		fi
	done
	for caly_tc_c in gmake make; do
		if caly_have "$caly_tc_c"; then
			CALY_MAKE=$(caly_which "$caly_tc_c")
			break
		fi
	done
	for caly_tc_c in pkg-config pkgconf; do
		if caly_have "$caly_tc_c"; then
			CALY_PKGCONFIG=$(caly_which "$caly_tc_c")
			break
		fi
	done

	unset caly_tc_c caly_tc_ver caly_tc_maj
}

caly_detect_libbpf() {
	CALY_LIBBPF="no"
	CALY_LIBBPF_VERSION=""
	CALY_LIBBPF_DEVEL="no"
	CALY_LIBELF_DEVEL="no"
	CALY_ZLIB_DEVEL="no"
	CALY_KERNEL_HEADERS=""

	if [ -n "${CALY_PKGCONFIG:-}" ]; then
		CALY_LIBBPF_VERSION=$("$CALY_PKGCONFIG" --modversion libbpf 2>/dev/null || true)
		[ -n "$CALY_LIBBPF_VERSION" ] && CALY_LIBBPF="yes"
	fi

	if [ "$CALY_LIBBPF" = "no" ]; then
		for caly_lb_f in /usr/lib64/libbpf.so.1* /usr/lib/libbpf.so.1* \
		    /usr/lib/*/libbpf.so.1* /lib64/libbpf.so.1* /lib/libbpf.so.1* \
		    /usr/lib64/libbpf.so.0* /usr/lib/libbpf.so.0* \
		    /usr/lib/*/libbpf.so.0* /lib/*/libbpf.so.0*; do
			if [ -e "$caly_lb_f" ]; then
				CALY_LIBBPF="yes"
				[ -n "$CALY_LIBBPF_VERSION" ] || \
					CALY_LIBBPF_VERSION=${caly_lb_f##*libbpf.so.}
				break
			fi
		done
	fi

	for caly_lb_f in /usr/include/bpf/libbpf.h /usr/local/include/bpf/libbpf.h \
	    /usr/include/*/bpf/libbpf.h; do
		if [ -r "$caly_lb_f" ]; then
			CALY_LIBBPF_DEVEL="yes"
			break
		fi
	done

	for caly_lb_f in /usr/include/libelf.h /usr/include/gelf.h \
	    /usr/local/include/libelf.h /usr/include/*/libelf.h; do
		if [ -r "$caly_lb_f" ]; then
			CALY_LIBELF_DEVEL="yes"
			break
		fi
	done

	for caly_lb_f in /usr/include/zlib.h /usr/local/include/zlib.h \
	    /usr/include/*/zlib.h; do
		if [ -r "$caly_lb_f" ]; then
			CALY_ZLIB_DEVEL="yes"
			break
		fi
	done

	for caly_lb_f in "/lib/modules/${CALY_KERNEL_RELEASE}/build" \
	    "/usr/src/kernels/${CALY_KERNEL_RELEASE}" \
	    "/usr/src/linux-headers-${CALY_KERNEL_RELEASE}" \
	    "/usr/src/linux"; do
		if [ -d "$caly_lb_f" ]; then
			CALY_KERNEL_HEADERS=$caly_lb_f
			break
		fi
	done

	unset caly_lb_f
}

caly_detect_bpftool() {
	CALY_BPFTOOL=""
	CALY_BPFTOOL_VERSION=""

	if caly_have bpftool; then
		CALY_BPFTOOL=$(caly_which bpftool)
	else
		# Ubuntu ships it inside the versioned linux-tools package and
		# does not always symlink it into PATH.
		for caly_bp_c in \
		    "/usr/lib/linux-tools/${CALY_KERNEL_RELEASE}/bpftool" \
		    "/usr/lib/linux-tools-${CALY_KERNEL_RELEASE}/bpftool" \
		    /usr/lib/linux-tools/*/bpftool \
		    /usr/sbin/bpftool /sbin/bpftool /usr/local/sbin/bpftool \
		    /usr/libexec/bpftool; do
			if [ -x "$caly_bp_c" ]; then
				CALY_BPFTOOL=$caly_bp_c
				break
			fi
		done
	fi

	if [ -n "$CALY_BPFTOOL" ]; then
		CALY_BPFTOOL_VERSION=$("$CALY_BPFTOOL" version 2>/dev/null | \
			sed -n '1s/.*v\([0-9][0-9.]*\).*/\1/p')
		[ -n "$CALY_BPFTOOL_VERSION" ] || CALY_BPFTOOL_VERSION="unknown"
	fi
	unset caly_bp_c
}

# Optional helper probes. These need root and a working bpftool; they are a
# convenience for the --report output. The loader does the authoritative probe
# with libbpf_probe_bpf_helper() at runtime.
caly_detect_bpf_features() {
	CALY_CAP_SYNPROXY="unknown"
	CALY_CAP_RINGBUF="unknown"

	if [ -n "${CALY_BPFTOOL:-}" ] && [ "${CALY_IS_ROOT:-no}" = "yes" ]; then
		caly_bf_out=$("$CALY_BPFTOOL" feature probe kernel 2>/dev/null || true)
		if [ -n "$caly_bf_out" ]; then
			CALY_CAP_SYNPROXY="no"
			CALY_CAP_RINGBUF="no"
			case "$caly_bf_out" in
			*tcp_raw_gen_syncookie_ipv4*) CALY_CAP_SYNPROXY="yes" ;;
			esac
			case "$caly_bf_out" in
			*ringbuf_output*|*"map_type ringbuf is available"*)
				CALY_CAP_RINGBUF="yes" ;;
			esac
		fi
		unset caly_bf_out
	fi

	# Version based fallback when we could not probe. Deliberately
	# conservative: reported as "likely", never as fact.
	if [ "$CALY_CAP_SYNPROXY" = "unknown" ]; then
		if caly_kver_ge 5 15; then
			CALY_CAP_SYNPROXY="likely"
		else
			CALY_CAP_SYNPROXY="unlikely"
		fi
	fi
	if [ "$CALY_CAP_RINGBUF" = "unknown" ]; then
		if caly_kver_ge 5 8; then
			CALY_CAP_RINGBUF="likely"
		else
			CALY_CAP_RINGBUF="unlikely"
		fi
	fi
}

# ---------------------------------------------------------------------------
# 9. Virtualisation / container
# ---------------------------------------------------------------------------
caly_detect_virt() {
	CALY_VIRT="none"
	CALY_VIRT_TYPE="none"
	CALY_CONTAINER="no"

	if caly_have systemd-detect-virt; then
		caly_vt=$(systemd-detect-virt 2>/dev/null || true)
		if [ -n "$caly_vt" ] && [ "$caly_vt" != "none" ]; then
			CALY_VIRT_TYPE=$caly_vt
			if systemd-detect-virt --container >/dev/null 2>&1; then
				CALY_VIRT="container"
				CALY_CONTAINER="yes"
			else
				CALY_VIRT="vm"
			fi
		fi
		unset caly_vt
	fi

	# Manual fallbacks. systemd-detect-virt is absent on Alpine/OpenRC and
	# inside minimal containers, which is exactly where this matters most.
	if [ "$CALY_VIRT_TYPE" = "none" ]; then
		if [ -e /proc/user_beancounters ] || [ -d /proc/vz ]; then
			CALY_VIRT="container"; CALY_VIRT_TYPE="openvz"; CALY_CONTAINER="yes"
		elif [ -e /.dockerenv ]; then
			CALY_VIRT="container"; CALY_VIRT_TYPE="docker"; CALY_CONTAINER="yes"
		elif [ -e /run/.containerenv ]; then
			CALY_VIRT="container"; CALY_VIRT_TYPE="podman"; CALY_CONTAINER="yes"
		elif [ -r /proc/1/environ ] && \
		     tr '\0' '\n' < /proc/1/environ 2>/dev/null | \
		     grep -q '^container='; then
			CALY_VIRT="container"
			CALY_VIRT_TYPE=$(tr '\0' '\n' < /proc/1/environ 2>/dev/null | \
				sed -n 's/^container=//p' | sed -n 1p)
			[ -n "$CALY_VIRT_TYPE" ] || CALY_VIRT_TYPE="lxc"
			CALY_CONTAINER="yes"
		elif [ -r /proc/self/cgroup ] && \
		     grep -qE '(docker|lxc|kubepods|containerd|podman)' \
		     /proc/self/cgroup 2>/dev/null; then
			CALY_VIRT="container"; CALY_VIRT_TYPE="lxc"; CALY_CONTAINER="yes"
		elif [ -d /proc/xen ]; then
			CALY_VIRT="vm"; CALY_VIRT_TYPE="xen"
		elif [ -r /sys/class/dmi/id/product_name ]; then
			caly_vp=$(caly_first_line /sys/class/dmi/id/product_name)
			case "$caly_vp" in
			*KVM*|*QEMU*)      CALY_VIRT="vm"; CALY_VIRT_TYPE="kvm" ;;
			*VMware*)          CALY_VIRT="vm"; CALY_VIRT_TYPE="vmware" ;;
			*VirtualBox*)      CALY_VIRT="vm"; CALY_VIRT_TYPE="oracle" ;;
			*Bochs*)           CALY_VIRT="vm"; CALY_VIRT_TYPE="bochs" ;;
			*"Virtual Machine"*) CALY_VIRT="vm"; CALY_VIRT_TYPE="microsoft" ;;
			*Parallels*)       CALY_VIRT="vm"; CALY_VIRT_TYPE="parallels" ;;
			esac
			unset caly_vp
		fi
	fi

	# LXD/LXC often only shows up in /proc/1/environ, which an unprivileged
	# reader cannot see. A read-only /sys is another strong hint.
	if [ "$CALY_CONTAINER" = "no" ] && [ ! -w /sys/kernel ] && \
	   [ "${CALY_IS_ROOT:-no}" = "yes" ] && [ -e /sys/kernel ]; then
		caly_debug "sysfs not writable as root: possibly a container"
	fi
}

# ---------------------------------------------------------------------------
# 10. Network interfaces, drivers and XDP capability
#
# There is no reliable read-only way to ask "does this driver implement
# ndo_bpf/XDP_SETUP_PROG". The only authoritative probe is to attach a program
# in DRV mode and see whether it fails, which the loader does at runtime (and
# falls back to SKB mode on failure). What we do here is a documented HINT
# based on the driver name, used to pick a starting rung and to warn early.
# ---------------------------------------------------------------------------

# Drivers with in-tree XDP support. Some entries gained it in a specific
# release (igb 5.15, igc 5.11, virtio_net 4.10), which is why the result is
# only ever a hint.
CALY_XDP_NATIVE_DRIVERS="mlx5_core mlx4_en i40e ice ixgbe ixgbevf igb igc \
ena bnxt_en nfp qede sfc atlantic virtio_net veth tun thunder-nicvf hns3 \
mvneta mvpp2 stmmac dpaa2-eth cxgb4 fec octeontx2_nicpf otx2_nicvf \
tsnep netsec ti-am65-cpsw-nuss lan966x gve xdp_dummy"

caly_driver_of() {
	caly_do_if=$1
	caly_do_drv=""
	if [ -L "/sys/class/net/${caly_do_if}/device/driver" ]; then
		caly_do_drv=$(readlink "/sys/class/net/${caly_do_if}/device/driver" \
			2>/dev/null || true)
		caly_do_drv=${caly_do_drv##*/}
	fi
	if [ -z "$caly_do_drv" ] && caly_have ethtool; then
		caly_do_drv=$(ethtool -i "$caly_do_if" 2>/dev/null | \
			sed -n 's/^driver: *//p' | sed -n 1p)
	fi
	if [ -z "$caly_do_drv" ]; then
		if [ -d "/sys/class/net/${caly_do_if}/bridge" ]; then
			caly_do_drv="bridge"
		elif [ -d "/sys/class/net/${caly_do_if}/bonding" ]; then
			caly_do_drv="bonding"
		elif [ -e "/sys/class/net/${caly_do_if}/tun_flags" ]; then
			caly_do_drv="tun"
		else
			caly_do_drv="virtual"
		fi
	fi
	printf '%s' "$caly_do_drv"
	unset caly_do_if caly_do_drv
}

caly_xdp_hint_for_driver() {
	caly_xh_drv=$1
	for caly_xh_k in $CALY_XDP_NATIVE_DRIVERS; do
		if [ "$caly_xh_k" = "$caly_xh_drv" ]; then
			printf 'native'
			unset caly_xh_drv caly_xh_k
			return 0
		fi
	done
	case "$caly_xh_drv" in
	bridge|bonding|team|vlan|macvlan|wireguard|virtual|ppp|sit|gre|ip6gre)
		printf 'none' ;;
	*)
		printf 'generic' ;;
	esac
	unset caly_xh_drv caly_xh_k
}

caly_detect_net() {
	CALY_NICS=""
	CALY_NIC_COUNT=0
	CALY_NIC_TABLE=""
	CALY_DEFAULT_IFACE=""
	CALY_DEFAULT_DRIVER=""
	CALY_HAVE_IP="no"
	CALY_HAVE_TC="no"
	CALY_HAVE_ETHTOOL="no"
	CALY_HAVE_SS="no"

	caly_have ip && CALY_HAVE_IP="yes"
	caly_have tc && CALY_HAVE_TC="yes"
	caly_have ethtool && CALY_HAVE_ETHTOOL="yes"
	caly_have ss && CALY_HAVE_SS="yes"

	if [ -d /sys/class/net ]; then
		for caly_nt_p in /sys/class/net/*; do
			[ -e "$caly_nt_p" ] || continue
			caly_nt_if=${caly_nt_p##*/}
			[ "$caly_nt_if" = "lo" ] && continue
			case "$caly_nt_if" in
			bonding_masters) continue ;;
			esac

			caly_nt_drv=$(caly_driver_of "$caly_nt_if")
			caly_nt_xdp=$(caly_xdp_hint_for_driver "$caly_nt_drv")
			caly_nt_st="unknown"
			[ -r "${caly_nt_p}/operstate" ] && \
				caly_nt_st=$(caly_first_line "${caly_nt_p}/operstate")
			caly_nt_mtu="?"
			[ -r "${caly_nt_p}/mtu" ] && \
				caly_nt_mtu=$(caly_first_line "${caly_nt_p}/mtu")

			CALY_NICS="${CALY_NICS}${CALY_NICS:+ }${caly_nt_if}"
			CALY_NIC_COUNT=$(( CALY_NIC_COUNT + 1 ))
			CALY_NIC_TABLE="${CALY_NIC_TABLE}${caly_nt_if} ${caly_nt_drv} ${caly_nt_xdp} ${caly_nt_st} ${caly_nt_mtu}
"
		done
	fi

	# The interface carrying the default route is the WAN candidate.
	if [ "$CALY_HAVE_IP" = "yes" ]; then
		CALY_DEFAULT_IFACE=$(ip -4 route show default 2>/dev/null | \
			sed -n 's/.*[ \t]dev[ \t]\([^ \t]*\).*/\1/p' | sed -n 1p)
		if [ -z "$CALY_DEFAULT_IFACE" ]; then
			CALY_DEFAULT_IFACE=$(ip -6 route show default 2>/dev/null | \
				sed -n 's/.*[ \t]dev[ \t]\([^ \t]*\).*/\1/p' | sed -n 1p)
		fi
	fi
	if [ -z "$CALY_DEFAULT_IFACE" ] && [ -r /proc/net/route ]; then
		CALY_DEFAULT_IFACE=$(awk '$2 == "00000000" && $1 != "Iface" \
			{ print $1; exit }' /proc/net/route 2>/dev/null || true)
	fi
	if [ -z "$CALY_DEFAULT_IFACE" ]; then
		# Last resort: first non-loopback interface that is up.
		for caly_nt_if in $CALY_NICS; do
			if [ -r "/sys/class/net/${caly_nt_if}/operstate" ] && \
			   [ "$(caly_first_line "/sys/class/net/${caly_nt_if}/operstate")" \
			     = "up" ]; then
				CALY_DEFAULT_IFACE=$caly_nt_if
				break
			fi
		done
	fi

	if [ -n "$CALY_DEFAULT_IFACE" ]; then
		CALY_DEFAULT_DRIVER=$(caly_driver_of "$CALY_DEFAULT_IFACE")
	fi

	unset caly_nt_p caly_nt_if caly_nt_drv caly_nt_xdp caly_nt_st caly_nt_mtu
}

# Number of combined/rx channels vs CPUs. virtio-net without multiqueue cannot
# do native XDP, and native XDP on virtio needs at least as many queues as
# there are CPUs because XDP_TX needs a dedicated TX queue per core.
caly_virtio_mq_ok() {
	caly_vm_if=$1
	[ -n "$caly_vm_if" ] || return 1
	caly_have ethtool || return 1
	caly_vm_n=$(ethtool -l "$caly_vm_if" 2>/dev/null | \
		awk '/^Current hardware settings:/,0 { \
			if ($1 == "Combined:") { print $2; exit } \
			if ($1 == "RX:") { rx=$2 } } \
		     END { if (rx != "") print rx }' | sed -n 1p)
	case "$caly_vm_n" in
	''|*[!0-9]*) unset caly_vm_if caly_vm_n; return 1 ;;
	esac
	if [ "$caly_vm_n" -ge "${CALY_NPROC:-1}" ]; then
		unset caly_vm_if caly_vm_n
		return 0
	fi
	unset caly_vm_if caly_vm_n
	return 1
}

# ---------------------------------------------------------------------------
# 11. Legacy firewall tooling (rungs 4 and 5)
# ---------------------------------------------------------------------------
caly_detect_fw() {
	CALY_HAVE_NFT="no"
	CALY_NFT_VERSION=""
	CALY_HAVE_IPTABLES="no"
	CALY_HAVE_IP6TABLES="no"
	CALY_HAVE_IPSET="no"

	if caly_have nft; then
		CALY_HAVE_NFT="yes"
		CALY_NFT_VERSION=$(nft --version 2>/dev/null | \
			sed -n '1s/.*nftables v\([0-9][0-9.]*\).*/\1/p')
	fi
	caly_have iptables && CALY_HAVE_IPTABLES="yes"
	caly_have ip6tables && CALY_HAVE_IP6TABLES="yes"
	caly_have ipset && CALY_HAVE_IPSET="yes"
}

# ---------------------------------------------------------------------------
# 12. Degradation ladder decision
#
# Mirrors docs/ARCHITECTURE.md section 2. Callers may override with an explicit
# --dataplane= flag; this only computes the best *automatic* choice.
# ---------------------------------------------------------------------------
caly_choose_dataplane() {
	CALY_BPF_OK="no"
	CALY_XDP_OK="no"
	CALY_XDP_MODE_BEST="none"
	CALY_DATAPLANE_BEST="none"
	CALY_DATAPLANE_REASON=""

	# --- can we run eBPF at all? ---
	caly_cd_bpf_reason=""
	if [ "$CALY_HAVE_BPF_SYSCALL" = "no" ]; then
		caly_cd_bpf_reason="kernel built without CONFIG_BPF_SYSCALL"
	elif [ "$CALY_VIRT_TYPE" = "openvz" ]; then
		caly_cd_bpf_reason="OpenVZ containers cannot load BPF programs"
	elif [ "$CALY_HAVE_BTF" != "yes" ]; then
		caly_cd_bpf_reason="no BTF at /sys/kernel/btf/vmlinux (CO-RE impossible)"
	elif ! caly_kver_ge 4 18; then
		caly_cd_bpf_reason="kernel ${CALY_KERNEL_RELEASE} is older than 4.18"
	else
		CALY_BPF_OK="yes"
	fi

	if [ "$CALY_BPF_OK" = "no" ]; then
		if [ "$CALY_HAVE_NFT" = "yes" ]; then
			CALY_DATAPLANE_BEST="nftables"
			CALY_DATAPLANE_REASON="$caly_cd_bpf_reason"
		elif [ "$CALY_HAVE_IPTABLES" = "yes" ]; then
			CALY_DATAPLANE_BEST="iptables"
			CALY_DATAPLANE_REASON="${caly_cd_bpf_reason}; nft unavailable"
		else
			CALY_DATAPLANE_BEST="none"
			CALY_DATAPLANE_REASON="${caly_cd_bpf_reason}; no nft, no iptables"
		fi
		unset caly_cd_bpf_reason
		return 0
	fi

	# --- XDP availability ---
	case "$CALY_VIRT_TYPE" in
	openvz)
		CALY_DATAPLANE_BEST="nftables"
		CALY_DATAPLANE_REASON="OpenVZ: no BPF"
		return 0 ;;
	lxc|lxc-libvirt|systemd-nspawn|docker|podman|rkt|wsl)
		CALY_XDP_OK="no"
		CALY_DATAPLANE_BEST="tc"
		CALY_DATAPLANE_REASON="running inside a ${CALY_VIRT_TYPE} container: XDP attach is unavailable or unreliable, using tc/clsact"
		if [ "$CALY_HAVE_CLS_BPF" = "no" ]; then
			CALY_DATAPLANE_BEST="nftables"
			CALY_DATAPLANE_REASON="container without CONFIG_NET_CLS_BPF"
		fi
		return 0 ;;
	esac

	if [ -z "$CALY_DEFAULT_IFACE" ]; then
		CALY_DATAPLANE_BEST="tc"
		CALY_DATAPLANE_REASON="no default route interface found; pick one with --iface="
		return 0
	fi

	caly_cd_hint=$(caly_xdp_hint_for_driver "$CALY_DEFAULT_DRIVER")
	case "$caly_cd_hint" in
	native)
		CALY_XDP_OK="yes"
		CALY_XDP_MODE_BEST="native"
		CALY_DATAPLANE_BEST="xdp-native"
		CALY_DATAPLANE_REASON="driver ${CALY_DEFAULT_DRIVER} implements native XDP"
		# virtio-net needs multiqueue for native XDP with XDP_TX.
		if [ "$CALY_DEFAULT_DRIVER" = "virtio_net" ]; then
			if ! caly_virtio_mq_ok "$CALY_DEFAULT_IFACE"; then
				CALY_XDP_MODE_BEST="generic"
				CALY_DATAPLANE_BEST="xdp-generic"
				CALY_DATAPLANE_REASON="virtio_net without enough queues for native XDP (need >= ${CALY_NPROC}); using generic/skb mode"
			fi
		fi ;;
	generic)
		CALY_XDP_OK="yes"
		CALY_XDP_MODE_BEST="generic"
		CALY_DATAPLANE_BEST="xdp-generic"
		CALY_DATAPLANE_REASON="driver ${CALY_DEFAULT_DRIVER} has no known native XDP support; using generic/skb mode" ;;
	*)
		CALY_XDP_OK="no"
		CALY_XDP_MODE_BEST="none"
		if [ "$CALY_HAVE_CLS_BPF" != "no" ]; then
			CALY_DATAPLANE_BEST="tc"
			CALY_DATAPLANE_REASON="interface ${CALY_DEFAULT_IFACE} (${CALY_DEFAULT_DRIVER}) cannot carry XDP; using tc/clsact"
		elif [ "$CALY_HAVE_NFT" = "yes" ]; then
			CALY_DATAPLANE_BEST="nftables"
			CALY_DATAPLANE_REASON="no XDP and no CONFIG_NET_CLS_BPF"
		else
			CALY_DATAPLANE_BEST="iptables"
			CALY_DATAPLANE_REASON="no XDP, no tc BPF, no nftables"
		fi ;;
	esac

	unset caly_cd_bpf_reason caly_cd_hint
}

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------
caly_detect_all() {
	[ "${CALY_DETECTED:-0}" = "1" ] && return 0
	caly_detect_os
	caly_detect_pkgmgr
	caly_detect_init
	caly_detect_libc
	caly_detect_arch
	caly_detect_kernel
	caly_detect_btf
	caly_detect_bpffs
	caly_detect_kconfig
	caly_detect_toolchain
	caly_detect_libbpf
	caly_detect_bpftool
	caly_detect_bpf_features
	caly_detect_virt
	caly_detect_net
	caly_detect_fw
	caly_choose_dataplane
	CALY_DETECTED=1
	caly_export_all
	return 0
}

# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
caly_row() {
	printf '  %-22s %s\n' "$1" "$2"
}

caly_report() {
	caly_detect_all

	printf '%s\n' "${CALY_C_BOLD}Caly Anti - environment report${CALY_C_RESET}"
	printf '%s\n' "  detect-env ${CALY_DETECT_VERSION}   $(date 2>/dev/null || true)"
	printf '\n%s\n' "${CALY_C_BOLD}System${CALY_C_RESET}"
	caly_row "distribution" "${CALY_OS_PRETTY}"
	caly_row "os id / family" "${CALY_OS_ID} / ${CALY_OS_FAMILY}"
	caly_row "version" "${CALY_OS_VERSION_ID:-unknown}"
	caly_row "architecture" "${CALY_ARCH} (kernel arch dir: ${CALY_ARCH_BPF})"
	caly_row "cpus / memory" "${CALY_NPROC} cpu, $(( CALY_MEM_TOTAL_KB / 1024 )) MiB"
	caly_row "libc" "${CALY_LIBC} ${CALY_LIBC_VERSION}"
	caly_row "init system" "${CALY_INIT} ${CALY_INIT_VERSION}"
	caly_row "package manager" "${CALY_PKGMGR}"
	caly_row "running as root" "${CALY_IS_ROOT}"
	caly_row "selinux" "${CALY_SELINUX}"

	printf '\n%s\n' "${CALY_C_BOLD}Kernel${CALY_C_RESET}"
	caly_row "release" "${CALY_KERNEL_RELEASE}"
	caly_row "parsed version" "${CALY_KERNEL_MAJOR}.${CALY_KERNEL_MINOR}.${CALY_KERNEL_PATCH} (code ${CALY_KERNEL_CODE})"
	caly_row "vendor kernel" "${CALY_KERNEL_VENDOR}"
	caly_row "BTF" "${CALY_HAVE_BTF}${CALY_BTF_PATH:+ (${CALY_BTF_PATH})}"
	caly_row "bpffs" "${CALY_BPFFS_MOUNTED} (${CALY_BPFFS})"
	caly_row "CONFIG_BPF_SYSCALL" "${CALY_HAVE_BPF_SYSCALL}"
	caly_row "CONFIG_NET_CLS_BPF" "${CALY_HAVE_CLS_BPF}"
	caly_row "CONFIG_BPF_JIT" "${CALY_HAVE_BPF_JIT}"
	caly_row "kernel config" "${CALY_KCONFIG:-not found}"
	caly_row "raw syncookie helpers" "${CALY_CAP_SYNPROXY} (needs 5.15+)"
	caly_row "BPF ringbuf" "${CALY_CAP_RINGBUF} (needs 5.8+)"

	printf '\n%s\n' "${CALY_C_BOLD}Toolchain${CALY_C_RESET}"
	caly_row "clang" "${CALY_CLANG:-not found} ${CALY_CLANG_VERSION}"
	caly_row "clang usable" "${CALY_CLANG_OK} (need >= 10 for CO-RE, >= 11 recommended)"
	caly_row "llvm-strip" "${CALY_LLVM_STRIP:-not found}"
	caly_row "c compiler" "${CALY_CC:-not found}"
	caly_row "make" "${CALY_MAKE:-not found}"
	caly_row "pkg-config" "${CALY_PKGCONFIG:-not found}"
	caly_row "libbpf" "${CALY_LIBBPF} ${CALY_LIBBPF_VERSION}"
	caly_row "libbpf headers" "${CALY_LIBBPF_DEVEL}"
	caly_row "libelf headers" "${CALY_LIBELF_DEVEL}"
	caly_row "zlib headers" "${CALY_ZLIB_DEVEL}"
	caly_row "kernel headers" "${CALY_KERNEL_HEADERS:-not found}"
	caly_row "bpftool" "${CALY_BPFTOOL:-not found} ${CALY_BPFTOOL_VERSION}"

	printf '\n%s\n' "${CALY_C_BOLD}Virtualisation${CALY_C_RESET}"
	caly_row "type" "${CALY_VIRT} / ${CALY_VIRT_TYPE}"
	caly_row "container" "${CALY_CONTAINER}"

	printf '\n%s\n' "${CALY_C_BOLD}Network interfaces${CALY_C_RESET}"
	printf '  %-14s %-14s %-9s %-8s %s\n' NAME DRIVER XDP-HINT STATE MTU
	printf '%s' "$CALY_NIC_TABLE" | while read -r caly_rp_n caly_rp_d \
	    caly_rp_x caly_rp_s caly_rp_m; do
		[ -n "$caly_rp_n" ] || continue
		printf '  %-14s %-14s %-9s %-8s %s\n' "$caly_rp_n" "$caly_rp_d" \
			"$caly_rp_x" "$caly_rp_s" "$caly_rp_m"
	done
	caly_row "default route iface" "${CALY_DEFAULT_IFACE:-none} (${CALY_DEFAULT_DRIVER:-?})"

	printf '\n%s\n' "${CALY_C_BOLD}Legacy firewall tooling${CALY_C_RESET}"
	caly_row "nft" "${CALY_HAVE_NFT} ${CALY_NFT_VERSION}"
	caly_row "iptables" "${CALY_HAVE_IPTABLES}"
	caly_row "ip6tables" "${CALY_HAVE_IP6TABLES}"
	caly_row "ipset" "${CALY_HAVE_IPSET}"
	caly_row "iproute2 ip / tc" "${CALY_HAVE_IP} / ${CALY_HAVE_TC}"
	caly_row "ethtool" "${CALY_HAVE_ETHTOOL}"

	printf '\n%s\n' "${CALY_C_BOLD}Selected dataplane${CALY_C_RESET}"
	caly_row "best rung" "${CALY_C_GREEN}${CALY_DATAPLANE_BEST}${CALY_C_RESET}"
	caly_row "reason" "${CALY_DATAPLANE_REASON:-driver and kernel support it}"
	caly_row "xdp mode" "${CALY_XDP_MODE_BEST}"

	printf '\n%s\n' "${CALY_C_BOLD}Notes${CALY_C_RESET}"
	if [ "$CALY_HAVE_BTF" != "yes" ]; then
		printf '  - No BTF: the eBPF dataplane cannot be used. This is a\n'
		printf '    documented fallback to nftables, not an error.\n'
	fi
	if [ "$CALY_CLANG_OK" = "too-old" ]; then
		printf '  - clang %s is too old for CO-RE; version 10 is the minimum\n' \
			"$CALY_CLANG_VERSION"
		printf '    and 11+ is recommended.\n'
	fi
	if [ "$CALY_CONTAINER" = "yes" ]; then
		printf '  - Container detected (%s). XDP attach usually fails inside\n' \
			"$CALY_VIRT_TYPE"
		printf '    containers; the tc/clsact rung is used instead.\n'
	fi
	if [ "$CALY_BPFFS_MOUNTED" != "yes" ]; then
		printf '  - bpffs is not mounted. The installer mounts it at %s and\n' \
			"$CALY_BPFFS"
		printf '    adds an fstab entry so it survives a reboot.\n'
	fi
	if [ "${CALY_CAP_SYNPROXY}" = "unlikely" ] || [ "${CALY_CAP_SYNPROXY}" = "no" ]; then
		printf '  - Kernel lacks the raw syncookie helpers (5.15+). The SYN\n'
		printf '    proxy program is not autoloaded; the per-source SYN token\n'
		printf '    bucket plus net.ipv4.tcp_syncookies=1 is used instead.\n'
	fi
	printf '\n'
}

caly_report_brief() {
	caly_detect_all
	printf '%s %s / kernel %s / %s / btf=%s / dataplane=%s\n' \
		"$CALY_OS_ID" "${CALY_OS_VERSION_ID:-?}" "$CALY_KERNEL_RELEASE" \
		"$CALY_ARCH" "$CALY_HAVE_BTF" "$CALY_DATAPLANE_BEST"
}

caly_export_shell() {
	caly_detect_all
	for caly_es_v in $CALY_VARS; do
		eval "caly_es_val=\${$caly_es_v-}"
		# Single quote and escape embedded single quotes so the output is
		# safe to eval.
		caly_es_q=$(printf '%s' "$caly_es_val" | sed "s/'/'\\\\''/g")
		printf "%s='%s'\n" "$caly_es_v" "$caly_es_q"
	done
	unset caly_es_v caly_es_val caly_es_q
}

caly_detect_usage() {
	cat <<'EOF'
Usage: detect-env.sh [--report|--export|--brief|--get VAR|--help]

  --report   human readable environment table (default)
  --export   CALY_x='y' lines, safe to eval in a POSIX shell
  --brief    single summary line
  --get VAR  print one detected variable
  --help     this text

Exit status is 0 unless an unknown option is given. Detection itself never
fails: unavailable facts are reported as "unknown" or "no".
EOF
}

caly_detect_main() {
	caly_dm_mode="report"
	caly_dm_var=""
	while [ $# -gt 0 ]; do
		case "$1" in
		--report)  caly_dm_mode="report" ;;
		--export)  caly_dm_mode="export" ;;
		--brief)   caly_dm_mode="brief" ;;
		--get)     caly_dm_mode="get"; caly_dm_var=${2:-}; shift ;;
		--get=*)   caly_dm_mode="get"; caly_dm_var=${1#--get=} ;;
		--no-color) CALY_COLOR="never"; caly_init_colors ;;
		-h|--help) caly_detect_usage; return 0 ;;
		*)
			caly_err "detect-env.sh: unknown option '$1'"
			caly_detect_usage >&2
			return 2 ;;
		esac
		shift
	done

	case "$caly_dm_mode" in
	report) caly_report ;;
	export) caly_export_shell ;;
	brief)  caly_report_brief ;;
	get)
		caly_detect_all
		if [ -z "$caly_dm_var" ]; then
			caly_err "--get needs a variable name"
			return 2
		fi
		eval "printf '%s\n' \"\${$caly_dm_var-}\"" ;;
	esac
	unset caly_dm_mode caly_dm_var
}

# Run the CLI only when executed directly, never when sourced.
case "${0##*/}" in
detect-env.sh)
	set -u
	caly_detect_main "$@"
	exit $?
	;;
esac
