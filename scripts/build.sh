#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Caly Anti - scripts/build.sh
#
# A thin, dependency-light wrapper around `make` for people who would rather run
# one command than read docs/INSTALL.md section 3. It discovers a working
# clang / llvm-strip / bpftool (including the versioned binaries that Ubuntu and
# Debian ship, e.g. clang-14 with no unversioned `clang`), then invokes the
# top-level Makefile with them. It builds nothing itself; the Makefile is the
# single source of truth for how the object and the daemon are produced.
#
#   scripts/build.sh                 build everything into build/
#   scripts/build.sh --debug         -O1 -g userspace build
#   scripts/build.sh --libbpf=bundled
#   scripts/build.sh --jobs=4
#   scripts/build.sh --clang=clang-12
#   scripts/build.sh clean           pass any target(s) straight to make
#
# POSIX sh: runs under dash, busybox ash, bash and ksh without modification.

set -eu

# --------------------------------------------------------------------------
# Locate the source tree (this script lives in scripts/).
# --------------------------------------------------------------------------
caly_self=$0
case "$caly_self" in
*/*) caly_self_dir=${caly_self%/*} ;;
*)   caly_self_dir=. ;;
esac
SCRIPT_DIR=$(cd "$caly_self_dir" 2>/dev/null && pwd) || SCRIPT_DIR=$PWD
SRC_ROOT=$(cd "${SCRIPT_DIR}/.." 2>/dev/null && pwd) || SRC_ROOT=$SCRIPT_DIR
unset caly_self caly_self_dir

bs_say()  { printf 'build.sh: %s\n' "$*"; }
bs_warn() { printf 'build.sh: warning: %s\n' "$*" >&2; }
bs_err()  { printf 'build.sh: error: %s\n' "$*" >&2; }

have() { command -v "$1" >/dev/null 2>&1; }

usage() {
	cat <<'EOF'
Usage: build.sh [OPTIONS] [make-target ...]

  --clang=BIN        clang to use (default: autodetected)
  --llvm-strip=BIN   llvm-strip to use (default: matched to clang)
  --bpftool=BIN      bpftool to use (default: autodetected)
  --cc=BIN           userspace C compiler (default: cc)
  --libbpf=MODE      auto | system | bundled  (default: auto)
  --prefix=DIR       install prefix (default: /usr)
  --jobs=N, -jN      parallel make jobs (default: number of CPUs)
  --debug            build the daemon with -O1 -g
  --verbose, -v      echo the compiler command lines
  -h, --help         this text

Any non-option argument is passed through to make as a target, so
`build.sh clean` and `build.sh install` work as expected.
EOF
}

# --------------------------------------------------------------------------
# Toolchain discovery. Honour the environment first, then look for versioned
# binaries newest-first, which is what old Ubuntu/Debian need.
# --------------------------------------------------------------------------
pick_clang() {
	if [ -n "${CLANG:-}" ] && have "$CLANG"; then
		printf '%s' "$CLANG"; return 0
	fi
	if have clang; then printf 'clang'; return 0; fi
	# clang-20 .. clang-10, newest first.
	for v in 20 19 18 17 16 15 14 13 12 11 10; do
		if have "clang-$v"; then printf 'clang-%s' "$v"; return 0; fi
	done
	return 1
}

# llvm-strip must match the clang version or DWARF/BTF handling can differ.
pick_llvm_strip() {
	_clang=$1
	if [ -n "${LLVM_STRIP:-}" ] && have "$LLVM_STRIP"; then
		printf '%s' "$LLVM_STRIP"; return 0
	fi
	case "$_clang" in
	*clang-*)
		_v=${_clang##*clang-}
		if have "llvm-strip-$_v"; then printf 'llvm-strip-%s' "$_v"; return 0; fi
		;;
	esac
	if have llvm-strip; then printf 'llvm-strip'; return 0; fi
	# Some distros only ship the versioned strip.
	for v in 20 19 18 17 16 15 14 13 12 11 10; do
		if have "llvm-strip-$v"; then printf 'llvm-strip-%s' "$v"; return 0; fi
	done
	# Last resort: llvm-objcopy can strip too; but llvm-strip is expected.
	printf 'llvm-strip'
}

pick_bpftool() {
	if [ -n "${BPFTOOL:-}" ] && have "$BPFTOOL"; then
		printf '%s' "$BPFTOOL"; return 0
	fi
	if have bpftool; then printf 'bpftool'; return 0; fi
	# Ubuntu tucks bpftool inside linux-tools-<uname -r>.
	_kr=$(uname -r 2>/dev/null || echo unknown)
	for c in \
	    "/usr/lib/linux-tools/${_kr}/bpftool" \
	    "/usr/lib/linux-tools-${_kr}/bpftool" \
	    /usr/sbin/bpftool /sbin/bpftool /usr/libexec/bpftool; do
		if [ -x "$c" ]; then printf '%s' "$c"; return 0; fi
	done
	return 1
}

# --------------------------------------------------------------------------
# Option parsing
# --------------------------------------------------------------------------
OPT_JOBS=""
OPT_DEBUG=0
OPT_VERBOSE=0
OPT_LIBBPF=""
OPT_PREFIX=""
OPT_CC=""
OPT_CLANG=""
OPT_STRIP=""
OPT_BPFTOOL=""
MAKE_TARGETS=""

while [ $# -gt 0 ]; do
	case "$1" in
	--clang=*)      OPT_CLANG=${1#--clang=} ;;
	--llvm-strip=*) OPT_STRIP=${1#--llvm-strip=} ;;
	--bpftool=*)    OPT_BPFTOOL=${1#--bpftool=} ;;
	--cc=*)         OPT_CC=${1#--cc=} ;;
	--libbpf=*)     OPT_LIBBPF=${1#--libbpf=} ;;
	--prefix=*)     OPT_PREFIX=${1#--prefix=} ;;
	--jobs=*)       OPT_JOBS=${1#--jobs=} ;;
	-j)             shift; OPT_JOBS=${1:-} ;;
	-j*)            OPT_JOBS=${1#-j} ;;
	--debug)        OPT_DEBUG=1 ;;
	--verbose|-v)   OPT_VERBOSE=1 ;;
	-h|--help)      usage; exit 0 ;;
	--)             shift; while [ $# -gt 0 ]; do MAKE_TARGETS="${MAKE_TARGETS} $1"; shift; done; break ;;
	-*)             bs_err "unknown option '$1'"; usage >&2; exit 2 ;;
	*)              MAKE_TARGETS="${MAKE_TARGETS} $1" ;;
	esac
	shift
done

[ -n "$OPT_CLANG" ] && CLANG=$OPT_CLANG
[ -n "$OPT_STRIP" ] && LLVM_STRIP=$OPT_STRIP
[ -n "$OPT_BPFTOOL" ] && BPFTOOL=$OPT_BPFTOOL

# --------------------------------------------------------------------------
# make
# --------------------------------------------------------------------------
MAKE_BIN=${MAKE:-}
if [ -z "$MAKE_BIN" ]; then
	if have make; then MAKE_BIN=make
	elif have gmake; then MAKE_BIN=gmake
	else bs_err "make is not installed"; exit 1; fi
fi

if [ -z "$OPT_JOBS" ]; then
	OPT_JOBS=$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)
fi
case "$OPT_JOBS" in ''|*[!0-9]*) OPT_JOBS=1 ;; esac

# --------------------------------------------------------------------------
# Resolve the toolchain. Only clang is mandatory for the eBPF dataplane; if it
# is missing we still let make run (a legacy/nftables-only tree needs no clang),
# but we say so loudly.
# --------------------------------------------------------------------------
CC_BIN=${OPT_CC:-${CC:-cc}}

if CLANG_BIN=$(pick_clang); then
	:
else
	CLANG_BIN=${CLANG:-clang}
	bs_warn "no clang found; the BPF object cannot be built. Install clang 10+."
fi
STRIP_BIN=$(pick_llvm_strip "$CLANG_BIN")

if BPFTOOL_BIN=$(pick_bpftool); then
	:
else
	BPFTOOL_BIN=${BPFTOOL:-bpftool}
	bs_warn "no bpftool found; vmlinux.h generation and BPF linking will fail. \
Install bpftool (Arch: 'bpf'; Ubuntu: linux-tools-\$(uname -r))."
fi

bs_say "clang      = ${CLANG_BIN}"
bs_say "llvm-strip = ${STRIP_BIN}"
bs_say "bpftool    = ${BPFTOOL_BIN}"
bs_say "cc         = ${CC_BIN}"

set -- \
	CLANG="$CLANG_BIN" \
	LLVM_STRIP="$STRIP_BIN" \
	BPFTOOL="$BPFTOOL_BIN" \
	CC="$CC_BIN"
[ -n "$OPT_LIBBPF" ] && set -- "$@" LIBBPF="$OPT_LIBBPF"
[ -n "$OPT_PREFIX" ] && set -- "$@" PREFIX="$OPT_PREFIX"
[ "$OPT_DEBUG" = "1" ] && set -- "$@" DEBUG=1
[ "$OPT_VERBOSE" = "1" ] && set -- "$@" V=1

# Default target is the Makefile's default (all) when none was named.
# shellcheck disable=SC2086
bs_say "running: ${MAKE_BIN} -C ${SRC_ROOT} -j${OPT_JOBS} $* ${MAKE_TARGETS}"
# shellcheck disable=SC2086
exec "$MAKE_BIN" -C "$SRC_ROOT" -j"$OPT_JOBS" "$@" ${MAKE_TARGETS}
