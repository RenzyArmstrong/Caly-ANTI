#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Caly Anti - scripts/gen-vmlinux.sh
#
# Generate src/bpf/vmlinux.h from the running kernel's BTF.
#
# CO-RE needs a vmlinux.h that describes the kernel the object will run on.
# The canonical source is /sys/kernel/btf/vmlinux, which exists when the
# kernel was built with CONFIG_DEBUG_INFO_BTF=y. When it is missing we try, in
# order:
#
#   1. bpftool btf dump file /sys/kernel/btf/vmlinux format c   (the normal path)
#   2. bpftool btf dump file <vmlinux image with embedded BTF>  (split debug)
#   3. a pre-generated header bundled with the source tree, per architecture
#   4. give up with exit status 2, which tells install.sh to fall back to the
#      nftables dataplane (rung 4) rather than failing the installation
#
# Exit status:
#   0  header generated (or already present and valid)
#   1  hard error (bad arguments, unwritable output path)
#   2  no BTF available anywhere: caller must degrade down the ladder
#
# This script is standalone on purpose: the Makefile calls it directly, so it
# must work without detect-env.sh being present.

set -eu

CALY_GV_SELF=$0
case "$CALY_GV_SELF" in
*/*) CALY_GV_DIR=${CALY_GV_SELF%/*} ;;
*)   CALY_GV_DIR=. ;;
esac
CALY_GV_DIR=$(cd "$CALY_GV_DIR" 2>/dev/null && pwd) || CALY_GV_DIR=$PWD
CALY_SRC_ROOT=${CALY_SRC_ROOT:-$(cd "${CALY_GV_DIR}/.." 2>/dev/null && pwd)}

OUT=""
FORCE=0
QUIET=0
BPFTOOL=${BPFTOOL:-}
ARCH=${ARCH:-}
BUNDLED_DIR=""

gv_say() {
	[ "$QUIET" = "1" ] && return 0
	printf 'gen-vmlinux: %s\n' "$*"
}
gv_warn() { printf 'gen-vmlinux: warning: %s\n' "$*" >&2; }
gv_err()  { printf 'gen-vmlinux: error: %s\n' "$*" >&2; }

gv_usage() {
	cat <<'EOF'
Usage: gen-vmlinux.sh [OPTIONS] [OUTPUT]

  -o, --output PATH   where to write vmlinux.h
                      (default: <srcroot>/src/bpf/vmlinux.h)
  -f, --force         regenerate even when the output already looks valid
      --bpftool PATH  use this bpftool binary
      --arch NAME     architecture for the bundled-header fallback
                      (default: derived from uname -m)
  -q, --quiet         only print errors
  -h, --help          this text

Exit status: 0 generated, 1 hard error, 2 no BTF available (caller should fall
back to the nftables dataplane).
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	-o|--output) OUT=${2:-}; shift ;;
	--output=*)  OUT=${1#--output=} ;;
	-f|--force)  FORCE=1 ;;
	--bpftool)   BPFTOOL=${2:-}; shift ;;
	--bpftool=*) BPFTOOL=${1#--bpftool=} ;;
	--arch)      ARCH=${2:-}; shift ;;
	--arch=*)    ARCH=${1#--arch=} ;;
	-q|--quiet)  QUIET=1 ;;
	-h|--help)   gv_usage; exit 0 ;;
	-*)          gv_err "unknown option '$1'"; gv_usage >&2; exit 1 ;;
	*)           OUT=$1 ;;
	esac
	shift
done

[ -n "$OUT" ] || OUT="${CALY_SRC_ROOT}/src/bpf/vmlinux.h"

# --------------------------------------------------------------------------
# Architecture name, matching the kernel's arch/ directory layout. Bundled
# headers live in src/bpf/vmlinux/<arch>/vmlinux.h.
# --------------------------------------------------------------------------
if [ -z "$ARCH" ]; then
	case "$(uname -m 2>/dev/null || echo unknown)" in
	x86_64|amd64)        ARCH="x86" ;;
	i?86)                ARCH="x86" ;;
	aarch64|arm64)       ARCH="arm64" ;;
	armv6l|armv7l|arm)   ARCH="arm" ;;
	ppc64le|ppc64)       ARCH="powerpc" ;;
	s390x)               ARCH="s390" ;;
	riscv64)             ARCH="riscv" ;;
	mips*)               ARCH="mips" ;;
	loongarch64)         ARCH="loongarch" ;;
	*)                   ARCH=$(uname -m 2>/dev/null || echo unknown) ;;
	esac
fi

BUNDLED_DIR="${CALY_SRC_ROOT}/src/bpf/vmlinux"

# --------------------------------------------------------------------------
# Locate bpftool. Ubuntu installs it inside linux-tools-<uname -r> and does
# not always put it in PATH.
# --------------------------------------------------------------------------
gv_find_bpftool() {
	if [ -n "$BPFTOOL" ] && [ -x "$BPFTOOL" ]; then
		return 0
	fi
	if command -v bpftool >/dev/null 2>&1; then
		BPFTOOL=$(command -v bpftool)
		return 0
	fi
	gv_kr=$(uname -r 2>/dev/null || echo unknown)
	for gv_c in \
	    "/usr/lib/linux-tools/${gv_kr}/bpftool" \
	    "/usr/lib/linux-tools-${gv_kr}/bpftool" \
	    /usr/lib/linux-tools/*/bpftool \
	    /usr/sbin/bpftool /sbin/bpftool /usr/local/sbin/bpftool \
	    /usr/libexec/bpftool; do
		if [ -x "$gv_c" ]; then
			BPFTOOL=$gv_c
			return 0
		fi
	done
	BPFTOOL=""
	return 1
}

# --------------------------------------------------------------------------
# Sanity check a generated or bundled header. A truncated dump is worse than
# no dump at all: the build fails somewhere deep inside a struct definition
# with an error that says nothing about BTF.
# --------------------------------------------------------------------------
gv_validate() {
	gv_f=$1
	[ -s "$gv_f" ] || return 1

	gv_lines=$(wc -l < "$gv_f" 2>/dev/null || echo 0)
	case "$gv_lines" in
	''|*[!0-9]*) return 1 ;;
	esac
	[ "$gv_lines" -ge 500 ] || return 1

	# Types every one of our BPF programs dereferences. If the dump does not
	# describe them it is not usable, whatever its size.
	grep -q 'struct xdp_md' "$gv_f" 2>/dev/null || return 1
	grep -q 'struct __sk_buff' "$gv_f" 2>/dev/null || return 1
	grep -q 'struct ethhdr' "$gv_f" 2>/dev/null || return 1
	grep -q 'struct iphdr' "$gv_f" 2>/dev/null || return 1
	grep -q 'struct ipv6hdr' "$gv_f" 2>/dev/null || return 1
	grep -q 'struct tcphdr' "$gv_f" 2>/dev/null || return 1
	grep -q 'struct udphdr' "$gv_f" 2>/dev/null || return 1
	return 0
}

gv_atomic_install() {
	# $1 = temp file, $2 = destination
	gv_dst_dir=${2%/*}
	[ -d "$gv_dst_dir" ] || mkdir -p "$gv_dst_dir"
	if [ -f "$2" ]; then
		cp -p "$2" "${2}.bak" 2>/dev/null || true
	fi
	mv -f "$1" "$2"
	chmod 0644 "$2" 2>/dev/null || true
}

# --------------------------------------------------------------------------
# Already have a good one?
# --------------------------------------------------------------------------
if [ "$FORCE" != "1" ] && [ -f "$OUT" ]; then
	if gv_validate "$OUT"; then
		gv_say "$OUT already exists and looks valid, keeping it (--force to regenerate)"
		exit 0
	fi
	gv_warn "$OUT exists but failed validation; regenerating"
fi

OUT_DIR=${OUT%/*}
[ "$OUT_DIR" = "$OUT" ] && OUT_DIR="."
if [ ! -d "$OUT_DIR" ]; then
	mkdir -p "$OUT_DIR" || { gv_err "cannot create $OUT_DIR"; exit 1; }
fi
if [ ! -w "$OUT_DIR" ]; then
	gv_err "output directory $OUT_DIR is not writable"
	exit 1
fi

TMP="${OUT}.tmp.$$"
# shellcheck disable=SC2064
trap "rm -f '$TMP'" EXIT INT TERM HUP

# --------------------------------------------------------------------------
# Source 1: the running kernel's BTF.
# --------------------------------------------------------------------------
if gv_find_bpftool; then
	gv_say "using bpftool at $BPFTOOL"
else
	gv_warn "bpftool not found (install bpftool, or linux-tools-\$(uname -r) on Ubuntu)"
fi

if [ -n "$BPFTOOL" ] && [ -r /sys/kernel/btf/vmlinux ]; then
	gv_say "dumping BTF from /sys/kernel/btf/vmlinux"
	if "$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c \
	    > "$TMP" 2>/dev/null && gv_validate "$TMP"; then
		gv_atomic_install "$TMP" "$OUT"
		gv_say "wrote $OUT ($(wc -l < "$OUT" 2>/dev/null || echo '?') lines) from the running kernel"
		trap - EXIT INT TERM HUP
		exit 0
	fi
	gv_warn "bpftool could not produce a usable dump from /sys/kernel/btf/vmlinux"
	rm -f "$TMP"
fi

# --------------------------------------------------------------------------
# Source 2: a vmlinux image with embedded BTF (split debug packages).
# --------------------------------------------------------------------------
if [ -n "$BPFTOOL" ]; then
	KREL=$(uname -r 2>/dev/null || echo unknown)
	for gv_img in \
	    "/boot/vmlinux-${KREL}" \
	    "/lib/modules/${KREL}/vmlinux" \
	    "/lib/modules/${KREL}/build/vmlinux" \
	    "/usr/lib/debug/boot/vmlinux-${KREL}" \
	    "/usr/lib/debug/lib/modules/${KREL}/vmlinux" \
	    "/usr/lib/modules/${KREL}/vmlinux"; do
		[ -r "$gv_img" ] || continue
		gv_say "trying BTF embedded in $gv_img"
		if "$BPFTOOL" btf dump file "$gv_img" format c > "$TMP" 2>/dev/null && \
		   gv_validate "$TMP"; then
			gv_atomic_install "$TMP" "$OUT"
			gv_say "wrote $OUT from $gv_img"
			trap - EXIT INT TERM HUP
			exit 0
		fi
		rm -f "$TMP"
	done
fi

# --------------------------------------------------------------------------
# Source 3: a header bundled with the source tree.
#
# This is what makes cross-building and BTF-less build hosts work: generate on
# a machine that has BTF, commit the result under src/bpf/vmlinux/<arch>/, and
# every build host of that architecture can compile the object even though the
# BUILD kernel has no BTF. Note that the RUNTIME kernel still needs BTF for
# CO-RE relocation - a bundled header lets you build, not necessarily load.
# --------------------------------------------------------------------------
for gv_b in \
    "${BUNDLED_DIR}/${ARCH}/vmlinux.h" \
    "${BUNDLED_DIR}/vmlinux-${ARCH}.h" \
    "${CALY_SRC_ROOT}/third_party/vmlinux/${ARCH}/vmlinux.h"; do
	[ -r "$gv_b" ] || continue
	gv_say "falling back to the bundled header $gv_b"
	if gv_validate "$gv_b"; then
		cp "$gv_b" "$TMP"
		gv_atomic_install "$TMP" "$OUT"
		gv_warn "using a BUNDLED vmlinux.h for arch ${ARCH}. It describes the \
kernel it was generated on, not this one. CO-RE relocations still adapt the \
object at load time, but the running kernel must expose BTF at \
/sys/kernel/btf/vmlinux for that to happen."
		trap - EXIT INT TERM HUP
		exit 0
	fi
	gv_warn "bundled header $gv_b failed validation, ignoring it"
done

# --------------------------------------------------------------------------
# Out of options.
# --------------------------------------------------------------------------
rm -f "$TMP"
trap - EXIT INT TERM HUP

cat >&2 <<EOF
gen-vmlinux: cannot produce vmlinux.h on this system.

  kernel        : $(uname -r 2>/dev/null || echo unknown)
  architecture  : ${ARCH}
  bpftool       : ${BPFTOOL:-not found}
  /sys/kernel/btf/vmlinux : $( [ -r /sys/kernel/btf/vmlinux ] && echo present || echo ABSENT )

What this means
  The eBPF dataplane (XDP and tc rungs) needs CO-RE, and CO-RE needs BTF.
  Without it the object cannot be compiled here and would not relocate on
  this kernel even if it were.

This is a supported, documented degradation - not a failure:
  * install.sh drops to the nftables dataplane (ladder rung 4) automatically,
    or to iptables+ipset (rung 5) when nft is unavailable. Policy is
    preserved; throughput and the per-source token buckets are not.
  * To get the eBPF dataplane instead, either
      - boot a kernel built with CONFIG_DEBUG_INFO_BTF=y (every mainstream
        distro kernel since roughly 2020 has it: RHEL 8.2+, Ubuntu 20.10+,
        Debian 11+, Fedora 31+, Alpine 3.18+ with linux-lts), or
      - install bpftool and the matching kernel debug image, or
      - commit a pre-generated header to src/bpf/vmlinux/${ARCH}/vmlinux.h
        and rebuild (build-time only; the runtime kernel still needs BTF).
EOF
exit 2
