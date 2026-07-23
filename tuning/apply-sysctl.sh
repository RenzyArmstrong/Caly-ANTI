#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Caly Anti - XDP/eBPF DDoS mitigation suite
# tuning/apply-sysctl.sh - apply the kernel tuning profile, safely.
#
# Design rules, in priority order:
#
#   1. NEVER fail the whole run because one key is missing. Kernels differ:
#      net.core.netdev_budget_usecs is 4.14+, the nf_conntrack keys only exist
#      once the module is loaded, Alpine's kernel omits several, and a
#      container's /proc/sys is mostly read-only. A tuning script that aborts
#      on the first ENOENT is a tuning script that has never been run on
#      anything but the author's laptop.
#   2. Back up BEFORE writing. Every run emits a self-contained restore script
#      containing the exact previous values.
#   3. Verify AFTER writing. A successful write() is not proof: the kernel
#      clamps some values silently, and another sysctl file may win later.
#   4. Never write a value that would take the SYN proxy offline. See
#      --syncookies below.
#
# POSIX sh only: this has to run under bash (RHEL/Fedora/Arch/SUSE), dash
# (Debian/Ubuntu) and busybox ash (Alpine) without modification.
#
# `set -e` is deliberately NOT used. Almost every operation here is allowed to
# fail; error handling is explicit and per-key.

set -u

PROG="apply-sysctl.sh"
VERSION="1.0"
ABI="calyanti-1.0"

# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || SCRIPT_DIR="."

PROFILE=""
# Candidate profile locations, in priority order. Kept as a function that
# tests each path individually and quoted, rather than a whitespace-split
# string, so an install path containing a space (common on macOS, possible
# anywhere) does not tear a path in half during discovery.
find_default_profile() {
	for _c in \
		"$SCRIPT_DIR/99-calyanti-sysctl.conf" \
		"/usr/share/calyanti/tuning/99-calyanti-sysctl.conf" \
		"/usr/local/share/calyanti/tuning/99-calyanti-sysctl.conf" \
		"/etc/calyanti/tuning/99-calyanti-sysctl.conf" \
		"/etc/sysctl.d/99-calyanti-sysctl.conf"; do
		if [ -f "$_c" ]; then
			printf '%s\n' "$_c"
			return 0
		fi
	done
	return 1
}

INSTALL_PATH="/etc/sysctl.d/99-calyanti-sysctl.conf"
MODPROBE_PATH="/etc/modprobe.d/99-calyanti-conntrack.conf"
MODLOAD_PATH="/etc/modules-load.d/99-calyanti.conf"

BACKUP_DIR="/var/lib/calyanti/sysctl"
BACKUP_DIR_FALLBACK="/var/tmp/calyanti-sysctl"

# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------

ACTION="apply"          # apply | check | list | revert | install | uninstall
DRY_RUN="no"
WANT_OPTIONAL="no"
DO_BACKUP="yes"
LOAD_CONNTRACK="no"
SYNCOOKIES="auto"       # auto | 0 | 1 | 2 | keep
ONLY_PAT=""
SKIP_PAT=""
RESTORE_FILE=""
VERBOSE="no"
QUIET="no"
CT_HASHSIZE=""          # derived from the profile unless overridden

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------

N_CHANGED=0
N_UNCHANGED=0
N_MISSING=0
N_READONLY=0
N_FAILED=0
N_MISMATCH=0
N_SKIPPED=0

TMPD=""

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

C_R=""; C_G=""; C_Y=""; C_B=""; C_0=""
if [ -t 1 ] && [ "${NO_COLOR:-}" = "" ] && [ "${TERM:-dumb}" != "dumb" ]; then
	C_R=$(printf '\033[31m'); C_G=$(printf '\033[32m')
	C_Y=$(printf '\033[33m'); C_B=$(printf '\033[1m')
	C_0=$(printf '\033[0m')
fi

say()  { [ "$QUIET" = yes ] || printf '%s\n' "$*"; }
info() { [ "$QUIET" = yes ] || printf '%s\n' "$*"; }
vrb()  { [ "$VERBOSE" = yes ] && printf '  %s\n' "$*"; return 0; }
warn() { printf '%s%s: warning:%s %s\n' "$C_Y" "$PROG" "$C_0" "$*" >&2; }
err()  { printf '%s%s: error:%s %s\n' "$C_R" "$PROG" "$C_0" "$*" >&2; }
die()  { err "$*"; cleanup; exit 1; }

cleanup() {
	[ -n "$TMPD" ] && [ -d "$TMPD" ] && rm -rf "$TMPD"
	TMPD=""
}
trap 'cleanup' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

usage() {
	cat <<'EOF'
Caly Anti - apply the kernel network tuning profile.

USAGE
    apply-sysctl.sh [options]                 apply the profile to the running kernel
    apply-sysctl.sh --check                   report drift without changing anything
    apply-sysctl.sh --list                    print the parsed profile and exit
    apply-sysctl.sh --revert [FILE]           restore the values saved by a previous run
    apply-sysctl.sh --install                 also persist the profile for the next boot
    apply-sysctl.sh --uninstall               remove the persisted files

OPTIONS
    -p, --profile FILE     Profile to read. Default: the first of
                             <script dir>/99-calyanti-sysctl.conf
                             /usr/share/calyanti/tuning/99-calyanti-sysctl.conf
                             /etc/calyanti/tuning/99-calyanti-sysctl.conf
                             /etc/sysctl.d/99-calyanti-sysctl.conf
        --optional         Also apply the "#OPT" entries. Read each one's
                           comment block first: they are opt-in because at
                           least one plausible production workload breaks.
    -n, --dry-run          Show what would change. Writes nothing, not even
                           the backup.
        --no-backup        Do not write a restore script. Not recommended.
        --backup-dir DIR   Where restore scripts go. Default /var/lib/calyanti/sysctl
        --only PATTERN     Only keys matching this shell glob (e.g. 'net.ipv4.*').
        --skip PATTERN     Skip keys matching this shell glob. Repeatable is not
                           supported; use one glob with braces or run twice.
        --syncookies MODE  auto (default) | 0 | 1 | 2 | keep
                           Controls net.ipv4.tcp_syncookies only. See below.
        --load-conntrack   modprobe nf_conntrack first, so the
                           net.netfilter.nf_conntrack_* keys exist. Without
                           this they are skipped with a note when the module
                           is not loaded.
        --ct-hashsize N    Override the conntrack hash bucket count.
    -v, --verbose          Print every key, not just the changed ones.
    -q, --quiet            Errors and warnings only.
    -h, --help             This text.
    -V, --version          Version.

THE --syncookies OPTION
    The XDP SYN proxy REQUIRES net.ipv4.tcp_syncookies=2, because it answers
    SYNs itself with a cookie minted by the kernel's own secret and the stack
    must be willing to validate that cookie when the client's ACK arrives. At
    value 1 the stack only validates while its accept queue is overflowing,
    which it never is, so every proxied connection is reset.

    The raw syncookie helpers are kernel 5.15+ (plus RHEL 9's backported
    5.14). On older kernels the dataplane falls back to SYN rate limiting and
    1 is the better value, because 2 makes every connection cookie-based for
    no benefit.

      auto   2 on kernels >= 5.15 and on .el9/.el10 kernels, otherwise 1.
             When the version cannot be parsed, 2 - because writing 2 where
             the proxy is absent merely costs a little handshake efficiency,
             while writing 1 where the proxy is active breaks every inbound
             connection.
      2      Force 2. Use this on any kernel where the loader reported
             CALY_F_CAP_SYNPROXY, whatever `uname -r` says.
      1      Force 1. Correct only when the SYN proxy is definitely not in use.
      keep   Do not touch the key at all.

EXIT STATUS
    0   everything applied (or already correct)
    1   fatal: bad usage, no profile, /proc/sys unavailable, not root
    2   partial: some keys could not be applied or did not verify. The run
        completed; see the summary.

EXAMPLES
    ./apply-sysctl.sh --dry-run                 # see the diff first
    ./apply-sysctl.sh --load-conntrack          # typical first run
    ./apply-sysctl.sh --install --load-conntrack
    ./apply-sysctl.sh --check                   # after a reboot, or weekly
    ./apply-sysctl.sh --revert                  # undo the last run
EOF
}

# ---------------------------------------------------------------------------
# sysctl primitives - implemented against /proc/sys directly.
#
# The sysctl(8) binary is not universal (busybox ships a different one, some
# minimal images ship none) and its error handling differs between procps-ng
# and busybox. /proc/sys is the actual interface and it is always there.
# ---------------------------------------------------------------------------

key_path() {
	printf '/proc/sys/%s\n' "$(printf '%s' "$1" | tr '.' '/')"
}

# Print a key's current value, whitespace-normalised. Returns 1 if absent.
sysctl_get() {
	_kp=$(key_path "$1")
	[ -e "$_kp" ] || return 1
	[ -r "$_kp" ] || return 1
	# $1=$1 collapses tabs and runs of spaces to single spaces, which is what
	# makes "4096	131072	16777216" comparable to "4096 131072 16777216".
	awk '{ $1 = $1; printf "%s%s", (NR > 1 ? " " : ""), $0 } END { printf "\n" }' \
		"$_kp" 2>/dev/null
	return 0
}

# 0 written, 3 no such key, 4 not writable, 5 write rejected by the kernel.
sysctl_put() {
	_kp=$(key_path "$1")
	[ -e "$_kp" ] || return 3
	[ -w "$_kp" ] || return 4
	if printf '%s\n' "$2" > "$_kp" 2>/dev/null; then
		return 0
	fi
	return 5
}

norm() {
	printf '%s' "$*" | awk '{ $1 = $1; print }'
}

# ---------------------------------------------------------------------------
# Environment probes
# ---------------------------------------------------------------------------

kver_num() {
	uname -r 2>/dev/null | awk -F'[.-]' '
		{
			maj = $1 + 0; min = $2 + 0; pat = $3 + 0;
			if (maj == 0) { print 0; exit }
			printf "%d\n", maj * 10000 + min * 100 + (pat > 99 ? 99 : pat);
			exit
		}' 2>/dev/null
}

is_enterprise_backport() {
	case "$(uname -r 2>/dev/null)" in
	*.el9*|*.el10*|*.el11*) return 0 ;;
	esac
	return 1
}

in_container() {
	[ -f /.dockerenv ] && return 0
	[ -d /proc/vz ] && [ ! -d /proc/bc ] && return 0
	if command -v systemd-detect-virt >/dev/null 2>&1; then
		if systemd-detect-virt --container >/dev/null 2>&1; then
			return 0
		fi
	fi
	if [ -r /proc/1/environ ]; then
		if tr '\0' '\n' < /proc/1/environ 2>/dev/null | grep -q '^container='; then
			return 0
		fi
	fi
	return 1
}

conntrack_present() {
	[ -e /proc/sys/net/netfilter/nf_conntrack_max ]
}

conntrack_load() {
	conntrack_present && return 0
	command -v modprobe >/dev/null 2>&1 || return 1
	modprobe nf_conntrack >/dev/null 2>&1
	# Kernels older than 4.19 split the v4 tracker into its own module. On
	# newer kernels this modprobe simply fails and that is fine.
	modprobe nf_conntrack_ipv4 >/dev/null 2>&1
	conntrack_present
}

is_conntrack_key() {
	case "$1" in
	net.netfilter.nf_conntrack_*|net.nf_conntrack_max) return 0 ;;
	esac
	return 1
}

# ---------------------------------------------------------------------------
# Profile parsing
#
# Emits "opt|key|value" per entry. Values never contain '|' or '#', which the
# profile format guarantees.
# ---------------------------------------------------------------------------

parse_profile() {
	awk '
	{
		line = $0
		sub(/\r$/, "", line)                 # tolerate a CRLF-mangled copy
		opt = 0
		if (line ~ /^[ \t]*#OPT[ \t]+/) {
			opt = 1
			sub(/^[ \t]*#OPT[ \t]+/, "", line)
		}
		sub(/#.*$/, "", line)                # strip trailing comments
		if (line !~ /=/) next
		key = line
		sub(/=.*$/, "", key)
		gsub(/[ \t]/, "", key)
		val = line
		sub(/^[^=]*=/, "", val)
		gsub(/^[ \t]+/, "", val)
		gsub(/[ \t]+$/, "", val)
		gsub(/[ \t]+/, " ", val)
		if (key == "" || val == "") next
		if (key ~ /\|/ || val ~ /\|/) next
		printf "%d|%s|%s\n", opt, key, val
	}' "$1"
}

# ---------------------------------------------------------------------------
# Backup / restore script generation
# ---------------------------------------------------------------------------

RESTORE_OUT=""

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
			DO_BACKUP="no"
			return 1
		fi
	fi
	RESTORE_OUT="$BACKUP_DIR/restore-$_ts.sh"
	cat > "$RESTORE_OUT" <<EOF
#!/bin/sh
# Generated by Caly Anti $PROG $VERSION on $(date 2>/dev/null || echo unknown).
# Restores the sysctl values that were in effect BEFORE the profile was applied.
#
# Keys that did not exist at backup time are not listed: there is nothing to
# restore them to.
#
# Run as root:  sh $RESTORE_OUT
set -u
_rc=0
caly_restore() {
	_p="/proc/sys/\$(printf '%s' "\$1" | tr '.' '/')"
	if [ ! -e "\$_p" ]; then
		printf 'skip (gone):    %s\n' "\$1"
		return 0
	fi
	if [ ! -w "\$_p" ]; then
		printf 'skip (ro):      %s\n' "\$1"
		return 0
	fi
	if printf '%s\n' "\$2" > "\$_p" 2>/dev/null; then
		printf 'restored:       %-52s = %s\n' "\$1" "\$2"
	else
		printf 'FAILED:         %-52s = %s\n' "\$1" "\$2"
		_rc=2
	fi
	return 0
}

EOF
	chmod 0700 "$RESTORE_OUT" 2>/dev/null
	return 0
}

restore_add() {
	[ "$DO_BACKUP" = yes ] || return 0
	[ -n "$RESTORE_OUT" ] || return 0
	# Record the ORIGINAL value only once per key. A key can be written twice
	# in one run (e.g. rp_filter is set to 2 by the default block and to 1 by
	# the --optional block); backing it up on the second write would capture
	# our own first write, so --revert would restore the wrong value.
	if [ -n "${TMPD:-}" ]; then
		case "$1" in
		*/*) return 0 ;;   # keys never contain '/', keep the marker path safe
		esac
		[ -e "$TMPD/bkp.$1" ] && return 0
		: > "$TMPD/bkp.$1" 2>/dev/null
	fi
	printf "caly_restore '%s' '%s'\n" "$1" "$2" >> "$RESTORE_OUT"
}

restore_end() {
	[ "$DO_BACKUP" = yes ] || return 0
	[ -n "$RESTORE_OUT" ] || return 0
	printf '\nexit "$_rc"\n' >> "$RESTORE_OUT"
	cp -f "$RESTORE_OUT" "$BACKUP_DIR/restore-latest.sh" 2>/dev/null
	chmod 0700 "$BACKUP_DIR/restore-latest.sh" 2>/dev/null
	info ""
	info "Restore script: $RESTORE_OUT"
	info "                $BACKUP_DIR/restore-latest.sh  (used by --revert)"
	return 0
}

# ---------------------------------------------------------------------------
# Conflict attribution for --check
# ---------------------------------------------------------------------------

find_conflicts() {
	# $1 = key. Print the files that also set it, in application order.
	_k=$1
	_esc=$(printf '%s' "$_k" | sed 's/\./\\./g')
	for _f in /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /run/sysctl.d/*.conf \
	          /etc/sysctl.d/*.conf /etc/sysctl.conf; do
		[ -f "$_f" ] || continue
		[ "$_f" = "$INSTALL_PATH" ] && continue
		if grep -Eq "^[[:space:]]*(-)?$_esc[[:space:]]*=" "$_f" 2>/dev/null; then
			printf '        also set in %s\n' "$_f"
		fi
	done
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

while [ $# -gt 0 ]; do
	case "$1" in
	-p|--profile)   [ $# -ge 2 ] || die "--profile needs an argument"; PROFILE=$2; shift 2 ;;
	--profile=*)    PROFILE=${1#--profile=}; shift ;;
	--optional)     WANT_OPTIONAL="yes"; shift ;;
	-n|--dry-run)   DRY_RUN="yes"; shift ;;
	--no-backup)    DO_BACKUP="no"; shift ;;
	--backup-dir)   [ $# -ge 2 ] || die "--backup-dir needs an argument"; BACKUP_DIR=$2; shift 2 ;;
	--backup-dir=*) BACKUP_DIR=${1#--backup-dir=}; shift ;;
	--only)         [ $# -ge 2 ] || die "--only needs an argument"; ONLY_PAT=$2; shift 2 ;;
	--only=*)       ONLY_PAT=${1#--only=}; shift ;;
	--skip)         [ $# -ge 2 ] || die "--skip needs an argument"; SKIP_PAT=$2; shift 2 ;;
	--skip=*)       SKIP_PAT=${1#--skip=}; shift ;;
	--syncookies)   [ $# -ge 2 ] || die "--syncookies needs an argument"; SYNCOOKIES=$2; shift 2 ;;
	--syncookies=*) SYNCOOKIES=${1#--syncookies=}; shift ;;
	--load-conntrack) LOAD_CONNTRACK="yes"; shift ;;
	--ct-hashsize)  [ $# -ge 2 ] || die "--ct-hashsize needs an argument"; CT_HASHSIZE=$2; shift 2 ;;
	--ct-hashsize=*) CT_HASHSIZE=${1#--ct-hashsize=}; shift ;;
	--check)        ACTION="check"; shift ;;
	--list)         ACTION="list"; shift ;;
	--revert)
		ACTION="revert"; shift
		if [ $# -gt 0 ]; then
			case "$1" in
			-*) : ;;
			*) RESTORE_FILE=$1; shift ;;
			esac
		fi
		;;
	--install)      ACTION="install"; shift ;;
	--uninstall)    ACTION="uninstall"; shift ;;
	-v|--verbose)   VERBOSE="yes"; shift ;;
	-q|--quiet)     QUIET="yes"; shift ;;
	-h|--help)      usage; exit 0 ;;
	-V|--version)   printf '%s %s (%s)\n' "$PROG" "$VERSION" "$ABI"; exit 0 ;;
	--)             shift; break ;;
	*)              die "unknown option '$1' (try --help)" ;;
	esac
done

case "$SYNCOOKIES" in
auto|keep|0|1|2) : ;;
*) die "--syncookies must be auto, keep, 0, 1 or 2" ;;
esac

# ---------------------------------------------------------------------------
# --revert
# ---------------------------------------------------------------------------

if [ "$ACTION" = revert ]; then
	[ "$(id -u 2>/dev/null || echo 1)" = "0" ] || die "--revert must run as root"
	if [ -z "$RESTORE_FILE" ]; then
		RESTORE_FILE="$BACKUP_DIR/restore-latest.sh"
		[ -f "$RESTORE_FILE" ] || RESTORE_FILE="$BACKUP_DIR_FALLBACK/restore-latest.sh"
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
	_rc=$?
	say ""
	if [ $_rc -eq 0 ]; then
		say "Revert complete. The persisted files (if any) were NOT removed;"
		say "use --uninstall for that, or the profile returns at the next boot."
	else
		warn "some keys could not be restored (see above)"
	fi
	exit $_rc
fi

# ---------------------------------------------------------------------------
# Locate the profile
# ---------------------------------------------------------------------------

if [ -z "$PROFILE" ]; then
	PROFILE=$(find_default_profile) || PROFILE=""
fi
[ -n "$PROFILE" ] || die "no profile found; pass --profile FILE"
[ -f "$PROFILE" ] || die "profile '$PROFILE' does not exist"
[ -r "$PROFILE" ] || die "profile '$PROFILE' is not readable"

# ---------------------------------------------------------------------------
# --uninstall
# ---------------------------------------------------------------------------

if [ "$ACTION" = uninstall ]; then
	[ "$(id -u 2>/dev/null || echo 1)" = "0" ] || die "--uninstall must run as root"
	_n=0
	for _f in "$INSTALL_PATH" "$MODPROBE_PATH" "$MODLOAD_PATH"; do
		if [ -f "$_f" ]; then
			if rm -f "$_f" 2>/dev/null; then
				say "removed  $_f"
				_n=$((_n + 1))
			else
				warn "could not remove $_f"
			fi
		fi
	done
	[ "$_n" -eq 0 ] && say "nothing to remove"
	say ""
	say "The RUNNING kernel still has the tuned values. To put them back the way"
	say "they were, run:  $0 --revert"
	exit 0
fi

# ---------------------------------------------------------------------------
# Parse
# ---------------------------------------------------------------------------

if ! TMPD=$(mktemp -d 2>/dev/null) || [ -z "$TMPD" ]; then
	# No mktemp (very minimal images). Create a directory that must not
	# already exist, so a pre-planted symlink in /tmp cannot be followed.
	TMPD="${TMPDIR:-/tmp}/calyanti-sysctl.$$.$(date +%s 2>/dev/null || echo 0)"
	(umask 077; mkdir "$TMPD") 2>/dev/null || die "cannot create a temporary directory"
fi
chmod 0700 "$TMPD" 2>/dev/null
[ -d "$TMPD" ] || die "cannot create a temporary directory"
PARSED="$TMPD/parsed"

parse_profile "$PROFILE" > "$PARSED" 2>/dev/null || die "failed to parse $PROFILE"
[ -s "$PARSED" ] || die "profile '$PROFILE' contains no settable keys"

if [ "$ACTION" = list ]; then
	say "# profile: $PROFILE"
	say "# columns: state key = value"
	while IFS='|' read -r _o _k _v; do
		if [ "$_o" = "1" ]; then
			printf 'optional  %-52s = %s\n' "$_k" "$_v"
		else
			printf 'default   %-52s = %s\n' "$_k" "$_v"
		fi
	done < "$PARSED"
	exit 0
fi

# ---------------------------------------------------------------------------
# Determine the effective tcp_syncookies value
# ---------------------------------------------------------------------------

SYNCOOKIE_VALUE=""
if [ "$SYNCOOKIES" = keep ]; then
	SYNCOOKIE_VALUE=""
elif [ "$SYNCOOKIES" = auto ]; then
	_kv=$(kver_num)
	[ -n "$_kv" ] || _kv=0
	if [ "$_kv" -ge 51500 ] 2>/dev/null; then
		SYNCOOKIE_VALUE=2
	elif is_enterprise_backport; then
		SYNCOOKIE_VALUE=2
	elif [ "$_kv" -eq 0 ]; then
		SYNCOOKIE_VALUE=2
	else
		SYNCOOKIE_VALUE=1
	fi
else
	SYNCOOKIE_VALUE="$SYNCOOKIES"
fi

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

[ -d /proc/sys ] || die "/proc/sys is not mounted; nothing to tune"

if [ "$ACTION" = apply ] || [ "$ACTION" = install ]; then
	if [ "$DRY_RUN" = no ] && [ "$(id -u 2>/dev/null || echo 1)" != "0" ]; then
		die "must run as root (or use --dry-run / --check)"
	fi
fi

if in_container; then
	warn "this looks like a container. net.* sysctls are per network namespace:"
	warn "you are tuning THIS namespace, and most keys will be read-only."
	warn "Tune the host, not the container."
fi

# nf_conntrack: the keys only exist once the module is loaded, and at boot
# systemd-sysctl usually runs before anything loads it - which is why the
# conntrack half of a sysctl.d file so often appears to do nothing.
CT_AVAILABLE="no"
if grep -q 'nf_conntrack' "$PARSED" 2>/dev/null; then
	if conntrack_present; then
		CT_AVAILABLE="yes"
	elif [ "$LOAD_CONNTRACK" = yes ] && [ "$DRY_RUN" = no ]; then
		if conntrack_load; then
			CT_AVAILABLE="yes"
			info "loaded nf_conntrack so its sysctls exist"
		else
			warn "could not load nf_conntrack; its keys will be skipped"
		fi
	else
		info "nf_conntrack is not loaded: its keys will be SKIPPED."
		info "  Re-run with --load-conntrack to size the conntrack table now,"
		info "  or ignore this if nothing on this host uses netfilter conntrack."
	fi
fi

# ---------------------------------------------------------------------------
# Main pass
# ---------------------------------------------------------------------------

if [ "$ACTION" = check ]; then
	say "${C_B}Caly Anti sysctl drift check${C_0}"
else
	say "${C_B}Caly Anti sysctl profile${C_0}"
fi
say "  profile:     $PROFILE"
say "  kernel:      $(uname -r 2>/dev/null || echo unknown)"
if [ -n "$SYNCOOKIE_VALUE" ]; then
	say "  syncookies:  $SYNCOOKIE_VALUE (--syncookies $SYNCOOKIES)"
else
	say "  syncookies:  untouched (--syncookies keep)"
fi
[ "$DRY_RUN" = yes ] && say "  mode:        DRY RUN, nothing will be written"
say ""

if [ "$ACTION" != check ] && [ "$DRY_RUN" = no ] && [ "$DO_BACKUP" = yes ]; then
	restore_begin || true
fi

while IFS='|' read -r OPT KEY VAL; do
	[ -n "$KEY" ] || continue

	# --- selection filters -------------------------------------------------
	if [ "$OPT" = "1" ] && [ "$WANT_OPTIONAL" != yes ]; then
		N_SKIPPED=$((N_SKIPPED + 1))
		vrb "optional (not requested): $KEY"
		continue
	fi
	if [ -n "$ONLY_PAT" ]; then
		# shellcheck disable=SC2254
		case "$KEY" in
		$ONLY_PAT) : ;;
		*) N_SKIPPED=$((N_SKIPPED + 1)); continue ;;
		esac
	fi
	if [ -n "$SKIP_PAT" ]; then
		# shellcheck disable=SC2254
		case "$KEY" in
		$SKIP_PAT) N_SKIPPED=$((N_SKIPPED + 1)); vrb "skipped by --skip: $KEY"; continue ;;
		esac
	fi
	if is_conntrack_key "$KEY" && [ "$CT_AVAILABLE" != yes ]; then
		N_SKIPPED=$((N_SKIPPED + 1))
		vrb "conntrack not loaded: $KEY"
		continue
	fi

	# --- per-key value overrides ------------------------------------------
	if [ "$KEY" = "net.ipv4.tcp_syncookies" ]; then
		if [ -z "$SYNCOOKIE_VALUE" ]; then
			N_SKIPPED=$((N_SKIPPED + 1))
			vrb "syncookies untouched by request"
			continue
		fi
		VAL="$SYNCOOKIE_VALUE"
	fi
	if [ "$KEY" = "net.netfilter.nf_conntrack_buckets" ] && [ -n "$CT_HASHSIZE" ]; then
		VAL="$CT_HASHSIZE"
	fi
	if [ "$KEY" = "net.netfilter.nf_conntrack_buckets" ] && [ -z "$CT_HASHSIZE" ]; then
		CT_HASHSIZE="$VAL"
	fi

	WANT=$(norm "$VAL")

	# --- read the current value -------------------------------------------
	if ! CUR=$(sysctl_get "$KEY"); then
		N_MISSING=$((N_MISSING + 1))
		vrb "absent on this kernel: $KEY"
		continue
	fi
	CUR=$(norm "$CUR")

	if [ "$CUR" = "$WANT" ]; then
		N_UNCHANGED=$((N_UNCHANGED + 1))
		vrb "ok        $KEY = $CUR"
		continue
	fi

	# --- check mode reports and moves on ----------------------------------
	if [ "$ACTION" = check ]; then
		N_MISMATCH=$((N_MISMATCH + 1))
		printf '%sDRIFT%s   %-48s is %-18s want %s\n' \
			"$C_Y" "$C_0" "$KEY" "$CUR" "$WANT"
		find_conflicts "$KEY"
		continue
	fi

	# --- dry run ----------------------------------------------------------
	if [ "$DRY_RUN" = yes ]; then
		N_CHANGED=$((N_CHANGED + 1))
		printf 'would set %-48s %s -> %s\n' "$KEY" "$CUR" "$WANT"
		continue
	fi

	# --- back up, then write ----------------------------------------------
	restore_add "$KEY" "$CUR"

	sysctl_put "$KEY" "$WANT"
	RC=$?

	if [ $RC -eq 3 ]; then
		N_MISSING=$((N_MISSING + 1))
		vrb "vanished between read and write: $KEY"
		continue
	fi
	if [ $RC -eq 4 ]; then
		N_READONLY=$((N_READONLY + 1))
		warn "read-only (namespace or hardened kernel): $KEY"
		continue
	fi
	if [ $RC -ne 0 ]; then
		# The conntrack hash table is a module parameter on older kernels and
		# the sysctl rejects the write. Resizing through the module parameter
		# does the same job and works everywhere the parameter is writable.
		if [ "$KEY" = "net.netfilter.nf_conntrack_buckets" ] && \
		   [ -w /sys/module/nf_conntrack/parameters/hashsize ]; then
			if printf '%s\n' "$WANT" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null; then
				N_CHANGED=$((N_CHANGED + 1))
				printf '%schanged%s  %-48s %s -> %s (via module parameter)\n' \
					"$C_G" "$C_0" "$KEY" "$CUR" "$WANT"
				continue
			fi
		fi
		N_FAILED=$((N_FAILED + 1))
		warn "kernel rejected $KEY = $WANT (current $CUR)"
		continue
	fi

	# --- verify -----------------------------------------------------------
	NEW=$(sysctl_get "$KEY" 2>/dev/null) || NEW=""
	NEW=$(norm "$NEW")
	if [ "$NEW" = "$WANT" ]; then
		N_CHANGED=$((N_CHANGED + 1))
		printf '%schanged%s  %-48s %s -> %s\n' "$C_G" "$C_0" "$KEY" "$CUR" "$NEW"
	else
		N_MISMATCH=$((N_MISMATCH + 1))
		warn "wrote $KEY = $WANT but it reads back as '$NEW' (kernel clamped it?)"
	fi
done < "$PARSED"

[ "$ACTION" != check ] && [ "$DRY_RUN" = no ] && restore_end

# ---------------------------------------------------------------------------
# --install: persist for the next boot
# ---------------------------------------------------------------------------

if [ "$ACTION" = install ] && [ "$DRY_RUN" = no ]; then
	say ""
	say "${C_B}Persisting for the next boot${C_0}"

	if [ ! -d /etc/sysctl.d ]; then
		mkdir -p /etc/sysctl.d 2>/dev/null || warn "cannot create /etc/sysctl.d"
	fi

	if [ -d /etc/sysctl.d ]; then
		# Copy the profile, rewriting only the syncookies line so that the
		# boot-time value matches what we just applied.
		if [ -n "$SYNCOOKIE_VALUE" ]; then
			sed "s/^\([[:space:]]*net\.ipv4\.tcp_syncookies[[:space:]]*=[[:space:]]*\).*$/\1$SYNCOOKIE_VALUE/" \
				"$PROFILE" > "$INSTALL_PATH.tmp.$$" 2>/dev/null
		else
			cp -f "$PROFILE" "$INSTALL_PATH.tmp.$$" 2>/dev/null
		fi
		if [ -s "$INSTALL_PATH.tmp.$$" ]; then
			chmod 0644 "$INSTALL_PATH.tmp.$$" 2>/dev/null
			if mv -f "$INSTALL_PATH.tmp.$$" "$INSTALL_PATH" 2>/dev/null; then
				say "installed  $INSTALL_PATH"
			else
				rm -f "$INSTALL_PATH.tmp.$$" 2>/dev/null
				warn "could not install $INSTALL_PATH"
			fi
		else
			rm -f "$INSTALL_PATH.tmp.$$" 2>/dev/null
			warn "could not stage $INSTALL_PATH"
		fi
	fi

	if [ "$WANT_OPTIONAL" = yes ]; then
		warn "--optional entries were applied to the RUNNING kernel but are still"
		warn "commented out in $INSTALL_PATH, so they will NOT come back after a"
		warn "reboot. Delete the '#OPT ' prefix on the ones you want to keep."
	fi

	# Conntrack: the sysctl file is applied long before anything loads
	# nf_conntrack, so the sizing has to be a module parameter as well.
	if [ "$LOAD_CONNTRACK" = yes ] || conntrack_present; then
		if [ -d /etc/modprobe.d ] || mkdir -p /etc/modprobe.d 2>/dev/null; then
			_hs="$CT_HASHSIZE"
			if [ -z "$_hs" ]; then
				_hs=$(awk -F'|' \
					'$2 == "net.netfilter.nf_conntrack_buckets" { print $3; exit }' \
					"$PARSED" 2>/dev/null)
			fi
			[ -n "$_hs" ] || _hs=65536
			{
				printf '# Caly Anti conntrack sizing. Applied at module load, because\n'
				printf '# net.netfilter.nf_conntrack_buckets is read-only on some kernels\n'
				printf '# and because sysctl.d runs before nf_conntrack is loaded.\n'
				printf 'options nf_conntrack hashsize=%s\n' "$_hs"
			} > "$MODPROBE_PATH.tmp.$$" 2>/dev/null
			if [ -s "$MODPROBE_PATH.tmp.$$" ]; then
				chmod 0644 "$MODPROBE_PATH.tmp.$$" 2>/dev/null
				mv -f "$MODPROBE_PATH.tmp.$$" "$MODPROBE_PATH" 2>/dev/null \
					&& say "installed  $MODPROBE_PATH (hashsize=$_hs)" \
					|| { rm -f "$MODPROBE_PATH.tmp.$$" 2>/dev/null; warn "could not install $MODPROBE_PATH"; }
			fi
		fi
		if [ "$LOAD_CONNTRACK" = yes ]; then
			if [ -d /etc/modules-load.d ] || mkdir -p /etc/modules-load.d 2>/dev/null; then
				printf '# Caly Anti: load conntrack early so its sysctls exist at boot.\nnf_conntrack\n' \
					> "$MODLOAD_PATH" 2>/dev/null \
					&& { chmod 0644 "$MODLOAD_PATH" 2>/dev/null; say "installed  $MODLOAD_PATH"; } \
					|| warn "could not install $MODLOAD_PATH"
			fi
			if [ ! -d /etc/modules-load.d ] && [ -f /etc/modules ]; then
				# Debian-style fallback for systems without systemd-modules-load.
				grep -q '^nf_conntrack$' /etc/modules 2>/dev/null || \
					printf 'nf_conntrack\n' >> /etc/modules 2>/dev/null
			fi
		fi
	fi

	say ""
	say "Verify what a fresh boot would produce:  sysctl --system   (or reboot)"
	say "TRAP: /etc/sysctl.conf is applied AFTER every sysctl.d drop-in. If a key"
	say "      is also set there, it wins. '$0 --check' will name the file."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

say ""
say "${C_B}Summary${C_0}"
if [ "$ACTION" = check ]; then
	say "  matching profile:      $N_UNCHANGED"
	say "  drifted:               $N_MISMATCH"
else
	if [ "$DRY_RUN" = yes ]; then
		say "  would change:          $N_CHANGED"
	else
		say "  changed:               $N_CHANGED"
	fi
	say "  already correct:       $N_UNCHANGED"
	[ "$N_MISMATCH" -gt 0 ] && say "  ${C_Y}did not verify:        $N_MISMATCH${C_0}"
	[ "$N_FAILED" -gt 0 ]   && say "  ${C_R}rejected by kernel:    $N_FAILED${C_0}"
	[ "$N_READONLY" -gt 0 ] && say "  read-only:             $N_READONLY"
fi
say "  absent on this kernel: $N_MISSING"
say "  skipped:               $N_SKIPPED"

if [ "$N_MISSING" -gt 0 ] && [ "$VERBOSE" != yes ]; then
	say ""
	say "  ($N_MISSING keys do not exist on this kernel. That is expected and is"
	say "   not an error - re-run with -v to see which. Older kernels lack"
	say "   netdev_budget_usecs, some hardened kernels lack the BPF JIT knobs,"
	say "   and the conntrack keys only exist once nf_conntrack is loaded.)"
fi

if [ "$ACTION" = check ]; then
	[ "$N_MISMATCH" -gt 0 ] && exit 2
	exit 0
fi

if [ "$N_FAILED" -gt 0 ] || [ "$N_MISMATCH" -gt 0 ] || [ "$N_READONLY" -gt 0 ]; then
	exit 2
fi
exit 0
