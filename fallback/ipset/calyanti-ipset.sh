#!/bin/sh
# shellcheck shell=sh
#
# =============================================================================
#  Caly Anti - ipset manager for the iptables fallback  (ladder rung 5)
# =============================================================================
#
#  Creates and maintains the hash:net sets that back the iptables dataplane
#  (fallback/iptables/calyanti-iptables.sh):
#
#    calyanti_allow4 / calyanti_allow6   operator allowlist (escape hatch)
#    calyanti_block4 / calyanti_block6   static operator blocklist
#    calyanti_ban4   / calyanti_ban6     dynamic auto-ban, per-entry timeout
#
#  The allow/block sets are populated from calyanti.conf. The ban sets are
#  created with a default timeout so entries added by the dataplane (the
#  `-j SET --add-set calyanti_ban4 src` rule) or by the daemon/CLI expire on
#  their own - a source can never be banned forever by accident.
#
#  Restore semantics use `ipset restore` against a temporary "swap" set and
#  `ipset swap`, so a reload is atomic: the iptables rules that reference the
#  set by name never see a half-populated set and never a missing one.
#
#  USAGE
#    calyanti-ipset.sh [options] {create|reload|save|restore|list|flush|destroy|add|del}
#
#  COMMANDS
#    create        create any missing sets and load allow/block from config
#    reload        atomically replace allow/block contents from config
#    save          write all calyanti_* sets to the save file
#    restore       load the sets from the save file (for boot)
#    list          show the sets and their members
#    flush         empty the sets but keep them (keeps iptables refs valid)
#    destroy       remove the sets entirely (run AFTER removing iptables refs)
#    add SET CIDR [TTL]   add one element (SET = allow4/block4/ban4/...)
#    del SET CIDR         remove one element
#
#  OPTIONS
#    -c, --config PATH   configuration    (default /etc/calyanti/calyanti.conf)
#    -f, --file PATH     save/restore file (default /etc/calyanti/ipset.save)
#        --ban-ttl DUR   default ban timeout (default: from config ban_ttl_base)
#        --max N         hashsize/maxelem hint (default 262144)
#    -q,-v,-h            quiet / verbose / help
#
#  EXIT CODES
#    0 ok  1 usage  2 missing dependency  3 config/file error  4 ipset failure
# =============================================================================

set -eu

PROG="calyanti-ipset"
VERSION="1.0"

CONF_FILE="/etc/calyanti/calyanti.conf"
SAVE_FILE="/etc/calyanti/ipset.save"
BAN_TTL_OPT=""
MAXELEM=262144
VERBOSITY=1
IPSET_BIN=""
COMMAND=""
ARG1=""
ARG2=""
ARG3=""

SETS4="calyanti_allow4 calyanti_block4 calyanti_ban4"
SETS6="calyanti_allow6 calyanti_block6 calyanti_ban6"

log_err() { printf '%s: error: %s\n' "$PROG" "$*" >&2; }
log_warn() { [ "$VERBOSITY" -ge 1 ] && printf '%s: warning: %s\n' "$PROG" "$*" >&2; return 0; }
log_info() { [ "$VERBOSITY" -ge 1 ] && printf '%s: %s\n' "$PROG" "$*" >&2; return 0; }
log_dbg() { [ "$VERBOSITY" -ge 2 ] && printf '%s: debug: %s\n' "$PROG" "$*" >&2; return 0; }
die() {
	_rc=$1
	shift
	log_err "$*"
	exit "$_rc"
}

usage() {
	cat <<'USAGE_EOF'
calyanti-ipset - ipset manager for the iptables fallback (ladder rung 5)

Usage: calyanti-ipset.sh [options] {create|reload|save|restore|list|flush|destroy|add|del}

Commands
  create               create missing sets, load allow/block from config
  reload               atomically replace allow/block contents from config
  save                 write all calyanti_* sets to the save file
  restore              load the sets from the save file (boot)
  list                 show the sets and their members
  flush                empty the sets but keep them
  destroy              remove the sets (run AFTER removing iptables refs)
  add SET CIDR [TTL]   add one element (SET = allow4/block4/ban4/...)
  del SET CIDR         remove one element

Options
  -c, --config PATH    configuration (default /etc/calyanti/calyanti.conf)
  -f, --file PATH      save/restore file (default /etc/calyanti/ipset.save)
      --ban-ttl DUR    default ban timeout (default: config ban_ttl_base)
      --max N          hashsize/maxelem hint (default 262144)
  -q, --quiet
  -v, --verbose
  -h, --help

Exit codes
  0 ok  1 usage  2 missing dependency  3 config/file error  4 ipset failure
USAGE_EOF
}

# -----------------------------------------------------------------------------
while [ $# -gt 0 ]; do
	case "$1" in
	-c | --config)
		[ $# -ge 2 ] || die 1 "--config needs an argument"
		CONF_FILE=$2
		shift 2
		;;
	-f | --file)
		[ $# -ge 2 ] || die 1 "--file needs an argument"
		SAVE_FILE=$2
		shift 2
		;;
	--ban-ttl)
		[ $# -ge 2 ] || die 1 "--ban-ttl needs an argument"
		BAN_TTL_OPT=$2
		shift 2
		;;
	--max)
		[ $# -ge 2 ] || die 1 "--max needs an argument"
		MAXELEM=$2
		shift 2
		;;
	-q | --quiet)
		VERBOSITY=0
		shift
		;;
	-v | --verbose)
		VERBOSITY=2
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	create | reload | save | restore | list | flush | destroy | add | del)
		COMMAND=$1
		shift
		;;
	*)
		if [ -z "$COMMAND" ]; then
			die 1 "unknown argument '$1' (try --help)"
		elif [ -z "$ARG1" ]; then
			ARG1=$1
		elif [ -z "$ARG2" ]; then
			ARG2=$1
		elif [ -z "$ARG3" ]; then
			ARG3=$1
		else
			die 1 "too many arguments"
		fi
		shift
		;;
	esac
done

[ -n "$COMMAND" ] || die 1 "a command is required (try --help)"

case "$MAXELEM" in '' | *[!0-9]*) die 1 "--max must be a whole number" ;; esac
[ "$MAXELEM" -lt 1024 ] && MAXELEM=1024

# -----------------------------------------------------------------------------
find_ipset() {
	for _c in ipset /usr/sbin/ipset /sbin/ipset /usr/bin/ipset; do
		if command -v "$_c" >/dev/null 2>&1; then
			IPSET_BIN=$(command -v "$_c")
			return 0
		fi
	done
	die 2 "ipset not found; the iptables fallback will use inline '-m recent' instead"
}

# -----------------------------------------------------------------------------
# Config parsing (identical semantics to the other fallback scripts)
# -----------------------------------------------------------------------------
conf_all() {
	[ -f "$CONF_FILE" ] || return 0
	awk -v key="$1" '
		{ sub(/#.*$/, "") }
		/^[ \t]*\[/ { next }
		{
			line = $0
			if (index(line, "=") == 0) next
			k = line; sub(/=.*$/, "", k)
			gsub(/^[ \t]+|[ \t]+$/, "", k)
			if (k != key) next
			v = line; sub(/^[^=]*=/, "", v)
			gsub(/^[ \t]+|[ \t]+$/, "", v)
			if (v != "") print v
		}
	' "$CONF_FILE"
}
conf_get() {
	_v=$(conf_all "$1" | tail -n 1)
	if [ -z "$_v" ]; then printf '%s' "${2-}"; else printf '%s' "$_v"; fi
}
dur_secs() {
	_raw=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
	_n=$(printf '%s' "$_raw" | sed 's/[^0-9].*$//')
	_u=$(printf '%s' "$_raw" | sed 's/^[0-9]*//')
	case "$_n" in '' | *[!0-9]*) _n=0 ;; esac
	case "$_u" in
	'' | s | sec | secs) _s=$_n ;;
	ms) _s=$(((_n + 999) / 1000)) ;;
	us | ns) _s=1 ;;
	m | min) _s=$((_n * 60)) ;;
	h | hr | hour | hours) _s=$((_n * 3600)) ;;
	d | day | days) _s=$((_n * 86400)) ;;
	*) _s=$_n ;;
	esac
	[ "$_s" -lt 1 ] && _s=1
	printf '%s' "$_s"
}
is_v6() { case "$1" in *:*) return 0 ;; *) return 1 ;; esac; }
valid_cidr() { case "$1" in '' | *[!0-9a-fA-F.:/]*) return 1 ;; *) return 0 ;; esac; }

resolve_ban_ttl() {
	if [ -n "$BAN_TTL_OPT" ]; then
		BAN_TTL=$(dur_secs "$BAN_TTL_OPT")
	else
		BAN_TTL=$(dur_secs "$(conf_get ban_ttl_base 10m)")
	fi
}

# hashsize should be a power of two and roughly maxelem/4; ipset will round.
hashsize_for() {
	_h=$((MAXELEM / 4))
	[ "$_h" -lt 1024 ] && _h=1024
	printf '%s' "$_h"
}

# -----------------------------------------------------------------------------
# Set creation. `-exist` makes create idempotent: an existing set of the same
# type is left untouched, so `create` is safe to run repeatedly.
# -----------------------------------------------------------------------------
create_one() {
	# create_one SETNAME FAMILY HAS_TIMEOUT
	_name=$1
	_fam=$2
	_timeout=$3
	_hs=$(hashsize_for)
	if [ "$_timeout" = "yes" ]; then
		"$IPSET_BIN" create "$_name" hash:net family "$_fam" \
			hashsize "$_hs" maxelem "$MAXELEM" timeout "$BAN_TTL" counters -exist 2>/dev/null ||
			"$IPSET_BIN" create "$_name" hash:net family "$_fam" \
				hashsize "$_hs" maxelem "$MAXELEM" timeout "$BAN_TTL" -exist ||
			die 4 "failed to create set $_name"
	else
		"$IPSET_BIN" create "$_name" hash:net family "$_fam" \
			hashsize "$_hs" maxelem "$MAXELEM" -exist ||
			die 4 "failed to create set $_name"
	fi
	log_dbg "set $_name ready (family=$_fam timeout=$_timeout)"
}

create_all() {
	resolve_ban_ttl
	create_one calyanti_allow4 inet no
	create_one calyanti_block4 inet no
	create_one calyanti_ban4 inet yes
	create_one calyanti_allow6 inet6 no
	create_one calyanti_block6 inet6 no
	create_one calyanti_ban6 inet6 yes
}

# -----------------------------------------------------------------------------
# Load allow/block from the config into a swap set, then swap atomically.
# The live set that iptables references is never emptied mid-flight.
# -----------------------------------------------------------------------------
load_list_into() {
	# load_list_into SETNAME FAMILY CONFKEY
	_name=$1
	_fam=$2
	_key=$3
	_tmp="${_name}_swp"
	_hs=$(hashsize_for)

	"$IPSET_BIN" create "$_tmp" hash:net family "$_fam" hashsize "$_hs" maxelem "$MAXELEM" -exist ||
		die 4 "failed to create swap set $_tmp"
	"$IPSET_BIN" flush "$_tmp" 2>/dev/null || true

	_count=0
	conf_all "$_key" | tr ',' '\n' | sed -e 's/^[ \t]*//' -e 's/[ \t]*$//' -e '/^$/d' >"$TMP_LIST"
	while IFS= read -r _cidr; do
		[ -n "$_cidr" ] || continue
		valid_cidr "$_cidr" || {
			log_warn "ignoring malformed '$_key' entry '$_cidr'"
			continue
		}
		if [ "$_fam" = inet6 ]; then
			is_v6 "$_cidr" || continue
		else
			is_v6 "$_cidr" && continue
		fi
		if "$IPSET_BIN" add "$_tmp" "$_cidr" -exist 2>>"$TMP_ERR"; then
			_count=$((_count + 1))
		else
			log_warn "ipset rejected '$_cidr' for $_name"
		fi
	done <"$TMP_LIST"

	# Ensure the live set exists before swapping into it.
	"$IPSET_BIN" create "$_name" hash:net family "$_fam" hashsize "$_hs" maxelem "$MAXELEM" -exist || true
	"$IPSET_BIN" swap "$_tmp" "$_name" || die 4 "failed to swap $_tmp into $_name"
	"$IPSET_BIN" destroy "$_tmp" 2>/dev/null || true
	log_info "loaded $_count entries into $_name"
}

reload_lists() {
	load_list_into calyanti_allow4 inet allow
	load_list_into calyanti_block4 inet block
	load_list_into calyanti_allow6 inet6 allow
	load_list_into calyanti_block6 inet6 block
}

# -----------------------------------------------------------------------------
save_sets() {
	_dir=$(dirname -- "$SAVE_FILE")
	[ -d "$_dir" ] || mkdir -p "$_dir" || die 3 "cannot create $_dir"
	# Save only our own sets so restore never resurrects someone else's.
	: >"$SAVE_FILE.tmp"
	for _s in $SETS4 $SETS6; do
		if "$IPSET_BIN" list "$_s" >/dev/null 2>&1; then
			"$IPSET_BIN" save "$_s" >>"$SAVE_FILE.tmp" 2>/dev/null || true
		fi
	done
	if [ ! -s "$SAVE_FILE.tmp" ]; then
		rm -f "$SAVE_FILE.tmp"
		die 3 "no calyanti_* sets are loaded; nothing to save"
	fi
	mv "$SAVE_FILE.tmp" "$SAVE_FILE"
	log_info "saved calyanti_* sets to $SAVE_FILE"
}

restore_sets() {
	[ -f "$SAVE_FILE" ] || die 3 "save file '$SAVE_FILE' not found"
	# `ipset restore` is all-or-nothing. `-exist` lets it overwrite sets
	# that already exist (e.g. after create ran at boot).
	if "$IPSET_BIN" restore -exist <"$SAVE_FILE" 2>>"$TMP_ERR"; then
		log_info "restored sets from $SAVE_FILE"
	else
		log_err "$(sed 's/^/  /' "$TMP_ERR" 2>/dev/null)"
		die 4 "ipset restore failed"
	fi
}

list_sets() {
	_any=0
	for _s in $SETS4 $SETS6; do
		if "$IPSET_BIN" list "$_s" >/dev/null 2>&1; then
			"$IPSET_BIN" list "$_s"
			_any=1
		fi
	done
	[ "$_any" -eq 1 ] || {
		log_info "no calyanti_* sets are loaded"
		return 1
	}
	return 0
}

flush_sets() {
	for _s in $SETS4 $SETS6; do
		"$IPSET_BIN" flush "$_s" 2>/dev/null || true
	done
	log_info "flushed calyanti_* sets (sets kept so iptables references stay valid)"
}

destroy_sets() {
	# Also clean up any leftover swap sets from an interrupted reload.
	for _s in $SETS4 $SETS6; do
		"$IPSET_BIN" destroy "$_s" 2>/dev/null || true
		"$IPSET_BIN" destroy "${_s}_swp" 2>/dev/null || true
	done
	log_info "destroyed calyanti_* sets"
	log_warn "make sure the iptables chains referencing these sets were removed first (calyanti-iptables.sh --remove)"
}

# add/del a single element. Set alias accepts short names (allow4, ban6, ...).
set_alias() {
	case "$1" in
	allow4 | calyanti_allow4) printf 'calyanti_allow4' ;;
	block4 | calyanti_block4) printf 'calyanti_block4' ;;
	ban4 | calyanti_ban4) printf 'calyanti_ban4' ;;
	allow6 | calyanti_allow6) printf 'calyanti_allow6' ;;
	block6 | calyanti_block6) printf 'calyanti_block6' ;;
	ban6 | calyanti_ban6) printf 'calyanti_ban6' ;;
	*) return 1 ;;
	esac
}

add_element() {
	[ -n "$ARG1" ] && [ -n "$ARG2" ] || die 1 "add needs: SET CIDR [TTL]"
	_set=$(set_alias "$ARG1") || die 1 "unknown set '$ARG1' (allow4/block4/ban4/allow6/block6/ban6)"
	valid_cidr "$ARG2" || die 1 "'$ARG2' is not a valid address/prefix"
	# family sanity
	case "$_set" in
	*6)
		is_v6 "$ARG2" || die 1 "$_set is IPv6 but '$ARG2' is not"
		;;
	*)
		is_v6 "$ARG2" && die 1 "$_set is IPv4 but '$ARG2' is IPv6"
		;;
	esac
	if [ -n "$ARG3" ]; then
		_ttl=$(dur_secs "$ARG3")
		"$IPSET_BIN" add "$_set" "$ARG2" timeout "$_ttl" -exist || die 4 "add failed"
	else
		"$IPSET_BIN" add "$_set" "$ARG2" -exist || die 4 "add failed"
	fi
	log_info "added $ARG2 to $_set"
}

del_element() {
	[ -n "$ARG1" ] && [ -n "$ARG2" ] || die 1 "del needs: SET CIDR"
	_set=$(set_alias "$ARG1") || die 1 "unknown set '$ARG1'"
	"$IPSET_BIN" del "$_set" "$ARG2" -exist || die 4 "del failed"
	log_info "removed $ARG2 from $_set"
}

# -----------------------------------------------------------------------------
setup_tmp() {
	TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/calyanti-ipset.XXXXXX") || die 4 "cannot create a temporary directory"
	TMP_LIST="$TMP_DIR/list"
	TMP_ERR="$TMP_DIR/err"
	: >"$TMP_ERR"
}
cleanup() { [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR"; return 0; }
trap cleanup EXIT HUP INT TERM

need_root() { [ "$(id -u)" -eq 0 ] || die 4 "'$COMMAND' requires root"; }

# -----------------------------------------------------------------------------
find_ipset
setup_tmp

case "$COMMAND" in
create)
	need_root
	create_all
	reload_lists
	log_info "ipsets created and populated; wire them in with calyanti-iptables.sh --apply"
	;;
reload)
	need_root
	create_all
	reload_lists
	;;
save)
	save_sets
	;;
restore)
	need_root
	restore_sets
	;;
list)
	list_sets
	;;
flush)
	need_root
	flush_sets
	;;
destroy)
	need_root
	destroy_sets
	;;
add)
	need_root
	add_element
	;;
del)
	need_root
	del_element
	;;
*)
	die 1 "unknown command '$COMMAND'"
	;;
esac
