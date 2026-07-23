#!/bin/sh
# shellcheck shell=sh
#
# =============================================================================
#  Caly Anti - nftables fallback applier   (degradation ladder rung 4)
# =============================================================================
#
#  Renders fallback/nftables/calyanti.nft against /etc/calyanti/calyanti.conf,
#  validates the result with `nft -c -f`, applies it atomically, and can roll
#  back - including automatically, on a timer, if you lose your session.
#
#  Nothing outside `table inet calyanti` is ever read, written or flushed.
#
#  USAGE
#    apply.sh [options] [command]
#
#  COMMANDS
#    apply            render, validate and load the ruleset          (default)
#    check            render and validate only, exit non-zero on error
#    dry-run          render and print the ruleset, change nothing
#    remove           delete table inet calyanti
#    status           show whether the table is loaded, plus counters
#    rollback         restore the ruleset saved by the last apply
#    confirm          cancel a pending --commit-timeout rollback
#    version          print the detected nft version and feature verdicts
#
#  OPTIONS
#    -c, --config PATH     configuration file  (default /etc/calyanti/calyanti.conf)
#    -r, --ruleset PATH    template            (default: calyanti.nft next to me)
#    -s, --state DIR       state directory     (default /run/calyanti)
#    -o, --output PATH     also write the rendered ruleset here
#    -t, --commit-timeout N  revert automatically after N seconds unless
#                          `apply.sh confirm` runs first. Use this over SSH.
#        --legacy          force the reduced ruleset (skip the full attempt)
#        --monitor         force monitor mode (count, never drop)
#        --enforce         force enforcing mode even if monitor_only = yes
#        --no-auto-safety  do not derive mgmt safety from $SSH_CONNECTION
#        --no-force-ssh    do not force TCP/22 into the mgmt set (DANGEROUS)
#    -q, --quiet           errors only
#    -v, --verbose         trace every decision
#    -h, --help            this text
#
#  EXIT CODES
#    0 ok   1 usage   2 missing dependency   3 render/validate failure
#    4 apply failure  5 refused for safety
# =============================================================================

set -eu

PROG="calyanti-nft"
VERSION="1.0"

CONF_FILE="/etc/calyanti/calyanti.conf"
STATE_DIR="/run/calyanti"
RULESET_TMPL=""
OUTPUT_FILE=""
COMMAND="apply"
COMMIT_TIMEOUT=0
FORCE_LEGACY=0
FORCE_MONITOR=0
FORCE_ENFORCE=0
AUTO_SAFETY=1
FORCE_SSH_PORT=1
VERBOSITY=1
NFT_BIN=""
NFT_VER=""
NFT_MAJOR=0
NFT_MINOR=0
NFT_PATCH=0
WORK_DIR=""

# -----------------------------------------------------------------------------
# Logging. Everything diagnostic goes to stderr so `dry-run` can be piped.
# -----------------------------------------------------------------------------
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

cleanup() {
	if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
		rm -rf "$WORK_DIR"
	fi
}
trap cleanup EXIT HUP INT TERM

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
usage() {
	cat <<'USAGE_EOF'
calyanti-nft - nftables fallback applier (degradation ladder rung 4)

Usage: apply.sh [options] [command]

Commands
  apply            render, validate and load the ruleset          (default)
  check            render and validate only, exit non-zero on error
  dry-run          render and print the ruleset, change nothing
  remove           delete table inet calyanti
  status           show whether the table is loaded, plus counters
  rollback         restore the ruleset saved by the last apply
  confirm          cancel a pending --commit-timeout rollback
  version          print the detected nft version and feature verdicts

Options
  -c, --config PATH       configuration file (default /etc/calyanti/calyanti.conf)
  -r, --ruleset PATH      template (default: calyanti.nft next to this script)
  -s, --state DIR         state directory (default /run/calyanti)
  -o, --output PATH       also write the rendered ruleset here
  -t, --commit-timeout N  revert automatically after N seconds unless
                          "apply.sh confirm" runs first. Use this over SSH.
      --legacy            force the reduced ruleset
      --monitor           force monitor mode (count, never drop)
      --enforce           force enforcing mode even if monitor_only = yes
      --no-auto-safety    do not derive mgmt safety from $SSH_CONNECTION
      --no-force-ssh      do not force TCP/22 into the mgmt set (DANGEROUS)
  -q, --quiet             errors only
  -v, --verbose           trace every decision
  -h, --help              this text

Exit codes
  0 ok   1 usage   2 missing dependency   3 render/validate failure
  4 apply failure  5 refused for safety
USAGE_EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	-c | --config)
		[ $# -ge 2 ] || die 1 "--config needs an argument"
		CONF_FILE=$2
		shift 2
		;;
	-r | --ruleset)
		[ $# -ge 2 ] || die 1 "--ruleset needs an argument"
		RULESET_TMPL=$2
		shift 2
		;;
	-s | --state)
		[ $# -ge 2 ] || die 1 "--state needs an argument"
		STATE_DIR=$2
		shift 2
		;;
	-o | --output)
		[ $# -ge 2 ] || die 1 "--output needs an argument"
		OUTPUT_FILE=$2
		shift 2
		;;
	-t | --commit-timeout)
		[ $# -ge 2 ] || die 1 "--commit-timeout needs an argument"
		COMMIT_TIMEOUT=$2
		shift 2
		;;
	--legacy)
		FORCE_LEGACY=1
		shift
		;;
	--monitor)
		FORCE_MONITOR=1
		shift
		;;
	--enforce)
		FORCE_ENFORCE=1
		shift
		;;
	--no-auto-safety)
		AUTO_SAFETY=0
		shift
		;;
	--no-force-ssh)
		FORCE_SSH_PORT=0
		shift
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
	--dry-run)
		COMMAND="dry-run"
		shift
		;;
	--apply)
		COMMAND="apply"
		shift
		;;
	--remove)
		COMMAND="remove"
		shift
		;;
	--check)
		COMMAND="check"
		shift
		;;
	apply | check | dry-run | dryrun | remove | status | rollback | confirm | version)
		COMMAND=$1
		[ "$COMMAND" = "dryrun" ] && COMMAND="dry-run"
		shift
		;;
	--)
		shift
		break
		;;
	-*)
		die 1 "unknown option '$1' (try --help)"
		;;
	*)
		die 1 "unknown command '$1' (try --help)"
		;;
	esac
done

case "$COMMIT_TIMEOUT" in
'' | *[!0-9]*) die 1 "--commit-timeout must be a whole number of seconds" ;;
esac

if [ "$FORCE_MONITOR" -eq 1 ] && [ "$FORCE_ENFORCE" -eq 1 ]; then
	die 1 "--monitor and --enforce are mutually exclusive"
fi

# Locate the template next to this script when it was not given explicitly.
if [ -z "$RULESET_TMPL" ]; then
	_self_dir=$(dirname -- "$0")
	RULESET_TMPL="$_self_dir/calyanti.nft"
fi

BACKUP_FILE="$STATE_DIR/nft-previous.nft"
ACTIVE_FILE="$STATE_DIR/nft-active.nft"
CONFIRM_FILE="$STATE_DIR/nft-commit-pending"
WATCHDOG_FILE="$STATE_DIR/nft-watchdog.sh"

# -----------------------------------------------------------------------------
# nft discovery and version comparison
# -----------------------------------------------------------------------------
find_nft() {
	if [ -n "${NFT:-}" ] && [ -x "$NFT" ]; then
		NFT_BIN=$NFT
		return 0
	fi
	for _c in nft /usr/sbin/nft /sbin/nft /usr/bin/nft /usr/local/sbin/nft; do
		if command -v "$_c" >/dev/null 2>&1; then
			NFT_BIN=$(command -v "$_c")
			return 0
		fi
	done
	return 1
}

parse_nft_version() {
	# `nft --version` prints e.g. "nftables v1.0.9 (Old Doc Yak #3)"
	NFT_VER=$("$NFT_BIN" --version 2>/dev/null | sed -n 's/^nftables v\([0-9][0-9.]*\).*$/\1/p' | head -n 1)
	[ -n "$NFT_VER" ] || NFT_VER="0.0.0"
	NFT_MAJOR=$(printf '%s' "$NFT_VER" | cut -d. -f1)
	NFT_MINOR=$(printf '%s' "$NFT_VER" | cut -d. -f2)
	NFT_PATCH=$(printf '%s' "$NFT_VER" | cut -d. -f3)
	case "$NFT_MAJOR" in '' | *[!0-9]*) NFT_MAJOR=0 ;; esac
	case "$NFT_MINOR" in '' | *[!0-9]*) NFT_MINOR=0 ;; esac
	case "$NFT_PATCH" in '' | *[!0-9]*) NFT_PATCH=0 ;; esac
}

# nft_at_least MAJOR MINOR PATCH
nft_at_least() {
	_a=$((NFT_MAJOR * 1000000 + NFT_MINOR * 1000 + NFT_PATCH))
	_b=$(($1 * 1000000 + $2 * 1000 + $3))
	[ "$_a" -ge "$_b" ]
}

require_nft() {
	find_nft || die 2 "nft binary not found; this host cannot use the nftables fallback (drop to fallback/iptables)"
	parse_nft_version
	log_dbg "nft binary $NFT_BIN version $NFT_VER"
	if ! nft_at_least 0 8 0; then
		log_warn "nft $NFT_VER is very old; forcing the reduced (legacy) ruleset"
		FORCE_LEGACY=1
	elif ! nft_at_least 0 9 0; then
		log_warn "nft $NFT_VER predates 0.9.0: dynamic sets and ct count may be unavailable"
	fi
}

# =============================================================================
# Configuration parsing
# =============================================================================

# conf_all KEY -> every value assigned to KEY, one per line, comments stripped.
conf_all() {
	[ -f "$CONF_FILE" ] || return 0
	awk -v key="$1" '
		{ sub(/#.*$/, "") }
		/^[ \t]*\[/ { next }
		{
			line = $0
			if (index(line, "=") == 0) next
			k = line
			sub(/=.*$/, "", k)
			gsub(/^[ \t]+|[ \t]+$/, "", k)
			if (k != key) next
			v = line
			sub(/^[^=]*=/, "", v)
			gsub(/^[ \t]+|[ \t]+$/, "", v)
			if (v != "") print v
		}
	' "$CONF_FILE"
}

# conf_get KEY [DEFAULT] -> the last assignment, or DEFAULT.
conf_get() {
	_v=$(conf_all "$1" | tail -n 1)
	if [ -z "$_v" ]; then
		printf '%s' "${2-}"
	else
		printf '%s' "$_v"
	fi
}

# conf_bool KEY DEFAULT(0|1) -> 0 or 1
conf_bool() {
	_v=$(conf_get "$1" "")
	if [ -z "$_v" ]; then
		printf '%s' "$2"
		return 0
	fi
	case "$_v" in
	yes | YES | Yes | true | TRUE | True | on | ON | On | 1) printf '1' ;;
	no | NO | No | false | FALSE | False | off | OFF | Off | 0) printf '0' ;;
	*)
		log_warn "key '$1' has non-boolean value '$_v'; using default"
		printf '%s' "$2"
		;;
	esac
}

# split_list "a, b , c" -> one item per line
split_list() {
	printf '%s\n' "$1" | tr ',' '\n' | sed -e 's/^[ \t]*//' -e 's/[ \t]*$//' -e '/^$/d'
}

# num_suffix VALUE -> integer, honouring k/m/g and ki/mi/gi
num_suffix() {
	_raw=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
	_n=$(printf '%s' "$_raw" | sed 's/[^0-9].*$//')
	_u=$(printf '%s' "$_raw" | sed 's/^[0-9]*//')
	case "$_n" in '' | *[!0-9]*) _n=0 ;; esac
	case "$_u" in
	'') printf '%s' "$_n" ;;
	k) printf '%s' "$((_n * 1000))" ;;
	m) printf '%s' "$((_n * 1000000))" ;;
	g) printf '%s' "$((_n * 1000000000))" ;;
	ki) printf '%s' "$((_n * 1024))" ;;
	mi) printf '%s' "$((_n * 1048576))" ;;
	gi) printf '%s' "$((_n * 1073741824))" ;;
	*)
		log_warn "unrecognised numeric suffix in '$1'; treating as $_n"
		printf '%s' "$_n"
		;;
	esac
}

# dur_secs VALUE -> whole seconds (minimum 1). Bare integer means seconds.
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
	*)
		log_warn "unrecognised duration suffix in '$1'; treating as seconds"
		_s=$_n
		;;
	esac
	[ "$_s" -lt 1 ] && _s=1
	printf '%s' "$_s"
}

# clamp_rate VALUE -> at least 1 (nft rejects rate 0)
clamp_rate() {
	if [ "$1" -lt 1 ]; then printf '1'; else printf '%s' "$1"; fi
}

# is_v6 STRING -> success when the CIDR/address is IPv6
is_v6() {
	case "$1" in
	*:*) return 0 ;;
	*) return 1 ;;
	esac
}

# valid_cidr STRING -> success for something that looks like an address/prefix.
# Deliberately permissive: nft itself is the authority and validation happens
# in the `nft -c` pass. This only keeps shell metacharacters out of the file.
valid_cidr() {
	case "$1" in
	*[!0-9a-fA-F.:/]*) return 1 ;;
	'') return 1 ;;
	*) return 0 ;;
	esac
}

# valid_port STRING -> success for "80" or "8000-8010"
valid_port() {
	case "$1" in
	'' | *[!0-9-]*) return 1 ;;
	*-*-*) return 1 ;;
	*) return 0 ;;
	esac
}

# =============================================================================
# Rendering
# =============================================================================

# The tags we enable, as a space separated list.
ENABLED_TAGS=""
tag_enable() {
	case " $ENABLED_TAGS " in
	*" $1 "*) ;;
	*) ENABLED_TAGS="$ENABLED_TAGS $1" ;;
	esac
}
tag_is_enabled() {
	case " $ENABLED_TAGS " in
	*" $1 "*) return 0 ;;
	*) return 1 ;;
	esac
}

# Values collected from the configuration.
CFG_MGMT_TCP=""
CFG_MGMT_UDP=""
CFG_LAN_IFACES=""
CFG_ALLOW4=""
CFG_ALLOW6=""
CFG_BLOCK4=""
CFG_BLOCK6=""
CFG_LOCAL4=""
CFG_LOCAL6=""
CFG_OPEN_TCP=""
CFG_OPEN_UDP=""
CFG_CLOSED_TCP=""
CFG_CLOSED_UDP=""
CFG_SYNPROXY_PORTS=""
CFG_AMP_EXEMPT=""
CFG_AMP_EXTRA=""
CFG_RL_RULES=""

add_item() {
	# add_item VARNAME VALUE  (space separated accumulation)
	eval "_cur=\${$1}"
	# shellcheck disable=SC2154
	case " $_cur " in
	*" $2 "*) return 0 ;;
	esac
	eval "$1=\"\$_cur \$2\""
}

collect_config() {
	if [ ! -f "$CONF_FILE" ]; then
		log_warn "configuration '$CONF_FILE' not found; using the template defaults"
	else
		log_dbg "reading configuration from $CONF_FILE"
	fi

	# --- management ports -------------------------------------------------
	for _v in $(conf_all mgmt_tcp_ports | tr ',' ' '); do
		if valid_port "$_v"; then add_item CFG_MGMT_TCP "$_v"; else log_warn "ignoring bad mgmt_tcp_ports entry '$_v'"; fi
	done
	for _v in $(conf_all mgmt_udp_ports | tr ',' ' '); do
		if valid_port "$_v"; then add_item CFG_MGMT_UDP "$_v"; else log_warn "ignoring bad mgmt_udp_ports entry '$_v'"; fi
	done

	# --- interfaces: zone lan/dmz or disabled bypass the ruleset ----------
	add_item CFG_LAN_IFACES "lo"
	conf_all interface >"$WORK_DIR/ifaces.txt"
	while IFS= read -r _line; do
		[ -n "$_line" ] || continue
		_name=$(printf '%s' "$_line" | awk '{print $1}')
		case "$_name" in '' | *[!0-9a-zA-Z._@:-]*)
			log_warn "ignoring interface directive with an unusable name: $_line"
			continue
			;;
		esac
		case "$_line" in
		*zone=lan* | *zone=dmz* | *disabled*)
			add_item CFG_LAN_IFACES "$_name"
			log_dbg "interface $_name bypasses the ruleset"
			;;
		esac
	done <"$WORK_DIR/ifaces.txt"

	# --- address lists ----------------------------------------------------
	for _key in allow block local; do
		conf_all "$_key" | tr ',' '\n' | sed -e 's/^[ \t]*//' -e 's/[ \t]*$//' -e '/^$/d' >"$WORK_DIR/list.txt"
		while IFS= read -r _cidr; do
			[ -n "$_cidr" ] || continue
			if ! valid_cidr "$_cidr"; then
				log_warn "ignoring malformed '$_key' entry '$_cidr'"
				continue
			fi
			if is_v6 "$_cidr"; then
				case "$_key" in
				allow) add_item CFG_ALLOW6 "$_cidr" ;;
				block) add_item CFG_BLOCK6 "$_cidr" ;;
				local) add_item CFG_LOCAL6 "$_cidr" ;;
				esac
			else
				case "$_key" in
				allow) add_item CFG_ALLOW4 "$_cidr" ;;
				block) add_item CFG_BLOCK4 "$_cidr" ;;
				local) add_item CFG_LOCAL4 "$_cidr" ;;
				esac
			fi
		done <"$WORK_DIR/list.txt"
	done

	# --- per-port policy --------------------------------------------------
	# Syntax: tcp_port = <port|range> <closed|open|ratelimit> [rate=N] [burst=N]
	for _proto in tcp udp; do
		conf_all "${_proto}_port" >"$WORK_DIR/ports.txt"
		while IFS= read -r _line; do
			[ -n "$_line" ] || continue
			_port=$(printf '%s' "$_line" | awk '{print $1}')
			_mode=$(printf '%s' "$_line" | awk '{print tolower($2)}')
			if ! valid_port "$_port"; then
				log_warn "ignoring ${_proto}_port entry with bad port '$_port'"
				continue
			fi
			[ -n "$_mode" ] || _mode="open"
			case "$_mode" in
			open)
				if [ "$_proto" = tcp ]; then add_item CFG_OPEN_TCP "$_port"; else add_item CFG_OPEN_UDP "$_port"; fi
				;;
			closed)
				if [ "$_proto" = tcp ]; then add_item CFG_CLOSED_TCP "$_port"; else add_item CFG_CLOSED_UDP "$_port"; fi
				;;
			ratelimit)
				_r=$(printf '%s' "$_line" | sed -n 's/.*[ \t]rate=\([^ \t]*\).*/\1/p')
				_b=$(printf '%s' "$_line" | sed -n 's/.*[ \t]burst=\([^ \t]*\).*/\1/p')
				[ -n "$_r" ] || _r="10k"
				[ -n "$_b" ] || _b="20k"
				_r=$(clamp_rate "$(num_suffix "$_r")")
				_b=$(clamp_rate "$(num_suffix "$_b")")
				# A rate-limited port is also an open port: conforming
				# traffic is accepted by the caly_port_rl rule itself.
				CFG_RL_RULES="$CFG_RL_RULES${CFG_RL_RULES:+
}$_proto $_port $_r $_b"
				;;
			*)
				log_warn "ignoring ${_proto}_port entry with unknown mode '$_mode'"
				;;
			esac
		done <"$WORK_DIR/ports.txt"
	done

	# --- synproxy ports ---------------------------------------------------
	for _v in $(conf_all synproxy_port | tr ',' ' '); do
		if valid_port "$_v"; then add_item CFG_SYNPROXY_PORTS "$_v"; else log_warn "ignoring bad synproxy_port '$_v'"; fi
	done

	# --- amplifier port adjustments --------------------------------------
	for _v in $(conf_all amp_exempt | tr ',' ' '); do
		if valid_port "$_v"; then add_item CFG_AMP_EXEMPT "$_v"; else log_warn "ignoring bad amp_exempt '$_v'"; fi
	done
	for _v in $(conf_all amp_extra | tr ',' ' '); do
		if valid_port "$_v"; then add_item CFG_AMP_EXTRA "$_v"; else log_warn "ignoring bad amp_extra '$_v'"; fi
	done
}

# --- management safety -------------------------------------------------------
#
# Refuse to produce a ruleset we cannot prove leaves a way back in. TCP/22 is
# forced unless the operator disabled that explicitly AND supplied another
# mgmt port, exactly mirroring the loader invariant in src/bpf/common.h.
enforce_mgmt_safety() {
	if [ "$AUTO_SAFETY" -eq 1 ] && [ -n "${SSH_CONNECTION:-}" ]; then
		# "<client ip> <client port> <server ip> <server port>"
		_sport=$(printf '%s' "$SSH_CONNECTION" | awk '{print $4}')
		_cip=$(printf '%s' "$SSH_CONNECTION" | awk '{print $1}')
		if valid_port "$_sport"; then
			add_item CFG_MGMT_TCP "$_sport"
			log_info "auto-safety: adding the port of this SSH session (tcp/$_sport) to the mgmt set"
		fi
		if [ -n "$_cip" ] && valid_cidr "$_cip"; then
			if is_v6 "$_cip"; then
				add_item CFG_ALLOW6 "$_cip"
			else
				add_item CFG_ALLOW4 "$_cip"
			fi
			log_info "auto-safety: allowlisting the peer of this SSH session ($_cip)"
		fi
	fi

	if [ "$FORCE_SSH_PORT" -eq 1 ]; then
		add_item CFG_MGMT_TCP "22"
	fi

	_mgmt_count=0
	for _p in $CFG_MGMT_TCP; do
		[ -n "$_p" ] && _mgmt_count=$((_mgmt_count + 1))
	done
	if [ "$_mgmt_count" -eq 0 ]; then
		die 5 "refusing to apply: no management TCP port could be determined. Set mgmt_tcp_ports in $CONF_FILE or drop --no-force-ssh."
	fi
	log_dbg "management TCP ports:$CFG_MGMT_TCP"
}

# --- tag selection -----------------------------------------------------------
select_tags() {
	_monitor=$(conf_bool monitor_only 0)
	_mode=$(conf_get mode "normal")
	case "$_mode" in
	monitor | monitor-only | monitor_only) _monitor=1 ;;
	esac
	[ "$FORCE_MONITOR" -eq 1 ] && _monitor=1
	[ "$FORCE_ENFORCE" -eq 1 ] && _monitor=0
	if [ "$_monitor" -eq 1 ]; then
		tag_enable MONITOR
		log_info "monitor mode: every rule is evaluated and counted, nothing is dropped"
	fi

	[ "$(conf_bool default_deny 0)" -eq 1 ] && {
		tag_enable DEFAULT_DENY
		log_warn "default_deny is on: inbound traffic to any port not listed in tcp_port/udp_port/mgmt_tcp_ports will be dropped"
	}
	[ "$(conf_bool wan_drop_private 0)" -eq 1 ] && tag_enable DROP_PRIVATE
	[ "$(conf_bool drop_all_fragments 0)" -eq 1 ] && tag_enable DROP_ALL_FRAGS
	[ "$(conf_bool strict_rpf 0)" -eq 1 ] && tag_enable URPF
	[ "$(conf_bool mgmt_bruteforce_guard 0)" -eq 1 ] && tag_enable SSHGUARD

	# The kernel SYN proxy is only wired up when the operator both asked
	# for it and listed at least one port to protect, and only when nft is
	# new enough to have the expression at all.
	if [ "$(conf_bool synproxy 0)" -eq 1 ] && [ -n "$CFG_SYNPROXY_PORTS" ]; then
		if nft_at_least 0 9 0; then
			tag_enable SYNPROXY
			log_info "kernel SYN proxy enabled for ports:$CFG_SYNPROXY_PORTS (requires net.ipv4.tcp_syncookies=2 and nf_synproxy_core)"
		else
			log_warn "synproxy requested but nft $NFT_VER is too old; falling back to the SYN rate limits"
		fi
	fi

	[ "$FORCE_LEGACY" -eq 1 ] && tag_enable LEGACY
	return 0
}

# --- textual substitution of rate literals -----------------------------------
build_sed_script() {
	_sed=$WORK_DIR/rates.sed
	: >"$_sed"

	_rate_pps=$(clamp_rate "$(num_suffix "$(conf_get rate_pps 200000)")")
	_burst_pps=$(clamp_rate "$(num_suffix "$(conf_get rate_pps_burst 400000)")")
	_rate_bps=$(clamp_rate "$(num_suffix "$(conf_get rate_bps 250000000)")")
	_burst_bps=$(clamp_rate "$(num_suffix "$(conf_get rate_bps_burst 500000000)")")
	_rate_syn=$(clamp_rate "$(num_suffix "$(conf_get rate_syn 2000)")")
	_burst_syn=$(clamp_rate "$(num_suffix "$(conf_get rate_syn_burst 4000)")")
	_rate_udp=$(clamp_rate "$(num_suffix "$(conf_get rate_udp 50000)")")
	_burst_udp=$(clamp_rate "$(num_suffix "$(conf_get rate_udp_burst 100000)")")
	_rate_icmp=$(clamp_rate "$(num_suffix "$(conf_get rate_icmp 200)")")
	_burst_icmp=$(clamp_rate "$(num_suffix "$(conf_get rate_icmp_burst 400)")")
	_rate_new=$(clamp_rate "$(num_suffix "$(conf_get rate_newconn 500)")")
	_burst_new=$(clamp_rate "$(num_suffix "$(conf_get rate_newconn_burst 1000)")")
	_syn_fallback=$(clamp_rate "$(num_suffix "$(conf_get syn_fallback_pps 100000)")")

	# Strikes: fw_config models "N strikes inside a window"; nft models a
	# token bucket. Convert to strikes per minute so the two agree on the
	# number of violations needed before a ban.
	_strike_limit=$(num_suffix "$(conf_get strike_limit 10)")
	[ "$_strike_limit" -lt 1 ] && _strike_limit=1
	_strike_window=$(dur_secs "$(conf_get strike_window 60s)")
	_strike_per_min=$(((_strike_limit * 60 + _strike_window - 1) / _strike_window))
	_strike_per_min=$(clamp_rate "$_strike_per_min")

	_scan_thresh=$(num_suffix "$(conf_get scan_port_threshold 60)")
	[ "$_scan_thresh" -lt 1 ] && _scan_thresh=1
	_scan_window=$(dur_secs "$(conf_get scan_window 30s)")
	_scan_per_sec=$(((_scan_thresh + _scan_window - 1) / _scan_window))
	_scan_per_sec=$(clamp_rate "$_scan_per_sec")
	_scan_burst=$((_scan_thresh))

	_ct_max=$(num_suffix "$(conf_get max_conn_per_source 200)")
	[ "$_ct_max" -lt 1 ] && _ct_max=200

	_icmp_size=$(num_suffix "$(conf_get icmp_max_payload 1472)")
	_icmp_total=$((_icmp_size + 28))
	[ "$_icmp_total" -lt 64 ] && _icmp_total=64

	_frag_min=$(num_suffix "$(conf_get frag_min_size 128)")
	[ "$_frag_min" -lt 8 ] && _frag_min=128

	_ban_ttl=$(dur_secs "$(conf_get ban_ttl_base 10m)")

	# Normalise to a bare integer like every other rate, so no config text can
	# reach the sed replacement (a stray `|` would break the s/// command; a
	# valid-but-permissive injection could weaken the rendered SSHGUARD rule).
	_mgmt_bf_rate=$(clamp_rate "$(num_suffix "$(conf_get mgmt_bruteforce_rate 10)")")

	# Every substitution is anchored on its [caly:NAME] marker so a rate
	# literal can never be rewritten on a rule it does not belong to.
	{
		printf '/caly:pps\\]/s|rate over [0-9]*/second|rate over %s/second|\n' "$_rate_pps"
		printf '/caly:pps\\]/s|burst [0-9]* packets|burst %s packets|\n' "$_burst_pps"
		printf '/caly:bps\\]/s|rate over [0-9]* bytes/second|rate over %s bytes/second|\n' "$_rate_bps"
		printf '/caly:bps\\]/s|burst [0-9]* bytes|burst %s bytes|\n' "$_burst_bps"
		printf '/caly:syn\\]/s|rate over [0-9]*/second|rate over %s/second|\n' "$_rate_syn"
		printf '/caly:syn\\]/s|burst [0-9]* packets|burst %s packets|\n' "$_burst_syn"
		printf '/caly:udp\\]/s|rate over [0-9]*/second|rate over %s/second|\n' "$_rate_udp"
		printf '/caly:udp\\]/s|burst [0-9]* packets|burst %s packets|\n' "$_burst_udp"
		printf '/caly:icmp\\]/s|rate over [0-9]*/second|rate over %s/second|\n' "$_rate_icmp"
		printf '/caly:icmp\\]/s|burst [0-9]* packets|burst %s packets|\n' "$_burst_icmp"
		printf '/caly:newconn\\]/s|rate over [0-9]*/second|rate over %s/second|\n' "$_rate_new"
		printf '/caly:newconn\\]/s|burst [0-9]* packets|burst %s packets|\n' "$_burst_new"
		printf '/caly:synglobal\\]/s|rate over [0-9]*/second|rate over %s/second|\n' "$_syn_fallback"
		printf '/caly:synglobal\\]/s|burst [0-9]* packets|burst %s packets|\n' "$((_syn_fallback * 2))"
		printf '/caly:strike\\]/s|rate over [0-9]*/minute|rate over %s/minute|\n' "$_strike_per_min"
		printf '/caly:strike\\]/s|burst [0-9]* packets|burst %s packets|\n' "$_strike_limit"
		printf '/caly:scan\\]/s|rate over [0-9]*/second|rate over %s/second|\n' "$_scan_per_sec"
		printf '/caly:scan\\]/s|burst [0-9]* packets|burst %s packets|\n' "$_scan_burst"
		printf '/caly:sshguard\\]/s|rate over [0-9]*/minute|rate over %s/minute|\n' "$_mgmt_bf_rate"
		printf '/caly:ctcount\\]/s|ct count over [0-9]*|ct count over %s|\n' "$_ct_max"
		printf '/caly:icmpsize\\]/s|length > [0-9]*|length > %s|\n' "$_icmp_total"
		printf '/caly:fragmin\\]/s|length < [0-9]*|length < %s|\n' "$_frag_min"
		printf '/caly:bantimeout/s|timeout [0-9a-z]*|timeout %ss|\n' "$_ban_ttl"
	} >>"$_sed"

	printf '%s' "$_sed"
}

# The amplifier source-port defaults, identical to CALY_AMP_PORTS_INIT in
# src/bpf/common.h. apply.sh computes the live set as (defaults + amp_extra -
# amp_exempt) and repopulates caly_amp_ports from that, so it never has to
# add a duplicate or delete a non-member (both are hard errors in nft).
DEFAULT_AMP="17 19 53 69 111 123 137 161 389 520 623 1434 1900 3283 5093 5351 5353 11211 27015 30718 37810"

# --- element emission --------------------------------------------------------
emit_elements() {
	# Written after the table block, in the SAME `nft -f` transaction, so a
	# reload stays atomic. Each managed set is flushed first and then
	# repopulated: the sets carry inline defaults (e.g. caly_mgmt_tcp = {22})
	# so the file is safe to load standalone, and `flush set` + `add element`
	# is the documented idiom for replacing their contents without tripping
	# the "element already exists" error that a bare `add` would hit on 22.
	_out=$1

	_repop() {
		# _repop SETNAME "item item item"  -> flush then (maybe) add
		printf 'flush set inet calyanti %s\n' "$1" >>"$_out"
		_items=""
		for _i in $2; do
			[ -n "$_i" ] || continue
			_items="$_items${_items:+, }$_i"
		done
		[ -n "$_items" ] || return 0
		printf 'add element inet calyanti %s { %s }\n' "$1" "$_items" >>"$_out"
	}

	_repop caly_mgmt_tcp "$CFG_MGMT_TCP"
	_repop caly_mgmt_udp "$CFG_MGMT_UDP"
	_repop caly_allow4 "$CFG_ALLOW4"
	_repop caly_allow6 "$CFG_ALLOW6"
	_repop caly_block4 "$CFG_BLOCK4"
	_repop caly_block6 "$CFG_BLOCK6"
	_repop caly_local4 "$CFG_LOCAL4"
	_repop caly_local6 "$CFG_LOCAL6"
	_repop caly_open_tcp "$CFG_OPEN_TCP"
	_repop caly_open_udp "$CFG_OPEN_UDP"
	_repop caly_closed_tcp "$CFG_CLOSED_TCP"
	_repop caly_closed_udp "$CFG_CLOSED_UDP"
	_repop caly_synproxy_ports "$CFG_SYNPROXY_PORTS"

	# caly_amp_ports = defaults + amp_extra - amp_exempt, computed in the
	# shell so the emitted transaction only ever contains a clean add list.
	_amp_final=""
	for _p in $DEFAULT_AMP $CFG_AMP_EXTRA; do
		[ -n "$_p" ] || continue
		case " $CFG_AMP_EXEMPT " in *" $_p "*) continue ;; esac
		case " $_amp_final " in *" $_p "*) continue ;; esac
		_amp_final="$_amp_final $_p"
	done
	_repop caly_amp_ports "$_amp_final"

	# Per-port rate limits: conforming traffic is accepted here, excess is
	# dropped. Appending into the empty caly_port_rl chain preserves the
	# order in which the operator wrote them.
	printf '%s\n' "$CFG_RL_RULES" | while IFS=' ' read -r _proto _port _rate _burst; do
		[ -n "$_proto" ] || continue
		printf 'add rule inet calyanti caly_port_rl %s dport %s ct state new limit rate %s/second burst %s packets counter accept comment "per-port rate limit: conforming"\n' \
			"$_proto" "$_port" "$_rate" "$_burst" >>"$_out"
		printf 'add rule inet calyanti caly_port_rl %s dport %s ct state new counter jump caly_drop comment "per-port rate limit: exceeded"\n' \
			"$_proto" "$_port" >>"$_out"
	done
}

# render OUTPUT_PATH
render() {
	_dst=$1
	[ -f "$RULESET_TMPL" ] || die 3 "ruleset template '$RULESET_TMPL' not found"

	_sedfile=$(build_sed_script)

	# 1. interface bypass define
	_ifaces=""
	for _i in $CFG_LAN_IFACES; do
		[ -n "$_i" ] || continue
		_ifaces="$_ifaces${_ifaces:+, }\"$_i\""
	done
	[ -n "$_ifaces" ] || _ifaces='"lo"'

	# 2. tag transform + define replacement, in one awk pass
	awk -v tags="$ENABLED_TAGS" -v ifaces="$_ifaces" '
		BEGIN {
			n = split(tags, t, " ")
			for (i = 1; i <= n; i++)
				if (t[i] != "") on[t[i]] = 1
			indefs = 0
		}
		/^# >>> CALYANTI-DEFINES-BEGIN/ {
			print
			print "define caly_lan_ifaces = { " ifaces " }"
			indefs = 1
			next
		}
		/^# <<< CALYANTI-DEFINES-END/ { indefs = 0; print; next }
		indefs == 1 { next }
		{
			line = $0

			# "<rule>  #@-TAG@"  -> drop the line when TAG is active
			if (match(line, /#@-[A-Z_]+@/)) {
				tag = substr(line, RSTART + 3, RLENGTH - 4)
				if (tag in on) next
				sub(/[ \t]*#@-[A-Z_]+@[ \t]*$/, "", line)
				print line
				next
			}

			# "#@+TAG@ <rule>"   -> activate the line when TAG is active
			if (match(line, /^[ \t]*#@[+][A-Z_]+@ /)) {
				tag = line
				sub(/^[ \t]*#@[+]/, "", tag)
				sub(/@ .*$/, "", tag)
				if (!(tag in on)) next
				sub(/^[ \t]*#@[+][A-Z_]+@ /, "", line)
				print line
				next
			}

			print line
		}
	' "$RULESET_TMPL" | sed -f "$_sedfile" >"$_dst"

	# 3. elements and generated rules
	emit_elements "$_dst"

	log_dbg "rendered ruleset to $_dst ($(wc -l <"$_dst" | tr -d ' ') lines)"
}

# validate FILE -> 0 when `nft -c -f` accepts it
validate() {
	if "$NFT_BIN" -c -f "$1" 2>"$WORK_DIR/nft.err"; then
		return 0
	fi
	return 1
}

# render_and_validate -> leaves the accepted ruleset in $WORK_DIR/ruleset.nft
render_and_validate() {
	render "$WORK_DIR/ruleset.nft"
	if validate "$WORK_DIR/ruleset.nft"; then
		log_dbg "ruleset validated by nft -c"
		return 0
	fi

	if tag_is_enabled LEGACY; then
		log_err "the reduced ruleset was still rejected by nft:"
		sed 's/^/  /' "$WORK_DIR/nft.err" >&2
		return 1
	fi

	log_warn "nft rejected the full ruleset; retrying with the reduced (legacy) ruleset"
	[ "$VERBOSITY" -ge 2 ] && sed 's/^/  /' "$WORK_DIR/nft.err" >&2
	tag_enable LEGACY
	render "$WORK_DIR/ruleset.nft"
	# The reduced ruleset has no dynamic-set statements, so the sets that
	# only existed to carry them are harmless; strip the eval flag they no
	# longer need in case the kernel is what refused it. (`sed -i` is not
	# portable across GNU/BSD/busybox, hence the copy.)
	sed 's/flags dynamic,timeout/flags timeout/' "$WORK_DIR/ruleset.nft" >"$WORK_DIR/ruleset.tmp"
	mv "$WORK_DIR/ruleset.tmp" "$WORK_DIR/ruleset.nft"
	if validate "$WORK_DIR/ruleset.nft"; then
		log_warn "running the REDUCED ruleset: no auto-ban, no per-source token buckets, no scan detection"
		return 0
	fi
	log_err "nft rejected both the full and the reduced ruleset:"
	sed 's/^/  /' "$WORK_DIR/nft.err" >&2
	return 1
}

# =============================================================================
# State handling
# =============================================================================
ensure_state_dir() {
	[ -d "$STATE_DIR" ] || mkdir -p "$STATE_DIR" || die 4 "cannot create state directory '$STATE_DIR'"
}

table_loaded() {
	"$NFT_BIN" list table inet calyanti >/dev/null 2>&1
}

save_backup() {
	ensure_state_dir
	if table_loaded; then
		{
			printf '# calyanti: ruleset captured before the last apply\n'
			printf 'table inet calyanti\n'
			printf 'delete table inet calyanti\n'
			"$NFT_BIN" list table inet calyanti
		} >"$BACKUP_FILE.tmp" && mv "$BACKUP_FILE.tmp" "$BACKUP_FILE"
		log_dbg "previous ruleset saved to $BACKUP_FILE"
	else
		{
			printf '# calyanti: no table was loaded before the last apply\n'
			printf 'table inet calyanti\n'
			printf 'delete table inet calyanti\n'
		} >"$BACKUP_FILE.tmp" && mv "$BACKUP_FILE.tmp" "$BACKUP_FILE"
		log_dbg "no previous table; rollback will simply remove ours"
	fi
}

arm_watchdog() {
	[ "$COMMIT_TIMEOUT" -gt 0 ] || return 0
	ensure_state_dir
	: >"$CONFIRM_FILE"
	cat >"$WATCHDOG_FILE" <<WATCHDOG_EOF
#!/bin/sh
# Automatic rollback for calyanti's nftables ruleset. Generated by apply.sh.
set -u
sleep $COMMIT_TIMEOUT
[ -f "$CONFIRM_FILE" ] || exit 0
rm -f "$CONFIRM_FILE"
if [ -f "$BACKUP_FILE" ]; then
	"$NFT_BIN" -f "$BACKUP_FILE" 2>/dev/null || "$NFT_BIN" delete table inet calyanti 2>/dev/null
else
	"$NFT_BIN" delete table inet calyanti 2>/dev/null
fi
logger -t calyanti "nftables ruleset rolled back: not confirmed within ${COMMIT_TIMEOUT}s" 2>/dev/null || true
WATCHDOG_EOF
	chmod 0700 "$WATCHDOG_FILE"
	# Detached so it survives this shell and any SSH session that dies.
	if command -v setsid >/dev/null 2>&1; then
		setsid /bin/sh "$WATCHDOG_FILE" >/dev/null 2>&1 &
	else
		nohup /bin/sh "$WATCHDOG_FILE" >/dev/null 2>&1 &
	fi
	log_info "commit watchdog armed: run '$0 confirm' within ${COMMIT_TIMEOUT}s or the ruleset is rolled back"
}

# =============================================================================
# Commands
# =============================================================================
cmd_render_common() {
	WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/calyanti-nft.XXXXXX") || die 4 "cannot create a temporary directory"
	collect_config
	enforce_mgmt_safety
	select_tags
	render_and_validate || exit 3
}

cmd_apply() {
	[ "$(id -u)" -eq 0 ] || die 5 "applying the ruleset requires root"
	cmd_render_common
	save_backup
	if ! "$NFT_BIN" -f "$WORK_DIR/ruleset.nft" 2>"$WORK_DIR/nft.err"; then
		log_err "nft refused the ruleset at load time:"
		sed 's/^/  /' "$WORK_DIR/nft.err" >&2
		exit 4
	fi
	ensure_state_dir
	cp "$WORK_DIR/ruleset.nft" "$ACTIVE_FILE" 2>/dev/null || true
	[ -n "$OUTPUT_FILE" ] && cp "$WORK_DIR/ruleset.nft" "$OUTPUT_FILE"
	log_info "table inet calyanti loaded (tags:${ENABLED_TAGS:- none})"
	arm_watchdog
	log_info "make it survive a reboot with: nft list table inet calyanti > /etc/nftables.d/calyanti.nft (distro dependent)"
	return 0
}

cmd_check() {
	cmd_render_common
	log_info "ruleset is valid (tags:${ENABLED_TAGS:- none})"
	return 0
}

cmd_dry_run() {
	cmd_render_common
	if [ -n "$OUTPUT_FILE" ]; then
		cp "$WORK_DIR/ruleset.nft" "$OUTPUT_FILE"
		log_info "rendered ruleset written to $OUTPUT_FILE"
	fi
	cat "$WORK_DIR/ruleset.nft"
	return 0
}

cmd_remove() {
	[ "$(id -u)" -eq 0 ] || die 5 "removing the ruleset requires root"
	if table_loaded; then
		"$NFT_BIN" delete table inet calyanti || die 4 "failed to delete table inet calyanti"
		log_info "table inet calyanti removed; no other table was touched"
	else
		log_info "table inet calyanti is not loaded; nothing to do"
	fi
	rm -f "$CONFIRM_FILE"
	return 0
}

cmd_status() {
	if table_loaded; then
		printf '%s: table inet calyanti is LOADED\n' "$PROG"
		if [ -f "$CONFIRM_FILE" ]; then
			printf '%s: a commit watchdog is PENDING - run "%s confirm" to keep this ruleset\n' "$PROG" "$0"
		fi
		"$NFT_BIN" list table inet calyanti
	else
		printf '%s: table inet calyanti is NOT loaded\n' "$PROG"
		return 1
	fi
	return 0
}

cmd_rollback() {
	[ "$(id -u)" -eq 0 ] || die 5 "rollback requires root"
	[ -f "$BACKUP_FILE" ] || die 4 "no saved ruleset at $BACKUP_FILE"
	if "$NFT_BIN" -f "$BACKUP_FILE"; then
		log_info "rolled back to the ruleset saved at the last apply"
		rm -f "$CONFIRM_FILE"
		return 0
	fi
	log_warn "restoring the saved ruleset failed; removing our table instead"
	"$NFT_BIN" delete table inet calyanti 2>/dev/null || true
	rm -f "$CONFIRM_FILE"
	return 0
}

cmd_confirm() {
	if [ -f "$CONFIRM_FILE" ]; then
		rm -f "$CONFIRM_FILE"
		log_info "ruleset confirmed; the automatic rollback has been cancelled"
	else
		log_info "no rollback was pending"
	fi
	return 0
}

cmd_version() {
	printf '%s %s\n' "$PROG" "$VERSION"
	printf 'nft binary        : %s\n' "${NFT_BIN:-not found}"
	printf 'nft version       : %s\n' "$NFT_VER"
	if nft_at_least 0 9 0; then
		printf 'dynamic sets      : yes (auto-ban and per-source buckets available)\n'
		printf 'ct count          : yes (per-source connection ceiling available)\n'
		printf 'synproxy expr     : yes (needs nf_synproxy_core + tcp_syncookies=2)\n'
	else
		printf 'dynamic sets      : uncertain - the reduced ruleset may be used\n'
		printf 'ct count          : uncertain\n'
		printf 'synproxy expr     : no\n'
	fi
	printf 'config            : %s%s\n' "$CONF_FILE" "$([ -f "$CONF_FILE" ] && printf '' || printf ' (missing)')"
	printf 'template          : %s%s\n' "$RULESET_TMPL" "$([ -f "$RULESET_TMPL" ] && printf '' || printf ' (missing)')"
	return 0
}

# =============================================================================
# Dispatch
# =============================================================================
require_nft

case "$COMMAND" in
apply) cmd_apply ;;
check) cmd_check ;;
dry-run) cmd_dry_run ;;
remove) cmd_remove ;;
status) cmd_status ;;
rollback) cmd_rollback ;;
confirm) cmd_confirm ;;
version) cmd_version ;;
*) die 1 "unknown command '$COMMAND'" ;;
esac
