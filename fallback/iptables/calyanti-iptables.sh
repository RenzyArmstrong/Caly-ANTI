#!/bin/sh
# shellcheck shell=sh
#
# =============================================================================
#  Caly Anti - iptables/ip6tables fallback dataplane  (ladder rung 5)
# =============================================================================
#
#  The last-resort dataplane, for hosts too old or too minimal for nftables.
#  Correctness is preserved; throughput is not. Everything lives in custom
#  chains named CALY_* so the distro's own rules are never touched, and every
#  chain is flushed-then-rebuilt on each apply, which is what makes the script
#  idempotent: re-running it can only converge on the same state.
#
#  Controls implemented:
#    * management accept FIRST, in the mangle PREROUTING early-drop path and
#      again in filter INPUT, so SSH survives every code path below it
#    * ipset-backed allow / block / dynamic-ban sets (via calyanti-ipset.sh),
#      with an inline `-m recent` auto-ban when ipset is unavailable
#    * conntrack fast path (ESTABLISHED,RELATED accept; INVALID drop)
#    * illegal TCP flag combinations (NULL/FIN/SYN+FIN/SYN+RST/FIN+RST/Xmas/all)
#    * martian / bogon source filtering in mangle PREROUTING (pre-conntrack)
#    * fragment handling (-f, tiny-fragment and fragmented-ICMP drops)
#    * per-source token buckets via -m hashlimit: pps, SYN, UDP, ICMP, new-conn
#    * per-source concurrent connection ceiling via -m connlimit
#    * reflection/amplification source-port filter (matches common.h list)
#    * ICMP policy that still permits PMTUD (type 3 / type 2) and IPv6 ND
#    * per-port policy (open / closed / rate-limited)
#    * global SYN ceiling as the pre-5.15 syn_fallback_pps equivalent
#
#  What this rung CANNOT do (present only on rungs 1-3):
#    * escalating ban TTLs, distinct-destination-port scan detection, and
#      exact per-source byte accounting at line rate.
#
#  USAGE
#    calyanti-iptables.sh [options] {--apply|--remove|--dry-run|--status}
#
#  OPTIONS
#    -c, --config PATH     configuration    (default /etc/calyanti/calyanti.conf)
#    -4                    only touch IPv4 (skip ip6tables)
#    -6                    only touch IPv6 (skip iptables)
#        --no-ipset        do not use ipset even if present (inline -m recent)
#        --monitor         count in a LOG-only chain, never drop
#        --no-force-ssh    do not force TCP/22 into the mgmt allow (DANGEROUS)
#    -q, --quiet / -v, --verbose / -h, --help
#
#  EXIT CODES
#    0 ok  1 usage  2 missing dependency  3 config error  4 apply failure
#    5 refused for safety
# =============================================================================

set -eu

PROG="calyanti-iptables"
VERSION="1.0"

CONF_FILE="/etc/calyanti/calyanti.conf"
DO_V4=1
DO_V6=1
USE_IPSET=1
MONITOR=0
FORCE_SSH_PORT=1
VERBOSITY=1
ACTION=""

IPT=""
IP6T=""
IPT_KIND="unknown"
IPSET_BIN=""
SELF_DIR=""
IPSET_HELPER=""

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

usage() {
	cat <<'USAGE_EOF'
calyanti-iptables - iptables/ip6tables fallback dataplane (ladder rung 5)

Usage: calyanti-iptables.sh [options] {--apply|--remove|--dry-run|--status}

Options
  -c, --config PATH    configuration (default /etc/calyanti/calyanti.conf)
  -4                   only touch IPv4 (skip ip6tables)
  -6                   only touch IPv6 (skip iptables)
      --no-ipset       do not use ipset even if present (inline -m recent)
      --monitor        count in a LOG-only chain, never drop
      --no-force-ssh   do not force TCP/22 into the mgmt allow (DANGEROUS)
  -q, --quiet
  -v, --verbose
  -h, --help

Exit codes
  0 ok  1 usage  2 missing dependency  3 config error  4 apply failure
  5 refused for safety
USAGE_EOF
}

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
while [ $# -gt 0 ]; do
	case "$1" in
	-c | --config)
		[ $# -ge 2 ] || die 1 "--config needs an argument"
		CONF_FILE=$2
		shift 2
		;;
	-4)
		DO_V6=0
		shift
		;;
	-6)
		DO_V4=0
		shift
		;;
	--no-ipset)
		USE_IPSET=0
		shift
		;;
	--monitor)
		MONITOR=1
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
	--apply | apply)
		ACTION="apply"
		shift
		;;
	--remove | remove)
		ACTION="remove"
		shift
		;;
	--dry-run | dry-run | dryrun)
		ACTION="dry-run"
		shift
		;;
	--status | status)
		ACTION="status"
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*) die 1 "unknown argument '$1' (try --help)" ;;
	esac
done

[ -n "$ACTION" ] || die 1 "one of --apply / --remove / --dry-run / --status is required"

SELF_DIR=$(dirname -- "$0")
IPSET_HELPER="$SELF_DIR/../ipset/calyanti-ipset.sh"

# =============================================================================
# Tool discovery. Detect iptables-nft vs iptables-legacy so the operator knows
# which backend their rules land in (they are wire-compatible, but mixing them
# with the distro firewall on the other backend is a classic footgun).
# =============================================================================
detect_backend() {
	_bin=$1
	_v=$("$_bin" --version 2>/dev/null | head -n 1)
	case "$_v" in
	*nf_tables*) printf 'nft' ;;
	*legacy*) printf 'legacy' ;;
	*) printf 'unknown' ;;
	esac
}

find_tools() {
	if [ "$DO_V4" -eq 1 ]; then
		for _c in iptables /usr/sbin/iptables /sbin/iptables; do
			if command -v "$_c" >/dev/null 2>&1; then
				IPT=$(command -v "$_c")
				break
			fi
		done
		if [ -z "$IPT" ]; then
			if [ "$ACTION" = "dry-run" ]; then
				IPT="iptables"
				log_warn "iptables not found; dry-run will show the commands it WOULD run"
			else
				die 2 "iptables not found; this host has no usable dataplane fallback"
			fi
		fi
		IPT_KIND=$(detect_backend "$IPT")
		log_dbg "iptables: $IPT (backend: $IPT_KIND)"
	fi
	if [ "$DO_V6" -eq 1 ]; then
		for _c in ip6tables /usr/sbin/ip6tables /sbin/ip6tables; do
			if command -v "$_c" >/dev/null 2>&1; then
				IP6T=$(command -v "$_c")
				break
			fi
		done
		if [ -z "$IP6T" ]; then
			if [ "$ACTION" = "dry-run" ]; then
				IP6T="ip6tables"
			else
				log_warn "ip6tables not found; IPv6 will be left unprotected"
				DO_V6=0
			fi
		else
			log_dbg "ip6tables: $IP6T (backend: $(detect_backend "$IP6T"))"
		fi
	fi
	if [ "$USE_IPSET" -eq 1 ]; then
		if command -v ipset >/dev/null 2>&1; then
			IPSET_BIN=$(command -v ipset)
			log_dbg "ipset: $IPSET_BIN"
		else
			log_warn "ipset not found; using inline '-m recent' for auto-ban (limited to 100 addresses per list)"
			USE_IPSET=0
		fi
	fi
	if [ "$IPT_KIND" = "nft" ] && [ "$ACTION" = "apply" ]; then
		log_info "note: this iptables is the nf_tables backend. Prefer the native nftables fallback (fallback/nftables) on this host."
	fi
}

# =============================================================================
# Config parsing  (kept byte-identical in behaviour to apply.sh)
# =============================================================================
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
conf_bool() {
	_v=$(conf_get "$1" "")
	if [ -z "$_v" ]; then
		printf '%s' "$2"
		return 0
	fi
	case "$_v" in
	yes | YES | Yes | true | TRUE | True | on | ON | On | 1) printf '1' ;;
	no | NO | No | false | FALSE | False | off | OFF | Off | 0) printf '0' ;;
	*) printf '%s' "$2" ;;
	esac
}
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
	*) printf '%s' "$_n" ;;
	esac
}
is_v6() { case "$1" in *:*) return 0 ;; *) return 1 ;; esac; }
valid_cidr() { case "$1" in '' | *[!0-9a-fA-F.:/]*) return 1 ;; *) return 0 ;; esac; }
valid_port() { case "$1" in '' | *[!0-9-]*) return 1 ;; *-*-*) return 1 ;; *) return 0 ;; esac; }
# iptables uses a colon for port ranges, not a hyphen.
ipt_port() { printf '%s' "$1" | tr '-' ':'; }

# hashlimit names must be <= 15 characters (IFNAMSIZ). Keep them short.
HL_UPTO="/second"

# =============================================================================
# Config collection
# =============================================================================
CFG_MGMT_TCP=""
CFG_MGMT_UDP=""
CFG_LAN_IFACES="lo"
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
CFG_AMP_EXEMPT=""
CFG_AMP_EXTRA=""

R_PPS=200000
R_PPS_BURST=400000
R_SYN=2000
R_SYN_BURST=4000
R_UDP=50000
R_UDP_BURST=100000
R_ICMP=200
R_ICMP_BURST=400
R_NEW=500
R_NEW_BURST=1000
R_SYN_GLOBAL=100000
CT_MAX=200
ICMP_TOTAL=1500
FRAG_MIN=128
BAN_TTL=600
WAN_DROP_PRIVATE=0
DEFAULT_DENY=0
DROP_ALL_FRAGS=0

AMP_PORTS="17 19 53 69 111 123 137 161 389 520 623 1434 1900 3283 5093 5351 5353 11211 27015 30718 37810"

add_item() {
	eval "_cur=\${$1}"
	# shellcheck disable=SC2154
	case " $_cur " in *" $2 "*) return 0 ;; esac
	eval "$1=\"\$_cur \$2\""
}

collect_config() {
	[ -f "$CONF_FILE" ] || log_warn "configuration '$CONF_FILE' not found; using built-in defaults"

	for _v in $(conf_all mgmt_tcp_ports | tr ',' ' '); do
		valid_port "$_v" && add_item CFG_MGMT_TCP "$_v"
	done
	for _v in $(conf_all mgmt_udp_ports | tr ',' ' '); do
		valid_port "$_v" && add_item CFG_MGMT_UDP "$_v"
	done

	conf_all interface >"$TMP_IFACES"
	while IFS= read -r _line; do
		[ -n "$_line" ] || continue
		_name=$(printf '%s' "$_line" | awk '{print $1}')
		case "$_name" in '' | *[!0-9a-zA-Z._@:-]*) continue ;; esac
		case "$_line" in
		*zone=lan* | *zone=dmz* | *disabled*) add_item CFG_LAN_IFACES "$_name" ;;
		esac
	done <"$TMP_IFACES"

	for _key in allow block local; do
		conf_all "$_key" | tr ',' '\n' | sed -e 's/^[ \t]*//' -e 's/[ \t]*$//' -e '/^$/d' >"$TMP_LIST"
		while IFS= read -r _cidr; do
			[ -n "$_cidr" ] || continue
			valid_cidr "$_cidr" || {
				log_warn "ignoring malformed '$_key' entry '$_cidr'"
				continue
			}
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
		done <"$TMP_LIST"
	done

	for _proto in tcp udp; do
		conf_all "${_proto}_port" >"$TMP_PORTS"
		while IFS= read -r _line; do
			[ -n "$_line" ] || continue
			_port=$(printf '%s' "$_line" | awk '{print $1}')
			_mode=$(printf '%s' "$_line" | awk '{print tolower($2)}')
			valid_port "$_port" || continue
			[ -n "$_mode" ] || _mode="open"
			case "$_mode" in
			open | ratelimit)
				# rung 5 has no per-port bucket; a rate-limited port
				# degrades to open (still covered by the per-source
				# buckets and the global ceilings).
				if [ "$_proto" = tcp ]; then add_item CFG_OPEN_TCP "$_port"; else add_item CFG_OPEN_UDP "$_port"; fi
				[ "$_mode" = ratelimit ] && log_warn "${_proto}_port $_port: per-port rate limits are unavailable at rung 5; treating as open"
				;;
			closed)
				if [ "$_proto" = tcp ]; then add_item CFG_CLOSED_TCP "$_port"; else add_item CFG_CLOSED_UDP "$_port"; fi
				;;
			esac
		done <"$TMP_PORTS"
	done

	for _v in $(conf_all amp_exempt | tr ',' ' '); do
		valid_port "$_v" && add_item CFG_AMP_EXEMPT "$_v"
	done
	for _v in $(conf_all amp_extra | tr ',' ' '); do
		valid_port "$_v" && add_item CFG_AMP_EXTRA "$_v"
	done

	R_PPS=$(num_suffix "$(conf_get rate_pps 200k)")
	R_PPS_BURST=$(num_suffix "$(conf_get rate_pps_burst 400k)")
	R_SYN=$(num_suffix "$(conf_get rate_syn 2k)")
	R_SYN_BURST=$(num_suffix "$(conf_get rate_syn_burst 4k)")
	R_UDP=$(num_suffix "$(conf_get rate_udp 50k)")
	R_UDP_BURST=$(num_suffix "$(conf_get rate_udp_burst 100k)")
	R_ICMP=$(num_suffix "$(conf_get rate_icmp 200)")
	R_ICMP_BURST=$(num_suffix "$(conf_get rate_icmp_burst 400)")
	R_NEW=$(num_suffix "$(conf_get rate_newconn 500)")
	R_NEW_BURST=$(num_suffix "$(conf_get rate_newconn_burst 1k)")
	R_SYN_GLOBAL=$(num_suffix "$(conf_get syn_fallback_pps 100k)")
	CT_MAX=$(num_suffix "$(conf_get max_conn_per_source 200)")
	_icmp_size=$(num_suffix "$(conf_get icmp_max_payload 1472)")
	ICMP_TOTAL=$((_icmp_size + 28))
	FRAG_MIN=$(num_suffix "$(conf_get frag_min_size 128)")
	BAN_TTL=$(conf_get ban_ttl_base 10m)
	BAN_TTL=$(dur_secs "$BAN_TTL")
	WAN_DROP_PRIVATE=$(conf_bool wan_drop_private 0)
	DEFAULT_DENY=$(conf_bool default_deny 0)
	DROP_ALL_FRAGS=$(conf_bool drop_all_fragments 0)

	# hashlimit needs a non-zero burst; iptables rejects 0.
	for _var in R_PPS R_PPS_BURST R_SYN R_SYN_BURST R_UDP R_UDP_BURST R_ICMP R_ICMP_BURST R_NEW R_NEW_BURST R_SYN_GLOBAL CT_MAX; do
		eval "_val=\$$_var"
		[ "$_val" -lt 1 ] && eval "$_var=1"
	done
	[ "$ICMP_TOTAL" -lt 64 ] && ICMP_TOTAL=64
	[ "$FRAG_MIN" -lt 8 ] && FRAG_MIN=128

	# amp_extra adds, amp_exempt removes.
	for _p in $CFG_AMP_EXTRA; do
		case " $AMP_PORTS " in *" $_p "*) ;; *) AMP_PORTS="$AMP_PORTS $_p" ;; esac
	done
	for _p in $CFG_AMP_EXEMPT; do
		AMP_PORTS=$(printf '%s' "$AMP_PORTS" | tr ' ' '\n' | grep -vx "$_p" | tr '\n' ' ')
	done
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

# =============================================================================
# Management safety
# =============================================================================
enforce_mgmt_safety() {
	if [ -n "${SSH_CONNECTION:-}" ]; then
		_sport=$(printf '%s' "$SSH_CONNECTION" | awk '{print $4}')
		valid_port "$_sport" && add_item CFG_MGMT_TCP "$_sport" && log_info "auto-safety: adding tcp/$_sport (this SSH session) to the mgmt allow"
	fi
	[ "$FORCE_SSH_PORT" -eq 1 ] && add_item CFG_MGMT_TCP "22"
	_count=0
	for _p in $CFG_MGMT_TCP; do [ -n "$_p" ] && _count=$((_count + 1)); done
	[ "$_count" -eq 0 ] && die 5 "refusing to apply: no management TCP port. Set mgmt_tcp_ports in $CONF_FILE or drop --no-force-ssh."
	log_dbg "management TCP ports:$CFG_MGMT_TCP"
}

# =============================================================================
# iptables emission
#
# DRY is set for --dry-run: every rule is printed instead of executed. The
# same code path builds the commands either way, so dry-run is a faithful
# preview, never a separate implementation that can drift.
# =============================================================================
DRY=0

# ipt FAMILY args...   FAMILY is 4, 6 or "both"
ipt() {
	_fam=$1
	shift
	if [ "$_fam" = 4 ] || [ "$_fam" = both ]; then
		[ "$DO_V4" -eq 1 ] && _run "$IPT" "$@"
	fi
	if [ "$_fam" = 6 ] || [ "$_fam" = both ]; then
		[ "$DO_V6" -eq 1 ] && _run "$IP6T" "$@"
	fi
	# A disabled-family no-op (the guard above short-circuits to status 1) or an
	# accumulated _run failure must NOT propagate up: under `set -e` a bare
	# top-level `ipt 6 ...`/`ipt both ...` call would otherwise abort the whole
	# script - after flush_chains has already unhooked the old ruleset, leaving
	# the box unprotected. _run records failures in APPLY_FAILED; do_apply
	# reports them at the end. Always return success here.
	return 0
}

_run() {
	_bin=$1
	shift
	if [ "$DRY" -eq 1 ]; then
		_b=$(basename -- "$_bin")
		printf '%s' "$_b"
		for _a in "$@"; do
			case "$_a" in
			*[" 	"]* | '') printf " '%s'" "$_a" ;;
			*) printf ' %s' "$_a" ;;
			esac
		done
		printf '\n'
		return 0
	fi
	if "$_bin" "$@" 2>>"$TMP_ERR"; then
		return 0
	fi
	# During --apply a failing rule is fatal; record which one.
	log_err "command failed: $(basename -- "$_bin") $*"
	APPLY_FAILED=1
	return 1
}

# The verdict target: the CALY_DROP chain, which logs then drops (or, in
# monitor mode, logs then returns so evaluation continues).
DROP_TGT="CALY_DROP"

# =============================================================================
# Chain construction
# =============================================================================
# Chains build_chains creates via new_chain (caly_strike is created separately
# by build_strike_helper, so it is excluded here to avoid a double -N).
CHAINS_FILTER="CALY_INPUT CALY_FWD CALY_DROP CALY_LOGDROP CALY_BUCKETS CALY_PORTS CALY_AMP CALY_SYNCEIL"
CHAINS_MANGLE="CALY_EARLY"
# Every chain we own, for flush/delete. caly_strike is last: it is the target
# of jumps from the others, so it must be flushed with them but can only be
# deleted once nothing references it.
FLUSH_FILTER="$CHAINS_FILTER caly_strike"

flush_chains() {
	# Flush ALL our chains first (this removes every inter-chain jump, e.g.
	# caly_strike -> CALY_DROP), THEN unhook from the base chains, THEN
	# delete. Deleting before flushing would fail with "chain in use" and
	# leave a stale chain that the next -N could not recreate. Only our own
	# CALY_*/caly_* chains are touched; the distro ruleset is left intact.
	for _fam in 4 6; do
		{ [ "$_fam" = 4 ] && [ "$DO_V4" -eq 1 ]; } || { [ "$_fam" = 6 ] && [ "$DO_V6" -eq 1 ]; } || continue
		[ "$DRY" -eq 0 ] || continue
		_ipt=$IPT
		[ "$_fam" = 6 ] && _ipt=$IP6T

		# 1. flush our chains (drops all inter-chain references)
		for _c in $FLUSH_FILTER; do
			"$_ipt" -t filter -F "$_c" 2>/dev/null || true
		done
		for _c in $CHAINS_MANGLE; do
			"$_ipt" -t mangle -F "$_c" 2>/dev/null || true
		done

		# 2. unhook from the base chains (repeat until no copy remains)
		_del_jump() {
			while "$_ipt" -t "$1" -C "$2" -j "$3" 2>/dev/null; do
				"$_ipt" -t "$1" -D "$2" -j "$3" 2>/dev/null || break
			done
		}
		_del_jump mangle PREROUTING CALY_EARLY
		_del_jump filter INPUT CALY_INPUT
		_del_jump filter FORWARD CALY_FWD

		# 3. delete our now-unreferenced chains
		for _c in $FLUSH_FILTER; do
			"$_ipt" -t filter -X "$_c" 2>/dev/null || true
		done
		for _c in $CHAINS_MANGLE; do
			"$_ipt" -t mangle -X "$_c" 2>/dev/null || true
		done
	done
}

new_chain() {
	# new_chain TABLE CHAIN  - create, or empty it if a stale copy survived,
	# so a re-apply after a partial failure always converges.
	if [ "$DRY" -eq 1 ]; then
		ipt both -t "$1" -N "$2"
		return 0
	fi
	if [ "$DO_V4" -eq 1 ]; then
		"$IPT" -t "$1" -N "$2" 2>/dev/null || "$IPT" -t "$1" -F "$2" 2>>"$TMP_ERR" || {
			log_err "cannot create or flush chain $2 (v4)"
			APPLY_FAILED=1
		}
	fi
	if [ "$DO_V6" -eq 1 ]; then
		"$IP6T" -t "$1" -N "$2" 2>/dev/null || "$IP6T" -t "$1" -F "$2" 2>>"$TMP_ERR" || {
			log_err "cannot create or flush chain $2 (v6)"
			APPLY_FAILED=1
		}
	fi
}

build_chains() {
	# --- create chains ---------------------------------------------------
	for _c in $CHAINS_FILTER; do new_chain filter "$_c"; done
	new_chain mangle CALY_EARLY

	# --- terminal drop / logdrop ----------------------------------------
	# One rate-limited log line, then the verdict. In monitor mode the
	# verdict is RETURN so evaluation continues and nothing is lost.
	ipt both -t filter -A CALY_LOGDROP -m limit --limit 5/second --limit-burst 10 -j LOG --log-prefix "calyanti-drop: " --log-level 6
	ipt both -t filter -A CALY_DROP -j CALY_LOGDROP
	if [ "$MONITOR" -eq 1 ]; then
		ipt both -t filter -A CALY_DROP -j RETURN
		log_info "monitor mode: matches are logged and counted, never dropped"
	else
		ipt both -t filter -A CALY_DROP -j DROP
	fi

	# NOTE: the illegal-TCP-flag combinations are enforced in mangle
	# CALY_EARLY (PREROUTING), which covers both local and forwarded
	# traffic pre-conntrack, so there is no separate filter-table flag
	# chain here - it would be dead weight duplicating those drops.

	# --- amplification source-port filter -------------------------------
	# Reaches this chain only for ct state NEW UDP (replies to our own
	# queries are ESTABLISHED and were accepted on the fast path), so a
	# real DNS/NTP server still works: queries have dport 53, not sport 53.
	for _p in $AMP_PORTS; do
		ipt both -t filter -A CALY_AMP -p udp --sport "$_p" -j "$DROP_TGT"
	done
	ipt both -t filter -A CALY_AMP -j RETURN

	build_early
	build_buckets
	build_ports
	build_synceil
	build_input
	build_forward
	wire_hooks
}

# --- global SYN ceiling sub-chain (filter) -----------------------------------
# The pre-5.15 syn_fallback_pps equivalent. It MUST be a sub-chain, not two
# inline rules in CALY_INPUT: a conforming SYN has to keep flowing to the
# per-port policy (closed ports / default_deny), so it must fall through and
# RESUME in CALY_INPUT rather than RETURN out of it (a RETURN from CALY_INPUT
# lands back in the built-in INPUT chain, whose policy is ACCEPT, bypassing
# CALY_PORTS entirely). Only the EXCESS is dropped here; a conforming SYN simply
# reaches the end of this chain and returns to the caller.
#
# The rate is expressed with -m hashlimit in GLOBAL mode (no --hashlimit-mode,
# so all SYNs share one bucket). xt_limit cannot be used: its userspace parser
# clamps both --limit and --limit-burst to 10000 (XT_LIMIT_SCALE), so any
# DDoS-scale ceiling (default 100000/second) is rejected at parse time and the
# rule never loads. hashlimit's rev2 scale carries the high rate, exactly like
# the per-source buckets. Because only the excess is dropped, a hashlimit that
# somehow failed to load fails OPEN (no SYN ceiling) rather than black-holing
# every new TCP connection.
build_synceil() {
	ipt both -t filter -A CALY_SYNCEIL -p tcp --tcp-flags SYN,ACK SYN \
		-m hashlimit --hashlimit-name caly_gsyn --hashlimit-above "${R_SYN_GLOBAL}${HL_UPTO}" \
		--hashlimit-burst "$((R_SYN_GLOBAL * 2))" -j "$DROP_TGT"
}

# --- mangle PREROUTING: pre-conntrack early drops ----------------------------
build_early() {
	# Bypass loopback and LAN/DMZ interfaces.
	for _if in $CFG_LAN_IFACES; do
		ipt both -t mangle -A CALY_EARLY -i "$_if" -j RETURN
	done

	# IPv6 ND / PMTUD must survive: allow before any bogon/martian rule.
	ipt 6 -t mangle -A CALY_EARLY -p ipv6-icmp -m icmp6 --icmpv6-type 133 -j RETURN
	ipt 6 -t mangle -A CALY_EARLY -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j RETURN
	ipt 6 -t mangle -A CALY_EARLY -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j RETURN
	ipt 6 -t mangle -A CALY_EARLY -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j RETURN
	ipt 6 -t mangle -A CALY_EARLY -p ipv6-icmp -m icmp6 --icmpv6-type 2 -j RETURN

	# ORDERING (mirrors the XDP ladder and the nft chain):
	#   anomaly drops  ->  allowlist  ->  mgmt accept  ->  reputation drop
	# The anomaly drops run first because none of them can match a real
	# management packet (no legit SSH client sources from a bogon, sends a
	# NULL-flag segment, or fragments to the minimum). Reputation (block +
	# ban), which CAN catch an admin who tripped a limit, is deferred until
	# AFTER the mgmt accept so it can never lock the operator out.

	# --- martian / bogon sources (mangle is pre-conntrack) --------------
	for _b in 0.0.0.0/8 127.0.0.0/8 169.254.0.0/16 192.0.2.0/24 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
		ipt 4 -t mangle -A CALY_EARLY -s "$_b" -j "$DROP_TGT"
	done
	# `::` (unspecified) as a source is a martian everywhere else (common.h
	# STAT_DROP_IP6_SRC_UNSPEC, nft drops ::/128); the only legitimate use is a
	# DAD neighbour solicitation, which the icmpv6-type 135 RETURN above already
	# exempted, so dropping it here matches the other dataplanes.
	ipt 6 -t mangle -A CALY_EARLY -s ::/128 -j "$DROP_TGT"
	ipt 6 -t mangle -A CALY_EARLY -s ::1/128 -j "$DROP_TGT"
	ipt 6 -t mangle -A CALY_EARLY -s ff00::/8 -j "$DROP_TGT"
	ipt 6 -t mangle -A CALY_EARLY -s 0100::/64 -j "$DROP_TGT"
	if [ "$WAN_DROP_PRIVATE" -eq 1 ]; then
		for _b in 10.0.0.0/8 100.64.0.0/10 172.16.0.0/12 192.168.0.0/16; do
			ipt 4 -t mangle -A CALY_EARLY -s "$_b" -j "$DROP_TGT"
		done
		ipt 6 -t mangle -A CALY_EARLY -s fc00::/7 -j "$DROP_TGT"
		ipt 6 -t mangle -A CALY_EARLY -s fe80::/10 -j "$DROP_TGT"
	fi

	# --- LAND / self-spoof ----------------------------------------------
	for _c in $CFG_LOCAL4; do ipt 4 -t mangle -A CALY_EARLY -s "$_c" -j "$DROP_TGT"; done
	for _c in $CFG_LOCAL6; do ipt 6 -t mangle -A CALY_EARLY -s "$_c" -j "$DROP_TGT"; done

	# --- fragment anomalies (pre-defrag in mangle PREROUTING) -----------
	# -f matches all non-first IPv4 fragments; combined with a tiny total
	# length it catches the classic overlap-evasion fragment.
	ipt 4 -t mangle -A CALY_EARLY -f -m length --length 0:"$FRAG_MIN" -j "$DROP_TGT"
	ipt 4 -t mangle -A CALY_EARLY -f -p icmp -j "$DROP_TGT"
	if [ "$DROP_ALL_FRAGS" -eq 1 ]; then
		ipt 4 -t mangle -A CALY_EARLY -f -j "$DROP_TGT"
	fi

	# --- illegal TCP flags (cheap, pre-conntrack) -----------------------
	# Inlined here in the mangle chain: PREROUTING covers both local and
	# forwarded traffic, so these drops need no filter-table counterpart.
	ipt both -t mangle -A CALY_EARLY -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j "$DROP_TGT"
	ipt both -t mangle -A CALY_EARLY -p tcp --tcp-flags SYN,FIN SYN,FIN -j "$DROP_TGT"
	ipt both -t mangle -A CALY_EARLY -p tcp --tcp-flags SYN,RST SYN,RST -j "$DROP_TGT"
	ipt both -t mangle -A CALY_EARLY -p tcp --tcp-flags FIN,RST FIN,RST -j "$DROP_TGT"
	ipt both -t mangle -A CALY_EARLY -p tcp --tcp-flags FIN,PSH,URG FIN,PSH,URG -j "$DROP_TGT"
	ipt both -t mangle -A CALY_EARLY -p tcp --tcp-flags ALL ALL -j "$DROP_TGT"

	# port 0 is never legitimate.
	ipt both -t mangle -A CALY_EARLY -p tcp --sport 0 -j "$DROP_TGT"
	ipt both -t mangle -A CALY_EARLY -p udp --sport 0 -j "$DROP_TGT"

	# --- allowlist escape hatch (before all reputation/policy drops) ----
	if [ "$USE_IPSET" -eq 1 ]; then
		ipt 4 -t mangle -A CALY_EARLY -m set --match-set calyanti_allow4 src -j RETURN
		ipt 6 -t mangle -A CALY_EARLY -m set --match-set calyanti_allow6 src -j RETURN
	else
		for _c in $CFG_ALLOW4; do ipt 4 -t mangle -A CALY_EARLY -s "$_c" -j RETURN; done
		for _c in $CFG_ALLOW6; do ipt 6 -t mangle -A CALY_EARLY -s "$_c" -j RETURN; done
	fi

	# --- MANAGEMENT ACCEPT: precedes reputation so a banned/blocklisted
	# --- admin address can still reach SSH (XDP ladder step 3b < step 4).
	for _p in $CFG_MGMT_TCP; do
		ipt both -t mangle -A CALY_EARLY -p tcp --dport "$(ipt_port "$_p")" -j RETURN
	done

	# --- reputation: static operator block only -------------------------
	# The static blocklist is deliberate operator intent, so it drops here,
	# pre-conntrack, for every packet including established replies. The
	# DYNAMIC auto-ban is NOT applied here: it is deferred to CALY_INPUT /
	# CALY_FWD, AFTER the conntrack ESTABLISHED,RELATED accept, so that a ban
	# installed off a spoofable per-source bucket (an attacker forging the
	# address of an upstream resolver/NTP/peer we depend on) can never sever
	# our own solicited/established traffic to that address. See build_input.
	if [ "$USE_IPSET" -eq 1 ]; then
		ipt 4 -t mangle -A CALY_EARLY -m set --match-set calyanti_block4 src -j "$DROP_TGT"
		ipt 6 -t mangle -A CALY_EARLY -m set --match-set calyanti_block6 src -j "$DROP_TGT"
	else
		for _c in $CFG_BLOCK4; do ipt 4 -t mangle -A CALY_EARLY -s "$_c" -j "$DROP_TGT"; done
		for _c in $CFG_BLOCK6; do ipt 6 -t mangle -A CALY_EARLY -s "$_c" -j "$DROP_TGT"; done
	fi
}

# --- per-source token buckets (filter, conntrack available) ------------------
# Each bucket that is exceeded jumps to caly_strike, which bans on sustained
# abuse and drops in the meantime. hashlimit --hashlimit-above fires ONLY when
# the source is over its rate, so a conforming source falls straight through.
build_buckets() {
	# per-source total pps
	ipt both -t filter -A CALY_BUCKETS \
		-m hashlimit --hashlimit-name caly_pps --hashlimit-above "${R_PPS}${HL_UPTO}" \
		--hashlimit-burst "$R_PPS_BURST" --hashlimit-mode srcip -j caly_strike

	# per-source SYN pps
	ipt both -t filter -A CALY_BUCKETS -p tcp --tcp-flags SYN,ACK SYN \
		-m hashlimit --hashlimit-name caly_syn --hashlimit-above "${R_SYN}${HL_UPTO}" \
		--hashlimit-burst "$R_SYN_BURST" --hashlimit-mode srcip -j caly_strike

	# per-source UDP pps
	ipt both -t filter -A CALY_BUCKETS -p udp \
		-m hashlimit --hashlimit-name caly_udp --hashlimit-above "${R_UDP}${HL_UPTO}" \
		--hashlimit-burst "$R_UDP_BURST" --hashlimit-mode srcip -j caly_strike

	# per-source ICMP pps
	ipt 4 -t filter -A CALY_BUCKETS -p icmp \
		-m hashlimit --hashlimit-name caly_icmp --hashlimit-above "${R_ICMP}${HL_UPTO}" \
		--hashlimit-burst "$R_ICMP_BURST" --hashlimit-mode srcip -j caly_strike
	ipt 6 -t filter -A CALY_BUCKETS -p ipv6-icmp \
		-m hashlimit --hashlimit-name caly_icmp6 --hashlimit-above "${R_ICMP}${HL_UPTO}" \
		--hashlimit-burst "$R_ICMP_BURST" --hashlimit-mode srcip -j caly_strike

	ipt both -t filter -A CALY_BUCKETS -j RETURN
}

# --- per-port policy (filter) ------------------------------------------------
build_ports() {
	for _p in $CFG_CLOSED_TCP; do
		ipt both -t filter -A CALY_PORTS -p tcp --dport "$(ipt_port "$_p")" -m conntrack --ctstate NEW -j "$DROP_TGT"
	done
	for _p in $CFG_CLOSED_UDP; do
		ipt both -t filter -A CALY_PORTS -p udp --dport "$(ipt_port "$_p")" -m conntrack --ctstate NEW -j "$DROP_TGT"
	done
	for _p in $CFG_OPEN_TCP; do
		ipt both -t filter -A CALY_PORTS -p tcp --dport "$(ipt_port "$_p")" -m conntrack --ctstate NEW -j RETURN
	done
	for _p in $CFG_OPEN_UDP; do
		ipt both -t filter -A CALY_PORTS -p udp --dport "$(ipt_port "$_p")" -m conntrack --ctstate NEW -j RETURN
	done
	if [ "$DEFAULT_DENY" -eq 1 ]; then
		log_warn "default_deny is on: new inbound flows to unlisted ports will be dropped"
		ipt both -t filter -A CALY_PORTS -p tcp -m conntrack --ctstate NEW -j "$DROP_TGT"
		ipt both -t filter -A CALY_PORTS -p udp -m conntrack --ctstate NEW -j "$DROP_TGT"
	fi
	ipt both -t filter -A CALY_PORTS -j RETURN
}

# --- filter INPUT ------------------------------------------------------------
build_input() {
	for _if in $CFG_LAN_IFACES; do
		ipt both -t filter -A CALY_INPUT -i "$_if" -j RETURN
	done

	# conntrack fast path (accept established; the INVALID drop is deferred
	# to after the mgmt accept so a legit SSH packet that conntrack has lost
	# track of - e.g. just after a conntrack flush - is never dropped).
	ipt both -t filter -A CALY_INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN

	# allowlist + management (before every drop below).
	if [ "$USE_IPSET" -eq 1 ]; then
		ipt 4 -t filter -A CALY_INPUT -m set --match-set calyanti_allow4 src -j RETURN
		ipt 6 -t filter -A CALY_INPUT -m set --match-set calyanti_allow6 src -j RETURN
	else
		for _c in $CFG_ALLOW4; do ipt 4 -t filter -A CALY_INPUT -s "$_c" -j RETURN; done
		for _c in $CFG_ALLOW6; do ipt 6 -t filter -A CALY_INPUT -s "$_c" -j RETURN; done
	fi
	for _p in $CFG_MGMT_TCP; do
		ipt both -t filter -A CALY_INPUT -p tcp --dport "$(ipt_port "$_p")" -j RETURN
	done
	for _p in $CFG_MGMT_UDP; do
		ipt both -t filter -A CALY_INPUT -p udp --dport "$(ipt_port "$_p")" -j RETURN
	done

	# dynamic auto-ban (moved here from CALY_EARLY): placed AFTER the
	# ESTABLISHED,RELATED accept, the allowlist and the mgmt accept. A ban can
	# be installed off a spoofable per-source bucket, so enforcing it only past
	# the established fast path means our own solicited replies from a
	# spoof-banned upstream survive, an allowlisted peer is exempt, and an
	# auto-banned admin can still reach SSH. Static blocklists stay in EARLY.
	if [ "$USE_IPSET" -eq 1 ]; then
		ipt 4 -t filter -A CALY_INPUT -m set --match-set calyanti_ban4 src -j "$DROP_TGT"
		ipt 6 -t filter -A CALY_INPUT -m set --match-set calyanti_ban6 src -j "$DROP_TGT"
	else
		ipt both -t filter -A CALY_INPUT -m recent --name calyban --rcheck --seconds "$BAN_TTL" -j "$DROP_TGT"
	fi

	# conntrack INVALID: forged or out-of-window segment (deferred past mgmt).
	ipt both -t filter -A CALY_INPUT -m conntrack --ctstate INVALID -j "$DROP_TGT"

	# IPv6 ND / PMTUD accept.
	ipt 6 -t filter -A CALY_INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 133 -j RETURN
	ipt 6 -t filter -A CALY_INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j RETURN
	ipt 6 -t filter -A CALY_INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 135 -j RETURN
	ipt 6 -t filter -A CALY_INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 136 -j RETURN
	ipt 6 -t filter -A CALY_INPUT -p ipv6-icmp -m icmp6 --icmpv6-type 2 -j RETURN
	ipt 4 -t filter -A CALY_INPUT -p icmp -m icmp --icmp-type 3 -j RETURN

	# ICMP policy (mandatory-pass types already returned above).
	ipt 4 -t filter -A CALY_INPUT -p icmp -m length --length "$((ICMP_TOTAL + 1)):65535" -j "$DROP_TGT"
	ipt 6 -t filter -A CALY_INPUT -p ipv6-icmp -m length --length "$((ICMP_TOTAL + 1)):65535" -j "$DROP_TGT"
	ipt 4 -t filter -A CALY_INPUT -p icmp -m icmp --icmp-type echo-request -m limit --limit 100/second --limit-burst 200 -j RETURN
	ipt 4 -t filter -A CALY_INPUT -p icmp -m icmp --icmp-type echo-request -j "$DROP_TGT"
	ipt 6 -t filter -A CALY_INPUT -p ipv6-icmp -m icmp6 --icmpv6-type echo-request -m limit --limit 100/second --limit-burst 200 -j RETURN
	ipt 6 -t filter -A CALY_INPUT -p ipv6-icmp -m icmp6 --icmpv6-type echo-request -j "$DROP_TGT"

	# unsolicited SYN-ACK (scan / reflected backscatter).
	ipt both -t filter -A CALY_INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m conntrack --ctstate NEW -j "$DROP_TGT"

	# reflection filter for NEW udp only.
	ipt both -t filter -A CALY_INPUT -p udp -m conntrack --ctstate NEW -j CALY_AMP

	# per-source volumetric buckets.
	ipt both -t filter -A CALY_INPUT -j CALY_BUCKETS

	# per-source new-connection rate + concurrent ceiling.
	ipt both -t filter -A CALY_INPUT -m conntrack --ctstate NEW \
		-m hashlimit --hashlimit-name caly_new --hashlimit-above "${R_NEW}${HL_UPTO}" \
		--hashlimit-burst "$R_NEW_BURST" --hashlimit-mode srcip -j caly_strike
	ipt 4 -t filter -A CALY_INPUT -p tcp -m conntrack --ctstate NEW \
		-m connlimit --connlimit-above "$CT_MAX" --connlimit-mask 32 -j "$DROP_TGT"
	ipt 6 -t filter -A CALY_INPUT -p tcp -m conntrack --ctstate NEW \
		-m connlimit --connlimit-above "$CT_MAX" --connlimit-mask 128 -j "$DROP_TGT"

	# global SYN ceiling (pre-5.15 syn_fallback_pps equivalent). Delegated to
	# CALY_SYNCEIL, which drops only the excess; conforming SYNs fall through
	# and RESUME here, so they still reach CALY_PORTS below. See build_synceil.
	ipt both -t filter -A CALY_INPUT -p tcp --tcp-flags SYN,ACK SYN -j CALY_SYNCEIL

	# per-port policy.
	ipt both -t filter -A CALY_INPUT -j CALY_PORTS
}

# --- filter FORWARD ----------------------------------------------------------
build_forward() {
	for _if in $CFG_LAN_IFACES; do
		ipt both -t filter -A CALY_FWD -i "$_if" -j RETURN
	done
	ipt both -t filter -A CALY_FWD -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
	# dynamic auto-ban past the established fast path, so a spoof-induced ban
	# never severs an established transiting flow (mirrors CALY_INPUT).
	if [ "$USE_IPSET" -eq 1 ]; then
		ipt 4 -t filter -A CALY_FWD -m set --match-set calyanti_ban4 src -j "$DROP_TGT"
		ipt 6 -t filter -A CALY_FWD -m set --match-set calyanti_ban6 src -j "$DROP_TGT"
	else
		ipt both -t filter -A CALY_FWD -m recent --name calyban --rcheck --seconds "$BAN_TTL" -j "$DROP_TGT"
	fi
	ipt both -t filter -A CALY_FWD -m conntrack --ctstate INVALID -j "$DROP_TGT"
	ipt both -t filter -A CALY_FWD -p tcp --tcp-flags SYN,ACK SYN,ACK -m conntrack --ctstate NEW -j "$DROP_TGT"
	ipt both -t filter -A CALY_FWD -p udp -m conntrack --ctstate NEW -j CALY_AMP
	ipt both -t filter -A CALY_FWD -m conntrack --ctstate NEW \
		-m hashlimit --hashlimit-name caly_fnew --hashlimit-above "${R_NEW}${HL_UPTO}" \
		--hashlimit-burst "$R_NEW_BURST" --hashlimit-mode srcip -j "$DROP_TGT"
}

# The strike helper. With ipset it inserts into the timed ban set (which the
# early chain then drops); without ipset it uses -m recent. Either way one
# burst does not ban - the hashlimit above only jumps here on sustained abuse.
build_strike_helper() {
	new_chain filter caly_strike
	if [ "$USE_IPSET" -eq 1 ]; then
		ipt 4 -t filter -A caly_strike -j SET --add-set calyanti_ban4 src --exist
		ipt 6 -t filter -A caly_strike -j SET --add-set calyanti_ban6 src --exist
	else
		ipt both -t filter -A caly_strike -m recent --name calyban --set
	fi
	ipt both -t filter -A caly_strike -j "$DROP_TGT"
}

# --- attach our chains to the real hooks -------------------------------------
wire_hooks() {
	ipt both -t mangle -A PREROUTING -j CALY_EARLY
	ipt both -t filter -A INPUT -j CALY_INPUT
	ipt both -t filter -A FORWARD -j CALY_FWD
}

# =============================================================================
# ipset integration
# =============================================================================
setup_ipsets() {
	[ "$USE_IPSET" -eq 1 ] || return 0
	if [ -x "$IPSET_HELPER" ] || [ -f "$IPSET_HELPER" ]; then
		log_dbg "creating ipsets via $IPSET_HELPER"
		if [ "$DRY" -eq 1 ]; then
			printf 'sh %s --config %s create\n' "$IPSET_HELPER" "$CONF_FILE"
		else
			sh "$IPSET_HELPER" --config "$CONF_FILE" create ||
				die 4 "ipset setup failed; re-run with --no-ipset to use inline -m recent"
		fi
	else
		# Create the minimum sets ourselves if the helper is missing.
		log_warn "ipset helper $IPSET_HELPER not found; creating sets inline"
		for _s in calyanti_allow4 calyanti_block4 calyanti_ban4; do
			if [ "$DRY" -eq 1 ]; then
				printf 'ipset create %s hash:net family inet -exist\n' "$_s"
			else
				"$IPSET_BIN" create "$_s" hash:net family inet -exist 2>>"$TMP_ERR" || true
			fi
		done
		for _s in calyanti_allow6 calyanti_block6 calyanti_ban6; do
			if [ "$DRY" -eq 1 ]; then
				printf 'ipset create %s hash:net family inet6 -exist\n' "$_s"
			else
				"$IPSET_BIN" create "$_s" hash:net family inet6 -exist 2>>"$TMP_ERR" || true
			fi
		done
		# Populate ban with a timeout so inline creation still expires.
		if [ "$DRY" -eq 0 ]; then
			"$IPSET_BIN" create calyanti_ban4 hash:net family inet timeout "$BAN_TTL" -exist 2>/dev/null || true
			"$IPSET_BIN" create calyanti_ban6 hash:net family inet6 timeout "$BAN_TTL" -exist 2>/dev/null || true
		fi
	fi
}

# =============================================================================
# Commands
# =============================================================================
setup_tmp() {
	TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/calyanti-ipt.XXXXXX") || die 4 "cannot create a temporary directory"
	TMP_IFACES="$TMP_DIR/ifaces"
	TMP_LIST="$TMP_DIR/list"
	TMP_PORTS="$TMP_DIR/ports"
	TMP_ERR="$TMP_DIR/err"
	: >"$TMP_ERR"
}
cleanup() { [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ] && rm -rf "$TMP_DIR"; return 0; }
trap cleanup EXIT HUP INT TERM

APPLY_FAILED=0

do_apply() {
	[ "$(id -u)" -eq 0 ] || die 5 "applying requires root"
	setup_tmp
	collect_config
	enforce_mgmt_safety
	setup_ipsets
	flush_chains
	build_strike_helper
	build_chains
	if [ "$APPLY_FAILED" -eq 1 ]; then
		log_err "one or more rules failed to load; the ruleset may be incomplete"
		log_err "$(cat "$TMP_ERR" 2>/dev/null | sed 's/^/  /')"
		die 4 "apply incomplete"
	fi
	log_info "iptables fallback active (v4:$DO_V4 v6:$DO_V6 ipset:$USE_IPSET monitor:$MONITOR)"
	log_info "persist across reboot with: iptables-save > /etc/iptables/rules.v4 (and ip6tables-save; distro dependent)"
}

do_remove() {
	[ "$(id -u)" -eq 0 ] || die 5 "removing requires root"
	setup_tmp
	# flush_chains unhooks from the base chains and deletes every CALY_*
	# and caly_strike chain (caly_strike is in FLUSH_FILTER).
	flush_chains
	# Best-effort cleanup of the inline -m recent list used when ipset is
	# unavailable, so a --no-ipset run leaves nothing behind either.
	for _fam in 4 6; do
		{ [ "$_fam" = 4 ] && [ "$DO_V4" -eq 1 ]; } || { [ "$_fam" = 6 ] && [ "$DO_V6" -eq 1 ]; } || continue
		_ipt=$IPT
		[ "$_fam" = 6 ] && _ipt=$IP6T
		"$_ipt" -t filter -F caly_strike 2>/dev/null || true
		"$_ipt" -t filter -X caly_strike 2>/dev/null || true
	done
	log_info "iptables fallback chains removed; the distro ruleset was not touched"
	if [ "$USE_IPSET" -eq 1 ] && { [ -x "$IPSET_HELPER" ] || [ -f "$IPSET_HELPER" ]; }; then
		log_info "ipsets left intact; remove them with: sh $IPSET_HELPER destroy"
	fi
}

do_dry_run() {
	DRY=1
	setup_tmp
	collect_config
	enforce_mgmt_safety
	printf '# ---- ipset setup ----\n'
	setup_ipsets
	printf '# ---- strike helper ----\n'
	build_strike_helper
	printf '# ---- chains ----\n'
	build_chains
	printf '# ---- (dry run: nothing above was executed) ----\n'
}

do_status() {
	setup_tmp
	_loaded=0
	for _fam in 4 6; do
		{ [ "$_fam" = 4 ] && [ "$DO_V4" -eq 1 ]; } || { [ "$_fam" = 6 ] && [ "$DO_V6" -eq 1 ]; } || continue
		_ipt=$IPT
		_label="IPv4"
		[ "$_fam" = 6 ] && {
			_ipt=$IP6T
			_label="IPv6"
		}
		if "$_ipt" -t filter -L CALY_INPUT >/dev/null 2>&1; then
			printf '%s: %s CALY chains are LOADED\n' "$PROG" "$_label"
			"$_ipt" -t filter -L CALY_INPUT -v -n 2>/dev/null || true
			"$_ipt" -t mangle -L CALY_EARLY -v -n 2>/dev/null || true
			_loaded=1
		else
			printf '%s: %s CALY chains are NOT loaded\n' "$PROG" "$_label"
		fi
	done
	[ "$_loaded" -eq 1 ]
}

# =============================================================================
# Dispatch
# =============================================================================
find_tools

case "$ACTION" in
apply) do_apply ;;
remove) do_remove ;;
dry-run) do_dry_run ;;
status) do_status ;;
*) die 1 "unknown action '$ACTION'" ;;
esac
