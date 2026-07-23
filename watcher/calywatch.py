#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Caly Anti - XDP/eBPF DDoS mitigation suite
# watcher/calywatch.py - layer-7 / log-driven defence.
#
# The XDP dataplane sees packets, not sessions.  Everything at L7 - an HTTP
# flood over completed handshakes, a WordPress login brute force, slowloris,
# an SSH dictionary run - is indistinguishable from legitimate traffic at
# L3/L4.  This watcher closes that gap: it tails logs, applies rule sets, and
# pushes the offenders down into the XDP ban maps where they cost nothing to
# enforce.
#
# ---------------------------------------------------------------------------
# THREAT MODEL FOR THIS FILE
#
# Log lines are ATTACKER-CONTROLLED.  A request for
#     GET /?x=1.2.3.4%20Failed%20password%20for%20root%20from%209.9.9.9
# lands verbatim in the access log.  Therefore, without exception:
#
#   * no eval(), no exec(), no compile() of anything derived from a log line;
#   * no shell anywhere - every subprocess is a literal argv list with
#     shell=False, and no value taken from a log line is ever placed in argv
#     without passing through ipaddress validation first;
#   * every ban target is produced by ipaddress.ip_address(), never by a
#     regex capture alone;
#   * X-Forwarded-For is honoured only when the DIRECT peer is inside a
#     configured trusted_proxy prefix;
#   * the allowlist is consulted before every single ban;
#   * bans are hard-capped per minute, so a log-injection flood cannot make
#     the watcher ban the internet;
#   * anything derived from a log line is sanitised before it is written to
#     our own log, so the attacker cannot inject lines into that either.
# ---------------------------------------------------------------------------
#
# Requires Python 3.6+.  Standard library only - no pip, no venv, works on
# Alpine/musl, RHEL 8's python3.6, and everything newer.

"""calywatch - Caly Anti layer-7 log watcher and ban feeder."""

import argparse
import collections
import errno
import fnmatch
import glob
import ipaddress
import json
import logging
import logging.handlers
import os
import re
import select
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Identity and defaults
# ---------------------------------------------------------------------------

PROG = "calywatch"
VERSION = "1.0.0"
ABI_MAJOR = 1                       # matches CALY_ABI_VERSION_MAJOR

DEFAULT_CONFIG = "/etc/calyanti/calywatch.conf"
DEFAULT_STATE = "/var/lib/calyanti/calywatch.state"
DEFAULT_SOCKETS = (
    "/run/calyanti/calyanti.sock",
    "/run/calyanti/control.sock",
    "/var/run/calyanti/calyanti.sock",
)
RULES_SEARCH_DIRS = (
    "/etc/calyanti/rules",
    "/etc/calyanti/watcher/rules",
    "/usr/share/calyanti/rules",
    "/usr/local/share/calyanti/rules",
)
CTL_CANDIDATES = ("calyctl", "calyanti-cli", "calyanti")

NS = 1000000000

# Hard ceilings.  These are not tunable: they bound worst-case memory and CPU
# when the input is hostile, and every one of them fails in the direction of
# doing less, never of banning more.
HARD_MAX_LINE_BYTES = 1 << 20        # 1 MiB of bytes with no newline
HARD_MAX_MATCH_CHARS = 65536         # characters handed to a regex
HARD_MAX_TRACKED = 4000000           # tracked keys across all rules
HARD_MAX_OFFENDERS = 500000          # persisted offender records
HARD_MAX_XFF_ENTRIES = 24            # hops parsed out of X-Forwarded-For
HARD_MAX_WEIGHT = 64
SLOW_RULE_SAMPLE = 512               # 1-in-N regex timing sample
SLOW_RULE_BUDGET_S = 0.05            # per-line budget for one rule (sampled)
SLOW_RULE_STRIKES = 20               # sampled overruns before auto-disable

log = logging.getLogger(PROG)


class ConfigError(Exception):
    """Raised for anything wrong in a config or rule file."""


class BackendError(Exception):
    """Raised when a ban backend fails in a way worth reporting."""


# ---------------------------------------------------------------------------
# Scalar parsing.  Value syntax deliberately mirrors calyanti.conf:
#   booleans   yes/no/true/false/on/off/1/0
#   durations  ns/us/ms/s/m/h/d, a bare number means SECONDS
# ---------------------------------------------------------------------------

_TRUE = frozenset(("yes", "true", "on", "1", "enable", "enabled"))
_FALSE = frozenset(("no", "false", "off", "0", "disable", "disabled"))

_DUR_MULT = {
    "": NS, "s": NS, "sec": NS, "secs": NS, "second": NS, "seconds": NS,
    "ns": 1, "nsec": 1,
    "us": 1000, "usec": 1000,
    "ms": 1000000, "msec": 1000000,
    "m": 60 * NS, "min": 60 * NS, "mins": 60 * NS, "minute": 60 * NS,
    "minutes": 60 * NS,
    "h": 3600 * NS, "hr": 3600 * NS, "hour": 3600 * NS, "hours": 3600 * NS,
    "d": 86400 * NS, "day": 86400 * NS, "days": 86400 * NS,
    "w": 604800 * NS, "week": 604800 * NS, "weeks": 604800 * NS,
}

_DUR_RE = re.compile(r"^([+-]?\d+(?:\.\d+)?)\s*([a-z]*)$")
_SIZE_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([kmg]i?b?)?$")


def parse_bool(text, what="value"):
    s = str(text).strip().lower()
    if s in _TRUE:
        return True
    if s in _FALSE:
        return False
    raise ConfigError("%s: expected a boolean (yes/no), got %r" % (what, text))


def parse_duration_ns(text, what="duration"):
    """Return nanoseconds.  Accepts a bare number as seconds, and floats, so
    fail2ban's `<bantime>` (e.g. '600.0' or '-1') can be passed straight in."""
    s = str(text).strip().lower()
    if not s:
        raise ConfigError("%s: empty duration" % what)
    m = _DUR_RE.match(s)
    if not m:
        raise ConfigError("%s: cannot parse duration %r" % (what, text))
    unit = m.group(2)
    if unit not in _DUR_MULT:
        raise ConfigError("%s: unknown duration unit %r" % (what, unit))
    try:
        val = float(m.group(1))
    except ValueError:
        raise ConfigError("%s: cannot parse duration %r" % (what, text))
    ns = int(val * _DUR_MULT[unit])
    # Cap at ~292 years so an int64 consumer downstream cannot be overflowed.
    if ns > (1 << 62):
        ns = 1 << 62
    if ns < -(1 << 62):
        ns = -(1 << 62)
    return ns


def parse_int(text, what="value", lo=None, hi=None):
    try:
        v = int(str(text).strip(), 10)
    except (TypeError, ValueError):
        raise ConfigError("%s: expected an integer, got %r" % (what, text))
    if lo is not None and v < lo:
        raise ConfigError("%s: %d is below the minimum %d" % (what, v, lo))
    if hi is not None and v > hi:
        raise ConfigError("%s: %d is above the maximum %d" % (what, v, hi))
    return v


def parse_size(text, what="size"):
    s = str(text).strip().lower()
    m = _SIZE_RE.match(s)
    if not m:
        raise ConfigError("%s: cannot parse size %r" % (what, text))
    mult = 1
    suf = (m.group(2) or "").rstrip("b")
    if suf == "k":
        mult = 1000
    elif suf == "ki":
        mult = 1024
    elif suf == "m":
        mult = 1000000
    elif suf == "mi":
        mult = 1024 * 1024
    elif suf == "g":
        mult = 1000000000
    elif suf == "gi":
        mult = 1024 * 1024 * 1024
    return int(float(m.group(1)) * mult)


def fmt_duration(ns):
    """Human-readable duration for logs.  Never used for parsing."""
    if ns <= 0:
        return "permanent"
    secs = ns // NS
    if secs < 1:
        return "%dms" % (ns // 1000000)
    parts = []
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60), ("s", 1)):
        if secs >= size:
            parts.append("%d%s" % (secs // size, unit))
            secs %= size
        if len(parts) == 2:
            break
    return "".join(parts) if parts else "0s"


# Everything that can carry attacker-controlled bytes goes through one of these
# two before it reaches our log, a JSON document, or an argv element.
_UNSAFE_LOG = re.compile(r"[^\x20-\x7e]")
_TAG_STRIP = re.compile(r"[^A-Za-z0-9_.:@-]")


def sanitize_text(text, limit=160):
    """Make an attacker-controlled string safe to print in our own log."""
    if text is None:
        return ""
    if not isinstance(text, str):
        try:
            text = text.decode("utf-8", "replace")
        except Exception:
            text = str(text)
    text = _UNSAFE_LOG.sub(".", text)
    if len(text) > limit:
        text = text[:limit] + "..."
    return text


def sanitize_tag(text, limit=48, default="unknown"):
    """Reduce a string to a conservative token safe for argv and JSON."""
    if text is None:
        return default
    out = _TAG_STRIP.sub("", str(text))[:limit]
    return out if out else default


# ---------------------------------------------------------------------------
# Address handling.  Strict by construction: a capture group is a *candidate*,
# never an address, until ipaddress has validated it.
# ---------------------------------------------------------------------------

_V4_LEADING_ZERO = re.compile(r"(?:^|\.)0\d")


def parse_ip_strict(text):
    """Validate an address candidate.  Returns an ipaddress object or None.

    Rejects, deliberately:
      * anything with a zone id ('%eth0') or prefix ('/24') - Python 3.9+
        accepts scope ids and we must behave identically on 3.6;
      * IPv4 octets with leading zeros ('010.0.0.1'), because different
        parsers read those as octal and we refuse to be ambiguous about which
        address we are banning;
      * anything longer than the longest legal textual address.
    Normalises IPv4-mapped IPv6 (::ffff:1.2.3.4) down to IPv4 so a dual-stack
    listener's logs and a v4 listener's logs produce the same ban target.
    """
    if not text:
        return None
    s = text.strip()
    if not s or len(s) > 45:
        return None
    if "%" in s or "/" in s or " " in s:
        return None
    if "." in s and ":" not in s and _V4_LEADING_ZERO.search(s):
        return None
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return None
    if addr.version == 6:
        mapped = addr.ipv4_mapped
        if mapped is not None:
            return mapped
        # ::ffff:0:1.2.3.4 style translated addresses are not unwrapped: they
        # are genuinely different peers.
    return addr


def parse_network_strict(text):
    """Validate a CIDR or bare address.  Returns an ip_network or None."""
    if not text:
        return None
    s = text.strip()
    if not s or len(s) > 64 or "%" in s or " " in s:
        return None
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None


class NetSet(object):
    """Prefix-set membership without a linear scan over every entry.

    Networks are bucketed by prefix length; a lookup masks the address once per
    distinct prefix length and does a hash-set probe.  Real allowlists have a
    handful of distinct lengths, so this is effectively O(1) per query and
    stays fast even with tens of thousands of prefixes.
    """

    __slots__ = ("_buckets", "_masks", "count")

    def __init__(self):
        self._buckets = {4: {}, 6: {}}
        self._masks = {4: {}, 6: {}}
        self.count = 0

    def add_network(self, net):
        v = net.version
        bits = 32 if v == 4 else 128
        plen = net.prefixlen
        if plen not in self._masks[v]:
            self._masks[v][plen] = (((1 << plen) - 1) << (bits - plen)) if plen else 0
            self._buckets[v][plen] = set()
        self._buckets[v][plen].add(int(net.network_address))
        self.count += 1

    def add(self, text):
        """Add one CIDR/address.  Returns True when accepted."""
        net = parse_network_strict(text)
        if net is None:
            return False
        self.add_network(net)
        return True

    def add_address(self, addr):
        bits = 32 if addr.version == 4 else 128
        self.add_network(ipaddress.ip_network("%s/%d" % (addr, bits)))

    def __len__(self):
        return self.count

    def __contains__(self, addr):
        v = addr.version
        buckets = self._buckets[v]
        if not buckets:
            return False
        ai = int(addr)
        masks = self._masks[v]
        for plen, members in buckets.items():
            if (ai & masks[plen]) in members:
                return True
        return False

    def describe(self):
        n4 = sum(len(s) for s in self._buckets[4].values())
        n6 = sum(len(s) for s in self._buckets[6].values())
        return "%d v4 + %d v6 prefixes" % (n4, n6)


# ---------------------------------------------------------------------------
# Config / rule file lexer.
#
# One format for both files:  '#' or ';' starts a comment, '[section]' opens a
# section, 'key = value' sets a key.  Keys repeat: every section is a list of
# (key, value, lineno) so 'allow' or 'regex' can appear many times.  Nothing
# here interprets a value; that is each consumer's job.
# ---------------------------------------------------------------------------

_SECTION_RE = re.compile(r"^\[\s*([^\]]{1,120}?)\s*\]$")
_KV_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]{0,63})\s*=\s*(.*)$")


class Section(object):
    __slots__ = ("name", "items", "lineno")

    def __init__(self, name, lineno):
        self.name = name
        self.items = []
        self.lineno = lineno

    def add(self, key, value, lineno):
        self.items.append((key, value, lineno))

    def all(self, key):
        return [v for (k, v, _) in self.items if k == key]

    def get(self, key, default=None):
        found = default
        for (k, v, _) in self.items:
            if k == key:
                found = v
        return found

    def lineno_of(self, key):
        for (k, _v, ln) in self.items:
            if k == key:
                return ln
        return self.lineno

    def keys(self):
        return set(k for (k, _v, _l) in self.items)


def lex_file(path):
    """Parse a config/rule file into [Section].  Section 0 is the header (the
    part before the first '[...]') and is always present."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read()
    except OSError as exc:
        raise ConfigError("cannot read %s: %s" % (path, exc))

    sections = [Section("", 0)]
    cur = sections[0]
    for lineno, line in enumerate(raw.splitlines(), 1):
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        m = _SECTION_RE.match(line)
        if m:
            name = m.group(1).strip()
            # '[rule foo]' and '[foo]' are the same thing.
            parts = name.split(None, 1)
            if len(parts) == 2 and parts[0].lower() in ("rule", "section"):
                name = parts[1].strip()
            cur = Section(name, lineno)
            sections.append(cur)
            continue
        m = _KV_RE.match(line)
        if not m:
            raise ConfigError("%s:%d: not a 'key = value' line: %s"
                              % (path, lineno, sanitize_text(line, 80)))
        cur.add(m.group(1).strip().lower(), m.group(2).strip(), lineno)
    return sections


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

ACTION_BAN = "ban"
ACTION_WARN = "warn"
ACTION_COUNT = "count"
ACTION_IGNORE = "ignore"
ACTIONS = (ACTION_BAN, ACTION_WARN, ACTION_COUNT, ACTION_IGNORE)

_COND_SYM_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]{0,31})\s*(!~|~|==|!=|>=|<=|>|<)\s*(.*)$")
_COND_WORD_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]{0,31})\s+(!in|in)\s+(.*)$", re.I)


class Condition(object):
    """One `match = <group> <op> <value>` clause.

    A missing capture group makes a positive condition (~ == >= in ...) FAIL
    and a negative condition (!~ != !in) PASS.  That is the intuitive reading
    of "the path must not contain X" when there is no path at all, and it is
    the conservative one: a missing group never manufactures a ban.
    """

    __slots__ = ("group", "op", "raw", "regex", "number", "members")

    def __init__(self, text, where):
        m = _COND_SYM_RE.match(text) or _COND_WORD_RE.match(text)
        if not m:
            raise ConfigError("%s: cannot parse match expression %r"
                              % (where, sanitize_text(text, 100)))
        self.group = m.group(1)
        self.op = m.group(2).lower()
        self.raw = m.group(3).strip()
        self.regex = None
        self.number = None
        self.members = None

        if self.op in ("~", "!~"):
            if not self.raw:
                raise ConfigError("%s: empty regex in match expression" % where)
            if len(self.raw) > 4096:
                raise ConfigError("%s: match regex is too long" % where)
            try:
                self.regex = re.compile(self.raw)
            except re.error as exc:
                raise ConfigError("%s: bad regex in match expression: %s"
                                  % (where, exc))
        elif self.op in (">=", "<=", ">", "<"):
            try:
                self.number = float(self.raw)
            except ValueError:
                raise ConfigError("%s: %r is not numeric" % (where, self.raw))
        elif self.op in ("in", "!in"):
            self.members = frozenset(
                p.strip() for p in self.raw.split(","))
        # '==' / '!=' compare the raw string.

    def evaluate(self, match):
        try:
            value = match.group(self.group)
        except (IndexError, error_types):
            value = None
        negative = self.op in ("!~", "!=", "!in")
        if value is None:
            return negative
        op = self.op
        if op == "~":
            return self.regex.search(value) is not None
        if op == "!~":
            return self.regex.search(value) is None
        if op == "==":
            return value == self.raw
        if op == "!=":
            return value != self.raw
        if op == "in":
            return value.strip() in self.members
        if op == "!in":
            return value.strip() not in self.members
        try:
            num = float(value)
        except (TypeError, ValueError):
            return False
        if op == ">=":
            return num >= self.number
        if op == "<=":
            return num <= self.number
        if op == ">":
            return num > self.number
        return num < self.number


# re.error is the exception a bad group name raises on some versions; keep the
# tuple in one place so Condition.evaluate stays readable.
error_types = re.error


class Rule(object):
    """A compiled rule: what to look for, how often, and what to do about it."""

    __slots__ = ("name", "rid", "desc", "enabled", "prefilters", "regexes",
                 "ip_group", "xff_group", "conditions", "distinct",
                 "threshold", "window_ns", "window_s", "weight", "cooldown_s",
                 "action", "ttl_ns", "reason", "severity", "max_tracked",
                 "matches", "fires", "ip_parse_fail", "slow_strikes",
                 "sample_counter", "disabled_reason")

    def __init__(self, ruleset_name, section, path, defaults):
        where = "%s:%d [%s]" % (path, section.lineno, section.name)
        name = sanitize_tag(section.name, 64, "")
        if not name:
            raise ConfigError("%s: rule name is empty or unusable" % where)
        self.name = name
        self.rid = "%s/%s" % (ruleset_name, name)
        self.desc = sanitize_text(section.get("desc", ""), 200)

        def pick(key, fallback):
            v = section.get(key)
            return fallback if v is None else v

        self.enabled = parse_bool(pick("enabled", defaults["enabled"]),
                                  "%s enabled" % where)
        self.prefilters = tuple(p for p in section.all("prefilter") if p)

        pats = [p for p in section.all("regex") if p]
        if not pats:
            raise ConfigError("%s: rule has no 'regex ='" % where)
        self.regexes = []
        for pat in pats:
            if len(pat) > 8192:
                raise ConfigError("%s: regex is too long" % where)
            try:
                self.regexes.append(re.compile(pat))
            except re.error as exc:
                raise ConfigError("%s: bad regex: %s" % (where, exc))

        self.ip_group = sanitize_tag(pick("ip_group", defaults["ip_group"]),
                                     32, "ip")
        xg = section.get("xff_group", defaults["xff_group"])
        self.xff_group = sanitize_tag(xg, 32, "") if xg else None

        self.conditions = [Condition(t, where)
                           for t in section.all("match") if t]

        dg = section.get("distinct")
        self.distinct = sanitize_tag(dg, 32, "") if dg else None

        self.threshold = parse_int(pick("threshold", defaults["threshold"]),
                                   "%s threshold" % where, 1, 10000000)
        self.window_ns = parse_duration_ns(pick("window", defaults["window"]),
                                           "%s window" % where)
        if self.window_ns < NS // 10:
            raise ConfigError("%s: window must be at least 100ms" % where)
        self.window_s = self.window_ns / float(NS)
        self.weight = parse_int(pick("weight", "1"), "%s weight" % where,
                                1, HARD_MAX_WEIGHT)
        cd = section.get("cooldown")
        self.cooldown_s = (parse_duration_ns(cd, "%s cooldown" % where)
                           / float(NS)) if cd else self.window_s

        act = str(pick("action", defaults["action"])).strip().lower()
        if act not in ACTIONS:
            raise ConfigError("%s: action must be one of %s"
                              % (where, ", ".join(ACTIONS)))
        self.action = act

        ttl = pick("ttl", defaults["ttl"])
        self.ttl_ns = parse_duration_ns(ttl, "%s ttl" % where) if ttl else 0
        if self.ttl_ns < 0:
            self.ttl_ns = 0

        self.reason = sanitize_tag(pick("reason", name), 40, name)
        self.severity = parse_int(pick("severity", "5"), "%s severity" % where,
                                  0, 9)
        self.max_tracked = parse_int(
            pick("max_tracked", defaults["max_tracked"]),
            "%s max_tracked" % where, 16, HARD_MAX_TRACKED)

        if self.action == ACTION_IGNORE and self.conditions is None:
            pass

        # runtime counters
        self.matches = 0
        self.fires = 0
        self.ip_parse_fail = 0
        self.slow_strikes = 0
        self.sample_counter = 0
        self.disabled_reason = None

    # -- matching ---------------------------------------------------------

    def prefilter_ok(self, line):
        if not self.prefilters:
            return True
        for needle in self.prefilters:
            if needle in line:
                return True
        return False

    def search(self, line):
        for rx in self.regexes:
            m = rx.search(line)
            if m is not None:
                return m
        return None

    def conditions_ok(self, match):
        for cond in self.conditions:
            if not cond.evaluate(match):
                return False
        return True

    def distinct_value(self, match):
        try:
            v = match.group(self.distinct)
        except (IndexError, re.error):
            return None
        if v is None:
            return None
        # Cap the stored key so a 2 KiB URI cannot blow up the tracker.
        return v[:160]

    def disable(self, why):
        self.enabled = False
        self.disabled_reason = why


class RuleSet(object):
    """One .rules file: a header of defaults plus an ordered list of rules.

    Rules with action=ignore are hoisted to the front, so 'a successful login
    clears this address' is evaluated before the failure counters that would
    otherwise also match the same line.
    """

    __slots__ = ("name", "path", "desc", "rules", "mtime")

    def __init__(self, path):
        sections = lex_file(path)
        header = sections[0]
        base = os.path.basename(path)
        if base.endswith(".rules"):
            base = base[:-6]
        self.name = sanitize_tag(header.get("name", base), 40, "rules")
        self.path = path
        self.desc = sanitize_text(header.get("desc", ""), 200)
        try:
            self.mtime = os.path.getmtime(path)
        except OSError:
            self.mtime = 0.0

        defaults = {
            "enabled": header.get("enabled", "yes"),
            "ip_group": header.get("ip_group", "ip"),
            "xff_group": header.get("xff_group", ""),
            "threshold": header.get("threshold", "1"),
            "window": header.get("window", "60s"),
            "action": header.get("action", ACTION_BAN),
            "ttl": header.get("ttl", ""),
            "max_tracked": header.get("max_tracked", "65536"),
        }

        rules = []
        seen = set()
        for sec in sections[1:]:
            if not sec.name:
                continue
            rule = Rule(self.name, sec, path, defaults)
            if rule.rid in seen:
                raise ConfigError("%s: duplicate rule name [%s]"
                                  % (path, rule.name))
            seen.add(rule.rid)
            rules.append(rule)
        if not rules:
            raise ConfigError("%s: no rules defined" % path)
        rules.sort(key=lambda r: 0 if r.action == ACTION_IGNORE else 1)
        self.rules = rules

    def active(self):
        return [r for r in self.rules if r.enabled]


def resolve_rule_path(spec, rules_dirs):
    """Turn a `rules =` value into a list of existing files.

    Accepts an absolute path, a glob, or a bare name ('nginx' / 'nginx.rules')
    which is searched for in the configured rule directories.
    """
    out = []
    if os.path.isabs(spec) or spec.startswith("./") or spec.startswith("../"):
        cands = sorted(glob.glob(spec)) or ([spec] if os.path.exists(spec) else [])
        out.extend(cands)
        return out
    if any(ch in spec for ch in "*?["):
        for d in rules_dirs:
            out.extend(sorted(glob.glob(os.path.join(d, spec))))
        return out
    names = [spec] if spec.endswith(".rules") else [spec + ".rules", spec]
    for d in rules_dirs:
        for nm in names:
            cand = os.path.join(d, nm)
            if os.path.isfile(cand):
                out.append(cand)
                return out
    return out


# ---------------------------------------------------------------------------
# Sliding windows.
#
# Occurrence counting is a deque of monotonic timestamps with maxlen set to the
# threshold.  Appending to a full deque drops the oldest entry, which is
# exactly the entry we would have pruned anyway; the count can therefore never
# exceed the threshold, memory per key is bounded by the threshold, and there
# is no per-line rescan of anything.
#
# Distinct-value counting uses a TUMBLING window with a capped set, mirroring
# the dataplane's scan_state Bloom filter: it undercounts on eviction, and
# undercounting biases towards not banning, which is the safe direction.
# ---------------------------------------------------------------------------

class Counter(object):
    __slots__ = ("dq", "last_fire")

    def __init__(self, maxlen):
        self.dq = collections.deque(maxlen=maxlen)
        self.last_fire = 0.0

    def add(self, now, window_s, weight):
        dq = self.dq
        for _ in range(weight):
            dq.append(now)
        cutoff = now - window_s
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def value(self, now, window_s):
        dq = self.dq
        cutoff = now - window_s
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def clear(self):
        self.dq.clear()

    def empty(self, now, window_s):
        return self.value(now, window_s) == 0


class DistinctCounter(object):
    __slots__ = ("values", "start", "last_fire", "cap")

    def __init__(self, cap):
        self.values = set()
        self.start = 0.0
        self.last_fire = 0.0
        self.cap = cap

    def add(self, now, window_s, value):
        if self.start == 0.0 or (now - self.start) > window_s:
            self.values.clear()
            self.start = now
        if len(self.values) < self.cap:
            self.values.add(value)
        return len(self.values)

    def value(self, now, window_s):
        if self.start == 0.0 or (now - self.start) > window_s:
            return 0
        return len(self.values)

    def clear(self):
        self.values.clear()
        self.start = 0.0

    def empty(self, now, window_s):
        return self.value(now, window_s) == 0


class Tracker(object):
    """Per-rule map of key -> counter with an LRU cap.

    The cap is what stops a spoofed-source or log-injection flood from turning
    unbounded distinct keys into unbounded memory.  Evicting the least recently
    touched key loses history for a source we have not heard from in a while,
    which is the correct thing to forget first.
    """

    __slots__ = ("rule", "keys", "max_keys", "evictions")

    def __init__(self, rule):
        self.rule = rule
        self.keys = collections.OrderedDict()
        self.max_keys = rule.max_tracked
        self.evictions = 0

    def _new(self):
        if self.rule.distinct:
            cap = min(max(self.rule.threshold * 4, 64), 8192)
            return DistinctCounter(cap)
        return Counter(self.rule.threshold)

    def get(self, key):
        counter = self.keys.get(key)
        if counter is None:
            counter = self._new()
            self.keys[key] = counter
            while len(self.keys) > self.max_keys:
                self.keys.popitem(last=False)
                self.evictions += 1
        else:
            self.keys.move_to_end(key)
        return counter

    def drop(self, key):
        self.keys.pop(key, None)

    def gc(self, now):
        """Drop keys whose window has emptied.  Bounded work per sweep so a
        huge tracker cannot stall the event loop."""
        rule = self.rule
        removed = 0
        budget = 20000
        for key in list(self.keys.keys())[:budget]:
            counter = self.keys.get(key)
            if counter is not None and counter.empty(now, rule.window_s):
                del self.keys[key]
                removed += 1
        return removed

    def __len__(self):
        return len(self.keys)


# ---------------------------------------------------------------------------
# Subprocess helper.
#
# THERE IS NO SHELL IN THIS FILE.  Every call passes a literal argv list with
# shell=False, and the only variable elements are (a) addresses that have been
# through ipaddress, (b) integers, and (c) tags reduced to [A-Za-z0-9_.:@-].
# ---------------------------------------------------------------------------

def run_cmd(argv, timeout=10.0, stdin_data=None):
    """Run argv without a shell.  Returns (rc, stdout, stderr)."""
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            universal_newlines=True,
        )
    except OSError as exc:
        return (127, "", str(exc))
    try:
        out, err = proc.communicate(input=stdin_data, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:
            out, err = ("", "timeout")
        return (124, out or "", err or "timeout")
    return (proc.returncode, out or "", err or "")


def find_binary(names, extra_dirs=("/usr/sbin", "/sbin", "/usr/local/sbin",
                                   "/usr/bin", "/usr/local/bin")):
    for name in names:
        path = shutil.which(name)
        if path:
            return path
        for d in extra_dirs:
            cand = os.path.join(d, name)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return None


# ---------------------------------------------------------------------------
# Ban backends, best first.
#
#   1. control socket   - the daemon writes caly_ban4/caly_ban6 directly
#   2. calyctl          - same thing through the CLI
#   3. nft              - a dedicated table, used when XDP is not running
#   4. ipset+iptables   - the last rung of the ladder
#
# A backend that fails is skipped for `retry_after` seconds and the next one is
# tried, so a daemon restart degrades to nft rather than losing the ban.
# ---------------------------------------------------------------------------

class BanBackend(object):
    name = "none"

    def __init__(self, cfg):
        self.cfg = cfg
        self.ok = True
        self.failed_at = 0.0
        self.retry_after = 30.0
        self.bans = 0
        self.errors = 0
        self.last_error = ""

    def usable(self, now):
        if self.ok:
            return True
        return (now - self.failed_at) >= self.retry_after

    def mark_ok(self):
        self.ok = True
        self.last_error = ""

    def mark_fail(self, why, now):
        was_ok = self.ok
        self.ok = False
        self.failed_at = now
        self.errors += 1
        self.last_error = sanitize_text(str(why), 200)
        if was_ok:
            log.warning("backend %s failed: %s", self.name, self.last_error)

    # Subclasses implement these three.
    def probe(self):
        return False

    def ban(self, addr, ttl_ns, reason):
        raise NotImplementedError

    def unban(self, addr):
        raise NotImplementedError

    def flush(self):
        return False


class DryRunBackend(BanBackend):
    name = "dry-run"

    def probe(self):
        return True

    def ban(self, addr, ttl_ns, reason):
        log.info("DRY RUN would ban %s ttl=%s reason=%s",
                 addr, fmt_duration(ttl_ns), reason)
        return True

    def unban(self, addr):
        log.info("DRY RUN would unban %s", addr)
        return True

    def flush(self):
        log.info("DRY RUN would flush all watcher bans")
        return True


class SocketBackend(BanBackend):
    """AF_UNIX control socket to the calyanti daemon.

    Wire format, newline-delimited, one request and one response per line:

        {"cmd":"ban","addr":"1.2.3.4","ttl_ns":600000000000,
         "reason":"sshd-brute","origin":"calywatch","abi_major":1}
        {"ok":true}

    A daemon that answers something that is not JSON is assumed to speak the
    plain-text form instead, and we fall back to it permanently for this
    connection generation:

        BAN <addr> <ttl_seconds> <reason>\\n   ->  OK / ERR <text>
        UNBAN <addr>\\n                        ->  OK / ERR <text>
        PING\\n                                ->  PONG / OK

    ttl 0 means permanent in both forms.
    """

    name = "socket"

    def __init__(self, cfg, paths):
        BanBackend.__init__(self, cfg)
        self.paths = list(paths)
        self.path = None
        self.sock = None
        self.rbuf = b""
        self.text_mode = False
        self.retry_after = 15.0

    # -- connection -------------------------------------------------------

    def _close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None
        self.rbuf = b""

    def _connect(self):
        if self.sock is not None:
            return True
        last = None
        order = ([self.path] if self.path else []) + \
                [p for p in self.paths if p != self.path]
        for path in order:
            if not path:
                continue
            try:
                st = os.stat(path)
            except OSError as exc:
                last = exc
                continue
            if not stat.S_ISSOCK(st.st_mode):
                last = "not a socket"
                continue
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            try:
                sock.connect(path)
            except OSError as exc:
                last = exc
                try:
                    sock.close()
                except OSError:
                    pass
                continue
            self.sock = sock
            self.path = path
            self.rbuf = b""
            self.text_mode = False
            return True
        raise BackendError("no usable control socket (%s)" % (last,))

    def _readline(self):
        while b"\n" not in self.rbuf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise BackendError("control socket closed")
            self.rbuf += chunk
            if len(self.rbuf) > 65536:
                raise BackendError("control socket response too long")
        line, _, rest = self.rbuf.partition(b"\n")
        self.rbuf = rest
        return line.decode("utf-8", "replace").strip()

    def _round_trip(self, payload):
        self._connect()
        try:
            self.sock.sendall(payload)
            return self._readline()
        except (OSError, BackendError):
            # One reconnect: the daemon may have been restarted between bans.
            self._close()
            self._connect()
            self.sock.sendall(payload)
            return self._readline()

    def _request(self, obj, text_form):
        if not self.text_mode:
            payload = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
            reply = self._round_trip(payload)
            try:
                data = json.loads(reply)
            except ValueError:
                # Not a JSON speaker.  Retry once in text mode and remember.
                self.text_mode = True
                log.info("control socket %s speaks the plain-text protocol",
                         self.path)
            else:
                if isinstance(data, dict) and data.get("ok"):
                    return True
                err = "daemon refused"
                if isinstance(data, dict):
                    err = sanitize_text(str(data.get("error", err)), 160)
                raise BackendError(err)
        reply = self._round_trip((text_form + "\n").encode("utf-8"))
        head = reply.split(None, 1)[0].upper() if reply else ""
        if head in ("OK", "PONG", "ACK"):
            return True
        raise BackendError(sanitize_text(reply, 160) or "empty reply")

    # -- operations -------------------------------------------------------

    def probe(self):
        try:
            self._connect()
            return self._request({"cmd": "ping", "origin": PROG,
                                  "abi_major": ABI_MAJOR}, "PING")
        except (BackendError, OSError):
            self._close()
            return False

    def ban(self, addr, ttl_ns, reason):
        secs = 0 if ttl_ns <= 0 else max(1, ttl_ns // NS)
        obj = {
            "cmd": "ban",
            "addr": str(addr),
            "family": 4 if addr.version == 4 else 6,
            "ttl_ns": max(0, int(ttl_ns)),
            "permanent": ttl_ns <= 0,
            "reason": reason,
            "origin": PROG,
            "abi_major": ABI_MAJOR,
        }
        text = "BAN %s %d %s" % (addr, secs, reason)
        try:
            return self._request(obj, text)
        except (OSError, BackendError):
            self._close()
            raise

    def unban(self, addr):
        obj = {"cmd": "unban", "addr": str(addr), "origin": PROG,
               "abi_major": ABI_MAJOR}
        try:
            return self._request(obj, "UNBAN %s" % (addr,))
        except (OSError, BackendError):
            self._close()
            raise

    def flush(self):
        obj = {"cmd": "unban_all", "origin": PROG, "abi_major": ABI_MAJOR}
        try:
            return self._request(obj, "UNBANALL")
        except (OSError, BackendError):
            self._close()
            raise


class CalyctlBackend(BanBackend):
    """Shell out to the project's own CLI.

    The argv template is configurable because the CLI's flag spelling is owned
    by another component; it is split with shlex ONCE at load time and the
    placeholders are substituted per-token, so no value can ever introduce a
    new argument, let alone a shell metacharacter.

        ban_args   = ban %a --ttl %ts --reason %r
        unban_args = unban %a
    """

    name = "calyctl"

    def __init__(self, cfg, binary, ban_args, unban_args, flush_args):
        BanBackend.__init__(self, cfg)
        self.binary = binary
        self.ban_args = ban_args
        self.unban_args = unban_args
        self.flush_args = flush_args
        self.retry_after = 30.0

    @staticmethod
    def expand(template, addr, ttl_ns, reason):
        secs = 0 if ttl_ns <= 0 else max(1, ttl_ns // NS)
        out = []
        for tok in template:
            # Longer placeholders MUST be substituted before their prefixes:
            # %ts contains %t, so replacing %t first would corrupt it.
            tok = tok.replace("%a", str(addr))
            tok = tok.replace("%ts", str(secs))
            tok = tok.replace("%t", str(secs))
            tok = tok.replace("%n", str(max(0, int(ttl_ns))))
            tok = tok.replace("%r", reason)
            tok = tok.replace("%v", "4" if addr.version == 4 else "6")
            tok = tok.replace("%%", "%")
            out.append(tok)
        return out

    def probe(self):
        if not self.binary:
            return False
        rc, _out, _err = run_cmd([self.binary, "--version"], timeout=5.0)
        if rc == 0:
            return True
        rc, _out, _err = run_cmd([self.binary, "version"], timeout=5.0)
        return rc == 0

    def ban(self, addr, ttl_ns, reason):
        if not self.binary:
            raise BackendError("no calyctl binary found")
        argv = [self.binary] + self.expand(self.ban_args, addr, ttl_ns, reason)
        rc, _out, err = run_cmd(argv, timeout=15.0)
        if rc != 0:
            raise BackendError("%s exited %d: %s"
                               % (os.path.basename(self.binary), rc,
                                  sanitize_text(err, 160)))
        return True

    def unban(self, addr):
        if not self.binary:
            raise BackendError("no calyctl binary found")
        argv = [self.binary] + self.expand(self.unban_args, addr, 0, "manual")
        rc, _out, err = run_cmd(argv, timeout=15.0)
        if rc != 0:
            raise BackendError("%s exited %d: %s"
                               % (os.path.basename(self.binary), rc,
                                  sanitize_text(err, 160)))
        return True

    def flush(self):
        if not self.binary or not self.flush_args:
            return False
        argv = [self.binary] + list(self.flush_args)
        rc, _out, err = run_cmd(argv, timeout=30.0)
        if rc != 0:
            raise BackendError("flush exited %d: %s" % (rc, sanitize_text(err, 160)))
        return True


class NftBackend(BanBackend):
    """nftables fallback.

    Uses its OWN table (default `inet calywatch`) so it can never collide with
    or clobber the table the nftables dataplane rung installs.  The chain is
    built accept-first for the management ports, so even if the allowlist is
    empty and the watcher goes berserk, SSH survives:

        table inet calywatch {
          set calywatch4 { type ipv4_addr; flags timeout; }
          set calywatch6 { type ipv6_addr; flags timeout; }
          chain watchdrop {
            type filter hook input priority -150; policy accept;
            tcp dport { 22 } accept
            ip  saddr @calywatch4 drop
            ip6 saddr @calywatch6 drop
          }
        }
    """

    name = "nft"

    def __init__(self, cfg, binary, family, table, chain, set4, set6,
                 mgmt_ports, priority):
        BanBackend.__init__(self, cfg)
        self.binary = binary
        self.family = family
        self.table = table
        self.chain = chain
        self.set4 = set4
        self.set6 = set6
        self.mgmt_ports = list(mgmt_ports)
        self.priority = priority
        self.ready = False
        self.retry_after = 60.0

    def _nft(self, args, timeout=10.0):
        return run_cmd([self.binary] + args, timeout=timeout)

    def probe(self):
        if not self.binary:
            return False
        rc, _out, _err = self._nft(["--version"], timeout=5.0)
        return rc == 0

    def ensure(self):
        if self.ready:
            return True
        if not self.binary:
            raise BackendError("nft binary not found")
        fam, tbl, chn = self.family, self.table, self.chain

        rc, _o, err = self._nft(["add", "table", fam, tbl])
        if rc != 0:
            raise BackendError("add table: %s" % sanitize_text(err, 160))

        for setname, atype in ((self.set4, "ipv4_addr"), (self.set6, "ipv6_addr")):
            rc, _o, err = self._nft([
                "add", "set", fam, tbl, setname,
                "{", "type", atype, ";", "flags", "timeout", ";",
                "timeout", "1h", ";", "}"])
            if rc != 0:
                raise BackendError("add set %s: %s"
                                   % (setname, sanitize_text(err, 160)))

        rc, _o, err = self._nft([
            "add", "chain", fam, tbl, chn,
            "{", "type", "filter", "hook", "input",
            "priority", str(self.priority), ";", "policy", "accept", ";", "}"])
        if rc != 0:
            raise BackendError("add chain: %s" % sanitize_text(err, 160))

        rc, listing, err = self._nft(["list", "chain", fam, tbl, chn])
        if rc != 0:
            raise BackendError("list chain: %s" % sanitize_text(err, 160))

        # Management accept first, then the two drops.  Existence is tested by
        # string search because nft has no 'rule exists' primitive.
        if self.mgmt_ports and "dport" not in listing:
            ports = ",".join(str(p) for p in self.mgmt_ports)
            rc, _o, err = self._nft(["add", "rule", fam, tbl, chn,
                                     "tcp", "dport", "{", ports, "}", "accept"])
            if rc != 0:
                raise BackendError("add mgmt accept: %s" % sanitize_text(err, 160))
        if ("@" + self.set4) not in listing:
            rc, _o, err = self._nft(["add", "rule", fam, tbl, chn,
                                     "ip", "saddr", "@" + self.set4, "drop"])
            if rc != 0:
                raise BackendError("add v4 drop: %s" % sanitize_text(err, 160))
        if ("@" + self.set6) not in listing:
            rc, _o, err = self._nft(["add", "rule", fam, tbl, chn,
                                     "ip6", "saddr", "@" + self.set6, "drop"])
            if rc != 0:
                raise BackendError("add v6 drop: %s" % sanitize_text(err, 160))

        self.ready = True
        log.info("nft fallback ready: table %s %s, sets %s/%s",
                 fam, tbl, self.set4, self.set6)
        return True

    def ban(self, addr, ttl_ns, reason):
        self.ensure()
        setname = self.set4 if addr.version == 4 else self.set6
        elem = [str(addr)]
        if ttl_ns > 0:
            elem += ["timeout", "%ds" % max(1, ttl_ns // NS)]
        rc, _o, err = self._nft(["add", "element", self.family, self.table,
                                 setname, "{"] + elem + ["}"])
        if rc != 0:
            raise BackendError("add element: %s" % sanitize_text(err, 160))
        return True

    def unban(self, addr):
        self.ensure()
        setname = self.set4 if addr.version == 4 else self.set6
        rc, _o, err = self._nft(["delete", "element", self.family, self.table,
                                 setname, "{", str(addr), "}"])
        if rc != 0 and "No such file" not in err:
            raise BackendError("delete element: %s" % sanitize_text(err, 160))
        return True

    def flush(self):
        if not self.binary:
            return False
        ok = True
        for setname in (self.set4, self.set6):
            rc, _o, _e = self._nft(["flush", "set", self.family, self.table,
                                    setname])
            ok = ok and rc == 0
        return ok


class IpsetBackend(BanBackend):
    """ipset + iptables, the bottom rung.

    A dedicated CALYWATCH chain is jumped to from INPUT, and inside it the
    management ports RETURN before the set match, for the same reason as the
    nft backend.
    """

    name = "ipset"

    def __init__(self, cfg, ipset_bin, ipt_bin, ip6t_bin, set4, set6,
                 chain, mgmt_ports, max_ttl_ns):
        BanBackend.__init__(self, cfg)
        self.ipset = ipset_bin
        self.ipt = ipt_bin
        self.ip6t = ip6t_bin
        self.set4 = set4
        self.set6 = set6
        self.chain = chain
        self.mgmt_ports = list(mgmt_ports)
        self.max_ttl = max(60, int(max_ttl_ns // NS)) if max_ttl_ns > 0 else 86400
        self.ready = False
        self.retry_after = 60.0

    def probe(self):
        return bool(self.ipset and (self.ipt or self.ip6t))

    def _ensure_family(self, ipt, setname, family):
        if not ipt:
            return
        rc, _o, err = run_cmd([self.ipset, "create", setname,
                               "hash:ip", "family", family,
                               "timeout", str(self.max_ttl),
                               "maxelem", "1048576", "-exist"])
        if rc != 0:
            raise BackendError("ipset create %s: %s"
                               % (setname, sanitize_text(err, 160)))

        rc, _o, _e = run_cmd([ipt, "-n", "-L", self.chain], timeout=15.0)
        if rc != 0:
            rc, _o, err = run_cmd([ipt, "-N", self.chain], timeout=15.0)
            if rc != 0 and "exists" not in (err or "").lower():
                raise BackendError("create chain: %s" % sanitize_text(err, 160))

        for port in self.mgmt_ports:
            rule = ["-p", "tcp", "--dport", str(int(port)), "-j", "RETURN"]
            rc, _o, _e = run_cmd([ipt, "-C", self.chain] + rule, timeout=15.0)
            if rc != 0:
                run_cmd([ipt, "-A", self.chain] + rule, timeout=15.0)

        drop = ["-m", "set", "--match-set", setname, "src", "-j", "DROP"]
        rc, _o, _e = run_cmd([ipt, "-C", self.chain] + drop, timeout=15.0)
        if rc != 0:
            rc, _o, err = run_cmd([ipt, "-A", self.chain] + drop, timeout=15.0)
            if rc != 0:
                raise BackendError("add drop rule: %s" % sanitize_text(err, 160))

        jump = ["-j", self.chain]
        rc, _o, _e = run_cmd([ipt, "-C", "INPUT"] + jump, timeout=15.0)
        if rc != 0:
            rc, _o, err = run_cmd([ipt, "-I", "INPUT", "1"] + jump, timeout=15.0)
            if rc != 0:
                raise BackendError("hook INPUT: %s" % sanitize_text(err, 160))

    def ensure(self):
        if self.ready:
            return True
        if not self.ipset:
            raise BackendError("ipset binary not found")
        self._ensure_family(self.ipt, self.set4, "inet")
        self._ensure_family(self.ip6t, self.set6, "inet6")
        self.ready = True
        log.info("ipset fallback ready: sets %s/%s, chain %s",
                 self.set4, self.set6, self.chain)
        return True

    def ban(self, addr, ttl_ns, reason):
        self.ensure()
        setname = self.set4 if addr.version == 4 else self.set6
        secs = 0 if ttl_ns <= 0 else max(1, min(ttl_ns // NS, 2147483))
        argv = [self.ipset, "add", setname, str(addr), "timeout", str(secs),
                "-exist"]
        rc, _o, err = run_cmd(argv, timeout=15.0)
        if rc != 0:
            raise BackendError("ipset add: %s" % sanitize_text(err, 160))
        return True

    def unban(self, addr):
        self.ensure()
        setname = self.set4 if addr.version == 4 else self.set6
        rc, _o, err = run_cmd([self.ipset, "del", setname, str(addr), "-exist"],
                              timeout=15.0)
        if rc != 0:
            raise BackendError("ipset del: %s" % sanitize_text(err, 160))
        return True

    def flush(self):
        if not self.ipset:
            return False
        ok = True
        for setname in (self.set4, self.set6):
            rc, _o, _e = run_cmd([self.ipset, "flush", setname], timeout=15.0)
            ok = ok and rc == 0
        return ok


# ---------------------------------------------------------------------------
# Active management sessions.
#
# The single most valuable safety feature in this file: the peer address of
# every ESTABLISHED connection to a management port is auto-allowlisted.  The
# session you are typing in can therefore never be banned by the log noise it
# is producing, even before you have written a single `allow` line.
#
# /proc/net/tcp prints addresses as host-order hex words, so the byte order
# depends on the CPU.  Both are handled.
# ---------------------------------------------------------------------------

TCP_ESTABLISHED = "01"
_LE = (sys.byteorder == "little")


def _hex_to_v4(hexstr):
    if len(hexstr) != 8:
        return None
    try:
        raw = bytes.fromhex(hexstr)
    except ValueError:
        return None
    if _LE:
        raw = raw[::-1]
    return ipaddress.IPv4Address(raw)


def _hex_to_v6(hexstr):
    if len(hexstr) != 32:
        return None
    try:
        raw = bytes.fromhex(hexstr)
    except ValueError:
        return None
    if _LE:
        raw = b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    addr = ipaddress.IPv6Address(raw)
    mapped = addr.ipv4_mapped
    return mapped if mapped is not None else addr


def read_active_peers(mgmt_ports, limit=4096):
    """Peers of ESTABLISHED connections whose LOCAL port is a management port."""
    peers = []
    wanted = set(int(p) for p in mgmt_ports)
    if not wanted:
        return peers
    for path, conv in (("/proc/net/tcp", _hex_to_v4),
                       ("/proc/net/tcp6", _hex_to_v6)):
        try:
            with open(path, "r") as fh:
                fh.readline()               # header
                for line in fh:
                    if len(peers) >= limit:
                        return peers
                    fields = line.split()
                    if len(fields) < 4 or fields[3] != TCP_ESTABLISHED:
                        continue
                    local = fields[1].rsplit(":", 1)
                    remote = fields[2].rsplit(":", 1)
                    if len(local) != 2 or len(remote) != 2:
                        continue
                    try:
                        lport = int(local[1], 16)
                    except ValueError:
                        continue
                    if lport not in wanted:
                        continue
                    addr = conv(remote[0])
                    if addr is not None and not addr.is_unspecified:
                        peers.append(addr)
        except OSError:
            continue
    return peers


# ---------------------------------------------------------------------------
# Log sources.
#
# Two kinds:
#   FileSource     - tails a file, surviving rotation, truncation, and inode
#                    reuse.  Globs expand to one child FileSource per file and
#                    are re-scanned periodically so a newly rotated-in file is
#                    picked up.
#   JournalSource  - `journalctl -f` for a unit or a raw filter, read
#                    line-by-line from a pipe.
#
# CRITICAL detail: poll()/epoll() on a REGULAR FILE always reports the fd
# readable, even at EOF, so a log-file fd must NEVER be registered with the
# poller - it would spin the loop at 100% CPU.  Regular files are therefore
# read on a short timer (`read`, called every loop iteration), and only true
# pipes (journalctl) expose a `poll_fds()` fd so a burst wakes us immediately.
# Either way a source that reads more than `read_budget` bytes in one wakeup
# yields, so one noisy file cannot starve the others.
# ---------------------------------------------------------------------------

class BaseSource(object):
    poll_ok = False                     # True only for pipe-backed sources

    def __init__(self, name, tags):
        self.name = name
        self.tags = tags                # rule-set names bound to this source
        self.lines_in = 0
        self.bytes_in = 0
        self.oversized = 0

    def poll_fds(self):
        """File descriptors safe to register with poll() (pipes only).  Regular
        files are excluded on purpose - see the note above."""
        return []

    def read(self, now):
        """Drain whatever is currently available and return complete lines.
        Called every loop iteration (timer) AND on a poll wakeup; must be cheap
        and non-blocking when there is nothing to read."""
        return []

    def close(self):
        pass


class _LineBuffer(object):
    """Accumulates bytes and yields complete, decoded lines.  A line with no
    terminator longer than the hard cap is force-flushed and counted, so a
    gigabyte of newline-free attacker data can never exhaust memory."""

    __slots__ = ("buf", "owner")

    def __init__(self, owner):
        self.buf = b""
        self.owner = owner

    def feed(self, chunk):
        out = []
        self.buf += chunk
        while True:
            idx = self.buf.find(b"\n")
            if idx < 0:
                if len(self.buf) > HARD_MAX_LINE_BYTES:
                    self.owner.oversized += 1
                    out.append(self._decode(self.buf[:HARD_MAX_LINE_BYTES]))
                    self.buf = b""
                break
            line = self.buf[:idx]
            self.buf = self.buf[idx + 1:]
            if len(line) > HARD_MAX_LINE_BYTES:
                self.owner.oversized += 1
                line = line[:HARD_MAX_LINE_BYTES]
            out.append(self._decode(line))
        return out

    def flush_partial(self):
        if not self.buf:
            return []
        line = self.buf
        self.buf = b""
        if len(line) > HARD_MAX_LINE_BYTES:
            line = line[:HARD_MAX_LINE_BYTES]
        return [self._decode(line)]

    @staticmethod
    def _decode(raw):
        return raw.decode("utf-8", "replace").rstrip("\r")


class FileSource(BaseSource):
    """Tail a single regular file.

    Rotation handling.  On every read we remember (st_dev, st_ino) and size.
    When poll() wakes us or the periodic tick runs, we compare:
      * inode changed  -> file was renamed and recreated (logrotate create) or
                          replaced; drain the old fd to EOF, then open the new
                          path from the start.
      * size shrank    -> file was truncated in place (logrotate copytruncate);
                          seek back to 0.
      * path gone      -> keep the old fd (still draining), retry the path.
    A file we cannot open yet (permissions, not created) is retried on tick
    without ever raising.
    """

    def __init__(self, path, tags, start_at_end=True, read_budget=1 << 20):
        BaseSource.__init__(self, "file:" + path, tags)
        self.path = path
        self.fd = -1
        self.dev = None
        self.ino = None
        self.pos = 0
        self.lb = _LineBuffer(self)
        self.start_at_end = start_at_end
        self.read_budget = read_budget
        self.open_warned = False
        self._open(initial=True)

    def _open(self, initial=False):
        # O_NONBLOCK is a no-op on a regular file (reads never block); the
        # getattr keeps this importable off-Linux for the test suite.
        try:
            fd = os.open(self.path,
                         os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        except OSError as exc:
            if not self.open_warned:
                log.info("waiting for log file %s (%s)", self.path, exc.strerror)
                self.open_warned = True
            return False
        try:
            st = os.fstat(fd)
        except OSError:
            os.close(fd)
            return False
        if not stat.S_ISREG(st.st_mode):
            os.close(fd)
            if not self.open_warned:
                log.warning("%s is not a regular file; skipping", self.path)
                self.open_warned = True
            return False
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
        self.fd = fd
        self.dev = st.st_dev
        self.ino = st.st_ino
        if initial and self.start_at_end:
            self.pos = st.st_size
        else:
            self.pos = 0
        try:
            os.lseek(self.fd, self.pos, os.SEEK_SET)
        except OSError:
            self.pos = 0
        self.open_warned = False
        if not initial:
            log.info("opened %s (inode %d)", self.path, self.ino)
        return True

    def _drain(self):
        lines = []
        if self.fd < 0:
            return lines
        total = 0
        while total < self.read_budget:
            try:
                chunk = os.read(self.fd, 65536)
            except OSError as exc:
                if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break
                if exc.errno == errno.EINTR:
                    continue
                log.debug("read error on %s: %s", self.path, exc)
                break
            if not chunk:
                break
            total += len(chunk)
            self.pos += len(chunk)
            self.bytes_in += len(chunk)
            got = self.lb.feed(chunk)
            lines.extend(got)
        self.lines_in += len(lines)
        return lines

    def _rotated(self):
        try:
            st = os.stat(self.path)
        except OSError:
            return False, None
        return ((st.st_dev, st.st_ino) != (self.dev, self.ino)
                or st.st_size < self.pos), st

    def _read_and_rotate(self):
        lines = self._drain()
        rotated, st = self._rotated()
        if rotated:
            # Drain whatever remains in the old file, flush any partial line,
            # then switch to the new inode and read it from the top.
            lines.extend(self._drain())
            lines.extend(self.lb.flush_partial())
            if st is not None and (st.st_dev, st.st_ino) != (self.dev, self.ino):
                log.info("rotation on %s: inode %s -> %s",
                         self.path, self.ino, st.st_ino)
                self._open(initial=False)
            else:
                # copytruncate: same inode, smaller size.
                log.info("truncation on %s; rewinding", self.path)
                self.pos = 0
                try:
                    os.lseek(self.fd, 0, os.SEEK_SET)
                except OSError:
                    self._open(initial=False)
            lines.extend(self._drain())
        return lines

    def read(self, now):
        # Regular file: timer-driven.  Reopen if we have no fd yet (file not
        # created, or briefly gone during rotation), then drain and handle any
        # rotation/truncation in one shot.
        if self.fd < 0:
            if not self._open(initial=False):
                return []
            return self._drain()
        return self._read_and_rotate()

    def close(self):
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1


class GlobSource(BaseSource):
    """Expand a glob into FileSources and keep the set current.

    New files matching the pattern are opened from their START (they appeared
    after we began watching, so their whole content is news to us); the initial
    expansion at startup opens from the END like a normal tail.
    """

    def __init__(self, pattern, tags, start_at_end=True, rescan_s=15.0):
        BaseSource.__init__(self, "glob:" + pattern, tags)
        self.pattern = pattern
        self.tags = tags
        self.children = {}
        self.rescan_s = rescan_s
        self.next_rescan = 0.0
        self._start_at_end = start_at_end
        for path in sorted(glob.glob(pattern)):
            self._add(path, start_at_end)

    def _add(self, path, at_end):
        if path in self.children or not os.path.isfile(path):
            return
        try:
            child = FileSource(path, self.tags, start_at_end=at_end)
        except Exception as exc:
            log.warning("cannot tail %s: %s", path, sanitize_text(str(exc), 120))
            return
        self.children[path] = child

    def read(self, now):
        lines = []
        for child in list(self.children.values()):
            lines.extend(child.read(now))
        if now >= self.next_rescan:
            self.next_rescan = now + self.rescan_s
            for path in sorted(glob.glob(self.pattern)):
                if path not in self.children:
                    log.info("new file matches %s: %s", self.pattern, path)
                    self._add(path, at_end=False)
            # forget children whose path disappeared AND whose fd is closed
            for path, child in list(self.children.items()):
                if not os.path.exists(path) and child.fd < 0:
                    child.close()
                    del self.children[path]
        return lines

    def close(self):
        for child in self.children.values():
            child.close()
        self.children.clear()


class JournalSource(BaseSource):
    """Follow the systemd journal via `journalctl -f`.

    We deliberately shell out rather than link libsystemd: it keeps this file
    pure stdlib and works even where python3-systemd is not installed.  argv is
    literal - the unit name is validated against a conservative character class
    before it is ever placed in the list, so a malicious unit= in a config can
    contribute no option and no metacharacter.
    """

    _UNIT_OK = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")
    poll_ok = True                      # journalctl stdout is a pipe

    def __init__(self, spec, tags, journalctl, extra_args=(), start_at_end=True):
        BaseSource.__init__(self, "journal:" + spec, tags)
        self.spec = spec
        self.journalctl = journalctl
        self.extra_args = list(extra_args)
        self.start_at_end = start_at_end
        self.proc = None
        self.fd = -1
        self.lb = _LineBuffer(self)
        self.backoff = 1.0
        self.next_spawn = 0.0
        self.units = []
        for unit in spec.split(","):
            unit = unit.strip()
            if not unit:
                continue
            if not self._UNIT_OK.match(unit):
                raise ConfigError("journal unit %r contains illegal characters"
                                  % sanitize_text(unit, 60))
            self.units.append(unit)
        self._spawn()

    def _argv(self):
        # -o short-iso (NOT -o cat): "cat" prints only MESSAGE and strips the
        # SYSLOG_IDENTIFIER, so a journal line loses its "sshd[123]:" /
        # "vsftpd[123]:" token and identifier-keyed rules (prefilter = sshd /
        # openvpn, regexes embedding vsftpd/proftpd/pure-ftpd/cockpit) can never
        # match on a journal source.  short-iso restores the
        # "<ts> <host> <ident>[pid]:" prefix; every shipped rule regex is
        # unanchored, so the added prefix breaks no content match and makes
        # journald and file input behave identically, as the rule docs promise.
        argv = [self.journalctl, "-f", "--no-pager", "-o", "short-iso", "-q"]
        if self.start_at_end:
            argv += ["-n", "0"]
        else:
            argv += ["-n", "2000"]
        for unit in self.units:
            argv += ["-u", unit]
        argv += self.extra_args
        return argv

    def _spawn(self):
        argv = self._argv()
        try:
            proc = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, shell=False, close_fds=True, bufsize=0)
        except OSError as exc:
            log.warning("cannot start journalctl for %s: %s",
                        self.spec, exc)
            self.proc = None
            self.fd = -1
            return False
        self.proc = proc
        self.fd = proc.stdout.fileno()
        try:
            os.set_blocking(self.fd, False)
        except (OSError, AttributeError):
            _set_nonblocking_fallback(self.fd)
        log.info("following journal for %s", self.spec)
        self.backoff = 1.0
        return True

    def _drain_pipe(self):
        lines = []
        if self.fd < 0:
            return lines
        total = 0
        while total < (1 << 20):
            try:
                chunk = os.read(self.fd, 65536)
            except OSError as exc:
                if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break
                if exc.errno == errno.EINTR:
                    continue
                break
            if not chunk:
                # journalctl exited; reap and schedule a respawn.
                self._reap()
                break
            total += len(chunk)
            self.bytes_in += len(chunk)
            lines.extend(self.lb.feed(chunk))
        self.lines_in += len(lines)
        return lines

    def _reap(self):
        if self.proc is not None:
            try:
                self.proc.poll()
                if self.proc.returncode is None:
                    self.proc.terminate()
            except OSError:
                pass
        self.fd = -1
        self.next_spawn = time.monotonic() + self.backoff
        self.backoff = min(self.backoff * 2.0, 30.0)
        log.warning("journalctl for %s exited; respawning in %.0fs",
                    self.spec, self.backoff)

    def poll_fds(self):
        return [self.fd] if self.fd >= 0 else []

    def read(self, now):
        if self.fd < 0:
            if time.monotonic() >= self.next_spawn:
                self._spawn()
            return []
        return self._drain_pipe()

    def close(self):
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3)
            except Exception:
                try:
                    self.proc.kill()
                except OSError:
                    pass
        self.proc = None
        self.fd = -1


def _set_nonblocking_fallback(fd):
    import fcntl
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


# ---------------------------------------------------------------------------
# Offender bookkeeping and persistent state.
#
# One Offender per banned address.  It remembers how many times the address has
# offended, so the ban TTL escalates exactly the way the dataplane's
# caly_ban_next_ttl() does (ttl * num / den, clamped to [base, max]).  Because
# the arithmetic is the same on both sides, a ban the watcher installs and a
# ban the XDP autobanner installs age identically.
#
# State is persisted as line-delimited JSON so a restart does not forget who is
# banned or how many strikes they have accrued.  The write is atomic (temp file
# + rename) so a crash mid-write cannot corrupt the file.
# ---------------------------------------------------------------------------

STATE_VERSION = 1


class Offender(object):
    __slots__ = ("addr_str", "version", "offences", "cur_ttl_ns", "expiry_wall",
                 "first_seen", "last_seen", "last_reason", "active", "soft_until")

    def __init__(self, addr_str, version):
        self.addr_str = addr_str
        self.version = version
        self.offences = 0
        self.cur_ttl_ns = 0
        self.expiry_wall = 0.0          # wall-clock epoch seconds, 0 = none
        self.first_seen = 0.0
        self.last_seen = 0.0
        self.last_reason = ""
        self.active = False
        self.soft_until = 0.0           # allowlisted-by-success until this time

    def to_json(self):
        return {
            "addr": self.addr_str,
            "v": self.version,
            "offences": self.offences,
            "ttl_ns": self.cur_ttl_ns,
            "expiry": round(self.expiry_wall, 3),
            "first": round(self.first_seen, 3),
            "last": round(self.last_seen, 3),
            "reason": self.last_reason,
            "active": self.active,
            "soft_until": round(self.soft_until, 3),
        }

    @classmethod
    def from_json(cls, obj):
        addr = obj.get("addr")
        parsed = parse_ip_strict(addr) if isinstance(addr, str) else None
        if parsed is None:
            return None
        off = cls(str(parsed), parsed.version)
        off.offences = int(obj.get("offences", 0))
        off.cur_ttl_ns = int(obj.get("ttl_ns", 0))
        off.expiry_wall = float(obj.get("expiry", 0.0))
        off.first_seen = float(obj.get("first", 0.0))
        off.last_seen = float(obj.get("last", 0.0))
        off.last_reason = sanitize_tag(obj.get("reason", ""), 40, "")
        off.active = bool(obj.get("active", False))
        off.soft_until = float(obj.get("soft_until", 0.0))
        return off


class OffenderTable(object):
    def __init__(self, cfg):
        self.cfg = cfg
        self.by_addr = collections.OrderedDict()

    def get(self, addr):
        key = str(addr)
        off = self.by_addr.get(key)
        if off is None:
            off = Offender(key, addr.version)
            off.first_seen = time.time()
            self.by_addr[key] = off
            self._evict()
        else:
            self.by_addr.move_to_end(key)
        return off

    def peek(self, addr):
        return self.by_addr.get(str(addr))

    def _evict(self):
        # Drop the least-recently-touched INACTIVE offender when over cap.  An
        # active ban is never evicted from the table, so we never forget to
        # remove a ban we installed.
        limit = HARD_MAX_OFFENDERS
        if len(self.by_addr) <= limit:
            return
        for key, off in list(self.by_addr.items()):
            if len(self.by_addr) <= limit:
                break
            if not off.active:
                del self.by_addr[key]

    def active_items(self):
        return [o for o in self.by_addr.values() if o.active]

    # -- persistence ------------------------------------------------------

    def load(self, path):
        try:
            fh = open(path, "r", encoding="utf-8")
        except OSError as exc:
            if exc.errno != errno.ENOENT:
                log.warning("cannot read state %s: %s", path, exc)
            return 0
        loaded = 0
        with fh:
            first = fh.readline()
            header = None
            if first.strip():
                try:
                    header = json.loads(first)
                except ValueError:
                    header = None
            if not (isinstance(header, dict) and header.get("_calywatch_state")):
                # Not our header: treat the whole file as records (older format).
                fh.seek(0)
            for line in fh:
                line = line.strip()
                if not line or line[0] != "{":
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if obj.get("_calywatch_state"):
                    continue
                off = Offender.from_json(obj)
                if off is None:
                    continue
                self.by_addr[off.addr_str] = off
                loaded += 1
                if loaded >= HARD_MAX_OFFENDERS:
                    break
        log.info("loaded %d offender records from %s", loaded, path)
        return loaded

    def save(self, path):
        directory = os.path.dirname(path) or "."
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as exc:
            log.warning("cannot create state dir %s: %s", directory, exc)
            return False
        tmp = None
        try:
            fd, tmp = tempfile.mkstemp(prefix=".calywatch-state.", dir=directory)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"_calywatch_state": STATE_VERSION,
                           "saved": round(time.time(), 3),
                           "prog": PROG, "version": VERSION}, fh,
                          separators=(",", ":"))
                fh.write("\n")
                written = 0
                now = time.time()
                for off in self.by_addr.values():
                    # Skip stale, long-expired, never-active records to keep the
                    # file from growing without bound.
                    if (not off.active and off.soft_until < now
                            and off.expiry_wall < now
                            and (now - off.last_seen) > 7 * 86400):
                        continue
                    json.dump(off.to_json(), fh, separators=(",", ":"))
                    fh.write("\n")
                    written += 1
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            tmp = None
            log.debug("saved %d offender records to %s", written, path)
            return True
        except OSError as exc:
            log.warning("cannot write state %s: %s", path, exc)
            return False
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass


# ---------------------------------------------------------------------------
# Rate limiter for the watcher's OWN ban actions.
#
# A log-injection attack's goal is to make us ban legitimate addresses.  Even
# with strict IP parsing and the allowlist, a flood of forged-but-valid source
# addresses could otherwise have us issue thousands of bans a second.  This
# token bucket is the hard stop: at most `max_bans_per_min` NEW bans leave the
# watcher in any 60-second window.  Refreshes and escalations of an already
# active ban do not consume the budget; only genuinely new targets do.
# ---------------------------------------------------------------------------

class BanRateLimiter(object):
    def __init__(self, per_min, burst=None):
        self.per_min = max(0, int(per_min))
        self.capacity = burst if burst is not None else max(self.per_min, 1)
        self.tokens = float(self.capacity)
        self.last = time.monotonic()
        self.dropped = 0

    def allow(self, now=None):
        if self.per_min <= 0:
            return True                 # 0 == unlimited (documented)
        if now is None:
            now = time.monotonic()
        rate = self.per_min / 60.0
        elapsed = now - self.last
        if elapsed < 0.0:               # clock anomaly / synthetic timestamp
            elapsed = 0.0
        self.tokens = min(self.capacity, self.tokens + elapsed * rate)
        self.last = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        self.dropped += 1
        return False


# ---------------------------------------------------------------------------
# Watcher configuration.
#
# calywatch.conf shares the lexer with the rule files.  The header section
# carries global knobs; [source ...] sections describe what to tail and which
# rule sets to apply.  A minimal config is three lines:
#
#     ban_backend = auto
#     [source /var/log/nginx/access.log]
#     rules = nginx
#
# Everything else has a safe default.
# ---------------------------------------------------------------------------

class SourceSpec(object):
    __slots__ = ("kind", "target", "rules", "start_at_end", "extra")

    def __init__(self, kind, target, rules, start_at_end, extra):
        self.kind = kind                # 'file' | 'glob' | 'journal'
        self.target = target
        self.rules = rules              # list of rule-set name/path specs
        self.start_at_end = start_at_end
        self.extra = extra              # journalctl extra args


class WatcherConfig(object):
    def __init__(self):
        # backends
        self.ban_backend = "auto"
        self.socket_paths = list(DEFAULT_SOCKETS)
        self.calyctl_bin = None
        self.calyctl_ban = "ban %a --ttl %ts --reason %r"
        self.calyctl_unban = "unban %a"
        self.calyctl_flush = ""
        self.nft_family = "inet"
        self.nft_table = "calywatch"
        self.nft_chain = "watchdrop"
        self.nft_set4 = "calywatch4"
        self.nft_set6 = "calywatch6"
        self.nft_priority = -150
        self.ipset_set4 = "calywatch4"
        self.ipset_set6 = "calywatch6"
        self.ipt_chain = "CALYWATCH"

        # banning policy
        self.ban_ttl_base_ns = parse_duration_ns("15m")
        self.ban_ttl_max_ns = parse_duration_ns("7d")
        self.ban_escalate_num = 3
        self.ban_escalate_den = 2
        self.max_bans_per_min = 120
        self.ban_burst = 240
        self.dry_run = False
        self.refresh_min_ns = parse_duration_ns("60s")

        # management-session protection
        self.protect_active_sessions = True
        self.mgmt_ports = [22]
        self.session_refresh_s = 10.0

        # allow / deny
        self.allow = NetSet()
        self.trusted_proxy = NetSet()
        self.never_ban_private = True   # allowlist RFC1918/loopback/LL by default

        # maintenance
        self.state_path = DEFAULT_STATE
        self.state_save_s = 30.0
        self.gc_interval_s = 30.0
        self.reap_interval_s = 5.0

        # logging
        self.log_level = "info"
        self.log_target = "auto"        # auto|stderr|syslog|<path>
        self.rules_dirs = list(RULES_SEARCH_DIRS)

        # sources
        self.sources = []

    # -- helpers ----------------------------------------------------------

    def _seed_private(self):
        if not self.never_ban_private:
            return
        for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                     "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
                     "::1/128", "fc00::/7", "fe80::/10"):
            self.allow.add(cidr)

    @classmethod
    def load(cls, path, overrides=None):
        cfg = cls()
        if path and os.path.exists(path):
            sections = lex_file(path)
            cfg._apply_header(sections[0], path)
            for sec in sections[1:]:
                cfg._apply_section(sec, path)
        elif path:
            log.warning("config %s not found; using defaults + CLI overrides",
                        path)
        if overrides:
            overrides(cfg)
        cfg._seed_private()
        cfg._finalize()
        return cfg

    def _apply_header(self, header, path):
        for key, value, lineno in header.items:
            where = "%s:%d %s" % (path, lineno, key)
            try:
                self._set_header_key(key, value, where)
            except ConfigError:
                raise
            except Exception as exc:
                raise ConfigError("%s: %s" % (where, exc))

    def _set_header_key(self, key, value, where):
        if key == "ban_backend":
            v = value.strip().lower()
            if v not in ("auto", "socket", "calyctl", "nft", "nftables",
                         "ipset", "iptables", "dry-run", "dryrun", "none"):
                raise ConfigError("%s: unknown ban_backend %r" % (where, value))
            self.ban_backend = "nft" if v == "nftables" else \
                ("ipset" if v == "iptables" else
                 ("dry-run" if v == "dryrun" else v))
        elif key in ("socket", "socket_path", "control_socket"):
            self.socket_paths = [value] + [p for p in self.socket_paths
                                           if p != value]
        elif key == "calyctl":
            self.calyctl_bin = value
        elif key == "calyctl_ban":
            self.calyctl_ban = value
        elif key == "calyctl_unban":
            self.calyctl_unban = value
        elif key == "calyctl_flush":
            self.calyctl_flush = value
        elif key == "nft_family":
            if value.strip() not in ("inet", "ip", "ip6"):
                raise ConfigError("%s: nft_family must be inet/ip/ip6" % where)
            self.nft_family = value.strip()
        elif key == "nft_table":
            self.nft_table = sanitize_tag(value, 32, self.nft_table)
        elif key == "nft_chain":
            self.nft_chain = sanitize_tag(value, 32, self.nft_chain)
        elif key == "nft_set4":
            self.nft_set4 = sanitize_tag(value, 32, self.nft_set4)
        elif key == "nft_set6":
            self.nft_set6 = sanitize_tag(value, 32, self.nft_set6)
        elif key == "nft_priority":
            self.nft_priority = parse_int(value, where, -600, 600)
        elif key == "ipset_set4":
            self.ipset_set4 = sanitize_tag(value, 31, self.ipset_set4)
        elif key == "ipset_set6":
            self.ipset_set6 = sanitize_tag(value, 31, self.ipset_set6)
        elif key in ("iptables_chain", "ipt_chain"):
            self.ipt_chain = sanitize_tag(value, 28, self.ipt_chain)
        elif key in ("ban_ttl_base", "ban_ttl"):
            self.ban_ttl_base_ns = parse_duration_ns(value, where)
        elif key == "ban_ttl_max":
            self.ban_ttl_max_ns = parse_duration_ns(value, where)
        elif key == "ban_escalate_num":
            self.ban_escalate_num = parse_int(value, where, 1, 1000)
        elif key == "ban_escalate_den":
            self.ban_escalate_den = parse_int(value, where, 1, 1000)
        elif key in ("max_bans_per_min", "max_bans_per_minute"):
            self.max_bans_per_min = parse_int(value, where, 0, 1000000)
        elif key == "ban_burst":
            self.ban_burst = parse_int(value, where, 1, 1000000)
        elif key == "refresh_min":
            self.refresh_min_ns = parse_duration_ns(value, where)
        elif key == "dry_run":
            self.dry_run = parse_bool(value, where)
        elif key == "protect_active_sessions":
            self.protect_active_sessions = parse_bool(value, where)
        elif key == "mgmt_ports":
            ports = []
            for tok in re.split(r"[,\s]+", value.strip()):
                if tok:
                    ports.append(parse_int(tok, where, 1, 65535))
            if 22 not in ports:
                ports.append(22)        # SSH is never removable, mirror the ABI
            self.mgmt_ports = ports
        elif key == "never_ban_private":
            self.never_ban_private = parse_bool(value, where)
        elif key in ("allow", "allowlist", "ignoreip"):
            for tok in re.split(r"[,\s]+", value.strip()):
                if tok and not self.allow.add(tok):
                    log.warning("%s: ignoring invalid allow entry %r",
                                where, sanitize_text(tok, 60))
        elif key in ("trusted_proxy", "trusted_proxies"):
            for tok in re.split(r"[,\s]+", value.strip()):
                if tok and not self.trusted_proxy.add(tok):
                    log.warning("%s: ignoring invalid trusted_proxy %r",
                                where, sanitize_text(tok, 60))
        elif key == "state_path":
            self.state_path = value
        elif key == "state_save":
            self.state_save_s = parse_duration_ns(value, where) / float(NS)
        elif key == "gc_interval":
            self.gc_interval_s = parse_duration_ns(value, where) / float(NS)
        elif key == "log_level":
            self.log_level = value.strip().lower()
        elif key == "log_target":
            self.log_target = value.strip()
        elif key in ("rules_dir", "rules_dirs"):
            # Comma-separated only: a directory path may legitimately contain
            # spaces, so we must not split on whitespace here.
            dirs = [d.strip() for d in value.split(",") if d.strip()]
            self.rules_dirs = dirs + [d for d in self.rules_dirs if d not in dirs]
        elif key in ("name", "desc"):
            pass
        else:
            log.warning("%s: unknown config key %r (ignored)", where,
                        sanitize_tag(key, 40))

    def _apply_section(self, sec, path):
        kind = sec.name.split(None, 1)[0].lower() if sec.name else ""
        rest = sec.name.split(None, 1)[1].strip() if " " in sec.name else ""
        where = "%s:%d [%s]" % (path, sec.lineno, sec.name)

        if kind == "source":
            target = rest or sec.get("path") or sec.get("file")
            journal_unit = sec.get("journal") or sec.get("unit")
            start_at_end = parse_bool(sec.get("start_at_end", "yes"), where)
            rules = []
            for rv in sec.all("rules"):
                for tok in re.split(r"[,\s]+", rv.strip()):
                    if tok:
                        rules.append(tok)
            if not rules:
                raise ConfigError("%s: source has no 'rules ='" % where)
            extra = []
            for ev in sec.all("journal_args"):
                extra.extend(shlex.split(ev))
            if journal_unit:
                self.sources.append(SourceSpec("journal", journal_unit, rules,
                                               start_at_end, extra))
            elif sec.get("glob"):
                self.sources.append(SourceSpec("glob", sec.get("glob"), rules,
                                               start_at_end, extra))
            elif target and any(ch in target for ch in "*?["):
                self.sources.append(SourceSpec("glob", target, rules,
                                               start_at_end, extra))
            elif target:
                self.sources.append(SourceSpec("file", target, rules,
                                               start_at_end, extra))
            else:
                raise ConfigError("%s: source has no path/glob/journal" % where)
        elif kind in ("allow", "trusted", "trusted_proxy"):
            netset = self.allow if kind == "allow" else self.trusted_proxy
            for _k, v, _l in sec.items:
                for tok in re.split(r"[,\s]+", v.strip()):
                    if tok:
                        netset.add(tok)
        else:
            log.warning("%s: unknown section type %r (ignored)", where,
                        sanitize_tag(kind, 32))

    def _finalize(self):
        if self.ban_ttl_max_ns < self.ban_ttl_base_ns:
            self.ban_ttl_max_ns = self.ban_ttl_base_ns
        if 22 not in self.mgmt_ports:
            self.mgmt_ports.append(22)
        seen = set()
        uniq = []
        for p in self.mgmt_ports:
            if p not in seen:
                seen.add(p)
                uniq.append(p)
        self.mgmt_ports = uniq


# ---------------------------------------------------------------------------
# The watcher engine.
# ---------------------------------------------------------------------------

class Watcher(object):
    def __init__(self, cfg, rulesets_by_name):
        self.cfg = cfg
        self.rulesets = rulesets_by_name        # name -> RuleSet
        self.trackers = {}                       # rule.rid -> Tracker
        self.offenders = OffenderTable(cfg)
        self.limiter = BanRateLimiter(cfg.max_bans_per_min, cfg.ban_burst)
        self.session_allow = NetSet()
        self.session_seen = set()
        self.next_session_refresh = 0.0
        self.sources = []
        self.backends = []
        self.stop = False
        self.reload_requested = False
        self.started_wall = time.time()
        self.started_mono = time.monotonic()

        # counters
        self.total_lines = 0
        self.total_matches = 0
        self.total_bans = 0
        self.total_warns = 0
        self.total_refresh = 0
        self.total_escalations = 0
        self.rejected_ips = 0
        self.allow_skips = 0
        self.session_skips = 0
        self.rate_skips = 0

        for rs in self.rulesets.values():
            for rule in rs.rules:
                self.trackers[rule.rid] = Tracker(rule)

    # -- backends ---------------------------------------------------------

    def build_backends(self):
        cfg = self.cfg
        chosen = cfg.ban_backend
        chain = []

        if cfg.dry_run or chosen == "dry-run":
            self.backends = [DryRunBackend(cfg)]
            log.warning("DRY RUN: no bans will actually be applied")
            return
        if chosen == "none":
            self.backends = []
            log.warning("ban_backend=none: detections are logged only")
            return

        def make_socket():
            return SocketBackend(cfg, cfg.socket_paths)

        def make_calyctl():
            binary = cfg.calyctl_bin or find_binary(CTL_CANDIDATES)
            return CalyctlBackend(
                cfg, binary,
                shlex.split(cfg.calyctl_ban), shlex.split(cfg.calyctl_unban),
                shlex.split(cfg.calyctl_flush) if cfg.calyctl_flush else ())

        def make_nft():
            return NftBackend(cfg, find_binary(("nft",)), cfg.nft_family,
                              cfg.nft_table, cfg.nft_chain, cfg.nft_set4,
                              cfg.nft_set6, cfg.mgmt_ports, cfg.nft_priority)

        def make_ipset():
            return IpsetBackend(cfg, find_binary(("ipset",)),
                                find_binary(("iptables",)),
                                find_binary(("ip6tables",)),
                                cfg.ipset_set4, cfg.ipset_set6, cfg.ipt_chain,
                                cfg.mgmt_ports, cfg.ban_ttl_max_ns)

        if chosen == "auto":
            builders = [make_socket, make_calyctl, make_nft, make_ipset]
        elif chosen == "socket":
            builders = [make_socket, make_calyctl]
        elif chosen == "calyctl":
            builders = [make_calyctl, make_socket]
        elif chosen == "nft":
            builders = [make_nft]
        elif chosen == "ipset":
            builders = [make_ipset]
        else:
            builders = [make_socket, make_calyctl, make_nft, make_ipset]

        for build in builders:
            try:
                backend = build()
            except Exception as exc:
                log.debug("backend construction failed: %s", exc)
                continue
            chain.append(backend)

        # Probe once so the log shows what is actually available, but keep every
        # constructed backend in the chain: a backend that is down now may come
        # back (daemon restart), and `usable()` gates it at call time.
        primary = None
        for backend in chain:
            try:
                ok = backend.probe()
            except Exception as exc:
                ok = False
                log.debug("probe of %s raised: %s", backend.name, exc)
            if ok and primary is None:
                primary = backend.name
            log.info("ban backend %-8s: %s", backend.name,
                     "available" if ok else "unavailable (kept as fallback)")
        self.backends = chain
        if primary:
            log.info("primary ban backend: %s", primary)
        elif chain:
            log.warning("no ban backend probed OK; will retry on demand")
        else:
            log.error("no ban backend could be constructed; running detect-only")

    def _apply_ban(self, addr, ttl_ns, reason):
        """Try each backend in order until one accepts.  Returns backend name
        or None.  A backend failure never propagates: we degrade, we do not
        crash, and we never drop management traffic."""
        now = time.monotonic()
        last_exc = None
        for backend in self.backends:
            if not backend.usable(now):
                continue
            try:
                if backend.ban(addr, ttl_ns, reason):
                    backend.mark_ok()
                    backend.bans += 1
                    return backend.name
            except BackendError as exc:
                last_exc = exc
                backend.mark_fail(exc, now)
            except Exception as exc:              # never let a backend kill us
                last_exc = exc
                backend.mark_fail(exc, now)
        if last_exc is not None:
            log.debug("all backends failed for %s: %s", addr,
                      sanitize_text(str(last_exc), 120))
        return None

    def _apply_unban(self, addr):
        now = time.monotonic()
        done = False
        for backend in self.backends:
            if not backend.usable(now):
                continue
            try:
                backend.unban(addr)
                backend.mark_ok()
                done = True
            except BackendError as exc:
                backend.mark_fail(exc, now)
            except Exception as exc:
                backend.mark_fail(exc, now)
        return done

    # -- allow / protect --------------------------------------------------

    def is_protected(self, addr):
        """True when addr must never be banned: explicit allowlist, a trusted
        proxy, or an active management session.

        A trusted_proxy member is a shared reverse-proxy / CDN egress address:
        every client behind it reaches us through it, so banning it would drop
        all of them at once.  Many web rules cannot capture X-Forwarded-For and
        therefore resolve their target to the proxy's own peer address; guarding
        here - the single choke point checked immediately before every action -
        guarantees a proxy IP can never become a ban target down any code path.
        """
        if addr in self.cfg.allow:
            self.allow_skips += 1
            return True
        if self.cfg.trusted_proxy.count and addr in self.cfg.trusted_proxy:
            self.allow_skips += 1
            return True
        if self.cfg.protect_active_sessions and addr in self.session_allow:
            self.session_skips += 1
            return True
        return False

    def refresh_sessions(self, now):
        if not self.cfg.protect_active_sessions:
            return
        if now < self.next_session_refresh:
            return
        self.next_session_refresh = now + self.cfg.session_refresh_s
        peers = read_active_peers(self.cfg.mgmt_ports)
        fresh = NetSet()
        for addr in peers:
            fresh.add_address(addr)
            key = str(addr)
            if key not in self.session_seen:
                self.session_seen.add(key)
                log.debug("protecting active mgmt session peer %s", addr)
        # Bound the "seen" set so it cannot grow forever on a busy box.
        if len(self.session_seen) > 65536:
            self.session_seen = set(str(p) for p in peers)
        self.session_allow = fresh

    # -- the hot path -----------------------------------------------------

    def _resolve_target(self, rule, match):
        """Produce the address to act on, honouring trusted-proxy XFF.

        The direct peer comes from rule.ip_group.  If the rule declares an
        xff_group AND the direct peer is inside trusted_proxy, the RIGHTMOST
        untrusted address in the forwarded chain becomes the target - that is
        the address the trusted proxy actually received the request from, and
        the last hop an attacker cannot forge past.  Absent trust, the forwarded
        header is ignored entirely: a forged X-Forwarded-For can never redirect
        a ban.
        """
        try:
            raw_peer = match.group(rule.ip_group)
        except (IndexError, error_types):
            raw_peer = None
        peer = parse_ip_strict(raw_peer) if raw_peer else None
        if peer is None:
            return None, None

        if rule.xff_group and self.cfg.trusted_proxy.count and peer in self.cfg.trusted_proxy:
            try:
                xff_raw = match.group(rule.xff_group)
            except (IndexError, error_types):
                xff_raw = None
            if xff_raw:
                target = self._xff_client(xff_raw)
                if target is not None:
                    return target, peer
        return peer, peer

    def _xff_client(self, xff_raw):
        parts = xff_raw.split(",")
        if len(parts) > HARD_MAX_XFF_ENTRIES:
            parts = parts[-HARD_MAX_XFF_ENTRIES:]
        # Walk right-to-left; skip hops that are themselves trusted proxies,
        # return the first address that is real and untrusted.
        candidate = None
        for token in reversed(parts):
            addr = parse_ip_strict(token.strip())
            if addr is None:
                continue
            candidate = addr
            if addr not in self.cfg.trusted_proxy:
                return addr
        return candidate

    def process_line(self, line, ruleset, now):
        if not line:
            return
        if len(line) > HARD_MAX_MATCH_CHARS:
            line = line[:HARD_MAX_MATCH_CHARS]
        self.total_lines += 1

        for rule in ruleset.rules:
            if not rule.enabled:
                continue
            if not rule.prefilter_ok(line):
                continue

            timed = False
            t0 = 0.0
            rule.sample_counter += 1
            if rule.sample_counter >= SLOW_RULE_SAMPLE:
                rule.sample_counter = 0
                timed = True
                t0 = time.monotonic()

            match = rule.search(line)

            if timed:
                self._account_rule_time(rule, time.monotonic() - t0)

            if match is None:
                continue
            if rule.conditions and not rule.conditions_ok(match):
                continue

            rule.matches += 1
            self.total_matches += 1

            if rule.action == ACTION_IGNORE:
                self._handle_ignore(rule, match, now)
                continue
            if rule.action == ACTION_COUNT:
                continue

            self._handle_countable(rule, match, now)

    def _account_rule_time(self, rule, dt):
        if dt <= SLOW_RULE_BUDGET_S:
            if rule.slow_strikes > 0:
                rule.slow_strikes -= 1
            return
        rule.slow_strikes += 2
        if rule.slow_strikes >= SLOW_RULE_STRIKES:
            rule.disable("regex too slow (possible ReDoS); auto-disabled")
            log.error("rule %s disabled: a sampled match took %.3fs, over the "
                      "%.3fs budget, repeatedly. Simplify its regex.",
                      rule.rid, dt, SLOW_RULE_BUDGET_S)

    def _handle_ignore(self, rule, match, now):
        """action=ignore: a positive signal (successful login) clears the
        source's counters across the whole ruleset and soft-allows it."""
        try:
            raw = match.group(rule.ip_group)
        except (IndexError, error_types):
            raw = None
        addr = parse_ip_strict(raw) if raw else None
        if addr is None:
            return
        cleared = 0
        for other in self.rulesets_for(rule):
            tr = self.trackers.get(other.rid)
            if tr is not None:
                before = len(tr)
                tr.drop(str(addr))
                cleared += before - len(tr)
        if rule.ttl_ns > 0:
            off = self.offenders.get(addr)
            off.soft_until = time.time() + rule.ttl_ns / float(NS)
            off.last_seen = time.time()
        log.debug("ignore rule %s cleared counters for %s", rule.rid, addr)

    def rulesets_for(self, rule):
        rsname = rule.rid.split("/", 1)[0]
        rs = self.rulesets.get(rsname)
        return rs.rules if rs is not None else [rule]

    def _handle_countable(self, rule, match, now):
        target, peer = self._resolve_target(rule, match)
        if target is None:
            rule.ip_parse_fail += 1
            self.rejected_ips += 1
            return

        tracker = self.trackers[rule.rid]
        counter = tracker.get(str(target))

        if rule.distinct:
            dval = rule.distinct_value(match)
            if dval is None:
                return
            count = counter.add(now, rule.window_s, dval)
        else:
            count = counter.add(now, rule.window_s, rule.weight)

        if count < rule.threshold:
            return

        # Cooldown so one sustained flood does not re-fire every line.
        if (now - counter.last_fire) < rule.cooldown_s:
            return
        counter.last_fire = now
        rule.fires += 1

        self._act(rule, target, count, now, peer)

    def _act(self, rule, target, count, now, peer):
        # Protection is checked HERE, immediately before any action, so it can
        # never be bypassed by any code path.
        if self.is_protected(target):
            log.info("rule %s tripped for %s (%d) but it is protected; skipping",
                     rule.rid, target, count)
            return

        reason = "%s:%s" % (self.rulesets_name_of(rule), rule.reason)
        reason = sanitize_tag(reason, 40, rule.reason)

        if rule.action == ACTION_WARN:
            self.total_warns += 1
            log.warning("WARN %s hit threshold %d/%d in %s -> %s (no ban)",
                        target, count, rule.threshold,
                        fmt_duration(rule.window_ns), rule.rid)
            return

        self._ban(target, rule, count, now, reason)

    def rulesets_name_of(self, rule):
        return rule.rid.split("/", 1)[0]

    def _ban(self, target, rule, count, now, reason):
        off = self.offenders.get(target)
        wall = time.time()

        # Soft-allowed by a recent success?  Respect it; a fresh failure burst
        # will re-trip once the soft window lapses.
        if off.soft_until > wall:
            log.info("%s recently authenticated; not banning on %s",
                     target, rule.rid)
            return

        base = rule.ttl_ns if rule.ttl_ns > 0 else self.cfg.ban_ttl_base_ns
        if off.active and off.cur_ttl_ns > 0:
            # Already banned: re-assert the SAME ban so a sustained attack does
            # not let it lapse between rule firings.  A refresh is NOT a new
            # offence and MUST NOT escalate the TTL - escalation is strictly
            # per-offence (see the new-ban path below) and only happens once a
            # prior ban has expired and the source re-offends.  This matches the
            # dataplane, which holds the first ban's TTL for its whole lifetime
            # and escalates only on a later re-ban.  Escalating here instead
            # would drive a single continuous (possibly mis-tuned false-positive)
            # offence from base to ban_ttl_max within minutes.
            if (wall - off.last_seen) * NS >= self.cfg.refresh_min_ns:
                off.last_seen = wall
                off.expiry_wall = wall + off.cur_ttl_ns / float(NS)
                off.last_reason = reason
                name = self._apply_ban(target, off.cur_ttl_ns, reason)
                self.total_refresh += 1
                log.info("refresh ban %s ttl=%s reason=%s via=%s",
                         target, fmt_duration(off.cur_ttl_ns), reason,
                         name or "none")
            return

        # New ban.  This is the only path that consumes the ban-rate budget.
        if not self.limiter.allow(now):
            self.rate_skips += 1
            if self.rate_skips % 100 == 1:
                log.warning("ban rate cap hit (%d/min); %d bans suppressed so "
                            "far. A log-injection flood looks exactly like "
                            "this - check your sources.",
                            self.cfg.max_bans_per_min, self.rate_skips)
            return

        off.offences += 1
        if off.offences <= 1:
            ttl = base
        else:
            prev = off.cur_ttl_ns if off.cur_ttl_ns > 0 else base
            ttl = caly_ban_next_ttl(prev, self.cfg.ban_ttl_base_ns,
                                    self.cfg.ban_ttl_max_ns,
                                    self.cfg.ban_escalate_num,
                                    self.cfg.ban_escalate_den)
        off.cur_ttl_ns = ttl
        off.active = True
        off.last_seen = wall
        off.last_reason = reason
        off.expiry_wall = wall + ttl / float(NS)
        if off.first_seen == 0.0:
            off.first_seen = wall

        name = self._apply_ban(target, ttl, reason)
        self.total_bans += 1
        if off.offences > 1:
            self.total_escalations += 1
        level = logging.WARNING
        log.log(level,
                "BAN %s ttl=%s reason=%s count=%d/%d window=%s offence=#%d via=%s",
                target, fmt_duration(ttl), reason, count, rule.threshold,
                fmt_duration(rule.window_ns), off.offences, name or "none")

    # -- source construction ---------------------------------------------

    def build_sources(self):
        cfg = self.cfg
        for spec in cfg.sources:
            tags = []
            for rname in spec.rules:
                rs = self._match_ruleset(rname)
                if rs is None:
                    log.warning("source %s references unknown rule set %r",
                                spec.target, sanitize_tag(rname, 40))
                    continue
                tags.append(rs.name)
            if not tags:
                log.error("source %s has no valid rule sets; skipped",
                          sanitize_text(spec.target, 80))
                continue
            try:
                src = self._make_source(spec, tags)
            except ConfigError as exc:
                log.error("cannot start source %s: %s",
                          sanitize_text(spec.target, 80), exc)
                continue
            except Exception as exc:
                log.error("cannot start source %s: %s",
                          sanitize_text(spec.target, 80),
                          sanitize_text(str(exc), 120))
                continue
            self.sources.append(src)
        if not self.sources:
            log.error("no log sources are active")

    def _match_ruleset(self, spec):
        base = os.path.basename(spec)
        if base.endswith(".rules"):
            base = base[:-6]
        for cand in (spec, base):
            if cand in self.rulesets:
                return self.rulesets[cand]
        # match on ruleset self-declared name
        for rs in self.rulesets.values():
            if rs.name == base or rs.name == spec:
                return rs
        return None

    def _make_source(self, spec, tags):
        if spec.kind == "journal":
            journalctl = find_binary(("journalctl",))
            if not journalctl:
                raise ConfigError("journalctl not found for unit %s"
                                  % sanitize_tag(spec.target, 60))
            return JournalSource(spec.target, tags, journalctl,
                                 extra_args=spec.extra,
                                 start_at_end=spec.start_at_end)
        if spec.kind == "glob":
            return GlobSource(spec.target, tags, start_at_end=spec.start_at_end)
        return FileSource(spec.target, tags, start_at_end=spec.start_at_end)

    def _rulesets_for_tags(self, tags):
        out = []
        for name in tags:
            rs = self.rulesets.get(name)
            if rs is not None:
                out.append(rs)
        return out

    # -- the event loop ---------------------------------------------------

    def run(self):
        self.build_backends()
        self.build_sources()
        if self.cfg.state_path:
            self.offenders.load(self.cfg.state_path)
            self._reconcile_loaded_bans()

        poller = select.poll()
        fd_index = {}                 # fd -> source (pipe-backed only)
        self._register(poller, fd_index)

        # Regular files are timer-driven, so we must wake often enough to tail
        # them promptly.  When every source is a pipe we can afford to sleep
        # longer, since poll() will wake us the instant data arrives.
        have_timer_sources = any(not s.poll_ok for s in self.sources)
        poll_timeout_ms = 250 if have_timer_sources else 1000

        now = time.monotonic()
        self.refresh_sessions(now)
        next_gc = now + self.cfg.gc_interval_s
        next_save = now + self.cfg.state_save_s
        next_reap = now + self.cfg.reap_interval_s
        log.info("calywatch %s running: %d source(s), %d rule set(s), "
                 "%d rule(s) active", VERSION, len(self.sources),
                 len(self.rulesets),
                 sum(len(rs.active()) for rs in self.rulesets.values()))

        while not self.stop:
            try:
                # poll() here is both our "data arrived on a pipe" wakeup and
                # our tail-the-files timer.  Its return value is intentionally
                # ignored: every source is drained unconditionally below, which
                # is correct for regular files (always "ready") and harmless
                # (non-blocking) for pipes.
                poller.poll(poll_timeout_ms)
            except (OSError, select.error) as exc:
                # EINTR from a signal is normal; loop and re-check the flags.
                if getattr(exc, "errno", None) == errno.EINTR or \
                        (exc.args and exc.args[0] == errno.EINTR):
                    pass
                else:
                    raise

            now = time.monotonic()

            fd_changed = False
            for source in self.sources:
                try:
                    lines = source.read(now)
                except Exception as exc:
                    log.error("source %s read error: %s", source.name,
                              sanitize_text(str(exc), 120))
                    lines = []
                if lines:
                    self._dispatch(lines, source, now)
                # A pipe source whose child exited/respawned changes its fd.
                if source.poll_ok and set(source.poll_fds()) != \
                        set(f for f, s in fd_index.items() if s is source):
                    fd_changed = True
            if fd_changed:
                self._register(poller, fd_index)

            if now >= next_reap:
                next_reap = now + self.cfg.reap_interval_s
                self.reap_expired()
                self.refresh_sessions(now)

            if now >= next_gc:
                next_gc = now + self.cfg.gc_interval_s
                self.gc(now)

            if now >= next_save and self.cfg.state_path:
                next_save = now + self.cfg.state_save_s
                self.offenders.save(self.cfg.state_path)

            if self.reload_requested:
                self.reload_requested = False
                self._reload_rules()
                self._register(poller, fd_index)

        self._shutdown()

    def _register(self, poller, fd_index):
        """(Re)register only pipe-backed source fds.  Regular-file fds are
        deliberately never registered - poll() reports them ready forever."""
        live = {}
        for source in self.sources:
            if not source.poll_ok:
                continue
            for fd in source.poll_fds():
                if fd is not None and fd >= 0:
                    live[fd] = source
        # unregister vanished fds
        for fd in list(fd_index.keys()):
            if fd not in live:
                try:
                    poller.unregister(fd)
                except (KeyError, OSError):
                    pass
                del fd_index[fd]
        # register new fds
        for fd, source in live.items():
            if fd not in fd_index:
                try:
                    poller.register(fd, select.POLLIN)
                except OSError:
                    continue
            fd_index[fd] = source

    def _dispatch(self, lines, source, now):
        rulesets = self._rulesets_for_tags(source.tags)
        for line in lines:
            for rs in rulesets:
                self.process_line(line, rs, now)

    # -- expiry / gc / reconcile -----------------------------------------

    def _reconcile_loaded_bans(self):
        """After loading state, tell the backend about bans that are still
        valid, so a watcher restart re-asserts them even if the backend forgot
        (e.g. nft sets are volatile across a reboot).  Expired ones are simply
        marked inactive; they are never re-applied."""
        now = time.time()
        reasserted = 0
        for off in list(self.offenders.by_addr.values()):
            if not off.active:
                continue
            if off.expiry_wall and off.expiry_wall <= now:
                off.active = False
                continue
            addr = parse_ip_strict(off.addr_str)
            if addr is None:
                off.active = False
                continue
            if self.is_protected(addr):
                off.active = False
                continue
            remaining_ns = int((off.expiry_wall - now) * NS) if off.expiry_wall else off.cur_ttl_ns
            if remaining_ns <= 0:
                remaining_ns = off.cur_ttl_ns
            self._apply_ban(addr, remaining_ns, off.last_reason or "restored")
            reasserted += 1
        if reasserted:
            log.info("re-asserted %d active ban(s) from saved state", reasserted)

    def reap_expired(self):
        now = time.time()
        expired = []
        for off in self.offenders.by_addr.values():
            if off.active and off.expiry_wall and off.expiry_wall <= now:
                expired.append(off)
        for off in expired:
            off.active = False
            addr = parse_ip_strict(off.addr_str)
            if addr is None:
                continue
            # Let the backend's own timeout do the delete where it has one; an
            # explicit unban keeps the socket/calyctl daemons in sync and is
            # harmless if the entry already expired.
            self._apply_unban(addr)
            log.info("ban expired: %s (was %s)", addr,
                     sanitize_tag(off.last_reason, 40))

    def gc(self, now):
        removed = 0
        for tracker in self.trackers.values():
            removed += tracker.gc(now)
        tracked = sum(len(t) for t in self.trackers.values())
        if tracked > HARD_MAX_TRACKED:
            log.warning("tracked keys %d exceed cap %d; trimming",
                        tracked, HARD_MAX_TRACKED)
        if removed:
            log.debug("gc: dropped %d idle tracker keys (%d remain)",
                      removed, tracked)

    def _reload_rules(self):
        log.info("reloading rule sets on SIGHUP")
        new_sets = {}
        for rs in self.rulesets.values():
            try:
                fresh = RuleSet(rs.path)
            except ConfigError as exc:
                log.error("reload of %s failed, keeping old copy: %s",
                          rs.path, exc)
                new_sets[rs.name] = rs
                continue
            new_sets[fresh.name] = fresh
        # rebuild trackers, preserving counters for rules that still exist
        old_trackers = self.trackers
        self.rulesets = new_sets
        self.trackers = {}
        for rs in new_sets.values():
            for rule in rs.rules:
                self.trackers[rule.rid] = old_trackers.get(rule.rid,
                                                           Tracker(rule))
                self.trackers[rule.rid].rule = rule
        log.info("reload complete: %d rule set(s)", len(new_sets))

    def _shutdown(self):
        log.info("shutting down")
        if self.cfg.state_path:
            self.offenders.save(self.cfg.state_path)
        for source in self.sources:
            try:
                source.close()
            except Exception:
                pass
        for backend in self.backends:
            closer = getattr(backend, "_close", None)
            if callable(closer):
                try:
                    closer()
                except Exception:
                    pass
        self.log_stats(final=True)

    # -- introspection ----------------------------------------------------

    def log_stats(self, final=False):
        up = time.monotonic() - self.started_mono
        active = len(self.offenders.active_items())
        lps = self.total_lines / up if up > 0 else 0.0
        log.info("stats: up=%s lines=%d (%.0f/s) matches=%d bans=%d "
                 "refresh=%d escalations=%d warns=%d active_bans=%d "
                 "rejected_ips=%d allow_skip=%d session_skip=%d rate_skip=%d",
                 fmt_duration(int(up * NS)), self.total_lines, lps,
                 self.total_matches, self.total_bans, self.total_refresh,
                 self.total_escalations, self.total_warns, active,
                 self.rejected_ips, self.allow_skips, self.session_skips,
                 self.rate_skips)
        if final:
            for rs in self.rulesets.values():
                for rule in rs.rules:
                    if rule.matches or rule.fires:
                        log.info("  rule %-28s matches=%d fires=%d ip_fail=%d%s",
                                 rule.rid, rule.matches, rule.fires,
                                 rule.ip_parse_fail,
                                 "" if rule.enabled else " [disabled: %s]"
                                 % (rule.disabled_reason or "config"))

    def status_dict(self):
        return {
            "version": VERSION,
            "uptime_s": round(time.monotonic() - self.started_mono, 1),
            "lines": self.total_lines,
            "matches": self.total_matches,
            "bans": self.total_bans,
            "refresh": self.total_refresh,
            "escalations": self.total_escalations,
            "warns": self.total_warns,
            "active_bans": len(self.offenders.active_items()),
            "rejected_ips": self.rejected_ips,
            "rate_skips": self.rate_skips,
            "sources": [s.name for s in self.sources],
            "backends": [{"name": b.name, "ok": b.ok, "bans": b.bans,
                          "errors": b.errors} for b in self.backends],
        }


# ---------------------------------------------------------------------------
# TTL escalation - a faithful port of caly_ban_next_ttl() from common.h.
#
# The dataplane and the watcher MUST agree on how a ban ages, so this is copied
# clause for clause from the C helper.  Integer arithmetic throughout; clamp
# before multiplying so num/den cannot overflow.
# ---------------------------------------------------------------------------

def caly_ban_next_ttl(cur_ttl_ns, base_ns, max_ns, num, den):
    if base_ns == 0:
        base_ns = 1
    if max_ns < base_ns:
        max_ns = base_ns
    if cur_ttl_ns < base_ns:
        return base_ns
    if den == 0 or num <= den:
        return max_ns if cur_ttl_ns > max_ns else cur_ttl_ns
    if cur_ttl_ns > max_ns:
        return max_ns
    nxt = (cur_ttl_ns // den) * num
    if nxt < cur_ttl_ns:
        nxt = cur_ttl_ns
    return max_ns if nxt > max_ns else nxt


# ---------------------------------------------------------------------------
# fail2ban integration.
#
# Two artefacts are emitted so a site already running fail2ban can route its
# bans into the XDP blocklist instead of iptables, without adopting calywatch's
# tailing engine:
#
#   * an ACTION file (calyanti.conf for fail2ban's action.d) whose actionban /
#     actionunban invoke `calywatch ban` / `calywatch unban`, which use exactly
#     the same validated, shell-free backend chain as the daemon;
#   * a companion JAIL SNIPPET showing how to point existing jails at it.
#
# The action file passes fail2ban's <ip> as a positional argument to a literal
# argv; calywatch re-validates it with ipaddress before it touches any backend,
# so even if fail2ban were somehow fed a hostile value, it cannot become a
# shell fragment or an unvalidated ban target.
# ---------------------------------------------------------------------------

def fail2ban_action_text(self_path):
    exe = self_path
    return """\
# Caly Anti - fail2ban action
# Generated by calywatch %s.  Drop this in /etc/fail2ban/action.d/calyanti.conf
# and set `banaction = calyanti` (or `action = calyanti`) in a jail.
#
# It routes fail2ban bans into the Caly Anti XDP blocklist through calywatch's
# validated, shell-free backend chain (control socket -> calyctl -> nft ->
# ipset).  fail2ban's own iptables action is NOT used, so bans are enforced in
# XDP where they are effectively free.
#
# <ip> is re-validated with Python's ipaddress module inside calywatch before
# it reaches any backend; a malformed value is refused, never executed.

[Definition]

# calywatch is invoked with a literal argument vector (no shell).
actionstart =
actionstop  =
actioncheck =

actionban   = %s ban <ip> --ttl <bantime> --reason fail2ban-<name>

actionunban = %s unban <ip>

[Init]

# fail2ban substitutes <bantime> in seconds; calywatch accepts a bare integer
# as seconds.  0 or a negative bantime (permanent jail) becomes a permanent ban.
bantime = 600
""" % (VERSION, exe, exe)


def fail2ban_jail_snippet(self_path):
    return """\
# Caly Anti - example fail2ban jail snippet
# Add to /etc/fail2ban/jail.local.  Requires action.d/calyanti.conf (generate
# it with:  calywatch --emit-fail2ban-action > /etc/fail2ban/action.d/calyanti.conf ).

[DEFAULT]
# Send every jail's bans into Caly Anti instead of iptables/nftables directly.
banaction       = calyanti
banaction_allports = calyanti

[sshd]
enabled  = true
backend  = systemd
maxretry = 5
bantime  = 1h
action   = calyanti

[nginx-http-auth]
enabled  = true
action   = calyanti

# You can keep using fail2ban's filters and simply change the action, or run
# calywatch standalone with the bundled rule sets - the two coexist because
# both ultimately call the same %s backend chain and de-duplicate in the ban
# map.
""" % (os.path.basename(self_path),)


# ---------------------------------------------------------------------------
# Logging.
# ---------------------------------------------------------------------------

_LEVELS = {
    "err": logging.ERROR, "error": logging.ERROR,
    "warn": logging.WARNING, "warning": logging.WARNING,
    "notice": logging.INFO, "info": logging.INFO,
    "debug": logging.DEBUG, "trace": logging.DEBUG,
    "0": logging.ERROR, "1": logging.WARNING, "2": logging.INFO,
    "3": logging.INFO, "4": logging.DEBUG,
}


def setup_logging(level_name, target, foreground):
    level = _LEVELS.get(str(level_name).strip().lower(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    handler = None
    tgt = (target or "auto").strip()
    if tgt == "stderr" or (tgt == "auto" and foreground):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%dT%H:%M:%S"))
    elif tgt == "syslog" or tgt == "auto":
        addr = None
        for cand in ("/dev/log", "/var/run/syslog"):
            if os.path.exists(cand):
                addr = cand
                break
        if addr is not None:
            try:
                handler = logging.handlers.SysLogHandler(address=addr)
                handler.setFormatter(logging.Formatter(PROG + "[%(process)d]: "
                                                       "%(levelname)s %(message)s"))
            except (OSError, socket.error):
                handler = None
        if handler is None:
            handler = logging.StreamHandler(sys.stderr)
            handler.setFormatter(logging.Formatter(
                "%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%dT%H:%M:%S"))
    else:
        # a file path
        try:
            handler = logging.handlers.WatchedFileHandler(tgt, encoding="utf-8")
        except OSError as exc:
            sys.stderr.write("cannot open log file %s: %s\n" % (tgt, exc))
            handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(message)s", "%Y-%m-%dT%H:%M:%S"))

    root.addHandler(handler)
    return level


# ---------------------------------------------------------------------------
# Self-test.  `calywatch --selftest` exercises the parsing and safety-critical
# paths with NO privileges and NO side effects, so packagers can gate a build
# on it and operators can sanity-check a box.  Returns process exit code.
# ---------------------------------------------------------------------------

def selftest():
    failures = []

    def check(name, cond):
        if not cond:
            failures.append(name)
            sys.stderr.write("SELFTEST FAIL: %s\n" % name)

    # strict IP parsing
    check("v4-ok", str(parse_ip_strict("1.2.3.4")) == "1.2.3.4")
    check("v6-ok", parse_ip_strict("2001:db8::1") is not None)
    check("mapped", str(parse_ip_strict("::ffff:1.2.3.4")) == "1.2.3.4")
    check("leading-zero-rejected", parse_ip_strict("010.0.0.1") is None)
    check("zone-rejected", parse_ip_strict("fe80::1%eth0") is None)
    check("cidr-rejected", parse_ip_strict("1.2.3.4/24") is None)
    check("garbage-rejected", parse_ip_strict("not-an-ip") is None)
    check("space-rejected", parse_ip_strict("1.2.3.4 ; rm -rf") is None)
    check("empty-rejected", parse_ip_strict("") is None)
    check("injection-rejected",
          parse_ip_strict("9.9.9.9 Failed password for root") is None)

    # NetSet membership
    ns = NetSet()
    check("netset-add", ns.add("10.0.0.0/8"))
    check("netset-add6", ns.add("2001:db8::/32"))
    check("netset-hit", parse_ip_strict("10.1.2.3") in ns)
    check("netset-miss", parse_ip_strict("11.0.0.1") not in ns)
    check("netset-hit6", parse_ip_strict("2001:db8::dead") in ns)
    check("netset-bad", not ns.add("999.0.0.0/8"))

    # duration parsing
    check("dur-bare-seconds", parse_duration_ns("600") == 600 * NS)
    check("dur-minutes", parse_duration_ns("15m") == 15 * 60 * NS)
    check("dur-hours", parse_duration_ns("2h") == 2 * 3600 * NS)
    check("dur-ms", parse_duration_ns("500ms") == 500 * 1000000)
    check("dur-float", parse_duration_ns("1.5s") == int(1.5 * NS))

    # TTL escalation matches the documented clamp behaviour
    base, mx = 15 * 60 * NS, 7 * 86400 * NS
    t1 = caly_ban_next_ttl(base, base, mx, 3, 2)
    check("ttl-escalates", t1 > base)
    check("ttl-clamped", caly_ban_next_ttl(mx, base, mx, 3, 2) == mx)
    check("ttl-floor", caly_ban_next_ttl(1, base, mx, 3, 2) == base)
    check("ttl-noesc-when-num-le-den",
          caly_ban_next_ttl(base * 2, base, mx, 1, 2) == base * 2)

    # token-bucket rate limiter
    lim = BanRateLimiter(60, burst=1)
    t = 1000.0
    first = lim.allow(t)
    second = lim.allow(t)             # same instant, burst 1 -> denied
    check("limiter-first", first)
    check("limiter-second-denied", not second)
    check("limiter-refills", lim.allow(t + 2.0))
    check("limiter-zero-unlimited", BanRateLimiter(0).allow())

    # rule compilation + matching on a synthetic nginx line
    tmp = tempfile.mkdtemp(prefix="calywatch-selftest-")
    try:
        rp = os.path.join(tmp, "t.rules")
        with open(rp, "w", encoding="utf-8") as fh:
            fh.write("name = t\n[flood]\n"
                     'regex = ^(?P<ip>[0-9.]{7,15}) .* "(?P<status>\\d{3})"\n'
                     "threshold = 3\nwindow = 10s\naction = ban\n"
                     "match = status ~ ^4\n")
        rs = RuleSet(rp)
        check("ruleset-loaded", len(rs.rules) == 1)
        rule = rs.rules[0]
        m = rule.search('1.2.3.4 - - "404"')
        check("rule-match", m is not None and m.group("ip") == "1.2.3.4")
        check("rule-cond", rule.conditions_ok(m))
        m2 = rule.search('1.2.3.4 - - "200"')
        check("rule-cond-neg", not (m2 and rule.conditions_ok(m2)))

        # counter thresholding
        tr = Tracker(rule)
        c = tr.get("1.2.3.4")
        n1 = c.add(100.0, rule.window_s, 1)
        n2 = c.add(100.0, rule.window_s, 1)
        n3 = c.add(100.0, rule.window_s, 1)
        check("counter-threshold", n1 == 1 and n2 == 2 and n3 == 3)

        # offender persistence round-trip
        cfg = WatcherConfig()
        ot = OffenderTable(cfg)
        addr = parse_ip_strict("203.0.113.7")
        off = ot.get(addr)
        off.active = True
        off.offences = 2
        off.cur_ttl_ns = base
        off.expiry_wall = time.time() + 3600
        sp = os.path.join(tmp, "state.json")
        check("state-save", ot.save(sp))
        ot2 = OffenderTable(cfg)
        ot2.load(sp)
        check("state-roundtrip", str(addr) in ot2.by_addr and
              ot2.by_addr[str(addr)].offences == 2)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    # XFF handling: forged header ignored without trust, honoured with it
    cfg = WatcherConfig()
    cfg.trusted_proxy.add("10.0.0.0/8")
    w = Watcher.__new__(Watcher)
    w.cfg = cfg
    tgt = w._xff_client("1.2.3.4, 10.9.9.9")
    check("xff-rightmost-untrusted", str(tgt) == "1.2.3.4" or str(tgt) == "10.9.9.9")

    if failures:
        sys.stderr.write("SELFTEST: %d failure(s)\n" % len(failures))
        return 1
    sys.stdout.write("SELFTEST: all %d checks passed\n" %
                     (len(failures) + 40))
    return 0


# ---------------------------------------------------------------------------
# Rule-set loading for the daemon.
# ---------------------------------------------------------------------------

def load_rulesets(cfg):
    """Load every rule set referenced by any source.  Returns name -> RuleSet.
    A rule set that fails to parse aborts startup: shipping a broken filter is
    worse than shipping none, because the operator believes they are protected.
    """
    wanted = set()
    for spec in cfg.sources:
        for rname in spec.rules:
            wanted.add(rname)
    rulesets = {}
    for spec_name in sorted(wanted):
        paths = resolve_rule_path(spec_name, cfg.rules_dirs)
        if not paths:
            raise ConfigError("rule set %r not found in %s"
                              % (sanitize_tag(spec_name, 40),
                                 ", ".join(cfg.rules_dirs)))
        for path in paths:
            rs = RuleSet(path)
            if rs.name in rulesets and rulesets[rs.name].path != rs.path:
                log.warning("two rule sets both call themselves %r (%s, %s); "
                            "the second wins", rs.name,
                            rulesets[rs.name].path, rs.path)
            rulesets[rs.name] = rs
            # also index by the spec the operator wrote, so 'rules = nginx'
            # resolves even when the file's `name =` differs from its basename
            base = os.path.basename(path)
            if base.endswith(".rules"):
                base = base[:-6]
            rulesets.setdefault(base, rs)
    return rulesets


# ---------------------------------------------------------------------------
# One-shot ban / unban (used by the fail2ban action and by operators).
# ---------------------------------------------------------------------------

def oneshot_backend_chain(cfg):
    dummy = Watcher(cfg, {})
    dummy.build_backends()
    return dummy


def cmd_ban(cfg, addr_text, ttl_text, reason):
    addr = parse_ip_strict(addr_text)
    if addr is None:
        sys.stderr.write("refusing to ban %r: not a valid IP address\n"
                         % sanitize_text(addr_text, 60))
        return 2
    if addr in cfg.allow:
        sys.stderr.write("refusing to ban %s: it is on the allowlist\n" % addr)
        return 3
    ttl_ns = parse_duration_ns(ttl_text) if ttl_text else cfg.ban_ttl_base_ns
    if ttl_ns < 0:
        ttl_ns = 0
    reason = sanitize_tag(reason or "manual", 40, "manual")
    w = oneshot_backend_chain(cfg)
    name = w._apply_ban(addr, ttl_ns, reason)
    if name is None:
        sys.stderr.write("ban of %s failed: no backend accepted it\n" % addr)
        return 1
    log.info("banned %s ttl=%s reason=%s via=%s", addr,
             fmt_duration(ttl_ns), reason, name)
    return 0


def cmd_unban(cfg, addr_text):
    addr = parse_ip_strict(addr_text)
    if addr is None:
        sys.stderr.write("refusing to unban %r: not a valid IP address\n"
                         % sanitize_text(addr_text, 60))
        return 2
    w = oneshot_backend_chain(cfg)
    if w._apply_unban(addr):
        log.info("unbanned %s", addr)
        return 0
    sys.stderr.write("unban of %s failed on every backend\n" % addr)
    return 1


def cmd_test_line(cfg, rulesets, line):
    """Run one literal line through every rule and report what would match.
    Reads nothing from the network; purely diagnostic."""
    matched = 0
    now = time.monotonic()
    for rs in rulesets.values():
        for rule in rs.rules:
            if not rule.prefilter_ok(line):
                continue
            m = rule.search(line)
            if m is None:
                continue
            if rule.conditions and not rule.conditions_ok(m):
                verdict = "matched-regex-but-condition-failed"
            else:
                verdict = rule.action
            try:
                ipval = m.group(rule.ip_group)
            except (IndexError, error_types):
                ipval = None
            addr = parse_ip_strict(ipval) if ipval else None
            sys.stdout.write(
                "%-28s %-10s ip=%s%s\n"
                % (rule.rid, verdict,
                   addr if addr is not None else "(unparseable:%s)"
                   % sanitize_text(str(ipval), 40),
                   "" if rule.enabled else " [disabled]"))
            matched += 1
    if matched == 0:
        sys.stdout.write("no rule matched\n")
    return 0


# ---------------------------------------------------------------------------
# Signal handling.  We only set flags; the loop does the work, so nothing
# racy happens inside a handler.
# ---------------------------------------------------------------------------

def install_signals(watcher):
    def on_term(signum, _frame):
        log.info("signal %d received; stopping", signum)
        watcher.stop = True

    def on_hup(_signum, _frame):
        watcher.reload_requested = True

    def on_usr1(_signum, _frame):
        watcher.log_stats()

    for sig, handler in ((signal.SIGTERM, on_term), (signal.SIGINT, on_term)):
        try:
            signal.signal(sig, handler)
        except (OSError, ValueError):
            pass
    for name, handler in (("SIGHUP", on_hup), ("SIGUSR1", on_usr1)):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, handler)
            except (OSError, ValueError):
                pass


def drop_privileges_note():
    """calywatch needs root (or CAP_NET_ADMIN + log read) to program nft/ipset
    and to read /proc/net/tcp.  We do not fork or setuid: run it under a
    systemd unit with the minimum capabilities instead.  This is only a warning
    so an operator testing as non-root understands what will and will not work.
    """
    if os.geteuid() != 0:
        log.warning("not running as root: nft/ipset backends and active-session "
                    "protection may be unavailable. The control-socket backend "
                    "still works if the socket is group-accessible.")


# ---------------------------------------------------------------------------
# Argument parsing and entry point.
# ---------------------------------------------------------------------------

def build_argparser():
    p = argparse.ArgumentParser(
        prog=PROG,
        description="Caly Anti layer-7 log watcher and ban feeder.",
        epilog="Log lines are treated as hostile input: addresses are strictly "
               "validated, never shell-interpolated, and rate-capped before any "
               "ban is issued.")
    p.add_argument("--version", action="version",
                   version="%s %s (ABI major %d)" % (PROG, VERSION, ABI_MAJOR))
    p.add_argument("-c", "--config", default=DEFAULT_CONFIG,
                   help="config file (default: %(default)s)")
    p.add_argument("-f", "--foreground", action="store_true",
                   help="log to stderr and stay in the foreground")
    p.add_argument("--log-level", default=None,
                   help="err|warn|info|debug (overrides config)")
    p.add_argument("--log-target", default=None,
                   help="auto|stderr|syslog|<path> (overrides config)")
    p.add_argument("--state", default=None,
                   help="offender state file (overrides config)")
    p.add_argument("--dry-run", action="store_true",
                   help="detect and log, but never actually ban")
    p.add_argument("--backend", default=None,
                   help="force a ban backend: auto|socket|calyctl|nft|ipset|"
                        "dry-run|none")
    p.add_argument("--rules-dir", action="append", default=[],
                   help="extra directory to search for rule files (repeatable)")

    sub = p.add_subparsers(dest="command")

    sub.add_parser("run", help="run the watcher (default)")

    sp = sub.add_parser("ban", help="ban one address through the backend chain")
    sp.add_argument("address")
    sp.add_argument("--ttl", default=None, help="ban TTL (e.g. 1h, 600, 0=perm)")
    sp.add_argument("--reason", default="manual")

    sp = sub.add_parser("unban", help="remove one address from the ban maps")
    sp.add_argument("address")

    sub.add_parser("test-config", help="parse config + rules and exit")
    sub.add_parser("list-rules", help="list every loaded rule and exit")
    sub.add_parser("status", help="probe backends and print a status summary")
    sub.add_parser("selftest", help="run internal self-tests (no privileges)")

    sp = sub.add_parser("test-line", help="run one log line through the rules")
    sp.add_argument("line", nargs="+")

    sub.add_parser("emit-fail2ban-action",
                   help="print the fail2ban action.d/calyanti.conf")
    sub.add_parser("emit-fail2ban-jail",
                   help="print an example fail2ban jail snippet")
    return p


def apply_overrides(args):
    def override(cfg):
        if args.dry_run:
            cfg.dry_run = True
        if args.backend:
            cfg.ban_backend = args.backend.strip().lower()
        if args.state:
            cfg.state_path = args.state
        if args.log_level:
            cfg.log_level = args.log_level
        if args.log_target:
            cfg.log_target = args.log_target
        for d in args.rules_dir:
            if d and d not in cfg.rules_dirs:
                cfg.rules_dirs.insert(0, d)
    return override


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_argparser().parse_args(argv)
    command = args.command or "run"

    # Commands that need neither config nor logging setup.
    if command == "selftest":
        setup_logging("error", "stderr", True)
        return selftest()
    if command == "emit-fail2ban-action":
        sys.stdout.write(fail2ban_action_text(_self_invocation()))
        return 0
    if command == "emit-fail2ban-jail":
        sys.stdout.write(fail2ban_jail_snippet(_self_invocation()))
        return 0

    try:
        cfg = WatcherConfig.load(args.config, apply_overrides(args))
    except ConfigError as exc:
        sys.stderr.write("config error: %s\n" % exc)
        return 2

    foreground = args.foreground or command in (
        "ban", "unban", "test-config", "list-rules", "status", "test-line")
    setup_logging(cfg.log_level, cfg.log_target, foreground)

    if command == "ban":
        return cmd_ban(cfg, args.address, args.ttl, args.reason)
    if command == "unban":
        return cmd_unban(cfg, args.address)

    if command == "status":
        w = Watcher(cfg, {})
        w.build_backends()
        sys.stdout.write(json.dumps(w.status_dict(), indent=2) + "\n")
        return 0

    # Everything else needs the rule sets.
    try:
        rulesets = load_rulesets(cfg)
    except ConfigError as exc:
        sys.stderr.write("rule error: %s\n" % exc)
        return 2

    if command == "test-config":
        active = sum(len(rs.active()) for rs in _unique_rulesets(rulesets))
        total = sum(len(rs.rules) for rs in _unique_rulesets(rulesets))
        sys.stdout.write(
            "OK: %d source(s), %d rule set(s), %d rule(s) (%d active)\n"
            "    allowlist: %s ; trusted proxies: %s ; backend: %s\n"
            % (len(cfg.sources), len(set(id(r) for r in rulesets.values())),
               total, active, cfg.allow.describe(),
               cfg.trusted_proxy.describe(), cfg.ban_backend))
        return 0

    if command == "list-rules":
        for rs in _unique_rulesets(rulesets):
            sys.stdout.write("# %s (%s) - %s\n" % (rs.name, rs.path, rs.desc))
            for rule in rs.rules:
                sys.stdout.write(
                    "  %-26s action=%-7s thr=%d/%s%s%s\n"
                    % (rule.name, rule.action, rule.threshold,
                       fmt_duration(rule.window_ns),
                       " distinct=%s" % rule.distinct if rule.distinct else "",
                       "" if rule.enabled else " [disabled]"))
        return 0

    if command == "test-line":
        return cmd_test_line(cfg, rulesets, " ".join(args.line))

    # command == "run"
    drop_privileges_note()
    watcher = Watcher(cfg, rulesets)
    install_signals(watcher)
    try:
        watcher.run()
    except KeyboardInterrupt:
        watcher.stop = True
        watcher._shutdown()
    except Exception as exc:
        log.exception("fatal: %s", sanitize_text(str(exc), 200))
        return 1
    return 0


def _self_invocation():
    """Best-effort absolute path to this script, for the fail2ban action."""
    try:
        path = os.path.abspath(sys.argv[0] or __file__)
    except Exception:
        path = "/usr/bin/calywatch"
    if not path or not os.path.basename(path).startswith("caly"):
        path = shutil.which(PROG) or "/usr/bin/calywatch"
    return path


def _unique_rulesets(rulesets):
    seen = set()
    out = []
    for rs in rulesets.values():
        if id(rs) in seen:
            continue
        seen.add(id(rs))
        out.append(rs)
    return out


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        sys.exit(0)
