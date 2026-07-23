// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
/*
 * Caly Anti - src/user/ctl.c
 *
 * The daemon side of the operator control protocol: newline-delimited JSON
 * over the SOCK_STREAM control socket, spoken by cli/calyctl and
 * watcher/calywatch.py.  See ctl.h for the wire format.
 *
 * This module lives entirely in the daemon's own world (loader.h + util.h):
 * it reaches the BPF maps through the loader's caly_bpf handle and raw libbpf
 * syscalls, so it does not pull in the parallel maps.c/config.c layer. A
 * root-only control socket is still untrusted input, so it carries its own
 * small, bounded JSON parser rather than a library.
 */

#ifndef CALY_USERSPACE
#define CALY_USERSPACE 1
#endif

/* common.h uses the fixed-width kernel types (__u32/__u8/...) but does not
 * include their definition: on the BPF side they come from vmlinux.h, on the
 * userspace side from <linux/types.h>. Pull that in BEFORE common.h. */
#include <linux/types.h>

#include "common.h"
#include "loader.h"
#include "util.h"
#include "ctl.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <bpf/bpf.h>

/* Family selector for the read/dump paths. */
#define CTL_FAM_ANY  0u
#define CTL_FAM_V4   CALY_UTIL_AF_INET
#define CTL_FAM_V6   CALY_UTIL_AF_INET6

/* Local set ids for allow/block/local (kept independent of any header). */
#define CTL_SET_ALLOW  0
#define CTL_SET_BLOCK  1
#define CTL_SET_LOCAL  2

/* Bounds for the generic map collector. Every key we iterate (u32, in6_key,
 * lpm_key_v6, conn_key) fits in 64 bytes; every value (ban_entry, src_stats,
 * conn_state, rule_meta) fits in 512. */
#define CTL_KEY_MAX  64
#define CTL_VAL_MAX  512

/* -------------------------------------------------------------------------
 * enum caly_dataplane -> string (kept local so ctl.c needs nothing extra).
 * ------------------------------------------------------------------------- */
static const char *ctl_dataplane_str(__u32 dp)
{
	switch (dp) {
	case CALY_DP_XDP_NATIVE:  return "xdp-native";
	case CALY_DP_XDP_GENERIC: return "xdp-generic";
	case CALY_DP_TC:          return "tc";
	case CALY_DP_NFTABLES:    return "nftables";
	case CALY_DP_IPTABLES:    return "iptables";
	case CALY_DP_AUTO:        return "auto";
	default:                  return "none";
	}
}

/* =========================================================================
 * sbuf: a growable output buffer. Every append is bounds-checked and sets an
 * error flag on allocation failure; the caller checks ->err once before it
 * writes, so no partial or oversized response is ever emitted.
 * ========================================================================= */

struct sbuf {
	char  *buf;
	size_t len;
	size_t cap;
	int    err;
};

/* Hard ceiling on any single response, kept below the 8 MiB line limit the
 * clients enforce, so an over-large dump is a clean error not a torn socket. */
#define CTL_RESP_MAX  (7u * 1024u * 1024u)

static void sb_init(struct sbuf *s)
{
	s->buf = NULL;
	s->len = 0;
	s->cap = 0;
	s->err = 0;
}

static void sb_free(struct sbuf *s)
{
	free(s->buf);
	s->buf = NULL;
	s->len = 0;
	s->cap = 0;
}

static int sb_reserve(struct sbuf *s, size_t extra)
{
	size_t need;
	char  *nb;

	if (s->err)
		return -1;
	if (extra > CTL_RESP_MAX || s->len > CTL_RESP_MAX - extra) {
		s->err = 1;
		return -1;
	}
	need = s->len + extra + 1;
	if (need <= s->cap)
		return 0;
	if (s->cap == 0)
		s->cap = 1024;
	while (s->cap < need) {
		if (s->cap > CTL_RESP_MAX) {
			s->err = 1;
			return -1;
		}
		s->cap *= 2;
	}
	nb = realloc(s->buf, s->cap);
	if (!nb) {
		s->err = 1;
		return -1;
	}
	s->buf = nb;
	return 0;
}

static void sb_write(struct sbuf *s, const char *p, size_t n)
{
	if (sb_reserve(s, n) != 0)
		return;
	memcpy(s->buf + s->len, p, n);
	s->len += n;
	s->buf[s->len] = '\0';
}

static void sb_puts(struct sbuf *s, const char *p)
{
	sb_write(s, p, strlen(p));
}

static void sb_putc(struct sbuf *s, char c)
{
	sb_write(s, &c, 1);
}

static void sb_u64(struct sbuf *s, __u64 v)
{
	char tmp[24];
	int  n = snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)v);

	if (n > 0)
		sb_write(s, tmp, (size_t)n);
}

static void sb_i64(struct sbuf *s, long long v)
{
	char tmp[24];
	int  n = snprintf(tmp, sizeof(tmp), "%lld", v);

	if (n > 0)
		sb_write(s, tmp, (size_t)n);
}

/* Append a JSON string literal: quotes, escaping " backslash and controls. */
static void sb_jstr(struct sbuf *s, const char *p, size_t n)
{
	size_t i;

	sb_putc(s, '"');
	for (i = 0; i < n; i++) {
		unsigned char c = (unsigned char)p[i];

		switch (c) {
		case '"':  sb_puts(s, "\\\""); break;
		case '\\': sb_puts(s, "\\\\"); break;
		case '\b': sb_puts(s, "\\b");  break;
		case '\f': sb_puts(s, "\\f");  break;
		case '\n': sb_puts(s, "\\n");  break;
		case '\r': sb_puts(s, "\\r");  break;
		case '\t': sb_puts(s, "\\t");  break;
		default:
			if (c < 0x20) {
				char u[8];
				int  k = snprintf(u, sizeof(u), "\\u%04x", c);

				if (k > 0)
					sb_write(s, u, (size_t)k);
			} else {
				sb_putc(s, (char)c);
			}
			break;
		}
	}
	sb_putc(s, '"');
}

static void sb_jstrz(struct sbuf *s, const char *p)
{
	sb_jstr(s, p, strlen(p));
}

static void sb_key(struct sbuf *s, const char *k)
{
	sb_jstrz(s, k);
	sb_putc(s, ':');
}

/* =========================================================================
 * A small, bounded JSON parser producing a flat DOM in a fixed arena.
 * ========================================================================= */

#define J_MAX_NODES  4096
#define J_MAX_DEPTH  64

enum jkind { JK_NULL, JK_BOOL, JK_NUM, JK_STR, JK_ARR, JK_OBJ };

struct jnode {
	enum jkind kind;
	int        bval;
	__u64      num;
	int        neg;
	char      *str;
	size_t     slen;
	char      *key;
	size_t     klen;
	int        child;
	int        next;
};

struct jparse {
	char        *cur;
	char        *end;
	struct jnode nodes[J_MAX_NODES];
	int          n;
	int          depth;
};

static void j_skip_ws(struct jparse *jp)
{
	while (jp->cur < jp->end) {
		char c = *jp->cur;

		if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
			jp->cur++;
		else
			break;
	}
}

static int j_alloc(struct jparse *jp)
{
	int idx;

	if (jp->n >= J_MAX_NODES)
		return -1;
	idx = jp->n++;
	jp->nodes[idx].kind  = JK_NULL;
	jp->nodes[idx].bval  = 0;
	jp->nodes[idx].num   = 0;
	jp->nodes[idx].neg   = 0;
	jp->nodes[idx].str   = NULL;
	jp->nodes[idx].slen  = 0;
	jp->nodes[idx].key   = NULL;
	jp->nodes[idx].klen  = 0;
	jp->nodes[idx].child = -1;
	jp->nodes[idx].next  = -1;
	return idx;
}

static int j_parse_value(struct jparse *jp);

static int j_parse_string_raw(struct jparse *jp, char **out, size_t *len)
{
	char *w = jp->cur;

	*out = jp->cur;
	while (jp->cur < jp->end) {
		unsigned char c = (unsigned char)*jp->cur;

		if (c == '"') {
			*len = (size_t)(w - *out);
			jp->cur++;
			return 0;
		}
		if (c == '\\') {
			jp->cur++;
			if (jp->cur >= jp->end)
				return -1;
			switch (*jp->cur) {
			case '"':  *w++ = '"';  break;
			case '\\': *w++ = '\\'; break;
			case '/':  *w++ = '/';  break;
			case 'b':  *w++ = '\b'; break;
			case 'f':  *w++ = '\f'; break;
			case 'n':  *w++ = '\n'; break;
			case 'r':  *w++ = '\r'; break;
			case 't':  *w++ = '\t'; break;
			case 'u': {
				unsigned int cp = 0;
				int i;

				if (jp->end - jp->cur < 5)
					return -1;
				for (i = 1; i <= 4; i++) {
					char h = jp->cur[i];
					int  dg;

					if (h >= '0' && h <= '9')
						dg = h - '0';
					else if (h >= 'a' && h <= 'f')
						dg = h - 'a' + 10;
					else if (h >= 'A' && h <= 'F')
						dg = h - 'A' + 10;
					else
						return -1;
					cp = (cp << 4) | (unsigned int)dg;
				}
				jp->cur += 4;
				if (cp < 0x80) {
					*w++ = (char)cp;
				} else if (cp < 0x800) {
					*w++ = (char)(0xC0 | (cp >> 6));
					*w++ = (char)(0x80 | (cp & 0x3F));
				} else {
					*w++ = (char)(0xE0 | (cp >> 12));
					*w++ = (char)(0x80 | ((cp >> 6) & 0x3F));
					*w++ = (char)(0x80 | (cp & 0x3F));
				}
				break;
			}
			default:
				return -1;
			}
			jp->cur++;
		} else if (c < 0x20) {
			return -1;
		} else {
			if (w != jp->cur)
				*w = (char)c;
			w++;
			jp->cur++;
		}
	}
	return -1;
}

static int j_parse_string(struct jparse *jp)
{
	int idx;

	jp->cur++;
	idx = j_alloc(jp);
	if (idx < 0)
		return -1;
	jp->nodes[idx].kind = JK_STR;
	if (j_parse_string_raw(jp, &jp->nodes[idx].str, &jp->nodes[idx].slen) != 0)
		return -1;
	return idx;
}

static int j_parse_number(struct jparse *jp)
{
	int   idx = j_alloc(jp);
	int   neg = 0;
	__u64 v   = 0;

	if (idx < 0)
		return -1;
	if (jp->cur < jp->end && *jp->cur == '-') {
		neg = 1;
		jp->cur++;
	} else if (jp->cur < jp->end && *jp->cur == '+') {
		jp->cur++;
	}
	if (jp->cur >= jp->end || *jp->cur < '0' || *jp->cur > '9')
		return -1;
	while (jp->cur < jp->end && *jp->cur >= '0' && *jp->cur <= '9') {
		unsigned int dg = (unsigned int)(*jp->cur - '0');

		if (v > (0xFFFFFFFFFFFFFFFFULL - dg) / 10ULL)
			v = 0xFFFFFFFFFFFFFFFFULL;
		else
			v = v * 10ULL + dg;
		jp->cur++;
	}
	while (jp->cur < jp->end) {
		char c = *jp->cur;

		if ((c >= '0' && c <= '9') || c == '.' || c == 'e' ||
		    c == 'E' || c == '+' || c == '-')
			jp->cur++;
		else
			break;
	}
	jp->nodes[idx].kind = JK_NUM;
	jp->nodes[idx].num  = v;
	jp->nodes[idx].neg  = neg;
	return idx;
}

static int j_lit(struct jparse *jp, const char *lit, enum jkind kind, int bval)
{
	size_t l = strlen(lit);
	int    idx;

	if ((size_t)(jp->end - jp->cur) < l || memcmp(jp->cur, lit, l) != 0)
		return -1;
	idx = j_alloc(jp);
	if (idx < 0)
		return -1;
	jp->cur += l;
	jp->nodes[idx].kind = kind;
	jp->nodes[idx].bval = bval;
	return idx;
}

static int j_parse_array(struct jparse *jp)
{
	int idx, last = -1;

	jp->cur++;
	idx = j_alloc(jp);
	if (idx < 0)
		return -1;
	jp->nodes[idx].kind = JK_ARR;
	if (++jp->depth > J_MAX_DEPTH)
		return -1;
	j_skip_ws(jp);
	if (jp->cur < jp->end && *jp->cur == ']') {
		jp->cur++;
		jp->depth--;
		return idx;
	}
	for (;;) {
		int child = j_parse_value(jp);

		if (child < 0)
			return -1;
		if (last < 0)
			jp->nodes[idx].child = child;
		else
			jp->nodes[last].next = child;
		last = child;
		j_skip_ws(jp);
		if (jp->cur >= jp->end)
			return -1;
		if (*jp->cur == ',') {
			jp->cur++;
			j_skip_ws(jp);
			continue;
		}
		if (*jp->cur == ']') {
			jp->cur++;
			break;
		}
		return -1;
	}
	jp->depth--;
	return idx;
}

static int j_parse_object(struct jparse *jp)
{
	int idx, last = -1;

	jp->cur++;
	idx = j_alloc(jp);
	if (idx < 0)
		return -1;
	jp->nodes[idx].kind = JK_OBJ;
	if (++jp->depth > J_MAX_DEPTH)
		return -1;
	j_skip_ws(jp);
	if (jp->cur < jp->end && *jp->cur == '}') {
		jp->cur++;
		jp->depth--;
		return idx;
	}
	for (;;) {
		char  *key;
		size_t klen;
		int    child;

		j_skip_ws(jp);
		if (jp->cur >= jp->end || *jp->cur != '"')
			return -1;
		jp->cur++;
		if (j_parse_string_raw(jp, &key, &klen) != 0)
			return -1;
		j_skip_ws(jp);
		if (jp->cur >= jp->end || *jp->cur != ':')
			return -1;
		jp->cur++;
		child = j_parse_value(jp);
		if (child < 0)
			return -1;
		jp->nodes[child].key  = key;
		jp->nodes[child].klen = klen;
		if (last < 0)
			jp->nodes[idx].child = child;
		else
			jp->nodes[last].next = child;
		last = child;
		j_skip_ws(jp);
		if (jp->cur >= jp->end)
			return -1;
		if (*jp->cur == ',') {
			jp->cur++;
			continue;
		}
		if (*jp->cur == '}') {
			jp->cur++;
			break;
		}
		return -1;
	}
	jp->depth--;
	return idx;
}

static int j_parse_value(struct jparse *jp)
{
	j_skip_ws(jp);
	if (jp->cur >= jp->end)
		return -1;
	switch (*jp->cur) {
	case '{': return j_parse_object(jp);
	case '[': return j_parse_array(jp);
	case '"': return j_parse_string(jp);
	case 't': return j_lit(jp, "true",  JK_BOOL, 1);
	case 'f': return j_lit(jp, "false", JK_BOOL, 0);
	case 'n': return j_lit(jp, "null",  JK_NULL, 0);
	default:  return j_parse_number(jp);
	}
}

static int j_obj_get(struct jparse *jp, int obj, const char *key)
{
	int    c;
	size_t kl;

	if (obj < 0 || jp->nodes[obj].kind != JK_OBJ)
		return -1;
	kl = strlen(key);
	for (c = jp->nodes[obj].child; c >= 0; c = jp->nodes[c].next) {
		if (jp->nodes[c].klen == kl &&
		    memcmp(jp->nodes[c].key, key, kl) == 0)
			return c;
	}
	return -1;
}

static const char *j_as_str(struct jparse *jp, int idx, size_t *len)
{
	if (idx < 0 || jp->nodes[idx].kind != JK_STR)
		return NULL;
	if (len)
		*len = jp->nodes[idx].slen;
	return jp->nodes[idx].str;
}

static int j_str_dup(struct jparse *jp, int idx, char *buf, size_t cap)
{
	size_t      len;
	const char *s = j_as_str(jp, idx, &len);

	if (!s || len >= cap)
		return -1;
	memcpy(buf, s, len);
	buf[len] = '\0';
	return 0;
}

static int j_as_u64(struct jparse *jp, int idx, __u64 *out)
{
	if (idx < 0)
		return -1;
	if (jp->nodes[idx].kind == JK_NUM) {
		*out = jp->nodes[idx].neg ? 0 : jp->nodes[idx].num;
		return 0;
	}
	if (jp->nodes[idx].kind == JK_STR) {
		char        tmp[32];
		const char *s = jp->nodes[idx].str;
		size_t      l = jp->nodes[idx].slen;

		if (l == 0 || l >= sizeof(tmp))
			return -1;
		memcpy(tmp, s, l);
		tmp[l] = '\0';
		if (caly_parse_u64(tmp, out) != 0)
			return -1;
		return 0;
	}
	return -1;
}

static int j_as_bool(struct jparse *jp, int idx, int *out)
{
	if (idx < 0)
		return -1;
	if (jp->nodes[idx].kind == JK_BOOL) {
		*out = jp->nodes[idx].bval;
		return 0;
	}
	if (jp->nodes[idx].kind == JK_NUM) {
		*out = jp->nodes[idx].num != 0;
		return 0;
	}
	return -1;
}

/* =========================================================================
 * Raw BPF map access (the daemon's world: fds from caly_bpf_map_fd).
 * ========================================================================= */

static int ctl_fd(const struct caly_bpf *b, int id)
{
	return caly_bpf_map_fd(b, id);
}

/* Collect every (key,value) pair from a hash/LPM map into malloc'd byte
 * arrays. Returns the count (>=0) or -1. Caller frees *keys and *vals. */
static long ctl_map_collect(int fd, size_t ksz, size_t vsz,
			    unsigned char **keys, unsigned char **vals)
{
	unsigned char curk[CTL_KEY_MAX], nextk[CTL_KEY_MAX], val[CTL_VAL_MAX];
	unsigned char *kbuf = NULL, *vbuf = NULL;
	size_t cap = 0, n = 0;
	int have = 0;

	*keys = NULL;
	*vals = NULL;
	if (ksz == 0 || ksz > CTL_KEY_MAX || vsz == 0 || vsz > CTL_VAL_MAX)
		return -1;
	while (bpf_map_get_next_key(fd, have ? curk : NULL, nextk) == 0) {
		if (bpf_map_lookup_elem(fd, nextk, val) == 0) {
			if (n == cap) {
				size_t nc = cap ? cap * 2 : 64;
				unsigned char *nk = realloc(kbuf, nc * ksz);
				unsigned char *nv;

				if (!nk) {
					free(kbuf);
					free(vbuf);
					return -1;
				}
				kbuf = nk;
				nv = realloc(vbuf, nc * vsz);
				if (!nv) {
					free(kbuf);
					free(vbuf);
					return -1;
				}
				vbuf = nv;
				cap = nc;
			}
			memcpy(kbuf + n * ksz, nextk, ksz);
			memcpy(vbuf + n * vsz, val, vsz);
			n++;
		}
		memcpy(curk, nextk, ksz);
		have = 1;
		if (n >= 2000000)   /* runaway guard */
			break;
	}
	*keys = kbuf;
	*vals = vbuf;
	return (long)n;
}

static int ctl_ban_add(const struct caly_bpf *b, const struct caly_cidr *c,
		       __u64 ttl, __u32 flags)
{
	__u64 now = caly_now_ns();
	struct ban_entry e;
	int fd;

	memset(&e, 0, sizeof(e));
	e.first_seen_ns = now;
	e.last_hit_ns   = now;
	e.cur_ttl_ns    = ttl;
	e.flags         = flags;
	e.offences      = 1;
	e.reason        = STAT_DROP_TOTAL;
	e.expiry_ns     = (flags & CALY_BAN_F_PERMANENT) ? 0 : now + ttl;

	if (c->family == CALY_UTIL_AF_INET) {
		__u32 k;

		fd = ctl_fd(b, CALY_MID_BAN4);
		if (fd < 0)
			return -1;
		memcpy(&k, c->addr, 4);
		return bpf_map_update_elem(fd, &k, &e, BPF_ANY);
	} else {
		struct in6_key k;

		fd = ctl_fd(b, CALY_MID_BAN6);
		if (fd < 0)
			return -1;
		memcpy(k.a, c->addr, 16);
		return bpf_map_update_elem(fd, &k, &e, BPF_ANY);
	}
}

static int ctl_ban_del(const struct caly_bpf *b, const struct caly_cidr *c)
{
	int fd;

	if (c->family == CALY_UTIL_AF_INET) {
		__u32 k;

		fd = ctl_fd(b, CALY_MID_BAN4);
		if (fd < 0)
			return -1;
		memcpy(&k, c->addr, 4);
		return bpf_map_delete_elem(fd, &k);
	} else {
		struct in6_key k;

		fd = ctl_fd(b, CALY_MID_BAN6);
		if (fd < 0)
			return -1;
		memcpy(k.a, c->addr, 16);
		return bpf_map_delete_elem(fd, &k);
	}
}

static int ctl_lpm_map_id(int set, int v6)
{
	switch (set) {
	case CTL_SET_ALLOW: return v6 ? CALY_MID_ALLOW6 : CALY_MID_ALLOW4;
	case CTL_SET_BLOCK: return v6 ? CALY_MID_BLOCK6 : CALY_MID_BLOCK4;
	default:            return v6 ? CALY_MID_LOCAL6 : CALY_MID_LOCAL4;
	}
}

static int ctl_set_del(const struct caly_bpf *b, int set,
		       const struct caly_cidr *c)
{
	int v6 = (c->family == CALY_UTIL_AF_INET6);
	int fd = ctl_fd(b, ctl_lpm_map_id(set, v6));

	if (fd < 0)
		return -1;
	if (v6) {
		struct lpm_key_v6 k;

		memset(&k, 0, sizeof(k));
		k.prefixlen = c->prefixlen;
		memcpy(k.addr, c->addr, 16);
		return bpf_map_delete_elem(fd, &k);
	} else {
		struct lpm_key_v4 k;

		memset(&k, 0, sizeof(k));
		k.prefixlen = c->prefixlen;
		memcpy(k.addr, c->addr, 4);
		return bpf_map_delete_elem(fd, &k);
	}
}

/* =========================================================================
 * CIDR argument helpers
 * ========================================================================= */

static __u32 ctl_arg_family(struct jparse *jp, int args)
{
	int    idx = j_obj_get(jp, args, "family");
	__u64  n;
	char   buf[16];

	if (idx < 0)
		return CTL_FAM_ANY;
	if (j_as_u64(jp, idx, &n) == 0) {
		if (n == 4)
			return CTL_FAM_V4;
		if (n == 6)
			return CTL_FAM_V6;
		return CTL_FAM_ANY;
	}
	if (j_str_dup(jp, idx, buf, sizeof(buf)) == 0) {
		if (caly_strcaseeq(buf, "4") || caly_strcaseeq(buf, "v4") ||
		    caly_strcaseeq(buf, "inet") || caly_strcaseeq(buf, "ipv4"))
			return CTL_FAM_V4;
		if (caly_strcaseeq(buf, "6") || caly_strcaseeq(buf, "v6") ||
		    caly_strcaseeq(buf, "inet6") || caly_strcaseeq(buf, "ipv6"))
			return CTL_FAM_V6;
	}
	return CTL_FAM_ANY;
}

static int ctl_arg_cidr(struct jparse *jp, int args, const char *key,
			struct caly_cidr *out, const char **code,
			const char **msg)
{
	int  idx = j_obj_get(jp, args, key);
	char buf[CALY_CIDR_STRLEN];

	/* calyctl spells the address "cidr"; calywatch spells it "addr". */
	if (idx < 0)
		idx = j_obj_get(jp, args, "addr");
	if (idx < 0)
		idx = j_obj_get(jp, args, "cidr");
	if (idx < 0 || j_str_dup(jp, idx, buf, sizeof(buf)) != 0) {
		*code = "bad_request";
		*msg  = "missing or oversized address ('cidr'/'addr')";
		return -1;
	}
	if (caly_parse_cidr(buf, out) != 0) {
		*code = "bad_request";
		*msg  = "malformed CIDR";
		return -1;
	}
	(void)caly_cidr_apply_mask(out);
	return 0;
}

static int ctl_is_default_route(const struct caly_cidr *c)
{
	return c->prefixlen == 0;
}

static int ctl_is_host(const struct caly_cidr *c)
{
	if (c->family == CALY_UTIL_AF_INET)
		return c->prefixlen == 32;
	return c->prefixlen == 128;
}

static void ctl_emit_cidr(struct sbuf *d, const struct caly_cidr *c)
{
	char buf[CALY_CIDR_STRLEN];

	if (caly_format_cidr(c, buf, sizeof(buf)) != 0)
		(void)caly_strlcpy(buf, "?", sizeof(buf));
	sb_jstrz(d, buf);
}

static void ctl_emit_addr(struct sbuf *d, __u32 family, const __u8 *addr)
{
	char buf[CALY_ADDR_STRLEN];

	if (caly_format_ip(family, addr, buf, sizeof(buf)) != 0)
		(void)caly_strlcpy(buf, "?", sizeof(buf));
	sb_jstrz(d, buf);
}

/* =========================================================================
 * Command handlers. Each appends the "data" VALUE to `d` and returns 0, or
 * returns -1 with the code and msg out-params set for an error response.
 * ========================================================================= */

static int h_ping(struct sbuf *d)
{
	sb_puts(d, "{\"pong\":true}");
	return 0;
}

static void ctl_emit_config(const struct fw_config *c, struct sbuf *d)
{
	int i;

	sb_putc(d, '{');
	sb_key(d, "abi_version");        sb_u64(d, c->abi_version);        sb_putc(d, ',');
	sb_key(d, "config_gen");         sb_u64(d, c->config_gen);         sb_putc(d, ',');
	sb_key(d, "flags");              sb_u64(d, c->flags);              sb_putc(d, ',');

	sb_key(d, "tb_rate"); sb_putc(d, '[');
	for (i = 0; i < CALY_TB_MAX; i++) {
		if (i) sb_putc(d, ',');
		sb_u64(d, c->tb_rate[i]);
	}
	sb_puts(d, "],");
	sb_key(d, "tb_burst"); sb_putc(d, '[');
	for (i = 0; i < CALY_TB_MAX; i++) {
		if (i) sb_putc(d, ',');
		sb_u64(d, c->tb_burst[i]);
	}
	sb_puts(d, "],");

	sb_key(d, "global_pps_hi");      sb_u64(d, c->global_pps_hi);      sb_putc(d, ',');
	sb_key(d, "global_pps_lo");      sb_u64(d, c->global_pps_lo);      sb_putc(d, ',');
	sb_key(d, "global_bps_hi");      sb_u64(d, c->global_bps_hi);      sb_putc(d, ',');
	sb_key(d, "global_bps_lo");      sb_u64(d, c->global_bps_lo);      sb_putc(d, ',');
	sb_key(d, "global_syn_pps_hi");  sb_u64(d, c->global_syn_pps_hi);  sb_putc(d, ',');
	sb_key(d, "global_syn_pps_lo");  sb_u64(d, c->global_syn_pps_lo);  sb_putc(d, ',');
	sb_key(d, "attack_dwell_ns");    sb_u64(d, c->attack_dwell_ns);    sb_putc(d, ',');
	sb_key(d, "syn_fallback_pps");   sb_u64(d, c->syn_fallback_pps);   sb_putc(d, ',');

	sb_key(d, "ban_ttl_base_ns");    sb_u64(d, c->ban_ttl_base_ns);    sb_putc(d, ',');
	sb_key(d, "ban_ttl_max_ns");     sb_u64(d, c->ban_ttl_max_ns);     sb_putc(d, ',');
	sb_key(d, "strike_window_ns");   sb_u64(d, c->strike_window_ns);   sb_putc(d, ',');
	sb_key(d, "scan_window_ns");     sb_u64(d, c->scan_window_ns);     sb_putc(d, ',');

	sb_key(d, "ct_tcp_est_ns");      sb_u64(d, c->ct_tcp_est_ns);      sb_putc(d, ',');
	sb_key(d, "ct_udp_ns");          sb_u64(d, c->ct_udp_ns);          sb_putc(d, ',');

	sb_key(d, "mode");               sb_u64(d, c->mode);               sb_putc(d, ',');
	sb_key(d, "strike_limit");       sb_u64(d, c->strike_limit);       sb_putc(d, ',');
	sb_key(d, "scan_port_threshold"); sb_u64(d, c->scan_port_threshold); sb_putc(d, ',');
	sb_key(d, "log_sample_rate");    sb_u64(d, c->log_sample_rate);    sb_putc(d, ',');
	sb_key(d, "log_level");          sb_u64(d, c->log_level);          sb_putc(d, ',');
	sb_key(d, "dataplane_pref");     sb_u64(d, c->dataplane_pref);     sb_putc(d, ',');

	sb_key(d, "mgmt_tcp_ports"); sb_putc(d, '[');
	for (i = 0; i < (int)c->mgmt_tcp_count && i < CALY_MGMT_PORTS_MAX; i++) {
		if (i) sb_putc(d, ',');
		sb_u64(d, c->mgmt_tcp_ports[i]);
	}
	sb_puts(d, "],");
	sb_key(d, "mgmt_udp_ports"); sb_putc(d, '[');
	for (i = 0; i < (int)c->mgmt_udp_count && i < CALY_MGMT_PORTS_MAX; i++) {
		if (i) sb_putc(d, ',');
		sb_u64(d, c->mgmt_udp_ports[i]);
	}
	sb_putc(d, ']');
	sb_putc(d, '}');
}

static __u64 ctl_count(const struct caly_bpf *b, int id)
{
	long n = caly_bpf_map_count(b, id);

	return n < 0 ? 0 : (__u64)n;
}

static int h_status(const struct caly_ctl_env *env, struct sbuf *d)
{
	__u64 now = caly_wall_ns();
	__u64 uptime = (now > env->start_wall_ns) ? now - env->start_wall_ns : 0;
	__u32 best_dp = CALY_DP_AUTO;
	int   i;

	sb_putc(d, '{');
	sb_key(d, "version");   sb_jstrz(d, env->version ? env->version : "?"); sb_putc(d, ',');
	sb_key(d, "pid");       sb_i64(d, (long long)env->pid);                 sb_putc(d, ',');
	sb_key(d, "uptime_ns"); sb_u64(d, uptime);                             sb_putc(d, ',');
	sb_key(d, "mode");      sb_u64(d, *env->cur_mode);                     sb_putc(d, ',');
	sb_key(d, "base_mode"); sb_u64(d, *env->base_mode);                    sb_putc(d, ',');
	sb_key(d, "synproxy");  sb_puts(d, env->synproxy_loaded ? "true" : "false"); sb_putc(d, ',');
	sb_key(d, "ringbuf");   sb_puts(d, env->ringbuf_active ? "true" : "false"); sb_putc(d, ',');
	sb_key(d, "events_seen"); sb_u64(d, env->events_seen ? *env->events_seen : 0); sb_putc(d, ',');
	sb_key(d, "events_lost"); sb_u64(d, env->events_lost ? *env->events_lost : 0); sb_putc(d, ',');

	sb_key(d, "interfaces"); sb_putc(d, '[');
	for (i = 0; i < env->nlink; i++) {
		const struct caly_link *l = &env->links[i];

		if (i) sb_putc(d, ',');
		sb_putc(d, '{');
		sb_key(d, "name");      sb_jstrz(d, l->ifname);           sb_putc(d, ',');
		sb_key(d, "ifindex");   sb_u64(d, l->ifindex);            sb_putc(d, ',');
		sb_key(d, "dataplane"); sb_jstrz(d, ctl_dataplane_str(l->dataplane)); sb_putc(d, ',');
		sb_key(d, "attached");  sb_puts(d, l->xdp_attached ? "true" : "false"); sb_putc(d, ',');
		sb_key(d, "tc");        sb_puts(d, l->tc_attached ? "true" : "false"); sb_putc(d, ',');
		sb_key(d, "prog_id");   sb_u64(d, l->prog_id);
		sb_putc(d, '}');
		if (l->dataplane != CALY_DP_AUTO &&
		    (best_dp == CALY_DP_AUTO || l->dataplane < best_dp))
			best_dp = l->dataplane;
	}
	sb_puts(d, "],");
	sb_key(d, "dataplane"); sb_jstrz(d, ctl_dataplane_str(best_dp)); sb_putc(d, ',');
	sb_key(d, "xdp_mode");  sb_jstrz(d, ctl_dataplane_str(best_dp)); sb_putc(d, ',');

	sb_key(d, "counts"); sb_putc(d, '{');
	sb_key(d, "bans");  sb_u64(d, ctl_count(env->bpf, CALY_MID_BAN4) +
					ctl_count(env->bpf, CALY_MID_BAN6)); sb_putc(d, ',');
	sb_key(d, "allow"); sb_u64(d, ctl_count(env->bpf, CALY_MID_ALLOW4) +
					ctl_count(env->bpf, CALY_MID_ALLOW6)); sb_putc(d, ',');
	sb_key(d, "block"); sb_u64(d, ctl_count(env->bpf, CALY_MID_BLOCK4) +
					ctl_count(env->bpf, CALY_MID_BLOCK6)); sb_putc(d, ',');
	sb_key(d, "local"); sb_u64(d, ctl_count(env->bpf, CALY_MID_LOCAL4) +
					ctl_count(env->bpf, CALY_MID_LOCAL6)); sb_putc(d, ',');
	sb_key(d, "conn");  sb_u64(d, ctl_count(env->bpf, CALY_MID_CONN));  sb_putc(d, ',');
	sb_key(d, "rate");  sb_u64(d, ctl_count(env->bpf, CALY_MID_RATE4) +
					ctl_count(env->bpf, CALY_MID_RATE6)); sb_putc(d, ',');
	sb_key(d, "scan");  sb_u64(d, ctl_count(env->bpf, CALY_MID_SCAN4) +
					ctl_count(env->bpf, CALY_MID_SCAN6));
	sb_puts(d, "},");

	sb_key(d, "config"); ctl_emit_config(env->cfg, d);
	sb_putc(d, '}');
	return 0;
}

static int h_stats(const struct caly_ctl_env *env, struct sbuf *d,
		   const char **code, const char **msg)
{
	__u64 *pkts, *bytes, gauges[CALY_G_MAX];
	int    i;

	pkts = calloc(STAT_MAX, sizeof(*pkts));
	bytes = calloc(STAT_MAX, sizeof(*bytes));
	if (!pkts || !bytes) {
		free(pkts);
		free(bytes);
		*code = "internal";
		*msg  = "out of memory";
		return -1;
	}
	if (caly_bpf_read_stats(env->bpf, pkts, bytes, STAT_MAX) != 0) {
		free(pkts);
		free(bytes);
		*code = "internal";
		*msg  = "cannot read the statistics map";
		return -1;
	}
	memset(gauges, 0, sizeof(gauges));
	(void)caly_bpf_read_gauges(env->bpf, gauges, CALY_G_MAX);

	sb_putc(d, '{');
	sb_key(d, "ts_ns"); sb_u64(d, caly_wall_ns()); sb_putc(d, ',');
	sb_key(d, "packets"); sb_putc(d, '[');
	for (i = 0; i < STAT_MAX; i++) {
		if (i) sb_putc(d, ',');
		sb_u64(d, pkts[i]);
	}
	sb_puts(d, "],");
	sb_key(d, "bytes"); sb_putc(d, '[');
	for (i = 0; i < STAT_MAX; i++) {
		if (i) sb_putc(d, ',');
		sb_u64(d, bytes[i]);
	}
	sb_puts(d, "],");
	sb_key(d, "gauges"); sb_putc(d, '[');
	for (i = 0; i < CALY_G_MAX; i++) {
		if (i) sb_putc(d, ',');
		sb_u64(d, gauges[i]);
	}
	sb_putc(d, ']');
	sb_putc(d, '}');
	free(pkts);
	free(bytes);
	return 0;
}

/* --- top talkers ------------------------------------------------------- */

struct ctl_top_row {
	__u32            family;
	__u8             addr[16];
	struct src_stats st;
};

static int ctl_top_sort_field;   /* single-threaded daemon; safe file scope */

static int ctl_top_cmp(const void *a, const void *b)
{
	const struct ctl_top_row *x = a;
	const struct ctl_top_row *y = b;
	__u64 xa, ya;

	switch (ctl_top_sort_field) {
	case 1: xa = x->st.bytes;         ya = y->st.bytes;         break;
	case 2: xa = x->st.drops;         ya = y->st.drops;         break;
	case 3: xa = x->st.drop_bytes;    ya = y->st.drop_bytes;    break;
	case 4: xa = x->st.last_seen_ns;  ya = y->st.last_seen_ns;  break;
	default: xa = x->st.packets;      ya = y->st.packets;       break;
	}
	if (xa < ya) return 1;   /* descending */
	if (xa > ya) return -1;
	return 0;
}

static int ctl_top_gather(const struct caly_bpf *b, int mapid, int v6,
			  struct ctl_top_row **rows, size_t *n, size_t *cap)
{
	unsigned char *keys = NULL, *vals = NULL;
	size_t ksz = v6 ? sizeof(struct in6_key) : sizeof(__u32);
	long cnt, j;
	int fd = ctl_fd(b, mapid);

	if (fd < 0)
		return 0;
	cnt = ctl_map_collect(fd, ksz, sizeof(struct src_stats), &keys, &vals);
	if (cnt < 0)
		return -1;
	for (j = 0; j < cnt; j++) {
		struct ctl_top_row *r;

		if (*n == *cap) {
			size_t nc = *cap ? *cap * 2 : 64;
			struct ctl_top_row *nr = realloc(*rows, nc * sizeof(*nr));

			if (!nr) {
				free(keys);
				free(vals);
				return -1;
			}
			*rows = nr;
			*cap = nc;
		}
		r = &(*rows)[*n];
		memset(r, 0, sizeof(*r));
		r->family = v6 ? CALY_UTIL_AF_INET6 : CALY_UTIL_AF_INET;
		memcpy(r->addr, keys + (size_t)j * ksz, v6 ? 16 : 4);
		memcpy(&r->st, vals + (size_t)j * sizeof(struct src_stats),
		       sizeof(struct src_stats));
		(*n)++;
	}
	free(keys);
	free(vals);
	return 0;
}

static int h_top(const struct caly_ctl_env *env, struct sbuf *d,
		 struct jparse *jp, int args, const char **code,
		 const char **msg)
{
	struct ctl_top_row *rows = NULL;
	size_t n = 0, cap = 0, i;
	__u64  limit = 20;
	__u32  fam = ctl_arg_family(jp, args);
	int    idx;

	idx = j_obj_get(jp, args, "n");
	if (idx >= 0)
		(void)j_as_u64(jp, idx, &limit);
	if (limit == 0 || limit > 100000)
		limit = 100000;

	ctl_top_sort_field = 0;
	idx = j_obj_get(jp, args, "sort");
	if (idx >= 0) {
		char sbuf[16];

		if (j_str_dup(jp, idx, sbuf, sizeof(sbuf)) == 0) {
			if (caly_strcaseeq(sbuf, "bytes"))
				ctl_top_sort_field = 1;
			else if (caly_strcaseeq(sbuf, "drops"))
				ctl_top_sort_field = 2;
			else if (caly_strcaseeq(sbuf, "drop_bytes"))
				ctl_top_sort_field = 3;
			else if (caly_strcaseeq(sbuf, "last_seen"))
				ctl_top_sort_field = 4;
		}
	}

	if (fam != CTL_FAM_V6 &&
	    ctl_top_gather(env->bpf, CALY_MID_TOP4, 0, &rows, &n, &cap) != 0) {
		free(rows);
		*code = "internal";
		*msg  = "top-talker query failed";
		return -1;
	}
	if (fam != CTL_FAM_V4 &&
	    ctl_top_gather(env->bpf, CALY_MID_TOP6, 1, &rows, &n, &cap) != 0) {
		free(rows);
		*code = "internal";
		*msg  = "top-talker query failed";
		return -1;
	}
	if (n > 1)
		qsort(rows, n, sizeof(*rows), ctl_top_cmp);

	sb_puts(d, "{\"sources\":[");
	for (i = 0; i < n && i < limit; i++) {
		const struct ctl_top_row *r = &rows[i];

		if (i) sb_putc(d, ',');
		sb_putc(d, '{');
		sb_key(d, "addr"); ctl_emit_addr(d, r->family, r->addr); sb_putc(d, ',');
		sb_key(d, "family"); sb_u64(d, r->family); sb_putc(d, ',');
		sb_key(d, "packets"); sb_u64(d, r->st.packets); sb_putc(d, ',');
		sb_key(d, "bytes"); sb_u64(d, r->st.bytes); sb_putc(d, ',');
		sb_key(d, "drops"); sb_u64(d, r->st.drops); sb_putc(d, ',');
		sb_key(d, "drop_bytes"); sb_u64(d, r->st.drop_bytes); sb_putc(d, ',');
		sb_key(d, "first_seen_ns"); sb_u64(d, r->st.first_seen_ns); sb_putc(d, ',');
		sb_key(d, "last_seen_ns"); sb_u64(d, r->st.last_seen_ns); sb_putc(d, ',');
		sb_key(d, "last_reason"); sb_u64(d, r->st.last_reason);
		sb_putc(d, '}');
	}
	sb_puts(d, "]}");
	free(rows);
	return 0;
}

/* --- lists (bans / allow / block / local) ------------------------------ */

static int h_list_bans(const struct caly_ctl_env *env, struct sbuf *d,
		       int mapid, int v6, int first)
{
	unsigned char *keys = NULL, *vals = NULL;
	size_t ksz = v6 ? sizeof(struct in6_key) : sizeof(__u32);
	long cnt, j;
	int fd = ctl_fd(env->bpf, mapid);

	if (fd < 0)
		return first;
	cnt = ctl_map_collect(fd, ksz, sizeof(struct ban_entry), &keys, &vals);
	if (cnt < 0)
		return first;
	for (j = 0; j < cnt; j++) {
		const struct ban_entry *e =
			(const struct ban_entry *)(vals + (size_t)j * sizeof(*e));
		__u8 addr[16];

		memset(addr, 0, sizeof(addr));
		memcpy(addr, keys + (size_t)j * ksz, v6 ? 16 : 4);

		if (!first) sb_putc(d, ',');
		first = 0;
		sb_putc(d, '{');
		sb_key(d, "cidr");
		ctl_emit_addr(d, v6 ? CALY_UTIL_AF_INET6 : CALY_UTIL_AF_INET, addr);
		sb_putc(d, ',');
		sb_key(d, "family"); sb_u64(d, v6 ? 6 : 4); sb_putc(d, ',');
		sb_key(d, "expiry_ns"); sb_u64(d, e->expiry_ns); sb_putc(d, ',');
		sb_key(d, "first_seen_ns"); sb_u64(d, e->first_seen_ns); sb_putc(d, ',');
		sb_key(d, "last_hit_ns"); sb_u64(d, e->last_hit_ns); sb_putc(d, ',');
		sb_key(d, "cur_ttl_ns"); sb_u64(d, e->cur_ttl_ns); sb_putc(d, ',');
		sb_key(d, "hit_pkts"); sb_u64(d, e->hit_pkts); sb_putc(d, ',');
		sb_key(d, "hit_bytes"); sb_u64(d, e->hit_bytes); sb_putc(d, ',');
		sb_key(d, "reason"); sb_u64(d, e->reason); sb_putc(d, ',');
		sb_key(d, "strikes"); sb_u64(d, e->strikes); sb_putc(d, ',');
		sb_key(d, "offences"); sb_u64(d, e->offences); sb_putc(d, ',');
		sb_key(d, "flags"); sb_u64(d, e->flags);
		sb_putc(d, '}');
	}
	free(keys);
	free(vals);
	return first;
}

static int h_list_lpm(const struct caly_ctl_env *env, struct sbuf *d,
		      int mapid, int v6, int first)
{
	unsigned char *keys = NULL, *vals = NULL;
	size_t ksz = v6 ? sizeof(struct lpm_key_v6) : sizeof(struct lpm_key_v4);
	long cnt, j;
	int fd = ctl_fd(env->bpf, mapid);

	if (fd < 0)
		return first;
	cnt = ctl_map_collect(fd, ksz, sizeof(struct rule_meta), &keys, &vals);
	if (cnt < 0)
		return first;
	for (j = 0; j < cnt; j++) {
		const struct rule_meta *m =
			(const struct rule_meta *)(vals + (size_t)j * sizeof(*m));
		struct caly_cidr c;

		memset(&c, 0, sizeof(c));
		if (v6) {
			const struct lpm_key_v6 *k =
				(const struct lpm_key_v6 *)(keys + (size_t)j * ksz);
			c.family = CALY_UTIL_AF_INET6;
			c.prefixlen = k->prefixlen;
			memcpy(c.addr, k->addr, 16);
		} else {
			const struct lpm_key_v4 *k =
				(const struct lpm_key_v4 *)(keys + (size_t)j * ksz);
			c.family = CALY_UTIL_AF_INET;
			c.prefixlen = k->prefixlen;
			memcpy(c.addr, k->addr, 4);
		}

		if (!first) sb_putc(d, ',');
		first = 0;
		sb_putc(d, '{');
		sb_key(d, "cidr"); ctl_emit_cidr(d, &c); sb_putc(d, ',');
		sb_key(d, "family"); sb_u64(d, v6 ? 6 : 4); sb_putc(d, ',');
		sb_key(d, "flags"); sb_u64(d, m->flags); sb_putc(d, ',');
		sb_key(d, "tag"); sb_u64(d, m->tag); sb_putc(d, ',');
		sb_key(d, "added_ns"); sb_u64(d, m->added_ns); sb_putc(d, ',');
		sb_key(d, "hits"); sb_u64(d, m->hits);
		sb_putc(d, '}');
	}
	free(keys);
	free(vals);
	return first;
}

static int h_list(const struct caly_ctl_env *env, struct sbuf *d,
		  struct jparse *jp, int args, const char **code,
		  const char **msg)
{
	char what[16];
	int  idx = j_obj_get(jp, args, "what");
	int  first = 1;

	if (idx < 0 || j_str_dup(jp, idx, what, sizeof(what)) != 0) {
		*code = "bad_request";
		*msg  = "missing 'what' (allow|block|local|bans)";
		return -1;
	}

	sb_puts(d, "{\"entries\":[");
	if (caly_strcaseeq(what, "bans")) {
		first = h_list_bans(env, d, CALY_MID_BAN4, 0, first);
		first = h_list_bans(env, d, CALY_MID_BAN6, 1, first);
	} else if (caly_strcaseeq(what, "allow")) {
		first = h_list_lpm(env, d, CALY_MID_ALLOW4, 0, first);
		first = h_list_lpm(env, d, CALY_MID_ALLOW6, 1, first);
	} else if (caly_strcaseeq(what, "block")) {
		first = h_list_lpm(env, d, CALY_MID_BLOCK4, 0, first);
		first = h_list_lpm(env, d, CALY_MID_BLOCK6, 1, first);
	} else if (caly_strcaseeq(what, "local")) {
		first = h_list_lpm(env, d, CALY_MID_LOCAL4, 0, first);
		first = h_list_lpm(env, d, CALY_MID_LOCAL6, 1, first);
	} else {
		*code = "bad_request";
		*msg  = "unknown list; use allow|block|local|bans";
		return -1;
	}
	(void)first;
	sb_puts(d, "]}");
	return 0;
}

static int h_ban(const struct caly_ctl_env *env, struct sbuf *d,
		 struct jparse *jp, int args, const char **code,
		 const char **msg)
{
	struct caly_cidr c;
	__u64  ttl = 0;
	__u32  flags = CALY_BAN_F_MANUAL;
	int    permanent = 0;
	int    idx;

	if (ctl_arg_cidr(jp, args, "cidr", &c, code, msg) != 0)
		return -1;
	if (ctl_is_default_route(&c)) {
		*code = "refused";
		*msg  = "refusing to ban the default route";
		return -1;
	}
	if (!ctl_is_host(&c)) {
		*code = "bad_request";
		*msg  = "ban requires a host address (/32 or /128)";
		return -1;
	}
	idx = j_obj_get(jp, args, "permanent");
	if (idx >= 0)
		(void)j_as_bool(jp, idx, &permanent);
	if (permanent)
		flags |= CALY_BAN_F_PERMANENT;

	idx = j_obj_get(jp, args, "ttl_ns");
	if (idx >= 0)
		(void)j_as_u64(jp, idx, &ttl);
	else if (!permanent)
		ttl = env->cfg->ban_ttl_base_ns;

	if (ctl_ban_add(env->bpf, &c, ttl, flags) != 0) {
		*code = "internal";
		*msg  = "ban insert failed";
		return -1;
	}
	sb_puts(d, "{\"changed\":1}");
	return 0;
}

static int h_unban(const struct caly_ctl_env *env, struct sbuf *d,
		   struct jparse *jp, int args, const char **code,
		   const char **msg)
{
	struct caly_cidr c;
	int rc;

	if (ctl_arg_cidr(jp, args, "cidr", &c, code, msg) != 0)
		return -1;
	rc = ctl_ban_del(env->bpf, &c);
	sb_puts(d, "{\"changed\":");
	sb_u64(d, (rc == 0) ? 1 : 0);
	sb_putc(d, '}');
	return 0;
}

static int h_set_add(const struct caly_ctl_env *env, struct sbuf *d,
		     struct jparse *jp, int args, int set,
		     const char **code, const char **msg)
{
	struct caly_cidr c;
	int v6, rc;

	if (ctl_arg_cidr(jp, args, "cidr", &c, code, msg) != 0)
		return -1;
	if (set == CTL_SET_BLOCK && ctl_is_default_route(&c)) {
		*code = "refused";
		*msg  = "refusing to blocklist the default route";
		return -1;
	}
	v6 = (c.family == CALY_UTIL_AF_INET6);
	rc = caly_lpm_insert(env->bpf, ctl_lpm_map_id(set, v6), &c, 0,
			     CALY_TAG_CLI);
	if (rc != 0 && rc != -EEXIST) {
		*code = "internal";
		*msg  = "set insert failed";
		return -1;
	}
	sb_puts(d, "{\"changed\":1}");
	return 0;
}

static int h_set_del(const struct caly_ctl_env *env, struct sbuf *d,
		     struct jparse *jp, int args, int set,
		     const char **code, const char **msg)
{
	struct caly_cidr c;
	int rc;

	if (ctl_arg_cidr(jp, args, "cidr", &c, code, msg) != 0)
		return -1;
	rc = ctl_set_del(env->bpf, set, &c);
	sb_puts(d, "{\"changed\":");
	sb_u64(d, (rc == 0) ? 1 : 0);
	sb_putc(d, '}');
	return 0;
}

static int h_mode(const struct caly_ctl_env *env, struct sbuf *d,
		  struct jparse *jp, int args, const char **code,
		  const char **msg)
{
	__u64 mode = 0;
	int   idx = j_obj_get(jp, args, "mode");

	if (idx < 0 || j_as_u64(jp, idx, &mode) != 0) {
		*code = "bad_request";
		*msg  = "missing integer 'mode'";
		return -1;
	}
	if (mode > FW_MODE_MONITOR_ONLY) {
		*code = "bad_request";
		*msg  = "mode out of range (0..4)";
		return -1;
	}
	env->cfg->mode  = (__u32)mode;
	*env->base_mode = (__u32)mode;
	*env->cur_mode  = (__u32)mode;
	if (caly_bpf_config_write(env->bpf, env->cfg) != 0) {
		*code = "internal";
		*msg  = "cannot write the config map";
		return -1;
	}
	sb_puts(d, "{\"changed\":1,\"mode\":");
	sb_u64(d, mode);
	sb_putc(d, '}');
	return 0;
}

static int h_port(const struct caly_ctl_env *env, struct sbuf *d,
		  struct jparse *jp, int args, const char **code,
		  const char **msg)
{
	char   proto[8];
	int    is_udp, fd, p, idx;
	__u64  first = 0, last = 0, rate = 0, burst = 0;
	char   action[16];
	struct port_rule pr;
	__u32  changed = 0;

	idx = j_obj_get(jp, args, "proto");
	if (idx < 0 || j_str_dup(jp, idx, proto, sizeof(proto)) != 0) {
		*code = "bad_request";
		*msg  = "missing 'proto' (tcp|udp)";
		return -1;
	}
	if (caly_strcaseeq(proto, "tcp"))
		is_udp = 0;
	else if (caly_strcaseeq(proto, "udp"))
		is_udp = 1;
	else {
		*code = "bad_request";
		*msg  = "proto must be tcp or udp";
		return -1;
	}

	idx = j_obj_get(jp, args, "first");
	if (idx < 0 || j_as_u64(jp, idx, &first) != 0) {
		*code = "bad_request";
		*msg  = "missing 'first' port";
		return -1;
	}
	idx = j_obj_get(jp, args, "last");
	if (idx < 0 || j_as_u64(jp, idx, &last) != 0)
		last = first;
	if (first > 65535 || last > 65535 || last < first) {
		*code = "bad_request";
		*msg  = "port range out of bounds";
		return -1;
	}

	idx = j_obj_get(jp, args, "action");
	if (idx < 0 || j_str_dup(jp, idx, action, sizeof(action)) != 0) {
		*code = "bad_request";
		*msg  = "missing 'action' (open|close|limit)";
		return -1;
	}
	memset(&pr, 0, sizeof(pr));
	pr.flags = CALY_PORT_F_PRESENT;
	if (caly_strcaseeq(action, "open")) {
		pr.mode = CALY_PORT_OPEN;
	} else if (caly_strcaseeq(action, "close") ||
		   caly_strcaseeq(action, "closed")) {
		pr.mode = CALY_PORT_CLOSED;
	} else if (caly_strcaseeq(action, "limit") ||
		   caly_strcaseeq(action, "ratelimit")) {
		pr.mode = CALY_PORT_RATELIMIT;
		idx = j_obj_get(jp, args, "rate");
		if (idx >= 0)
			(void)j_as_u64(jp, idx, &rate);
		idx = j_obj_get(jp, args, "burst");
		if (idx >= 0)
			(void)j_as_u64(jp, idx, &burst);
		pr.rate = rate;
		pr.burst = burst ? burst : rate;
	} else {
		*code = "bad_request";
		*msg  = "action must be open, close or limit";
		return -1;
	}

	fd = ctl_fd(env->bpf, is_udp ? CALY_MID_PORT_UDP : CALY_MID_PORT_TCP);
	if (fd < 0) {
		*code = "internal";
		*msg  = "port map unavailable";
		return -1;
	}
	for (p = (int)first; p <= (int)last; p++) {
		__u32 key = (__u32)p;

		if (bpf_map_update_elem(fd, &key, &pr, BPF_ANY) == 0)
			changed++;
	}
	sb_puts(d, "{\"changed\":");
	sb_u64(d, changed);
	sb_putc(d, '}');
	return 0;
}

static __u32 ctl_proto_num(const char *s)
{
	if (caly_strcaseeq(s, "tcp"))
		return CALY_IPPROTO_TCP;
	if (caly_strcaseeq(s, "udp"))
		return CALY_IPPROTO_UDP;
	if (caly_strcaseeq(s, "icmp"))
		return CALY_IPPROTO_ICMP;
	if (caly_strcaseeq(s, "icmpv6") || caly_strcaseeq(s, "icmp6"))
		return CALY_IPPROTO_ICMPV6;
	return 0;
}

static int h_conntrack(const struct caly_ctl_env *env, struct sbuf *d,
		       struct jparse *jp, int args, const char **code,
		       const char **msg)
{
	unsigned char *keys = NULL, *vals = NULL;
	long cnt, j;
	size_t emitted = 0;
	__u64  limit = 50;
	__u32  want_proto = 0;
	int    idx, fd;

	idx = j_obj_get(jp, args, "limit");
	if (idx >= 0)
		(void)j_as_u64(jp, idx, &limit);
	if (limit == 0 || limit > 100000)
		limit = 100000;

	idx = j_obj_get(jp, args, "proto");
	if (idx >= 0) {
		char pbuf[8];

		if (j_str_dup(jp, idx, pbuf, sizeof(pbuf)) == 0)
			want_proto = ctl_proto_num(pbuf);
	}

	fd = ctl_fd(env->bpf, CALY_MID_CONN);
	sb_puts(d, "{\"flows\":[");
	if (fd < 0) {
		sb_puts(d, "]}");
		return 0;
	}
	cnt = ctl_map_collect(fd, sizeof(struct conn_key),
			      sizeof(struct conn_state), &keys, &vals);
	if (cnt < 0) {
		*code = "internal";
		*msg  = "conntrack dump failed";
		return -1;
	}
	for (j = 0; j < cnt && emitted < limit; j++) {
		const struct conn_key   *k =
			(const struct conn_key *)(keys + (size_t)j * sizeof(*k));
		const struct conn_state *st =
			(const struct conn_state *)(vals + (size_t)j * sizeof(*st));
		__u32 fam = (k->family == CALY_AF_INET) ?
			    CALY_UTIL_AF_INET : CALY_UTIL_AF_INET6;
		__u8 saddr[16], daddr[16];

		if (want_proto && k->proto != want_proto)
			continue;
		memset(saddr, 0, sizeof(saddr));
		memset(daddr, 0, sizeof(daddr));
		if (k->family == CALY_AF_INET) {
			memcpy(saddr, &k->saddr[0], 4);
			memcpy(daddr, &k->daddr[0], 4);
		} else {
			memcpy(saddr, k->saddr, 16);
			memcpy(daddr, k->daddr, 16);
		}

		if (emitted) sb_putc(d, ',');
		sb_putc(d, '{');
		sb_key(d, "family"); sb_u64(d, k->family); sb_putc(d, ',');
		sb_key(d, "proto"); sb_u64(d, k->proto); sb_putc(d, ',');
		sb_key(d, "saddr"); ctl_emit_addr(d, fam, saddr); sb_putc(d, ',');
		sb_key(d, "sport"); sb_u64(d, ntohs(k->sport)); sb_putc(d, ',');
		sb_key(d, "daddr"); ctl_emit_addr(d, fam, daddr); sb_putc(d, ',');
		sb_key(d, "dport"); sb_u64(d, ntohs(k->dport)); sb_putc(d, ',');
		sb_key(d, "state"); sb_u64(d, st->state); sb_putc(d, ',');
		sb_key(d, "flags"); sb_u64(d, st->flags); sb_putc(d, ',');
		sb_key(d, "pkts_in"); sb_u64(d, st->pkts_in); sb_putc(d, ',');
		sb_key(d, "bytes_in"); sb_u64(d, st->bytes_in); sb_putc(d, ',');
		sb_key(d, "pkts_out"); sb_u64(d, st->pkts_out); sb_putc(d, ',');
		sb_key(d, "bytes_out"); sb_u64(d, st->bytes_out); sb_putc(d, ',');
		sb_key(d, "created_ns"); sb_u64(d, st->created_ns); sb_putc(d, ',');
		sb_key(d, "last_seen_ns"); sb_u64(d, st->last_seen_ns); sb_putc(d, ',');
		sb_key(d, "ifindex"); sb_u64(d, st->ifindex);
		sb_putc(d, '}');
		emitted++;
	}
	free(keys);
	free(vals);
	sb_puts(d, "]}");
	return 0;
}

static int ctl_ban_flush_one(const struct caly_bpf *b, int mapid, size_t ksz,
			     size_t *removed)
{
	unsigned char *keys = NULL, *vals = NULL;
	long cnt, j;
	int fd = ctl_fd(b, mapid);

	if (fd < 0)
		return 0;
	cnt = ctl_map_collect(fd, ksz, sizeof(struct ban_entry), &keys, &vals);
	if (cnt < 0)
		return -1;
	for (j = 0; j < cnt; j++) {
		if (bpf_map_delete_elem(fd, keys + (size_t)j * ksz) == 0)
			(*removed)++;
	}
	free(keys);
	free(vals);
	return 0;
}

static int h_unban_all(const struct caly_ctl_env *env, struct sbuf *d,
		       const char **code, const char **msg)
{
	size_t removed = 0;

	if (ctl_ban_flush_one(env->bpf, CALY_MID_BAN4, sizeof(__u32),
			      &removed) != 0 ||
	    ctl_ban_flush_one(env->bpf, CALY_MID_BAN6, sizeof(struct in6_key),
			      &removed) != 0) {
		*code = "internal";
		*msg  = "ban flush failed";
		return -1;
	}
	sb_puts(d, "{\"changed\":");
	sb_u64(d, removed);
	sb_putc(d, '}');
	return 0;
}

static int h_reload(const struct caly_ctl_env *env, struct sbuf *d)
{
	if (env->reload_pending)
		*env->reload_pending = 1;
	sb_puts(d, "{\"config_gen\":");
	sb_u64(d, env->cfg->config_gen);
	sb_putc(d, '}');
	return 0;
}

static int h_subscribe(struct sbuf *d)
{
	sb_puts(d, "{\"streams\":[\"events\"]}");
	return 0;
}

/* =========================================================================
 * Response helpers + dispatch
 * ========================================================================= */

static void ctl_send_raw(int fd, const char *buf, size_t len)
{
	(void)caly_write_all(fd, buf, len);
}

static void ctl_send_err(int fd, __u64 id, const char *code, const char *msg)
{
	struct sbuf s;

	sb_init(&s);
	sb_puts(&s, "{\"id\":");
	sb_u64(&s, id);
	sb_puts(&s, ",\"ok\":false,\"error\":");
	sb_jstrz(&s, msg ? msg : "error");
	sb_puts(&s, ",\"code\":");
	sb_jstrz(&s, code ? code : "error");
	sb_puts(&s, "}\n");
	if (!s.err)
		ctl_send_raw(fd, s.buf, s.len);
	sb_free(&s);
}

enum caly_ctl_action caly_ctl_dispatch(const struct caly_ctl_env *env, int fd,
				       const char *line, size_t len)
{
	struct jparse *jp;
	char          *copy;
	int            root, cmd_idx, args, hrc;
	__u64          id = 0;
	char           cmd[32];
	const char    *code = "internal";
	const char    *msg = "internal error";
	struct sbuf    data;
	int            subscribed = 0;

	while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
		len--;
	if (len == 0)
		return CALY_CTL_CONTINUE;

	copy = malloc(len + 1);
	jp = calloc(1, sizeof(*jp));
	if (!copy || !jp) {
		free(copy);
		free(jp);
		ctl_send_err(fd, 0, "internal", "out of memory");
		return CALY_CTL_CONTINUE;
	}
	memcpy(copy, line, len);
	copy[len] = '\0';
	jp->cur = copy;
	jp->end = copy + len;

	root = j_parse_value(jp);
	j_skip_ws(jp);
	if (root < 0 || jp->nodes[root].kind != JK_OBJ) {
		ctl_send_err(fd, 0, "bad_request", "request is not a JSON object");
		free(copy);
		free(jp);
		return CALY_CTL_CONTINUE;
	}

	{
		int iid = j_obj_get(jp, root, "id");

		if (iid >= 0)
			(void)j_as_u64(jp, iid, &id);
	}
	cmd_idx = j_obj_get(jp, root, "cmd");
	if (cmd_idx < 0 || j_str_dup(jp, cmd_idx, cmd, sizeof(cmd)) != 0) {
		ctl_send_err(fd, id, "bad_request", "missing 'cmd'");
		free(copy);
		free(jp);
		return CALY_CTL_CONTINUE;
	}

	/* calyctl nests parameters under "args"; calywatch puts them flat at the
	 * top level. Fall back to the root when there is no explicit args. */
	args = j_obj_get(jp, root, "args");
	if (args < 0)
		args = root;

	sb_init(&data);

	if (caly_strcaseeq(cmd, "ping")) {
		hrc = h_ping(&data);
	} else if (caly_strcaseeq(cmd, "status")) {
		hrc = h_status(env, &data);
	} else if (caly_strcaseeq(cmd, "stats")) {
		hrc = h_stats(env, &data, &code, &msg);
	} else if (caly_strcaseeq(cmd, "top")) {
		hrc = h_top(env, &data, jp, args, &code, &msg);
	} else if (caly_strcaseeq(cmd, "list")) {
		hrc = h_list(env, &data, jp, args, &code, &msg);
	} else if (caly_strcaseeq(cmd, "ban")) {
		hrc = h_ban(env, &data, jp, args, &code, &msg);
	} else if (caly_strcaseeq(cmd, "unban")) {
		hrc = h_unban(env, &data, jp, args, &code, &msg);
	} else if (caly_strcaseeq(cmd, "unban_all") ||
		   caly_strcaseeq(cmd, "unban-all") ||
		   caly_strcaseeq(cmd, "flush")) {
		hrc = h_unban_all(env, &data, &code, &msg);
	} else if (caly_strcaseeq(cmd, "allow")) {
		hrc = h_set_add(env, &data, jp, args, CTL_SET_ALLOW, &code, &msg);
	} else if (caly_strcaseeq(cmd, "unallow")) {
		hrc = h_set_del(env, &data, jp, args, CTL_SET_ALLOW, &code, &msg);
	} else if (caly_strcaseeq(cmd, "block")) {
		hrc = h_set_add(env, &data, jp, args, CTL_SET_BLOCK, &code, &msg);
	} else if (caly_strcaseeq(cmd, "unblock")) {
		hrc = h_set_del(env, &data, jp, args, CTL_SET_BLOCK, &code, &msg);
	} else if (caly_strcaseeq(cmd, "mode")) {
		hrc = h_mode(env, &data, jp, args, &code, &msg);
	} else if (caly_strcaseeq(cmd, "port")) {
		hrc = h_port(env, &data, jp, args, &code, &msg);
	} else if (caly_strcaseeq(cmd, "conntrack")) {
		hrc = h_conntrack(env, &data, jp, args, &code, &msg);
	} else if (caly_strcaseeq(cmd, "reload")) {
		hrc = h_reload(env, &data);
	} else if (caly_strcaseeq(cmd, "subscribe")) {
		hrc = h_subscribe(&data);
		if (hrc == 0)
			subscribed = 1;
	} else {
		ctl_send_err(fd, id, "unknown_command", "unknown command");
		sb_free(&data);
		free(copy);
		free(jp);
		return CALY_CTL_CONTINUE;
	}

	if (hrc != 0 || data.err) {
		if (data.err) {
			code = "internal";
			msg = "response too large";
		}
		ctl_send_err(fd, id, code, msg);
		sb_free(&data);
		free(copy);
		free(jp);
		return CALY_CTL_CONTINUE;
	}

	{
		struct sbuf out;

		sb_init(&out);
		sb_puts(&out, "{\"id\":");
		sb_u64(&out, id);
		sb_puts(&out, ",\"ok\":true,\"data\":");
		sb_write(&out, data.buf ? data.buf : "{}",
			 data.buf ? data.len : 2);
		sb_puts(&out, "}\n");
		if (!out.err)
			ctl_send_raw(fd, out.buf, out.len);
		else
			ctl_send_err(fd, id, "internal", "response too large");
		sb_free(&out);
	}

	sb_free(&data);
	free(copy);
	free(jp);
	return subscribed ? CALY_CTL_SUBSCRIBE : CALY_CTL_CONTINUE;
}

/* =========================================================================
 * Event stream formatting (called by main.c for every subscriber)
 * ========================================================================= */

int caly_ctl_format_event(const struct event *ev, char *buf, size_t cap)
{
	struct sbuf s;
	__u8   saddr[16], daddr[16];
	__u32  fam = (ev->family == CALY_AF_INET) ?
		     CALY_UTIL_AF_INET : CALY_UTIL_AF_INET6;
	int    ret = -1;

	memset(saddr, 0, sizeof(saddr));
	memset(daddr, 0, sizeof(daddr));
	if (ev->family == CALY_AF_INET) {
		memcpy(saddr, &ev->saddr[0], 4);
		memcpy(daddr, &ev->daddr[0], 4);
	} else {
		memcpy(saddr, ev->saddr, 16);
		memcpy(daddr, ev->daddr, 16);
	}

	sb_init(&s);
	sb_puts(&s, "{\"stream\":\"events\",\"event\":{");
	sb_key(&s, "ts_ns"); sb_u64(&s, ev->ts_ns); sb_putc(&s, ',');
	sb_key(&s, "ban_ttl_ns"); sb_u64(&s, ev->ban_ttl_ns); sb_putc(&s, ',');
	sb_key(&s, "value"); sb_u64(&s, ev->value); sb_putc(&s, ',');
	sb_key(&s, "saddr"); ctl_emit_addr(&s, fam, saddr); sb_putc(&s, ',');
	sb_key(&s, "daddr"); ctl_emit_addr(&s, fam, daddr); sb_putc(&s, ',');
	sb_key(&s, "family"); sb_u64(&s, ev->family); sb_putc(&s, ',');
	sb_key(&s, "ifindex"); sb_u64(&s, ev->ifindex); sb_putc(&s, ',');
	sb_key(&s, "reason"); sb_u64(&s, ev->reason); sb_putc(&s, ',');
	sb_key(&s, "reason_str"); sb_jstrz(&s, stat_reason_str(ev->reason)); sb_putc(&s, ',');
	sb_key(&s, "verdict"); sb_u64(&s, ev->verdict); sb_putc(&s, ',');
	sb_key(&s, "proto"); sb_u64(&s, ev->proto); sb_putc(&s, ',');
	sb_key(&s, "pkt_len"); sb_u64(&s, ev->pkt_len); sb_putc(&s, ',');
	sb_key(&s, "sport"); sb_u64(&s, ntohs(ev->sport)); sb_putc(&s, ',');
	sb_key(&s, "dport"); sb_u64(&s, ntohs(ev->dport)); sb_putc(&s, ',');
	sb_key(&s, "tcp_flags"); sb_u64(&s, ev->tcp_flags); sb_putc(&s, ',');
	sb_key(&s, "mode"); sb_u64(&s, ev->mode);
	sb_puts(&s, "}}\n");

	if (!s.err && s.len < cap) {
		memcpy(buf, s.buf, s.len);
		buf[s.len] = '\0';
		ret = (int)s.len;
	}
	sb_free(&s);
	return ret;
}
