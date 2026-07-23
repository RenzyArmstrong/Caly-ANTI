/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - XDP/eBPF DDoS mitigation suite
 * src/user/config.c - the configuration parser.
 *
 * See src/user/config.h for the contract and config/calyanti.conf for the
 * authoritative list of keys. Every scalar key here maps onto exactly one
 * field of struct fw_config; every list-valued key populates one of the
 * vectors on struct caly_conf, which src/user/maps.c later programs into the
 * BPF maps.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "config.h"
#include "maps.h"

/* =========================================================================
 * Small utilities
 * ========================================================================= */

static void caly_seterr(char *err, size_t errsz, const char *fmt, ...)
{
	va_list ap;

	if (!err || errsz == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errsz, fmt, ap);
	va_end(ap);
}

static void caly_warn(struct caly_conf *c, const char *fmt, ...)
{
	va_list ap;

	if (!c || c->n_warn >= CALY_CONF_MAX_WARN)
		return;
	va_start(ap, fmt);
	vsnprintf(c->warn[c->n_warn], CALY_CONF_WARNSZ, fmt, ap);
	va_end(ap);
	c->n_warn++;
}

/* Grow *v so it can hold `need` elements of `esz` bytes. */
static int vec_reserve(void **v, size_t *cap, size_t need, size_t esz)
{
	size_t nc;
	void *p;

	if (need <= *cap)
		return 0;
	nc = *cap ? *cap : 8;
	while (nc < need) {
		if (nc > (size_t)-1 / 2)
			return -ENOMEM;
		nc *= 2;
	}
	if (nc > (size_t)-1 / esz)
		return -ENOMEM;
	p = realloc(*v, nc * esz);
	if (!p)
		return -ENOMEM;
	*v = p;
	*cap = nc;
	return 0;
}

static int vec_push(void **v, size_t *n, size_t *cap, size_t esz,
		    const void *elem)
{
	int r = vec_reserve(v, cap, *n + 1, esz);

	if (r)
		return r;
	memcpy((char *)*v + (*n) * esz, elem, esz);
	(*n)++;
	return 0;
}

/* `arr` may still be NULL: sizeof(*(arr)) is a type query, not a load. */
#define VEC_PUSH(arr, n, cap, elemptr) \
	vec_push((void **)&(arr), &(n), &(cap), sizeof(*(arr)), (elemptr))

static char *str_trim(char *s)
{
	char *e;

	while (*s && isspace((unsigned char)*s))
		s++;
	if (*s == '\0')
		return s;
	e = s + strlen(s) - 1;
	while (e > s && isspace((unsigned char)*e))
		*e-- = '\0';
	return s;
}

/* Next comma-separated item; advances *p. Returns NULL when exhausted. */
static char *next_item(char **p)
{
	char *s = *p, *q;

	if (!s)
		return NULL;
	while (*s && (isspace((unsigned char)*s) || *s == ','))
		s++;
	if (*s == '\0') {
		*p = s;
		return NULL;
	}
	q = strchr(s, ',');
	if (q) {
		*q = '\0';
		*p = q + 1;
	} else {
		*p = s + strlen(s);
	}
	return str_trim(s);
}

/* Next whitespace-separated word; advances *p. */
static char *next_word(char **p)
{
	char *s = *p;

	if (!s)
		return NULL;
	while (*s && isspace((unsigned char)*s))
		s++;
	if (*s == '\0') {
		*p = s;
		return NULL;
	}
	*p = s;
	while (**p && !isspace((unsigned char)**p))
		(*p)++;
	if (**p) {
		**p = '\0';
		(*p)++;
	}
	return s;
}

/* =========================================================================
 * Value parsers
 * ========================================================================= */

int caly_parse_bool(const char *s, int *out)
{
	if (!s || !out)
		return -EINVAL;
	if (!strcasecmp(s, "yes") || !strcasecmp(s, "true") ||
	    !strcasecmp(s, "on") || !strcmp(s, "1") ||
	    !strcasecmp(s, "enable") || !strcasecmp(s, "enabled")) {
		*out = 1;
		return 0;
	}
	if (!strcasecmp(s, "no") || !strcasecmp(s, "false") ||
	    !strcasecmp(s, "off") || !strcmp(s, "0") ||
	    !strcasecmp(s, "disable") || !strcasecmp(s, "disabled")) {
		*out = 0;
		return 0;
	}
	return -EINVAL;
}

/* Parse a non-negative integer, rejecting overflow and trailing garbage.
 * *end receives the first unconsumed character. */
static int parse_u64_prefix(const char *s, __u64 *out, const char **end)
{
	__u64 v = 0;
	const char *p = s;

	if (!s || !isdigit((unsigned char)*p))
		return -EINVAL;
	while (isdigit((unsigned char)*p)) {
		unsigned d = (unsigned)(*p - '0');

		if (v > ((__u64)-1 - d) / 10ULL)
			return -ERANGE;
		v = v * 10ULL + d;
		p++;
	}
	*out = v;
	if (end)
		*end = p;
	return 0;
}

static int mul_checked(__u64 a, __u64 b, __u64 *out)
{
	if (b != 0 && a > (__u64)-1 / b)
		return -ERANGE;
	*out = a * b;
	return 0;
}

int caly_parse_duration_ns(const char *s, __u64 *out)
{
	const char *p;
	__u64 v, mult;
	int r;

	if (!s || !out)
		return -EINVAL;
	r = parse_u64_prefix(s, &v, &p);
	if (r)
		return r;
	while (*p && isspace((unsigned char)*p))
		p++;

	if (*p == '\0')
		mult = CALY_NSEC_PER_SEC;            /* bare integer = seconds */
	else if (!strcasecmp(p, "ns"))
		mult = 1ULL;
	else if (!strcasecmp(p, "us"))
		mult = 1000ULL;
	else if (!strcasecmp(p, "ms"))
		mult = 1000000ULL;
	else if (!strcasecmp(p, "s") || !strcasecmp(p, "sec"))
		mult = CALY_NSEC_PER_SEC;
	else if (!strcasecmp(p, "m") || !strcasecmp(p, "min"))
		mult = 60ULL * CALY_NSEC_PER_SEC;
	else if (!strcasecmp(p, "h") || !strcasecmp(p, "hr"))
		mult = 3600ULL * CALY_NSEC_PER_SEC;
	else if (!strcasecmp(p, "d") || !strcasecmp(p, "day"))
		mult = 86400ULL * CALY_NSEC_PER_SEC;
	else
		return -EINVAL;

	return mul_checked(v, mult, out);
}

int caly_parse_rate(const char *s, __u64 *out)
{
	const char *p;
	__u64 v, mult = 1ULL;
	int r;

	if (!s || !out)
		return -EINVAL;
	r = parse_u64_prefix(s, &v, &p);
	if (r)
		return r;
	while (*p && isspace((unsigned char)*p))
		p++;

	if (*p == 'k' || *p == 'K') {
		mult = 1000ULL;
		p++;
	} else if (*p == 'm' || *p == 'M') {
		mult = 1000000ULL;
		p++;
	} else if (*p == 'g' || *p == 'G') {
		mult = 1000000000ULL;
		p++;
	}

	/* Optional, purely decorative unit word. Byte rates are BYTES/s. */
	if (*p != '\0' && strcasecmp(p, "pps") && strcasecmp(p, "bps") &&
	    strcasecmp(p, "p/s") && strcasecmp(p, "b/s") &&
	    strcasecmp(p, "pkt/s") && strcasecmp(p, "packets") &&
	    strcasecmp(p, "bytes"))
		return -EINVAL;

	return mul_checked(v, mult, out);
}

int caly_parse_size(const char *s, __u64 *out)
{
	const char *p;
	__u64 v, mult = 1ULL;
	int binary = 0;
	int r;

	if (!s || !out)
		return -EINVAL;
	r = parse_u64_prefix(s, &v, &p);
	if (r)
		return r;
	while (*p && isspace((unsigned char)*p))
		p++;

	if (*p == 'k' || *p == 'K' || *p == 'm' || *p == 'M' ||
	    *p == 'g' || *p == 'G') {
		char c = (char)tolower((unsigned char)*p);

		p++;
		if (*p == 'i' || *p == 'I') {
			binary = 1;
			p++;
		}
		if (c == 'k')
			mult = binary ? 1024ULL : 1000ULL;
		else if (c == 'm')
			mult = binary ? 1048576ULL : 1000000ULL;
		else
			mult = binary ? 1073741824ULL : 1000000000ULL;
	}
	if (*p == 'b' || *p == 'B')
		p++;
	if (*p != '\0')
		return -EINVAL;

	return mul_checked(v, mult, out);
}

/* Zero every bit below the prefix length. */
static void caly_mask_addr(__u8 *a, unsigned nbytes, unsigned plen)
{
	unsigned i;

	if (plen > nbytes * 8u)
		plen = nbytes * 8u;
	for (i = 0; i < nbytes; i++) {
		unsigned bit_lo = i * 8u;

		if (plen >= bit_lo + 8u)
			continue;
		if (plen <= bit_lo)
			a[i] = 0;
		else
			a[i] = (__u8)(a[i] &
				      (__u8)(0xFFu << (8u - (plen - bit_lo))));
	}
}

int caly_parse_cidr(const char *s, struct caly_cidr *out)
{
	char buf[128];
	char *slash;
	unsigned plen;
	size_t len;

	if (!s || !out)
		return -EINVAL;
	len = strlen(s);
	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;
	memcpy(buf, s, len + 1);

	memset(out, 0, sizeof(*out));

	slash = strchr(buf, '/');
	if (slash) {
		const char *p;
		__u64 v;

		*slash = '\0';
		if (parse_u64_prefix(slash + 1, &v, &p) || *p != '\0')
			return -EINVAL;
		if (v > 128)
			return -EINVAL;
		plen = (unsigned)v;
	} else {
		plen = (unsigned)-1;
	}

	if (strchr(buf, ':')) {
		struct in6_addr a6;

		if (inet_pton(AF_INET6, buf, &a6) != 1)
			return -EINVAL;
		if (plen == (unsigned)-1)
			plen = 128;
		if (plen > 128)
			return -EINVAL;
		out->family = CALY_AF_INET6;
		out->prefixlen = (__u8)plen;
		memcpy(out->addr, &a6, 16);
		caly_mask_addr(out->addr, 16, plen);
	} else {
		struct in_addr a4;

		if (inet_pton(AF_INET, buf, &a4) != 1)
			return -EINVAL;
		if (plen == (unsigned)-1)
			plen = 32;
		if (plen > 32)
			return -EINVAL;
		out->family = CALY_AF_INET;
		out->prefixlen = (__u8)plen;
		memcpy(out->addr, &a4, 4);
		caly_mask_addr(out->addr, 4, plen);
	}
	return 0;
}

void caly_cidr_from_addr(struct caly_cidr *out, __u8 family, const __u8 *addr)
{
	memset(out, 0, sizeof(*out));
	out->family = family;
	if (family == CALY_AF_INET6) {
		out->prefixlen = 128;
		memcpy(out->addr, addr, 16);
	} else {
		out->family = CALY_AF_INET;
		out->prefixlen = 32;
		memcpy(out->addr, addr, 4);
	}
}

const char *caly_cidr_str(const struct caly_cidr *c, char *buf, size_t sz)
{
	char ip[INET6_ADDRSTRLEN];

	if (!buf || sz == 0)
		return "";
	if (!c) {
		snprintf(buf, sz, "(null)");
		return buf;
	}
	if (c->family == CALY_AF_INET6) {
		if (!inet_ntop(AF_INET6, c->addr, ip, sizeof(ip)))
			snprintf(ip, sizeof(ip), "??");
	} else {
		if (!inet_ntop(AF_INET, c->addr, ip, sizeof(ip)))
			snprintf(ip, sizeof(ip), "??");
	}
	snprintf(buf, sz, "%s/%u", ip, (unsigned)c->prefixlen);
	return buf;
}

int caly_cidr_contains(const struct caly_cidr *net, const struct caly_cidr *h)
{
	unsigned nbytes, full, rem, i;

	if (!net || !h || net->family != h->family)
		return 0;
	if (net->prefixlen > h->prefixlen)
		return 0;
	nbytes = (net->family == CALY_AF_INET6) ? 16u : 4u;
	full = net->prefixlen / 8u;
	rem = net->prefixlen % 8u;
	if (full > nbytes)
		return 0;
	for (i = 0; i < full; i++)
		if (net->addr[i] != h->addr[i])
			return 0;
	if (rem) {
		__u8 mask = (__u8)(0xFFu << (8u - rem));

		if (full >= nbytes)
			return 0;
		if ((__u8)(net->addr[full] & mask) !=
		    (__u8)(h->addr[full] & mask))
			return 0;
	}
	return 1;
}

int caly_parse_port_range(const char *s, __u32 *lo, __u32 *hi)
{
	const char *p;
	__u64 a, b;

	if (!s || !lo || !hi)
		return -EINVAL;
	if (parse_u64_prefix(s, &a, &p))
		return -EINVAL;
	if (a > 65535)
		return -ERANGE;
	if (*p == '\0') {
		*lo = (__u32)a;
		*hi = (__u32)a;
		return 0;
	}
	if (*p != '-' && *p != ':')
		return -EINVAL;
	p++;
	if (parse_u64_prefix(p, &b, &p) || *p != '\0')
		return -EINVAL;
	if (b > 65535)
		return -ERANGE;
	if (b < a)
		return -EINVAL;
	*lo = (__u32)a;
	*hi = (__u32)b;
	return 0;
}

int caly_parse_fw_mode(const char *s, __u32 *out)
{
	if (!s || !out)
		return -EINVAL;
	if (!strcasecmp(s, "normal"))
		*out = FW_MODE_NORMAL;
	else if (!strcasecmp(s, "elevated"))
		*out = FW_MODE_ELEVATED;
	else if (!strcasecmp(s, "under-attack") ||
		 !strcasecmp(s, "under_attack") || !strcasecmp(s, "attack"))
		*out = FW_MODE_UNDER_ATTACK;
	else if (!strcasecmp(s, "lockdown"))
		*out = FW_MODE_LOCKDOWN;
	else if (!strcasecmp(s, "monitor-only") ||
		 !strcasecmp(s, "monitor_only") || !strcasecmp(s, "monitor"))
		*out = FW_MODE_MONITOR_ONLY;
	else
		return -EINVAL;
	return 0;
}

int caly_parse_zone(const char *s, __u32 *out)
{
	if (!s || !out)
		return -EINVAL;
	if (!strcasecmp(s, "wan"))
		*out = CALY_ZONE_WAN;
	else if (!strcasecmp(s, "lan"))
		*out = CALY_ZONE_LAN;
	else if (!strcasecmp(s, "dmz"))
		*out = CALY_ZONE_DMZ;
	else
		return -EINVAL;
	return 0;
}

int caly_parse_dataplane(const char *s, __u32 *out)
{
	if (!s || !out)
		return -EINVAL;
	if (!strcasecmp(s, "auto"))
		*out = CALY_DP_AUTO;
	else if (!strcasecmp(s, "xdp-native") || !strcasecmp(s, "xdp_native"))
		*out = CALY_DP_XDP_NATIVE;
	else if (!strcasecmp(s, "xdp-generic") || !strcasecmp(s, "xdp_generic"))
		*out = CALY_DP_XDP_GENERIC;
	else if (!strcasecmp(s, "tc-bpf") || !strcasecmp(s, "tc"))
		*out = CALY_DP_TC;
	else if (!strcasecmp(s, "nftables") || !strcasecmp(s, "nft"))
		*out = CALY_DP_NFTABLES;
	else if (!strcasecmp(s, "iptables") || !strcasecmp(s, "iptables+ipset"))
		*out = CALY_DP_IPTABLES;
	else
		return -EINVAL;
	return 0;
}

int caly_parse_xdp_mode(const char *s, __u32 *out)
{
	if (!s || !out)
		return -EINVAL;
	if (!strcasecmp(s, "auto"))
		*out = CALY_XDP_AUTO;
	else if (!strcasecmp(s, "native") || !strcasecmp(s, "drv"))
		*out = CALY_XDP_NATIVE;
	else if (!strcasecmp(s, "generic") || !strcasecmp(s, "skb"))
		*out = CALY_XDP_GENERIC;
	else if (!strcasecmp(s, "offload") || !strcasecmp(s, "hw"))
		*out = CALY_XDP_OFFLOAD;
	else
		return -EINVAL;
	return 0;
}

int caly_parse_port_mode(const char *s, __u32 *out)
{
	if (!s || !out)
		return -EINVAL;
	if (!strcasecmp(s, "closed") || !strcasecmp(s, "close") ||
	    !strcasecmp(s, "deny") || !strcasecmp(s, "drop"))
		*out = CALY_PORT_CLOSED;
	else if (!strcasecmp(s, "open") || !strcasecmp(s, "allow") ||
		 !strcasecmp(s, "accept"))
		*out = CALY_PORT_OPEN;
	else if (!strcasecmp(s, "ratelimit") || !strcasecmp(s, "rate-limit") ||
		 !strcasecmp(s, "limit"))
		*out = CALY_PORT_RATELIMIT;
	else
		return -EINVAL;
	return 0;
}

int caly_parse_icmp_policy(const char *s, __u32 *out)
{
	if (!s || !out)
		return -EINVAL;
	if (!strcasecmp(s, "drop") || !strcasecmp(s, "deny"))
		*out = CALY_ICMP_DROP;
	else if (!strcasecmp(s, "pass") || !strcasecmp(s, "allow") ||
		 !strcasecmp(s, "accept"))
		*out = CALY_ICMP_PASS;
	else if (!strcasecmp(s, "ratelimit") || !strcasecmp(s, "rate-limit") ||
		 !strcasecmp(s, "limit"))
		*out = CALY_ICMP_RATELIMIT;
	else
		return -EINVAL;
	return 0;
}

/* =========================================================================
 * Defaults - these mirror config/calyanti.conf exactly, so a key that is
 * absent from the file behaves the same as the shipped value.
 * ========================================================================= */

void caly_conf_set_defaults(struct caly_conf *c)
{
	struct fw_config *f;

	if (!c)
		return;

	free(c->allow);
	free(c->block);
	free(c->local);
	free(c->ports);
	free(c->icmp);
	free(c->ifaces);
	free(c->amp_exempt);
	free(c->amp_extra);
	free(c->synproxy_ports);

	memset(c, 0, sizeof(*c));
	f = &c->fw;

	f->abi_version = CALY_ABI_VERSION;
	f->config_gen  = 0;
	f->flags       = CALY_F_DEFAULT_POLICY | CALY_F_PORT_POLICY |
			 CALY_F_TUNNEL_INSPECT | CALY_F_DROP_RH0 |
			 CALY_F_SYNPROXY;

	/* --- per-source token buckets (generous by design) --- */
	f->tb_rate[CALY_TB_PPS]      = 200000ULL;
	f->tb_burst[CALY_TB_PPS]     = 400000ULL;
	f->tb_rate[CALY_TB_BPS]      = 250000000ULL;
	f->tb_burst[CALY_TB_BPS]     = 500000000ULL;
	f->tb_rate[CALY_TB_SYN]      = 2000ULL;
	f->tb_burst[CALY_TB_SYN]     = 4000ULL;
	f->tb_rate[CALY_TB_UDP]      = 50000ULL;
	f->tb_burst[CALY_TB_UDP]     = 100000ULL;
	f->tb_rate[CALY_TB_ICMP]     = 200ULL;
	f->tb_burst[CALY_TB_ICMP]    = 400ULL;
	f->tb_rate[CALY_TB_NEWCONN]  = 500ULL;
	f->tb_burst[CALY_TB_NEWCONN] = 1000ULL;

	/* --- global gauges --- */
	f->global_pps_hi          = 4000000ULL;
	f->global_pps_lo          = 2000000ULL;
	f->global_bps_hi          = 1250000000ULL;
	f->global_bps_lo          = 800000000ULL;
	f->global_syn_pps_hi      = 40000ULL;
	f->global_syn_pps_lo      = 15000ULL;
	f->global_newconn_pps_hi  = 100000ULL;
	f->global_newconn_pps_lo  = 50000ULL;
	f->attack_dwell_ns        = 120ULL * CALY_NSEC_PER_SEC;
	f->syn_fallback_pps       = 100000ULL;

	/* --- banning --- */
	f->ban_ttl_base_ns  = 600ULL * CALY_NSEC_PER_SEC;
	f->ban_ttl_max_ns   = 86400ULL * CALY_NSEC_PER_SEC;
	f->ban_ttl_scan_ns  = 3600ULL * CALY_NSEC_PER_SEC;
	f->ban_ttl_amp_ns   = 6ULL * 3600ULL * CALY_NSEC_PER_SEC;
	f->strike_window_ns = 60ULL * CALY_NSEC_PER_SEC;

	/* --- scan detection --- */
	f->scan_window_ns = 30ULL * CALY_NSEC_PER_SEC;

	/* --- conntrack timeouts --- */
	f->ct_tcp_syn_ns    = 60ULL * CALY_NSEC_PER_SEC;
	f->ct_tcp_est_ns    = 4ULL * 3600ULL * CALY_NSEC_PER_SEC;
	f->ct_tcp_fin_ns    = 30ULL * CALY_NSEC_PER_SEC;
	f->ct_udp_ns        = 30ULL * CALY_NSEC_PER_SEC;
	f->ct_udp_stream_ns = 180ULL * CALY_NSEC_PER_SEC;
	f->ct_icmp_ns       = 30ULL * CALY_NSEC_PER_SEC;
	f->ct_generic_ns    = 60ULL * CALY_NSEC_PER_SEC;

	/* --- userspace GC --- */
	f->rate_idle_ns    = 300ULL * CALY_NSEC_PER_SEC;
	f->scan_idle_ns    = 300ULL * CALY_NSEC_PER_SEC;
	f->srcstat_idle_ns = 600ULL * CALY_NSEC_PER_SEC;

	/* --- 32-bit knobs --- */
	f->mode                = FW_MODE_NORMAL;
	f->default_zone        = CALY_ZONE_LAN;
	f->strike_limit        = 10;
	f->ban_escalate_num    = 2;
	f->ban_escalate_den    = 1;
	f->scan_port_threshold = 60;
	f->icmp_max_payload    = 1472;
	f->icmp6_max_payload   = 1472;
	f->frag_min_bytes      = 128;
	f->ip_min_ttl          = 0;
	f->vlan_max_depth      = CALY_VLAN_MAX_DEPTH;
	f->ip6_ext_max         = CALY_IP6_EXT_MAX;
	f->tunnel_max_depth    = CALY_TUNNEL_MAX_DEPTH;
	f->tcp_min_doff        = 5;
	f->log_sample_rate     = 100;
	f->log_max_pps         = 1000;
	f->log_level           = 2;
	f->event_pages         = 16;
	f->max_ban_entries     = 262144;
	f->max_conn_entries    = 262144;
	f->max_rate_entries    = 524288;
	f->max_scan_entries    = 131072;
	f->max_srcstat_entries = 131072;
	f->max_allow_entries   = 65536;
	f->max_block_entries   = 262144;
	f->max_iface_entries   = 64;
	f->dataplane_pref      = CALY_DP_AUTO;
	f->xdp_attach_pref     = CALY_XDP_AUTO;
	f->poll_interval_ms    = 200;
	f->stats_interval_ms   = 1000;
	f->gc_interval_ms      = 5000;
	f->gc_batch            = 4096;

	/* Management ports: TCP/22 is forced, always, in every mode. */
	f->mgmt_tcp_ports[0] = 22;
	f->mgmt_tcp_count    = 1;
	f->mgmt_udp_count    = 0;

	c->allow_bypass_rate = 1;
	c->strict            = 1;
}

struct caly_conf *caly_conf_alloc(void)
{
	struct caly_conf *c = calloc(1, sizeof(*c));

	if (!c)
		return NULL;
	caly_conf_set_defaults(c);
	return c;
}

void caly_conf_free(struct caly_conf *c)
{
	if (!c)
		return;
	free(c->allow);
	free(c->block);
	free(c->local);
	free(c->ports);
	free(c->icmp);
	free(c->ifaces);
	free(c->amp_exempt);
	free(c->amp_extra);
	free(c->synproxy_ports);
	free(c);
}

/* =========================================================================
 * List-valued directive handlers
 * ========================================================================= */

static int add_cidr_list(struct caly_conf *c, const char *val, int which,
			 char *err, size_t errsz)
{
	char *dup, *p, *item;
	int rc = 0;

	dup = strdup(val);
	if (!dup)
		return -ENOMEM;
	p = dup;

	while ((item = next_item(&p)) != NULL) {
		struct caly_cidr cd;

		if (*item == '\0')
			continue;
		if (caly_parse_cidr(item, &cd)) {
			caly_seterr(err, errsz, "not a valid CIDR: '%s'", item);
			rc = -EINVAL;
			goto out;
		}
		cd.tag = CALY_TAG_CONF;
		switch (which) {
		case 0:
			cd.flags = CALY_RULE_F_ALLOW;
			if (c->allow_bypass_rate)
				cd.flags |= CALY_RULE_F_BYPASS_RATE;
			rc = VEC_PUSH(c->allow, c->n_allow, c->c_allow, &cd);
			break;
		case 1:
			cd.flags = CALY_RULE_F_BLOCK;
			rc = VEC_PUSH(c->block, c->n_block, c->c_block, &cd);
			break;
		default:
			cd.flags = CALY_RULE_F_LOCAL;
			rc = VEC_PUSH(c->local, c->n_local, c->c_local, &cd);
			break;
		}
		if (rc) {
			caly_seterr(err, errsz, "out of memory");
			goto out;
		}
	}
out:
	free(dup);
	return rc;
}

static int key_allow(struct caly_conf *c, const char *v, char *e, size_t es)
{
	return add_cidr_list(c, v, 0, e, es);
}

static int key_block(struct caly_conf *c, const char *v, char *e, size_t es)
{
	return add_cidr_list(c, v, 1, e, es);
}

static int key_local(struct caly_conf *c, const char *v, char *e, size_t es)
{
	return add_cidr_list(c, v, 2, e, es);
}

static int key_allow_bypass(struct caly_conf *c, const char *v,
			    char *e, size_t es)
{
	int b;

	if (caly_parse_bool(v, &b)) {
		caly_seterr(e, es, "not a boolean: '%s'", v);
		return -EINVAL;
	}
	c->allow_bypass_rate = b;
	return 0;
}

/* mgmt_tcp_ports / mgmt_udp_ports. Values ACCUMULATE across occurrences and
 * across reloads of the same file: removing a port here can never take
 * effect, which is exactly the intent documented in calyanti.conf. */
static int add_mgmt_ports(struct caly_conf *c, const char *val, int udp,
			  char *err, size_t errsz)
{
	char *dup, *p, *item;
	int rc = 0;

	dup = strdup(val);
	if (!dup)
		return -ENOMEM;
	p = dup;

	while ((item = next_item(&p)) != NULL) {
		__u32 lo, hi, port;
		__u16 *list;
		size_t *n, max;

		if (*item == '\0')
			continue;
		if (caly_parse_port_range(item, &lo, &hi)) {
			caly_seterr(err, errsz, "not a valid port: '%s'", item);
			rc = -EINVAL;
			goto out;
		}
		if (lo == 0) {
			caly_seterr(err, errsz,
				    "management port 0 is not meaningful");
			rc = -EINVAL;
			goto out;
		}
		list = udp ? c->mgmt_udp : c->mgmt_tcp;
		n    = udp ? &c->n_mgmt_udp : &c->n_mgmt_tcp;
		max  = CALY_MGMT_PORTS_MAX * 2u;

		for (port = lo; port <= hi; port++) {
			size_t i;
			int dup_found = 0;

			for (i = 0; i < *n; i++)
				if (list[i] == (__u16)port)
					dup_found = 1;
			if (dup_found)
				continue;
			if (*n >= max) {
				caly_seterr(err, errsz,
					    "too many management ports (max %u)",
					    CALY_MGMT_PORTS_MAX);
				rc = -E2BIG;
				goto out;
			}
			list[*n] = (__u16)port;
			(*n)++;
		}
	}
out:
	free(dup);
	return rc;
}

static int key_mgmt_tcp(struct caly_conf *c, const char *v, char *e, size_t es)
{
	return add_mgmt_ports(c, v, 0, e, es);
}

static int key_mgmt_udp(struct caly_conf *c, const char *v, char *e, size_t es)
{
	return add_mgmt_ports(c, v, 1, e, es);
}

/* tcp_port / udp_port:
 *   <port|range|list> <closed|open|ratelimit> [rate=<pps>] [burst=<pkts>]
 *                     [nolog|log] [noct] [synproxy]
 */
/* A token made only of digits, '-', ':' and ',' is part of the port list,
 * so `tcp_port = 80, 443 open` parses the same as `tcp_port = 80,443 open`. */
static int is_portish(const char *w)
{
	int digits = 0;

	for (; *w; w++) {
		if (isdigit((unsigned char)*w)) {
			digits = 1;
			continue;
		}
		if (*w == '-' || *w == ':' || *w == ',')
			continue;
		return 0;
	}
	return digits;
}

static int portbuf_append(char *buf, size_t sz, const char *tok)
{
	size_t len = strlen(buf);

	if (len && buf[len - 1] != ',') {
		if (len + 2 > sz)
			return -E2BIG;
		buf[len++] = ',';
		buf[len] = '\0';
	}
	if (len + strlen(tok) + 1 > sz)
		return -E2BIG;
	memcpy(buf + len, tok, strlen(tok) + 1);
	return 0;
}

static int add_port_rule(struct caly_conf *c, const char *val, __u32 proto,
			 char *err, size_t errsz)
{
	char portlist[1024];
	char *dup, *p, *w;
	__u32 mode = CALY_PORT_OPEN;
	__u32 flags = 0;
	__u64 rate = 0, burst = 0;
	int have_mode = 0;
	int in_ports = 1;
	int rc = 0;

	dup = strdup(val);
	if (!dup)
		return -ENOMEM;
	p = dup;
	portlist[0] = '\0';

	while ((w = next_word(&p)) != NULL) {
		if (*w == '\0')
			continue;
		if (in_ports && is_portish(w)) {
			if (portbuf_append(portlist, sizeof(portlist), w)) {
				caly_seterr(err, errsz,
					    "port list is too long");
				rc = -E2BIG;
				goto out;
			}
			continue;
		}
		in_ports = 0;
		if (!strncasecmp(w, "rate=", 5)) {
			if (caly_parse_rate(w + 5, &rate)) {
				caly_seterr(err, errsz,
					    "bad rate= value: '%s'", w + 5);
				rc = -EINVAL;
				goto out;
			}
		} else if (!strncasecmp(w, "burst=", 6)) {
			if (caly_parse_rate(w + 6, &burst)) {
				caly_seterr(err, errsz,
					    "bad burst= value: '%s'", w + 6);
				rc = -EINVAL;
				goto out;
			}
		} else if (!strcasecmp(w, "log")) {
			flags |= CALY_PORT_F_LOG;
		} else if (!strcasecmp(w, "noct") ||
			   !strcasecmp(w, "no-conntrack")) {
			flags |= CALY_PORT_F_NO_CT;
		} else if (!strcasecmp(w, "synproxy")) {
			flags |= CALY_PORT_F_SYNPROXY;
		} else if (!caly_parse_port_mode(w, &mode)) {
			have_mode = 1;
		} else {
			caly_seterr(err, errsz, "unknown port option: '%s'", w);
			rc = -EINVAL;
			goto out;
		}
	}

	if (!have_mode) {
		caly_seterr(err, errsz,
			    "missing mode (closed|open|ratelimit)");
		rc = -EINVAL;
		goto out;
	}
	if (mode == CALY_PORT_RATELIMIT && rate == 0) {
		caly_seterr(err, errsz,
			    "mode 'ratelimit' requires rate=<pps>");
		rc = -EINVAL;
		goto out;
	}
	if (mode != CALY_PORT_RATELIMIT && (rate || burst)) {
		rate = 0;
		burst = 0;
	}
	if (mode == CALY_PORT_RATELIMIT && burst == 0) {
		burst = (rate > (__u64)-1 / 2ULL) ? rate : rate * 2ULL;
		caly_warn(c, "port rule '%s': burst defaulted to %llu packets",
			  portlist, (unsigned long long)burst);
	}

	{
		char *lp = portlist, *item;
		size_t nports = 0;

		while ((item = next_item(&lp)) != NULL) {
			struct caly_portspec ps;
			__u32 lo, hi;

			if (*item == '\0')
				continue;
			if (caly_parse_port_range(item, &lo, &hi)) {
				caly_seterr(err, errsz,
					    "not a valid port or range: '%s'",
					    item);
				rc = -EINVAL;
				goto out;
			}
			memset(&ps, 0, sizeof(ps));
			ps.lo    = lo;
			ps.hi    = hi;
			ps.proto = proto;
			ps.mode  = mode;
			ps.flags = flags;
			ps.rate  = rate;
			ps.burst = burst;
			rc = VEC_PUSH(c->ports, c->n_ports, c->c_ports, &ps);
			if (rc) {
				caly_seterr(err, errsz, "out of memory");
				goto out;
			}
			nports++;
		}
		if (nports == 0) {
			caly_seterr(err, errsz,
				    "missing port specification");
			rc = -EINVAL;
			goto out;
		}
	}
out:
	free(dup);
	return rc;
}

static int key_tcp_port(struct caly_conf *c, const char *v, char *e, size_t es)
{
	return add_port_rule(c, v, CALY_IPPROTO_TCP, e, es);
}

static int key_udp_port(struct caly_conf *c, const char *v, char *e, size_t es)
{
	return add_port_rule(c, v, CALY_IPPROTO_UDP, e, es);
}

/* icmp4_type / icmp6_type: <type|range> <drop|pass|ratelimit> */
static int add_icmp_rule(struct caly_conf *c, const char *val, __u32 family,
			 char *err, size_t errsz)
{
	char *dup, *p, *tw, *pw;
	struct caly_icmpspec is;
	__u32 lo, hi, pol;
	int rc = 0;

	dup = strdup(val);
	if (!dup)
		return -ENOMEM;
	p = dup;

	tw = next_word(&p);
	pw = next_word(&p);
	if (!tw || !pw) {
		caly_seterr(err, errsz,
			    "expected '<type> <drop|pass|ratelimit>'");
		rc = -EINVAL;
		goto out;
	}
	if (next_word(&p) != NULL) {
		caly_seterr(err, errsz, "trailing garbage after ICMP policy");
		rc = -EINVAL;
		goto out;
	}
	if (caly_parse_port_range(tw, &lo, &hi) || lo > 255 || hi > 255) {
		caly_seterr(err, errsz, "ICMP type must be 0..255: '%s'", tw);
		rc = -EINVAL;
		goto out;
	}
	if (caly_parse_icmp_policy(pw, &pol)) {
		caly_seterr(err, errsz, "unknown ICMP policy: '%s'", pw);
		rc = -EINVAL;
		goto out;
	}

	memset(&is, 0, sizeof(is));
	is.family = family;
	is.lo     = lo;
	is.hi     = hi;
	is.policy = pol;
	rc = VEC_PUSH(c->icmp, c->n_icmp, c->c_icmp, &is);
	if (rc)
		caly_seterr(err, errsz, "out of memory");
out:
	free(dup);
	return rc;
}

static int key_icmp4_type(struct caly_conf *c, const char *v,
			  char *e, size_t es)
{
	return add_icmp_rule(c, v, CALY_AF_INET, e, es);
}

static int key_icmp6_type(struct caly_conf *c, const char *v,
			  char *e, size_t es)
{
	return add_icmp_rule(c, v, CALY_AF_INET6, e, es);
}

/* interface = <name> zone=<wan|lan|dmz> [monitor] [disabled] [drop-private]
 *                                       [no-ipv6] [trust-vlan] */
static int key_interface(struct caly_conf *c, const char *val,
			 char *err, size_t errsz)
{
	struct caly_ifspec ifs;
	char *dup, *p, *w;
	int rc = 0;

	dup = strdup(val);
	if (!dup)
		return -ENOMEM;
	p = dup;

	memset(&ifs, 0, sizeof(ifs));
	ifs.zone = CALY_ZONE_UNSPEC;

	w = next_word(&p);
	if (!w || *w == '\0') {
		caly_seterr(err, errsz, "missing interface name");
		rc = -EINVAL;
		goto out;
	}
	if (strlen(w) >= sizeof(ifs.name)) {
		caly_seterr(err, errsz, "interface name too long: '%s'", w);
		rc = -EINVAL;
		goto out;
	}
	memcpy(ifs.name, w, strlen(w) + 1);

	while ((w = next_word(&p)) != NULL) {
		if (*w == '\0')
			continue;
		if (!strncasecmp(w, "zone=", 5)) {
			if (caly_parse_zone(w + 5, &ifs.zone)) {
				caly_seterr(err, errsz,
					    "unknown zone: '%s'", w + 5);
				rc = -EINVAL;
				goto out;
			}
		} else if (!caly_parse_zone(w, &ifs.zone)) {
			/* bare 'wan' / 'lan' / 'dmz' */
		} else if (!strcasecmp(w, "monitor")) {
			ifs.flags |= CALY_IF_F_MONITOR;
		} else if (!strcasecmp(w, "disabled") ||
			   !strcasecmp(w, "disable")) {
			ifs.flags |= CALY_IF_F_DISABLED;
		} else if (!strcasecmp(w, "drop-private") ||
			   !strcasecmp(w, "drop_private")) {
			ifs.flags |= CALY_IF_F_DROP_PRIVATE;
		} else if (!strcasecmp(w, "no-ipv6") ||
			   !strcasecmp(w, "no_ipv6")) {
			ifs.flags |= CALY_IF_F_NO_IPV6;
		} else if (!strcasecmp(w, "trust-vlan") ||
			   !strcasecmp(w, "trust_vlan")) {
			ifs.flags |= CALY_IF_F_TRUST_VLAN;
		} else {
			caly_seterr(err, errsz,
				    "unknown interface option: '%s'", w);
			rc = -EINVAL;
			goto out;
		}
	}

	if (ifs.zone == CALY_ZONE_UNSPEC)
		ifs.zone = CALY_ZONE_LAN;
	if (ifs.zone == CALY_ZONE_WAN)
		ifs.flags |= CALY_IF_F_WAN;

	rc = VEC_PUSH(c->ifaces, c->n_ifaces, c->c_ifaces, &ifs);
	if (rc)
		caly_seterr(err, errsz, "out of memory");
out:
	free(dup);
	return rc;
}

static int add_range_list(struct caly_conf *c, const char *val, int which,
			  char *err, size_t errsz)
{
	char *dup, *p, *item;
	int rc = 0;

	dup = strdup(val);
	if (!dup)
		return -ENOMEM;
	p = dup;

	while ((item = next_item(&p)) != NULL) {
		struct caly_range r;
		__u32 lo, hi;

		if (*item == '\0')
			continue;
		if (caly_parse_port_range(item, &lo, &hi)) {
			caly_seterr(err, errsz,
				    "not a valid port or range: '%s'", item);
			rc = -EINVAL;
			goto out;
		}
		r.lo = lo;
		r.hi = hi;
		if (which == 0)
			rc = VEC_PUSH(c->amp_exempt, c->n_amp_exempt,
				      c->c_amp_exempt, &r);
		else if (which == 1)
			rc = VEC_PUSH(c->amp_extra, c->n_amp_extra,
				      c->c_amp_extra, &r);
		else
			rc = VEC_PUSH(c->synproxy_ports, c->n_synproxy,
				      c->c_synproxy, &r);
		if (rc) {
			caly_seterr(err, errsz, "out of memory");
			goto out;
		}
	}
out:
	free(dup);
	return rc;
}

static int key_amp_exempt(struct caly_conf *c, const char *v,
			  char *e, size_t es)
{
	return add_range_list(c, v, 0, e, es);
}

static int key_amp_extra(struct caly_conf *c, const char *v, char *e, size_t es)
{
	return add_range_list(c, v, 1, e, es);
}

static int key_synproxy_port(struct caly_conf *c, const char *v,
			     char *e, size_t es)
{
	return add_range_list(c, v, 2, e, es);
}

/* =========================================================================
 * Key table
 * ========================================================================= */

enum caly_ckind {
	CK_FLAG = 0,   /* boolean -> one bit of fw_config.flags               */
	CK_U32,        /* integer with k/m/g suffix -> __u32 field            */
	CK_U64,        /* integer with k/m/g suffix -> __u64 field            */
	CK_DUR_NS,     /* duration -> __u64 nanoseconds                       */
	CK_DUR_MS,     /* duration -> __u32 milliseconds                      */
	CK_RATE,       /* rate     -> __u64 units/sec                         */
	CK_MODE,
	CK_ZONE,
	CK_DATAPLANE,
	CK_XDPMODE,
	CK_CUSTOM
};

struct caly_keydef {
	const char    *name;
	unsigned char  kind;
	unsigned short off;      /* byte offset into struct fw_config */
	__u64          flagbit;
	__u64          min;
	__u64          max;
	int          (*fn)(struct caly_conf *, const char *, char *, size_t);
};

#define FOFF(field) ((unsigned short)offsetof(struct fw_config, field))
#define TBOFF(arr, idx) \
	((unsigned short)(offsetof(struct fw_config, arr) + \
			  (idx) * sizeof(__u64)))

static const struct caly_keydef caly_keys[] = {
	/* ---------------- [general] ---------------- */
	{ "enabled",        CK_FLAG, 0, CALY_F_ENABLED,      0, 0, NULL },
	{ "monitor_only",   CK_FLAG, 0, CALY_F_MONITOR_ONLY, 0, 0, NULL },
	{ "mode",           CK_MODE, FOFF(mode), 0, 0, FW_MODE_MAX - 1, NULL },
	{ "ipv4",           CK_FLAG, 0, CALY_F_IPV4,         0, 0, NULL },
	{ "ipv6",           CK_FLAG, 0, CALY_F_IPV6,         0, 0, NULL },
	{ "log_level",      CK_U32,  FOFF(log_level),       0, 0, 4, NULL },
	{ "poll_interval",  CK_DUR_MS, FOFF(poll_interval_ms),
	  0, 1, 60000, NULL },
	{ "stats_interval", CK_DUR_MS, FOFF(stats_interval_ms),
	  0, 10, 3600000, NULL },
	{ "gc_interval",    CK_DUR_MS, FOFF(gc_interval_ms),
	  0, 10, 3600000, NULL },
	{ "gc_batch",       CK_U32,  FOFF(gc_batch),        0, 16, 1048576,
	  NULL },

	/* ---------------- [dataplane] ---------------- */
	{ "dataplane",  CK_DATAPLANE, FOFF(dataplane_pref), 0, 0,
	  CALY_DP_MAX - 1, NULL },
	{ "xdp_mode",   CK_XDPMODE,   FOFF(xdp_attach_pref), 0, 0,
	  CALY_XDP_MODE_MAX - 1, NULL },
	{ "event_pages", CK_U32, FOFF(event_pages), 0, 1, 1024, NULL },

	/* ---------------- [interfaces] ---------------- */
	{ "interface",    CK_CUSTOM, 0, 0, 0, 0, key_interface },
	{ "default_zone", CK_ZONE, FOFF(default_zone), 0, 0,
	  CALY_ZONE_MAX - 1, NULL },

	/* ---------------- [management] ---------------- */
	{ "mgmt_tcp_ports", CK_CUSTOM, 0, 0, 0, 0, key_mgmt_tcp },
	{ "mgmt_udp_ports", CK_CUSTOM, 0, 0, 0, 0, key_mgmt_udp },
	{ "mgmt_bypass_ratelimit", CK_FLAG, 0, CALY_F_MGMT_BYPASS_ALL,
	  0, 0, NULL },

	/* ---------------- [allowlist] ---------------- */
	{ "allow", CK_CUSTOM, 0, 0, 0, 0, key_allow },
	{ "allowlist_bypass_ratelimit", CK_CUSTOM, 0, 0, 0, 0,
	  key_allow_bypass },
	{ "allowlist_enabled", CK_FLAG, 0, CALY_F_ALLOWLIST, 0, 0, NULL },

	/* ---------------- [local] ---------------- */
	{ "local", CK_CUSTOM, 0, 0, 0, 0, key_local },

	/* ---------------- [blocklist] ---------------- */
	{ "block", CK_CUSTOM, 0, 0, 0, 0, key_block },
	{ "blocklist_enabled", CK_FLAG, 0, CALY_F_BLOCKLIST, 0, 0, NULL },

	/* ---------------- [anomaly] ---------------- */
	{ "anomaly_checks",   CK_FLAG, 0, CALY_F_ANOMALY_CHECKS, 0, 0, NULL },
	{ "land_check",       CK_FLAG, 0, CALY_F_LAND_CHECK,     0, 0, NULL },
	{ "bogon_filter",     CK_FLAG, 0, CALY_F_BOGON_FILTER,   0, 0, NULL },
	{ "wan_drop_private", CK_FLAG, 0, CALY_F_WAN_DROP_PRIVATE, 0, 0, NULL },
	{ "tcp_flag_checks",  CK_FLAG, 0, CALY_F_TCP_FLAG_CHECKS, 0, 0, NULL },
	{ "frag_checks",      CK_FLAG, 0, CALY_F_FRAG_CHECKS,    0, 0, NULL },
	{ "frag_min_size",    CK_U32,  FOFF(frag_min_bytes), 0, 0, 65535,
	  NULL },
	{ "drop_all_fragments", CK_FLAG, 0, CALY_F_DROP_ALL_FRAGS, 0, 0, NULL },
	{ "drop_ip4_options", CK_FLAG, 0, CALY_F_DROP_IP4_OPTIONS, 0, 0, NULL },
	{ "drop_ipv6_rh0",    CK_FLAG, 0, CALY_F_DROP_RH0,       0, 0, NULL },
	{ "min_ttl",          CK_U32,  FOFF(ip_min_ttl), 0, 0, 255, NULL },
	{ "drop_unknown_ethertype", CK_FLAG, 0, CALY_F_DROP_UNKNOWN_L3,
	  0, 0, NULL },
	/* max 0 = no parse-time ceiling; finalize clamps these to the
	 * compiled CALY_*_MAX bounds, as calyanti.conf documents. */
	{ "vlan_max_depth",   CK_U32, FOFF(vlan_max_depth),   0, 0, 0, NULL },
	{ "ipv6_ext_max",     CK_U32, FOFF(ip6_ext_max),      0, 0, 0, NULL },
	{ "tunnel_max_depth", CK_U32, FOFF(tunnel_max_depth), 0, 0, 0, NULL },
	{ "vlan_inspect",     CK_FLAG, 0, CALY_F_VLAN_INSPECT,   0, 0, NULL },
	{ "tunnel_inspect",   CK_FLAG, 0, CALY_F_TUNNEL_INSPECT, 0, 0, NULL },
	{ "tcp_min_doff",     CK_U32, FOFF(tcp_min_doff), 0, 0, 15, NULL },

	/* ---------------- [icmp] ---------------- */
	{ "icmp_filter",      CK_FLAG, 0, CALY_F_ICMP_FILTER, 0, 0, NULL },
	{ "icmp_max_payload", CK_U32, FOFF(icmp_max_payload), 0, 0, 65535,
	  NULL },
	{ "icmp6_max_payload", CK_U32, FOFF(icmp6_max_payload), 0, 0, 65535,
	  NULL },
	{ "icmp4_type", CK_CUSTOM, 0, 0, 0, 0, key_icmp4_type },
	{ "icmp6_type", CK_CUSTOM, 0, 0, 0, 0, key_icmp6_type },

	/* ---------------- [ratelimit] ---------------- */
	{ "ratelimit_enabled", CK_FLAG, 0, CALY_F_RATE_LIMIT, 0, 0, NULL },
	{ "rate_pps",        CK_RATE, TBOFF(tb_rate,  CALY_TB_PPS),
	  0, 0, 0, NULL },
	{ "rate_pps_burst",  CK_RATE, TBOFF(tb_burst, CALY_TB_PPS),
	  0, 0, 0, NULL },
	{ "rate_bps",        CK_RATE, TBOFF(tb_rate,  CALY_TB_BPS),
	  0, 0, 0, NULL },
	{ "rate_bps_burst",  CK_RATE, TBOFF(tb_burst, CALY_TB_BPS),
	  0, 0, 0, NULL },
	{ "rate_syn",        CK_RATE, TBOFF(tb_rate,  CALY_TB_SYN),
	  0, 0, 0, NULL },
	{ "rate_syn_burst",  CK_RATE, TBOFF(tb_burst, CALY_TB_SYN),
	  0, 0, 0, NULL },
	{ "rate_udp",        CK_RATE, TBOFF(tb_rate,  CALY_TB_UDP),
	  0, 0, 0, NULL },
	{ "rate_udp_burst",  CK_RATE, TBOFF(tb_burst, CALY_TB_UDP),
	  0, 0, 0, NULL },
	{ "rate_icmp",       CK_RATE, TBOFF(tb_rate,  CALY_TB_ICMP),
	  0, 0, 0, NULL },
	{ "rate_icmp_burst", CK_RATE, TBOFF(tb_burst, CALY_TB_ICMP),
	  0, 0, 0, NULL },
	{ "rate_newconn",    CK_RATE, TBOFF(tb_rate,  CALY_TB_NEWCONN),
	  0, 0, 0, NULL },
	{ "rate_newconn_burst", CK_RATE, TBOFF(tb_burst, CALY_TB_NEWCONN),
	  0, 0, 0, NULL },
	{ "max_rate_entries", CK_U32, FOFF(max_rate_entries), 0, 0, 0, NULL },
	{ "rate_idle_timeout", CK_DUR_NS, FOFF(rate_idle_ns), 0, 0, 0, NULL },

	/* ---------------- [banning] ---------------- */
	{ "autoban",          CK_FLAG, 0, CALY_F_AUTOBAN, 0, 0, NULL },
	{ "strike_limit",     CK_U32, FOFF(strike_limit), 0, 1, 1000000, NULL },
	{ "strike_window",    CK_DUR_NS, FOFF(strike_window_ns), 0, 0, 0, NULL },
	{ "ban_ttl_base",     CK_DUR_NS, FOFF(ban_ttl_base_ns), 0, 0, 0, NULL },
	{ "ban_ttl_max",      CK_DUR_NS, FOFF(ban_ttl_max_ns), 0, 0, 0, NULL },
	{ "ban_escalate_num", CK_U32, FOFF(ban_escalate_num), 0, 1, 1000,
	  NULL },
	{ "ban_escalate_den", CK_U32, FOFF(ban_escalate_den), 0, 1, 1000,
	  NULL },
	{ "ban_ttl_scan",     CK_DUR_NS, FOFF(ban_ttl_scan_ns), 0, 0, 0, NULL },
	{ "ban_ttl_amp",      CK_DUR_NS, FOFF(ban_ttl_amp_ns), 0, 0, 0, NULL },
	{ "max_ban_entries",  CK_U32, FOFF(max_ban_entries), 0, 0, 0, NULL },
	{ "max_block_entries", CK_U32, FOFF(max_block_entries), 0, 0, 0, NULL },
	{ "max_allow_entries", CK_U32, FOFF(max_allow_entries), 0, 0, 0, NULL },
	{ "max_iface_entries", CK_U32, FOFF(max_iface_entries), 0, 0, 0, NULL },

	/* ---------------- [amplification] ---------------- */
	{ "anti_amplification", CK_FLAG, 0, CALY_F_ANTI_AMPLIFY, 0, 0, NULL },
	{ "amp_exempt", CK_CUSTOM, 0, 0, 0, 0, key_amp_exempt },
	{ "amp_extra",  CK_CUSTOM, 0, 0, 0, 0, key_amp_extra },

	/* ---------------- [ports] ---------------- */
	{ "default_deny", CK_FLAG, 0, CALY_F_DEFAULT_DENY, 0, 0, NULL },
	{ "port_policy",  CK_FLAG, 0, CALY_F_PORT_POLICY,  0, 0, NULL },
	{ "tcp_port", CK_CUSTOM, 0, 0, 0, 0, key_tcp_port },
	{ "udp_port", CK_CUSTOM, 0, 0, 0, 0, key_udp_port },

	/* ---------------- [conntrack] ---------------- */
	{ "conntrack", CK_FLAG, 0, CALY_F_CONNTRACK, 0, 0, NULL },
	{ "ct_tcp_syn",         CK_DUR_NS, FOFF(ct_tcp_syn_ns), 0, 0, 0, NULL },
	{ "ct_tcp_established", CK_DUR_NS, FOFF(ct_tcp_est_ns), 0, 0, 0, NULL },
	{ "ct_tcp_fin",         CK_DUR_NS, FOFF(ct_tcp_fin_ns), 0, 0, 0, NULL },
	{ "ct_udp",             CK_DUR_NS, FOFF(ct_udp_ns), 0, 0, 0, NULL },
	{ "ct_udp_stream",      CK_DUR_NS, FOFF(ct_udp_stream_ns),
	  0, 0, 0, NULL },
	{ "ct_icmp",            CK_DUR_NS, FOFF(ct_icmp_ns), 0, 0, 0, NULL },
	{ "ct_generic",         CK_DUR_NS, FOFF(ct_generic_ns), 0, 0, 0, NULL },
	{ "max_conn_entries",   CK_U32, FOFF(max_conn_entries), 0, 0, 0, NULL },

	/* ---------------- [portscan] ---------------- */
	{ "portscan_detect", CK_FLAG, 0, CALY_F_PORTSCAN_DETECT, 0, 0, NULL },
	{ "scan_port_threshold", CK_U32, FOFF(scan_port_threshold),
	  0, 1, CALY_SCAN_BITMAP_BITS, NULL },
	{ "scan_window",       CK_DUR_NS, FOFF(scan_window_ns), 0, 0, 0, NULL },
	{ "max_scan_entries",  CK_U32, FOFF(max_scan_entries), 0, 0, 0, NULL },
	{ "scan_idle_timeout", CK_DUR_NS, FOFF(scan_idle_ns), 0, 0, 0, NULL },

	/* ---------------- [synproxy] ---------------- */
	{ "synproxy", CK_FLAG, 0, CALY_F_SYNPROXY, 0, 0, NULL },
	{ "synproxy_port", CK_CUSTOM, 0, 0, 0, 0, key_synproxy_port },
	{ "global_syn_pps_high", CK_RATE, FOFF(global_syn_pps_hi),
	  0, 0, 0, NULL },
	{ "global_syn_pps_low",  CK_RATE, FOFF(global_syn_pps_lo),
	  0, 0, 0, NULL },
	{ "syn_fallback_pps",    CK_RATE, FOFF(syn_fallback_pps),
	  0, 0, 0, NULL },

	/* ---------------- [attack] ---------------- */
	{ "global_pps_high", CK_RATE, FOFF(global_pps_hi), 0, 0, 0, NULL },
	{ "global_pps_low",  CK_RATE, FOFF(global_pps_lo), 0, 0, 0, NULL },
	{ "global_bps_high", CK_RATE, FOFF(global_bps_hi), 0, 0, 0, NULL },
	{ "global_bps_low",  CK_RATE, FOFF(global_bps_lo), 0, 0, 0, NULL },
	{ "global_newconn_pps_high", CK_RATE, FOFF(global_newconn_pps_hi),
	  0, 0, 0, NULL },
	{ "global_newconn_pps_low",  CK_RATE, FOFF(global_newconn_pps_lo),
	  0, 0, 0, NULL },
	{ "attack_dwell",    CK_DUR_NS, FOFF(attack_dwell_ns), 0, 0, 0, NULL },
	{ "lockdown_allow_icmp", CK_FLAG, 0, CALY_F_LOCKDOWN_ICMP,
	  0, 0, NULL },

	/* ---------------- [telemetry] ---------------- */
	{ "log_events",      CK_FLAG, 0, CALY_F_LOG_EVENTS, 0, 0, NULL },
	{ "log_sample_rate", CK_U32, FOFF(log_sample_rate), 0, 0, 1000000000,
	  NULL },
	{ "log_max_pps",     CK_U32, FOFF(log_max_pps), 0, 0, 100000000, NULL },
	{ "src_stats",       CK_FLAG, 0, CALY_F_SRC_STATS, 0, 0, NULL },
	{ "max_srcstat_entries", CK_U32, FOFF(max_srcstat_entries),
	  0, 0, 0, NULL },
	{ "srcstat_idle_timeout", CK_DUR_NS, FOFF(srcstat_idle_ns),
	  0, 0, 0, NULL },
};

#define CALY_NKEYS (sizeof(caly_keys) / sizeof(caly_keys[0]))

static const struct caly_keydef *find_key(const char *name)
{
	size_t i;

	for (i = 0; i < CALY_NKEYS; i++)
		if (!strcasecmp(caly_keys[i].name, name))
			return &caly_keys[i];
	return NULL;
}

static const char *const caly_sections[] = {
	"general", "dataplane", "interfaces", "management", "allowlist",
	"local", "blocklist", "anomaly", "icmp", "ratelimit", "banning",
	"amplification", "ports", "conntrack", "portscan", "synproxy",
	"attack", "telemetry"
};

static int known_section(const char *s)
{
	size_t i;

	for (i = 0; i < sizeof(caly_sections) / sizeof(caly_sections[0]); i++)
		if (!strcasecmp(caly_sections[i], s))
			return 1;
	return 0;
}

/* =========================================================================
 * The parser proper
 * ========================================================================= */

static int apply_scalar(struct caly_conf *c, const struct caly_keydef *k,
			const char *val, char *err, size_t errsz)
{
	unsigned char *base = (unsigned char *)&c->fw;
	__u64 v = 0;
	int b;

	switch (k->kind) {
	case CK_FLAG:
		if (caly_parse_bool(val, &b)) {
			caly_seterr(err, errsz, "not a boolean: '%s'", val);
			return -EINVAL;
		}
		if (b)
			c->fw.flags |= k->flagbit;
		else
			c->fw.flags &= ~k->flagbit;
		return 0;

	case CK_U32:
	case CK_U64:
		if (caly_parse_size(val, &v)) {
			caly_seterr(err, errsz, "not an integer: '%s'", val);
			return -EINVAL;
		}
		break;

	case CK_RATE:
		if (caly_parse_rate(val, &v)) {
			caly_seterr(err, errsz, "not a rate: '%s'", val);
			return -EINVAL;
		}
		break;

	case CK_DUR_NS:
	case CK_DUR_MS:
		if (caly_parse_duration_ns(val, &v)) {
			caly_seterr(err, errsz, "not a duration: '%s'", val);
			return -EINVAL;
		}
		if (k->kind == CK_DUR_MS)
			v /= CALY_NSEC_PER_MSEC;
		break;

	case CK_MODE:
		if (caly_parse_fw_mode(val, (__u32 *)(void *)(base + k->off))) {
			caly_seterr(err, errsz, "unknown mode: '%s'", val);
			return -EINVAL;
		}
		return 0;

	case CK_ZONE:
		if (caly_parse_zone(val, (__u32 *)(void *)(base + k->off))) {
			caly_seterr(err, errsz,
				    "unknown zone (wan|lan|dmz): '%s'", val);
			return -EINVAL;
		}
		return 0;

	case CK_DATAPLANE:
		if (caly_parse_dataplane(val,
					 (__u32 *)(void *)(base + k->off))) {
			caly_seterr(err, errsz, "unknown dataplane: '%s'", val);
			return -EINVAL;
		}
		return 0;

	case CK_XDPMODE:
		if (caly_parse_xdp_mode(val,
					(__u32 *)(void *)(base + k->off))) {
			caly_seterr(err, errsz, "unknown xdp_mode: '%s'", val);
			return -EINVAL;
		}
		return 0;

	default:
		caly_seterr(err, errsz, "internal: bad key kind");
		return -EINVAL;
	}

	if (k->min && v < k->min) {
		caly_seterr(err, errsz, "value %llu below minimum %llu",
			    (unsigned long long)v, (unsigned long long)k->min);
		return -ERANGE;
	}
	if (k->max && v > k->max) {
		caly_seterr(err, errsz, "value %llu above maximum %llu",
			    (unsigned long long)v, (unsigned long long)k->max);
		return -ERANGE;
	}

	if (k->kind == CK_U32 || k->kind == CK_DUR_MS) {
		if (v > 0xFFFFFFFFULL) {
			caly_seterr(err, errsz,
				    "value %llu does not fit in 32 bits",
				    (unsigned long long)v);
			return -ERANGE;
		}
		*(__u32 *)(void *)(base + k->off) = (__u32)v;
	} else {
		*(__u64 *)(void *)(base + k->off) = v;
	}
	return 0;
}

int caly_conf_parse_string(struct caly_conf *c, const char *text,
			   const char *origin, char *err, size_t errsz)
{
	const char *cur = text;
	char section[64] = "general";
	char *line = NULL;
	size_t linecap = 0;
	size_t lineno = 0;
	int rc = 0;

	if (!c || !text)
		return -EINVAL;
	if (!origin)
		origin = "<memory>";

	while (*cur || lineno == 0) {
		const char *nl = strchr(cur, '\n');
		size_t len = nl ? (size_t)(nl - cur) : strlen(cur);
		char *s, *eq, *key, *val, *hash;

		lineno++;

		if (len + 1 > linecap) {
			char *p = realloc(line, len + 1);

			if (!p) {
				caly_seterr(err, errsz, "%s: out of memory",
					    origin);
				rc = -ENOMEM;
				goto out;
			}
			line = p;
			linecap = len + 1;
		}
		memcpy(line, cur, len);
		line[len] = '\0';

		if (nl)
			cur = nl + 1;
		else
			cur += len;

		hash = strchr(line, '#');
		if (hash)
			*hash = '\0';
		s = str_trim(line);
		if (*s == '\0')
			goto next;

		if (*s == '[') {
			char *close = strchr(s, ']');

			if (!close) {
				caly_seterr(err, errsz,
					    "%s:%zu: unterminated section header",
					    origin, lineno);
				rc = -EINVAL;
				goto out;
			}
			*close = '\0';
			snprintf(section, sizeof(section), "%s",
				 str_trim(s + 1));
			if (!known_section(section))
				caly_warn(c, "%s:%zu: unknown section [%s]",
					  origin, lineno, section);
			goto next;
		}

		eq = strchr(s, '=');
		if (!eq) {
			caly_seterr(err, errsz,
				    "%s:%zu: expected 'key = value'", origin,
				    lineno);
			rc = -EINVAL;
			goto out;
		}
		*eq = '\0';
		key = str_trim(s);
		val = str_trim(eq + 1);

		if (*key == '\0') {
			caly_seterr(err, errsz, "%s:%zu: empty key name",
				    origin, lineno);
			rc = -EINVAL;
			goto out;
		}

		{
			const struct caly_keydef *k = find_key(key);
			char sub[CALY_CONF_ERRSZ];

			if (!k) {
				if (c->strict) {
					caly_seterr(err, errsz,
						    "%s:%zu: unknown key '%s'",
						    origin, lineno, key);
					rc = -EINVAL;
					goto out;
				}
				caly_warn(c, "%s:%zu: ignoring unknown key '%s'",
					  origin, lineno, key);
				goto next;
			}

			sub[0] = '\0';
			if (k->kind == CK_CUSTOM) {
				/* An empty value is legal for every list
				 * directive: it is how the shipped file
				 * documents "nothing configured here". */
				if (*val == '\0')
					goto next;
				rc = k->fn(c, val, sub, sizeof(sub));
			} else {
				if (*val == '\0') {
					caly_seterr(err, errsz,
						    "%s:%zu: key '%s' needs a value",
						    origin, lineno, key);
					rc = -EINVAL;
					goto out;
				}
				rc = apply_scalar(c, k, val, sub, sizeof(sub));
			}
			if (rc) {
				caly_seterr(err, errsz, "%s:%zu: %s: %s",
					    origin, lineno, key,
					    sub[0] ? sub : strerror(-rc));
				goto out;
			}
		}
next:
		if (!nl)
			break;
	}
out:
	free(line);
	return rc;
}

int caly_conf_parse_file(struct caly_conf *c, const char *path,
			 char *err, size_t errsz)
{
	FILE *f;
	char *buf = NULL;
	size_t cap = 0, len = 0;
	int rc = 0;

	if (!c || !path)
		return -EINVAL;

	f = fopen(path, "re");
	if (!f) {
		rc = -errno;
		caly_seterr(err, errsz, "cannot open %s: %s", path,
			    strerror(-rc));
		return rc;
	}

	for (;;) {
		size_t got;

		if (len + 65536 + 1 > cap) {
			char *p;

			if (cap > (size_t)-1 - 131072) {
				rc = -EFBIG;
				caly_seterr(err, errsz, "%s: file too large",
					    path);
				goto out;
			}
			cap = cap ? cap * 2 : 131072;
			if (cap < len + 65537)
				cap = len + 65537;
			p = realloc(buf, cap);
			if (!p) {
				rc = -ENOMEM;
				caly_seterr(err, errsz, "%s: out of memory",
					    path);
				goto out;
			}
			buf = p;
		}
		got = fread(buf + len, 1, 65536, f);
		len += got;
		if (got < 65536) {
			if (ferror(f)) {
				rc = -EIO;
				caly_seterr(err, errsz, "%s: read error", path);
				goto out;
			}
			break;
		}
	}

	if (!buf) {
		buf = malloc(1);
		if (!buf) {
			rc = -ENOMEM;
			goto out;
		}
	}
	buf[len] = '\0';

	snprintf(c->path, sizeof(c->path), "%s", path);
	rc = caly_conf_parse_string(c, buf, path, err, errsz);
out:
	free(buf);
	fclose(f);
	return rc;
}

/* =========================================================================
 * Administrative peer detection
 * ========================================================================= */

static int peer_known(const struct caly_admin_peer *arr, size_t n,
		      const struct caly_cidr *cd)
{
	size_t i;

	for (i = 0; i < n; i++) {
		if (arr[i].addr.family != cd->family)
			continue;
		if (!memcmp(arr[i].addr.addr, cd->addr, 16))
			return 1;
	}
	return 0;
}

static void scan_proc_net(const char *path, int v6, const __u16 *ports,
			  size_t nports, struct caly_admin_peer *out,
			  size_t max, size_t *n)
{
	FILE *f;
	char line[512];
	int first = 1;

	f = fopen(path, "re");
	if (!f)
		return;

	while (fgets(line, sizeof(line), f)) {
		unsigned int w[8];
		unsigned int lport = 0, rport = 0, state = 0;
		struct caly_cidr cd;
		size_t i;
		int match = 0;

		if (first) {          /* header row */
			first = 0;
			continue;
		}

		memset(w, 0, sizeof(w));
		if (v6) {
			if (sscanf(line,
				   "%*u: %8x%8x%8x%8x:%4x %8x%8x%8x%8x:%4x %2x",
				   &w[0], &w[1], &w[2], &w[3], &lport,
				   &w[4], &w[5], &w[6], &w[7], &rport,
				   &state) != 11)
				continue;
		} else {
			if (sscanf(line, "%*u: %8x:%4x %8x:%4x %2x",
				   &w[0], &lport, &w[4], &rport, &state) != 5)
				continue;
		}

		(void)rport;                    /* not part of the decision */
		if (state != 0x01)              /* TCP_ESTABLISHED */
			continue;

		for (i = 0; i < nports; i++)
			if (ports[i] == (__u16)lport)
				match = 1;
		if (!match)
			continue;

		memset(&cd, 0, sizeof(cd));
		if (v6) {
			__u32 a[4];

			a[0] = w[4];
			a[1] = w[5];
			a[2] = w[6];
			a[3] = w[7];
			cd.family = CALY_AF_INET6;
			cd.prefixlen = 128;
			memcpy(cd.addr, a, 16);
			/* v4-mapped ::ffff:a.b.c.d shows up in tcp6 */
			if (cd.addr[0] == 0 && cd.addr[1] == 0 &&
			    cd.addr[2] == 0 && cd.addr[3] == 0 &&
			    cd.addr[4] == 0 && cd.addr[5] == 0 &&
			    cd.addr[6] == 0 && cd.addr[7] == 0 &&
			    cd.addr[8] == 0 && cd.addr[9] == 0 &&
			    cd.addr[10] == 0xFF && cd.addr[11] == 0xFF) {
				__u8 v4[4];

				memcpy(v4, cd.addr + 12, 4);
				memset(&cd, 0, sizeof(cd));
				cd.family = CALY_AF_INET;
				cd.prefixlen = 32;
				memcpy(cd.addr, v4, 4);
			}
		} else {
			__u32 a = w[4];

			cd.family = CALY_AF_INET;
			cd.prefixlen = 32;
			memcpy(cd.addr, &a, 4);
		}

		if (peer_known(out, *n, &cd))
			continue;
		if (*n >= max)
			break;
		out[*n].addr = cd;
		out[*n].addr.tag = CALY_TAG_ADMIN;
		out[*n].local_port = lport;
		out[*n].source = CALY_ADMIN_SRC_PROC;
		(*n)++;
	}
	fclose(f);
}

int caly_detect_admin_peers(const __u16 *ports, size_t nports,
			    struct caly_admin_peer *out, size_t max,
			    size_t *n)
{
	const char *env;

	if (!out || !n || max == 0)
		return -EINVAL;
	*n = 0;

	/* 1. $SSH_CONNECTION = "cip cport sip sport", $SSH_CLIENT =
	 *    "cip cport sport". Present when the daemon was launched from an
	 *    interactive session, which is exactly the risky case. */
	env = getenv("SSH_CONNECTION");
	if (!env)
		env = getenv("SSH_CLIENT");
	if (env) {
		char buf[256];
		char *p, *w;

		snprintf(buf, sizeof(buf), "%s", env);
		p = buf;
		w = next_word(&p);
		if (w && *w) {
			struct caly_cidr cd;

			if (!caly_parse_cidr(w, &cd) && cd.prefixlen >= 32) {
				cd.tag = CALY_TAG_ADMIN;
				out[*n].addr = cd;
				out[*n].local_port = 22;
				out[*n].source = CALY_ADMIN_SRC_ENV;
				(*n)++;
			}
		}
	}

	/* 2. Established inbound sockets on a management port. */
	if (ports && nports) {
		if (*n < max)
			scan_proc_net("/proc/net/tcp", 0, ports, nports,
				      out, max, n);
		if (*n < max)
			scan_proc_net("/proc/net/tcp6", 1, ports, nports,
				      out, max, n);
	}
	return 0;
}

/* =========================================================================
 * Finalisation: forced invariants, clamping, lockout refusal
 * ========================================================================= */

static int mgmt_has(const __u16 *list, __u32 n, __u16 port)
{
	__u32 i;

	for (i = 0; i < n && i < CALY_MGMT_PORTS_MAX; i++)
		if (list[i] == port)
			return 1;
	return 0;
}

static void clamp_u32(struct caly_conf *c, const char *name, __u32 *v,
		      __u32 lo, __u32 hi)
{
	if (*v < lo) {
		caly_warn(c, "%s: %u is below the minimum, clamped to %u",
			  name, *v, lo);
		*v = lo;
	} else if (*v > hi) {
		caly_warn(c, "%s: %u is above the maximum, clamped to %u",
			  name, *v, hi);
		*v = hi;
	}
}

/* Is `port` covered by an explicit open/ratelimit rule for `proto`? */
static int port_is_reachable(const struct caly_conf *c, __u32 proto, __u32 port)
{
	size_t i;
	int found = 0;

	for (i = 0; i < c->n_ports; i++) {
		const struct caly_portspec *ps = &c->ports[i];

		if (ps->proto != proto)
			continue;
		if (port < ps->lo || port > ps->hi)
			continue;
		found = (ps->mode != CALY_PORT_CLOSED);
	}
	return found;
}

int caly_conf_finalize(struct caly_conf *c, char *err, size_t errsz)
{
	struct fw_config *f;
	__u16 tcp[CALY_MGMT_PORTS_MAX];
	__u32 ntcp = 0, nudp = 0;
	size_t i;
	int mandatory4[CALY_ICMP4_MANDATORY_COUNT] = CALY_ICMP4_MANDATORY_INIT;
	int mandatory6[CALY_ICMP6_MANDATORY_COUNT] = CALY_ICMP6_MANDATORY_INIT;

	if (!c)
		return -EINVAL;
	f = &c->fw;

	f->abi_version = CALY_ABI_VERSION;

	/* ---------------------------------------------------------------
	 * 1. Management ports. TCP/22 occupies slot 0 unconditionally.
	 *
	 * Slot 0 is load bearing: caly_map_config_set() overwrites the
	 * 720-byte config in one memcpy, and a concurrently running XDP
	 * program can in principle observe a partially written struct. With
	 * 22 pinned at slot 0 and mgmt_tcp_count >= 1 in both the old and the
	 * new image, no interleaving of those bytes can ever produce a
	 * configuration in which SSH is not a management port.
	 * --------------------------------------------------------------- */
	memset(tcp, 0, sizeof(tcp));
	tcp[ntcp++] = 22;
	for (i = 0; i < c->n_mgmt_tcp; i++) {
		if (c->mgmt_tcp[i] == 22)
			continue;
		if (ntcp >= CALY_MGMT_PORTS_MAX) {
			caly_seterr(err, errsz,
				    "too many mgmt_tcp_ports: %zu configured, "
				    "at most %u fit (TCP/22 is always one of them)",
				    c->n_mgmt_tcp, CALY_MGMT_PORTS_MAX);
			return -E2BIG;
		}
		tcp[ntcp++] = c->mgmt_tcp[i];
	}
	memset(f->mgmt_tcp_ports, 0, sizeof(f->mgmt_tcp_ports));
	memcpy(f->mgmt_tcp_ports, tcp, ntcp * sizeof(__u16));
	f->mgmt_tcp_count = ntcp;

	memset(f->mgmt_udp_ports, 0, sizeof(f->mgmt_udp_ports));
	for (i = 0; i < c->n_mgmt_udp; i++) {
		if (nudp >= CALY_MGMT_PORTS_MAX) {
			caly_seterr(err, errsz,
				    "too many mgmt_udp_ports: at most %u",
				    CALY_MGMT_PORTS_MAX);
			return -E2BIG;
		}
		f->mgmt_udp_ports[nudp++] = c->mgmt_udp[i];
	}
	f->mgmt_udp_count = nudp;

	if (!mgmt_has(f->mgmt_tcp_ports, f->mgmt_tcp_count, 22)) {
		caly_seterr(err, errsz,
			    "internal: TCP/22 missing from the management list");
		return -EINVAL;
	}

	/* ---------------------------------------------------------------
	 * 2. Mode / flag coupling.
	 * --------------------------------------------------------------- */
	if (f->mode >= FW_MODE_MAX) {
		caly_seterr(err, errsz, "mode %u is not a valid mode", f->mode);
		return -EINVAL;
	}
	if (f->mode == FW_MODE_MONITOR_ONLY)
		f->flags |= CALY_F_MONITOR_ONLY;
	if (f->flags & CALY_F_MONITOR_ONLY)
		caly_warn(c, "monitor_only is enabled: every rule is evaluated "
			     "and reported but NOTHING is dropped");
	if (f->default_zone == CALY_ZONE_UNSPEC)
		f->default_zone = CALY_ZONE_LAN;
	if (f->default_zone >= CALY_ZONE_MAX) {
		caly_seterr(err, errsz, "default_zone %u is not a valid zone",
			    f->default_zone);
		return -EINVAL;
	}
	if (!(f->flags & CALY_F_ENABLED))
		caly_warn(c, "enabled = no: the dataplane will count packets "
			     "and pass all of them");

	/* Capability bits are discovered by the loader; the operator may not
	 * set them from the configuration file. */
	f->flags &= CALY_F_OPERATOR_MASK;

	/* ---------------------------------------------------------------
	 * 3. Parse-depth knobs may only LOWER the verifier-checked bounds.
	 * --------------------------------------------------------------- */
	if (f->vlan_max_depth > CALY_VLAN_MAX_DEPTH) {
		caly_warn(c, "vlan_max_depth %u clamped to the compiled bound %u",
			  f->vlan_max_depth, CALY_VLAN_MAX_DEPTH);
		f->vlan_max_depth = CALY_VLAN_MAX_DEPTH;
	}
	if (f->ip6_ext_max > CALY_IP6_EXT_MAX) {
		caly_warn(c, "ipv6_ext_max %u clamped to the compiled bound %u",
			  f->ip6_ext_max, CALY_IP6_EXT_MAX);
		f->ip6_ext_max = CALY_IP6_EXT_MAX;
	}
	if (f->tunnel_max_depth > CALY_TUNNEL_MAX_DEPTH) {
		caly_warn(c, "tunnel_max_depth %u clamped to the compiled bound %u",
			  f->tunnel_max_depth, CALY_TUNNEL_MAX_DEPTH);
		f->tunnel_max_depth = CALY_TUNNEL_MAX_DEPTH;
	}
	if (f->tcp_min_doff < 5) {
		caly_warn(c, "tcp_min_doff %u is below the protocol minimum, "
			     "raised to 5", f->tcp_min_doff);
		f->tcp_min_doff = 5;
	}

	/* ---------------------------------------------------------------
	 * 4. Token buckets.
	 * --------------------------------------------------------------- */
	for (i = 0; i < CALY_TB_MAX; i++) {
		if (f->tb_rate[i] > CALY_TB_RATE_MAX) {
			caly_warn(c, "tb_rate[%zu] clamped to %llu (arithmetic "
				     "bound)", i,
				  (unsigned long long)CALY_TB_RATE_MAX);
			f->tb_rate[i] = CALY_TB_RATE_MAX;
		}
		if (f->tb_burst[i] > CALY_TB_RATE_MAX)
			f->tb_burst[i] = CALY_TB_RATE_MAX;
		if (f->tb_rate[i] && f->tb_burst[i] == 0)
			caly_warn(c, "tb_rate[%zu] is set but its burst is 0: "
				     "that DISABLES the bucket", i);
		if (f->tb_rate[i] && f->tb_burst[i] &&
		    f->tb_burst[i] < f->tb_rate[i])
			caly_warn(c, "tb_burst[%zu] (%llu) is smaller than "
				     "tb_rate[%zu] (%llu): bursty but "
				     "conforming traffic will be penalised",
				  i, (unsigned long long)f->tb_burst[i], i,
				  (unsigned long long)f->tb_rate[i]);
	}

	/* ---------------------------------------------------------------
	 * 5. Banning / escalation sanity.
	 * --------------------------------------------------------------- */
	if (f->strike_limit == 0)
		f->strike_limit = 1;
	if (f->ban_escalate_den == 0)
		f->ban_escalate_den = 1;
	if (f->ban_ttl_base_ns == 0) {
		caly_warn(c, "ban_ttl_base is 0, raised to 1s");
		f->ban_ttl_base_ns = CALY_NSEC_PER_SEC;
	}
	if (f->ban_ttl_max_ns < f->ban_ttl_base_ns) {
		caly_warn(c, "ban_ttl_max is below ban_ttl_base, raised to it");
		f->ban_ttl_max_ns = f->ban_ttl_base_ns;
	}
	if (f->ban_ttl_scan_ns == 0)
		f->ban_ttl_scan_ns = f->ban_ttl_base_ns;
	if (f->ban_ttl_amp_ns == 0)
		f->ban_ttl_amp_ns = f->ban_ttl_base_ns;
	if (f->strike_window_ns == 0) {
		caly_warn(c, "strike_window is 0, raised to 60s");
		f->strike_window_ns = 60ULL * CALY_NSEC_PER_SEC;
	}

	/* ---------------------------------------------------------------
	 * 6. Hysteresis pairs. An inverted pair makes the daemon flap
	 *    between policies, which is worse than either policy.
	 * --------------------------------------------------------------- */
	{
		struct {
			const char *name;
			__u64 hi, lo;
		} pairs[] = {
			{ "global_pps",          f->global_pps_hi,
			  f->global_pps_lo },
			{ "global_bps",          f->global_bps_hi,
			  f->global_bps_lo },
			{ "global_syn_pps",      f->global_syn_pps_hi,
			  f->global_syn_pps_lo },
			{ "global_newconn_pps",  f->global_newconn_pps_hi,
			  f->global_newconn_pps_lo },
		};
		size_t p;

		for (p = 0; p < sizeof(pairs) / sizeof(pairs[0]); p++) {
			if (pairs[p].hi == 0 || pairs[p].lo == 0)
				continue;
			if (pairs[p].lo >= pairs[p].hi) {
				caly_seterr(err, errsz,
					    "%s_low (%llu) must be strictly "
					    "below %s_high (%llu) or the daemon "
					    "will oscillate between modes",
					    pairs[p].name,
					    (unsigned long long)pairs[p].lo,
					    pairs[p].name,
					    (unsigned long long)pairs[p].hi);
				return -EINVAL;
			}
		}
	}

	/* ---------------------------------------------------------------
	 * 7. Map sizing and daemon timings.
	 * --------------------------------------------------------------- */
	clamp_u32(c, "max_ban_entries",     &f->max_ban_entries,     1024,
		  4194304);
	clamp_u32(c, "max_conn_entries",    &f->max_conn_entries,    1024,
		  8388608);
	clamp_u32(c, "max_rate_entries",    &f->max_rate_entries,    1024,
		  8388608);
	clamp_u32(c, "max_scan_entries",    &f->max_scan_entries,    1024,
		  4194304);
	clamp_u32(c, "max_srcstat_entries", &f->max_srcstat_entries, 1024,
		  4194304);
	clamp_u32(c, "max_allow_entries",   &f->max_allow_entries,   16,
		  1048576);
	clamp_u32(c, "max_block_entries",   &f->max_block_entries,   16,
		  4194304);
	clamp_u32(c, "max_iface_entries",   &f->max_iface_entries,   4, 4096);
	clamp_u32(c, "poll_interval",       &f->poll_interval_ms,    1, 60000);
	clamp_u32(c, "stats_interval",      &f->stats_interval_ms,   10,
		  3600000);
	clamp_u32(c, "gc_interval",         &f->gc_interval_ms,      10,
		  3600000);
	clamp_u32(c, "gc_batch",            &f->gc_batch,            16,
		  1048576);

	if (f->max_allow_entries < c->n_allow + 16) {
		caly_warn(c, "max_allow_entries raised from %u to fit %zu "
			     "configured prefixes",
			  f->max_allow_entries, c->n_allow);
		f->max_allow_entries = (__u32)(c->n_allow + 16);
	}
	if (f->max_block_entries < c->n_block + 16) {
		caly_warn(c, "max_block_entries raised from %u to fit %zu "
			     "configured prefixes",
			  f->max_block_entries, c->n_block);
		f->max_block_entries = (__u32)(c->n_block + 16);
	}
	if (f->max_iface_entries < c->n_ifaces + 4)
		f->max_iface_entries = (__u32)(c->n_ifaces + 4);

	if (f->event_pages == 0 || (f->event_pages & (f->event_pages - 1))) {
		caly_seterr(err, errsz,
			    "event_pages must be a power of two, got %u",
			    f->event_pages);
		return -EINVAL;
	}

	if (f->scan_port_threshold > CALY_SCAN_BITMAP_BITS) {
		caly_seterr(err, errsz,
			    "scan_port_threshold %u exceeds the %u-bit Bloom "
			    "filter and can never be reached",
			    f->scan_port_threshold, CALY_SCAN_BITMAP_BITS);
		return -EINVAL;
	}
	if (f->scan_port_threshold > CALY_SCAN_BITMAP_BITS / 2)
		caly_warn(c, "scan_port_threshold %u is close to the Bloom "
			     "filter capacity (%u bits); collisions bias the "
			     "distinct-port estimate low and the threshold may "
			     "never trigger",
			  f->scan_port_threshold, CALY_SCAN_BITMAP_BITS);
	if (f->scan_window_ns == 0)
		f->scan_window_ns = 30ULL * CALY_NSEC_PER_SEC;

	/* ---------------------------------------------------------------
	 * 8. Feature interlocks.
	 * --------------------------------------------------------------- */
	if ((f->flags & CALY_F_DEFAULT_DENY) && !(f->flags & CALY_F_CONNTRACK)) {
		caly_seterr(err, errsz,
			    "default_deny = yes with conntrack = no would drop "
			    "the reply to every outbound connection this host "
			    "makes; enable conntrack or disable default_deny");
		return -EINVAL;
	}
	if ((f->flags & CALY_F_DEFAULT_DENY) &&
	    !(f->flags & CALY_F_PORT_POLICY)) {
		caly_warn(c, "default_deny requires port_policy; default_deny "
			     "has been disabled");
		f->flags &= ~CALY_F_DEFAULT_DENY;
	}
	if ((f->flags & CALY_F_ANTI_AMPLIFY) && !(f->flags & CALY_F_CONNTRACK))
		caly_warn(c, "anti_amplification without conntrack will drop "
			     "the replies to this host's own DNS/NTP queries");
	if (!(f->flags & CALY_F_IPV6))
		caly_warn(c, "ipv6 = no DROPS IPv6 traffic "
			     "(STAT_DROP_IP6_DISABLED); it does not pass it");
	if (!(f->flags & CALY_F_ALLOWLIST) && c->n_allow)
		caly_warn(c, "%zu allowlist prefixes are configured but "
			     "allowlist_enabled = no", c->n_allow);
	if ((f->flags & CALY_F_DEFAULT_DENY) && c->n_allow == 0)
		caly_warn(c, "default_deny is on with an empty allowlist: only "
			     "management ports and conntracked flows will reach "
			     "this host");

	/* ---------------------------------------------------------------
	 * 9. ICMP mandatory types. Non-negotiable.
	 * --------------------------------------------------------------- */
	for (i = 0; i < c->n_icmp; i++) {
		const struct caly_icmpspec *is = &c->icmp[i];
		size_t k;

		if (is->lo > 255 || is->hi > 255 || is->hi < is->lo) {
			caly_seterr(err, errsz,
				    "ICMP type range %u-%u is out of bounds",
				    is->lo, is->hi);
			return -EINVAL;
		}
		if (is->policy != CALY_ICMP_DROP)
			continue;
		if (is->family == CALY_AF_INET) {
			for (k = 0; k < CALY_ICMP4_MANDATORY_COUNT; k++) {
				__u32 t = (__u32)mandatory4[k];

				if (t >= is->lo && t <= is->hi) {
					caly_seterr(err, errsz,
						    "icmp4_type %u may never be "
						    "'drop': it carries "
						    "Fragmentation Needed and "
						    "dropping it black-holes "
						    "Path MTU Discovery", t);
					return -EINVAL;
				}
			}
		} else {
			for (k = 0; k < CALY_ICMP6_MANDATORY_COUNT; k++) {
				__u32 t = (__u32)mandatory6[k];

				if (t >= is->lo && t <= is->hi) {
					caly_seterr(err, errsz,
						    "icmp6_type %u may never be "
						    "'drop': IPv6 has no ARP, "
						    "and types 2/133/134/135/136 "
						    "are PMTUD and neighbour "
						    "discovery", t);
					return -EINVAL;
				}
			}
		}
	}

	/* ---------------------------------------------------------------
	 * 10. Port rules.
	 * --------------------------------------------------------------- */
	for (i = 0; i < c->n_ports; i++) {
		const struct caly_portspec *ps = &c->ports[i];

		if (ps->mode >= CALY_PORT_MODE_MAX) {
			caly_seterr(err, errsz, "invalid port mode %u",
				    ps->mode);
			return -EINVAL;
		}
		if (ps->lo > 65535 || ps->hi > 65535 || ps->hi < ps->lo) {
			caly_seterr(err, errsz, "invalid port range %u-%u",
				    ps->lo, ps->hi);
			return -EINVAL;
		}
		if (ps->proto == CALY_IPPROTO_TCP &&
		    ps->mode == CALY_PORT_CLOSED) {
			__u32 p;

			for (p = ps->lo; p <= ps->hi; p++)
				if (mgmt_has(f->mgmt_tcp_ports,
					     f->mgmt_tcp_count, (__u16)p))
					caly_warn(c, "tcp_port %u is 'closed' "
						     "but is also a management "
						     "port; the management "
						     "check runs first, so it "
						     "stays reachable", p);
		}
	}

	/* ---------------------------------------------------------------
	 * 11. Lockout refusal against a detected administrative session.
	 * --------------------------------------------------------------- */
	c->n_admin = 0;
	caly_detect_admin_peers(f->mgmt_tcp_ports, f->mgmt_tcp_count,
				c->admin, CALY_CONF_MAX_ADMIN, &c->n_admin);

	for (i = 0; i < c->n_admin; i++) {
		const struct caly_admin_peer *ap = &c->admin[i];
		char abuf[80];
		size_t j;
		int allowed = 0, blocked = 0;
		int mgmt = mgmt_has(f->mgmt_tcp_ports, f->mgmt_tcp_count,
				    (__u16)ap->local_port);

		caly_cidr_str(&ap->addr, abuf, sizeof(abuf));

		for (j = 0; j < c->n_allow; j++)
			if (caly_cidr_contains(&c->allow[j], &ap->addr))
				allowed = 1;
		for (j = 0; j < c->n_block; j++)
			if (caly_cidr_contains(&c->block[j], &ap->addr))
				blocked = 1;

		if (blocked && !allowed) {
			caly_seterr(err, errsz,
				    "refusing config: your own administrative "
				    "peer %s (connected to port %u) is covered "
				    "by a blocklist entry and is not "
				    "allowlisted", abuf, ap->local_port);
			return -EPERM;
		}

		if (f->mode == FW_MODE_LOCKDOWN && !allowed && !mgmt) {
			caly_seterr(err, errsz,
				    "refusing config: mode = lockdown passes "
				    "only allowlisted sources, management ports "
				    "and established flows, and your session "
				    "from %s to port %u matches none of them",
				    abuf, ap->local_port);
			return -EPERM;
		}

		if ((f->flags & CALY_F_DEFAULT_DENY) && !allowed && !mgmt &&
		    !port_is_reachable(c, CALY_IPPROTO_TCP, ap->local_port)) {
			caly_seterr(err, errsz,
				    "refusing config: default_deny is on and "
				    "port %u (your session from %s) is neither "
				    "a management port, nor allowlisted, nor "
				    "opened by a tcp_port rule",
				    ap->local_port, abuf);
			return -EPERM;
		}

		if (!allowed)
			caly_warn(c, "administrative peer %s is not in the "
				     "allowlist; consider adding it",
				  abuf);
	}

	/* ---------------------------------------------------------------
	 * 12. Blanket-prefix sanity.
	 * --------------------------------------------------------------- */
	for (i = 0; i < c->n_allow; i++)
		if (c->allow[i].prefixlen == 0)
			caly_warn(c, "allowlist contains a default route "
				     "(/0): NOTHING can be dropped for that "
				     "address family");
	for (i = 0; i < c->n_block; i++) {
		if (c->block[i].prefixlen != 0)
			continue;
		if (c->n_allow == 0) {
			caly_seterr(err, errsz,
				    "refusing config: blocklist contains a "
				    "default route (/0) and the allowlist is "
				    "empty; everything except management ports "
				    "would be dropped");
			return -EINVAL;
		}
		caly_warn(c, "blocklist contains a default route (/0): only "
			     "allowlisted sources and management ports will "
			     "reach this host");
	}

	c->finalized = 1;
	return 0;
}

int caly_conf_load(const char *path, struct caly_conf **out,
		   char *err, size_t errsz)
{
	struct caly_conf *c;
	int rc;

	if (!path || !out)
		return -EINVAL;
	*out = NULL;

	c = caly_conf_alloc();
	if (!c) {
		caly_seterr(err, errsz, "out of memory");
		return -ENOMEM;
	}

	rc = caly_conf_parse_file(c, path, err, errsz);
	if (rc == 0)
		rc = caly_conf_finalize(c, err, errsz);
	if (rc) {
		caly_conf_free(c);
		return rc;
	}
	*out = c;
	return 0;
}

/* =========================================================================
 * Diagnostics
 * ========================================================================= */

size_t caly_conf_warning_count(const struct caly_conf *c)
{
	return c ? c->n_warn : 0;
}

const char *caly_conf_warning(const struct caly_conf *c, size_t i)
{
	if (!c || i >= c->n_warn)
		return NULL;
	return c->warn[i];
}

void caly_conf_print(const struct caly_conf *c, FILE *f)
{
	char buf[80];
	size_t i;

	if (!c || !f)
		return;

	fprintf(f, "# caly anti configuration (%s)\n",
		c->path[0] ? c->path : "<defaults>");
	fprintf(f, "abi_version      = %u.%u\n",
		(unsigned)(c->fw.abi_version >> 16),
		(unsigned)(c->fw.abi_version & 0xFFFFu));
	fprintf(f, "mode             = %s\n", fw_mode_str(c->fw.mode));
	fprintf(f, "flags            = 0x%016llx\n",
		(unsigned long long)c->fw.flags);
	fprintf(f, "default_zone     = %u\n", c->fw.default_zone);
	fprintf(f, "dataplane_pref   = %s\n",
		caly_dataplane_str(c->fw.dataplane_pref));

	fprintf(f, "mgmt_tcp_ports   =");
	for (i = 0; i < c->fw.mgmt_tcp_count && i < CALY_MGMT_PORTS_MAX; i++)
		fprintf(f, " %u", c->fw.mgmt_tcp_ports[i]);
	fprintf(f, "\n");
	fprintf(f, "mgmt_udp_ports   =");
	for (i = 0; i < c->fw.mgmt_udp_count && i < CALY_MGMT_PORTS_MAX; i++)
		fprintf(f, " %u", c->fw.mgmt_udp_ports[i]);
	fprintf(f, "\n");

	for (i = 0; i < CALY_TB_MAX; i++)
		fprintf(f, "tb[%zu]            = %llu/s burst %llu\n", i,
			(unsigned long long)c->fw.tb_rate[i],
			(unsigned long long)c->fw.tb_burst[i]);

	fprintf(f, "allow            = %zu prefixes\n", c->n_allow);
	for (i = 0; i < c->n_allow; i++)
		fprintf(f, "  allow %s\n",
			caly_cidr_str(&c->allow[i], buf, sizeof(buf)));
	fprintf(f, "block            = %zu prefixes\n", c->n_block);
	fprintf(f, "local            = %zu prefixes\n", c->n_local);
	fprintf(f, "port rules       = %zu\n", c->n_ports);
	fprintf(f, "icmp rules       = %zu\n", c->n_icmp);
	fprintf(f, "interfaces       = %zu\n", c->n_ifaces);

	for (i = 0; i < c->n_admin; i++)
		fprintf(f, "admin peer       = %s -> port %u\n",
			caly_cidr_str(&c->admin[i].addr, buf, sizeof(buf)),
			c->admin[i].local_port);

	for (i = 0; i < c->n_warn; i++)
		fprintf(f, "warning: %s\n", c->warn[i]);
}

/* =========================================================================
 * SIGHUP driven reload
 * ========================================================================= */

volatile sig_atomic_t caly_reload_pending;

static void caly_sighup_handler(int sig)
{
	(void)sig;
	caly_reload_pending = 1;
}

int caly_conf_install_sighup(void)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = caly_sighup_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	if (sigaction(SIGHUP, &sa, NULL) < 0)
		return -errno;
	return 0;
}

int caly_conf_reload_pending_take(void)
{
	if (!caly_reload_pending)
		return 0;
	caly_reload_pending = 0;
	return 1;
}

int caly_conf_reload(struct caly_maps *maps, struct caly_conf **cur,
		     char *err, size_t errsz)
{
	struct caly_conf *fresh = NULL;
	char path[CALY_CONF_PATHSZ];
	int rc;

	if (!maps || !cur || !*cur)
		return -EINVAL;

	snprintf(path, sizeof(path), "%s",
		 (*cur)->path[0] ? (*cur)->path : CALY_CONF_PATH);

	/* Parse and validate in full BEFORE touching a single map. A config
	 * that does not survive caly_conf_finalize() never reaches the
	 * dataplane, so a typo cannot disarm a running firewall. */
	rc = caly_conf_load(path, &fresh, err, errsz);
	if (rc)
		return rc;

	/* Carry over the generation counter so config_gen stays monotonic
	 * across reloads even if the map is repopulated from scratch. */
	fresh->fw.config_gen = (*cur)->fw.config_gen + 1;

	rc = caly_maps_apply_config(maps, fresh, err, errsz);
	if (rc) {
		caly_conf_free(fresh);
		return rc;
	}

	caly_conf_free(*cur);
	*cur = fresh;
	return 0;
}
