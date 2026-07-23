/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/util.c
 *
 * See util.h for the contract.  Nothing in this file allocates without
 * checking, formats without bounds, or ignores a syscall return value.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "util.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/utsname.h>

#define CALY_U64_MAX  0xFFFFFFFFFFFFFFFFULL

/* Compile-time check that our family constants match common.h's. */
typedef char caly_util_af_check[(CALY_UTIL_AF_INET == 4u &&
				 CALY_UTIL_AF_INET6 == 6u) ? 1 : -1];

/* ================================================================== *
 * Safe strings
 * ================================================================== */

size_t caly_strlcpy(char *dst, const char *src, size_t dstsz)
{
	size_t srclen;

	if (src == NULL)
		src = "";
	srclen = strlen(src);

	if (dst == NULL || dstsz == 0)
		return srclen;

	if (srclen < dstsz) {
		memcpy(dst, src, srclen + 1);
	} else {
		memcpy(dst, src, dstsz - 1);
		dst[dstsz - 1] = '\0';
	}
	return srclen;
}

size_t caly_strlcat(char *dst, const char *src, size_t dstsz)
{
	size_t dlen, slen;

	if (src == NULL)
		src = "";
	slen = strlen(src);

	if (dst == NULL || dstsz == 0)
		return slen;

	dlen = strnlen(dst, dstsz);
	if (dlen == dstsz)          /* not NUL terminated: nothing sane to do */
		return dstsz + slen;

	if (dlen + slen < dstsz) {
		memcpy(dst + dlen, src, slen + 1);
	} else {
		memcpy(dst + dlen, src, dstsz - dlen - 1);
		dst[dstsz - 1] = '\0';
	}
	return dlen + slen;
}

int caly_vsnprintf(char *dst, size_t dstsz, const char *fmt, va_list ap)
{
	int n;

	if (dst == NULL || dstsz == 0)
		return -1;

	n = vsnprintf(dst, dstsz, fmt, ap);
	if (n < 0) {
		dst[0] = '\0';
		return -1;
	}
	if ((size_t)n >= dstsz) {
		dst[dstsz - 1] = '\0';
		return -1;          /* truncated */
	}
	return n;
}

int caly_snprintf(char *dst, size_t dstsz, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = caly_vsnprintf(dst, dstsz, fmt, ap);
	va_end(ap);
	return n;
}

char *caly_strdup(const char *s)
{
	size_t n;
	char *p;

	if (s == NULL)
		return NULL;
	n = strlen(s) + 1;
	p = malloc(n);
	if (p == NULL)
		return NULL;
	memcpy(p, s, n);
	return p;
}

char *caly_strndup(const char *s, size_t n)
{
	size_t len;
	char *p;

	if (s == NULL)
		return NULL;
	len = strnlen(s, n);
	p = malloc(len + 1);
	if (p == NULL)
		return NULL;
	memcpy(p, s, len);
	p[len] = '\0';
	return p;
}

char *caly_trim(char *s)
{
	char *end;

	if (s == NULL)
		return NULL;
	while (*s != '\0' && isspace((unsigned char)*s))
		s++;
	if (*s == '\0')
		return s;

	end = s + strlen(s) - 1;
	while (end > s && isspace((unsigned char)*end))
		end--;
	end[1] = '\0';
	return s;
}

int caly_streq(const char *a, const char *b)
{
	if (a == NULL || b == NULL)
		return a == b;
	return strcmp(a, b) == 0;
}

int caly_strcaseeq(const char *a, const char *b)
{
	if (a == NULL || b == NULL)
		return a == b;
	while (*a != '\0' && *b != '\0') {
		if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
			return 0;
		a++;
		b++;
	}
	return *a == *b;
}

int caly_str_startswith(const char *s, const char *prefix)
{
	size_t n;

	if (s == NULL || prefix == NULL)
		return 0;
	n = strlen(prefix);
	return strncmp(s, prefix, n) == 0;
}

int caly_str_split(char *s, const char *seps, char **out, int max)
{
	int n = 0;

	if (s == NULL || seps == NULL || out == NULL || max <= 0)
		return 0;

	while (*s != '\0' && n < max) {
		while (*s != '\0' && strchr(seps, *s) != NULL)
			s++;
		if (*s == '\0')
			break;
		out[n++] = s;
		while (*s != '\0' && strchr(seps, *s) == NULL)
			s++;
		if (*s != '\0')
			*s++ = '\0';
	}
	return n;
}

/* ================================================================== *
 * Value parsers
 * ================================================================== */

int caly_parse_bool(const char *s, int *out)
{
	if (s == NULL || out == NULL)
		return -1;

	if (caly_strcaseeq(s, "yes") || caly_strcaseeq(s, "true") ||
	    caly_strcaseeq(s, "on") || caly_streq(s, "1")) {
		*out = 1;
		return 0;
	}
	if (caly_strcaseeq(s, "no") || caly_strcaseeq(s, "false") ||
	    caly_strcaseeq(s, "off") || caly_streq(s, "0")) {
		*out = 0;
		return 0;
	}
	return -1;
}

int caly_parse_u64(const char *s, __u64 *out)
{
	unsigned long long v;
	char *end = NULL;

	if (s == NULL || out == NULL)
		return -1;

	while (*s != '\0' && isspace((unsigned char)*s))
		s++;
	if (*s == '\0' || *s == '-')
		return -1;

	errno = 0;
	v = strtoull(s, &end, 0);
	if (errno != 0 || end == s)
		return -1;
	while (*end != '\0' && isspace((unsigned char)*end))
		end++;
	if (*end != '\0')
		return -1;

	*out = (__u64)v;
	return 0;
}

int caly_parse_u32(const char *s, __u32 *out)
{
	__u64 v;

	if (out == NULL || caly_parse_u64(s, &v) != 0)
		return -1;
	if (v > 0xFFFFFFFFULL)
		return -1;
	*out = (__u32)v;
	return 0;
}

int caly_parse_u16(const char *s, __u16 *out)
{
	__u64 v;

	if (out == NULL || caly_parse_u64(s, &v) != 0)
		return -1;
	if (v > 0xFFFFULL)
		return -1;
	*out = (__u16)v;
	return 0;
}

/*
 * Shared front-end for the three scaled parsers.  Reads an optionally
 * fractional decimal number and hands back the integer and fractional parts
 * plus a pointer to the first character of the suffix.
 *
 * frac is normalised to billionths so that a nanosecond-resolution duration
 * loses nothing: "1.5" yields whole=1, frac=500000000.
 */
#define CALY_FRAC_SCALE  1000000000ULL

static int caly_parse_decimal(const char *s, __u64 *whole, __u64 *frac,
			      const char **suffix)
{
	__u64 w = 0, f = 0, div = 1;
	int digits = 0;

	while (*s != '\0' && isspace((unsigned char)*s))
		s++;
	if (!isdigit((unsigned char)*s))
		return -1;

	while (isdigit((unsigned char)*s)) {
		unsigned int d = (unsigned int)(*s - '0');

		if (w > (CALY_U64_MAX - d) / 10ULL)
			return -1;          /* overflow */
		w = w * 10ULL + d;
		s++;
		digits++;
	}

	if (*s == '.') {
		s++;
		while (isdigit((unsigned char)*s)) {
			if (div < CALY_FRAC_SCALE) {
				f = f * 10ULL + (__u64)(*s - '0');
				div *= 10ULL;
			}
			s++;
			digits++;
		}
	}
	if (digits == 0)
		return -1;

	/* Scale the fraction to billionths. */
	f = (div > 1ULL) ? (f * (CALY_FRAC_SCALE / div)) : 0ULL;

	while (*s != '\0' && isspace((unsigned char)*s))
		s++;

	*whole = w;
	*frac = f;
	*suffix = s;
	return 0;
}

/*
 * Multiply whole.frac by `mul` without losing the fraction and without
 * overflowing.  Returns -1 on overflow.
 *
 * The fraction term is computed by splitting MUL rather than FRAC.  Splitting
 * frac would evaluate (frac % 1e9) * mul, and with a day-scale multiplier
 * (86400e9) that is 1e9 * 8.64e13 = 8.6e22, which overflows __u64 silently.
 * frac is always < 1e9, so (mul % 1e9) * frac is at most ~1e18 and (mul / 1e9)
 * * frac is at most mul: both are safe.
 */
static int caly_scale(__u64 whole, __u64 frac, __u64 mul, __u64 *out)
{
	__u64 a, b;

	if (mul != 0 && whole > CALY_U64_MAX / mul)
		return -1;
	a = whole * mul;
	b = (mul / CALY_FRAC_SCALE) * frac +
	    ((mul % CALY_FRAC_SCALE) * frac) / CALY_FRAC_SCALE;
	if (a > CALY_U64_MAX - b)
		return -1;
	*out = a + b;
	return 0;
}

int caly_parse_duration_ns(const char *s, __u64 *out_ns)
{
	__u64 whole = 0, frac = 0, mul;
	const char *suf = NULL;
	__u64 v;

	if (s == NULL || out_ns == NULL)
		return -1;
	if (caly_parse_decimal(s, &whole, &frac, &suf) != 0)
		return -1;

	if (*suf == '\0')
		mul = 1000000000ULL;                    /* bare == seconds */
	else if (caly_strcaseeq(suf, "ns"))
		mul = 1ULL;
	else if (caly_strcaseeq(suf, "us") || caly_strcaseeq(suf, "usec"))
		mul = 1000ULL;
	else if (caly_strcaseeq(suf, "ms") || caly_strcaseeq(suf, "msec"))
		mul = 1000000ULL;
	else if (caly_strcaseeq(suf, "s") || caly_strcaseeq(suf, "sec"))
		mul = 1000000000ULL;
	else if (caly_strcaseeq(suf, "m") || caly_strcaseeq(suf, "min"))
		mul = 60ULL * 1000000000ULL;
	else if (caly_strcaseeq(suf, "h") || caly_strcaseeq(suf, "hr"))
		mul = 3600ULL * 1000000000ULL;
	else if (caly_strcaseeq(suf, "d") || caly_strcaseeq(suf, "day"))
		mul = 86400ULL * 1000000000ULL;
	else
		return -1;

	if (caly_scale(whole, frac, mul, &v) != 0)
		return -1;
	*out_ns = v;
	return 0;
}

/* Strip a trailing unit word that carries no scale information. */
static const char *caly_strip_rate_unit(const char *suf)
{
	static const char *const noise[] = {
		"pps", "bps", "b/s", "B/s", "/s", "ps", "b", "B", NULL
	};
	int i;

	for (i = 0; noise[i] != NULL; i++) {
		size_t n = strlen(noise[i]);

		if (strncasecmp(suf, noise[i], n) == 0 && suf[n] == '\0')
			return "";
	}
	return suf;
}

int caly_parse_rate(const char *s, __u64 *out)
{
	__u64 whole = 0, frac = 0, mul = 1;
	const char *suf = NULL;
	__u64 v;

	if (s == NULL || out == NULL)
		return -1;
	if (caly_parse_decimal(s, &whole, &frac, &suf) != 0)
		return -1;

	if (*suf == 'k' || *suf == 'K') {
		mul = 1000ULL;
		suf++;
	} else if (*suf == 'm' || *suf == 'M') {
		mul = 1000000ULL;
		suf++;
	} else if (*suf == 'g' || *suf == 'G') {
		mul = 1000000000ULL;
		suf++;
	}

	suf = caly_strip_rate_unit(suf);
	if (*suf != '\0')
		return -1;

	if (caly_scale(whole, frac, mul, &v) != 0)
		return -1;
	*out = v;
	return 0;
}

int caly_parse_size(const char *s, __u64 *out)
{
	__u64 whole = 0, frac = 0, mul = 1;
	const char *suf = NULL;
	__u64 v;

	if (s == NULL || out == NULL)
		return -1;
	if (caly_parse_decimal(s, &whole, &frac, &suf) != 0)
		return -1;

	if (*suf != '\0') {
		int binary = (suf[1] == 'i' || suf[1] == 'I');

		switch (*suf) {
		case 'k': case 'K':
			mul = binary ? 1024ULL : 1000ULL;
			break;
		case 'm': case 'M':
			mul = binary ? 1024ULL * 1024ULL : 1000000ULL;
			break;
		case 'g': case 'G':
			mul = binary ? 1024ULL * 1024ULL * 1024ULL
				     : 1000000000ULL;
			break;
		default:
			return -1;
		}
		suf += binary ? 2 : 1;

		/* Tolerate a trailing 'b'/'B' ("10MiB", "4kb"). */
		if (*suf == 'b' || *suf == 'B')
			suf++;
		if (*suf != '\0')
			return -1;
	}

	if (caly_scale(whole, frac, mul, &v) != 0)
		return -1;
	*out = v;
	return 0;
}

int caly_parse_port_range(const char *s, __u32 *lo, __u32 *hi)
{
	char buf[32];
	char *dash;
	__u32 a, b;

	if (s == NULL || lo == NULL || hi == NULL)
		return -1;
	if (caly_strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
		return -1;

	dash = strchr(buf, '-');
	if (dash != NULL) {
		*dash = '\0';
		if (caly_parse_u32(caly_trim(buf), &a) != 0)
			return -1;
		if (caly_parse_u32(caly_trim(dash + 1), &b) != 0)
			return -1;
	} else {
		if (caly_parse_u32(caly_trim(buf), &a) != 0)
			return -1;
		b = a;
	}

	if (a > 65535u || b > 65535u || a > b)
		return -1;

	*lo = a;
	*hi = b;
	return 0;
}

/* ================================================================== *
 * Addresses and prefixes
 * ================================================================== */

int caly_parse_ip4(const char *s, __u8 out[4])
{
	struct in_addr a;

	if (s == NULL || out == NULL)
		return -1;
	if (inet_pton(AF_INET, s, &a) != 1)
		return -1;
	memcpy(out, &a.s_addr, 4);      /* already network order */
	return 0;
}

int caly_parse_ip6(const char *s, __u8 out[16])
{
	struct in6_addr a;

	if (s == NULL || out == NULL)
		return -1;
	if (inet_pton(AF_INET6, s, &a) != 1)
		return -1;
	memcpy(out, &a, 16);
	return 0;
}

int caly_parse_cidr(const char *s, struct caly_cidr *out)
{
	char buf[CALY_CIDR_STRLEN + 16];
	struct caly_cidr c;
	char *slash;
	__u32 plen;

	if (s == NULL || out == NULL)
		return -1;
	if (caly_strlcpy(buf, s, sizeof(buf)) >= sizeof(buf))
		return -1;

	memset(&c, 0, sizeof(c));

	slash = strchr(buf, '/');
	if (slash != NULL) {
		*slash = '\0';
		if (caly_parse_u32(caly_trim(slash + 1), &plen) != 0)
			return -1;
	} else {
		plen = 0xFFFFFFFFu;     /* "use the family maximum" */
	}

	if (strchr(buf, ':') != NULL) {
		if (caly_parse_ip6(caly_trim(buf), c.addr) != 0)
			return -1;
		c.family = CALY_UTIL_AF_INET6;
		if (plen == 0xFFFFFFFFu)
			plen = 128u;
		if (plen > 128u)
			return -1;
	} else {
		if (caly_parse_ip4(caly_trim(buf), c.addr) != 0)
			return -1;
		c.family = CALY_UTIL_AF_INET;
		if (plen == 0xFFFFFFFFu)
			plen = 32u;
		if (plen > 32u)
			return -1;
	}

	c.prefixlen = plen;
	*out = c;
	return 0;
}

int caly_cidr_apply_mask(struct caly_cidr *c)
{
	unsigned int nbytes, i, full, rem;

	if (c == NULL)
		return -1;

	if (c->family == CALY_UTIL_AF_INET)
		nbytes = 4;
	else if (c->family == CALY_UTIL_AF_INET6)
		nbytes = 16;
	else
		return -1;

	if (c->prefixlen > nbytes * 8u)
		return -1;

	full = c->prefixlen / 8u;
	rem = c->prefixlen % 8u;

	if (rem != 0 && full < nbytes)
		c->addr[full] = (__u8)(c->addr[full] &
				       (__u8)(0xFFu << (8u - rem)));
	for (i = full + (rem != 0 ? 1u : 0u); i < 16u; i++)
		c->addr[i] = 0;
	return 0;
}

int caly_format_ip(__u32 family, const __u8 *addr, char *buf, size_t len)
{
	if (addr == NULL || buf == NULL || len == 0)
		return -1;
	buf[0] = '\0';

	if (family == CALY_UTIL_AF_INET) {
		if (len < INET_ADDRSTRLEN)
			return -1;
		if (inet_ntop(AF_INET, addr, buf, (socklen_t)len) == NULL)
			return -1;
		return 0;
	}
	if (family == CALY_UTIL_AF_INET6) {
		if (len < INET6_ADDRSTRLEN)
			return -1;
		if (inet_ntop(AF_INET6, addr, buf, (socklen_t)len) == NULL)
			return -1;
		return 0;
	}
	return -1;
}

int caly_format_cidr(const struct caly_cidr *c, char *buf, size_t len)
{
	char ip[CALY_ADDR_STRLEN];

	if (c == NULL || buf == NULL || len == 0)
		return -1;
	if (caly_format_ip(c->family, c->addr, ip, sizeof(ip)) != 0)
		return -1;
	return caly_snprintf(buf, len, "%s/%u", ip,
			     (unsigned int)c->prefixlen) < 0 ? -1 : 0;
}

int caly_format_ip4_be(__u32 be_addr, char *buf, size_t len)
{
	__u8 a[4];

	memcpy(a, &be_addr, 4);
	return caly_format_ip(CALY_UTIL_AF_INET, a, buf, len);
}

int caly_format_ip6_be(const __u32 be_words[4], char *buf, size_t len)
{
	__u8 a[16];

	if (be_words == NULL)
		return -1;
	memcpy(a, be_words, 16);
	return caly_format_ip(CALY_UTIL_AF_INET6, a, buf, len);
}

int caly_format_addr_words(__u32 family, const __u32 words[4],
			   char *buf, size_t len)
{
	if (words == NULL)
		return -1;
	if (family == CALY_UTIL_AF_INET)
		return caly_format_ip4_be(words[0], buf, len);
	if (family == CALY_UTIL_AF_INET6)
		return caly_format_ip6_be(words, buf, len);
	if (buf != NULL && len > 0)
		buf[0] = '\0';
	return -1;
}

/* ================================================================== *
 * Time
 * ================================================================== */

static __u64 caly_clock_ns(clockid_t clk)
{
	struct timespec ts;

	if (clock_gettime(clk, &ts) != 0) {
		/* CLOCK_BOOTTIME is 2.6.39+ and CLOCK_MONOTONIC is universal.
		 * Fall back rather than returning 0: a zero timestamp reads as
		 * "never seen" everywhere else in this codebase. */
		if (clk == CLOCK_MONOTONIC)
			return 0;
		if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
			return 0;
	}
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

__u64 caly_now_ns(void)
{
	return caly_clock_ns(CLOCK_MONOTONIC);
}

__u64 caly_boot_ns(void)
{
#ifdef CLOCK_BOOTTIME
	return caly_clock_ns(CLOCK_BOOTTIME);
#else
	return caly_clock_ns(CLOCK_MONOTONIC);
#endif
}

__u64 caly_wall_ns(void)
{
	return caly_clock_ns(CLOCK_REALTIME);
}

int caly_sleep_ms(unsigned int ms)
{
	struct timespec ts, rem;

	ts.tv_sec = (time_t)(ms / 1000u);
	ts.tv_nsec = (long)(ms % 1000u) * 1000000L;

	while (nanosleep(&ts, &rem) != 0) {
		if (errno != EINTR)
			return -1;
		ts = rem;
	}
	return 0;
}

int caly_fmt_duration_ns(__u64 ns, char *buf, size_t len)
{
	__u64 secs = ns / 1000000000ULL;
	__u64 msec = (ns % 1000000000ULL) / 1000000ULL;
	__u64 d, h, m, s;

	if (buf == NULL || len == 0)
		return -1;

	if (secs == 0) {
		if (msec > 0)
			return caly_snprintf(buf, len, "%llums",
					     (unsigned long long)msec) < 0
				? -1 : 0;
		return caly_snprintf(buf, len, "%lluns",
				     (unsigned long long)ns) < 0 ? -1 : 0;
	}

	d = secs / 86400ULL;
	h = (secs % 86400ULL) / 3600ULL;
	m = (secs % 3600ULL) / 60ULL;
	s = secs % 60ULL;

	if (d > 0)
		return caly_snprintf(buf, len, "%llud%lluh",
				     (unsigned long long)d,
				     (unsigned long long)h) < 0 ? -1 : 0;
	if (h > 0)
		return caly_snprintf(buf, len, "%lluh%llum",
				     (unsigned long long)h,
				     (unsigned long long)m) < 0 ? -1 : 0;
	if (m > 0)
		return caly_snprintf(buf, len, "%llum%llus",
				     (unsigned long long)m,
				     (unsigned long long)s) < 0 ? -1 : 0;
	return caly_snprintf(buf, len, "%llus", (unsigned long long)s) < 0
		? -1 : 0;
}

int caly_fmt_wallclock(__u64 wall_ns, char *buf, size_t len)
{
	time_t t = (time_t)(wall_ns / 1000000000ULL);
	struct tm tmv;

	if (buf == NULL || len == 0)
		return -1;
	buf[0] = '\0';

	if (localtime_r(&t, &tmv) == NULL)
		return -1;
	if (strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tmv) == 0)
		return -1;
	return 0;
}

__u64 caly_mono_to_wall_ns(__u64 mono_ns)
{
	__u64 mono = caly_now_ns();
	__u64 wall = caly_wall_ns();

	if (mono_ns >= mono)
		return wall + (mono_ns - mono);
	if (wall < (mono - mono_ns))
		return 0;
	return wall - (mono - mono_ns);
}

/* ================================================================== *
 * Files
 * ================================================================== */

int caly_file_exists(const char *path)
{
	struct stat st;

	if (path == NULL)
		return 0;
	return stat(path, &st) == 0;
}

int caly_is_dir(const char *path)
{
	struct stat st;

	if (path == NULL)
		return 0;
	if (stat(path, &st) != 0)
		return 0;
	return S_ISDIR(st.st_mode) ? 1 : 0;
}

int caly_mkdir_p(const char *path, mode_t mode)
{
	char buf[PATH_MAX_SAFE];
	size_t i, len;

	if (path == NULL || path[0] == '\0')
		return -1;
	if (caly_strlcpy(buf, path, sizeof(buf)) >= sizeof(buf)) {
		errno = ENAMETOOLONG;
		return -1;
	}

	len = strlen(buf);
	while (len > 1 && buf[len - 1] == '/')
		buf[--len] = '\0';

	for (i = 1; i < len; i++) {
		if (buf[i] != '/')
			continue;
		buf[i] = '\0';
		if (mkdir(buf, mode) != 0 && errno != EEXIST)
			return -1;
		buf[i] = '/';
	}
	if (mkdir(buf, mode) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

ssize_t caly_read_all(int fd, void *buf, size_t len)
{
	size_t done = 0;
	char *p = buf;

	if (fd < 0 || buf == NULL)
		return -1;

	while (done < len) {
		ssize_t n = read(fd, p + done, len - done);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		done += (size_t)n;
	}
	return (ssize_t)done;
}

ssize_t caly_write_all(int fd, const void *buf, size_t len)
{
	size_t done = 0;
	const char *p = buf;

	if (fd < 0 || buf == NULL)
		return -1;

	while (done < len) {
		ssize_t n = write(fd, p + done, len - done);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		done += (size_t)n;
	}
	return (ssize_t)done;
}

ssize_t caly_read_file(const char *path, void *buf, size_t len)
{
	int fd;
	ssize_t n;

	if (path == NULL || buf == NULL || len == 0)
		return -1;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	n = caly_read_all(fd, buf, len);
	/* A read-only descriptor has nothing to flush, so a close() error here
	 * cannot invalidate the bytes we already hold. */
	(void)close(fd);
	return n;
}

ssize_t caly_read_file_str(const char *path, char *buf, size_t len)
{
	ssize_t n;

	if (buf == NULL || len == 0)
		return -1;
	buf[0] = '\0';

	n = caly_read_file(path, buf, len - 1);
	if (n < 0)
		return -1;

	buf[n] = '\0';
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = '\0';
	return n;
}

int caly_read_u64_file(const char *path, __u64 *out)
{
	char buf[64];

	if (out == NULL)
		return -1;
	if (caly_read_file_str(path, buf, sizeof(buf)) < 0)
		return -1;
	return caly_parse_u64(caly_trim(buf), out);
}

int caly_write_file_atomic(const char *path, const void *data, size_t len,
			   mode_t mode)
{
	char tmp[PATH_MAX_SAFE];
	char dirbuf[PATH_MAX_SAFE];
	char *slash;
	int fd, dfd;
	ssize_t n;

	if (path == NULL || (data == NULL && len > 0))
		return -1;
	if (caly_snprintf(tmp, sizeof(tmp), "%s.tmpXXXXXX", path) < 0) {
		errno = ENAMETOOLONG;
		return -1;
	}

	fd = mkstemp(tmp);
	if (fd < 0)
		return -1;

	n = caly_write_all(fd, data, len);
	if (n < 0 || (size_t)n != len)
		goto fail;
	if (fchmod(fd, mode) != 0)
		goto fail;
	if (fsync(fd) != 0)
		goto fail;
	if (close(fd) != 0) {
		fd = -1;
		goto fail;
	}
	fd = -1;

	if (rename(tmp, path) != 0)
		goto fail;

	/* Make the rename durable. */
	if (caly_strlcpy(dirbuf, path, sizeof(dirbuf)) >= sizeof(dirbuf))
		return 0;   /* renamed already; only the fsync is skipped */
	slash = strrchr(dirbuf, '/');
	if (slash == NULL)
		return 0;
	if (slash == dirbuf)
		dirbuf[1] = '\0';
	else
		*slash = '\0';

	dfd = open(dirbuf, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dfd >= 0) {
		if (fsync(dfd) != 0)
			errno = 0;      /* best effort */
		(void)close(dfd);
	}
	return 0;

fail:
	{
		int saved = errno;

		if (fd >= 0)
			(void)close(fd);
		(void)unlink(tmp);
		errno = saved;
	}
	return -1;
}

int caly_set_cloexec(int fd)
{
	int flags = fcntl(fd, F_GETFD);

	if (flags < 0)
		return -1;
	if ((flags & FD_CLOEXEC) != 0)
		return 0;
	return fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0 ? -1 : 0;
}

int caly_set_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL);

	if (flags < 0)
		return -1;
	if ((flags & O_NONBLOCK) != 0)
		return 0;
	return fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ? -1 : 0;
}

void caly_close_fd(int *fd)
{
	if (fd == NULL || *fd < 0)
		return;
	(void)close(*fd);
	*fd = -1;
}

/* ================================================================== *
 * Pidfile
 * ================================================================== */

int caly_pidfile_acquire(const char *path, pid_t *other_pid)
{
	int fd;

	if (other_pid != NULL)
		*other_pid = 0;
	if (path == NULL)
		return -1;

	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
	if (fd < 0)
		return -1;

	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		int saved = errno;

		if (saved == EWOULDBLOCK || saved == EAGAIN) {
			pid_t p = 0;

			if (caly_pidfile_read(path, &p) == 0 && other_pid)
				*other_pid = p;
			saved = EEXIST;
		}
		(void)close(fd);
		errno = saved;
		return -1;
	}
	return fd;
}

int caly_pidfile_write(int fd, pid_t pid)
{
	char buf[32];
	int n;

	if (fd < 0)
		return -1;

	n = caly_snprintf(buf, sizeof(buf), "%ld\n", (long)pid);
	if (n < 0)
		return -1;
	if (ftruncate(fd, 0) != 0)
		return -1;
	if (lseek(fd, 0, SEEK_SET) == (off_t)-1)
		return -1;
	if (caly_write_all(fd, buf, (size_t)n) != (ssize_t)n)
		return -1;
	if (fsync(fd) != 0)
		return -1;
	return 0;
}

int caly_pidfile_read(const char *path, pid_t *out)
{
	char buf[32];
	__u64 v;

	if (out == NULL)
		return -1;
	if (caly_read_file_str(path, buf, sizeof(buf)) < 0)
		return -1;
	if (caly_parse_u64(caly_trim(buf), &v) != 0)
		return -1;
	if (v == 0 || v > 0x7FFFFFFFULL)
		return -1;
	*out = (pid_t)v;
	return 0;
}

void caly_pidfile_release(int fd, const char *path)
{
	if (path != NULL)
		(void)unlink(path);
	if (fd >= 0) {
		(void)flock(fd, LOCK_UN);
		(void)close(fd);
	}
}

/* ================================================================== *
 * Interfaces
 * ================================================================== */

unsigned int caly_if_index(const char *name)
{
	if (name == NULL || name[0] == '\0')
		return 0;
	return if_nametoindex(name);
}

const char *caly_if_name(unsigned int ifindex, char *buf, size_t len)
{
	char tmp[IF_NAMESIZE];

	if (buf == NULL || len == 0)
		return NULL;
	buf[0] = '\0';

	if (ifindex == 0)
		return NULL;
	if (if_indextoname(ifindex, tmp) == NULL)
		return NULL;
	if (caly_strlcpy(buf, tmp, len) >= len)
		return NULL;
	return buf;
}

static int caly_if_sysfs_path(const char *name, const char *leaf,
			      char *buf, size_t len)
{
	if (name == NULL || name[0] == '\0')
		return -1;
	/* Reject anything that could escape /sys/class/net. */
	if (strchr(name, '/') != NULL || caly_streq(name, ".") ||
	    caly_streq(name, ".."))
		return -1;
	if (strlen(name) >= IF_NAMESIZE)
		return -1;
	return caly_snprintf(buf, len, "/sys/class/net/%s/%s", name, leaf) < 0
		? -1 : 0;
}

int caly_if_is_up(const char *name)
{
	char path[PATH_MAX_SAFE];
	char buf[32];
	__u64 flags;

	if (caly_if_sysfs_path(name, "flags", path, sizeof(path)) != 0)
		return -1;
	if (caly_read_file_str(path, buf, sizeof(buf)) < 0)
		return -1;
	if (caly_parse_u64(caly_trim(buf), &flags) != 0)
		return -1;
	return (flags & 0x1ULL) != 0 ? 1 : 0;   /* IFF_UP */
}

int caly_if_is_loopback(const char *name)
{
	char path[PATH_MAX_SAFE];
	char buf[32];
	__u64 flags;

	if (caly_if_sysfs_path(name, "flags", path, sizeof(path)) != 0)
		return 0;
	if (caly_read_file_str(path, buf, sizeof(buf)) < 0)
		return 0;
	if (caly_parse_u64(caly_trim(buf), &flags) != 0)
		return 0;
	return (flags & 0x8ULL) != 0 ? 1 : 0;   /* IFF_LOOPBACK */
}

int caly_if_driver(const char *name, char *buf, size_t len)
{
	char path[PATH_MAX_SAFE];
	char link[PATH_MAX_SAFE];
	ssize_t n;
	const char *base;

	if (buf == NULL || len == 0)
		return -1;
	buf[0] = '\0';

	if (caly_if_sysfs_path(name, "device/driver", path,
			       sizeof(path)) != 0)
		return -1;

	n = readlink(path, link, sizeof(link) - 1);
	if (n < 0) {
		/* No backing device: veth, bridge, tun, wireguard, lo. */
		return caly_strlcpy(buf, "virtual", len) >= len ? -1 : 0;
	}
	link[n] = '\0';

	base = strrchr(link, '/');
	base = (base != NULL) ? base + 1 : link;
	return caly_strlcpy(buf, base, len) >= len ? -1 : 0;
}

/* Count directory entries whose name begins with `prefix`.  Returns the count
 * or -1 when the directory cannot be opened. */
static int caly_count_dir_prefix(const char *dirpath, const char *prefix)
{
	DIR *d;
	struct dirent *de;
	int count = 0;

	d = opendir(dirpath);
	if (d == NULL)
		return -1;

	errno = 0;
	while ((de = readdir(d)) != NULL) {
		if (caly_str_startswith(de->d_name, prefix))
			count++;
		errno = 0;
	}
	if (errno != 0) {
		int saved = errno;

		(void)closedir(d);
		errno = saved;
		return -1;
	}
	(void)closedir(d);
	return count;
}

int caly_if_num_rx_queues(const char *name)
{
	char path[PATH_MAX_SAFE];

	if (caly_if_sysfs_path(name, "queues", path, sizeof(path)) != 0)
		return -1;
	return caly_count_dir_prefix(path, "rx-");
}

int caly_if_enumerate(struct caly_if_entry *out, int max)
{
	struct if_nameindex *list, *p;
	int n = 0;

	if (out == NULL || max <= 0)
		return -1;

	list = if_nameindex();
	if (list == NULL)
		return -1;

	for (p = list; p->if_index != 0 || p->if_name != NULL; p++) {
		if (p->if_name == NULL)
			continue;
		if (n >= max)
			break;
		out[n].index = p->if_index;
		if (caly_strlcpy(out[n].name, p->if_name,
				 sizeof(out[n].name)) >= sizeof(out[n].name))
			continue;
		n++;
	}
	if_freenameindex(list);
	return n;
}

/* ================================================================== *
 * System probes
 * ================================================================== */

int caly_kernel_version(unsigned int *maj, unsigned int *min,
			unsigned int *patch)
{
	struct utsname u;
	unsigned int a = 0, b = 0, c = 0;

	if (uname(&u) != 0)
		return -1;
	if (sscanf(u.release, "%u.%u.%u", &a, &b, &c) < 2)
		return -1;

	if (maj != NULL)
		*maj = a;
	if (min != NULL)
		*min = b;
	if (patch != NULL)
		*patch = c;
	return 0;
}

__u32 caly_kver_code(unsigned int maj, unsigned int min, unsigned int patch)
{
	if (patch > 255u)
		patch = 255u;
	if (min > 255u)
		min = 255u;
	return (__u32)((maj << 16) | (min << 8) | patch);
}

int caly_have_btf(void)
{
	return access("/sys/kernel/btf/vmlinux", R_OK) == 0 ? 1 : 0;
}

int caly_is_container(void)
{
	char buf[512];
	ssize_t n;
	int fd;

	if (caly_file_exists("/proc/user_beancounters") ||
	    caly_file_exists("/proc/vz"))
		return 1;
	if (caly_file_exists("/.dockerenv") ||
	    caly_file_exists("/run/.containerenv"))
		return 1;

	/* /proc/1/environ carries container=lxc / container=podman when the
	 * init inside the container was started by a container manager. */
	fd = open("/proc/1/environ", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		n = caly_read_all(fd, buf, sizeof(buf) - 1);
		(void)close(fd);
		if (n > 0) {
			ssize_t i;

			buf[n] = '\0';
			/* NUL-separated; walk entry by entry. */
			for (i = 0; i < n; i += (ssize_t)strlen(buf + i) + 1) {
				if (caly_str_startswith(buf + i, "container="))
					return 1;
			}
		}
	}
	return 0;
}

int caly_detect_virt(char *buf, size_t len)
{
	char tmp[128];

	if (buf == NULL || len == 0)
		return 0;
	buf[0] = '\0';

	if (caly_file_exists("/proc/user_beancounters") ||
	    caly_file_exists("/proc/vz")) {
		(void)caly_strlcpy(buf, "openvz", len);
		return 1;
	}
	if (caly_file_exists("/.dockerenv")) {
		(void)caly_strlcpy(buf, "docker", len);
		return 1;
	}
	if (caly_file_exists("/run/.containerenv")) {
		(void)caly_strlcpy(buf, "podman", len);
		return 1;
	}
	if (caly_is_container()) {
		(void)caly_strlcpy(buf, "container", len);
		return 1;
	}
	if (caly_read_file_str("/sys/hypervisor/type", tmp, sizeof(tmp)) > 0) {
		(void)caly_strlcpy(buf, caly_trim(tmp), len);
		return 1;
	}
	if (caly_read_file_str("/sys/class/dmi/id/sys_vendor",
			       tmp, sizeof(tmp)) > 0) {
		const char *v = caly_trim(tmp);

		if (strstr(v, "QEMU") != NULL || strstr(v, "KVM") != NULL) {
			(void)caly_strlcpy(buf, "kvm", len);
			return 1;
		}
		if (strstr(v, "VMware") != NULL) {
			(void)caly_strlcpy(buf, "vmware", len);
			return 1;
		}
		if (strstr(v, "Microsoft") != NULL) {
			(void)caly_strlcpy(buf, "hyperv", len);
			return 1;
		}
		if (strstr(v, "Xen") != NULL) {
			(void)caly_strlcpy(buf, "xen", len);
			return 1;
		}
		if (strstr(v, "innotek") != NULL ||
		    strstr(v, "Oracle") != NULL) {
			(void)caly_strlcpy(buf, "virtualbox", len);
			return 1;
		}
		if (strstr(v, "Amazon") != NULL) {
			(void)caly_strlcpy(buf, "aws", len);
			return 1;
		}
		if (strstr(v, "Google") != NULL) {
			(void)caly_strlcpy(buf, "gcp", len);
			return 1;
		}
	}

	/* Last resort: the hypervisor CPUID bit surfaces in /proc/cpuinfo. */
	{
		char big[8192];
		ssize_t n = caly_read_file("/proc/cpuinfo", big,
					   sizeof(big) - 1);

		if (n > 0) {
			big[n] = '\0';
			if (strstr(big, "hypervisor") != NULL) {
				(void)caly_strlcpy(buf, "vm", len);
				return 1;
			}
		}
	}

	(void)caly_strlcpy(buf, "none", len);
	return 0;
}

long caly_num_possible_cpus(void)
{
	char buf[128];
	long n;
	char *p;
	long max_id = -1;

	if (caly_read_file_str("/sys/devices/system/cpu/possible",
			       buf, sizeof(buf)) > 0) {
		p = caly_trim(buf);
		/* Format is a comma-separated list of "a" or "a-b" ranges. */
		while (*p != '\0') {
			long a = 0, b = 0;
			char *end = NULL;

			errno = 0;
			a = strtol(p, &end, 10);
			if (end == p || errno != 0)
				break;
			p = end;
			b = a;
			if (*p == '-') {
				p++;
				errno = 0;
				b = strtol(p, &end, 10);
				if (end == p || errno != 0)
					break;
				p = end;
			}
			if (b > max_id)
				max_id = b;
			if (*p == ',')
				p++;
			else
				break;
		}
		if (max_id >= 0)
			return max_id + 1;
	}

	n = sysconf(_SC_NPROCESSORS_CONF);
	if (n > 0)
		return n;
	return 1;
}

int caly_have_capability(int cap)
{
	char buf[4096];
	ssize_t n;
	char *line;
	unsigned long long eff = 0;

	if (cap < 0 || cap > 63)
		return 0;

	n = caly_read_file("/proc/self/status", buf, sizeof(buf) - 1);
	if (n <= 0)
		return geteuid() == 0 ? 1 : 0;
	buf[n] = '\0';

	line = strstr(buf, "CapEff:");
	if (line == NULL)
		return geteuid() == 0 ? 1 : 0;

	if (sscanf(line + 7, "%llx", &eff) != 1)
		return geteuid() == 0 ? 1 : 0;

	return ((eff >> cap) & 1ULL) != 0 ? 1 : 0;
}

static int caly_sysctl_path(const char *name, char *buf, size_t len)
{
	size_t i, off;

	if (name == NULL || name[0] == '\0')
		return -1;
	if (strstr(name, "..") != NULL || strchr(name, '/') != NULL)
		return -1;

	off = caly_strlcpy(buf, "/proc/sys/", len);
	if (off >= len)
		return -1;

	for (i = 0; name[i] != '\0'; i++) {
		if (off + 1 >= len)
			return -1;
		buf[off++] = (name[i] == '.') ? '/' : name[i];
	}
	buf[off] = '\0';
	return 0;
}

int caly_sysctl_read(const char *name, char *buf, size_t len)
{
	char path[PATH_MAX_SAFE];

	if (caly_sysctl_path(name, path, sizeof(path)) != 0)
		return -1;
	return caly_read_file_str(path, buf, len) < 0 ? -1 : 0;
}

int caly_sysctl_read_int(const char *name, long *out)
{
	char buf[64];
	char *end = NULL;
	long v;

	if (out == NULL)
		return -1;
	if (caly_sysctl_read(name, buf, sizeof(buf)) != 0)
		return -1;

	errno = 0;
	v = strtol(caly_trim(buf), &end, 10);
	if (end == buf || errno != 0)
		return -1;
	*out = v;
	return 0;
}

int caly_sysctl_write(const char *name, const char *value)
{
	char path[PATH_MAX_SAFE];
	int fd;
	size_t len;
	ssize_t n;

	if (value == NULL)
		return -1;
	if (caly_sysctl_path(name, path, sizeof(path)) != 0)
		return -1;

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	len = strlen(value);
	n = caly_write_all(fd, value, len);
	if (close(fd) != 0 && n >= 0)
		return -1;
	return (n == (ssize_t)len) ? 0 : -1;
}
