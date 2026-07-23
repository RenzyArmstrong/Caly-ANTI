/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - src/user/util.h
 *
 * Dependency-free userspace helpers: safe strings, value parsers, CIDR
 * parse/format for v4 and v6, monotonic time, file helpers, interface
 * name/index resolution and a handful of system probes.
 *
 * This header intentionally does NOT include common.h or libbpf: it is the
 * bottom of the dependency graph and every other userspace object may include
 * it.  The only assumption it makes about the ABI is that CALY_UTIL_AF_INET
 * and CALY_UTIL_AF_INET6 have the same numeric values as CALY_AF_INET and
 * CALY_AF_INET6 in common.h (4 and 6), which is checked in util.c.
 *
 * Conventions used throughout:
 *   - functions returning int return 0 on success and -1 on failure unless
 *     documented otherwise; errno is left meaningful where the failure came
 *     from a syscall.
 *   - every function that writes into a caller buffer takes the buffer size
 *     and never truncates silently: truncation is reported as failure.
 *   - nothing here allocates unless the name says so (caly_strdup).
 */

#ifndef CALY_UTIL_H
#define CALY_UTIL_H

#include <stdarg.h>
#include <stddef.h>
#include <sys/types.h>
#include <net/if.h>
#include <linux/types.h>

/* Mirrors CALY_AF_INET / CALY_AF_INET6 from common.h. */
#define CALY_UTIL_AF_INET   4u
#define CALY_UTIL_AF_INET6  6u

/* Capability bit numbers (from include/uapi/linux/capability.h).  Used by
 * caly_have_capability(); CAP_BPF only exists on 5.8+, on older kernels the
 * equivalent authority is CAP_SYS_ADMIN. */
#define CALY_CAP_NET_ADMIN     12
#define CALY_CAP_NET_RAW       13
#define CALY_CAP_SYS_ADMIN     21
#define CALY_CAP_SYS_RESOURCE  24
#define CALY_CAP_PERFMON       38
#define CALY_CAP_BPF           39

/* Longest textual IPv6 CIDR: 39 chars + '/' + 3 digits + NUL. */
#define CALY_CIDR_STRLEN  48
/* Longest textual address alone. */
#define CALY_ADDR_STRLEN  46

/* Path buffer size used throughout the daemon.  Deliberately a local constant
 * rather than PATH_MAX: PATH_MAX is not guaranteed to be defined on every
 * libc, and every path this program builds is well under 4 KiB.  Every
 * function that builds a path reports truncation rather than proceeding. */
#define PATH_MAX_SAFE  4096

/* A parsed network prefix.  addr[] is in NETWORK byte order, most significant
 * byte first, exactly the layout struct lpm_key_v4/v6 wants.  For IPv4 only
 * addr[0..3] are meaningful; addr[4..15] are zeroed. */
struct caly_cidr {
	__u8  addr[16];
	__u32 prefixlen;
	__u32 family;      /* CALY_UTIL_AF_INET or CALY_UTIL_AF_INET6 */
};

struct caly_if_entry {
	unsigned int index;
	char         name[IF_NAMESIZE];
};

/* ------------------------------------------------------------------ *
 * Safe strings
 * ------------------------------------------------------------------ */

/* BSD strlcpy/strlcat semantics: always NUL terminate (when dstsz > 0) and
 * return the length the result WOULD have had, so truncation is
 * "return >= dstsz". */
size_t caly_strlcpy(char *dst, const char *src, size_t dstsz);
size_t caly_strlcat(char *dst, const char *src, size_t dstsz);

/* snprintf wrappers that treat truncation as an error.  Return the number of
 * bytes written (excluding the NUL) or -1 on error/truncation.  dst is always
 * NUL terminated when dstsz > 0. */
int caly_vsnprintf(char *dst, size_t dstsz, const char *fmt, va_list ap);
int caly_snprintf(char *dst, size_t dstsz, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

/* Allocating helpers.  Return NULL on allocation failure - callers must
 * check; nothing in this tree calls malloc without checking. */
char *caly_strdup(const char *s);
char *caly_strndup(const char *s, size_t n);

/* In-place whitespace trim.  Returns a pointer into s. */
char *caly_trim(char *s);

int caly_streq(const char *a, const char *b);
int caly_strcaseeq(const char *a, const char *b);
int caly_str_startswith(const char *s, const char *prefix);

/* Destructive split on any character in `seps`.  Consecutive separators are
 * collapsed.  Returns the number of fields stored in out[] (at most max). */
int caly_str_split(char *s, const char *seps, char **out, int max);

/* ------------------------------------------------------------------ *
 * Value parsers.  All return 0 on success, -1 on malformed input, and never
 * write to *out on failure.
 * ------------------------------------------------------------------ */

/* yes/no/true/false/on/off/1/0, case-insensitive. */
int caly_parse_bool(const char *s, int *out);

int caly_parse_u64(const char *s, __u64 *out);
int caly_parse_u32(const char *s, __u32 *out);
int caly_parse_u16(const char *s, __u16 *out);

/* Duration -> nanoseconds.  Suffixes ns/us/ms/s/m/h/d; a bare integer means
 * SECONDS.  Accepts a decimal point ("1.5s"). */
int caly_parse_duration_ns(const char *s, __u64 *out_ns);

/* Rate -> units/second.  Suffix k/m/g = 1e3/1e6/1e9 (decimal, not binary).
 * An optional trailing unit word (pps, bps, b, B, /s) is ignored.  BYTE rates
 * are bytes, never bits: 125m is 1 Gbit/s. */
int caly_parse_rate(const char *s, __u64 *out);

/* Size -> bytes.  k/m/g = 1e3/1e6/1e9, ki/mi/gi = 1024^n. */
int caly_parse_size(const char *s, __u64 *out);

/* "80" or "1000-2000".  Both bounds inclusive, 0..65535. */
int caly_parse_port_range(const char *s, __u32 *lo, __u32 *hi);

/* ------------------------------------------------------------------ *
 * Addresses and prefixes
 * ------------------------------------------------------------------ */

int caly_parse_ip4(const char *s, __u8 out[4]);
int caly_parse_ip6(const char *s, __u8 out[16]);

/* "a.b.c.d", "a.b.c.d/len", "::1", "2001:db8::/32".  A bare address gets the
 * full-length prefix (32 or 128).  Host bits are NOT cleared - call
 * caly_cidr_apply_mask() if you want them zeroed (recommended before an LPM
 * trie insert so that two spellings of the same prefix cannot both exist). */
int caly_parse_cidr(const char *s, struct caly_cidr *out);

/* Zero every bit below prefixlen.  Returns 0, or -1 if the prefix length is
 * out of range for the family. */
int caly_cidr_apply_mask(struct caly_cidr *c);

/* Formatting.  Return 0 on success, -1 on truncation or bad family. */
int caly_format_ip(__u32 family, const __u8 *addr, char *buf, size_t len);
int caly_format_cidr(const struct caly_cidr *c, char *buf, size_t len);

/* Convenience for the on-the-wire representations used by struct event and
 * struct conn_key: a network-order __u32 and a network-order __u32[4]. */
int caly_format_ip4_be(__u32 be_addr, char *buf, size_t len);
int caly_format_ip6_be(const __u32 be_words[4], char *buf, size_t len);

/* Format whichever of the two the family selects.  `words` must point at four
 * network-order __u32 (IPv4 uses words[0] only), matching struct event. */
int caly_format_addr_words(__u32 family, const __u32 words[4],
			   char *buf, size_t len);

/* ------------------------------------------------------------------ *
 * Time
 * ------------------------------------------------------------------ */

/* CLOCK_MONOTONIC in nanoseconds.  This is the same clock bpf_ktime_get_ns()
 * reads, so values from BPF maps may be compared with it directly. */
__u64 caly_now_ns(void);

/* CLOCK_BOOTTIME (includes suspend) - the clock bpf_ktime_get_boot_ns() uses. */
__u64 caly_boot_ns(void);

/* CLOCK_REALTIME in nanoseconds, for human-readable timestamps only. */
__u64 caly_wall_ns(void);

/* Sleep, restarting across EINTR.  Returns 0. */
int caly_sleep_ms(unsigned int ms);

/* "3d4h", "1m30s", "250ms".  Returns 0 on success, -1 on truncation. */
int caly_fmt_duration_ns(__u64 ns, char *buf, size_t len);

/* "2026-07-23 14:05:11" from a CLOCK_REALTIME nanosecond value. */
int caly_fmt_wallclock(__u64 wall_ns, char *buf, size_t len);

/* Convert a CLOCK_MONOTONIC nanosecond stamp (as produced by BPF) into a
 * CLOCK_REALTIME one so it can be printed.  Approximate by construction: the
 * offset is sampled at call time. */
__u64 caly_mono_to_wall_ns(__u64 mono_ns);

/* ------------------------------------------------------------------ *
 * Files and file descriptors
 * ------------------------------------------------------------------ */

int  caly_file_exists(const char *path);
int  caly_is_dir(const char *path);

/* mkdir -p.  Existing directories are not an error. */
int  caly_mkdir_p(const char *path, mode_t mode);

/* Read at most len-1 bytes, NUL terminate, strip one trailing newline.
 * Returns the number of bytes stored, or -1. */
ssize_t caly_read_file_str(const char *path, char *buf, size_t len);

/* Read up to len bytes of binary content.  Returns bytes read or -1. */
ssize_t caly_read_file(const char *path, void *buf, size_t len);

/* Write via a temporary file in the same directory + rename, so a reader
 * never observes a partial file.  Returns 0 or -1. */
int  caly_write_file_atomic(const char *path, const void *data, size_t len,
			    mode_t mode);

int  caly_read_u64_file(const char *path, __u64 *out);

/* Loop over short reads/writes and EINTR.  Return the full count or -1. */
ssize_t caly_write_all(int fd, const void *buf, size_t len);
ssize_t caly_read_all(int fd, void *buf, size_t len);

int  caly_set_cloexec(int fd);
int  caly_set_nonblock(int fd);

/* Close and set *fd to -1.  Safe on -1.  Retries are not needed: Linux
 * releases the descriptor even when close() reports an error. */
void caly_close_fd(int *fd);

/* ------------------------------------------------------------------ *
 * Pidfile.  flock-based, so a crashed previous instance leaves a stale file
 * that is detected and taken over rather than blocking startup forever.
 * ------------------------------------------------------------------ */

/* Returns a held file descriptor on success (keep it open for the process
 * lifetime - closing it releases the lock), or -1.  When another live
 * instance holds the lock, errno is set to EEXIST and *other_pid, when
 * non-NULL, receives its pid. */
int  caly_pidfile_acquire(const char *path, pid_t *other_pid);
int  caly_pidfile_write(int fd, pid_t pid);
int  caly_pidfile_read(const char *path, pid_t *out);
void caly_pidfile_release(int fd, const char *path);

/* ------------------------------------------------------------------ *
 * Interfaces
 * ------------------------------------------------------------------ */

/* 0 when the interface does not exist. */
unsigned int caly_if_index(const char *name);

/* Returns buf on success, NULL on failure.  len must be >= IF_NAMESIZE. */
const char *caly_if_name(unsigned int ifindex, char *buf, size_t len);

/* 1 up, 0 down, -1 unknown. */
int caly_if_is_up(const char *name);

/* 1 if the interface is a loopback device. */
int caly_if_is_loopback(const char *name);

/* Driver name from /sys/class/net/<if>/device/driver.  Virtual devices have
 * no such link; the function then reports "virtual". */
int caly_if_driver(const char *name, char *buf, size_t len);

/* Number of combined/rx channels, or -1 when unknown.  Native XDP on
 * virtio-net needs at least as many queues as CPUs. */
int caly_if_num_rx_queues(const char *name);

/* Fills out[] with every interface on the system.  Returns the count stored
 * (<= max), or -1. */
int caly_if_enumerate(struct caly_if_entry *out, int max);

/* ------------------------------------------------------------------ *
 * System probes
 * ------------------------------------------------------------------ */

int  caly_kernel_version(unsigned int *maj, unsigned int *min,
			 unsigned int *patch);
__u32 caly_kver_code(unsigned int maj, unsigned int min, unsigned int patch);

/* 1 when /sys/kernel/btf/vmlinux is readable. */
int  caly_have_btf(void);

/* 1 when running virtualised, 0 when bare metal, and a short token such as
 * "kvm", "vmware", "xen", "openvz", "lxc", "docker" written into buf. */
int  caly_detect_virt(char *buf, size_t len);

/* 1 when running inside a container (OpenVZ, LXC, Docker, podman). */
int  caly_is_container(void);

long caly_num_possible_cpus(void);

/* 1 when the effective capability set contains `cap`.  Root (euid 0) without
 * capability filtering reports 1 for everything. */
int  caly_have_capability(int cap);

/* sysctl name in dotted form, e.g. "net.ipv4.tcp_syncookies". */
int  caly_sysctl_read(const char *name, char *buf, size_t len);
int  caly_sysctl_write(const char *name, const char *value);
int  caly_sysctl_read_int(const char *name, long *out);

#endif /* CALY_UTIL_H */
