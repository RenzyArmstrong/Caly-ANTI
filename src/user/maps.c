/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - XDP/eBPF DDoS mitigation suite
 * src/user/maps.c - typed userspace wrappers over every map in the ABI.
 *
 * See src/user/maps.h for the contract.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "maps.h"

/*
 * BPF_MAP_*_BATCH wrappers appeared in libbpf 0.0.7 but the version macros
 * only exist from 0.6, so anything older silently falls back to the
 * per-entry loops below. A build system that has probed for the symbols can
 * force the fast path with -DCALY_HAVE_BATCH_OPS=1.
 */
#ifndef CALY_HAVE_BATCH_OPS
#  if defined(LIBBPF_MAJOR_VERSION)
#    define CALY_HAVE_BATCH_OPS 1
#  else
#    define CALY_HAVE_BATCH_OPS 0
#  endif
#endif

#define CALY_ARRAY_SIZE(a)  (sizeof(a) / sizeof((a)[0]))
#define CALY_ROUND_UP8(x)   (((x) + 7u) & ~(size_t)7u)
#define CALY_PORT_TABLE_SZ  65536u
#define CALY_ICMP_TABLE_SZ  256u

/* =========================================================================
 * Errno normalisation
 *
 * libbpf < 1.0 returns -1 and sets errno; libbpf >= 1.0 returns -errno and
 * also sets errno. Reading errno therefore works for both, with a defensive
 * fallback for the (impossible in practice) case of errno == 0.
 * ========================================================================= */

static int caly_err(int ret)
{
	int e;

	if (ret >= 0)
		return 0;
	e = errno;
	if (e > 0)
		return -e;
	if (ret < -1)
		return ret;
	return -EIO;
}

static void caly_seterr(char *err, size_t errsz, const char *fmt, ...)
	__attribute__((format(printf, 3, 4)));

static void caly_seterr(char *err, size_t errsz, const char *fmt, ...)
{
	va_list ap;

	if (!err || errsz == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(err, errsz, fmt, ap);
	va_end(ap);
}

/* =========================================================================
 * Map name table
 * ========================================================================= */

static const char *const caly_map_names[CALY_MAP_ID_MAX] = {
	[CALY_MAP_ID_CONFIG]    = CALY_MAP_CONFIG,
	[CALY_MAP_ID_STATS]     = CALY_MAP_STATS,
	[CALY_MAP_ID_STATS_B]   = CALY_MAP_STATS_BYTES,
	[CALY_MAP_ID_GLOBAL]    = CALY_MAP_GLOBAL,
	[CALY_MAP_ID_ALLOW4]    = CALY_MAP_ALLOW_V4,
	[CALY_MAP_ID_ALLOW6]    = CALY_MAP_ALLOW_V6,
	[CALY_MAP_ID_BLOCK4]    = CALY_MAP_BLOCK_V4,
	[CALY_MAP_ID_BLOCK6]    = CALY_MAP_BLOCK_V6,
	[CALY_MAP_ID_LOCAL4]    = CALY_MAP_LOCAL_V4,
	[CALY_MAP_ID_LOCAL6]    = CALY_MAP_LOCAL_V6,
	[CALY_MAP_ID_BAN4]      = CALY_MAP_BAN_V4,
	[CALY_MAP_ID_BAN6]      = CALY_MAP_BAN_V6,
	[CALY_MAP_ID_RATE4]     = CALY_MAP_RATE_V4,
	[CALY_MAP_ID_RATE6]     = CALY_MAP_RATE_V6,
	[CALY_MAP_ID_CONN]      = CALY_MAP_CONN,
	[CALY_MAP_ID_SCAN4]     = CALY_MAP_SCAN_V4,
	[CALY_MAP_ID_SCAN6]     = CALY_MAP_SCAN_V6,
	[CALY_MAP_ID_TOP4]      = CALY_MAP_TOP_V4,
	[CALY_MAP_ID_TOP6]      = CALY_MAP_TOP_V6,
	[CALY_MAP_ID_PORT_TCP]  = CALY_MAP_PORT_TCP,
	[CALY_MAP_ID_PORT_UDP]  = CALY_MAP_PORT_UDP,
	[CALY_MAP_ID_PORT_TB]   = CALY_MAP_PORT_TB,
	[CALY_MAP_ID_ICMP4_POL] = CALY_MAP_ICMP4_POL,
	[CALY_MAP_ID_ICMP6_POL] = CALY_MAP_ICMP6_POL,
	[CALY_MAP_ID_IFACE]     = CALY_MAP_IFACE,
	[CALY_MAP_ID_EVENTS]    = CALY_MAP_EVENTS,
	[CALY_MAP_ID_EVENTS_RB] = CALY_MAP_EVENTS_RB,
	[CALY_MAP_ID_PROGS]     = CALY_MAP_PROGS,
	[CALY_MAP_ID_SCRATCH]   = CALY_MAP_SCRATCH,
};

/* Maps whose absence is not an error: ringbuf needs 5.8+, the prog array and
 * the scratch area are only interesting to the loader itself. */
static int map_is_optional(int id)
{
	return id == CALY_MAP_ID_EVENTS_RB || id == CALY_MAP_ID_PROGS ||
	       id == CALY_MAP_ID_SCRATCH;
}

const char *caly_map_name(int id)
{
	if (id < 0 || id >= CALY_MAP_ID_MAX || !caly_map_names[id])
		return "(invalid)";
	return caly_map_names[id];
}

int caly_maps_fd(const struct caly_maps *m, int id)
{
	if (!m || id < 0 || id >= CALY_MAP_ID_MAX)
		return -EINVAL;
	if (m->fd[id] < 0)
		return -ENOENT;
	return m->fd[id];
}

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

void caly_maps_init(struct caly_maps *m)
{
	int i;

	if (!m)
		return;
	memset(m, 0, sizeof(*m));
	for (i = 0; i < CALY_MAP_ID_MAX; i++)
		m->fd[i] = -1;
	m->ncpu = libbpf_num_possible_cpus();
	if (m->ncpu <= 0)
		m->ncpu = 1;
	m->lpm_shadow_enabled = 1;
	m->have_batch = CALY_HAVE_BATCH_OPS;
}

void caly_maps_close(struct caly_maps *m)
{
	int i, s, f;

	if (!m)
		return;
	for (i = 0; i < CALY_MAP_ID_MAX; i++) {
		if (m->owned[i] && m->fd[i] >= 0)
			close(m->fd[i]);
		m->fd[i] = -1;
		m->owned[i] = 0;
	}
	free(m->shadow_tcp);
	free(m->shadow_udp);
	m->shadow_tcp = NULL;
	m->shadow_udp = NULL;
	for (s = 0; s < CALY_SET_MAX; s++) {
		for (f = 0; f < 2; f++) {
			free(m->lpm_shadow[s][f].v);
			m->lpm_shadow[s][f].v = NULL;
			m->lpm_shadow[s][f].n = 0;
			m->lpm_shadow[s][f].cap = 0;
		}
	}
}

int caly_maps_set_fd(struct caly_maps *m, int id, int fd, int owned)
{
	if (!m || id < 0 || id >= CALY_MAP_ID_MAX)
		return -EINVAL;
	if (m->owned[id] && m->fd[id] >= 0 && m->fd[id] != fd)
		close(m->fd[id]);
	m->fd[id] = fd;
	m->owned[id] = owned ? 1 : 0;
	return 0;
}

void caly_maps_mark_fresh(struct caly_maps *m)
{
	if (m)
		m->fresh = 1;
}

int caly_maps_bind_object(struct caly_maps *m, struct bpf_object *obj,
			  char *err, size_t errsz)
{
	int i;

	if (!m || !obj)
		return -EINVAL;
	if (m->ncpu <= 0)
		caly_maps_init(m);

	for (i = 0; i < CALY_MAP_ID_MAX; i++) {
		struct bpf_map *map;
		int fd;

		map = bpf_object__find_map_by_name(obj, caly_map_name(i));
		if (!map) {
			if (map_is_optional(i))
				continue;
			caly_seterr(err, errsz,
				    "BPF object has no map named '%s'",
				    caly_map_name(i));
			return -ENOENT;
		}
		fd = bpf_map__fd(map);
		if (fd < 0) {
			if (map_is_optional(i))
				continue;
			caly_seterr(err, errsz,
				    "map '%s' is not created yet (fd %d)",
				    caly_map_name(i), fd);
			return -EBADF;
		}
		/* libbpf owns these fds; do not close them. */
		caly_maps_set_fd(m, i, fd, 0);
	}
	caly_maps_probe_batch(m);
	return 0;
}

int caly_maps_open_pinned(struct caly_maps *m, const char *pin_dir,
			  char *err, size_t errsz)
{
	char path[4096];
	int i;

	if (!m)
		return -EINVAL;
	if (m->ncpu <= 0)
		caly_maps_init(m);
	if (!pin_dir || !*pin_dir)
		pin_dir = CALY_PIN_DIR;

	for (i = 0; i < CALY_MAP_ID_MAX; i++) {
		int fd;

		snprintf(path, sizeof(path), "%s/%s", pin_dir,
			 caly_map_name(i));
		errno = 0;
		fd = bpf_obj_get(path);
		if (fd < 0) {
			if (map_is_optional(i))
				continue;
			caly_seterr(err, errsz, "cannot open pin %s: %s",
				    path, strerror(errno ? errno : ENOENT));
			return caly_err(fd);
		}
		caly_maps_set_fd(m, i, fd, 1);
	}
	caly_maps_probe_batch(m);
	return 0;
}

__u64 caly_now_ns(void)
{
	struct timespec ts;

	/* bpf_ktime_get_ns() is ktime_get_mono_fast_ns(), i.e. CLOCK_MONOTONIC
	 * without the suspend offset. CLOCK_MONOTONIC is the closest userspace
	 * equivalent: identical while the machine is awake, which is the only
	 * time the dataplane is stamping anything. */
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (__u64)ts.tv_sec * CALY_NSEC_PER_SEC + (__u64)ts.tv_nsec;
}

int caly_map_max_entries(const struct caly_maps *m, int id, __u32 *out)
{
	struct bpf_map_info info;
	__u32 len = sizeof(info);
	int fd = caly_maps_fd(m, id);
	int ret;

	if (fd < 0)
		return fd;
	if (!out)
		return -EINVAL;
	memset(&info, 0, sizeof(info));
	errno = 0;
	ret = bpf_obj_get_info_by_fd(fd, &info, &len);
	if (ret < 0)
		return caly_err(ret);
	*out = info.max_entries;
	return 0;
}

/* =========================================================================
 * Batch plumbing
 * ========================================================================= */

#if CALY_HAVE_BATCH_OPS
static void batch_opts_init(struct bpf_map_batch_opts *o)
{
	memset(o, 0, sizeof(*o));
	o->sz = sizeof(*o);
	o->elem_flags = 0;
	o->flags = 0;
}
#endif

int caly_maps_probe_batch(struct caly_maps *m)
{
#if CALY_HAVE_BATCH_OPS
	struct bpf_map_batch_opts opts;
	__u32 key = 0, out_batch = 0;
	struct ban_entry val;
	__u32 count = 1;
	int fd, ret, e;

	if (!m)
		return 0;
	fd = caly_maps_fd(m, CALY_MAP_ID_BAN4);
	if (fd < 0) {
		m->have_batch = 0;
		return 0;
	}
	batch_opts_init(&opts);
	memset(&val, 0, sizeof(val));
	errno = 0;
	ret = bpf_map_lookup_batch(fd, NULL, &out_batch, &key, &val, &count,
				   &opts);
	e = errno;
	/* Success, or "iteration finished" on an empty map, both mean the
	 * command exists. -EINVAL / -EOPNOTSUPP mean it does not. */
	m->have_batch = (ret == 0 || e == ENOENT) ? 1 : 0;
	return m->have_batch;
#else
	if (m)
		m->have_batch = 0;
	return 0;
#endif
}

static int batch_usable(const struct caly_maps *m, int id)
{
	if (!m || !m->have_batch)
		return 0;
	if (id < 0 || id >= CALY_MAP_ID_MAX)
		return 0;
	return !m->batch_broken[id];
}

/* Update `n` (key, value) pairs. Tries the batch syscall, falls back to a
 * per-entry loop on any failure and remembers not to try again. */
static int update_many(struct caly_maps *m, int id, const void *keys,
		       size_t ksz, const void *vals, size_t vsz, size_t n)
{
	int fd = caly_maps_fd(m, id);
	size_t i;
	int rc = 0;

	if (fd < 0)
		return fd;
	if (n == 0)
		return 0;

#if CALY_HAVE_BATCH_OPS
	if (batch_usable(m, id) && n > 8) {
		struct bpf_map_batch_opts opts;
		__u32 done = 0;
		size_t off = 0;
		int failed = 0;

		batch_opts_init(&opts);
		while (off < n) {
			__u32 chunk = (__u32)((n - off > 65536) ? 65536
							       : (n - off));
			int ret;

			errno = 0;
			done = chunk;
			ret = bpf_map_update_batch(fd,
						   (const char *)keys + off * ksz,
						   (const char *)vals + off * vsz,
						   &done, &opts);
			if (ret < 0) {
				failed = 1;
				break;
			}
			if (done == 0) {
				failed = 1;
				break;
			}
			off += done;
		}
		if (!failed)
			return 0;
		m->batch_broken[id] = 1;
		/* fall through to the per-entry loop */
	}
#endif

	for (i = 0; i < n; i++) {
		int ret;

		errno = 0;
		ret = bpf_map_update_elem(fd, (const char *)keys + i * ksz,
					  (const char *)vals + i * vsz,
					  BPF_ANY);
		if (ret < 0) {
			int e = caly_err(ret);

			/* An LPM trie or hash that is full must not abort a
			 * bulk import: record the first failure and keep
			 * going so the operator gets as much policy as fits. */
			if (rc == 0)
				rc = e;
		}
	}
	return rc;
}

/* =========================================================================
 * Generic hash iteration
 * ========================================================================= */

static int buf_reserve(void **v, size_t *cap, size_t need, size_t esz)
{
	size_t nc;
	void *p;

	if (need <= *cap)
		return 0;
	nc = *cap ? *cap : 64;
	while (nc < need) {
		if (nc > (size_t)-1 / 2)
			return -ENOMEM;
		nc *= 2;
	}
	if (esz && nc > (size_t)-1 / esz)
		return -ENOMEM;
	p = realloc(*v, nc * esz);
	if (!p)
		return -ENOMEM;
	*v = p;
	*cap = nc;
	return 0;
}

/*
 * Dump an entire hash/LRU map. Keys and values are returned as two parallel
 * malloc'd arrays; the caller frees both. Entries that vanish between
 * get_next_key and lookup (LRU eviction) are skipped, not treated as errors.
 */
static int hash_dump(struct caly_maps *m, int id, size_t ksz, size_t vsz,
		     void **keys_out, void **vals_out, size_t *n_out)
{
	int fd = caly_maps_fd(m, id);
	unsigned char *keys = NULL, *vals = NULL;
	unsigned char *cur = NULL, *nxt = NULL;
	size_t kcap = 0, vcap = 0, n = 0;
	int have_cur = 0;
	int rc = 0;

	if (fd < 0)
		return fd;
	if (!keys_out || !vals_out || !n_out)
		return -EINVAL;

	*keys_out = NULL;
	*vals_out = NULL;
	*n_out = 0;

	cur = calloc(1, ksz);
	nxt = calloc(1, ksz);
	if (!cur || !nxt) {
		rc = -ENOMEM;
		goto out;
	}

#if CALY_HAVE_BATCH_OPS
	if (batch_usable(m, id)) {
		struct bpf_map_batch_opts opts;
		unsigned char *in = NULL;
		unsigned char *inbuf = calloc(1, ksz);
		unsigned char *outbuf = calloc(1, ksz);
		int failed = 0;

		if (!inbuf || !outbuf) {
			free(inbuf);
			free(outbuf);
			rc = -ENOMEM;
			goto out;
		}
		batch_opts_init(&opts);

		for (;;) {
			__u32 count;
			int ret, e;

			if (buf_reserve((void **)&keys, &kcap, n + 512, ksz) ||
			    buf_reserve((void **)&vals, &vcap, n + 512, vsz)) {
				failed = 1;
				rc = -ENOMEM;
				break;
			}
			count = (__u32)(kcap - n);
			if (count > 4096)
				count = 4096;

			errno = 0;
			ret = bpf_map_lookup_batch(fd, in, outbuf,
						   keys + n * ksz,
						   vals + n * vsz,
						   &count, &opts);
			e = errno;
			if (ret == 0 || e == ENOENT)
				n += count;
			if (ret < 0) {
				if (e != ENOENT) {
					m->batch_broken[id] = 1;
					failed = 1;
					n = 0;
				}
				break;
			}
			if (count == 0)
				break;
			memcpy(inbuf, outbuf, ksz);
			in = inbuf;
		}
		free(inbuf);
		free(outbuf);
		if (!failed && rc == 0) {
			*keys_out = keys;
			*vals_out = vals;
			*n_out = n;
			free(cur);
			free(nxt);
			return 0;
		}
		if (rc)
			goto out;
		/* batch failed: restart with the portable walk */
		n = 0;
	}
#endif

	for (;;) {
		int ret;

		errno = 0;
		ret = bpf_map_get_next_key(fd, have_cur ? cur : NULL, nxt);
		if (ret < 0)
			break;

		rc = buf_reserve((void **)&keys, &kcap, n + 1, ksz);
		if (rc)
			goto out;
		rc = buf_reserve((void **)&vals, &vcap, n + 1, vsz);
		if (rc)
			goto out;

		errno = 0;
		if (bpf_map_lookup_elem(fd, nxt, vals + n * vsz) == 0) {
			memcpy(keys + n * ksz, nxt, ksz);
			n++;
		}
		memcpy(cur, nxt, ksz);
		have_cur = 1;
	}

	*keys_out = keys;
	*vals_out = vals;
	*n_out = n;
	free(cur);
	free(nxt);
	return 0;

out:
	free(keys);
	free(vals);
	free(cur);
	free(nxt);
	return rc;
}

/*
 * Walk a hash map and delete every entry for which `pred` returns non-zero.
 * pred == NULL deletes everything.
 *
 * The next key is fetched BEFORE the current one is deleted: asking for the
 * successor of a key that no longer exists restarts the iteration from the
 * beginning, which would make this loop non-terminating.
 */
static int hash_sweep(struct caly_maps *m, int id, size_t ksz, size_t vsz,
		      int (*pred)(const void *k, const void *v, void *ctx),
		      void *ctx, __u32 budget, size_t *removed)
{
	int fd = caly_maps_fd(m, id);
	unsigned char *cur = NULL, *nxt = NULL, *val = NULL;
	size_t nrm = 0;
	__u32 examined = 0;
	int rc = 0, have;

	if (fd < 0)
		return fd;

	cur = calloc(1, ksz);
	nxt = calloc(1, ksz);
	val = calloc(1, vsz ? vsz : 1);
	if (!cur || !nxt || !val) {
		rc = -ENOMEM;
		goto out;
	}

	errno = 0;
	have = bpf_map_get_next_key(fd, NULL, cur);
	while (have == 0) {
		int have_next;
		int doit = 1;

		errno = 0;
		have_next = bpf_map_get_next_key(fd, cur, nxt);

		if (pred) {
			errno = 0;
			if (bpf_map_lookup_elem(fd, cur, val) != 0)
				doit = 0;
			else
				doit = pred(cur, val, ctx);
		}
		if (doit) {
			errno = 0;
			if (bpf_map_delete_elem(fd, cur) == 0)
				nrm++;
		}

		examined++;
		if (budget && examined >= budget)
			break;
		if (have_next != 0)
			break;
		memcpy(cur, nxt, ksz);
	}

out:
	free(cur);
	free(nxt);
	free(val);
	if (removed)
		*removed = nrm;
	return rc;
}

/* =========================================================================
 * caly_config
 * ========================================================================= */

int caly_map_config_get(const struct caly_maps *m, struct fw_config *out)
{
	__u32 key = 0;
	int fd = caly_maps_fd(m, CALY_MAP_ID_CONFIG);
	int ret;

	if (fd < 0)
		return fd;
	if (!out)
		return -EINVAL;
	errno = 0;
	ret = bpf_map_lookup_elem(fd, &key, out);
	return caly_err(ret);
}

int caly_map_config_set(const struct caly_maps *m, const struct fw_config *in)
{
	__u32 key = 0;
	int fd = caly_maps_fd(m, CALY_MAP_ID_CONFIG);
	int ret;

	if (fd < 0)
		return fd;
	if (!in)
		return -EINVAL;
	errno = 0;
	ret = bpf_map_update_elem(fd, &key, in, BPF_ANY);
	return caly_err(ret);
}

static int mgmt_list_has(const __u16 *list, __u32 count, __u16 port)
{
	__u32 i;

	for (i = 0; i < count && i < CALY_MGMT_PORTS_MAX; i++)
		if (list[i] == port)
			return 1;
	return 0;
}

int caly_map_config_install(const struct caly_maps *m, struct fw_config *in,
			    char *err, size_t errsz)
{
	struct fw_config cur;
	int rc;

	if (!m || !in)
		return -EINVAL;

	/* The one invariant that is never negotiable, re-checked here so that
	 * no code path - CLI, daemon escalation, reload - can write a config
	 * without SSH in the management list. */
	if (!mgmt_list_has(in->mgmt_tcp_ports, in->mgmt_tcp_count, 22) ||
	    in->mgmt_tcp_count == 0 || in->mgmt_tcp_ports[0] != 22) {
		caly_seterr(err, errsz,
			    "refusing to install a configuration whose "
			    "management list does not start with TCP/22");
		return -EPERM;
	}
	if (in->mgmt_tcp_count > CALY_MGMT_PORTS_MAX ||
	    in->mgmt_udp_count > CALY_MGMT_PORTS_MAX) {
		caly_seterr(err, errsz, "management port count out of range");
		return -EINVAL;
	}

	memset(&cur, 0, sizeof(cur));
	rc = caly_map_config_get(m, &cur);
	if (rc == 0 && cur.abi_version != 0) {
		__u32 have_major = (__u32)(cur.abi_version >> 16);

		if (have_major != CALY_ABI_VERSION_MAJOR) {
			caly_seterr(err, errsz,
				    "ABI major mismatch: the running config map "
				    "is v%u.%u, this build is v%u.%u; detach and "
				    "reload the dataplane",
				    have_major,
				    (unsigned)(cur.abi_version & 0xFFFFu),
				    CALY_ABI_VERSION_MAJOR,
				    CALY_ABI_VERSION_MINOR);
			return -EPROTO;
		}
		/* Capability bits belong to the loader, not to the file. */
		in->flags = (in->flags & ~CALY_F_CAP_MASK) |
			    (cur.flags & CALY_F_CAP_MASK);
		if (in->config_gen <= cur.config_gen)
			in->config_gen = cur.config_gen + 1;
	} else if (in->config_gen == 0) {
		in->config_gen = 1;
	}

	in->abi_version = CALY_ABI_VERSION;

	rc = caly_map_config_set(m, in);
	if (rc)
		caly_seterr(err, errsz, "cannot write %s: %s",
			    CALY_MAP_CONFIG, strerror(-rc));
	return rc;
}

int caly_map_config_set_mode(const struct caly_maps *m, __u32 mode)
{
	struct fw_config cfg;
	__u32 prev_mode;
	int rc;

	if (mode >= FW_MODE_MAX)
		return -EINVAL;
	rc = caly_map_config_get(m, &cfg);
	if (rc)
		return rc;
	if (cfg.mode == mode)
		return 0;
	prev_mode = cfg.mode;
	cfg.mode = mode;
	/*
	 * The dataplane suppresses every drop off CALY_F_MONITOR_ONLY, not off
	 * the mode enum, so this bit MUST track the mode both ways: entering
	 * FW_MODE_MONITOR_ONLY sets it, leaving MONITOR_ONLY clears it. Without
	 * the clear the flag is sticky and the firewall stays disarmed (fail
	 * open) after an ordinary runtime escalation such as monitor->under-attack.
	 *
	 * The clear is gated on the PREVIOUS mode having been MONITOR_ONLY so
	 * that an operator who set `monitor_only = yes` in the configuration file
	 * (which raises the same bit while leaving mode at, e.g., NORMAL) keeps
	 * their explicit observe-only guarantee across a mode change.
	 */
	if (mode == FW_MODE_MONITOR_ONLY)
		cfg.flags |= CALY_F_MONITOR_ONLY;
	else if (prev_mode == FW_MODE_MONITOR_ONLY)
		cfg.flags &= ~CALY_F_MONITOR_ONLY;
	cfg.config_gen++;
	return caly_map_config_set(m, &cfg);
}

int caly_map_config_set_caps(const struct caly_maps *m, __u64 set, __u64 clear)
{
	struct fw_config cfg;
	int rc;

	rc = caly_map_config_get(m, &cfg);
	if (rc)
		return rc;
	cfg.flags &= ~(clear & CALY_F_CAP_MASK);
	cfg.flags |= (set & CALY_F_CAP_MASK);
	cfg.config_gen++;
	return caly_map_config_set(m, &cfg);
}

/* =========================================================================
 * LPM sets
 * ========================================================================= */

static int set_map_id(int set, __u32 family)
{
	int v6 = (family == CALY_AF_INET6);

	switch (set) {
	case CALY_SET_ALLOW: return v6 ? CALY_MAP_ID_ALLOW6 : CALY_MAP_ID_ALLOW4;
	case CALY_SET_BLOCK: return v6 ? CALY_MAP_ID_BLOCK6 : CALY_MAP_ID_BLOCK4;
	case CALY_SET_LOCAL: return v6 ? CALY_MAP_ID_LOCAL6 : CALY_MAP_ID_LOCAL4;
	default:             return -EINVAL;
	}
}

static int cidr_valid(const struct caly_cidr *c)
{
	if (!c)
		return 0;
	if (c->family == CALY_AF_INET)
		return c->prefixlen <= 32;
	if (c->family == CALY_AF_INET6)
		return c->prefixlen <= 128;
	return 0;
}

/* Pack into the kernel's LPM key layout: prefixlen first in HOST order,
 * then the address MSB-first with every host bit zeroed. */
static void cidr_to_lpm4(const struct caly_cidr *c, struct lpm_key_v4 *k)
{
	memset(k, 0, sizeof(*k));
	k->prefixlen = c->prefixlen;
	memcpy(k->addr, c->addr, 4);
}

static void cidr_to_lpm6(const struct caly_cidr *c, struct lpm_key_v6 *k)
{
	memset(k, 0, sizeof(*k));
	k->prefixlen = c->prefixlen;
	memcpy(k->addr, c->addr, 16);
}

static void lpm4_to_cidr(const struct lpm_key_v4 *k, struct caly_cidr *c)
{
	memset(c, 0, sizeof(*c));
	c->family = CALY_AF_INET;
	c->prefixlen = (__u8)(k->prefixlen > 32 ? 32 : k->prefixlen);
	memcpy(c->addr, k->addr, 4);
}

static void lpm6_to_cidr(const struct lpm_key_v6 *k, struct caly_cidr *c)
{
	memset(c, 0, sizeof(*c));
	c->family = CALY_AF_INET6;
	c->prefixlen = (__u8)(k->prefixlen > 128 ? 128 : k->prefixlen);
	memcpy(c->addr, k->addr, 16);
}

static int cidr_same(const struct caly_cidr *a, const struct caly_cidr *b)
{
	return a->family == b->family && a->prefixlen == b->prefixlen &&
	       memcmp(a->addr, b->addr, 16) == 0;
}

static void shadow_add(struct caly_maps *m, int set, const struct caly_cidr *c)
{
	struct caly_cidr_vec *vec;
	int fi;

	if (!m || !m->lpm_shadow_enabled)
		return;
	if (set < 0 || set >= CALY_SET_MAX)
		return;
	fi = (c->family == CALY_AF_INET6) ? 1 : 0;
	vec = &m->lpm_shadow[set][fi];
	if (buf_reserve((void **)&vec->v, &vec->cap, vec->n + 1,
			sizeof(*vec->v)) != 0)
		return;                 /* shadow is an optimisation only */
	vec->v[vec->n++] = *c;
}

static void shadow_del(struct caly_maps *m, int set, const struct caly_cidr *c)
{
	struct caly_cidr_vec *vec;
	size_t i;
	int fi;

	if (!m || !m->lpm_shadow_enabled)
		return;
	if (set < 0 || set >= CALY_SET_MAX)
		return;
	fi = (c->family == CALY_AF_INET6) ? 1 : 0;
	vec = &m->lpm_shadow[set][fi];
	for (i = 0; i < vec->n; i++) {
		if (!cidr_same(&vec->v[i], c))
			continue;
		vec->v[i] = vec->v[vec->n - 1];
		vec->n--;
		return;
	}
}

static void shadow_clear(struct caly_maps *m, int set, int fi)
{
	if (!m || set < 0 || set >= CALY_SET_MAX || fi < 0 || fi > 1)
		return;
	m->lpm_shadow[set][fi].n = 0;
}

static int cidr_sort_cmp(const void *a, const void *b);

/*
 * Collapse duplicate prefixes in one family's shadow vector.
 *
 * The shadow is an in-process mirror of the LPM map's keys (the only way to
 * enumerate a trie on kernels < 4.20, which lack trie_get_next_key). The map
 * de-duplicates by key, but shadow_add() appends unconditionally, so a bulk
 * import that re-inserts a prefix already present - exactly what every config
 * reload / threat-feed refresh does - would otherwise grow the shadow without
 * bound. Deduplicating after each bulk add keeps it a faithful, bounded set.
 *
 * This only removes redundant copies, never a distinct prefix, so it is safe
 * to run before sync_set()'s delete-stale walk: the pre-reload state (needed
 * to evict prefixes dropped from the config on a < 4.20 kernel) is preserved.
 */
static void shadow_dedup_family(struct caly_maps *m, int set, int fi)
{
	struct caly_cidr_vec *vec;
	size_t i, w;

	if (!m || !m->lpm_shadow_enabled)
		return;
	if (set < 0 || set >= CALY_SET_MAX || fi < 0 || fi > 1)
		return;
	vec = &m->lpm_shadow[set][fi];
	if (vec->n < 2)
		return;
	qsort(vec->v, vec->n, sizeof(*vec->v), cidr_sort_cmp);
	w = 1;
	for (i = 1; i < vec->n; i++) {
		if (cidr_same(&vec->v[w - 1], &vec->v[i]))
			continue;
		if (w != i)
			vec->v[w] = vec->v[i];
		w++;
	}
	vec->n = w;
}

int caly_set_add(struct caly_maps *m, int set, const struct caly_cidr *c)
{
	struct lpm_key_v4 k4;
	struct lpm_key_v6 k6;
	struct rule_meta meta;
	const void *key;
	int id, fd, ret;

	if (!m || !cidr_valid(c))
		return -EINVAL;
	id = set_map_id(set, c->family);
	if (id < 0)
		return id;
	fd = caly_maps_fd(m, id);
	if (fd < 0)
		return fd;

	memset(&meta, 0, sizeof(meta));
	meta.added_ns = caly_now_ns();
	meta.hits = 0;
	meta.flags = c->flags;
	meta.tag = c->tag;
	if (meta.flags == 0)
		meta.flags = (set == CALY_SET_ALLOW) ? CALY_RULE_F_ALLOW :
			     (set == CALY_SET_BLOCK) ? CALY_RULE_F_BLOCK :
						       CALY_RULE_F_LOCAL;

	if (c->family == CALY_AF_INET6) {
		cidr_to_lpm6(c, &k6);
		key = &k6;
	} else {
		cidr_to_lpm4(c, &k4);
		key = &k4;
	}

	errno = 0;
	ret = bpf_map_update_elem(fd, key, &meta, BPF_ANY);
	if (ret < 0)
		return caly_err(ret);

	shadow_add(m, set, c);
	return 0;
}

int caly_set_del(struct caly_maps *m, int set, const struct caly_cidr *c)
{
	struct lpm_key_v4 k4;
	struct lpm_key_v6 k6;
	const void *key;
	int id, fd, ret;

	if (!m || !cidr_valid(c))
		return -EINVAL;
	id = set_map_id(set, c->family);
	if (id < 0)
		return id;
	fd = caly_maps_fd(m, id);
	if (fd < 0)
		return fd;

	if (c->family == CALY_AF_INET6) {
		cidr_to_lpm6(c, &k6);
		key = &k6;
	} else {
		cidr_to_lpm4(c, &k4);
		key = &k4;
	}

	errno = 0;
	ret = bpf_map_delete_elem(fd, key);
	shadow_del(m, set, c);
	if (ret < 0 && errno == ENOENT)
		return 0;
	return caly_err(ret);
}

int caly_set_lookup(const struct caly_maps *m, int set,
		    const struct caly_cidr *c, struct rule_meta *out)
{
	struct lpm_key_v4 k4;
	struct lpm_key_v6 k6;
	struct rule_meta tmp;
	const void *key;
	int id, fd, ret;

	if (!m || !cidr_valid(c))
		return -EINVAL;
	id = set_map_id(set, c->family);
	if (id < 0)
		return id;
	fd = caly_maps_fd(m, id);
	if (fd < 0)
		return fd;

	if (c->family == CALY_AF_INET6) {
		cidr_to_lpm6(c, &k6);
		key = &k6;
	} else {
		cidr_to_lpm4(c, &k4);
		key = &k4;
	}

	errno = 0;
	ret = bpf_map_lookup_elem(fd, key, out ? out : &tmp);
	return caly_err(ret);
}

int caly_set_add_many(struct caly_maps *m, int set,
		      const struct caly_cidr *arr, size_t n, size_t *added)
{
	struct lpm_key_v4 *k4 = NULL;
	struct lpm_key_v6 *k6 = NULL;
	struct rule_meta *m4 = NULL, *m6 = NULL;
	size_t n4 = 0, n6 = 0, i;
	__u64 now = caly_now_ns();
	int rc = 0, r;

	if (!m || (!arr && n))
		return -EINVAL;
	if (added)
		*added = 0;
	if (n == 0)
		return 0;

	for (i = 0; i < n; i++) {
		if (!cidr_valid(&arr[i]))
			continue;
		if (arr[i].family == CALY_AF_INET6)
			n6++;
		else
			n4++;
	}

	if (n4) {
		k4 = calloc(n4, sizeof(*k4));
		m4 = calloc(n4, sizeof(*m4));
	}
	if (n6) {
		k6 = calloc(n6, sizeof(*k6));
		m6 = calloc(n6, sizeof(*m6));
	}
	if ((n4 && (!k4 || !m4)) || (n6 && (!k6 || !m6))) {
		rc = -ENOMEM;
		goto out;
	}

	n4 = 0;
	n6 = 0;
	for (i = 0; i < n; i++) {
		const struct caly_cidr *c = &arr[i];
		struct rule_meta meta;

		if (!cidr_valid(c))
			continue;
		memset(&meta, 0, sizeof(meta));
		meta.added_ns = now;
		meta.flags = c->flags ? c->flags :
			     ((set == CALY_SET_ALLOW) ? CALY_RULE_F_ALLOW :
			      (set == CALY_SET_BLOCK) ? CALY_RULE_F_BLOCK :
							CALY_RULE_F_LOCAL);
		meta.tag = c->tag;

		if (c->family == CALY_AF_INET6) {
			cidr_to_lpm6(c, &k6[n6]);
			m6[n6] = meta;
			n6++;
		} else {
			cidr_to_lpm4(c, &k4[n4]);
			m4[n4] = meta;
			n4++;
		}
		shadow_add(m, set, c);
	}

	if (n4) {
		r = update_many(m, set_map_id(set, CALY_AF_INET), k4,
				sizeof(*k4), m4, sizeof(*m4), n4);
		if (r && rc == 0)
			rc = r;
		else if (added)
			*added += n4;
	}
	if (n6) {
		r = update_many(m, set_map_id(set, CALY_AF_INET6), k6,
				sizeof(*k6), m6, sizeof(*m6), n6);
		if (r && rc == 0)
			rc = r;
		else if (added)
			*added += n6;
	}

	/* shadow_add() above appended every wanted prefix unconditionally;
	 * collapse the duplicates a reload just created so the shadow tracks the
	 * map's key set rather than growing on every apply. */
	if (n4)
		shadow_dedup_family(m, set, 0);
	if (n6)
		shadow_dedup_family(m, set, 1);

out:
	free(k4);
	free(k6);
	free(m4);
	free(m6);
	return rc;
}

int caly_set_dump(struct caly_maps *m, int set, __u32 family,
		  struct caly_rule_dump **out, size_t *n)
{
	struct caly_rule_dump *res = NULL;
	size_t cap = 0, total = 0;
	int fam_pass, rc = 0;

	if (!m || !out || !n)
		return -EINVAL;
	*out = NULL;
	*n = 0;

	for (fam_pass = 0; fam_pass < 2; fam_pass++) {
		__u32 fam = fam_pass ? CALY_AF_INET6 : CALY_AF_INET;
		void *keys = NULL, *vals = NULL;
		size_t got = 0, i;
		size_t ksz = fam_pass ? sizeof(struct lpm_key_v6)
				      : sizeof(struct lpm_key_v4);
		int id;

		if (family != CALY_FAM_ANY && family != fam)
			continue;
		id = set_map_id(set, fam);
		if (id < 0) {
			rc = id;
			goto fail;
		}
		if (caly_maps_fd(m, id) < 0)
			continue;

		rc = hash_dump(m, id, ksz, sizeof(struct rule_meta),
			       &keys, &vals, &got);
		if (rc) {
			free(keys);
			free(vals);
			goto fail;
		}

		/* Kernels before 4.20 have no trie_get_next_key(); the walk
		 * returns nothing. Fall back to what we inserted ourselves. */
		if (got == 0 && m->lpm_shadow_enabled &&
		    m->lpm_shadow[set][fam_pass].n) {
			struct caly_cidr_vec *vec = &m->lpm_shadow[set][fam_pass];

			free(keys);
			free(vals);
			rc = buf_reserve((void **)&res, &cap,
					 total + vec->n, sizeof(*res));
			if (rc)
				goto fail;
			for (i = 0; i < vec->n; i++) {
				struct rule_meta meta;

				memset(&meta, 0, sizeof(meta));
				if (caly_set_lookup(m, set, &vec->v[i], &meta))
					continue;
				res[total].cidr = vec->v[i];
				res[total].meta = meta;
				total++;
			}
			continue;
		}

		rc = buf_reserve((void **)&res, &cap, total + got,
				 sizeof(*res));
		if (rc) {
			free(keys);
			free(vals);
			goto fail;
		}
		for (i = 0; i < got; i++) {
			struct caly_cidr cd;

			if (fam_pass)
				lpm6_to_cidr((struct lpm_key_v6 *)
					     ((char *)keys + i * ksz), &cd);
			else
				lpm4_to_cidr((struct lpm_key_v4 *)
					     ((char *)keys + i * ksz), &cd);
			res[total].meta =
				((struct rule_meta *)vals)[i];
			cd.flags = res[total].meta.flags;
			cd.tag = res[total].meta.tag;
			res[total].cidr = cd;
			total++;
		}
		free(keys);
		free(vals);
	}

	*out = res;
	*n = total;
	return 0;

fail:
	free(res);
	return rc;
}

int caly_set_flush(struct caly_maps *m, int set, __u32 family,
		   int by_tag, __u32 tag, size_t *removed)
{
	struct caly_rule_dump *d = NULL;
	size_t n = 0, i, nrm = 0;
	int rc;

	if (removed)
		*removed = 0;

	rc = caly_set_dump(m, set, family, &d, &n);
	if (rc)
		return rc;

	for (i = 0; i < n; i++) {
		if (by_tag && d[i].meta.tag != tag)
			continue;
		if (caly_set_del(m, set, &d[i].cidr) == 0)
			nrm++;
	}
	free(d);

	if (!by_tag) {
		if (family == CALY_FAM_ANY || family == CALY_AF_INET)
			shadow_clear(m, set, 0);
		if (family == CALY_FAM_ANY || family == CALY_AF_INET6)
			shadow_clear(m, set, 1);
	}
	if (removed)
		*removed = nrm;
	return 0;
}

/*
 * Converge a set onto `want` WITHOUT a window in which coverage is missing:
 * everything wanted is inserted first, then the entries we own that are no
 * longer wanted are removed. Doing it the other way round would briefly drop
 * the allowlist, which is precisely the moment an operator cannot afford.
 */
static int cidr_sort_cmp(const void *a, const void *b)
{
	const struct caly_cidr *x = a, *y = b;

	if (x->family != y->family)
		return (int)x->family - (int)y->family;
	if (x->prefixlen != y->prefixlen)
		return (int)x->prefixlen - (int)y->prefixlen;
	return memcmp(x->addr, y->addr, 16);
}

static int sync_set(struct caly_maps *m, int set, const struct caly_cidr *want,
		    size_t nwant, const __u32 *owned_tags, size_t n_owned,
		    size_t *added, size_t *removed)
{
	struct caly_cidr *sorted = NULL;
	struct caly_rule_dump *have = NULL;
	size_t nhave = 0, i, j, nrm = 0;
	int rc;

	rc = caly_set_add_many(m, set, want, nwant, added);
	if (rc)
		return rc;

	if (nwant) {
		sorted = malloc(nwant * sizeof(*sorted));
		if (!sorted)
			return -ENOMEM;
		memcpy(sorted, want, nwant * sizeof(*sorted));
		qsort(sorted, nwant, sizeof(*sorted), cidr_sort_cmp);
	}

	rc = caly_set_dump(m, set, CALY_FAM_ANY, &have, &nhave);
	if (rc) {
		free(sorted);
		return rc;
	}

	for (i = 0; i < nhave; i++) {
		int mine = 0;

		for (j = 0; j < n_owned; j++)
			if (have[i].meta.tag == owned_tags[j])
				mine = 1;
		if (!mine)
			continue;
		if (sorted && bsearch(&have[i].cidr, sorted, nwant,
				      sizeof(*sorted), cidr_sort_cmp))
			continue;
		if (caly_set_del(m, set, &have[i].cidr) == 0)
			nrm++;
	}

	free(sorted);
	free(have);
	if (removed)
		*removed = nrm;
	return 0;
}

/* =========================================================================
 * Dynamic bans
 * ========================================================================= */

static void cidr_to_in6key(const struct caly_cidr *c, struct in6_key *k)
{
	memset(k, 0, sizeof(*k));
	memcpy(k->a, c->addr, 16);
}

static void in6key_to_cidr(const struct in6_key *k, struct caly_cidr *c)
{
	memset(c, 0, sizeof(*c));
	c->family = CALY_AF_INET6;
	c->prefixlen = 128;
	memcpy(c->addr, k->a, 16);
}

static int ban_map_id(__u32 family)
{
	return (family == CALY_AF_INET6) ? CALY_MAP_ID_BAN6 : CALY_MAP_ID_BAN4;
}

int caly_ban_add(const struct caly_maps *m, const struct caly_cidr *addr,
		 __u64 ttl_ns, __u32 reason, __u32 flags)
{
	struct ban_entry e;
	struct in6_key k6;
	__u32 k4 = 0;
	const void *key;
	__u64 now;
	int fd, ret;

	if (!m || !cidr_valid(addr))
		return -EINVAL;
	if (addr->family == CALY_AF_INET && addr->prefixlen != 32)
		return -EINVAL;   /* a prefix ban belongs in the blocklist */
	if (addr->family == CALY_AF_INET6 && addr->prefixlen != 128)
		return -EINVAL;

	fd = caly_maps_fd(m, ban_map_id(addr->family));
	if (fd < 0)
		return fd;

	if (addr->family == CALY_AF_INET6) {
		cidr_to_in6key(addr, &k6);
		key = &k6;
	} else {
		memcpy(&k4, addr->addr, 4);
		key = &k4;
	}

	now = caly_now_ns();

	memset(&e, 0, sizeof(e));
	errno = 0;
	if (bpf_map_lookup_elem(fd, key, &e) != 0) {
		memset(&e, 0, sizeof(e));
		e.first_seen_ns = now;
		e.offences = 1;
	} else {
		e.offences++;
		e.flags |= CALY_BAN_F_ESCALATED;
	}

	e.cur_ttl_ns = ttl_ns;
	e.expiry_ns = (flags & CALY_BAN_F_PERMANENT) ? (__u64)-1 : now + ttl_ns;
	e.last_hit_ns = now;
	e.reason = reason;
	e.flags |= flags ? flags : CALY_BAN_F_MANUAL;

	errno = 0;
	ret = bpf_map_update_elem(fd, key, &e, BPF_ANY);
	return caly_err(ret);
}

int caly_ban_get(const struct caly_maps *m, const struct caly_cidr *addr,
		 struct ban_entry *out)
{
	struct in6_key k6;
	struct ban_entry tmp;
	__u32 k4 = 0;
	const void *key;
	int fd, ret;

	if (!m || !cidr_valid(addr))
		return -EINVAL;
	fd = caly_maps_fd(m, ban_map_id(addr->family));
	if (fd < 0)
		return fd;
	if (addr->family == CALY_AF_INET6) {
		cidr_to_in6key(addr, &k6);
		key = &k6;
	} else {
		memcpy(&k4, addr->addr, 4);
		key = &k4;
	}
	errno = 0;
	ret = bpf_map_lookup_elem(fd, key, out ? out : &tmp);
	return caly_err(ret);
}

int caly_ban_del(struct caly_maps *m, const struct caly_cidr *addr)
{
	struct in6_key k6;
	__u32 k4 = 0;
	const void *key;
	int fd, ret;

	if (!m || !cidr_valid(addr))
		return -EINVAL;
	fd = caly_maps_fd(m, ban_map_id(addr->family));
	if (fd < 0)
		return fd;
	if (addr->family == CALY_AF_INET6) {
		cidr_to_in6key(addr, &k6);
		key = &k6;
	} else {
		memcpy(&k4, addr->addr, 4);
		key = &k4;
	}
	errno = 0;
	ret = bpf_map_delete_elem(fd, key);
	if (ret < 0 && errno == ENOENT)
		return -ENOENT;
	return caly_err(ret);
}

int caly_ban_dump(struct caly_maps *m, __u32 family,
		  struct caly_ban_dump **out, size_t *n)
{
	struct caly_ban_dump *res = NULL;
	size_t cap = 0, total = 0;
	int pass, rc = 0;

	if (!m || !out || !n)
		return -EINVAL;
	*out = NULL;
	*n = 0;

	for (pass = 0; pass < 2; pass++) {
		__u32 fam = pass ? CALY_AF_INET6 : CALY_AF_INET;
		size_t ksz = pass ? sizeof(struct in6_key) : sizeof(__u32);
		void *keys = NULL, *vals = NULL;
		size_t got = 0, i;
		int id = ban_map_id(fam);

		if (family != CALY_FAM_ANY && family != fam)
			continue;
		if (caly_maps_fd(m, id) < 0)
			continue;

		rc = hash_dump(m, id, ksz, sizeof(struct ban_entry),
			       &keys, &vals, &got);
		if (rc) {
			free(keys);
			free(vals);
			free(res);
			return rc;
		}
		rc = buf_reserve((void **)&res, &cap, total + got,
				 sizeof(*res));
		if (rc) {
			free(keys);
			free(vals);
			free(res);
			return rc;
		}
		for (i = 0; i < got; i++) {
			if (pass)
				in6key_to_cidr((struct in6_key *)
					       ((char *)keys + i * ksz),
					       &res[total].addr);
			else
				caly_cidr_from_addr(&res[total].addr,
						    CALY_AF_INET,
						    (const __u8 *)keys +
						    i * ksz);
			res[total].entry = ((struct ban_entry *)vals)[i];
			total++;
		}
		free(keys);
		free(vals);
	}

	*out = res;
	*n = total;
	return 0;
}

int caly_ban_flush(struct caly_maps *m, __u32 family, size_t *removed)
{
	size_t nrm = 0, sub = 0;
	int rc = 0;

	if (family == CALY_FAM_ANY || family == CALY_AF_INET) {
		rc = hash_sweep(m, CALY_MAP_ID_BAN4, sizeof(__u32),
				sizeof(struct ban_entry), NULL, NULL, 0, &sub);
		nrm += sub;
	}
	if (!rc && (family == CALY_FAM_ANY || family == CALY_AF_INET6)) {
		rc = hash_sweep(m, CALY_MAP_ID_BAN6, sizeof(struct in6_key),
				sizeof(struct ban_entry), NULL, NULL, 0, &sub);
		nrm += sub;
	}
	if (removed)
		*removed = nrm;
	return rc;
}

static int ban_expired(const void *k, const void *v, void *ctx)
{
	const struct ban_entry *e = v;
	__u64 now = *(const __u64 *)ctx;

	(void)k;
	if (e->flags & CALY_BAN_F_PERMANENT)
		return 0;
	if (e->expiry_ns == 0)
		return 1;          /* malformed, never let it linger */
	return e->expiry_ns <= now;
}

int caly_ban_sweep(struct caly_maps *m, __u64 now_ns, __u32 budget,
		   size_t *removed)
{
	size_t nrm = 0, sub = 0;
	__u64 now = now_ns ? now_ns : caly_now_ns();
	int rc;

	rc = hash_sweep(m, CALY_MAP_ID_BAN4, sizeof(__u32),
			sizeof(struct ban_entry), ban_expired, &now,
			budget, &sub);
	nrm += sub;
	if (!rc) {
		rc = hash_sweep(m, CALY_MAP_ID_BAN6, sizeof(struct in6_key),
				sizeof(struct ban_entry), ban_expired, &now,
				budget, &sub);
		nrm += sub;
	}
	if (removed)
		*removed = nrm;
	return rc;
}

/* =========================================================================
 * Conntrack-lite
 * ========================================================================= */

int caly_conn_dump(struct caly_maps *m, struct caly_conn_dump **out, size_t *n)
{
	void *keys = NULL, *vals = NULL;
	struct caly_conn_dump *res = NULL;
	size_t got = 0, i;
	int rc;

	if (!m || !out || !n)
		return -EINVAL;
	*out = NULL;
	*n = 0;

	rc = hash_dump(m, CALY_MAP_ID_CONN, sizeof(struct conn_key),
		       sizeof(struct conn_state), &keys, &vals, &got);
	if (rc) {
		free(keys);
		free(vals);
		return rc;
	}
	if (got) {
		res = calloc(got, sizeof(*res));
		if (!res) {
			free(keys);
			free(vals);
			return -ENOMEM;
		}
		for (i = 0; i < got; i++) {
			res[i].key = ((struct conn_key *)keys)[i];
			res[i].state = ((struct conn_state *)vals)[i];
		}
	}
	free(keys);
	free(vals);
	*out = res;
	*n = got;
	return 0;
}

int caly_conn_del(const struct caly_maps *m, const struct conn_key *k)
{
	struct conn_key key;
	int fd = caly_maps_fd(m, CALY_MAP_ID_CONN);
	int ret;

	if (fd < 0)
		return fd;
	if (!k)
		return -EINVAL;

	/* Padding is part of the hash key: never hand the kernel a struct
	 * that was not fully zeroed first. */
	memset(&key, 0, sizeof(key));
	memcpy(key.saddr, k->saddr, sizeof(key.saddr));
	memcpy(key.daddr, k->daddr, sizeof(key.daddr));
	key.sport = k->sport;
	key.dport = k->dport;
	key.proto = k->proto;
	key.family = k->family;

	errno = 0;
	ret = bpf_map_delete_elem(fd, &key);
	if (ret < 0 && errno == ENOENT)
		return -ENOENT;
	return caly_err(ret);
}

int caly_conn_flush(struct caly_maps *m, size_t *removed)
{
	return hash_sweep(m, CALY_MAP_ID_CONN, sizeof(struct conn_key),
			  sizeof(struct conn_state), NULL, NULL, 0, removed);
}

int caly_conn_count(struct caly_maps *m, size_t *n)
{
	struct caly_conn_dump *d = NULL;
	size_t got = 0;
	int rc = caly_conn_dump(m, &d, &got);

	if (rc)
		return rc;
	free(d);
	if (n)
		*n = got;
	return 0;
}

struct conn_gc_ctx {
	__u64 now;
	const struct fw_config *cfg;
};

static int conn_expired(const void *k, const void *v, void *ctx)
{
	const struct conn_key *ck = k;
	const struct conn_state *cs = v;
	const struct conn_gc_ctx *g = ctx;
	__u64 timeout;

	/* Flows touching a management port are never garbage collected: the
	 * operator's own SSH session must not lose its conntrack entry while
	 * default_deny is on. */
	if (cs->flags & CALY_CT_F_MGMT)
		return 0;

	switch (ck->proto) {
	case CALY_IPPROTO_TCP:
		if (cs->state == CALY_CT_ESTABLISHED)
			timeout = g->cfg->ct_tcp_est_ns;
		else if (cs->state == CALY_CT_FIN_WAIT ||
			 cs->state == CALY_CT_CLOSED)
			timeout = g->cfg->ct_tcp_fin_ns;
		else
			timeout = g->cfg->ct_tcp_syn_ns;
		break;
	case CALY_IPPROTO_UDP:
		timeout = (cs->flags & CALY_CT_F_SEEN_REPLY)
				? g->cfg->ct_udp_stream_ns
				: g->cfg->ct_udp_ns;
		break;
	case CALY_IPPROTO_ICMP:
	case CALY_IPPROTO_ICMPV6:
		timeout = g->cfg->ct_icmp_ns;
		break;
	default:
		timeout = g->cfg->ct_generic_ns;
		break;
	}
	if (timeout == 0)
		return 0;
	if (cs->last_seen_ns == 0 || cs->last_seen_ns > g->now)
		return 0;
	return (g->now - cs->last_seen_ns) > timeout;
}

int caly_conn_sweep(struct caly_maps *m, const struct fw_config *cfg,
		    __u64 now_ns, __u32 budget, size_t *removed)
{
	struct conn_gc_ctx ctx;

	if (!cfg)
		return -EINVAL;
	ctx.now = now_ns ? now_ns : caly_now_ns();
	ctx.cfg = cfg;
	return hash_sweep(m, CALY_MAP_ID_CONN, sizeof(struct conn_key),
			  sizeof(struct conn_state), conn_expired, &ctx,
			  budget, removed);
}

/* =========================================================================
 * Statistics
 *
 * Reading a PERCPU map needs a buffer of num_possible_cpus() slots, each
 * rounded up to 8 bytes. Sizing it from sizeof(value) is the classic way to
 * smash the stack here.
 * ========================================================================= */

static int percpu_sum(const struct caly_maps *m, int id, __u32 key, __u64 *out)
{
	size_t stride = CALY_ROUND_UP8(sizeof(__u64));
	unsigned char *buf;
	__u64 sum = 0;
	int fd = caly_maps_fd(m, id);
	int i, ret, ncpu;

	if (fd < 0)
		return fd;
	ncpu = m->ncpu > 0 ? m->ncpu : 1;

	buf = calloc((size_t)ncpu, stride);
	if (!buf)
		return -ENOMEM;

	errno = 0;
	ret = bpf_map_lookup_elem(fd, &key, buf);
	if (ret < 0) {
		free(buf);
		*out = 0;
		return caly_err(ret);
	}
	for (i = 0; i < ncpu; i++)
		sum += *(__u64 *)(void *)(buf + (size_t)i * stride);
	free(buf);
	*out = sum;
	return 0;
}

static int percpu_zero(const struct caly_maps *m, int id, __u32 max_key)
{
	size_t stride = CALY_ROUND_UP8(sizeof(__u64));
	unsigned char *buf;
	int fd = caly_maps_fd(m, id);
	int ncpu, rc = 0;
	__u32 k;

	if (fd < 0)
		return fd;
	ncpu = m->ncpu > 0 ? m->ncpu : 1;
	buf = calloc((size_t)ncpu, stride);
	if (!buf)
		return -ENOMEM;

	for (k = 0; k < max_key; k++) {
		int ret;

		errno = 0;
		ret = bpf_map_update_elem(fd, &k, buf, BPF_ANY);
		if (ret < 0 && rc == 0)
			rc = caly_err(ret);
	}
	free(buf);
	return rc;
}

int caly_stats_read(struct caly_maps *m, __u64 *pkts, __u64 *bytes, size_t n)
{
	size_t i;

	if (!m)
		return -EINVAL;
	if (!pkts && !bytes)
		return -EINVAL;

	for (i = 0; i < n; i++) {
		__u64 v;

		if (pkts) {
			pkts[i] = 0;
			if (percpu_sum(m, CALY_MAP_ID_STATS, (__u32)i, &v) == 0)
				pkts[i] = v;
		}
		if (bytes) {
			bytes[i] = 0;
			if (percpu_sum(m, CALY_MAP_ID_STATS_B, (__u32)i,
				       &v) == 0)
				bytes[i] = v;
		}
	}
	return 0;
}

int caly_gauges_read(struct caly_maps *m, __u64 *g, size_t n)
{
	size_t i;

	if (!m || !g)
		return -EINVAL;
	for (i = 0; i < n; i++) {
		__u64 v;

		g[i] = 0;
		if (percpu_sum(m, CALY_MAP_ID_GLOBAL, (__u32)i, &v) == 0)
			g[i] = v;
	}
	return 0;
}

int caly_stats_reset(struct caly_maps *m)
{
	int rc, rc2;

	if (!m)
		return -EINVAL;
	rc = percpu_zero(m, CALY_MAP_ID_STATS, STAT_MAX);
	rc2 = percpu_zero(m, CALY_MAP_ID_STATS_B, STAT_MAX);
	return rc ? rc : rc2;
}

int caly_gauges_reset(struct caly_maps *m)
{
	if (!m)
		return -EINVAL;
	return percpu_zero(m, CALY_MAP_ID_GLOBAL, CALY_G_MAX);
}

/* =========================================================================
 * Top talkers
 * ========================================================================= */

static int top_cmp_pkts(const void *a, const void *b)
{
	const struct caly_top_entry *x = a, *y = b;

	if (x->stats.packets == y->stats.packets)
		return 0;
	return (x->stats.packets < y->stats.packets) ? 1 : -1;
}

static int top_cmp_bytes(const void *a, const void *b)
{
	const struct caly_top_entry *x = a, *y = b;

	if (x->stats.bytes == y->stats.bytes)
		return 0;
	return (x->stats.bytes < y->stats.bytes) ? 1 : -1;
}

static int top_cmp_drops(const void *a, const void *b)
{
	const struct caly_top_entry *x = a, *y = b;

	if (x->stats.drops == y->stats.drops)
		return 0;
	return (x->stats.drops < y->stats.drops) ? 1 : -1;
}

static int top_cmp_dropb(const void *a, const void *b)
{
	const struct caly_top_entry *x = a, *y = b;

	if (x->stats.drop_bytes == y->stats.drop_bytes)
		return 0;
	return (x->stats.drop_bytes < y->stats.drop_bytes) ? 1 : -1;
}

static int top_cmp_seen(const void *a, const void *b)
{
	const struct caly_top_entry *x = a, *y = b;

	if (x->stats.last_seen_ns == y->stats.last_seen_ns)
		return 0;
	return (x->stats.last_seen_ns < y->stats.last_seen_ns) ? 1 : -1;
}

int caly_top_query(struct caly_maps *m, __u32 family, int sort, size_t limit,
		   struct caly_top_entry **out, size_t *n)
{
	struct caly_top_entry *res = NULL;
	size_t cap = 0, total = 0;
	int (*cmp)(const void *, const void *);
	int pass, rc = 0;

	if (!m || !out || !n)
		return -EINVAL;
	*out = NULL;
	*n = 0;

	for (pass = 0; pass < 2; pass++) {
		__u32 fam = pass ? CALY_AF_INET6 : CALY_AF_INET;
		size_t ksz = pass ? sizeof(struct in6_key) : sizeof(__u32);
		int id = pass ? CALY_MAP_ID_TOP6 : CALY_MAP_ID_TOP4;
		void *keys = NULL, *vals = NULL;
		size_t got = 0, i;

		if (family != CALY_FAM_ANY && family != fam)
			continue;
		if (caly_maps_fd(m, id) < 0)
			continue;

		rc = hash_dump(m, id, ksz, sizeof(struct src_stats),
			       &keys, &vals, &got);
		if (rc) {
			free(keys);
			free(vals);
			free(res);
			return rc;
		}
		rc = buf_reserve((void **)&res, &cap, total + got,
				 sizeof(*res));
		if (rc) {
			free(keys);
			free(vals);
			free(res);
			return rc;
		}
		for (i = 0; i < got; i++) {
			memset(&res[total], 0, sizeof(res[total]));
			if (pass)
				in6key_to_cidr((struct in6_key *)
					       ((char *)keys + i * ksz),
					       &res[total].addr);
			else
				caly_cidr_from_addr(&res[total].addr,
						    CALY_AF_INET,
						    (const __u8 *)keys +
						    i * ksz);
			res[total].stats = ((struct src_stats *)vals)[i];
			total++;
		}
		free(keys);
		free(vals);
	}

	switch (sort) {
	case CALY_TOP_BY_BYTES:      cmp = top_cmp_bytes; break;
	case CALY_TOP_BY_DROPS:      cmp = top_cmp_drops; break;
	case CALY_TOP_BY_DROP_BYTES: cmp = top_cmp_dropb; break;
	case CALY_TOP_BY_LAST_SEEN:  cmp = top_cmp_seen;  break;
	default:                     cmp = top_cmp_pkts;  break;
	}
	if (total > 1)
		qsort(res, total, sizeof(*res), cmp);

	if (limit && total > limit)
		total = limit;

	*out = res;
	*n = total;
	return 0;
}

int caly_top_flush(struct caly_maps *m, __u32 family, size_t *removed)
{
	size_t nrm = 0, sub = 0;
	int rc = 0;

	if (family == CALY_FAM_ANY || family == CALY_AF_INET) {
		rc = hash_sweep(m, CALY_MAP_ID_TOP4, sizeof(__u32),
				sizeof(struct src_stats), NULL, NULL, 0, &sub);
		nrm += sub;
	}
	if (!rc && (family == CALY_FAM_ANY || family == CALY_AF_INET6)) {
		rc = hash_sweep(m, CALY_MAP_ID_TOP6, sizeof(struct in6_key),
				sizeof(struct src_stats), NULL, NULL, 0, &sub);
		nrm += sub;
	}
	if (removed)
		*removed = nrm;
	return rc;
}

/* =========================================================================
 * Idle-state garbage collection
 * ========================================================================= */

struct idle_ctx {
	__u64 now;
	__u64 idle;
	size_t off;   /* byte offset of the last_seen_ns field in the value */
};

static int value_idle(const void *k, const void *v, void *ctx)
{
	const struct idle_ctx *ic = ctx;
	__u64 last;

	(void)k;
	memcpy(&last, (const char *)v + ic->off, sizeof(last));
	if (ic->idle == 0)
		return 0;
	if (last == 0)
		return 1;
	if (last > ic->now)
		return 0;
	return (ic->now - last) > ic->idle;
}

static int idle_sweep_pair(struct caly_maps *m, int id4, int id6, size_t vsz,
			   size_t last_seen_off, __u64 now, __u64 idle,
			   __u32 budget, size_t *removed)
{
	struct idle_ctx ic;
	size_t nrm = 0, sub = 0;
	int rc;

	ic.now = now ? now : caly_now_ns();
	ic.idle = idle;
	ic.off = last_seen_off;

	rc = hash_sweep(m, id4, sizeof(__u32), vsz, value_idle, &ic, budget,
			&sub);
	nrm += sub;
	if (!rc) {
		rc = hash_sweep(m, id6, sizeof(struct in6_key), vsz,
				value_idle, &ic, budget, &sub);
		nrm += sub;
	}
	if (removed)
		*removed = nrm;
	return rc;
}

int caly_rate_sweep(struct caly_maps *m, __u64 now_ns, __u64 idle_ns,
		    __u32 budget, size_t *removed)
{
	return idle_sweep_pair(m, CALY_MAP_ID_RATE4, CALY_MAP_ID_RATE6,
			       sizeof(struct rate_state),
			       offsetof(struct rate_state, last_seen_ns),
			       now_ns, idle_ns, budget, removed);
}

int caly_scan_sweep(struct caly_maps *m, __u64 now_ns, __u64 idle_ns,
		    __u32 budget, size_t *removed)
{
	return idle_sweep_pair(m, CALY_MAP_ID_SCAN4, CALY_MAP_ID_SCAN6,
			       sizeof(struct scan_state),
			       offsetof(struct scan_state, last_seen_ns),
			       now_ns, idle_ns, budget, removed);
}

int caly_srcstat_sweep(struct caly_maps *m, __u64 now_ns, __u64 idle_ns,
		       __u32 budget, size_t *removed)
{
	return idle_sweep_pair(m, CALY_MAP_ID_TOP4, CALY_MAP_ID_TOP6,
			       sizeof(struct src_stats),
			       offsetof(struct src_stats, last_seen_ns),
			       now_ns, idle_ns, budget, removed);
}

int caly_maps_gc(struct caly_maps *m, const struct fw_config *cfg,
		 __u64 now_ns, struct caly_gc_stats *out)
{
	struct caly_gc_stats st;
	__u64 now = now_ns ? now_ns : caly_now_ns();
	__u32 budget;
	int rc = 0, r;

	if (!m || !cfg)
		return -EINVAL;
	memset(&st, 0, sizeof(st));
	budget = cfg->gc_batch ? cfg->gc_batch : 4096;

	r = caly_ban_sweep(m, now, budget, &st.bans_expired);
	if (r && !rc)
		rc = r;
	r = caly_rate_sweep(m, now, cfg->rate_idle_ns, budget, &st.rate_idle);
	if (r && !rc)
		rc = r;
	r = caly_scan_sweep(m, now, cfg->scan_idle_ns, budget, &st.scan_idle);
	if (r && !rc)
		rc = r;
	r = caly_srcstat_sweep(m, now, cfg->srcstat_idle_ns, budget,
			       &st.srcstat_idle);
	if (r && !rc)
		rc = r;
	r = caly_conn_sweep(m, cfg, now, budget, &st.conn_expired);
	if (r && !rc)
		rc = r;

	if (out)
		*out = st;
	return rc;
}

/* =========================================================================
 * Port policy
 * ========================================================================= */

int caly_port_get(const struct caly_maps *m, int is_udp, __u32 port,
		  struct port_rule *out)
{
	int fd = caly_maps_fd(m, is_udp ? CALY_MAP_ID_PORT_UDP
					: CALY_MAP_ID_PORT_TCP);
	int ret;

	if (fd < 0)
		return fd;
	if (!out || port > 65535)
		return -EINVAL;
	errno = 0;
	ret = bpf_map_lookup_elem(fd, &port, out);
	return caly_err(ret);
}

int caly_port_tb_reset(const struct caly_maps *m, int is_udp, __u32 port)
{
	struct token_bucket tb;
	__u32 idx;
	int fd = caly_maps_fd(m, CALY_MAP_ID_PORT_TB);
	int ret;

	if (fd < 0)
		return fd;
	if (port > 65535)
		return -EINVAL;
	idx = CALY_PORT_TB_IDX(is_udp, port);
	memset(&tb, 0, sizeof(tb));
	errno = 0;
	ret = bpf_map_update_elem(fd, &idx, &tb, BPF_ANY);
	return caly_err(ret);
}

int caly_port_set(struct caly_maps *m, int is_udp, __u32 port,
		  const struct port_rule *in)
{
	int fd = caly_maps_fd(m, is_udp ? CALY_MAP_ID_PORT_UDP
					: CALY_MAP_ID_PORT_TCP);
	struct port_rule *shadow;
	int ret;

	if (fd < 0)
		return fd;
	if (!in || port > 65535)
		return -EINVAL;

	errno = 0;
	ret = bpf_map_update_elem(fd, &port, in, BPF_ANY);
	if (ret < 0)
		return caly_err(ret);

	/* A changed rate configuration must not inherit the tokens the old
	 * one accumulated. Zeroing the bucket makes caly_tb_consume() reseed
	 * it on the next packet (last_refill_ns == 0 is the "fresh" marker). */
	if (in->mode == CALY_PORT_RATELIMIT)
		caly_port_tb_reset(m, is_udp, port);

	shadow = is_udp ? m->shadow_udp : m->shadow_tcp;
	if (shadow)
		shadow[port] = *in;
	return 0;
}

/*
 * Write a whole 65536-entry port table, touching only the entries that differ
 * from what we last wrote. The very first call after attaching to maps we did
 * not create has no shadow, so it writes everything: the table's default mode
 * depends on default_deny and a zeroed array does not encode it.
 */
static int write_port_table(struct caly_maps *m, int is_udp,
			    const struct port_rule *want)
{
	int id = is_udp ? CALY_MAP_ID_PORT_UDP : CALY_MAP_ID_PORT_TCP;
	struct port_rule **shadowp = is_udp ? &m->shadow_udp : &m->shadow_tcp;
	struct port_rule *shadow = *shadowp;
	__u32 *keys = NULL;
	struct port_rule *vals = NULL;
	size_t n = 0;
	__u32 p;
	int rc;

	if (caly_maps_fd(m, id) < 0)
		return -ENOENT;

	keys = malloc(CALY_PORT_TABLE_SZ * sizeof(*keys));
	vals = malloc(CALY_PORT_TABLE_SZ * sizeof(*vals));
	if (!keys || !vals) {
		free(keys);
		free(vals);
		return -ENOMEM;
	}

	for (p = 0; p < CALY_PORT_TABLE_SZ; p++) {
		if (shadow && memcmp(&shadow[p], &want[p],
				     sizeof(struct port_rule)) == 0)
			continue;
		keys[n] = p;
		vals[n] = want[p];
		n++;
	}

	rc = update_many(m, id, keys, sizeof(*keys), vals, sizeof(*vals), n);

	/* Reset the per-port bucket for every rate-limited port we just
	 * (re)wrote, so a lowered rate cannot be spent from a stale surplus. */
	if (rc == 0) {
		size_t i;

		for (i = 0; i < n; i++)
			if (vals[i].mode == CALY_PORT_RATELIMIT)
				caly_port_tb_reset(m, is_udp, keys[i]);
	}

	if (rc == 0) {
		if (!shadow) {
			shadow = malloc(CALY_PORT_TABLE_SZ * sizeof(*shadow));
			if (shadow)
				*shadowp = shadow;
		}
		if (shadow)
			memcpy(shadow, want,
			       CALY_PORT_TABLE_SZ * sizeof(*shadow));
	}

	free(keys);
	free(vals);
	return rc;
}

static void range_apply_flag(struct port_rule *tab, __u32 lo, __u32 hi,
			     __u32 flag, int set)
{
	__u32 p;

	if (hi > 65535)
		hi = 65535;
	for (p = lo; p <= hi && p < CALY_PORT_TABLE_SZ; p++) {
		if (set)
			tab[p].flags |= flag;
		else
			tab[p].flags &= ~flag;
	}
}

int caly_maps_apply_ports(struct caly_maps *m, const struct caly_conf *c,
			  char *err, size_t errsz)
{
	static const __u16 amp_ports[CALY_AMP_PORTS_COUNT] = CALY_AMP_PORTS_INIT;
	struct port_rule *tcp = NULL, *udp = NULL;
	__u32 defmode;
	size_t i;
	__u32 p;
	int rc;

	if (!m || !c)
		return -EINVAL;

	tcp = calloc(CALY_PORT_TABLE_SZ, sizeof(*tcp));
	udp = calloc(CALY_PORT_TABLE_SZ, sizeof(*udp));
	if (!tcp || !udp) {
		free(tcp);
		free(udp);
		caly_seterr(err, errsz, "out of memory building port tables");
		return -ENOMEM;
	}

	/*
	 * An array slot that was never written reads back as mode 0, which is
	 * CALY_PORT_CLOSED. That is the right answer only when default_deny
	 * is on. With default_deny off, "no rule" has to mean "not closed",
	 * so the unlisted default is written as CALY_PORT_OPEN.
	 */
	defmode = (c->fw.flags & CALY_F_DEFAULT_DENY) ? CALY_PORT_CLOSED
						      : CALY_PORT_OPEN;
	for (p = 0; p < CALY_PORT_TABLE_SZ; p++) {
		tcp[p].mode = defmode;
		udp[p].mode = defmode;
	}

	/* Reflection filter: the built-in amplifier source ports, then the
	 * operator's additions, then the operator's exemptions. Exemptions
	 * are applied last so `amp_exempt = 53` always wins. */
	for (i = 0; i < CALY_AMP_PORTS_COUNT; i++)
		udp[amp_ports[i]].flags |= CALY_PORT_F_AMPLIFIER;
	for (i = 0; i < c->n_amp_extra; i++)
		range_apply_flag(udp, c->amp_extra[i].lo, c->amp_extra[i].hi,
				 CALY_PORT_F_AMPLIFIER, 1);
	for (i = 0; i < c->n_amp_exempt; i++)
		range_apply_flag(udp, c->amp_exempt[i].lo,
				 c->amp_exempt[i].hi,
				 CALY_PORT_F_AMPLIFIER, 0);

	/* Explicit operator rules. */
	for (i = 0; i < c->n_ports; i++) {
		const struct caly_portspec *ps = &c->ports[i];
		struct port_rule *tab;
		__u32 hi = ps->hi > 65535 ? 65535 : ps->hi;

		tab = (ps->proto == CALY_IPPROTO_UDP) ? udp : tcp;
		for (p = ps->lo; p <= hi && p < CALY_PORT_TABLE_SZ; p++) {
			__u32 keep = tab[p].flags & CALY_PORT_F_AMPLIFIER;

			tab[p].mode  = ps->mode;
			tab[p].rate  = ps->rate;
			tab[p].burst = ps->burst;
			tab[p].flags = ps->flags | keep | CALY_PORT_F_PRESENT;
		}
	}

	/*
	 * Management ports. The dataplane checks the management list before
	 * the port policy, so this is belt and braces - but a port table that
	 * says "closed" for SSH is a trap waiting for the day someone
	 * reorders the packet path, so mark it and, unless the operator
	 * explicitly wrote a rule for it, open it.
	 */
	for (i = 0; i < c->fw.mgmt_tcp_count && i < CALY_MGMT_PORTS_MAX; i++) {
		__u32 mp = c->fw.mgmt_tcp_ports[i];

		if (mp >= CALY_PORT_TABLE_SZ)
			continue;
		tcp[mp].flags |= CALY_PORT_F_MGMT;
		if (!(tcp[mp].flags & CALY_PORT_F_PRESENT))
			tcp[mp].mode = CALY_PORT_OPEN;
	}
	for (i = 0; i < c->fw.mgmt_udp_count && i < CALY_MGMT_PORTS_MAX; i++) {
		__u32 mp = c->fw.mgmt_udp_ports[i];

		if (mp >= CALY_PORT_TABLE_SZ)
			continue;
		udp[mp].flags |= CALY_PORT_F_MGMT;
		if (!(udp[mp].flags & CALY_PORT_F_PRESENT))
			udp[mp].mode = CALY_PORT_OPEN;
	}

	/* SYN proxy coverage. An empty synproxy_port list means "every TCP
	 * port whose policy lets traffic in", per calyanti.conf. */
	if (c->fw.flags & CALY_F_SYNPROXY) {
		if (c->n_synproxy) {
			for (i = 0; i < c->n_synproxy; i++)
				range_apply_flag(tcp, c->synproxy_ports[i].lo,
						 c->synproxy_ports[i].hi,
						 CALY_PORT_F_SYNPROXY, 1);
		} else {
			for (p = 0; p < CALY_PORT_TABLE_SZ; p++)
				if (tcp[p].mode == CALY_PORT_OPEN ||
				    tcp[p].mode == CALY_PORT_RATELIMIT)
					tcp[p].flags |= CALY_PORT_F_SYNPROXY;
		}
	}

	/* Port 0 can never carry a real flow; the dataplane drops it with
	 * STAT_DROP_L4_PORT_ZERO before it ever gets here. Keep the slot
	 * closed so a stray lookup cannot open anything. */
	tcp[0].mode = CALY_PORT_CLOSED;
	udp[0].mode = CALY_PORT_CLOSED;
	tcp[0].flags &= ~(CALY_PORT_F_MGMT | CALY_PORT_F_SYNPROXY);
	udp[0].flags &= ~CALY_PORT_F_MGMT;

	rc = write_port_table(m, 0, tcp);
	if (rc) {
		caly_seterr(err, errsz, "cannot write %s: %s",
			    CALY_MAP_PORT_TCP, strerror(-rc));
		goto out;
	}
	rc = write_port_table(m, 1, udp);
	if (rc)
		caly_seterr(err, errsz, "cannot write %s: %s",
			    CALY_MAP_PORT_UDP, strerror(-rc));

out:
	free(tcp);
	free(udp);
	return rc;
}

/* =========================================================================
 * ICMP policy
 * ========================================================================= */

int caly_icmp_policy_get(const struct caly_maps *m, __u32 family, __u32 type,
			 __u32 *out)
{
	int fd = caly_maps_fd(m, family == CALY_AF_INET6
				 ? CALY_MAP_ID_ICMP6_POL
				 : CALY_MAP_ID_ICMP4_POL);
	int ret;

	if (fd < 0)
		return fd;
	if (!out || type > 255)
		return -EINVAL;
	errno = 0;
	ret = bpf_map_lookup_elem(fd, &type, out);
	return caly_err(ret);
}

int caly_icmp_policy_set(const struct caly_maps *m, __u32 family, __u32 type,
			 __u32 policy)
{
	static const int mand4[CALY_ICMP4_MANDATORY_COUNT] =
		CALY_ICMP4_MANDATORY_INIT;
	static const int mand6[CALY_ICMP6_MANDATORY_COUNT] =
		CALY_ICMP6_MANDATORY_INIT;
	int fd = caly_maps_fd(m, family == CALY_AF_INET6
				 ? CALY_MAP_ID_ICMP6_POL
				 : CALY_MAP_ID_ICMP4_POL);
	size_t i;
	int ret;

	if (fd < 0)
		return fd;
	if (type > 255 || policy >= CALY_ICMP_POL_MAX)
		return -EINVAL;

	/* Non-negotiable, enforced here as well as in the parser so that no
	 * CLI path can disconnect the host either. */
	if (policy == CALY_ICMP_DROP) {
		if (family == CALY_AF_INET6) {
			for (i = 0; i < CALY_ICMP6_MANDATORY_COUNT; i++)
				if ((__u32)mand6[i] == type)
					return -EPERM;
		} else {
			for (i = 0; i < CALY_ICMP4_MANDATORY_COUNT; i++)
				if ((__u32)mand4[i] == type)
					return -EPERM;
		}
	}

	errno = 0;
	ret = bpf_map_update_elem(fd, &type, &policy, BPF_ANY);
	return caly_err(ret);
}

int caly_maps_apply_icmp(struct caly_maps *m, const struct caly_conf *c,
			 char *err, size_t errsz)
{
	static const int mand4[CALY_ICMP4_MANDATORY_COUNT] =
		CALY_ICMP4_MANDATORY_INIT;
	static const int mand6[CALY_ICMP6_MANDATORY_COUNT] =
		CALY_ICMP6_MANDATORY_INIT;
	__u32 keys[CALY_ICMP_TABLE_SZ];
	__u32 pol4[CALY_ICMP_TABLE_SZ];
	__u32 pol6[CALY_ICMP_TABLE_SZ];
	__u32 dflt;
	size_t i;
	__u32 t;
	int rc;

	if (!m || !c)
		return -EINVAL;

	/* With the filter off, everything passes: a policy table that says
	 * DROP while the feature flag is clear is a landmine for whoever
	 * changes the packet path next. */
	dflt = (c->fw.flags & CALY_F_ICMP_FILTER) ? CALY_ICMP_DROP
						  : CALY_ICMP_PASS;
	for (t = 0; t < CALY_ICMP_TABLE_SZ; t++) {
		keys[t] = t;
		pol4[t] = dflt;
		pol6[t] = dflt;
	}

	for (i = 0; i < c->n_icmp; i++) {
		const struct caly_icmpspec *is = &c->icmp[i];
		__u32 hi = is->hi > 255 ? 255 : is->hi;

		for (t = is->lo; t <= hi && t < CALY_ICMP_TABLE_SZ; t++) {
			if (is->family == CALY_AF_INET6)
				pol6[t] = is->policy;
			else
				pol4[t] = is->policy;
		}
	}

	/* Mandatory types can never end up DROP, whether by an explicit rule
	 * (already refused by the parser) or by the unlisted default. */
	for (i = 0; i < CALY_ICMP4_MANDATORY_COUNT; i++) {
		__u32 idx = (__u32)mand4[i];

		if (idx < CALY_ICMP_TABLE_SZ && pol4[idx] == CALY_ICMP_DROP)
			pol4[idx] = CALY_ICMP_PASS;
	}
	for (i = 0; i < CALY_ICMP6_MANDATORY_COUNT; i++) {
		__u32 idx = (__u32)mand6[i];

		if (idx < CALY_ICMP_TABLE_SZ && pol6[idx] == CALY_ICMP_DROP)
			pol6[idx] = CALY_ICMP_PASS;
	}

	rc = update_many(m, CALY_MAP_ID_ICMP4_POL, keys, sizeof(keys[0]),
			 pol4, sizeof(pol4[0]), CALY_ICMP_TABLE_SZ);
	if (rc) {
		caly_seterr(err, errsz, "cannot write %s: %s",
			    CALY_MAP_ICMP4_POL, strerror(-rc));
		return rc;
	}
	rc = update_many(m, CALY_MAP_ID_ICMP6_POL, keys, sizeof(keys[0]),
			 pol6, sizeof(pol6[0]), CALY_ICMP_TABLE_SZ);
	if (rc)
		caly_seterr(err, errsz, "cannot write %s: %s",
			    CALY_MAP_ICMP6_POL, strerror(-rc));
	return rc;
}

/* =========================================================================
 * Interfaces
 * ========================================================================= */

int caly_iface_set(const struct caly_maps *m, __u32 ifindex, __u32 zone,
		   __u64 flags)
{
	struct iface_config ic;
	int fd = caly_maps_fd(m, CALY_MAP_ID_IFACE);
	int ret;

	if (fd < 0)
		return fd;
	if (ifindex == 0 || zone >= CALY_ZONE_MAX)
		return -EINVAL;

	memset(&ic, 0, sizeof(ic));
	ic.ifindex = ifindex;
	ic.zone = zone;
	ic.flags = flags;
	if (zone == CALY_ZONE_WAN)
		ic.flags |= CALY_IF_F_WAN;

	errno = 0;
	ret = bpf_map_update_elem(fd, &ifindex, &ic, BPF_ANY);
	return caly_err(ret);
}

int caly_iface_get(const struct caly_maps *m, __u32 ifindex,
		   struct iface_config *out)
{
	int fd = caly_maps_fd(m, CALY_MAP_ID_IFACE);
	int ret;

	if (fd < 0)
		return fd;
	if (!out)
		return -EINVAL;
	errno = 0;
	ret = bpf_map_lookup_elem(fd, &ifindex, out);
	return caly_err(ret);
}

int caly_iface_del(const struct caly_maps *m, __u32 ifindex)
{
	int fd = caly_maps_fd(m, CALY_MAP_ID_IFACE);
	int ret;

	if (fd < 0)
		return fd;
	errno = 0;
	ret = bpf_map_delete_elem(fd, &ifindex);
	if (ret < 0 && errno == ENOENT)
		return -ENOENT;
	return caly_err(ret);
}

int caly_iface_dump(struct caly_maps *m, struct caly_iface_dump **out,
		    size_t *n)
{
	void *keys = NULL, *vals = NULL;
	struct caly_iface_dump *res = NULL;
	size_t got = 0, i;
	int rc;

	if (!m || !out || !n)
		return -EINVAL;
	*out = NULL;
	*n = 0;

	rc = hash_dump(m, CALY_MAP_ID_IFACE, sizeof(__u32),
		       sizeof(struct iface_config), &keys, &vals, &got);
	if (rc) {
		free(keys);
		free(vals);
		return rc;
	}
	if (got) {
		res = calloc(got, sizeof(*res));
		if (!res) {
			free(keys);
			free(vals);
			return -ENOMEM;
		}
		for (i = 0; i < got; i++) {
			res[i].ifindex = ((__u32 *)keys)[i];
			res[i].cfg = ((struct iface_config *)vals)[i];
			if (!if_indextoname(res[i].ifindex, res[i].name))
				snprintf(res[i].name, sizeof(res[i].name),
					 "if%u", res[i].ifindex);
		}
	}
	free(keys);
	free(vals);
	*out = res;
	*n = got;
	return 0;
}

int caly_maps_apply_ifaces(struct caly_maps *m, const struct caly_conf *c,
			   char *err, size_t errsz)
{
	struct caly_iface_dump *have = NULL;
	__u32 *want = NULL;
	size_t nhave = 0, nwant = 0, i, j;
	int rc = 0;

	if (!m || !c)
		return -EINVAL;
	if (caly_maps_fd(m, CALY_MAP_ID_IFACE) < 0)
		return -ENOENT;

	if (c->n_ifaces) {
		want = calloc(c->n_ifaces, sizeof(*want));
		if (!want) {
			caly_seterr(err, errsz, "out of memory");
			return -ENOMEM;
		}
	}

	for (i = 0; i < c->n_ifaces; i++) {
		const struct caly_ifspec *ifs = &c->ifaces[i];
		unsigned int idx = if_nametoindex(ifs->name);
		int r;

		if (idx == 0) {
			/* Not an error: an interface can legitimately appear
			 * later (hotplug, VPN, container veth). The daemon
			 * re-applies on netlink link events. */
			continue;
		}
		r = caly_iface_set(m, idx, ifs->zone, ifs->flags);
		if (r && rc == 0)
			rc = r;
		want[nwant++] = idx;
	}

	/* Drop entries for interfaces the operator removed from the file. */
	if (caly_iface_dump(m, &have, &nhave) == 0) {
		for (i = 0; i < nhave; i++) {
			int keep = 0;

			for (j = 0; j < nwant; j++)
				if (want[j] == have[i].ifindex)
					keep = 1;
			if (!keep)
				caly_iface_del(m, have[i].ifindex);
		}
		free(have);
	}

	free(want);
	if (rc)
		caly_seterr(err, errsz, "cannot write %s: %s", CALY_MAP_IFACE,
			    strerror(-rc));
	return rc;
}

/* =========================================================================
 * Local prefixes from the running system
 * ========================================================================= */

int caly_maps_populate_local(struct caly_maps *m, size_t *added)
{
	struct ifaddrs *ifa = NULL, *p;
	size_t n = 0;
	int rc;

	if (!m)
		return -EINVAL;
	if (added)
		*added = 0;

	if (getifaddrs(&ifa) != 0)
		return -errno;

	for (p = ifa; p; p = p->ifa_next) {
		struct caly_cidr cd;

		if (!p->ifa_addr)
			continue;

		memset(&cd, 0, sizeof(cd));
		if (p->ifa_addr->sa_family == AF_INET) {
			const struct sockaddr_in *sin =
				(const struct sockaddr_in *)(void *)p->ifa_addr;

			cd.family = CALY_AF_INET;
			cd.prefixlen = 32;   /* host route: exactly ours */
			memcpy(cd.addr, &sin->sin_addr, 4);
		} else if (p->ifa_addr->sa_family == AF_INET6) {
			const struct sockaddr_in6 *sin6 =
				(const struct sockaddr_in6 *)(void *)p->ifa_addr;

			cd.family = CALY_AF_INET6;
			cd.prefixlen = 128;
			memcpy(cd.addr, &sin6->sin6_addr, 16);
		} else {
			continue;
		}

		cd.flags = CALY_RULE_F_LOCAL;
		cd.tag = CALY_TAG_AUTO;

		rc = caly_set_add(m, CALY_SET_LOCAL, &cd);
		if (rc == 0)
			n++;
	}

	freeifaddrs(ifa);
	if (added)
		*added = n;
	return 0;
}

/* =========================================================================
 * Whole-policy application
 * ========================================================================= */

int caly_maps_apply_sets(struct caly_maps *m, const struct caly_conf *c,
			 char *err, size_t errsz)
{
	static const __u32 conf_tag[] = { CALY_TAG_CONF };
	static const __u32 local_tags[] = { CALY_TAG_CONF, CALY_TAG_AUTO };
	int rc;

	if (!m || !c)
		return -EINVAL;

	/* Allowlist first and always: it is the escape hatch, and sync_set()
	 * inserts before it deletes so coverage is never briefly absent. */
	rc = sync_set(m, CALY_SET_ALLOW, c->allow, c->n_allow,
		      conf_tag, CALY_ARRAY_SIZE(conf_tag), NULL, NULL);
	if (rc) {
		caly_seterr(err, errsz, "cannot program the allowlist: %s",
			    strerror(-rc));
		return rc;
	}

	rc = sync_set(m, CALY_SET_BLOCK, c->block, c->n_block,
		      conf_tag, CALY_ARRAY_SIZE(conf_tag), NULL, NULL);
	if (rc) {
		caly_seterr(err, errsz, "cannot program the blocklist: %s",
			    strerror(-rc));
		return rc;
	}

	rc = sync_set(m, CALY_SET_LOCAL, c->local, c->n_local,
		      local_tags, CALY_ARRAY_SIZE(local_tags), NULL, NULL);
	if (rc) {
		caly_seterr(err, errsz, "cannot program local prefixes: %s",
			    strerror(-rc));
		return rc;
	}

	/* The interface addresses are added back after the sync, because the
	 * sync removes CALY_TAG_AUTO entries that are not in the file. */
	caly_maps_populate_local(m, NULL);
	return 0;
}

int caly_maps_apply_config(struct caly_maps *m, struct caly_conf *c,
			   char *err, size_t errsz)
{
	int rc;

	if (!m || !c)
		return -EINVAL;
	if (!c->finalized) {
		caly_seterr(err, errsz,
			    "internal: configuration was never validated");
		return -EINVAL;
	}

	/*
	 * Order matters. Every table the dataplane consults is written BEFORE
	 * the config that enables the feature reading it, so there is no
	 * instant at which a flag is on and its table is empty. The config
	 * map is written last for exactly that reason.
	 */
	rc = caly_maps_apply_sets(m, c, err, errsz);
	if (rc)
		return rc;

	rc = caly_maps_apply_ports(m, c, err, errsz);
	if (rc)
		return rc;

	rc = caly_maps_apply_icmp(m, c, err, errsz);
	if (rc)
		return rc;

	rc = caly_maps_apply_ifaces(m, c, err, errsz);
	if (rc && rc != -ENOENT)
		return rc;

	rc = caly_map_config_install(m, &c->fw, err, errsz);
	if (rc)
		return rc;

	return 0;
}
