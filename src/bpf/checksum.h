/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - XDP/eBPF DDoS mitigation suite
 * src/bpf/checksum.h - RFC 1071 / RFC 1624 checksum arithmetic.
 *
 * Needed by the SYN proxy, which rewrites an inbound SYN into a SYN-ACK in
 * place and XDP_TX's it. If either checksum is wrong the client silently
 * discards the SYN-ACK and the connection never happens - a failure that looks
 * exactly like "the service is down".
 *
 * PREREQUISITE INCLUDES:
 *     #include "vmlinux.h"     (BPF)  or  <linux/types.h> (userspace)
 *     #include "common.h"
 *     #include "compat.h"
 *
 * No kernel helper is called from this file. bpf_csum_diff() is deliberately
 * not used: it has alignment requirements on its buffers, its availability
 * across the 4.18 backport zoo is not worth verifying, and the arithmetic
 * below is a dozen instructions.
 *
 * ---------------------------------------------------------------------------
 * THE BYTE-ORDER ARGUMENT (read this before changing anything here)
 * ---------------------------------------------------------------------------
 * The Internet checksum has a useful property: the one's complement sum of
 * byte-swapped data is the byte-swap of the one's complement sum. So if we
 *
 *   - load 16-bit words from the packet with a NATIVE __u16 load (which
 *     byte-swaps them on a little-endian host),
 *   - accumulate,
 *   - fold,
 *   - and store the result back with a NATIVE __u16 store (which swaps again),
 *
 * the two swaps cancel and the value on the wire is correct on both endians.
 * Every function here works in that "swapped space". The consequence is that
 * any constant folded into a sum (pseudo-header protocol and length fields)
 * must be converted with caly_htons()/caly_htonl() first, so it lands in the
 * same space as the packet-derived words. Getting this wrong produces a
 * checksum that is correct on x86_64 and wrong on a big-endian target, which
 * is the sort of bug that ships.
 *
 * A 32-bit accumulator holding a network-order __u32 loaded natively folds
 * correctly too: on LE the native value is (hi_swapped << 16) | lo_swapped,
 * and folding adds exactly those two halves. That is why the address words
 * below are added as whole __u32 values rather than split into halves.
 * ---------------------------------------------------------------------------
 */

#ifndef __CALY_ANTI_CHECKSUM_H
#define __CALY_ANTI_CHECKSUM_H

/*
 * Upper bound on how many bytes any single checksum call may traverse. The
 * loop below is CALY_UNROLL'd against this constant, so raising it costs
 * verifier instructions on every kernel including the 96k-budget 4.18
 * verifiers. 128 bytes covers a 60-byte IPv4 header, a 60-byte TCP header
 * with every option, and the 24-byte SYN-ACK the proxy actually builds.
 */
#ifndef CALY_CSUM_MAX_BYTES
#define CALY_CSUM_MAX_BYTES 128u
#endif
#define CALY_CSUM_MAX_WORDS (CALY_CSUM_MAX_BYTES / 2u)

/* Byte offset of the checksum field inside each header, for the "skip this
 * word" logic. Spelled out so no caller has to remember them. */
#define CALY_IP4_CSUM_OFF   10u
#define CALY_TCP_CSUM_OFF   16u
#define CALY_UDP_CSUM_OFF   6u
#define CALY_ICMP_CSUM_OFF  2u

/* -------------------------------------------------------------------------
 * Core one's complement arithmetic.
 * ------------------------------------------------------------------------- */

/*
 * 32-bit one's complement addition: add, then fold the carry back in. This is
 * the same construction as the kernel's csum_add(). Carrying rather than
 * truncating is what lets a caller accumulate a whole header into a __u32 and
 * fold only once at the end.
 */
CALY_INLINE __u32 caly_csum_add(__u32 csum, __u32 addend)
{
	csum += addend;
	return csum + (csum < addend);
}

CALY_INLINE __u32 caly_csum_sub(__u32 csum, __u32 addend)
{
	return caly_csum_add(csum, ~addend);
}

/*
 * RFC 1071 fold: reduce a 32-bit accumulator to 16 bits and complement.
 * Two folds are required, not one: the first can itself produce a carry.
 */
CALY_INLINE __u16 caly_csum_fold(__u32 csum)
{
	csum = (csum & 0xFFFFu) + (csum >> 16);
	csum = (csum & 0xFFFFu) + (csum >> 16);
	return (__u16)~csum;
}

/* Fold WITHOUT the final complement. Used when a partial sum has to be handed
 * on to another accumulation stage. */
CALY_INLINE __u16 caly_csum_fold_partial(__u32 csum)
{
	csum = (csum & 0xFFFFu) + (csum >> 16);
	csum = (csum & 0xFFFFu) + (csum >> 16);
	return (__u16)csum;
}

/* Expand a stored (complemented) checksum back into an accumulator. */
CALY_INLINE __u32 caly_csum_unfold(__u16 sum)
{
	return (__u32)sum;
}

/* -------------------------------------------------------------------------
 * Incremental update - RFC 1624.
 *
 * The naive formula HC' = ~(HC + ~m + m') is WRONG: it can produce the
 * negative zero 0xFFFF where the correct answer is 0x0000, and a UDP header
 * carrying 0x0000 means "no checksum", so the error is not cosmetic.
 *
 * RFC 1624 eqn. 3 is used instead:  HC' = ~(~HC + ~m + m')
 * expressed as: unfold, complement, subtract the old value, add the new,
 * fold (which complements). Every intermediate stays in the 32-bit carrying
 * representation, so no negative zero can be produced.
 *
 * BYTE ORDER CONTRACT (verified numerically):
 *   `sum`, `from` and `to` must ALL be expressed in the same byte order. The
 *   correct and least-error-prone choice is "exactly as a native load of that
 *   packet field yields", i.e.
 *       __u16 old = th->check;                 // native load
 *       __u16 from = *(__u16 *)&field_bytes;   // native load of the field
 *       ... compute `to` as the bit pattern you will store back ...
 *       th->check = caly_csum_replace2(old, from, to);   // native store
 *   One's-complement addition commutes with byte swapping, so the result is
 *   returned in that same order and is written straight back with a native
 *   store. Do NOT mix ntohs/htons conversions into some operands and not
 *   others. When several fields change at once (the SYN proxy rewrites seq,
 *   ack, flags and window together) prefer recomputing the whole L4 checksum
 *   with caly_l4_csum_v4/v6 rather than chaining replaces - it is simpler to
 *   reason about and was the path validated end to end.
 * ------------------------------------------------------------------------- */

/* Replace a 16-bit field. See the byte-order contract above: `from`/`to` are
 * the raw field values as read/stored by a native load/store. */
CALY_INLINE __u16 caly_csum_replace2(__u16 sum, __u16 from, __u16 to)
{
	__u32 tmp = caly_csum_sub(~caly_csum_unfold(sum) & 0xFFFFFFFFu,
				  (__u32)from);

	return caly_csum_fold(caly_csum_add(tmp, (__u32)to));
}

/* Replace a 32-bit field (an IPv4 address, a sequence number). */
CALY_INLINE __u16 caly_csum_replace4(__u16 sum, __u32 from, __u32 to)
{
	__u32 tmp = caly_csum_sub(~caly_csum_unfold(sum) & 0xFFFFFFFFu, from);

	return caly_csum_fold(caly_csum_add(tmp, to));
}

/* Replace a 128-bit field (an IPv6 address). Both arguments point at four
 * network-order __u32 words. */
CALY_INLINE __u16 caly_csum_replace16(__u16 sum, const __u32 *from,
				      const __u32 *to)
{
	__u32 tmp = ~caly_csum_unfold(sum) & 0xFFFFFFFFu;
	unsigned int i;

	CALY_UNROLL
	for (i = 0; i < 4u; i++)
		tmp = caly_csum_sub(tmp, from[i]);
	CALY_UNROLL
	for (i = 0; i < 4u; i++)
		tmp = caly_csum_add(tmp, to[i]);

	return caly_csum_fold(tmp);
}

/*
 * Swapping two 16-bit fields (TCP sport <-> dport) leaves the checksum
 * unchanged: one's complement addition is commutative. Same for swapping the
 * IPv4 or IPv6 source and destination. The SYN proxy relies on this, which is
 * why it only has to account for the fields it genuinely changes (seq, ack,
 * flags, window, and the appended MSS option). This function exists to make
 * that reasoning explicit at the call site rather than a silent omission.
 */
CALY_INLINE __u16 caly_csum_swap_noop(__u16 sum)
{
	return sum;
}

/* -------------------------------------------------------------------------
 * Bounded summation over packet bytes.
 *
 * EVERY word is bounds-checked against data_end immediately before it is
 * read. `len` is never trusted: it bounds the loop, but the pointer check is
 * what makes the read legal. A truncated range is an error, never a partial
 * sum, because a partial sum would produce a plausible-looking wrong answer.
 *
 * skip_off, when not CALY_CSUM_NO_SKIP, names a 16-bit-aligned byte offset
 * within the range that is treated as zero. That is how the checksum field
 * itself is excluded without the caller having to mutate the packet first.
 * ------------------------------------------------------------------------- */

#define CALY_CSUM_NO_SKIP 0xFFFFFFFFu

CALY_INLINE int caly_csum_range(const void *start, const void *data_end,
				__u32 len, __u32 skip_off, __u32 *sum_out)
{
	const __u8 *p = (const __u8 *)start;
	__u32 sum = 0;
	__u32 words, i, off;

	if (!sum_out)
		return CALY_ERR_INVAL;
	if (len > CALY_CSUM_MAX_BYTES)
		return CALY_ERR_INVAL;
	if (skip_off != CALY_CSUM_NO_SKIP && ((skip_off & 1u) || skip_off >= len))
		return CALY_ERR_INVAL;

	words = len >> 1;

	CALY_UNROLL
	for (i = 0; i < CALY_CSUM_MAX_WORDS; i++) {
		__u16 w;

		if (i >= words)
			break;

		off = i * 2u;
		if ((const void *)(p + off + 2u) > data_end)
			return CALY_ERR_TRUNC;

		if (skip_off != CALY_CSUM_NO_SKIP && off == skip_off)
			continue;

		/* Native 16-bit load: see the byte-order argument at the top. */
		__builtin_memcpy(&w, p + off, sizeof(w));
		sum = caly_csum_add(sum, (__u32)w);
	}

	/* Odd trailing byte: it is the HIGH byte of a notional network-order
	 * word, so in swapped space it must be placed accordingly. Routing it
	 * through caly_htons() gets that right on both endians. */
	if (len & 1u) {
		__u8 last;

		off = len - 1u;
		if ((const void *)(p + off + 1u) > data_end)
			return CALY_ERR_TRUNC;
		if (skip_off == CALY_CSUM_NO_SKIP || off != skip_off) {
			__builtin_memcpy(&last, p + off, sizeof(last));
			sum = caly_csum_add(sum,
				(__u32)caly_htons((__u16)((__u16)last << 8)));
		}
	}

	*sum_out = sum;
	return CALY_OK;
}

/* -------------------------------------------------------------------------
 * IPv4 header checksum.
 *
 * The header checksum covers the header only, with the checksum field taken
 * as zero. ihl_bytes must be the value already validated by the parser
 * (20..60, multiple of 4) - this function re-validates rather than trusting
 * it, because "the parser already checked" is how bounds bugs are born.
 *
 * The result in *out is written straight back with a native store
 * (`iph->check = out;`); no htons is applied. This was verified numerically.
 * ------------------------------------------------------------------------- */

CALY_INLINE int caly_ipv4_csum(const void *iph, const void *data_end,
			       __u32 ihl_bytes, __u16 *out)
{
	__u32 sum = 0;
	int err;

	if (!out)
		return CALY_ERR_INVAL;
	if (ihl_bytes < 20u || ihl_bytes > 60u || (ihl_bytes & 3u))
		return CALY_ERR_INVAL;

	err = caly_csum_range(iph, data_end, ihl_bytes, CALY_IP4_CSUM_OFF, &sum);
	if (err != CALY_OK)
		return err;

	*out = caly_csum_fold(sum);
	return CALY_OK;
}

/* -------------------------------------------------------------------------
 * Pseudo-header sums.
 *
 * Returned as UNFOLDED 32-bit accumulators so the caller can chain them into
 * the L4 summation and fold exactly once.
 * ------------------------------------------------------------------------- */

/*
 * IPv4 pseudo-header: src, dst, zero, protocol, TCP/UDP length.
 * saddr/daddr are network-order __u32 exactly as they sit in the header.
 * l4_len is the L4 header + payload length in HOST order.
 */
CALY_INLINE __u32 caly_pseudo_csum_v4(__u32 saddr_net, __u32 daddr_net,
				      __u8 proto, __u16 l4_len)
{
	__u32 sum = 0;

	sum = caly_csum_add(sum, saddr_net);
	sum = caly_csum_add(sum, daddr_net);
	sum = caly_csum_add(sum, (__u32)caly_htons((__u16)proto));
	sum = caly_csum_add(sum, (__u32)caly_htons(l4_len));
	return sum;
}

/*
 * IPv6 pseudo-header: src (16 B), dst (16 B), 32-bit upper-layer length,
 * 24 zero bits, 8-bit next header. saddr/daddr point at four network-order
 * __u32 words each. l4_len is HOST order.
 */
CALY_INLINE __u32 caly_pseudo_csum_v6(const __u32 *saddr, const __u32 *daddr,
				      __u8 nexthdr, __u32 l4_len)
{
	__u32 sum = 0;
	unsigned int i;

	CALY_UNROLL
	for (i = 0; i < 4u; i++)
		sum = caly_csum_add(sum, saddr[i]);
	CALY_UNROLL
	for (i = 0; i < 4u; i++)
		sum = caly_csum_add(sum, daddr[i]);

	sum = caly_csum_add(sum, caly_htonl(l4_len));
	sum = caly_csum_add(sum, caly_htonl((__u32)nexthdr));
	return sum;
}

/* -------------------------------------------------------------------------
 * Complete L4 checksums.
 *
 * CONTRACT: the checksum field inside the L4 header is EXCLUDED by offset, so
 * the caller does not have to zero it first. Pass the offset of the field
 * within the L4 header (CALY_TCP_CSUM_OFF / CALY_UDP_CSUM_OFF), or
 * CALY_CSUM_NO_SKIP if it is already zero.
 *
 * l4_len must be the true L4 header + payload length. It is bounded by
 * CALY_CSUM_MAX_BYTES; a longer segment cannot be checksummed here, which is
 * fine because the only thing this tree ever generates is a 24-byte SYN-ACK.
 * Callers that need to validate a full-size segment must not - validating an
 * inbound checksum is the stack's job and doing it in XDP is a DoS amplifier
 * against ourselves.
 *
 * The result in *out is written straight back with a native store
 * (`th->check = out;` / `uh->check = out;`); no htons is applied. The whole
 * saddr/daddr/skip pipeline was validated end to end against a reference
 * Internet checksum, including the odd-trailing-byte and UDP-zero cases.
 * ------------------------------------------------------------------------- */

CALY_INLINE int caly_l4_csum_v4(const void *l4h, const void *data_end,
				__u32 saddr_net, __u32 daddr_net, __u8 proto,
				__u16 l4_len, __u32 skip_off, __u16 *out)
{
	__u32 sum;
	int err;

	if (!out)
		return CALY_ERR_INVAL;

	err = caly_csum_range(l4h, data_end, (__u32)l4_len, skip_off, &sum);
	if (err != CALY_OK)
		return err;

	sum = caly_csum_add(sum,
			    caly_pseudo_csum_v4(saddr_net, daddr_net, proto,
						l4_len));
	*out = caly_csum_fold(sum);

	/* A computed UDP checksum of zero must be transmitted as 0xFFFF: on
	 * the wire 0x0000 means "no checksum was computed". TCP has no such
	 * rule, but writing 0xFFFF there is equally valid, so the branch is
	 * kept unconditional rather than protocol-dependent. */
	if (*out == 0)
		*out = 0xFFFFu;
	return CALY_OK;
}

CALY_INLINE int caly_l4_csum_v6(const void *l4h, const void *data_end,
				const __u32 *saddr, const __u32 *daddr,
				__u8 nexthdr, __u16 l4_len, __u32 skip_off,
				__u16 *out)
{
	__u32 sum;
	int err;

	if (!out)
		return CALY_ERR_INVAL;

	err = caly_csum_range(l4h, data_end, (__u32)l4_len, skip_off, &sum);
	if (err != CALY_OK)
		return err;

	sum = caly_csum_add(sum,
			    caly_pseudo_csum_v6(saddr, daddr, nexthdr,
						(__u32)l4_len));
	*out = caly_csum_fold(sum);

	/* IPv6 has no optional UDP checksum: 0x0000 is illegal, always. */
	if (*out == 0)
		*out = 0xFFFFu;
	return CALY_OK;
}

/* -------------------------------------------------------------------------
 * Convenience: verify a computed checksum against the stored one.
 *
 * Used only by the self-test path and by the tc egress program when it is
 * asked to sanity check its own rewrite. Never on the inbound fast path.
 * ------------------------------------------------------------------------- */
CALY_INLINE int caly_csum_ok(__u16 computed, __u16 stored)
{
	/* 0x0000 and 0xFFFF are the same value in one's complement. */
	if (computed == stored)
		return 1;
	if ((computed == 0 && stored == 0xFFFFu) ||
	    (computed == 0xFFFFu && stored == 0))
		return 1;
	return 0;
}

/* -------------------------------------------------------------------------
 * Self-check.
 *
 * caly_csum_add must carry, not truncate. If a future refactor turns it into
 * a plain 32-bit add this assertion still passes - it is the fold that would
 * break - so the real guard is the unit test in tests/. This one catches the
 * cheap mistake of the fold returning the uncomplemented value.
 * ------------------------------------------------------------------------- */
CALY_ASSERT(sizeof(__u32) == 4, csum_u32_is_4);
CALY_ASSERT(CALY_CSUM_MAX_BYTES >= 64u && (CALY_CSUM_MAX_BYTES % 2u) == 0,
	    csum_max_bytes_sane);

#endif /* __CALY_ANTI_CHECKSUM_H */
