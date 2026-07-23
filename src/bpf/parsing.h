/* SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0 */
/*
 * Caly Anti - XDP/eBPF DDoS mitigation suite
 * src/bpf/parsing.h - bounds-safe, cursor-based packet parsers.
 *
 * PREREQUISITE INCLUDES:
 *     #include "vmlinux.h"
 *     #include <bpf/bpf_helpers.h>
 *     #include <bpf/bpf_endian.h>
 *     #include "common.h"
 *     #include "compat.h"
 *     #include "parsing.h"
 *
 * ---------------------------------------------------------------------------
 * RULES OBEYED BY EVERY FUNCTION IN THIS FILE
 * ---------------------------------------------------------------------------
 * 1. EVERY read is preceded by an explicit (ptr + size > data_end) test. There
 *    is no "the previous check covered it" reasoning anywhere: each parser
 *    re-derives its own bound from the cursor. The verifier will not take our
 *    word for it and neither should a reviewer.
 *
 * 2. NO length field from the packet is ever used to compute an offset that
 *    has not itself been bounds-checked. Length fields bound loops; pointer
 *    comparisons authorise reads. An attacker controls the former entirely.
 *
 * 3. Every loop has a COMPILE-TIME constant bound (CALY_VLAN_MAX_DEPTH,
 *    CALY_IP6_EXT_MAX, CALY_TUNNEL_MAX_DEPTH) and is CALY_UNROLL'd. Runtime
 *    configuration may only LOWER the effective bound, never raise it.
 *
 * 4. Failures are negative CALY_ERR_* codes from compat.h, one per
 *    enum stat_reason, translated by caly_parse_err_reason(). Three of them
 *    (ENCRYPTED, NO_NEXT, FRAG_NO_L4) mean "well formed, but no L4 to look
 *    at" and MUST NOT become drops - see caly_parse_err_benign().
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE DEFINES ITS OWN HEADER STRUCTS
 * ---------------------------------------------------------------------------
 * vmlinux.h is emitted by bpftool wrapped in
 *
 *     #pragma clang attribute push (__attribute__((preserve_access_index)), ...)
 *
 * so every access to a vmlinux struct - including one pointed at PACKET DATA -
 * generates a CO-RE relocation. For kernel structs that is exactly right. For
 * wire formats it is wrong twice over: the layout is fixed by the RFC and not
 * by the running kernel, and struct iphdr / struct tcphdr carry BITFIELDS
 * (version/ihl, doff/res1) whose CO-RE bitfield relocations are a well known
 * source of subtly wrong reads.
 *
 * The structs below are therefore ours: fixed-width members, NO bitfields (the
 * version/ihl and doff/flags bytes are read whole and masked by hand), and
 * natural alignment that is asserted at the bottom of the file. Nothing here
 * is packed, because __attribute__((packed)) makes clang emit byte-at-a-time
 * loads for every multi-byte field and this is the hot path.
 */

#ifndef __CALY_ANTI_PARSING_H
#define __CALY_ANTI_PARSING_H

/* -------------------------------------------------------------------------
 * Wire structures. All multi-byte fields are NETWORK byte order.
 * ------------------------------------------------------------------------- */

struct caly_ethhdr {
	__u8  dst[6];
	__u8  src[6];
	__u16 proto;              /* ethertype, network order */
};

struct caly_vlanhdr {
	__u16 tci;                /* pcp(3) dei(1) vid(12), network order */
	__u16 proto;              /* inner ethertype, network order */
};

struct caly_iphdr {
	__u8  version_ihl;        /* high nibble version, low nibble ihl */
	__u8  tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;           /* flags(3) | offset(13) */
	__u8  ttl;
	__u8  protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
	/* options follow when ihl > 5 */
};

struct caly_ipv6hdr {
	__u32 ver_tc_fl;          /* version(4) tc(8) flowlabel(20) */
	__u16 payload_len;
	__u8  nexthdr;
	__u8  hop_limit;
	__u32 saddr[4];
	__u32 daddr[4];
};

/* Generic IPv6 extension header: HOPOPTS, DSTOPTS, MH. */
struct caly_ip6_ext {
	__u8 nexthdr;
	__u8 hdrlen;              /* length in 8-byte units, not counting 1st */
};

/* Routing header. Needed in full because RH0 is identified by `type`. */
struct caly_ip6_rt {
	__u8 nexthdr;
	__u8 hdrlen;
	__u8 type;
	__u8 segments_left;
};

/* Fragment header: fixed 8 bytes, hdrlen field is reserved and meaningless. */
struct caly_ip6_frag {
	__u8  nexthdr;
	__u8  reserved;
	__u16 frag_off;           /* offset(13) res(2) M(1), network order */
	__u32 identification;
};

/* Authentication header. `hdrlen` is in 4-byte units MINUS 2 - a different
 * convention from every other extension header, and a classic off-by-8 bug. */
struct caly_ip6_auth {
	__u8  nexthdr;
	__u8  hdrlen;
	__u16 reserved;
	__u32 spi;
	__u32 seq;
};

struct caly_tcphdr {
	__u16 source;
	__u16 dest;
	__u32 seq;
	__u32 ack_seq;
	__u8  doff_res;           /* high nibble data offset, low nibble res */
	__u8  flags;              /* CWR ECE URG ACK PSH RST SYN FIN */
	__u16 window;
	__u16 check;
	__u16 urg_ptr;
	/* options follow when doff > 5 */
};

struct caly_udphdr {
	__u16 source;
	__u16 dest;
	__u16 len;                /* header + payload, minimum 8 */
	__u16 check;
};

/* Common to ICMPv4 and ICMPv6: 4 bytes of header plus 4 bytes of
 * type-specific "rest of header". Every RFC 792 / RFC 4443 message has at
 * least these 8 bytes. */
struct caly_icmphdr {
	__u8  type;
	__u8  code;
	__u16 checksum;
	__u32 rest;
};

/* RFC 2784 / RFC 2890 GRE. Optional fields follow depending on flags. */
struct caly_grehdr {
	__u16 flags;
	__u16 proto;              /* inner ethertype, network order */
};

#define CALY_GRE_F_CSUM      0x8000u
#define CALY_GRE_F_ROUTING   0x4000u   /* RFC 2784: MUST be zero */
#define CALY_GRE_F_KEY       0x2000u
#define CALY_GRE_F_SEQ       0x1000u
#define CALY_GRE_F_SSR       0x0800u
#define CALY_GRE_F_RECUR     0x0700u
#define CALY_GRE_F_RESERVED0 0x00F8u   /* RFC 2784: MUST be zero */
#define CALY_GRE_F_VERSION   0x0007u

#define CALY_ETH_P_TEB       0x6558    /* transparent ethernet bridging */

/* IPv4 fragment field decomposition. */
#define CALY_IP4_FRAG_RF     0x8000u
#define CALY_IP4_FRAG_DF     0x4000u
#define CALY_IP4_FRAG_MF     0x2000u
#define CALY_IP4_FRAG_MASK   0x1FFFu

/* IPv6 fragment header field decomposition. */
#define CALY_IP6_FRAG_MF     0x0001u
#define CALY_IP6_FRAG_SHIFT  3u

/* ICMP type/code are stashed in pkt_ctx.tcp_flags, which is meaningless for
 * ICMP. Deliberately NOT stashed in sport/dport: those are documented as
 * network-order ports and a reader decoding an event must never see a port
 * that is really an ICMP type. */
#define CALY_PKT_ICMP_PACK(type, code) \
	((((__u32)(type)) << 8) | ((__u32)(code) & 0xFFu))
#define CALY_PKT_ICMP_TYPE(pkt) ((__u8)(((pkt)->tcp_flags >> 8) & 0xFFu))
#define CALY_PKT_ICMP_CODE(pkt) ((__u8)((pkt)->tcp_flags & 0xFFu))

/* -------------------------------------------------------------------------
 * The cursor.
 *
 * `pos` is the next unread byte, `end` is one past the last readable byte
 * (ctx->data_end). Both are packet pointers as far as the verifier is
 * concerned, which is why they must be plain void * and must not be laundered
 * through any integer type.
 * ------------------------------------------------------------------------- */

struct caly_cursor {
	void *pos;
	void *end;
};

CALY_INLINE void caly_cursor_init(struct caly_cursor *c, void *data,
				  void *data_end)
{
	c->pos = data;
	c->end = data_end;
}

/*
 * Reserve `len` bytes and advance. Returns NULL when the read would pass
 * data_end - the ONLY sanctioned way to obtain a dereferenceable pointer in
 * this file.
 *
 * `len` is a compile-time constant at almost every call site (sizeof of one
 * of the structs above). Where it is not - IPv4 options, IPv6 extension
 * headers, GRE optional fields - the caller MUST bound it first; the
 * CALY_PULL_MAX guard below is a backstop for that, not a substitute.
 */
#define CALY_PULL_MAX 2048u

CALY_INLINE void *caly_pull(struct caly_cursor *c, __u32 len)
{
	void *p = c->pos;

	if (len > CALY_PULL_MAX)
		return 0;
	if (p + len > c->end)
		return 0;

	c->pos = p + len;
	return p;
}

/* Peek without advancing. Same bounds discipline. */
CALY_INLINE void *caly_peek(struct caly_cursor *c, __u32 len)
{
	void *p = c->pos;

	if (len > CALY_PULL_MAX)
		return 0;
	if (p + len > c->end)
		return 0;

	return p;
}

/* Bytes still readable. Used for length cross-checks, never to authorise a
 * read on its own. */
CALY_INLINE __u32 caly_avail(const struct caly_cursor *c)
{
	if (c->pos > c->end)
		return 0;
	return (__u32)((__u8 *)c->end - (__u8 *)c->pos);
}

/* Offset of the cursor from the start of the frame. */
CALY_INLINE __u32 caly_offset(const struct caly_cursor *c, const void *data)
{
	if (c->pos < data)
		return 0;
	return (__u32)((__u8 *)c->pos - (__u8 *)data);
}

/* -------------------------------------------------------------------------
 * Layer 2: Ethernet and up to CALY_VLAN_MAX_DEPTH VLAN tags.
 *
 * Tags are ALWAYS parsed, regardless of CALY_F_VLAN_INSPECT: without walking
 * them there is no L3 header to find at all, so refusing to parse would turn
 * every tagged frame into an unclassifiable packet. The flag governs policy
 * decisions the caller makes about VLANs, not whether we can see through one.
 *
 * Hardware VLAN offload strips the tag on some drivers before XDP runs, and
 * struct xdp_md has no vlan_tci field on any kernel, so what is in the frame
 * is the only truth available (see CALY_HAVE_XDP_VLAN_META).
 * ------------------------------------------------------------------------- */

CALY_INLINE int caly_eth_proto_is_vlan(__u16 proto_host)
{
	return proto_host == CALY_ETH_P_8021Q  ||
	       proto_host == CALY_ETH_P_8021AD ||
	       proto_host == CALY_ETH_P_QINQ1  ||
	       proto_host == CALY_ETH_P_QINQ2  ||
	       proto_host == CALY_ETH_P_QINQ3;
}

/*
 * On success *proto_host holds the first non-VLAN ethertype in HOST order and
 * *vlan_depth the number of tags consumed. *eth_out, when non-NULL, receives
 * the Ethernet header pointer - the SYN proxy needs it to swap MAC addresses.
 *
 * max_vlan is the operator's per-config limit (fw_config.vlan_max_depth); it
 * may only LOWER the effective bound, never raise it above the compile-time
 * constant CALY_VLAN_MAX_DEPTH that the loop is unrolled against. A frame that
 * still carries a tag after max_vlan have been consumed is rejected with
 * CALY_ERR_VLAN_DEPTH - the operator asked us not to look deeper.
 */
CALY_INLINE int caly_parse_eth(struct caly_cursor *c,
			       struct caly_ethhdr **eth_out,
			       __u16 *proto_host, __u32 *vlan_depth,
			       __u32 max_vlan)
{
	struct caly_ethhdr *eth;
	__u16 proto;
	__u32 depth = 0;
	unsigned int i;

	if (max_vlan > CALY_VLAN_MAX_DEPTH)
		max_vlan = CALY_VLAN_MAX_DEPTH;

	eth = caly_pull(c, sizeof(*eth));
	if (!eth)
		return CALY_ERR_ETH_TRUNC;

	proto = caly_ntohs(eth->proto);

	CALY_UNROLL
	for (i = 0; i < CALY_VLAN_MAX_DEPTH; i++) {
		struct caly_vlanhdr *vh;

		if (i >= max_vlan)
			break;
		if (!caly_eth_proto_is_vlan(proto))
			break;

		vh = caly_pull(c, sizeof(*vh));
		if (!vh)
			return CALY_ERR_VLAN_TRUNC;

		proto = caly_ntohs(vh->proto);
		depth++;
	}

	/* Still tagged after the (possibly operator-lowered) walk: more tags
	 * than we are willing to follow. Either a misconfiguration or a
	 * deliberate attempt to hide L3 behind a tag stack. */
	if (caly_eth_proto_is_vlan(proto))
		return CALY_ERR_VLAN_DEPTH;

	if (eth_out)
		*eth_out = eth;
	if (proto_host)
		*proto_host = proto;
	if (vlan_depth)
		*vlan_depth = depth;
	return CALY_OK;
}

/* -------------------------------------------------------------------------
 * Layer 3: IPv4.
 *
 * Validates, in this order: presence of the fixed header, version, ihl >= 5,
 * tot_len >= ihl*4, tot_len within the actual frame, and the presence of the
 * option bytes when ihl > 5. Only then are the addresses trusted.
 *
 * `frame_left` is how many bytes remain from the START of this IPv4 header, so
 * that the tot_len cross-check works identically for an outer header and for
 * a tunnelled inner one.
 * ------------------------------------------------------------------------- */

struct caly_ip4_info {
	__u32 saddr;              /* network order */
	__u32 daddr;              /* network order */
	__u32 hdr_bytes;          /* ihl * 4 */
	__u32 payload_len;        /* tot_len - hdr_bytes */
	__u32 frag_off;           /* 8-byte units, host order */
	__u8  protocol;
	__u8  ttl;
	__u8  more_frags;
	__u8  dont_frag;
};

CALY_INLINE int caly_parse_ipv4(struct caly_cursor *c, __u64 cfg_flags,
				struct caly_ip4_info *out)
{
	struct caly_iphdr *ip;
	__u32 ihl_bytes, tot_len, optlen, avail_at_l3;
	__u16 frag_field;

	avail_at_l3 = caly_avail(c);

	ip = caly_pull(c, sizeof(*ip));
	if (!ip)
		return CALY_ERR_IP4_TRUNC;

	if ((ip->version_ihl >> 4) != 4u)
		return CALY_ERR_L3_UNKNOWN;

	ihl_bytes = ((__u32)(ip->version_ihl & 0x0Fu)) * 4u;
	if (ihl_bytes < 20u)
		return CALY_ERR_IP4_IHL;

	tot_len = (__u32)caly_ntohs(ip->tot_len);
	if (tot_len < ihl_bytes)
		return CALY_ERR_IP4_TOTLEN;

	/* tot_len may be SHORTER than the frame (Ethernet pads runts to 60
	 * bytes, which is legitimate); it may never be LONGER. */
	if (tot_len > avail_at_l3)
		return CALY_ERR_IP4_TOTLEN;

	if (ihl_bytes > 20u) {
		if (cfg_flags & CALY_F_DROP_IP4_OPTIONS)
			return CALY_ERR_IP4_OPTIONS;

		optlen = ihl_bytes - 20u;
		if (optlen > 40u)               /* ihl <= 15 by construction */
			return CALY_ERR_IP4_IHL;
		if (!caly_pull(c, optlen))
			return CALY_ERR_IP4_TRUNC;
	}

	frag_field = caly_ntohs(ip->frag_off);

	out->saddr       = ip->saddr;
	out->daddr       = ip->daddr;
	out->hdr_bytes   = ihl_bytes;
	out->payload_len = tot_len - ihl_bytes;
	out->frag_off    = (__u32)(frag_field & CALY_IP4_FRAG_MASK);
	out->protocol    = ip->protocol;
	out->ttl         = ip->ttl;
	out->more_frags  = (frag_field & CALY_IP4_FRAG_MF) ? 1u : 0u;
	out->dont_frag   = (frag_field & CALY_IP4_FRAG_DF) ? 1u : 0u;
	return CALY_OK;
}

/* -------------------------------------------------------------------------
 * Layer 3: IPv6 and the extension header chain.
 * ------------------------------------------------------------------------- */

struct caly_ip6_info {
	__u32 saddr[4];           /* network order */
	__u32 daddr[4];           /* network order */
	__u32 payload_len;        /* from the header; 0 means jumbogram */
	__u32 ext_bytes;          /* total extension header bytes walked */
	__u32 frag_off;           /* 8-byte units, host order */
	__u8  nexthdr;            /* final upper-layer protocol */
	__u8  hop_limit;
	__u8  more_frags;
	__u8  ext_count;
};

CALY_INLINE int caly_parse_ipv6(struct caly_cursor *c,
				struct caly_ip6_info *out)
{
	struct caly_ipv6hdr *ip6;
	__u32 avail_at_l3, plen;
	unsigned int i;

	avail_at_l3 = caly_avail(c);

	ip6 = caly_pull(c, sizeof(*ip6));
	if (!ip6)
		return CALY_ERR_IP6_TRUNC;

	if ((caly_ntohl(ip6->ver_tc_fl) >> 28) != 6u)
		return CALY_ERR_L3_UNKNOWN;

	plen = (__u32)caly_ntohs(ip6->payload_len);

	/* payload_len == 0 is a jumbogram (RFC 2675) or an unset length from a
	 * segmentation-offload path. Treat the rest of the frame as the
	 * payload rather than refusing: dropping every GSO'd local packet
	 * would be a self-inflicted outage. */
	if (plen != 0 && plen + sizeof(*ip6) > avail_at_l3)
		return CALY_ERR_IP6_TRUNC;

	CALY_UNROLL
	for (i = 0; i < 4u; i++) {
		out->saddr[i] = ip6->saddr[i];
		out->daddr[i] = ip6->daddr[i];
	}
	out->payload_len = plen;
	out->ext_bytes   = 0;
	out->frag_off    = 0;
	out->nexthdr     = ip6->nexthdr;
	out->hop_limit   = ip6->hop_limit;
	out->more_frags  = 0;
	out->ext_count   = 0;
	return CALY_OK;
}

/*
 * Walk up to CALY_IP6_EXT_MAX extension headers.
 *
 * Handles HOPOPTS, ROUTING, DSTOPTS, FRAGMENT, AH and MH. Stops at ESP
 * (CALY_ERR_ENCRYPTED) and at NONE (CALY_ERR_NO_NEXT) - both are "well formed,
 * nothing more to see", NOT drops. Routing header type 0 is reported
 * separately because RFC 5095 deprecated it precisely because it is an
 * amplification primitive.
 *
 * `ext_max` may lower the bound but the loop is always compiled against the
 * constant, so no configuration value can make the verifier's job unbounded.
 */
CALY_INLINE int caly_skip_ip6_exts(struct caly_cursor *c, __u64 cfg_flags,
				   __u32 ext_max, struct caly_ip6_info *info)
{
	__u8 nh = info->nexthdr;
	__u32 walked = 0;
	unsigned int i;

	if (ext_max > CALY_IP6_EXT_MAX)
		ext_max = CALY_IP6_EXT_MAX;

	CALY_UNROLL
	for (i = 0; i < CALY_IP6_EXT_MAX; i++) {
		__u32 hlen;

		if (i >= ext_max)
			break;

		switch (nh) {
		case CALY_IPPROTO_HOPOPTS:
		case CALY_IPPROTO_DSTOPTS:
		case CALY_IPPROTO_MH: {
			struct caly_ip6_ext *ext = caly_peek(c, sizeof(*ext));

			if (!ext)
				return CALY_ERR_IP6_EXT_TRUNC;

			hlen = ((__u32)ext->hdrlen + 1u) * 8u;
			if (hlen < 8u || hlen > 2048u)
				return CALY_ERR_IP6_EXT_TRUNC;
			nh = ext->nexthdr;
			if (!caly_pull(c, hlen))
				return CALY_ERR_IP6_EXT_TRUNC;
			break;
		}
		case CALY_IPPROTO_ROUTING: {
			struct caly_ip6_rt *rt = caly_peek(c, sizeof(*rt));

			if (!rt)
				return CALY_ERR_IP6_EXT_TRUNC;

			/* RFC 5095: type 0 is deprecated. It lets a single
			 * packet be bounced between two hosts many times over,
			 * which is a traffic amplifier, so it is refused
			 * whenever the operator has not opted out. */
			if (rt->type == 0 && (cfg_flags & CALY_F_DROP_RH0))
				return CALY_ERR_IP6_RH0;

			hlen = ((__u32)rt->hdrlen + 1u) * 8u;
			if (hlen < 8u || hlen > 2048u)
				return CALY_ERR_IP6_EXT_TRUNC;
			nh = rt->nexthdr;
			if (!caly_pull(c, hlen))
				return CALY_ERR_IP6_EXT_TRUNC;
			break;
		}
		case CALY_IPPROTO_FRAGMENT: {
			struct caly_ip6_frag *fh = caly_peek(c, sizeof(*fh));
			__u16 fo;

			if (!fh)
				return CALY_ERR_IP6_EXT_TRUNC;

			fo = caly_ntohs(fh->frag_off);
			info->frag_off   = (__u32)(fo >> CALY_IP6_FRAG_SHIFT);
			info->more_frags = (fo & CALY_IP6_FRAG_MF) ? 1u : 0u;
			nh = fh->nexthdr;

			/* Always exactly 8 bytes; the hdrlen byte is reserved
			 * and must not be used to size it. */
			if (!caly_pull(c, sizeof(*fh)))
				return CALY_ERR_IP6_EXT_TRUNC;
			hlen = sizeof(*fh);
			break;
		}
		case CALY_IPPROTO_AH: {
			struct caly_ip6_auth *ah = caly_peek(c, sizeof(*ah));

			if (!ah)
				return CALY_ERR_IP6_EXT_TRUNC;

			/* AH length is in 4-byte units MINUS 2, unlike every
			 * other extension header. Getting this wrong lands the
			 * cursor 8 bytes off and misparses the whole L4. */
			hlen = ((__u32)ah->hdrlen + 2u) * 4u;
			if (hlen < 8u || hlen > 1024u)
				return CALY_ERR_IP6_EXT_TRUNC;
			nh = ah->nexthdr;
			if (!caly_pull(c, hlen))
				return CALY_ERR_IP6_EXT_TRUNC;
			break;
		}
		case CALY_IPPROTO_ESP:
			info->nexthdr = nh;
			info->ext_bytes = walked;
			info->ext_count = (__u8)i;
			return CALY_ERR_ENCRYPTED;
		case CALY_IPPROTO_NONE:
			info->nexthdr = nh;
			info->ext_bytes = walked;
			info->ext_count = (__u8)i;
			return CALY_ERR_NO_NEXT;
		default:
			/* Upper-layer protocol reached. */
			info->nexthdr = nh;
			info->ext_bytes = walked;
			info->ext_count = (__u8)i;
			return CALY_OK;
		}

		walked += hlen;
		info->ext_count = (__u8)(i + 1u);
	}

	/* Fell out of the constant-bounded loop while still in the chain. */
	info->nexthdr = nh;
	info->ext_bytes = walked;

	switch (nh) {
	case CALY_IPPROTO_HOPOPTS:
	case CALY_IPPROTO_DSTOPTS:
	case CALY_IPPROTO_ROUTING:
	case CALY_IPPROTO_FRAGMENT:
	case CALY_IPPROTO_AH:
	case CALY_IPPROTO_MH:
		return CALY_ERR_IP6_EXT_DEPTH;
	case CALY_IPPROTO_ESP:
		return CALY_ERR_ENCRYPTED;
	case CALY_IPPROTO_NONE:
		return CALY_ERR_NO_NEXT;
	default:
		return CALY_OK;
	}
}

/* -------------------------------------------------------------------------
 * Layer 4: TCP, UDP, ICMP, ICMPv6.
 *
 * Each returns the ports (network order) it read, and TCP also returns the
 * flag byte and validates the data offset. A non-first fragment has no L4
 * header at all; the caller detects that from frag_off and does not call
 * these - but they still bounds-check, so a lie about frag_off cannot cause
 * an over-read.
 * ------------------------------------------------------------------------- */

struct caly_l4_info {
	__u16 sport;              /* network order (ICMP: type/code packed)  */
	__u16 dport;              /* network order                           */
	__u32 hdr_bytes;          /* L4 header length                        */
	__u8  tcp_flags;          /* 0 for non-TCP                           */
	__u8  icmp_type;
	__u8  icmp_code;
	__u8  pad;
};

CALY_INLINE int caly_parse_tcp(struct caly_cursor *c, __u32 min_doff,
			       struct caly_l4_info *out)
{
	struct caly_tcphdr *th;
	__u32 doff_bytes, optlen;

	th = caly_pull(c, sizeof(*th));
	if (!th)
		return CALY_ERR_L4_TRUNC;

	/* Populate the ports and flags FIRST, so every subsequent error path
	 * surfaces the crafted values to the caller (which puts them in the
	 * event) instead of leaving *out uninitialised - a read of which the
	 * verifier would reject and which would leak stack into an event. */
	out->sport     = th->source;
	out->dport     = th->dest;
	out->tcp_flags = th->flags;
	out->icmp_type = 0;
	out->icmp_code = 0;

	doff_bytes = ((__u32)(th->doff_res >> 4)) * 4u;
	out->hdr_bytes = doff_bytes;

	if (min_doff < 5u || min_doff > 15u)
		min_doff = 5u;
	if (doff_bytes < min_doff * 4u)
		return CALY_ERR_TCP_DOFF;

	/* Ports of zero are illegal and are a fingerprint of crafted scan
	 * traffic; the caller decides the disposition, we only surface it. */
	if (th->source == 0 || th->dest == 0)
		return CALY_ERR_L4_PORT_ZERO;

	if (doff_bytes > sizeof(*th)) {
		optlen = doff_bytes - sizeof(*th);
		if (optlen > 40u)               /* doff <= 15 by construction */
			return CALY_ERR_TCP_DOFF;
		if (!caly_pull(c, optlen))
			return CALY_ERR_L4_TRUNC;
	}

	return CALY_OK;
}

CALY_INLINE int caly_parse_udp(struct caly_cursor *c, struct caly_l4_info *out)
{
	struct caly_udphdr *uh;

	uh = caly_pull(c, sizeof(*uh));
	if (!uh)
		return CALY_ERR_L4_TRUNC;

	out->sport     = uh->source;
	out->dport     = uh->dest;
	out->hdr_bytes = sizeof(*uh);
	out->tcp_flags = 0;
	out->icmp_type = 0;
	out->icmp_code = 0;

	if (uh->source == 0 || uh->dest == 0)
		return CALY_ERR_L4_PORT_ZERO;

	return CALY_OK;
}

/*
 * ICMP (v4 or v6): read the 8-byte common header. type/code are packed into
 * out->sport via CALY_PKT_ICMP_PACK so a single field carries them, but they
 * are ALSO returned in icmp_type/icmp_code so the caller does not have to
 * unpack. dport is left zero: an ICMP message has no ports.
 */
CALY_INLINE int caly_parse_icmp(struct caly_cursor *c, struct caly_l4_info *out)
{
	struct caly_icmphdr *ih;

	ih = caly_pull(c, sizeof(*ih));
	if (!ih)
		return CALY_ERR_L4_TRUNC;

	out->sport     = (__u16)CALY_PKT_ICMP_PACK(ih->type, ih->code);
	out->dport     = 0;
	out->hdr_bytes = sizeof(*ih);
	out->tcp_flags = 0;
	out->icmp_type = ih->type;
	out->icmp_code = ih->code;
	return CALY_OK;
}

/* -------------------------------------------------------------------------
 * One level of tunnel decapsulation: IPIP, IP6IP6/6in4, and GRE.
 *
 * The point is INSPECTION, not decapsulation: we look through exactly one
 * layer so that an attack tunnelled inside a GRE or 6in4 wrapper is scored on
 * its real inner addresses and ports, and then stop. CALY_TUNNEL_MAX_DEPTH is
 * 1 and the loop is compiled against it; nesting beyond that is refused rather
 * than followed, because unbounded decapsulation is itself a DoS vector.
 *
 * Returns the inner L3 protocol family via *inner_is_v6, or a negative code.
 * On CALY_OK the cursor sits at the inner L3 header, ready for
 * caly_parse_ipv4/ipv6 to run again.
 * ------------------------------------------------------------------------- */

CALY_INLINE int caly_parse_gre(struct caly_cursor *c, __u16 *inner_eth_host)
{
	struct caly_grehdr *gre;
	__u16 flags, ver, inner;
	__u32 optbytes = 0;

	gre = caly_pull(c, sizeof(*gre));
	if (!gre)
		return CALY_ERR_TUNNEL_TRUNC;

	flags = caly_ntohs(gre->flags);
	ver   = flags & CALY_GRE_F_VERSION;

	/* Only RFC 2784/2890 GRE version 0. Version 1 is PPTP and carries no
	 * inspectable inner IP header; the reserved bits and the routing bit
	 * must be zero. Anything else we refuse to parse rather than guess. */
	if (ver != 0)
		return CALY_ERR_GRE_MALFORMED;
	if (flags & (CALY_GRE_F_ROUTING | CALY_GRE_F_SSR | CALY_GRE_F_RESERVED0))
		return CALY_ERR_GRE_MALFORMED;

	inner = caly_ntohs(gre->proto);

	/* Optional fields, in their fixed order. Each is bounds-checked by the
	 * caly_pull below; the arithmetic here only sizes them. */
	if (flags & CALY_GRE_F_CSUM)
		optbytes += 4u;                 /* checksum + reserved1 */
	if (flags & CALY_GRE_F_KEY)
		optbytes += 4u;
	if (flags & CALY_GRE_F_SEQ)
		optbytes += 4u;

	if (optbytes > 12u)
		return CALY_ERR_GRE_MALFORMED;
	if (optbytes && !caly_pull(c, optbytes))
		return CALY_ERR_TUNNEL_TRUNC;

	if (inner_eth_host)
		*inner_eth_host = inner;
	return CALY_OK;
}

/*
 * Decap-inspect dispatcher. `outer_proto` is the outer L4/next-header value
 * (IPPROTO_IPIP, IPPROTO_IPV6, or IPPROTO_GRE). On success *inner_is_v6 tells
 * the caller which L3 parser to run next; *tunnel_depth is incremented.
 */
CALY_INLINE int caly_tunnel_inspect(struct caly_cursor *c, __u8 outer_proto,
				    __u32 *tunnel_depth, int *inner_is_v6)
{
	__u16 inner_eth;

	if (*tunnel_depth >= CALY_TUNNEL_MAX_DEPTH)
		return CALY_ERR_TUNNEL_DEPTH;

	switch (outer_proto) {
	case CALY_IPPROTO_IPIP:
		*inner_is_v6 = 0;
		break;
	case CALY_IPPROTO_IPV6:
		*inner_is_v6 = 1;
		break;
	case CALY_IPPROTO_GRE: {
		int err = caly_parse_gre(c, &inner_eth);

		if (err != CALY_OK)
			return err;

		if (inner_eth == CALY_ETH_P_IP)
			*inner_is_v6 = 0;
		else if (inner_eth == CALY_ETH_P_IPV6)
			*inner_is_v6 = 1;
		else if (inner_eth == CALY_ETH_P_TEB) {
			/* Transparent ethernet bridging: an inner Ethernet
			 * frame follows. Peel one Ethernet header (plus VLAN
			 * tags) and re-dispatch on its ethertype. */
			struct caly_ethhdr *ieth;
			__u16 iproto;
			__u32 ivlan;
			int e2 = caly_parse_eth(c, &ieth, &iproto, &ivlan,
						CALY_VLAN_MAX_DEPTH);

			if (e2 != CALY_OK)
				return e2;
			if (iproto == CALY_ETH_P_IP)
				*inner_is_v6 = 0;
			else if (iproto == CALY_ETH_P_IPV6)
				*inner_is_v6 = 1;
			else
				return CALY_ERR_TUNNEL_PROTO;
		} else
			return CALY_ERR_TUNNEL_PROTO;
		break;
	}
	default:
		return CALY_ERR_TUNNEL_PROTO;
	}

	(*tunnel_depth)++;
	return CALY_OK;
}

CALY_INLINE int caly_proto_is_tunnel(__u8 proto)
{
	return proto == CALY_IPPROTO_IPIP ||
	       proto == CALY_IPPROTO_IPV6 ||
	       proto == CALY_IPPROTO_GRE;
}

/* -------------------------------------------------------------------------
 * conn_key construction.
 *
 * BOTH helpers __builtin_memset the whole key first. This is not optional:
 * BPF hash lookups compare raw bytes including pad[2], and IPv4 must leave
 * saddr/daddr words 1..3 zero. Skipping the memset silently turns every
 * conntrack lookup into a miss. Orientation is ALWAYS ingress-relative:
 * saddr/sport is the remote peer, daddr/dport is us. The tc egress program
 * swaps before inserting an outbound flow.
 * ------------------------------------------------------------------------- */

CALY_INLINE void caly_conn_key_v4(struct conn_key *k, __u32 saddr_net,
				  __u32 daddr_net, __u16 sport_net,
				  __u16 dport_net, __u8 proto)
{
	__builtin_memset(k, 0, sizeof(*k));
	k->saddr[0] = saddr_net;
	k->daddr[0] = daddr_net;
	k->sport    = sport_net;
	k->dport    = dport_net;
	k->proto    = proto;
	k->family   = CALY_AF_INET;
}

CALY_INLINE void caly_conn_key_v6(struct conn_key *k, const __u32 *saddr,
				  const __u32 *daddr, __u16 sport_net,
				  __u16 dport_net, __u8 proto)
{
	unsigned int i;

	__builtin_memset(k, 0, sizeof(*k));
	CALY_UNROLL
	for (i = 0; i < 4u; i++) {
		k->saddr[i] = saddr[i];
		k->daddr[i] = daddr[i];
	}
	k->sport  = sport_net;
	k->dport  = dport_net;
	k->proto  = proto;
	k->family = CALY_AF_INET6;
}

/* Swap a key into egress orientation, for the tc egress program. Copies so
 * the caller's ingress key is left intact. */
CALY_INLINE void caly_conn_key_swap(struct conn_key *dst,
				    const struct conn_key *src)
{
	unsigned int i;

	__builtin_memset(dst, 0, sizeof(*dst));
	CALY_UNROLL
	for (i = 0; i < 4u; i++) {
		dst->saddr[i] = src->daddr[i];
		dst->daddr[i] = src->saddr[i];
	}
	dst->sport  = src->dport;
	dst->dport  = src->sport;
	dst->proto  = src->proto;
	dst->family = src->family;
}

/* -------------------------------------------------------------------------
 * Top-level: parse a whole frame into struct pkt_ctx.
 *
 * This is the single entry point the main XDP program calls. It fills every
 * field of pkt_ctx that later stages read, sets the CALY_PKT_F_* flags, and
 * returns CALY_OK or a negative code. On a benign "no L4" code (ESP, NONE,
 * non-first fragment) it still returns that code but leaves the L3 fields
 * populated, so the caller can apply reputation and bogon checks to a packet
 * whose ports it cannot see.
 *
 * `data`/`data_end` are ctx->data/ctx->data_end. `ingress_ifindex` and the
 * WAN flag come from the caller's iface lookup. `now_ns` is stamped in so the
 * value is identical everywhere downstream.
 * ------------------------------------------------------------------------- */

CALY_INLINE void caly_pkt_ctx_reset(struct pkt_ctx *pkt, void *data,
				    void *data_end, __u32 ifindex, __u64 now_ns)
{
	__builtin_memset(pkt, 0, sizeof(*pkt));
	pkt->ts_ns   = now_ns;
	pkt->ifindex = ifindex;
	pkt->pkt_len = (__u32)((__u8 *)data_end - (__u8 *)data);
}

/* Fold an IPv4 32-bit address into the four-word pkt_ctx address slot. */
CALY_INLINE void caly_pkt_set_v4_addrs(struct pkt_ctx *pkt, __u32 saddr_net,
				       __u32 daddr_net)
{
	pkt->saddr[0] = saddr_net;
	pkt->saddr[1] = 0;
	pkt->saddr[2] = 0;
	pkt->saddr[3] = 0;
	pkt->daddr[0] = daddr_net;
	pkt->daddr[1] = 0;
	pkt->daddr[2] = 0;
	pkt->daddr[3] = 0;
}

CALY_INLINE void caly_pkt_set_v6_addrs(struct pkt_ctx *pkt, const __u32 *saddr,
				       const __u32 *daddr)
{
	unsigned int i;

	CALY_UNROLL
	for (i = 0; i < 4u; i++) {
		pkt->saddr[i] = saddr[i];
		pkt->daddr[i] = daddr[i];
	}
}

/* Dispatch the final L4 header into pkt fields. Shared by the v4 and v6 tails
 * so the two protocols cannot drift. `frag_no_l4` is set when the packet is a
 * non-first fragment (v4 frag_off != 0, or v6 frag_off != 0): the L4 header is
 * simply not present and must not be read. */
CALY_INLINE int caly_pkt_fill_l4(struct pkt_ctx *pkt, struct caly_cursor *c,
				 void *data, __u8 proto, __u32 min_doff,
				 int frag_no_l4)
{
	struct caly_l4_info l4;
	int err;
	/* ICMP/ICMPv6 pack type/code into l4.sport (see caly_parse_icmp); that
	 * channel MUST NOT reach pkt->sport/dport, which are documented as
	 * network-order ports (parsing.h lines 186-189). The type/code travel
	 * only in pkt->tcp_flags below. */
	int is_icmp = (proto == CALY_IPPROTO_ICMP || proto == CALY_IPPROTO_ICMPV6);

	/* Zero first: a TRUNC return from a parser leaves *out untouched, and
	 * the error branch below still reads l4.sport/dport to surface them.
	 * Reading uninitialised stack is a verifier rejection, so define it. */
	__builtin_memset(&l4, 0, sizeof(l4));

	pkt->proto   = proto;
	pkt->l4_off  = caly_offset(c, data);

	if (frag_no_l4) {
		/* We know the protocol but not the ports. Leave them zero and
		 * tell the caller this is a legitimate no-L4 situation. */
		pkt->sport = 0;
		pkt->dport = 0;
		pkt->flags |= CALY_PKT_F_L4_TRUNC;
		return CALY_ERR_FRAG_NO_L4;
	}

	switch (proto) {
	case CALY_IPPROTO_TCP:
		err = caly_parse_tcp(c, min_doff, &l4);
		break;
	case CALY_IPPROTO_UDP:
		err = caly_parse_udp(c, &l4);
		break;
	case CALY_IPPROTO_ICMP:
	case CALY_IPPROTO_ICMPV6:
		err = caly_parse_icmp(c, &l4);
		break;
	default:
		return CALY_ERR_L4_UNKNOWN;
	}

	if (err != CALY_OK) {
		if (err == CALY_ERR_L4_TRUNC)
			pkt->flags |= CALY_PKT_F_L4_TRUNC;
		/* Ports may be surfaced even on PORT_ZERO so an event can show
		 * the crafted zero; the caller charges the reason. ICMP has no
		 * ports, so its packed type/code must not leak here. */
		pkt->sport = is_icmp ? 0 : l4.sport;
		pkt->dport = is_icmp ? 0 : l4.dport;
		pkt->tcp_flags = (proto == CALY_IPPROTO_TCP) ? l4.tcp_flags
							     : pkt->tcp_flags;
		return err;
	}

	pkt->sport       = is_icmp ? 0 : l4.sport;
	pkt->dport       = is_icmp ? 0 : l4.dport;
	pkt->payload_off = caly_offset(c, data);

	if (proto == CALY_IPPROTO_TCP)
		pkt->tcp_flags = l4.tcp_flags;
	else if (proto == CALY_IPPROTO_ICMP || proto == CALY_IPPROTO_ICMPV6)
		pkt->tcp_flags = CALY_PKT_ICMP_PACK(l4.icmp_type, l4.icmp_code);

	if (pkt->pkt_len >= pkt->l4_off)
		pkt->l4_len = (__u16)caly_min_u32(pkt->pkt_len - pkt->l4_off,
						  0xFFFFu);
	return CALY_OK;
}

/*
 * Result of parsing ONE L3 header. The L3 parsers below are deliberately NON
 * recursive: they parse a single header, populate pkt's L3 fields, and report
 * what comes next. The tunnel descent is then driven by a constant-bounded
 * LOOP in caly_parse_l3_and_l4, not by the parsers calling each other.
 *
 * Mutual recursion between two __always_inline functions does not compile -
 * clang emits "inlining failed in call to always_inline" because it cannot
 * prove the recursion terminates at compile time. An explicit loop with a
 * CALY_TUNNEL_MAX_DEPTH+1 bound both compiles and gives the verifier the
 * fixed instruction budget it needs.
 */
struct caly_l3_result {
	__u8 proto;        /* final next-header / candidate L4 protocol      */
	__u8 is_tunnel;    /* proto is a tunnel and the packet is not a frag */
	__u8 frag_no_l4;   /* non-first fragment: no L4 header present        */
	__u8 pad;
};

/*
 * Parse one IPv4 L3 header at the cursor. Fills pkt's L3 fields and *r. Does
 * NOT read L4 and does NOT descend tunnels - the caller's loop does that.
 * Returns CALY_OK, or a negative drop / benign code.
 */
CALY_INLINE int caly_parse_l3v4(struct pkt_ctx *pkt, struct caly_cursor *c,
				void *data, const struct fw_config *cfg,
				struct caly_l3_result *r)
{
	struct caly_ip4_info ip;
	__u64 cflags = cfg ? cfg->flags : 0;
	int err;

	r->proto = 0;
	r->is_tunnel = 0;
	r->frag_no_l4 = 0;
	r->pad = 0;

	pkt->family    = CALY_AF_INET;
	pkt->eth_proto = CALY_ETH_P_IP;
	pkt->l3_off    = caly_offset(c, data);

	err = caly_parse_ipv4(c, cflags, &ip);
	if (err != CALY_OK)
		return err;

	caly_pkt_set_v4_addrs(pkt, ip.saddr, ip.daddr);
	pkt->frag_off = ip.frag_off;
	if (ip.frag_off != 0 || ip.more_frags) {
		pkt->flags |= CALY_PKT_F_FRAG;
		if (ip.frag_off == 0)
			pkt->flags |= CALY_PKT_F_FRAG_FIRST;
	}

	r->proto = ip.protocol;
	r->frag_no_l4 = (ip.frag_off != 0) ? 1u : 0u;
	/* Tunnel descent is only sensible on a non-fragmented packet: a
	 * fragmented tunnel cannot be reassembled in XDP. */
	if (ip.frag_off == 0 && !ip.more_frags &&
	    caly_proto_is_tunnel(ip.protocol))
		r->is_tunnel = 1u;
	return CALY_OK;
}

/*
 * Parse one IPv6 L3 header plus its extension chain at the cursor. Fills pkt's
 * L3 fields and *r. Does NOT read L4 and does NOT descend tunnels.
 */
CALY_INLINE int caly_parse_l3v6(struct pkt_ctx *pkt, struct caly_cursor *c,
				void *data, const struct fw_config *cfg,
				struct caly_l3_result *r)
{
	struct caly_ip6_info ip6;
	__u64 cflags = cfg ? cfg->flags : 0;
	__u32 ext_max = cfg ? caly_clamp_ip6_ext(cfg->ip6_ext_max)
			    : CALY_IP6_EXT_MAX;
	int err;

	r->proto = 0;
	r->is_tunnel = 0;
	r->frag_no_l4 = 0;
	r->pad = 0;

	pkt->family    = CALY_AF_INET6;
	pkt->eth_proto = CALY_ETH_P_IPV6;
	pkt->l3_off    = caly_offset(c, data);

	err = caly_parse_ipv6(c, &ip6);
	if (err != CALY_OK)
		return err;

	caly_pkt_set_v6_addrs(pkt, ip6.saddr, ip6.daddr);

	err = caly_skip_ip6_exts(c, cflags, ext_max, &ip6);
	pkt->frag_off = ip6.frag_off;
	if (ip6.frag_off != 0 || ip6.more_frags) {
		pkt->flags |= CALY_PKT_F_FRAG;
		if (ip6.frag_off == 0)
			pkt->flags |= CALY_PKT_F_FRAG_FIRST;
	}

	if (err != CALY_OK) {
		/* RH0 and depth/truncation are real drops; ESP/NONE are
		 * benign and reported with the L3 fields already set. */
		if (err == CALY_ERR_ENCRYPTED || err == CALY_ERR_NO_NEXT)
			pkt->proto = ip6.nexthdr;
		return err;
	}

	r->proto = ip6.nexthdr;
	r->frag_no_l4 = (ip6.frag_off != 0) ? 1u : 0u;
	if (ip6.frag_off == 0 && !ip6.more_frags &&
	    caly_proto_is_tunnel(ip6.nexthdr))
		r->is_tunnel = 1u;
	return CALY_OK;
}

/*
 * Drive L3 parsing, one optional tunnel descent, and L4 parsing with a single
 * constant-bounded loop. `is_v6` selects the first L3 parser; a TEB/6in4/IPIP
 * tunnel switches it for the inner header. The loop runs at most
 * CALY_TUNNEL_MAX_DEPTH + 1 times, so the verifier sees a fixed bound and the
 * compiler needs no recursion.
 */
CALY_INLINE int caly_parse_l3_and_l4(struct pkt_ctx *pkt, struct caly_cursor *c,
				     void *data, const struct fw_config *cfg,
				     int is_v6)
{
	__u64 cflags = cfg ? cfg->flags : 0;
	__u32 min_doff = cfg ? cfg->tcp_min_doff : 5u;
	unsigned int i;
	int err;

	CALY_UNROLL
	for (i = 0; i < CALY_TUNNEL_MAX_DEPTH + 1u; i++) {
		struct caly_l3_result r;

		err = is_v6 ? caly_parse_l3v6(pkt, c, data, cfg, &r)
			    : caly_parse_l3v4(pkt, c, data, cfg, &r);
		if (err != CALY_OK)
			return err;

		if (r.is_tunnel && (cflags & CALY_F_TUNNEL_INSPECT) &&
		    pkt->tunnel_depth < CALY_TUNNEL_MAX_DEPTH) {
			int inner_v6 = 0;
			int terr = caly_tunnel_inspect(c, r.proto,
						       &pkt->tunnel_depth,
						       &inner_v6);

			if (terr == CALY_OK) {
				pkt->flags |= CALY_PKT_F_TUNNELED;
				is_v6 = inner_v6;
				continue;      /* re-parse inner as L3 */
			}
			if (!caly_parse_err_benign(terr))
				return terr;
			/* Benign: fall through and treat the tunnel protocol
			 * as the L4, which yields CALY_ERR_L4_UNKNOWN. */
		}

		return caly_pkt_fill_l4(pkt, c, data, r.proto, min_doff,
					r.frag_no_l4);
	}

	/* Still pointing at a tunnel after the bounded descent: refuse rather
	 * than follow. Unbounded decap is itself a DoS vector. */
	return CALY_ERR_TUNNEL_DEPTH;
}

/*
 * THE entry point. Parses Ethernet -> VLAN -> IPv4/IPv6 -> ext -> tunnel -> L4
 * into `pkt`. Returns CALY_OK, a benign no-L4 code, or a negative drop code.
 *
 * `eth_out` (optional) receives the outer Ethernet header for the SYN proxy's
 * MAC swap. It is set even on some error paths (once the header is parsed) so
 * the caller can still emit a meaningful event.
 */
CALY_INLINE int caly_parse_packet(struct pkt_ctx *pkt, void *data,
				  void *data_end, __u32 ifindex, __u64 now_ns,
				  const struct fw_config *cfg,
				  struct caly_ethhdr **eth_out)
{
	struct caly_cursor c;
	struct caly_ethhdr *eth = 0;
	__u16 proto = 0;
	__u32 vlan_depth = 0;
	__u32 max_vlan = cfg ? caly_clamp_vlan_depth(cfg->vlan_max_depth)
			     : CALY_VLAN_MAX_DEPTH;
	int err;

	caly_pkt_ctx_reset(pkt, data, data_end, ifindex, now_ns);
	caly_cursor_init(&c, data, data_end);

	err = caly_parse_eth(&c, &eth, &proto, &vlan_depth, max_vlan);
	if (eth_out)
		*eth_out = eth;
	if (err != CALY_OK)
		return err;

	pkt->vlan_depth = vlan_depth;
	pkt->eth_proto  = proto;
	if (vlan_depth)
		pkt->flags |= CALY_PKT_F_VLAN;

	switch (proto) {
	case CALY_ETH_P_IP:
		return caly_parse_l3_and_l4(pkt, &c, data, cfg, 0);
	case CALY_ETH_P_IPV6:
		return caly_parse_l3_and_l4(pkt, &c, data, cfg, 1);
	case CALY_ETH_P_ARP:
		/* ARP is not IP; the caller's policy decides pass/drop. Report
		 * a distinct code so it is not confused with a parse failure. */
		pkt->eth_proto = CALY_ETH_P_ARP;
		return CALY_ERR_NO_NEXT;
	default:
		return CALY_ERR_L3_UNKNOWN;
	}
}

/* -------------------------------------------------------------------------
 * Layout assertions for the wire structs. If any trips, a compiler has
 * inserted padding into a header we read at a fixed offset, and every parse
 * downstream is wrong.
 * ------------------------------------------------------------------------- */
CALY_ASSERT(sizeof(struct caly_ethhdr)  == 14, wire_eth_size);
CALY_ASSERT(sizeof(struct caly_vlanhdr) == 4,  wire_vlan_size);
CALY_ASSERT(sizeof(struct caly_iphdr)   == 20, wire_ip4_size);
CALY_ASSERT(sizeof(struct caly_ipv6hdr) == 40, wire_ip6_size);
CALY_ASSERT(sizeof(struct caly_ip6_ext) == 2,  wire_ip6ext_size);
CALY_ASSERT(sizeof(struct caly_ip6_rt)  == 4,  wire_ip6rt_size);
CALY_ASSERT(sizeof(struct caly_ip6_frag) == 8, wire_ip6frag_size);
CALY_ASSERT(sizeof(struct caly_ip6_auth) == 12, wire_ip6auth_size);
CALY_ASSERT(sizeof(struct caly_tcphdr)  == 20, wire_tcp_size);
CALY_ASSERT(sizeof(struct caly_udphdr)  == 8,  wire_udp_size);
CALY_ASSERT(sizeof(struct caly_icmphdr) == 8,  wire_icmp_size);
CALY_ASSERT(sizeof(struct caly_grehdr)  == 4,  wire_gre_size);

#endif /* __CALY_ANTI_PARSING_H */
