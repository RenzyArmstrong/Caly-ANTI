// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
/*
 * Caly Anti - unified BPF object.
 *
 * All four dataplane programs are compiled together in ONE translation unit so
 * the maps they share (maps.h) are defined exactly once. This replaces the
 * older "one object per program, linked with `bpftool gen object`" build: that
 * linker refuses to merge the duplicate non-weak map symbols each object
 * defines ("conflicting non-weak symbol ... caly_config") and produced a
 * zero-byte, unloadable object - and is fragile on bleeding-edge toolchains
 * (clang 21 / bpftool 7.5). A single clang compile is robust and needs no link.
 *
 * ONE wrinkle. xdp_firewall.bpf.c is self-contained: it defines its own
 * packet-header structs (caly_ethhdr, caly_iphdr, ...) with a DIFFERENT field
 * layout than the shared parsing.h that the other three programs include. The
 * two cannot coexist under the same names in one translation unit. Since
 * xdp_firewall never includes parsing.h, we rename its versions to xf_* for the
 * span of its inclusion (token substitution, so every use is renamed
 * consistently), then restore the names so xdp_synproxy/tc_* get parsing.h's
 * originals. The five CALY_GRE_F_* flag macros overlap too; they are cleared
 * after xdp_firewall so parsing.h can define its own without a redefinition
 * warning. Verified up front: these 8 structs + 5 macros are the ENTIRE overlap
 * between xdp_firewall.bpf.c and parsing.h - no function names collide.
 *
 * The loader (src/user/loader.c) opens this one object and resolves every
 * program out of it by name: caly_xdp_main, caly_xdp_synproxy, caly_tc_ingress,
 * caly_tc_egress.
 */

/* --- isolate xdp_firewall's private parsing types from parsing.h --- */
#define caly_ethhdr   xf_ethhdr
#define caly_vlanhdr  xf_vlanhdr
#define caly_iphdr    xf_iphdr
#define caly_ip6_ext  xf_ip6_ext
#define caly_tcphdr   xf_tcphdr
#define caly_udphdr   xf_udphdr
#define caly_icmphdr  xf_icmphdr
#define caly_grehdr   xf_grehdr

#include "xdp_firewall.bpf.c"

#undef caly_ethhdr
#undef caly_vlanhdr
#undef caly_iphdr
#undef caly_ip6_ext
#undef caly_tcphdr
#undef caly_udphdr
#undef caly_icmphdr
#undef caly_grehdr
#undef CALY_GRE_F_CSUM
#undef CALY_GRE_F_KEY
#undef CALY_GRE_F_ROUTING
#undef CALY_GRE_F_SEQ
#undef CALY_GRE_F_SSR

/* --- the remaining three programs share parsing.h --- */
#include "xdp_synproxy.bpf.c"
#include "tc_ingress.bpf.c"
#include "tc_egress.bpf.c"
