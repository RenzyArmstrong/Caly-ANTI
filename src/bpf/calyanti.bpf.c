// SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
/*
 * Caly Anti - unified BPF object.
 *
 * All four dataplane programs are compiled together in ONE translation unit,
 * so the maps they share (maps.h) are defined exactly once. This replaces the
 * older "one object per program, linked with `bpftool gen object`" build: that
 * linker refuses to merge the duplicate non-weak map symbols each object
 * defines ("conflicting non-weak symbol ... caly_config"), and produced a
 * zero-byte, unloadable object.
 *
 * Correctness of this arrangement was checked up front:
 *   - maps.h and every shared header (common.h, compat.h, parsing.h,
 *     ratelimit.h, checksum.h, vmlinux.h) has an include guard, so each is
 *     expanded once here.
 *   - the four programs use distinct file-scope names (caly_/sp_/tci_/tce_
 *     prefixes) with no static-function or struct-name collisions.
 *   - the single "Dual BSD/GPL" license string is emitted once, guarded by
 *     CALY_LICENSE_DEFINED (see each program file).
 *
 * The loader (src/user/loader.c) opens this one object and resolves every
 * program out of it by name: caly_xdp_main, caly_xdp_synproxy, caly_tc_ingress,
 * caly_tc_egress.
 */

#include "xdp_firewall.bpf.c"
#include "xdp_synproxy.bpf.c"
#include "tc_ingress.bpf.c"
#include "tc_egress.bpf.c"
