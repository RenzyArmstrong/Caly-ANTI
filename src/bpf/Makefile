# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Caly Anti - src/bpf/Makefile
#
# Builds the single BPF object the loader opens: calyanti.bpf.o.
#
# The dataplane lives in four translation units - xdp_firewall.bpf.c,
# xdp_synproxy.bpf.c, tc_ingress.bpf.c and tc_egress.bpf.c - each of which
# includes maps.h and defines exactly one entry program plus the shared "Dual
# BSD/GPL" license string. They are compiled to partial BPF objects and then
# BPF-static-linked into ONE object with `bpftool gen object`, because
# src/user/loader.c opens a single file (CALY_BPF_OBJ_NAME = "calyanti.bpf.o")
# and resolves every program out of it by name. This is exactly the model
# maps.h documents: "separate objects ... linked", agreeing on map layout
# because they share maps.h.
#
# FEATURE PROBES
#   compat.h names every optional kernel capability with a CALY_HAVE_* macro and
#   states that "every macro may be overridden from the Makefile with
#   -DCALY_HAVE_x=0/1". Two of those cannot be decided reliably by the
#   preprocessor alone, so this Makefile probes the real toolchain and emits a
#   generated header ($(BPF_FEATURES)) that is force-included ahead of every
#   compile:
#
#     CALY_HAVE_SYNCOOKIE_RAW  1 iff the installed bpf_helper_defs.h actually
#                              declares bpf_tcp_raw_gen_syncookie_ipv4(). Without
#                              this probe compat.h defaults to 1 on clang >= 12,
#                              which fails to COMPILE against an old libbpf whose
#                              headers predate the helper.
#     CALY_HAVE_RINGBUF        1 iff vmlinux.h carries BPF_MAP_TYPE_RINGBUF.
#
#   compat.h derives CALY_HAVE_MAP_AUTOCREATE from CALY_HAVE_RINGBUF on the BPF
#   side; the userspace value (a libbpf 0.8 API question) is probed by the
#   top-level Makefile. CALY_SPLIT_IPV6 is a plain switch, defaulted off, passed
#   straight through.
#
# This Makefile is standalone (`make -C src/bpf`) and is also driven by the
# top-level Makefile, which passes OUTPUT, the toolchain binaries and the
# resolved libbpf include flags.

# --------------------------------------------------------------------------
# Locate ourselves so the script and header paths work under `make -C`.
# --------------------------------------------------------------------------
BPFDIR  := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
TOPDIR  := $(abspath $(BPFDIR)/../..)
SCRIPTS := $(TOPDIR)/scripts

# --------------------------------------------------------------------------
# Toolchain. Overridable; the top-level Makefile and scripts/install.sh pass
# the versioned binaries they discovered (e.g. CLANG=clang-12).
# --------------------------------------------------------------------------
CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= bpftool
PKG_CONFIG ?= pkg-config

# libbpf headers, for <bpf/bpf_helpers.h> and <bpf/bpf_endian.h>. When invoked
# standalone we ask pkg-config; the top-level Makefile overrides this on the
# command line (including the bundled-libbpf include directory).
LIBBPF_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)

# --------------------------------------------------------------------------
# Architecture. SRCARCH matches the kernel's arch/<name> convention and feeds
# both -D__TARGET_ARCH_<srcarch> and gen-vmlinux.sh's bundled-header fallback.
# --------------------------------------------------------------------------
ARCH ?= $(shell uname -m 2>/dev/null)
SRCARCH := $(ARCH)
SRCARCH := $(patsubst x86_64,x86,$(SRCARCH))
SRCARCH := $(patsubst amd64,x86,$(SRCARCH))
SRCARCH := $(patsubst i386,x86,$(SRCARCH))
SRCARCH := $(patsubst i686,x86,$(SRCARCH))
SRCARCH := $(patsubst aarch64,arm64,$(SRCARCH))
SRCARCH := $(patsubst armv7l,arm,$(SRCARCH))
SRCARCH := $(patsubst ppc64le,powerpc,$(SRCARCH))
SRCARCH := $(patsubst s390x,s390,$(SRCARCH))
SRCARCH := $(patsubst riscv64,riscv,$(SRCARCH))

# --------------------------------------------------------------------------
# Where things land. OUTPUT defaults to this directory for standalone builds;
# the top-level Makefile passes an absolute build/ path. Partial objects and
# the generated feature header go in a subdirectory that scripts/install.sh
# does NOT scan for *.bpf.o, so only the linked object is ever installed.
# --------------------------------------------------------------------------
OUTPUT ?= $(BPFDIR)
OBJDIR := $(OUTPUT)/bpfobj

VMLINUX_H  ?= $(BPFDIR)/vmlinux.h
SPLIT_IPV6 ?= 0

# BPF ISA level. v2 (kernel 4.14+) is the safe floor for the 4.18 RHEL8 kernel.
# v3 (jmp32 / ALU32, needs 5.1+) produces tighter bytecode AND lets the verifier
# track 32-bit value ranges cheaply - which dramatically lowers the state-space
# complexity that pushes big programs past the verifier's budget (-E2BIG). We
# auto-select v3 on kernel 5.4+ (where it is well supported) and fall back to v2
# on older kernels. Override explicitly with BPF_CPU=v2 or BPF_CPU=v3.
BPF_CPU ?= $(shell k=`uname -r 2>/dev/null`; k=$${k%%-*}; maj=$${k%%.*}; rest=$${k#*.}; min=$${rest%%.*}; case "$$maj" in ''|*[!0-9]*) maj=0;; esac; case "$$min" in ''|*[!0-9]*) min=0;; esac; if [ "$$maj" -gt 5 ]; then echo v3; elif [ "$$maj" -eq 5 ] && [ "$$min" -ge 4 ]; then echo v3; else echo v2; fi)

# calyanti.bpf.c #includes the four program sources so the shared maps (maps.h)
# are defined exactly once, in a single translation unit. The individual
# program files are dependencies, not separately-compiled objects.
BPF_MAIN     := calyanti.bpf.c
BPF_PROGS    := xdp_firewall.bpf.c xdp_synproxy.bpf.c tc_ingress.bpf.c tc_egress.bpf.c
BPF_OBJ      := $(OUTPUT)/calyanti.bpf.o
BPF_FEATURES := $(OBJDIR)/caly_bpf_features.h

# Base flags. These are used both for the real compiles and for the feature
# probes, so they must NOT force-include $(BPF_FEATURES) (that would be
# circular); the real compiles add the -include below.
BPF_CFLAGS := -g -O2 -target bpf -mcpu=$(BPF_CPU) \
	-Wall -Wno-unused-function -Wno-compare-distinct-pointer-types \
	-Wno-address-of-packed-member -Wno-gnu-variable-sized-type-not-at-end \
	-Wno-pass-failed \
	-fno-stack-protector \
	-D__TARGET_ARCH_$(SRCARCH) -DCALY_SPLIT_IPV6=$(SPLIT_IPV6) \
	-I$(BPFDIR) -I$(dir $(VMLINUX_H)) $(LIBBPF_CFLAGS)

V ?= 0
ifeq ($(V),0)
Q := @
else
Q :=
endif

.PHONY: all bpf clean
all: bpf
bpf: $(BPF_OBJ)

# --------------------------------------------------------------------------
# vmlinux.h from the running kernel's BTF. gen-vmlinux.sh keeps an existing,
# valid header untouched, so a user-supplied VMLINUX_H is never clobbered and a
# rebuild does not re-dump BTF needlessly. Exit 2 (no BTF anywhere) is fatal
# here on purpose - a caller that wants graceful degradation to nftables uses
# scripts/install.sh, which runs this script itself and drops down the ladder.
# --------------------------------------------------------------------------
$(VMLINUX_H):
	$(Q)echo '  GEN     $@'
	$(Q)/bin/sh $(SCRIPTS)/gen-vmlinux.sh --output '$@' \
		--bpftool '$(BPFTOOL)' --arch '$(SRCARCH)'

# --------------------------------------------------------------------------
# Toolchain feature probes -> generated, force-included header.
# Runs after vmlinux.h exists so the probes can reference kernel types.
# --------------------------------------------------------------------------
$(BPF_FEATURES): $(VMLINUX_H) | $(OBJDIR)
	$(Q)echo '  PROBE   BPF toolchain features'
	$(Q)printf '/* Generated by src/bpf/Makefile - do not edit. */\n' > $@.tmp
	$(Q)printf '#ifndef CALY_BPF_FEATURES_H\n#define CALY_BPF_FEATURES_H\n' >> $@.tmp
	$(Q)printf '#include "vmlinux.h"\n#include <bpf/bpf_helpers.h>\nint _caly_p(struct xdp_md *c){struct iphdr *i=(void *)0;struct tcphdr *t=(void *)0;(void)c;return (int)bpf_tcp_raw_gen_syncookie_ipv4(i,t,0);}\n' > $(OBJDIR)/.probe_syn.c
	$(Q)if $(CLANG) $(BPF_CFLAGS) -c $(OBJDIR)/.probe_syn.c -o /dev/null >/dev/null 2>&1; then \
		printf '#define CALY_HAVE_SYNCOOKIE_RAW 1\n' >> $@.tmp; \
		echo '  PROBE   syncookie helpers: yes'; \
	else \
		printf '#define CALY_HAVE_SYNCOOKIE_RAW 0\n' >> $@.tmp; \
		echo '  PROBE   syncookie helpers: no (SYN proxy compiled out)'; \
	fi
	$(Q)printf '#include "vmlinux.h"\nint _caly_rb = BPF_MAP_TYPE_RINGBUF;\n' > $(OBJDIR)/.probe_rb.c
	$(Q)if $(CLANG) $(BPF_CFLAGS) -c $(OBJDIR)/.probe_rb.c -o /dev/null >/dev/null 2>&1; then \
		printf '#define CALY_HAVE_RINGBUF 1\n' >> $@.tmp; \
		echo '  PROBE   ring buffer: yes'; \
	else \
		printf '#define CALY_HAVE_RINGBUF 0\n' >> $@.tmp; \
		echo '  PROBE   ring buffer: no (events over the perf array)'; \
	fi
	$(Q)printf '#endif /* CALY_BPF_FEATURES_H */\n' >> $@.tmp
	$(Q)rm -f $(OBJDIR)/.probe_syn.c $(OBJDIR)/.probe_rb.c
	$(Q)mv -f $@.tmp $@

# --------------------------------------------------------------------------
# The single object the loader opens. calyanti.bpf.c pulls in all four program
# sources, so one clang compile produces one object with the maps defined once
# - no bpftool link step (which refused to merge the duplicate non-weak map
# symbols the per-file objects each defined). -g keeps BTF for CO-RE; the
# following llvm-strip -g drops DWARF while keeping the .BTF section.
# --------------------------------------------------------------------------
$(BPF_OBJ): $(BPFDIR)/$(BPF_MAIN) $(addprefix $(BPFDIR)/,$(BPF_PROGS)) \
	    $(wildcard $(BPFDIR)/*.h) $(BPF_FEATURES) $(VMLINUX_H) | $(OUTPUT) $(OBJDIR)
	$(Q)echo '  BPF     $(BPF_MAIN) -> $@'
	$(Q)$(CLANG) $(BPF_CFLAGS) -include $(BPF_FEATURES) -c $(BPFDIR)/$(BPF_MAIN) -o $@
	$(Q)$(LLVM_STRIP) -g $@

$(OUTPUT) $(OBJDIR):
	$(Q)mkdir -p $@

clean:
	$(Q)rm -f $(BPF_OBJ)
	$(Q)rm -rf $(OBJDIR)
