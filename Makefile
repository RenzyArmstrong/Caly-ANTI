# SPDX-License-Identifier: BSD-2-Clause OR GPL-2.0
#
# Caly Anti - top-level Makefile
#
# The documented build entry point. README.md and docs/INSTALL.md instruct
# `make` then `sudo make install`; scripts/install.sh runs `make -C <root> -j
# CLANG=... BPFTOOL=... LLVM_STRIP=...` and then discovers build/calyd (daemon),
# build/calyctl (CLI) and build/*.bpf.o (the dataplane object).
#
#   make                 vmlinux.h + BPF object + daemon + CLI, all into build/
#   make bpf             just the calyanti.bpf.o dataplane object
#   make daemon          just the calyd loader/daemon
#   make install         install to $(PREFIX)/$(SYSCONFDIR) (DESTDIR-aware)
#   make uninstall       remove what install put down (config/state kept)
#   make clean           remove build/
#   make distclean       clean + drop the generated src/bpf/vmlinux.h
#   make help            list variables and targets
#
# BUILD VARIABLES (documented in docs/INSTALL.md section 3)
#   CLANG=clang-12       BPF compiler (use the versioned binary on old distros)
#   LLVM_STRIP=...       must match CLANG's version
#   BPFTOOL=...          for vmlinux.h generation and BPF static linking
#   CC=cc                userspace C compiler
#   LIBBPF=auto          auto | system | bundled
#   PREFIX=/usr          install prefix
#   SYSCONFDIR=/etc      configuration prefix
#   DESTDIR=             staging root for packaging
#   ARCH=                x86_64 / aarch64 (autodetected from uname -m)
#   VMLINUX_H=path       use a pre-generated vmlinux.h instead of dumping BTF
#   SPLIT_IPV6=0         build the optional split IPv6 program (verifier budget)
#   DEBUG=1              -O1 -g userspace build
#   V=1                  echo the compiler command lines

VERSION := $(shell cat $(CURDIR)/VERSION 2>/dev/null || echo 1.0.0)

# --------------------------------------------------------------------------
# Toolchain
# --------------------------------------------------------------------------
CC         ?= cc
CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= bpftool
PKG_CONFIG ?= pkg-config
INSTALL    ?= install

# --------------------------------------------------------------------------
# Install layout. Matches docs/INSTALL.md section 0 and the paths the loader
# searches (caly_bpf_find_object: $(PREFIX)/lib/calyanti) and the shipped
# systemd unit (ExecStart=/usr/sbin/calyd).
# --------------------------------------------------------------------------
PREFIX      ?= /usr
SYSCONFDIR  ?= /etc
DESTDIR     ?=
SBINDIR     ?= $(PREFIX)/sbin
BINDIR      ?= $(PREFIX)/bin
LIBDIR      ?= $(PREFIX)/lib/calyanti
SCRIPTSDIR  ?= $(LIBDIR)/scripts
NFTDIR      ?= $(LIBDIR)/nftables.d
DATADIR     ?= $(PREFIX)/share
DOCDIR      ?= $(DATADIR)/doc/calyanti
UNITDIR     ?= $(PREFIX)/lib/systemd/system
SYSCTLDIR   ?= $(SYSCONFDIR)/sysctl.d
CONFDIR     ?= $(SYSCONFDIR)/calyanti

# --------------------------------------------------------------------------
# Layout of the build tree
# --------------------------------------------------------------------------
BUILD    := build
BUILD_ABS := $(abspath $(BUILD))
USERDIR  := src/user
BPFSRC   := src/bpf

VMLINUX_H ?= $(BPFSRC)/vmlinux.h
VMLINUX_H_ABS := $(abspath $(VMLINUX_H))

ARCH ?= $(shell uname -m 2>/dev/null)
SPLIT_IPV6 ?= 0

DAEMON   := $(BUILD)/calyd
CLI      := $(BUILD)/calyctl
CLI_SRC  := cli/calyctl
BPF_OBJ  := $(BUILD)/calyanti.bpf.o

USER_SRCS := $(sort $(wildcard $(USERDIR)/*.c))
USER_OBJS := $(patsubst $(USERDIR)/%.c,$(BUILD)/user/%.o,$(USER_SRCS))
USER_DEPS := $(USER_OBJS:.o=.d)

V ?= 0
ifeq ($(V),0)
Q := @
else
Q :=
endif

ifdef DEBUG
OPT := -O1 -g -DDEBUG
else
OPT := -O2
endif

# --------------------------------------------------------------------------
# libbpf resolution. `auto` prefers a system libbpf >= 0.8 (the loader's probe
# APIs floor) and otherwise builds the vendored copy when the submodule is
# present; `system`/`bundled` force the choice. See docs/INSTALL.md section 2.
# --------------------------------------------------------------------------
LIBBPF ?= auto
BUNDLED := third_party/libbpf

PKG_LIBBPF   := $(shell $(PKG_CONFIG) --exists libbpf 2>/dev/null && echo yes)
LIBBPF_GE_08 := $(shell $(PKG_CONFIG) --atleast-version=0.8 libbpf 2>/dev/null && echo yes)

ifeq ($(LIBBPF),auto)
  ifeq ($(LIBBPF_GE_08),yes)
    LIBBPF_MODE := system
  else ifneq ($(wildcard $(BUNDLED)/src/Makefile),)
    LIBBPF_MODE := bundled
  else
    LIBBPF_MODE := system
  endif
else
  LIBBPF_MODE := $(LIBBPF)
endif

ifeq ($(LIBBPF_MODE),bundled)
  ifeq ($(wildcard $(BUNDLED)/src/Makefile),)
    $(error LIBBPF=bundled but $(BUNDLED) is not checked out. Run: \
	git submodule update --init --recursive)
  endif
  LIBBPF_STAGE  := $(BUILD_ABS)/libbpf
  LIBBPF_A      := $(LIBBPF_STAGE)/libbpf.a
  LIBBPF_CFLAGS := -I$(LIBBPF_STAGE)
  LIBBPF_LIBS   := $(LIBBPF_A) -lelf -lz
  LIBBPF_DEP    := $(LIBBPF_A)
else
  ifneq ($(PKG_LIBBPF),yes)
    $(warning pkg-config cannot find libbpf; falling back to -lbpf. Install \
	libbpf-devel/libbpf-dev, or build with LIBBPF=bundled.)
  endif
  LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
  LIBBPF_LIBS   := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null)
  ifeq ($(strip $(LIBBPF_LIBS)),)
    LIBBPF_LIBS := -lbpf -lelf -lz
  endif
  LIBBPF_DEP    :=
endif

# --------------------------------------------------------------------------
# Userspace feature defines that loader.c / events.c / maps.c consult.
#
#  * LIBBPF_MAJOR/MINOR_VERSION: force-defined ONLY when <bpf/libbpf_version.h>
#    is absent (libbpf < 0.6). loader.c includes that header when present and
#    self-defaults to 0 otherwise, so the force-define keeps CALY_LIBBPF_AT_LEAST
#    honest on ancient system libbpf. A bundled libbpf is always modern and
#    ships the header, so no force-define is needed (or wanted - it would
#    redefine the header's value).
#  * CALY_HAVE_MAP_AUTOCREATE: bpf_map__set_autocreate() is libbpf 0.8+. loader.c
#    gates the ringbuf-skip path on it; we pin the answer here so the guess is
#    the toolchain's, not a version heuristic's.
# --------------------------------------------------------------------------
USER_FEATURE_DEFS :=

ifeq ($(LIBBPF_MODE),bundled)
  USER_FEATURE_DEFS += -DCALY_HAVE_MAP_AUTOCREATE=1
else
  HAVE_LIBBPF_VERSION_H := $(shell printf '#include <bpf/libbpf_version.h>\nint _x;\n' \
	| $(CC) $(LIBBPF_CFLAGS) -x c -c -o /dev/null - 2>/dev/null && echo yes)
  ifneq ($(HAVE_LIBBPF_VERSION_H),yes)
    LIBBPF_MODVER := $(shell $(PKG_CONFIG) --modversion libbpf 2>/dev/null)
    LIBBPF_MAJ := $(word 1,$(subst ., ,$(LIBBPF_MODVER)))
    LIBBPF_MIN := $(word 2,$(subst ., ,$(LIBBPF_MODVER)))
    ifneq ($(strip $(LIBBPF_MAJ)),)
      USER_FEATURE_DEFS += -DLIBBPF_MAJOR_VERSION=$(LIBBPF_MAJ) \
	-DLIBBPF_MINOR_VERSION=$(if $(strip $(LIBBPF_MIN)),$(LIBBPF_MIN),0)
    endif
  endif
  HAVE_AUTOCREATE := $(shell printf '#include <bpf/libbpf.h>\nvoid *_p=(void *)bpf_map__set_autocreate;\n' \
	| $(CC) $(LIBBPF_CFLAGS) -x c -c -o /dev/null - 2>/dev/null && echo yes)
  ifeq ($(HAVE_AUTOCREATE),yes)
    USER_FEATURE_DEFS += -DCALY_HAVE_MAP_AUTOCREATE=1
  else
    USER_FEATURE_DEFS += -DCALY_HAVE_MAP_AUTOCREATE=0
  endif
endif

USER_CFLAGS := -std=gnu11 -Wall -Wextra -Wno-unused-parameter $(OPT) \
	-D_GNU_SOURCE -DCALY_USERSPACE=1 -DCALY_VERSION=\"$(VERSION)\" \
	-I$(USERDIR) -I$(BPFSRC) $(LIBBPF_CFLAGS) $(USER_FEATURE_DEFS) $(CFLAGS)
USER_LDLIBS := $(LIBBPF_LIBS) -lpthread $(LDLIBS)

# --------------------------------------------------------------------------
# Targets
# --------------------------------------------------------------------------
.PHONY: all bpf daemon cli install uninstall install-config clean distclean help
.DELETE_ON_ERROR:

all: bpf daemon cli

# BPF object: delegate to src/bpf/Makefile, handing it the resolved toolchain,
# libbpf include flags and output directory. For a bundled libbpf its headers
# must be staged first, hence the order-only-style prerequisite.
bpf: $(LIBBPF_DEP)
	$(Q)$(MAKE) -C $(BPFSRC) bpf \
		OUTPUT='$(BUILD_ABS)' \
		CLANG='$(CLANG)' BPFTOOL='$(BPFTOOL)' LLVM_STRIP='$(LLVM_STRIP)' \
		PKG_CONFIG='$(PKG_CONFIG)' \
		VMLINUX_H='$(VMLINUX_H_ABS)' ARCH='$(ARCH)' \
		SPLIT_IPV6='$(SPLIT_IPV6)' \
		LIBBPF_CFLAGS='$(LIBBPF_CFLAGS)' V='$(V)'

daemon: $(DAEMON)
cli: $(CLI)

$(DAEMON): $(USER_OBJS) | $(BUILD)
	$(Q)echo '  LD      $@'
	$(Q)$(CC) $(USER_OBJS) -o $@ $(LDFLAGS) $(USER_LDLIBS)

$(BUILD)/user/%.o: $(USERDIR)/%.c $(LIBBPF_DEP) | $(BUILD)/user
	$(Q)echo '  CC      $<'
	$(Q)$(CC) $(USER_CFLAGS) -MMD -MP -c $< -o $@

# The CLI is a self-contained Python program; "building" it is staging it into
# build/ under the name scripts/install.sh looks for.
$(CLI): $(CLI_SRC) | $(BUILD)
	$(Q)echo '  GEN     $@'
	$(Q)cp -f $< $@
	$(Q)chmod 0755 $@

# Vendored libbpf: static-only build following the standard libbpf src Makefile
# install contract. Produces $(LIBBPF_A) and stages headers under $(LIBBPF_STAGE)
# so <bpf/bpf_helpers.h> and <bpf/libbpf.h> resolve for both sides of the build.
ifeq ($(LIBBPF_MODE),bundled)
$(LIBBPF_A): | $(BUILD)
	$(Q)echo '  MAKE    bundled libbpf'
	$(Q)$(MAKE) -C $(BUNDLED)/src \
		BUILD_STATIC_ONLY=1 \
		OBJDIR='$(LIBBPF_STAGE)/obj' \
		DESTDIR='$(LIBBPF_STAGE)' \
		PREFIX= LIBDIR= INCLUDEDIR= UAPIDIR= \
		install install_uapi_headers
endif

$(BUILD) $(BUILD)/user:
	$(Q)mkdir -p $@

# --------------------------------------------------------------------------
# Install / uninstall. DESTDIR-aware so distribution packaging can stage.
# --------------------------------------------------------------------------
install: all
	$(Q)echo '  INSTALL binaries and dataplane object'
	$(Q)$(INSTALL) -d '$(DESTDIR)$(SBINDIR)' '$(DESTDIR)$(BINDIR)' \
		'$(DESTDIR)$(LIBDIR)' '$(DESTDIR)$(SCRIPTSDIR)' '$(DESTDIR)$(NFTDIR)' \
		'$(DESTDIR)$(UNITDIR)' '$(DESTDIR)$(SYSCTLDIR)' '$(DESTDIR)$(CONFDIR)' \
		'$(DESTDIR)$(DOCDIR)'
	$(Q)$(INSTALL) -m 0755 '$(DAEMON)' '$(DESTDIR)$(SBINDIR)/calyd'
	$(Q)ln -sf calyd '$(DESTDIR)$(SBINDIR)/calyantid'
	$(Q)$(INSTALL) -m 0755 '$(CLI)' '$(DESTDIR)$(BINDIR)/calyctl'
	$(Q)ln -sf calyctl '$(DESTDIR)$(BINDIR)/calyanti-cli'
	$(Q)$(INSTALL) -m 0644 '$(BPF_OBJ)' '$(DESTDIR)$(LIBDIR)/calyanti.bpf.o'
	$(Q)for s in detect-env.sh deps.sh gen-vmlinux.sh install.sh uninstall.sh build.sh; do \
		[ -f "scripts/$$s" ] && $(INSTALL) -m 0755 "scripts/$$s" \
			"$(DESTDIR)$(SCRIPTSDIR)/$$s" || true; \
	done
	$(Q)[ -f fallback/nftables/calyanti.nft ] && $(INSTALL) -m 0644 \
		fallback/nftables/calyanti.nft '$(DESTDIR)$(NFTDIR)/calyanti.nft' || true
	$(Q)[ -f fallback/nftables/apply.sh ] && $(INSTALL) -m 0755 \
		fallback/nftables/apply.sh '$(DESTDIR)$(NFTDIR)/apply.sh' || true
	$(Q)[ -f systemd/calyanti.service ] && $(INSTALL) -m 0644 \
		systemd/calyanti.service '$(DESTDIR)$(UNITDIR)/calyanti.service' || true
	$(Q)[ -f tuning/99-calyanti-sysctl.conf ] && $(INSTALL) -m 0644 \
		tuning/99-calyanti-sysctl.conf \
		'$(DESTDIR)$(SYSCTLDIR)/99-calyanti-sysctl.conf' || true
	$(Q)[ -f LICENSE ] && $(INSTALL) -m 0644 LICENSE \
		'$(DESTDIR)$(DOCDIR)/LICENSE' || true
	$(Q)$(MAKE) --no-print-directory install-config
	$(Q)echo 'Installed. calyd -> $(SBINDIR)/calyd, object -> $(LIBDIR)/calyanti.bpf.o'

# The sample config is never overwritten: an upgrade must not clobber an
# operator's mgmt_tcp_ports / interface zones. Mirrors scripts/install.sh.
install-config:
	$(Q)if [ -f '$(DESTDIR)$(CONFDIR)/calyanti.conf' ]; then \
		echo '  KEEP    $(DESTDIR)$(CONFDIR)/calyanti.conf (already present)'; \
	elif [ -f config/calyanti.conf ]; then \
		echo '  INSTALL $(DESTDIR)$(CONFDIR)/calyanti.conf'; \
		$(INSTALL) -m 0640 config/calyanti.conf \
			'$(DESTDIR)$(CONFDIR)/calyanti.conf'; \
	fi

uninstall:
	$(Q)echo '  REMOVE  installed files (config and state are kept)'
	$(Q)rm -f '$(DESTDIR)$(SBINDIR)/calyd' '$(DESTDIR)$(SBINDIR)/calyantid'
	$(Q)rm -f '$(DESTDIR)$(BINDIR)/calyctl' '$(DESTDIR)$(BINDIR)/calyanti-cli'
	$(Q)rm -f '$(DESTDIR)$(LIBDIR)/calyanti.bpf.o'
	$(Q)rm -f '$(DESTDIR)$(UNITDIR)/calyanti.service'
	$(Q)rm -f '$(DESTDIR)$(SYSCTLDIR)/99-calyanti-sysctl.conf'
	$(Q)rm -f '$(DESTDIR)$(DOCDIR)/LICENSE'
	$(Q)rm -rf '$(DESTDIR)$(NFTDIR)'
	$(Q)for s in detect-env.sh deps.sh gen-vmlinux.sh install.sh uninstall.sh build.sh; do \
		rm -f "$(DESTDIR)$(SCRIPTSDIR)/$$s"; \
	done
	$(Q)rmdir '$(DESTDIR)$(SCRIPTSDIR)' '$(DESTDIR)$(LIBDIR)' 2>/dev/null || true
	$(Q)echo 'Left $(CONFDIR) and /var/lib/calyanti in place; remove manually if desired.'

clean:
	$(Q)echo '  CLEAN   build/'
	$(Q)rm -rf $(BUILD)

distclean: clean
	$(Q)echo '  CLEAN   generated vmlinux.h'
	$(Q)rm -f $(BPFSRC)/vmlinux.h

help:
	@echo 'Caly Anti $(VERSION) - build targets'
	@echo '  all (default)  vmlinux.h + BPF object + daemon + CLI into build/'
	@echo '  bpf            build/calyanti.bpf.o only'
	@echo '  daemon         build/calyd only'
	@echo '  cli            build/calyctl only'
	@echo '  install        install into $(DESTDIR)$(PREFIX) (DESTDIR-aware)'
	@echo '  uninstall      remove installed files (config/state kept)'
	@echo '  clean          remove build/'
	@echo '  distclean      also remove the generated src/bpf/vmlinux.h'
	@echo ''
	@echo 'Resolved: LIBBPF_MODE=$(LIBBPF_MODE) ARCH=$(ARCH) CLANG=$(CLANG)'
	@echo '  CC=$(CC) BPFTOOL=$(BPFTOOL) LLVM_STRIP=$(LLVM_STRIP)'
	@echo '  PREFIX=$(PREFIX) SYSCONFDIR=$(SYSCONFDIR)'

-include $(USER_DEPS)
