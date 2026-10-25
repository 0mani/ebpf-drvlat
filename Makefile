# SPDX-License-Identifier: BSD-2-Clause
#
# Build:   make                    (needs clang, bpftool, libbpf-dev, libelf-dev)
# Run:     sudo ./build/drvlat
#
# vmlinux.h is generated from the running kernel's BTF. To build for another
# target, copy that target's /sys/kernel/btf/vmlinux and pass VMLINUX_BTF=...

OUT        ?= build
CLANG      ?= clang
BPFTOOL    ?= bpftool
CC         ?= cc
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/' \
          -e 's/armv7.*/arm/' -e 's/riscv64/riscv/')

CFLAGS     ?= -O2 -g -Wall -Wextra
BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) -I$(OUT) -Isrc
LIBS       := -lbpf -lelf -lz

.PHONY: all clean

all: $(OUT)/drvlat

$(OUT):
	mkdir -p $@

$(OUT)/vmlinux.h: | $(OUT)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

$(OUT)/drvlat.bpf.o: src/drvlat.bpf.c src/drvlat.h $(OUT)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUT)/drvlat.skel.h: $(OUT)/drvlat.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(OUT)/drvlat: src/drvlat.c src/drvlat.h $(OUT)/drvlat.skel.h
	$(CC) $(CFLAGS) -I$(OUT) -Isrc $< -o $@ $(LIBS)

clean:
	rm -rf $(OUT)
