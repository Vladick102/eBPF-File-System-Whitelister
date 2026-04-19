CLANG      ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL    ?= $(shell command -v bpftool 2>/dev/null || echo /usr/sbin/bpftool)
ARCH       ?= x86

BUILD_DIR  := build
VMLINUX    := $(BUILD_DIR)/vmlinux.h
BPF_OBJ    := $(BUILD_DIR)/whitelister.bpf.o
SKEL       := $(BUILD_DIR)/whitelister.skel.h
BIN        := $(BUILD_DIR)/whitelister

.PHONY: all clean
all: $(BIN)

$(BUILD_DIR):
	mkdir -p $@

$(VMLINUX): | $(BUILD_DIR)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): whitelister.bpf.c $(VMLINUX)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
	         -I$(BUILD_DIR) -c $< -o $@
	$(LLVM_STRIP) -g $@

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(BIN): whitelister.c $(SKEL)
	$(CLANG) -g -O2 -Wall -I$(BUILD_DIR) $< -lbpf -lelf -lz -o $@

clean:
	rm -rf $(BUILD_DIR)
