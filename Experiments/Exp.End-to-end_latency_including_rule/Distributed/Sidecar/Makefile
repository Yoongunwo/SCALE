# === CONFIG ===
BPF_CLANG=clang

ifneq ($(RINGBUF_POW2),)
	RINGBUF_SIZE := $(shell sh -c 'echo $$((1 << $(RINGBUF_POW2)))')
endif

BPF_CFLAGS=-g -O2 -Wall -target bpf -D__TARGET_ARCH_x86_64 \
	$(if $(RINGBUF_SIZE),-DRINGBUF_SIZE=$(RINGBUF_SIZE))

SRC_DIR := src
OBJ_DIR := obj
BUILD_DIR := build

RULE_SRC_DIR := rule_engine

BPF_HEADERS := $(SRC_DIR)/vmlinux.h

# BPF Source
BPF_SRC := $(SRC_DIR)/syscall_collector.bpf.c
BPF_OBJ := $(OBJ_DIR)/syscall_collector.bpf.o
BPF_SKEL := $(SRC_DIR)/syscall_collector.skel.h

# User-space Collector
USER_SRC := $(SRC_DIR)/syscall_collector.c
USER_BIN := $(BUILD_DIR)/syscall_collector

# =========================
# 🔥 Rule Engine (NEW)
# =========================
RULE_SRC := $(RULE_SRC_DIR)/syscall_rule_engine.c
RULE_BIN := $(BUILD_DIR)/syscall_rule_engine

.PHONY: all clean

# === RULES ===
all: $(BPF_HEADERS) $(BPF_OBJ) $(BPF_SKEL) $(USER_BIN) $(RULE_BIN)

$(BPF_HEADERS):
	@echo "[*] Generating vmlinux.h..."
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(BPF_HEADERS)
	@mkdir -p $(OBJ_DIR)
	@echo "[*] Compiling $< → $@"
	@$(BPF_CLANG) $(BPF_CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	@echo "[*] Generating skeleton $@ from $<"
	@bpftool gen skeleton $< > $@

$(USER_BIN): $(USER_SRC) $(BPF_SKEL)
	@mkdir -p $(BUILD_DIR)
	@echo "[*] Compiling collector $< → $@"
	@clang -g -O2 -Wall -I$(SRC_DIR) -o $@ $< \
		-lbpf -lelf -lz -ljansson

# =========================
# 🔥 Rule Engine build
# =========================
$(RULE_BIN): $(RULE_SRC)
	@mkdir -p $(BUILD_DIR)
	@echo "[*] Compiling rule engine $< → $@"
	@clang -g -O2 -Wall -o $@ $< -ljansson

clean:
	@echo "[*] Cleaning..."
	@rm -rf $(OBJ_DIR) $(BUILD_DIR) \
		$(SRC_DIR)/syscall_collector.skel.h \
		$(SRC_DIR)/vmlinux.h
