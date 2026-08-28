# === CONFIG ===
BPF_CLANG=clang

RINGBUF_POW2 ?= 20
RINGBUF_SIZE := $(shell echo $$((1 << $(RINGBUF_POW2))))

BPF_CFLAGS=-g -O2 -Wall -target bpf -D__TARGET_ARCH_x86_64 \
	$(if $(RINGBUF_SIZE),-DRINGBUF_SIZE=$(RINGBUF_SIZE))

SRC_DIR := src
OBJ_DIR := obj
BUILD_DIR := build

BPF_HEADERS := $(SRC_DIR)/vmlinux.h

BPF_SRC := $(SRC_DIR)/syscall_collector.bpf.c
BPF_OBJ := $(OBJ_DIR)/syscall_collector.bpf.o
BPF_SKEL := $(SRC_DIR)/syscall_collector.skel.h

USER_SRC := $(SRC_DIR)/syscall_collector.c
USER_BIN := $(BUILD_DIR)/syscall_collector

# Map reader source / executable
READER_SRC := $(SRC_DIR)/map_reader.c
READER_BIN := $(BUILD_DIR)/map_reader

.PHONY: all clean

# === RULES ===
all: $(BPF_HEADERS) $(BPF_OBJ) $(BPF_SKEL) $(USER_BIN) $(READER_BIN)

$(BPF_HEADERS):
	@echo "[*] Generating vmlinux.h..."
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(BPF_HEADERS)
	@mkdir -p $(OBJ_DIR)
	@echo "[*] RINGBUF_SIZE=$(RINGBUF_SIZE) (2^$(RINGBUF_POW2))"
	@echo "[*] Compiling $< → $@"
	@$(BPF_CLANG) $(BPF_CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	@echo "[*] Generating skeleton $@ from $<"
	@bpftool gen skeleton $< > $@

$(USER_BIN): $(USER_SRC) $(BPF_SKEL)
	@mkdir -p $(BUILD_DIR)
	@echo "[*] Compiling $< → $@"
	@clang -g -O2 -Wall -I$(SRC_DIR) -o $@ $< -lbpf -lelf -lz -ljansson

# Map reader build rule
$(READER_BIN): $(READER_SRC)
	@mkdir -p $(BUILD_DIR)
	@echo "[*] Compiling $< → $@"
	@clang -g -O2 -Wall -I$(SRC_DIR) -o $@ $< -lbpf -lelf -lz

clean:
	@echo "[*] Cleaning..."
	@rm -rf $(OBJ_DIR) $(BUILD_DIR) \
		$(SRC_DIR)/syscall_collector.skel.h $(SRC_DIR)/vmlinux.h
