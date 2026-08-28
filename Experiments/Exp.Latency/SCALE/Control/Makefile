# === CONFIG ===
BPF_CLANG=clang
BPF_CFLAGS=-g -O2 -Wall -target bpf -D__TARGET_ARCH_x86_64

SRC_DIR := src
OBJ_DIR := obj
BUILD_DIR := build

BPF_HEADERS := $(SRC_DIR)/vmlinux.h

# BPF Source & Target
BPF_C_FILE := dispatcher.bpf.c
BPF_SRC := $(SRC_DIR)/$(BPF_C_FILE)
BPF_OBJ := $(OBJ_DIR)/$(BPF_C_FILE:.bpf.c=.bpf.o)
BPF_SKEL := $(SRC_DIR)/$(BPF_C_FILE:.bpf.c=.skel.h)

# User-space program
USER_SRC := main_controller.c
USER_BIN := main_controller
USER_FULL_SRC := $(SRC_DIR)/$(USER_SRC)
USER_TARGET := $(BUILD_DIR)/$(USER_BIN)

READ_SRC := $(SRC_DIR)/read_counter.c
READ_TARGET := $(BUILD_DIR)/read_counter

.PHONY: all clean

# === RULES ===
all: $(BPF_HEADERS) $(BPF_OBJ) $(BPF_SKEL) $(USER_TARGET) $(READ_TARGET)

$(BPF_HEADERS):
	@echo "[*] Generating vmlinux.h..."
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(OBJ_DIR)/%.bpf.o: $(SRC_DIR)/%.bpf.c $(BPF_HEADERS)
	@mkdir -p $(OBJ_DIR)
	@echo "[*] Compiling $< → $@"
	@$(BPF_CLANG) $(BPF_CFLAGS) -I$(SRC_DIR) -c $< -o $@

$(SRC_DIR)/%.skel.h: $(OBJ_DIR)/%.bpf.o
	@echo "[*] Generating $@ from $<"
	@bpftool gen skeleton $< > $@

$(BUILD_DIR)/%: $(SRC_DIR)/%.c $(BPF_SKEL)
	@mkdir -p $(BUILD_DIR)
	@echo "[*] Compiling $< → $@"
	@clang -g -O2 -Wall -I$(SRC_DIR) -o $@ $< -lbpf -lelf -lz -ljansson

$(READ_TARGET): $(READ_SRC)
	@mkdir -p $(BUILD_DIR)
	@echo "[*] Compiling $< → $@"
	@clang -g -O2 -Wall -I$(SRC_DIR) -o $@ $< -lbpf -lelf -lz

clean:
	@echo "[*] Cleaning..."
	@rm -rf $(OBJ_DIR) $(BUILD_DIR) $(SRC_DIR)/*.skel.h $(SRC_DIR)/vmlinux.h
