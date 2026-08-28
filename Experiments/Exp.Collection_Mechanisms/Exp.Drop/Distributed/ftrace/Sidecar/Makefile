# Makefile
SHELL := /bin/bash

# Paths
SRC_DIR   := src
BUILD_DIR := build
TARGET    := $(BUILD_DIR)/syscall_collector

# Toolchain
CC      := gcc
CFLAGS  ?= -O2 -g -Wall -Wextra -std=gnu11 -D_GNU_SOURCE
LDFLAGS ?=
# NOTE: 일부 오래된 glibc에서는 clock_gettime 위해 -lrt 필요.
# 최신 배포판에서도 문제 없으나, 에러나면 LDLIBS를 비우세요.
LDLIBS  ?= -lrt

# Sources / Objects
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

.PHONY: all clean run dirs

all: $(TARGET)

$(TARGET): $(OBJS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -rf $(BUILD_DIR)

# 편의: root 권한 필요할 수 있음
run: $(TARGET)
	sudo $(TARGET)
