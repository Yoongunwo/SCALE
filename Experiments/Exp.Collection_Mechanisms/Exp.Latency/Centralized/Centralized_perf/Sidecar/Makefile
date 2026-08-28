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
# NOTE: some older glibc versions need -lrt for clock_gettime.
# It is fine on modern distributions; if it errors out, clear LDLIBS.
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

# convenience: may require root privileges
run: $(TARGET)
	sudo $(TARGET)
