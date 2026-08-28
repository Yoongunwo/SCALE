#!/usr/bin/env bash
set -euo pipefail

echo "[+] RINGBUF_POW2=${RINGBUF_POW2:-unset}"

make RINGBUF_POW2="${RINGBUF_POW2:-}" 

# collector → background
./build/syscall_collector 1 &
COL_PID=$!

echo "[+] syscall_collector started (pid=${COL_PID})"

# rule engine → foreground
exec ./build/syscall_rule_engine