#!/bin/bash
set -euo pipefail

# save the read_counter output
OUT=$(sudo ./build/read_counter)

# sum
TOTAL=$(echo "$OUT" | grep "Events:" | awk '{sum += $NF} END {print sum}')

# output
echo "$OUT"
echo "=========================="
echo "TOTAL Events = $TOTAL"
