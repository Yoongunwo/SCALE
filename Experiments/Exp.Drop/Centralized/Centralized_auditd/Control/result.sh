#!/bin/bash
set -euo pipefail

# read_counter 실행 결과 저장
OUT=$(sudo ./build/read_counter)

# 합산
TOTAL=$(echo "$OUT" | grep "Events:" | awk '{sum += $NF} END {print sum}')

# 출력
echo "$OUT"
echo "=========================="
echo "TOTAL Events = $TOTAL"
