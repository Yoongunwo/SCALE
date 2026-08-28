#!/bin/bash
set -euo pipefail

NAMESPACE=default   # 필요하면 변경
TOTAL=0

# exp3* pod 목록 가져오기
PODS=$(kubectl get pods -n "$NAMESPACE" -o name | grep '^pod/exp2')

for P in $PODS; do
  echo "[INFO] Processing $P"
  # proxy 컨테이너에서 wc 실행
  # syscall* 파일이 없으면 에러가 나므로 2>/dev/null 처리
  COUNT=$(kubectl exec -n "$NAMESPACE" "$P" -c proxy -- sh -c 'wc -l syscall* 2>/dev/null | awk "{sum += \$1} END {print sum+0}"')
  echo "  $P -> $COUNT"
  TOTAL=$((TOTAL + COUNT))
done

echo "==============================="
echo "TOTAL syscalls line count = $TOTAL"
