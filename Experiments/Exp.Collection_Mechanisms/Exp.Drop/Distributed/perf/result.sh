#!/bin/bash
set -euo pipefail

NAMESPACE=default   # change if needed
TOTAL=0

# get the list of exp3* pods
PODS=$(kubectl get pods -n "$NAMESPACE" -o name | grep '^pod/exp2')

for P in $PODS; do
  echo "[INFO] Processing $P"
  # run wc in the proxy container
  # a missing syscall* file would raise an error, hence 2>/dev/null
  COUNT=$(kubectl exec -n "$NAMESPACE" "$P" -c proxy -- sh -c 'wc -l syscall* 2>/dev/null | awk "{sum += \$1} END {print sum+0}"')
  echo "  $P -> $COUNT"
  TOTAL=$((TOTAL + COUNT))
done

echo "==============================="
echo "TOTAL syscalls line count = $TOTAL"
