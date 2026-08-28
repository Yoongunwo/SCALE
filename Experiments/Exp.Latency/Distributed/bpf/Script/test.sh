#!/usr/bin/env bash
set -euo pipefail

NS="default"
POD_PREFIX="exp2-"
LINES=3000
TOPK=100

# Pod 목록
mapfile -t PODS < <(kubectl get pods -n "$NS" \
  --field-selector=status.phase=Running \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' \
  | grep -E "^${POD_PREFIX}")

if [[ ${#PODS[@]} -eq 0 ]]; then
  echo "No running pods matched prefix '$POD_PREFIX' in namespace '$NS'." >&2
  exit 1
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

declare -A LOGFILES=()

# 각 Pod에서 최신 로그 파일 찾기
for pod in "${PODS[@]}"; do
  logfile="$(kubectl exec -n "$NS" "$pod" -- sh -c '
    for p in /app/syscalls_*.log; do
      ls -t $p 2>/dev/null | head -n1 && exit 0
    done
    exit 1
  ' 2>/dev/null || true)"
  if [[ -n "$logfile" ]]; then
    LOGFILES[$pod]="$logfile"
  fi
done

if [[ ${#LOGFILES[@]} -eq 0 ]]; then
  echo "No valid logfiles found." >&2
  exit 1
fi

# 끝에서 1번째 ~ LINES번째 줄까지 확인
for n in $(seq 1 $LINES); do
  min_ev=""
  max_co=""
  valid=false

  for pod in "${PODS[@]}"; do
    logfile="${LOGFILES[$pod]:-}"
    [[ -z "$logfile" ]] && continue

    # 끝에서 $LINES 줄 가져온 뒤, 그 블록에서 $n번째 줄 추출
    line="$(kubectl exec -n "$NS" "$pod" -- sh -c "tail -n $LINES $logfile | sed -n '${n}p'" 2>/dev/null || true)"
    [[ -z "$line" ]] && continue

    ev=$(sed -n 's/.*Evoked Time=\([0-9.]\+\).*/\1/p' <<<"$line")
    co=$(sed -n 's/.*Collected Time=\([0-9.]\+\).*/\1/p' <<<"$line")
    [[ -z "$ev" || -z "$co" ]] && continue

    if [[ -z "$min_ev" || $(awk -v a="$ev" -v b="$min_ev" 'BEGIN{print (a<b)}') -eq 1 ]]; then
      min_ev="$ev"
    fi
    if [[ -z "$max_co" || $(awk -v a="$co" -v b="$max_co" 'BEGIN{print (a>b)}') -eq 1 ]]; then
      max_co="$co"
    fi
    valid=true
  done

  if $valid; then
    diff=$(awk -v a="$max_co" -v b="$min_ev" 'BEGIN{printf "%.6f", a-b}')
    echo "line=$n earliest_evoked=$min_ev latest_collected=$max_co elapsed=$diff" >> "$TMP"
  fi
done

if [[ ! -s "$TMP" ]]; then
  echo "No valid data collected."
  exit 2
fi

echo "=== Top $TOPK fastest elapsed times ==="
sort -k4,4g "$TMP" | head -n "$TOPK"
