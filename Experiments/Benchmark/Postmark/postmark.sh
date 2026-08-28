#!/usr/bin/env bash
# resume_postmark.sh
# exp* Pod들의 sys-gen 컨테이너에 저장된 /tmp/pm.pid를 읽고 SIGCONT 전송

set -euo pipefail

NS="${1:-}"             # 첫 인자: namespace (없으면 current context)
PREFIX="${2:-exp}"      # 둘째 인자: pod name prefix (기본: exp)
CONTAINER="${3:-sys-gen}"  # 셋째 인자: container name (기본: sys-gen)

K="kubectl"
[[ -n "$NS" ]] && K+=" -n $NS"

# Running 중인 PREFIX* Pod만 추리기
mapfile -t PODS < <(
  $K get pods \
    -o jsonpath='{range .items[?(@.status.phase=="Running")]}{.metadata.name}{"\n"}{end}' \
  | grep -E "^${PREFIX}" || true
)

if ((${#PODS[@]}==0)); then
  echo "No Running pods with prefix '${PREFIX}' in namespace '${NS:-current}'." >&2
  exit 1
fi

for pod in "${PODS[@]}"; do
  # 컨테이너 PID 읽기
  pid="$($K exec -i "$pod" -c "$CONTAINER" -- sh -c 'cat /tmp/pm.pid 2>/dev/null' || true)"

  if [[ -z "$pid" ]]; then
    echo "[$pod] /tmp/pm.pid not found (container '$CONTAINER' not ready or gate mode off?)"
    continue
  fi

  echo "[$pod] sending SIGCONT to pid=$pid"
  if $K exec -i "$pod" -c "$CONTAINER" -- sh -c "kill -CONT $pid"; then
    echo "[$pod] resumed."
  else
    echo "[$pod] failed to send SIGCONT." >&2
  fi
done
