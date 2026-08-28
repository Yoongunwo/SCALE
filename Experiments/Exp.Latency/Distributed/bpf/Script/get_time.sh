#!/usr/bin/env bash
set -euo pipefail

NS="default"
POD_PREFIX="exp2-"
CONTAINER=""

usage() {
  cat <<EOF
Usage: $0 [-n NAMESPACE] [-p POD_PREFIX] [-c CONTAINER]
  -n   Kubernetes namespace (default: default)
  -p   Pod name prefix to match (default: exp2-)
  -c   Container name (optional; for multi-container pods)
EOF
}

while getopts ":n:p:c:h" opt; do
  case "$opt" in
    n) NS="$OPTARG" ;;
    p) POD_PREFIX="$OPTARG" ;;
    c) CONTAINER="$OPTARG" ;;
    h) usage; exit 0 ;;
    \?) echo "Invalid option: -$OPTARG" >&2; usage; exit 1 ;;
    :)  echo "Option -$OPTARG requires an argument." >&2; usage; exit 1 ;;
  esac
done

# Pod 목록 (Running 상태만)
mapfile -t PODS < <(kubectl get pods -n "$NS" \
  --field-selector=status.phase=Running \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | grep -E "^${POD_PREFIX}")

if [[ ${#PODS[@]} -eq 0 ]]; then
  echo "No running pods matched prefix '$POD_PREFIX' in namespace '$NS'." >&2
  exit 1
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

# 각 Pod에서: 최신 syscalls_*.log 찾고, 마지막에서 두 번째 줄을 출력
for pod in "${PODS[@]}"; do
  # 원격에서 실행할 쉘 스니펫
  read -r -d '' REMOTE <<'SH' || true
set -e
# 후보 경로에서 최신 파일 선택
f=""
for p in /var/log/syscalls_*.log /tmp/syscalls_*.log /workspace/syscalls_*.log /app/syscalls_*.log; do
  # 글롭이 실패해도 에러 안나게: nullglob 비슷한 동작
  for cand in $p; do
    [ -e "$cand" ] || continue
    echo "$cand"
  done
done | xargs -r ls -1t 2>/dev/null | head -1 > /tmp/.syslog_candidate || true

if [ -s /tmp/.syslog_candidate ]; then
  f="$(cat /tmp/.syslog_candidate)"
  # 마지막에서 2번째 줄
  # tail -n 2 "$f" | head -n 1
  tail -n 1 "$f" | head -n 1
fi
SH

  # kubectl exec (컨테이너 지정 여부)
  if [[ -n "$CONTAINER" ]]; then
    LINE="$(kubectl exec -n "$NS" -c "$CONTAINER" "$pod" -- sh -lc "$REMOTE" 2>/dev/null || true)"
  else
    LINE="$(kubectl exec -n "$NS" "$pod" -- sh -lc "$REMOTE" 2>/dev/null || true)"
  fi

  if [[ -z "$LINE" ]]; then
    echo "WARN: no data from pod '$pod' (no log or too few lines)" >&2
    continue
  fi

  # Evoked / Collected 파싱
  EV="$(sed -n 's/.*Evoked Time=\([0-9]\+\.[0-9]\+\).*/\1/p' <<<"$LINE" | head -n1)"
  CO="$(sed -n 's/.*Collected Time=\([0-9]\+\.[0-9]\+\).*/\1/p' <<<"$LINE" | head -n1)"

  if [[ -z "$EV" || -z "$CO" ]]; then
    echo "WARN: malformed line from '$pod': $LINE" >&2
    continue
  fi

  # 결과를 일괄 처리용으로 저장: "<pod> <evoked> <collected>"
  echo "$pod $EV $CO" >> "$TMP"
done

if [[ ! -s "$TMP" ]]; then
  echo "No valid data collected." >&2
  exit 2
fi

# 출력: Pod별 값 + 전체 통계(가장 이른 Evoked, 가장 늦은 Collected, 차이)
awk '
{
  pod=$1; ev=$2; co=$3;
  printf "%-32s evoked=%s collected=%s\n", pod, ev, co;
  if (min_ev=="" || ev < min_ev) min_ev=ev;
  if (max_co=="" || co > max_co) max_co=co;
}
END {
  if (NR>0) {
    diff = max_co - min_ev;
    printf "\nEarliest Evoked : %s\n", min_ev;
    printf "Latest Collected: %s\n", max_co;
    printf "Time delta (s)  : %.6f\n", diff;
  } else {
    print "No data.";
  }
}
' "$TMP"

