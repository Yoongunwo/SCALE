#!/usr/bin/env bash
set -euo pipefail

# ---- 기본값 ----
PREFIX="${PREFIX:-exp3-}"
NAMESPACE="${NAMESPACE:-}"
CONTAINER="${CONTAINER:-proxy}"
DURATION="${DURATION:-10}"
CMD_PATH="${CMD_PATH:-./build/syscall_collector}"
LOG_FILE="${LOG_FILE:-syscalls_*.log}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  -p, --prefix STR        Pod name prefix (default: $PREFIX)
  -n, --namespace STR     Kubernetes namespace (default: current context ns)
  -c, --container STR     Container name (default: $CONTAINER)
  -d, --duration SEC      Collect duration seconds (default: $DURATION)
  -x, --cmd PATH          Collector command path (default: $CMD_PATH)
  -f, --log-file GLOB     Log file glob in container (default: $LOG_FILE)
  -h, --help              Show this help
EOF
}

# ---- 옵션 파싱 ----
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--prefix) PREFIX="$2"; shift 2 ;;
    -n|--namespace) NAMESPACE="$2"; shift 2 ;;
    -c|--container) CONTAINER="$2"; shift 2 ;;
    -d|--duration) DURATION="$2"; shift 2 ;;
    -x|--cmd) CMD_PATH="$2"; shift 2 ;;
    -f|--log-file) LOG_FILE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

NSFLAG=()
[[ -n "$NAMESPACE" ]] && NSFLAG=(-n "$NAMESPACE")

echo ">> Finding pods with prefix '$PREFIX'..."
mapfile -t PODS < <(kubectl get pods "${NSFLAG[@]}" -o custom-columns=NAME:.metadata.name --no-headers | grep "^${PREFIX}" || true)
if [[ ${#PODS[@]} -eq 0 ]]; then
  echo "No pods found with prefix '${PREFIX}'."
  exit 1
fi
echo "Found ${#PODS[@]} pods."

declare -A PIDMAP

# ---- 수집 전: 이전 로그 삭제 ----
for pod in "${PODS[@]}"; do
  echo "[$pod] pre-clean logs ($LOG_FILE)"
  kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc 'rm -f '"$LOG_FILE"' 2>/dev/null || true' || true
done

# ---- collector 시작 ----
for pod in "${PODS[@]}"; do
  echo "[$pod] starting collector in container '$CONTAINER' -> $CMD_PATH"
  set +e
  PID=$(kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc \
    "if [ ! -x \"$CMD_PATH\" ] && [ ! -f \"$CMD_PATH\" ]; then echo '__MISSING__'; exit 0; fi;
     nohup $CMD_PATH >/dev/null 2>&1 & echo \$!")
  rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    echo "[$pod] ERROR: failed to start collector"; continue
  fi
  if [[ "$PID" == "__MISSING__" ]]; then
    echo "[$pod] WARNING: $CMD_PATH not found or not executable in container."; continue
  fi
  if ! [[ "$PID" =~ ^[0-9]+$ ]]; then
    echo "[$pod] WARNING: could not obtain PID; will try pkill on stop."
    PID="__UNKNOWN__"
  fi
  PIDMAP["$pod"]="$PID"
done

echo ">> Collecting for ${DURATION}s..."
sleep "$DURATION"

# ---- collector 종료 ----
for pod in "${PODS[@]}"; do
  PID="${PIDMAP[$pod]:-__UNKNOWN__}"
  BNAME="$(basename "$CMD_PATH")"   # 실행 파일명만 사용 (예: syscall_collector)
  echo "[$pod] stopping collector (PID=$PID)"

  # exec 내부에서 sh가 pkill에 맞아 죽지 않도록 -x(정확히 실행파일명 매칭) 사용
  kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc '
    set -eu
    PID='"$PID"'
    BNAME='"$BNAME"'

    if [ "$PID" != "__UNKNOWN__" ]; then
      kill -TERM "$PID" 2>/dev/null || true
    else
      pids=$(pgrep -x "$BNAME" || true)
      if [ -n "$pids" ]; then
        kill -TERM $pids 2>/dev/null || true
      fi
    fi

    # 최대 3초 기다리며 내려갔는지 확인 (필요하면 SIGKILL 추가 가능)
    for i in 1 2 3; do
      sleep 1
      pgrep -x "$BNAME" >/dev/null || exit 0
    done
    exit 0
  ' || true
done

# ---- 결과 요약: 최신 파일 1개만 사용 ----
printf "\n%-24s  %-18s  %-12s\n" "POD" "duration(sec)" "lines"
printf "%-24s  %-18s  %-12s\n" "------------------------" "------------------" "------------"

for pod in "${PODS[@]}"; do
  kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc '
    F=$(ls -1t '"$LOG_FILE"' 2>/dev/null | head -n1 || true)
    if [ -z "$F" ] || [ ! -s "$F" ]; then
      echo "0 0"
      exit 0
    fi
    CNT=$(wc -l < "$F")
    DUR=$(LC_ALL=C awk '\''match($1,/^[0-9]+\.[0-9]+$/){ if(!got){s=$1; got=1} e=$1 } END{ d=e-s; if(d<0)d=0; printf "%.6f", d }'\'' "$F")
    printf "%s %s\n" "$DUR" "$CNT"
  ' | {
    read -r dur cnt || { dur=0; cnt=0; }
    printf "%-24s  %-18s  %-12s\n" "$pod" "$dur" "$cnt"
  }
done

# ---- 각 파드에서 로그 파일 삭제 ----
# echo -e "\n>> Deleting logs in each container ($LOG_FILE)"
# for pod in "${PODS[@]}"; do
#   echo "[$pod] rm -f $LOG_FILE"
#   kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc 'rm -f '"$LOG_FILE"' 2>/dev/null || true' || true
# done

echo ">> Done."
