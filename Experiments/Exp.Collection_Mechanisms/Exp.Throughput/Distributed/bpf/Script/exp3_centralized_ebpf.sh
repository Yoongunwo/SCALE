#!/usr/bin/env bash
set -euo pipefail

# ---- defaults (override with options at run time) ----
PREFIX="${PREFIX:-exp2-}"                 # pod name prefix
NAMESPACE="${NAMESPACE:-}"               # namespace
CONTAINER="${CONTAINER:-proxy}"          # container name
DURATION="${DURATION:-10}"               # collection time (seconds)
CMD_PATH="${CMD_PATH:-./build/syscall_collector}"  # collector to run
LOG_FILE="${LOG_FILE:-syscalls_*.log}"   # log glob inside the container
READER_PATH="${READER_PATH:-./build/map_reader}"   # drop reader executable

usage() {
  cat <<'EOF'
Usage: ./collect.sh [options]

Options:
  -p, --prefix STR        Pod name prefix
  -n, --namespace STR     Kubernetes namespace
  -c, --container STR     Container name
  -d, --duration SEC      Collect duration seconds
  -x, --cmd PATH          Collector command path
  -f, --log-file GLOB     Log file glob in container
  -r, --reader PATH       Map reader path
  -h, --help              Show this help

You can also override via env vars: PREFIX, NAMESPACE, CONTAINER, DURATION, CMD_PATH, LOG_FILE, READER_PATH
EOF
}

# ---- option parsing ----
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--prefix)     PREFIX="$2"; shift 2 ;;
    -n|--namespace)  NAMESPACE="$2"; shift 2 ;;
    -c|--container)  CONTAINER="$2"; shift 2 ;;
    -d|--duration)   DURATION="$2"; shift 2 ;;
    -x|--cmd)        CMD_PATH="$2"; shift 2 ;;
    -f|--log-file)   LOG_FILE="$2"; shift 2 ;;
    -r|--reader)     READER_PATH="$2"; shift 2 ;;
    -h|--help)       usage; exit 0 ;;
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
declare -A DROPMAP

# ---- start collecting in each pod ----
for pod in "${PODS[@]}"; do
  echo "[$pod] starting collector in container '$CONTAINER' -> $CMD_PATH"
  set +e
  PID=$(kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc \
    "if [ ! -x \"$CMD_PATH\" ] && [ ! -f \"$CMD_PATH\" ]; then echo '__MISSING__'; exit 0; fi;
     nohup $CMD_PATH >/dev/null 2>&1 & echo \$!")
  rc=$?
  set -e

  if [[ $rc -ne 0 ]]; then
    echo "[$pod] ERROR: failed to start collector"
    continue
  fi
  if [[ "$PID" == "__MISSING__" ]]; then
    echo "[$pod] WARNING: $CMD_PATH not found or not executable in container."
    continue
  fi
  if ! [[ "$PID" =~ ^[0-9]+$ ]]; then
    echo "[$pod] WARNING: could not obtain PID; will try pkill on stop."
    PID="__UNKNOWN__"
  fi

  PIDMAP["$pod"]="$PID"
done

echo ">> Collecting for ${DURATION}s..."
sleep "$DURATION"

# ---- stop collecting ----
for pod in "${PODS[@]}"; do
  PID="${PIDMAP[$pod]:-__UNKNOWN__}"
  echo "[$pod] stopping collector (PID=$PID)"
  kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc \
    "{ [ \"$PID\" != \"__UNKNOWN__\" ] && kill -TERM \"$PID\" 2>/dev/null; } || pkill -f \"$CMD_PATH\" 2>/dev/null || true"
done

# ---- read the drops in each pod (map_reader) ----
for pod in "${PODS[@]}"; do
  echo "[$pod] reading drops with '$READER_PATH'"
  set +e
  DROPVAL=$(kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc \
    "if [ -x \"$READER_PATH\" ] || [ -f \"$READER_PATH\" ]; then
        $READER_PATH 2>/dev/null | awk '/^DROP:/ {print \$2; exit}';
     fi")
  rc=$?
  set -e
  if [[ $rc -ne 0 || -z "${DROPVAL:-}" ]]; then
    DROPMAP["$pod"]="N/A"
  else
    DROPMAP["$pod"]="$DROPVAL"
  fi
done

# ---- result summary ----
printf "\n%-24s  %-18s  %-12s  %-12s\n" "POD" "duration(sec)" "lines" "drops"
printf "%-24s  %-18s  %-12s  %-12s\n" "------------------------" "------------------" "------------" "------------"

for pod in "${PODS[@]}"; do
  start=$(kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc '
    ts=$(cat '"$LOG_FILE"' 2>/dev/null | head -n 1 | awk "{print \$1}")
    if [ -n "$ts" ]; then echo "$ts"; else echo 0; fi' || echo 0)

  end=$(kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc '
    ts=$(cat '"$LOG_FILE"' 2>/dev/null | tail -n 2 | head -n 1 | awk "{print \$1}")
    if [ -n "$ts" ]; then echo "$ts"; else echo 0; fi' || echo 0)

  count=$(kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc '
    cat '"$LOG_FILE"' 2>/dev/null | wc -l' || echo 0)

  dur=$(awk "BEGIN { s=$start+0; e=$end+0; d=e-s; if (d<0) d=0; printf \"%.3f\", d }")
  drops="${DROPMAP[$pod]:-N/A}"
  printf "%-24s  %-18s  %-12s  %-12s\n" "$pod" "$dur" "$count" "$drops"
done

# ---- cleanup ----
echo -e "\n>> Cleaning logs in each container ($LOG_FILE)"
for pod in "${PODS[@]}"; do
  kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc "rm -f $LOG_FILE 2>/dev/null || true" || true
done

# clear /sys/fs/bpf: only once, on the first pod
FIRST_POD="${PODS[0]}"
echo ">> Cleaning /sys/fs/bpf once in $FIRST_POD"
kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$FIRST_POD" -- sh -lc 'mountpoint -q /sys/fs/bpf && rm -rf /sys/fs/bpf/* 2>/dev/null || true' || true

echo ">> Done."
