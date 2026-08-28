#!/usr/bin/env bash
set -euo pipefail

# ---- defaults ----
PREFIX="${PREFIX:-exp3-}"
NAMESPACE="${NAMESPACE:-}"
CONTAINER="${CONTAINER:-proxy}"          # container where the collector runs
DURATION="${DURATION:-10}"
CMD_PATH="${CMD_PATH:-./build/syscall_collector}"
LOG_FILE="${LOG_FILE:-syscalls_*.log}"

# sys_generator related
GEN_CONTAINER="${GEN_CONTAINER:-sys-gen}"
GEN_CMD_PATH="${GEN_CMD_PATH:-./sys_generator}"
GEN_DURATION="${GEN_DURATION:-2}"

# pods to exclude (comma separated: podA,podB)
EXCLUDE="${EXCLUDE:-}"

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  -p, --prefix STR        Pod name prefix (default: $PREFIX)
  -n, --namespace STR     Kubernetes namespace (default: current context ns)
  -c, --container STR     Collector container (default: $CONTAINER)
  -d, --duration SEC      Collect duration seconds (default: $DURATION)
  -x, --cmd PATH          Collector command path (default: $CMD_PATH)
  -f, --log-file GLOB     Log file glob in collector container (default: $LOG_FILE)

  -g, --gen-container STR Container running sys_generator (default: $GEN_CONTAINER)
  -G, --gen-cmd PATH      Path to sys_generator in that container (default: $GEN_CMD_PATH)
  -t, --gen-duration SEC  How long to run sys_generator (default: $GEN_DURATION)

  -X, --exclude LIST      Comma-separated pod names to exclude (default: empty)
  -h, --help              Show this help
EOF
}

# ---- option parsing ----
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--prefix) PREFIX="$2"; shift 2 ;;
    -n|--namespace) NAMESPACE="$2"; shift 2 ;;
    -c|--container) CONTAINER="$2"; shift 2 ;;
    -d|--duration) DURATION="$2"; shift 2 ;;
    -x|--cmd) CMD_PATH="$2"; shift 2 ;;
    -f|--log-file) LOG_FILE="$2"; shift 2 ;;
    -g|--gen-container) GEN_CONTAINER="$2"; shift 2 ;;
    -G|--gen-cmd) GEN_CMD_PATH="$2"; shift 2 ;;
    -t|--gen-duration) GEN_DURATION="$2"; shift 2 ;;
    -X|--exclude) EXCLUDE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

NSFLAG=()
[[ -n "$NAMESPACE" ]] && NSFLAG=(-n "$NAMESPACE")

# ---- process the exclusion list ----
declare -A EXSET
if [[ -n "$EXCLUDE" ]]; then
  IFS=',' read -r -a _arr <<<"$EXCLUDE"
  for name in "${_arr[@]}"; do
    name="$(echo "$name" | xargs)"   # trim
    [[ -n "$name" ]] && EXSET["$name"]=1
  done
fi
is_excluded() { [[ -n "${EXSET[$1]:-}" ]]; }

echo ">> Finding pods with prefix '$PREFIX'..."
mapfile -t PODS < <(kubectl get pods "${NSFLAG[@]}" -o custom-columns=NAME:.metadata.name --no-headers | grep "^${PREFIX}" || true)
if [[ ${#PODS[@]} -eq 0 ]]; then
  echo "No pods found with prefix '${PREFIX}'."
  exit 1
fi

# apply the exclusions
FILTERED=()
for p in "${PODS[@]}"; do
  if is_excluded "$p"; then
    echo "  - exclude $p"
    continue
  fi
  FILTERED+=("$p")
done
PODS=("${FILTERED[@]}")

if [[ ${#PODS[@]} -eq 0 ]]; then
  echo "All pods are excluded."
  exit 0
fi
echo "Found ${#PODS[@]} pods after exclusion."

declare -A PIDMAP

# ---- before collecting: remove the previous logs ----
for pod in "${PODS[@]}"; do
  echo "[$pod] pre-clean logs in collector container ($LOG_FILE)"
  kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc 'rm -f '"$LOG_FILE"' 2>/dev/null || true' || true
done

# ---- start the collector ----
for pod in "${PODS[@]}"; do
  echo "[$pod] starting collector in '$CONTAINER' -> $CMD_PATH"
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
    echo "[$pod] WARNING: $CMD_PATH not found or not executable in '$CONTAINER'."
    continue
  fi
  if ! [[ "$PID" =~ ^[0-9]+$ ]]; then
    echo "[$pod] WARNING: could not obtain PID; will try pkill on stop."
    PID="__UNKNOWN__"
  fi
  PIDMAP["$pod"]="$PID"
done

# ---- run sys_generator for 2s (selected pods only, sys-gen container) ----
for pod in "${PODS[@]}"; do
  echo "[$pod] launching sys_generator for ${GEN_DURATION}s in '$GEN_CONTAINER' -> $GEN_CMD_PATH"
  kubectl exec "${NSFLAG[@]}" -c "$GEN_CONTAINER" "$pod" -- sh -lc '
    CMD='"$GEN_CMD_PATH"';
    DUR='"$GEN_DURATION"';
    # check existence
    if [ ! -x "$CMD" ] && [ ! -f "$CMD" ]; then
      echo "__GEN_MISSING__"
      exit 0
    fi
    # run it and record the PID
    (nohup "$CMD" >/dev/null 2>&1 & echo $! > /tmp/sysgen.pid) || true
    # schedule termination after DUR (try pkill, killall, then ps-kill)
    nohup sh -c "
      sleep \"$DUR\";
      { test -f /tmp/sysgen.pid && kill -TERM \$(cat /tmp/sysgen.pid) 2>/dev/null; } || \
      pkill -f \"\$CMD\" 2>/dev/null || \
      killall -q sys_generator 2>/dev/null || \
      { for p in \$(ps -C sys_generator -o pid= 2>/dev/null); do kill -TERM \$p 2>/dev/null; done; } || true
    " >/dev/null 2>&1 &
    echo "__GEN_STARTED__"
  ' >/dev/null || echo "[$pod] WARN: failed to launch sys_generator (container missing?)"
done

echo ">> Collecting for ${DURATION}s..."
sleep "$DURATION"

# ---- stop the collector ----
for pod in "${PODS[@]}"; do
  PID="${PIDMAP[$pod]:-__UNKNOWN__}"
  echo "[$pod] stopping collector (PID=$PID)"
  kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc \
    "{ [ \"$PID\" != \"__UNKNOWN__\" ] && kill -TERM \"$PID\" 2>/dev/null; } || pkill -f \"$CMD_PATH\" 2>/dev/null || true"
done

# ---- result summary: use only the newest file ----
printf "\n%-24s  %-14s  %-12s\n" "POD" "duration(sec)" "lines"
printf "%-24s  %-14s  %-12s\n" "------------------------" "------------" "------------"

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
    printf "%-24s  %-14s  %-12s\n" "$pod" "$dur" "$cnt"
  }
done

# ---- delete the log files in each pod ----
echo -e "\n>> Deleting logs in collector containers ($LOG_FILE)"
for pod in "${PODS[@]}"; do
  echo "[$pod] rm -f $LOG_FILE"
  kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$pod" -- sh -lc 'rm -f '"$LOG_FILE"' 2>/dev/null || true' || true
done

# ---- clean up the ftrace instance (once; try both tracing and debug) ----
FIRST_POD="${PODS[0]}"
echo -e "\n>> Cleaning ftrace instances once in $FIRST_POD"
kubectl exec "${NSFLAG[@]}" -c "$CONTAINER" "$FIRST_POD" -- sh -lc '
for ROOT in /sys/kernel/tracing /sys/kernel/debug/tracing; do
  [ -d "$ROOT/instances" ] || continue
  for i in "$ROOT"/instances/*; do
    [ -d "$i" ] || continue
    echo 0 > "$i/tracing_on" 2>/dev/null || true
    : > "$i/trace" 2>/dev/null || true
    rmdir "$i" 2>/dev/null || true
  done
done
' || true

echo ">> Done."
