#!/usr/bin/env bash
# resume_postmark.sh
# read /tmp/pm.pid stored in the sys-gen container of the exp* Pods and send SIGCONT

set -euo pipefail

NS="${1:-}"             # first argument: namespace (current context if omitted)
PREFIX="${2:-exp}"      # second argument: pod name prefix (default: exp)
CONTAINER="${3:-sys-gen}"  # third argument: container name (default: sys-gen)

K="kubectl"
[[ -n "$NS" ]] && K+=" -n $NS"

# keep only the Running PREFIX* Pods
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
  # read the container PID
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
