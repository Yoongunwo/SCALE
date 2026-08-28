#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./trace_postmark_by_pid.sh [DURATION_SEC] [OUT_FILE] [PROC_NAME]
# Example:
#   ./trace_postmark_by_pid.sh 5 syscall_postmark.scap postmark

DUR="${1:-15}"                        # capture time (seconds)
OUT="${2:-syscall_postmark.scap}"    # output file (sysdig -w writes the scap format)
NAME="${3:-postmark}"                # process name (exact match)

# 1) collect the target PIDs
if command -v pgrep >/dev/null 2>&1; then
  mapfile -t PIDS < <(pgrep -x "$NAME" || true)
else
  mapfile -t PIDS < <(ps -C "$NAME" -o pid= | awk '{print $1}' || true)
fi

if ((${#PIDS[@]}==0)); then
  echo "ERR: process '$NAME' not found on this node." >&2
  exit 1
fi

# 2) build the PID OR filter
FILTER='('
for i in "${!PIDS[@]}"; do
  (( i > 0 )) && FILTER+=" or "
  FILTER+="proc.pid=${PIDS[$i]}"
done
FILTER+=')'

echo "[*] Target process name : $NAME"
echo "[*] PIDs                 : ${PIDS[*]}"
echo "[*] Sysdig filter        : evt.dir=\"<\" and $FILTER"
echo "[*] Duration             : ${DUR}s"
echo "[*] Output (scap)        : $OUT"
echo

# 3) save the capture (-w writes scap; see the note below if text is needed)
sysdig -w "$OUT" 'evt.dir="<" and '"$FILTER"

# 4) summarize the total captured count (quick check: rerun the same filter with -pc; 0s is effectively instant)
# SUMMARY="$(sysdig -r "$OUT" | wc -l)"
# echo
# echo "[*] Summary: ${SUMMARY:-Captured Events: (unknown)}"

# ---- notes ----
# to store text lines instead (real-time format):
# sysdig -M "$DUR" -p "%evt.time %proc.pid %proc.name %evt.type %evt.args" \
#   'evt.dir="<" and '"$FILTER" | tee syscall_postmark.txt
