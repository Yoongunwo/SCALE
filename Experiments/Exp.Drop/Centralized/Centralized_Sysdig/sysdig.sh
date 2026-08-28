#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./trace_postmark_by_pid.sh [DURATION_SEC] [OUT_FILE] [PROC_NAME]
# Example:
#   ./trace_postmark_by_pid.sh 5 syscall_postmark.scap postmark

DUR="${1:-15}"                        # 캡처 시간(초)
OUT="${2:-syscall_postmark.scap}"    # 출력 파일 (sysdig -w 는 scap 포맷)
NAME="${3:-postmark}"                # 프로세스 이름(정확 매칭)

# 1) 대상 PID 수집
if command -v pgrep >/dev/null 2>&1; then
  mapfile -t PIDS < <(pgrep -x "$NAME" || true)
else
  mapfile -t PIDS < <(ps -C "$NAME" -o pid= | awk '{print $1}' || true)
fi

if ((${#PIDS[@]}==0)); then
  echo "ERR: process '$NAME' not found on this node." >&2
  exit 1
fi

# 2) PID OR 필터 생성
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

# 3) 캡처 저장 (-w 는 scap 포맷; 텍스트가 필요하면 아래 주석 참고)
sysdig -w "$OUT" 'evt.dir="<" and '"$FILTER"

# 4) 총 캡처 개수 요약(빠른 확인: -pc로 같은 필터 재실행, 짧게 0초≈즉시)
# SUMMARY="$(sysdig -r "$OUT" | wc -l)"
# echo
# echo "[*] Summary: ${SUMMARY:-Captured Events: (unknown)}"

# ---- 참고 ----
# 텍스트 라인으로 저장하고 싶으면(실시간 포맷):
# sysdig -M "$DUR" -p "%evt.time %proc.pid %proc.name %evt.type %evt.args" \
#   'evt.dir="<" and '"$FILTER" | tee syscall_postmark.txt
