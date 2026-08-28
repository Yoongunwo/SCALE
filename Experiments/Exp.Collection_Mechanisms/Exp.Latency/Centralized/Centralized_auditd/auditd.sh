#!/usr/bin/env bash
# audit_track_pids.sh
# usage: sudo ./audit_track_pids.sh [process_name] [duration_sec]
# ex)    sudo ./audit_track_pids.sh sys_generator 10
#
# - 대상 프로세스의 모든 스레드(TID)에 대해 -F pid=<tid> 규칙 설치
# - 고유 key(실행마다 다름)로만 ausearch → 시간 파싱 이슈 회피
# - 출력: 수집 길이(usec), lines(수집된 SYSCALL 수), drops(가능하면)
# - 실패 내성: auditctl/ausearch 부분 실패해도 스크립트 자체는 계속 진행

set -u  # unset 변수만 잡고, 나머지는 실패해도 중단하지 않음
shopt -s nullglob

NAME="${1:-sys_generator}"
DUR="${2:-20}"      # seconds

need_cmds=(auditctl ausearch pgrep ps awk grep date)
for c in "${need_cmds[@]}"; do
  if ! command -v "$c" >/dev/null 2>&1; then
    echo "ERR: missing cmd: $c" >&2
    exit 1
  fi
done

if [[ $EUID -ne 0 ]]; then
  echo "ERR: must run as root" >&2
  exit 1
fi

# --- auditd 상태 ---
if ! pgrep -x auditd >/dev/null 2>&1; then
  echo "ERR: auditd not running (try: systemctl start auditd)" >&2
  exit 1
fi

st="$(auditctl -s 2>/dev/null || true)"
echo "$st" | grep -q 'enabled 1' || {
  echo "ERR: audit not enabled (see 'auditctl -s')" >&2
  exit 1
}
if echo "$st" | grep -q 'immutable 1'; then
  echo "ERR: audit rules are immutable. Reboot or disable immutability." >&2
  exit 1
fi

# --- 대상 TGID 수집 ---
if ! pgrep -x "$NAME" >/dev/null 2>&1; then
  mapfile -t TGIDS < <(ps -eo pid=,comm= | awk -v n="$NAME" '$2==n{print $1}')
else
  mapfile -t TGIDS < <(pgrep -x "$NAME")
fi

if [[ ${#TGIDS[@]} -eq 0 ]]; then
  echo "No '$NAME' processes found."
  exit 0
fi
echo "[INFO] Found $NAME TGIDs: ${TGIDS[*]}"

# --- 설치용 고유 key & 정리 트랩 ---
KEY="tid_trace_$$"
cleanup() {
  echo "[INFO] Cleaning rules (key='$KEY')..."
  auditctl -D -k "$KEY" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

ARCHES=(b64)  # 필요시 b32 추가: ARCHES=(b64 b32)

# --- 규칙 설치 (모든 스레드 TID) ---
INSTALLED_CNT=0
for tgid in "${TGIDS[@]}"; do
  for d in /proc/"$tgid"/task/[0-9]*; do
    [[ -d "$d" ]] || continue
    tid="${d##*/}"
    for arch in "${ARCHES[@]}"; do
      # 실패해도 계속 진행
      auditctl -a always,exit -F arch="$arch" -F pid="$tid" -S all -k "$KEY" >/dev/null 2>&1 || true
    done
    ((INSTALLED_CNT++))
  done
done
echo "[INFO] Installed $INSTALLED_CNT pid rules (by TIDs) with key='$KEY'"

# (옵션) 설치 확인(실패해도 무시)
echo "[INFO] Current rules with key:"
auditctl -l 2>/dev/null | grep -F "key=$KEY" || true

# --- 수집 대기 ---
START_EPOCH="$(date +%s)"
sleep "$DUR"
END_EPOCH="$(date +%s)"

# --- 집계 (이번 key만) ---
LINES="$(ausearch -k "$KEY" -m SYSCALL 2>/dev/null | grep -c '^type=SYSCALL' || true)"

# drops는 시간 창 필요 → 유닉스 epoch로 시도, 실패 시 0
DROPS="0"
if ausearch -m DAEMON_LOST -ts "@$START_EPOCH" -te "@$END_EPOCH" >/dev/null 2>&1; then
  DROPS="$(ausearch -m DAEMON_LOST -ts "@$START_EPOCH" -te "@$END_EPOCH" 2>/dev/null | grep -c '^type=DAEMON_LOST' || true)"
fi

# --- 출력(μs) ---
DUR_US=$(( DUR * 1000000 ))
printf "\n--- Results ---\n"
printf "%-18s %-10s %-10s\n" "duration(usec)" "lines" "drops"
printf "%-18s %-10s %-10s\n" "$DUR_US" "$LINES" "$DROPS"

# 샘플(사람 읽기용)
echo
echo "Sample records (first 6, decoded):"
ausearch -k "$KEY" -m SYSCALL -i 2>/dev/null | head -n 30 || true
