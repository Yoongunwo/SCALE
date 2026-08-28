#!/usr/bin/env bash
# audit_track_pids.sh (final version)
# usage: sudo ./audit_track_pids.sh [process_name] [duration_sec]
# ex)     sudo ./audit_track_pids.sh sys_generator 10

set -euo pipefail

NAME="${1:-sys_generator}"
DUR="${2:-10}"

# --- 필수 커맨드/권한 체크 ---
need_cmds=(auditctl ausearch awk grep date pgrep ps)
for c in "${need_cmds[@]}"; do
  command -v "$c" >/dev/null 2>&1 || { echo "ERR: missing cmd: $c" >&2; exit 1; }
done
if [[ $EUID -ne 0 ]]; then
  echo "ERR: must run as root" >&2
  exit 1
fi

# --- auditd 상태 확인 ---
if ! pgrep -x auditd >/dev/null 2>&1; then
  echo "ERR: auditd not running (try: systemctl start auditd)" >&2
  exit 1
fi

# --- PID 수집 (정확 매칭) ---
if ! pgrep -x "$NAME" >/dev/null 2>&1; then
    mapfile -t PIDS < <(ps -eo pid=,comm= | awk -v n="$NAME" '$2==n{print $1}')
else
    mapfile -t PIDS < <(pgrep -x "$NAME")
fi

if [[ ${#PIDS[@]} -eq 0 ]]; then
  echo "No '$NAME' processes found."
  exit 1
fi
echo "Found $NAME PIDs: ${PIDS[*]}"

# --- 아키텍처 결정 ---
ARCHES=(b64)
if uname -m | grep -Eq 'x86_64|amd64'; then
  ARCHES=(b64 b32)
fi

# --- 커널/데몬 설정 확인 ---
st="$(auditctl -s 2>/dev/null || true)"
echo "$st" | grep -q 'enabled 1' || {
  echo "ERR: audit not enabled (see 'auditctl -s')" >&2; exit 1;
}
if echo "$st" | grep -q 'immutable 1'; then
  echo "ERR: audit rules are immutable. Reboot or disable immutability." >&2
  exit 1
fi

# --- rule 키 생성 ---
make_key() { echo "pid_${1}_trace_$$"; }

# --- rule 설치/삭제 함수 ---
install_rules_for_pid() {
  local pid="$1" key="$2"
  for arch in "${ARCHES[@]}"; do
    if ! auditctl -a always,exit -F arch="$arch" -F pid="$pid" -S all -k "$key"; then
      echo "ERR: Failed to add audit rule for pid=$pid arch=$arch" >&2
      return 1
    fi
  done
  return 0
}

delete_rules_by_key() {
  local key="$1"
  auditctl -D -k "$key" >/dev/null 2>&1 || true
}

# --- 모든 PID에 룰 설치 ---
declare -A KEYS
trap 'echo "Cleaning up rules..."; for k in "${KEYS[@]:-}"; do delete_rules_by_key "$k"; done' EXIT HUP INT TERM

for pid in "${PIDS[@]}"; do
  key="$(make_key "$pid")"
  if ! install_rules_for_pid "$pid" "$key"; then
    exit 1
  fi
  KEYS["$pid"]="$key"
  echo "Successfully installed rules for PID $pid with key $key"
done

# --- 수집 구간 ---
echo "Auditing for $DUR seconds..."
START_TIME_FOR_AUSEARCH="now"
sleep "$DUR"
echo "Audit finished."

# --- 룰 제거 ---
for k in "${KEYS[@]}"; do
  delete_rules_by_key "$k"
done
trap - EXIT HUP INT TERM

# --- 결과 집계 ---
echo "Aggregating results..."

UNIQUE_KEYS=$(printf -- '-k %s ' "${KEYS[@]}")

LINES="$(ausearch $UNIQUE_KEYS -ts $START_TIME_FOR_AUSEARCH -m SYSCALL -i 2>/dev/null \
      | grep -c '^type=SYSCALL' || true)"

DROPS="$(ausearch -ts $START_TIME_FOR_AUSEARCH -m DAEMON_LOST -i 2>/dev/null | grep -c '^type=DAEMON_LOST' || true)"

# --- 출력 ---
printf "\n--- Results ---\n"
printf "%-15s %-10s %-10s\n" "duration(sec)" "lines" "drops"
printf "%-15s %-10s %-10s\n" "$DUR" "$LINES" "$DROPS"
