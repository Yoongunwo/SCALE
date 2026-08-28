#!/usr/bin/env bash
set -euo pipefail

# =========================
# audit_syscalls_by_comm.sh
# - auditd로 특정 프로세스(comm)의 syscalls 수집
# - 규칙은 comm 대신 exe(실행파일 경로) 기준으로 설치
# - 수집 시간 동안 SYSCALL 카운트/초당(EPS) 및 DAEMON_LOST 감지
#
# 요구사항:
#  1) 호스트에서 실행 권장 (컨테이너면 /var/log/audit 및 auditctl/ausearch 사용 가능해야 함)
#  2) auditd 실행 중이어야 하며 커널 audit 켜짐 (enabled=1)
# =========================

COMM="${1:-sys_generator}"   # 대상 프로세스명 (comm)
DUR="${2:-10}"               # 수집(대기) 시간(초)
KEY="${3:-sysgen_trace}"     # audit rule key
VERBOSE="${VERBOSE:-1}"      # 1: 로그 노출

# 전역(검출된 아키)
ARCHES=()

# ---------- 유틸 ----------
err(){ echo "ERR: $*" >&2; }
log(){ [[ "$VERBOSE" == "1" ]] && echo "[*] $*"; }

require_cmds() {
  local miss=0
  for c in auditctl ausearch ausyscall awk sed grep date readlink pgrep ps; do
    command -v "$c" >/dev/null 2>&1 || { err "missing cmd: $c"; miss=1; }
  done
  [[ $miss -eq 0 ]] || exit 1
}

check_auditd() {
  if ! pgrep -x auditd >/dev/null 2>&1; then
    err "auditd not running. Start it (e.g., 'sudo systemctl start auditd')."
    exit 1
  fi
  # enabled=1 확인
  if ! auditctl -s 2>/dev/null | grep -q '^enabled[[:space:]]\+1'; then
    err "auditd is not enabled (enabled!=1). Check kernel boot param 'audit=1' or policies."
    exit 1
  fi
}

detect_arches() {
  # 안전하게 b64만 먼저. (필요 시 b32는 별도로 확장)
  ARCHES=(b64)
  log "arches: ${ARCHES[*]}"
}

dump_syscall_list() {
  # 사용가능한 syscall 이름 전체 목록
  ausyscall --dump 2>/dev/null | awk 'NR>1 {print $2}' | sort -u
}

# COMM으로 실행 중인 PID들의 exe 경로를 유니크 수집
collect_exe_paths_for_comm() {
  local comm="$1"
  local -a pids=()
  if command -v pgrep >/dev/null 2>&1; then
    mapfile -t pids < <(pgrep -x "$comm" || true)
  else
    mapfile -t pids < <(ps -C "$comm" -o pid= | awk '{print $1}' || true)
  fi
  [[ ${#pids[@]} -eq 0 ]] && return 0

  local -A seen=()
  local exe real
  for pid in "${pids[@]}"; do
    exe="/proc/$pid/exe"
    if [[ -L "$exe" ]]; then
      real="$(readlink -f "$exe" 2>/dev/null || true)"
      [[ -n "$real" ]] && seen["$real"]=1
    fi
  done

  for k in "${!seen[@]}"; do
    echo "$k"
  done
}

# exe 경로 하나에 대해 규칙 설치 (작은 청크로 분할)
install_rules_for_exe() {
  local exe_path="$1"    # /app/sys_generator 같은 절대경로
  local syscall_list="$2"
  local rc=0
  local MAX_PER_RULE=32

  for arch in "${ARCHES[@]}"; do
    local -a chunk=()
    local cnt=0
    # 리스트는 공백으로 구분된 토큰들
    for sc in $syscall_list; do
      chunk+=("$sc"); ((cnt++))
      if (( cnt >= MAX_PER_RULE )); then
        set +e
        auditctl -a always,exit -F arch="$arch" -F exe="$exe_path" $(printf ' -S %s' "${chunk[@]}") -k "$KEY"
        rc=$?
        set -e
        if (( rc != 0 )); then
          echo "FAILED: auditctl add rules (arch=$arch, exe=$exe_path, chunk=${#chunk[@]})" >&2
          auditctl -s || true
          printf '  chunk: %s\n' "${chunk[*]}" >&2
          return $rc
        fi
        cnt=0; chunk=()
      fi
    done
    if (( ${#chunk[@]} > 0 )); then
      set +e
      auditctl -a always,exit -F arch="$arch" -F exe="$exe_path" $(printf ' -S %s' "${chunk[@]}") -k "$KEY"
      rc=$?
      set -e
      if (( rc != 0 )); then
        echo "FAILED: auditctl add rules (arch=$arch, exe=$exe_path, chunk=${#chunk[@]})" >&2
        auditctl -s || true
        printf '  chunk: %s\n' "${chunk[*]}" >&2
        return $rc
      fi
    fi
  done
}

# 여러 exe 경로에 대해 규칙 설치 래퍼
install_rules() {
  local syscall_list="$1"
  local -a exes=()
  mapfile -t exes < <(collect_exe_paths_for_comm "$COMM")
  if [[ ${#exes[@]} -eq 0 ]]; then
    echo "WARN: no running PIDs for comm=$COMM; cannot derive exe path(s). Start the process first." >&2
    return 1
  fi
  log "exe paths: ${exes[*]}"
  for ex in "${exes[@]}"; do
    install_rules_for_exe "$ex" "$syscall_list" || return $?
  done
}

delete_rules() {
  # KEY로 태깅된 규칙들 제거
  auditctl -D -k "$KEY" >/dev/null 2>&1 || true
}

count_events_in_window() {
  local start_ts="$1"  # "YYYY-MM-DD HH:MM:SS"
  local end_ts="$2"
  # SYSCALL 레코드 개수로 카운트(헤더/경로 등 부수 레코드 제외)
  ausearch -k "$KEY" --start "$start_ts" --end "$end_ts" -m SYSCALL 2>/dev/null \
    | grep -c '^type=SYSCALL' || true
}

check_lost_events() {
  local start_ts="$1" end_ts="$2"
  # DAEMON_LOST 메시지 존재 여부
  if ausearch --start "$start_ts" --end "$end_ts" -m DAEMON_LOST >/dev/null 2>&1; then
    echo 1
  else
    echo 0
  fi
}

main() {
  require_cmds
  check_auditd
  detect_arches

  log "target comm : ${COMM}"
  log "duration    : ${DUR}s"
  log "rule key    : ${KEY}"

  # syscall 이름 목록 획득
  local SYSCALLS
  SYSCALLS="$(dump_syscall_list)"
  if [[ -z "$SYSCALLS" ]]; then
    err "failed to dump syscall list via ausyscall"
    exit 1
  fi

  # 현재 실행 중인 PIDs (참고용)
  local -a PIDS=()
  if command -v pgrep >/dev/null 2>&1; then
    mapfile -t PIDS < <(pgrep -x "$COMM" || true)
  else
    mapfile -t PIDS < <(ps -C "$COMM" -o pid= | awk '{print $1}' || true)
  fi
  log "current PIDs : ${PIDS[*]:-<none>}"

  # 종료 시 규칙 정리
  trap 'delete_rules || true' EXIT

  # 기존 동일 KEY 룰 제거 후 설치
  delete_rules || true
  if ! install_rules "$SYSCALLS"; then
    echo "[!] Installing audit rules failed." >&2
    echo "    - 확인: 'auditctl -s' enabled=1, auditd running" >&2
    echo "    - 프로세스가 실행 중인지(경로 추출 필요)" >&2
    exit 1
  fi

  # 수집 구간
  local start_ts end_ts
  start_ts="$(date '+%Y-%m-%d %H:%M:%S')"
  log "collection start: ${start_ts}"
  sleep "$DUR"
  end_ts="$(date '+%Y-%m-%d %H:%M:%S')"
  log "collection end  : ${end_ts}"

  # 룰 제거 (trap에서도 한 번 더 제거됨)
  delete_rules || true

  # 이벤트 개수 / EPS / 유실
  local total eps lost
  total="$(count_events_in_window "$start_ts" "$end_ts")"
  total="${total:-0}"
  if (( DUR > 0 )); then
    eps="$(awk -v n="$total" -v d="$DUR" 'BEGIN{printf "%.2f",(d>0)?(n/d):0}')"
  else
    eps="0.00"
  fi
  lost="$(check_lost_events "$start_ts" "$end_ts")"

  echo
  echo "=== auditd syscall summary ==="
  echo "comm               : ${COMM}"
  echo "arches             : ${ARCHES[*]}"
  echo "duration(sec)      : ${DUR}"
  echo "events(SYSCALL)    : ${total}"
  echo "EPS                : ${eps}"
  echo "lost_detected      : ${lost}  (1=some DAEMON_LOST in window)"
}

main "$@"
