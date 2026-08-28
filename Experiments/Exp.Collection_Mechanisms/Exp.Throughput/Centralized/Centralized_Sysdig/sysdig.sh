#!/usr/bin/env bash
set -euo pipefail

# =========================
# audit_syscalls_by_comm.sh
# - collect the syscalls of one process (comm) with auditd
# - the rules are installed by exe (executable path) rather than by comm
# - over the collection window, count SYSCALL records, compute EPS, and detect DAEMON_LOST
#
# Requirements:
#  1) preferably run on the host (in a container, /var/log/audit and auditctl/ausearch must be usable)
#  2) auditd must be running with kernel auditing enabled (enabled=1)
# =========================

COMM="${1:-sys_generator}"   # target process name (comm)
DUR="${2:-10}"               # collection (wait) time in seconds
KEY="${3:-sysgen_trace}"     # audit rule key
VERBOSE="${VERBOSE:-1}"      # 1: show the logs

# global (the detected architecture)
ARCHES=()

# ---------- utilities ----------
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
  # confirm enabled=1
  if ! auditctl -s 2>/dev/null | grep -q '^enabled[[:space:]]\+1'; then
    err "auditd is not enabled (enabled!=1). Check kernel boot param 'audit=1' or policies."
    exit 1
  fi
}

detect_arches() {
  # start safely with b64 only (extend to b32 separately if needed)
  ARCHES=(b64)
  log "arches: ${ARCHES[*]}"
}

dump_syscall_list() {
  # the full list of usable syscall names
  ausyscall --dump 2>/dev/null | awk 'NR>1 {print $2}' | sort -u
}

# collect the unique exe paths of the PIDs running as COMM
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

# install the rules for one exe path (split into small chunks)
install_rules_for_exe() {
  local exe_path="$1"    # an absolute path such as /app/sys_generator
  local syscall_list="$2"
  local rc=0
  local MAX_PER_RULE=32

  for arch in "${ARCHES[@]}"; do
    local -a chunk=()
    local cnt=0
    # the list is whitespace separated tokens
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

# wrapper that installs the rules for several exe paths
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
  # remove the rules tagged with KEY
  auditctl -D -k "$KEY" >/dev/null 2>&1 || true
}

count_events_in_window() {
  local start_ts="$1"  # "YYYY-MM-DD HH:MM:SS"
  local end_ts="$2"
  # count SYSCALL records only (excluding auxiliary records such as headers and paths)
  ausearch -k "$KEY" --start "$start_ts" --end "$end_ts" -m SYSCALL 2>/dev/null \
    | grep -c '^type=SYSCALL' || true
}

check_lost_events() {
  local start_ts="$1" end_ts="$2"
  # whether a DAEMON_LOST message is present
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

  # obtain the syscall name list
  local SYSCALLS
  SYSCALLS="$(dump_syscall_list)"
  if [[ -z "$SYSCALLS" ]]; then
    err "failed to dump syscall list via ausyscall"
    exit 1
  fi

  # the currently running PIDs (for reference)
  local -a PIDS=()
  if command -v pgrep >/dev/null 2>&1; then
    mapfile -t PIDS < <(pgrep -x "$COMM" || true)
  else
    mapfile -t PIDS < <(ps -C "$COMM" -o pid= | awk '{print $1}' || true)
  fi
  log "current PIDs : ${PIDS[*]:-<none>}"

  # clean up the rules on exit
  trap 'delete_rules || true' EXIT

  # remove any existing rules with the same KEY, then install
  delete_rules || true
  if ! install_rules "$SYSCALLS"; then
    echo "[!] Installing audit rules failed." >&2
    echo "    - check: 'auditctl -s' enabled=1, auditd running" >&2
    echo "    - whether the process is running (its path has to be extracted)" >&2
    exit 1
  fi

  # collection window
  local start_ts end_ts
  start_ts="$(date '+%Y-%m-%d %H:%M:%S')"
  log "collection start: ${start_ts}"
  sleep "$DUR"
  end_ts="$(date '+%Y-%m-%d %H:%M:%S')"
  log "collection end  : ${end_ts}"

  # remove the rules (the trap removes them once more)
  delete_rules || true

  # event count / EPS / losses
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
