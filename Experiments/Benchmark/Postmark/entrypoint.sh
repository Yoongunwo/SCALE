#!/usr/bin/env bash
set -euo pipefail

# ========================
# Config preparation
# ========================
if [[ -s /config/pm.conf ]]; then
  CONF=/config/pm.conf
else
  CONF=/tmp/pm.conf
  cat > "$CONF" <<EOF
set size ${PM_SIZE_MIN_KB:-5} ${PM_SIZE_MAX_KB:-512}
set number ${PM_NUMBER:-500}
set transactions ${PM_TRANSACTIONS:-25000}
set read ${PM_READ:-512}
set write ${PM_WRITE:-512}
set location ${PM_LOCATION:-/data}
set seed ${PM_SEED:-42}
run
quit
EOF
fi

MODE=${PM_MODE:-once}             # once | loop | sleep | gate
INTERVAL=${PM_INTERVAL:-10}       # loop 간격(초)
START_FILE="${PM_START_FILE:-}"   # gate/sleep 모드에서 파일 트리거 경로(선택)

echo $$ > /tmp/sh.pid || true
log() { echo "[$(date +%H:%M:%S)] $*"; }

gate_once() {
  command -v postmark >/dev/null || { log "postmark not found"; tail -f /dev/null; }
  postmark "$CONF" &
  PM_PID=$!
  echo "$PM_PID" > /tmp/pm.pid
  log "spawned postmark pid=$PM_PID (STOP for registration)"

  # /proc 엔트리 대기
  for i in $(seq 1 100); do
    [[ -e "/proc/$PM_PID/exe" ]] && break
    sleep 0.02
  done

  if readlink -f "/proc/$PM_PID/exe" 2>/dev/null | grep -q '/postmark$'; then
    log "confirmed /proc/$PM_PID/exe -> postmark"
  else
    log "WARN: /proc/$PM_PID/exe check failed or not postmark"
  fi

  kill -STOP "$PM_PID" || { log "failed to STOP $PM_PID"; return 1; }
  log "postmark($PM_PID) STOPPED. Register then send SIGCONT."

  if [[ -n "$START_FILE" ]]; then
    log "waiting for file trigger: $START_FILE"
    while [[ ! -f "$START_FILE" ]]; do sleep 0.1; done
    rm -f "$START_FILE" || true
    log "file detected. sending SIGCONT to $PM_PID"
    kill -CONT "$PM_PID" || true
  else
    log "manual trigger example: kill -CONT \$(cat /tmp/pm.pid)"
  fi

  wait "$PM_PID"
  log "postmark($PM_PID) finished."
}

case "$MODE" in
  gate)
    GATE_LOOP="${PM_GATE_LOOP:-0}"   # 1이면 반복, 0이면 1회
    if [[ "$GATE_LOOP" = "1" ]]; then
      while :; do
        gate_once || true
      done
    else
      gate_once
    fi
    ;;

  loop)
    log "loop mode: every ${INTERVAL}s"
    while true; do
      postmark "$CONF" || true
      sleep "$INTERVAL"
    done
    ;;

  sleep)
    # 변경: gate와 동일하게 STOP→SIGCONT 대기 후 실행, 완료 후 컨테이너 유지
    log "sleep mode: STOP→CONT gate, then keep alive"
    gate_once || true
    log "completed. keeping container alive..."
    tail -f /dev/null
    ;;

  *)
    log "once mode: run and exit"
    exec postmark "$CONF"
    ;;
esac
