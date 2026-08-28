#!/usr/bin/env bash
# =============================================================================
# Tetragon baseline — collection & measurement
#
# 설계 원칙 (논문 Appendix "Tetragon" / "Measurement" 문단과 대응):
#   1. Tetragon 네이티브 파일 export 로 종료한다.
#      stdout/CRI 중계, gRPC(tetra getevents), export 사이드카를 쓰지 않는다.
#   2. 소비자는 에이전트와 같은 노드에서 돈다.
#      측정 경로에 Kubernetes API server 가 없다 (kubectl logs / exec 금지).
#   3. 예산은 tetragon 컨테이너 하나에만 부여한다 (30m x N).
#   4. 드롭의 분모는 워크로드가 발생시킨 syscall 수다. 도구 카운터는 교차 검증용.
#
# 실행 위치가 서브커맨드마다 다르다.
#
#   [control-plane]  kubectl / helm 이 있는 곳
#     ./exe_v1.sh setup  30    # 사이드카 제거, CPU 예산, ConfigMap, 롤아웃
#     ./exe_v1.sh verify 30    # 클러스터 설정 검증
#
#   [worker]  sys-gen 과 tetragon 이 실제로 도는 노드 (kubectl 불필요)
#     ./exe_v1.sh check  30    # 로그 파일 상태 / 이벤트 타입 분포 확인
#     ./exe_v1.sh start  30    # 수집 시작 (백그라운드)
#     ...워크로드 실행, 발생 syscall 수 기록...
#     ./exe_v1.sh stop   30    # 수집 종료 + 집계
# =============================================================================
set -euo pipefail

N="${2:-30}"                          # application container 수
RB_TOTAL=$(( N * 1048576 ))           # ring buffer 총량 = N MB (bytes)
CPU="$(( N * 30 ))m"                  # CPU 예산 = 30m x N
NS=kube-system
LOG=/var/run/cilium/tetragon/tetragon.log
NSPACE="${NSPACE:-default}"          # 벤치마크 파드가 있는 namespace
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # collect.py / calculate.py 위치
OUT="${OUT_DIR:-$SCRIPT_DIR/out}"                            # 측정 산출물 위치
METRICS_PORT="${METRICS_PORT:-2112}"

mkdir -p "$OUT"
EVENTS="$OUT/syscalls_events.ndjson"
PIDFILE="$OUT/collector.pid"

log() { echo "[*] $*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }
need_cluster() {
  have kubectl && have helm && return 0
  echo "[!] 이 노드에는 kubectl/helm 이 없다. '$1' 은 control-plane 에서 실행할 것." >&2
  exit 1
}

tetra_pod() {
  kubectl -n "$NS" get pods -l app.kubernetes.io/name=tetragon \
    --field-selector "spec.nodeName=$(hostname)" -o name | head -n1
}

# -----------------------------------------------------------------------------
# setup : 파일 export / rate limit 해제 / 버퍼 총량 / 사이드카 제거 / CPU 예산
# -----------------------------------------------------------------------------
cmd_setup() {
  need_cluster setup
  log "N=$N  rb-size-total=${RB_TOTAL}B ($((RB_TOTAL/1048576)) MB)  cpu=${CPU}"

  # 대상 파드가 이 노드에 없으면 여기서 아무것도 관측되지 않는다.
  # Tetragon 은 DaemonSet 이라 각 노드의 에이전트가 자기 노드 syscall 만 본다.
  local target_node
  target_node=$(kubectl get pods -n "$NSPACE" -l app=sys-gen \
    -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null || true)
  if [[ -n "$target_node" ]]; then
    log "수집 대상 노드: ${target_node}  ->  start/stop 은 거기서 실행할 것"
  else
    echo "[!] label app=sys-gen 인 파드를 찾지 못했다 (ns=$NSPACE)." >&2
  fi

  # (1) export 사이드카 제거 + 예산은 tetragon 컨테이너에만.
  #     hubble-export-stdout 은 export 파일을 tail 해서 stdout 으로 되뿜는 중계기일 뿐이므로,
  #     끄더라도 수집되는 이벤트는 동일하다.
  #     차트의 해당 키는 export.mode 이고 "" 가 비활성화다 ('"stdout". "" to disable.').
  #     export.stdout.enabled 같은 존재하지 않는 키는 helm 이 오류 없이 무시하므로 주의.
  helm upgrade tetragon cilium/tetragon -n "$NS" --reuse-values \
    --set export.mode="" \
    --set tetragon.resources.requests.cpu="$CPU" \
    --set tetragon.resources.limits.cpu="$CPU"

  # (2) ConfigMap 은 반드시 helm upgrade **뒤에** 고친다.
  #     helm 3 의 3-way merge 는 차트 템플릿에 존재하는 키(export-allowlist 등)를
  #     템플릿 기본값으로 되돌린다. 순서가 반대면 여기서 넣은 값이 지워진다.
  #
  #     export-allowlist: base sensor 의 노드 전역 process_exec/process_exit 을 배제하고
  #     TracingPolicy 가 만드는 tracepoint 이벤트만 파일에 남긴다.
  #     주의: 이 필터는 유저스페이스 export 단계다. 걸러진 이벤트도 이미 링버퍼를
  #     건너온 뒤이므로, 커널->유저스페이스 구간의 비용과 버퍼 점유는 그대로 발생한다.
  #     export-file-max-size-mb: 기본 10MB 마다 로테이션한다. 부하가 크면 초당 여러 번
  #     갈아치우고, 그때마다 tail 이 이벤트를 놓쳐 delivered 가 심하게 과소집계된다.
  #     사실상 로테이션이 일어나지 않도록 크게 잡는다.
  #     field-filters: export 되는 필드를 최소화한다 (pid / binary / args).
  #     기본 페이로드는 pod·parent 블록 때문에 이벤트당 ~2,470 B 인데, 이 필터를 켜면
  #     ~343 B 로 줄어 직렬화 비용이 크게 감소한다. 즉 baseline 에 유리한 방향이다.
  #     반드시 명시적으로 켜거나 끄고, 그 상태를 결과와 함께 기록할 것.
  #     (helm upgrade 가 차트 템플릿 키를 기본값으로 되돌리므로 여기서 매번 다시 쓴다.)
  #     rb-queue-size: 유저스페이스 내부 채널 크기(이벤트 수, 기본 65535).
  #     큐가 구속 조건이 되지 않도록 크게 잡아, 유실이 예산 배정한 자원에서 나게 한다.
  ALLOW="{\\\"event_set\\\":[\\\"PROCESS_TRACEPOINT\\\"],\\\"namespace\\\":[\\\"${NSPACE}\\\"]}"
  if [[ "${FIELD_FILTER:-1}" == "1" ]]; then
    FF="{\\\"event_set\\\":[\\\"PROCESS_TRACEPOINT\\\"],\\\"fields\\\":\\\"process.pid,process.binary,args\\\",\\\"action\\\":\\\"INCLUDE\\\"}"
  else
    FF=""
  fi
  kubectl -n "$NS" patch cm tetragon-config --type merge -p "{\"data\":{
    \"export-filename\":\"${LOG}\",
    \"export-rate-limit\":\"-1\",
    \"export-allowlist\":\"${ALLOW}\",
    \"field-filters\":\"${FF}\",
    \"rb-queue-size\":\"${RB_QUEUE:-1000000}\",
    \"export-file-max-size-mb\":\"${MAX_MB:-102400}\",
    \"export-file-max-backups\":\"128\",
    \"export-file-compress\":\"false\",
    \"rb-size-total\":\"${RB_TOTAL}\"
  }}"

  # (3) ConfigMap 변경은 재시작해야 반영된다.
  kubectl -n "$NS" rollout restart ds/tetragon
  kubectl -n "$NS" rollout status  ds/tetragon --timeout=180s
  cmd_verify
}

# -----------------------------------------------------------------------------
# verify : 설정이 실제로 적용됐는지 확인 (측정 전 반드시 통과할 것)
# -----------------------------------------------------------------------------
cmd_verify() {
  need_cluster verify
  local pod; pod="$(tetra_pod)"
  [[ -n "$pod" ]] || { echo "[!] 이 노드에 tetragon pod 없음" >&2; exit 1; }

  echo "--- containers (tetragon 하나만 나와야 함) ---"
  kubectl -n "$NS" get "$pod" -o jsonpath='{range .spec.containers[*]}{.name}{"\t"}{.resources.limits.cpu}{"\n"}{end}'

  echo "--- effective config ---"
  kubectl -n "$NS" get cm tetragon-config -o \
    jsonpath='export-filename={.data.export-filename}{"\n"}export-rate-limit={.data.export-rate-limit}{"\n"}rb-size-total={.data.rb-size-total}{"\n"}rb-queue-size={.data.rb-queue-size}{"\n"}export-file-max-size-mb={.data.export-file-max-size-mb}{"\n"}export-allowlist={.data.export-allowlist}{"\n"}field-filters={.data.field-filters}{"\n"}'

  echo "--- tracing policy (CR) ---"
  kubectl get tracingpolicynamespaced -n "$NSPACE" 2>/dev/null || true

  # CR 이 존재하는 것과 센서가 커널에 로드된 것은 다르다.
  # 로드 실패 시 CR 은 그대로 있으면서 이벤트만 안 나온다.
  echo "--- loaded sensors (tetra status) ---"
  kubectl exec -n "$NS" "$pod" -c tetragon -- tetra status 2>/dev/null \
    | grep -iE 'policy|sensor|tracingpolicy|enabled|error' || echo "  (tetra status 조회 실패)"

  # podSelector 가 매칭할 대상이 실제로 도는지.
  echo "--- target pods (label app=sys-gen, ns=$NSPACE) ---"
  kubectl get pods -n "$NSPACE" -l app=sys-gen \
    -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,STATUS:.status.phase 2>/dev/null \
    || echo "  (조회 실패)"

  echo
  echo "[i] 로그 파일 확인은 대상 노드에서: ./exe_v1.sh check $N"
}

# -----------------------------------------------------------------------------
# reset : 측정 전 로그 초기화 (대상 노드에서)
#   본 파일은 truncate 만 한다. rm 으로 지우면 exporter 가 unlink 된 inode 에
#   계속 쓰게 되어 경로가 재생성되지 않고, tetragon 재시작 전까지 로그가 사라진다.
#   로테이션된 백업(.log.1 등)만 rm 한다.
# -----------------------------------------------------------------------------
cmd_reset() {
  if ! sudo test -e "$LOG"; then
    echo "[!] $LOG 가 없다. rm 으로 지웠다면 tetragon 을 재시작해야 재생성된다:" >&2
    echo "    [control-plane] kubectl -n $NS delete pod -l app.kubernetes.io/name=tetragon --field-selector spec.nodeName=$(hostname)" >&2
    exit 1
  fi
  sudo truncate -s 0 "$LOG"
  sudo rm -f "$LOG".*
  log "초기화 완료: $(sudo ls -l "$LOG" | awk '{print $5}')B, 백업 $(sudo ls "$LOG".* 2>/dev/null | wc -l)개"
}

# -----------------------------------------------------------------------------
# check : 대상 노드에서 로그 상태 확인 (kubectl 불필요)
# -----------------------------------------------------------------------------
cmd_check() {
  echo "--- host ---"
  echo "  $(hostname)"

  echo "--- export log ---"
  if sudo test -e "$LOG"; then
    sudo ls -l "$LOG"
  elif sudo test -d "$(dirname "$LOG")"; then
    # exporter 는 첫 이벤트를 쓸 때 파일을 만든다. allowlist 로 걸러진 상태에서
    # 워크로드가 놀고 있으면 매칭되는 이벤트가 0 이라 파일이 아직 없을 수 있다.
    echo "  [i] $LOG 아직 없음. 디렉터리는 존재:"
    sudo ls -la "$(dirname "$LOG")"
    echo "  → 워크로드를 한 번 돌리면 생성된다. 그래도 안 생기면 export-filename/allowlist 확인."
  else
    echo "[!] $(dirname "$LOG") 자체가 없음 — 이 노드에 tetragon 이 안 떠 있다."
    return 1
  fi

  # base sensor 의 노드 전역 이벤트가 섞여 들어오는지 확인.
  # process_tracepoint 외의 타입이 보이면 export-allowlist 가 안 먹은 것이다.
  echo "--- 최근 200줄 이벤트 타입 분포 (process_tracepoint 만 나와야 함) ---"
  sudo tail -n 200 "$LOG" 2>/dev/null     | grep -oE '"(process_exec|process_exit|process_kprobe|process_tracepoint)"'     | sort | uniq -c || echo "  (로그 비어 있음)"

  # 정책이 의도한 파드만 잡고 있는지 (tracepoint 이벤트의 파드 이름 분포)
  echo "--- process_tracepoint 의 파드 분포 (sys-gen 만 나와야 함) ---"
  sudo grep '"process_tracepoint"' "$LOG" 2>/dev/null | tail -n 500     | grep -oE '"name":"[^"]*"' | sort | uniq -c | head || echo "  (tracepoint 이벤트 없음)"

  # 로테이션이 돌면 tail 이 이벤트를 놓친다. 백업 파일이 보이면 설정이 안 먹은 것.
  echo "--- 로테이션 흔적 (백업 파일이 없어야 함) ---"
  sudo ls -l "$(dirname "$LOG")" | grep -v "^total" || true

  echo "--- metrics endpoint ---"
  curl -s -o /dev/null -w "  localhost:${METRICS_PORT}/metrics -> HTTP %{http_code}
"     "localhost:${METRICS_PORT}/metrics" || echo "  (접근 실패)"
}

# 파이프라인 각 단계의 카운터만 "이름 값" 으로 남긴다.
# HELP/TYPE 주석과 라벨 붙은 시계열(tetragon_events_total{...})은 제외한다.
#   received  : 커널에서 실제로 받은 총량   <- 발생량과의 차이가 커널 측 손실
#   lost      : perf ring buffer 유실
#   errors    : 링버퍼 읽기 오류
#   queue_*   : 유저스페이스 내부 채널
METRIC_KEYS='tetragon_observer_ringbuf_events_received_total|tetragon_observer_ringbuf_events_lost_total|tetragon_observer_ringbuf_errors_total|tetragon_observer_ringbuf_queue_events_received_total|tetragon_observer_ringbuf_queue_events_lost_total|tetragon_notify_overflowed_events_total|tetragon_export_ratelimit_events_dropped_total|tetragon_events_exported_total'

snapshot_metrics() {
  curl -s "localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep -vE '^#' \
    | grep -E "^(${METRIC_KEYS}) " \
    | sort > "$1" \
    || echo "[!] metrics 스크레이프 실패 (포트 ${METRICS_PORT})" >&2
}

# -----------------------------------------------------------------------------
# start : 노드 로컬 파일을 노드에서 tail. kubectl / jq / per-event fork 없음.
#   collect.py 가 수신 시각(recv_ns)을 찍는다. 노드에서 돌므로 이벤트의 time 필드와
#   같은 시계 영역이 되어, 지연 = recv_ns - event.time 이 성립한다.
# -----------------------------------------------------------------------------
cmd_start() {
  sudo test -d "$(dirname "$LOG")" || {
    echo "[!] $(dirname "$LOG") 없음 — 이 노드에 tetragon 이 안 떠 있다." >&2; exit 1; }
  sudo test -e "$LOG" || log "[i] $LOG 아직 없음 — tail -F 가 생성되는 대로 따라붙는다."
  [[ -f "$SCRIPT_DIR/collect.py" ]] || { echo "[!] $SCRIPT_DIR/collect.py 없음" >&2; exit 1; }

  snapshot_metrics "$OUT/metrics_before.txt"
  : > "$EVENTS"

  # -n0 : 기존 내용 무시하고 지금부터. stdbuf 로 파이프 버퍼링 제거.
  ( sudo tail -F -n0 "$LOG" | EVENTS_OUT="$EVENTS" stdbuf -oL python3 -u "$SCRIPT_DIR/collect.py" ) &
  echo $! > "$PIDFILE"
  log "collector started (pid $(cat "$PIDFILE")) -> $EVENTS"
  log "이제 워크로드를 실행하고, 발생시킨 syscall 수를 기록해 두십시오."
}

# -----------------------------------------------------------------------------
# stop : 수집 종료 + 집계
# -----------------------------------------------------------------------------
# 파이프라인이 비워질 때까지 대기한다.
#   에이전트 지연이 수 초 단위이므로, 워크로드 종료 직후 stop 하면 아직 밀려 있는
#   이벤트가 잘려나가 delivered 가 과소 집계되고 유실률이 부풀려진다.
#   export 로그 크기가 STABLE_SEC 동안 변하지 않으면 드레인 완료로 본다.
drain_wait() {
  local stable=0 last=-1 cur elapsed=0
  local STABLE_SEC="${DRAIN_STABLE_SEC:-10}" MAX="${DRAIN_MAX_SEC:-180}"
  log "드레인 대기 (로그 크기가 ${STABLE_SEC}s 동안 불변이면 종료, 최대 ${MAX}s)"
  while (( elapsed < MAX )); do
    cur=$(sudo stat -c %s "$LOG" 2>/dev/null || echo 0)
    if [[ "$cur" == "$last" ]]; then
      stable=$((stable+1))
      (( stable >= STABLE_SEC )) && { log "드레인 완료 (${elapsed}s, ${cur}B)"; return 0; }
    else
      stable=0
    fi
    last="$cur"; sleep 1; elapsed=$((elapsed+1))
  done
  echo "[!] ${MAX}s 안에 안정되지 않음 — 파이프라인이 여전히 밀려 있다." >&2
}

cmd_stop() {
  [[ "${SKIP_DRAIN:-0}" == "1" ]] || drain_wait

  if [[ -f "$PIDFILE" ]]; then
    pkill -P "$(cat "$PIDFILE")" 2>/dev/null || true
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE"
  fi
  sleep 1
  snapshot_metrics "$OUT/metrics_after.txt"

  # process_tracepoint 만 센다. base sensor 의 process_exec/exit 는 정책과 무관하게
  # 노드 전역으로 발생하므로 syscall 수집량에 포함하면 안 된다.
  local delivered raw raw_all base_ev
  delivered=$(grep -c '"process_tracepoint"' "$EVENTS" || true)
  raw=$(sudo grep -c '"process_tracepoint"' "$LOG" || true)
  raw_all=$(sudo wc -l "$LOG" | awk '{print $1}')
  base_ev=$(sudo grep -cE '"(process_exec|process_exit)"' "$LOG" || true)

  # 로테이션된 백업까지 합산. 백업이 존재하면 tail 은 그 구간을 놓쳤다는 뜻이므로,
  # delivered(tail) 은 신뢰할 수 없고 파일 합산값을 써야 한다.
  local nrot rot_total
  nrot=$(sudo ls "$LOG"* 2>/dev/null | grep -vc "^${LOG}$" || true)
  rot_total=$(sudo cat "$LOG"* 2>/dev/null | grep -c '"process_tracepoint"' || true)

  echo
  echo "=== Tetragon collection summary (N=$N) ==="
  local bpe=0
  [[ "$raw_all" -gt 0 ]] && bpe=$(( $(sudo stat -c %s "$LOG") / raw_all ))
  echo "  buffer (total)      : $((RB_TOTAL/1048576)) MB"
  echo "  rb-queue-size       : ${RB_QUEUE:-1000000}"
  echo "  field-filter        : ${FIELD_FILTER:-1}  (1=최소 페이로드)"
  echo "  bytes / event       : ${bpe}  [회차 간 이 값이 다르면 설정이 다른 것]"
  echo "  cpu budget          : $CPU"
  echo "  delivered (tail)    : $delivered   [process_tracepoint only]"
  echo "  export log lines    : $raw          [process_tracepoint only]"
  echo "  export log (all)    : $raw_all"
  echo "  rotated backups     : $nrot"
  echo "  all files combined  : $rot_total  [process_tracepoint, 로테이션 포함]"
  if [[ "${nrot:-0}" -gt 0 ]]; then
    echo
    echo "  [!] 로테이션이 발생했다. tail 은 로테이션 구간을 놓치므로"
    echo "      delivered(tail) 대신 'all files combined' 를 쓸 것."
    echo "      지연 통계는 표본이 끊겨 있어 신뢰할 수 없다."
  fi
  echo "  base sensor events  : $base_ev      [exec/exit, 노드 전역 — 수집량에서 제외]"
  echo
  echo "  drop rate = 1 - delivered / <워크로드가 발생시킨 syscall 수>"
  echo "  (분모는 sys_generator 의 발생량. 도구 카운터가 아님.)"
  echo
  echo "--- kernel/queue loss (before -> after) ---"
  paste <(sort "$OUT/metrics_before.txt") <(sort "$OUT/metrics_after.txt") 2>/dev/null \
    | grep -E 'lost|drop' || true
  echo
  # A && B || C 로 쓰면 B(calculate.py) 가 정상적으로 0 아닌 코드로 끝났을 때도
  # C 가 실행되어 "파일 없음" 이라는 거짓 메시지가 찍힌다. if/else 로 분리한다.
  if [[ -f "$SCRIPT_DIR/calculate.py" ]]; then
    EVENTS_OUT="$EVENTS" python3 "$SCRIPT_DIR/calculate.py" || true
  else
    echo "[i] $SCRIPT_DIR/calculate.py 없음 — 지연 집계 생략."
  fi
}

# -----------------------------------------------------------------------------
# drop-sidecar : helm 키를 못 찾았을 때의 임시 조치.
#   DaemonSet 에서 export-stdout 컨테이너를 직접 제거한다.
#   주의: 다음 helm upgrade 때 되살아난다. 측정 직전에 실행할 것.
# -----------------------------------------------------------------------------
cmd_drop_sidecar() {
  local idx
  idx=$(kubectl -n "$NS" get ds/tetragon -o json         | python3 -c 'import json,sys;c=[x["name"] for x in json.load(sys.stdin)["spec"]["template"]["spec"]["containers"]];print(c.index("export-stdout") if "export-stdout" in c else -1)')
  if [[ "$idx" -lt 0 ]]; then echo "[i] export-stdout 없음"; return 0; fi
  kubectl -n "$NS" patch ds/tetragon --type json     -p "[{\"op\":\"remove\",\"path\":\"/spec/template/spec/containers/${idx}\"}]"
  kubectl -n "$NS" rollout status ds/tetragon --timeout=180s
  cmd_verify
}

case "${1:-}" in
  setup)  cmd_setup  ;;
  drop-sidecar) cmd_drop_sidecar ;;
  verify) cmd_verify ;;
  check)  cmd_check  ;;
  reset)  cmd_reset  ;;
  start)  cmd_start  ;;
  stop)   cmd_stop   ;;
  *) echo "usage: $0 {setup|drop-sidecar|verify|check|reset|start|stop} [N]   (default N=30)" >&2; exit 1 ;;
esac
