#!/usr/bin/env bash
# =============================================================================
# Tracee baseline — collection & measurement
#
# 설계 원칙 (논문 Appendix "Tracee" / "Measurement" 문단과 대응):
#   1. Tracee 네이티브 파일 출력으로 종료한다.
#      stdout/CRI 중계(kubectl logs)를 쓰지 않는다. CRI 는 16KB 에서 줄을 쪼개고
#      kubelet 로테이션(기본 10MB x 5)으로 조용히 유실시킨다.
#   2. 소비자는 에이전트와 같은 노드에서 돈다.
#      측정 경로에 Kubernetes API server 가 없다 (kubectl logs / exec 금지).
#   3. 예산은 tracee 컨테이너 하나에만 부여한다 (30m x N).
#   4. 드롭의 분모는 워크로드가 발생시킨 syscall 수다. 도구 카운터는 교차 검증용.
#
# perf buffer 에 대하여
#   Tracee 는 온라인 CPU 마다 perf buffer 를 하나씩 잡고, 크기는 "페이지 수/CPU"
#   로 지정한다. 게다가 2 의 거듭제곱이어야 한다. 따라서 총량을 N MB 로 정확히
#   맞출 수 없다. 여기서는 노드 vCPU 수를 읽어 N MB 이상이 되는 최소 2^k 를 쓴다.
#   즉 Tracee 는 규칙이 요구하는 것보다 적지 않은 버퍼를 받는다 (baseline 에 유리).
#
# 실행 위치가 서브커맨드마다 다르다.
#
#   [control-plane]  kubectl 이 있는 곳
#     ./exe_v1.sh setup  30    # 정책 적용, CPU 예산, 파일 출력, 롤아웃
#     ./exe_v1.sh verify 30    # 클러스터 설정 검증
#
#   [worker]  sys-gen 과 tracee 가 실제로 도는 노드 (kubectl 불필요)
#     ./exe_v1.sh check  30    # 로그 파일 상태 / 이벤트 분포 확인
#     ./exe_v1.sh reset  30    # 측정 전 로그 초기화
#     ./exe_v1.sh start  30    # 수집 시작 (백그라운드)
#     ...워크로드 실행, 발생 syscall 수 기록...
#     ./exe_v1.sh stop   30    # 수집 종료 + 집계
# =============================================================================
set -euo pipefail

N="${2:-30}"                              # application container 수
CPU="$(( N * 30 ))m"                      # CPU 예산 = 30m x N
NS="${TRACEE_NS:-tracee}"                 # tracee DaemonSet 의 namespace
DS="${TRACEE_DS:-tracee}"
NSPACE="${NSPACE:-default}"               # 벤치마크 파드가 있는 namespace
EVENT="${EVENT:-sys_enter}"               # 수집 대상 이벤트

# Tracee 컨테이너 안에서 쓰기 가능한 hostPath. 차트가 마운트하는 경로여야 한다.
# verify 가 실제 마운트 목록을 출력하니 다르면 TRACEE_OUT_DIR 로 덮어쓸 것.
OUTDIR_NODE="${TRACEE_OUT_DIR:-/tmp/tracee}"
LOG="$OUTDIR_NODE/events.json"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # collect.py / calculate.py 위치
OUT="${OUT_DIR:-$SCRIPT_DIR/out}"                            # 측정 산출물 위치
METRICS_PORT="${METRICS_PORT:-3366}"                         # Tracee Prometheus 기본 포트

mkdir -p "$OUT"
EVENTS="$OUT/syscalls_events.ndjson"
PIDFILE="$OUT/collector.pid"

log() { echo "[*] $*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }
need_cluster() {
  have kubectl && return 0
  echo "[!] 이 노드에는 kubectl 이 없다. '$1' 은 control-plane 에서 실행할 것." >&2
  exit 1
}

tracee_pod() {
  kubectl -n "$NS" get pods -l app.kubernetes.io/name=tracee \
    --field-selector "spec.nodeName=$(hostname)" -o name 2>/dev/null | head -n1
}

# perf-buffer-size 계산: 총량이 N MB 이상이 되는 최소 2^k 페이지/CPU.
#   pages = ceil(N * 1MB / (C * 4KB)) = ceil(256N / C), 이를 2 의 거듭제곱으로 올림.
calc_pages() {
  local C="${VCPU:-$(nproc 2>/dev/null || echo 8)}"
  python3 -c '
import sys, math
N, C = int(sys.argv[1]), int(sys.argv[2])
need = int(math.ceil(256.0 * N / C))
p = 1
while p < need: p *= 2
print("%d %d %.2f" % (p, C, p * 4096 * C / 1048576.0))
' "$N" "$C"
}

# -----------------------------------------------------------------------------
# setup : 정책 적용 / 파일 출력 / perf buffer / CPU 예산 / 롤아웃
# -----------------------------------------------------------------------------
cmd_setup() {
  need_cluster setup

  # 대상 노드를 먼저 정한다. perf buffer 는 "대상 노드"의 온라인 CPU 마다 하나씩
  # 잡히는데, setup 은 control-plane 에서 돌기 때문에 로컬 nproc 을 쓰면 틀린다.
  # 두 노드의 vCPU 수가 다르면 버퍼 총량이 통째로 어긋난다.
  local target_node node_cpu
  target_node=$(kubectl get pods -n "$NSPACE" -l app=sys-gen \
    -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null || true)
  if [[ -n "$target_node" ]]; then
    node_cpu=$(kubectl get node "$target_node" -o jsonpath='{.status.capacity.cpu}' 2>/dev/null || true)
    [[ -n "$node_cpu" ]] && export VCPU="$node_cpu"
    log "수집 대상 노드: ${target_node} (vCPU=${VCPU:-?})  ->  check/reset/start/stop 은 거기서 실행할 것"
  else
    echo "[!] label app=sys-gen 인 파드를 찾지 못했다 (ns=$NSPACE). 로컬 nproc 으로 계산한다." >&2
  fi

  read -r PAGES VCPUS TOTMB <<<"$(calc_pages)"
  log "N=$N  cpu=$CPU  perf-buffer-size=${PAGES} pages/CPU x ${VCPUS} vCPU = ${TOTMB} MB (target ${N} MB)"

  # (1) 정책. container/podName 은 rule filter 가 아니라 scope 다.
  kubectl apply -f "$SCRIPT_DIR/policy.yaml"

  # (2) Tracee config.
  #     기존 config 를 통째로 덮어쓰지 않고 필요한 키만 병합한다.
  #     tracee-operator 가 넣어둔 키를 날리면 에이전트가 기동 실패할 수 있다.
  #       - output: JSON 을 노드 로컬 파일로. stdout/CRI 경로를 쓰지 않는다.
  #       - perf-buffer-size: CPU 당 페이지 수 (2 의 거듭제곱)
  #       - healthz/metrics: 3366 포트. readiness probe 와 유실 카운터가 여기 의존한다.
  #       - parse-arguments=false: 인자 해석을 끄면 이벤트당 비용이 줄어 baseline 에 유리
  kubectl -n "$NS" get cm tracee-config -o jsonpath='{.data.config\.yaml}' \
    > "$OUT/tracee-config.orig.yaml" 2>/dev/null || true
  if [[ -s "$OUT/tracee-config.orig.yaml" ]]; then
    log "기존 config 백업: $OUT/tracee-config.orig.yaml ($(wc -l < "$OUT/tracee-config.orig.yaml") 줄)"
  else
    echo "[!] 기존 tracee-config 를 못 읽었다. 새로 만든다." >&2
    : > "$OUT/tracee-config.orig.yaml"
  fi

  python3 - "$OUT/tracee-config.orig.yaml" "$PAGES" "$LOG" > "$OUT/tracee-config.new.yaml" <<'PY'
import sys, io
try:
    import yaml
except ImportError:
    sys.exit("[!] python3-yaml 이 없다. 'sudo apt install python3-yaml' 후 다시 실행할 것.")

src, pages, logpath = sys.argv[1], int(sys.argv[2]), sys.argv[3]
with io.open(src, encoding="utf-8") as f:
    cfg = yaml.safe_load(f.read()) or {}

cfg["perf-buffer-size"] = pages
cfg["blob-perf-buffer-size"] = pages
cfg["healthz"] = True          # readiness probe 가 :3366/healthz 를 친다
cfg["metrics"] = True          # 유실 카운터 교차검증
cfg["pprof"] = False

out = cfg.setdefault("output", {})
# stdout 계열 싱크는 제거하고 파일 하나만 남긴다.
for k in ("table", "table-verbose", "gob", "gotemplate", "forward", "webhook"):
    out.pop(k, None)
out["json"] = {"files": [logpath]}
opts = out.setdefault("options", {})
opts["parse-arguments"] = False
opts["stack-addresses"] = False
opts["exec-env"] = False

sys.stdout.write(yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False))
PY

  echo "--- 적용할 config ---"
  cat "$OUT/tracee-config.new.yaml"
  kubectl -n "$NS" create cm tracee-config \
    --from-file=config.yaml="$OUT/tracee-config.new.yaml" \
    --dry-run=client -o yaml | kubectl apply -f -

  # (3) 예산은 tracee 컨테이너에만.
  kubectl -n "$NS" set resources "ds/$DS" -c tracee \
    --requests=cpu="$CPU" --limits=cpu="$CPU"

  # (4) ConfigMap 변경은 재시작해야 반영된다.
  kubectl -n "$NS" rollout restart "ds/$DS"
  kubectl -n "$NS" rollout status  "ds/$DS" --timeout=180s
  cmd_verify
}

# -----------------------------------------------------------------------------
# verify : 설정이 실제로 적용됐는지 확인 (측정 전 반드시 통과할 것)
# -----------------------------------------------------------------------------
cmd_verify() {
  need_cluster verify

  echo "--- containers / cpu limit ---"
  kubectl -n "$NS" get "ds/$DS" -o \
    jsonpath='{range .spec.template.spec.containers[*]}{.name}{"\t"}{.resources.limits.cpu}{"\n"}{end}'

  echo "--- container args (config 를 CLI 로 넘기는 배포도 있다) ---"
  kubectl -n "$NS" get "ds/$DS" -o jsonpath='{.spec.template.spec.containers[0].args}{"\n"}'

  echo "--- hostPath mounts (출력 파일이 노드에서 보이려면 필요) ---"
  kubectl -n "$NS" get "ds/$DS" -o \
    jsonpath='{range .spec.template.spec.volumes[*]}{.name}{"\t"}{.hostPath.path}{"\n"}{end}'
  echo "  [i] 위 목록에 ${OUTDIR_NODE} 가 없으면 TRACEE_OUT_DIR 로 바꿔야 한다."

  echo "--- effective config ---"
  kubectl -n "$NS" get cm tracee-config -o jsonpath='{.data.config\.yaml}{"\n"}' 2>/dev/null \
    || echo "  (tracee-config ConfigMap 없음 — 이 배포는 CLI args 를 쓸 수 있다)"

  echo "--- policy ---"
  kubectl get policy sysgen-sysenter -o yaml 2>/dev/null | sed -n '/^spec:/,$p' \
    || kubectl get policies.tracee.aquasec.com 2>/dev/null || echo "  (정책 조회 실패)"

  echo "--- tracee pods (노드별 / Ready 상태) ---"
  kubectl -n "$NS" get pods -l app.kubernetes.io/name=tracee -o     custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,READY:.status.containerStatuses[0].ready,RESTARTS:.status.containerStatuses[0].restartCount

  # 오퍼레이터가 ConfigMap 을 되돌릴 수 있다. helm 이 Tetragon 설정을 되돌렸던 것과 같은 함정.
  echo "--- tracee-operator (config 를 되돌릴 수 있음) ---"
  kubectl -n "$NS" get deploy 2>/dev/null | grep -i operator     || echo "  (operator deployment 없음)"

  echo "--- target pods (label app=sys-gen, ns=$NSPACE) ---"
  kubectl get pods -n "$NSPACE" -l app=sys-gen \
    -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,STATUS:.status.phase 2>/dev/null || true

  echo
  echo "[i] 로그 파일 확인은 대상 노드에서: ./exe_v1.sh check $N"
}

# -----------------------------------------------------------------------------
# reset : 측정 전 로그 초기화 (대상 노드에서)
#   본 파일은 truncate 만 한다. rm 으로 지우면 tracee 가 unlink 된 inode 에 계속
#   쓰게 되어 경로가 재생성되지 않는다.
# -----------------------------------------------------------------------------
cmd_reset() {
  if ! sudo test -e "$LOG"; then
    echo "[!] $LOG 가 없다. 아직 이벤트가 없거나 출력 경로가 다르다." >&2
    sudo ls -la "$OUTDIR_NODE" 2>/dev/null || echo "  $OUTDIR_NODE 자체가 없음"
    exit 1
  fi
  sudo truncate -s 0 "$LOG"
  sudo rm -f "$LOG".*
  log "초기화 완료: $(sudo stat -c %s "$LOG")B"
}

# -----------------------------------------------------------------------------
# check : 대상 노드에서 로그 상태 확인 (kubectl 불필요)
# -----------------------------------------------------------------------------
cmd_check() {
  echo "--- host ---"
  echo "  $(hostname)   vCPU=$(nproc)"

  echo "--- output file ---"
  if sudo test -e "$LOG"; then
    sudo ls -l "$LOG"
  elif sudo test -d "$OUTDIR_NODE"; then
    echo "  [i] $LOG 아직 없음. 디렉터리는 존재:"
    sudo ls -la "$OUTDIR_NODE"
    echo "  → 워크로드를 한 번 돌리면 생성된다. 안 생기면 output.json.files 경로 확인."
  else
    echo "[!] $OUTDIR_NODE 자체가 없음 — 이 노드에 tracee 가 없거나 hostPath 가 다르다."
    return 1
  fi

  # 정책이 의도한 이벤트/파드만 잡고 있는지.
  echo "--- eventName 분포 (최근 500줄; ${EVENT} 만 나와야 함) ---"
  sudo tail -n 500 "$LOG" 2>/dev/null \
    | grep -oE '"eventName":"[^"]*"' | sort | uniq -c | sort -rn | head || echo "  (로그 비어 있음)"

  echo "--- podName 분포 (최근 500줄; sys-gen 만 나와야 함) ---"
  sudo tail -n 500 "$LOG" 2>/dev/null \
    | grep -oE '"podName":"[^"]*"' | sort | uniq -c | sort -rn | head || echo "  (파드 정보 없음)"

  echo "--- 이벤트 한 줄 샘플 (timestamp 가 epoch ns 인지 boot-relative 인지 확인) ---"
  sudo head -c 600 "$LOG" 2>/dev/null || true
  echo
  echo "  now epoch_ns = $(date +%s%N)   /proc/uptime = $(cut -d' ' -f1 /proc/uptime)s"
  echo "  [i] timestamp 가 epoch ns 면 그대로 쓰면 되고, boot-relative(=uptime 근처) 면"
  echo "      TRACEE_TS=relative 로 calculate.py 에 알려줄 것."

  echo "--- metrics endpoint ---"
  local mh; mh="$(metrics_host)"
  echo "  host = ${mh}"
  curl -s -o /dev/null -w "  ${mh}:${METRICS_PORT}/metrics -> HTTP %{http_code}\n" \
    "http://${mh}:${METRICS_PORT}/metrics" \
    || echo "  (접근 실패 — TRACEE_METRICS_HOST 로 파드 IP 를 직접 지정할 것)"
  echo "--- 노출되는 tracee 카운터 (이름이 다르면 METRIC_KEYS 수정) ---"
  curl -s "http://${mh}:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep -E '^tracee_' | grep -iE 'lost|error|total' | head -20 || echo "  (없음)"
}

# Tracee 파드는 hostNetwork 가 아니라 자기 파드 IP 에 바인딩된다.
# 노드의 localhost:3366 으로는 도달하지 않으므로 파드 IP 를 찾아야 한다.
# 워커에는 kubectl 이 없으므로 crictl 로 조회한다. TRACEE_METRICS_HOST 로 덮어쓸 수 있다.
#   (Tetragon 은 hostNetwork 라 localhost 로 붙었다. 도구마다 다르다.)
METRICS_HOST_CACHE=""
metrics_host() {
  if [[ -n "${TRACEE_METRICS_HOST:-}" ]]; then echo "$TRACEE_METRICS_HOST"; return; fi
  if [[ -n "$METRICS_HOST_CACHE" ]]; then echo "$METRICS_HOST_CACHE"; return; fi

  # (a) hostNetwork 배포라면 localhost 로 붙는다
  if curl -s -o /dev/null --max-time 2 "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null; then
    METRICS_HOST_CACHE=localhost; echo localhost; return
  fi

  # (b) crictl 로 이 노드의 tracee 파드 IP 조회
  local id ip
  id=$(sudo crictl pods --name 'tracee' -q 2>/dev/null | head -n1)
  if [[ -n "$id" ]]; then
    ip=$(sudo crictl inspectp "$id" 2>/dev/null | grep -oE '"ip":[[:space:]]*"[0-9.]+"' \
         | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' || true)
    if [[ -n "$ip" ]] && curl -s -o /dev/null --max-time 2 "http://${ip}:${METRICS_PORT}/metrics" 2>/dev/null; then
      METRICS_HOST_CACHE="$ip"; echo "$ip"; return
    fi
  fi

  echo localhost
}

# 파이프라인 각 단계의 카운터. 이름은 버전마다 다르므로 check 로 실제 목록을 확인할 것.
METRIC_KEYS='tracee_ebpf_events_total|tracee_ebpf_events_filtered|tracee_ebpf_lostevents_total|tracee_ebpf_lostbpf_total|tracee_ebpf_lostwr_total|tracee_ebpf_errors_total|tracee_ebpf_perfbuffer_lost_total'

snapshot_metrics() {
  local h; h="$(metrics_host)"
  curl -s "http://${h}:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep -vE '^#' \
    | grep -E "^(${METRIC_KEYS}) " \
    | sort > "$1" \
    || echo "[!] metrics 스크레이프 실패 (${h}:${METRICS_PORT}) — TRACEE_METRICS_HOST 로 파드 IP 지정" >&2
}

# -----------------------------------------------------------------------------
# start : 노드 로컬 파일을 노드에서 tail. kubectl / jq / per-event fork 없음.
#   collect.py 가 수신 시각(recv_ns)을 찍는다. 노드에서 돌므로 이벤트 timestamp 와
#   같은 시계 영역이 되어, 지연 = recv_ns - timestamp 가 성립한다.
# -----------------------------------------------------------------------------
cmd_start() {
  sudo test -d "$OUTDIR_NODE" || {
    echo "[!] $OUTDIR_NODE 없음 — 이 노드에 tracee 가 안 떠 있다." >&2; exit 1; }
  sudo test -e "$LOG" || log "[i] $LOG 아직 없음 — tail -F 가 생성되는 대로 따라붙는다."
  [[ -f "$SCRIPT_DIR/collect.py" ]] || { echo "[!] $SCRIPT_DIR/collect.py 없음" >&2; exit 1; }

  snapshot_metrics "$OUT/metrics_before.txt"
  : > "$EVENTS"

  ( sudo tail -F -n0 "$LOG" | EVENTS_OUT="$EVENTS" stdbuf -oL python3 -u "$SCRIPT_DIR/collect.py" ) &
  echo $! > "$PIDFILE"
  log "collector started (pid $(cat "$PIDFILE")) -> $EVENTS"
  log "이제 워크로드를 실행하고, 발생시킨 syscall 수를 기록해 두십시오."
}

# -----------------------------------------------------------------------------
# stop : 수집 종료 + 집계
# -----------------------------------------------------------------------------
#   에이전트 지연이 수 초~수십 초이므로, 워크로드 종료 직후 stop 하면 아직 밀려
#   있는 이벤트가 잘려나가 delivered 가 과소 집계되고 유실률이 부풀려진다.
drain_wait() {
  local stable=0 last=-1 cur elapsed=0
  local STABLE_SEC="${DRAIN_STABLE_SEC:-30}" MAX="${DRAIN_MAX_SEC:-300}"
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
    # tail 은 sudo 로 띄웠으므로 root 소유다. 일반 사용자의 pkill 로는 안 죽어
    # 수집기가 살아남고, 다음 회차의 파일에 계속 쓴다.
    sudo pkill -P "$(cat "$PIDFILE")" 2>/dev/null || true
    pkill      -P "$(cat "$PIDFILE")" 2>/dev/null || true
    kill          "$(cat "$PIDFILE")" 2>/dev/null || true
    sudo pkill -f "tail -F -n0 $LOG"  2>/dev/null || true
    rm -f "$PIDFILE"
  fi
  sleep 1
  snapshot_metrics "$OUT/metrics_after.txt"

  local delivered raw raw_all other bpe fsize
  delivered=$(grep -c "\"eventName\":\"${EVENT}\"" "$EVENTS" || true)
  raw=$(sudo grep -c "\"eventName\":\"${EVENT}\"" "$LOG" || true)
  raw_all=$(sudo wc -l "$LOG" | awk '{print $1}')
  other=$(( raw_all - raw ))
  fsize=$(sudo stat -c %s "$LOG")
  # set -e 아래에서 `[[ ]] && x=y` 는 조건이 거짓일 때 스크립트를 종료시킨다.
  bpe=0
  if [[ "${raw_all:-0}" -gt 0 ]]; then bpe=$(( fsize / raw_all )); fi

  read -r PAGES VCPUS TOTMB <<<"$(calc_pages)"

  echo
  echo "=== Tracee collection summary (N=$N) ==="
  echo "  perf-buffer-size    : ${PAGES} pages/CPU x ${VCPUS} vCPU = ${TOTMB} MB (target ${N} MB)"
  echo "  cpu budget          : $CPU"
  echo "  bytes / event       : ${bpe}  [회차 간 이 값이 다르면 설정이 다른 것]"
  echo "  delivered (tail)    : $delivered   [${EVENT} only]"
  echo "  output file lines   : $raw          [${EVENT} only]"
  echo "  output file (all)   : $raw_all"
  echo "  other events        : $other      [정책 밖 이벤트 — 수집량에서 제외]"
  echo
  echo "  drop rate = 1 - delivered / <워크로드가 발생시킨 syscall 수>"
  echo "  (분모는 read_counter 의 발생량. 도구 카운터가 아님.)"
  echo
  echo "--- tracee counters (before -> after -> delta) ---"
  if [[ -s "$OUT/metrics_before.txt" && -s "$OUT/metrics_after.txt" ]]; then
    join "$OUT/metrics_before.txt" "$OUT/metrics_after.txt" \
      | awk '{printf "  %-46s %14s -> %-14s  delta=%s\n", $1, $2, $3, $3-$2}'
  else
    echo "  (메트릭 없음 — check 로 카운터 이름 확인 후 METRIC_KEYS 수정)"
  fi
  echo
  # A && B || C 로 쓰면 B(calculate.py) 가 정상적으로 0 아닌 코드로 끝났을 때도
  # C 가 실행되어 "파일 없음" 이라는 거짓 메시지가 찍힌다. if/else 로 분리한다.
  if [[ -f "$SCRIPT_DIR/calculate.py" ]]; then
    EVENTS_OUT="$EVENTS" python3 "$SCRIPT_DIR/calculate.py" || true
  else
    echo "[i] $SCRIPT_DIR/calculate.py 없음 — 지연 집계 생략."
  fi
}

case "${1:-}" in
  setup)  cmd_setup  ;;
  verify) cmd_verify ;;
  check)  cmd_check  ;;
  reset)  cmd_reset  ;;
  start)  cmd_start  ;;
  stop)   cmd_stop   ;;
  *) echo "usage: $0 {setup|verify|check|reset|start|stop} [N]   (default N=30)" >&2; exit 1 ;;
esac
