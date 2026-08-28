#!/usr/bin/env bash
# =============================================================================
# Tracee baseline — collection & measurement
#
# Design principles (matching the "Tracee" / "Measurement" paragraphs in the
# appendix of the paper):
#   1. Terminate at Tracee's native file output.
#      No stdout/CRI relay (kubectl logs): CRI splits lines at 16KB and kubelet
#      rotation (10MB x 5 by default) silently drops data.
#   2. The consumer runs on the same node as the agent.
#      The Kubernetes API server is not on the measurement path (no kubectl logs / exec).
#   3. The budget is given to the tracee container only (30m x N).
#   4. The denominator of the drop rate is the number of syscalls the workload issued.
#      Tool-side counters are only for cross-checking.
#
# About the perf buffer
#   Tracee allocates one perf buffer per online CPU, sized in "pages per CPU", and
#   the value must be a power of two. The total therefore cannot be matched to N MB
#   exactly. Here we read the node's vCPU count and use the smallest 2^k that reaches
#   at least N MB. In other words Tracee never gets less buffer than the rule asks
#   for (which favours the baseline).
#
# The place to run each subcommand differs.
#
#   [control-plane]  where kubectl is available
#     ./exe_v1.sh setup  30    # apply policy, CPU budget, file output, rollout
#     ./exe_v1.sh verify 30    # verify the cluster configuration
#
#   [worker]  the node where sys-gen and tracee actually run (kubectl not needed)
#     ./exe_v1.sh check  30    # log file status / event distribution
#     ./exe_v1.sh reset  30    # clear the log before measuring
#     ./exe_v1.sh start  30    # start collection (in the background)
#     ...run the workload, record the number of syscalls issued...
#     ./exe_v1.sh stop   30    # stop collection + aggregate
# =============================================================================
set -euo pipefail

N="${2:-30}"                              # number of application containers
CPU="$(( N * 30 ))m"                      # CPU budget = 30m x N
NS="${TRACEE_NS:-tracee}"                 # namespace of the tracee DaemonSet
DS="${TRACEE_DS:-tracee}"
NSPACE="${NSPACE:-default}"               # namespace that holds the benchmark pods
EVENT="${EVENT:-sys_enter}"               # event to collect

# A hostPath that is writable inside the tracee container. It must be a path the chart
# mounts. verify prints the actual mount list; override with TRACEE_OUT_DIR if it differs.
OUTDIR_NODE="${TRACEE_OUT_DIR:-/tmp/tracee}"
LOG="$OUTDIR_NODE/events.json"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # location of collect.py / calculate.py
OUT="${OUT_DIR:-$SCRIPT_DIR/out}"                            # where measurement artifacts are written
METRICS_PORT="${METRICS_PORT:-3366}"                         # Tracee Prometheus default port

mkdir -p "$OUT"
EVENTS="$OUT/syscalls_events.ndjson"
PIDFILE="$OUT/collector.pid"

log() { echo "[*] $*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }
need_cluster() {
  have kubectl && return 0
  echo "[!] This node has no kubectl. Run '$1' on the control-plane." >&2
  exit 1
}

tracee_pod() {
  kubectl -n "$NS" get pods -l app.kubernetes.io/name=tracee \
    --field-selector "spec.nodeName=$(hostname)" -o name 2>/dev/null | head -n1
}

# perf-buffer-size: the smallest 2^k pages/CPU whose total reaches at least N MB.
#   pages = ceil(N * 1MB / (C * 4KB)) = ceil(256N / C), rounded up to a power of two.
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
# setup : apply policy / file output / perf buffer / CPU budget / rollout
# -----------------------------------------------------------------------------
cmd_setup() {
  need_cluster setup

  # Determine the target node first. One perf buffer is allocated per online CPU of
  # the *target* node, and since setup runs on the control-plane, using the local
  # nproc would be wrong. If the two nodes differ in vCPU count the total buffer size
  # is off entirely.
  local target_node node_cpu
  target_node=$(kubectl get pods -n "$NSPACE" -l app=sys-gen \
    -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null || true)
  if [[ -n "$target_node" ]]; then
    node_cpu=$(kubectl get node "$target_node" -o jsonpath='{.status.capacity.cpu}' 2>/dev/null || true)
    [[ -n "$node_cpu" ]] && export VCPU="$node_cpu"
    log "collection target node: ${target_node} (vCPU=${VCPU:-?})  ->  run check/reset/start/stop there"
  else
    echo "[!] no pod with label app=sys-gen was found (ns=$NSPACE). Falling back to the local nproc." >&2
  fi

  read -r PAGES VCPUS TOTMB <<<"$(calc_pages)"
  log "N=$N  cpu=$CPU  perf-buffer-size=${PAGES} pages/CPU x ${VCPUS} vCPU = ${TOTMB} MB (target ${N} MB)"

  # (1) Policy. container/podName are scope, not rule filters.
  kubectl apply -f "$SCRIPT_DIR/policy.yaml"

  # (2) Tracee config.
  #     Merge only the keys we need instead of overwriting the whole config.
  #     Dropping keys placed there by tracee-operator can keep the agent from starting.
  #       - output: JSON into a node-local file. The stdout/CRI path is not used.
  #       - perf-buffer-size: pages per CPU (a power of two)
  #       - healthz/metrics: port 3366. The readiness probe and the loss counters rely on it.
  #       - parse-arguments=false: skipping argument decoding lowers the per-event cost,
  #         which favours the baseline
  kubectl -n "$NS" get cm tracee-config -o jsonpath='{.data.config\.yaml}' \
    > "$OUT/tracee-config.orig.yaml" 2>/dev/null || true
  if [[ -s "$OUT/tracee-config.orig.yaml" ]]; then
    log "backed up the existing config: $OUT/tracee-config.orig.yaml ($(wc -l < "$OUT/tracee-config.orig.yaml") lines)"
  else
    echo "[!] could not read the existing tracee-config. Creating a new one." >&2
    : > "$OUT/tracee-config.orig.yaml"
  fi

  python3 - "$OUT/tracee-config.orig.yaml" "$PAGES" "$LOG" > "$OUT/tracee-config.new.yaml" <<'PY'
import sys, io
try:
    import yaml
except ImportError:
    sys.exit("[!] python3-yaml is missing. Run 'sudo apt install python3-yaml' and try again.")

src, pages, logpath = sys.argv[1], int(sys.argv[2]), sys.argv[3]
with io.open(src, encoding="utf-8") as f:
    cfg = yaml.safe_load(f.read()) or {}

cfg["perf-buffer-size"] = pages
cfg["blob-perf-buffer-size"] = pages
cfg["healthz"] = True          # the readiness probe hits :3366/healthz
cfg["metrics"] = True          # cross-check against the loss counters
cfg["pprof"] = False

out = cfg.setdefault("output", {})
# Drop the stdout-family sinks and keep only the single file sink.
for k in ("table", "table-verbose", "gob", "gotemplate", "forward", "webhook"):
    out.pop(k, None)
out["json"] = {"files": [logpath]}
opts = out.setdefault("options", {})
opts["parse-arguments"] = False
opts["stack-addresses"] = False
opts["exec-env"] = False

sys.stdout.write(yaml.safe_dump(cfg, default_flow_style=False, sort_keys=False))
PY

  echo "--- config to apply ---"
  cat "$OUT/tracee-config.new.yaml"
  kubectl -n "$NS" create cm tracee-config \
    --from-file=config.yaml="$OUT/tracee-config.new.yaml" \
    --dry-run=client -o yaml | kubectl apply -f -

  # (3) The budget goes to the tracee container only.
  kubectl -n "$NS" set resources "ds/$DS" -c tracee \
    --requests=cpu="$CPU" --limits=cpu="$CPU"

  # (4) ConfigMap changes take effect only after a restart.
  kubectl -n "$NS" rollout restart "ds/$DS"
  kubectl -n "$NS" rollout status  "ds/$DS" --timeout=180s
  cmd_verify
}

# -----------------------------------------------------------------------------
# verify : confirm the settings actually took effect (must pass before measuring)
# -----------------------------------------------------------------------------
cmd_verify() {
  need_cluster verify

  echo "--- containers / cpu limit ---"
  kubectl -n "$NS" get "ds/$DS" -o \
    jsonpath='{range .spec.template.spec.containers[*]}{.name}{"\t"}{.resources.limits.cpu}{"\n"}{end}'

  echo "--- container args (some deployments pass the config on the CLI) ---"
  kubectl -n "$NS" get "ds/$DS" -o jsonpath='{.spec.template.spec.containers[0].args}{"\n"}'

  echo "--- hostPath mounts (needed for the output file to be visible on the node) ---"
  kubectl -n "$NS" get "ds/$DS" -o \
    jsonpath='{range .spec.template.spec.volumes[*]}{.name}{"\t"}{.hostPath.path}{"\n"}{end}'
  echo "  [i] If ${OUTDIR_NODE} is not in the list above, change it with TRACEE_OUT_DIR."

  echo "--- effective config ---"
  kubectl -n "$NS" get cm tracee-config -o jsonpath='{.data.config\.yaml}{"\n"}' 2>/dev/null \
    || echo "  (no tracee-config ConfigMap - this deployment may use CLI args)"

  echo "--- policy ---"
  kubectl get policy sysgen-sysenter -o yaml 2>/dev/null | sed -n '/^spec:/,$p' \
    || kubectl get policies.tracee.aquasec.com 2>/dev/null || echo "  (failed to query the policy)"

  echo "--- tracee pods (per node / Ready state) ---"
  kubectl -n "$NS" get pods -l app.kubernetes.io/name=tracee -o     custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,READY:.status.containerStatuses[0].ready,RESTARTS:.status.containerStatuses[0].restartCount

  # The operator may revert the ConfigMap: the same trap as helm reverting the Tetragon config.
  echo "--- tracee-operator (may revert the config) ---"
  kubectl -n "$NS" get deploy 2>/dev/null | grep -i operator     || echo "  (no operator deployment)"

  echo "--- target pods (label app=sys-gen, ns=$NSPACE) ---"
  kubectl get pods -n "$NSPACE" -l app=sys-gen \
    -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,STATUS:.status.phase 2>/dev/null || true

  echo
  echo "[i] Check the log file on the target node: ./exe_v1.sh check $N"
}

# -----------------------------------------------------------------------------
# reset : clear the log before measuring (on the target node)
#   This only truncates. Removing the file with rm makes tracee keep writing to the
#   unlinked inode, so the path is never recreated.
# -----------------------------------------------------------------------------
cmd_reset() {
  if ! sudo test -e "$LOG"; then
    echo "[!] $LOG is missing. Either there are no events yet, or the output path differs." >&2
    sudo ls -la "$OUTDIR_NODE" 2>/dev/null || echo "  $OUTDIR_NODE itself does not exist"
    exit 1
  fi
  sudo truncate -s 0 "$LOG"
  sudo rm -f "$LOG".*
  log "reset done: $(sudo stat -c %s "$LOG")B"
}

# -----------------------------------------------------------------------------
# check : inspect the log status on the target node (kubectl not needed)
# -----------------------------------------------------------------------------
cmd_check() {
  echo "--- host ---"
  echo "  $(hostname)   vCPU=$(nproc)"

  echo "--- output file ---"
  if sudo test -e "$LOG"; then
    sudo ls -l "$LOG"
  elif sudo test -d "$OUTDIR_NODE"; then
    echo "  [i] $LOG does not exist yet. The directory is there:"
    sudo ls -la "$OUTDIR_NODE"
    echo "  -> It appears once the workload runs. If it does not, check the output.json.files path."
  else
    echo "[!] $OUTDIR_NODE itself is missing - tracee is not on this node, or the hostPath differs."
    return 1
  fi

  # Check that the policy captures only the intended events/pods.
  echo "--- eventName distribution (last 500 lines; only ${EVENT} expected) ---"
  sudo tail -n 500 "$LOG" 2>/dev/null \
    | grep -oE '"eventName":"[^"]*"' | sort | uniq -c | sort -rn | head || echo "  (log is empty)"

  echo "--- podName distribution (last 500 lines; only sys-gen expected) ---"
  sudo tail -n 500 "$LOG" 2>/dev/null \
    | grep -oE '"podName":"[^"]*"' | sort | uniq -c | sort -rn | head || echo "  (no pod information)"

  echo "--- one sample event line (check whether timestamp is epoch ns or boot-relative) ---"
  sudo head -c 600 "$LOG" 2>/dev/null || true
  echo
  echo "  now epoch_ns = $(date +%s%N)   /proc/uptime = $(cut -d' ' -f1 /proc/uptime)s"
  echo "  [i] If timestamp is epoch ns it can be used as is; if it is boot-relative"
  echo "      (close to uptime), tell calculate.py with TRACEE_TS=relative."

  echo "--- metrics endpoint ---"
  local mh; mh="$(metrics_host)"
  echo "  host = ${mh}"
  curl -s -o /dev/null -w "  ${mh}:${METRICS_PORT}/metrics -> HTTP %{http_code}\n" \
    "http://${mh}:${METRICS_PORT}/metrics" \
    || echo "  (access failed - set the pod IP explicitly with TRACEE_METRICS_HOST)"
  echo "--- exposed tracee counters (if the names differ, update METRIC_KEYS) ---"
  curl -s "http://${mh}:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep -E '^tracee_' | grep -iE 'lost|error|total' | head -20 || echo "  (none)"
}

# The tracee pod is not on hostNetwork; it binds to its own pod IP.
# The node's localhost:3366 does not reach it, so the pod IP has to be discovered.
# Workers have no kubectl, so crictl is used. Override with TRACEE_METRICS_HOST.
#   (Tetragon runs on hostNetwork, so localhost worked there. It differs per tool.)
METRICS_HOST_CACHE=""
metrics_host() {
  if [[ -n "${TRACEE_METRICS_HOST:-}" ]]; then echo "$TRACEE_METRICS_HOST"; return; fi
  if [[ -n "$METRICS_HOST_CACHE" ]]; then echo "$METRICS_HOST_CACHE"; return; fi

  # (a) on a hostNetwork deployment, localhost works
  if curl -s -o /dev/null --max-time 2 "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null; then
    METRICS_HOST_CACHE=localhost; echo localhost; return
  fi

  # (b) look up this node's tracee pod IP with crictl
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

# Counters for each pipeline stage. The names differ between versions, so use check to
# see the actual list.
METRIC_KEYS='tracee_ebpf_events_total|tracee_ebpf_events_filtered|tracee_ebpf_lostevents_total|tracee_ebpf_lostbpf_total|tracee_ebpf_lostwr_total|tracee_ebpf_errors_total|tracee_ebpf_perfbuffer_lost_total'

snapshot_metrics() {
  local h; h="$(metrics_host)"
  curl -s "http://${h}:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep -vE '^#' \
    | grep -E "^(${METRIC_KEYS}) " \
    | sort > "$1" \
    || echo "[!] metrics scrape failed (${h}:${METRICS_PORT}) - set the pod IP with TRACEE_METRICS_HOST" >&2
}

# -----------------------------------------------------------------------------
# start : tail the node-local file on the node itself. No kubectl, no jq, no per-event fork.
#   collect.py stamps the receive time (recv_ns). Since it runs on the node it shares the
#   clock domain of the event timestamp, so latency = recv_ns - timestamp holds.
# -----------------------------------------------------------------------------
cmd_start() {
  sudo test -d "$OUTDIR_NODE" || {
    echo "[!] $OUTDIR_NODE is missing - tracee is not running on this node." >&2; exit 1; }
  sudo test -e "$LOG" || log "[i] $LOG does not exist yet - tail -F attaches as soon as it is created."
  [[ -f "$SCRIPT_DIR/collect.py" ]] || { echo "[!] $SCRIPT_DIR/collect.py not found" >&2; exit 1; }

  snapshot_metrics "$OUT/metrics_before.txt"
  : > "$EVENTS"

  ( sudo tail -F -n0 "$LOG" | EVENTS_OUT="$EVENTS" stdbuf -oL python3 -u "$SCRIPT_DIR/collect.py" ) &
  echo $! > "$PIDFILE"
  log "collector started (pid $(cat "$PIDFILE")) -> $EVENTS"
  log "Now run the workload and record the number of syscalls it issues."
}

# -----------------------------------------------------------------------------
# stop : end collection + aggregate
# -----------------------------------------------------------------------------
#   Agent latency ranges from seconds to tens of seconds, so stopping right after the
#   workload ends truncates events still in flight, undercounting delivered and
#   inflating the loss rate.
drain_wait() {
  local stable=0 last=-1 cur elapsed=0
  local STABLE_SEC="${DRAIN_STABLE_SEC:-30}" MAX="${DRAIN_MAX_SEC:-300}"
  log "waiting for drain (finishes when the log size is unchanged for ${STABLE_SEC}s, max ${MAX}s)"
  while (( elapsed < MAX )); do
    cur=$(sudo stat -c %s "$LOG" 2>/dev/null || echo 0)
    if [[ "$cur" == "$last" ]]; then
      stable=$((stable+1))
      (( stable >= STABLE_SEC )) && { log "drain complete (${elapsed}s, ${cur}B)"; return 0; }
    else
      stable=0
    fi
    last="$cur"; sleep 1; elapsed=$((elapsed+1))
  done
  echo "[!] not stable within ${MAX}s - the pipeline is still backed up." >&2
}

cmd_stop() {
  [[ "${SKIP_DRAIN:-0}" == "1" ]] || drain_wait

  if [[ -f "$PIDFILE" ]]; then
    # tail was started with sudo, so it is owned by root. A plain-user pkill does not
    # kill it, the collector survives, and it keeps writing into the next run's file.
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
  # Under set -e, `[[ ]] && x=y` exits the script when the condition is false.
  bpe=0
  if [[ "${raw_all:-0}" -gt 0 ]]; then bpe=$(( fsize / raw_all )); fi

  read -r PAGES VCPUS TOTMB <<<"$(calc_pages)"

  echo
  echo "=== Tracee collection summary (N=$N) ==="
  echo "  perf-buffer-size    : ${PAGES} pages/CPU x ${VCPUS} vCPU = ${TOTMB} MB (target ${N} MB)"
  echo "  cpu budget          : $CPU"
  echo "  bytes / event       : ${bpe}  [if this differs across runs, the configuration differs]"
  echo "  delivered (tail)    : $delivered   [${EVENT} only]"
  echo "  output file lines   : $raw          [${EVENT} only]"
  echo "  output file (all)   : $raw_all"
  echo "  other events        : $other      [events outside the policy - excluded from the collected count]"
  echo
  echo "  drop rate = 1 - delivered / <number of syscalls the workload issued>"
  echo "  (the denominator is what read_counter measured, not a tool counter.)"
  echo
  echo "--- tracee counters (before -> after -> delta) ---"
  if [[ -s "$OUT/metrics_before.txt" && -s "$OUT/metrics_after.txt" ]]; then
    join "$OUT/metrics_before.txt" "$OUT/metrics_after.txt" \
      | awk '{printf "  %-46s %14s -> %-14s  delta=%s\n", $1, $2, $3, $3-$2}'
  else
    echo "  (no metrics - check the counter names with check, then update METRIC_KEYS)"
  fi
  echo
  # Written as A && B || C, C would also run when B (calculate.py) legitimately exits
  # non-zero, printing a bogus "file not found" message. Split into if/else instead.
  if [[ -f "$SCRIPT_DIR/calculate.py" ]]; then
    EVENTS_OUT="$EVENTS" python3 "$SCRIPT_DIR/calculate.py" || true
  else
    echo "[i] $SCRIPT_DIR/calculate.py not found - skipping latency aggregation."
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
