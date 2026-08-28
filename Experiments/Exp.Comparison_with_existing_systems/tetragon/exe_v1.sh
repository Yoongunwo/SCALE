#!/usr/bin/env bash
# =============================================================================
# Tetragon baseline — collection & measurement
#
# Design principles (matching the "Tetragon" / "Measurement" paragraphs in the
# appendix of the paper):
#   1. Terminate at Tetragon's native file export.
#      No stdout/CRI relay, no gRPC (tetra getevents), no export sidecar.
#   2. The consumer runs on the same node as the agent.
#      The Kubernetes API server is not on the measurement path (no kubectl logs / exec).
#   3. The budget is given to the tetragon container only (30m x N).
#   4. The denominator of the drop rate is the number of syscalls the workload issued.
#      Tool-side counters are only for cross-checking.
#
# The place to run each subcommand differs.
#
#   [control-plane]  where kubectl / helm are available
#     ./exe_v1.sh setup  30    # remove sidecars, CPU budget, ConfigMap, rollout
#     ./exe_v1.sh verify 30    # verify the cluster configuration
#
#   [worker]  the node where sys-gen and tetragon actually run (kubectl not needed)
#     ./exe_v1.sh check  30    # log file status / event type distribution
#     ./exe_v1.sh start  30    # start collection (in the background)
#     ...run the workload, record the number of syscalls issued...
#     ./exe_v1.sh stop   30    # stop collection + aggregate
# =============================================================================
set -euo pipefail

N="${2:-30}"                          # number of application containers
RB_TOTAL=$(( N * 1048576 ))           # total ring buffer = N MB (bytes)
CPU="$(( N * 30 ))m"                  # CPU budget = 30m x N
NS=kube-system
LOG=/var/run/cilium/tetragon/tetragon.log
NSPACE="${NSPACE:-default}"          # namespace that holds the benchmark pods
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # location of collect.py / calculate.py
OUT="${OUT_DIR:-$SCRIPT_DIR/out}"                            # where measurement artifacts are written
METRICS_PORT="${METRICS_PORT:-2112}"

mkdir -p "$OUT"
EVENTS="$OUT/syscalls_events.ndjson"
PIDFILE="$OUT/collector.pid"

log() { echo "[*] $*" >&2; }
have() { command -v "$1" >/dev/null 2>&1; }
need_cluster() {
  have kubectl && have helm && return 0
  echo "[!] This node has no kubectl/helm. Run '$1' on the control-plane." >&2
  exit 1
}

tetra_pod() {
  kubectl -n "$NS" get pods -l app.kubernetes.io/name=tetragon \
    --field-selector "spec.nodeName=$(hostname)" -o name | head -n1
}

# -----------------------------------------------------------------------------
# setup : file export / lift rate limit / buffer total / drop sidecar / CPU budget
# -----------------------------------------------------------------------------
cmd_setup() {
  need_cluster setup
  log "N=$N  rb-size-total=${RB_TOTAL}B ($((RB_TOTAL/1048576)) MB)  cpu=${CPU}"

  # If no target pod runs on this node, nothing is observed here.
  # Tetragon is a DaemonSet, so each node's agent sees only its own node's syscalls.
  local target_node
  target_node=$(kubectl get pods -n "$NSPACE" -l app=sys-gen \
    -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null || true)
  if [[ -n "$target_node" ]]; then
    log "collection target node: ${target_node}  ->  run start/stop there"
  else
    echo "[!] no pod with label app=sys-gen was found (ns=$NSPACE)." >&2
  fi

  # (1) Drop the export sidecar and give the budget to the tetragon container only.
  #     hubble-export-stdout is only a relay that tails the export file and echoes it back
  #     to stdout, so disabling it does not change which events are collected.
  #     The chart key is export.mode, and "" disables it ('"stdout". "" to disable.').
  #     Beware: a non-existent key such as export.stdout.enabled is silently ignored by helm.
  helm upgrade tetragon cilium/tetragon -n "$NS" --reuse-values \
    --set export.mode="" \
    --set tetragon.resources.requests.cpu="$CPU" \
    --set tetragon.resources.limits.cpu="$CPU"

  # (2) The ConfigMap must be patched **after** helm upgrade.
  #     Helm 3's 3-way merge resets keys that exist in the chart template
  #     (export-allowlist and the like) back to their template defaults, so in the
  #     reverse order the values set here would be wiped out.
  #
  #     export-allowlist: excludes the base sensor's node-wide process_exec/process_exit
  #     so that only the tracepoint events produced by the TracingPolicy reach the file.
  #     Note that this filter acts at the userspace export stage: filtered-out events have
  #     already crossed the ring buffer, so the kernel->userspace cost and the buffer
  #     occupancy are incurred all the same.
  #     export-file-max-size-mb: by default the file rotates every 10MB. Under load it is
  #     rotated several times per second, and tail misses events at each rotation, which
  #     badly undercounts delivered. Set it large enough that rotation effectively never
  #     happens.
  #     field-filters: minimizes the exported fields (pid / binary / args).
  #     The default payload is ~2,470 B per event because of the pod and parent blocks;
  #     with this filter it shrinks to ~343 B, greatly reducing serialization cost -- that
  #     is, it works in the baseline's favour. Always turn it on or off explicitly and
  #     record that state together with the results.
  #     (helm upgrade resets chart template keys to their defaults, so it is rewritten here
  #     every time.)
  #     rb-queue-size: size of the internal userspace channel (in events, default 65535).
  #     Keep it large so the queue is not the binding constraint and losses come from the
  #     resources we budgeted.
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

  # (3) ConfigMap changes take effect only after a restart.
  kubectl -n "$NS" rollout restart ds/tetragon
  kubectl -n "$NS" rollout status  ds/tetragon --timeout=180s
  cmd_verify
}

# -----------------------------------------------------------------------------
# verify : confirm the settings actually took effect (must pass before measuring)
# -----------------------------------------------------------------------------
cmd_verify() {
  need_cluster verify
  local pod; pod="$(tetra_pod)"
  [[ -n "$pod" ]] || { echo "[!] no tetragon pod on this node" >&2; exit 1; }

  echo "--- containers (only tetragon should be listed) ---"
  kubectl -n "$NS" get "$pod" -o jsonpath='{range .spec.containers[*]}{.name}{"\t"}{.resources.limits.cpu}{"\n"}{end}'

  echo "--- effective config ---"
  kubectl -n "$NS" get cm tetragon-config -o \
    jsonpath='export-filename={.data.export-filename}{"\n"}export-rate-limit={.data.export-rate-limit}{"\n"}rb-size-total={.data.rb-size-total}{"\n"}rb-queue-size={.data.rb-queue-size}{"\n"}export-file-max-size-mb={.data.export-file-max-size-mb}{"\n"}export-allowlist={.data.export-allowlist}{"\n"}field-filters={.data.field-filters}{"\n"}'

  echo "--- tracing policy (CR) ---"
  kubectl get tracingpolicynamespaced -n "$NSPACE" 2>/dev/null || true

  # A CR existing is not the same as the sensor being loaded into the kernel.
  # When loading fails the CR stays in place while no events are produced.
  echo "--- loaded sensors (tetra status) ---"
  kubectl exec -n "$NS" "$pod" -c tetragon -- tetra status 2>/dev/null \
    | grep -iE 'policy|sensor|tracingpolicy|enabled|error' || echo "  (failed to query tetra status)"

  # Check that the targets matched by podSelector are actually running.
  echo "--- target pods (label app=sys-gen, ns=$NSPACE) ---"
  kubectl get pods -n "$NSPACE" -l app=sys-gen \
    -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,STATUS:.status.phase 2>/dev/null \
    || echo "  (query failed)"

  echo
  echo "[i] Check the log file on the target node: ./exe_v1.sh check $N"
}

# -----------------------------------------------------------------------------
# reset : clear the log before measuring (on the target node)
#   This only truncates. Removing the file with rm makes the exporter keep writing to
#   the unlinked inode, so the path is never recreated and the log stays gone until
#   tetragon is restarted. Only rotated backups (.log.1 and so on) are removed.
# -----------------------------------------------------------------------------
cmd_reset() {
  if ! sudo test -e "$LOG"; then
    echo "[!] $LOG is missing. If it was deleted with rm, tetragon must be restarted to recreate it:" >&2
    echo "    [control-plane] kubectl -n $NS delete pod -l app.kubernetes.io/name=tetragon --field-selector spec.nodeName=$(hostname)" >&2
    exit 1
  fi
  sudo truncate -s 0 "$LOG"
  sudo rm -f "$LOG".*
  log "reset done: $(sudo ls -l "$LOG" | awk '{print $5}')B, $(sudo ls "$LOG".* 2>/dev/null | wc -l) backups"
}

# -----------------------------------------------------------------------------
# check : inspect the log status on the target node (kubectl not needed)
# -----------------------------------------------------------------------------
cmd_check() {
  echo "--- host ---"
  echo "  $(hostname)"

  echo "--- export log ---"
  if sudo test -e "$LOG"; then
    sudo ls -l "$LOG"
  elif sudo test -d "$(dirname "$LOG")"; then
    # The exporter creates the file when it writes the first event. With the allowlist
    # in place and the workload idle, no event matches, so the file may not exist yet.
    echo "  [i] $LOG does not exist yet. The directory is there:"
    sudo ls -la "$(dirname "$LOG")"
    echo "  -> It appears once the workload runs. If it still does not, check export-filename/allowlist."
  else
    echo "[!] $(dirname "$LOG") itself is missing - tetragon is not running on this node."
    return 1
  fi

  # Check whether the base sensor's node-wide events are leaking in.
  # Any type other than process_tracepoint means export-allowlist did not take effect.
  echo "--- event type distribution over the last 200 lines (only process_tracepoint expected) ---"
  sudo tail -n 200 "$LOG" 2>/dev/null     | grep -oE '"(process_exec|process_exit|process_kprobe|process_tracepoint)"'     | sort | uniq -c || echo "  (log is empty)"

  # Check that the policy captures only the intended pods (pod name distribution of the
  # tracepoint events).
  echo "--- pod distribution of process_tracepoint (only sys-gen expected) ---"
  sudo grep '"process_tracepoint"' "$LOG" 2>/dev/null | tail -n 500     | grep -oE '"name":"[^"]*"' | sort | uniq -c | head || echo "  (no tracepoint events)"

  # Rotation makes tail miss events, so any backup file means the setting did not apply.
  echo "--- rotation traces (there should be no backup files) ---"
  sudo ls -l "$(dirname "$LOG")" | grep -v "^total" || true

  echo "--- metrics endpoint ---"
  curl -s -o /dev/null -w "  localhost:${METRICS_PORT}/metrics -> HTTP %{http_code}
"     "localhost:${METRICS_PORT}/metrics" || echo "  (access failed)"
}

# Keep only the counters of each pipeline stage, as "name value" pairs.
# HELP/TYPE comments and labelled time series (tetragon_events_total{...}) are excluded.
#   received  : total actually received from the kernel; the gap against the issued
#               count is the kernel-side loss
#   lost      : perf ring buffer loss
#   errors    : ring buffer read errors
#   queue_*   : the internal userspace channel
METRIC_KEYS='tetragon_observer_ringbuf_events_received_total|tetragon_observer_ringbuf_events_lost_total|tetragon_observer_ringbuf_errors_total|tetragon_observer_ringbuf_queue_events_received_total|tetragon_observer_ringbuf_queue_events_lost_total|tetragon_notify_overflowed_events_total|tetragon_export_ratelimit_events_dropped_total|tetragon_events_exported_total'

snapshot_metrics() {
  curl -s "localhost:${METRICS_PORT}/metrics" 2>/dev/null \
    | grep -vE '^#' \
    | grep -E "^(${METRIC_KEYS}) " \
    | sort > "$1" \
    || echo "[!] metrics scrape failed (port ${METRICS_PORT})" >&2
}

# start : tail the node-local file on the node itself. No kubectl, no jq, no per-event fork.
#   collect.py stamps the receive time (recv_ns). Since it runs on the node it shares the
#   clock domain of the event's time field, so latency = recv_ns - event.time holds.
# -----------------------------------------------------------------------------
cmd_start() {
  sudo test -d "$(dirname "$LOG")" || {
    echo "[!] $(dirname "$LOG") is missing - tetragon is not running on this node." >&2; exit 1; }
  sudo test -e "$LOG" || log "[i] $LOG does not exist yet - tail -F attaches as soon as it is created."
  [[ -f "$SCRIPT_DIR/collect.py" ]] || { echo "[!] $SCRIPT_DIR/collect.py not found" >&2; exit 1; }

  snapshot_metrics "$OUT/metrics_before.txt"
  : > "$EVENTS"

  # -n0 : ignore existing content and start from now. stdbuf removes pipe buffering.
  ( sudo tail -F -n0 "$LOG" | EVENTS_OUT="$EVENTS" stdbuf -oL python3 -u "$SCRIPT_DIR/collect.py" ) &
  echo $! > "$PIDFILE"
  log "collector started (pid $(cat "$PIDFILE")) -> $EVENTS"
  log "Now run the workload and record the number of syscalls it issues."
}

# -----------------------------------------------------------------------------
# stop : end collection + aggregate
# -----------------------------------------------------------------------------
# Wait until the pipeline has drained.
#   Agent latency is on the order of seconds, so stopping right after the workload ends
#   truncates events that are still in flight, undercounting delivered and inflating the
#   loss rate. The drain is considered complete when the export log size does not change
#   for STABLE_SEC seconds.
drain_wait() {
  local stable=0 last=-1 cur elapsed=0
  local STABLE_SEC="${DRAIN_STABLE_SEC:-10}" MAX="${DRAIN_MAX_SEC:-180}"
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
    pkill -P "$(cat "$PIDFILE")" 2>/dev/null || true
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE"
  fi
  sleep 1
  snapshot_metrics "$OUT/metrics_after.txt"

  # Count process_tracepoint only. The base sensor's process_exec/exit occur node-wide,
  # independently of the policy, so they must not be counted as collected syscalls.
  local delivered raw raw_all base_ev
  delivered=$(grep -c '"process_tracepoint"' "$EVENTS" || true)
  raw=$(sudo grep -c '"process_tracepoint"' "$LOG" || true)
  raw_all=$(sudo wc -l "$LOG" | awk '{print $1}')
  base_ev=$(sudo grep -cE '"(process_exec|process_exit)"' "$LOG" || true)

  # Include the rotated backups. If backups exist, tail missed those stretches, so
  # delivered(tail) cannot be trusted and the file-based total must be used instead.
  local nrot rot_total
  nrot=$(sudo ls "$LOG"* 2>/dev/null | grep -vc "^${LOG}$" || true)
  rot_total=$(sudo cat "$LOG"* 2>/dev/null | grep -c '"process_tracepoint"' || true)

  echo
  echo "=== Tetragon collection summary (N=$N) ==="
  local bpe=0
  [[ "$raw_all" -gt 0 ]] && bpe=$(( $(sudo stat -c %s "$LOG") / raw_all ))
  echo "  buffer (total)      : $((RB_TOTAL/1048576)) MB"
  echo "  rb-queue-size       : ${RB_QUEUE:-1000000}"
  echo "  field-filter        : ${FIELD_FILTER:-1}  (1=minimal payload)"
  echo "  bytes / event       : ${bpe}  [if this differs across runs, the configuration differs]"
  echo "  cpu budget          : $CPU"
  echo "  delivered (tail)    : $delivered   [process_tracepoint only]"
  echo "  export log lines    : $raw          [process_tracepoint only]"
  echo "  export log (all)    : $raw_all"
  echo "  rotated backups     : $nrot"
  echo "  all files combined  : $rot_total  [process_tracepoint, rotations included]"
  if [[ "${nrot:-0}" -gt 0 ]]; then
    echo
    echo "  [!] Rotation occurred. tail misses the rotated stretches, so use"
    echo "      'all files combined' instead of delivered(tail)."
    echo "      The latency statistics are unreliable because the sample is broken up."
  fi
  echo "  base sensor events  : $base_ev      [exec/exit, node-wide - excluded from the collected count]"
  echo
  echo "  drop rate = 1 - delivered / <number of syscalls the workload issued>"
  echo "  (the denominator is what sys_generator issued, not a tool counter.)"
  echo
  echo "--- kernel/queue loss (before -> after) ---"
  paste <(sort "$OUT/metrics_before.txt") <(sort "$OUT/metrics_after.txt") 2>/dev/null \
    | grep -E 'lost|drop' || true
  echo
  # Written as A && B || C, C would also run when B (calculate.py) legitimately exits
  # non-zero, printing a bogus "file not found" message. Split into if/else instead.
  if [[ -f "$SCRIPT_DIR/calculate.py" ]]; then
    EVENTS_OUT="$EVENTS" python3 "$SCRIPT_DIR/calculate.py" || true
  else
    echo "[i] $SCRIPT_DIR/calculate.py not found - skipping latency aggregation."
  fi
}

# -----------------------------------------------------------------------------
# drop-sidecar : fallback for when the helm key cannot be found.
#   Removes the export-stdout container directly from the DaemonSet.
#   Note: it comes back on the next helm upgrade, so run this right before measuring.
# -----------------------------------------------------------------------------
cmd_drop_sidecar() {
  local idx
  idx=$(kubectl -n "$NS" get ds/tetragon -o json         | python3 -c 'import json,sys;c=[x["name"] for x in json.load(sys.stdin)["spec"]["template"]["spec"]["containers"]];print(c.index("export-stdout") if "export-stdout" in c else -1)')
  if [[ "$idx" -lt 0 ]]; then echo "[i] no export-stdout"; return 0; fi
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
