#!/usr/bin/env bash
set -euo pipefail

# =========================================
# sysdig.sh
# - maps several sys_generator processes onto host PIDs and captures them with the
#   kernel filter evt.dir="<" + (proc.pid=H1 or proc.pid=H2 ...)
# - /host/proc must be mounted as a hostPath for the host PID mapping to be accurate
#   (readOnly OK)
# =========================================

NAME="${1:-sys_generator}"   # process name (exact match, default sys_generator)
DUR="${2:-10}"               # collection time in seconds - sysdig -M
SNAP="${3:-80}"              # snaplen -s (the smaller, the fewer drops)

# /host/proc must be mounted:
# spec:
#   volumes:
#   - name: host-proc
#     hostPath: { path: /proc }
#   containers:
#   - volumeMounts:
#     - name: host-proc
#       mountPath: /host/proc
#       readOnly: true

# --------- utilities ----------
_now_ns() { date +%s%N; }

_num_or_zero() {
  local s="${1:-}"
  if [[ -z "$s" ]]; then echo 0; return; fi
  echo "$s" | tr -d ',' | awk '{gsub(/[^0-9.]/,""); if($0=="") print 0; else print}'
}

# --------- map several PIDs (container PID -> host PIDs) ----------
# output: one line per entry, "cpid:host1,host2,..."
resolve_host_pids_all() {
  local name="${1:-sys_generator}"

  # 1) collect the container PIDs (exact match)
  local cpids=()
  if command -v pgrep >/dev/null 2>&1; then
    while IFS= read -r pid; do
      [[ -n "$pid" ]] && cpids+=("$pid")
    done < <(pgrep -x "$name" || true)
  else
    while IFS= read -r pid; do
      [[ -n "$pid" ]] && cpids+=("$pid")
    done < <(ps -C "$name" -o pid= | awk '{print $1}' || true)
  fi

  if [[ ${#cpids[@]} -eq 0 ]]; then
    echo "ERR: $name not found in container namespace" >&2
    return 1
  fi

  # without /host/proc, return container PIDs only (the filter works, but not in kernel PID terms)
  if [[ ! -r /host/proc ]]; then
    echo "WARN: /host/proc not mounted; using container PIDs as-is" >&2
    for cpid in "${cpids[@]}"; do
      echo "${cpid}:${cpid}"
    done
    return 0
  fi

  # 2) scan /host/proc: the last NSpid == cpid && comm == name
  declare -A host_by_cpid
  local sp pid last comm

  while IFS= read -r -d '' sp; do
    pid="${sp#/host/proc/}"
    pid="${pid%/status}"

    # take the last NSpid token (the container PID)
    last="$(awk '/^NSpid:/{for(i=2;i<=NF;i++) L=$i} END{if(L!="") print L}' "$sp" 2>/dev/null)" || true
    [[ -z "$last" ]] && continue

    if read -r comm <"/host/proc/$pid/comm"; then
      [[ "$comm" == "$name" ]] || continue
    else
      continue
    fi

    host_by_cpid["$last"]+="${host_by_cpid[$last]:+ }$pid"
  done < <(find /host/proc -maxdepth 2 -type f -name status -print0 2>/dev/null)

  # 3) print the result
  for cpid in "${cpids[@]}"; do
    if [[ -n "${host_by_cpid[$cpid]:-}" ]]; then
      read -r -a arr <<<"${host_by_cpid[$cpid]}"
      # uniq + sort
      mapfile -t uniq_arr < <(printf "%s\n" "${arr[@]}" | awk '!seen[$0]++' | sort -n)
      printf "%s:%s\n" "$cpid" "$(IFS=,; echo "${uniq_arr[*]}")"
    else
      # empty when nothing matches
      printf "%s:\n" "$cpid"
    fi
  done
}

# --------- build the sysdig filter (OR over the host PIDs) ----------
make_sysdig_pid_filter_from_name() {
  local name="${1:-sys_generator}"
  local hosts=()

  while IFS=: read -r _ hostlist; do
    [[ -z "$hostlist" ]] && continue
    IFS=, read -r -a arr <<< "$hostlist"
    for h in "${arr[@]}"; do
      [[ -n "$h" ]] && hosts+=("$h")
    done
  done < <(resolve_host_pids_all "$name")

  if [[ ${#hosts[@]} -eq 0 ]]; then
    echo ""
    return 1
  fi

  local filter='('
  for i in "${!hosts[@]}"; do
    (( i > 0 )) && filter+=" or "
    filter+="proc.pid=${hosts[$i]}"
  done
  filter+=')'
  echo "$filter"
}

# --------- run ----------
main() {
  # for display: show the container->host list
  echo -n "PID map:"
  if out="$(resolve_host_pids_all "$NAME" 2>/dev/null)"; then
    echo
    while IFS=: read -r cpid hostlist; do
      echo "  container=${cpid}  host=${hostlist:-N/A}"
    done <<< "$out"
  else
    echo " (resolve failed)"
  fi

  # build the kernel filter
  FILTER="$(make_sysdig_pid_filter_from_name "$NAME")" || {
    echo "filter error: could not build host PID filter" >&2
    # last fallback: an OR filter over container PIDs (less accurate)
    if command -v pgrep >/dev/null 2>&1; then
      mapfile -t CPIDS < <(pgrep -x "$NAME" || true)
    else
      mapfile -t CPIDS < <(ps -C "$NAME" -o pid= | awk '{print $1}' || true)
    fi
    if [[ ${#CPIDS[@]} -eq 0 ]]; then
      echo "process '$NAME' not found" >&2
      exit 1
    fi
    FILTER='('
    for i in "${!CPIDS[@]}"; do
      (( i > 0 )) && FILTER+=" or "
      FILTER+="proc.pid=${CPIDS[$i]}"
    done
    FILTER+=')'
    echo "WARN: using container PIDs filter: $FILTER" >&2
  }

  # --- run sysdig ---
  # evt.dir="<" (enter only), -s SNAP, -M DUR, -v summary; the output is discarded
  # measure the wall-clock time
  local start_ns=$(_now_ns)
  local OUT
  OUT="$(sysdig -M "$DUR" -v -s "$SNAP" -w /dev/null 'evt.dir="<" and '"$FILTER" 2>&1 || true)"
  local end_ns=$(_now_ns)

  # print the raw summary line first, verbatim (for diagnostics)
  echo "$OUT" | sed -n '1,10p' | sed 's/^/ /'

  # ---- parsing ----
  local driver_events driver_drops elapsed_span captured eps_span
  driver_events="$(echo "$OUT" | sed -n 's/^Driver Events[[:space:]:]*\([0-9,][0-9,]*\).*/\1/p' | head -n1)"
  driver_drops="$( echo "$OUT" | sed -n 's/^Driver Drops[[:space:]:]*\([0-9,][0-9,]*\).*/\1/p'  | head -n1)"
  elapsed_span="$( echo "$OUT" | sed -n 's/^Elapsed time:[[:space:]]*\([0-9.][0-9.]*\).*/\1/p' | head -n1)"
  captured="$(     echo "$OUT" | sed -n 's/^Elapsed time:.*Captured Events:[[:space:]]*\([0-9,][0-9,]*\).*/\1/p' | head -n1)"
  eps_span="$(     echo "$OUT" | sed -n 's/^Elapsed time:.*,[[:space:]]*\([0-9.][0-9.]*\)[[:space:]]*eps$/\1/p' | head -n1)"

  local wall_s
  # ns → s
  wall_s="$(awk -v s="$start_ns" -v e="$end_ns" 'BEGIN{printf "%.6f",(e-s)/1e9}')"

  # convert to numbers
  local ev dr es cap eps
  ev=$(_num_or_zero "$driver_events")
  dr=$(_num_or_zero "$driver_drops")
  es=$(_num_or_zero "$elapsed_span")
  cap=$(_num_or_zero "$captured")
  eps=$(_num_or_zero "$eps_span")

  local drop_rate="N/A"
  if (( ev > 0 )); then
    drop_rate="$(awk -v e="$ev" -v d="$dr" 'BEGIN{printf "%.2f%%",(d/e)*100}')"
  fi

  local eps_wall="N/A"
  if (( cap > 0 )); then
    eps_wall="$(awk -v c="$cap" -v d="$DUR" 'BEGIN{ if(d>0) printf "%.2f", c/d; else print "N/A"}')"
  fi

  # ---- human-friendly summary ----
  echo
  echo "=== sysdig PID monitor summary ==="
  echo "Process name        : ${NAME}"
  echo -n "Container PIDs      : "
  if command -v pgrep >/dev/null 2>&1; then
    pgrep -x "$NAME" | tr '\n' ' '; echo
  else
    ps -C "$NAME" -o pid= | awk '{printf "%s ",$1} END{print ""}'
  fi
  echo -n "Host PIDs           : "
  if out2="$(resolve_host_pids_all "$NAME" 2>/dev/null)"; then
    echo "$out2" | awk -F: '{printf "%s ",$2}' | sed 's/  */ /g'
    echo
  else
    echo "N/A"
  fi
  echo "Duration (target)   : ${DUR}s"
  printf "Elapsed (event span): %ss\n" "${es}"
  printf "Elapsed (wall)      : %ss\n" "${wall_s}"
  printf "Driver Events       : %s\n" "${ev}"
  printf "Driver Drops        : %s\n" "${dr}"
  printf "Drop Rate           : %s\n" "${drop_rate}"
  printf "Captured Events     : %s\n" "${cap}"
  printf "EPS (wall clock)    : %s\n" "${eps_wall}"
  printf "EPS (event span)    : %s\n" "${eps}"

  exit 0
}

main "$@"
