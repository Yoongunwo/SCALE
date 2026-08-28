#!/usr/bin/env bash
set -euo pipefail

# =========================================
# sysdig.sh
# - 여러 개의 sys_generator 프로세스를 host PID로 매핑하여
#   evt.dir="<" + (proc.pid=H1 or proc.pid=H2 ...) 커널 필터로 캡처
# - /host/proc 가 hostPath 로 마운트되어 있어야 정확한 host PID 매핑 가능
#   (readOnly OK)
# =========================================

NAME="${1:-sys_generator}"   # 프로세스 이름(정확 매칭, 기본 sys_generator)
DUR="${2:-10}"               # 수집 시간(초) - sysdig -M
SNAP="${3:-80}"              # 스냅렌 -s (작게 할수록 드롭 감소)

# /host/proc 마운트 필요:
# spec:
#   volumes:
#   - name: host-proc
#     hostPath: { path: /proc }
#   containers:
#   - volumeMounts:
#     - name: host-proc
#       mountPath: /host/proc
#       readOnly: true

# --------- 유틸 ----------
_now_ns() { date +%s%N; }

_num_or_zero() {
  local s="${1:-}"
  if [[ -z "$s" ]]; then echo 0; return; fi
  echo "$s" | tr -d ',' | awk '{gsub(/[^0-9.]/,""); if($0=="") print 0; else print}'
}

# --------- 여러 PID 매핑 (container PID -> host PID들) ----------
# 출력: 각 줄 "cpid:host1,host2,..."
resolve_host_pids_all() {
  local name="${1:-sys_generator}"

  # 1) 컨테이너 PID들 수집 (정확 매칭)
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

  # /host/proc 없으면 컨테이너 PID로만 리턴(필터는 작동하지만 커널 PID 기준이 아님)
  if [[ ! -r /host/proc ]]; then
    echo "WARN: /host/proc not mounted; using container PIDs as-is" >&2
    for cpid in "${cpids[@]}"; do
      echo "${cpid}:${cpid}"
    done
    return 0
  fi

  # 2) /host/proc 스캔: NSpid 마지막 == cpid && comm == name
  declare -A host_by_cpid
  local sp pid last comm

  while IFS= read -r -d '' sp; do
    pid="${sp#/host/proc/}"
    pid="${pid%/status}"

    # 마지막 NSpid 토큰(컨테이너 PID)을 뽑음
    last="$(awk '/^NSpid:/{for(i=2;i<=NF;i++) L=$i} END{if(L!="") print L}' "$sp" 2>/dev/null)" || true
    [[ -z "$last" ]] && continue

    if read -r comm <"/host/proc/$pid/comm"; then
      [[ "$comm" == "$name" ]] || continue
    else
      continue
    fi

    host_by_cpid["$last"]+="${host_by_cpid[$last]:+ }$pid"
  done < <(find /host/proc -maxdepth 2 -type f -name status -print0 2>/dev/null)

  # 3) 결과 출력
  for cpid in "${cpids[@]}"; do
    if [[ -n "${host_by_cpid[$cpid]:-}" ]]; then
      read -r -a arr <<<"${host_by_cpid[$cpid]}"
      # uniq + 정렬
      mapfile -t uniq_arr < <(printf "%s\n" "${arr[@]}" | awk '!seen[$0]++' | sort -n)
      printf "%s:%s\n" "$cpid" "$(IFS=,; echo "${uniq_arr[*]}")"
    else
      # 매칭 실패 시 빈값
      printf "%s:\n" "$cpid"
    fi
  done
}

# --------- sysdig 필터 생성 (host PID들로 OR) ----------
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

# --------- 실행 ----------
main() {
  # 매핑 표기용: container->host 리스트를 보여줌
  echo -n "PID map:"
  if out="$(resolve_host_pids_all "$NAME" 2>/dev/null)"; then
    echo
    while IFS=: read -r cpid hostlist; do
      echo "  container=${cpid}  host=${hostlist:-N/A}"
    done <<< "$out"
  else
    echo " (resolve failed)"
  fi

  # 커널 필터 생성
  FILTER="$(make_sysdig_pid_filter_from_name "$NAME")" || {
    echo "filter error: could not build host PID filter" >&2
    # 마지막 폴백: 컨테이너 PID OR 필터 (정확도↓)
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

  # --- sysdig 실행 ---
  # evt.dir="<" (enter만), -s SNAP, -M DUR, -v 요약, 출력은 버림
  # 벽시계 시간 측정
  local start_ns=$(_now_ns)
  local OUT
  OUT="$(sysdig -M "$DUR" -v -s "$SNAP" -w /dev/null 'evt.dir="<" and '"$FILTER" 2>&1 || true)"
  local end_ns=$(_now_ns)

  # 원본 요약 라인 먼저 그대로 출력(진단용)
  echo "$OUT" | sed -n '1,10p' | sed 's/^/ /'

  # ---- 파싱 ----
  local driver_events driver_drops elapsed_span captured eps_span
  driver_events="$(echo "$OUT" | sed -n 's/^Driver Events[[:space:]:]*\([0-9,][0-9,]*\).*/\1/p' | head -n1)"
  driver_drops="$( echo "$OUT" | sed -n 's/^Driver Drops[[:space:]:]*\([0-9,][0-9,]*\).*/\1/p'  | head -n1)"
  elapsed_span="$( echo "$OUT" | sed -n 's/^Elapsed time:[[:space:]]*\([0-9.][0-9.]*\).*/\1/p' | head -n1)"
  captured="$(     echo "$OUT" | sed -n 's/^Elapsed time:.*Captured Events:[[:space:]]*\([0-9,][0-9,]*\).*/\1/p' | head -n1)"
  eps_span="$(     echo "$OUT" | sed -n 's/^Elapsed time:.*,[[:space:]]*\([0-9.][0-9.]*\)[[:space:]]*eps$/\1/p' | head -n1)"

  local wall_s
  # ns → s
  wall_s="$(awk -v s="$start_ns" -v e="$end_ns" 'BEGIN{printf "%.6f",(e-s)/1e9}')"

  # 숫자화
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

  # ---- 사람이 보기 쉬운 요약 ----
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
