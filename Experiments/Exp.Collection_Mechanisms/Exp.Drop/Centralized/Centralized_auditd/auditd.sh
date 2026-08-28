#!/usr/bin/env bash
# audit_track_pids.sh
# usage: sudo ./audit_track_pids.sh [process_name] [duration_sec]
# ex)    sudo ./audit_track_pids.sh sys_generator 10
#
# - install a -F pid=<tid> rule for every thread (TID) of the target process
# - ausearch only by a unique key (different per run), avoiding time parsing issues
# - output: collection window (usec), lines (number of SYSCALL records), drops (when available)
# - fault tolerant: the script keeps going even if auditctl/ausearch partially fails

set -u  # catch unset variables only; other failures do not abort the script
shopt -s nullglob

NAME="${1:-sys_generator}"
DUR="${2:-20}"      # seconds

need_cmds=(auditctl ausearch pgrep ps awk grep date)
for c in "${need_cmds[@]}"; do
  if ! command -v "$c" >/dev/null 2>&1; then
    echo "ERR: missing cmd: $c" >&2
    exit 1
  fi
done

if [[ $EUID -ne 0 ]]; then
  echo "ERR: must run as root" >&2
  exit 1
fi

# --- auditd status ---
if ! pgrep -x auditd >/dev/null 2>&1; then
  echo "ERR: auditd not running (try: systemctl start auditd)" >&2
  exit 1
fi

st="$(auditctl -s 2>/dev/null || true)"
echo "$st" | grep -q 'enabled 1' || {
  echo "ERR: audit not enabled (see 'auditctl -s')" >&2
  exit 1
}
if echo "$st" | grep -q 'immutable 1'; then
  echo "ERR: audit rules are immutable. Reboot or disable immutability." >&2
  exit 1
fi

# --- collect the target TGIDs ---
if ! pgrep -x "$NAME" >/dev/null 2>&1; then
  mapfile -t TGIDS < <(ps -eo pid=,comm= | awk -v n="$NAME" '$2==n{print $1}')
else
  mapfile -t TGIDS < <(pgrep -x "$NAME")
fi

if [[ ${#TGIDS[@]} -eq 0 ]]; then
  echo "No '$NAME' processes found."
  exit 0
fi
echo "[INFO] Found $NAME TGIDs: ${TGIDS[*]}"

# --- unique key for the installation & cleanup trap ---
KEY="tid_trace_$$"
cleanup() {
  echo "[INFO] Cleaning rules (key='$KEY')..."
  auditctl -D -k "$KEY" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

ARCHES=(b64)  # add b32 if needed: ARCHES=(b64 b32)

# --- install the rules (every thread TID) ---
INSTALLED_CNT=0
for tgid in "${TGIDS[@]}"; do
  for d in /proc/"$tgid"/task/[0-9]*; do
    [[ -d "$d" ]] || continue
    tid="${d##*/}"
    for arch in "${ARCHES[@]}"; do
      # keep going on failure
      auditctl -a always,exit -F arch="$arch" -F pid="$tid" -S all -k "$KEY" >/dev/null 2>&1 || true
    done
    ((INSTALLED_CNT++))
  done
done
echo "[INFO] Installed $INSTALLED_CNT pid rules (by TIDs) with key='$KEY'"

# (optional) verify the installation (ignored on failure)
echo "[INFO] Current rules with key:"
auditctl -l 2>/dev/null | grep -F "key=$KEY" || true

# --- wait while collecting ---
START_EPOCH="$(date +%s)"
sleep "$DUR"
END_EPOCH="$(date +%s)"

# --- aggregate (this key only) ---
LINES="$(ausearch -k "$KEY" -m SYSCALL 2>/dev/null | grep -c '^type=SYSCALL' || true)"

# drops needs a time window -> try the unix epoch, fall back to 0
DROPS="0"
if ausearch -m DAEMON_LOST -ts "@$START_EPOCH" -te "@$END_EPOCH" >/dev/null 2>&1; then
  DROPS="$(ausearch -m DAEMON_LOST -ts "@$START_EPOCH" -te "@$END_EPOCH" 2>/dev/null | grep -c '^type=DAEMON_LOST' || true)"
fi

# --- output (us) ---
DUR_US=$(( DUR * 1000000 ))
printf "\n--- Results ---\n"
printf "%-18s %-10s %-10s\n" "duration(usec)" "lines" "drops"
printf "%-18s %-10s %-10s\n" "$DUR_US" "$LINES" "$DROPS"

# sample (for human reading)
echo
echo "Sample records (first 6, decoded):"
ausearch -k "$KEY" -m SYSCALL -i 2>/dev/null | head -n 30 || true
