#!/usr/bin/env python3
"""
Tracee NDJSON aggregation: recv_ns (collector receive time) - event.timestamp
(kernel event time)

Reads the file produced by collect.py. One line has the form:
    {"recv_ns": <int ns>, "event": { ...tracee json... }}

The unit and reference point of Tracee's timestamp depend on the version and the
output options:
  - default: epoch nanoseconds
  - with the 'relative-time' output option: nanoseconds since boot
Dump one line with 'exe_v1.sh check' to confirm, and if it is boot-relative run
with TRACEE_TS=relative. In that case the boot time is derived from /proc/uptime
and the current epoch time, and used as the correction.

Note: we deliberately do NOT 'correct' the difference by subtracting its median
      offset. Doing so drives p50 structurally to 0 and erases the latency
      signal. Running the collector on the node removes the need for any such
      correction in the first place.
"""
import json, os, sys, time

EVENT = os.environ.get("EVENT", "sys_enter")
TS_MODE = os.environ.get("TRACEE_TS", "epoch")   # epoch | relative

p = os.environ.get(
    "EVENTS_OUT",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "out", "syscalls_events.ndjson"),
)
if not os.path.exists(p):
    sys.exit("[!] %s not found - collect with start before running this." % p)
if os.path.getsize(p) == 0:
    sys.exit("[!] %s is empty - the workload may not have issued any syscalls." % p)

boot_ns = 0
if TS_MODE == "relative":
    with open("/proc/uptime") as f:
        up_s = float(f.read().split()[0])
    boot_ns = time.time_ns() - int(up_s * 1e9)


def pct(a, q):
    if not a:
        return float("nan")
    i = int(round(q * (len(a) - 1)))
    return a[max(0, min(i, len(a) - 1))]


lat_ms = []
tps_recv = {}      # events per second, by receive time
tps_kern = {}      # events per second, by kernel time
n = 0
recv_min = recv_max = None
kern_min = kern_max = None
skipped = 0

with open(p, encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            o = json.loads(line)
        except Exception:
            skipped += 1
            continue
        recv = o.get("recv_ns")
        ev = o.get("event") or {}
        if recv is None:
            skipped += 1
            continue
        if EVENT and ev.get("eventName") != EVENT:
            continue
        ts = ev.get("timestamp")
        if ts is None:
            skipped += 1
            continue
        ts = int(ts) + boot_ns

        n += 1
        recv = int(recv)
        recv_min = recv if recv_min is None or recv < recv_min else recv_min
        recv_max = recv if recv_max is None or recv > recv_max else recv_max
        kern_min = ts if kern_min is None or ts < kern_min else kern_min
        kern_max = ts if kern_max is None or ts > kern_max else kern_max

        lat_ms.append((recv - ts) / 1e6)
        sr = recv // 1_000_000_000
        sk = ts // 1_000_000_000
        tps_recv[sr] = tps_recv.get(sr, 0) + 1
        tps_kern[sk] = tps_kern.get(sk, 0) + 1

if n == 0:
    sys.exit("[!] no events with eventName=%s." % EVENT)

recv_win = (recv_max - recv_min) / 1e9
kern_win = (kern_max - kern_min) / 1e9

lat_ms.sort()
tv = sorted(tps_recv.values())

print("Events: %d   (skipped %d)" % (n, skipped))
print("Recv window   : %.3fs   -> avg %.2f eps" % (recv_win, n / recv_win if recv_win > 0 else 0))
print("Kernel window : %.3fs   -> avg %.2f eps" % (kern_win, n / kern_win if kern_win > 0 else 0))
print("  [i] The kernel window is the workload runtime; if the receive window is longer, the difference is backlog.")

neg = sum(1 for x in lat_ms if x < 0)
print("Latency ms: mean=%.3f p50=%.3f p90=%.3f p99=%.3f max=%.3f  (negative=%d)" % (
    sum(lat_ms) / len(lat_ms), pct(lat_ms, .5), pct(lat_ms, .9), pct(lat_ms, .99), lat_ms[-1], neg))
if neg:
    print("  [!] negative latencies -> the timestamp reference may be wrong. Check TRACEE_TS.")

print("Per-second TPS (recv) p50/p90/p99/peak: %d / %d / %d / %d" % (
    pct(tv, .5), pct(tv, .9), pct(tv, .99), tv[-1]))
avg = n / recv_win if recv_win > 0 else 0
p50 = pct(tv, .5)
if p50:
    d = 100.0 * abs(avg - p50) / p50
    print("  avg vs p50 difference: %.1f%%   %s" % (d, "OK" if d <= 5 else "[!] over 5%% - the window may include idle time"))

first = sorted(tps_recv.items())[:5]
print("TPS samples (first 5 secs):")
for s, c in first:
    print("  %d %d" % (s, c))
