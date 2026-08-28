#!/usr/bin/env python3
"""
Tracee NDJSON 집계: recv_ns(수집기 수신 시각) - event.timestamp(커널 이벤트 시각)

collect.py 가 만든 파일을 읽는다. 한 줄 형식:
    {"recv_ns": <int ns>, "event": { ...tracee json... }}

Tracee 의 timestamp 단위/기준은 버전과 출력 옵션에 따라 다르다.
  - 기본: epoch nanoseconds
  - 'relative-time' 출력 옵션: boot 기준 nanoseconds
exe_v1.sh check 로 한 줄 덤프해 확인한 뒤, boot 기준이면 TRACEE_TS=relative 로 실행한다.
그 경우 /proc/uptime 과 현재 epoch 로 boot 시각을 구해 보정한다.

주의: 두 시각의 차이에서 중앙값 오프셋을 빼는 식의 '보정'은 하지 않는다.
      그렇게 하면 p50 이 구조적으로 0 이 되어 지연 신호가 사라진다.
      수집기를 노드에서 돌리면 보정 자체가 불필요하다.
"""
import json, os, sys, time

EVENT = os.environ.get("EVENT", "sys_enter")
TS_MODE = os.environ.get("TRACEE_TS", "epoch")   # epoch | relative

p = os.environ.get(
    "EVENTS_OUT",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "out", "syscalls_events.ndjson"),
)
if not os.path.exists(p):
    sys.exit("[!] %s 없음 — start 로 수집한 뒤 실행할 것." % p)
if os.path.getsize(p) == 0:
    sys.exit("[!] %s 가 비어 있음 — 워크로드가 syscall 을 만들지 않았을 가능성." % p)

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
tps_recv = {}      # 수신 시각 기준 초당 건수
tps_kern = {}      # 커널 시각 기준 초당 건수
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
    sys.exit("[!] eventName=%s 인 이벤트가 없음." % EVENT)

recv_win = (recv_max - recv_min) / 1e9
kern_win = (kern_max - kern_min) / 1e9

lat_ms.sort()
tv = sorted(tps_recv.values())

print("Events: %d   (skipped %d)" % (n, skipped))
print("Recv window   : %.3fs   -> avg %.2f eps" % (recv_win, n / recv_win if recv_win > 0 else 0))
print("Kernel window : %.3fs   -> avg %.2f eps" % (kern_win, n / kern_win if kern_win > 0 else 0))
print("  [i] 커널 창이 워크로드 실행 시간, 수신 창이 그보다 길면 그 차이가 적체다.")

neg = sum(1 for x in lat_ms if x < 0)
print("Latency ms: mean=%.3f p50=%.3f p90=%.3f p99=%.3f max=%.3f  (negative=%d)" % (
    sum(lat_ms) / len(lat_ms), pct(lat_ms, .5), pct(lat_ms, .9), pct(lat_ms, .99), lat_ms[-1], neg))
if neg:
    print("  [!] 음수 지연이 있다 -> timestamp 기준이 틀렸을 수 있다. TRACEE_TS 확인.")

print("Per-second TPS (recv) p50/p90/p99/peak: %d / %d / %d / %d" % (
    pct(tv, .5), pct(tv, .9), pct(tv, .99), tv[-1]))
avg = n / recv_win if recv_win > 0 else 0
p50 = pct(tv, .5)
if p50:
    d = 100.0 * abs(avg - p50) / p50
    print("  avg vs p50 차이: %.1f%%   %s" % (d, "OK" if d <= 5 else "[!] 5%% 초과 — 창에 유휴가 섞였을 수 있다"))

first = sorted(tps_recv.items())[:5]
print("TPS samples (first 5 secs):")
for s, c in first:
    print("  %d %d" % (s, c))
