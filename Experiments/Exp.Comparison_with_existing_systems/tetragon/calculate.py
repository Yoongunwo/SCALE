import json, os, sys, datetime as dt
from pathlib import Path
from statistics import mean

# 입력 경로는 EVENTS_OUT 환경변수로 받는다 (exe_v1.sh 가 설정).
p = Path(os.environ.get(
    "EVENTS_OUT",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "out", "syscalls_events.ndjson"),
))
if not p.exists():
    sys.exit(f"[!] {p} 없음 — start 로 수집한 뒤 실행할 것.")
if p.stat().st_size == 0:
    sys.exit(f"[!] {p} 가 비어 있음 — 워크로드가 syscall 을 만들지 않았을 가능성.")

tps = {}          # {sec: count}
lat = []          # latency(ms) 샘플들
n_total = 0
recv_first = None
recv_last  = None

def parse_evt_ts(s: str):
    # "2025-09-09T06:45:22.965171343Z" → datetime(UTC)
    s = (s or '').rstrip('Z')
    if not s:
        return None
    if '.' in s:
        dtstr, frac = s.split('.', 1)
        usec = int((frac + '000000')[:6])  # ns→µs 절삭
    else:
        dtstr, usec = s, 0
    base = dt.datetime.strptime(dtstr, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc)
    return base.replace(microsecond=usec)

def pct(a, p):
    if not a: return float('nan')
    a = sorted(a)
    idx = int(round(p * (len(a)-1)))
    idx = max(0, min(idx, len(a)-1))
    return a[idx]

for line in p.open():
    try:
        obj = json.loads(line)
    except Exception:
        continue
    recv_ns = obj.get('recv_ns')
    evt     = obj.get('event', {})
    if recv_ns is None:
        continue

    n_total += 1
    recv_dt = dt.datetime.fromtimestamp(int(recv_ns)/1e9, tz=dt.timezone.utc)
    recv_first = recv_dt if recv_first is None or recv_dt < recv_first else recv_first
    recv_last  = recv_dt if recv_last  is None or recv_dt > recv_last  else recv_last

    sec = int(recv_ns) // 1_000_000_000
    tps[sec] = tps.get(sec, 0) + 1

    evt_ts = parse_evt_ts(evt.get('time', ''))
    if evt_ts is not None:
        lat.append((recv_dt - evt_ts).total_seconds() * 1000.0)

# --- 출력 ---
# 샘플 TPS 5초
print("TPS samples (first 5 secs):")
for i, (sec, c) in enumerate(sorted(tps.items())[:5]):
    print(dt.datetime.fromtimestamp(sec, tz=dt.timezone.utc).isoformat(), c)

# 레이턴시 요약
if lat:
    print("Latency ms: mean=%.3f p50=%.3f p90=%.3f p99=%.3f max=%.3f"
          % (mean(lat), pct(lat,0.5), pct(lat,0.9), pct(lat,0.99), max(lat)))
else:
    print("No latency samples.")

# 처리량(throughput)
if n_total and recv_first and recv_last:
    duration = (recv_last - recv_first).total_seconds()
    duration = max(duration, 1e-9)  # 0분모 방지
    avg_eps = n_total / duration    # 전체 평균 이벤트/초
    tps_vals = list(tps.values())
    peak_tps = max(tps_vals) if tps_vals else 0
    peak_sec = max(tps, key=tps.get) if tps else None

    print("Events:", n_total)
    print("Window :", f"{recv_first.isoformat()} → {recv_last.isoformat()} ({duration:.3f}s)")
    print("Average throughput (events/s): %.2f" % avg_eps)
    if peak_sec is not None:
        print("Peak 1s TPS:", peak_tps, "at",
              dt.datetime.fromtimestamp(peak_sec, tz=dt.timezone.utc).isoformat())
        print("Per-second TPS percentiles p50/p90/p99:",
              pct(tps_vals,0.5), pct(tps_vals,0.9), pct(tps_vals,0.99))
else:
    print("No events or timestamps.")
