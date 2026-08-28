#!/usr/bin/env python3
import re
import statistics as stats

# 파일 경로만 바꾸면 됨
PATH_EVOKED  = "./Exp/5.Latency/Proposed/result/host.log"   # 예: "Evoked Time=6854085.408962, PID=..., syscall=..."
PATH_LATER   = "./Exp/5.Latency/Proposed/result/pod.log"    # 예: "6854085.409008 PID=... syscall=..."

re_evoked = re.compile(
    r'^Evoked Time=(?P<t>\d+\.\d+),\s*PID=(?P<pid>\d+)\s+syscall=(?P<sc>\d+)'
)
re_later  = re.compile(
    r'^(?P<t>\d+\.\d+)\s+PID=(?P<pid>\d+)\s+syscall=(?P<sc>\d+)'
)

def parse_file(path, regex):
    out = []
    with open(path, 'r') as f:
        for ln in f:
            m = regex.match(ln.strip())
            if not m:
                continue
            t   = float(m.group('t'))
            pid = int(m.group('pid'))
            sc  = int(m.group('sc'))
            out.append((t, pid, sc))
    return out

def main():
    evoked  = parse_file(PATH_EVOKED, re_evoked)   # 더 과거(먼저 찍힌) 로그
    later   = parse_file(PATH_LATER,  re_later)    # 나중(뒤에 찍힌) 로그

    n = min(len(evoked), len(later))
    if n == 0:
        print("입력 로그에서 파싱된 항목이 없습니다.")
        return

    deltas = []  # seconds
    mismatches = 0

    for i in range(n):
        t0, pid0, sc0 = evoked[i]
        t1, pid1, sc1 = later[i]

        if pid0 != pid1 or sc0 != sc1:
            mismatches += 1
            print(f"[warn] i={i}: (pid,sc) 불일치 — evoked=({pid0},{sc0}) vs later=({pid1},{sc1}); 건너뜀")
            continue

        delta = t1 - t0  # 둘 다 MONOTONIC 기준이므로 단순 차이
        deltas.append(delta)

    if not deltas:
        print("매칭된 (pid,syscall) 쌍이 없습니다.")
        return

    mean_delta = sum(deltas) / len(deltas)
    std_delta  = stats.pstdev(deltas) if len(deltas) > 1 else 0.0
    min_delta  = min(deltas)
    max_delta  = max(deltas)

    print(f"# pairs used: {len(deltas)} / parsed: evoked={len(evoked)}, later={len(later)}, mismatches={mismatches}")
    print(f"평균 지연: {mean_delta:.9f} s  ({mean_delta*1e6:.3f} µs)")
    print(f"표준편차: {std_delta:.9f} s  ({std_delta*1e6:.3f} µs)")
    print(f"최소/최대: {min_delta:.9f} s ~ {max_delta:.9f} s")
    print("\n상위 10개 샘플(초, µs):")
    for d in deltas[:10]:
        print(f"  {d:.9f} s  ({d*1e6:.3f} µs)")

if __name__ == "__main__":
    main()
