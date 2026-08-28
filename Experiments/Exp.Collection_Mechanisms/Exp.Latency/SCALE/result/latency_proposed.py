#!/usr/bin/env python3
import re
import statistics as stats

# only the file paths need to change
PATH_EVOKED  = "./Exp/5.Latency/Proposed/result/host.log"   # e.g. "Evoked Time=6854085.408962, PID=..., syscall=..."
PATH_LATER   = "./Exp/5.Latency/Proposed/result/pod.log"    # e.g. "6854085.409008 PID=... syscall=..."

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
    evoked  = parse_file(PATH_EVOKED, re_evoked)   # the earlier log (stamped first)
    later   = parse_file(PATH_LATER,  re_later)    # the later log (stamped afterwards)

    n = min(len(evoked), len(later))
    if n == 0:
        print("No entries were parsed from the input logs.")
        return

    deltas = []  # seconds
    mismatches = 0

    for i in range(n):
        t0, pid0, sc0 = evoked[i]
        t1, pid1, sc1 = later[i]

        if pid0 != pid1 or sc0 != sc1:
            mismatches += 1
            print(f"[warn] i={i}: (pid,sc) mismatch - evoked=({pid0},{sc0}) vs later=({pid1},{sc1}); skipped")
            continue

        delta = t1 - t0  # both are MONOTONIC, so a plain difference is enough
        deltas.append(delta)

    if not deltas:
        print("No matching (pid,syscall) pairs.")
        return

    mean_delta = sum(deltas) / len(deltas)
    std_delta  = stats.pstdev(deltas) if len(deltas) > 1 else 0.0
    min_delta  = min(deltas)
    max_delta  = max(deltas)

    print(f"# pairs used: {len(deltas)} / parsed: evoked={len(evoked)}, later={len(later)}, mismatches={mismatches}")
    print(f"Mean latency: {mean_delta:.9f} s  ({mean_delta*1e6:.3f} µs)")
    print(f"Std deviation: {std_delta:.9f} s  ({std_delta*1e6:.3f} µs)")
    print(f"Min/Max: {min_delta:.9f} s ~ {max_delta:.9f} s")
    print("\nTop 10 samples (s, µs):")
    for d in deltas[:10]:
        print(f"  {d:.9f} s  ({d*1e6:.3f} µs)")

if __name__ == "__main__":
    main()
