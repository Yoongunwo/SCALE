#!/usr/bin/env python3
import subprocess
import tempfile

NS = "default"
POD_PREFIX = "exp2-"
LINES = 30000
TOPK = 10

def run(cmd):
    return subprocess.check_output(cmd, shell=True, text=True).strip()

# 1. get the list of Running Pods
pods = run(
    f"kubectl get pods -n {NS} "
    f"--field-selector=status.phase=Running "
    f"-o jsonpath='{{.items[*].metadata.name}}'"
).split()

pods = [p for p in pods if p.startswith(POD_PREFIX)]
if not pods:
    print("No running pods.")
    exit(1)

# 2. get the tail output of each Pod
pod_lines = {}
for pod in pods:
    try:
        cmd = (
            f"kubectl exec -n {NS} {pod} -- sh -c '"
            "f=$(ls -t /var/log/syscalls_*.log /tmp/syscalls_*.log "
            "/workspace/syscalls_*.log /app/syscalls_*.log ./syscalls_*.log "
            "2>/dev/null | head -1); "
            f"[ -n \"$f\" ] && tail -n {LINES} \"$f\" || true'"
        )
        out = run(cmd)
        if out:
            pod_lines[pod] = out.splitlines()
    except subprocess.CalledProcessError:
        continue

if not pod_lines:
    print("No valid data collected.")
    exit(2)

# 3. compare every pod at each line index
results = []
for n in range(LINES):
    min_ev, max_co = None, None
    for pod, lines in pod_lines.items():
        if n >= len(lines):
            continue
        line = lines[n]
        import re
        m_ev = re.search(r"Evoked Time=([0-9]+\.[0-9]+)", line)
        m_co = re.search(r"Collected Time=([0-9]+\.[0-9]+)", line)
        if not m_ev or not m_co:
            continue
        ev, co = float(m_ev.group(1)), float(m_co.group(1))
        min_ev = ev if min_ev is None or ev < min_ev else min_ev
        max_co = co if max_co is None or co > max_co else max_co
    if min_ev is not None and max_co is not None:
        elapsed = max_co - min_ev
        results.append((n+1, min_ev, max_co, elapsed))

# 4. sort the results and print them
if not results:
    print("No valid elapsed times.")
    exit(3)

results.sort(key=lambda x: x[3])  # ascending by elapsed
sum = 0.0   

print(f"=== Top {TOPK} fastest elapsed times ===")
for line, ev, co, diff in results[:TOPK]:
    print(f"line={line} earliest_evoked={ev:.6f} latest_collected={co:.6f} elapsed={diff:.6f}")
    sum += diff

avg = sum / min(TOPK, len(results))
print(f"Average of top {TOPK} elapsed times: {avg:.6f}")