import sys, os, time

# The output path comes from the EVENTS_OUT environment variable (set by exe_v1.sh).
# If it is unset, events are written to out/ next to this script.
out = os.environ.get(
    "EVENTS_OUT",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "out", "syscalls_events.ndjson"),
)
os.makedirs(os.path.dirname(out), exist_ok=True)
f = open(out, 'a', buffering=1)

for line in sys.stdin:
    line = line.strip()
    if not line: continue
    t_ns = time.time_ns()  # userspace receive time (ns). This runs on the node, so it
                           # shares the same clock domain as the event's time field
                           # (the node clock).
    # event is one raw JSON line from tetra: wrapped and recorded without parsing.
    f.write(f'{{"recv_ns":{t_ns},"event":{line}}}\n')
