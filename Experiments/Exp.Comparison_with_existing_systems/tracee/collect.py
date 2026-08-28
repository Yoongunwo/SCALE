import sys, os, time

# Reads one JSON line of Tracee output and records it with the userspace receive
# time appended. This runs on the node, so time.time_ns() shares the same clock
# domain as the event timestamp.
#
# The output path comes from the EVENTS_OUT environment variable (set by exe_v1.sh).
out = os.environ.get(
    "EVENTS_OUT",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "out", "syscalls_events.ndjson"),
)
os.makedirs(os.path.dirname(out), exist_ok=True)
f = open(out, 'a', buffering=1)

for line in sys.stdin:
    line = line.strip()
    if not line or not line.startswith('{'):
        continue
    t_ns = time.time_ns()
    # Wrap the raw JSON as-is, without parsing: parsing cost must not become the
    # collector's bottleneck.
    f.write('{"recv_ns":%d,"event":%s}\n' % (t_ns, line))
