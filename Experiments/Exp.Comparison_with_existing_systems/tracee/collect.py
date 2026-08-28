import sys, os, time

# Tracee 의 JSON 출력 한 줄을 받아 유저스페이스 수신 시각을 덧붙여 기록한다.
# 노드에서 실행되므로 time.time_ns() 는 이벤트 timestamp 와 같은 시계 영역이다.
#
# 출력 경로는 EVENTS_OUT 환경변수로 받는다 (exe_v1.sh 가 설정).
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
    # 파싱 없이 원본 JSON 을 그대로 감싼다. 파싱 비용이 수집기 병목이 되면 안 된다.
    f.write('{"recv_ns":%d,"event":%s}\n' % (t_ns, line))
