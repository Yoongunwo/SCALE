import sys, os, time

# 출력 경로는 EVENTS_OUT 환경변수로 받는다 (exe_v1.sh 가 설정).
# 없으면 스크립트 옆의 out/ 로 떨어뜨린다.
out = os.environ.get(
    "EVENTS_OUT",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "out", "syscalls_events.ndjson"),
)
os.makedirs(os.path.dirname(out), exist_ok=True)
f = open(out, 'a', buffering=1)

for line in sys.stdin:
    line = line.strip()
    if not line: continue
    t_ns = time.time_ns()  # 유저스페이스 수신 시각(ns). 노드에서 실행되므로
                           # 이벤트의 time 필드(노드 시계)와 같은 시계 영역이다.
    # event는 tetra의 원본 JSON 한 줄. 파싱 없이 감싸서 기록.
    f.write(f'{{"recv_ns":{t_ns},"event":{line}}}\n')
