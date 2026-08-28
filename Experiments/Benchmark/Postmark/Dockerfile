FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends postmark ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# 기본 파라미터 (환경변수로 덮어쓰기 가능)
ENV PM_NUMBER=500 \
    PM_TRANSACTIONS=25000 \
    PM_SIZE_MIN_KB=5 \
    PM_SIZE_MAX_KB=512 \
    PM_READ=512 \
    PM_WRITE=512 \
    PM_LOCATION=/data \
    PM_SEED=42

# 데이터/설정 경로
RUN mkdir -p /data /config
COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && chmod +x /entrypoint.sh
RUN chmod +x /entrypoint.sh

VOLUME ["/data"]   # 벤치 대상 FS를 /data로 마운트
ENTRYPOINT ["/entrypoint.sh"]
