# syntax=docker/dockerfile:1

############################
# 1) Build stage
############################
FROM debian:bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY audisp_ts.c .
RUN gcc -O2 -Wall -Wextra -o audisp_ts audisp_ts.c && strip audisp_ts

############################
# 2) Runtime stage
############################
FROM debian:bookworm-slim
WORKDIR /opt/dist

# 도구들: auditctl/ausearch(=auditd, audispd-plugins 패키지에서 제공),
#         pgrep/ps(=procps), awk(=gawk), grep
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      auditd audispd-plugins \
      procps gawk grep \
      bash coreutils && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /src/audisp_ts /opt/dist/audisp_ts
COPY ./init.sh   /opt/dist/init.sh
COPY ./get_latency.sh /opt/dist/get_latency.sh

# 실행 가능하게
RUN chmod +x /opt/dist/init.sh /opt/dist/get_latency.sh /opt/dist/audisp_ts

# ⚠️ 쉘을 통해 && 를 사용해야 하므로 bash -lc로 실행
ENTRYPOINT ["/bin/bash", "-lc", "/opt/dist/init.sh"]


