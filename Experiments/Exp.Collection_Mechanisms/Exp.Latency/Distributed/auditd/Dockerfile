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

# tools: auditctl/ausearch (from the auditd and audispd-plugins packages),
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

# make it executable
RUN chmod +x /opt/dist/init.sh /opt/dist/get_latency.sh /opt/dist/audisp_ts

# && has to go through a shell, so run it with bash -lc
ENTRYPOINT ["/bin/bash", "-lc", "/opt/dist/init.sh"]


