# build stage
FROM ubuntu:22.04 AS build

WORKDIR /src

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential pkg-config &&\
    rm -rf /var/lib/apt/lists/*

COPY . .

RUN make

# runtime stage
FROM ubuntu:22.04

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    procps grep coreutils ca-certificates \
    linux-tools-5.15.0-141-generic && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build /src/build/syscall_collector /app/build/syscall_collector

RUN mkdir -p ./log

# 컨테이너는 떠 있기만 하면 됨
ENTRYPOINT ["bash","-lc","sleep infinity"]