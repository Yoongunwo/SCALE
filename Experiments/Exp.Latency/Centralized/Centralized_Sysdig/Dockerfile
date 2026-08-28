FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y \
    build-essential \
    cmake \
    libelf-dev \
    libssl-dev \
    sysdig

WORKDIR /app

COPY ./collect.c .

RUN gcc -O2 -Wall -Wextra -o sysdig_latency_logger collect.c

ENTRYPOINT ["sleep", "infinity"]