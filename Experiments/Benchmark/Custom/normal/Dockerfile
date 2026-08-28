FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y \
    gcc \
    make \
    libc6-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY sys_generator.c .

RUN gcc -o sys_generator sys_generator.c

CMD ["./sys_generator"]