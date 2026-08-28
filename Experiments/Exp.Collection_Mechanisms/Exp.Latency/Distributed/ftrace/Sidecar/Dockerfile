# FROM libbpf image

WORKDIR /app

RUN apt-get update && apt-get install -y \
    make \
    clang \
    llvm \
    gcc \
    libelf-dev \
    libbpf-dev \
    libz-dev \
    iproute2 \
    pkg-config \
    libjansson-dev \
    linux-headers-{Kernel Version}

COPY . .

# ENTRYPOINT ["sh", "-c", "make RINGBUF_POW2=$RINGBUF_POW2 && ./build/syscall_collector 1"]
ENTRYPOINT sh -c 'make && sleep infinity'

