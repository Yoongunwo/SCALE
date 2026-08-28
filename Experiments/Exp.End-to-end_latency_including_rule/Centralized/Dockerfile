FROM yoongunwo/ebpf:1.1-libbpf

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
    linux-headers-5.15.0-141-generic

COPY . .

CMD ["sleep", "infinity"]