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

# Previously the container ran sleep infinity and we exec'd in to run make && ./collector by hand.
# In the per-condition sweep collection must start as soon as the pod comes up, so run it directly.
# vmlinux.h is generated from the node BTF, so the build must happen at run time (not at image build time).
ENTRYPOINT ["sh", "-c", "make && ./collector"]