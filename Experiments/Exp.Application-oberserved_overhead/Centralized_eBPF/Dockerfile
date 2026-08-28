# From libbpf image

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

# 예전에는 sleep infinity 로 띄워놓고 exec 로 들어가 손으로 make && ./collector 했다.
# 조건별 스윕에서는 파드가 뜨는 즉시 수집이 시작돼야 하므로 바로 실행한다.
# vmlinux.h 를 노드 BTF 에서 생성하니 빌드는 실행 시점에 해야 한다 (이미지 빌드 시점 X).
ENTRYPOINT ["sh", "-c", "make && ./collector"]