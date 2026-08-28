BPF_CLANG=clang
BPF_CFLAGS=-g -O2 -Wall -target bpf -D__TARGET_ARCH_x86_64

all: collector.skel.h main read_counter

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

collector.bpf.o: collector.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -I. -c $< -o $@

collector.skel.h: collector.bpf.o
	bpftool gen skeleton $< > $@

main: collector.c collector.skel.h
	clang -g -O2 -Wall -I. -o collector collector.c -lelf -lz -lbpf

read_counter: read_counter.c
	clang -g -O2 -Wall -I. -o read_counter read_counter.c -lelf -lz -lbpf

clean:
	rm -f *.o *.skel.h collector vmlinux.h syscalls.log read_counter