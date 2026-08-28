BPF_CLANG=clang
BPF_CFLAGS=-g -O2 -Wall -target bpf -D__TARGET_ARCH_x86_64

all: collector.skel.h main syscall_rule_engine

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

collector.bpf.o: collector.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -I. -c $< -o $@

collector.skel.h: collector.bpf.o
	bpftool gen skeleton $< > $@

main: collector.c collector.skel.h
	clang -g -O2 -Wall -I. -o collector collector.c -lelf -lz -lbpf

syscall_rule_engine: syscall_rule_engine.c
	clang -g -O2 -Wall -o syscall_rule_engine syscall_rule_engine.c -ljansson

clean:
	rm -f *.o *.skel.h collector vmlinux.h syscalls.log syscall_rule_engine