#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    // __uint(type, BPF_MAP_TYPE_HASH);
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);         // (gpid << 32) | syscall_nr
    __type(value, u32);       // index into prog_array_map
    __uint(max_entries, 4480);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pid_syscall_to_index SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 4480);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} prog_array_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 128);  // pid 최대 개수
    __type(key, u32);           // pid
    __type(value, u64);         // count
} counter SEC(".maps");

static __always_inline void increment_counter(u32 pid) {
    u64 init = 0;
    u64 *val = bpf_map_lookup_elem(&counter, &pid);

    if (!val) {
        // 해당 pid 키가 없으면 새로 삽입
        bpf_map_update_elem(&counter, &pid, &init, BPF_ANY);
        val = bpf_map_lookup_elem(&counter, &pid);
        if (!val) return; // 실패 시
    }

    __sync_fetch_and_add(val, 1); // per-CPU라서 race 거의 없음, atomic하게 증가
}

SEC("tracepoint/syscalls/sys_enter_read")
int trace_enter_read(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 0;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 1;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_enter_open(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 2;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int trace_enter_close(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 3;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newstat")
int trace_enter_newstat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 4;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstat")
int trace_enter_newfstat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 5;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newlstat")
int trace_enter_newlstat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 6;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_poll")
int trace_enter_poll(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 7;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lseek")
int trace_enter_lseek(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 8;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_enter_mmap(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 9;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int trace_enter_mprotect(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 10;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_enter_munmap(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 11;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_brk")
int trace_enter_brk(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 12;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigaction")
int trace_enter_rt_sigaction(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 13;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigprocmask")
int trace_enter_rt_sigprocmask(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 14;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigreturn")
int trace_enter_rt_sigreturn(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 15;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int trace_enter_ioctl(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 16;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pread64")
int trace_enter_pread64(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 17;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int trace_enter_pwrite64(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 18;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int trace_enter_readv(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 19;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int trace_enter_writev(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 20;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_access")
int trace_enter_access(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 21;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe")
int trace_enter_pipe(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 22;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_select")
int trace_enter_select(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 23;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_yield")
int trace_enter_sched_yield(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 24;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mremap")
int trace_enter_mremap(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 25;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_msync")
int trace_enter_msync(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 26;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mincore")
int trace_enter_mincore(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 27;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_madvise")
int trace_enter_madvise(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 28;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmget")
int trace_enter_shmget(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 29;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmat")
int trace_enter_shmat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 30;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmctl")
int trace_enter_shmctl(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 31;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup")
int trace_enter_dup(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 32;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int trace_enter_dup2(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 33;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pause")
int trace_enter_pause(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 34;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int trace_enter_nanosleep(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 35;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getitimer")
int trace_enter_getitimer(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 36;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_alarm")
int trace_enter_alarm(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 37;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setitimer")
int trace_enter_setitimer(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 38;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int trace_enter_getpid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 39;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendfile64")
int trace_enter_sendfile64(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 40;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_enter_socket(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 41;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 42;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int trace_enter_accept(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 43;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 44;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int trace_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 45;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 46;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int trace_enter_recvmsg(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 47;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int trace_enter_shutdown(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 48;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int trace_enter_bind(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 49;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_listen")
int trace_enter_listen(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 50;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockname")
int trace_enter_getsockname(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 51;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpeername")
int trace_enter_getpeername(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 52;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socketpair")
int trace_enter_socketpair(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 53;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int trace_enter_setsockopt(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 54;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockopt")
int trace_enter_getsockopt(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 55;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int trace_enter_clone(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 56;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fork")
int trace_enter_fork(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 57;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_vfork")
int trace_enter_vfork(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 58;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 59;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int trace_enter_exit(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 60;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_wait4")
int trace_enter_wait4(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 61;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int trace_enter_kill(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 62;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newuname")
int trace_enter_newuname(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 63;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_semget")
int trace_enter_semget(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 64;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_semop")
int trace_enter_semop(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 65;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_semctl")
int trace_enter_semctl(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 66;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmdt")
int trace_enter_shmdt(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 67;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgget")
int trace_enter_msgget(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 68;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgsnd")
int trace_enter_msgsnd(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 69;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgrcv")
int trace_enter_msgrcv(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 70;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgctl")
int trace_enter_msgctl(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 71;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fcntl")
int trace_enter_fcntl(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 72;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_flock")
int trace_enter_flock(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 73;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int trace_enter_fsync(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 74;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int trace_enter_fdatasync(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 75;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int trace_enter_truncate(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 76;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int trace_enter_ftruncate(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 77;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents")
int trace_enter_getdents(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 78;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getcwd")
int trace_enter_getcwd(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 79;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chdir")
int trace_enter_chdir(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 80;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchdir")
int trace_enter_fchdir(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 81;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int trace_enter_rename(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 82;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdir")
int trace_enter_mkdir(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 83;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int trace_enter_rmdir(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 84;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int trace_enter_creat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 85;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_link")
int trace_enter_link(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 86;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int trace_enter_unlink(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 87;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int trace_enter_symlink(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 88;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlink")
int trace_enter_readlink(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 89;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int trace_enter_chmod(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 90;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int trace_enter_fchmod(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 91;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chown")
int trace_enter_chown(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 92;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchown")
int trace_enter_fchown(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 93;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lchown")
int trace_enter_lchown(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 94;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_umask")
int trace_enter_umask(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 95;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_gettimeofday")
int trace_enter_gettimeofday(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 96;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrlimit")
int trace_enter_getrlimit(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 97;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrusage")
int trace_enter_getrusage(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 98;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sysinfo")
int trace_enter_sysinfo(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 99;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_times")
int trace_enter_times(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 100;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_enter_ptrace(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 101;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getuid")
int trace_enter_getuid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 102;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_syslog")
int trace_enter_syslog(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 103;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getgid")
int trace_enter_getgid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 104;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_enter_setuid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 105;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_enter_setgid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 106;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_geteuid")
int trace_enter_geteuid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 107;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getegid")
int trace_enter_getegid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 108;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setpgid")
int trace_enter_setpgid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 109;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getppid")
int trace_enter_getppid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 110;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpgrp")
int trace_enter_getpgrp(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 111;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setsid")
int trace_enter_setsid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 112;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int trace_enter_setreuid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 113;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int trace_enter_setregid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 114;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getgroups")
int trace_enter_getgroups(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 115;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgroups")
int trace_enter_setgroups(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 116;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int trace_enter_setresuid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 117;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getresuid")
int trace_enter_getresuid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 118;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int trace_enter_setresgid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 119;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getresgid")
int trace_enter_getresgid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 120;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpgid")
int trace_enter_getpgid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 121;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setfsuid")
int trace_enter_setfsuid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 122;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setfsgid")
int trace_enter_setfsgid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 123;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsid")
int trace_enter_getsid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 124;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_capget")
int trace_enter_capget(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 125;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int trace_enter_capset(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 126;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigpending")
int trace_enter_rt_sigpending(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 127;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigtimedwait")
int trace_enter_rt_sigtimedwait(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 128;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigqueueinfo")
int trace_enter_rt_sigqueueinfo(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 129;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigsuspend")
int trace_enter_rt_sigsuspend(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 130;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sigaltstack")
int trace_enter_sigaltstack(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 131;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_utime")
int trace_enter_utime(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 132;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknod")
int trace_enter_mknod(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 133;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_personality")
int trace_enter_personality(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 135;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ustat")
int trace_enter_ustat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 136;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_statfs")
int trace_enter_statfs(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 137;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fstatfs")
int trace_enter_fstatfs(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 138;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sysfs")
int trace_enter_sysfs(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 139;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpriority")
int trace_enter_getpriority(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 140;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setpriority")
int trace_enter_setpriority(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 141;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setparam")
int trace_enter_sched_setparam(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 142;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getparam")
int trace_enter_sched_getparam(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 143;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setscheduler")
int trace_enter_sched_setscheduler(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 144;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getscheduler")
int trace_enter_sched_getscheduler(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 145;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_get_priority_max")
int trace_enter_sched_get_priority_max(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 146;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_get_priority_min")
int trace_enter_sched_get_priority_min(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 147;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_rr_get_interval")
int trace_enter_sched_rr_get_interval(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 148;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlock")
int trace_enter_mlock(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 149;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munlock")
int trace_enter_munlock(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 150;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlockall")
int trace_enter_mlockall(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 151;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munlockall")
int trace_enter_munlockall(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 152;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_vhangup")
int trace_enter_vhangup(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 153;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_modify_ldt")
int trace_enter_modify_ldt(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 154;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pivot_root")
int trace_enter_pivot_root(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 155;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int trace_enter_prctl(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 157;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_arch_prctl")
int trace_enter_arch_prctl(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 158;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_adjtimex")
int trace_enter_adjtimex(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 159;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setrlimit")
int trace_enter_setrlimit(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 160;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chroot")
int trace_enter_chroot(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 161;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync")
int trace_enter_sync(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 162;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_acct")
int trace_enter_acct(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 163;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_settimeofday")
int trace_enter_settimeofday(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 164;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int trace_enter_mount(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 165;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_umount")
int trace_enter_umount(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 166;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_swapon")
int trace_enter_swapon(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 167;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_swapoff")
int trace_enter_swapoff(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 168;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_reboot")
int trace_enter_reboot(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 169;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sethostname")
int trace_enter_sethostname(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 170;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setdomainname")
int trace_enter_setdomainname(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 171;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_iopl")
int trace_enter_iopl(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 172;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioperm")
int trace_enter_ioperm(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 173;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int trace_enter_init_module(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 175;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int trace_enter_delete_module(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 176;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_quotactl")
int trace_enter_quotactl(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 179;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_gettid")
int trace_enter_gettid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 186;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readahead")
int trace_enter_readahead(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 187;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setxattr")
int trace_enter_setxattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 188;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lsetxattr")
int trace_enter_lsetxattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 189;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsetxattr")
int trace_enter_fsetxattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 190;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getxattr")
int trace_enter_getxattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 191;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lgetxattr")
int trace_enter_lgetxattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 192;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fgetxattr")
int trace_enter_fgetxattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 193;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_listxattr")
int trace_enter_listxattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 194;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_llistxattr")
int trace_enter_llistxattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 195;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_flistxattr")
int trace_enter_flistxattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 196;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_removexattr")
int trace_enter_removexattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 197;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lremovexattr")
int trace_enter_lremovexattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 198;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fremovexattr")
int trace_enter_fremovexattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 199;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int trace_enter_tkill(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 200;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_time")
int trace_enter_time(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 201;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_futex")
int trace_enter_futex(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 202;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setaffinity")
int trace_enter_sched_setaffinity(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 203;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getaffinity")
int trace_enter_sched_getaffinity(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 204;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_setup")
int trace_enter_io_setup(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 206;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_destroy")
int trace_enter_io_destroy(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 207;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_getevents")
int trace_enter_io_getevents(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 208;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_submit")
int trace_enter_io_submit(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 209;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_cancel")
int trace_enter_io_cancel(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 210;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_create")
int trace_enter_epoll_create(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 213;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_remap_file_pages")
int trace_enter_remap_file_pages(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 216;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents64")
int trace_enter_getdents64(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 217;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_tid_address")
int trace_enter_set_tid_address(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 218;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_restart_syscall")
int trace_enter_restart_syscall(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 219;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_semtimedop")
int trace_enter_semtimedop(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 220;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fadvise64")
int trace_enter_fadvise64(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 221;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_create")
int trace_enter_timer_create(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 222;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_settime")
int trace_enter_timer_settime(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 223;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_gettime")
int trace_enter_timer_gettime(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 224;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_getoverrun")
int trace_enter_timer_getoverrun(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 225;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_delete")
int trace_enter_timer_delete(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 226;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_settime")
int trace_enter_clock_settime(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 227;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_gettime")
int trace_enter_clock_gettime(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 228;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_getres")
int trace_enter_clock_getres(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 229;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_nanosleep")
int trace_enter_clock_nanosleep(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 230;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int trace_enter_exit_group(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 231;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int trace_enter_epoll_wait(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 232;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_ctl")
int trace_enter_epoll_ctl(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 233;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_tgkill")
int trace_enter_tgkill(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 234;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_utimes")
int trace_enter_utimes(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 235;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mbind")
int trace_enter_mbind(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 237;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_mempolicy")
int trace_enter_set_mempolicy(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 238;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_get_mempolicy")
int trace_enter_get_mempolicy(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 239;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_open")
int trace_enter_mq_open(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 240;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_unlink")
int trace_enter_mq_unlink(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 241;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_timedsend")
int trace_enter_mq_timedsend(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 242;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_timedreceive")
int trace_enter_mq_timedreceive(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 243;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_notify")
int trace_enter_mq_notify(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 244;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_getsetattr")
int trace_enter_mq_getsetattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 245;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kexec_load")
int trace_enter_kexec_load(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 246;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_waitid")
int trace_enter_waitid(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 247;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_add_key")
int trace_enter_add_key(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 248;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_request_key")
int trace_enter_request_key(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 249;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_keyctl")
int trace_enter_keyctl(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 250;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioprio_set")
int trace_enter_ioprio_set(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 251;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioprio_get")
int trace_enter_ioprio_get(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 252;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_init")
int trace_enter_inotify_init(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 253;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_add_watch")
int trace_enter_inotify_add_watch(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 254;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_rm_watch")
int trace_enter_inotify_rm_watch(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 255;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_migrate_pages")
int trace_enter_migrate_pages(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 256;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 257;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int trace_enter_mkdirat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 258;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknodat")
int trace_enter_mknodat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 259;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int trace_enter_fchownat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 260;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_futimesat")
int trace_enter_futimesat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 261;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstatat")
int trace_enter_newfstatat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 262;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 263;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int trace_enter_renameat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 264;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int trace_enter_linkat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 265;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int trace_enter_symlinkat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 266;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlinkat")
int trace_enter_readlinkat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 267;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int trace_enter_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 268;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat")
int trace_enter_faccessat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 269;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pselect6")
int trace_enter_pselect6(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 270;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ppoll")
int trace_enter_ppoll(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 271;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_enter_unshare(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 272;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_robust_list")
int trace_enter_set_robust_list(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 273;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_get_robust_list")
int trace_enter_get_robust_list(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 274;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_splice")
int trace_enter_splice(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 275;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_tee")
int trace_enter_tee(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 276;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync_file_range")
int trace_enter_sync_file_range(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 277;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_vmsplice")
int trace_enter_vmsplice(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 278;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_move_pages")
int trace_enter_move_pages(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 279;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_utimensat")
int trace_enter_utimensat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 280;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait")
int trace_enter_epoll_pwait(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 281;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_signalfd")
int trace_enter_signalfd(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 282;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_create")
int trace_enter_timerfd_create(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 283;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_eventfd")
int trace_enter_eventfd(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 284;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fallocate")
int trace_enter_fallocate(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 285;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_settime")
int trace_enter_timerfd_settime(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 286;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_gettime")
int trace_enter_timerfd_gettime(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 287;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int trace_enter_accept4(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 288;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_signalfd4")
int trace_enter_signalfd4(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 289;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_eventfd2")
int trace_enter_eventfd2(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 290;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_create1")
int trace_enter_epoll_create1(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 291;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int trace_enter_dup3(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 292;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe2")
int trace_enter_pipe2(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 293;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_init1")
int trace_enter_inotify_init1(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 294;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv")
int trace_enter_preadv(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 295;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev")
int trace_enter_pwritev(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 296;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_tgsigqueueinfo")
int trace_enter_rt_tgsigqueueinfo(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 297;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_perf_event_open")
int trace_enter_perf_event_open(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 298;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int trace_enter_recvmmsg(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 299;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fanotify_init")
int trace_enter_fanotify_init(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 300;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fanotify_mark")
int trace_enter_fanotify_mark(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 301;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_prlimit64")
int trace_enter_prlimit64(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 302;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_name_to_handle_at")
int trace_enter_name_to_handle_at(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 303;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open_by_handle_at")
int trace_enter_open_by_handle_at(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 304;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_adjtime")
int trace_enter_clock_adjtime(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 305;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_syncfs")
int trace_enter_syncfs(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 306;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int trace_enter_sendmmsg(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 307;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int trace_enter_setns(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 308;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getcpu")
int trace_enter_getcpu(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 309;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int trace_enter_process_vm_readv(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 310;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int trace_enter_process_vm_writev(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 311;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kcmp")
int trace_enter_kcmp(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 312;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int trace_enter_finit_module(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 313;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setattr")
int trace_enter_sched_setattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 314;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getattr")
int trace_enter_sched_getattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 315;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int trace_enter_renameat2(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 316;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_seccomp")
int trace_enter_seccomp(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 317;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrandom")
int trace_enter_getrandom(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 318;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int trace_enter_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 319;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kexec_file_load")
int trace_enter_kexec_file_load(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 320;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int trace_enter_bpf(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 321;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_enter_execveat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 322;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_userfaultfd")
int trace_enter_userfaultfd(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 323;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_membarrier")
int trace_enter_membarrier(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 324;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlock2")
int trace_enter_mlock2(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 325;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_copy_file_range")
int trace_enter_copy_file_range(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 326;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv2")
int trace_enter_preadv2(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 327;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev2")
int trace_enter_pwritev2(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 328;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pkey_mprotect")
int trace_enter_pkey_mprotect(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 329;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pkey_alloc")
int trace_enter_pkey_alloc(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 330;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pkey_free")
int trace_enter_pkey_free(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 331;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_statx")
int trace_enter_statx(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 332;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_pgetevents")
int trace_enter_io_pgetevents(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 333;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rseq")
int trace_enter_rseq(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 334;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_send_signal")
int trace_enter_pidfd_send_signal(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 424;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_setup")
int trace_enter_io_uring_setup(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 425;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_enter")
int trace_enter_io_uring_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 426;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_register")
int trace_enter_io_uring_register(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 427;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open_tree")
int trace_enter_open_tree(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 428;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_move_mount")
int trace_enter_move_mount(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 429;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsopen")
int trace_enter_fsopen(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 430;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsconfig")
int trace_enter_fsconfig(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 431;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsmount")
int trace_enter_fsmount(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 432;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fspick")
int trace_enter_fspick(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 433;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_open")
int trace_enter_pidfd_open(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 434;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone3")
int trace_enter_clone3(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 435;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close_range")
int trace_enter_close_range(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 436;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_enter_openat2(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 437;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_getfd")
int trace_enter_pidfd_getfd(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 438;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat2")
int trace_enter_faccessat2(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 439;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_madvise")
int trace_enter_process_madvise(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 440;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait2")
int trace_enter_epoll_pwait2(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 441;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount_setattr")
int trace_enter_mount_setattr(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 442;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_quotactl_fd")
int trace_enter_quotactl_fd(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 443;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_create_ruleset")
int trace_enter_landlock_create_ruleset(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 444;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_add_rule")
int trace_enter_landlock_add_rule(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 445;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_restrict_self")
int trace_enter_landlock_restrict_self(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 446;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_secret")
int trace_enter_memfd_secret(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 447;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_mrelease")
int trace_enter_process_mrelease(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 key = ((u64)pid << 32) | 448;
    u32 *index = bpf_map_lookup_elem(&pid_syscall_to_index, &key);
    if (!index) return 0;
    increment_counter(pid);
    bpf_tail_call(ctx, &prog_array_map, *index);
    return 0;
}

