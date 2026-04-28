#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct syscall_event_t {
    u32 pid;
    u64 syscall_nr;
    char str_args[3][64];
    u8 str_valid[3];
    u64 int_args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} ringbuf_local SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int handle_read(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int handle_open(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int handle_close(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newstat")
int handle_newstat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstat")
int handle_newfstat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newlstat")
int handle_newlstat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_poll")
int handle_poll(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lseek")
int handle_lseek(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int handle_mmap(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mprotect")
int handle_mprotect(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munmap")
int handle_munmap(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_brk")
int handle_brk(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigaction")
int handle_rt_sigaction(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigprocmask")
int handle_rt_sigprocmask(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigreturn")
int handle_rt_sigreturn(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int handle_ioctl(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pread64")
int handle_pread64(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int handle_pwrite64(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int handle_readv(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int handle_writev(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_access")
int handle_access(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe")
int handle_pipe(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_select")
int handle_select(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_yield")
int handle_sched_yield(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mremap")
int handle_mremap(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_msync")
int handle_msync(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mincore")
int handle_mincore(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[2]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_madvise")
int handle_madvise(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmget")
int handle_shmget(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmat")
int handle_shmat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmctl")
int handle_shmctl(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup")
int handle_dup(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup2")
int handle_dup2(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pause")
int handle_pause(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int handle_nanosleep(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getitimer")
int handle_getitimer(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_alarm")
int handle_alarm(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setitimer")
int handle_setitimer(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpid")
int handle_getpid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendfile64")
int handle_sendfile64(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int handle_socket(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]);
    e->int_args[1] = sa.sin_port;
    e->int_args[2] = sa.sin_addr.s_addr;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept")
int handle_accept(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]);
    e->int_args[1] = sa.sin_port;
    e->int_args[2] = sa.sin_addr.s_addr;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_sendto(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[4]);
    e->int_args[4] = sa.sin_port;
    e->int_args[5] = sa.sin_addr.s_addr;
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int handle_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[4]);
    e->int_args[4] = sa.sin_port;
    e->int_args[5] = sa.sin_addr.s_addr;
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int handle_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int handle_recvmsg(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int handle_shutdown(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bind")
int handle_bind(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]);
    e->int_args[1] = sa.sin_port;
    e->int_args[2] = sa.sin_addr.s_addr;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_listen")
int handle_listen(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockname")
int handle_getsockname(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]);
    e->int_args[1] = sa.sin_port;
    e->int_args[2] = sa.sin_addr.s_addr;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpeername")
int handle_getpeername(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]);
    e->int_args[1] = sa.sin_port;
    e->int_args[2] = sa.sin_addr.s_addr;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socketpair")
int handle_socketpair(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setsockopt")
int handle_setsockopt(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[3]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsockopt")
int handle_getsockopt(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[3]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int handle_clone(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fork")
int handle_fork(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_vfork")
int handle_vfork(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    if (bpf_probe_read_user_str(e->str_args[2], sizeof(e->str_args[2]), (void *)ctx->args[2]) > 0)
        e->str_valid[2] = 1;
    else
        e->str_valid[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit")
int handle_exit(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_wait4")
int handle_wait4(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int handle_kill(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newuname")
int handle_newuname(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_semget")
int handle_semget(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_semop")
int handle_semop(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_semctl")
int handle_semctl(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_shmdt")
int handle_shmdt(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgget")
int handle_msgget(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgsnd")
int handle_msgsnd(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgrcv")
int handle_msgrcv(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_msgctl")
int handle_msgctl(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fcntl")
int handle_fcntl(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_flock")
int handle_flock(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int handle_fsync(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fdatasync")
int handle_fdatasync(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_truncate")
int handle_truncate(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ftruncate")
int handle_ftruncate(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents")
int handle_getdents(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getcwd")
int handle_getcwd(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chdir")
int handle_chdir(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchdir")
int handle_fchdir(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rename")
int handle_rename(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdir")
int handle_mkdir(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rmdir")
int handle_rmdir(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_creat")
int handle_creat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_link")
int handle_link(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlink")
int handle_unlink(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int handle_symlink(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlink")
int handle_readlink(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chmod")
int handle_chmod(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmod")
int handle_fchmod(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chown")
int handle_chown(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchown")
int handle_fchown(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lchown")
int handle_lchown(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_umask")
int handle_umask(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_gettimeofday")
int handle_gettimeofday(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrlimit")
int handle_getrlimit(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrusage")
int handle_getrusage(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sysinfo")
int handle_sysinfo(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_times")
int handle_times(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int handle_ptrace(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getuid")
int handle_getuid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_syslog")
int handle_syslog(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getgid")
int handle_getgid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int handle_setgid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_geteuid")
int handle_geteuid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getegid")
int handle_getegid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setpgid")
int handle_setpgid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getppid")
int handle_getppid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpgrp")
int handle_getpgrp(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setsid")
int handle_setsid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setreuid")
int handle_setreuid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setregid")
int handle_setregid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getgroups")
int handle_getgroups(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgroups")
int handle_setgroups(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresuid")
int handle_setresuid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getresuid")
int handle_getresuid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setresgid")
int handle_setresgid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getresgid")
int handle_getresgid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpgid")
int handle_getpgid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setfsuid")
int handle_setfsuid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setfsgid")
int handle_setfsgid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getsid")
int handle_getsid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_capget")
int handle_capget(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_capset")
int handle_capset(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigpending")
int handle_rt_sigpending(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigtimedwait")
int handle_rt_sigtimedwait(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigqueueinfo")
int handle_rt_sigqueueinfo(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_sigsuspend")
int handle_rt_sigsuspend(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sigaltstack")
int handle_sigaltstack(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_utime")
int handle_utime(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknod")
int handle_mknod(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_personality")
int handle_personality(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ustat")
int handle_ustat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_statfs")
int handle_statfs(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fstatfs")
int handle_fstatfs(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sysfs")
int handle_sysfs(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getpriority")
int handle_getpriority(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setpriority")
int handle_setpriority(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setparam")
int handle_sched_setparam(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getparam")
int handle_sched_getparam(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setscheduler")
int handle_sched_setscheduler(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getscheduler")
int handle_sched_getscheduler(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_get_priority_max")
int handle_sched_get_priority_max(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_get_priority_min")
int handle_sched_get_priority_min(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_rr_get_interval")
int handle_sched_rr_get_interval(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlock")
int handle_mlock(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munlock")
int handle_munlock(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlockall")
int handle_mlockall(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_munlockall")
int handle_munlockall(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_vhangup")
int handle_vhangup(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_modify_ldt")
int handle_modify_ldt(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pivot_root")
int handle_pivot_root(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_prctl")
int handle_prctl(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_arch_prctl")
int handle_arch_prctl(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_adjtimex")
int handle_adjtimex(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setrlimit")
int handle_setrlimit(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_chroot")
int handle_chroot(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync")
int handle_sync(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_acct")
int handle_acct(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_settimeofday")
int handle_settimeofday(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int handle_mount(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    if (bpf_probe_read_user_str(e->str_args[2], sizeof(e->str_args[2]), (void *)ctx->args[2]) > 0)
        e->str_valid[2] = 1;
    else
        e->str_valid[2] = 0;
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_umount")
int handle_umount(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_swapon")
int handle_swapon(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_swapoff")
int handle_swapoff(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_reboot")
int handle_reboot(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sethostname")
int handle_sethostname(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setdomainname")
int handle_setdomainname(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_iopl")
int handle_iopl(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioperm")
int handle_ioperm(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int handle_init_module(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[2]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int handle_delete_module(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_quotactl")
int handle_quotactl(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_gettid")
int handle_gettid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readahead")
int handle_readahead(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setxattr")
int handle_setxattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lsetxattr")
int handle_lsetxattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsetxattr")
int handle_fsetxattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getxattr")
int handle_getxattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lgetxattr")
int handle_lgetxattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fgetxattr")
int handle_fgetxattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_listxattr")
int handle_listxattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_llistxattr")
int handle_llistxattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_flistxattr")
int handle_flistxattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_removexattr")
int handle_removexattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_lremovexattr")
int handle_lremovexattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fremovexattr")
int handle_fremovexattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_tkill")
int handle_tkill(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_time")
int handle_time(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_futex")
int handle_futex(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setaffinity")
int handle_sched_setaffinity(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getaffinity")
int handle_sched_getaffinity(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_setup")
int handle_io_setup(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_destroy")
int handle_io_destroy(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_getevents")
int handle_io_getevents(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_submit")
int handle_io_submit(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_cancel")
int handle_io_cancel(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_create")
int handle_epoll_create(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_remap_file_pages")
int handle_remap_file_pages(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getdents64")
int handle_getdents64(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_tid_address")
int handle_set_tid_address(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_restart_syscall")
int handle_restart_syscall(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_semtimedop")
int handle_semtimedop(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fadvise64")
int handle_fadvise64(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_create")
int handle_timer_create(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_settime")
int handle_timer_settime(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_gettime")
int handle_timer_gettime(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_getoverrun")
int handle_timer_getoverrun(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timer_delete")
int handle_timer_delete(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_settime")
int handle_clock_settime(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_gettime")
int handle_clock_gettime(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_getres")
int handle_clock_getres(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_nanosleep")
int handle_clock_nanosleep(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_exit_group")
int handle_exit_group(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_wait")
int handle_epoll_wait(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_ctl")
int handle_epoll_ctl(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_tgkill")
int handle_tgkill(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_utimes")
int handle_utimes(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mbind")
int handle_mbind(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_mempolicy")
int handle_set_mempolicy(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_get_mempolicy")
int handle_get_mempolicy(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_open")
int handle_mq_open(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_unlink")
int handle_mq_unlink(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_timedsend")
int handle_mq_timedsend(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_timedreceive")
int handle_mq_timedreceive(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_notify")
int handle_mq_notify(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mq_getsetattr")
int handle_mq_getsetattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kexec_load")
int handle_kexec_load(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_waitid")
int handle_waitid(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_add_key")
int handle_add_key(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_request_key")
int handle_request_key(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[1]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    if (bpf_probe_read_user_str(e->str_args[2], sizeof(e->str_args[2]), (void *)ctx->args[2]) > 0)
        e->str_valid[2] = 1;
    else
        e->str_valid[2] = 0;
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_keyctl")
int handle_keyctl(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioprio_set")
int handle_ioprio_set(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ioprio_get")
int handle_ioprio_get(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_init")
int handle_inotify_init(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = 0;
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_add_watch")
int handle_inotify_add_watch(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_rm_watch")
int handle_inotify_rm_watch(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_migrate_pages")
int handle_migrate_pages(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int handle_mkdirat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknodat")
int handle_mknodat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchownat")
int handle_fchownat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_futimesat")
int handle_futimesat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_newfstatat")
int handle_newfstatat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int handle_renameat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[3]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_linkat")
int handle_linkat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[3]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int handle_symlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[2]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlinkat")
int handle_readlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[2]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int handle_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat")
int handle_faccessat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pselect6")
int handle_pselect6(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ppoll")
int handle_ppoll(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int handle_unshare(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_set_robust_list")
int handle_set_robust_list(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_get_robust_list")
int handle_get_robust_list(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_splice")
int handle_splice(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_tee")
int handle_tee(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sync_file_range")
int handle_sync_file_range(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_vmsplice")
int handle_vmsplice(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_move_pages")
int handle_move_pages(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_utimensat")
int handle_utimensat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait")
int handle_epoll_pwait(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_signalfd")
int handle_signalfd(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_create")
int handle_timerfd_create(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_eventfd")
int handle_eventfd(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fallocate")
int handle_fallocate(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_settime")
int handle_timerfd_settime(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_timerfd_gettime")
int handle_timerfd_gettime(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_accept4")
int handle_accept4(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    struct sockaddr_in sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), (void *)ctx->args[1]);
    e->int_args[1] = sa.sin_port;
    e->int_args[2] = sa.sin_addr.s_addr;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_signalfd4")
int handle_signalfd4(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_eventfd2")
int handle_eventfd2(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_create1")
int handle_epoll_create1(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_dup3")
int handle_dup3(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pipe2")
int handle_pipe2(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_inotify_init1")
int handle_inotify_init1(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv")
int handle_preadv(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev")
int handle_pwritev(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rt_tgsigqueueinfo")
int handle_rt_tgsigqueueinfo(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_perf_event_open")
int handle_perf_event_open(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvmmsg")
int handle_recvmmsg(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fanotify_init")
int handle_fanotify_init(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fanotify_mark")
int handle_fanotify_mark(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[4]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_prlimit64")
int handle_prlimit64(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_name_to_handle_at")
int handle_name_to_handle_at(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open_by_handle_at")
int handle_open_by_handle_at(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clock_adjtime")
int handle_clock_adjtime(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_syncfs")
int handle_syncfs(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendmmsg")
int handle_sendmmsg(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setns")
int handle_setns(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getcpu")
int handle_getcpu(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_readv")
int handle_process_vm_readv(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int handle_process_vm_writev(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kcmp")
int handle_kcmp(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int handle_finit_module(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_setattr")
int handle_sched_setattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sched_getattr")
int handle_sched_getattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int handle_renameat2(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[3]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_seccomp")
int handle_seccomp(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_getrandom")
int handle_getrandom(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int handle_memfd_create(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kexec_file_load")
int handle_kexec_file_load(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[3]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_bpf")
int handle_bpf(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int handle_execveat(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[2]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    if (bpf_probe_read_user_str(e->str_args[2], sizeof(e->str_args[2]), (void *)ctx->args[3]) > 0)
        e->str_valid[2] = 1;
    else
        e->str_valid[2] = 0;
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_userfaultfd")
int handle_userfaultfd(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_membarrier")
int handle_membarrier(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mlock2")
int handle_mlock2(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_copy_file_range")
int handle_copy_file_range(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_preadv2")
int handle_preadv2(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pwritev2")
int handle_pwritev2(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pkey_mprotect")
int handle_pkey_mprotect(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pkey_alloc")
int handle_pkey_alloc(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pkey_free")
int handle_pkey_free(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_statx")
int handle_statx(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_pgetevents")
int handle_io_pgetevents(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_rseq")
int handle_rseq(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_send_signal")
int handle_pidfd_send_signal(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_setup")
int handle_io_uring_setup(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_enter")
int handle_io_uring_enter(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_io_uring_register")
int handle_io_uring_register(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open_tree")
int handle_open_tree(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_move_mount")
int handle_move_mount(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    if (bpf_probe_read_user_str(e->str_args[1], sizeof(e->str_args[1]), (void *)ctx->args[3]) > 0)
        e->str_valid[1] = 1;
    else
        e->str_valid[1] = 0;
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsopen")
int handle_fsopen(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[0]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsconfig")
int handle_fsconfig(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[2]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fsmount")
int handle_fsmount(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fspick")
int handle_fspick(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_open")
int handle_pidfd_open(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone3")
int handle_clone3(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close_range")
int handle_close_range(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int handle_openat2(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_getfd")
int handle_pidfd_getfd(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_faccessat2")
int handle_faccessat2(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_madvise")
int handle_process_madvise(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_epoll_pwait2")
int handle_epoll_pwait2(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = ctx->args[5];
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount_setattr")
int handle_mount_setattr(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    if (bpf_probe_read_user_str(e->str_args[0], sizeof(e->str_args[0]), (void *)ctx->args[1]) > 0)
        e->str_valid[0] = 1;
    else
        e->str_valid[0] = 0;
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = ctx->args[4];
    e->int_args[5] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_quotactl_fd")
int handle_quotactl_fd(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_create_ruleset")
int handle_landlock_create_ruleset(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_add_rule")
int handle_landlock_add_rule(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = ctx->args[2];
    e->int_args[3] = ctx->args[3];
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_landlock_restrict_self")
int handle_landlock_restrict_self(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_secret")
int handle_memfd_secret(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = 0;
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_mrelease")
int handle_process_mrelease(struct trace_event_raw_sys_enter *ctx) {
    struct syscall_event_t *e;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->int_args[0] = ctx->args[0];
    e->int_args[1] = ctx->args[1];
    e->int_args[2] = 0;
    e->int_args[3] = 0;
    e->int_args[4] = 0;
    e->int_args[5] = 0;
    e->str_valid[0] = 0;
    e->str_valid[1] = 0;
    e->str_valid[2] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

