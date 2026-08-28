#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct syscall_event_t {
    u32 pid;
    u32 syscall_nr;
    // u64 timestamp_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u8);
    __uint(max_entries, 1024);
} target_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} events SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *found = bpf_map_lookup_elem(&target_pids, &pid);
    if (!found) return 0;

    struct syscall_event_t *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
    if (!evt) return 0;

    evt->pid = pid;
    evt->syscall_nr = ctx->id;    // evt->timestamp_ns = bpf_ktime_get_ns();

    bpf_ringbuf_submit(evt, 0);

    return 0;
}
