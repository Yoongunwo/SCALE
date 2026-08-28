#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef RINGBUF_SIZE
#define RINGBUF_SIZE (1 << 20)
#endif

char LICENSE[] SEC("license") = "GPL";

struct syscall_event_t {
    u32 pid;
    u32 syscall_nr;
    u64 ts_ns;  // timestamp in nanoseconds
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} ringbuf_local SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);   // PID to trace
    __type(value, u8);  // dummy 1
    __uint(max_entries, 1024);
} pid_filter_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, u32);
    __type(value, u64);
} stats SEC(".maps");

static __always_inline void incr(u32 idx)
{
    u64 *p = bpf_map_lookup_elem(&stats, &idx);
    if (p) (*p)++;  // percpu map, so atomicity is less of a concern
}

SEC("tracepoint/raw_syscalls/sys_enter")
int syscall_collector(struct trace_event_raw_sys_enter *ctx) {

    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *val = bpf_map_lookup_elem(&pid_filter_map, &pid);
    if (!val) return 0;  // PID not in filter map

    u64 ts = bpf_ktime_get_ns();
    
    struct syscall_event_t *e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) {
        /* the ring buffer is full and the record cannot be written = drop */
        incr(1);  // dropped++
        return 0;
    }

    e->pid = pid;
    e->syscall_nr = ctx->id;
    e->ts_ns = ts;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
