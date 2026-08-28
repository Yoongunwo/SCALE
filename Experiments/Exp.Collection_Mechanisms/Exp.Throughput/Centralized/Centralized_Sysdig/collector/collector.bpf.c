#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u8);
    __uint(max_entries, 1024);
} target_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1);  // maximum number of pids
    __type(key, u32);           // pid
    __type(value, u64);         // count
} counter SEC(".maps");

static __always_inline void increment_counter(u32 pid) {
    u64 init = 0;
    u64 *val = bpf_map_lookup_elem(&counter, &pid);

    if (!val) {
        // insert a new entry if this pid key is absent
        bpf_map_update_elem(&counter, &pid, &init, BPF_ANY);
        val = bpf_map_lookup_elem(&counter, &pid);
        if (!val) return; // on failure
    }

    __sync_fetch_and_add(val, 1); // per-CPU, so races are unlikely; increment atomically
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *found = bpf_map_lookup_elem(&target_pids, &pid);
    if (!found) return 0;

    increment_counter(1);
    return 0;
}