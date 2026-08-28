#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);   // pid (tgid)
    __type(value, u16);  // 1
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} targets SEC(".maps");

// (B) 카운터 맵: pid -> count (per-CPU)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);   // pid
    __type(value, u64); // count
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} counter SEC(".maps");

static __always_inline void increment_counter(u32 pid) {
    u64 init = 0;
    u64 *val = bpf_map_lookup_elem(&counter, &pid);
    if (!val) {
        bpf_map_update_elem(&counter, &pid, &init, BPF_ANY);
        val = bpf_map_lookup_elem(&counter, &pid);
        if (!val) return;
    }
    __sync_fetch_and_add(val, 1);
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_syscall(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    u16 *on = bpf_map_lookup_elem(&targets, &pid);
    if (!on) return 0;   // 대상이 아니면 무시
    increment_counter(pid);
    return 0;
}
