#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// #include <bpf/bpf.h>

char LICENSE[] SEC("license") = "GPL";

struct syscall_event_t {
    u32 pid;
    u32 syscall_nr;
    u64 ts_ns;  // timestamp in nanoseconds
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
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

SEC("fentry/__x64_sys_read")
int handle_read(unsigned int fd, char *buf, size_t count)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *val = bpf_map_lookup_elem(&pid_filter_map, &pid);
    if (!val) return 0;

    u64 ts = bpf_ktime_get_ns();

    struct syscall_event_t *e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->syscall_nr = 1;
    e->ts_ns = ts;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/__x64_sys_close")
int handle_close(unsigned int fd) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *val = bpf_map_lookup_elem(&pid_filter_map, &pid);
    if (!val) return 0;

    u64 ts = bpf_ktime_get_ns();

    struct syscall_event_t *e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->syscall_nr = 3;
    e->ts_ns = ts;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/__x64_sys_mmap")
int handle_mmap(struct pt_regs *regs) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *val = bpf_map_lookup_elem(&pid_filter_map, &pid);
    if (!val) return 0;

    u64 ts = bpf_ktime_get_ns();

    struct syscall_event_t *e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->syscall_nr = 9;
    e->ts_ns = ts;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_sched_yield")
int handle_sched_yield(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *val = bpf_map_lookup_elem(&pid_filter_map, &pid);
    if (!val) return 0;

    u64 ts = bpf_ktime_get_ns();

    struct syscall_event_t *e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->syscall_nr = 24;
    e->ts_ns = ts;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_getpid")
int handle_getpid(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *val = bpf_map_lookup_elem(&pid_filter_map, &pid);
    if (!val) return 0;

    u64 ts = bpf_ktime_get_ns();

    struct syscall_event_t *e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->syscall_nr = 39;
    e->ts_ns = ts;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/__x64_sys_gettimeofday")
int handle_gettimeofday(struct __kernel_old_timeval *tv, struct timezone *tz) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *val = bpf_map_lookup_elem(&pid_filter_map, &pid);
    if (!val) return 0;

    u64 ts = bpf_ktime_get_ns();

    struct syscall_event_t *e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->syscall_nr = 96;
    e->ts_ns = ts;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_getuid")
int handle_getuid(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *val = bpf_map_lookup_elem(&pid_filter_map, &pid);
    if (!val) return 0;

    u64 ts = bpf_ktime_get_ns();

    struct syscall_event_t *e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->syscall_nr = 102;
    e->ts_ns = ts;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/__x64_sys_getppid")
int handle_getppid(void) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *val = bpf_map_lookup_elem(&pid_filter_map, &pid);
    if (!val) return 0;

    u64 ts = bpf_ktime_get_ns();

    struct syscall_event_t *e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->syscall_nr = 110;
    e->ts_ns = ts;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/__x64_sys_clock_gettime")
int handle_clock_gettime(clockid_t which_clock, struct __kernel_timespec *tp) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *val = bpf_map_lookup_elem(&pid_filter_map, &pid);
    if (!val) return 0;

    u64 ts = bpf_ktime_get_ns();

    struct syscall_event_t *e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->syscall_nr = 228;
    e->ts_ns = ts;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("fentry/__x64_sys_openat")
int handle_openat(int dfd, const char *filename, int flags, umode_t mode) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    u8 *val = bpf_map_lookup_elem(&pid_filter_map, &pid);
    if (!val) return 0;

    u64 ts = bpf_ktime_get_ns();

    struct syscall_event_t *e = bpf_ringbuf_reserve(&ringbuf_local, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = pid;
    e->syscall_nr = 257;
    e->ts_ns = ts;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

