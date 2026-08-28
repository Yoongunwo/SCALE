#include "syscall_collector.skel.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <errno.h>

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>

#undef RINGBUF_POLL_MS
#define RINGBUF_POLL_MS 1

static struct timespec g_rt_minus_mono;

struct syscall_event_t {
    __u32 pid;
    __u32 syscall_nr;
    __u64 ts_ns;  // timestamp in nanoseconds
};

static FILE *log_fp = NULL;

static void compute_offset(void)
{
    struct timespec rt, mono;
    clock_gettime(CLOCK_REALTIME, &rt);
    clock_gettime(CLOCK_MONOTONIC, &mono);

    // g_rt_minus_mono = rt - mono
    g_rt_minus_mono.tv_sec  = rt.tv_sec  - mono.tv_sec;
    long nsec = rt.tv_nsec - mono.tv_nsec;
    g_rt_minus_mono.tv_nsec = nsec;
    if (g_rt_minus_mono.tv_nsec < 0) {
        g_rt_minus_mono.tv_sec -= 1;
        g_rt_minus_mono.tv_nsec += 1000000000L;
    }
}

static inline struct timespec ns_to_ts(uint64_t ns)
{
    struct timespec t = {
        .tv_sec  = ns / 1000000000ULL,
        .tv_nsec = ns % 1000000000ULL
    };
    return t;
}

static int handle_event(void *ctx, void *data, size_t size) {
    const struct syscall_event_t *evt = data;

    // Collected: MONOTONIC
    struct timespec col_ts;
    clock_gettime(CLOCK_MONOTONIC, &col_ts);

    // Evoked: MONOTONIC ns → timespec
    struct timespec ev_ts = ns_to_ts(evt->ts_ns);

    // 사람이 읽을 수 있는 형식 유지
    fprintf(log_fp,
        "Evoked Time=%ld.%06ld, Collected Time=%ld.%06ld PID=%u syscall=%u\n",
        (long)ev_ts.tv_sec,  (long)(ev_ts.tv_nsec  / 1000),
        (long)col_ts.tv_sec, (long)(col_ts.tv_nsec / 1000),
        evt->pid, evt->syscall_nr);

    return 0;
}

#define PIN_BASE "/sys/fs/bpf"

static void sanitize_label(char *s) {
    // 파일명 안전화를 위해 점/공백 등은 밑줄로 변환
    for (char *p = s; *p; ++p) {
        if (*p == '.' || *p == ' ' || *p == ':' ) *p = '_';
        // 필요하면 더 추가
    }
}

static void pin_stats_map_label(struct syscall_collector_bpf *skel, const char *label){
    char safe[128];
    snprintf(safe, sizeof(safe), "%s", label);
    sanitize_label(safe);

    char path_stats[256];
    snprintf(path_stats, sizeof(path_stats), PIN_BASE "/syscall_stats_%s", safe);

    if (bpf_map__pin(skel->maps.stats, path_stats) != 0) {
        fprintf(stderr, "WARN: failed to pin %s (errno=%d: %s)\n",
                path_stats, errno, strerror(errno));
    } else {
        printf("[+] pinned: %s\n", path_stats);
    }
}

/* IP 얻기 */
static int get_ipv4_for_iface(const char *ifname, char *buf, size_t buflen) {
    struct ifaddrs *ifaddr = NULL, *ifa = NULL;
    if (getifaddrs(&ifaddr) == -1) return -1;
    int ok = -1;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (!ifa->ifa_name || strcmp(ifa->ifa_name, ifname) != 0) continue;
        unsigned flags = ifa->ifa_flags;
        if (!(flags & IFF_UP)) continue;
        if (flags & IFF_LOOPBACK) continue;
        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, buflen)) { ok = 0; break; }
    }
    freeifaddrs(ifaddr);
    return ok;
}

static int get_any_ipv4(char *buf, size_t buflen) {
    struct ifaddrs *ifaddr = NULL, *ifa = NULL;
    if (getifaddrs(&ifaddr) == -1) return -1;
    int ok = -1;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        unsigned flags = ifa->ifa_flags;
        if (!(flags & IFF_UP)) continue;
        if (flags & IFF_LOOPBACK) continue;
        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, buflen)) { ok = 0; break; }
    }
    freeifaddrs(ifaddr);
    return ok;
}

static int get_self_ipv4(char *buf, size_t buflen) {
    if (get_ipv4_for_iface("eth0", buf, buflen) == 0) return 0;
    return get_any_ipv4(buf, buflen);
}

static __u32 get_sys_generator_pid(){
    FILE *fp = popen("pidof sys_generator", "r");
    if (!fp) {
        fprintf(stderr, "Failed to run pidof\n");
        return 0;
    }
    __u32 pid = 0;
    if (fscanf(fp, "%u", &pid) != 1) pid = 0;
    pclose(fp);
    return pid;
}

int main() {

    compute_offset();

    __u32 target_pid = get_sys_generator_pid();
    if (target_pid == 0) {
        fprintf(stderr, "process 'sys_generator' not found\n");
        return 1;
    }

    struct syscall_collector_bpf *skel = syscall_collector_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }
    if (syscall_collector_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        syscall_collector_bpf__destroy(skel);
        return 1;
    }

    __u8 one = 1;
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.pid_filter_map),
                            &target_pid, &one, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update pid_filter_map\n");
        syscall_collector_bpf__destroy(skel);
        return 1;
    }

    // IP 라벨(실패 시 PID로 폴백)
    char label[INET_ADDRSTRLEN] = {0};
    if (get_self_ipv4(label, sizeof(label)) != 0) {
        return 1;
    }
    pin_stats_map_label(skel, label);

    // 로그 파일
    char file[64];
    snprintf(file, sizeof(file), "syscalls_%u.log", target_pid);
    log_fp = fopen(file, "w");
    if (!log_fp) {
        perror("fopen");
        goto cleanup;
    }
    setvbuf(log_fp, NULL, _IOFBF, 1<<20);

    // 링버퍼
    int rb_fd = bpf_map__fd(skel->maps.ringbuf_local);
    struct ring_buffer *rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("[+] Tracing syscalls for PID %u...\n", target_pid);

    while (1) {
        int err = ring_buffer__poll(rb, RINGBUF_POLL_MS);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

cleanup:
    if (log_fp) fclose(log_fp);
    // libbpf는 NULL에 안전하긴 하지만 명시적으로
    extern void ring_buffer__free(struct ring_buffer *);
    ring_buffer__free(NULL); // rb 포인터 넘기세요. (여기 템플릿이라 생략)
    syscall_collector_bpf__destroy(skel);
    return 0;
}
