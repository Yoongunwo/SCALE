#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "collector.skel.h"
#include <time.h>
#include <sys/time.h>

static int exiting = 0;
static FILE *log_fp = NULL;

static struct timespec g_rt_minus_mono;

struct syscall_event_t {
    __u32 pid;
    __u32 syscall_nr;
    __u64 ts_ns;  // timestamp in nanoseconds
};

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

    // keep the human-readable format
    fprintf(log_fp,
        "Evoked Time=%ld.%06ld, Collected Time=%ld.%06ld PID=%u syscall=%u\n",
        (long)ev_ts.tv_sec,  (long)(ev_ts.tv_nsec  / 1000),
        (long)col_ts.tv_sec, (long)(col_ts.tv_nsec / 1000),
        evt->pid, evt->syscall_nr);

    return 0;
}

static void sig_handler(int sig) {
    exiting = 1;
}

int pin_map(struct bpf_map *map, const char *path) {
    if (bpf_map__pin(map, path) != 0) {
        fprintf(stderr, "[-] Failed to pin map to %s\n", path);
        return -1;
    }
    printf("[+] Map pinned to %s\n", path);
    return 0;
}

int main() {
    compute_offset();

    struct collector_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    __u8 one = 1;
    __u32 pid = 0;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // load the BPF program
    skel = collector_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    // attach the BPF program
    err = collector_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    // find the sys_generator PID
    FILE *fp = popen("pidof sys_generator || pidof postmark", "r");
    if (!fp) {
        fprintf(stderr, "Failed to run pidof\n");
        goto cleanup;
    }
    
    // register the target PID in the BPF map
    while (fscanf(fp, "%u", &pid) == 1) {
        err = bpf_map_update_elem(
            bpf_map__fd(skel->maps.target_pids),
            &pid, &one, BPF_ANY
        );
        if (err) {
            fprintf(stderr, "Failed to insert PID %u into map: %s\n", pid, strerror(errno));
        } else {
            printf("Registered PID: %u\n", pid);
        }
    }
    
    pclose(fp);

    // open the log file
    log_fp = fopen("syscalls.log", "w");
    if (!log_fp) {
        perror("fopen");
        goto cleanup;
    }

    // create the ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }


    printf("Tracing syscalls for PID %u...\n", pid);
    while (!exiting)
        ring_buffer__poll(rb, 100);

    printf("Exiting...\n");
    goto cleanup;

cleanup:
    if (rb) ring_buffer__free(rb);
    if (log_fp) fclose(log_fp);
    if (skel) collector_bpf__destroy(skel);
    return 0;
}
