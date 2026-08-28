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

#define RINGBUF_POLL_MS 100
volatile sig_atomic_t RESET = 0;
int COUNTER = 0;

void handle_reset(int sig) {
    RESET = 1;
}

struct syscall_event_t {
    __u32 pid;
    __u32 syscall_nr;
};

static FILE *log_fp = NULL;

static int handle_event(void *ctx, void *data, size_t size) {
    const struct syscall_event_t *evt = data;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME_COARSE, &ts);
    fprintf(log_fp, "%ld.%06ld PID=%u syscall=%u\n",
            (long)ts.tv_sec, (long)(ts.tv_nsec / 1000), evt->pid, evt->syscall_nr);
    return 0;
}

#define PIN_BASE "/sys/fs/bpf"

// The stats map was removed on the BPF side, so there is nothing to pin.
// If drop accounting is needed again, restore the stats map in .bpf.c and this function with it.

static __u32 get_pid_from_rootNS(void) {
    __u32 cpid = 0;

    // 1) find the container PID
    FILE *pf = popen("ps -C sys_generator -o pid=", "r");
    if (!pf) { perror("popen(ps)"); return 0; }

    char line[64];
    while (fgets(line, sizeof(line), pf)) {
        char *p = line;
        while (*p==' ' || *p=='\t') p++;
        long v = strtol(p, NULL, 10);
        if (v > 0) { cpid = (__u32)v; break; }
    }
    pclose(pf);

    if (!cpid) {
        fprintf(stderr, "sys_generator PID not found\n");
        return 0;
    }

    // 2) cgroup path of the container PID
    char cgroup_path[256];
    snprintf(cgroup_path, sizeof(cgroup_path), "/proc/%u/cgroup", cpid);
    FILE *cgf = fopen(cgroup_path, "r");
    if (!cgf) { perror("open cgroup"); return 0; }

    char cgroup_line[256], target_cgroup[256] = {0};
    while (fgets(cgroup_line, sizeof(cgroup_line), cgf)) {
        char *pos = strchr(cgroup_line, '/');
        if (pos) {
            strncpy(target_cgroup, pos, sizeof(target_cgroup)-1);
            size_t len = strlen(target_cgroup);
            if (len && target_cgroup[len-1]=='\n') target_cgroup[len-1] = '\0';
            break;
        }
    }
    fclose(cgf);
    if (target_cgroup[0] == '\0') {
        fprintf(stderr, "failed to parse container cgroup for PID %u\n", cpid);
        return 0;
    }

    // 3) find the PID in the host /proc with the same cgroup
    FILE *fp = popen("ls -1 /host/proc | grep -E '^[0-9]+$' | sort -n", "r");
    if (!fp) { perror("popen(ls /host/proc)"); return 0; }

    char pid_buf[32];
    int host_pid = 0;               // <- only this outer variable is used
    while (fgets(pid_buf, sizeof(pid_buf), fp)) {
        int cand = atoi(pid_buf);   // <- a distinct name instead of shadowing
        if (cand <= 0) continue;

        char hcg_path[256];
        snprintf(hcg_path, sizeof(hcg_path), "/host/proc/%d/cgroup", cand);
        FILE *hcgf = fopen(hcg_path, "r");
        if (!hcgf) continue;

        char line2[256];
        int match = 0;
        while (fgets(line2, sizeof(line2), hcgf)) {
            if (strstr(line2, target_cgroup)) { match = 1; break; }
        }
        fclose(hcgf);

        if (match) {
            host_pid = cand;        // <- assign to the outer variable
            printf("Container PID %u -> Host PID %d\n", cpid, host_pid);
            break;
        }
    }
    pclose(fp);

    return (host_pid > 0) ? ( __u32)host_pid : 0;
}

int main() {
    // Under kubectl logs, stdout is a pipe, so glibc uses full buffering (4KB).
    // If the printfs below stay in the buffer while we enter the endless poll loop,
    // nothing appears in the log and it looks "stuck". Line buffering makes it visible immediately.
    setvbuf(stdout, NULL, _IOLBF, 0);

    // get target pid

    __u32 target_pid = 0;

    target_pid = get_pid_from_rootNS();


    if (target_pid == 0) {
        fprintf(stderr, "process 'sys_generator' not found\n");
        return 1;
    }

    struct syscall_collector_bpf *skel = NULL;
    skel = syscall_collector_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF program\n");
        return 1;
    }

    if (syscall_collector_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        syscall_collector_bpf__destroy(skel);
        return 1;
    }

    // 🎯 Add PID to map
    __u8 one = 1;
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.pid_filter_map), &target_pid, &one, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update pid_filter_map\n");
        syscall_collector_bpf__destroy(skel);
        return 1;
    }

    // Declare rb above the fopen check. Below it, a failing fopen would make
    // goto cleanup read an uninitialized rb.
    struct ring_buffer *rb = NULL;

    char file[64];
    snprintf(file, sizeof(file), "syscalls_%d.log", target_pid);

    log_fp = fopen(file, "w");
    if (!log_fp) {
        perror("fopen");
        goto cleanup;
    }
    // The script terminates us with SIGTERM, and with no handler fclose never runs.
    // With the default full buffering the last 4KB (about 100 lines) would be lost entirely,
    // so switch to line buffering to prevent the tail from disappearing.
    setvbuf(log_fp, NULL, _IOLBF, 0);

    int rb_fd = bpf_map__fd(skel->maps.ringbuf_local);
    rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("[+] Tracing syscalls for PID %d...\n", target_pid);


    while (1) {
        ring_buffer__poll(rb, RINGBUF_POLL_MS);
    }

cleanup:
    if (log_fp) fclose(log_fp);
    if (rb) ring_buffer__free(rb);
    syscall_collector_bpf__destroy(skel);
    return 0;
}
