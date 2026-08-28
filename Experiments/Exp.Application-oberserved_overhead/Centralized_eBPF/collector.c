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

struct syscall_event_t {
    __u32 pid;
    __u32 syscall_nr;
    // __u64 timestamp_ns;
};

static int handle_event(void *ctx, void *data, size_t size) {
    struct syscall_event_t *evt = data;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME_COARSE, &ts);
    fprintf(log_fp, "%ld.%06ld PID=%u syscall=%lu\n",
            ts.tv_sec, ts.tv_nsec / 1000, evt->pid, evt->syscall_nr);
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
    // kubectl logs 로 볼 때 stdout 은 파이프라 glibc 가 전(全)버퍼링(4KB)을 쓴다.
    // 아래 printf 들이 버퍼에 쌓인 채 무한 poll 루프로 들어가면 로그에 아무것도
    // 안 나와 "멈춘 것처럼" 보인다. 줄 단위 버퍼링으로 바꿔 즉시 보이게 한다.
    setvbuf(stdout, NULL, _IOLBF, 0);

    struct collector_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    __u8 one = 1;
    __u32 pid = 0;
    int nregistered = 0;
    int rc = 0;                 // 비정상 종료를 exit code 로 드러내기 위한 것

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // BPF 프로그램 로드
    skel = collector_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    // BPF 프로그램 attach
    err = collector_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    // sys_generator PID 찾기
    FILE *fp = popen("pidof sys_generator", "r");
    if (!fp) {
        fprintf(stderr, "Failed to run pidof\n");
        goto cleanup;
    }
    
    // BPF map에 target PID 등록
    while (fscanf(fp, "%u", &pid) == 1) {
        err = bpf_map_update_elem(
            bpf_map__fd(skel->maps.target_pids),
            &pid, &one, BPF_ANY
        );
        if (err) {
            fprintf(stderr, "Failed to insert PID %u into map: %s\n", pid, strerror(errno));
        } else {
            printf("Registered PID: %u\n", pid);
            nregistered++;
        }
    }

    pclose(fp);

    // 중앙집중 조건에서는 collector 가 sys_generator 파드보다 먼저 뜰 수 있다.
    // 그러면 등록할 PID 가 없어 조용히 0건을 수집하고, 실험은 성공한 것처럼 보인다.
    // 명시적으로 실패시켜 파드가 CrashLoopBackOff 로 드러나게 한다.
    if (nregistered == 0) {
        fprintf(stderr, "[-] no sys_generator process found. "
                        "sys-gen pods must be Running before this collector starts.\n");
        rc = 1;
        goto cleanup;
    }
    printf("[+] registered %d target PID(s)\n", nregistered);

    // 로그 파일 열기
    log_fp = fopen("syscalls.log", "w");
    if (!log_fp) {
        perror("fopen");
        goto cleanup;
    }

    // ring buffer 생성
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
    return rc;
}
