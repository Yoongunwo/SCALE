#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

static FILE *log_fp = NULL;

static struct timespec g_rt_minus_mono;

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

// static int handle_event(void *data, size_t size) {
//     struct timespec ts;
//     clock_gettime(CLOCK_MONOTONIC, &ts);
//     fprintf(log_fp, "%ld.%06ld : %s",
//             ts.tv_sec, ts.tv_nsec / 1000, (char *)data);
//     return 0;
// }

static int handle_event(void *data, size_t size){
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);      // ★ wall-clock 사용
    // 하루 기준 마이크로초
    unsigned long long sec_of_day = (unsigned long long)(ts.tv_sec % 86400);
    unsigned long long user_us = sec_of_day*1000000ULL + (unsigned long long)(ts.tv_nsec/1000);
    fprintf(log_fp, "%llu : %s", user_us, (char*)data);  // ★ µs 정수로 출력
    return 0;
}

static uint32_t get_container_pid(void) {
    FILE *pf = popen("ps -C sys_generator -o pid=", "r");
    if (!pf) { perror("popen(ps)"); return 0; }
    char line[64]; uint32_t cpid = 0;
    while (fgets(line, sizeof(line), pf)) {
        char *p = line; while (*p==' '||*p=='\t') p++;
        long v = strtol(p, NULL, 10);
        if (v > 0) { cpid = (uint32_t)v; break; }
    }
    pclose(pf);
    return cpid;
}

int main(void) {
    compute_offset();

    int n = get_container_pid();
    printf("Monitoring PIDs: %d\n", n);

    // perf trace 커맨드 구성 (-p pid1,pid2,...)
    char perf_cmd[8192];
    snprintf(perf_cmd, sizeof(perf_cmd),
             "perf trace -e syscalls:sys_enter_* -p %d -T 2>&1", n);

    FILE *fp = popen(perf_cmd, "r");
    if (!fp) { perror("popen perf trace"); return 1; }

    // 단일 합산 로그로 저장(원하면 PID별로 분리도 가능)
    log_fp = fopen("syscalls_sys_generator.log", "w");
    if (!log_fp) { perror("fopen log"); pclose(fp); return 1; }

    char line[2048];
    while (fgets(line, sizeof(line), fp)) {
        handle_event(line, strlen(line));
    }

    fclose(log_fp);
    pclose(fp);
    return 0;
}