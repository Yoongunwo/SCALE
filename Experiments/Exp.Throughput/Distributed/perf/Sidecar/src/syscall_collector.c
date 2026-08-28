#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>  // ✅ 이거 꼭 필요
#include <signal.h>

static FILE *log_fp = NULL;

static int handle_event(void *data, size_t size) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME_COARSE, &ts);
    fprintf(log_fp, "%ld.%06ld : %s",
            ts.tv_sec, ts.tv_nsec / 1000, (char *)data);
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
    uint32_t target_pid = get_container_pid();
    if (!target_pid) {
        fprintf(stderr, "Failed to obtain host PID\n");
        return 1;
    }
    char perf_cmd[128];
    snprintf(perf_cmd, sizeof(perf_cmd), "perf trace -e syscalls:sys_enter_* -p %u 2>&1", target_pid);

    FILE *fp = popen(perf_cmd, "r");
    if (!fp) {
        perror("popen failed");
        return 1;
    }

    char file[64];
    snprintf(file, sizeof(file), "syscalls_%u.log", target_pid);
    log_fp = fopen(file, "w");

    char buf[1024];
    while (fgets(buf, sizeof(buf), fp)) {
        handle_event(buf, strlen(buf));
    }

    pclose(fp);
    return 0;
}
