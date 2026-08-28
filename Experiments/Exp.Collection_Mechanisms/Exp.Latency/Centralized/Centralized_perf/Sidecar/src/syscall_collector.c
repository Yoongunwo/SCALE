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

static int handle_event(void *data, size_t size) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    fprintf(log_fp, "%ld.%06ld : %s",
            ts.tv_sec, ts.tv_nsec / 1000, (char *)data);
    return 0;
}

/* convert the pidof result (space separated) into a comma separated list */
static int build_pid_list(const char *comm, char *out, size_t outsz) {
    FILE *pf = popen("pidof sys_generator || pidof postmark", "r");
    if (!pf) { perror("popen(pidof)"); return -1; }

    out[0] = '\0';
    int count = 0;
    char buf[4096];
    if (fgets(buf, sizeof(buf), pf)) {
        // buf example: "1234 2345 3456\n"
        char *tok = strtok(buf, " \t\r\n");
        while (tok) {
            if (count > 0) strncat(out, ",", outsz - strlen(out) - 1);
            strncat(out, tok, outsz - strlen(out) - 1);
            count++;
            tok = strtok(NULL, " \t\r\n");
        }
    }
    pclose(pf);
    return count; // 0 means the process does not exist
}

int main(void) {
    compute_offset();

    // every sys_generator
    char pidlist[4096];
    int n = build_pid_list("sys_generator", pidlist, sizeof(pidlist));
    if (n <= 0) {
        fprintf(stderr, "no sys_generator process found\n");
        return 1;
    }
    printf("Monitoring PIDs: %s\n", pidlist);

    // build the perf trace command (-p pid1,pid2,...)
    char perf_cmd[8192];
    snprintf(perf_cmd, sizeof(perf_cmd),
             "perf trace -e syscalls:sys_enter_* -p %s 2>&1", pidlist);

    FILE *fp = popen(perf_cmd, "r");
    if (!fp) { perror("popen perf trace"); return 1; }

    // store as a single combined log (it can be split per PID if desired)
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
