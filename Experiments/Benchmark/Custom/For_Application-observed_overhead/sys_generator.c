// v3/sys_generator.c
// Keeps the same syscall kinds and order as v2, stamping the time only right before and after each call.
//
// Purpose
//   Measures directly, from the application side, how much a single syscall round trip
//   grows once the dispatcher adds two map lookups and one tail call.
//
// Comparison conditions (the same binary is run four times)
//   baseline / central / distributed / scale
//   As the container count grows to 1, 5, 10, 20, 30, distributed should rise linearly
//   while scale stays flat. GEN_LABEL distinguishes the conditions in the records.
//
// About the measurement
//   clock_gettime(CLOCK_MONOTONIC) itself costs ~25ns, so the values below are
//   inflated by that much. That cost is constant across conditions, however, so
//   the delta against the baseline stays valid. If absolute values are needed,
//   measure the timer overhead separately and subtract it (the 'timer' entry below).
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdint.h>
#include <errno.h>
#include <sys/stat.h>

#define NS_PER_SEC 1000000000L

// Latency histogram: 1ns buckets up to 65us. Anything above is counted as overflow.
#define HIST_MAX 65536

volatile sig_atomic_t triggered = 0;

long get_env_long(const char* name, long default_val) {
    const char* val = getenv(name);
    if (val) return strtol(val, NULL, 10);
    return default_val;
}
static const char* get_env_str(const char* name, const char* dv) {
    const char* v = getenv(name);
    return (v && *v) ? v : dv;
}

void handle_sigusr1(int signo) {
    (void)signo;
    triggered = 1;
}

// v2's call order carried over verbatim, plus one timer self-measurement
enum {
    S_GETPID, S_GETPPID, S_GETUID, S_CLOCK_GETTIME, S_GETTIMEOFDAY,
    S_SCHED_YIELD, S_OPENAT, S_READ, S_CLOSE, S_MMAP, S_TIMER, S_N
};
static const char* S_NAME[S_N] = {
    "getpid", "getppid", "getuid", "clock_gettime", "gettimeofday",
    "sched_yield", "openat", "read", "close", "mmap", "(timer overhead)"
};

static uint64_t  cnt[S_N], sum[S_N], mn[S_N], mx[S_N], ovf[S_N];
static uint32_t *hist[S_N];

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * NS_PER_SEC + ts.tv_nsec;
}

static inline void record(int k, uint64_t d) {
    cnt[k]++; sum[k] += d;
    if (d < mn[k]) mn[k] = d;
    if (d > mx[k]) mx[k] = d;
    if (d < HIST_MAX) hist[k][d]++; else ovf[k]++;
}

// Macro wrapping each call. Every line of v2 was simply replaced with it.
#define TIMED(k, CALL) do {              \
        uint64_t _a = now_ns();          \
        CALL;                            \
        uint64_t _b = now_ns();          \
        record((k), _b - _a);            \
    } while (0)

static uint64_t pct(int k, double p) {
    uint64_t want = (uint64_t)(p * (double)cnt[k]), acc = 0;
    for (uint64_t i = 0; i < HIST_MAX; i++) {
        acc += hist[k][i];
        if (acc >= want) return i;
    }
    return mx[k];
}

void perform_syscalls(long duration_sec, long rate_limit) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    long nanos_per_loop = (rate_limit > 0) ? NS_PER_SEC / rate_limit : 0;

    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((now.tv_sec - start.tv_sec) >= duration_sec) break;

        // --- same kinds and order as v2 ---
        TIMED(S_GETPID,        syscall(SYS_getpid));
        TIMED(S_GETPPID,       syscall(SYS_getppid));
        TIMED(S_GETUID,        syscall(SYS_getuid));
        TIMED(S_CLOCK_GETTIME, syscall(SYS_clock_gettime, CLOCK_REALTIME, NULL));
        TIMED(S_GETTIMEOFDAY,  syscall(SYS_gettimeofday, NULL, NULL));
        TIMED(S_SCHED_YIELD,   syscall(SYS_sched_yield));

        int fd = -1;
        TIMED(S_OPENAT, fd = syscall(SYS_openat, AT_FDCWD, "/dev/zero", O_RDONLY));
        if (fd >= 0) {
            char buf[64];
            TIMED(S_READ,  syscall(SYS_read, fd, buf, sizeof(buf)));
            TIMED(S_CLOSE, syscall(SYS_close, fd));
        }

        TIMED(S_MMAP, syscall(SYS_mmap, NULL, 4096, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));

        // Timer self-measurement: the gap between two now_ns() calls, with no syscall.
        // Shows, under the same conditions, how much timer cost is baked into the values above.
        { uint64_t a = now_ns(); uint64_t b = now_ns(); record(S_TIMER, b - a); }

        if (nanos_per_loop > 0) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = nanos_per_loop };
            nanosleep(&ts, NULL);
        }
    }
}

// Prints the results to stdout. If GEN_OUT_DIR is set, a per-round file is written too.
//   The file is created inside the container, so an emptyDir/hostPath mount is needed to retrieve it.
//   Without a mount it disappears with the pod, so the default is stdout only.
static void report(const char* label, const char* host, long run, const char* out_dir) {
    FILE *fp = NULL;
    if (out_dir && *out_dir) {
        char path[512];
        mkdir(out_dir, 0755);            // ignored with EEXIST if it already exists
        snprintf(path, sizeof(path), "%s/%s_%s_run%ld.csv", out_dir, label, host, run);
        fp = fopen(path, "w");
        if (!fp) fprintf(stderr, "[!] fopen %s: %s\n", path, strerror(errno));
        else {
            fprintf(fp, "label,host,run,syscall,count,mean_ns,p50_ns,p99_ns,min_ns,max_ns,overflow\n");
            printf("[*] writing %s\n", path);
        }
    }

    printf("\n=== syscall latency (label=%s host=%s run=%ld) ===\n", label, host, run);
    printf("%-18s %10s %10s %10s %10s %10s %10s\n",
           "syscall", "count", "mean(ns)", "p50", "p99", "min", "max");
    printf("%s\n", "--------------------------------------------------------------------------------");
    for (int k = 0; k < S_N; k++) {
        if (!cnt[k]) continue;
        printf("%-18s %10llu %10.1f %10llu %10llu %10llu %10llu\n",
               S_NAME[k], (unsigned long long)cnt[k],
               (double)sum[k] / (double)cnt[k],
               (unsigned long long)pct(k, 0.50), (unsigned long long)pct(k, 0.99),
               (unsigned long long)mn[k], (unsigned long long)mx[k]);
    }
    // machine readable
    for (int k = 0; k < S_N; k++) {
        if (!cnt[k]) continue;
        double mean = (double)sum[k] / (double)cnt[k];
        printf("CSV,%s,%s,%ld,%s,%llu,%.1f,%llu,%llu,%llu,%llu,%llu\n",
               label, host, run, S_NAME[k],
               (unsigned long long)cnt[k], mean,
               (unsigned long long)pct(k, 0.50), (unsigned long long)pct(k, 0.99),
               (unsigned long long)mn[k], (unsigned long long)mx[k],
               (unsigned long long)ovf[k]);
        if (fp)
            fprintf(fp, "%s,%s,%ld,%s,%llu,%.1f,%llu,%llu,%llu,%llu,%llu\n",
                    label, host, run, S_NAME[k],
                    (unsigned long long)cnt[k], mean,
                    (unsigned long long)pct(k, 0.50), (unsigned long long)pct(k, 0.99),
                    (unsigned long long)mn[k], (unsigned long long)mx[k],
                    (unsigned long long)ovf[k]);
    }
    if (fp) fclose(fp);
    for (int k = 0; k < S_N; k++)
        if (ovf[k])
            printf("[!] %s: %llu samples exceeded %d ns (likely scheduled out / interrupted)\n",
                   S_NAME[k], (unsigned long long)ovf[k], HIST_MAX);
    fflush(stdout);
}

static void reset_stats(void) {
    for (int k = 0; k < S_N; k++) {
        cnt[k] = sum[k] = mx[k] = ovf[k] = 0;
        mn[k] = ~0ULL;
        memset(hist[k], 0, HIST_MAX * sizeof(uint32_t));
    }
}

int main() {
    long duration_sec = get_env_long("GEN_DURATION_SEC", 10);
    long rate_limit   = get_env_long("GEN_RATE_LIMIT", 0);
    const char* label   = get_env_str("GEN_LABEL", "baseline");
    const char* out_dir = get_env_str("GEN_OUT_DIR", "");   // empty means stdout only
    char host[256] = "unknown";
    gethostname(host, sizeof(host) - 1);   // on k8s this yields the pod name
    long run = 0;

    for (int k = 0; k < S_N; k++) {
        hist[k] = calloc(HIST_MAX, sizeof(uint32_t));
        if (!hist[k]) { perror("calloc"); return 1; }
    }
    reset_stats();

    signal(SIGUSR1, handle_sigusr1);

    printf("[+] label=%s duration=%lds rate_limit=%ld\n", label, duration_sec, rate_limit);
    printf("[+] Waiting for SIGUSR1 to start syscall generation...\n");
    fflush(stdout);

    while (1) {
        pause();  // Wait for signal
        if (triggered) {
            printf("[+] Received signal, generating syscalls for %ld sec\n", duration_sec);
            fflush(stdout);
            triggered = 0;
            reset_stats();                 // restart the statistics for each round
            perform_syscalls(duration_sec, rate_limit);
            report(label, host, ++run, out_dir);
            printf("[+] Finished syscall generation, waiting again...\n");
            fflush(stdout);
        }
    }

    return 0;
}
