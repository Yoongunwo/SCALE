// v3/sys_generator.c
// v2 와 동일한 syscall 종류·순서를 유지하고, 각 호출 직전/직후 시각만 찍는다.
//
// 목적
//   dispatcher 가 map lookup 2회 + tail call 1회를 얹으면 syscall 한 번의 왕복이
//   얼마나 늘어나는지를 애플리케이션 쪽에서 직접 잰다.
//
// 비교 조건 (같은 바이너리로 네 번 돌린다)
//   baseline / central / distributed / scale
//   컨테이너 수를 1,5,10,20,30 으로 늘리면 distributed 는 선형 증가,
//   scale 은 평평해야 한다. GEN_LABEL 로 조건을 구분해 기록한다.
//
// 측정에 대하여
//   clock_gettime(CLOCK_MONOTONIC) 자체가 ~25ns 든다. 그래서 아래 값들은
//   그만큼 부풀려져 있다. 다만 그 비용은 조건과 무관하게 일정하므로
//   baseline 대비 증가분(delta)은 그대로 유효하다. 절대값이 필요하면
//   부록에 타이머 오버헤드를 따로 재서 빼면 된다 (아래 'timer' 항목).
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

// 지연 히스토그램: 1ns 단위, 65us 까지. 그 위는 overflow 로 센다.
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

// v2 의 호출 순서를 그대로 옮긴 것 + 타이머 자기측정 1개
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

// 호출 직전/직후를 감싸는 매크로. v2 의 각 줄을 이걸로 바꾸기만 했다.
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

        // --- v2 와 동일한 종류·순서 ---
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

        // 타이머 자기측정: syscall 없이 now_ns() 두 번의 간격.
        // 위 값들에 섞여 있는 타이머 비용이 얼마인지 같은 조건에서 알 수 있다.
        { uint64_t a = now_ns(); uint64_t b = now_ns(); record(S_TIMER, b - a); }

        if (nanos_per_loop > 0) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = nanos_per_loop };
            nanosleep(&ts, NULL);
        }
    }
}

// 결과를 stdout 에 찍는다. GEN_OUT_DIR 이 있으면 회차별 파일도 남긴다.
//   파일은 컨테이너 안에 생기므로 꺼내려면 emptyDir/hostPath 마운트가 필요하다.
//   마운트가 없으면 파드 종료와 함께 사라지므로 기본값은 stdout 전용이다.
static void report(const char* label, const char* host, long run, const char* out_dir) {
    FILE *fp = NULL;
    if (out_dir && *out_dir) {
        char path[512];
        mkdir(out_dir, 0755);            // 이미 있으면 EEXIST 로 무시된다
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
    // 기계 판독용
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
            printf("[!] %s: %llu 건이 %d ns 를 넘었다 (스케줄 아웃/인터럽트 추정)\n",
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
    const char* out_dir = get_env_str("GEN_OUT_DIR", "");   // 비면 stdout 전용
    char host[256] = "unknown";
    gethostname(host, sizeof(host) - 1);   // k8s 에서는 파드 이름이 들어온다
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
            reset_stats();                 // 회차마다 통계를 새로 시작한다
            perform_syscalls(duration_sec, rate_limit);
            report(label, host, ++run, out_dir);
            printf("[+] Finished syscall generation, waiting again...\n");
            fflush(stdout);
        }
    }

    return 0;
}
