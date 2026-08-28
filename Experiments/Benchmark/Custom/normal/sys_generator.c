#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdatomic.h>

#define NS_PER_SEC 1000000000L

volatile sig_atomic_t triggered = 0;

long get_env_long(const char* name, long default_val) {
    const char* val = getenv(name);
    if (val) return strtol(val, NULL, 10);
    return default_val;
}

void handle_sigusr1(int signo) {
    triggered = 1;
}

void perform_syscalls(long duration_sec, long rate_limit) {
    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    long nanos_per_loop = (rate_limit > 0) ? NS_PER_SEC / rate_limit : 0;

    while (1) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((now.tv_sec - start.tv_sec) >= duration_sec) break;

        syscall(SYS_getpid);
        syscall(SYS_getppid);
        syscall(SYS_getuid);
        syscall(SYS_clock_gettime, CLOCK_REALTIME, NULL);
        syscall(SYS_gettimeofday, NULL, NULL);
        syscall(SYS_sched_yield);

        int fd = syscall(SYS_openat, AT_FDCWD, "/dev/zero", O_RDONLY);
        if (fd >= 0) {
            char buf[64];
            syscall(SYS_read, fd, buf, sizeof(buf));
            syscall(SYS_close, fd);
        }

        syscall(SYS_mmap, NULL, 4096, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (nanos_per_loop > 0) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = nanos_per_loop };
            nanosleep(&ts, NULL);
        }
    }
}

int main() {
    long duration_sec = get_env_long("GEN_DURATION_SEC", 10);
    long rate_limit = get_env_long("GEN_RATE_LIMIT", 0);

    signal(SIGUSR1, handle_sigusr1);

    printf("[+] Waiting for SIGUSR1 to start syscall generation...\n");
    fflush(stdout);

    while (1) {
        pause();  // Wait for signal
        if (triggered) {
            printf("[+] Received signal, generating syscalls for %ld sec\n", duration_sec);
            fflush(stdout);
            triggered = 0;
            perform_syscalls(duration_sec, rate_limit);
            printf("[+] Finished syscall generation, waiting again...\n");
            fflush(stdout);
        }
    }

    return 0;
}
