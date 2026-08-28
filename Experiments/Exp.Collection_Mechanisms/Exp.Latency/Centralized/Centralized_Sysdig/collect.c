// sysdig_latency_logger.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

// ----------------- Config & Signals -----------------
static volatile sig_atomic_t g_stop = 0;

static void on_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static inline uint64_t realtime_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts); // epoch-based
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

// ----------------- Main -----------------
int main(int argc, char **argv) {
    const char *proc_name = "sys_generator";
    const char *out_path  = "pod.log";
    int append_mode = 0;   // 0: overwrite, 1: append
    int enter_only = 1;    // default: syscall enter (<)

    // Options
    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--proc") && i + 1 < argc) {
            proc_name = argv[++i];
        } else if (!strcmp(argv[i], "--out") && i + 1 < argc) {
            out_path = argv[++i];
        } else if (!strcmp(argv[i], "--append")) {
            append_mode = 1;
        } else if (!strcmp(argv[i], "--all")) {
            enter_only = 0; // include both enter/exit
        } else if (!strcmp(argv[i], "--help")) {
            fprintf(stderr,
                "Usage: %s [--proc NAME] [--out FILE] [--append] [--all]\n"
                "  --proc   process name to trace (default: sys_generator)\n"
                "  --out    output log file (default: pod.log)\n"
                "  --append append to file instead of overwrite\n"
                "  --all    capture both enter and exit events (default: enter only)\n",
                argv[0]);
            return 0;
        }
    }

    // Signal handlers
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    // Build sysdig command:
    // - epoch ns: %evt.rawtime
    // - pid/tid:  %proc.pid %thread.tid
    // - type:     %evt.type
    // - filter:   proc.name=... and (evt.dir=< if enter_only)
    char filter[256];
    if (enter_only) {
        snprintf(filter, sizeof(filter), "'evt.dir=< and proc.name=%s'", proc_name);
    } else {
        snprintf(filter, sizeof(filter), "'proc.name=%s'", proc_name);
    }

    char cmd[768];
    // stdbuf -oL to get line-buffered output from sysdig to minimize extra delay
    snprintf(cmd, sizeof(cmd),
        "stdbuf -oL sysdig -t r %s -p '%%evt.rawtime %%proc.pid %%thread.tid %%evt.type'",
        filter);

    // Launch sysdig
    FILE *pp = popen(cmd, "r");
    if (!pp) die("popen(sysdig) failed: %s", strerror(errno));

    // Open output
    FILE *fp = fopen(out_path, append_mode ? "a" : "w");
    if (!fp) {
        pclose(pp);
        die("fopen(%s) failed: %s", out_path, strerror(errno));
    }
    // Large buffer for throughput
    setvbuf(fp, NULL, _IOFBF, 1 << 20);

    // Header (only when overwriting)
    if (!append_mode) {
        // Fields: user_epoch_ns evt_epoch_ns latency_ns pid tid evt.type
        fprintf(fp, "# user_epoch_ns evt_epoch_ns latency_ns pid tid evt.type\n");
        fflush(fp);
    }

    // Read loop
    char line[4096];
    unsigned long long lines = 0;

    while (!g_stop && fgets(line, sizeof(line), pp)) {
        // Expected: "<evt_raw_ns> <pid> <tid> <evt.type...>"
        // Example : "1725749651234567890 2824054 2824054 clock_gettime"
        char *p = line, *endptr = NULL;

        errno = 0;
        uint64_t evt_raw_ns = strtoull(p, &endptr, 10);
        if (errno || endptr == p) continue;
        p = endptr;

        errno = 0;
        long pid = strtol(p, &endptr, 10);
        if (endptr == p) continue;
        p = endptr;

        errno = 0;
        long tid = strtol(p, &endptr, 10);
        if (endptr == p) continue;
        p = endptr;

        while (*p == ' ' || *p == '\t') ++p;
        char *evt = p;
        size_t len = strlen(evt);
        while (len > 0 && (evt[len - 1] == '\n' || evt[len - 1] == '\r')) {
            evt[--len] = 0;
        }

        // User receive time (epoch ns)
        uint64_t user_now_ns = realtime_ns();

        // Latency (ensure non-negative)
        uint64_t latency_ns = (user_now_ns >= evt_raw_ns) ? (user_now_ns - evt_raw_ns) : 0;

        // Log one line (plain text, not CSV)
        // user_epoch_ns evt_epoch_ns latency_ns pid tid evt.type
        fprintf(fp, "%llu %llu %llu %ld %ld %s\n",
                (unsigned long long)user_now_ns,
                (unsigned long long)evt_raw_ns,
                (unsigned long long)latency_ns,
                pid, tid, evt);

        // Flush periodically to keep the log durable without killing throughput
        if ((++lines & 0x3FFF) == 0) { // every 16384 lines
            fflush(fp);
        }
    }

    // Cleanup
    fflush(fp);
    fclose(fp);
    int status = pclose(pp);
    (void)status;

    fprintf(stderr, "[*] wrote %llu lines to %s\n",
            (unsigned long long)lines, out_path);
    return 0;
}
