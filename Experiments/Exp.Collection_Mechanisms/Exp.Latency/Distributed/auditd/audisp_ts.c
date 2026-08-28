// audisp_ts.c
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

static double now_rt(void){ struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); return ts.tv_sec + ts.tv_nsec/1e9; }
static double now_mono(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec + ts.tv_nsec/1e9; }

// robust: "audit(SEC.USEC:SER)" 또는 "msg=audit(SEC.USEC:SER)"
static int parse_audit_ts(const char *s, double *out_sec, long *serial_out) {
    const char *p = strstr(s, "audit(");
    if (!p) return -1;
    p += 6; // after "audit("

    long sec = 0, usec = 0, serial = -1;
    // 예: 1700000000.123456:1) ...
    int n = sscanf(p, "%ld.%ld:%ld", &sec, &usec, &serial);
    if (n != 3) return -1;

    // usec 자릿수는 0~6 가정. 초에 합산.
    if (usec < 0) usec = 0;
    if (usec > 999999) usec = 999999;

    *out_sec = (double)sec + (double)usec / 1e6;
    if (serial_out) *serial_out = serial;
    return 0;
}

static int parse_field_long(const char *s, const char *key, long *out) {
    const char *p = strstr(s, key); if (!p) return -1;
    p += strlen(key);
    char *end = NULL; long v = strtol(p, &end, 10);
    if (p == end) return -1;
    *out = v; return 0;
}

static int parse_field_str(const char *s, const char *key, char *buf, size_t buflen) {
    const char *p = strstr(s, key); if (!p) return -1;
    p += strlen(key);
    if (*p != '\"') return -1;
    p++;
    const char *q = strchr(p, '\"'); if (!q) return -1;
    size_t n = (size_t)(q - p);
    if (n >= buflen) n = buflen - 1;
    memcpy(buf, p, n); buf[n] = '\0';
    return 0;
}

int main(void) {
    const char *outpath = "/var/log/audit/audisp_ts.log";
    FILE *fp = fopen(outpath, "a");
    if (!fp) {
        fprintf(stderr, "ERR: fopen(%s): %s\n", outpath, strerror(errno));
        return 1;
    }
    setvbuf(fp, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);

    char *line = NULL; size_t cap = 0;
    while (getline(&line, &cap, stdin) > 0) {
        if (!strstr(line, "type=SYSCALL")) {
            // 필요시 디버깅
            // fprintf(stderr, "SKIP: not SYSCALL: %s", line);
            continue;
        }

        double evoked_rt = 0.0; long serial = -1;
        if (parse_audit_ts(line, &evoked_rt, &serial) != 0) {
            fprintf(stderr, "SKIP: parse_audit_ts failed: %s", line);
            continue;
        }

        long pid = -1, sc = -1;
        if (parse_field_long(line, " pid=", &pid) != 0)
            fprintf(stderr, "WARN: no pid field\n");
        if (parse_field_long(line, " syscall=", &sc) != 0)
            fprintf(stderr, "WARN: no syscall field\n");

        char keybuf[128] = "";
        (void)parse_field_str(line, " key=", keybuf, sizeof(keybuf)); // 없으면 빈 문자열

        double collected_rt   = now_rt();
        double collected_mono = now_mono();

        if (fprintf(fp,
            "{\"EvokedRT\":%.6f,\"CollectedRT\":%.6f,\"CollectedMono\":%.6f,"
            "\"pid\":%ld,\"syscall\":%ld,\"serial\":%ld,\"key\":\"%s\"}\n",
            evoked_rt, collected_rt, collected_mono, pid, sc, serial, keybuf) < 0) {
            fprintf(stderr, "ERR: fprintf to %s failed: %s\n", outpath, strerror(errno));
        }
        fflush(fp);
        fsync(fileno(fp));
    }
    free(line);
    fclose(fp);
    return 0;
}
