#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <jansson.h>
#include <time.h>
#include <errno.h>

#define LOG_FILE   "/app/syscalls.log"          // ★ collector 로그 파일에 맞추기
#define RULE_FILE  "/app/rules.json"
#define ALERT_LOG  "/app/alert.log"

typedef struct {
    char name[64];
    int syscall;
} rule_t;

static rule_t *rules = NULL;
static size_t rule_cnt = 0;

/* === timestamp: rule_engine 자체 기록용 (CLOCK_MONOTONIC, sec.usec) === */
static void print_ts(FILE *fp)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    fprintf(fp, "%ld.%06ld ", ts.tv_sec, ts.tv_nsec / 1000);
}

static void load_rules(void)
{
    json_error_t err;
    json_t *root = json_load_file(RULE_FILE, 0, &err);
    if (!root) {
        fprintf(stderr, "rule load error: %s\n", err.text);
        exit(1);
    }

    json_t *arr = json_object_get(root, "rules");
    if (!json_is_array(arr)) {
        fprintf(stderr, "rule load error: rules is not array\n");
        json_decref(root);
        exit(1);
    }

    rule_cnt = json_array_size(arr);
    rules = calloc(rule_cnt, sizeof(rule_t));
    if (!rules) {
        perror("calloc");
        json_decref(root);
        exit(1);
    }

    for (size_t i = 0; i < rule_cnt; i++) {
        json_t *r = json_array_get(arr, i);

        const char *name = json_string_value(json_object_get(r, "name"));
        json_t *scj = json_object_get(r, "syscall");
        if (!name || !json_is_integer(scj)) {
            fprintf(stderr, "rule load warning: invalid rule at index %zu\n", i);
            continue;
        }

        rules[i].syscall = (int)json_integer_value(scj);
        strncpy(rules[i].name, name, sizeof(rules[i].name) - 1);
    }

    json_decref(root);
    fprintf(stderr, "[+] loaded %zu rules\n", rule_cnt);
}

/*
 * Parse formats:
 *  1) New (collector):
 *     "Evoked Time=%lf, Collected Time=%lf PID=%d syscall=%u"
 *  2) Old fallback:
 *     "%lf PID=%d syscall=%d"
 *
 * Returns 1 if parsed, 0 otherwise.
 */
static int parse_line(const char *line,
                      double *evoked_s,
                      double *collected_s,
                      int *pid,
                      unsigned *sc)
{
    double ev = 0.0, col = 0.0;
    int p = 0;
    unsigned s = 0;

    // New format (spaces after comma can vary, so keep it tolerant)
    if (sscanf(line,
               "Evoked Time=%lf, Collected Time=%lf PID=%d syscall=%u",
               &ev, &col, &p, &s) == 4) {
        *evoked_s = ev;
        *collected_s = col;
        *pid = p;
        *sc = s;
        return 1;
    }

    return 0;
}

int main(void)
{
    load_rules();

    FILE *log = fopen(LOG_FILE, "r");
    FILE *alert = fopen(ALERT_LOG, "a");
    if (!log || !alert) {
        perror("fopen");
        return 1;
    }

    // 원하면 “프로그램 시작 이후”만 보고 싶을 때 사용:
    // fseek(log, 0, SEEK_END);

    char line[512];

    while (1) {
        if (!fgets(line, sizeof(line), log)) {
            if (feof(log)) {
                clearerr(log);      // tail -f 핵심
                usleep(50000);
                continue;
            }
            if (ferror(log)) {
                perror("fgets");
                clearerr(log);
                usleep(50000);
                continue;
            }
            usleep(50000);
            continue;
        }

        // 디버그
        // fprintf(stderr, "[DEBUG] read line: %s", line);

        double evoked_s = 0.0, collected_s = 0.0;
        int pid = 0;
        unsigned sc = 0;

        if (!parse_line(line, &evoked_s, &collected_s, &pid, &sc)) {
            print_ts(alert);
            fprintf(alert, "PASS parse_fail %s", line);
            fflush(alert);
            continue;
        }

        int matched = 0;
        for (size_t i = 0; i < rule_cnt; i++) {
            if ((unsigned)rules[i].syscall == sc) {
                print_ts(alert);
                fprintf(alert,
                        "ALERT rule=%s pid=%d syscall=%u\n",rules[i].name, pid, sc);
                fflush(alert);
                matched = 1;
            }
        }

        if (!matched) {
            print_ts(alert);
            fprintf(alert,
                    "PASS pid=%d syscall=%u\n", pid, sc);
            fflush(alert);
        }
    }

    return 0;
}
