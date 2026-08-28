#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <jansson.h>
#include <time.h>
#include <errno.h>

#define LOG_FILE   "/app/syscall_log.txt"
#define RULE_FILE  "/app/rule_engine/rules.json"
#define ALERT_LOG  "/app/alert.log"

typedef struct {
    char name[64];
    int syscall;
} rule_t;

static rule_t *rules = NULL;
static size_t rule_cnt = 0;

/* === timestamp: collector와 동일 (CLOCK_MONOTONIC, sec.usec) === */
static void print_ts(FILE *fp)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    fprintf(fp, "%ld.%06ld ",
            ts.tv_sec, ts.tv_nsec / 1000);
}

/* === rule load === */
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
        exit(1);
    }

    rule_cnt = json_array_size(arr);
    rules = calloc(rule_cnt, sizeof(rule_t));
    if (!rules) {
        perror("calloc");
        exit(1);
    }

    for (size_t i = 0; i < rule_cnt; i++) {
        json_t *r = json_array_get(arr, i);

        const char *name =
            json_string_value(json_object_get(r, "name"));
        rules[i].syscall =
            json_integer_value(json_object_get(r, "syscall"));

        strncpy(rules[i].name, name, sizeof(rules[i].name) - 1);
    }

    json_decref(root);

    fprintf(stderr, "[+] loaded %zu rules\n", rule_cnt);
}

/* === main === */
int main(void)
{
    load_rules();

    FILE *log = fopen(LOG_FILE, "r");
    FILE *alert = fopen(ALERT_LOG, "a");

    if (!log || !alert) {
        perror("fopen");
        return 1;
    }

    /* tail -f: 시작 시점 이후 이벤트만 */
    // fseek(log, 0, SEEK_END);

    char line[256];

    while (1) {
        if (!fgets(line, sizeof(line), log)) {
            if (feof(log)) {
                clearerr(log);          // ★ EOF 플래그 제거 (핵심)
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

        double ts;
        int pid, sc;
        if (sscanf(line, "%lf PID=%d syscall=%d", &ts, &pid, &sc) != 3) {
            print_ts(alert);
            fprintf(alert, "PASS parse_fail %s", line);
            fflush(alert);
            continue;
        }

        int matched = 0;
        for (size_t i = 0; i < rule_cnt; i++) {
            if (rules[i].syscall == sc) {
                print_ts(alert);
                fprintf(alert, "ALERT rule=%s pid=%d syscall=%d\n", rules[i].name, pid, sc);
                fflush(alert);
                matched = 1;
            }
        }
        if (!matched) {
            print_ts(alert);
            fprintf(alert, "PASS pid=%d syscall=%d\n", pid, sc);
            fflush(alert);
        }
    }

    return 0;
}
