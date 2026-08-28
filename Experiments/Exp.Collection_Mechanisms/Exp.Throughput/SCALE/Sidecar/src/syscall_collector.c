#include "syscall_collector.skel.h"
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <jansson.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define PIN_BASE_PATH "/sys/fs/bpf/"
#define PROG_PREFIX   "syscall_prog_"
#define SYSCALL_JSON  "./x86-64_ABI.json"

static FILE *log_fp = NULL;

struct syscall_event_t {
    __u32 pid;
    __u32 syscall_nr;
};

static int handle_event(void *ctx, void *data, size_t size) {
    struct syscall_event_t *evt = data;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME_COARSE, &ts);
    fprintf(log_fp, "%ld.%06ld PID=%u syscall=%lu\n",
            ts.tv_sec, ts.tv_nsec / 1000, evt->pid, evt->syscall_nr);
}

typedef struct {
    int number;
    char *name;
} syscall_entry_t;

int get_syscalls(syscall_entry_t **entries_out, size_t *count_out) {
    json_error_t error;
    json_t *root = json_load_file(SYSCALL_JSON, 0, &error);
    if (!root) {
        fprintf(stderr, "[-] Failed to parse syscall JSON: %s\n", error.text);
        return -1;
    }

    json_t *syscalls = json_object_get(root, "syscalls");
    if (!json_is_array(syscalls)) {
        fprintf(stderr, "[-] JSON format error: 'syscalls' is not an array\n");
        json_decref(root);
        return -1;
    }

    size_t count = json_array_size(syscalls);
    syscall_entry_t *entries = malloc(sizeof(syscall_entry_t) * count);
    if (!entries) {
        perror("malloc");
        json_decref(root);
        return -1;
    }

    for (size_t i = 0; i < count; ++i) {
        json_t *item = json_array_get(syscalls, i);
        if (!json_is_object(item)) {
            fprintf(stderr, "[-] Item %zu is not an object\n", i);
            continue;
        }

        json_t *num = json_object_get(item, "number");
        json_t *name = json_object_get(item, "name");

        if (!json_is_integer(num) || !json_is_string(name)) {
            fprintf(stderr, "[-] Invalid format in syscall entry %zu\n", i);
            continue;
        }

        entries[i].number = json_integer_value(num);
        entries[i].name = strdup(json_string_value(name));  // strdup 사용
    }

    *entries_out = entries;
    *count_out = count;

    json_decref(root);
    return 0;
}

int main(int argc, char **argv) {
    char ip_str[INET_ADDRSTRLEN];
    struct in_addr addr;
    char ringbuf_path[256];

    FILE *fp = popen("hostname -i", "r");
    if (!fp || !fgets(ip_str, sizeof(ip_str), fp)) {
        perror("get IP");
        return 1;
    }
    pclose(fp);
    ip_str[strcspn(ip_str, "\n")] = '\0';
    if (inet_aton(ip_str, &addr) == 0) {
        fprintf(stderr, "Invalid IP: %s\n", ip_str);
        return 1;
    }
    for (int i = 0; ip_str[i]; ++i) {
        if (ip_str[i] == '.') ip_str[i] = '_';
    }

    uint32_t ip_int = ntohl(addr.s_addr);
    printf("[+] Using IP: %s (int: %u)\n", ip_str, ip_int);

    snprintf(ringbuf_path, sizeof(ringbuf_path), "/sys/fs/bpf/ringbuf/syscall_ringbuf_%s", ip_str);

    struct syscall_collector_bpf *skel = syscall_collector_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    syscall_entry_t *entries = NULL;
    size_t count = 0;

    if (get_syscalls(&entries, &count) == 0) {
        for (size_t i = 0; i < count; ++i) {
            char* prog_name;
            if (asprintf(&prog_name, "handle_%s", entries[i].name) < 0) {
                perror("asprintf");
                continue;
            }
            struct bpf_program *prog = bpf_object__find_program_by_name(skel->obj, prog_name);
            if (!prog) {
                fprintf(stderr, "[-] No BPF program named '%s' in skeleton\n", entries[i].name);
                continue;
            }

            char pin_path[256];
            snprintf(pin_path, sizeof(pin_path), "%s%s%s_%u", PIN_BASE_PATH, PROG_PREFIX, entries[i].name, ip_int);

            if (bpf_program__pin(prog, pin_path) < 0) {
                fprintf(stderr, "[-] Failed to pin %s at %s\n", entries[i].name, pin_path);
            } else {
                printf("[+] Pinned %s at %s\n", entries[i].name, pin_path);
            }   
        }
    }

    // Setup ring buffer for actual collection
    char* log_name = "syscall_log.txt";
    log_fp = fopen(log_name, "w");
    if (!log_fp) {
        perror("fopen");
        syscall_collector_bpf__destroy(skel);
        return 1;
    }

    int rb_fd = bpf_map__fd(skel->maps.ringbuf_local);
    struct ring_buffer *rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        fclose(log_fp);
        syscall_collector_bpf__destroy(skel);
        return 1;
    }

    printf("[+] Tracing syscalls\n");
    const char *poll_env = getenv("RINGBUF_POLL_MS");
    int poll_interval_ms = 50;
    if (poll_env) {
        int val = atoi(poll_env);
        if (val > 0) {
            poll_interval_ms = val;
        } else {
            fprintf(stderr, "[-] Invalid RINGBUF_POLL_MS value: %s, using default 50ms\n", poll_env);
        }
    }
    while (1) ring_buffer__poll(rb, poll_interval_ms); 

    ring_buffer__free(rb);
    fclose(log_fp);
    syscall_collector_bpf__destroy(skel);
    return 0;
}
