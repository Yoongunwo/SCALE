// main_controller.c
#include "dispatcher.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <jansson.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sysinfo.h>  // get_nprocs()
#include <time.h>
#include <sys/time.h>

#define MAX_PAIRS 100 
#define RINGBUF_POLL_MS 100 // ms

static FILE *log_fp = NULL;
static struct timespec g_rt_minus_mono;

struct pid_ip_pair {
    uint32_t ip;
    uint32_t pid;
};

struct syscall_event_t {
    __u32 pid;
    __u32 syscall_nr;
    __u64 ts_ns;  // timestamp in nanoseconds
};

#define PIN_BASE_PATH "/sys/fs/bpf/"
#define PROG_PREFIX  "syscall_prog_"
#define SYSCALL_JSON "./x86-64_ABI.json"

int extract_string_from_json(const char *cmd, const char *field, char *output, size_t len) {
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char *pos = strstr(line, field);
        if (pos) {
            char *colon = strchr(pos, ':');
            if (!colon) continue;
            char *start = strchr(colon, '\"');
            if (!start) continue;
            start++;
            char *end = strchr(start, '\"');
            if (!end) continue;

            size_t copy_len = end - start;
            if (copy_len >= len) copy_len = len - 1;
            strncpy(output, start, copy_len);
            output[copy_len] = '\0';
            pclose(fp);
            return 0;
        }
    }

    pclose(fp);
    return -1;
}

int create_pid_to_podip_map(struct pid_ip_pair *out_pairs, int *out_count) {
    FILE *ps = popen("crictl ps --name '^proxy$' | awk 'NR>1 {print $1}'", "r");
    if (!ps) {
        perror("popen(crictl ps)");
        return 1;
    }

    int pair_index = 0;
    char container_id[128];

    while (fgets(container_id, sizeof(container_id), ps)) {
        container_id[strcspn(container_id, "\n")] = '\0';
        printf("[INFO] Found proxy container ID: %s\n", container_id);

        // 1. Get sandbox ID
        char sandbox_id[128], cmd[256];
        snprintf(cmd, sizeof(cmd), "crictl inspect %s", container_id);
        if (extract_string_from_json(cmd, "sandboxID", sandbox_id, sizeof(sandbox_id)) != 0) {
            fprintf(stderr, "  [!] Failed to extract sandboxID\n");
            continue;
        }

        // 2. Get Pod IP
        char pod_ip_str[64];
        snprintf(cmd, sizeof(cmd), "crictl inspectp %s", sandbox_id);
        if (extract_string_from_json(cmd, "ip", pod_ip_str, sizeof(pod_ip_str)) != 0) {
            fprintf(stderr, "  [!] Failed to extract Pod IP\n");
            continue;
        }
        printf("[INFO] pod IP: %s\n", pod_ip_str);

        struct in_addr addr;
        if (!inet_aton(pod_ip_str, &addr)) {
            fprintf(stderr, "  [!] Invalid IP format\n");
            continue;
        }
        uint32_t ip_int = ntohl(addr.s_addr);

        // 3. Find containerd-shim PID for the sandbox
        snprintf(cmd, sizeof(cmd),
                 "ps -ef | grep containerd-shim | grep %s | grep -v grep | awk '{print $2}'",
                 sandbox_id);
        FILE *shim_ps = popen(cmd, "r");
        if (!shim_ps || !fgets(cmd, sizeof(cmd), shim_ps)) {
            fprintf(stderr, "  [!] Failed to get containerd-shim PID for sandbox %s\n", sandbox_id);
            if (shim_ps) pclose(shim_ps);
            continue;
        }
        pclose(shim_ps);

        int shim_pid = atoi(cmd);
        if (shim_pid <= 0) {
            fprintf(stderr, "  [!] Invalid shim PID\n");
            continue;
        }
        printf("[INFO] containerd-shim PID: %d\n", shim_pid);

        // 4. Collect all PIDs under the shim process tree
        snprintf(cmd, sizeof(cmd),
                "pstree -ap %d | grep -E 'sys_generator|postmark' | grep -o ',[0-9]*' | tr -d ','", shim_pid);
        
        FILE *pstree = popen(cmd, "r");
        if (!pstree) {
            perror("popen(pstree)");
            printf("[INFO] Failed to get pstree for PID %d\n", shim_pid);
            continue;
        }

        char pid_line[64];
        if(fgets(pid_line, sizeof(pid_line), pstree)){
            int pid = atoi(pid_line);
            if (pid > 0) {
                printf("[INFO] Mapped IP %s -> PID %d\n", pod_ip_str, pid);
                out_pairs[pair_index].ip = ip_int;
                out_pairs[pair_index].pid = pid;
                pair_index++;
            }
        }
        pclose(pstree);
    }

    pclose(ps);
    *out_count = pair_index;
    printf("[+] PID to PodIP map populated.\n");
    return 0;
}

void register_programs(int hash_fd, int prog_array_fd, json_t *syscalls, struct pid_ip_pair *pairs, int count) {
    size_t index;
    json_t *entry;

    static uint32_t next_index = 0;
    for (int i = 0; i < count; i++) {
        uint32_t ip = pairs[i].ip;
        uint32_t pid = pairs[i].pid;

        json_array_foreach(syscalls, index, entry) {
            json_t *name = json_object_get(entry, "name");
            json_t *number = json_object_get(entry, "number");
            if (!json_is_string(name) || !json_is_integer(number)) continue;
    
            const char *syscall = json_string_value(name);
            int syscall_nr = json_integer_value(number);
    
            char pin_path[256];
            snprintf(pin_path, sizeof(pin_path), "%s%s%s_%u", PIN_BASE_PATH, PROG_PREFIX, syscall, ip);
            printf("[+] program path: %s\n", pin_path);
            int prog_fd = bpf_obj_get(pin_path);
            if (prog_fd < 0) {
                fprintf(stderr, "[-] Failed to get pinned prog: %s\n", pin_path);
                continue;
            }
    
            uint64_t key = ((uint64_t)pid << 32) | syscall_nr;
            uint32_t index_in_array = next_index++;
    
            if (bpf_map_update_elem(hash_fd, &key, &index_in_array, BPF_ANY) != 0)
                fprintf(stderr, "[-] Failed to map hash[%lu] = %u\n", key, index_in_array);
    
            if (bpf_map_update_elem(prog_array_fd, &index_in_array, &prog_fd, BPF_ANY) != 0)
                fprintf(stderr, "[-] Failed to map prog_array[%u] = fd %d\n", index_in_array, prog_fd);
            else
                printf("[+] Registered (%d, %d) -> index %u -> fd %d\n", pid, syscall_nr, index_in_array, prog_fd);

            close(prog_fd);
        }
    }
}

int pin_map(struct bpf_map *map, const char *path) {
    if (bpf_map__pin(map, path) != 0) {
        fprintf(stderr, "[-] Failed to pin map to %s\n", path);
        return -1;
    }
    printf("[+] Map pinned to %s\n", path);
    return 0;
}

static inline struct timespec ns_to_ts(uint64_t ns)
{
    struct timespec t = {
        .tv_sec  = ns / 1000000000ULL,
        .tv_nsec = ns % 1000000000ULL
    };
    return t;
}

static int handle_event(void *ctx, void *data, size_t size) {
    const struct syscall_event_t *evt = data;

    // Evoked: MONOTONIC ns → timespec
    struct timespec ev_ts = ns_to_ts(evt->ts_ns);

    // 사람이 읽을 수 있는 형식 유지
    fprintf(log_fp,
        "Evoked Time=%ld.%06ld, PID=%u syscall=%u\n",
        (long)ev_ts.tv_sec,  (long)(ev_ts.tv_nsec  / 1000),
        evt->pid, evt->syscall_nr);

    return 0;
}

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

int main() {
    compute_offset();

    struct dispatcher_bpf *skel = dispatcher_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "[-] Failed to load dispatcher BPF\n");
        return 1;
    }

    if (dispatcher_bpf__attach(skel)) {
        fprintf(stderr, "[-] Failed to attach dispatcher BPF\n");
        dispatcher_bpf__destroy(skel);
        return 1;
    }
    printf("[+] dispatcher BPF attached.\n");

    if (pin_map(skel->maps.counter, "/sys/fs/bpf/counter") !=0 ) {
        dispatcher_bpf__destroy(skel);
        return 1;
    }

    json_error_t error;
    json_t *root = json_load_file(SYSCALL_JSON, 0, &error);
    if (!root) {
        fprintf(stderr, "[-] Failed to parse syscall JSON: %s\n", error.text);
        return 1;
    }

    json_t *syscalls = json_object_get(root, "syscalls");
    if (!json_is_array(syscalls)) {
        fprintf(stderr, "[-] JSON format error\n");
        json_decref(root);
        return 1;
    }

    
    int hash_fd = bpf_map__fd(skel->maps.pid_syscall_to_index);
    int prog_fd = bpf_map__fd(skel->maps.prog_array_map);
    if (hash_fd < 0 || prog_fd < 0) {
        fprintf(stderr, "[-] Failed to get map fds\n");
        return 1;
    }
    
    struct pid_ip_pair pairs[MAX_PAIRS];
    int count = 0;
    create_pid_to_podip_map(pairs, &count);

    register_programs(hash_fd, prog_fd, syscalls, pairs, count);


    // 로그 파일
    char file[64] = "syscalls_all.log";
    log_fp = fopen(file, "w");
    if (!log_fp) {
        perror("fopen");
        goto cleanup;
    }
    setvbuf(log_fp, NULL, _IOFBF, 1<<20);

    // 링버퍼
    int rb_fd = bpf_map__fd(skel->maps.ringbuf_local);
    struct ring_buffer *rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }
    
    while (1) {
        int err = ring_buffer__poll(rb, RINGBUF_POLL_MS);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

cleanup:
    dispatcher_bpf__destroy(skel);
    return 0;
}