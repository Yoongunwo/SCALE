#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/sysinfo.h>

#define MAX_PAIRS 100

struct pid_ip_pair {
    uint32_t ip;
    uint32_t pid;
    char pod_name[64];
};

// jq로 문자열 필드 추출
int extract_string_using_jq(const char *cmd, const char *jq_expr, char *output, size_t len) {
    char full_cmd[512];
    snprintf(full_cmd, sizeof(full_cmd), "%s | jq -r '%s'", cmd, jq_expr);

    FILE *fp = popen(full_cmd, "r");
    if (!fp) return -1;

    if (fgets(output, len, fp)) {
        output[strcspn(output, "\n")] = '\0';  // 줄바꿈 제거
        pclose(fp);
        return 0;
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

        char cmd[256], sandbox_id[128], pod_ip_str[64], pod_name[64] = "unknown";

        // sandboxID 추출
        snprintf(cmd, sizeof(cmd), "crictl inspect %s", container_id);
        if (extract_string_using_jq(cmd, ".info.sandboxID", sandbox_id, sizeof(sandbox_id)) != 0)
            continue;

        // pod IP 추출
        snprintf(cmd, sizeof(cmd), "crictl inspectp %s", sandbox_id);
        if (extract_string_using_jq(cmd, ".status.network.ip", pod_ip_str, sizeof(pod_ip_str)) != 0)
            continue;

        struct in_addr addr;
        if (!inet_aton(pod_ip_str, &addr)) continue;
        uint32_t ip_int = ntohl(addr.s_addr);

        // pod 이름 추출
        snprintf(cmd, sizeof(cmd), "crictl inspectp %s", sandbox_id);
        extract_string_using_jq(cmd, ".status.metadata.name", pod_name, sizeof(pod_name));

        // shim PID 추출
        snprintf(cmd, sizeof(cmd),
                 "ps -ef | grep containerd-shim | grep %s | grep -v grep | awk '{print $2}'",
                 sandbox_id);
        FILE *shim_ps = popen(cmd, "r");
        if (!shim_ps || !fgets(cmd, sizeof(cmd), shim_ps)) {
            if (shim_ps) pclose(shim_ps);
            continue;
        }
        pclose(shim_ps);

        int shim_pid = atoi(cmd);
        if (shim_pid <= 0) continue;

        // sys_generator PID 추출
        snprintf(cmd, sizeof(cmd),
                 "pstree -ap %d | grep 'sys_generator' | grep -o ',[0-9]*' | tr -d ','", shim_pid);
        FILE *pstree = popen(cmd, "r");
        if (!pstree) continue;

        char pid_line[64];
        if (fgets(pid_line, sizeof(pid_line), pstree)) {
            int pid = atoi(pid_line);
            if (pid > 0) {
                out_pairs[pair_index].ip = ip_int;
                out_pairs[pair_index].pid = pid;
                strncpy(out_pairs[pair_index].pod_name, pod_name, sizeof(out_pairs[pair_index].pod_name));
                pair_index++;
            }
        }
        pclose(pstree);
    }

    pclose(ps);
    *out_count = pair_index;
    return 0;
}

void dump_counter_map(int map_fd, struct pid_ip_pair *pairs, int pair_count) {
    __u32 key = 0, next_key;
    int n_cpus = get_nprocs();

    printf("\n[+] Dumping counter map:\n");

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        __u64 values[n_cpus];
        memset(values, 0, sizeof(values));

        if (bpf_map_lookup_elem(map_fd, &next_key, values) != 0) {
            key = next_key;
            continue;
        }

        __u64 sum = 0;
        for (int i = 0; i < n_cpus; i++) sum += values[i];

        char ip_buf[INET_ADDRSTRLEN] = "unknown";
        char pod_buf[64] = "unknown";
        for (int i = 0; i < pair_count; i++) {
            if (pairs[i].pid == next_key) {
                struct in_addr addr = { .s_addr = htonl(pairs[i].ip) };
                inet_ntop(AF_INET, &addr, ip_buf, sizeof(ip_buf));
                strncpy(pod_buf, pairs[i].pod_name, sizeof(pod_buf));
                break;
            }
        }

        printf("  [PID %5u] IP: %-15s POD: %-20s → Events: %llu\n",
               next_key, ip_buf, pod_buf, sum);

        key = next_key;
    }
}

int main() {
    int map_fd = bpf_obj_get("/sys/fs/bpf/counter");
    if (map_fd < 0) {
        perror("[-] Failed to open /sys/fs/bpf/counter");
        return 1;
    }

    struct pid_ip_pair pairs[MAX_PAIRS];
    int count = 0;
    if (create_pid_to_podip_map(pairs, &count) != 0) {
        fprintf(stderr, "[-] Failed to create PID↔IP map\n");
        return 1;
    }

    dump_counter_map(map_fd, pairs, count);

    return 0;
}
