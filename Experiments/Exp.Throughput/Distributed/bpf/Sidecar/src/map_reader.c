#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/sysinfo.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>

#define MAP_PATH "/sys/fs/bpf/syscall_stats"

static __u32 get_pid_from_rootNS(void) {
    __u32 cpid = 0;

    // 1) 컨테이너 PID 찾기
    FILE *pf = popen("ps -C sys_generator -o pid=", "r");
    if (!pf) { perror("popen(ps)"); return 0; }

    char line[64];
    while (fgets(line, sizeof(line), pf)) {
        char *p = line;
        while (*p==' ' || *p=='\t') p++;
        long v = strtol(p, NULL, 10);
        if (v > 0) { cpid = (__u32)v; break; }
    }
    pclose(pf);

    if (!cpid) {
        fprintf(stderr, "sys_generator PID not found\n");
        return 0;
    }

    // 2) 컨테이너 PID의 cgroup 경로
    char cgroup_path[256];
    snprintf(cgroup_path, sizeof(cgroup_path), "/proc/%u/cgroup", cpid);
    FILE *cgf = fopen(cgroup_path, "r");
    if (!cgf) { perror("open cgroup"); return 0; }

    char cgroup_line[256], target_cgroup[256] = {0};
    while (fgets(cgroup_line, sizeof(cgroup_line), cgf)) {
        char *pos = strchr(cgroup_line, '/');
        if (pos) {
            strncpy(target_cgroup, pos, sizeof(target_cgroup)-1);
            size_t len = strlen(target_cgroup);
            if (len && target_cgroup[len-1]=='\n') target_cgroup[len-1] = '\0';
            break;
        }
    }
    fclose(cgf);
    if (target_cgroup[0] == '\0') {
        fprintf(stderr, "failed to parse container cgroup for PID %u\n", cpid);
        return 0;
    }

    // 3) host /proc에서 같은 cgroup 가진 PID 찾기
    FILE *fp = popen("ls -1 /host/proc | grep -E '^[0-9]+$' | sort -n", "r");
    if (!fp) { perror("popen(ls /host/proc)"); return 0; }

    char pid_buf[32];
    int host_pid = 0;               // ← 바깥 변수 하나만 사용
    while (fgets(pid_buf, sizeof(pid_buf), fp)) {
        int cand = atoi(pid_buf);   // ← 섀도잉 대신 다른 이름
        if (cand <= 0) continue;

        char hcg_path[256];
        snprintf(hcg_path, sizeof(hcg_path), "/host/proc/%d/cgroup", cand);
        FILE *hcgf = fopen(hcg_path, "r");
        if (!hcgf) continue;

        char line2[256];
        int match = 0;
        while (fgets(line2, sizeof(line2), hcgf)) {
            if (strstr(line2, target_cgroup)) { match = 1; break; }
        }
        fclose(hcgf);

        if (match) {
            host_pid = cand;        // ← 바깥 변수에 대입
            printf("Container PID %u -> Host PID %d\n", cpid, host_pid);
            break;
        }
    }
    pclose(fp);

    return (host_pid > 0) ? ( __u32)host_pid : 0;
}

int main(void) {
    __u32 target_pid = 0;
    target_pid = get_pid_from_rootNS();

    if (target_pid == 0) {
        fprintf(stderr, "process 'sys_generator' not found\n");
        return 1;
    }
    char pin_path[256];
    snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/syscall_stats_%u", target_pid);

    int map_fd = bpf_obj_get(pin_path);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    int n_cpus = get_nprocs_conf();
    __u32 key_drop = 1;
    __u64 *percpu_vals = calloc(n_cpus, sizeof(__u64));
    if (!percpu_vals) { perror("calloc"); close(map_fd); return 1; }

    if (bpf_map_lookup_elem(map_fd, &key_drop, percpu_vals) != 0) {
        perror("lookup key 1 (drop)");
        free(percpu_vals);
        close(map_fd);
        return 1;
    }

    unsigned long long sum_drop = 0;
    for (int i = 0; i < n_cpus; i++) sum_drop += percpu_vals[i];

    printf("DROP: %llu\n", sum_drop);

    free(percpu_vals);
    close(map_fd);
    return 0;
}
