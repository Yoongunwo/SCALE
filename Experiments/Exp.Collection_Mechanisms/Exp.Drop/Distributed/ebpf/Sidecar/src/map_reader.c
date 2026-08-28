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

#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>

#define MAP_PATH "/sys/fs/bpf/syscall_stats"

static void sanitize_label(char *s) {
    // 파일명 안전화를 위해 점/공백 등은 밑줄로 변환
    for (char *p = s; *p; ++p) {
        if (*p == '.' || *p == ' ' || *p == ':' ) *p = '_';
        // 필요하면 더 추가
    }
}

static int get_ipv4_for_iface(const char *ifname, char *buf, size_t buflen) {
    struct ifaddrs *ifaddr = NULL, *ifa = NULL;
    if (getifaddrs(&ifaddr) == -1) return -1;
    int ok = -1;

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (!ifa->ifa_name || strcmp(ifa->ifa_name, ifname) != 0) continue;

        unsigned flags = ifa->ifa_flags;
        if (!(flags & IFF_UP)) continue;      // RUNNING까지 요구하지 않음
        if (flags & IFF_LOOPBACK) continue;

        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, buflen)) { ok = 0; break; }
    }
    freeifaddrs(ifaddr);
    return ok;
}

static int get_any_ipv4(char *buf, size_t buflen) {
    struct ifaddrs *ifaddr = NULL, *ifa = NULL;
    if (getifaddrs(&ifaddr) == -1) return -1;
    int ok = -1;

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        unsigned flags = ifa->ifa_flags;
        if (!(flags & IFF_UP)) continue;
        if (flags & IFF_LOOPBACK) continue;

        struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, buflen)) { ok = 0; break; }
    }
    freeifaddrs(ifaddr);
    return ok;
}

static int get_self_ipv4(char *buf, size_t buflen) {
    if (get_ipv4_for_iface("eth0", buf, buflen) == 0) return 0;
    return get_any_ipv4(buf, buflen);
}

int main(void) {
    char ip_label[INET_ADDRSTRLEN] = {0};
    if (get_self_ipv4(ip_label, sizeof(ip_label)) != 0) {
        printf("[-] Failed to get self IP, using PID label\n");
        return 1;
    }
    sanitize_label(ip_label);
    
    char pin_path[256];
    // snprintf(pin_path, sizeof(pin_path), "/sys/fs/bpf/syscall_stats_%u", target_pid);
    snprintf(pin_path, sizeof(pin_path), MAP_PATH "_%s", ip_label);

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
