// main_controller.c
#include "dispatcher.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int is_digits(const char *s) {
    if (!s || !*s) return 0;
    for (const char *p=s; *p; ++p) if (!isdigit((unsigned char)*p)) return 0;
    return 1;
}

static int comm_is_postmark(pid_t pid) {
    char path[64], buf[256] = {0};
    // 우선 comm 체크
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(buf, sizeof(buf), f)) {
            // 개행 제거
            buf[strcspn(buf, "\r\n")] = 0;
            fclose(f);
            return strcmp(buf, "postmark") == 0;
        }
        fclose(f);
    }
    // cmdline fallback (exec 경로 포함)
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    f = fopen(path, "r");
    if (!f) return 0;
    size_t n = fread(buf, 1, sizeof(buf)-1, f);
    fclose(f);
    if (n == 0) return 0;
    // cmdline은 NUL로 구분됨 → 전체 버퍼에 "postmark" 포함 여부만 확인
    return strstr(buf, "postmark") != NULL;
}

static int populate_targets_map(int map_fd) {
    DIR *d = opendir("/proc");
    if (!d) { perror("opendir(/proc)"); return -1; }

    int added = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!is_digits(de->d_name)) continue;
        pid_t pid = (pid_t)atoi(de->d_name);
        if (pid <= 1) continue;
        if (!comm_is_postmark(pid)) continue;

        uint16_t one = 1;
        if (bpf_map_update_elem(map_fd, &pid, &one, BPF_ANY) == 0) {
            printf("[+] target add: pid=%d\n", pid);
            added++;
        } else {
            fprintf(stderr, "[-] target add failed: pid=%d (errno=%d)\n", pid, errno);
        }
    }
    closedir(d);
    printf("[*] total postmark pids added: %d\n", added);
    return added;
}

static int pin_map(struct bpf_map *map, const char *path) {
    if (bpf_map__pin(map, path) != 0) {
        fprintf(stderr, "[-] Failed to pin %s\n", path);
        return -1;
    }
    printf("[+] pinned: %s\n", path);
    return 0;
}

int main(void) {
    struct dispatcher_bpf *skel = dispatcher_bpf__open_and_load();
    if (!skel) { fprintf(stderr, "load fail\n"); return 1; }
    if (dispatcher_bpf__attach(skel)) {
        fprintf(stderr, "attach fail\n");
        dispatcher_bpf__destroy(skel);
        return 1;
    }
    printf("[+] bpf attached\n");

    // (선택) 맵 핀
    pin_map(skel->maps.targets, "/sys/fs/bpf/targets");
    pin_map(skel->maps.counter,  "/sys/fs/bpf/counter");

    int targets_fd = bpf_map__fd(skel->maps.targets);
    if (targets_fd < 0) { fprintf(stderr, "map fd fail\n"); return 1; }

    // /proc에서 postmark 찾기 → {pid:1}로 등록
    populate_targets_map(targets_fd);

    printf("[*] press 'q' + ENTER to quit\n");
    int c;
    while ((c = getchar()) != EOF) {
        if (c == 'q' || c == 'Q') break;
    }

    dispatcher_bpf__destroy(skel);
    return 0;
}
