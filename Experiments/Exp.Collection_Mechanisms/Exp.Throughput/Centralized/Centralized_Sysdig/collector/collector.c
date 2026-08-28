#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "collector.skel.h"
#include <unistd.h> // for sleep


static int exiting = 0;

static void sig_handler(int sig) {
    exiting = 1;
}

int pin_map(struct bpf_map *map, const char *path) {
    if (bpf_map__pin(map, path) != 0) {
        fprintf(stderr, "[-] Failed to pin map to %s\n", path);
        return -1;
    }
    printf("[+] Map pinned to %s\n", path);
    return 0;
}

int main() {
    struct collector_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    __u8 one = 1;
    __u32 pid = 0;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // load the BPF program
    skel = collector_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    if (pin_map(skel->maps.counter, "/sys/fs/bpf/counter") !=0 ) {
        collector_bpf__destroy(skel);
        return 1;
    }

    // attach the BPF program
    err = collector_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    // find the sys_generator PID
    FILE *fp = popen("pidof sys_generator", "r");
    if (!fp) {
        fprintf(stderr, "Failed to run pidof\n");
        goto cleanup;
    }
    
    // register the target PID in the BPF map
    while (fscanf(fp, "%u", &pid) == 1) {
        err = bpf_map_update_elem(
            bpf_map__fd(skel->maps.target_pids),
            &pid, &one, BPF_ANY
        );
        if (err) {
            fprintf(stderr, "Failed to insert PID %u into map: %s\n", pid, strerror(errno));
        } else {
            printf("Registered PID: %u\n", pid);
        }
    }
    
    pclose(fp);

    printf("Tracing syscalls for PID %u...\n", pid);
    while (!exiting){
        sleep(1); 
    }

    printf("Exiting...\n");
    goto cleanup;

cleanup:
    if (skel) collector_bpf__destroy(skel);
    return 0;
}