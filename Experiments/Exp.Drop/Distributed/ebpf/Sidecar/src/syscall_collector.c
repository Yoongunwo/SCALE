// syscall_collector.c (fixed)
#include "syscall_collector.skel.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <stdint.h>

#undef RINGBUF_POLL_MS
#define RINGBUF_POLL_MS 1

struct syscall_event_t {
    __u32 pid;
    __u32 syscall_nr;
    __u64 ts_ns;  // MONOTONIC ns
};

static FILE *log_fp = NULL;

static inline struct timespec ns_to_ts(uint64_t ns) {
    struct timespec t = { .tv_sec = ns / 1000000000ULL, .tv_nsec = ns % 1000000000ULL };
    return t;
}

static void die(const char* msg){ perror(msg); exit(1); }

static int handle_event(void *ctx, void *data, size_t size) {
    const struct syscall_event_t *evt = data;
    struct timespec ev_ts = ns_to_ts(evt->ts_ns);
    // 사람이 보기 좋은 형식 (초.마이크로초)
    fprintf(log_fp, "Evoked Time=%ld.%06ld, PID=%u syscall=%u\n",
            (long)ev_ts.tv_sec, (long)(ev_ts.tv_nsec/1000),
            evt->pid, evt->syscall_nr);
    return 0;
}

#define PIN_BASE "/sys/fs/bpf"

static void sanitize_label(char *s) {
    for (char *p = s; *p; ++p) {
        if (*p == '.' || *p == ' ' || *p == ':') *p = '_';
    }
}

static void pin_stats_map_label(struct syscall_collector_bpf *skel, const char *label){
    char safe[128];
    snprintf(safe, sizeof(safe), "%s", label);
    sanitize_label(safe);

    char path_stats[256];
    snprintf(path_stats, sizeof(path_stats), PIN_BASE "/syscall_stats_%s", safe);

    if (bpf_map__pin(skel->maps.stats, path_stats) != 0) {
        fprintf(stderr, "WARN: failed to pin %s (errno=%d: %s)\n",
                path_stats, errno, strerror(errno));
    } else {
        printf("[+] pinned: %s\n", path_stats);
    }
}

/* IP 얻기 */
static int get_ipv4_for_iface(const char *ifname, char *buf, size_t buflen) {
    struct ifaddrs *ifaddr = NULL, *ifa = NULL;
    if (getifaddrs(&ifaddr) == -1) return -1;
    int ok = -1;
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (!ifa->ifa_name || strcmp(ifa->ifa_name, ifname) != 0) continue;
        unsigned flags = ifa->ifa_flags;
        if (!(flags & IFF_UP)) continue;
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

static int read_first_line(const char *p, char *buf, size_t sz){
    FILE *f=fopen(p,"r"); if(!f) return -1;
    if(!fgets(buf,(int)sz,f)){ fclose(f); return -1; }
    fclose(f);
    size_t n=strlen(buf); while(n && (buf[n-1]=='\n'||buf[n-1]=='\r')) buf[--n]=0;
    return 0;
}

static int collect_tids_for_tgid(int tgid, int *tids, int max_n){
    int n=0; char dirp[128]; snprintf(dirp,sizeof(dirp),"/proc/%d/task",tgid);
    DIR *d=opendir(dirp); if(!d) return 0;
    struct dirent *e;
    while((e=readdir(d))){
        if(e->d_type!=DT_DIR) continue;
        char *end; long tid=strtol(e->d_name,&end,10);
        if(*end!='\0'||tid<=0) continue; if(n<max_n) tids[n++]=(int)tid;
    }
    closedir(d); return n;
}

static int pick_one_tgid_by_comm(const char *comm){
    DIR *dp = opendir("/proc"); if(!dp) die("/proc");
    int picked=0;
    struct dirent *de;
    while((de=readdir(dp))){
        if(de->d_type!=DT_DIR) continue;
        char *e; long pid=strtol(de->d_name,&e,10);
        if(*e!='\0'||pid<=0) continue;
        char p[256], name[128];
        snprintf(p,sizeof(p),"/proc/%ld/comm",pid);
        if(read_first_line(p,name,sizeof(name))==0 && strcmp(name,comm)==0){
            picked=(int)pid; break;
        }
    }
    closedir(dp);
    return picked;
}

static int read_cgroup_path_for_proc(int pid, char *buf, size_t bufsz){
    char path[128]; snprintf(path,sizeof(path),"/proc/%d/cgroup",pid);
    FILE *f=fopen(path,"r"); if(!f) return -1;
    char line[512], chosen[512]={0};
    while(fgets(line,sizeof(line),f)){
        char *slash=strchr(line,'/'); if(!slash) continue;
        size_t len=strlen(slash);
        while(len && (slash[len-1]=='\n'||slash[len-1]=='\r')) slash[--len]=0;
        if(!strncmp(line,"0::",3)){ strncpy(chosen,slash,sizeof(chosen)-1); break; }
        strncpy(chosen,slash,sizeof(chosen)-1);
    }
    fclose(f);
    if(chosen[0]==0) return -1;
    strncpy(buf,chosen,bufsz-1); buf[bufsz-1]=0; return 0;
}

/* FIX: __32 → __u32, 반환형/지역변수 타입 수정 */
static __u32 find_host_tgid_by_cgroup_and_comm(const char *host_proc_root,
                                               const char *cgroup_path,
                                               const char *comm_target){
    DIR *dp=opendir(host_proc_root); if(!dp) die(host_proc_root);

    __u32 found = 0;
    struct dirent *de;

    while((de=readdir(dp))){
        if(de->d_type!=DT_DIR) continue;
        char *e; long pid=strtol(de->d_name,&e,10);
        if(*e!='\0'||pid<=0) continue;

        char cg[512]; snprintf(cg,sizeof(cg),"%s/%ld/cgroup",host_proc_root,pid);
        FILE *cf=fopen(cg,"r"); if(!cf) continue;
        int match=0; char ln[512];
        while(fgets(ln,sizeof(ln),cf)){
            char *slash=strchr(ln,'/'); if(!slash) continue;
            size_t len=strlen(slash);
            while(len && (slash[len-1]=='\n'||slash[len-1]=='\r')) slash[--len]=0;
            if(strcmp(slash,cgroup_path)==0){ match=1; break; }
        }
        fclose(cf);
        if(!match) continue;

        char cp[512], name[128];
        snprintf(cp,sizeof(cp),"%s/%ld/comm",host_proc_root,pid);
        if(read_first_line(cp,name,sizeof(name))==0 && strcmp(name,comm_target)==0){
            found=(__u32)pid;
            break;
        }
    }
    closedir(dp);
    return found;
}

int main(void) {
    const char *HOST_PROC = getenv("HOST_PROC"); if(!HOST_PROC||!*HOST_PROC) HOST_PROC="/host/proc";
    const char *FILTER_MODE = getenv("FILTER_MODE"); /* "set_event_pid" or "event_filter" */
    int use_set_event_pid = (FILTER_MODE && strcmp(FILTER_MODE,"set_event_pid")==0) ? 1 : 0;
    (void)use_set_event_pid; // 현재 사용 안 함

    if(access(HOST_PROC,R_OK)!=0){
        fprintf(stderr,"[ERR] %s not accessible. Mount host /proc there.\n", HOST_PROC);
        return 1;
    }

    /* 1) 같은 Pod에서 postmark 하나 고르기 */
    int c_tgid = pick_one_tgid_by_comm("postmark");
    if(c_tgid<=0){ fprintf(stderr,"[ERR] no postmark in this container\n"); return 1; }

    /* 2) 컨테이너 TIDs (정보용) */
    int c_tids[512]; int n_ctids = collect_tids_for_tgid(c_tgid, c_tids, 512);
    fprintf(stderr,"[INFO] container TGID=%d, TIDs=%d (ex: %d)\n", c_tgid, n_ctids, n_ctids?c_tids[0]:-1);

    /* 3) host TGID 매핑 */
    char cg[512];
    if(read_cgroup_path_for_proc(c_tgid, cg, sizeof(cg))!=0){
        fprintf(stderr,"[ERR] cannot read cgroup path for %d\n", c_tgid); return 1;
    }
    __u32 target_pid = find_host_tgid_by_cgroup_and_comm(HOST_PROC, cg, "postmark");
    if (target_pid == 0) {
        fprintf(stderr,"[ERR] cannot map to host TGID\n");
        return 1;
    }

    /* eBPF 로드/어태치 */
    struct syscall_collector_bpf *skel = syscall_collector_bpf__open_and_load();
    if (!skel) die("open_and_load");
    if (syscall_collector_bpf__attach(skel)) {
        syscall_collector_bpf__destroy(skel);
        die("attach");
    }

    /* PID 필터 설정 */
    __u8 one = 1;
    if (bpf_map_update_elem(bpf_map__fd(skel->maps.pid_filter_map),
                            &target_pid, &one, BPF_ANY) != 0) {
        syscall_collector_bpf__destroy(skel);
        die("pid_filter_map");
    }

    /* IP 라벨 핀 (실패 시 진행 계속) */
    char label[INET_ADDRSTRLEN] = {0};
    if (get_self_ipv4(label, sizeof(label)) == 0) {
        pin_stats_map_label(skel, label);
    }

    /* 로그 파일 */
    char file[64];
    snprintf(file, sizeof(file), "syscalls_%u.log", target_pid);
    log_fp = fopen(file, "w");
    if (!log_fp) { perror("fopen log"); goto cleanup; }
    setvbuf(log_fp, NULL, _IOFBF, 1<<20);

    /* 링버퍼 */
    int rb_fd = bpf_map__fd(skel->maps.ringbuf_local);
    struct ring_buffer *rb = ring_buffer__new(rb_fd, handle_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "ring_buffer__new failed\n"); goto cleanup; }

    printf("[+] Tracing syscalls for PID %u...\n", target_pid);

    while (1) {
        int err = ring_buffer__poll(rb, RINGBUF_POLL_MS);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

cleanup:
    if (log_fp) { fflush(log_fp); fclose(log_fp); }
    // 올바른 해제: 생성한 rb를 넘겨서 free
    // (여기서 rb가 scope 밖이면 위로 끌어올리세요)
    // ring_buffer__free(rb);
    syscall_collector_bpf__destroy(skel);
    return 0;
}
