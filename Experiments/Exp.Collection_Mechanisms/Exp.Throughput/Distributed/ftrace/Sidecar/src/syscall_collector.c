#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdint.h>

static FILE *log_fp = NULL;
static char instance_dir[256];  // ftrace instance name (for cleanup)

static void write_to_file(const char *path, const char *value) {
    FILE *f = fopen(path, "w");
    if (!f) {
        perror(path);
        exit(1);
    }
    fputs(value, f);
    fclose(f);
}

static void setup_ftrace_instance(const char *instance, const char *pid_str) {
    snprintf(instance_dir, sizeof(instance_dir), "%s", instance);

    char base[512];
    snprintf(base, sizeof(base), "/sys/kernel/debug/tracing/instances/%s", instance);
    mkdir(base, 0755);

    char path[1024];

    // Use function tracer
    snprintf(path, sizeof(path), "%s/current_tracer", base);
    write_to_file(path, "function");

    // Filter for syscall functions only
    snprintf(path, sizeof(path), "%s/set_ftrace_filter", base);
    write_to_file(path, "sys_*\n__x64_sys_*\n__do_sys_*\ndo_sys_*\n__se_sys_*\nSyS_*");

    // Target PID (host PID)
    snprintf(path, sizeof(path), "%s/set_ftrace_pid", base);
    write_to_file(path, pid_str);

    // Clear trace buffer
    snprintf(path, sizeof(path), "%s/trace", base);
    write_to_file(path, "");
}

static void cleanup_ftrace_instance(void) {
    if (strlen(instance_dir) == 0) return;

    char base[512], path[1024];
    snprintf(base, sizeof(base), "/sys/kernel/debug/tracing/instances/%s", instance_dir);

    // reset filters and pid
    snprintf(path, sizeof(path), "%s/set_ftrace_filter", base);
    write_to_file(path, "");

    snprintf(path, sizeof(path), "%s/set_ftrace_pid", base);
    write_to_file(path, "");

    // stop tracer just in case
    snprintf(path, sizeof(path), "%s/current_tracer", base);
    write_to_file(path, "nop");

    // clear trace buffer
    snprintf(path, sizeof(path), "%s/trace", base);
    write_to_file(path, "");

    // remove instance
    snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/instances/%s", instance_dir);
    if (rmdir(path) != 0) {
        perror("rmdir failed");
    } else {
        printf("[*] Successfully removed ftrace instance: %s\n", instance_dir);
    }
    instance_dir[0] = '\0';
}

static int handle_event(const char *data, size_t size) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME_COARSE, &ts);
    // log: "sec.usec : <ftrace line>"
    fprintf(log_fp, "%ld.%06ld : %.*s",
            ts.tv_sec, ts.tv_nsec / 1000, (int)size, data);
    return 0;
}

static void start_trace_pipe(const char *instance) {
    char path[512];
    snprintf(path, sizeof(path), "/sys/kernel/debug/tracing/instances/%s/trace_pipe", instance);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("fopen trace_pipe");
        exit(1);
    }

    char buf[4096];
    while (fgets(buf, sizeof(buf), fp)) {
        if (strstr(buf, "sys_") != NULL) {
            handle_event(buf, strlen(buf));
        }
    }
    fclose(fp);
}

static void die(const char* msg){ perror(msg); exit(1); }

static int read_first_line(const char *p, char *buf, size_t sz){
    FILE *f=fopen(p,"r"); if(!f) return -1;
    if(!fgets(buf,(int)sz,f)){ fclose(f); return -1; }
    fclose(f);
    size_t n=strlen(buf); while(n && (buf[n-1]=='\n'||buf[n-1]=='\r')) buf[--n]=0;
    return 0;
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

/* extract one cgroup path string (from the slash to the end) */
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

static int find_host_tgid_by_cgroup_and_comm(const char *host_proc_root,
                                             const char *cgroup_path,
                                             const char *comm_target){
    DIR *dp=opendir(host_proc_root); if(!dp) die(host_proc_root);
    int found=0; struct dirent *de;
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
            found=(int)pid; break;
        }
    }
    closedir(dp); return found;
}

static int collect_host_tids(int host_tgid, const char *host_proc_root, int *host_tids, int max_n){
    int n=0; char dirp[256]; snprintf(dirp,sizeof(dirp),"%s/%d/task",host_proc_root,host_tgid);
    DIR *d=opendir(dirp); if(!d) return 0;
    struct dirent *e; while((e=readdir(d))){
        if(e->d_type!=DT_DIR) continue;
        char *end; long tid=strtol(e->d_name,&end,10);
        if(*end!='\0'||tid<=0) continue; if(n<max_n) host_tids[n++]=(int)tid;
    }
    closedir(d); return n;
}

int main(void) {
    const char *HOST_PROC = getenv("HOST_PROC"); if(!HOST_PROC||!*HOST_PROC) HOST_PROC="/host/proc";
    const char *FILTER_MODE = getenv("FILTER_MODE"); /* "set_event_pid" or "event_filter" */
    int use_set_event_pid = (FILTER_MODE && strcmp(FILTER_MODE,"set_event_pid")==0) ? 1 : 0;

    if(access(HOST_PROC,R_OK)!=0){
        fprintf(stderr,"[ERR] %s not accessible. Mount host /proc there.\n", HOST_PROC);
        return 1;
    }

    /* 1) pick one sys_generator from the same Pod */
    int c_tgid = pick_one_tgid_by_comm("sys_generator");
    if(c_tgid<=0){ fprintf(stderr,"[ERR] no sys_generator in this container\n"); return 1; }

    /* 2) container TIDs */
    int c_tids[512]; int n_ctids = collect_tids_for_tgid(c_tgid, c_tids, 512);
    fprintf(stderr,"[INFO] container TGID=%d, TIDs=%d (ex: %d)\n", c_tgid, n_ctids, n_ctids?c_tids[0]:-1);

    /* 3) host TGID/TIDs (used to check the mapping and to name the log file) */
    char cg[512];
    if(read_cgroup_path_for_proc(c_tgid, cg, sizeof(cg))!=0){
        fprintf(stderr,"[ERR] cannot read cgroup path for %d\n", c_tgid); return 1;
    }
    int host_tgid = find_host_tgid_by_cgroup_and_comm(HOST_PROC, cg, "sys_generator");
    if(host_tgid<=0){ fprintf(stderr,"[ERR] cannot map to host TGID\n"); return 1; }
    int h_tids[512]; int n_htids = collect_host_tids(host_tgid, HOST_PROC, h_tids, 512);
    fprintf(stderr,"[INFO] mapped host TGID=%d, host TIDs=%d (ex: %d)\n",
            host_tgid, n_htids, n_htids?h_tids[0]:-1);

    // generate the instance name and the log file name automatically
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%u", host_tgid);

    char instance[64];
    snprintf(instance, sizeof(instance), "sc-%u", host_tgid);

    char file[64];
    snprintf(file, sizeof(file), "syscalls_%s.log", pid_str);

    log_fp = fopen(file, "w");
    if (!log_fp) {
        perror("fopen log");
        return 1;
    }
    setvbuf(log_fp, NULL, _IOLBF, 0); // line-buffered

    atexit(cleanup_ftrace_instance);

    // configure the ftrace instance
    setup_ftrace_instance(instance, pid_str);

    // read trace_pipe (endlessly)
    while (1) {
        start_trace_pipe(instance);
        // trace_pipe normally never reaches EOF.
        // Even on an error or a temporary break, we reattach.
    }

    // unreachable, kept for form
    fclose(log_fp);
    log_fp = NULL;
    cleanup_ftrace_instance();
    return 0;
}
