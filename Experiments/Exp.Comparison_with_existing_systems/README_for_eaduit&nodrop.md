# Baselines: how to run

Execution runbook for the two artifact-based baselines, **eAudit** and **NoDrop**.
Per-system details live in [eaudit/README.md](eaudit/README.md) and
[NoDrop/README.md](NoDrop/README.md); this file is the order of operations.

- **eAudit** runs as a privileged pod on the Kubernetes node `w-1` (Ubuntu 22.04).
- **NoDrop** runs on bare metal (Ubuntu 18.04, kernel 4.15) because its kernel
  module targets that release.

## Budget rule

Every system gets the same total: **3% of one CPU per application container**, so
`N` containers means a `3 x N`% collector budget.

|   N | collector budget | k8s `cpu` limit | cgroup quota (period 10 ms) | eAudit `-r` |
| --: | ---------------: | --------------: | --------------------------: | ----------: |
|   1 |               3% |           `30m` |                         300 |           1 |
|   2 |               6% |           `60m` |                         600 |           2 |
|   5 |              15% |          `150m` |                        1500 |           8 |
|  10 |              30% |          `300m` |                        3000 |          16 |
|  15 |              45% |          `450m` |                        4500 |          16 |
|  30 |              90% |          `900m` |                        9000 |          32 |

`-r` is the BPF ring buffer size in MB. It only accepts powers of two, so it is
rounded **up** to the next admissible size (never down). Same for Tracee's per-CPU
page count. Cap is 64 MB.

---

# eAudit

## 0. Build Docker Image

Clone the [eAudit](https://github.com/seclab-stonybrook/eaudit) repository, place the
Dockerfile in the root directory of `eaudit`, and build the image from it.

## 1. Set the budget and deploy

Edit both `requests.cpu` and `limits.cpu` in [eaudit/pod.yaml](eaudit/pod.yaml) to
`30 x N` millicores, then deploy.

```bash
kubectl apply -f eAudit/pod.yaml
kubectl get pod exp -o wide            # wait for Running on w-1
```

Resources are immutable on a running pod. To change N, recreate it:

```bash
kubectl replace --force -f eaudit/pod.yaml
```

The pod mounts the host directory `/home/yoon/eaudit` at `/tmp/log`, so anything
written there is already on the node -- no `kubectl cp` needed.

## 2. Find the target PID

`-P` takes thread group IDs and does **not** follow children, so pass the PID of the
process that actually issues the system calls.

```bash
pgrep -x postmark
```

## 3. Start collection

```bash
kubectl exec -it exp -c proxy -- bash

rm -f /tmp/log/metrics1.csv
/usr/local/bin/eaudit-entrypoint -P <PID> -M /tmp/log/metrics1.csv -s -r <MB> -v3 \
    > /tmp/log/eaudit.out 2>&1 &
```

BCC compiles `eauditk.c` on startup, which takes tens of seconds. Collection has not
begun until that finishes. The metrics CSV is created immediately afterwards, so its
existence is the readiness signal:

```bash
for i in $(seq 180); do
  [ -e /tmp/log/metrics1.csv ] && { echo "ready after ${i}s"; break; }
  pgrep -f eauditd.py > /dev/null || { echo "died early:"; cat /tmp/log/eaudit.out; break; }
  sleep 1
done
```

Cross-check that the probes attached:

```bash
bpftool prog show | grep -c tracepoint     # ~160 once loaded
```

## 4. Run the workload, then stop

```bash
# ... run the benchmark ...

pkill -INT -f eauditd.py       # SIGINT to python, not to the entrypoint wrapper
sleep 5
```

Send **SIGINT only**. `Ctrl-Z` or `kill -9` leaves the metrics CSV unflushed and the
ring buffer undrained, which looks exactly like "collected nothing".

## 5. Results

```bash
wc -l /tmp/log/metrics1.csv
tail -30 /tmp/log/eaudit.out
```

`eaudit.out` ends with the system call summary (`-s`) and, if the ring buffer
overflowed, `*** Dropped data *** Ring buffer output failed N times`.

`metrics1.csv` columns: `user_ts_ns, syscall_nr, syscall_tag, pid_exact, tid_exact,
record_size`. One line per delivered event, `user_ts_ns` being the userspace receive
time.

```bash
# throughput over the collection window
awk -F, 'NR>1 {n++; if(!s||$1<s)s=$1; if($1>e)e=$1}
         END {printf "%d events, %.3f s, %.0f events/s\n", n, (e-s)/1e9, n*1e9/(e-s)}' \
    /tmp/log/metrics1.csv
```

---

# NoDrop

Runs in **external collector mode**: the module is loaded with
`enable_monitor_injection=0`, so application threads are not hijacked to flush their
own buffers. A separate collector drains every per-thread buffer through `ioctl`,
which is what makes NoDrop comparable to the other baselines -- with injection
enabled there is no collector to give a budget to.

## 1. Build

```bash
cd ~/NoDrop && mkdir -p build && cd build
cmake ..
make ctrl        # also builds nodrop-dump
make kmodule
cp ../scripts/ctrl/analyze_stream.sh ./scripts/ctrl/
```

## 2. Collector cgroup (`3 x N`%)

```bash
sudo cgcreate -g cpu,cpuset:/nodrop_collector
echo 1 | sudo tee /sys/fs/cgroup/cpuset/nodrop_collector/cpuset.cpus
echo 0 | sudo tee /sys/fs/cgroup/cpuset/nodrop_collector/cpuset.mems

echo 10000        | sudo tee /sys/fs/cgroup/cpu/nodrop_collector/cpu.cfs_period_us
echo $((300 * N)) | sudo tee /sys/fs/cgroup/cpu/nodrop_collector/cpu.cfs_quota_us
```

A 10 ms period is used rather than the usual 100 ms. Both express the same
percentage, but with a 100 ms period the collector spends its whole quota in the
first few milliseconds and is then frozen for the rest of the period, which makes a
30 ms fetch interval impossible to honour.

`cpuset.cpus=1` caps the collector at one CPU no matter what the quota says. Once
`3 x N > 100`, widen it (e.g. `1,3`) or the drop rate reflects the cpuset rather than
the budget.

## 3. Workload cgroup (separate cores)

```bash
sudo cgcreate -g cpuset:/nodrop_workload
echo "2-$(($(nproc)-1))" | sudo tee /sys/fs/cgroup/cpuset/nodrop_workload/cpuset.cpus
echo 0 | sudo tee /sys/fs/cgroup/cpuset/nodrop_workload/cpuset.mems
```

## 4. Load the module

```bash
sudo rmmod nodrop 2>/dev/null || true
sudo insmod ./nodrop.ko target_comm=postmark enable_monitor_injection=0

./scripts/ctrl/ctrl bufsize 1024     # KB per thread
./scripts/ctrl/ctrl bufsize          # verify
```

`target_comm` matches a task's command name (`task->comm`, 15 characters max) and is
re-checked on every event. Set the buffer size **before** starting the workload:
`nod_buffer_size` is read when a thread is first traced, so threads that already
exist keep the buffer they were given.

## 5. Collect

```bash
./scripts/ctrl/ctrl start
./scripts/ctrl/ctrl record normal
./scripts/ctrl/ctrl clear-stat
./scripts/ctrl/ctrl clean
./scripts/ctrl/ctrl stat > /tmp/stat_before.txt

# collector: one process, 30 ms interval
sudo cgexec -g cpu,cpuset:nodrop_collector \
    ./scripts/ctrl/ctrl stream 0.03 /tmp/nodrop &

# workload, on the other cores
sudo cgexec -g cpuset:nodrop_workload postmark ...
```

One `ioctl` drains every per-thread buffer in a single pass, so a second collector
buys nothing and only contends for the same lock.

## 6. Stop and analyse

```bash
sudo pkill -INT -f "ctrl stream"
sleep 1
./scripts/ctrl/ctrl stat > /tmp/stat_after.txt

./scripts/ctrl/analyze_stream.sh /tmp/nodrop/stream.idx /tmp/nodrop/stream.raw \
    /tmp/stat_before.txt /tmp/stat_after.txt
```

Output: `kernel_syscalls_called`, `collected_events`, `missed_events`,
`drop_rate_percent`, `throughput_events_per_sec`, `latency_ms_p50/p95/p99`,
`fetch_batches`.

Check whether the budget was actually the limiting factor:

```bash
cat /sys/fs/cgroup/cpu/nodrop_collector/cpu.stat    # nr_throttled, throttled_time
```

---

# FYI

**Put the audit log on a different device from the workload's files.** `postmark` is a filesystem benchmark; if its working directory and the audit output share a block device, the disk rather than the CPU budget decides the result. Apply the same arrangement to every system.

**System call coverage differs.** eAudit attaches one tracepoint per system call and covers 82 of them; `lseek`, `fsync`, `getdents64` and similar are invisible to it. NoDrop records every system call (151 fully decoded, the rest as an ID). The event counts are therefore not measuring the same population.

**Where events are captured differs.** eAudit probes both entry and exit and emits most records at exit, where the return value is known. NoDrop records at `sys_exit`. Tracee and Tetragon hook `raw_syscalls:sys_enter` and see no return values at all.

**Neither `-P` nor `target_comm` follows children.** eAudit compiles a fixed list of thread group IDs into the eBPF program; NoDrop matches a command name, and a child drops out of scope the moment it `execve`s something else.
