# Baselines: how to run

Execution runbook for the two production baselines, **Tetragon** and **Tracee**.
Both are driven by a single script, `exe_v1.sh`, in their own directory; this
file is the order of operations.

Both agents run as DaemonSets on the Kubernetes node `w-1`, alongside the
workload. Subcommands are split by where they run:

| runs on     | subcommands                       | needs             |
| ----------- | --------------------------------- | ----------------- |
| Master Node | `setup`, `verify`                 | `kubectl`, `helm` |
| Worker Node | `check`, `reset`, `start`, `stop` | `sudo`, `crictl`  |

`N` is the number of application containers and is the only argument. It
defaults to 30.

## Budget rule

Every system gets the same total: **3% of one CPU per application container**, so
`N` containers means a `3 x N`% collector budget, applied to the agent container
only -- not to sidecars, not to the DaemonSet as a whole. Buffers get `N` MB.

|   N | collector budget | k8s `cpu` limit | Tetragon `rb-size-total` | Tracee buffer target |
| --: | ---------------: | --------------: | -----------------------: | -------------------: |
|   1 |               3% |           `30m` |              `1048576` B |                 1 MB |
|   5 |              15% |          `150m` |              `5242880` B |                 5 MB |
|  10 |              30% |          `300m` |             `10485760` B |                10 MB |
|  15 |              45% |          `450m` |             `15728640` B |                15 MB |
|  30 |              90% |          `900m` |             `31457280` B |                30 MB |

Tetragon takes the total in bytes, so it lands exactly. Tracee allocates one
perf buffer **per online CPU** and sizes it in **pages per CPU**, which must be
a power of two, so it is rounded **up** to the next admissible size (never
down). Same rule as eAudit's `-r`.

```
pages = next_pow2( ceil(256 * N / vCPU) )      # 256 pages = 1 MB at 4 KB/page
```

`setup` prints the resolved value: `perf-buffer-size=P pages/CPU x C vCPU = T MB`.

## Ground rules

Four constraints shape both scripts. Changing any of them breaks comparability.

1. **Native file export.** Events terminate in a node-local file written by the
   agent itself. No `kubectl logs`, no `tetra getevents`, no export sidecar. The
   CRI log path splits lines at 16 KB and kubelet rotation (10 MB x 5 by
   default) drops silently.
2. **Node-local consumer.** `collect.py` runs on the same node as the agent, so
   the Kubernetes API server is never in the measurement path and its `recv_ns`
   shares a clock domain with the event timestamp.
3. **Equal budget.** As above.
4. **Workload-side denominator.** Drop rate is `1 - delivered / issued`, where
   `issued` comes from the workload's own eBPF counter (`read_counter`). The
   agent's internal counters are cross-checks only.

---

# Tetragon

## 1. Install

```bash
helm repo add cilium https://helm.cilium.io
helm install tetragon cilium/tetragon -n kube-system
helm upgrade  tetragon cilium/tetragon -n kube-system --reuse-values \
  --set export.mode=""
```

`export.mode=""` is the key that disables stdout export. `export.stdout.enabled`
looks plausible and is **silently ignored** by the chart. Confirm with
`helm show values cilium/tetragon | grep -A20 '^export:'`.

## 2. Apply the policy

```bash
kubectl apply -f tetragon/policy.yaml
```

A `TracingPolicyNamespaced` scoped by `podSelector: app=sys-gen`, hooking the
`raw_syscalls/sys_enter` tracepoint and reading the syscall number from argument
index 4.

## 3. Set the budget and roll out (Master Node)

```bash
cd tetragon
./exe_v1.sh setup 30
```

This removes the `export-stdout` sidecar (a relay that tails the export file
back to stdout -- it would consume budget for nothing), sets the CPU limit, and
patches `tetragon-config`:

| key                       | value                                   | why                                                                                                        |
| ------------------------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| `export-filename`         | `/var/run/cilium/tetragon/tetragon.log` | native file sink                                                                                           |
| `export-rate-limit`       | `-1`                                    | a rate limit would fabricate drops                                                                         |
| `export-allowlist`        | `PROCESS_TRACEPOINT` in `default`       | excludes the base sensor's node-wide `process_exec`/`process_exit`                                         |
| `field-filters`           | `process.pid, process.binary, args`     | minimizes per-event serialization                                                                          |
| `rb-size-total`           | `N` MB                                  | kernel ring buffer                                                                                         |
| `rb-queue-size`           | `1000000`                               | userspace queue -- this is where drops actually happen                                                     |
| `export-file-max-size-mb` | `102400`                                | the 10 MB default rotates several times a second under load and `tail -F` loses events across the rotation |

The ConfigMap patch runs **after** `helm upgrade`, not before. Helm 3's
three-way merge reverts any key the chart template also defines, so patching
first silently loses `export-allowlist` and the rest.

## 4. Verify (Worker Node)

```bash
./exe_v1.sh verify 30
```

Check the CPU limit is on the `tetragon` container, that `export-filename` and
`export-allowlist` survived, and that the pods are Ready. Do not proceed if
anything is missing.

## 5. Check the log (Worker Node)

```bash
./exe_v1.sh check 30
```

Prints the log file size, the event-type distribution (only `PROCESS_TRACEPOINT`
should appear) and the pod distribution (only `sys-gen`). Anything else means
`export-allowlist` did not take effect.

## 6. Collect

```bash
./exe_v1.sh reset 30           # truncate, do not delete
./exe_v1.sh start 30           # consumer in background -> out/syscalls_events.ndjson
```

`reset` truncates rather than deletes: removing the file leaves the agent
writing to an unlinked inode and the path never reappears.

```bash
# [(Master Node)] run the workload
./postmark.sh default sys-gen sys-gen
```

## 7. Stop and analyse (Worker Node)

```bash
DRAIN_STABLE_SEC=30 ./exe_v1.sh stop 30
sudo ./build/read_counter          # the denominator: syscalls the workload issued
```

`stop` waits for the log size to hold steady before killing the consumer. The
agent lags by seconds to tens of seconds under load; stopping immediately after
the workload truncates the backlog, understating `delivered` and inflating the
drop rate. `SKIP_DRAIN=1` skips the wait deliberately.

## 8. Next N

```bash
kubectl scale deploy/sys-gen -n default --replicas=20
./exe_v1.sh setup 20               # re-run from step 3 with the new N
```

---

# Tracee

## 1. Install

```bash
helm repo add aqua https://aquasecurity.github.io/helm-charts/
helm install tracee aqua/tracee -n tracee --create-namespace
```

## 2. Set the budget and roll out (Master Node)

```bash
cd tracee
./exe_v1.sh setup 30
```

`setup` applies `policy.yaml`, computes the perf buffer size, merges the config,
sets the CPU limit, and restarts the DaemonSet.

**The policy.** `scope: [container, comm=postmark]`, `rules: [{event: sys_enter}]`.
`scope` selects _what to watch_; `rules[].filters` constrains _event data_. A
target qualifier placed under `rules[].filters` is ignored and the policy runs
globally. `podName=` is **not** a valid scope option in v0.24.1 (it fails with
`invalid scope option`) -- `comm=postmark` selects exactly the process set the
workload's own counter measures, so numerator and denominator agree.

**The config merge.** `setup` reads the existing `tracee-config`, changes only
the keys it needs, and writes it back. It does not overwrite wholesale:
`tracee-operator` injects keys of its own and dropping them can prevent startup.
The original is saved to `out/tracee-config.orig.yaml`.

| key                              | value                                                        |
| -------------------------------- | ------------------------------------------------------------ |
| `output.json.files`              | `[/tmp/tracee/events.json]` -- stdout sinks removed          |
| `perf-buffer-size`               | computed (see budget table)                                  |
| `healthz`, `metrics`             | `true` -- the readiness probe and loss counters need `:3366` |
| `output.options.parse-arguments` | `false` -- lowers per-event cost, favors the baseline        |

`setup` reads the vCPU count from the **target node** via `kubectl`, not local
`nproc`: it runs on the master node, and if the two nodes differ in core count
the buffer total comes out wrong. Override the output path with
`TRACEE_OUT_DIR` if the chart mounts a different `hostPath` -- `verify` prints
the actual mount list.

## 3. Verify (Master Node)

```bash
./exe_v1.sh verify 30
```

Confirm the `hostPath` mounts include the output directory, the config took, the
policy scope is right, and no `tracee-operator` has reverted anything.

## 4. Check the log (Worker Node)

```bash
./exe_v1.sh check 30
```

Prints the log state, the `eventName` distribution (only `sys_enter`), the
`podName` distribution (only `sys-gen`), the metrics endpoint status, and one
raw event.

**Read that raw event.** Tracee's `timestamp` is either epoch-ns or
boot-relative depending on configuration, and `check` prints it next to the
current epoch and `/proc/uptime` so you can tell which. If it is boot-relative,
say so at step 6.

**Metrics.** Tracee does not use `hostNetwork`, so `localhost:3366` does not
reach it. `metrics_host()` finds the pod IP with `crictl` (the worker has no
`kubectl`). Override with `TRACEE_METRICS_HOST` if discovery fails.

## 5. Collect

```bash
./exe_v1.sh reset 30
./exe_v1.sh start 30
```

```bash
# [Master Node] run the workload
./postmark.sh default sys-gen sys-gen
```

## 6. Stop and analyse (Worker Node)

```bash
DRAIN_STABLE_SEC=30 ./exe_v1.sh stop 30
sudo ./build/read_counter
```

If step 4 showed boot-relative timestamps:

```bash
TRACEE_TS=relative DRAIN_STABLE_SEC=30 ./exe_v1.sh stop 30
```

Negative latencies in the output mean this was set wrong; `calculate.py` counts
them and warns.

---

# Results

`stop` prints the buffer and CPU settings, `delivered` vs. raw line counts,
bytes per event, the before/after delta of the agent's own counters, and the
summary from `calculate.py`.

Artifacts land in `out/`:

```
out/syscalls_events.ndjson          delivered events with recv_ns (large; truncated on each start)
out/metrics_{before,after}.txt      agent counter snapshots
out/collector.pid                   consumer pid
out/tracee-config.{orig,new}.yaml   Tracee only
```

Each line of `syscalls_events.ndjson` is `{"recv_ns": <ns>, "event": <original JSON>}`.
`collect.py` does not parse the event -- parsing must never become the
consumer's bottleneck -- so `calculate.py` does it offline.

Report **average throughput, drop rate, and average latency**:

```
drop rate  = 1 - delivered / issued          # issued from read_counter
throughput = delivered / recv_window
latency    = recv_ns - event_timestamp
```

`bytes / event` should be identical across runs of the same N. If it moves, the
configuration moved.

---

# FYI

**`verify` is not optional.** Both agents are managed by components that revert
configuration behind your back -- Helm's three-way merge for Tetragon,
`tracee-operator` for Tracee. A run whose `verify` was skipped is a run whose
settings are unknown.

**Where events are captured differs.** Tetragon and Tracee both hook
`raw_syscalls:sys_enter` and see no return values. eAudit probes entry and exit
and emits most records at exit; NoDrop records at `sys_exit`. The event
populations are not the same.

**Tetragon's drops are in userspace, not the kernel.** The kernel ring buffer
(`rb-size-total`) reports `lost = 0` throughout while the userspace queue
(`rb-queue-size`) discards the bulk of events. Enlarging `rb-size-total` does
nothing for the drop rate; the cost is roughly 46 us per event on the export
path.

**Tracee gets no less buffer than the rule demands.** The power-of-two page
rounding is always upward, which favors the baseline.

**Stopping the consumer.** `tail` is started under `sudo` and is root-owned, so
an unprivileged `pkill` will not kill it -- it survives and keeps writing into
the next run's file. `stop` kills the process group as root.

**Put the audit log on a different device from the workload's files.**
`postmark` is a filesystem benchmark; if its working directory and the audit
output share a block device, the disk rather than the CPU budget decides the
result. Same arrangement for every system.
