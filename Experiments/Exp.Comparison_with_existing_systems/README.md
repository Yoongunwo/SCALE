# Baseline Collectors: Tetragon and Tracee

Measurement harnesses for the two production syscall collectors we compare
SCALE against. Each directory holds one driver script, `exe_v1.sh`, plus the
policy it applies and the two Python helpers it pipes through.

Both harnesses are built to the same rules so the numbers are comparable. Read
this section before changing anything; most of the script exists to satisfy one
of these four constraints.

| | |
|---|---|
| **Native file export** | Events terminate in a node-local file written by the agent itself. No `kubectl logs`, no `tetra getevents`, no export sidecar. The CRI log path splits lines at 16 KB and kubelet rotation (10 MB × 5 by default) drops silently. |
| **Node-local consumer** | The consumer runs on the same node as the agent. The Kubernetes API server is never in the measurement path, and `recv_ns` shares a clock domain with the event timestamp, so `latency = recv_ns - timestamp` is meaningful. |
| **Equal CPU budget** | `30m × N`, applied to the agent container only — not to sidecars, not to the DaemonSet as a whole. |
| **Workload-side denominator** | Drop rate is `1 - delivered / issued`, where `issued` comes from the workload's own eBPF counter. The tool's internal counters are cross-checks, never the denominator. |

---

## Layout

```
tetragon/                          tracee/
  exe_v1.sh    driver                exe_v1.sh    driver
  policy.yaml  TracingPolicyNamespaced  policy.yaml  Policy (tracee.aquasec.com)
  collect.py   stamps recv_ns         collect.py   stamps recv_ns
  calculate.py throughput + latency   calculate.py throughput + latency
  setup.sh     command crib sheet     setup.sh     command crib sheet
  out/         artifacts              out/         artifacts
```

`collect.py` wraps each raw JSON line without parsing it —
`{"recv_ns": <ns>, "event": <original>}` — because parsing must never become
the consumer's bottleneck. `calculate.py` does the parsing afterwards, offline.

---

## Subcommands

The two scripts mirror each other. **Where you run them matters**: `setup` and
`verify` need `kubectl` (and `helm`, for Tetragon) and run on the control
plane; everything else runs on the worker node where the agent and the workload
actually live.

```bash
# [control plane]
./exe_v1.sh setup  30      # apply policy, set CPU budget and buffers, roll out
./exe_v1.sh verify 30      # confirm the settings actually took effect

# [worker node]
./exe_v1.sh check  30      # log file state, event-type and pod distribution
./exe_v1.sh reset  30      # truncate the log before a run
./exe_v1.sh start  30      # start the collector in the background
#   ... run the workload, record how many syscalls it issued ...
./exe_v1.sh stop   30      # drain, stop, and summarize
```

`N` is the number of application containers and drives both the CPU budget and
the buffer size. It defaults to 30.

`verify` must pass before you trust a run. Both agents are managed by
components that can silently revert configuration — Helm's three-way merge for
Tetragon, `tracee-operator` for Tracee — and `verify` is what catches that.

---

## Tetragon

Applies `TracingPolicyNamespaced` scoped to `podSelector: app=sys-gen`, hooking
the `raw_syscalls/sys_enter` tracepoint and extracting the syscall number from
argument index 4.

Install first, then let `exe_v1.sh setup` take over:

```bash
helm install tetragon cilium/tetragon -n kube-system
helm upgrade  tetragon cilium/tetragon -n kube-system --reuse-values \
  --set export.mode=""
kubectl apply -f policy.yaml
```

`export.mode=""` is the correct key. `export.stdout.enabled` looks plausible
and is silently ignored by the chart — check with
`helm show values cilium/tetragon | grep -A20 '^export:'` if in doubt.

`setup` then patches the `tetragon-config` ConfigMap. Ordering is load-bearing:
the patch must come **after** `helm upgrade`, because Helm's three-way merge
reverts any key the chart template also defines.

| Key | Value | Why |
|---|---|---|
| `export-filename` | `/var/run/cilium/tetragon/tetragon.log` | Native file sink |
| `export-rate-limit` | `-1` | Unlimited; a rate limit would fabricate drops |
| `export-allowlist` | `PROCESS_TRACEPOINT` in the target namespace | Excludes the base sensor's node-wide `process_exec`/`process_exit` |
| `field-filters` | `process.pid, process.binary, args` | Minimizes per-event serialization cost |
| `rb-size-total` | `N MB` | Kernel ring buffer |
| `rb-queue-size` | `1000000` | Userspace queue — where the drops actually happen |
| `export-file-max-size-mb` | `102400` | The 10 MB default rotates several times per second under load and `tail -F` loses events across the rotation |

`setup` also removes the `export-stdout` sidecar. It is only a relay that tails
the export file back to stdout, and it would consume budget for nothing.

Metrics come from `localhost:2112` — Tetragon runs with `hostNetwork`.

---

## Tracee

Applies a `Policy` scoped with `scope: [container, comm=postmark]` and a single
`rules: [{event: sys_enter}]`.

The scope/filter distinction matters. `scope` selects *what to watch*;
`rules[].filters` constrains *event data*. A target qualifier placed under
`rules[].filters` is ignored and the policy runs globally. Note also that
`podName=` is **not** a valid scope option in this version (v0.24.1) — it fails
with `invalid scope option`. `comm=postmark` selects exactly the process set
that the workload's own eBPF counter measures, so the numerator and denominator
of the drop rate refer to the same processes.

### perf buffer sizing

Tracee allocates one perf buffer **per online CPU**, and the size is given in
**pages per CPU**, which must be a power of two. There is no way to hit an
exact total of N MB. `calc_pages()` therefore computes the smallest `2^k` whose
total meets or exceeds N MB:

```
pages = next_pow2( ceil(256 · N / vCPU) )      # 256 pages = 1 MB at 4 KB/page
```

Tracee thus receives no *less* buffer than the rule demands, which favors the
baseline. `setup` reads the vCPU count from the **target node** via `kubectl`,
not from local `nproc` — it runs on the control plane, and if the two nodes have
different core counts, using the local value gets the total wrong.

### config merge

`setup` reads the existing `tracee-config`, merges only the keys it needs, and
writes it back. It does not overwrite wholesale: `tracee-operator` injects keys
of its own, and dropping them can prevent the agent from starting.

| Key | Value |
|---|---|
| `output.json.files` | `[/tmp/tracee/events.json]` — file sink, stdout sinks removed |
| `perf-buffer-size` | computed above |
| `healthz`, `metrics` | `true` — the readiness probe and loss counters need `:3366` |
| `output.options.parse-arguments` | `false` — reduces per-event cost, favors the baseline |

Override the output directory with `TRACEE_OUT_DIR` if the chart mounts a
different `hostPath`; `verify` prints the actual mount list.

### metrics endpoint

Tracee does **not** use `hostNetwork`, so `localhost:3366` does not reach it.
`metrics_host()` finds the pod IP with `crictl` (the worker has no `kubectl`).
Override with `TRACEE_METRICS_HOST` if discovery fails.

### timestamp domain

Tracee's `timestamp` may be epoch-ns or boot-relative depending on
configuration. `check` prints one raw event next to the current epoch and
`/proc/uptime` so you can tell which. If it is boot-relative, tell
`calculate.py`:

```bash
TRACEE_TS=relative ./exe_v1.sh stop 30
```

Negative latencies in the output are the symptom of getting this wrong;
`calculate.py` reports the negative count and warns.

---

## Output

`stop` waits for the pipeline to drain before stopping — the agent lags by
seconds to tens of seconds under load, and stopping immediately after the
workload truncates the backlog, understating `delivered` and inflating the drop
rate. The wait ends when the log size holds steady:

```bash
DRAIN_STABLE_SEC=30 DRAIN_MAX_SEC=300 ./exe_v1.sh stop 30
SKIP_DRAIN=1 ./exe_v1.sh stop 30        # skip it deliberately
```

`stop` then prints the buffer and CPU settings, delivered vs. raw line counts,
bytes per event (a constant across runs — if it changes, the configuration
changed), the before/after delta of the agent's own counters, and finally the
throughput and latency summary from `calculate.py`.

Artifacts land in `out/`:

```
out/syscalls_events.ndjson    raw events with recv_ns   (large; truncated on each start)
out/metrics_{before,after}.txt  agent counter snapshots
out/collector.pid             consumer pid
out/tracee-config.{orig,new}.yaml   Tracee only: config backup and applied version
```

Report **average throughput, drop rate, and average latency**. The percentile
lines `calculate.py` prints are diagnostics.

---

## Pitfalls worth knowing

**Shell.** Under `set -e`, `[[ cond ]] && var=x` aborts the script when the
condition is false — use `if`/`fi`. And `A && B || C` runs `C` whenever `B`
exits non-zero, producing false error messages; both scripts use `if`/`else`
instead.

**`sudo` and redirection.** `sudo wc -l < FILE` fails because the *shell*
performs the redirect, not `sudo`. Use `sudo wc -l FILE | awk '{print $1}'`.

**Truncate, don't delete.** `reset` truncates the log. Deleting it leaves the
agent writing to an unlinked inode, and the path never reappears.

**Stopping the consumer.** `tail` is started under `sudo` and is root-owned, so
an unprivileged `pkill` will not kill it. It survives and keeps writing into the
next run's file. `stop` kills the process group as root.

**Verify what actually landed.** After `setup`, `check` shows the event-type and
pod distribution in the log. Anything other than the target event or the target
pods means a filter did not take effect — for Tetragon usually
`export-allowlist`, for Tracee usually a scope qualifier misplaced under
`rules[].filters`.
