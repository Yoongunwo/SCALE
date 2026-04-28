#!/usr/bin/env python3
import time
import subprocess
from pathlib import Path

import riskScheduler

POD_NAME = "nginx"
INTERVAL = 1.0  # seconds

scheduler = riskScheduler.RiskScheduler()

def sh(cmd):
    return subprocess.check_output(cmd, shell=True, text=True).strip()

def get_container_id(pod):
    cid = sh(f"crictl ps --name {pod} -q")
    if not cid:
        raise RuntimeError("container not found")
    return cid

def get_sandbox_id(cid):
    sid = sh(f"crictl inspect {cid} | jq -r '.info.sandboxID'")
    if not sid or sid == "null":
        raise RuntimeError("sandboxID not found")
    return sid

def get_pod_ip(sandbox):
    ip = sh(f"crictl inspectp {sandbox} | jq -r '.status.network.ip'")
    if not ip or ip == "null":
        raise RuntimeError("Pod IP not found")
    return ip


def get_cali_veth(pod_ip):
    veth = sh(
        f"ip route get {pod_ip} | awk '{{for(i=1;i<=NF;i++) if($i==\"dev\") print $(i+1)}}'"
    )
    if not veth:
        raise RuntimeError("cali veth not found")
    return veth


def get_cpu_stat_path(cid):
    base = Path("/sys/fs/cgroup/kubepods.slice")
    for p in base.rglob(f"cri-containerd-{cid}.scope"):
        return p / "cpu.stat"
    raise RuntimeError("cpu.stat not found")


def read_cpu_usec(path):
    with open(path) as f:
        for line in f:
            if line.startswith("usage_usec"):
                return int(line.split()[1])
    raise RuntimeError("usage_usec not found")


def read_net_bytes(veth):
    rx = int(Path(f"/sys/class/net/{veth}/statistics/rx_bytes").read_text())
    tx = int(Path(f"/sys/class/net/{veth}/statistics/tx_bytes").read_text())
    return rx, tx

if __name__ == "__main__":
    print("[*] Resolving pod...")
    cid = get_container_id(POD_NAME)
    sandbox = get_sandbox_id(cid)
    pod_ip = get_pod_ip(sandbox)
    veth = get_cali_veth(pod_ip)
    cpu_stat = get_cpu_stat_path(cid)

    print(f"[+] Pod       : {POD_NAME}")
    print(f"[+] Container : {cid[:12]}")
    print(f"[+] Pod IP    : {pod_ip}")
    print(f"[+] Veth      : {veth}")
    print(f"[+] CPU stat  : {cpu_stat}")
    print("-" * 60)

    prev_cpu = read_cpu_usec(cpu_stat)
    prev_rx, prev_tx = read_net_bytes(veth)
    prev_t = time.time()

    while True:
        time.sleep(INTERVAL)

        now_t = time.time()
        now_cpu = read_cpu_usec(cpu_stat)
        now_rx, now_tx = read_net_bytes(veth)

        dt = now_t - prev_t

        cpu_core = (now_cpu - prev_cpu) / dt / 1_000_000
        rx_bps = (now_rx - prev_rx) / dt
        tx_bps = (now_tx - prev_tx) / dt
        net_bps = rx_bps + tx_bps   # bytes/sec

        print(
            f"{POD_NAME:<20} "
            f"CPU: {cpu_core:6.2f} core  "
            f"RX: {rx_bps:8.2f} KB/s  "
            f"TX: {tx_bps:8.2f} KB/s"
        )

        R, changed, active = scheduler.update(
            pod=POD_NAME,
            cpu_core=cpu_core,
            net_bps=net_bps
        )

        
        if R is not None:
            print(
                f"R={R:.2f} "
                f"{'ACTIVE' if active else 'INACTIVE'}"
                f"{' (changed)' if changed else ''}"
            )

        prev_cpu, prev_rx, prev_tx, prev_t = now_cpu, now_rx, now_tx, now_t
