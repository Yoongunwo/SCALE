# SCALE-Risk-aware Distributed System Call Audit Framework for Cloud Native Environments

This repository provides **SCALE**, a risk-aware distributed system call event collection framework for cloud-native workloads running in Kubernetes. SCALE adopts the sidecar pattern, where a monitoring container is deployed alongside the application container. This design enables real-time collection of system calls from application containers without granting excessive privileges to the monitoring component.

# Overview

<div align="center">
    <img width="600" height="340" alt="Image" src="https://github.com/user-attachments/assets/ca47eb47-5101-4779-9a95-e71f53149253" />
</div>

In the user space, the components include the Init Manager, BPF Map Manager, BPF File Descriptor, and Monitoring Container. The Init Manager and BPF Map Manager identify required environmental information and distribute configurations, ensuring that each Monitoring Container can collect system call events effectively. Each Monitoring Container runs as a sidecar alongside its corresponding application container within the same network namespace. It creates probes for each system call that process event data within the kernel and collects the resulting outputs.

In the kernel space, SCALE consists of Container-Specific Probes, Invocation Map, and Syscall Dispatchers. The Syscall Dispatchers hooks into the system call path and, upon each system call, identifies the application container that issued the call and triggers the corresponding probe of its Monitoring container. Once activated, the probe extracts and preprocesses system call metadata before placing it into a shared buffer accessible to the collector.

# How to use

**SCALE** can be executed as follows:

1. Run `make` inside the `/SCALE/Control` directory
2. Launch the SCALE Manager by executing `/SCALE/build/main_controller`
3. On the Kubernetes master node, deploy `/SCALE/pod.yaml` to create a Pod containing both the application and monitoring containers

# Evaluation

The detailed evaluation methodology and results can be found in the paper (currently under review). The main evaluation involves a performance comparison with existing system call collection tools, Tetragon and Tracee, and the experimental results are shown below.

## Comparison with Existing Systems

To evaluate the practicality of SCALE, we compared it against Tracee and Tetragon, two widely used centralized monitoring tools in cloud-native environments. The experiments employed the postmark, where the number of containers running the benchmark was scaled, and the CPU resources of the monitoring containers were increased proportionally. As in previous experiments, each monitoring container in SCALE was allocated 3\% of a vCPU and a 1 MB ring buffer.

<div align="center">
  <img width="300" height="150" alt="Image" src="https://github.com/user-attachments/assets/a5204037-bc6e-4fe5-82a2-391caceaf383" />
  <br/>
  <em>Clust-wise collection rate.</em>
</div>

<div align="center">
  <img width="300" height="150" alt="Image" src="https://github.com/user-attachments/assets/f8e14093-52b6-46dd-bd78-3f72ca04201d" />
  <br/>
  <em>Data loss.</em>
</div>

<div align="center">
  <img width="300" height="150" alt="Image" src="https://github.com/user-attachments/assets/4e929ceb-b6c8-4ec9-9cfd-046e9b610b41" />
  <br/>
  <em>Kernel-to-User space latency.</em>
</div>

## End-to-End Latency: Invocation to Analysis

To demonstrate the effectiveness of differential resource allocation, we evaluated end-to-end latency from system call invocation through event collection to analysis under centralized, evenly distributed, and differential distributed configurations. We used a custom benchmark in which ten application containers each generated approximately 10K system calls per second. Total vCPU allocated to monitoring containers was fixed at 30\% across all configurations to ensure a fair comparison.

<div align="center">
  <img width="600" height="200" alt="Image" src="https://github.com/user-attachments/assets/d6bbf21f-6d8e-43fd-a13e-63db614c9e6d" />
  <br/>
  <em>End-to-end latency comparison across monitoring configurations: centralized (Cen), evenly distributed (Dis-Equal), and two differential distributed setups (Dis-Diff).</em>
</div>

## Evaluation using Real-World Scenario

In this evaluation, we conducted experiments in a real-world workload environment to validate the effectiveness of the proposed Network-Gated CPU Risk Score (NG-CRS) and the system built upon it. Specifically, we compared NG-CRS with three existing risk scoring baselines to assess how effectively each approach adapts to network-based attack scenarios. The baselines include: (1) CPU-only, with quantifies abnormal CPU usage based on deviations from an exponentially weighted moving average (EWMA); (2) Network-only, which measures network burstiness relative to a smoothed baseline; and (3) Non-Gated CPU–Network, which combines risk scores derived from CPU and network utilization through a weighted sum without explicitly modeling their dependency.

  <div align="center">
    <img width="500" height="125" alt="Image" src="https://github.com/user-attachments/assets/d973a4a7-cdb3-4f6d-88e3-21481469ee15" />
    <br/>
    <em>CPU-only baseline</em>
  </div>
  
  <div align="center">
    <img width="500" height="125" alt="Image" src="https://github.com/user-attachments/assets/5e320f37-9b75-44e8-8635-00a3853f3cf1" />
    <br/>
    <em>Network-only baseline</em>
  </div>
  
  <div align="center">
    <img width="500" height="125" alt="Image" src="https://github.com/user-attachments/assets/0e669a60-794b-4c9f-a984-6241aaf5b6e4" />
    <br/>
    <em>Non-gated CPU-Network baseline</em>
  </div>

  <div align="center">
    <img width="500" height="125" alt="Image" src="https://github.com/user-attachments/assets/27b06217-bcaf-410a-95ef-090ab12db9a2" />
    <br/>
    <em>Proposed Network-gated CPU risk score (NG-CRS)</em>
  </div>

## Evaluation using real attack scenarios

<div align="center">
  <img width="500" height="125" alt="Image" src="https://github.com/user-attachments/assets/69a9e270-f7c4-4619-9a23-0871c04f21b9" />
  <br/>
  <em>Risk score and system call collection latency accroding to NG-CRS using lateral movement attack scearnios on Online Boutique.</em>
</div>
