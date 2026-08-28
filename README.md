<!-- # SCALE-Risk-aware Distributed System Call Audit Framework for Cloud Native Environments -->

# SCALE: Differentiated Resource Allocation for Timely System Call Auditing in Containerized Environments

This repository provides **SCALE**, a risk-aware distributed system call event collection framework for containerized workloads. SCALE adopts the sidecar pattern, where a monitoring container is deployed alongside the application container. This design enables real-time collection of system calls from application containers without granting excessive privileges to the monitoring component.

# Overview

<div align="center">
    <img width="600" height="340" alt="Image" src="./figures/scale_overview.png" />
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
