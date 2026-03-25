# eBPF OOM Killer

> **University of Warsaw (MIMUW)** | Operating Systems (ZSO) 2025/2026 - Assignment 1

A custom Out of Memory (OOM) Killer implemented using BPF and `libbpf`. This project extends OS memory protection by monitoring system resource usage in kernel space and aggressively terminating specific misbehaving processes before the system becomes unresponsive. 

## Features & Kill Policies

The BPF program enforces memory and resource limits based on a strict set of policies. The OOM Killer logic operates entirely in kernel space.

**Global Triggers:**
* **Activation:** The killer is only active when at least **1 GB of RAM** is being used.
* **Targeting:** Only processes with `"oomp"` in their name are targeted.

**Resource Limits (Kill Conditions):**
If a targeted process exceeds *any* of the following thresholds, it gets killed:

| Monitored Resource / Activity | Kill Threshold |
| :--- | :--- |
| **File Descriptors** | 100 or more FDs opened |
| **File Writes** | 100 or more write operations (e.g., `write`, `pwrite64`) |
| **Data Read** | 10 MB or more read (e.g., `read`, `readv`) |
| **Threads** | 100 or more threads spawned |
| **`rand()` function** | 100 or more calls |
| **TCP Packets** | 1000 or more TCP packets sent |

## Architecture Details

* **Kernel Space (`*.bpf.c`):** Implements the core monitoring and killing logic using eBPF hooks (kprobes/tracepoints). 
* **User Space (`*.user.c`):** A lightweight loader built with `libbpf` that attaches the BPF program and periodically triggers `si_meminfo` (e.g., once a second) to ensure memory stats are up-to-date.
* **Data Structures:** Uses `BPF_MAP_TYPE_HASH` to maintain state and track resource usage per process.
* **Memory Probing:** Utilizes `kprobe/si_meminfo` and `kretprobe/si_meminfo` for system-wide memory checks.

## Prerequisites

To build and run this project, you need a Linux environment (Kernel 6.18.5 recommended) with the following tools installed (you can install it using `make` or `make deps`):
* `clang` & `llvm`
* `libbpf-dev`
* `bpftool` (Required to generate `vmlinux.h`)
* `make`

*Note: The `Makefile` handles the generation of `vmlinux.h` using `bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h` and installs any strictly required apt dependencies.*

## Build & Run

1. Clone the repository and navigate to the directory:
   ```bash
   git clone https://github.com/Qwerty8668/eBPF-OOMKiller/
   cd eBPF-OOMKiller
2. Compile the project (this will generate the ./oomkiller binary):
   ```bash
   make
3. Run the userspace loader with root privileges:
   ```bash
   sudo ./oomkiller
