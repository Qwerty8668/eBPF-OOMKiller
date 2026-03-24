#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "clone_flags.h"

#define SIGKILL   9

#define MAX_PROCESSES 4194304
#define MAX_MEM_MB 1000

#define RD_MAX  10000000
#define TCP_MAX 1000
#define FD_MAX  100
#define WRT_MAX 100
#define TH_MAX  100
#define RND_MAX 100

struct sysinfo *memory_data;
__kernel_ulong_t memory;

/* We have to use __u32 everywhere, because operations are atomic only on 32 and 64 bit values. */
struct counters {
    __u32 rd_cnt;    // 0-10 000 000
    __u32 tcp_cnt;   // 0-1 000
    __u32 fd_cnt;    // 0-100
    __u32 wrt_cnt;   // 0-100
    __u32 th_cnt;    // 0-100
    __u32 rnd_cnt;   // 0-100
};

/* Counters for the tracked events. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESSES);
    __type(key, __u32);
    __type(value, struct counters);
}  monitoring SEC(".maps");

/* Returns true, if the process could be killed.*/
/* The 'oomp' in the name should be checked before, using other method. */
static bool check_to_kill(pid_t pid) {
    struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);
    if (val == NULL) return false;

    bool to_kill = false;
    to_kill |= (val->fd_cnt >= FD_MAX) | (val->tcp_cnt >= TCP_MAX);
    to_kill |= (val->rd_cnt >= RD_MAX) | (val->wrt_cnt >= WRT_MAX);
    to_kill |= (val->th_cnt >= TH_MAX) | (val->rnd_cnt >= RND_MAX);
    to_kill &= (memory >= MAX_MEM_MB);
    return to_kill;
}

/* Check if the process has 'oomp' in it's name. */
static bool check_oomp(pid_t pid) {
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    for (int i = 0; i < 16 - 4; i++) {
        if(comm[i] == 'o' && comm[i + 1] == 'o' && comm[i + 2] == 'm' && comm[i + 3] == 'p') {
            return true;
        }
    }
    return false;
}

static int __always_inline do_handle_read(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_oomp(pid)) {
        return 0;
    }

    if (check_to_kill(pid)) {
        bpf_send_signal(SIGKILL);
        return 0;
    }
    long ret = PT_REGS_RC(ctx);

    if (ret >= 0) {
        struct counters init_val = { .rd_cnt = 1 };
        struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);

        if (!val)
            bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
        else
            __sync_add_and_fetch(&val->rd_cnt, ret);
    }
    return 0;
}

/* Tracking reading from files. */
SEC("kretprobe/vfs_read")
int handle_read(struct pt_regs *ctx) {
    return do_handle_read(ctx);
}

SEC("kretprobe/vfs_readv")
int handle_readv(struct pt_regs *ctx) {
    return do_handle_read(ctx);
}

/* Tracing sending TCP packets. */
SEC("tracepoint/syscalls/sys_enter_sendto")
int handle_tcp(struct trace_event_raw_sys_enter* ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (!check_oomp(pid)) {
        return 0;
    }

    if (check_to_kill(pid)) {
        bpf_send_signal(SIGKILL);
        return 0;
    }

    long unsigned int args[6];
    BPF_CORE_READ_INTO(&args, ctx, args);
    const void *buf = (void *)args[1];
    struct iphdr *ip = (struct iphdr *)buf;

    __u8 protocol;
    bpf_probe_read_user(&protocol, sizeof(protocol), &ip->protocol);

    if (protocol == IPPROTO_TCP) {
        bpf_printk("PID %d sent a TCP packet.", pid);
        struct counters init_val = { .tcp_cnt = 1 };
        struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);

        if (!val)
            bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
        else
            __sync_add_and_fetch(&val->tcp_cnt, 1);
    }

    return 0;
}

/* Tracking used file descriptors. */
SEC("kretprobe/alloc_fd")
int handle_fd(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (!check_oomp(pid)) {
        return 0;
    }

    if (check_to_kill(pid)) {
        bpf_send_signal(SIGKILL);
        return 0;
    }

    long ret = PT_REGS_RC(ctx);

    // If no error occured.
    if (ret >= 0) {
        bpf_printk("PID %d created a file descriptor.", pid);
        struct counters init_val = { .fd_cnt = 1 };
        struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);

        if (!val)
            bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
        else
            __sync_add_and_fetch(&val->fd_cnt, 1);
    }

    return 0;
}

static int __always_inline do_handle_write(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_oomp(pid)) {
        return 0;
    }

    if (check_to_kill(pid)) {
        bpf_send_signal(SIGKILL);
        return 0;
    }
    long ret = PT_REGS_RC(ctx);

    if (ret >= 0) {
        bpf_printk("PID %d written to the file.", pid);
        struct counters init_val = { .wrt_cnt = 1 };
        struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);

        if (!val)
            bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
        else
            __sync_add_and_fetch(&val->wrt_cnt, 1);
    }
    return 0;
}

/* Tracking writing to files. */
SEC("kretprobe/vfs_write")
int handle_write(struct pt_regs *ctx) {
    return do_handle_write(ctx);
}

SEC("kretprobe/vfs_writev")
int handle_writev(struct pt_regs *ctx) {
    return do_handle_write(ctx);
}

/* Tracking created threads. */
SEC("tp/syscalls/sys_enter_clone3")
int handle_threads(struct trace_event_raw_sys_enter *ctx) {

    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (!check_oomp(pid)) {
        return 0;
    }

    if (check_to_kill(pid)) {
        bpf_send_signal(SIGKILL);
        return 0;
    }

    long unsigned int args[6];
    BPF_CORE_READ_INTO(&args, ctx, args);
    struct clone_args *cl_args = (void *)args[0];

    __u64 flags;
    bpf_probe_read_user(&flags, sizeof(flags), &cl_args->flags);

    /* Clone3 flags for thread creation (pthread_create). */
    if (flags == (CLONE_VM | CLONE_FS | CLONE_FILES | 
        CLONE_SYSVSEM | CLONE_SIGHAND | CLONE_THREAD |
         CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID)) {

        bpf_printk("PID: %d created a thread.", pid);
        struct counters init_val = { .th_cnt = 1 };
        struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);

        if (!val)
            bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
        else
            __sync_add_and_fetch(&val->th_cnt, 1);
    }
    return 0;
}

/* Tracking rand() function from libc. */
SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:rand")
int handle_rand(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (!check_oomp(pid)) {
        return 0;
    }

    if (check_to_kill(pid)) {
        bpf_send_signal(SIGKILL);
        return 0;
    }

    bpf_printk("PID %d used a rand function.", pid);

    struct counters init_val = { .rnd_cnt = 1 };
    struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);

    if (!val)
        bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
    else
        __sync_add_and_fetch(&val->rnd_cnt, 1);

    return 0;
}

/* On exit, counters are deleted. */
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exit* ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("PID %d exited", pid);
    bpf_map_delete_elem(&monitoring, &pid);
    return 0;
}

/* Get the pointer, where the data about the memory will be saved. */
SEC("kprobe/si_meminfo")
int check_memory_pointer(struct pt_regs *ctx) {
    memory_data = (struct sysinfo *)PT_REGS_PARM1(ctx);
    return 0;
}

/* Get the actual data. */
SEC("kretprobe/si_meminfo")
int check_memory(struct pt_regs *ctx) {
    __kernel_ulong_t freeram = BPF_CORE_READ(memory_data, freeram);
    __kernel_ulong_t totalram = BPF_CORE_READ(memory_data, totalram);
    __kernel_ulong_t bufferram = BPF_CORE_READ(memory_data, bufferram);

    __u32 mem_unit = BPF_CORE_READ(memory_data, mem_unit);

    freeram *= mem_unit;
    totalram *= mem_unit;
    bufferram *= mem_unit;
    freeram /= 1000 * 1000;  /* MB */
    totalram /= 1000 * 1000; /* MB */
    bufferram /= 1000 * 1000;/* MB */

    memory = totalram - freeram - bufferram;
    bpf_printk("Totalram: %lu MB, Freeram: %lu MB, Bufferram: %lu MB, Used Memory: %lu MB",totalram, freeram, bufferram, memory);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";