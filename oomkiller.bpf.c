#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define SIGKILL   9

#define MAX_PROCESSES 4194304
#define MAX_MEM 1000 /* MB */
#define APROX_EBPF_SIZE 800 /* We don't want to include the oom killer in the mem usage*/

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
    __u32 to_kill;
};

/* Counters for the tracked events. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESSES);
    __type(key, __u32);
    __type(value, struct counters);
}  monitoring SEC(".maps");


/* Pids for the processes that have 'oomp' in their name. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESSES);
    __type(key, __u32);
    __type(value, __u8); // 1 if it contains oomp in the process name.
}  oomp SEC(".maps");

/* Ring buffer for kernel -> userspace communication. */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} ring_buffer SEC(".maps");

/* Returns true, if the process could be killed.*/
/* The 'oomp' in the name should be checked before, using other method. */
static bool check_to_kill(pid_t pid) {
    struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);
    if (val == NULL) return false;

    if (memory >= MAX_MEM && val->to_kill == 1) {
        return true;
    }

    return false;
}

/* We transfer the name of the process to the userspace for analysis. */
static void send_name_to_userspace(pid_t pid) {
        struct ringbuf_data *rb_data = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct ringbuf_data), 0);
        if(!rb_data) {
            bpf_printk("Failed to reserve the ringbuffer.");
            return;
        }

        rb_data->pid = pid;

        struct task_struct *task = (void *)bpf_get_current_task();

        char comm[16];

        BPF_CORE_READ_STR_INTO(&rb_data->name, task, comm);

        bpf_ringbuf_submit(rb_data, BPF_ANY);
}

/* Check if the process has 'oomp' in it's name. */
bool check_oomp(pid_t pid) {
    __u8 *val = bpf_map_lookup_elem(&oomp, &pid);
    if (val == NULL) {
        send_name_to_userspace(pid);
        /* We will skip one event - we must wait for the verdict from the userspace. */
        return false;
    }
    if (bpf_map_lookup_elem(&monitoring, &pid) == NULL) {
        struct counters init_val = {0};
        bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
    }
    return (*val == 1);
}

/* This process might be killed. */
void set_to_kill(pid_t pid) {
    struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);
    if (val == NULL) return;
    if (!val->to_kill) __sync_add_and_fetch(&val->to_kill, 1);
}

/*TODO - distinguish thread/proces creation */

/* If the new process was created, give it's name to the userspace */
/* If the new thread was created, trace it. */
// SEC("tp/sched/sched_process_fork")
// bool handle_process_or_thread_creation(struct trace_event_raw_sched_process_fork* ctx) {
//     pid_t pid = bpf_get_current_pid_tgid() >> 32;
//     pid_t tid = (__u32)bpf_get_current_pid_tgid();

//     if (pid == tid) {
//         /* New process */
        

//     } else {
//         /* New thread */
//         bpf_printk("PID %d - new thread created.", pid);
//         if (!check_oomp(pid)) {
//             return 0;
//         }

//         if (check_to_kill(pid)) {
//             bpf_send_signal(SIGKILL);
//             return 0;
//         }

//         struct counters init_val = { .th_cnt = 1 };
//         struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);

//         __u32 current_cnt = 1;
//         if (!val)
//             bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
//         else
//             current_cnt = __sync_add_and_fetch(&val->th_cnt, 1);

//         if (current_cnt >= TH_MAX) {
//             set_to_kill(pid);
//         }

//     }
//     return 0;
// }

/* Tracking used file descriptors. */
SEC("kretprobe/alloc_fd")
int handle_fd(struct pt_regs *ctx) 
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (!check_oomp(pid)) {
        return 0;
    }

    if (check_to_kill(pid)) {
        bpf_send_signal(SIGKILL);
        return 0;
    }

    bpf_printk("PID %d created a file descriptor.", pid);
    long ret = PT_REGS_RC(ctx);

    // If no error occured.
    if (ret >= 0) {
        struct counters init_val = { .fd_cnt = 1 };
        struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);

        __u32 current_cnt = 1;
        if (!val)
            bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
        else
            current_cnt = __sync_add_and_fetch(&val->fd_cnt, 1);

        if (current_cnt >= FD_MAX) {
            set_to_kill(pid);
        }
    }

    return 0;
}

static int __always_inline do_handle_write(struct pt_regs *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (!check_oomp(pid)) {
        return 0;
    }

    if (check_to_kill(pid)) {
        bpf_send_signal(SIGKILL);
        return 0;
    }
    long ret = PT_REGS_RC(ctx);

    bpf_printk("PID %d written to the file.", pid);

    if (ret >= 0) {
        struct counters init_val = { .wrt_cnt = 1 };
        struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);

        __u32 current_cnt = 1;
        if (!val)
            bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
        else
            current_cnt = __sync_add_and_fetch(&val->wrt_cnt, 1);

        if (current_cnt >= WRT_MAX) {
            set_to_kill(pid);
        }
    }
    return 0;
}

/* Tracking writing to files. */
SEC("kretprobe/vfs_write")
int handle_write(struct pt_regs *ctx)
{
    return do_handle_write(ctx);
}

SEC("kretprobe/vfs_writev")
int handle_writev(struct pt_regs *ctx)
{
    return do_handle_write(ctx);
}

static int __always_inline do_handle_read(struct pt_regs *ctx)
{
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

        __u32 current_cnt = 1;
        if (!val)
            bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
        else
            current_cnt = __sync_add_and_fetch(&val->rd_cnt, ret);

        if (current_cnt >= RD_MAX) {
            set_to_kill(pid);
        }
    }
    return 0;
}

/* Tracking reading from files. */
SEC("kretprobe/vfs_read")
int handle_read(struct pt_regs *ctx)
{
    return do_handle_read(ctx);
}

SEC("kretprobe/vfs_readv")
int handle_readv(struct pt_regs *ctx)
{
    return do_handle_read(ctx);
}

/* Tracking rand() function from libc. */
SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:rand")
int handle_rand(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (!check_oomp(pid)) {
        return 0;
    }

    if (check_to_kill(pid)) {
        bpf_printk("PID: %d killed", pid);
        bpf_send_signal(SIGKILL);
        return 0;
    }

    bpf_printk("PID %d used a rand function.", pid);

    struct counters init_val = { .rnd_cnt = 1 };
    struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);

    __u32 current_cnt = 1;
    if (!val)
        bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
    else
        current_cnt = __sync_add_and_fetch(&val->rnd_cnt, 1);

    if (current_cnt >= RND_MAX) {
        set_to_kill(pid);
    }
    return 0;
}

/* On exit, counters are deleted. */
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exit* ctx) 
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("PID %d exited", pid);
    bpf_map_delete_elem(&monitoring, &pid);
    bpf_map_delete_elem(&oomp, &pid);
    return 0;
}

/* Get the pointer, where the data about memory will be saved. */
SEC("kprobe/si_meminfo")
int check_memory_pointer(struct pt_regs *ctx)
{
    memory_data = (struct sysinfo *)PT_REGS_PARM1(ctx);
    return 0;
}

/* Get the actual data. */
SEC("kretprobe/si_meminfo")
int check_memory(struct pt_regs *ctx)
{
    __kernel_ulong_t freeram = BPF_CORE_READ(memory_data, freeram);
    __kernel_ulong_t totalram = BPF_CORE_READ(memory_data, totalram);

    __u32 mem_unit = BPF_CORE_READ(memory_data, mem_unit);

    freeram *= mem_unit;
    totalram *= mem_unit;
    freeram /= 1000 * 1000;  /* MB */
    totalram /= 1000 * 1000; /* MB */

    memory = totalram - freeram - APROX_EBPF_SIZE;
    bpf_printk("Totalram: %lu MB, Freeram: %lu MB, Used Memory: %lu MB",totalram, freeram, memory);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";