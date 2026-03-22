#define __TARGET_ARCH_x86
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define MAX_PROCESSES 4194304

#define RD_MAX  10000000
#define TCP_MAX 1000
#define FD_MAX  100
#define WRT_MAX 100
#define TH_MAX  100
#define RND_MAX 100


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

/* Pids for the procesess that should be killed when RAM usage is high. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PROCESSES);
    __type(key, __u32);
    __type(value, __u8); // 1 if it can be killed.
}  to_kill SEC(".maps");

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

bool check_to_kill(pid_t pid) {
    struct counters *val = bpf_map_lookup_elem(&to_kill, &pid);
    return val ? true : false;
}

bool check_oomp(pid_t pid) {
    struct counters *val = bpf_map_lookup_elem(&oomp, &pid);
    return val ? true : false;
}

// Move from 'monitoring' map to 'to_kill' map.
void move_to_kill(pid_t pid) {
    struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);
    bpf_map_delete_elem(&monitoring, &pid);
    bool init_val = true;
    bpf_map_update_elem(&to_kill, &pid, &init_val, BPF_ANY);

}

// Check if the name of the process contains 'oomp'.
//SEC() // TODO: hook on process creation
bool check_process_name(pid_t pid) {
    struct task_struct *task = (void *)bpf_get_current_task();
    char comm[16];
    BPF_CORE_READ_STR_INTO(&comm, task, comm);

    // We transfer the name of the process to the userspace for analysis.
    struct ringbuf_data *rb_data = bpf_ringbuf_reserve(&ring_buffer, sizeof(struct ringbuf_data), 0);
    if(!rb_data) {
        // if bpf_ringbuf_reserve fails, print an error message and return
        bpf_printk("bpf_ringbuf_reserve failed\n");
        return 1;
    }

    rb_data->pid = pid;
    rb_data->name = comm;

    bpf_ringbuf_submit(rb_data, 0);

    return 0;
    //return (strstr(comm, "oomp") != NULL);
}

/* Used file descriptors tracking. */
SEC("kretprobe/alloc_fd")
int handle_fd(struct pt_regs *ctx) 
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("PID %d created a file descriptor", pid);

    if (!check_oomp(pid) || check_to_kill(pid)) {
        return 0;
    }
    long ret = PT_REGS_RC(ctx);

    // If no error occured.
    if (ret >= 0) {
        struct counters init_val = { .fd_cnt = 1 };
        struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);

        __u32 current_cnt = 1;
        if (!val)
            bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
        else
            current_cnt = __sync_add_and_fetch(&val->wrt_cnt, 1);

        if (current_cnt >= FD_MAX) {
            move_to_kill(pid);
        }
    }

    return 0;
}

static int __always_inline do_handle_write(struct pt_regs *ctx)
{
    // We are not saving data about processes, that name has no 'oomp' string or are already sentenced to death.
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("PID %d written to the file.", pid);
    if (!check_oomp(pid) || check_to_kill(pid)) {
        return 0;
    }
    long ret = PT_REGS_RC(ctx);

    if (ret >= 0) {
        struct counters init_val = { .wrt_cnt = 1 };
        struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);

        __u32 current_cnt = 1;
        if (!val)
            bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
        else
            current_cnt = __sync_add_and_fetch(&val->wrt_cnt, 1);

        if (current_cnt >= WRT_MAX) {
            move_to_kill(pid);
        }
    }
    return 0;
}

/* Writing to files tracking. */
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
    if (!check_oomp(pid) || check_to_kill(pid)) {
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
            current_cnt = __sync_add_and_fetch(&val->wrt_cnt, ret);

        if (current_cnt >= RD_MAX) {
            move_to_kill(pid);
        }
    }
    return 0;
}

/* Reading from files tracking */
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

/* rand() function from libc tracking. */
SEC("uprobe//lib/x86_64-linux-gnu/libc.so.6:rand")
int handle_rand(struct pt_regs *ctx) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("PID %d used a rand function.", pid);

    if (!check_oomp(pid) || check_to_kill(pid)) {
        return 0;
    }

    struct counters init_val = { .rnd_cnt = 1 };
    struct counters *val = bpf_map_lookup_elem(&monitoring, &pid);

    __u32 current_cnt = 1;
    if (!val)
        bpf_map_update_elem(&monitoring, &pid, &init_val, BPF_ANY);
    else
        current_cnt = __sync_add_and_fetch(&val->wrt_cnt, 1);

    if (current_cnt >= RND_MAX) {
        move_to_kill(pid);
    }
    return 0;
}

// threads: https://ancat.github.io/kernel/2021/05/20/hooking-processes-and-threads.html


/* On exit, counters are deleted. */
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exit* ctx) 
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    bpf_printk("PID %d exited", pid);
    bpf_map_delete_elem(&monitoring, &pid);
    bpf_map_delete_elem(&to_kill, &pid);
    bpf_map_delete_elem(&oomp, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";