#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <string.h>
#include <signal.h>
#include "oomkiller.skel.h"
#include "common.h"

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    const int *oomp_map_fd = ctx;

    const struct ringbuf_data *e = data;
    
    __u8 value1 = 1;
    __u8 value0 = 0;
    if(strstr(e->name, "oomp")) {
        if (bpf_map_update_elem(*oomp_map_fd, &e->pid, &value1, BPF_ANY)) {
            fprintf(stderr, "bpf_map_lookup_elem");
            return -1;
        }
    } else {
        if (bpf_map_update_elem(*oomp_map_fd, &e->pid, &value0, BPF_ANY)) {
            fprintf(stderr, "bpf_map_lookup_elem");
            return -1;
        }
    }
    return 0;
}

int main(void)
{
    struct ring_buffer *rb = NULL;
    struct oomkiller *skel = oomkiller__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF object\n");
        return 1;
    }
    if (oomkiller__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    printf("BPF program attached");

    int oomp_map_fd = bpf_map__fd(skel->maps.oomp);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.ring_buffer), handle_event, &oomp_map_fd, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer manager\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int err;
    __u8 value = 1;
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        
        if (err == -EINTR) {
            err = 0;
            goto cleanup;
        }
        if (err < 0) {
            fprintf(stderr, "Error during polling: %d\n", err);
            goto cleanup;
        }
    }

cleanup:
    ring_buffer__free(rb);
    oomkiller__destroy(skel);
    return 0;
}