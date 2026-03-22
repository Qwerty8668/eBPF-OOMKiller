#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "oomkiller.skel.h"

int create_ringbuf_map(void) {
    // The size of the ringbuf is given in bytes by max_entries.
    int fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "ring_buffer_map_example",
                            0,    // key_size = 0 for ringbuf
                            0,    // value_size = 0 for ringbuf
                            4096,
                            NULL);
    if (fd < 0) {
        fprintf(stderr, "Failed to create ring buffer map: %s\n", strerror(errno));
    }
    return fd;
}

int main(void)
{
    struct oomkiller *skel = oomkiller__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF object\n");
        return 1;
    }
    if (oomkiller__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    printf("BPF program attached"
           "in another terminal.\n");
    printf("Press Enter after triggering...\n");
    getchar();

cleanup:
    oomkiller__destroy(skel);
    return 0;
}