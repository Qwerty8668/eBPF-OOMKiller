#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <time.h>
#include <sys/sysinfo.h>
#include "oomkiller.skel.h"

static volatile bool exiting = false;
static time_t last_time;
static struct sysinfo *memory;

void sig_handler() {
    exiting = true;
}

int main(void)
{
    time(&last_time);
    struct oomkiller *skel = oomkiller__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open/load BPF object\n");
        return 1;
    }
    if (oomkiller__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);

    while (!exiting) {
        sleep(1);
        sysinfo(memory);
    }


cleanup:
    oomkiller__destroy(skel);
    return 0;
}