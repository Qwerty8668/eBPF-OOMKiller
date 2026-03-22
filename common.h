#include "vmlinux.h"
#ifndef __COMMON_H
#define __COMMON_H

struct ringbuf_data {
    pid_t pid;
    char* name;
};

#endif