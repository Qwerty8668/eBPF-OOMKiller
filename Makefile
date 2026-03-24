CC = gcc
CLANG = clang
CFLAGS = -Wall -O2
BPF_CFLAGS = -g -Og -mcpu=v3 --target=bpf
LDFLAGS = -lbpf

.PHONY: all clean deps

all: deps vmlinux.h oomkiller

deps:
	sudo apt-get update
	sudo apt-get install -y clang llvm libbpf-dev gcc make bpftool

vmlinux.h:
	sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

oomkiller.bpf.o: oomkiller.bpf.c vmlinux.h clone_flags.h
	$(CLANG) $(BPF_CFLAGS) -c oomkiller.bpf.c -o $@

oomkiller.skel.h: oomkiller.bpf.o
	sudo bpftool gen skeleton $< name oomkiller > $@

oomkiller: oomkiller.user.c oomkiller.skel.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

clean:
	rm -f oomkiller oomkiller.user oomkiller.bpf.o oomkiller.skel.h vmlinux.h
