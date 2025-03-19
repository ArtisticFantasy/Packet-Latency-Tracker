UNAME_M := $(shell uname -m)

ifeq ($(UNAME_M), x86_64)
    TARGET_ARCH := x86
else ifeq ($(UNAME_M), aarch64)
    TARGET_ARCH := arm64
else ifeq ($(UNAME_M), armv7l)
    TARGET_ARCH := arm
else
    $(error Unsupported architecture: $(UNAME_M))
endif

CC := clang
COMMON_CFLAGS := -Wall -O2 -Iinclude
BPF_CFLAGS := $(COMMON_CFLAGS) -target bpf -D__TARGET_ARCH_$(TARGET_ARCH) -g -c
LOADER_CFLAGS := $(COMMON_CFLAGS)
BPF_LDFLAGS := -lbpf
BPF_PROG := src/packet-latency-tracker
MAIN := src/main

INT_FILES := $(BPF_PROG).o $(MAIN)

.PHONY: all clean run

all: $(MAIN)

$(BPF_PROG).o: $(BPF_PROG).c
	@if ! test -f include/vmlinux.h; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h || exit 1; \
	fi
	@$(CC) $(BPF_CFLAGS) -o $@ $^

$(MAIN): $(MAIN).c $(BPF_PROG).o
	@$(CC) $(LOADER_CFLAGS) -o $@ $< $(BPF_LDFLAGS)

run: $(MAIN)
	@sudo ./$(MAIN)

clean:
	@rm -f $(INT_FILES)