#!/usr/bin/python

from bcc import BPF

program = """
#include <asm/ptrace.h>
#include <uapi/linux/limits.h>

struct open_data_t {
    char fname[NAME_MAX];
};

BPF_PERF_OUTPUT(open_event);

int kprobe__sys_openat(struct pt_regs *ctx,
    int dirfd, char __user* pathname, int flags, mode_t mode) {

    struct open_data_t data = {{}};
    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)pathname);
    open_event.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

def print_open_event(cpu, data, size):
    event = b["open_event"].event(data)
    print event.fname

b = BPF(text=program)
b["open_event"].open_perf_buffer(print_open_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
