#!/usr/bin/python

from bcc import BPF
import sys

program = """
#include <asm/ptrace.h>
#include <uapi/linux/limits.h>

struct open_data_t {
    char fname[NAME_MAX];
};

BPF_PERF_OUTPUT(open_event);

int kprobe__sys_openat(struct pt_regs *ctx,
    int dirfd, char __user* pathname, int flags, mode_t mode) {

    PID_FILTER

    struct open_data_t data = {{}};
    bpf_probe_read(&data.fname, sizeof(data.fname), (void *)pathname);
    open_event.perf_submit(ctx, &data, sizeof(data));

    return 0;
}
"""

def print_open_event(cpu, data, size):
    event = b["open_event"].event(data)
    print event.fname

def insert_pid_filter(bpf_text, pid):
    bpf_text = "#define FILTER_PID {}\n".format(pid) + bpf_text
    pid_filter = """
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (pid_tgid >> 32 != FILTER_PID) {
        return 0;
    }
    """
    bpf_text = bpf_text.replace("PID_FILTER", pid_filter)

    return bpf_text

program = insert_pid_filter(program, sys.argv[1])

b = BPF(text=program)
b["open_event"].open_perf_buffer(print_open_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
