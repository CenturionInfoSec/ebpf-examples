#!/usr/bin/python
from __future__ import print_function

from datetime import datetime
from time import sleep
import argparse
import json
from bcc import BPF
from bcc.syscall import syscall_name, syscalls


parser = argparse.ArgumentParser(description="Trace syscalls.")

action_filter = parser.add_mutually_exclusive_group(required=True)
action_filter.add_argument("-a", "--aggregate", action="store_true")
action_filter.add_argument("-t", "--trace", action="store_true")

program_filter = parser.add_mutually_exclusive_group(required=True)
program_filter.add_argument("-p", "--pid", type=int)
program_filter.add_argument("-n", "--name", type=str)

parser.add_argument("--dump_prog", action="store_true")
parser.add_argument("--syscall_filter", type=str, nargs="+")
parser.add_argument("--syscall_filter_file", type=file)
parser.add_argument("-b", "--buffer_size", type=int, default=8)
parser.add_argument("-o", "--output", type=argparse.FileType("wb"))
args = parser.parse_args()

# Groups of syscalls with the same function signature.
# We should refactor this into another structure once
# it grows out of hand.

# syscall_list_a has the following signature:
# syscall__XXX(struct pt_regs *ctx, int dfd, const char __user *filename)
syscall_list_a = ["openat", "newfstatat", "readlinkat", "faccessat",]

# syscall_list_b has the following signature:
# syscall__XXX(struct pt_regs *ctx, const char __user *filename)
syscall_list_b = ["stat", "statfs",]

# syscall_list_ptrace has the following signature:
# syscall__XXX(struct pt_regs *ctx, long request, long pid)
syscall_list_ptrace = ["ptrace"]

syscall_list_all = (
    syscall_list_a + syscall_list_b + syscall_list_ptrace
)

LOST_EVENTS = 0


def insert_pid_filter(bpf_text, pid):
    bpf_text = "#define FILTER_PID {}\n".format(pid) + bpf_text
    pid_filter = """
    u64 pid_tgid_f = bpf_get_current_pid_tgid();
    if (pid_tgid_f >> 32 != FILTER_PID) {
        return 0;
    }
    """
    bpf_text = bpf_text.replace("PROCESS_FILTER", pid_filter)

    return bpf_text


def insert_name_filter(bpf_text, program_name):
    compare_statement = []
    # Android seem to truncate the process name to the
    # last 15 chars of the app name.
    for index, char in enumerate(program_name[-15:]):
        compare_statement.append(
            "(proc_name[{}] != '{}')".format(index, char))

    compare_statement = " || ".join(compare_statement)

    process_name_filter = """
    char proc_name[TASK_COMM_LEN];
    bpf_get_current_comm(&proc_name, sizeof(proc_name));

    if ({}) {{
        return 0;
    }}
    """.format(compare_statement)
    bpf_text = bpf_text.replace("PROCESS_FILTER", process_name_filter)

    return bpf_text


if args.trace:
    bpf_text = """
    #include <asm/ptrace.h>
    #include <uapi/linux/limits.h>
    #include <linux/sched.h>

    struct syscalls_data_t {
        u64 timestamp;
        long pid;
        long id;
    };

    struct syscall_w_fname_data_t {
        u64 timestamp;
        long pid;
        long id;
        char fname[NAME_MAX];
    };

    struct syscall_ptrace_data_t {
        u64 timestamp;
        long pid;
        long id;
        long request;
        long target_pid;
    };

    struct syscall_ret_value_data_t {
        u64 timestamp;
        long pid;
        long id;
        int return_value;
    };

    BPF_PERF_OUTPUT(syscall_events);
    BPF_PERF_OUTPUT(syscall_fname_events);
    BPF_PERF_OUTPUT(syscall_ptrace_events);
    BPF_PERF_OUTPUT(syscall_clone_events);

    int syscall__clone(struct pt_regs *ctx)
    {
        PROCESS_FILTER

        struct syscall_ret_value_data_t data = {};

        u64 pid_tgid = bpf_get_current_pid_tgid();
        data.pid = pid_tgid >> 32;

        data.timestamp = bpf_ktime_get_ns();

        data.id = 56;
        data.return_value = PT_REGS_RC(ctx);

        syscall_clone_events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }

    TRACEPOINT_PROBE(raw_syscalls, sys_enter)
    {
        PROCESS_FILTER

        SYSCALL_ALT_IMPL_FILTER

        SYSCALL_EVENT_FILTER

        struct syscalls_data_t data = {};

        data.timestamp = bpf_ktime_get_ns();

        u64 pid_tgid = bpf_get_current_pid_tgid();
        data.pid = pid_tgid >> 32;

        data.id = args->id;
        syscall_events.perf_submit(args, &data, sizeof(data));

        return 0;
    }
    """

    syscall_filter_code = ""
    # Invert the syscalls dictionary so we can lookup the
    # number based on the name.
    inverted_syscalls = {v: k for k, v in syscalls.items()}

    syscall_filter_code = [
        "args->id == {}".format(inverted_syscalls[i])
        for i in syscall_list_all + ["clone"]
    ]
    syscall_filter_code = """
    if ({}) {{
        return 0;
    }}
    """.format(" || ".join(syscall_filter_code))

    bpf_text = bpf_text.replace("SYSCALL_ALT_IMPL_FILTER", syscall_filter_code)

    if args.syscall_filter or args.syscall_filter_file:
        syscall_filter = args.syscall_filter or []
        if args.syscall_filter_file:
            syscall_filter = (
                syscall_filter +
                args.syscall_filter_file.read().rstrip().split("\n")
            )
            syscall_filter = [i.rstrip() for i in syscall_filter]

        syscall_filter_code = [
            "args->id == {}".format(inverted_syscalls[i])
            for i in syscall_filter
        ]

        syscall_filter_code = """
        if ({}) {{
            return 0;
        }}
        """.format(" || ".join(syscall_filter_code))
    else:
        syscall_filter = []

    bpf_text = bpf_text.replace("SYSCALL_EVENT_FILTER", syscall_filter_code)

    for syscall in syscall_list_a:
        if syscall in syscall_filter:
            continue

        bpf_text += """
    int syscall__{}(struct pt_regs *ctx,
        int dfd, const char __user *filename)
    {{
        PROCESS_FILTER

        struct syscall_w_fname_data_t data = {{}};

        u64 pid_tgid = bpf_get_current_pid_tgid();
        data.pid = pid_tgid >> 32;

        data.timestamp = bpf_ktime_get_ns();

        data.id = {};
        bpf_probe_read(&data.fname, sizeof(data.fname), (void *)filename);
        syscall_fname_events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }}
        """.format(syscall, inverted_syscalls[syscall])

    for syscall in syscall_list_b:
        if syscall in syscall_filter:
            continue

        bpf_text += """
    int syscall__{}(struct pt_regs *ctx, const char __user *filename)
    {{
        PROCESS_FILTER

        struct syscall_w_fname_data_t data = {{}};

        u64 pid_tgid = bpf_get_current_pid_tgid();
        data.pid = pid_tgid >> 32;

        data.timestamp = bpf_ktime_get_ns();

        data.id = {};
        bpf_probe_read(&data.fname, sizeof(data.fname), (void *)filename);
        syscall_fname_events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }}
        """.format(syscall, inverted_syscalls[syscall])

    for syscall in syscall_list_ptrace:
        if syscall in syscall_filter:
            continue

        bpf_text += """
    int syscall__{}(struct pt_regs *ctx, long request, long pid)
    {{
        PROCESS_FILTER

        struct syscall_ptrace_data_t data = {{}};

        u64 pid_tgid = bpf_get_current_pid_tgid();
        data.pid = pid_tgid >> 32;

        data.timestamp = bpf_ktime_get_ns();

        data.id = {};
        data.request = request;
        data.target_pid = pid;

        syscall_ptrace_events.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }}
        """.format(syscall, inverted_syscalls[syscall])

    if args.pid:
        bpf_text = insert_pid_filter(bpf_text, args.pid)
    else:
        bpf_text = insert_name_filter(bpf_text, args.name)

    if args.dump_prog:
        print(bpf_text)
        exit()

    out_data = []

    print("Tracing syscalls. CTRL-C to quit.")
    b = BPF(text=bpf_text)

    for syscall in syscall_list_all:
        if syscall in syscall_filter:
            continue

        syscall_fnname = b.get_syscall_fnname(syscall)
        if BPF.ksymname(syscall_fnname) != -1:
            b.attach_kprobe(
                event=syscall_fnname,
                fn_name="syscall__{}".format(syscall)
            )


    syscall_fnname = b.get_syscall_fnname("clone")
    b.attach_kretprobe(event=syscall_fnname, fn_name="syscall__clone")


    def print_syscall_event(cpu, data, size):
        event = b["syscall_events"].event(data)
        print("[{}] [{}] {}".format(
            event.timestamp, event.pid, syscall_name(event.id)
        ))

        out_data.append({
            "timestamp": event.timestamp,
            "pid": event.pid,
            "syscall": syscall_name(event.id),
            "arguments": None,
        })


    def print_syscall_fname_event(cpu, data, size):
        event = b["syscall_fname_events"].event(data)
        print("[{}] [{}] {}: {}".format(
            event.timestamp, event.pid, syscall_name(event.id), event.fname
        ))

        out_data.append({
            "timestamp": event.timestamp,
            "pid": event.pid,
            "syscall": syscall_name(event.id),
            "arguments": event.fname,
        })

    def print_syscall_ptrace_event(cpu, data, size):
        event = b["syscall_ptrace_events"].event(data)
        print("[{}] [{}] {}: request={} target_pid={}".format(
            event.timestamp, event.pid, syscall_name(event.id),
            event.request, event.target_pid
        ))

        out_data.append({
            "timestamp": event.timestamp,
            "pid": event.pid,
            "syscall": syscall_name(event.id),
            "arguments": "request={} target_pid={}".format(
                event.request, event.target_pid)
        })

    def print_syscall_clone_event(cpu, data, size):
        event = b["syscall_clone_events"].event(data)
        print("[{}] [{}] {}: child={}".format(
            event.timestamp, event.pid, syscall_name(event.id),
            event.return_value
        ))

        out_data.append({
            "timestamp": event.timestamp,
            "pid": event.pid,
            "syscall": syscall_name(event.id),
            "arguments": "child={}".format(event.return_value)
        })


    def lost_samples_counter(count):
        global LOST_EVENTS

        print("{} events lost.".format(count))
        LOST_EVENTS += count


    b["syscall_events"].open_perf_buffer(
        print_syscall_event,
        page_cnt=args.buffer_size,
        lost_cb=lost_samples_counter
    )
    b["syscall_fname_events"].open_perf_buffer(
        print_syscall_fname_event,
        page_cnt=args.buffer_size,
        lost_cb=lost_samples_counter
    )
    b["syscall_ptrace_events"].open_perf_buffer(
        print_syscall_ptrace_event,
        page_cnt=args.buffer_size,
        lost_cb=lost_samples_counter
    )
    b["syscall_clone_events"].open_perf_buffer(
        print_syscall_clone_event,
        page_cnt=args.buffer_size,
        lost_cb=lost_samples_counter
    )

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print()
            print("{} events lost in total.".format(LOST_EVENTS))

            if (args.output):
                json.dump(out_data, args.output)
                args.output.close()

            exit()

if args.aggregate:
    bpf_text = """
    #include <asm/ptrace.h>
    #include <uapi/linux/limits.h>
    #include <linux/sched.h>


    BPF_HASH(syscall_count, u32, u64);

    TRACEPOINT_PROBE(raw_syscalls, sys_enter)
    {
        PROCESS_FILTER

        u64 *val, zero = 0;
        u32 key = args->id;
        val = syscall_count.lookup_or_init(&key, &zero);
        ++(*val);

        return 0;
    }
    """

    if args.pid:
        bpf_text = insert_pid_filter(bpf_text, args.pid)
    else:
        bpf_text = insert_name_filter(bpf_text, args.name)

    if args.dump_prog:
        print(bpf_text)
        exit()

    print("Aggregating syscalls. CTRL-C to quit.")
    b = BPF(text=bpf_text)
    counter = b["syscall_count"]

    while True:
        try:
            sleep(1)
        except KeyboardInterrupt:
            print("")
            for k, v in sorted(counter.items(), key=lambda kv: -kv[1].value):
                print(b"%-22s %8d" % (syscall_name(k.value), v.value))

            exit()
