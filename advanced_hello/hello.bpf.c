#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// macro that instructs to attach the function below to the
// tracepoint triggered right before the openat syscall executes
SEC("tracepoint/syscalls/sys_enter_openat")

// ctx is the required argument (structure) that contains the context
// (the CPU registers and the raw arguments passed from user-space to the syscall)
int handle_openat(struct trace_event_raw_sys_enter *ctx) {

    // in the sys_enter_openat tracepoint, args[1] is a pointer to the filename
    const char *filename = (const char *)ctx->args[1];

    // eBPF equivalent of printf
    bpf_printk("eBPF file hook: %s\n", filename);
    return 0;
}

// the kernel requires eBPF programs to declare their license
char LICENSE[] SEC("license") = "GPL";
