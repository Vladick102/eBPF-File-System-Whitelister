// SPDX-License-Identifier: GPL-2.0
//
// eBPF LSM program: whitelist file access for a named process.
//
// Attached to the "file_open" LSM hook. For every open() / openat() the kernel
// passes us the resulting struct file*. If the current task's comm matches the
// configured target and the resolved path is not under any of the configured
// allowed prefixes, we return -EPERM and the kernel refuses the open.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// MAX_PATH is the size of the path buffer the LSM hook hands to bpf_d_path()
// and the per-prefix size in the config. The BPF stack is only 512 bytes,
// which would limit MAX_PATH to ~256 if the buffer lived on the stack; we
// instead store the path in a per-CPU array map (see scratch_path below) so
// the buffer can be much larger. PATH_MAX on Linux is 4096; 1024 covers
// real-world paths comfortably while keeping the prefix-scan inner loop
// reasonable for the verifier.
#define MAX_PATH 1024
#define TASK_COMM_LEN 16
// MAX_PREFIXES caps how many --allow entries the loader can push into the
// config map. The hot loop in whitelist_file_open() is bounded by this at
// compile time, so the verifier unrolls O(MAX_PREFIXES * MAX_PATH) state
// transitions. 32 keeps that comfortably under the kernel's instruction
// limit while leaving room for benchmarks that sweep up to ~25 entries.
#define MAX_PREFIXES 32

struct config {
    char target_comm[TASK_COMM_LEN];
    __u32 num_prefixes;
    __u32 prefix_lens[MAX_PREFIXES];
    char prefixes[MAX_PREFIXES][MAX_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

// Per-CPU scratch buffer for the resolved path. One value per CPU, no
// contention: each invocation of the program borrows this CPU's buffer
// for the lifetime of the LSM hook. Has to be a map (not a stack array)
// because MAX_PATH * sizeof(char) is far larger than the 512-byte BPF
// stack budget.
struct path_scratch {
    char buf[MAX_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_scratch);
} scratch_path SEC(".maps");

static __always_inline int comm_eq(const char *a, const char *b) {
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        char ca = a[i], cb = b[i];
        if (ca != cb)
            return 0;
        if (ca == 0)
            return 1;
    }
    return 1;
}

// Path-aware prefix: the match must end on a path component boundary.
// For prefix "/tmp/ftp", allow "/tmp/ftp" and "/tmp/ftp/anything" but NOT
// "/tmp/ftp_whitelist_demo/...". Assumes the user normalized off any trailing
// '/' before storing; bpf_d_path always null-terminates the path buffer.
static __always_inline int has_prefix(const char *path, const char *prefix,
                                      __u32 prefix_len) {
    if (prefix_len == 0 || prefix_len >= MAX_PATH)
        return 0;
    for (__u32 i = 0; i < MAX_PATH; i++) {
        if (i >= prefix_len) {
            char next = path[i];
            return next == '\0' || next == '/';
        }
        if (path[i] != prefix[i])
            return 0;
    }
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(whitelist_file_open, struct file *file) {
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg || cfg->num_prefixes == 0)
        return 0;

    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (!comm_eq(comm, cfg->target_comm))
        return 0;

    struct path_scratch *scratch = bpf_map_lookup_elem(&scratch_path, &key);
    if (!scratch)
        return 0;
    // Reset to keep stale data from leaking between invocations.
    __builtin_memset(scratch->buf, 0, sizeof(scratch->buf));

    long plen = bpf_d_path(&file->f_path, scratch->buf, sizeof(scratch->buf));
    if (plen < 0)
        return 0;

    for (__u32 i = 0; i < MAX_PREFIXES; i++) {
        if (i >= cfg->num_prefixes)
            break;
        if (has_prefix(scratch->buf, cfg->prefixes[i], cfg->prefix_lens[i]))
            return 0;
    }

    bpf_printk("whitelister: BLOCK pid=%d comm=%s path=%s",
               bpf_get_current_pid_tgid() >> 32, comm, scratch->buf);
    return -1; // -EPERM
}

char LICENSE[] SEC("license") = "GPL";
