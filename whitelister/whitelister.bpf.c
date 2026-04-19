// SPDX-License-Identifier: GPL-2.0
//
// eBPF LSM program: whitelist file access for a named process.
//
// Attached to the "file_open" LSM hook. For every open() / openat() the kernel
// passes us the resulting struct file*. If the current task's comm matches the
// configured target and the resolved path is not under any of the configured
// allowed prefixes, we return -EPERM and the kernel refuses the open.
//
// The LSM hook runs *after* the DAC (uid/gid) checks, so normal file
// permissions still apply; we can only be *more* restrictive, never less.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_PATH       256
#define TASK_COMM_LEN  16
#define MAX_PREFIXES   8

struct config {
    char     target_comm[TASK_COMM_LEN];
    __u32    num_prefixes;
    __u32    prefix_lens[MAX_PREFIXES];
    char     prefixes[MAX_PREFIXES][MAX_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

static __always_inline int comm_eq(const char *a, const char *b)
{
    for (int i = 0; i < TASK_COMM_LEN; i++) {
        char ca = a[i], cb = b[i];
        if (ca != cb) return 0;
        if (ca == 0)  return 1;
    }
    return 1;
}

// Path-aware prefix: the match must end on a path component boundary.
// For prefix "/tmp/ftp", allow "/tmp/ftp" and "/tmp/ftp/anything" but NOT
// "/tmp/ftp_whitelist_demo/...". Assumes the user normalized off any trailing
// '/' before storing; bpf_d_path always null-terminates the path buffer.
static __always_inline int has_prefix(const char *path,
                                      const char *prefix,
                                      __u32 prefix_len)
{
    if (prefix_len == 0 || prefix_len >= MAX_PATH) return 0;
    for (__u32 i = 0; i < MAX_PATH; i++) {
        if (i >= prefix_len) {
            char next = path[i];
            return next == '\0' || next == '/';
        }
        if (path[i] != prefix[i]) return 0;
    }
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(whitelist_file_open, struct file *file)
{
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if (!cfg || cfg->num_prefixes == 0)
        return 0;

    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));
    if (!comm_eq(comm, cfg->target_comm))
        return 0;

    char path[MAX_PATH] = {};
    long plen = bpf_d_path(&file->f_path, path, sizeof(path));
    if (plen < 0)
        return 0;

    for (__u32 i = 0; i < MAX_PREFIXES; i++) {
        if (i >= cfg->num_prefixes) break;
        if (has_prefix(path, cfg->prefixes[i], cfg->prefix_lens[i]))
            return 0;
    }

    bpf_printk("whitelister: BLOCK pid=%d comm=%s path=%s",
               bpf_get_current_pid_tgid() >> 32, comm, path);
    return -1;  // -EPERM
}

char LICENSE[] SEC("license") = "GPL";
