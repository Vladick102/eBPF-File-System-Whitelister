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
// config map. The outer prefix scan is implemented via bpf_loop() so the
// verifier complexity is O(MAX_PATH), not O(MAX_PREFIXES * MAX_PATH) --
// raising this constant therefore costs map memory but not verifier
// budget. The config map grows linearly with it (~100 KB at this size).
#define MAX_PREFIXES 100

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

// bpf_loop() callback context. The verifier enters the callback as a
// fresh subprog with no state from the caller, so we have to re-check
// cfg != NULL inside even though the LSM hook has already proven it
// non-NULL on the outer path.
struct prefix_check_ctx {
    const char *path;
    struct config *cfg;
    int matched;
};

static long prefix_check_one(__u32 i, struct prefix_check_ctx *ctx) {
    // Derive the array index via an explicit mask so the verifier sees a
    // hard upper bound that survives compiler optimisation. Just adding
    // `if (i >= MAX_PREFIXES) return 1;` isn't enough: clang often keeps
    // the original (unbounded) copy of `i` alive in another register and
    // re-truncates it for the indexed load, defeating the runtime check.
    // The AND below produces a fresh scalar whose [0, 127] bound is
    // attached to a value that is *mathematically* distinct from `i`
    // unless i < 128 -- which it always is at runtime, since bpf_loop()
    // only invokes the callback with i in [0, MAX_PREFIXES-1].
    __u32 idx = i & 0x7f;
    if (idx >= MAX_PREFIXES)
        return 1;

    struct config *cfg = ctx->cfg;
    if (!cfg)                       // verifier proof; runtime no-op
        return 1;
    if (idx >= cfg->num_prefixes)
        return 1;                   // past the live entries -> stop
    if (has_prefix(ctx->path, cfg->prefixes[idx], cfg->prefix_lens[idx])) {
        ctx->matched = 1;
        return 1;                   // hit -> stop early
    }
    return 0;                       // miss -> keep scanning
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

    // Runtime-bounded scan via bpf_loop(): the verifier sees the loop body
    // once (as a subprog) instead of unrolling MAX_PREFIXES copies, which
    // is what kept the program under the 1M-insn verifier limit when
    // MAX_PREFIXES grew past ~32.
    // Note: 'ctx' is taken by BPF_PROG's hidden first arg, so we name
    // ours 'pctx' (prefix-check context).
    struct prefix_check_ctx pctx = {
        .path    = scratch->buf,
        .cfg     = cfg,
        .matched = 0,
    };
    bpf_loop(MAX_PREFIXES, prefix_check_one, &pctx, 0);
    if (pctx.matched)
        return 0;

    bpf_printk("whitelister: BLOCK pid=%d comm=%s path=%s",
               bpf_get_current_pid_tgid() >> 32, comm, scratch->buf);
    return -1; // -EPERM
}

char LICENSE[] SEC("license") = "GPL";
