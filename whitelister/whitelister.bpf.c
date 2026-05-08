// eBPF LSM program: per-comm path-prefix whitelisting via LPM trie.
//
// Maps populated by the loader:
//
//   configured_comms : char[16] -> u8
//       Marker set: "this comm has a policy". A process whose task->comm
//       is NOT a key here is NEVER enforced -- the LSM hook returns 0 and
//       the VFS open proceeds unchanged. Opt-in per-comm.
//
//   allow_prefixes   : { __u32 prefixlen; char data[16 + 1024]; } -> u32
//       Longest-prefix-match trie keyed on (comm || path-prefix). The
//       prefix-length is in *bits*; we always set it as a multiple of 8
//       since path bytes are byte-aligned. The value stores the prefix's
//       path-portion length in bytes, which we use post-match to enforce
//       the path-component boundary rule (so prefix "/tmp/foo" matches
//       "/tmp/foo/x" but not "/tmp/foobar").

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "whitelister_config.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_COMMS);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, __u8);
} configured_comms SEC(".maps");

struct lpm_key {
    __u32 prefixlen;
    char data[TASK_COMM_LEN + LPM_PATH_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_PREFIXES);
    __uint(map_flags, BPF_F_NO_PREALLOC); // required for LPM_TRIE
    __type(key, struct lpm_key);
    __type(value, __u32);
} allow_prefixes SEC(".maps");

struct path_scratch {
    char buf[MAX_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_scratch);
} scratch_path SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lpm_key);
} scratch_lpm SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(whitelist_file_open, struct file *file) {
    __u32 zero = 0;

    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    if (!bpf_map_lookup_elem(&configured_comms, &comm))
        return 0;

    struct path_scratch *scratch = bpf_map_lookup_elem(&scratch_path, &zero);
    if (!scratch)
        return 0;
    __builtin_memset(scratch->buf, 0, sizeof(scratch->buf));
    long plen = bpf_d_path(&file->f_path, scratch->buf, sizeof(scratch->buf));
    if (plen <= 1)
        return 0;
    __u32 path_len = (__u32)plen - 1;
    if (path_len > MAX_PATH - 1)
        path_len = MAX_PATH - 1;

    __u32 lpm_path_len = path_len;
    if (lpm_path_len > LPM_PATH_MAX)
        lpm_path_len = LPM_PATH_MAX;

    struct lpm_key *key = bpf_map_lookup_elem(&scratch_lpm, &zero);
    if (!key)
        return 0;
    __builtin_memset(key, 0, sizeof(*key));
    key->prefixlen = (TASK_COMM_LEN + lpm_path_len) * 8;
    __builtin_memcpy(key->data, comm, TASK_COMM_LEN);

    for (__u32 j = 0; j < LPM_PATH_MAX; j++) {
        if (j >= lpm_path_len)
            break;
        key->data[TASK_COMM_LEN + j] = scratch->buf[j];
    }

    __u32 *match = bpf_map_lookup_elem(&allow_prefixes, key);
    if (match) {
        __u32 mlen = *match;

        if (mlen == path_len)
            return 0;

        if (mlen < path_len && mlen < MAX_PATH) {
            __u32 mlen_safe = mlen & (MAX_PATH - 1);
            char next = scratch->buf[mlen_safe];
            if (next == '/' || next == '\0')
                return 0;
        }
    }

    bpf_printk("whitelister: BLOCK pid=%d comm=%s path=%s",
               bpf_get_current_pid_tgid() >> 32, comm, scratch->buf);
    return -1; // -EPERM
}

char LICENSE[] SEC("license") = "GPL";
