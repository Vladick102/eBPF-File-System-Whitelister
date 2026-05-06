// SPDX-License-Identifier: GPL-2.0
//
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
//
// On every open() the hook does:
//
//   comm = current_task->comm
//   if comm not in configured_comms: return 0          // bypass
//   path = bpf_d_path(file->f_path)
//   key  = build (comm || path) with prefixlen = (16 + len(path))*8
//   m    = LPM lookup of key in allow_prefixes
//   if m and (path[m.path_len] == '/' || m.path_len == len(path)): return 0
//   return -EPERM                                      // deny
//
// Total work per open: one HASH probe + one LPM lookup + one byte read,
// no inner BPF loops. Verifier complexity is bounded and tiny.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// All compile-time tunables (path size, comm length, LPM-trie limits,
// max comms, max prefixes) live in whitelister_config.h. Bumping any of
// them is a one-file change; the loader and this BPF program both
// re-pick up the new values on rebuild.
#include "whitelister_config.h"

// ----- maps ------------------------------------------------------------------

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_COMMS);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, __u8);
} configured_comms SEC(".maps");

// LPM-trie key: prefixlen in bits, then the comm + path data. The trie
// matches the comm bytes byte-for-byte (16 bytes / 128 bits) and then
// walks the path bits looking for the longest stored prefix. Total
// data field is 256 bytes (LPM_DATA_SIZE_MAX in the kernel); we use
// the leading 16 for comm and the remaining LPM_PATH_MAX = 240 for the
// path-prefix portion.
struct lpm_key {
    __u32 prefixlen;
    char  data[TASK_COMM_LEN + LPM_PATH_MAX];
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, MAX_PREFIXES);
    __uint(map_flags, BPF_F_NO_PREALLOC);   // required for LPM_TRIE
    __type(key, struct lpm_key);
    __type(value, __u32);                   // matched prefix's path length (bytes)
} allow_prefixes SEC(".maps");

// Per-CPU scratch for the resolved path. bpf_d_path may write up to
// MAX_PATH bytes here; the BPF stack budget is only 512 bytes.
struct path_scratch {
    char buf[MAX_PATH];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct path_scratch);
} scratch_path SEC(".maps");

// Per-CPU scratch for the LPM lookup key (~260 B). Lives in a map
// instead of on the 512-byte BPF stack so other locals have room to
// breathe and so the verifier sees a fixed map_value pointer for the
// indexed writes below.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct lpm_key);
} scratch_lpm SEC(".maps");

// ----- main hook -------------------------------------------------------------

SEC("lsm/file_open")
int BPF_PROG(whitelist_file_open, struct file *file) {
    __u32 zero = 0;

    // Step 1: identify the calling task. comm is exactly 16 bytes
    // including a trailing NUL; bpf_get_current_comm() always
    // zero-fills the tail to keep the hash key reproducible.
    char comm[TASK_COMM_LEN] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    // Step 2: bypass if this comm has no policy at all. Fast path for
    // every unrelated process on the system.
    if (!bpf_map_lookup_elem(&configured_comms, &comm))
        return 0;

    // Step 3: resolve the absolute path the open is targeting.
    struct path_scratch *scratch = bpf_map_lookup_elem(&scratch_path, &zero);
    if (!scratch)
        return 0;
    __builtin_memset(scratch->buf, 0, sizeof(scratch->buf));
    long plen = bpf_d_path(&file->f_path, scratch->buf, sizeof(scratch->buf));
    if (plen <= 1)        // 1 means just the trailing NUL -> empty path
        return 0;
    __u32 path_len = (__u32)plen - 1;
    if (path_len > MAX_PATH - 1)
        path_len = MAX_PATH - 1;

    // The LPM key's path field caps at LPM_PATH_MAX bytes; truncate
    // longer paths down for the lookup. (The boundary check below still
    // uses scratch->buf for full-length path access if it needs to
    // verify a byte beyond LPM_PATH_MAX.)
    __u32 lpm_path_len = path_len;
    if (lpm_path_len > LPM_PATH_MAX)
        lpm_path_len = LPM_PATH_MAX;

    // Step 4: build the LPM lookup key in per-CPU scratch.
    //   data[0..15]            = comm (NUL-padded)
    //   data[16..16+lpm_path]  = the resolved path bytes (truncated)
    //   prefixlen              = (16 + lpm_path_len) * 8 bits
    // Zero-init first so any leftover bytes from a previous invocation
    // don't leak into the trie comparison.
    struct lpm_key *key = bpf_map_lookup_elem(&scratch_lpm, &zero);
    if (!key)
        return 0;
    __builtin_memset(key, 0, sizeof(*key));
    key->prefixlen = (TASK_COMM_LEN + lpm_path_len) * 8;
    __builtin_memcpy(key->data, comm, TASK_COMM_LEN);

    // Bounded path-byte copy. Single forward loop with one early break
    // and no conditional store -- verifier-friendly. The LPM_PATH_MAX
    // static bound makes this O(LPM_PATH_MAX) verifier work *once*.
    for (__u32 j = 0; j < LPM_PATH_MAX; j++) {
        if (j >= lpm_path_len)
            break;
        key->data[TASK_COMM_LEN + j] = scratch->buf[j];
    }

    // Step 5: LPM lookup. Returns the longest stored prefix that's a
    // bit-prefix of our key, or NULL.
    __u32 *match = bpf_map_lookup_elem(&allow_prefixes, key);
    if (match) {
        // The value is the matched stored prefix's PATH length in bytes
        // (the comm portion is always the full TASK_COMM_LEN). Use it
        // for the path-component boundary check.
        __u32 mlen = *match;

        if (mlen == path_len)
            return 0;                  // exact match, allow

        if (mlen < path_len && mlen < MAX_PATH) {
            // Mask gives the verifier a hard upper bound on the index.
            __u32 mlen_safe = mlen & (MAX_PATH - 1);
            char next = scratch->buf[mlen_safe];
            if (next == '/' || next == '\0')
                return 0;              // boundary OK, allow
        }
        // Fall through: prefix matched at the bit level but the byte
        // immediately after the matched prefix isn't a '/' or end-of-
        // path -- e.g. stored "/tmp/foo", path "/tmp/foobar". Treat as
        // no-match and deny.
    }

    bpf_printk("whitelister: BLOCK pid=%d comm=%s path=%s",
               bpf_get_current_pid_tgid() >> 32, comm, scratch->buf);
    return -1;  // -EPERM
}

char LICENSE[] SEC("license") = "GPL";
