// SPDX-License-Identifier: GPL-2.0
//
// Compile-time configuration for the eBPF file-system whitelister.
//
// Single source of truth shared between:
//   - whitelister.bpf.c   (the BPF program, compiled with clang -target bpf)
//   - whitelister.c       (the user-space loader, compiled as ordinary C)
//   - tests/run_tests.sh  (greps MAX_COMMS out of this file at runtime)
//
// Bumping any of these is a one-line change here -- both .c files pick
// the new value up on rebuild, no further drift to chase. The constants
// drive BPF map sizes and key/struct layouts, so the loader and the BPF
// program would silently mis-key each other if the values ever fell out
// of sync. Keeping them centralised eliminates that whole class of bug.

#ifndef WHITELISTER_CONFIG_H
#define WHITELISTER_CONFIG_H

// ----- path resolution ------------------------------------------------------

// Size of the buffer passed to bpf_d_path() and used for the post-match
// boundary read. Linux PATH_MAX is 4096; 1024 covers real-world resolved
// paths comfortably while keeping the per-CPU scratch maps small.
#define MAX_PATH        1024

// ----- comm / process identity ----------------------------------------------

// Linux's task_struct::comm is char[16] (TASK_COMM_LEN in the kernel's
// include/linux/sched.h). execve() and prctl(PR_SET_NAME) silently
// truncate longer strings to 15 chars + NUL; the loader applies the
// same truncation when building map keys so a long --comm value
// matches the kernel's truncated runtime comm bit-for-bit.
#define TASK_COMM_LEN   16

// ----- LPM trie sizing ------------------------------------------------------

// LPM_TRIE caps key data at 256 bytes (LPM_DATA_SIZE_MAX in
// kernel/bpf/lpm_trie.c). 16 bytes go to the comm; the rest is what's
// available for the path-prefix portion of each --allow. The loader
// rejects any --allow longer than this with a clear error.
#define LPM_PATH_MAX    240

// ----- per-instance limits --------------------------------------------------

// How many distinct --comm values one whitelister instance can hold.
// Backed by the `configured_comms` HASH map's max_entries.
//
// Bumping this raises that map's memory footprint linearly (BPF map
// overhead means a few hundred bytes for any reasonable cap).
//
// run_tests.sh greps this file for MAX_COMMS so the negative test
// "more than MAX_COMMS distinct --comm is rejected" probes the
// correct boundary -- so this define stays grep-friendly.
#define MAX_COMMS       16

// Total number of (comm, prefix) entries across ALL configured comms.
// Backed by the `allow_prefixes` LPM_TRIE max_entries. Each entry
// costs ~270 B in the kernel, so 128 entries ~= 35 KB regardless of
// how the entries are split across comms.
#define MAX_PREFIXES    128

#endif /* WHITELISTER_CONFIG_H */
