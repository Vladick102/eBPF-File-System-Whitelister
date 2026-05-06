// SPDX-License-Identifier: GPL-2.0
//
// User-space loader for the eBPF file-system whitelister.
//
// Parses repeating groups of `--comm <name> --allow <path> [--allow <path>...]`
// flags and pushes them into the BPF maps:
//
//   configured_comms   marker set: which comms have a policy at all.
//   allow_prefixes     (comm, prefix) pairs that are explicitly allowed.
//
// Multiple --comm groups may appear on one command line, so a single
// whitelister instance enforces independent allow-lists for several
// processes simultaneously. Re-stating the same --comm later in the
// argv just continues populating the same comm's allow-list.

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "whitelister.skel.h"

// Compile-time configuration (MAX_PATH, TASK_COMM_LEN, LPM_PATH_MAX,
// MAX_COMMS, MAX_PREFIXES) is shared with the BPF program via this
// header so map keys never drift between user-space and kernel-space.
#include "whitelister_config.h"

// Mirrors `struct lpm_key` in whitelister.bpf.c. The trie matches the
// comm bytes byte-for-byte (TASK_COMM_LEN bytes / 128 bits) and then
// the path-prefix bits one at a time looking for the longest stored
// match. prefixlen is in BITS, byte-aligned in our case.
struct lpm_key {
    uint32_t prefixlen;
    char     data[TASK_COMM_LEN + LPM_PATH_MAX];
};

// Held in this loader's memory while parsing argv; pushed to BPF maps in
// one pass after parsing finishes.
struct accumulator {
    char  comms[MAX_COMMS][TASK_COMM_LEN];
    int   num_comms;
    int   allows_per_comm[MAX_COMMS];

    struct {
        int  comm_idx;
        char path[MAX_PATH];
        size_t path_len;
    } allows[MAX_PREFIXES];
    int num_allows;
};

static volatile sig_atomic_t stop;
static void sig_handler(int _) {
    (void)_;
    stop = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *fmt,
                           va_list args) {
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, fmt, args);
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s --comm <name> --allow <path> [--allow <path>...]\n"
            "          [--comm <name> --allow <path> ...]\n"
            "\n"
            "  --comm   target process name (as in task->comm). The kernel\n"
            "           truncates comm to %d-1 = %d chars + NUL, so longer\n"
            "           --comm values are truncated to match.\n"
            "  --allow  allowed path prefix; repeatable. Each --allow attaches\n"
            "           to the most-recent --comm. Up to %d entries total\n"
            "           across all comms, %d distinct comms.\n"
            "\n"
            "Example (one binary, isolated):\n"
            "  sudo %s --comm vsftpd \\\n"
            "       --allow /srv/ftp \\\n"
            "       --allow /lib --allow /lib64 --allow /usr\n"
            "\n"
            "Example (two binaries, disjoint policies):\n"
            "  sudo %s --comm probe_a --allow /srv/A \\\n"
            "          --comm probe_b --allow /srv/B\n",
            prog, TASK_COMM_LEN, TASK_COMM_LEN - 1,
            MAX_PREFIXES, MAX_COMMS, prog, prog);
}

// Truncate `name` to TASK_COMM_LEN-1 chars + NUL. Returns the index of
// the comm in acc->comms (added if new, found if already there), or -1
// if the table is full.
static int find_or_add_comm(struct accumulator *acc, const char *name) {
    char buf[TASK_COMM_LEN] = {0};
    size_t n = strnlen(name, TASK_COMM_LEN - 1);
    memcpy(buf, name, n);
    // (rest is zero-initialised; matches what prctl()/execve() set)

    for (int i = 0; i < acc->num_comms; i++) {
        if (memcmp(acc->comms[i], buf, TASK_COMM_LEN) == 0)
            return i;
    }
    if (acc->num_comms >= MAX_COMMS)
        return -1;
    memcpy(acc->comms[acc->num_comms], buf, TASK_COMM_LEN);
    return acc->num_comms++;
}

// Strip trailing slashes from `path` (except the lone "/") and copy into
// `out` up to MAX_PATH bytes. Returns the canonicalised length, or 0 on
// invalid input (empty / too long).
static size_t canonicalise_prefix(const char *path, char *out) {
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/')
        len--;
    if (len == 0 || len >= MAX_PATH)
        return 0;
    memcpy(out, path, len);
    return len;
}

int main(int argc, char **argv) {
    struct accumulator acc = {0};
    int current_comm_idx = -1;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        }
        if (!strcmp(argv[i], "--comm") && i + 1 < argc) {
            current_comm_idx = find_or_add_comm(&acc, argv[++i]);
            if (current_comm_idx < 0) {
                fprintf(stderr, "error: too many distinct --comm values "
                                "(max %d)\n",
                        MAX_COMMS);
                return 1;
            }
            continue;
        }
        if (!strcmp(argv[i], "--allow") && i + 1 < argc) {
            if (current_comm_idx < 0) {
                fprintf(stderr, "error: --allow before any --comm\n");
                usage(argv[0]);
                return 1;
            }
            if (acc.num_allows >= MAX_PREFIXES) {
                fprintf(stderr, "error: too many --allow entries "
                                "(max %d total across all --comm)\n",
                        MAX_PREFIXES);
                return 1;
            }
            const char *p = argv[++i];
            size_t plen = canonicalise_prefix(p,
                                              acc.allows[acc.num_allows].path);
            if (plen == 0) {
                fprintf(stderr, "error: bad path: %s\n", p);
                return 1;
            }
            if (plen > LPM_PATH_MAX) {
                fprintf(stderr,
                        "error: prefix too long (%zu bytes, max %d): %s\n",
                        plen, LPM_PATH_MAX, p);
                return 1;
            }
            acc.allows[acc.num_allows].comm_idx = current_comm_idx;
            acc.allows[acc.num_allows].path_len = plen;
            acc.num_allows++;
            acc.allows_per_comm[current_comm_idx]++;
            continue;
        }
        fprintf(stderr, "error: unknown argument: %s\n", argv[i]);
        usage(argv[0]);
        return 1;
    }

    if (acc.num_comms == 0) {
        fprintf(stderr, "error: at least one --comm is required\n");
        usage(argv[0]);
        return 1;
    }
    for (int i = 0; i < acc.num_comms; i++) {
        if (acc.allows_per_comm[i] == 0) {
            fprintf(stderr, "error: --comm \"%.*s\" has no --allow entries\n",
                    TASK_COMM_LEN, acc.comms[i]);
            return 1;
        }
    }

    libbpf_set_print(libbpf_print_fn);

    struct whitelister_bpf *skel = whitelister_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "error: failed to open/load BPF skeleton\n");
        fprintf(stderr, "       is BPF LSM in /sys/kernel/security/lsm?\n");
        return 1;
    }

    int comms_fd  = bpf_map__fd(skel->maps.configured_comms);
    int allows_fd = bpf_map__fd(skel->maps.allow_prefixes);

    // Push every comm marker.
    uint8_t one = 1;
    for (int i = 0; i < acc.num_comms; i++) {
        if (bpf_map_update_elem(comms_fd, acc.comms[i], &one, BPF_ANY) != 0) {
            fprintf(stderr, "error: configured_comms[%.*s]: %s\n",
                    TASK_COMM_LEN, acc.comms[i], strerror(errno));
            whitelister_bpf__destroy(skel);
            return 1;
        }
    }

    // Push every (comm, prefix) entry into the LPM trie. The prefix
    // length is in BITS: 16 bytes of NUL-padded comm always, plus the
    // path-prefix bytes. The value stores the path-prefix length (in
    // bytes) -- the BPF side reads it back to verify the path-component
    // boundary after a match.
    struct lpm_key key;
    for (int i = 0; i < acc.num_allows; i++) {
        memset(&key, 0, sizeof(key));
        size_t plen = acc.allows[i].path_len;
        key.prefixlen = (uint32_t)((TASK_COMM_LEN + plen) * 8);
        memcpy(key.data, acc.comms[acc.allows[i].comm_idx], TASK_COMM_LEN);
        memcpy(key.data + TASK_COMM_LEN, acc.allows[i].path, plen);
        uint32_t plen_bytes = (uint32_t)plen;
        if (bpf_map_update_elem(allows_fd, &key, &plen_bytes, BPF_ANY) != 0) {
            fprintf(stderr, "error: allow_prefixes[%.*s|%s]: %s\n",
                    TASK_COMM_LEN, key.data, acc.allows[i].path,
                    strerror(errno));
            whitelister_bpf__destroy(skel);
            return 1;
        }
    }

    if (whitelister_bpf__attach(skel) != 0) {
        fprintf(stderr, "error: attaching LSM program failed (errno=%d)\n",
                errno);
        fprintf(stderr, "       enable BPF LSM: add 'bpf' to lsm= on the "
                        "kernel command line and reboot\n");
        whitelister_bpf__destroy(skel);
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("[whitelister] active  comms=%d  prefixes=%d\n",
           acc.num_comms, acc.num_allows);
    for (int i = 0; i < acc.num_comms; i++) {
        printf("              comm   \"%.*s\"\n",
               TASK_COMM_LEN, acc.comms[i]);
        for (int j = 0; j < acc.num_allows; j++) {
            if (acc.allows[j].comm_idx == i)
                printf("                  allow  %.*s\n",
                       (int)acc.allows[j].path_len, acc.allows[j].path);
        }
    }
    printf("[whitelister] denials: sudo cat "
           "/sys/kernel/debug/tracing/trace_pipe\n");
    printf("[whitelister] Ctrl+C to stop\n");
    fflush(stdout);

    while (!stop)
        sleep(1);

    printf("\n[whitelister] detaching\n");
    whitelister_bpf__destroy(skel);
    return 0;
}
