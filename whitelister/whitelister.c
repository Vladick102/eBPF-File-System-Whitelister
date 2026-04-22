// SPDX-License-Identifier: GPL-2.0
//
// User-space loader for the eBPF file-system whitelister.
// Parses --comm / --allow flags, pushes them into the BPF config map, then
// attaches the LSM program. Keeps running until SIGINT/SIGTERM.

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

#define MAX_PATH 256
#define TASK_COMM_LEN 16
#define MAX_PREFIXES 8

struct config {
    char target_comm[TASK_COMM_LEN];
    uint32_t num_prefixes;
    uint32_t prefix_lens[MAX_PREFIXES];
    char prefixes[MAX_PREFIXES][MAX_PATH];
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
            "Usage: %s --comm <name> --allow <path> [--allow <path> ...]\n"
            "\n"
            "  --comm   target process name (as shown in task->comm, 15 chars "
            "max)\n"
            "  --allow  allowed path prefix (repeatable, up to %d total)\n"
            "\n"
            "Example (confining FTP to /srv/ftp):\n"
            "  sudo %s --comm vsftpd \\\n"
            "       --allow /srv/ftp \\\n"
            "       --allow /lib --allow /lib64 --allow /usr \\\n"
            "       --allow /etc --allow /proc --allow /dev\n",
            prog, MAX_PREFIXES, prog);
}

int main(int argc, char **argv) {
    struct config cfg = {};

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        }
        if (!strcmp(argv[i], "--comm") && i + 1 < argc) {
            strncpy(cfg.target_comm, argv[++i], TASK_COMM_LEN - 1);
            continue;
        }
        if (!strcmp(argv[i], "--allow") && i + 1 < argc) {
            if (cfg.num_prefixes >= MAX_PREFIXES) {
                fprintf(stderr, "error: too many --allow (max %d)\n",
                        MAX_PREFIXES);
                return 1;
            }
            const char *p = argv[++i];
            size_t len = strlen(p);
            while (len > 1 && p[len - 1] == '/')
                len--;
            if (len == 0 || len >= MAX_PATH) {
                fprintf(stderr, "error: bad path length: %s\n", p);
                return 1;
            }
            memcpy(cfg.prefixes[cfg.num_prefixes], p, len);
            cfg.prefix_lens[cfg.num_prefixes] = (uint32_t)len;
            cfg.num_prefixes++;
            continue;
        }
        fprintf(stderr, "error: unknown argument: %s\n", argv[i]);
        usage(argv[0]);
        return 1;
    }

    if (cfg.target_comm[0] == '\0') {
        fprintf(stderr, "error: --comm is required\n");
        usage(argv[0]);
        return 1;
    }
    if (cfg.num_prefixes == 0) {
        fprintf(stderr, "error: at least one --allow is required\n");
        usage(argv[0]);
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    struct whitelister_bpf *skel = whitelister_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "error: failed to open/load BPF skeleton\n");
        fprintf(stderr, "       is BPF LSM in /sys/kernel/security/lsm?\n");
        return 1;
    }

    uint32_t key = 0;
    int map_fd = bpf_map__fd(skel->maps.config_map);
    if (bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY) != 0) {
        fprintf(stderr, "error: updating config map: %s\n", strerror(errno));
        whitelister_bpf__destroy(skel);
        return 1;
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

    printf("[whitelister] active  comm=\"%s\"  prefixes=%u\n", cfg.target_comm,
           cfg.num_prefixes);
    for (uint32_t i = 0; i < cfg.num_prefixes; i++)
        printf("              allow  %s\n", cfg.prefixes[i]);
    printf("[whitelister] denials: sudo cat "
           "/sys/kernel/debug/tracing/trace_pipe\n");
    printf("[whitelister] Ctrl+C to stop\n");

    while (!stop)
        sleep(1);

    printf("\n[whitelister] detaching\n");
    whitelister_bpf__destroy(skel);
    return 0;
}
