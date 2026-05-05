// SPDX-License-Identifier: GPL-2.0
//
// Benchmark for the eBPF file-system whitelister.
//
// Measures the wall-clock latency of open()/close() against a single target
// file, repeated for a configurable number of iterations. Latencies are
// collected per-call, sorted, and summarised as min / mean / stddev /
// p50 / p90 / p99 / p999 / max.
//
// The output line is one CSV record so that the runner script can parse
// and tabulate multiple runs (baseline vs. whitelister attached, etc.).
//
// Format:
//   <label>,<iters>,<mean_ns>,<stddev_ns>,<min>,<p50>,<p90>,<p99>,<p999>,<max>
//
// The same line is also rendered to stderr in human-readable form.

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

// Compiler-only fence: emits no instructions, but forces the compiler to
// treat all memory as clobbered across this point. Without it, -O2 is free
// to hoist or sink work across clock_gettime() (it has no side-effect
// annotation visible to the optimiser via a normal libc call) and the
// measured interval would no longer bracket the open() under test.
#define COMPILER_BARRIER() __asm__ __volatile__("" ::: "memory")

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static uint64_t ts_diff_ns(struct timespec *a, struct timespec *b) {
    return (uint64_t)(b->tv_sec - a->tv_sec) * 1000000000ULL +
           (uint64_t)(b->tv_nsec - a->tv_nsec);
}

static void usage(const char *p) {
    fprintf(stderr,
            "usage: %s --file <path> --iters <N> [--label NAME] "
            "[--warmup N] [--expect-deny] [--dump <file>] [--set-comm <name>]\n"
            "\n"
            "  --file        path to open()/close() repeatedly\n"
            "  --iters       number of timed iterations (e.g. 100000)\n"
            "  --label       free-form name printed in the CSV record\n"
            "  --warmup      number of untimed warmup opens (default 1000)\n"
            "  --expect-deny treat EPERM/EACCES as success (deny-path bench)\n"
            "  --dump        write raw uint64 ns samples (binary, little-endian)\n"
            "  --set-comm    prctl(PR_SET_NAME) right before warmup, so the\n"
            "                whitelister's --comm filter only matches the timed\n"
            "                phase (not libc/ld loads at exec time)\n",
            p);
}

int main(int argc, char **argv) {
    const char *path = NULL;
    const char *label = "bench";
    const char *dump_path = NULL;
    const char *set_comm = NULL;
    long iters = 0;
    long warmup = 1000;
    int expect_deny = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        }
        if (!strcmp(argv[i], "--file") && i + 1 < argc) {
            path = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "--iters") && i + 1 < argc) {
            iters = atol(argv[++i]);
            continue;
        }
        if (!strcmp(argv[i], "--label") && i + 1 < argc) {
            label = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "--warmup") && i + 1 < argc) {
            warmup = atol(argv[++i]);
            continue;
        }
        if (!strcmp(argv[i], "--expect-deny")) {
            expect_deny = 1;
            continue;
        }
        if (!strcmp(argv[i], "--dump") && i + 1 < argc) {
            dump_path = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "--set-comm") && i + 1 < argc) {
            set_comm = argv[++i];
            continue;
        }
        fprintf(stderr, "unknown argument: %s\n", argv[i]);
        usage(argv[0]);
        return 2;
    }

    if (!path || iters <= 0) {
        usage(argv[0]);
        return 2;
    }

    uint64_t *samples = malloc((size_t)iters * sizeof(uint64_t));
    if (!samples) {
        perror("malloc");
        return 1;
    }

    // Switch comm AFTER all libc / ld.so initialisation but BEFORE the first
    // open() the bench actually measures. The whitelister filters by comm,
    // so this confines the LSM hook activity to just the warmup + timed
    // loop. Without it, every libc.so / ld.so load done by exec() would
    // hit the prefix scan too and we'd need to allow /lib /usr /etc /...
    // just to keep the bench process alive -- which would eat the entire
    // MAX_PREFIXES=8 budget and leave nothing to sweep over.
    if (set_comm) {
        if (prctl(PR_SET_NAME, set_comm, 0, 0, 0) < 0) {
            perror("prctl(PR_SET_NAME)");
            free(samples);
            return 1;
        }
    }

    // Warmup: pull pages, prime caches, settle CPU frequency.
    for (long i = 0; i < warmup; i++) {
        int fd = open(path, O_RDONLY);
        if (expect_deny) {
            // The whitelister returns -EPERM; some kernels / LSM stacks may
            // also surface EACCES. Accept either as a valid deny.
            if (fd >= 0 || (errno != EACCES && errno != EPERM)) {
                if (fd >= 0)
                    close(fd);
                fprintf(stderr,
                        "warmup: expected EACCES/EPERM, got fd=%d errno=%d (%s)\n",
                        fd, errno, strerror(errno));
                free(samples);
                return 1;
            }
        } else {
            if (fd < 0) {
                fprintf(stderr, "warmup: open(%s) failed: %s\n", path,
                        strerror(errno));
                free(samples);
                return 1;
            }
            close(fd);
        }
    }

    struct timespec t0, t1;
    for (long i = 0; i < iters; i++) {
        COMPILER_BARRIER();
        clock_gettime(CLOCK_MONOTONIC, &t0);
        COMPILER_BARRIER();
        int fd = open(path, O_RDONLY);
        COMPILER_BARRIER();
        clock_gettime(CLOCK_MONOTONIC, &t1);
        COMPILER_BARRIER();

        if (expect_deny) {
            if (fd >= 0) {
                close(fd);
                fprintf(stderr,
                        "iter %ld: expected deny but open() succeeded\n", i);
                free(samples);
                return 1;
            }
            // EACCES (LSM denial surfaces as EACCES via security_file_open),
            // EPERM (also possible). Treat both as the deny path.
            if (errno != EACCES && errno != EPERM) {
                fprintf(stderr,
                        "iter %ld: unexpected errno %d (%s)\n", i, errno,
                        strerror(errno));
                free(samples);
                return 1;
            }
        } else {
            if (fd < 0) {
                fprintf(stderr, "iter %ld: open(%s) failed: %s\n", i, path,
                        strerror(errno));
                free(samples);
                return 1;
            }
            close(fd);
        }

        samples[i] = ts_diff_ns(&t0, &t1);
    }

    // Dump raw samples *before* sorting so the plotter can show jitter
    // over the run, not just the sorted distribution.
    if (dump_path) {
        FILE *df = fopen(dump_path, "wb");
        if (!df) {
            fprintf(stderr, "warning: failed to open dump file %s: %s\n",
                    dump_path, strerror(errno));
        } else {
            size_t wrote = fwrite(samples, sizeof(uint64_t), (size_t)iters, df);
            if (wrote != (size_t)iters)
                fprintf(stderr, "warning: short write on dump file (%zu/%ld)\n",
                        wrote, iters);
            fclose(df);
        }
    }

    qsort(samples, (size_t)iters, sizeof(uint64_t), cmp_u64);

    long double sum = 0;
    for (long i = 0; i < iters; i++)
        sum += samples[i];
    long double mean = sum / iters;

    long double sq = 0;
    for (long i = 0; i < iters; i++) {
        long double d = (long double)samples[i] - mean;
        sq += d * d;
    }
    long double stddev = sqrtl(sq / iters);

    long idx_p50 = iters * 50 / 100;
    long idx_p90 = iters * 90 / 100;
    long idx_p99 = iters * 99 / 100;
    long idx_p999 = iters * 999 / 1000;
    if (idx_p999 >= iters)
        idx_p999 = iters - 1;

    uint64_t pmin = samples[0];
    uint64_t p50 = samples[idx_p50];
    uint64_t p90 = samples[idx_p90];
    uint64_t p99 = samples[idx_p99];
    uint64_t p999 = samples[idx_p999];
    uint64_t pmax = samples[iters - 1];

    // CSV on stdout for the runner.
    printf("%s,%ld,%.2Lf,%.2Lf,%lu,%lu,%lu,%lu,%lu,%lu\n", label, iters, mean,
           stddev, pmin, p50, p90, p99, p999, pmax);
    fflush(stdout);

    // Human-readable on stderr (does not pollute the parsed CSV).
    fprintf(stderr,
            "[bench:%s] iters=%ld mean=%.0Lfns stddev=%.0Lfns "
            "min=%luns p50=%luns p90=%luns p99=%luns p999=%luns max=%luns\n",
            label, iters, mean, stddev, pmin, p50, p90, p99, p999, pmax);

    free(samples);
    return 0;
}
