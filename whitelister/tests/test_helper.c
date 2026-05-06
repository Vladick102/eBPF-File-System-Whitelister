// SPDX-License-Identifier: GPL-2.0
//
// Single-shot policy probe used by run_tests.sh. Sets the running process's
// comm via prctl(PR_SET_NAME) so the test harness can simulate arbitrary
// process identities, opens the requested file, and asserts that the
// outcome matches the expectation.
//
// Why prctl: TASK_COMM_LEN is 16 in the kernel, so the comm field is a
// 15-char-plus-NUL string sourced from the binary's basename at exec
// time. We can't change the binary name per-call, but we *can* re-write
// task->comm at runtime; the whitelister's policy lookup reads
// task->comm via bpf_get_current_comm() at the moment of file_open(),
// so flipping it just before open() is sufficient to impersonate any
// (truncated) comm.
//
// Exit codes:
//   0  outcome matched expectation
//   1  outcome did NOT match (open succeeded when deny was expected, or
//      vice versa; or open failed with an unexpected errno)
//   2  argument or system error

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

static void usage(const char *prog) {
    fprintf(stderr,
            "usage: %s --comm <name> --file <path> --expect <allow|deny>\n",
            prog);
}

int main(int argc, char **argv) {
    const char *comm = NULL;
    const char *file = NULL;
    const char *expect = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--comm") && i + 1 < argc) {
            comm = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "--file") && i + 1 < argc) {
            file = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "--expect") && i + 1 < argc) {
            expect = argv[++i];
            continue;
        }
        if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        }
        fprintf(stderr, "unknown argument: %s\n", argv[i]);
        usage(argv[0]);
        return 2;
    }

    if (!comm || !file || !expect) {
        usage(argv[0]);
        return 2;
    }
    int expect_allow = !strcmp(expect, "allow");
    int expect_deny  = !strcmp(expect, "deny");
    if (!expect_allow && !expect_deny) {
        fprintf(stderr, "--expect must be 'allow' or 'deny', got '%s'\n", expect);
        return 2;
    }

    // Flip comm AFTER all libc / ld.so loads have already happened. The
    // whitelister will only start matching us by the new comm from this
    // syscall onward, which is exactly the open() we're about to issue.
    if (prctl(PR_SET_NAME, comm, 0, 0, 0) < 0) {
        perror("prctl(PR_SET_NAME)");
        return 2;
    }

    int fd = open(file, O_RDONLY);
    int allowed = (fd >= 0);
    int saved_errno = errno;
    if (allowed)
        close(fd);

    if (expect_allow && allowed)
        return 0;
    if (expect_deny && !allowed && (saved_errno == EACCES || saved_errno == EPERM))
        return 0;

    // Mismatch -- report what actually happened so the test runner can
    // surface a useful failure line.
    const char *got;
    if (allowed)
        got = "allow";
    else if (saved_errno == EACCES || saved_errno == EPERM)
        got = "deny";
    else
        got = "error";

    fprintf(stderr, "[mismatch] comm=%s file=%s expected=%s got=%s",
            comm, file, expect, got);
    if (!allowed)
        fprintf(stderr, " errno=%d (%s)", saved_errno, strerror(saved_errno));
    fprintf(stderr, "\n");
    return 1;
}
