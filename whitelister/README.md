# whitelister — eBPF LSM-based FS access control

Attaches a BPF program to the **`lsm/file_open`** hook. For any `open(2)` /
`openat(2)` whose calling task has `comm == <target>`, the program resolves
the file's kernel path via `bpf_d_path()` and returns `-EPERM` unless that
path starts with one of the configured allowed prefixes.

Because this runs inside an LSM hook in the kernel, an in-process backdoor
cannot avoid it: the check fires on the *resulting struct file*, after any
path manipulation by the application itself.

## Files

- `whitelister.bpf.c` — the LSM BPF program (runs in the kernel).
- `whitelister.c` — libbpf loader; pushes config into BPF maps and attaches.
- `Makefile` — builds both.
- `setup.sh` — one script for install / check / build / demo.
- `tests/` — integration test suite (sudo `./tests/run_tests.sh`).
- `bench/` — open()/close() microbenchmark and plotting.

## Prerequisites

- Linux kernel with `CONFIG_BPF_LSM=y` (Ubuntu 22.04+, kernel ≥ 5.7).
- `bpf` must be present in `/sys/kernel/security/lsm`. If it is not, add it
  to the kernel command line (see `setup.sh check` — it prints the exact
  GRUB edit for your system).
- Root privileges at load time (`CAP_BPF` + `CAP_SYS_ADMIN`).

## Quick start

```bash
cd whitelister
sudo ./setup.sh all     # deps + check + build + demo
```

Or step by step:

```bash
sudo ./setup.sh deps    # apt install toolchain
     ./setup.sh check   # verify BPF LSM is active
     ./setup.sh build   # clang + bpftool + link
sudo ./setup.sh demo    # lay down demo files
```

## Usage

The binary is built out-of-source into `build/whitelister`. One invocation
can hold policies for multiple processes simultaneously — flags are read
left-to-right and each `--allow` attaches to the most-recent `--comm`:

```
sudo ./build/whitelister \
     --comm <name_A> --allow <path> [--allow <path> ...] \
     [--comm <name_B> --allow <path> ...]
```

- `--comm` matches Linux's `task->comm` field. **Why 15 chars + NUL:**
  `task_struct::comm` in the kernel is `char[16]` (`TASK_COMM_LEN = 16`,
  see `include/linux/sched.h`). `execve()` sources it from the binary's
  basename and `prctl(PR_SET_NAME, ...)` updates it at runtime; both
  silently truncate longer strings to 15 chars + NUL. The loader applies
  the same truncation to `--comm` values so the BPF-side comm key matches
  the kernel's truncated runtime value bit-for-bit.
- `--allow` is a path prefix; repeatable. Each prefix matches on path-
  component boundaries: `--allow /tmp/foo` allows `/tmp/foo` and
  `/tmp/foo/x` but **not** `/tmp/foobar`.
- A process whose comm is **not** in any `--comm` group bypasses the
  whitelister entirely. Only configured comms are enforced.

Limits (compile-time, in `whitelister.bpf.c`): 16 distinct `--comm`
values, 128 `--allow` entries total across all comms, 1024-byte path
prefix length.

### Single-binary example (vsftpd chroot'd to `/srv/ftp`):

```bash
sudo ./build/whitelister --comm vsftpd \
     --allow /srv/ftp \
     --allow /lib --allow /lib64 --allow /usr \
     --allow /etc --allow /proc --allow /dev
```

### Multi-binary example (independent policies):

```bash
sudo ./build/whitelister \
     --comm vsftpd  --allow /srv/ftp --allow /lib --allow /usr \
     --comm sshd    --allow /etc/ssh --allow /var/log/auth.log
```

Each comm only sees its own allow-list; vsftpd cannot reach
`/etc/ssh` and sshd cannot reach `/srv/ftp` even though both policies
are loaded by the same whitelister instance. Anything else
(comm not listed) is unaffected.

## Lookup model

The BPF program holds two flat hash maps:

- `configured_comms` — set of comms with a policy. Lookup `O(1)`; if the
  current comm is absent, the hook returns immediately and the open
  proceeds unchanged.
- `allow_prefixes` — `(comm, path)` → marker. For an open, the program
  walks the resolved path's component chain in descending length order
  (`/srv/ftp/file.txt` → `/srv/ftp` → `/srv` → `/`) and probes each
  step in this map. First hit allows; no hit by the time the walk
  reaches `/` denies. Cost is `O(D)` where `D` is path depth (~5–10 in
  practice), independent of how many entries are configured.

Denials are logged via `bpf_printk`:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## What gets enforced

- The hook sees the *resolved* path (`dentry` → full path). Symlink-jumping
  and relative-path tricks cannot escape it.
- The decision is kernel-side. A backdoor built into the daemon (e.g. a
  compromised vsftpd that tries to `open("/etc/shadow")`) receives EPERM
  from the kernel, regardless of what code path led there.
- DAC (file mode/uid) still applies first. BPF LSM can only *further*
  restrict, never grant access.
