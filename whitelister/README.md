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
- `whitelister.c` — libbpf loader; pushes config into a BPF map and attaches.
- `Makefile` — builds both.
- `setup.sh` — one script for install / check / build / demo.

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

The binary is built out-of-source into `build/whitelister`:

```
sudo ./build/whitelister --comm <process_name> --allow <path> [--allow <path> ...]
```

- `--comm` matches Linux's 16-byte `task->comm` (same as `ps -o comm`).
- `--allow` is a path prefix; pass one per directory. Up to 8.

Real FTP example (vsftpd chroot'd to `/srv/ftp`):

```bash
sudo ./build/whitelister --comm vsftpd \
     --allow /srv/ftp \
     --allow /lib --allow /lib64 --allow /usr \
     --allow /etc --allow /proc --allow /dev
```

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
