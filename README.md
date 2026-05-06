# eBPF File System Whitelister

Whitelist file-system access for one or more named applications using **eBPF**
attached to the **`lsm/file_open`** Linux Security Module hook. The primary
use case is to pin an application (e.g. `vsftpd`) to a specific set of
directories: any `open(2)` it makes whose resolved path is not under one
of the configured allow-prefixes is denied by the kernel with `EACCES`,
regardless of how the application got there (symlinks, relative paths,
in-process backdoors, etc.).

A single whitelister instance can hold **independent allow-lists for
multiple processes simultaneously** — e.g. one set of directories for
`vsftpd` and a disjoint set for `sshd` — keyed on the kernel's
`task_struct::comm` (15 chars + NUL).

## Layout

| Directory          | Purpose                                                                 |
| ------------------ | ----------------------------------------------------------------------- |
| [`advanced_hello/`](advanced_hello/) | A small CO-RE / `libbpf` "hello world" that traces `sys_enter_openat`. Useful as a reference for the toolchain and as a smoke test that BPF works on this kernel. |
| [`whitelister/`](whitelister/)       | The actual enforcer: an LSM BPF program plus its user-space loader. |
| [`whitelister/tests/`](whitelister/tests/) | Integration test suite (multi-comm isolation, bypass, path-component boundary, CLI validation). |
| [`whitelister/bench/`](whitelister/bench/) | A microbenchmark suite that measures the per-`open()` overhead vs. allow-list size and produces plots. |

## Prerequisites

- Linux ≥ 5.7 with `CONFIG_BPF_LSM=y` (Ubuntu 22.04+ ships this).
- `bpf` listed in `/sys/kernel/security/lsm`. If it is not there, append it
  to `lsm=` on the kernel command line (GRUB) and reboot. The
  [`whitelister/setup.sh check`](whitelister/setup.sh) helper detects this
  and prints the exact edit for your system.
- Root (`CAP_BPF` + `CAP_SYS_ADMIN`) at load time.
- Toolchain: `clang`, `llvm`, `libbpf-dev`, `libelf-dev`, `zlib1g-dev`,
  `linux-tools-common`, `linux-headers-$(uname -r)`,
  `linux-tools-$(uname -r)`.

`setup.sh deps` installs all of these via `apt`.

## Quick start

```bash
cd whitelister
sudo ./setup.sh all     # apt deps + LSM check + build + demo files
```

Or step by step:

```bash
sudo ./setup.sh deps
     ./setup.sh check
     ./setup.sh build
sudo ./setup.sh demo
```

That leaves a runnable demo under `/tmp/ftp_whitelist_demo/` and a fake
`ftp` reader at `/tmp/ftp`, with the exact commands to try printed to the
terminal.

### Confining a single process

```bash
sudo ./build/whitelister --comm ftp \
     --allow /tmp/ftp_whitelist_demo/allowed \
     --allow /tmp/ftp \
     --allow /lib --allow /lib64 --allow /usr \
     --allow /etc --allow /proc --allow /dev
```

### Confining multiple processes from one loader

```bash
sudo ./build/whitelister \
     --comm vsftpd  --allow /srv/ftp --allow /lib --allow /usr \
     --comm sshd    --allow /etc/ssh --allow /var/log/auth.log
```

Each comm sees only its own allow-list; `vsftpd` cannot reach `/etc/ssh`
and `sshd` cannot reach `/srv/ftp`. Processes whose comm is **not**
listed are unaffected by the whitelister.

Denials are logged via `bpf_printk`:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

See [whitelister/README.md](whitelister/README.md) for the full enforcer
documentation and limits (compile-time: 16 distinct comms, 128 prefixes
total, 1024-byte path).

## Architecture & lookup model

The BPF program holds two flat hash maps:

| Map                | Type        | Key                                       | Purpose                                      |
| ------------------ | ----------- | ----------------------------------------- | -------------------------------------------- |
| `configured_comms` | `HASH`      | `char[16]`                                | Set: which comms have any policy at all.     |
| `allow_prefixes`   | `HASH`      | `(char comm[16], char path[1024])`        | Allowed `(process, prefix)` pairs.           |

On every `open()` the LSM hook does:

1. Read `task->comm` via `bpf_get_current_comm()`.
2. Look up `configured_comms[comm]` (`O(1)`). If absent → return 0
   (the open proceeds; this comm has no policy).
3. Resolve the absolute path with `bpf_d_path()`.
4. Walk the resolved path's component chain in descending length order
   (`/srv/ftp/file.txt` → `/srv/ftp` → `/srv` → `/`) and probe each
   step in `allow_prefixes`. First hit → allow. No hit by `/` → deny
   (`-EPERM` ⇒ `EACCES` to userspace).

Cost is `O(D)` where `D` is the path's depth (typically 5–10), and
**independent of how many `--allow` entries** the loader pushed in. This
replaces an earlier linear-scan implementation whose cost grew with `N`;
the bench shows the difference directly via the `slope: X ns/entry`
annotation in its plot legends.

## Tests

Integration tests live in [`whitelister/tests/`](whitelister/tests/) and
cover the policy contract: multi-comm isolation, unconfigured-comm
bypass, path-component boundary semantics, single-comm backward compat,
comm truncation to 15 chars, and CLI validation (`--allow` before
`--comm`, exceeding `MAX_COMMS`).

```bash
cd whitelister
sudo ./tests/run_tests.sh -v
```

Returns 0 if every case passes, non-zero on any failure.

## Benchmarks

The bench quantifies per-`open()` cost against allow-list size and
saves two plots.

### Scenarios

1. **baseline** — no whitelister attached. Pure VFS `open()` cost.
2. **comm-miss** — whitelister loaded with `--comm <some_other_name>`
   so the bench process is unconfigured. The hook reads `comm`, finds
   it not in `configured_comms`, and bypasses immediately. This
   measures the cost the LSM hook imposes on every *unrelated*
   process on the system.
3. **comm-hit, allow** — whitelister configured with the bench's own
   comm, allow-list of size N includes the target file. Hash-walk
   ends in a hit.
4. **comm-hit, deny** — same comm match, but the target file is
   under no `--allow` prefix. Hash-walk reaches `/` without a hit;
   the kernel returns `EACCES`.

The bench process flips its own comm via `prctl(PR_SET_NAME)` *after*
all libc / ld.so loads, so the LSM hook only matches the warmup +
timed phase. That keeps the allow-list available exclusively for
the actual sweep instead of being eaten by `/lib`, `/usr`, etc.

### Building and running

```bash
# 1. build the whitelister itself (one-time)
cd whitelister
sudo ./setup.sh deps     # if you have not already
     ./setup.sh check
     ./setup.sh build

# 2. build and run the bench (script needs sudo for the loader)
sudo ./bench/run_bench.sh
```

### Knobs

| Variable | Default       | Meaning                                         |
| -------- | ------------- | ----------------------------------------------- |
| `ITERS`  | `10000`       | Timed `open()/close()` pairs per single run.    |
| `WARMUP` | `1000`        | Untimed warmup opens, primes caches and DVFS.   |
| `REPEATS`| `30`          | Independent runs per `(scenario, N)` cell. Per-run p50 is taken first, then aggregated mean ± stddev across repeats. |
| `NS`     | `1 5 10…100`  | Allow-list sizes to sweep.                      |
| `NO_PLOT`| unset         | If `1`, skip plotting; raw CSV is written either way. |
| `PYTHON` | `python`      | Interpreter for `plot.py` (must have `numpy` + `matplotlib`). |

```bash
sudo REPEATS=50 NS="1 10 20 30" ./bench/run_bench.sh
```

### Output

| File                                     | Contents                                                         |
| ---------------------------------------- | ---------------------------------------------------------------- |
| `bench/build/sweep.csv`                  | One row per `(scenario, N)`: `mean_p50_ns`, `stddev_p50_ns`, `min`, `max`. |
| `bench/build/whitelister.log`            | Loader stdout/stderr from the most recent BPF attach.            |
| `bench/build/plots/latency_vs_allowlist.png` | Median latency per scenario as a function of N, with ±1σ band and per-line slope annotation in the legend. |
| `bench/build/plots/overhead_vs_allowlist.png` | `(scenario_p50 − baseline_p50)` vs. N. Same band/slope treatment. |

#### Reading the plots

Each line in the legend is annotated with its linear-fit slope:
`[+0.0 ns/entry]` means cost is constant in N (the new hashmap-walk
regime), `[+50 ns/entry]` would indicate a linear-scan policy where
each added prefix costs another comparison. The intent of the bench
is to read this number directly: under the current architecture,
`comm-hit, allow` and `comm-hit, deny` should both pin near zero.

Re-render plots without re-collecting data:

```bash
python whitelister/bench/plot.py --build-dir whitelister/bench/build
```

`sudo` resets `PATH` by default, so a venv-activated shell will not
propagate; pass the venv interpreter explicitly with `PYTHON=` (or use
`sudo -E`):

```bash
sudo PYTHON=~/.venv/bin/python ./bench/run_bench.sh
```

### What the benchmark does *not* cover

- Microbenchmark per-`open()` latency only. Production workloads pay
  this on real `open()` syscalls; the hook does **not** intercept
  `read`/`write` on already-open file descriptors.
- It does not test multi-threaded contention. LSM hooks run in the
  caller's task context, so per-`open()` cost is what scales.
- The `comm`-miss scenario reflects the cost every *non-target*
  process on the system pays once a whitelister is loaded.
