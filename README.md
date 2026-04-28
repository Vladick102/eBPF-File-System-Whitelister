# eBPF File System Whitelister

Whitelist file-system access for a named application using **eBPF** attached
to the **`lsm/file_open`** Linux Security Module hook. The primary use case is
to pin an application (such as `vsftpd`) to a specific set of directories: any
`open(2)` it makes whose resolved path is not under one of the configured
allow-prefixes is denied by the kernel with `EACCES`, regardless of how the
application got there (symlinks, relative paths, in-process backdoors, etc.).

## Layout

| Directory          | Purpose                                                                 |
| ------------------ | ----------------------------------------------------------------------- |
| [`advanced_hello/`](advanced_hello/) | A small CO-RE / `libbpf` "hello world" that traces `sys_enter_openat`. Useful as a reference for the toolchain and as a smoke test that BPF works on this kernel. |
| [`whitelister/`](whitelister/)       | The actual enforcer: an LSM BPF program plus its user-space loader. |
| [`whitelister/bench/`](whitelister/bench/) | A microbenchmark suite that measures the per-`open()` overhead of the whitelister against a no-BPF baseline. |

## Prerequisites

- Linux ≥ 5.7 with `CONFIG_BPF_LSM=y` (Ubuntu 22.04+ ships this).
- `bpf` listed in `/sys/kernel/security/lsm`. If it is not there, append it
  to `lsm=` on the kernel command line (GRUB) and reboot. The
  [`whitelister/setup.sh check`](whitelister/setup.sh) helper detects this
  and prints the exact edit for your system.
- Root (`CAP_BPF` + `CAP_SYS_ADMIN`) at load time.
- Toolchain: `clang`, `llvm`, `libbpf-dev`, `libelf-dev`, `zlib1g-dev`,
  `bpftool`, `linux-headers-$(uname -r)`.

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
`ftp` reader binary at `/tmp/ftp`, with the exact commands to try printed
to the terminal. A typical confinement:

```bash
sudo ./build/whitelister --comm ftp \
     --allow /tmp/ftp_whitelist_demo/allowed \
     --allow /tmp/ftp \
     --allow /lib --allow /lib64 --allow /usr \
     --allow /etc --allow /proc --allow /dev
```

Denials are logged via `bpf_printk`:

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

See [whitelister/README.md](whitelister/README.md) for the full enforcer
documentation.

## Benchmarks

The benchmark suite quantifies the cost of the LSM hook on `open()` latency.
It exercises three things that matter independently:

1. **Baseline** — no BPF program attached. This is the raw VFS+filesystem
   `open()` cost on the host.
2. **BPF attached, `comm` miss** — the program is loaded but the bench
   process's `task->comm` does not match `--comm`, so the program returns
   from the early-out branch (LSM dispatch + `bpf_get_current_comm` + comm
   compare).
3. **BPF attached, `comm` hit, allow path** — the path is allowed, so the
   program walks the full hot path: `bpf_d_path()` to materialise the
   absolute path, then a linear prefix scan over the allow list.
4. **BPF attached, `comm` hit, deny path** — the path is *not* allowed, so
   the program returns `-EPERM` and the kernel surfaces `EACCES` to the
   caller.

The benchmark binary opens its target file from a process whose `comm`
is set (via a symlinked filename) to `wlbench_target`, so it fits within
the 15-byte `task->comm` limit and matches reliably across runs.

### Building and running

```bash
# 1. build the whitelister itself (one-time)
cd whitelister
sudo ./setup.sh deps     # if you have not already
     ./setup.sh check
     ./setup.sh build

# 2. build and run the bench (this script needs sudo for the loader)
cd bench
sudo ./run_bench.sh
```

Knobs (environment variables):

| Variable | Default | Meaning                                |
| -------- | ------- | -------------------------------------- |
| `ITERS`  | `50000` | Number of timed `open()`/`close()` pairs per scenario. |
| `WARMUP` | `2000`  | Untimed warmup opens before each scenario, to prime caches and CPU frequency. |

Example:

```bash
sudo ITERS=200000 WARMUP=5000 ./run_bench.sh
```

### Output

The script prints two tables: one with the per-scenario distribution
(mean, stddev, p50/p90/p99/max in nanoseconds), and a second showing the
mean overhead of each scenario relative to the baseline, both as an
absolute delta (`Δ ns`) and as a multiplicative factor (`× baseline`).

Per-run artefacts under `whitelister/bench/build/`:

| File                          | Contents                                              |
| ----------------------------- | ----------------------------------------------------- |
| `results.csv`                 | Summary stats: `label,iters,mean,stddev,min,p50,p90,p99,p999,max` (ns). |
| `raw_<scenario>.bin`          | Raw per-iteration latency samples (`uint64` ns, little-endian, insertion order). |
| `whitelister.log`             | stdout/stderr of the loader for the most recent scenario. |
| `plots/*.png`                 | Plots produced from the CSV + raw data (see below).   |

### Plots

After all scenarios finish, the runner generates a set of PNG plots under
`whitelister/bench/build/plots/`:

| File                              | What it shows                                                            |
| --------------------------------- | ------------------------------------------------------------------------ |
| `latency_summary.png`             | Mean per scenario as bars (whiskers = 1 stddev), with p50/p90/p99 markers overlaid. |
| `overhead_vs_baseline.png`        | Two panels: added latency over baseline (Δ ns) and the ratio (× baseline). |
| `latency_cdf.png`                 | CDF of per-`open()` latency across all scenarios on the same axes, with a tail-zoom inset (p90 → p100, log-scaled). |
| `latency_distribution.png`        | Violin plot of each scenario's distribution (clipped at 1.5 × p99) with median, mean, and p99 markers. |
| `jitter_timeline.png`             | Latency per iteration over the run, one panel per scenario (downsampled if huge). |

The plotter (`bench/plot.py`) needs `numpy` and `matplotlib`. The runner
calls whatever `python` resolves to (override with `PYTHON=...`) and
expects the modules to already be importable; if not, the plot step is
skipped with a warning and the raw data is left in `build/` for you to
plot yourself.

Set `NO_PLOT=1` to skip plotting entirely. Pick a different interpreter
with `PYTHON`:

```bash
sudo NO_PLOT=1 ./run_bench.sh
sudo PYTHON=/path/to/python ./run_bench.sh
```

Note: `sudo` resets `PATH` by default, so a `venv`-activated shell will
not propagate; pass the venv interpreter explicitly with `PYTHON=` (or
use `sudo -E`).

You can also re-plot from the raw data without re-running the bench:

```bash
python plot.py --build-dir build
```

### Path-length sweep

`run_bench.sh` measures the four scenarios at one fixed path. To see how
the BPF overhead scales with the *length* of the path that the kernel
hands to the LSM hook, use the sweep script:

```bash
sudo ./sweep.sh -v          # writes build/sweep.csv and build/plots/sweep_path_length.png
```

It runs each scenario across a range of target-path lengths
(`LENGTHS=64 128 192 ... 960` by default, override with the env var)
and produces a single multi-line chart: x = path length in bytes,
y = **median** `open()` latency, one line per scenario.

Why median, not mean: at this scale a single tail spike (scheduler
preemption, page-cache miss) can shift `mean ± stddev` bands by tens of
microseconds and swamp the actual signal. The median is robust to those
outliers and shows the trend a target process actually feels per call.

Expected shape: `baseline` and `bpf_comm_miss` stay nearly flat (no
path resolution, no prefix scan), while `bpf_comm_hit_allow` and
`bpf_deny` rise roughly linearly because `bpf_d_path()` walks the
dentry chain proportional to path length, and the prefix-compare loop
does the same.

> **Heads-up:** the sweep needs the larger `MAX_PATH=1024` BPF buffer
> introduced in `whitelister.bpf.c`. If you upgraded from an earlier
> version (`MAX_PATH=256`), rebuild the loader before running:
>
> ```bash
> sudo make -C whitelister clean && sudo make -C whitelister
> ```

To re-plot just the sweep without re-collecting data:

```bash
python plot.py --sweep --build-dir build
```

### What the benchmark does *not* cover

- It measures **microbenchmark** open-call latency on a single warm file.
  Production workloads pay this cost only on real `open()` syscalls; the
  hook does **not** intercept `read`/`write` on already-open file
  descriptors.
- It does not test multi-threaded contention. Real LSM enforcement runs
  in the calling task's context, so per-`open()` cost is what scales.
- The `comm`-miss path is reported as a separate scenario because it is
  what every *non-target* process on the system pays once the program
  is loaded.
