#!/usr/bin/env python
"""Plot the eBPF whitelister benchmark results.

Reads build/sweep.csv produced by run_bench.sh -- one row per
(scenario, allow-list size) pair, with mean and stddev computed over
REPEATS independent bench_open invocations -- and emits two plots that
show how per-open() latency scales with the number of allow-list entries.

Inputs:
  build/sweep.csv   columns: scenario, n_prefixes, repeats,
                             mean_p50_ns, stddev_p50_ns,
                             min_p50_ns, max_p50_ns

Outputs (under build/plots/):
  latency_vs_allowlist.png    median latency vs N, one line per scenario,
                              shaded +/- 1 stddev band of run-medians
  overhead_vs_allowlist.png   delta over baseline vs N, one line per
                              non-baseline scenario, with combined error band

Usage:
  python plot.py [--build-dir DIR] [--out DIR]
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# Same palette as before so figures are visually consistent across the
# project's reports.
SCENARIO_COLORS = {
    "baseline":             "#1f77b4",  # blue   - VFS only
    "bpf_comm_miss":        "#2ca02c",  # green  - early-out path
    "bpf_comm_hit_allow":   "#ff7f0e",  # orange - allow path (full scan)
    "bpf_deny":             "#d62728",  # red    - full deny path
}

SCENARIO_PRETTY = {
    "baseline":             "baseline (no BPF)",
    "bpf_comm_miss":        "BPF: comm-miss",
    "bpf_comm_hit_allow":   "BPF: comm-hit, allow",
    "bpf_deny":             "BPF: comm-hit, deny",
}

SCENARIO_ORDER = [
    "baseline",
    "bpf_comm_miss",
    "bpf_comm_hit_allow",
    "bpf_deny",
]


def pretty(label: str) -> str:
    return SCENARIO_PRETTY.get(label, label)


def color(label: str, fallback_idx: int = 0) -> str:
    if label in SCENARIO_COLORS:
        return SCENARIO_COLORS[label]
    cycle = plt.rcParams["axes.prop_cycle"].by_key()["color"]
    return cycle[fallback_idx % len(cycle)]


def setup_style() -> None:
    plt.rcParams.update({
        "figure.dpi":           120,
        "savefig.dpi":          200,
        "savefig.bbox":         "tight",
        "font.family":          "DejaVu Sans",
        "font.size":            11,
        "axes.titlesize":       13,
        "axes.titleweight":     "semibold",
        "axes.labelsize":       11,
        "axes.spines.top":      False,
        "axes.spines.right":    False,
        "axes.grid":            True,
        "axes.axisbelow":       True,
        "grid.linestyle":       "-",
        "grid.color":           "#e6e6e6",
        "grid.linewidth":       0.7,
        "legend.frameon":       False,
        "legend.fontsize":      10,
        "xtick.color":          "#444444",
        "ytick.color":          "#444444",
    })


def fmt_ns(ax, axis: str = "x") -> None:
    """Format a ns axis as either ns or us depending on magnitude."""
    def _fmt(v, _pos):
        if v >= 1000:
            return f"{v/1000:.1f} us"
        return f"{int(v)} ns"
    target = ax.xaxis if axis == "x" else ax.yaxis
    target.set_major_formatter(mticker.FuncFormatter(_fmt))


def load(build_dir: Path) -> dict[str, list[tuple[int, float, float, float, float]]]:
    """Read sweep.csv. Returns scenario -> sorted list of
    (n_prefixes, mean_p50, stddev_p50, min_p50, max_p50)."""
    csv_path = build_dir / "sweep.csv"
    if not csv_path.is_file():
        sys.exit(f"error: {csv_path} not found -- run run_bench.sh first")

    by: dict[str, list[tuple[int, float, float, float, float]]] = defaultdict(list)
    with csv_path.open() as f:
        for row in csv.DictReader(f):
            by[row["scenario"]].append((
                int(row["n_prefixes"]),
                float(row["mean_p50_ns"]),
                float(row["stddev_p50_ns"]),
                float(row["min_p50_ns"]),
                float(row["max_p50_ns"]),
            ))
    if not by:
        sys.exit(f"error: {csv_path} contains no rows")
    for k in by:
        by[k].sort(key=lambda r: r[0])
    return dict(by)


def ordered(scenarios) -> list[str]:
    out = [s for s in SCENARIO_ORDER if s in scenarios]
    for s in scenarios:
        if s not in out:
            out.append(s)
    return out


def plot_latency(by: dict, out: Path) -> None:
    """Latency vs allow-list size, one line per scenario, +/-stddev band.

    Same line-plot aesthetic as the project's other multi-scenario plots:
    shared palette, labelled markers, frameless legend in the top-left,
    nanosecond auto-scaling on the y-axis.
    """
    fig, ax = plt.subplots(figsize=(11, 6))

    for i, scenario in enumerate(ordered(by)):
        rows = by[scenario]
        xs   = np.array([r[0] for r in rows])
        ys   = np.array([r[1] for r in rows])
        sds  = np.array([r[2] for r in rows])
        c = color(scenario, i)

        # +/-1 stddev band of run-medians: shows cross-run variance after
        # the per-run p50 already collapsed within-run jitter. Soft alpha
        # keeps the central line readable when bands overlap.
        ax.fill_between(xs, ys - sds, ys + sds, color=c,
                        alpha=0.15, linewidth=0, zorder=2)
        ax.plot(xs, ys, marker="o", linewidth=2.0, markersize=5.5,
                color=c, label=pretty(scenario), zorder=3)

    ax.set_xlabel("Allow-list size (number of prefixes)")
    ax.set_ylabel("Median open()/close() latency")
    ax.set_title("eBPF whitelister - latency vs. allow-list size")
    fmt_ns(ax, "y")

    # y starts at 0 so absolute BPF overhead is visible at a glance.
    ax.set_ylim(bottom=0)
    ax.legend(loc="upper left", title=None)

    all_xs = sorted({r[0] for rows in by.values() for r in rows})
    if all_xs:
        ax.set_xticks(all_xs)

    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"[plot] wrote {out}")


def plot_overhead(by: dict, out: Path) -> None:
    """(scenario_p50 - baseline_p50) vs allow-list size.

    Error band combines per-scenario and baseline variance:
        sigma_delta = sqrt(sigma_scenario^2 + sigma_baseline^2)
    so it reflects the uncertainty in the *difference*, not in either
    point alone.
    """
    if "baseline" not in by:
        print("[plot] no baseline scenario; skipping overhead", file=sys.stderr)
        return
    base = {n: (mean, sd) for n, mean, sd, *_ in by["baseline"]}

    others = [s for s in ordered(by) if s != "baseline"]
    if not others:
        print("[plot] no non-baseline scenarios; skipping overhead", file=sys.stderr)
        return

    fig, ax = plt.subplots(figsize=(11, 6))

    for i, scenario in enumerate(others):
        rows = by[scenario]
        xs  = np.array([r[0] for r in rows])
        ys  = np.array([r[1] - base[r[0]][0] for r in rows])
        sds = np.array([np.hypot(r[2], base[r[0]][1]) for r in rows])
        c = color(scenario, i + 1)

        ax.fill_between(xs, ys - sds, ys + sds, color=c,
                        alpha=0.15, linewidth=0, zorder=2)
        ax.plot(xs, ys, marker="o", linewidth=2.0, markersize=5.5,
                color=c, label=pretty(scenario), zorder=3)

    ax.axhline(0, color="#888", linewidth=1, zorder=1)

    base_p50 = next(iter(base.values()))[0]
    ax.set_xlabel("Allow-list size (number of prefixes)")
    ax.set_ylabel(f"Latency added over baseline ({base_p50:.0f} ns)")
    ax.set_title("eBPF whitelister - overhead vs. allow-list size")
    fmt_ns(ax, "y")
    ax.legend(loc="upper left", title=None)

    all_xs = sorted({r[0] for rows in by.values() for r in rows})
    if all_xs:
        ax.set_xticks(all_xs)

    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"[plot] wrote {out}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    here = Path(__file__).resolve().parent
    p.add_argument("--build-dir", type=Path, default=here / "build",
                   help="directory holding sweep.csv")
    p.add_argument("--out", type=Path, default=None,
                   help="directory for plots (default: <build-dir>/plots)")
    args = p.parse_args()

    out_dir = args.out or (args.build_dir / "plots")
    out_dir.mkdir(parents=True, exist_ok=True)

    setup_style()

    by = load(args.build_dir)
    print(f"[plot] loaded {len(by)} scenario(s) from {args.build_dir}")

    plot_latency(by,  out_dir / "latency_vs_allowlist.png")
    plot_overhead(by, out_dir / "overhead_vs_allowlist.png")

    print(f"[plot] done -> {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
