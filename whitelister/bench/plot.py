#!/usr/bin/env python3
"""Plot the eBPF whitelister benchmark results.

Inputs:
  build/results.csv   summary stats (one row per scenario, written by bench_open)
  build/raw_<label>.bin  raw uint64 ns samples (one file per scenario)

Outputs (under build/plots/):
  latency_cdf.png            cumulative distribution (best for tail comparison)
  latency_distribution.png   per-scenario violin/histogram of latencies
  latency_summary.png        mean +/- stddev bar with p50/p90/p99 markers
  overhead_vs_baseline.png   delta of mean latency vs the baseline scenario
  jitter_timeline.png        latency over iteration index per scenario

Usage:
  python3 plot.py [--build-dir DIR] [--out DIR]
"""

from __future__ import annotations

import argparse
import csv
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker

# A consistent colour per scenario. Anything not listed falls back to a cycle.
SCENARIO_COLORS = {
    "baseline":             "#1f77b4",  # blue   - VFS only
    "bpf_comm_miss":        "#2ca02c",  # green  - early-out path
    "bpf_comm_hit_allow":   "#ff7f0e",  # orange - allow path (bpf_d_path + scan)
    "bpf_deny":             "#d62728",  # red    - full deny path
}

SCENARIO_PRETTY = {
    "baseline":             "baseline (no BPF)",
    "bpf_comm_miss":        "BPF: comm-miss",
    "bpf_comm_hit_allow":   "BPF: comm-hit, allow",
    "bpf_deny":             "BPF: comm-hit, deny",
}


@dataclass
class Scenario:
    label: str
    iters: int
    mean: float
    stddev: float
    p_min: int
    p50: int
    p90: int
    p99: int
    p999: int
    p_max: int
    samples: np.ndarray | None  # raw samples in insertion order, ns


def pretty(label: str) -> str:
    return SCENARIO_PRETTY.get(label, label)


def color(label: str, fallback_idx: int = 0) -> str:
    if label in SCENARIO_COLORS:
        return SCENARIO_COLORS[label]
    cycle = plt.rcParams["axes.prop_cycle"].by_key()["color"]
    return cycle[fallback_idx % len(cycle)]


def load_scenarios(build_dir: Path) -> list[Scenario]:
    csv_path = build_dir / "results.csv"
    if not csv_path.is_file():
        sys.exit(f"error: {csv_path} not found -- run the bench first")

    out: list[Scenario] = []
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            label = row["label"]
            raw_path = build_dir / f"raw_{label}.bin"
            samples = (
                np.fromfile(raw_path, dtype=np.uint64) if raw_path.is_file() else None
            )
            out.append(
                Scenario(
                    label=label,
                    iters=int(row["iters"]),
                    mean=float(row["mean_ns"]),
                    stddev=float(row["stddev_ns"]),
                    p_min=int(row["min_ns"]),
                    p50=int(row["p50_ns"]),
                    p90=int(row["p90_ns"]),
                    p99=int(row["p99_ns"]),
                    p999=int(row["p999_ns"]),
                    p_max=int(row["max_ns"]),
                    samples=samples,
                )
            )
    if not out:
        sys.exit(f"error: {csv_path} contains no rows")
    return out


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


def plot_cdf(scenarios: list[Scenario], out: Path) -> None:
    """Latency CDF: probability vs. open()/close() latency, one line per scenario."""
    fig, ax = plt.subplots(figsize=(11, 6))

    have_any = False
    for i, s in enumerate(scenarios):
        if s.samples is None or len(s.samples) == 0:
            continue
        have_any = True
        sorted_samples = np.sort(s.samples)
        y = np.arange(1, len(sorted_samples) + 1) / len(sorted_samples)
        c = color(s.label, i)
        ax.plot(sorted_samples, y, color=c, linewidth=2.0,
                label=pretty(s.label), zorder=3)

    if not have_any:
        plt.close(fig)
        print("[plot] no raw samples; skipping CDF", file=sys.stderr)
        return

    # Clip x at the slowest scenario's p99 so the *interesting* part of
    # each CDF (where the curves differ) actually fills the panel; rarer
    # tail outliers can stretch the axis to ~50us and squash everything
    # against the left edge otherwise.
    upper = max(s.p99 for s in scenarios)
    ax.set_xlim(0, upper * 1.10)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("open()/close() latency")
    ax.set_ylabel("Cumulative probability")
    ax.set_title("eBPF whitelister - latency CDF (clipped at p99)")
    fmt_ns(ax, "x")
    ax.legend(loc="lower right", title=None)

    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"[plot] wrote {out}")


def plot_distribution(scenarios: list[Scenario], out: Path) -> None:
    """Density-normalised step histograms, one line per scenario."""
    have = [s for s in scenarios if s.samples is not None and len(s.samples)]
    if not have:
        print("[plot] no raw samples; skipping distribution", file=sys.stderr)
        return

    fig, ax = plt.subplots(figsize=(11, 6))

    # Common x range across scenarios so densities are visually comparable.
    cap = max(s.p99 for s in have) * 1.4
    bins = np.linspace(0, cap, 80)

    for i, s in enumerate(have):
        c = color(s.label, i)
        clipped = np.clip(s.samples, 0, cap)
        ax.hist(clipped, bins=bins, histtype="step", color=c, linewidth=2.0,
                density=True, label=pretty(s.label), zorder=3)

    ax.set_xlabel("open()/close() latency")
    ax.set_ylabel("Density")
    ax.set_title("eBPF whitelister - latency distribution (clipped at 1.4xp99)")
    fmt_ns(ax, "x")
    ax.set_xlim(0, cap)
    ax.set_ylim(bottom=0)
    ax.legend(loc="upper right", title=None)

    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"[plot] wrote {out}")


def plot_summary(scenarios: list[Scenario], out: Path) -> None:
    """Lollipop chart: one stem per scenario from y=0 up to its p50, with
    p90 and p99 stacked above as separate markers. Same colour palette as
    the path-length sweep, top-left frameless legend, ns->us auto-axis."""
    fig, ax = plt.subplots(figsize=(11, 6))

    positions = np.arange(len(scenarios))
    p50s = np.array([s.p50 for s in scenarios])
    p90s = np.array([s.p90 for s in scenarios])
    p99s = np.array([s.p99 for s in scenarios])
    colors = [color(s.label, i) for i, s in enumerate(scenarios)]

    # Stems from baseline to the median.
    ax.vlines(positions, 0, p50s, colors=colors, linewidth=2.5, zorder=2)
    # Median marker (filled circle, white edge so it pops over the stem).
    ax.scatter(positions, p50s, color=colors, s=85, zorder=4,
               edgecolor="white", linewidth=1.4)
    # p90 / p99 as smaller markers above.
    ax.scatter(positions, p90s, color=colors, s=55, marker="^",
               zorder=3, alpha=0.85, edgecolor="white", linewidth=1.0)
    ax.scatter(positions, p99s, color=colors, s=55, marker="s",
               zorder=3, alpha=0.55, edgecolor="white", linewidth=1.0)

    ax.set_xticks(positions)
    ax.set_xticklabels([pretty(s.label) for s in scenarios], rotation=10)
    ax.set_ylabel("open()/close() latency")
    ax.set_title("eBPF whitelister - per-scenario latency (median + tail)")
    fmt_ns(ax, "y")
    ax.set_ylim(0, p99s.max() * 1.18)

    # Legend explains the marker shapes (colours come from the x-axis labels).
    handles = [
        plt.Line2D([0], [0], marker="o", color="#444", linestyle="none",
                   markersize=9, label="p50 (median)"),
        plt.Line2D([0], [0], marker="^", color="#444", linestyle="none",
                   markersize=7, label="p90"),
        plt.Line2D([0], [0], marker="s", color="#444", linestyle="none",
                   markersize=6, label="p99"),
    ]
    ax.legend(handles=handles, loc="upper left", title=None)

    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"[plot] wrote {out}")


def plot_overhead(scenarios: list[Scenario], out: Path) -> None:
    """Lollipop chart of median latency added over baseline. Single panel,
    same aesthetic as the summary plot. Median (not mean) so outliers don't
    distort the comparison."""
    if not scenarios:
        return
    baseline = next((s for s in scenarios if s.label == "baseline"), scenarios[0])
    others = [s for s in scenarios if s is not baseline]
    if not others:
        print("[plot] no non-baseline scenarios; skipping overhead", file=sys.stderr)
        return

    fig, ax = plt.subplots(figsize=(11, 6))

    positions = np.arange(len(others))
    deltas = np.array([s.p50 - baseline.p50 for s in others])
    colors = [color(s.label, i + 1) for i, s in enumerate(others)]

    ax.axhline(0, color="#888", linewidth=1, zorder=1)
    ax.vlines(positions, 0, deltas, colors=colors, linewidth=2.5, zorder=2)
    ax.scatter(positions, deltas, color=colors, s=85, zorder=4,
               edgecolor="white", linewidth=1.4)

    span = max(abs(deltas.min()), abs(deltas.max())) or 1
    for x, d, c in zip(positions, deltas, colors):
        sign = "+" if d >= 0 else ""
        ax.text(x, d + span * 0.04 * (1 if d >= 0 else -1),
                f"{sign}{d:.0f} ns",
                ha="center", va="bottom" if d >= 0 else "top",
                fontsize=10, fontweight="semibold", color=c)

    ax.set_xticks(positions)
    ax.set_xticklabels([pretty(s.label) for s in others], rotation=10)
    ax.set_ylabel(f"Median latency added over baseline ({baseline.p50:.0f} ns)")
    ax.set_title("eBPF whitelister - cost vs. baseline")
    fmt_ns(ax, "y")

    if deltas.min() >= 0:
        ax.set_ylim(0, deltas.max() * 1.22)
    else:
        ax.set_ylim(deltas.min() * 1.22, deltas.max() * 1.22)

    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"[plot] wrote {out}")


def load_sweep(build_dir: Path) -> dict[str, list[tuple[int, float, float, int, int, int]]]:
    """Read build/sweep.csv and group rows by scenario.

    Returns: scenario -> list of (path_length, mean_ns, stddev_ns, p50, p90, p99)
    sorted by path_length.
    """
    csv_path = build_dir / "sweep.csv"
    if not csv_path.is_file():
        sys.exit(f"error: {csv_path} not found -- run sweep.sh first")

    by_scenario: dict[str, list[tuple[int, float, float, int, int, int]]] = {}
    with csv_path.open() as f:
        reader = csv.DictReader(f)
        for row in reader:
            by_scenario.setdefault(row["scenario"], []).append((
                int(row["path_length"]),
                float(row["mean_ns"]),
                float(row["stddev_ns"]),
                int(row["p50_ns"]),
                int(row["p90_ns"]),
                int(row["p99_ns"]),
            ))
    for k in by_scenario:
        by_scenario[k].sort(key=lambda r: r[0])
    return by_scenario


def plot_sweep_path_length(by_scenario: dict, out: Path) -> None:
    """Multi-line latency-vs-path-length chart.

    Plots the *median* (p50) of each (scenario, length) point because mean
    is dominated by rare-but-large outliers (scheduler preemption, cold
    page-cache lookups). p50 is the typical observed latency a target
    process would see and produces a clean monotone trend.

    No shaded band: stddev for microbenchmarks at this scale is
    pathologically wide, and a single tail spike can swing it by 40 µs;
    drawing it would swamp the actual signal.
    """
    fig, ax = plt.subplots(figsize=(11, 6))

    ordered = [
        s for s in ("baseline", "bpf_comm_miss",
                    "bpf_comm_hit_allow", "bpf_deny")
        if s in by_scenario
    ]
    for s in by_scenario:
        if s not in ordered:
            ordered.append(s)

    for i, scenario in enumerate(ordered):
        rows = by_scenario[scenario]
        xs   = np.array([r[0] for r in rows])
        # Index 3 in the row is p50_ns; see load_sweep().
        p50s = np.array([r[3] for r in rows])
        c = color(scenario, i)
        ax.plot(xs, p50s, marker="o", linewidth=2.0, markersize=5.5,
                color=c, label=pretty(scenario), zorder=3)

    ax.set_xlabel("Target path length (bytes)")
    ax.set_ylabel("Median open()/close() latency")
    ax.set_title("eBPF whitelister - latency vs. target path length")
    fmt_ns(ax, "y")

    # y starts at 0 so the *absolute* size of the BPF overhead is visible.
    ax.set_ylim(bottom=0)
    ax.legend(loc="upper left", title=None)

    all_xs = sorted({r[0] for rows in by_scenario.values() for r in rows})
    if len(all_xs) <= 24:
        ax.set_xticks(all_xs)
        ax.tick_params(axis="x", labelrotation=45)

    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"[plot] wrote {out}")


def plot_jitter(scenarios: list[Scenario], out: Path) -> None:
    """Latency over iteration index, one panel per scenario.

    Stacked panels (not overlaid) because 4 scenarios x ~100k samples
    overlap into solid bands when drawn on the same axes. Shared y-axis
    so panels are visually comparable, scenario name in the top-left of
    each panel like the path-length plot's legend.
    """
    have = [s for s in scenarios if s.samples is not None and len(s.samples)]
    if not have:
        return

    fig, axes = plt.subplots(len(have), 1, figsize=(11, 2.4 * len(have)),
                             sharex=True, sharey=True, squeeze=False)
    axes = axes[:, 0]

    # Clip uniformly so all panels share the same y-range and outliers
    # don't push the median trace down to a flat line.
    cap = int(max(s.p99 for s in have) * 1.5)

    for ax, s, i in zip(axes, have, range(len(have))):
        c = color(s.label, i)
        x = np.arange(len(s.samples))
        y = np.minimum(s.samples, cap)
        if len(x) > 20000:
            step = len(x) // 20000
            x = x[::step]
            y = y[::step]
        ax.plot(x, y, color=c, linewidth=0.6, alpha=0.7, zorder=2)
        ax.axhline(s.p50, color="#222", linestyle="--", linewidth=0.9,
                   zorder=3)
        # Scenario label in the top-left, matching the legend position
        # of the path-length plot.
        ax.text(0.012, 0.92, f"{pretty(s.label)}  p50={s.p50:.0f} ns",
                transform=ax.transAxes, ha="left", va="top",
                fontsize=11, fontweight="semibold", color=c)
        ax.set_ylabel("Latency")
        fmt_ns(ax, "y")
        ax.set_ylim(0, cap)

    axes[-1].set_xlabel("Iteration")
    fig.suptitle("eBPF whitelister - latency over iteration (clipped at 1.5xp99)",
                 fontsize=13, fontweight="bold")
    fig.tight_layout()
    fig.savefig(out)
    plt.close(fig)
    print(f"[plot] wrote {out}")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    here = Path(__file__).resolve().parent
    p.add_argument("--build-dir", type=Path, default=here / "build",
                   help="directory holding results.csv + raw_*.bin")
    p.add_argument("--out", type=Path, default=None,
                   help="directory for plots (default: <build-dir>/plots)")
    p.add_argument("--sweep", action="store_true",
                   help="plot from sweep.csv (path-length sweep) instead of "
                        "the per-scenario summary")
    args = p.parse_args()

    out_dir = args.out or (args.build_dir / "plots")
    out_dir.mkdir(parents=True, exist_ok=True)

    setup_style()

    if args.sweep:
        by_scenario = load_sweep(args.build_dir)
        print(f"[plot] loaded sweep with {len(by_scenario)} scenario(s) "
              f"from {args.build_dir}")
        plot_sweep_path_length(by_scenario, out_dir / "sweep_path_length.png")
        print(f"[plot] done -> {out_dir}")
        return 0

    scenarios = load_scenarios(args.build_dir)
    print(f"[plot] loaded {len(scenarios)} scenario(s) from {args.build_dir}")

    plot_cdf(scenarios,          out_dir / "latency_cdf.png")
    plot_distribution(scenarios, out_dir / "latency_distribution.png")
    plot_summary(scenarios,      out_dir / "latency_summary.png")
    plot_overhead(scenarios,     out_dir / "overhead_vs_baseline.png")
    plot_jitter(scenarios,       out_dir / "jitter_timeline.png")

    print(f"[plot] done -> {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
