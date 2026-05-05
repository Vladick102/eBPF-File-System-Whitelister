#!/usr/bin/env bash
# Sweep the eBPF whitelister's per-open() latency as a function of the
# number of allow-list entries.
#
# For each scenario in (baseline, bpf_comm_miss, bpf_comm_hit_allow, bpf_deny)
# and each allow-list size N in NS (default {1, 4, 7, ..., 25}), we run the
# open() microbenchmark
# REPEATS times, take the per-run p50, and aggregate (mean, stddev) across
# the repeats. The repeats average out cross-run system noise (scheduler
# preemption, cache state, IRQ jitter) so the curves are representative
# rather than dominated by the variance of a single run.
#
# Trick to free up allow-list slots: bench_open does prctl(PR_SET_NAME)
# *after* all libc / ld.so loads, so the whitelister's --comm filter only
# matches the warmup + timed phase. That means we never have to allow
# /lib, /lib64, /usr, /etc, ... and the full MAX_PREFIXES budget is
# usable for the actual sweep.
#
# Allow-list shape per scenario (N total entries):
#
#   baseline            no whitelister attached, N has no meaning
#                       (replicated across N for plotting convenience)
#
#   bpf_comm_miss       --comm does NOT match the bench process; allow-list
#                       contains (N-1) decoys + the target prefix, but the
#                       prefix scan never runs (early-out on comm mismatch).
#                       Cost should be flat in N.
#
#   bpf_comm_hit_allow  --comm matches; (N-1) non-matching decoys followed
#                       by the target prefix LAST in the allow-list.
#                       Worst-case scan: visits all N entries before
#                       matching the last one. Cost ~ N * (per-entry cost).
#
#   bpf_deny            --comm matches; allow-list is N decoys, target file
#                       is NOT under any prefix -> full scan + EACCES.
#                       Cost ~ N * (per-entry cost) + deny path.
#
# Output:
#   build/sweep.csv                                summary stats
#   build/plots/latency_vs_allowlist.png           latency vs N (line + band)
#   build/plots/overhead_vs_allowlist.png          delta over baseline vs N
#
# Usage:
#   sudo ./run_bench.sh [-v|--verbose]
#
# Env knobs:
#   ITERS    timed open() iterations per single bench_open run  (default 10000)
#   WARMUP   warmup opens per single run                         (default 1000)
#   REPEATS  independent bench_open invocations per (scen, N)    (default 30)
#   NS       allow-list sizes to sweep (space-separated)         (default 1..8)

set -euo pipefail

VERBOSE=0
for arg in "$@"; do
    case "$arg" in
        -v | --verbose) VERBOSE=1 ;;
        -h | --help)
            sed -n '2,52p' "$0"
            exit 0
            ;;
        *)
            echo "unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must run as root (need CAP_BPF + CAP_SYS_ADMIN to attach)" >&2
    echo "       sudo $0 ${*:-}" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BENCH_BIN="$SCRIPT_DIR/build/bench_open"
WHITELISTER="$PROJECT_DIR/build/whitelister"
COMM_NAME="wlbench_target"   # set via prctl inside bench_open (<=15 bytes)

DATA_DIR=/tmp/whitelister_bench
ALLOWED_FILE="$DATA_DIR/allowed.txt"
DENIED_FILE="$DATA_DIR/denied/secret.txt"

WL_LOG="$SCRIPT_DIR/build/whitelister.log"
SWEEP_CSV="$SCRIPT_DIR/build/sweep.csv"
PLOT_PY="$SCRIPT_DIR/plot.py"
PLOTS_OUT="$SCRIPT_DIR/build/plots"

ITERS="${ITERS:-10000}"
WARMUP="${WARMUP:-1000}"
REPEATS="${REPEATS:-30}"
# Sweep up to 25 entries. MAX_PREFIXES in whitelister.bpf.c is 32, so this
# leaves a small safety margin without needing to rebuild the BPF program.
# Step of 3 -> 9 evenly-spaced points; tweak via NS=... to taste.
NS="${NS:-1 4 7 10 13 16 19 22 25}"

info() { echo "[*] $*"; }
vinfo() { ((VERBOSE)) && echo "[v] $*" >&2 || true; }
warn() { echo "[!] $*" >&2; }
die() {
    echo "error: $*" >&2
    exit 1
}

cleanup() {
    if [[ -n "${WL_PID:-}" ]] && kill -0 "$WL_PID" 2>/dev/null; then
        kill -INT "$WL_PID" 2>/dev/null || true
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$WL_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$WL_PID" 2>/dev/null || true
        wait "$WL_PID" 2>/dev/null || true
    fi
    pkill -KILL -f "$WHITELISTER" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

start_whitelister() {
    local comm="$1"
    shift
    : >"$WL_LOG"
    vinfo "loader: comm=$comm allow=$*"
    stdbuf -oL "$WHITELISTER" --comm "$comm" "$@" >"$WL_LOG" 2>&1 &
    WL_PID=$!
    local deadline=$((SECONDS + 5))
    while ((SECONDS < deadline)); do
        grep -q "active" "$WL_LOG" 2>/dev/null && return 0
        kill -0 "$WL_PID" 2>/dev/null || {
            cat "$WL_LOG" >&2
            die "loader exited"
        }
        sleep 0.1
    done
    if kill -0 "$WL_PID" 2>/dev/null; then
        warn "loader: no banner after 5s, assuming attached"
        return 0
    fi
    cat "$WL_LOG" >&2
    die "loader failed to start"
}

stop_whitelister() {
    [[ -z "${WL_PID:-}" ]] && return 0
    if kill -0 "$WL_PID" 2>/dev/null; then
        kill -INT "$WL_PID" 2>/dev/null || true
        local deadline=$((SECONDS + 3))
        while ((SECONDS < deadline)); do
            kill -0 "$WL_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill -0 "$WL_PID" 2>/dev/null && kill -KILL "$WL_PID" 2>/dev/null || true
    fi
    wait "$WL_PID" 2>/dev/null || true
    WL_PID=
    sleep 0.3
}

# Run one bench_open invocation, echo its p50_ns (column 6 of the CSV record).
run_one() {
    local label="$1" file="$2"
    shift 2
    local extra=("$@")
    local out
    out=$("$BENCH_BIN" --file "$file" --iters "$ITERS" --warmup "$WARMUP" \
        --label "$label" --set-comm "$COMM_NAME" \
        "${extra[@]}" 2>/dev/null)
    # CSV: label,iters,mean,stddev,min,p50,p90,p99,p999,max
    echo "$out" | cut -d, -f6
}

# Aggregate stats over a list of numeric samples on stdin.
# Echoes "mean,stddev,min,max" (mean / stddev with 2 decimals, min / max as ints).
aggregate() {
    awk '
    NR == 1 { mn = mx = $1 }
    {
        s += $1; ss += $1 * $1; n++
        if ($1 < mn) mn = $1
        if ($1 > mx) mx = $1
    }
    END {
        if (n == 0) { print "0,0,0,0"; exit }
        mean = s / n
        var  = (ss - s * s / n) / n
        sd   = (var < 0) ? 0 : sqrt(var)
        printf "%.2f,%.2f,%.0f,%.0f", mean, sd, mn, mx
    }'
}

# Run REPEATS bench_opens, append one aggregate row to sweep.csv.
sweep_point() {
    local scenario="$1" n="$2" file="$3"
    shift 3
    local extra=("$@")
    local p50s=()
    for ((r = 1; r <= REPEATS; r++)); do
        local p50
        p50=$(run_one "${scenario}_n${n}_r${r}" "$file" "${extra[@]}")
        p50s+=("$p50")
    done
    local stats
    stats=$(printf '%s\n' "${p50s[@]}" | aggregate)
    echo "$scenario,$n,$REPEATS,$stats" >>"$SWEEP_CSV"
    info "  $scenario n=$n -> mean=$(echo "$stats" | cut -d, -f1)ns ± $(echo "$stats" | cut -d, -f2)ns"
}

# Emit `--allow <decoy>` flags on stdout, $1 of them, deterministic paths.
gen_decoys() {
    local count="$1"
    for ((i = 0; i < count; i++)); do
        printf -- '--allow\n'
        printf -- '/__bench_decoy/pad%05d\n' "$i"
    done
}

# ----------------------------------------------------------------------- build
info "building bench_open ..."
make -C "$SCRIPT_DIR" >/dev/null
[[ -x "$BENCH_BIN" ]] || die "bench_open did not build"

if [[ ! -x "$WHITELISTER" ]]; then
    info "building whitelister ..."
    make -C "$PROJECT_DIR"
fi
[[ -x "$WHITELISTER" ]] || die "could not build whitelister"

# ------------------------------------------------------------------- test data
info "preparing test data under $DATA_DIR ..."
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR/denied"
echo "allowed payload" >"$ALLOWED_FILE"
echo "secret payload" >"$DENIED_FILE"
chmod -R a+rX "$DATA_DIR"

# ------------------------------------------------------------------- header
echo "scenario,n_prefixes,repeats,mean_p50_ns,stddev_p50_ns,min_p50_ns,max_p50_ns" \
    >"$SWEEP_CSV"

info "iters=$ITERS warmup=$WARMUP repeats=$REPEATS sizes=[$NS]"

# --------------------------------------------------------------------- baseline
# Baseline is independent of N (no BPF). We measure once with REPEATS samples
# and replicate the row across every N so the plotter can render it as a
# flat reference alongside the BPF scenarios.
info "scenario 1/4: baseline (no BPF)"
BASE_SAMPLES=()
for ((r = 1; r <= REPEATS; r++)); do
    BASE_SAMPLES+=("$(run_one "baseline_r$r" "$ALLOWED_FILE")")
done
BASE_STATS=$(printf '%s\n' "${BASE_SAMPLES[@]}" | aggregate)
for n in $NS; do
    echo "baseline,$n,$REPEATS,$BASE_STATS" >>"$SWEEP_CSV"
done
info "  baseline mean=$(echo "$BASE_STATS" | cut -d, -f1)ns ± $(echo "$BASE_STATS" | cut -d, -f2)ns"

# -------------------------------------------------------------------- comm-miss
info "scenario 2/4: bpf_comm_miss (early-out, expected flat)"
for n in $NS; do
    decoy_args=()
    if ((n > 1)); then
        mapfile -t decoy_args < <(gen_decoys $((n - 1)))
    fi
    start_whitelister "not_the_bench" "${decoy_args[@]}" --allow "$DATA_DIR"
    sweep_point bpf_comm_miss "$n" "$ALLOWED_FILE"
    stop_whitelister
done

# ------------------------------------------------------------- comm-hit / allow
# Place the matching prefix LAST so the scan visits all N entries before
# matching -- worst case, gives the cleanest "cost vs N" curve.
info "scenario 3/4: bpf_comm_hit_allow (worst-case scan: matching prefix last)"
for n in $NS; do
    decoy_args=()
    if ((n > 1)); then
        mapfile -t decoy_args < <(gen_decoys $((n - 1)))
    fi
    start_whitelister "$COMM_NAME" "${decoy_args[@]}" --allow "$DATA_DIR"
    sweep_point bpf_comm_hit_allow "$n" "$ALLOWED_FILE"
    stop_whitelister
done

# --------------------------------------------------------------- comm-hit / deny
# Target file is NOT covered by any prefix -> full scan + EACCES.
info "scenario 4/4: bpf_deny (full scan + EACCES)"
for n in $NS; do
    mapfile -t decoy_args < <(gen_decoys "$n")
    start_whitelister "$COMM_NAME" "${decoy_args[@]}"
    sweep_point bpf_deny "$n" "$DENIED_FILE" --expect-deny
    stop_whitelister
done

info "sweep done -> $SWEEP_CSV"

# ----------------------------------------------------------------------- plot
if [[ "${NO_PLOT:-0}" == "1" ]]; then
    info "NO_PLOT=1 set; skipping plots"
    exit 0
fi

PY="${PYTHON:-python}"

# This project standardises on the 'python' command. We never fall back
# to 'python3': if the active environment doesn't expose 'python', the
# user is expected to either install it, point $PYTHON at their interpreter,
# or set NO_PLOT=1 to skip plotting entirely.
if ! command -v "$PY" >/dev/null 2>&1; then
    warn "'$PY' not found in PATH; skipping plots"
    warn "this project requires 'python' (not 'python3') -- install it, or"
    warn "set PYTHON=/path/to/python, or NO_PLOT=1 to silence"
    exit 0
fi
if ! "$PY" -c "import numpy, matplotlib" 2>/dev/null; then
    warn "$PY missing numpy/matplotlib; skipping plots"
    warn "(install via 'pip install -r $SCRIPT_DIR/requirements.txt' or NO_PLOT=1)"
    exit 0
fi

info "plotting with $($PY --version 2>&1) ..."

# Drop privileges so plot files in build/ are owned by the invoking user.
if [[ -n "${SUDO_USER:-}" ]] && [[ "$(id -u)" -eq 0 ]]; then
    chown -R "$SUDO_USER":"$SUDO_USER" "$SCRIPT_DIR/build" 2>/dev/null || true
    sudo -u "$SUDO_USER" -- "$PY" "$PLOT_PY" --build-dir "$SCRIPT_DIR/build"
else
    "$PY" "$PLOT_PY" --build-dir "$SCRIPT_DIR/build"
fi

echo "plots: $PLOTS_OUT"
