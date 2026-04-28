#!/usr/bin/env bash
# Sweep the target-file path length and measure per-open() latency under
# each of the four scenarios from run_bench.sh. Output:
#
#   build/sweep.csv               scenario, path_length, iters, mean, stddev, p50, p90, p99
#   build/plots/sweep_path_length.png  one line per scenario, x = path length
#
# The point of this sweep: longer paths make bpf_d_path() do more work (it
# walks the dentry chain and writes more bytes into the user buffer), and
# they also make the BPF prefix-compare loop scan further before deciding
# match/no-match. So the BPF-on scenarios should slope upward with path
# length, while the baseline (no BPF) stays roughly flat.
#
# Usage:
#   sudo ./sweep.sh [-v|--verbose]
#
# Env knobs:
#   ITERS    iterations per (scenario, length) point   (default 5000)
#   WARMUP   warmup opens per point                    (default 500)
#   LENGTHS  space-separated path-length list          (default 32..240 step 16)

set -euo pipefail

VERBOSE=0
for arg in "$@"; do
    case "$arg" in
        -v|--verbose) VERBOSE=1 ;;
        -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must run as root (need CAP_BPF + CAP_SYS_ADMIN)" >&2
    echo "       sudo $0 ${*:-}" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BENCH_BIN_REAL="$SCRIPT_DIR/build/bench_open"
COMM_NAME="wlbench_target"
BENCH_BIN="$SCRIPT_DIR/build/$COMM_NAME"
WHITELISTER="$PROJECT_DIR/build/whitelister"

DATA_DIR=/tmp/whitelister_sweep
WL_LOG="$SCRIPT_DIR/build/whitelister.log"
SWEEP_CSV="$SCRIPT_DIR/build/sweep.csv"
PLOT_PY="$SCRIPT_DIR/plot.py"
PLOTS_OUT="$SCRIPT_DIR/build/plots"

ITERS="${ITERS:-20000}"
WARMUP="${WARMUP:-2000}"
# 64 .. 960 in steps of ~64. Capped just under MAX_PATH=1024 from the BPF
# program (need room for the trailing NUL and the leaf filename basename).
LENGTHS="${LENGTHS:-64 128 192 256 320 384 448 512 576 640 704 768 832 896 960}"

info()  { echo "[*] $*"; }
vinfo() { (( VERBOSE )) && echo "[v] $*" >&2 || true; }
warn()  { echo "[!] $*" >&2; }
die()   { echo "error: $*" >&2; exit 1; }

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
    local comm="$1"; shift
    : >"$WL_LOG"
    vinfo "loader: comm=$comm allow=$*"
    stdbuf -oL "$WHITELISTER" --comm "$comm" "$@" >"$WL_LOG" 2>&1 &
    WL_PID=$!
    local deadline=$((SECONDS + 5))
    while (( SECONDS < deadline )); do
        grep -q "active" "$WL_LOG" 2>/dev/null && { vinfo "loader pid=$WL_PID attached"; return 0; }
        kill -0 "$WL_PID" 2>/dev/null || { cat "$WL_LOG" >&2; die "loader exited"; }
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
        while (( SECONDS < deadline )); do
            kill -0 "$WL_PID" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$WL_PID" 2>/dev/null; then
            warn "loader pid=$WL_PID did not exit on SIGINT, escalating"
            kill -KILL "$WL_PID" 2>/dev/null || true
        fi
    fi
    wait "$WL_PID" 2>/dev/null || true
    WL_PID=
    sleep 0.3
}

# Build a target file whose absolute path is exactly L bytes long.
#
# Linux NAME_MAX is 255 bytes per path component, so for L >> 255 we have
# to split the suffix across nested directories. We use components of
# COMPONENT bytes each (each just a string of 'a's) plus a 1-byte slash,
# and a final filename component for the remainder. The DATA_DIR and one
# leading slash are fixed.
COMPONENT=200
make_target() {
    local L="$1"
    local root="$DATA_DIR/"             # "/tmp/whitelister_sweep/"
    local rlen=${#root}
    local need=$((L - rlen))
    if (( need < 1 )); then
        die "L=$L is too small: prefix already takes $rlen bytes"
    fi

    local dir="$DATA_DIR"
    while (( need > COMPONENT + 1 )); do
        # add one full component plus the slash that joins it to the next
        local comp
        comp=$(printf 'a%.0s' $(seq 1 "$COMPONENT"))
        dir="$dir/$comp"
        need=$((need - COMPONENT - 1))
    done

    # `need` is the size of the leaf filename. It must not exceed NAME_MAX.
    if (( need > 240 )); then
        die "internal: leaf filename ($need) > NAME_MAX-ish bound"
    fi
    local leaf
    leaf=$(printf 'a%.0s' $(seq 1 "$need"))
    mkdir -p "$dir"
    local target="$dir/$leaf"
    [[ -f "$target" ]] || echo "x" >"$target"
    echo "$target"
}

# Run the bench once and emit CSV columns: scenario, length, iters, mean,
# stddev, p50, p90, p99.
bench_point() {
    local scenario="$1" L="$2" file="$3"; shift 3
    local extra=("$@")
    local out
    out=$("$BENCH_BIN" --file "$file" --iters "$ITERS" --warmup "$WARMUP" \
                       --label "${scenario}_L${L}" "${extra[@]}" 2>/dev/null)
    # bench prints: label,iters,mean,stddev,min,p50,p90,p99,p999,max
    IFS=',' read -r _ iters mean stddev _ p50 p90 p99 _ _ <<<"$out"
    echo "$scenario,$L,$iters,$mean,$stddev,$p50,$p90,$p99"
}

# ----------------------------------------------------------------------- build
info "building bench_open ..."
make -C "$SCRIPT_DIR" >/dev/null
[[ -x "$BENCH_BIN_REAL" ]] || die "bench_open did not build"
ln -sf "$(basename "$BENCH_BIN_REAL")" "$BENCH_BIN"

if [[ ! -x "$WHITELISTER" ]]; then
    info "building whitelister ..."
    make -C "$PROJECT_DIR"
fi
[[ -x "$WHITELISTER" ]] || die "could not build whitelister"

# ------------------------------------------------------------------- test data
info "preparing test data under $DATA_DIR ..."
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"
chmod a+rX "$DATA_DIR"

declare -A TARGETS
for L in $LENGTHS; do
    TARGETS["$L"]=$(make_target "$L")
    vinfo "L=$L -> ${TARGETS[$L]} (len=${#TARGETS[$L]})"
done

ALLOW_LIST=(
    --allow "$DATA_DIR"
    --allow /lib --allow /lib64
    --allow /usr --allow /etc
    --allow /proc --allow /dev
)
DENY_ALLOW_LIST=(
    --allow /lib --allow /lib64
    --allow /usr --allow /etc
    --allow /proc --allow /dev
)

# ------------------------------------------------------------------- header
echo "scenario,path_length,iters,mean_ns,stddev_ns,p50_ns,p90_ns,p99_ns" \
    >"$SWEEP_CSV"

# ------------------------------------------------------------------- baseline
info "sweeping baseline (no BPF) ..."
for L in $LENGTHS; do
    row=$(bench_point baseline "$L" "${TARGETS[$L]}")
    echo "$row" >>"$SWEEP_CSV"
    info "  L=$L -> $(echo "$row" | cut -d, -f4) ns"
done

# ----------------------------------------------------------------- comm-miss
info "sweeping bpf_comm_miss ..."
start_whitelister not_the_bench "${ALLOW_LIST[@]}"
for L in $LENGTHS; do
    row=$(bench_point bpf_comm_miss "$L" "${TARGETS[$L]}")
    echo "$row" >>"$SWEEP_CSV"
    info "  L=$L -> $(echo "$row" | cut -d, -f4) ns"
done
stop_whitelister

# ------------------------------------------------------------- comm-hit allow
info "sweeping bpf_comm_hit_allow ..."
start_whitelister "$COMM_NAME" "${ALLOW_LIST[@]}"
for L in $LENGTHS; do
    row=$(bench_point bpf_comm_hit_allow "$L" "${TARGETS[$L]}")
    echo "$row" >>"$SWEEP_CSV"
    info "  L=$L -> $(echo "$row" | cut -d, -f4) ns"
done
stop_whitelister

# ------------------------------------------------------------- comm-hit deny
info "sweeping bpf_deny ..."
start_whitelister "$COMM_NAME" "${DENY_ALLOW_LIST[@]}"
for L in $LENGTHS; do
    row=$(bench_point bpf_deny "$L" "${TARGETS[$L]}" --expect-deny)
    echo "$row" >>"$SWEEP_CSV"
    info "  L=$L -> $(echo "$row" | cut -d, -f4) ns"
done
stop_whitelister

info "sweep done -> $SWEEP_CSV"

# ----------------------------------------------------------------------- plot
if [[ "${NO_PLOT:-0}" == "1" ]]; then
    info "NO_PLOT=1 set; skipping plot"
    exit 0
fi

PY="${PYTHON:-python}"
if ! command -v "$PY" >/dev/null 2>&1; then
    warn "'$PY' not found; skipping plot (sweep CSV is at $SWEEP_CSV)"
    exit 0
fi
if ! "$PY" -c "import numpy, matplotlib" 2>/dev/null; then
    warn "$PY missing numpy/matplotlib; skipping plot"
    warn "(set PYTHON=/path/to/python or NO_PLOT=1)"
    exit 0
fi

info "plotting with $($PY --version 2>&1) ..."
if [[ -n "${SUDO_USER:-}" ]] && [[ "$(id -u)" -eq 0 ]]; then
    sudo -u "$SUDO_USER" -- "$PY" "$PLOT_PY" --sweep --build-dir "$SCRIPT_DIR/build"
    chown -R "$SUDO_USER":"$SUDO_USER" "$SCRIPT_DIR/build" 2>/dev/null || true
else
    "$PY" "$PLOT_PY" --sweep --build-dir "$SCRIPT_DIR/build"
fi
echo "plot: $PLOTS_OUT/sweep_path_length.png"
