#!/usr/bin/env bash
# Runs the open()/close() microbenchmark in four configurations and prints a
# side-by-side comparison so the cost of the eBPF LSM hook is visible.
#
# Scenarios:
#
#   baseline       no whitelister attached      -> raw VFS open() cost
#   bpf_comm_miss  whitelister attached, --comm set to a name that does NOT
#                  match the bench binary       -> overhead = LSM dispatch
#                                                  + bpf_get_current_comm
#                                                  + comm mismatch early-out
#   bpf_comm_hit   whitelister attached, --comm matches the bench binary,
#                  target file under an --allow prefix
#                                              -> overhead = LSM dispatch
#                                                  + comm match
#                                                  + bpf_d_path()
#                                                  + prefix scan (1 iter)
#   bpf_deny       whitelister attached, --comm matches the bench binary,
#                  target file NOT under any --allow prefix
#                                              -> overhead = full deny path
#                                                  (open() returns EACCES)
#
# The bench binary is symlinked under a deterministic 15-char name
# ("wlbench_target") so we can wire it up to --comm reliably, since
# task->comm is truncated at 15 bytes.
#
# This script must be run as root: it loads a BPF program and writes test
# data under /tmp. We do NOT call sudo internally because the surrounding
# sudo (sudo-rs in particular) does not reliably forward SIGINT to the
# loader when stdout is redirected, and stop_whitelister hangs waiting on
# a child that never receives the signal.
#
# Usage:
#   sudo ./run_bench.sh [-v|--verbose]
#
# Env knobs:
#   ITERS    iterations per scenario             (default 50000)
#   WARMUP   warmup opens per scenario           (default 2000)

set -euo pipefail

VERBOSE=0
for arg in "$@"; do
    case "$arg" in
        -v|--verbose) VERBOSE=1 ;;
        -h|--help)
            sed -n '2,40p' "$0"
            exit 0
            ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: must run as root (need CAP_BPF + CAP_SYS_ADMIN to attach)" >&2
    echo "       sudo $0 ${*:-}" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

BENCH_BIN_REAL="$SCRIPT_DIR/build/bench_open"
COMM_NAME="wlbench_target"
BENCH_BIN="$SCRIPT_DIR/build/$COMM_NAME"
WHITELISTER="$PROJECT_DIR/build/whitelister"

DATA_DIR=/tmp/whitelister_bench
ALLOWED_FILE="$DATA_DIR/allowed.txt"
DENIED_FILE="$DATA_DIR/denied/secret.txt"

ITERS="${ITERS:-100000}"
WARMUP="${WARMUP:-5000}"
WL_LOG="$SCRIPT_DIR/build/whitelister.log"
RESULTS_CSV="$SCRIPT_DIR/build/results.csv"

info()  { echo "[*] $*"; }
vinfo() { (( VERBOSE )) && echo "[v] $*" >&2 || true; }
warn()  { echo "[!] $*" >&2; }
die()   { echo "error: $*" >&2; exit 1; }

dump_log() {
    local tag="$1"
    if [[ -s "$WL_LOG" ]]; then
        echo "--- whitelister log ($tag) ---" >&2
        cat "$WL_LOG" >&2
        echo "--- end log ---" >&2
    fi
}

cleanup() {
    if [[ -n "${WL_PID:-}" ]] && kill -0 "$WL_PID" 2>/dev/null; then
        vinfo "cleanup: killing leftover whitelister pid=$WL_PID"
        kill -INT "$WL_PID" 2>/dev/null || true
        # give it a chance, then escalate
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            kill -0 "$WL_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$WL_PID" 2>/dev/null || true
        wait "$WL_PID" 2>/dev/null || true
    fi
    # paranoia: make sure no stray whitelister survived the run
    pkill -KILL -f "$WHITELISTER" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

start_whitelister() {
    local comm="$1"; shift
    : >"$WL_LOG"

    vinfo "start: comm=$comm allow=$* (log: $WL_LOG)"

    # stdbuf -oL forces the loader's stdout to line-buffered mode so the
    # "[active]" banner reaches the file as soon as it is printed (older
    # loader binaries that block-buffer printf would otherwise hold the
    # banner until exit and break the readiness probe below).
    stdbuf -oL "$WHITELISTER" --comm "$comm" "$@" >"$WL_LOG" 2>&1 &
    WL_PID=$!
    vinfo "start: pid=$WL_PID"

    # Wait for the "[active]" banner (loader has loaded BPF + attached LSM).
    local deadline=$((SECONDS + 5))
    while (( SECONDS < deadline )); do
        if grep -q "active" "$WL_LOG" 2>/dev/null; then
            vinfo "start: pid=$WL_PID attached"
            return 0
        fi
        if ! kill -0 "$WL_PID" 2>/dev/null; then
            dump_log "exit during startup"
            die "whitelister exited during startup"
        fi
        sleep 0.1
    done

    # Fallback: process is still alive past the deadline. Either the BPF
    # attach actually took >5s, or the loader binary is buffering stdout.
    # If it is alive, libbpf has loaded successfully (load failure exits
    # immediately).
    if kill -0 "$WL_PID" 2>/dev/null; then
        warn "whitelister still running after 5s but banner not seen -- assuming attached"
        return 0
    fi
    dump_log "no banner, no process"
    die "whitelister failed to start"
}

stop_whitelister() {
    if [[ -z "${WL_PID:-}" ]]; then
        return 0
    fi

    if kill -0 "$WL_PID" 2>/dev/null; then
        vinfo "stop: SIGINT -> pid=$WL_PID"
        kill -INT "$WL_PID" 2>/dev/null || true

        # Poll for up to 3s; we are root so the signal is delivered directly.
        local deadline=$((SECONDS + 3))
        while (( SECONDS < deadline )); do
            kill -0 "$WL_PID" 2>/dev/null || break
            sleep 0.1
        done

        if kill -0 "$WL_PID" 2>/dev/null; then
            warn "stop: pid=$WL_PID did not exit on SIGINT, escalating to SIGKILL"
            kill -KILL "$WL_PID" 2>/dev/null || true
        fi
    fi

    wait "$WL_PID" 2>/dev/null || true
    vinfo "stop: pid=$WL_PID reaped"
    WL_PID=
    # let the kernel actually drop the program before the next attach
    sleep 0.3
}

run_bench() {
    local label="$1"; shift
    local file="$1"; shift
    local extra=("$@")
    local dump="$SCRIPT_DIR/build/raw_${label}.bin"
    vinfo "bench: label=$label file=$file dump=$dump extra=${extra[*]:-}"
    "$BENCH_BIN" --file "$file" --iters "$ITERS" --warmup "$WARMUP" \
                 --label "$label" --dump "$dump" "${extra[@]}"
}

# ----------------------------------------------------------------------- build
info "building bench_open ..."
make -C "$SCRIPT_DIR" >/dev/null

[[ -x "$BENCH_BIN_REAL" ]] || die "bench_open did not build"

# Symlink so the running process has comm == wlbench_target (<=15 bytes).
ln -sf "$(basename "$BENCH_BIN_REAL")" "$BENCH_BIN"
vinfo "bench binary: $BENCH_BIN -> $(basename "$BENCH_BIN_REAL")"

if [[ ! -x "$WHITELISTER" ]]; then
    warn "whitelister binary not found at $WHITELISTER"
    info "building it ..."
    make -C "$PROJECT_DIR"
fi
[[ -x "$WHITELISTER" ]] || die "could not build whitelister"
vinfo "whitelister binary: $WHITELISTER"

# ------------------------------------------------------------------- test data
info "preparing test data under $DATA_DIR ..."
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR/denied"
echo "allowed payload" >"$ALLOWED_FILE"
echo "secret payload"  >"$DENIED_FILE"
chmod -R a+rX "$DATA_DIR"

# ------------------------------------------------------------------- scenarios
: >"$RESULTS_CSV"
echo "label,iters,mean_ns,stddev_ns,min_ns,p50_ns,p90_ns,p99_ns,p999_ns,max_ns" \
    >>"$RESULTS_CSV"

# 1) baseline -- no whitelister at all
info "scenario 1/4: baseline (no BPF program attached)"
run_bench baseline "$ALLOWED_FILE" >>"$RESULTS_CSV"

# 2) BPF attached, comm does NOT match the bench process
info "scenario 2/4: BPF attached, comm-miss"
start_whitelister not_the_bench --allow "$DATA_DIR" \
                                --allow /lib --allow /lib64 \
                                --allow /usr --allow /etc \
                                --allow /proc --allow /dev
run_bench bpf_comm_miss "$ALLOWED_FILE" >>"$RESULTS_CSV"
stop_whitelister

# 3) BPF attached, comm matches, file is on the allow list
info "scenario 3/4: BPF attached, comm-hit, allow path"
start_whitelister "$COMM_NAME" --allow "$DATA_DIR" \
                               --allow /lib --allow /lib64 \
                               --allow /usr --allow /etc \
                               --allow /proc --allow /dev
run_bench bpf_comm_hit_allow "$ALLOWED_FILE" >>"$RESULTS_CSV"
stop_whitelister

# 4) BPF attached, comm matches, file is NOT on the allow list -> EACCES
info "scenario 4/4: BPF attached, comm-hit, deny path"
# Allow only the system directories the bench process needs at startup
# (libc, ld-cache, locale, /proc/self/* hits in glibc, /dev/null) so the
# binary can load and reach main(). $DATA_DIR is deliberately NOT allowed,
# so each open() of $DENIED_FILE inside the loop returns EACCES.
start_whitelister "$COMM_NAME" --allow /lib --allow /lib64 \
                               --allow /usr --allow /etc \
                               --allow /proc --allow /dev
run_bench bpf_deny "$DENIED_FILE" --expect-deny >>"$RESULTS_CSV"
stop_whitelister

# ----------------------------------------------------------------- comparison
echo
echo "=== results (ns per open()/close() pair) ==="
awk -F, '
NR == 1 {
    printf "%-22s %8s %10s %10s %10s %10s %10s %10s\n",
           "scenario","iters","mean","stddev","p50","p90","p99","max"
    next
}
{
    label=$1; iters=$2; mean=$3; sd=$4; p50=$6; p90=$7; p99=$8; max=$10
    printf "%-22s %8d %10.0f %10.0f %10d %10d %10d %10d\n",
           label, iters, mean, sd, p50, p90, p99, max
}
' "$RESULTS_CSV"

echo
echo "=== overhead vs. baseline (mean ns delta and ratio) ==="
awk -F, '
NR == 1 { next }
NR == 2 { base=$3; printf "%-22s %12s %10s\n", "scenario","delta_ns","x_baseline"
          printf "%-22s %12.0f %10s\n", $1, 0.0, "1.00x"; next }
{
    delta = $3 - base
    ratio = $3 / base
    printf "%-22s %12.0f %9.2fx\n", $1, delta, ratio
}
' "$RESULTS_CSV"

echo
echo "raw CSV: $RESULTS_CSV"

# ----------------------------------------------------------------------- plots
if [[ "${NO_PLOT:-0}" == "1" ]]; then
    info "NO_PLOT=1 set; skipping plot generation"
    exit 0
fi

PLOT_PY="$SCRIPT_DIR/plot.py"
PLOTS_OUT="$SCRIPT_DIR/build/plots"
PY="${PYTHON:-python}"

if ! command -v "$PY" >/dev/null 2>&1; then
    warn "'$PY' not found in PATH; skipping plots"
    warn "(set PYTHON=/path/to/python or NO_PLOT=1 to silence)"
    exit 0
fi
if ! "$PY" -c "import numpy, matplotlib" 2>/dev/null; then
    warn "$PY is missing numpy/matplotlib; skipping plots"
    warn "(install them in the active env or set PYTHON=... ; or NO_PLOT=1)"
    exit 0
fi

info "generating plots with $($PY --version 2>&1) ..."

# Drop privileges for matplotlib output so files in plots/ are owned by the
# invoking user, not root. SUDO_USER is set by sudo when present.
if [[ -n "${SUDO_USER:-}" ]] && [[ "$(id -u)" -eq 0 ]]; then
    sudo -u "$SUDO_USER" -- "$PY" "$PLOT_PY" --build-dir "$SCRIPT_DIR/build"
    chown -R "$SUDO_USER":"$SUDO_USER" "$SCRIPT_DIR/build" 2>/dev/null || true
else
    "$PY" "$PLOT_PY" --build-dir "$SCRIPT_DIR/build"
fi

echo "plots: $PLOTS_OUT"
