#!/usr/bin/env bash
# Integration test suite for the eBPF whitelister.
#
# Defines the policy semantics the redesign must satisfy:
#
#   1. Many comms : many resources -- two configured comms must have
#      disjoint allow-lists that don't leak into each other.
#   2. Unconfigured comms bypass the LSM enforcement entirely; only
#      processes whose comm appears in the loader's --comm list are
#      checked.
#   3. Path-component boundary semantics: prefix "/tmp/foo" allows
#      "/tmp/foo" and "/tmp/foo/x" but NOT "/tmp/foobar".
#   4. Backward compat for the single-comm CLI (--comm A --allow X --allow Y).
#   5. comm strings longer than TASK_COMM_LEN-1 (= 15 chars) get truncated
#      identically by the loader and prctl(PR_SET_NAME), so the resulting
#      truncated string still matches.
#
# Usage:
#   sudo ./run_tests.sh [-v|--verbose]
#
# Exit code 0 if every case passes, non-zero otherwise.

set -euo pipefail

VERBOSE=0
for arg in "$@"; do
    case "$arg" in
        -v | --verbose) VERBOSE=1 ;;
        -h | --help) sed -n '2,22p' "$0"; exit 0 ;;
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

WHITELISTER="$PROJECT_DIR/build/whitelister"
HELPER="$SCRIPT_DIR/build/test_helper"

DATA_DIR=/tmp/whitelister_tests
WL_LOG="$SCRIPT_DIR/build/whitelister.log"

PASS=0
FAIL=0
FAIL_NAMES=()
WL_PID=

# Pull MAX_COMMS straight from whitelister_config.h so the negative test
# below probes the correct boundary without hard-coding a duplicate. If
# the constant is ever bumped in the header, this script picks the new
# value up automatically on the next run.
CONFIG_HDR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/whitelister_config.h"
MAX_COMMS=$(awk '/^#define[[:space:]]+MAX_COMMS[[:space:]]/{print $3; exit}' "$CONFIG_HDR")
if [[ -z "$MAX_COMMS" ]]; then
    echo "error: could not parse MAX_COMMS from $CONFIG_HDR" >&2
    exit 1
fi

info()  { echo "[*] $*"; }
vinfo() { ((VERBOSE)) && echo "[v] $*" >&2 || true; }
die()   { echo "error: $*" >&2; exit 1; }

cleanup() {
    if [[ -n "${WL_PID:-}" ]] && kill -0 "$WL_PID" 2>/dev/null; then
        kill -KILL "$WL_PID" 2>/dev/null || true
        wait "$WL_PID" 2>/dev/null || true
    fi
    pkill -KILL -f "$WHITELISTER" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

start_whitelister() {
    : >"$WL_LOG"
    vinfo "loader args: $*"
    stdbuf -oL "$WHITELISTER" "$@" >"$WL_LOG" 2>&1 &
    WL_PID=$!
    local deadline=$((SECONDS + 5))
    while ((SECONDS < deadline)); do
        grep -q "active" "$WL_LOG" 2>/dev/null && return 0
        kill -0 "$WL_PID" 2>/dev/null || {
            cat "$WL_LOG" >&2
            die "loader exited during start"
        }
        sleep 0.1
    done
    if kill -0 "$WL_PID" 2>/dev/null; then
        return 0   # alive past 5s, banner not seen but assume attached
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

# probe COMM FILE EXPECT ; returns 0 on match, 1 on mismatch.
# Echoes the helper's stderr line on mismatch so the runner can show why.
probe() {
    local comm="$1" file="$2" expect="$3"
    local out
    if out=$("$HELPER" --comm "$comm" --file "$file" --expect "$expect" 2>&1); then
        return 0
    fi
    echo "    $out"
    return 1
}

# Run the loader synchronously and assert that it EXITS NON-ZERO. Used by
# the negative tests for argument validation.
expect_loader_failure() {
    : >"$WL_LOG"
    if "$WHITELISTER" "$@" >"$WL_LOG" 2>&1; then
        echo "    loader unexpectedly succeeded"
        return 1
    fi
    return 0
}

# run_case "name" body_fn ...
# body_fn must start the whitelister with whatever flags it needs and run
# its probes; it should return 0 on success. We always stop the whitelister
# afterwards so the next case starts clean.
run_case() {
    local name="$1"; shift
    local fn="$1"; shift
    info "test: $name"
    local rc=0
    "$fn" "$@" || rc=1
    stop_whitelister || true
    if (( rc == 0 )); then
        echo "  [PASS] $name"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $name"
        FAIL=$((FAIL + 1))
        FAIL_NAMES+=("$name")
    fi
}

# ----------------------------------------------------------------------- build
info "building whitelister + helper ..."
make -C "$PROJECT_DIR" >/dev/null
[[ -x "$WHITELISTER" ]] || die "whitelister did not build"
make -C "$SCRIPT_DIR" >/dev/null
[[ -x "$HELPER" ]] || die "test_helper did not build"

# ------------------------------------------------------------------- test data
info "preparing data under $DATA_DIR ..."
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR/dirA" "$DATA_DIR/dirB" "$DATA_DIR/foo" "$DATA_DIR/foobar"
echo "A"  >"$DATA_DIR/dirA/file"
echo "B"  >"$DATA_DIR/dirB/file"
echo "f"  >"$DATA_DIR/foo/file"
echo "fb" >"$DATA_DIR/foobar/file"
chmod -R a+rX "$DATA_DIR"

# ============================================================== TEST 1
# Two distinct comms, two disjoint allow-lists -- each comm must only see
# its own allowed directory.
test_multi_comm_isolation() {
    start_whitelister \
        --comm probe_a --allow "$DATA_DIR/dirA" \
        --comm probe_b --allow "$DATA_DIR/dirB"
    local rc=0
    probe probe_a "$DATA_DIR/dirA/file" allow || rc=1
    probe probe_a "$DATA_DIR/dirB/file" deny  || rc=1
    probe probe_b "$DATA_DIR/dirA/file" deny  || rc=1
    probe probe_b "$DATA_DIR/dirB/file" allow || rc=1
    return $rc
}
run_case "many comms : many resources" test_multi_comm_isolation

# ============================================================== TEST 2
# A process whose comm isn't in the loader's --comm list bypasses
# enforcement entirely (no policy applies).
test_unconfigured_bypass() {
    start_whitelister --comm probe_a --allow "$DATA_DIR/dirA"
    local rc=0
    probe other_proc "$DATA_DIR/dirA/file" allow || rc=1
    probe other_proc "$DATA_DIR/dirB/file" allow || rc=1
    probe other_proc /etc/hostname        allow || rc=1
    return $rc
}
run_case "unconfigured comm bypasses" test_unconfigured_bypass

# ============================================================== TEST 3
# Path-aware prefix: "/tmp/.../foo" must NOT match "/tmp/.../foobar".
test_path_boundary() {
    start_whitelister --comm probe_a --allow "$DATA_DIR/foo"
    local rc=0
    probe probe_a "$DATA_DIR/foo/file"    allow || rc=1
    probe probe_a "$DATA_DIR/foobar/file" deny  || rc=1
    return $rc
}
run_case "path-component boundary" test_path_boundary

# ============================================================== TEST 4
# Backward compat: single --comm followed by multiple --allow flags must
# still produce one comm with the union of those allow entries.
test_single_comm_multi_allow() {
    start_whitelister --comm probe_a \
        --allow "$DATA_DIR/dirA" \
        --allow "$DATA_DIR/foo"
    local rc=0
    probe probe_a "$DATA_DIR/dirA/file" allow || rc=1
    probe probe_a "$DATA_DIR/foo/file"  allow || rc=1
    probe probe_a "$DATA_DIR/dirB/file" deny  || rc=1
    return $rc
}
run_case "single comm, multiple allows (backward compat)" test_single_comm_multi_allow

# ============================================================== TEST 5
# A --comm value longer than TASK_COMM_LEN-1 (15) chars: the loader truncates
# to 15 chars + NUL, prctl(PR_SET_NAME) does the same on the probe side, so
# the policy still matches the (truncated) effective comm.
test_comm_truncation() {
    # 30-char string -- both ends will see "very_long_proce" (first 15).
    local long="very_long_process_name_xyz123"
    start_whitelister --comm "$long" --allow "$DATA_DIR/dirA"
    local rc=0
    probe "$long" "$DATA_DIR/dirA/file" allow || rc=1
    probe "$long" "$DATA_DIR/dirB/file" deny  || rc=1
    return $rc
}
run_case "comm truncated to TASK_COMM_LEN-1" test_comm_truncation

# ============================================================== TEST 6
# CLI validation: --allow before any --comm must fail with a non-zero
# exit code. Otherwise the prefix has no comm to attach to.
test_allow_without_comm_rejects() {
    expect_loader_failure --allow "$DATA_DIR/dirA"
}
run_case "--allow before --comm is rejected" test_allow_without_comm_rejects

# ============================================================== TEST 7
# CLI validation: more than MAX_COMMS distinct --comm names must fail.
# Build (MAX_COMMS + 1) groups of "--comm cN --allow X" and assert the
# loader exits non-zero before attaching.
test_too_many_comms_rejects() {
    local args=()
    for ((i = 0; i <= MAX_COMMS; i++)); do
        args+=(--comm "comm_$i" --allow "$DATA_DIR/dirA")
    done
    expect_loader_failure "${args[@]}"
}
run_case "more than MAX_COMMS distinct --comm is rejected" test_too_many_comms_rejects

# --------------------------------------------------------------- summary
echo
echo "================================================================"
echo "  passed: $PASS  failed: $FAIL"
if ((FAIL > 0)); then
    for n in "${FAIL_NAMES[@]}"; do
        echo "    - $n"
    done
fi
echo "================================================================"

exit $((FAIL > 0 ? 1 : 0))
