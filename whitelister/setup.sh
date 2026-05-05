#!/usr/bin/env bash
# eBPF File System Whitelister - one-shot setup / build / demo script.
#
# Subcommands:
#   deps   apt-install clang, libbpf, bpftool, kernel headers
#   check  verify CONFIG_BPF_LSM=y and that "bpf" is in the active LSM chain
#          (prints exact instructions to enable it via GRUB if missing)
#   build  compile the BPF program, generate skeleton, link user-space loader
#   demo   create /tmp/ftp_whitelist_demo with "allowed" and "secret" files
#          plus a fake "ftp" binary wrapper, then print commands to try
#   all    run all of the above in order
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR=/tmp/ftp_whitelist_demo
FAKE_FTP=/tmp/ftp

die() {
    echo "error: $*" >&2
    exit 1
}
info() { echo "[*] $*"; }
warn() { echo "[!] $*" >&2; }

need_root() {
    [[ "$(id -u)" -eq 0 ]] || die "subcommand '$1' needs root — run with sudo"
}

cmd_deps() {
    need_root deps
    info "installing build dependencies (apt)..."
    apt-get update
    # NOTE: we deliberately do NOT install the bare 'bpftool' package.
    # On Ubuntu 24.04+, 'bpftool' is a virtual package with multiple
    # providers (linux-tools-common, linux-lowlatency-tools-common, ...)
    # so 'apt-get install bpftool' fails with "no installation candidate".
    # linux-tools-$(uname -r) pulls in linux-tools-common, which provides
    # the /usr/sbin/bpftool dispatcher we actually want.
    apt-get install -y \
        clang llvm \
        libbpf-dev libelf-dev zlib1g-dev \
        linux-tools-common \
        linux-headers-"$(uname -r)" linux-tools-"$(uname -r)" ||
        apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
            linux-tools-common linux-headers-"$(uname -r)"

    if ! command -v bpftool >/dev/null 2>&1; then
        die "bpftool not on PATH after install — try 'apt install linux-tools-$(uname -r)' manually"
    fi
    info "bpftool: $(command -v bpftool) ($(bpftool version 2>&1 | head -1))"
    info "dependencies installed"
}

cmd_check() {
    info "checking BPF LSM support..."

    local cfg="/boot/config-$(uname -r)"
    if [[ -r "$cfg" ]] && grep -q '^CONFIG_BPF_LSM=y' "$cfg"; then
        info "kernel compiled with CONFIG_BPF_LSM=y"
    else
        warn "CONFIG_BPF_LSM=y not confirmed (kernel may still support it)"
    fi

    [[ -r /sys/kernel/security/lsm ]] ||
        die "/sys/kernel/security/lsm unreadable"

    local lsms
    lsms="$(cat /sys/kernel/security/lsm)"
    info "active LSMs: $lsms"

    if [[ ",$lsms," == *",bpf,"* ]]; then
        info "bpf is in the LSM chain"
        return 0
    fi

    local new_chain="${lsms},bpf"
    cat >&2 <<EOF

[!] 'bpf' is NOT in the active LSM chain — the whitelister will fail to attach.

    Active chain : $lsms
    Required     : $new_chain   (append ',bpf')

To fix (one-time, then reboot):

  1. sudo \$EDITOR /etc/default/grub
  2. Find the GRUB_CMDLINE_LINUX_DEFAULT="..." line and add (or extend)
     an lsm= argument with the full ordered chain:

       lsm=$new_chain

     Example:
       GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=$new_chain"

  3. sudo update-grub
  4. sudo reboot
  5. Verify:  cat /sys/kernel/security/lsm   (should contain 'bpf')

Note: the order matters. Keep the existing LSMs in the same order as
shown above and just append ',bpf' at the end — re-ordering 'capability'
or 'lockdown' can break the boot.

EOF
    exit 1
}

cmd_build() {
    info "building in $SCRIPT_DIR ..."
    cd "$SCRIPT_DIR"
    make clean >/dev/null 2>&1 || true
    make
    info "built: $SCRIPT_DIR/build/whitelister"
}

cmd_demo() {
    need_root demo
    info "creating demo files under $DEMO_DIR ..."
    rm -rf "$DEMO_DIR"
    mkdir -p "$DEMO_DIR/allowed"
    echo "this file is inside the whitelist, ftp may read it" >"$DEMO_DIR/allowed/public.txt"
    echo "this file is SECRET" >"$DEMO_DIR/secret.txt"
    chmod -R a+rX "$DEMO_DIR"

    info "building a minimal 'ftp' reader binary at $FAKE_FTP ..."
    local src=/tmp/ftp_reader.c
    cat >"$src" <<'EOS'
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <file>\n", argv[0]); return 2; }
    FILE *f = fopen(argv[1], "r");
    if (!f) { perror(argv[1]); return 1; }
    char buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) fwrite(buf, 1, n, stdout);
    fclose(f); return 0;
}
EOS
    cc -O2 -Wall "$src" -o "$FAKE_FTP"
    chmod 0755 "$FAKE_FTP"
    rm -f "$src"

    cat <<EOF

--- demo ready ---

Terminal A — start the whitelister:

  sudo $SCRIPT_DIR/build/whitelister --comm ftp \\
       --allow $DEMO_DIR/allowed \\
       --allow $FAKE_FTP \\
       --allow /lib --allow /lib64 --allow /usr \\
       --allow /etc --allow /proc --allow /dev

Terminal B — exercise it:

  # inside the whitelist: works
  $FAKE_FTP $DEMO_DIR/allowed/public.txt

  # "backdoor" attempt outside the whitelist: blocked (EPERM)
  $FAKE_FTP $DEMO_DIR/secret.txt
  $FAKE_FTP /root/.bash_history

Terminal C (optional) — watch kernel-side deny log:

  sudo cat /sys/kernel/debug/tracing/trace_pipe

EOF
}

sub="${1:-all}"
case "$sub" in
    deps) cmd_deps ;;
    check) cmd_check ;;
    build) cmd_build ;;
    demo) cmd_demo ;;
    all)
        cmd_deps
        cmd_check
        cmd_build
        cmd_demo
        ;;
    -h | --help | help)
        sed -n '2,15p' "$0"
        ;;
    *) die "unknown subcommand: $sub (try '$0 help')" ;;
esac
