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

die()  { echo "error: $*" >&2; exit 1; }
info() { echo "[*] $*"; }
warn() { echo "[!] $*" >&2; }

need_root() {
    [[ "$(id -u)" -eq 0 ]] || die "subcommand '$1' needs root — run with sudo"
}

cmd_deps() {
    need_root deps
    info "installing build dependencies (apt)..."
    apt-get update
    apt-get install -y \
        clang llvm \
        libbpf-dev libelf-dev zlib1g-dev \
        bpftool linux-headers-"$(uname -r)" linux-tools-"$(uname -r)" \
        || apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev \
                              bpftool linux-headers-"$(uname -r)"
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

    [[ -r /sys/kernel/security/lsm ]] \
        || die "/sys/kernel/security/lsm unreadable (securityfs not mounted?)"

    local lsms
    lsms="$(cat /sys/kernel/security/lsm)"
    info "active LSMs: $lsms"

    if [[ ",$lsms," == *",bpf,"* ]]; then
        info "bpf is in the LSM chain — you're good to go"
        return 0
    fi

    cat >&2 <<EOF

[!] 'bpf' is NOT in the active LSM chain — the whitelister will fail to attach.

To enable BPF LSM on Ubuntu/Debian:

  1) Edit /etc/default/grub and add 'lsm=...' to GRUB_CMDLINE_LINUX_DEFAULT,
     appending 'bpf' to the list of current LSMs. For your system:

       GRUB_CMDLINE_LINUX_DEFAULT="quiet splash lsm=${lsms},bpf"

  2) sudo update-grub
  3) reboot
  4) re-run:  $0 check

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
    echo "this file is inside the whitelist, ftp may read it"  > "$DEMO_DIR/allowed/public.txt"
    echo "this file is SECRET — a well-behaved ftp must NOT read it" > "$DEMO_DIR/secret.txt"
    chmod -R a+rX "$DEMO_DIR"

    info "building a minimal 'ftp' reader binary at $FAKE_FTP ..."
    # Tiny standalone reader, named literally "ftp" so task->comm == "ftp"
    # without any argv[0]-spoofing tricks (which fail on multi-call
    # coreutils binaries on Ubuntu 25.10+).
    local src=/tmp/ftp_reader.c
    cat > "$src" <<'EOS'
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

Terminal A — start the whitelister (run as root):

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
    deps)  cmd_deps  ;;
    check) cmd_check ;;
    build) cmd_build ;;
    demo)  cmd_demo  ;;
    all)   cmd_deps; cmd_check; cmd_build; cmd_demo ;;
    -h|--help|help)
        sed -n '2,15p' "$0"
        ;;
    *) die "unknown subcommand: $sub (try '$0 help')" ;;
esac
