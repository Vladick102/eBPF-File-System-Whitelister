### Installing Dependencies

To run the no-Python advanced hello, the following dependencies need to be installed:

```bash
sudo apt install clang llvm libbpf-dev bpftool linux-headers-$(uname -r)
```

### Compilation

Than we need to generate a header file for that contains every single data structure, type definition, and macro used by your currently running Linux kernel:

```bash
cd advanced_hello
```

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

or (`bpftool` may be installed in `/usr/sbin/` which is not present in `$PATH` by default):

```bash
/usr/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

compile the code for kernel:
```bash
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c hello.bpf.c -o hello.bpf.o
```

generate C-skeleton from the bytecode:
```bash
/usr/sbin/bpftool gen skeleton hello.bpf.o > hello.skel.h
```

compile the user-space program:
```bash
clang -g -O2 -Wall hello.c -lbpf -lelf -lz -o hello
```

### Execution

execute the compiled user-space loader:
```bash
sudo ./hello
```

to see the actual output of the program we can read the kernel pipe while `hello` is running:
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```