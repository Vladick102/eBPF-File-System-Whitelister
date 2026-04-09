"""
Run the following command to install bcc on a debian-based distro
sudo apt update
sudo apt install bpfcc-tools linux-headers-$(uname -r) python3-bpfcc

Run the script using sudo:
sudo python3 hello_bcc.py
"""

from bcc import BPF

bpf_program = """
int hello(void *ctx) {
    bpf_trace_printk("Hello, eBPF World!\\n");
    return 0;
}
"""

# compiling and loading the C code into kernel
b = BPF(text=bpf_program)

# get_syscall_fnname returns the full syscall name for the call "clone"
syscall_name = b.get_syscall_fnname("clone")

# attach the "hello" function using kprobe to the syscall "clone"
# (will execute each time "clone" is called)
b.attach_kprobe(event=syscall_name, fn_name="hello")

# read the kernel log
print(f"BCC is executed Successfully\n Tracking Syscalls: {syscall_name}...")

try:
    # b.trace_print() reads from the buffer that was populated by bpf_trace_printk (in "hello" func)
    b.trace_print()
except KeyboardInterrupt:
    print("\n Keyboard Interrupt")
