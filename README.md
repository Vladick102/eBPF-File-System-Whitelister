# eBPF File System Whitelister

The primary goal of this project is to whitelist application access to file resources using **eBPF (Extended Berkeley Packet Filter)**. The primary use case is to ensure that a target application (like an FTP server) has access only to a certain directory.

## Current State of the Work

* **`basic_hello/`:** Contains initial prototyping environment. Utilizes the **BCC (BPF Compiler Collection)** framework and a Python user-space agent (`hello_bcc.py`) to verify kernel configuration and intercept basic process creation events (the `clone` syscall).
  
* **`advanced_hello/`:** Contains transition to a **CO-RE (Compile Once - Run Everywhere)** architecture. It moves away from Python to a pure C implementation using `libbpf`. The directory contains the program that attaches to the `sys_enter_openat` tracepoint to monitor file access across the operating system. [README.md](advanced_hello/README.md) contains the guide on setting up the dependencies, compilation and execution of this program.
