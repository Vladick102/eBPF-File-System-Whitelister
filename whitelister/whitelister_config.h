// Single source of truth shared between:
//   - whitelister.bpf.c   (the BPF program, compiled with clang -target bpf)
//   - whitelister.c       (the user-space loader, compiled as ordinary C)
//   - tests/run_tests.sh  (greps MAX_COMMS out of this file at runtime)

#ifndef WHITELISTER_CONFIG_H
#define WHITELISTER_CONFIG_H

#define MAX_PATH        1024
#define TASK_COMM_LEN   16
#define LPM_PATH_MAX    240
#define MAX_COMMS       16
#define MAX_PREFIXES    128

#endif /* WHITELISTER_CONFIG_H */
