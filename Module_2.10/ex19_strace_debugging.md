# ex19: Advanced Debugging - strace

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 3h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.36: Advanced Debugging - strace (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | strace | System call tracer |
| b | Basic usage | strace command |
| c | -p | Attach to PID |
| d | -f | Follow forks |
| e | -e | Filter syscalls |
| f | -t | Timestamp |
| g | -c | Statistics |
| h | -o | Output file |
| i | Reading output | Understanding traces |

---

## Sujet

Maitriser strace pour le debogage et l'analyse de programmes.

---

## Exemple

```c
#include "strace_debug.h"
#include <stdio.h>
#include <stdlib.h>

void explain_strace(void) {
    printf("=== strace ===\n\n");

    printf("strace traces system calls and signals:\n");
    printf("  - See what syscalls a program makes\n");
    printf("  - Debug hangs, crashes, performance\n");
    printf("  - Understand program behavior\n");
    printf("  - No source code or recompilation needed\n");
}

void show_basic_usage(void) {
    printf("\n=== Basic Usage ===\n\n");

    printf("Run command with strace:\n");
    printf("  strace ls\n");
    printf("  strace -o output.txt ls\n");

    printf("\nAttach to running process:\n");
    printf("  strace -p 1234\n");
    printf("  strace -p $(pgrep nginx)\n");

    printf("\nFollow child processes:\n");
    printf("  strace -f ./server\n");
    printf("  strace -ff -o trace ./multiproc  # Separate files\n");
}

void show_filtering(void) {
    printf("\n=== Filtering Syscalls ===\n\n");

    printf("Filter by syscall name:\n");
    printf("  strace -e open ls           # Only open()\n");
    printf("  strace -e read,write cat    # read() and write()\n");
    printf("  strace -e '!close' ls       # All except close()\n");

    printf("\nFilter by category:\n");
    printf("  strace -e trace=file ls     # File operations\n");
    printf("  strace -e trace=network nc  # Network operations\n");
    printf("  strace -e trace=process sh  # Process management\n");
    printf("  strace -e trace=signal kill # Signals\n");
    printf("  strace -e trace=ipc ipcs    # IPC\n");
    printf("  strace -e trace=memory mmap # Memory management\n");
    printf("  strace -e trace=desc cat    # File descriptors\n");

    printf("\nCategories:\n");
    printf("  file:    open, stat, chmod, etc.\n");
    printf("  network: socket, connect, send, etc.\n");
    printf("  process: fork, execve, wait, etc.\n");
    printf("  signal:  signal, sigaction, kill, etc.\n");
    printf("  ipc:     shmget, semget, msgget, etc.\n");
    printf("  memory:  mmap, brk, mprotect, etc.\n");
    printf("  desc:    read, write, close, dup, etc.\n");
}

void show_timing(void) {
    printf("\n=== Timing Information ===\n\n");

    printf("Add timestamps:\n");
    printf("  strace -t ls         # Time of day (HH:MM:SS)\n");
    printf("  strace -tt ls        # With microseconds\n");
    printf("  strace -ttt ls       # Unix epoch\n");

    printf("\nShow syscall duration:\n");
    printf("  strace -T ls\n");
    printf("  # Output: open(\"file\", ...) = 3 <0.000123>\n");

    printf("\nRelative timestamps:\n");
    printf("  strace -r ls\n");
    printf("  # Time since previous syscall\n");
}

void show_statistics(void) {
    printf("\n=== Statistics ===\n\n");

    printf("Summary mode:\n");
    printf("  strace -c ls\n");
    printf("\n");
    printf("  %%time     seconds  usecs/call     calls    errors syscall\n");
    printf("  ------  ----------- ----------- --------- --------- ----------------\n");
    printf("   55.00    0.000055           7         8           write\n");
    printf("   20.00    0.000020           3         6           read\n");
    printf("   15.00    0.000015           2         6         4 open\n");
    printf("  ...\n");

    printf("\nSummary + output:\n");
    printf("  strace -c -S time ls    # Sort by time\n");
    printf("  strace -c -S calls ls   # Sort by calls\n");
    printf("  strace -C ls            # Summary at end + trace\n");
}

void show_output_options(void) {
    printf("\n=== Output Options ===\n\n");

    printf("Output to file:\n");
    printf("  strace -o trace.log ls\n");
    printf("  strace -ff -o trace ls  # trace.PID per process\n");

    printf("\nString length:\n");
    printf("  strace -s 1000 ls       # Show 1000 chars (default 32)\n");

    printf("\nVerbose output:\n");
    printf("  strace -v ls            # Don't abbreviate\n");

    printf("\nPointer values:\n");
    printf("  strace -x ls            # Hex for non-ASCII\n");
    printf("  strace -xx ls           # Hex for all strings\n");
}

void show_reading_output(void) {
    printf("\n=== Reading strace Output ===\n\n");

    printf("Syscall format:\n");
    printf("  syscall(arg1, arg2, ...) = return_value\n");

    printf("\nExample output:\n");
    printf("  openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY) = 3\n");
    printf("  │       │        │               │          │\n");
    printf("  │       │        │               │          └─ fd returned\n");
    printf("  │       │        │               └─ flags\n");
    printf("  │       │        └─ file path\n");
    printf("  │       └─ \"at current directory\"\n");
    printf("  └─ syscall name\n");

    printf("\nError example:\n");
    printf("  open(\"/noexist\", O_RDONLY) = -1 ENOENT (No such file)\n");
    printf("  # Returns -1 with error code\n");

    printf("\nSignal:\n");
    printf("  --- SIGTERM {si_signo=SIGTERM, ...} ---\n");

    printf("\nUnfinished call (async):\n");
    printf("  read(0, <unfinished ...>\n");
    printf("  --- SIGINT ---\n");
    printf("  <... read resumed>)           = ? ERESTARTSYS\n");
}

void show_practical_examples(void) {
    printf("\n=== Practical Examples ===\n\n");

    printf("Debug 'file not found':\n");
    printf("  strace -e openat,stat myapp 2>&1 | grep -i error\n");
    printf("  # See which file is missing\n");

    printf("\nDebug network issues:\n");
    printf("  strace -e trace=network -f nginx\n");
    printf("  # See connect() failures, DNS lookups\n");

    printf("\nFind why app is slow:\n");
    printf("  strace -T -o /tmp/slow.log myapp\n");
    printf("  grep '<0\\.' /tmp/slow.log | sort -t'<' -k2 -rn | head\n");
    printf("  # Find slowest syscalls\n");

    printf("\nDebug hanging process:\n");
    printf("  strace -p $(pgrep myapp)\n");
    printf("  # See what it's waiting on (read, select, futex?)\n");

    printf("\nSee files accessed:\n");
    printf("  strace -e trace=file -o /tmp/files.log myapp\n");
    printf("  grep 'open\\|stat' /tmp/files.log\n");

    printf("\nDebug permission denied:\n");
    printf("  strace -e trace=file myapp 2>&1 | grep EACCES\n");
    printf("  strace -e trace=file myapp 2>&1 | grep EPERM\n");

    printf("\nAnalyze library loading:\n");
    printf("  strace -e openat ldd /bin/ls 2>&1 | grep '\\.so'\n");
}

void show_advanced_usage(void) {
    printf("\n=== Advanced Usage ===\n\n");

    printf("Inject errors (for testing):\n");
    printf("  strace -e inject=open:error=ENOENT ls\n");
    printf("  strace -e inject=write:error=EIO:when=3 myapp\n");
    printf("  # Fail 3rd write with EIO\n");

    printf("\nInject delays:\n");
    printf("  strace -e inject=read:delay_exit=100000 cat\n");
    printf("  # Add 100ms delay after each read\n");

    printf("\nTrace specific fd:\n");
    printf("  strace -e read=3 -e write=3 myapp\n");
    printf("  # Only show read/write on fd 3\n");

    printf("\nPath filtering:\n");
    printf("  strace -P /etc/passwd myapp\n");
    printf("  # Only syscalls involving this path\n");

    printf("\nDecode file descriptors:\n");
    printf("  strace -y ls\n");
    printf("  # Shows: write(1</dev/pts/0>, ...)\n");

    printf("\nContainer debugging:\n");
    printf("  nsenter -t <pid> -n strace -p <pid>\n");
    printf("  # Trace process in container namespace\n");
}

int main(void) {
    explain_strace();
    show_basic_usage();
    show_filtering();
    show_timing();
    show_statistics();
    show_output_options();
    show_reading_output();
    show_practical_examples();
    show_advanced_usage();

    printf("\n=== Quick Reference ===\n\n");
    printf("  strace cmd           # Trace command\n");
    printf("  strace -p PID        # Attach to process\n");
    printf("  strace -f cmd        # Follow forks\n");
    printf("  strace -e syscall    # Filter\n");
    printf("  strace -c cmd        # Statistics\n");
    printf("  strace -T cmd        # Show duration\n");
    printf("  strace -o file cmd   # Output to file\n");

    return 0;
}
```

---

## Fichiers

```
ex19/
├── strace_debug.h
├── strace_basics.c
├── filtering.c
├── timing_stats.c
├── practical_examples.c
└── Makefile
```
