# PROJET: Kernel Module Collection & Analysis Tools

**Module**: 2.7 - Kernel Development & OS Internals
**Difficulte**: Expert
**Duree**: 20h
**Score qualite**: 98/100

## Objectifs

Creer une collection complete d'outils d'analyse kernel et de modules demonstratifs.

## Concepts Couverts (PROJET 2.7)

| Ref | Concept | Application |
|-----|---------|-------------|
| a | Hello world module | Basic module |
| b | /proc interface | Read/write proc file |
| c | Module parameters | Configurable |
| d | Character device | /dev/mydevice |
| e | ioctl commands | Control interface |
| f | Timer module | Periodic callback |
| g | Memory info | Custom /proc/mymem |
| h | Simple keylogger | Educational only |
| i | System call hooking | Intercept syscalls |
| j | Module communication | Netlink |
| k | Bonus: Block device | RAM disk |
| l | Bonus: Network filter | Packet filtering |
| m | Bonus: eBPF program | Tracing |

---

## Partie 1: Userspace Kernel Analysis Tools

### 1.1 Kernel Inspector (kernel_inspect)

```
Usage: kernel_inspect [OPTIONS]

Commands:
  modules    List loaded kernel modules
  symbols    Search kernel symbols
  memory     Display memory statistics
  cpu        Display CPU information
  syscalls   List system calls
  interrupts Display interrupt statistics
  devices    List character/block devices

Options:
  -v, --verbose    Verbose output
  -j, --json       JSON output format
  -h, --help       Show help
```

### 1.2 Module Analyzer (mod_analyze)

```
Usage: mod_analyze <module.ko> [OPTIONS]

Commands:
  info       Display module information
  symbols    List exported symbols
  depends    Show dependencies
  params     List parameters
  sections   Show ELF sections

Options:
  -a, --all        Show all information
  -h, --help       Show help
```

### 1.3 Syscall Tracer (syscall_trace)

```
Usage: syscall_trace [OPTIONS] -- command [args...]

Options:
  -p PID           Trace existing process
  -f, --follow     Follow forks
  -c, --count      Count syscalls
  -t, --time       Show timestamps
  -e SYSCALL       Trace specific syscall
  -o FILE          Output to file
```

---

## Partie 2: Kernel Modules (Educational - Simulated)

**Note**: This section defines module specifications. Actual kernel modules
require a Linux build environment. The implementation provides:
1. Complete module source code generation
2. Simulation of module behavior in userspace
3. Analysis of real kernel module concepts

### 2.1 Hello Module (PROJET 2.7.a)

**Specification**:
```c
// Module: hello_odyssey
// Purpose: Demonstrate basic module structure

Features:
- module_init/module_exit
- printk with multiple log levels
- MODULE_* macros
- Proper cleanup on errors
```

**Generated Code**:
```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init hello_odyssey_init(void)
{
    pr_info("ODYSSEY: Hello module loaded\n");
    pr_debug("ODYSSEY: Debug message\n");
    return 0;
}

static void __exit hello_odyssey_exit(void)
{
    pr_info("ODYSSEY: Hello module unloaded\n");
}

module_init(hello_odyssey_init);
module_exit(hello_odyssey_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ODYSSEY Curriculum");
MODULE_DESCRIPTION("Basic hello world module");
MODULE_VERSION("1.0");
```

### 2.2 Proc Interface Module (PROJET 2.7.b)

**Specification**:
```c
// Module: odyssey_proc
// Purpose: Read/write /proc interface

Features:
- /proc/odyssey_info (read-only)
- /proc/odyssey_config (read-write)
- seq_file interface for large data
- Proper locking
```

### 2.3 Configurable Module (PROJET 2.7.c)

**Specification**:
```c
// Module: odyssey_config
// Purpose: Module parameters demonstration

Parameters:
- debug_level (int, default=0)
- device_name (string, default="odyssey")
- enable_logging (bool, default=false)
- max_connections (int array)
```

### 2.4 Character Device (PROJET 2.7.d)

**Specification**:
```c
// Module: odyssey_chardev
// Purpose: Full character device driver

Features:
- Dynamic major number allocation
- /dev/odyssey device file
- Read/write operations
- Seek support
- Multiple open support
- Private data per file
```

### 2.5 ioctl Interface (PROJET 2.7.e)

**Specification**:
```c
// Device: /dev/odyssey_ctl

ioctl Commands:
#define ODYSSEY_IOC_MAGIC 'O'

#define ODYSSEY_GET_INFO    _IOR(ODYSSEY_IOC_MAGIC, 1, struct odyssey_info)
#define ODYSSEY_SET_CONFIG  _IOW(ODYSSEY_IOC_MAGIC, 2, struct odyssey_config)
#define ODYSSEY_RESET       _IO(ODYSSEY_IOC_MAGIC, 3)
#define ODYSSEY_GET_STATS   _IOR(ODYSSEY_IOC_MAGIC, 4, struct odyssey_stats)
```

### 2.6 Timer Module (PROJET 2.7.f)

**Specification**:
```c
// Module: odyssey_timer
// Purpose: Kernel timer demonstration

Features:
- Periodic timer (configurable interval)
- High-resolution timer option
- Statistics collection
- /proc/odyssey_timer for stats
```

### 2.7 Memory Info Module (PROJET 2.7.g)

**Specification**:
```c
// Module: odyssey_meminfo
// Purpose: Custom memory information

Provides:
/proc/odyssey_mem with:
- Physical memory map
- Virtual memory areas
- Slab cache statistics
- Per-CPU memory info
- Memory pressure indicators
```

### 2.8 Input Monitor (PROJET 2.7.h - Educational Only)

**IMPORTANT**: This module is for EDUCATIONAL PURPOSES ONLY.
It demonstrates kernel input subsystem concepts without actually
intercepting keystrokes on a production system.

**Specification**:
```c
// Module: odyssey_input_monitor
// Purpose: Understand input subsystem (EDUCATIONAL)

Features (Simulated):
- Input event structure analysis
- Keyboard scancode mapping
- Input device registration concept
- Event propagation demonstration

WARNING: Never deploy on production systems
This is for learning kernel internals only
```

### 2.9 Syscall Hooking (PROJET 2.7.i)

**IMPORTANT**: Modern kernels protect syscall table.
This demonstrates the concept for educational purposes.

**Specification**:
```c
// Module: odyssey_syscall_hook
// Purpose: Understand syscall interception (EDUCATIONAL)

Concepts demonstrated:
- Syscall table structure
- Function pointer replacement
- ftrace-based hooking (modern approach)
- Security implications
- Why this is blocked in production
```

### 2.10 Netlink Communication (PROJET 2.7.j)

**Specification**:
```c
// Module: odyssey_netlink
// Purpose: Kernel-userspace communication

Features:
- Custom netlink family
- Message types (request, response, event)
- Multicast groups
- Userspace client library
```

### 2.11 Bonus: RAM Disk (PROJET 2.7.k)

**Specification**:
```c
// Module: odyssey_ramdisk
// Purpose: Simple block device

Features:
- Configurable size
- Block I/O operations
- Request queue handling
- Partition support
```

### 2.12 Bonus: Network Filter (PROJET 2.7.l)

**Specification**:
```c
// Module: odyssey_netfilter
// Purpose: Packet filtering

Features:
- Netfilter hook registration
- Packet inspection
- Simple firewall rules
- Statistics collection
```

### 2.13 Bonus: eBPF Program (PROJET 2.7.m)

**Specification**:
```c
// Program: odyssey_trace.bpf.c
// Purpose: eBPF tracing

Features:
- Function entry/exit tracing
- Performance counters
- Histogram generation
- Maps for data storage
```

---

## Partie 3: Implementation

### API

```c
// ============== KERNEL INSPECTOR ==============

typedef struct {
    const char *name;
    size_t size;
    int use_count;
    const char *state;
    uint64_t address;
} module_entry_t;

typedef struct {
    const char *name;
    uint64_t address;
    const char *type;        // T, t, D, d, B, etc.
    const char *module;      // NULL for vmlinux
} symbol_entry_t;

typedef struct {
    uint64_t total_ram;
    uint64_t free_ram;
    uint64_t available;
    uint64_t buffers;
    uint64_t cached;
    uint64_t swap_total;
    uint64_t swap_free;
} memory_stats_t;

typedef struct {
    int number;
    const char *name;
    int argc;
    const char *prototype;
} syscall_entry_t;

// Module listing
int list_modules(module_entry_t **modules, int *count);
int get_module_info(const char *name, module_entry_t *info);
void free_modules(module_entry_t *modules, int count);

// Symbol operations
int search_symbols(const char *pattern, symbol_entry_t **syms, int *count);
int get_symbol_address(const char *name, uint64_t *addr);
void free_symbols(symbol_entry_t *syms, int count);

// Memory statistics
int get_memory_stats(memory_stats_t *stats);
void print_memory_stats(const memory_stats_t *stats);

// Syscall information
int list_syscalls(syscall_entry_t **calls, int *count);
int get_syscall_info(int nr, syscall_entry_t *info);

// ============== MODULE ANALYZER ==============

typedef struct {
    const char *name;
    const char *description;
    const char *author;
    const char *license;
    const char *version;
    const char **dependencies;
    int dep_count;
    const char **parameters;
    int param_count;
} module_metadata_t;

int analyze_module_file(const char *path, module_metadata_t *meta);
void print_module_metadata(const module_metadata_t *meta);

// ============== SYSCALL TRACER ==============

typedef struct {
    uint64_t timestamp_ns;
    pid_t pid;
    int syscall_nr;
    const char *name;
    uint64_t args[6];
    long retval;
    uint64_t duration_ns;
} syscall_event_t;

typedef void (*syscall_callback_t)(const syscall_event_t *event, void *userdata);

int trace_start(pid_t pid, syscall_callback_t cb, void *userdata);
int trace_stop(pid_t pid);

// ============== MODULE CODE GENERATION ==============

// Generate module source code
int generate_hello_module(const char *name, char **code);
int generate_proc_module(const char *name, const char *proc_name, char **code);
int generate_chardev_module(const char *name, const char *dev_name, char **code);
int generate_timer_module(const char *name, int interval_ms, char **code);
int generate_netlink_module(const char *name, int family, char **code);

// Generate Makefile
int generate_module_makefile(const char **modules, int count, char **makefile);

// ============== MODULE SIMULATION ==============

// Simulate module behavior in userspace
typedef struct {
    const char *name;
    void *private_data;
    int (*init)(void *data);
    void (*exit)(void *data);
    ssize_t (*read)(void *data, char *buf, size_t count);
    ssize_t (*write)(void *data, const char *buf, size_t count);
    int (*ioctl)(void *data, unsigned int cmd, void *arg);
} simulated_module_t;

int sim_module_load(simulated_module_t *mod);
int sim_module_unload(simulated_module_t *mod);
ssize_t sim_module_read(simulated_module_t *mod, char *buf, size_t count);
ssize_t sim_module_write(simulated_module_t *mod, const char *buf, size_t count);
int sim_module_ioctl(simulated_module_t *mod, unsigned int cmd, void *arg);
```

### Structures

```c
// ioctl structures for odyssey device
struct odyssey_info {
    char version[32];
    uint32_t features;
    uint64_t uptime_ns;
    int open_count;
};

struct odyssey_config {
    int debug_level;
    bool enable_logging;
    char device_name[64];
};

struct odyssey_stats {
    uint64_t bytes_read;
    uint64_t bytes_written;
    uint64_t ioctl_calls;
    uint64_t open_count;
    uint64_t close_count;
};

// Netlink message structures
struct odyssey_nl_msg {
    uint32_t cmd;
    uint32_t seq;
    uint32_t len;
    uint8_t data[];
};

enum odyssey_nl_cmd {
    ODYSSEY_CMD_GET_INFO,
    ODYSSEY_CMD_SET_CONFIG,
    ODYSSEY_CMD_GET_STATS,
    ODYSSEY_CMD_EVENT,
};
```

---

## Exemple d'Utilisation

```c
#include "kernel_modules.h"

int main(void) {
    // ============== KERNEL INSPECTOR ==============

    printf("=== Kernel Inspector ===\n\n");

    // List modules
    printf("Loaded Modules:\n");
    module_entry_t *modules;
    int mod_count;
    list_modules(&modules, &mod_count);
    for (int i = 0; i < min(mod_count, 10); i++) {
        printf("  %-20s %8zu bytes  %s\n",
               modules[i].name, modules[i].size, modules[i].state);
    }
    printf("  ... (%d total)\n\n", mod_count);

    // Memory stats
    printf("Memory Statistics:\n");
    memory_stats_t mem;
    get_memory_stats(&mem);
    print_memory_stats(&mem);
    /*
    Total RAM:     16384 MB
    Free RAM:       4096 MB
    Available:      8192 MB
    Buffers:         512 MB
    Cached:         4096 MB
    Swap Total:     8192 MB
    Swap Free:      8192 MB
    */

    // Search symbols
    printf("\nSymbols matching 'schedule':\n");
    symbol_entry_t *syms;
    int sym_count;
    search_symbols("schedule", &syms, &sym_count);
    for (int i = 0; i < min(sym_count, 5); i++) {
        printf("  %016lx %s %s\n",
               syms[i].address, syms[i].type, syms[i].name);
    }

    // ============== MODULE ANALYZER ==============

    printf("\n=== Module Analyzer ===\n\n");

    module_metadata_t meta;
    analyze_module_file("/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/intel/e1000/e1000.ko", &meta);
    print_module_metadata(&meta);
    /*
    Module: e1000
    Description: Intel(R) PRO/1000 Network Driver
    Author: Intel Corporation
    License: GPL v2
    Version: 7.3.21-k8-NAPI

    Dependencies:
      - mii

    Parameters:
      - TxDescriptors (int array)
      - RxDescriptors (int array)
      - Speed (int array)
      - Duplex (int array)
    */

    // ============== CODE GENERATION ==============

    printf("\n=== Module Code Generation ===\n\n");

    // Generate hello module
    char *hello_code;
    generate_hello_module("odyssey_hello", &hello_code);
    printf("Generated hello module:\n%s\n", hello_code);

    // Generate proc module
    char *proc_code;
    generate_proc_module("odyssey_proc", "odyssey_info", &proc_code);
    printf("Generated proc module:\n%s\n", proc_code);

    // Generate character device
    char *chardev_code;
    generate_chardev_module("odyssey_dev", "odyssey", &chardev_code);
    printf("Generated chardev module (truncated):\n%.500s...\n", chardev_code);

    // Generate Makefile
    const char *mod_names[] = {"odyssey_hello", "odyssey_proc", "odyssey_dev"};
    char *makefile;
    generate_module_makefile(mod_names, 3, &makefile);
    printf("Generated Makefile:\n%s\n", makefile);

    // ============== MODULE SIMULATION ==============

    printf("\n=== Module Simulation ===\n\n");

    // Simulate a character device module
    simulated_module_t sim_mod = {
        .name = "sim_odyssey",
        .init = sim_odyssey_init,
        .exit = sim_odyssey_exit,
        .read = sim_odyssey_read,
        .write = sim_odyssey_write,
        .ioctl = sim_odyssey_ioctl,
    };

    printf("Loading simulated module...\n");
    sim_module_load(&sim_mod);

    printf("Writing to simulated device...\n");
    const char *msg = "Hello, simulated kernel!";
    sim_module_write(&sim_mod, msg, strlen(msg));

    printf("Reading from simulated device...\n");
    char buf[256];
    ssize_t n = sim_module_read(&sim_mod, buf, sizeof(buf) - 1);
    buf[n] = '\0';
    printf("Read: %s\n", buf);

    printf("ioctl ODYSSEY_GET_INFO...\n");
    struct odyssey_info info;
    sim_module_ioctl(&sim_mod, ODYSSEY_GET_INFO, &info);
    printf("Version: %s, Open count: %d\n", info.version, info.open_count);

    printf("Unloading simulated module...\n");
    sim_module_unload(&sim_mod);

    // ============== SYSCALL TRACER ==============

    printf("\n=== Syscall Tracer ===\n\n");

    printf("Tracing 'ls -la' syscalls:\n");
    // Fork and trace child
    pid_t pid = fork();
    if (pid == 0) {
        // Child - traced
        execl("/bin/ls", "ls", "-la", NULL);
        exit(1);
    }

    // Parent - tracer
    trace_start(pid, syscall_print_callback, NULL);
    int status;
    waitpid(pid, &status, 0);
    trace_stop(pid);
    /*
    execve("/bin/ls", ["ls", "-la"], ...) = 0
    access("/etc/ld.so.preload", R_OK) = -1 ENOENT
    openat(AT_FDCWD, "/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
    read(3, "\177ELF...", 832) = 832
    ...
    write(1, "total 128\n", 10) = 10
    write(1, "drwxr-xr-x...", ...) = ...
    ...
    exit_group(0) = ?
    */

    // Cleanup
    free(hello_code);
    free(proc_code);
    free(chardev_code);
    free(makefile);
    free_modules(modules, mod_count);
    free_symbols(syms, sym_count);

    return 0;
}
```

---

## Tests Moulinette

```rust
// Kernel Inspector
#[test] fn test_list_modules()          // PROJET.a
#[test] fn test_search_symbols()        // PROJET.a
#[test] fn test_memory_stats()          // PROJET.g
#[test] fn test_syscall_list()          // PROJET.i

// Module Analyzer
#[test] fn test_analyze_module()        // PROJET.b-c

// Code Generation
#[test] fn test_generate_hello()        // PROJET.a
#[test] fn test_generate_proc()         // PROJET.b
#[test] fn test_generate_chardev()      // PROJET.d-e
#[test] fn test_generate_timer()        // PROJET.f
#[test] fn test_generate_netlink()      // PROJET.j

// Simulation
#[test] fn test_sim_module_load()       // PROJET.a
#[test] fn test_sim_module_io()         // PROJET.d
#[test] fn test_sim_module_ioctl()      // PROJET.e

// Syscall Tracer
#[test] fn test_syscall_trace()         // PROJET.i

// Bonus
#[test] fn test_netfilter_design()      // PROJET.l
#[test] fn test_ebpf_design()           // PROJET.m
```

---

## Bareme

| Composant | Points |
|-----------|--------|
| **Kernel Inspector** | |
| Module listing | 10 |
| Symbol search | 10 |
| Memory stats | 5 |
| Syscall info | 5 |
| **Module Analyzer** | |
| Module parsing | 10 |
| Dependency analysis | 5 |
| **Code Generation** | |
| Hello module | 5 |
| Proc module | 10 |
| Chardev module | 15 |
| Timer module | 5 |
| Netlink module | 10 |
| **Simulation** | |
| Module lifecycle | 5 |
| I/O operations | 5 |
| **Bonus** | |
| Block device design | +5 |
| Network filter design | +5 |
| eBPF program design | +5 |
| **Total** | **100 (+15)** |

---

## Fichiers

```
PROJET_kernel_modules/
├── include/
│   ├── kernel_modules.h
│   ├── kernel_inspect.h
│   ├── mod_analyze.h
│   ├── syscall_trace.h
│   └── odyssey_ioctl.h
├── src/
│   ├── inspector/
│   │   ├── modules.c
│   │   ├── symbols.c
│   │   ├── memory.c
│   │   └── syscalls.c
│   ├── analyzer/
│   │   ├── mod_parse.c
│   │   └── mod_deps.c
│   ├── generator/
│   │   ├── gen_hello.c
│   │   ├── gen_proc.c
│   │   ├── gen_chardev.c
│   │   ├── gen_timer.c
│   │   ├── gen_netlink.c
│   │   └── gen_makefile.c
│   ├── simulator/
│   │   ├── sim_module.c
│   │   └── sim_device.c
│   └── tracer/
│       └── syscall_trace.c
├── modules/              # Generated module source
│   ├── odyssey_hello/
│   ├── odyssey_proc/
│   ├── odyssey_chardev/
│   ├── odyssey_timer/
│   └── odyssey_netlink/
├── tools/
│   ├── kernel_inspect.c
│   ├── mod_analyze.c
│   └── syscall_trace.c
├── tests/
│   └── test_all.c
└── Makefile
```

---

## Notes Importantes

### Securite

1. **Input Monitor (PROJET 2.7.h)**: For EDUCATIONAL purposes only
   - Never deploy on production systems
   - Demonstrates concepts, not exploitation
   - Legal only in controlled environments

2. **Syscall Hooking (PROJET 2.7.i)**: Educational demonstration
   - Modern kernels prevent this
   - Shows why kernel protection exists
   - ftrace is the legitimate approach

### Environnement de Test

Pour tester les modules reels (si disponible):
```bash
# VM or test machine ONLY
qemu-system-x86_64 -kernel bzImage -initrd initramfs.cpio \
    -append "console=ttyS0" -nographic

# Inside VM
insmod odyssey_hello.ko
dmesg | tail
rmmod odyssey_hello
```

### References

- Linux Kernel Documentation: https://www.kernel.org/doc/html/latest/
- Linux Device Drivers (LDD3): https://lwn.net/Kernel/LDD3/
- The Linux Kernel Module Programming Guide
