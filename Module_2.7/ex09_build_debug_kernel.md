# ex09: Building & Debugging the Kernel

**Module**: 2.7 - Kernel Development & OS Internals
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.7.18: Building the Kernel (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | make menuconfig | Configure |
| b | .config | Configuration file |
| c | make | Build kernel |
| d | make modules | Build modules |
| e | make install | Install kernel |
| f | make modules_install | Install modules |
| g | initramfs | Initial RAM filesystem |
| h | GRUB | Bootloader configuration |

### 2.7.19: Kernel Debugging (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | printk | Kernel printf |
| b | dmesg | Kernel messages |
| c | Log levels | KERN_ERR, KERN_INFO |
| d | KGDB | Kernel debugger |
| e | QEMU + GDB | Debug kernel |
| f | ftrace | Function tracer |
| g | kprobes | Dynamic probes |
| h | eBPF | Extended BPF |
| i | crash | Crash dump analysis |

---

## Sujet

Comprendre la compilation du noyau et les techniques de debogage kernel.

### Structures

```c
#include <stdint.h>
#include <stdbool.h>

// 2.7.18.b: Kernel config entry
typedef struct {
    const char *name;           // CONFIG_XXX
    const char *value;          // y, m, n, or string/int
    bool is_set;
    const char *help;
} config_entry_t;

// Build target info
typedef struct {
    const char *target;         // make target
    const char *description;
    const char *output;         // Output file(s)
    bool requires_root;
} build_target_t;

// 2.7.18.g: initramfs info
typedef struct {
    const char *path;
    size_t size;
    const char *compression;    // gzip, lzma, xz
    int file_count;
    const char *init_program;   // /init
} initramfs_info_t;

// 2.7.18.h: GRUB entry
typedef struct {
    const char *title;
    const char *kernel;         // vmlinuz path
    const char *initrd;         // initramfs path
    const char *options;        // Kernel command line
    bool is_default;
} grub_entry_t;

// 2.7.19.a,c: printk log level
typedef enum {
    KERN_EMERG = 0,             // System unusable
    KERN_ALERT = 1,             // Action required
    KERN_CRIT = 2,              // Critical
    KERN_ERR = 3,               // Error
    KERN_WARNING = 4,           // Warning
    KERN_NOTICE = 5,            // Normal significant
    KERN_INFO = 6,              // Informational
    KERN_DEBUG = 7              // Debug
} kern_log_level_t;

// 2.7.19.b: dmesg entry
typedef struct {
    double timestamp;           // Seconds since boot
    int level;                  // Log level
    const char *facility;       // kern, user, etc.
    const char *message;
} dmesg_entry_t;

// 2.7.19.f: ftrace event
typedef struct {
    double timestamp;
    int cpu;
    pid_t pid;
    const char *comm;           // Process name
    const char *function;
    const char *parent;         // Caller
    uint64_t duration_ns;       // For function_graph
} ftrace_event_t;

// 2.7.19.g: kprobe info
typedef struct {
    const char *symbol;         // Probed function
    uint64_t address;
    int hit_count;
    bool is_return_probe;       // kretprobe
} kprobe_info_t;

// 2.7.19.h: eBPF program info
typedef struct {
    int id;
    const char *name;
    const char *type;           // kprobe, tracepoint, etc.
    bool jited;
    size_t bytes_xlated;
    size_t bytes_jited;
    uint64_t run_count;
    uint64_t run_time_ns;
} bpf_prog_info_t;
```

### API

```c
// ============== BUILDING THE KERNEL ==============
// 2.7.18

// 2.7.18.a: Configuration
void explain_menuconfig(void);
void explain_config_tools(void);
void list_config_tools(build_target_t **tools, int *count);

// 2.7.18.b: .config file
int read_kernel_config(const char *path, config_entry_t **entries, int *count);
const char *get_config_value(const char *name);
bool is_config_enabled(const char *name);
bool is_config_module(const char *name);
void print_config_diff(const char *old_config, const char *new_config);

// 2.7.18.c-d: Build commands
void explain_make_kernel(void);
void explain_make_modules(void);
void list_make_targets(build_target_t **targets, int *count);
void print_make_targets(void);

// 2.7.18.e-f: Installation
void explain_make_install(void);
void explain_modules_install(void);
void show_installed_kernels(void);

// 2.7.18.g: initramfs
void explain_initramfs(void);
int analyze_initramfs(const char *path, initramfs_info_t *info);
void print_initramfs_info(const initramfs_info_t *info);
int list_initramfs_contents(const char *path, char ***files, int *count);

// mkinitcpio/dracut/mkinitramfs
void explain_initramfs_tools(void);

// 2.7.18.h: GRUB
void explain_grub(void);
int list_grub_entries(grub_entry_t **entries, int *count);
void print_grub_entry(const grub_entry_t *entry);
void show_kernel_cmdline(void);

// ============== KERNEL DEBUGGING ==============
// 2.7.19

// 2.7.19.a: printk
void explain_printk(void);
void show_printk_examples(void);
const char *log_level_string(kern_log_level_t level);

// Modern pr_* macros
void explain_pr_macros(void);

// 2.7.19.b: dmesg
int read_dmesg(dmesg_entry_t **entries, int *count);
int filter_dmesg(kern_log_level_t min_level, dmesg_entry_t **entries, int *count);
void print_dmesg_entry(const dmesg_entry_t *entry);
void explain_dmesg(void);

// 2.7.19.c: Log levels
void explain_log_levels(void);
int get_current_console_loglevel(void);
int get_current_default_loglevel(void);

// 2.7.19.d: KGDB
void explain_kgdb(void);
void show_kgdb_setup(void);
void show_kgdb_commands(void);

// 2.7.19.e: QEMU + GDB
void explain_qemu_debugging(void);
void show_qemu_gdb_setup(void);
void show_gdb_kernel_commands(void);

// 2.7.19.f: ftrace
void explain_ftrace(void);
void show_ftrace_usage(void);
int read_ftrace_output(const char *trace_file, ftrace_event_t **events, int *count);
void print_ftrace_event(const ftrace_event_t *event);

// Available tracers
void list_available_tracers(void);
void explain_function_tracer(void);
void explain_function_graph_tracer(void);

// 2.7.19.g: kprobes
void explain_kprobes(void);
void show_kprobe_example(void);
int list_active_kprobes(kprobe_info_t **probes, int *count);
void print_kprobe_info(const kprobe_info_t *probe);

// 2.7.19.h: eBPF
void explain_ebpf(void);
void explain_bpf_tracing(void);
int list_bpf_programs(bpf_prog_info_t **progs, int *count);
void print_bpf_prog_info(const bpf_prog_info_t *prog);

// bpftrace/bcc
void explain_bpftrace(void);
void show_bpftrace_examples(void);

// 2.7.19.i: crash
void explain_crash_tool(void);
void show_crash_commands(void);
void explain_kdump(void);
```

---

## Exemple

```c
#include "build_debug_kernel.h"

int main(void) {
    // ============== BUILDING THE KERNEL ==============
    // 2.7.18

    printf("=== Building the Linux Kernel ===\n");

    // 2.7.18.a: make menuconfig
    printf("\n=== make menuconfig (a) ===\n");
    explain_menuconfig();
    /*
    make menuconfig: Text-based configuration

    Features:
      - Navigate menus with arrows
      - Space toggles options
      - Y = built-in, M = module, N = disabled
      - Enter for submenus
      - / to search options
      - ? for help on current option

    Other config tools:
      make xconfig    - Qt GUI
      make gconfig    - GTK GUI
      make nconfig    - Improved text UI
      make oldconfig  - Update from old .config
      make defconfig  - Default for architecture
      make tinyconfig - Minimal configuration
    */

    // 2.7.18.b: .config
    printf("\n=== .config File (b) ===\n");
    printf(".config: Kernel configuration file\n\n");

    printf("Format:\n");
    printf("  CONFIG_OPTION=y    # Built-in\n");
    printf("  CONFIG_OPTION=m    # Module\n");
    printf("  # CONFIG_OPTION is not set\n");
    printf("  CONFIG_STRING=\"value\"\n");
    printf("  CONFIG_INT=123\n\n");

    // Read current config
    printf("Checking some config options:\n");
    printf("  CONFIG_SMP: %s\n",
           is_config_enabled("SMP") ? "enabled" : "disabled");
    printf("  CONFIG_MODULES: %s\n",
           is_config_enabled("MODULES") ? "enabled" : "disabled");
    printf("  CONFIG_EXT4_FS: %s\n",
           is_config_module("EXT4_FS") ? "module" :
           (is_config_enabled("EXT4_FS") ? "built-in" : "disabled"));

    // 2.7.18.c-d: Building
    printf("\n=== Building (c-d) ===\n");
    print_make_targets();
    /*
    Common make targets:
      make              - Build vmlinux and modules
      make vmlinux      - Build kernel only
      make modules      - Build modules only
      make bzImage      - Compressed kernel (x86)
      make Image        - Kernel image (ARM)
      make clean        - Remove most generated files
      make mrproper     - Remove all generated files + .config
      make distclean    - mrproper + backup files

    Parallel build:
      make -j$(nproc)   - Use all CPU cores
      make -j8          - Use 8 jobs
    */

    printf("\nBuild output:\n");
    printf("  vmlinux        - Uncompressed kernel (for debugging)\n");
    printf("  arch/x86/boot/bzImage - Compressed bootable kernel\n");
    printf("  System.map     - Symbol table\n");
    printf("  .config        - Configuration used\n");

    // 2.7.18.e-f: Installation
    printf("\n=== Installation (e-f) ===\n");
    explain_make_install();
    /*
    make install (e):
      1. Copies bzImage to /boot/vmlinuz-<version>
      2. Copies System.map to /boot/
      3. Runs installkernel script
      4. May update bootloader

    make modules_install (f):
      1. Installs modules to /lib/modules/<version>/
      2. Generates modules.dep
      3. Runs depmod

    Typical sequence:
      make -j$(nproc)
      sudo make modules_install
      sudo make install
    */

    show_installed_kernels();
    /*
    Installed kernels:
      /boot/vmlinuz-6.1.0-generic
      /boot/vmlinuz-6.2.0-generic
      /boot/vmlinuz-6.3.0-custom
    */

    // 2.7.18.g: initramfs
    printf("\n=== initramfs (g) ===\n");
    explain_initramfs();
    /*
    initramfs: Initial RAM Filesystem

    Purpose:
      - Early boot environment
      - Load modules for root fs
      - Handle encrypted disks
      - Complex root device setup

    Contains:
      - /init script (or systemd)
      - Essential modules
      - Device manager (udev)
      - Minimal userspace

    Creation tools:
      mkinitcpio (Arch)
      dracut (Fedora, RHEL)
      mkinitramfs (Debian, Ubuntu)
      update-initramfs
    */

    initramfs_info_t initinfo;
    analyze_initramfs("/boot/initrd.img-$(uname -r)", &initinfo);
    print_initramfs_info(&initinfo);

    // 2.7.18.h: GRUB
    printf("\n=== GRUB (h) ===\n");
    explain_grub();
    /*
    GRUB: GRand Unified Bootloader

    Configuration:
      /boot/grub/grub.cfg - Main config (generated)
      /etc/default/grub   - User settings
      /etc/grub.d/        - Config scripts

    Entry format:
      menuentry 'Linux 6.1.0' {
          linux /vmlinuz-6.1.0 root=/dev/sda1 ro quiet
          initrd /initrd.img-6.1.0
      }

    Commands:
      update-grub         - Regenerate grub.cfg
      grub-install /dev/sda - Install to disk
    */

    printf("\nKernel command line:\n");
    show_kernel_cmdline();
    // root=/dev/sda1 ro quiet splash

    // ============== KERNEL DEBUGGING ==============
    // 2.7.19

    printf("\n=== Kernel Debugging ===\n");

    // 2.7.19.a: printk
    printf("\n=== printk (a) ===\n");
    explain_printk();
    /*
    printk: Kernel's printf

    Usage:
      printk(KERN_INFO "Message: %d\n", value);
      printk("Default level message\n");

    Modern pr_* macros (preferred):
      pr_emerg("Emergency!\n");
      pr_err("Error: %d\n", err);
      pr_warn("Warning\n");
      pr_info("Info\n");
      pr_debug("Debug\n");  // Needs CONFIG_DYNAMIC_DEBUG

    Rate limiting:
      printk_ratelimited(KERN_WARNING "Spammy message\n");
      pr_info_ratelimited("Also rate limited\n");
    */

    // 2.7.19.b: dmesg
    printf("\n=== dmesg (b) ===\n");
    explain_dmesg();
    /*
    dmesg: Display kernel ring buffer

    Options:
      dmesg          - Show all messages
      dmesg -T       - Human-readable timestamps
      dmesg -w       - Follow (like tail -f)
      dmesg -l err   - Only errors
      dmesg -c       - Clear after display
      dmesg --color  - Colorize by level
    */

    printf("\nRecent kernel messages:\n");
    dmesg_entry_t *entries;
    int count;
    read_dmesg(&entries, &count);
    for (int i = 0; i < (count > 5 ? 5 : count); i++) {
        print_dmesg_entry(&entries[i]);
    }

    // 2.7.19.c: Log levels
    printf("\n=== Log Levels (c) ===\n");
    explain_log_levels();
    /*
    Level | Name      | Meaning
    ------|-----------|--------
    0     | KERN_EMERG  | System unusable
    1     | KERN_ALERT  | Action must be taken
    2     | KERN_CRIT   | Critical conditions
    3     | KERN_ERR    | Error conditions
    4     | KERN_WARNING| Warning conditions
    5     | KERN_NOTICE | Normal but significant
    6     | KERN_INFO   | Informational
    7     | KERN_DEBUG  | Debug-level messages

    Console loglevel:
      /proc/sys/kernel/printk
      current default minimum boot-time-default
    */

    // 2.7.19.d: KGDB
    printf("\n=== KGDB (d) ===\n");
    explain_kgdb();
    /*
    KGDB: Kernel GNU Debugger

    Requirements:
      CONFIG_KGDB=y
      CONFIG_KGDB_SERIAL_CONSOLE=y

    Boot parameters:
      kgdboc=ttyS0,115200 kgdbwait

    Connect with GDB:
      (gdb) target remote /dev/ttyS0

    Features:
      - Breakpoints
      - Memory inspection
      - Single stepping
      - Core dumps
    */

    // 2.7.19.e: QEMU + GDB
    printf("\n=== QEMU + GDB (e) ===\n");
    explain_qemu_debugging();
    /*
    QEMU + GDB: Easiest kernel debugging

    Launch QEMU with debugging:
      qemu-system-x86_64 \
        -kernel bzImage \
        -initrd initramfs.cpio \
        -append "console=ttyS0 nokaslr" \
        -nographic \
        -s -S

    Options:
      -s    : GDB server on tcp::1234
      -S    : Pause at start
      nokaslr : Disable ASLR (easier debugging)

    Connect GDB:
      gdb vmlinux
      (gdb) target remote :1234
      (gdb) break start_kernel
      (gdb) continue
    */

    show_gdb_kernel_commands();

    // 2.7.19.f: ftrace
    printf("\n=== ftrace (f) ===\n");
    explain_ftrace();
    /*
    ftrace: Function tracer

    Interface: /sys/kernel/debug/tracing/

    Basic usage:
      # Enable function tracer
      echo function > current_tracer

      # Filter functions
      echo 'schedule*' > set_ftrace_filter

      # Enable tracing
      echo 1 > tracing_on

      # Read trace
      cat trace

      # Disable
      echo 0 > tracing_on

    Tracers:
      function       - Function entry
      function_graph - Entry/exit with duration
      nop            - Disabled
    */

    list_available_tracers();

    // 2.7.19.g: kprobes
    printf("\n=== kprobes (g) ===\n");
    explain_kprobes();
    /*
    kprobes: Dynamic kernel probes

    Types:
      kprobe    - Probe any instruction
      kretprobe - Probe function return
      jprobe    - Probe function entry (deprecated)

    Usage (via perf):
      perf probe --add 'do_sys_open'
      perf record -e probe:do_sys_open -a
      perf report

    Or via debugfs:
      echo 'p:myprobe do_sys_open' > /sys/kernel/debug/tracing/kprobe_events
      echo 1 > /sys/kernel/debug/tracing/events/kprobes/myprobe/enable
    */

    // 2.7.19.h: eBPF
    printf("\n=== eBPF (h) ===\n");
    explain_ebpf();
    /*
    eBPF: Extended Berkeley Packet Filter

    Modern tracing and networking:
      - Safe code runs in kernel
      - JIT compiled
      - Verified for safety
      - Attach to many hook points

    Program types:
      kprobe/kretprobe - Function tracing
      tracepoint       - Static tracepoints
      socket_filter    - Packet filtering
      xdp             - Fast packet processing

    Tools:
      bpftrace - High-level tracing language
      BCC      - Python/C toolkit
      libbpf   - Low-level C library
    */

    show_bpftrace_examples();
    /*
    # Count syscalls by process
    bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'

    # Function latency
    bpftrace -e 'kprobe:vfs_read { @start[tid] = nsecs; }
                 kretprobe:vfs_read /@start[tid]/ {
                     @ns = hist(nsecs - @start[tid]);
                     delete(@start[tid]);
                 }'

    # Stack traces
    bpftrace -e 'kprobe:schedule { @[kstack] = count(); }'
    */

    // 2.7.19.i: crash
    printf("\n=== crash (i) ===\n");
    explain_crash_tool();
    /*
    crash: Crash dump analysis

    Requirements:
      - Kernel with debug info (vmlinux)
      - Crash dump (vmcore)
      - crash utility

    Usage:
      crash vmlinux vmcore

    Commands:
      bt     - Backtrace
      ps     - Process list
      log    - dmesg
      dis    - Disassemble
      struct - Show structure
      sym    - Symbol lookup
      files  - Open files
      net    - Network info
    */

    explain_kdump();
    /*
    kdump: Kernel crash dump mechanism

    Works by:
      1. Reserve memory at boot (crashkernel=256M)
      2. On panic, kexec to capture kernel
      3. Capture kernel saves memory to disk
      4. Reboot normally

    Configuration:
      /etc/kdump.conf
      systemctl enable kdump
    */

    return 0;
}
```

---

## Tests Moulinette

```rust
// Building
#[test] fn test_config_read()           // 2.7.18.b
#[test] fn test_make_targets()          // 2.7.18.c-d
#[test] fn test_initramfs_analyze()     // 2.7.18.g
#[test] fn test_grub_entries()          // 2.7.18.h

// Debugging
#[test] fn test_printk_levels()         // 2.7.19.a,c
#[test] fn test_dmesg_parse()           // 2.7.19.b
#[test] fn test_ftrace()                // 2.7.19.f
#[test] fn test_ebpf_info()             // 2.7.19.h
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Configuration (2.7.18.a-b) | 15 |
| Building (2.7.18.c-f) | 15 |
| initramfs/GRUB (2.7.18.g-h) | 10 |
| printk/dmesg (2.7.19.a-c) | 20 |
| KGDB/QEMU (2.7.19.d-e) | 15 |
| ftrace/kprobes (2.7.19.f-g) | 15 |
| eBPF/crash (2.7.19.h-i) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex09/
├── build_debug_kernel.h
├── config.c
├── build.c
├── initramfs.c
├── grub.c
├── printk_dmesg.c
├── ftrace.c
├── ebpf.c
└── Makefile
```
