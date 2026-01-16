# ex07: Kernel Modules & /proc, /sys Filesystems

**Module**: 2.7 - Kernel Development & OS Internals
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.7.14: Kernel Modules (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Loadable module | Runtime extension |
| b | module_init | Entry point |
| c | module_exit | Cleanup |
| d | insmod | Load module |
| e | rmmod | Remove module |
| f | lsmod | List modules |
| g | modprobe | Load with dependencies |
| h | MODULE_LICENSE | License declaration |
| i | EXPORT_SYMBOL | Export symbol |
| j | Module parameters | module_param |

### 2.7.15: /proc and /sys Filesystems (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | procfs | Process information |
| b | /proc/[pid] | Per-process info |
| c | /proc/meminfo | Memory info |
| d | /proc/cpuinfo | CPU info |
| e | sysfs | Kernel object hierarchy |
| f | /sys/class | Device classes |
| g | /sys/devices | Device tree |
| h | kobject | Kernel object |
| i | Creating proc entry | proc_create |
| j | seq_file | Sequential file interface |

---

## Sujet

Comprendre les modules noyau et les systemes de fichiers virtuels /proc et /sys.

### Structures

```c
#include <stdint.h>
#include <stdbool.h>

// 2.7.14.a: Module info
typedef struct {
    const char *name;
    const char *filename;
    size_t size;
    int use_count;
    const char *dependencies[32];
    int dep_count;
    const char *state;          // Live, Loading, Unloading
    uint64_t address;           // Module base address
    bool tainted;               // Taint status
} module_info_t;

// 2.7.14.h: Module license
typedef enum {
    LICENSE_GPL,
    LICENSE_GPL_V2,
    LICENSE_GPL_AND_ADDITIONAL,
    LICENSE_BSD,
    LICENSE_MIT,
    LICENSE_PROPRIETARY
} module_license_t;

// 2.7.14.j: Module parameter
typedef struct {
    const char *name;
    const char *type;           // int, uint, bool, charp, etc.
    const char *description;
    int perm;                   // Permissions
    const char *value;          // Current value
} module_param_t;

// 2.7.14.i: Exported symbol
typedef struct {
    const char *name;
    uint64_t address;
    const char *module;         // NULL if kernel core
    bool gpl_only;              // EXPORT_SYMBOL_GPL
} exported_symbol_t;

// 2.7.15.a-d: /proc entry info
typedef struct {
    const char *path;           // e.g., "/proc/meminfo"
    mode_t mode;
    uid_t uid;
    gid_t gid;
    size_t size;
    const char *type;           // file, dir, link
} proc_entry_t;

// 2.7.15.b: Process info from /proc/[pid]
typedef struct {
    pid_t pid;
    char comm[256];             // Command name
    char state;                 // Process state
    pid_t ppid;                 // Parent PID
    uid_t uid;
    gid_t gid;
    uint64_t vsize;             // Virtual memory size
    long rss;                   // Resident set size
    uint64_t start_time;
    int num_threads;
} proc_pid_info_t;

// 2.7.15.c: Memory info
typedef struct {
    uint64_t mem_total;
    uint64_t mem_free;
    uint64_t mem_available;
    uint64_t buffers;
    uint64_t cached;
    uint64_t swap_total;
    uint64_t swap_free;
    uint64_t shmem;
    uint64_t slab;
} meminfo_t;

// 2.7.15.d: CPU info
typedef struct {
    int processor;              // CPU number
    const char *vendor_id;
    int family;
    int model;
    const char *model_name;
    int stepping;
    float mhz;
    size_t cache_size;
    int physical_id;
    int core_id;
    int siblings;
    int cores;
    const char *flags;
} cpuinfo_t;

// 2.7.15.e-g: sysfs entry
typedef struct {
    const char *path;
    const char *type;           // dir, file, link
    const char *subsystem;
    const char *driver;
    mode_t mode;
} sysfs_entry_t;

// 2.7.15.h: kobject simulation
typedef struct kobject {
    const char *name;
    struct kobject *parent;
    void *ktype;                // kobject type
    void *kset;                 // Set of kobjects
    int ref_count;
} kobject_t;
```

### API

```c
// ============== KERNEL MODULES ==============
// 2.7.14

// 2.7.14.a: Module information
int get_module_info(const char *name, module_info_t *info);
int list_loaded_modules(module_info_t **modules, int *count);
void print_module_info(const module_info_t *info);
void free_module_list(module_info_t *modules, int count);

// 2.7.14.d-g: Module operations (info only, not actual loading)
void explain_insmod(void);
void explain_rmmod(void);
void explain_lsmod(void);
void explain_modprobe(void);

// Parse lsmod output
int parse_lsmod_output(const char *output, module_info_t **modules, int *count);

// 2.7.14.b-c: module_init/exit
void explain_module_init_exit(void);
void show_module_skeleton(void);

// 2.7.14.h: License
const char *module_license_string(module_license_t license);
void explain_module_licenses(void);
module_license_t get_module_license(const char *module);

// 2.7.14.i: Exported symbols
int list_exported_symbols(exported_symbol_t **symbols, int *count);
int search_symbol(const char *name, exported_symbol_t *sym);
void explain_export_symbol(void);

// 2.7.14.j: Module parameters
int get_module_params(const char *module, module_param_t **params, int *count);
void print_module_params(const char *module);
void explain_module_params(void);

// Module dependencies
int get_module_dependencies(const char *module, char ***deps, int *count);
void print_module_tree(const char *module);

// ============== PROCFS ==============
// 2.7.15.a-d

// 2.7.15.a: Procfs structure
void explain_procfs(void);
int list_proc_entries(proc_entry_t **entries, int *count);
void print_proc_tree(void);

// 2.7.15.b: Per-process info
int get_proc_pid_info(pid_t pid, proc_pid_info_t *info);
void print_proc_pid_info(const proc_pid_info_t *info);
int list_proc_pid_files(pid_t pid, char ***files, int *count);

// Get specific files
int read_proc_cmdline(pid_t pid, char *buf, size_t size);
int read_proc_status(pid_t pid, proc_pid_info_t *info);
int read_proc_maps(pid_t pid, char ***maps, int *count);
int read_proc_fd(pid_t pid, char ***fds, int *count);

// 2.7.15.c: Memory info
int get_meminfo(meminfo_t *info);
void print_meminfo(const meminfo_t *info);

// 2.7.15.d: CPU info
int get_cpuinfo(cpuinfo_t **cpus, int *count);
void print_cpuinfo(const cpuinfo_t *cpu);
int get_cpu_count(void);

// Other /proc files
int read_proc_uptime(double *uptime, double *idle);
int read_proc_loadavg(double *load1, double *load5, double *load15);
int read_proc_version(char *buf, size_t size);

// ============== SYSFS ==============
// 2.7.15.e-h

// 2.7.15.e: Sysfs structure
void explain_sysfs(void);
int list_sysfs_entries(const char *path, sysfs_entry_t **entries, int *count);
void print_sysfs_tree(const char *path, int depth);

// 2.7.15.f: Device classes
int list_device_classes(char ***classes, int *count);
int list_class_devices(const char *class_name, char ***devices, int *count);
void print_class_devices(const char *class_name);

// 2.7.15.g: Device tree
void print_device_tree(void);
int get_device_info(const char *device_path, sysfs_entry_t *info);

// 2.7.15.h: kobject
void explain_kobject(void);
kobject_t *kobject_create(const char *name, kobject_t *parent);
void kobject_put(kobject_t *kobj);
void kobject_get(kobject_t *kobj);

// Read/write sysfs attributes
int sysfs_read_attr(const char *path, char *buf, size_t size);
int sysfs_write_attr(const char *path, const char *value);

// ============== PROC ENTRY CREATION (SIMULATION) ==============
// 2.7.15.i-j

// 2.7.15.i: proc_create simulation
typedef ssize_t (*proc_read_fn)(char *buf, size_t count);
typedef ssize_t (*proc_write_fn)(const char *buf, size_t count);

typedef struct {
    const char *name;
    mode_t mode;
    proc_read_fn read;
    proc_write_fn write;
    void *private_data;
} proc_ops_t;

int my_proc_create(const char *name, mode_t mode,
                   const proc_ops_t *ops);
void my_proc_remove(const char *name);

// 2.7.15.j: seq_file interface
void explain_seq_file(void);
void show_seq_file_example(void);
```

---

## Exemple

```c
#include "modules_proc_sys.h"

int main(void) {
    // ============== KERNEL MODULES ==============
    // 2.7.14

    printf("=== Kernel Modules ===\n");

    // 2.7.14.a: Loadable modules
    printf("\n=== Loadable Kernel Modules (a) ===\n");
    printf("Modules extend kernel at runtime:\n");
    printf("  - No reboot required\n");
    printf("  - Load only needed drivers\n");
    printf("  - Reduce kernel size\n");
    printf("  - File extension: .ko (kernel object)\n");

    // List loaded modules
    module_info_t *modules;
    int mod_count;
    list_loaded_modules(&modules, &mod_count);
    printf("\nLoaded modules: %d\n", mod_count);
    for (int i = 0; i < (mod_count > 5 ? 5 : mod_count); i++) {
        print_module_info(&modules[i]);
    }
    /*
    Module: nvidia
      Size: 26714112 bytes
      Used by: 0
      State: Live
      Address: 0xffffffffc0800000
    */

    // 2.7.14.b-c: module_init/exit
    printf("\n=== module_init/exit (b-c) ===\n");
    explain_module_init_exit();
    /*
    module_init(init_function):
      - Called when module is loaded
      - Returns 0 on success, negative on error
      - Performs initialization

    module_exit(exit_function):
      - Called when module is unloaded
      - Performs cleanup
      - Releases resources
    */

    printf("\nModule skeleton:\n");
    show_module_skeleton();
    /*
    #include <linux/module.h>
    #include <linux/kernel.h>
    #include <linux/init.h>

    static int __init my_init(void) {
        printk(KERN_INFO "Module loaded\n");
        return 0;
    }

    static void __exit my_exit(void) {
        printk(KERN_INFO "Module unloaded\n");
    }

    module_init(my_init);
    module_exit(my_exit);
    MODULE_LICENSE("GPL");
    */

    // 2.7.14.d-g: Module commands
    printf("\n=== Module Commands (d-g) ===\n");

    printf("\ninsmod (d): Load single module\n");
    explain_insmod();
    /*
    insmod module.ko [param=value]
      - Loads single module
      - Does NOT resolve dependencies
      - Module must be fully specified path
      - Fails if dependencies missing
    */

    printf("\nrmmod (e): Remove module\n");
    explain_rmmod();
    /*
    rmmod module_name
      - Unloads module
      - Fails if module in use
      - Calls module_exit()
    */

    printf("\nlsmod (f): List modules\n");
    explain_lsmod();
    /*
    lsmod
      Displays: Module, Size, Used by
      Reads from /proc/modules
    */

    printf("\nmodprobe (g): Smart loading\n");
    explain_modprobe();
    /*
    modprobe module_name
      - Resolves dependencies automatically
      - Uses /lib/modules/$(uname -r)/
      - Reads modules.dep
      - Preferred over insmod
    */

    // 2.7.14.h: License
    printf("\n=== MODULE_LICENSE (h) ===\n");
    explain_module_licenses();
    /*
    Required declaration:
      MODULE_LICENSE("GPL");

    Common licenses:
      "GPL"           - GNU GPL v2 or later
      "GPL v2"        - GNU GPL v2 only
      "Dual BSD/GPL"  - Choice of BSD or GPL
      "Proprietary"   - Non-free (taints kernel)

    Tainted kernel:
      - Missing license taints kernel
      - Some symbols only exported to GPL modules
      - Affects bug reports/support
    */

    // 2.7.14.i: Exported symbols
    printf("\n=== EXPORT_SYMBOL (i) ===\n");
    explain_export_symbol();
    /*
    EXPORT_SYMBOL(symbol):
      - Makes symbol available to other modules
      - Without export, symbol is private

    EXPORT_SYMBOL_GPL(symbol):
      - Only available to GPL modules
      - Used for internal kernel APIs

    Example:
      void my_function(int x);
      EXPORT_SYMBOL(my_function);
    */

    exported_symbol_t sym;
    if (search_symbol("printk", &sym) == 0) {
        printf("\nSymbol 'printk':\n");
        printf("  Address: 0x%lx\n", sym.address);
        printf("  Module: %s\n", sym.module ? sym.module : "kernel");
        printf("  GPL only: %s\n", sym.gpl_only ? "yes" : "no");
    }

    // 2.7.14.j: Module parameters
    printf("\n=== Module Parameters (j) ===\n");
    explain_module_params();
    /*
    module_param(name, type, perm):
      - Declares parameter settable at load time
      - Types: int, uint, bool, charp, etc.
      - Permissions for /sys/module/xxx/parameters/

    Example:
      static int debug = 0;
      module_param(debug, int, 0644);
      MODULE_PARM_DESC(debug, "Enable debug mode");

    Usage:
      insmod module.ko debug=1
      modprobe module debug=1
    */

    print_module_params("snd_hda_intel");
    /*
    Module: snd_hda_intel
    Parameters:
      index: int (0644) = -1
      model: charp (0644) = (null)
      position_fix: int (0644) = 0
      probe_mask: int (0644) = -1
    */

    free_module_list(modules, mod_count);

    // ============== PROCFS ==============
    // 2.7.15.a-d

    printf("\n=== /proc Filesystem ===\n");

    // 2.7.15.a: procfs overview
    printf("\n=== procfs (a) ===\n");
    explain_procfs();
    /*
    /proc: Virtual filesystem
      - Kernel interface to user space
      - Created dynamically
      - No disk storage
      - Process and system information
    */

    printf("\nKey /proc entries:\n");
    printf("  /proc/[pid]/    - Per-process directories\n");
    printf("  /proc/meminfo   - Memory statistics\n");
    printf("  /proc/cpuinfo   - CPU information\n");
    printf("  /proc/modules   - Loaded modules\n");
    printf("  /proc/version   - Kernel version\n");
    printf("  /proc/uptime    - System uptime\n");

    // 2.7.15.b: Per-process info
    printf("\n=== /proc/[pid] (b) ===\n");
    pid_t mypid = getpid();
    proc_pid_info_t pid_info;
    get_proc_pid_info(mypid, &pid_info);
    print_proc_pid_info(&pid_info);
    /*
    Process 12345:
      Command: test_program
      State: R (Running)
      Parent PID: 12340
      UID: 1000, GID: 1000
      Virtual Size: 4194304
      RSS: 1024 pages
      Threads: 1
    */

    printf("\nFiles in /proc/%d/:\n", mypid);
    char **files;
    int file_count;
    list_proc_pid_files(mypid, &files, &file_count);
    for (int i = 0; i < (file_count > 10 ? 10 : file_count); i++) {
        printf("  %s\n", files[i]);
    }
    /*
    cmdline, comm, cwd, environ, exe, fd,
    maps, mem, root, stat, status, ...
    */

    // 2.7.15.c: Memory info
    printf("\n=== /proc/meminfo (c) ===\n");
    meminfo_t mem;
    get_meminfo(&mem);
    print_meminfo(&mem);
    /*
    Memory Info:
      Total:      16384000 kB
      Free:        4096000 kB
      Available:   8192000 kB
      Buffers:      512000 kB
      Cached:      4096000 kB
      SwapTotal:   8192000 kB
      SwapFree:    8192000 kB
    */

    // 2.7.15.d: CPU info
    printf("\n=== /proc/cpuinfo (d) ===\n");
    cpuinfo_t *cpus;
    int cpu_count;
    get_cpuinfo(&cpus, &cpu_count);
    printf("CPUs: %d\n", cpu_count);
    if (cpu_count > 0) {
        print_cpuinfo(&cpus[0]);
    }
    /*
    CPU 0:
      Vendor: GenuineIntel
      Model: Intel(R) Core(TM) i7-10700K
      MHz: 3800.000
      Cache: 16384 KB
      Cores: 8
    */

    // ============== SYSFS ==============
    // 2.7.15.e-h

    printf("\n=== /sys Filesystem ===\n");

    // 2.7.15.e: sysfs overview
    printf("\n=== sysfs (e) ===\n");
    explain_sysfs();
    /*
    /sys: Kernel object hierarchy
      - One file per attribute
      - Reflects kernel data structures
      - kobjects exposed as directories
      - Attributes as files

    Structure:
      /sys/bus/        - Bus types
      /sys/class/      - Device classes
      /sys/devices/    - Device tree
      /sys/module/     - Loaded modules
      /sys/kernel/     - Kernel settings
    */

    // 2.7.15.f: Device classes
    printf("\n=== /sys/class (f) ===\n");
    printf("Device classes group similar devices:\n");

    char **classes;
    int class_count;
    list_device_classes(&classes, &class_count);
    printf("\nDevice classes:\n");
    for (int i = 0; i < (class_count > 10 ? 10 : class_count); i++) {
        printf("  %s\n", classes[i]);
    }
    /*
    block, net, input, tty, pci_bus,
    scsi_disk, sound, backlight, ...
    */

    printf("\nDevices in 'net' class:\n");
    print_class_devices("net");
    /*
    /sys/class/net/
      eth0 -> ../../devices/pci0000:00/.../net/eth0
      lo -> ../../devices/virtual/net/lo
      wlan0 -> ../../devices/pci0000:00/.../net/wlan0
    */

    // 2.7.15.g: Device tree
    printf("\n=== /sys/devices (g) ===\n");
    printf("Physical device hierarchy:\n");
    print_sysfs_tree("/sys/devices", 2);
    /*
    /sys/devices/
      pci0000:00/
        0000:00:02.0/  (VGA)
        0000:00:1f.0/  (LPC)
      platform/
      system/
        cpu/
        memory/
      virtual/
        block/
        net/
    */

    // 2.7.15.h: kobject
    printf("\n=== kobject (h) ===\n");
    explain_kobject();
    /*
    kobject: Kernel object
      - Base building block of sysfs
      - Reference counted
      - Hierarchical (parent/child)
      - Has attributes (files)

    struct kobject {
        const char *name;
        struct kobject *parent;
        struct kset *kset;
        struct kobj_type *ktype;
        struct kernfs_node *sd;
        struct kref kref;
    };

    Functions:
      kobject_init()
      kobject_add()
      kobject_get()/kobject_put()
      kobject_del()
    */

    // Reading sysfs attributes
    char buf[256];
    if (sysfs_read_attr("/sys/class/net/lo/mtu", buf, sizeof(buf)) == 0) {
        printf("\nLoopback MTU: %s", buf);
    }

    // 2.7.15.i-j: Creating proc entries
    printf("\n=== Creating /proc Entries (i-j) ===\n");
    printf("proc_create (i): Create /proc file\n");
    printf("  - Deprecated: create_proc_entry\n");
    printf("  - Modern: proc_create with proc_ops\n\n");

    printf("seq_file (j): Sequential file interface\n");
    explain_seq_file();
    /*
    seq_file: For large /proc files
      - Handles buffer management
      - Supports iteration
      - Simple API

    Operations:
      seq_open()    - Open seq_file
      seq_read()    - Standard read
      seq_lseek()   - Standard seek
      seq_release() - Standard release

    Iterator:
      start() - Start iteration
      next()  - Next item
      stop()  - End iteration
      show()  - Display item
    */

    return 0;
}
```

---

## Tests Moulinette

```rust
// Modules
#[test] fn test_list_modules()          // 2.7.14.a
#[test] fn test_module_info()           // 2.7.14.a-c
#[test] fn test_module_commands()       // 2.7.14.d-g
#[test] fn test_module_license()        // 2.7.14.h
#[test] fn test_exported_symbols()      // 2.7.14.i
#[test] fn test_module_params()         // 2.7.14.j

// Procfs
#[test] fn test_proc_pid()              // 2.7.15.a-b
#[test] fn test_meminfo()               // 2.7.15.c
#[test] fn test_cpuinfo()               // 2.7.15.d

// Sysfs
#[test] fn test_sysfs_structure()       // 2.7.15.e
#[test] fn test_device_classes()        // 2.7.15.f-g
#[test] fn test_kobject()               // 2.7.15.h
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Module listing (2.7.14.a) | 10 |
| init/exit (2.7.14.b-c) | 10 |
| Module commands (2.7.14.d-g) | 15 |
| License/symbols (2.7.14.h-i) | 10 |
| Module params (2.7.14.j) | 5 |
| procfs (2.7.15.a-d) | 25 |
| sysfs (2.7.15.e-h) | 20 |
| proc_create/seq_file (2.7.15.i-j) | 5 |
| **Total** | **100** |

---

## Fichiers

```
ex07/
├── modules_proc_sys.h
├── modules.c
├── procfs.c
├── sysfs.c
├── kobject.c
└── Makefile
```
