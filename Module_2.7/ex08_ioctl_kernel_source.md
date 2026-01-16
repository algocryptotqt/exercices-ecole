# ex08: ioctl Interface & Kernel Source Organization

**Module**: 2.7 - Kernel Development & OS Internals
**Difficulte**: Difficile
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.7.16: ioctl Interface (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | ioctl() | Device control |
| b | Request code | Command identifier |
| c | _IO, _IOR, _IOW, _IOWR | Macros |
| d | Type | Magic number |
| e | Number | Command number |
| f | Size | Data size |
| g | Implementation | switch on command |
| h | copy_from_user | Get user data |
| i | copy_to_user | Send user data |

### 2.7.17: Linux Kernel Source (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Source tree | Organization |
| b | arch/ | Architecture-specific |
| c | kernel/ | Core kernel |
| d | mm/ | Memory management |
| e | fs/ | File systems |
| f | drivers/ | Device drivers |
| g | net/ | Networking |
| h | include/ | Headers |
| i | Kconfig | Configuration |
| j | Makefile | Build system |

---

## Sujet

Comprendre l'interface ioctl et l'organisation du code source du noyau Linux.

### Structures

```c
#include <stdint.h>
#include <stdbool.h>

// 2.7.16.b-f: ioctl request code structure
typedef struct {
    uint8_t direction;        // _IOC_NONE, _IOC_READ, _IOC_WRITE
    uint8_t type;             // d: Magic number
    uint8_t number;           // e: Command number
    uint16_t size;            // f: Data size
    uint32_t full_code;       // Complete request code
} ioctl_code_t;

// Direction flags
typedef enum {
    IOC_NONE = 0,             // _IO
    IOC_WRITE = 1,            // _IOW (user writes to kernel)
    IOC_READ = 2,             // _IOR (user reads from kernel)
    IOC_READWRITE = 3         // _IOWR
} ioctl_direction_t;

// Known ioctl command
typedef struct {
    uint32_t code;
    const char *name;
    const char *description;
    const char *device;       // Associated device
    const char *struct_name;  // Data structure
} known_ioctl_t;

// 2.7.17.a: Source directory
typedef struct {
    const char *name;
    const char *description;
    size_t file_count;
    size_t line_count;
    const char *key_files[10];
} kernel_dir_t;

// Kconfig option
typedef struct {
    const char *name;
    const char *type;         // bool, tristate, int, string
    const char *help;
    const char *depends;
    const char *default_val;
    bool selected;
} kconfig_option_t;
```

### API

```c
// ============== IOCTL REQUEST CODES ==============
// 2.7.16.b-f

// 2.7.16.c: Build ioctl codes
uint32_t _IO(uint8_t type, uint8_t nr);
uint32_t _IOR(uint8_t type, uint8_t nr, size_t size);
uint32_t _IOW(uint8_t type, uint8_t nr, size_t size);
uint32_t _IOWR(uint8_t type, uint8_t nr, size_t size);

// Decode ioctl codes
void decode_ioctl(uint32_t code, ioctl_code_t *decoded);
void print_ioctl_code(uint32_t code);

// Get components
uint8_t _IOC_DIR(uint32_t code);
uint8_t _IOC_TYPE(uint32_t code);
uint8_t _IOC_NR(uint32_t code);
uint16_t _IOC_SIZE(uint32_t code);

// Explain macros
void explain_ioctl_macros(void);

// ============== IOCTL USAGE ==============
// 2.7.16.a,g

// 2.7.16.a: ioctl explanation
void explain_ioctl(void);

// 2.7.16.g: Implementation pattern
void show_ioctl_implementation(void);

// Known ioctls database
int lookup_ioctl(uint32_t code, known_ioctl_t *info);
int list_ioctls_for_device(const char *device, known_ioctl_t **ioctls, int *count);
void print_common_ioctls(void);

// ============== COPY TO/FROM USER ==============
// 2.7.16.h-i

// Simulate copy_from_user/copy_to_user
void explain_copy_user(void);
void show_copy_user_example(void);

// Memory access checking
bool access_ok(int type, const void *addr, size_t size);

// ============== KERNEL SOURCE TREE ==============
// 2.7.17.a-h

// 2.7.17.a: Source organization
void explain_kernel_source(void);
int get_kernel_directories(kernel_dir_t **dirs, int *count);
void print_kernel_tree(void);

// Specific directories
void explain_arch_dir(void);           // 2.7.17.b
void explain_kernel_dir(void);         // 2.7.17.c
void explain_mm_dir(void);             // 2.7.17.d
void explain_fs_dir(void);             // 2.7.17.e
void explain_drivers_dir(void);        // 2.7.17.f
void explain_net_dir(void);            // 2.7.17.g
void explain_include_dir(void);        // 2.7.17.h

// Get directory info
int get_dir_info(const char *dir_name, kernel_dir_t *info);

// ============== BUILD SYSTEM ==============
// 2.7.17.i-j

// 2.7.17.i: Kconfig
void explain_kconfig(void);
int parse_kconfig_option(const char *text, kconfig_option_t *opt);
void print_kconfig_option(const kconfig_option_t *opt);

// 2.7.17.j: Makefile
void explain_kernel_makefile(void);
void show_module_makefile(void);

// Configuration tools
void explain_menuconfig(void);
void explain_oldconfig(void);
void explain_defconfig(void);

// ============== CODE EXAMPLES ==============

// Show real kernel code examples
void show_syscall_implementation(const char *syscall);
void show_driver_example(const char *type);
void show_fs_example(const char *fs);
```

---

## Exemple

```c
#include "ioctl_kernel_source.h"

int main(void) {
    // ============== IOCTL INTERFACE ==============
    // 2.7.16

    printf("=== ioctl Interface ===\n");

    // 2.7.16.a: ioctl overview
    printf("\n=== ioctl() (a) ===\n");
    explain_ioctl();
    /*
    ioctl(): I/O Control
      - Device-specific operations
      - Beyond read/write
      - Format: ioctl(fd, request, arg)

    Use cases:
      - Get/set device parameters
      - Control device behavior
      - Query device status
      - Perform special operations
    */

    // 2.7.16.b: Request code
    printf("\n=== Request Code (b) ===\n");
    printf("ioctl request code encodes:\n");
    printf("  - Direction (2 bits): None, Read, Write, Both\n");
    printf("  - Type (8 bits): Magic number (device type)\n");
    printf("  - Number (8 bits): Command number\n");
    printf("  - Size (14 bits): Data size\n");

    // 2.7.16.c-f: Macros
    printf("\n=== ioctl Macros (c-f) ===\n");
    explain_ioctl_macros();
    /*
    Macros for creating request codes:

    _IO(type, nr):
      No data transfer
      Example: _IO('T', 1) for terminal ops

    _IOR(type, nr, size):
      Read from device (user gets data)
      Example: _IOR('T', 2, struct termios)

    _IOW(type, nr, size):
      Write to device (user sends data)
      Example: _IOW('T', 3, struct termios)

    _IOWR(type, nr, size):
      Both directions
      Example: _IOWR('T', 4, struct data)
    */

    // Build some ioctl codes
    printf("\nBuilding ioctl codes:\n");

    // Type (d)
    char magic = 'M';  // Our device magic number
    printf("Magic type (d): '%c' (0x%02x)\n", magic, magic);

    // Number (e)
    int cmd_get_status = 1;
    int cmd_set_param = 2;
    printf("Command numbers (e): GET_STATUS=%d, SET_PARAM=%d\n",
           cmd_get_status, cmd_set_param);

    // Size (f)
    struct my_status { int value; char name[32]; };
    printf("Data size (f): sizeof(struct my_status)=%zu\n",
           sizeof(struct my_status));

    // Create codes
    uint32_t MYDEV_GET_STATUS = _IOR(magic, cmd_get_status, sizeof(struct my_status));
    uint32_t MYDEV_SET_PARAM = _IOW(magic, cmd_set_param, sizeof(int));

    printf("\nGenerated codes:\n");
    print_ioctl_code(MYDEV_GET_STATUS);
    print_ioctl_code(MYDEV_SET_PARAM);
    /*
    Code 0x80244d01:
      Direction: Read (kernel -> user)
      Type: 'M' (0x4d)
      Number: 1
      Size: 36 bytes

    Code 0x40044d02:
      Direction: Write (user -> kernel)
      Type: 'M' (0x4d)
      Number: 2
      Size: 4 bytes
    */

    // Decode example
    printf("\nDecoding terminal ioctl TCGETS:\n");
    uint32_t TCGETS = 0x5401;
    print_ioctl_code(TCGETS);

    // 2.7.16.g: Implementation
    printf("\n=== ioctl Implementation (g) ===\n");
    show_ioctl_implementation();
    /*
    static long mydev_ioctl(struct file *file,
                            unsigned int cmd, unsigned long arg)
    {
        switch (cmd) {
        case MYDEV_GET_STATUS:
            // Read from device, send to user
            struct my_status status;
            get_device_status(&status);
            if (copy_to_user((void __user *)arg, &status,
                             sizeof(status)))
                return -EFAULT;
            return 0;

        case MYDEV_SET_PARAM:
            // Get data from user, write to device
            int param;
            if (copy_from_user(&param, (void __user *)arg,
                               sizeof(param)))
                return -EFAULT;
            set_device_param(param);
            return 0;

        default:
            return -ENOTTY;  // Invalid ioctl for device
        }
    }
    */

    // 2.7.16.h-i: copy_from_user / copy_to_user
    printf("\n=== copy_from_user / copy_to_user (h-i) ===\n");
    explain_copy_user();
    /*
    copy_from_user (h):
      - Copies data from user space to kernel
      - Checks user pointer validity
      - Returns number of bytes NOT copied
      - Returns 0 on success

    copy_to_user (i):
      - Copies data from kernel to user space
      - Checks user pointer validity
      - Returns number of bytes NOT copied
      - Returns 0 on success

    Why needed:
      - User pointers may be invalid
      - User memory may be swapped out
      - Security boundary enforcement
      - Page fault handling in kernel

    Never use memcpy with user pointers!
    */

    // Common ioctls
    printf("\n=== Common ioctls ===\n");
    print_common_ioctls();
    /*
    Terminal (tty):
      TCGETS    0x5401  Get termios
      TCSETS    0x5402  Set termios
      TIOCGWINSZ        Get window size
      TIOCSWINSZ        Set window size

    Block devices:
      BLKGETSIZE  Get size in sectors
      BLKFLSBUF   Flush buffer

    Network:
      SIOCGIFADDR   Get interface address
      SIOCSIFADDR   Set interface address
    */

    // ============== KERNEL SOURCE ORGANIZATION ==============
    // 2.7.17

    printf("\n=== Linux Kernel Source ===\n");

    // 2.7.17.a: Source tree
    printf("\n=== Source Tree (a) ===\n");
    explain_kernel_source();
    print_kernel_tree();
    /*
    linux/
    ├── arch/        (b) Architecture-specific
    ├── block/           Block device layer
    ├── certs/           Certificates
    ├── crypto/          Cryptographic API
    ├── Documentation/   Docs
    ├── drivers/     (f) Device drivers
    ├── firmware/        Firmware files
    ├── fs/          (e) File systems
    ├── include/     (h) Headers
    ├── init/            Kernel initialization
    ├── ipc/             IPC (shmem, semaphores)
    ├── kernel/      (c) Core kernel
    ├── lib/             Library routines
    ├── mm/          (d) Memory management
    ├── net/         (g) Networking
    ├── samples/         Sample code
    ├── scripts/         Build scripts
    ├── security/        Security modules
    ├── sound/           Sound drivers
    ├── tools/           Development tools
    ├── usr/             initramfs
    └── virt/            Virtualization
    */

    // 2.7.17.b: arch/
    printf("\n=== arch/ (b) ===\n");
    explain_arch_dir();
    /*
    arch/: Architecture-specific code
      arch/x86/      - x86 and x86-64
      arch/arm/      - 32-bit ARM
      arch/arm64/    - 64-bit ARM (aarch64)
      arch/riscv/    - RISC-V
      arch/powerpc/  - PowerPC
      ...

    arch/x86/ contains:
      boot/          - Boot code, compressed kernel
      entry/         - Entry points (syscalls, interrupts)
      kernel/        - x86-specific kernel code
      mm/            - x86 memory management
      include/       - x86 headers

    Key files:
      arch/x86/boot/compressed/head_64.S - Entry point
      arch/x86/kernel/head_64.S - 64-bit startup
      arch/x86/entry/entry_64.S - Syscall entry
    */

    // 2.7.17.c: kernel/
    printf("\n=== kernel/ (c) ===\n");
    explain_kernel_dir();
    /*
    kernel/: Core kernel subsystems
      sched/         - Scheduler
      locking/       - Synchronization
      time/          - Timekeeping
      power/         - Power management
      trace/         - Tracing
      bpf/           - eBPF

    Key files:
      kernel/fork.c         - Process creation
      kernel/exit.c         - Process termination
      kernel/signal.c       - Signal handling
      kernel/sys.c          - System calls
      kernel/sched/core.c   - Scheduler core
    */

    // 2.7.17.d: mm/
    printf("\n=== mm/ (d) ===\n");
    explain_mm_dir();
    /*
    mm/: Memory management
      Core files:
        mm/memory.c       - Page fault handling
        mm/mmap.c         - mmap implementation
        mm/page_alloc.c   - Page allocator
        mm/slab.c         - Slab allocator
        mm/vmalloc.c      - vmalloc implementation
        mm/swap.c         - Swapping
        mm/oom_kill.c     - OOM killer
    */

    // 2.7.17.e: fs/
    printf("\n=== fs/ (e) ===\n");
    explain_fs_dir();
    /*
    fs/: File systems
      ext4/          - ext4 filesystem
      xfs/           - XFS filesystem
      btrfs/         - Btrfs filesystem
      nfs/           - NFS client
      proc/          - /proc filesystem
      sysfs/         - /sys filesystem

    Core files:
      fs/open.c      - open/close syscalls
      fs/read_write.c - read/write syscalls
      fs/namei.c     - Path lookup
      fs/inode.c     - Inode management
      fs/super.c     - Superblock handling
    */

    // 2.7.17.f: drivers/
    printf("\n=== drivers/ (f) ===\n");
    explain_drivers_dir();
    /*
    drivers/: Device drivers (largest directory!)
      block/         - Block device drivers
      char/          - Character devices
      gpu/           - GPU drivers
      net/           - Network drivers
      usb/           - USB drivers
      pci/           - PCI bus
      nvme/          - NVMe storage
      scsi/          - SCSI drivers
      input/         - Input devices

    Organization:
      Each subdirectory is a driver category
      Hundreds of drivers in each
    */

    // 2.7.17.g: net/
    printf("\n=== net/ (g) ===\n");
    explain_net_dir();
    /*
    net/: Networking
      core/          - Core networking
      ipv4/          - IPv4 stack
      ipv6/          - IPv6 stack
      unix/          - Unix domain sockets
      netfilter/     - Packet filtering
      socket.c       - Socket interface

    Key files:
      net/socket.c       - Socket syscalls
      net/ipv4/tcp.c     - TCP implementation
      net/ipv4/udp.c     - UDP implementation
    */

    // 2.7.17.h: include/
    printf("\n=== include/ (h) ===\n");
    explain_include_dir();
    /*
    include/: Header files
      linux/         - Core kernel headers
      uapi/          - User-space API headers
      asm-generic/   - Generic arch headers
      net/           - Networking headers
      scsi/          - SCSI headers

    Key headers:
      include/linux/kernel.h   - Core definitions
      include/linux/sched.h    - Scheduler
      include/linux/fs.h       - Filesystem
      include/linux/module.h   - Module support
      include/uapi/linux/ioctl.h - ioctl macros
    */

    // 2.7.17.i: Kconfig
    printf("\n=== Kconfig (i) ===\n");
    explain_kconfig();
    /*
    Kconfig: Kernel configuration system

    Syntax:
      config OPTION_NAME
          tristate "Description"
          depends on OTHER_OPTION
          select DEPENDENCY
          default y
          help
            Help text here

    Types:
      bool      - y/n
      tristate  - y/m/n (module support)
      int       - Integer value
      string    - String value
      hex       - Hex value

    Files:
      Kconfig in each directory
      Hierarchical menu structure
    */

    kconfig_option_t opt;
    parse_kconfig_option(
        "config EXT4_FS\n"
        "    tristate \"The Extended 4 (ext4) filesystem\"\n"
        "    depends on BLOCK\n"
        "    select CRC16\n"
        "    help\n"
        "      This is the ext4 filesystem",
        &opt);
    print_kconfig_option(&opt);

    // 2.7.17.j: Makefile
    printf("\n=== Makefile (j) ===\n");
    explain_kernel_makefile();
    /*
    Kernel build system (Kbuild):

    Top-level Makefile:
      - Entry point for build
      - make, make modules, make install

    Subdirectory Makefile:
      obj-y += file.o       # Built-in
      obj-m += module.o     # Module
      obj-$(CONFIG_FOO) += foo.o

    Module Makefile (external):
      obj-m += mymodule.o
      mymodule-objs := file1.o file2.o

      KDIR := /lib/modules/$(shell uname -r)/build

      all:
          make -C $(KDIR) M=$(PWD) modules

      clean:
          make -C $(KDIR) M=$(PWD) clean
    */

    show_module_makefile();

    // Configuration tools
    printf("\n=== Configuration Tools ===\n");
    explain_menuconfig();
    /*
    make menuconfig:
      - Text-based menu
      - Navigate with arrows
      - Space to toggle
      - Enter for submenu
      - / to search

    make xconfig:
      - Qt-based GUI

    make nconfig:
      - ncurses menu

    make oldconfig:
      - Update .config for new options

    make defconfig:
      - Default configuration
    */

    return 0;
}
```

---

## Tests Moulinette

```rust
// ioctl
#[test] fn test_ioctl_macros()          // 2.7.16.c
#[test] fn test_ioctl_decode()          // 2.7.16.b,d-f
#[test] fn test_ioctl_implementation()  // 2.7.16.g
#[test] fn test_copy_user()             // 2.7.16.h-i

// Kernel source
#[test] fn test_source_tree()           // 2.7.17.a
#[test] fn test_arch_dir()              // 2.7.17.b
#[test] fn test_kernel_dirs()           // 2.7.17.c-g
#[test] fn test_include_dir()           // 2.7.17.h
#[test] fn test_kconfig()               // 2.7.17.i
#[test] fn test_makefile()              // 2.7.17.j
```

---

## Bareme

| Critere | Points |
|---------|--------|
| ioctl macros (2.7.16.c-f) | 25 |
| ioctl implementation (2.7.16.a,g) | 15 |
| copy_from/to_user (2.7.16.h-i) | 10 |
| Source organization (2.7.17.a-h) | 30 |
| Build system (2.7.17.i-j) | 20 |
| **Total** | **100** |

---

## Fichiers

```
ex08/
├── ioctl_kernel_source.h
├── ioctl.c
├── copy_user.c
├── kernel_tree.c
├── kconfig.c
├── makefile_parser.c
└── Makefile
```
