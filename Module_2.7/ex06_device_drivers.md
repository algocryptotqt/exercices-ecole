# ex06: Device Drivers & Character Devices

**Module**: 2.7 - Kernel Development & OS Internals
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.7.12: Device Drivers Basics (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Driver | Interface to hardware |
| b | Character device | Stream of bytes |
| c | Block device | Random access |
| d | Network device | Packets |
| e | Major/minor | Device identification |
| f | Device file | /dev/xxx |
| g | mknod | Create device file |
| h | udev | Dynamic device management |

### 2.7.13: Character Device Driver (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | file_operations | Driver callbacks |
| b | open | Device opened |
| c | release | Device closed |
| d | read | Read from device |
| e | write | Write to device |
| f | ioctl | Device control |
| g | register_chrdev | Register driver |
| h | cdev | Character device structure |
| i | /dev/null, /dev/zero | Simple examples |

---

## Sujet

Comprendre les pilotes de peripheriques et implementer un simulateur de character device.

### Structures

```c
#include <stdint.h>
#include <stdbool.h>

// 2.7.12.e: Major/minor numbers
typedef struct {
    int major;               // Major number
    int minor;               // Minor number
    uint32_t dev_t;          // Combined dev_t
} device_number_t;

// 2.7.12.b-d: Device types
typedef enum {
    DEV_CHAR,                // b: Character device
    DEV_BLOCK,               // c: Block device
    DEV_NET                  // d: Network device
} device_type_t;

// 2.7.12.f: Device file info
typedef struct {
    const char *path;        // /dev/xxx
    device_type_t type;
    device_number_t number;
    mode_t mode;             // Permissions
    uid_t uid;
    gid_t gid;
} device_file_t;

// 2.7.13.a: file_operations structure (simplified kernel API)
typedef struct file_operations {
    int (*open)(int fd);
    int (*release)(int fd);
    ssize_t (*read)(int fd, void *buf, size_t count);
    ssize_t (*write)(int fd, const void *buf, size_t count);
    int (*ioctl)(int fd, unsigned long request, void *arg);
    off_t (*llseek)(int fd, off_t offset, int whence);
    int (*flush)(int fd);
} file_operations_t;

// 2.7.13.h: cdev structure (simplified)
typedef struct cdev {
    const char *name;
    device_number_t dev;
    file_operations_t *ops;
    void *private_data;
    int count;               // Number of minor numbers
} cdev_t;

// 2.7.12.h: udev rule
typedef struct {
    const char *subsystem;
    const char *kernel;      // Kernel name pattern
    const char *symlink;     // Symlink to create
    const char *mode;        // Permissions
    const char *owner;
    const char *group;
    const char *action;      // add/remove
} udev_rule_t;

// Device instance (runtime state)
typedef struct {
    cdev_t *cdev;
    int minor;
    int open_count;
    void *data;
    size_t data_size;
    size_t data_pos;
} device_instance_t;
```

### API

```c
// ============== DEVICE NUMBERS ==============
// 2.7.12.e

// Make/extract dev_t
uint32_t MKDEV(int major, int minor);
int MAJOR(uint32_t dev);
int MINOR(uint32_t dev);

// Device number operations
void parse_dev_t(uint32_t dev, device_number_t *num);
void print_device_number(const device_number_t *num);

// Allocate device numbers
int alloc_chrdev_region(device_number_t *dev, int baseminor,
                        int count, const char *name);
int register_chrdev_region(device_number_t dev, int count,
                           const char *name);
void unregister_chrdev_region(device_number_t dev, int count);

// ============== DEVICE TYPES ==============
// 2.7.12.a-d

// Explain device types
void explain_device_types(void);
const char *device_type_name(device_type_t type);

// List devices by type
int list_char_devices(device_file_t **devs, int *count);
int list_block_devices(device_file_t **devs, int *count);
void print_device_list(device_file_t *devs, int count);

// Get device type from file
device_type_t get_device_type(const char *path);

// ============== DEVICE FILES ==============
// 2.7.12.f-g

// 2.7.12.g: mknod simulation
int my_mknod(const char *path, mode_t mode, uint32_t dev);
void explain_mknod(void);

// Read device file info
int get_device_file_info(const char *path, device_file_t *info);
void print_device_file(const device_file_t *info);

// List /dev contents
int list_dev_directory(device_file_t **files, int *count);

// ============== UDEV ==============
// 2.7.12.h

// Parse udev rules
int parse_udev_rule(const char *rule_str, udev_rule_t *rule);
void print_udev_rule(const udev_rule_t *rule);
void explain_udev(void);

// List udev rules
int list_udev_rules(const char *rules_dir, udev_rule_t **rules, int *count);

// ============== CHARACTER DEVICE DRIVER ==============
// 2.7.13

// 2.7.13.g-h: Register/unregister
int cdev_init(cdev_t *cdev, const file_operations_t *fops);
int cdev_add(cdev_t *cdev, device_number_t dev, int count);
void cdev_del(cdev_t *cdev);
int register_chrdev(int major, const char *name,
                    const file_operations_t *fops);
void unregister_chrdev(int major, const char *name);

// ============== FILE OPERATIONS SIMULATION ==============
// 2.7.13.a-f

// Create simulated devices
device_instance_t *create_null_device(void);   // 2.7.13.i
device_instance_t *create_zero_device(void);   // 2.7.13.i
device_instance_t *create_random_device(void);
device_instance_t *create_memory_device(size_t size);

// File operations
int device_open(device_instance_t *dev);       // 2.7.13.b
int device_release(device_instance_t *dev);    // 2.7.13.c
ssize_t device_read(device_instance_t *dev, void *buf, size_t count);   // 2.7.13.d
ssize_t device_write(device_instance_t *dev, const void *buf, size_t count); // 2.7.13.e
int device_ioctl(device_instance_t *dev, unsigned long request, void *arg);  // 2.7.13.f

// Free device
void device_destroy(device_instance_t *dev);

// ============== EXAMPLES ==============
// 2.7.13.i

// Study existing devices
void analyze_dev_null(void);
void analyze_dev_zero(void);
void analyze_dev_random(void);
void analyze_dev_tty(void);

// List well-known devices
void list_common_devices(void);
```

---

## Exemple

```c
#include "device_drivers.h"

int main(void) {
    // ============== DEVICE DRIVERS BASICS ==============
    // 2.7.12

    printf("=== Device Drivers (a) ===\n");
    printf("Driver: Software interface between OS and hardware\n");
    printf("  - Abstracts hardware details\n");
    printf("  - Provides standard interface\n");
    printf("  - Runs in kernel space\n");

    // 2.7.12.b-d: Device types
    printf("\n=== Device Types (b-d) ===\n");
    explain_device_types();
    /*
    Character Device (b):
      - Sequential access (stream)
      - Cannot seek (usually)
      - Examples: /dev/tty, /dev/null, /dev/random

    Block Device (c):
      - Random access
      - Fixed-size blocks
      - Usually buffered
      - Examples: /dev/sda, /dev/nvme0n1

    Network Device (d):
      - Packet-based
      - No /dev entry
      - Accessed via sockets
      - Examples: eth0, wlan0
    */

    // List devices
    printf("\nCharacter Devices:\n");
    device_file_t *char_devs;
    int char_count;
    list_char_devices(&char_devs, &char_count);
    print_device_list(char_devs, char_count > 10 ? 10 : char_count);

    // 2.7.12.e: Major/minor numbers
    printf("\n=== Major/Minor Numbers (e) ===\n");
    printf("Device identification:\n");
    printf("  Major: Identifies driver\n");
    printf("  Minor: Identifies specific device\n\n");

    device_number_t num;
    num.major = 1;
    num.minor = 3;
    num.dev_t = MKDEV(1, 3);
    print_device_number(&num);
    // Output: Device 1:3 (dev_t=0x103)

    printf("\nCommon major numbers:\n");
    printf("  1: mem (/dev/null, /dev/zero, /dev/random)\n");
    printf("  4: tty (serial ports)\n");
    printf("  8: sd (SCSI disks)\n");
    printf("  10: misc (miscellaneous)\n");

    // 2.7.12.f: Device files
    printf("\n=== Device Files (f) ===\n");
    printf("Device files in /dev provide interface to drivers\n\n");

    device_file_t info;
    get_device_file_info("/dev/null", &info);
    print_device_file(&info);
    /*
    /dev/null:
      Type: Character
      Major: 1, Minor: 3
      Mode: crw-rw-rw-
      Owner: root:root
    */

    // 2.7.12.g: mknod
    printf("\n=== mknod (g) ===\n");
    explain_mknod();
    /*
    mknod creates device files:
      mknod /dev/mydev c 240 0

    Parameters:
      - Path: /dev/mydev
      - Type: c (char) or b (block)
      - Major: 240
      - Minor: 0

    Requires root privileges
    Creates entry point for driver
    */

    // 2.7.12.h: udev
    printf("\n=== udev (h) ===\n");
    explain_udev();
    /*
    udev: Dynamic device management

    Features:
      - Auto-create device nodes
      - Persistent naming
      - Permissions management
      - Run scripts on events

    Rule example:
      KERNEL=="sd[a-z]", SUBSYSTEM=="block", \
        GROUP="disk", MODE="0660"

    Rule files: /etc/udev/rules.d/
    */

    udev_rule_t rule;
    parse_udev_rule("KERNEL==\"ttyUSB*\", MODE=\"0666\"", &rule);
    print_udev_rule(&rule);

    // ============== CHARACTER DEVICE DRIVER ==============
    // 2.7.13

    printf("\n=== Character Device Driver ===\n");

    // 2.7.13.a: file_operations
    printf("\n=== file_operations (a) ===\n");
    printf("struct file_operations defines driver callbacks:\n");
    printf("  .open     - Called when device opened\n");
    printf("  .release  - Called when device closed\n");
    printf("  .read     - Read from device\n");
    printf("  .write    - Write to device\n");
    printf("  .ioctl    - Device control commands\n");
    printf("  .llseek   - Seek in device\n");

    // 2.7.13.b-e: Basic operations
    printf("\n=== Basic Operations (b-e) ===\n");

    // Create a memory device for demonstration
    device_instance_t *memdev = create_memory_device(1024);

    // Open (b)
    printf("\nopen (b):\n");
    device_open(memdev);
    printf("  Device opened, open_count=%d\n", memdev->open_count);

    // Write (e)
    printf("\nwrite (e):\n");
    const char *data = "Hello from userspace!";
    ssize_t written = device_write(memdev, data, strlen(data));
    printf("  Wrote %zd bytes\n", written);

    // Read (d)
    printf("\nread (d):\n");
    char buf[64] = {0};
    memdev->data_pos = 0;  // Reset position
    ssize_t bytes_read = device_read(memdev, buf, sizeof(buf) - 1);
    printf("  Read %zd bytes: \"%s\"\n", bytes_read, buf);

    // Release (c)
    printf("\nrelease (c):\n");
    device_release(memdev);
    printf("  Device closed, open_count=%d\n", memdev->open_count);

    // 2.7.13.f: ioctl
    printf("\n=== ioctl (f) ===\n");
    printf("ioctl: Device-specific control commands\n");
    printf("  - Set device parameters\n");
    printf("  - Query device status\n");
    printf("  - Perform operations not covered by read/write\n");

    // Example ioctl
    size_t size;
    device_ioctl(memdev, 0x01, &size);  // Get size
    printf("  IOCTL get size: %zu bytes\n", size);

    device_destroy(memdev);

    // 2.7.13.g-h: Registration
    printf("\n=== Device Registration (g-h) ===\n");
    printf("cdev (h): Character device structure\n");
    printf("  - Associates file_operations with device number\n");
    printf("  - Managed by kernel's cdev subsystem\n\n");

    printf("register_chrdev (g):\n");
    printf("  - Old API, still usable\n");
    printf("  - Allocates major number\n");
    printf("  - Registers operations\n\n");

    printf("Modern approach:\n");
    printf("  1. alloc_chrdev_region() - get device numbers\n");
    printf("  2. cdev_init() - initialize cdev\n");
    printf("  3. cdev_add() - add to kernel\n");
    printf("  4. device_create() - create /dev entry\n");

    // 2.7.13.i: Examples
    printf("\n=== Example Devices (i) ===\n");

    // /dev/null
    printf("\n/dev/null:\n");
    analyze_dev_null();
    /*
    /dev/null:
      - Read returns EOF (0 bytes)
      - Write discards all data (returns count)
      - Infinite sink
    */

    // /dev/zero
    printf("\n/dev/zero:\n");
    analyze_dev_zero();
    /*
    /dev/zero:
      - Read returns zero bytes
      - Write discards data
      - Useful for creating empty files
    */

    // Simulate /dev/null
    printf("\n=== Simulating /dev/null ===\n");
    device_instance_t *null_dev = create_null_device();
    device_open(null_dev);

    char write_buf[] = "This data goes to null";
    written = device_write(null_dev, write_buf, strlen(write_buf));
    printf("write() returned: %zd (data discarded)\n", written);

    bytes_read = device_read(null_dev, buf, sizeof(buf));
    printf("read() returned: %zd (EOF)\n", bytes_read);

    device_release(null_dev);
    device_destroy(null_dev);

    // Simulate /dev/zero
    printf("\n=== Simulating /dev/zero ===\n");
    device_instance_t *zero_dev = create_zero_device();
    device_open(zero_dev);

    memset(buf, 0xFF, sizeof(buf));
    bytes_read = device_read(zero_dev, buf, 16);
    printf("read() returned: %zd bytes\n", bytes_read);
    printf("First 16 bytes (hex): ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", (unsigned char)buf[i]);
    }
    printf("\n");

    device_release(zero_dev);
    device_destroy(zero_dev);

    // Common devices
    printf("\n=== Common Character Devices ===\n");
    list_common_devices();
    /*
    /dev/null    (1, 3)  - Data sink
    /dev/zero    (1, 5)  - Zero source
    /dev/full    (1, 7)  - Always full
    /dev/random  (1, 8)  - Random bytes (blocking)
    /dev/urandom (1, 9)  - Random bytes (non-blocking)
    /dev/tty     (5, 0)  - Current terminal
    /dev/console (5, 1)  - System console
    /dev/ptmx    (5, 2)  - PTY master
    */

    return 0;
}
```

---

## Tests Moulinette

```rust
// Device numbers
#[test] fn test_mkdev()                 // 2.7.12.e
#[test] fn test_major_minor()           // 2.7.12.e
#[test] fn test_device_types()          // 2.7.12.b-d
#[test] fn test_device_files()          // 2.7.12.f-g

// Character device
#[test] fn test_file_operations()       // 2.7.13.a
#[test] fn test_open_release()          // 2.7.13.b-c
#[test] fn test_read_write()            // 2.7.13.d-e
#[test] fn test_ioctl()                 // 2.7.13.f
#[test] fn test_null_device()           // 2.7.13.i
#[test] fn test_zero_device()           // 2.7.13.i
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Device types (2.7.12.a-d) | 15 |
| Major/minor (2.7.12.e) | 15 |
| Device files/mknod (2.7.12.f-g) | 10 |
| udev (2.7.12.h) | 10 |
| file_operations (2.7.13.a-f) | 25 |
| Registration (2.7.13.g-h) | 10 |
| Example devices (2.7.13.i) | 15 |
| **Total** | **100** |

---

## Fichiers

```
ex06/
├── device_drivers.h
├── device_numbers.c
├── device_types.c
├── device_files.c
├── udev.c
├── char_device.c
├── example_devices.c
└── Makefile
```
