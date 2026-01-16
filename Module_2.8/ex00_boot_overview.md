# ex00: PC Boot Process Overview

**Module**: 2.8 - Boot Process & Bare Metal
**Difficulte**: Difficile
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.8.1: PC Boot Overview (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Power on | CPU starts |
| b | Reset vector | First instruction |
| c | Firmware | BIOS or UEFI |
| d | POST | Power-On Self Test |
| e | Boot device | Selection |
| f | Bootloader | Load kernel |
| g | Kernel | Start OS |
| h | Init | First user process |

### 2.8.2: BIOS (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | BIOS | Basic Input/Output System |
| b | ROM | Firmware storage |
| c | POST | Hardware check |
| d | Boot order | Device priority |
| e | MBR | Master Boot Record |
| f | MBR location | First 512 bytes |
| g | Boot signature | 0xAA55 |
| h | BIOS services | Int 0x10, 0x13, etc. |
| i | Real mode | 16-bit mode |

### 2.8.3: UEFI (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | UEFI | Unified EFI |
| b | Advantages | 64-bit, large disks, GUI |
| c | ESP | EFI System Partition |
| d | FAT32 | ESP filesystem |
| e | .efi files | UEFI executables |
| f | GPT | GUID Partition Table |
| g | Secure Boot | Signed boot |
| h | UEFI shell | Built-in shell |
| i | UEFI variables | Runtime config |

---

## Sujet

Comprendre le processus de demarrage d'un PC, du BIOS/UEFI au systeme d'exploitation.

### Structures

```c
#include <stdint.h>
#include <stdbool.h>

// 2.8.1: Boot stage info
typedef struct {
    const char *stage_name;
    const char *description;
    uint64_t start_time_ms;    // Approximate
    const char *next_stage;
} boot_stage_t;

// 2.8.2.e-g: MBR structure
typedef struct {
    uint8_t bootstrap[446];     // Boot code
    uint8_t partition_table[64]; // 4 × 16-byte entries
    uint16_t signature;          // 0xAA55
} __attribute__((packed)) mbr_t;

// 2.8.2.e: Partition entry
typedef struct {
    uint8_t status;             // 0x80 = bootable
    uint8_t first_chs[3];       // CHS of first sector
    uint8_t type;               // Partition type
    uint8_t last_chs[3];        // CHS of last sector
    uint32_t first_lba;         // First sector (LBA)
    uint32_t sector_count;      // Number of sectors
} __attribute__((packed)) partition_entry_t;

// 2.8.2.h: BIOS interrupt info
typedef struct {
    uint8_t interrupt;
    uint8_t function;           // AH value
    const char *name;
    const char *description;
    const char *parameters;
} bios_interrupt_t;

// 2.8.3.c-d: ESP info
typedef struct {
    const char *mount_point;
    const char *device;
    uint64_t size_bytes;
    const char *filesystem;
    int file_count;
} esp_info_t;

// 2.8.3.e: EFI boot entry
typedef struct {
    uint16_t boot_num;          // BootXXXX
    const char *description;
    const char *path;           // EFI file path
    bool active;
    int order;
} efi_boot_entry_t;

// 2.8.3.i: UEFI variable
typedef struct {
    const char *name;
    const char *guid;
    uint32_t attributes;
    size_t data_size;
    const uint8_t *data;
} uefi_variable_t;
```

### API

```c
// ============== BOOT SEQUENCE ==============
// 2.8.1

// Boot stages
int get_boot_stages(boot_stage_t **stages, int *count);
void print_boot_stages(void);
void explain_boot_stage(const char *stage);

// 2.8.1.a-b: Power on and reset vector
void explain_power_on(void);
void explain_reset_vector(void);
uint64_t get_reset_vector_address(void);  // 0xFFFFFFF0

// 2.8.1.c: Firmware detection
bool is_uefi_boot(void);
bool is_bios_boot(void);
const char *get_firmware_type(void);

// ============== BIOS ==============
// 2.8.2

// 2.8.2.a-c: BIOS basics
void explain_bios(void);
void explain_post(void);

// 2.8.2.d: Boot order
int get_bios_boot_order(char ***devices, int *count);  // Simulated

// 2.8.2.e-g: MBR
int read_mbr(const char *device, mbr_t *mbr);
bool verify_mbr_signature(const mbr_t *mbr);
void print_mbr_info(const mbr_t *mbr);
void parse_partition_entry(const uint8_t *entry, partition_entry_t *part);
void print_partition_table(const mbr_t *mbr);

// 2.8.2.h: BIOS interrupts
int get_bios_interrupts(bios_interrupt_t **ints, int *count);
void print_bios_interrupts(void);
void explain_bios_interrupt(uint8_t interrupt, uint8_t function);

// 2.8.2.i: Real mode
void explain_real_mode(void);

// ============== UEFI ==============
// 2.8.3

// 2.8.3.a-b: UEFI basics
void explain_uefi(void);
void compare_bios_uefi(void);

// 2.8.3.c-e: ESP and EFI files
int get_esp_info(esp_info_t *info);
void print_esp_info(const esp_info_t *info);
int list_efi_files(char ***files, int *count);

// 2.8.3.f: GPT (detailed in next exercise)
bool is_gpt_disk(const char *device);

// 2.8.3.g: Secure Boot
bool is_secure_boot_enabled(void);
void explain_secure_boot(void);

// 2.8.3.h: UEFI shell
void explain_uefi_shell(void);
void show_uefi_shell_commands(void);

// 2.8.3.i: UEFI variables
int list_uefi_variables(uefi_variable_t **vars, int *count);
int read_uefi_variable(const char *name, uefi_variable_t *var);
void print_uefi_variable(const uefi_variable_t *var);

// Boot entries (via efibootmgr)
int list_efi_boot_entries(efi_boot_entry_t **entries, int *count);
void print_efi_boot_entries(void);

// ============== ANALYSIS ==============

// Current system boot analysis
void analyze_current_boot(void);
void show_boot_log(void);  // From journalctl/dmesg
```

---

## Exemple

```c
#include "boot_overview.h"

int main(void) {
    // ============== PC BOOT OVERVIEW ==============
    // 2.8.1

    printf("=== PC Boot Process ===\n\n");

    // 2.8.1.a: Power on
    printf("=== Stage 1: Power On (a) ===\n");
    explain_power_on();
    /*
    Power On:
      1. PSU sends Power Good signal
      2. CPU receives RESET signal
      3. CPU initializes registers
      4. CPU jumps to reset vector
    */

    // 2.8.1.b: Reset vector
    printf("\n=== Stage 2: Reset Vector (b) ===\n");
    explain_reset_vector();
    /*
    Reset Vector (x86):
      Address: 0xFFFFFFF0 (FFFF:FFF0 in real mode)
      Location: 16 bytes below 4GB
      Contains: JMP to BIOS code
      Size: 16 bytes only

    First instruction executed by CPU after reset
    */
    printf("Reset vector address: 0x%lX\n", get_reset_vector_address());

    // 2.8.1.c: Firmware
    printf("\n=== Stage 3: Firmware (c) ===\n");
    printf("Firmware type: %s\n", get_firmware_type());
    if (is_uefi_boot()) {
        printf("System booted via UEFI\n");
    } else {
        printf("System booted via Legacy BIOS\n");
    }

    // 2.8.1.d: POST
    printf("\n=== Stage 4: POST (d) ===\n");
    explain_post();
    /*
    POST (Power-On Self Test):
      1. CPU test
      2. Memory test (RAM)
      3. Detect hardware devices
      4. Initialize devices
      5. Show BIOS/UEFI screen
      6. Find boot device
    */

    // 2.8.1.e-h: Boot sequence
    printf("\n=== Boot Sequence (e-h) ===\n");
    print_boot_stages();
    /*
    Boot Stages:
      1. Power On       - Hardware initialization
      2. Reset Vector   - CPU starts executing
      3. POST           - Hardware tests
      4. Boot Device    - Find bootable disk (e)
      5. Bootloader     - GRUB, Windows Boot Manager (f)
      6. Kernel         - Linux, Windows NT kernel (g)
      7. Init           - systemd, SysV init (h)
      8. User Space     - Desktop/services
    */

    // ============== BIOS ==============
    // 2.8.2

    printf("\n=== BIOS ===\n");

    // 2.8.2.a-b: BIOS basics
    printf("\n=== BIOS Basics (a-b) ===\n");
    explain_bios();
    /*
    BIOS (Basic Input/Output System):
      - Firmware stored in ROM/Flash (b)
      - First code to run after power on
      - Provides hardware abstraction
      - Limited to 16-bit real mode

    Functions:
      - POST (hardware testing)
      - Boot device selection
      - BIOS services (interrupts)
      - Setup utility
    */

    // 2.8.2.c: POST details
    printf("\n=== POST (c) ===\n");
    printf("POST checks:\n");
    printf("  - CPU registers and flags\n");
    printf("  - DMA controller\n");
    printf("  - Timer (PIT)\n");
    printf("  - Memory (base + extended)\n");
    printf("  - Keyboard controller\n");
    printf("  - Video adapter\n");

    // 2.8.2.d: Boot order
    printf("\n=== Boot Order (d) ===\n");
    printf("Typical boot order:\n");
    printf("  1. CD/DVD\n");
    printf("  2. USB drive\n");
    printf("  3. Hard disk\n");
    printf("  4. Network (PXE)\n");

    // 2.8.2.e-g: MBR
    printf("\n=== MBR (e-g) ===\n");
    printf("MBR (Master Boot Record) structure (e):\n");
    printf("  Offset 0x000: Bootstrap code (446 bytes)\n");
    printf("  Offset 0x1BE: Partition table (64 bytes)\n");
    printf("  Offset 0x1FE: Signature 0xAA55 (2 bytes)\n");
    printf("\nLocation (f): First 512 bytes of disk (LBA 0)\n");
    printf("Signature (g): 0x55 0xAA (little-endian 0xAA55)\n");

    // Read MBR (if on MBR system)
    mbr_t mbr;
    if (read_mbr("/dev/sda", &mbr) == 0) {
        if (verify_mbr_signature(&mbr)) {
            printf("\nMBR signature valid\n");
            print_partition_table(&mbr);
        }
    }

    // 2.8.2.h: BIOS interrupts
    printf("\n=== BIOS Interrupts (h) ===\n");
    print_bios_interrupts();
    /*
    Key BIOS Interrupts:
    INT 0x10 - Video services
      AH=0x00 - Set video mode
      AH=0x0E - Teletype output (print char)
      AH=0x13 - Write string

    INT 0x13 - Disk services
      AH=0x00 - Reset disk
      AH=0x02 - Read sectors
      AH=0x03 - Write sectors
      AH=0x08 - Get drive parameters
      AH=0x42 - Extended read (LBA)

    INT 0x15 - System services
      AX=0xE820 - Get memory map

    INT 0x16 - Keyboard services
      AH=0x00 - Read key
      AH=0x01 - Check key ready
    */

    // 2.8.2.i: Real mode
    printf("\n=== Real Mode (i) ===\n");
    explain_real_mode();
    /*
    Real Mode:
      - Original 8086 mode
      - 16-bit execution
      - 1MB address space (20-bit)
      - No memory protection
      - Segment:Offset addressing
      - BIOS runs in this mode
      - Bootloader starts here
    */

    // ============== UEFI ==============
    // 2.8.3

    printf("\n=== UEFI ===\n");

    // 2.8.3.a-b: UEFI basics
    printf("\n=== UEFI Overview (a-b) ===\n");
    explain_uefi();
    /*
    UEFI (Unified Extensible Firmware Interface):
      - Modern replacement for BIOS
      - 32-bit or 64-bit execution
      - GUI support
      - Mouse support
      - Network support
      - Larger disk support (GPT)
      - Faster boot
    */

    compare_bios_uefi();
    /*
    BIOS vs UEFI:
                    BIOS            UEFI
    Bit mode        16-bit          32/64-bit
    Max disk        2TB             9.4ZB
    Partitions      4 primary       128+
    Boot from       MBR             ESP (.efi)
    Interface       Text            GUI/Text
    Secure Boot     No              Yes
    Network         Limited         Yes
    */

    // 2.8.3.c-d: ESP
    printf("\n=== ESP (c-d) ===\n");
    esp_info_t esp;
    if (get_esp_info(&esp) == 0) {
        print_esp_info(&esp);
    }
    /*
    EFI System Partition (c):
      Mount: /boot/efi
      Device: /dev/sda1
      Size: 512 MB
      Filesystem: FAT32 (d)

    Contains:
      EFI/
        BOOT/
          BOOTX64.EFI (default bootloader)
        ubuntu/
          grubx64.efi
          shimx64.efi
        Microsoft/
          Boot/
            bootmgfw.efi
    */

    // 2.8.3.e: EFI files
    printf("\n=== EFI Files (e) ===\n");
    printf(".efi files are PE32+ executables\n");
    printf("Loaded and executed by UEFI firmware\n");

    // 2.8.3.f: GPT
    printf("\n=== GPT (f) ===\n");
    printf("UEFI typically uses GPT partitioning\n");
    printf("(Detailed in next exercise)\n");

    // 2.8.3.g: Secure Boot
    printf("\n=== Secure Boot (g) ===\n");
    explain_secure_boot();
    /*
    Secure Boot:
      - Verify bootloader signature
      - Only run signed code
      - Prevents bootkit malware
      - Uses PKI (certificates)

    Key databases:
      PK  - Platform Key (owner)
      KEK - Key Exchange Key
      db  - Signature database (allowed)
      dbx - Forbidden signatures
    */
    printf("Secure Boot: %s\n",
           is_secure_boot_enabled() ? "Enabled" : "Disabled");

    // 2.8.3.h: UEFI shell
    printf("\n=== UEFI Shell (h) ===\n");
    explain_uefi_shell();
    show_uefi_shell_commands();
    /*
    UEFI Shell Commands:
      help          - List commands
      ls/dir        - List files
      cd            - Change directory
      cp/mv/rm      - File operations
      map           - Show mapped drives
      edit          - Text editor
      bcfg          - Boot config
      exit          - Exit shell
    */

    // 2.8.3.i: UEFI variables
    printf("\n=== UEFI Variables (i) ===\n");
    printf("Stored in NVRAM, persist across boots\n\n");

    print_efi_boot_entries();
    /*
    Boot Entries:
    Boot0000* ubuntu
    Boot0001* Windows Boot Manager
    Boot0002  USB Drive
    BootOrder: 0000,0001,0002
    */

    // Current boot analysis
    printf("\n=== Current Boot Analysis ===\n");
    analyze_current_boot();

    return 0;
}
```

---

## Tests Moulinette

```rust
// Boot overview
#[test] fn test_boot_stages()           // 2.8.1
#[test] fn test_reset_vector()          // 2.8.1.b
#[test] fn test_firmware_detect()       // 2.8.1.c

// BIOS
#[test] fn test_mbr_read()              // 2.8.2.e-f
#[test] fn test_mbr_signature()         // 2.8.2.g
#[test] fn test_partition_parse()       // 2.8.2.e
#[test] fn test_bios_interrupts()       // 2.8.2.h

// UEFI
#[test] fn test_esp_info()              // 2.8.3.c-d
#[test] fn test_efi_boot_entries()      // 2.8.3.e
#[test] fn test_uefi_variables()        // 2.8.3.i
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Boot stages (2.8.1.a-h) | 20 |
| MBR structure (2.8.2.e-g) | 25 |
| BIOS interrupts (2.8.2.h) | 15 |
| ESP/EFI (2.8.3.c-e) | 20 |
| UEFI features (2.8.3.g-i) | 20 |
| **Total** | **100** |

---

## Fichiers

```
ex00/
├── boot_overview.h
├── boot_stages.c
├── mbr.c
├── bios.c
├── uefi.c
├── esp.c
└── Makefile
```
