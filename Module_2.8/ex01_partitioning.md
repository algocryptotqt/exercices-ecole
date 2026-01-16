# ex01: MBR & GPT Partitioning

**Module**: 2.8 - Boot Process & Bare Metal
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 97/100

## Concepts Couverts

### 2.8.4: MBR Partitioning (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | MBR structure | Boot code + partition table |
| b | Boot code | 446 bytes |
| c | Partition table | 4 entries |
| d | Partition entry | Status, type, CHS, LBA |
| e | Extended partition | More than 4 |
| f | Active partition | Bootable |
| g | Limitations | 2TB max, 4 primary |
| h | fdisk | MBR tool |

### 2.8.5: GPT Partitioning (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | GPT | GUID Partition Table |
| b | Protective MBR | Compatibility |
| c | GPT header | Primary and backup |
| d | Partition entries | 128 typical |
| e | GUID | Unique identifier |
| f | No 4-partition limit | Many partitions |
| g | Large disks | > 2TB support |
| h | gdisk | GPT tool |

---

## Sujet

Parser et analyser les tables de partition MBR et GPT.

### Structures

```c
#include <stdint.h>
#include <stdbool.h>

// 2.8.4.a-d: MBR structures
typedef struct {
    uint8_t status;              // 0x80 = bootable (f)
    uint8_t first_head;
    uint8_t first_sector;        // Bits 0-5, cylinder high in 6-7
    uint8_t first_cylinder;
    uint8_t type;                // Partition type code
    uint8_t last_head;
    uint8_t last_sector;
    uint8_t last_cylinder;
    uint32_t first_lba;          // Starting LBA
    uint32_t sector_count;       // Total sectors
} __attribute__((packed)) mbr_partition_t;

typedef struct {
    uint8_t boot_code[446];      // b: Bootstrap code
    mbr_partition_t partitions[4]; // c: 4 partition entries
    uint16_t signature;          // 0xAA55
} __attribute__((packed)) mbr_t;

// Partition type codes
typedef struct {
    uint8_t code;
    const char *name;
    const char *description;
} partition_type_t;

// 2.8.5.b: Protective MBR
// Same structure as MBR but with special values

// 2.8.5.c: GPT header
typedef struct {
    char signature[8];           // "EFI PART"
    uint32_t revision;
    uint32_t header_size;
    uint32_t header_crc32;
    uint32_t reserved;
    uint64_t current_lba;
    uint64_t backup_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    uint8_t disk_guid[16];       // e: Disk GUID
    uint64_t partition_entry_lba;
    uint32_t num_partition_entries; // d: 128 typical
    uint32_t partition_entry_size;  // Usually 128 bytes
    uint32_t partition_array_crc32;
} __attribute__((packed)) gpt_header_t;

// 2.8.5.d-e: GPT partition entry
typedef struct {
    uint8_t type_guid[16];       // Partition type GUID
    uint8_t partition_guid[16];  // e: Unique partition GUID
    uint64_t first_lba;
    uint64_t last_lba;
    uint64_t attributes;
    uint16_t name[36];           // UTF-16LE name
} __attribute__((packed)) gpt_partition_t;

// Common GUIDs
typedef struct {
    const char *guid;
    const char *name;
    const char *description;
} known_guid_t;
```

### API

```c
// ============== MBR ==============
// 2.8.4

int read_mbr(const char *device, mbr_t *mbr);
bool is_valid_mbr(const mbr_t *mbr);
void print_mbr(const mbr_t *mbr);

// 2.8.4.d: Parse partition entry
void parse_chs(uint8_t head, uint8_t sector, uint8_t cylinder,
               int *c, int *h, int *s);
uint64_t chs_to_lba(int c, int h, int s, int heads, int sectors);
const char *get_partition_type_name(uint8_t type);
void print_partition_entry(int index, const mbr_partition_t *part);

// 2.8.4.e: Extended partitions
int read_extended_partitions(const char *device, uint32_t ebr_lba,
                            mbr_partition_t **parts, int *count);
void print_extended_partitions(const char *device);

// 2.8.4.f: Bootable check
bool is_bootable_partition(const mbr_partition_t *part);
int find_active_partition(const mbr_t *mbr);

// 2.8.4.g: Limitations
void explain_mbr_limitations(void);
uint64_t mbr_max_disk_size(void);  // 2TB

// 2.8.4.h: fdisk info
void show_fdisk_usage(void);

// ============== GPT ==============
// 2.8.5

int read_gpt_header(const char *device, gpt_header_t *header);
int read_gpt_partitions(const char *device, const gpt_header_t *header,
                       gpt_partition_t **parts, int *count);
bool is_valid_gpt(const gpt_header_t *header);
bool verify_gpt_crc(const char *device, const gpt_header_t *header);

// 2.8.5.b: Protective MBR
bool has_protective_mbr(const char *device);
void explain_protective_mbr(void);

// 2.8.5.c: Header operations
void print_gpt_header(const gpt_header_t *header);
int read_backup_gpt_header(const char *device, gpt_header_t *header);

// 2.8.5.d-e: Partition entries
void print_gpt_partition(int index, const gpt_partition_t *part);
void guid_to_string(const uint8_t *guid, char *str);
const char *get_gpt_type_name(const uint8_t *type_guid);

// 2.8.5.f-g: Advantages
void compare_mbr_gpt(void);
void explain_gpt_advantages(void);

// 2.8.5.h: gdisk info
void show_gdisk_usage(void);

// ============== UTILITIES ==============

// Auto-detect partition scheme
typedef enum { SCHEME_UNKNOWN, SCHEME_MBR, SCHEME_GPT } partition_scheme_t;
partition_scheme_t detect_partition_scheme(const char *device);

// Full disk analysis
void analyze_disk(const char *device);
```

---

## Exemple

```c
#include "partitioning.h"

int main(void) {
    // ============== MBR PARTITIONING ==============
    // 2.8.4

    printf("=== MBR Partitioning ===\n\n");

    // 2.8.4.a-b: MBR structure
    printf("=== MBR Structure (a-b) ===\n");
    printf("MBR Layout:\n");
    printf("  [0x000-0x1BD] Boot code (446 bytes) (b)\n");
    printf("  [0x1BE-0x1FD] Partition table (64 bytes)\n");
    printf("  [0x1FE-0x1FF] Boot signature (0xAA55)\n");

    // 2.8.4.c: Partition table
    printf("\n=== Partition Table (c) ===\n");
    printf("4 partition entries × 16 bytes each\n");

    // 2.8.4.d: Partition entry format
    printf("\n=== Partition Entry (d) ===\n");
    printf("Entry format (16 bytes):\n");
    printf("  [0x00] Status (0x80=bootable, 0x00=inactive)\n");
    printf("  [0x01-0x03] First sector (CHS)\n");
    printf("  [0x04] Partition type\n");
    printf("  [0x05-0x07] Last sector (CHS)\n");
    printf("  [0x08-0x0B] First sector (LBA)\n");
    printf("  [0x0C-0x0F] Sector count\n");

    // Read actual MBR
    mbr_t mbr;
    const char *device = "/dev/sda";
    if (read_mbr(device, &mbr) == 0 && is_valid_mbr(&mbr)) {
        printf("\n%s MBR:\n", device);
        print_mbr(&mbr);
        /*
        Partition 1: Active, Type 0x07 (NTFS), Start 2048, Size 512000
        Partition 2: Inactive, Type 0x83 (Linux), Start 514048, Size 1024000
        Partition 3: Inactive, Type 0x82 (Linux swap), Start 1538048, Size 102400
        Partition 4: Inactive, Type 0x05 (Extended), Start 1640448, Size 500000
        */
    }

    // Common partition types
    printf("\n=== Partition Types ===\n");
    printf("  0x00 - Empty\n");
    printf("  0x01 - FAT12\n");
    printf("  0x04 - FAT16 <32MB\n");
    printf("  0x05 - Extended\n");
    printf("  0x06 - FAT16\n");
    printf("  0x07 - NTFS\n");
    printf("  0x0B - FAT32 (CHS)\n");
    printf("  0x0C - FAT32 (LBA)\n");
    printf("  0x0E - FAT16 (LBA)\n");
    printf("  0x0F - Extended (LBA)\n");
    printf("  0x82 - Linux swap\n");
    printf("  0x83 - Linux\n");
    printf("  0xEE - GPT Protective\n");
    printf("  0xEF - EFI System\n");

    // 2.8.4.e: Extended partitions
    printf("\n=== Extended Partitions (e) ===\n");
    printf("Extended partition contains EBR chain:\n");
    printf("  - Each EBR has 2 entries\n");
    printf("  - Entry 1: Logical partition\n");
    printf("  - Entry 2: Next EBR (or empty)\n");
    print_extended_partitions(device);

    // 2.8.4.f: Active partition
    printf("\n=== Active Partition (f) ===\n");
    int active = find_active_partition(&mbr);
    printf("Active partition: %d\n", active);
    printf("Status byte 0x80 marks bootable partition\n");

    // 2.8.4.g: Limitations
    printf("\n=== MBR Limitations (g) ===\n");
    explain_mbr_limitations();
    /*
    MBR Limitations:
      - Max 4 primary partitions
      - Max disk size: 2TB (2^32 × 512 bytes)
      - 32-bit LBA addressing
      - No redundancy (single copy)
      - No partition name support
      - No checksum protection
    */

    // 2.8.4.h: fdisk
    printf("\n=== fdisk Tool (h) ===\n");
    show_fdisk_usage();

    // ============== GPT PARTITIONING ==============
    // 2.8.5

    printf("\n=== GPT Partitioning ===\n\n");

    // 2.8.5.a: GPT overview
    printf("=== GPT Overview (a) ===\n");
    printf("GUID Partition Table:\n");
    printf("  - Modern replacement for MBR\n");
    printf("  - Part of UEFI specification\n");
    printf("  - Uses GUIDs for identification\n");

    // 2.8.5.b: Protective MBR
    printf("\n=== Protective MBR (b) ===\n");
    explain_protective_mbr();
    /*
    Protective MBR (LBA 0):
      - Contains single partition entry
      - Type 0xEE (GPT Protective)
      - Covers entire disk
      - Prevents MBR tools from damaging GPT
      - Makes disk appear "used" to old tools
    */

    // 2.8.5.c: GPT header
    printf("\n=== GPT Header (c) ===\n");
    gpt_header_t gpt;
    if (read_gpt_header(device, &gpt) == 0 && is_valid_gpt(&gpt)) {
        print_gpt_header(&gpt);
        /*
        GPT Header (LBA 1):
          Signature: "EFI PART"
          Revision: 1.0
          Header size: 92 bytes
          Current LBA: 1
          Backup LBA: last sector
          First usable: 34
          Last usable: (total - 34)
          Disk GUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
          Partition entries: LBA 2
          Num entries: 128
          Entry size: 128 bytes
        */

        // Backup header
        printf("\nBackup header at end of disk (redundancy)\n");
    }

    // 2.8.5.d: Partition entries
    printf("\n=== Partition Entries (d) ===\n");
    printf("Entry format (128 bytes):\n");
    printf("  [0x00-0x0F] Partition type GUID\n");
    printf("  [0x10-0x1F] Unique partition GUID\n");
    printf("  [0x20-0x27] First LBA\n");
    printf("  [0x28-0x2F] Last LBA\n");
    printf("  [0x30-0x37] Attributes\n");
    printf("  [0x38-0x7F] Name (72 bytes UTF-16LE)\n");

    gpt_partition_t *parts;
    int part_count;
    if (read_gpt_partitions(device, &gpt, &parts, &part_count) == 0) {
        printf("\nPartitions:\n");
        for (int i = 0; i < part_count; i++) {
            print_gpt_partition(i, &parts[i]);
        }
    }

    // 2.8.5.e: GUIDs
    printf("\n=== GUIDs (e) ===\n");
    printf("Common partition type GUIDs:\n");
    printf("  EFI System:  C12A7328-F81F-11D2-BA4B-00A0C93EC93B\n");
    printf("  MS Reserved: E3C9E316-0B5C-4DB8-817D-F92DF00215AE\n");
    printf("  MS Basic:    EBD0A0A2-B9E5-4433-87C0-68B6B72699C7\n");
    printf("  Linux FS:    0FC63DAF-8483-4772-8E79-3D69D8477DE4\n");
    printf("  Linux Swap:  0657FD6D-A4AB-43C4-84E5-0933C84B4F4F\n");
    printf("  Linux LVM:   E6D6D379-F507-44C2-A23C-238F2A3DF928\n");

    // 2.8.5.f-g: Advantages
    printf("\n=== GPT Advantages (f-g) ===\n");
    compare_mbr_gpt();
    /*
                    MBR             GPT
    Max partitions  4 primary       128+
    Max disk size   2 TB            9.4 ZB (f)
    Addressing      32-bit LBA      64-bit LBA (g)
    Redundancy      None            Backup at end
    Checksum        None            CRC32
    Names           No              Yes (UTF-16)
    */

    // 2.8.5.h: gdisk
    printf("\n=== gdisk Tool (h) ===\n");
    show_gdisk_usage();

    // Auto-detect
    printf("\n=== Disk Analysis ===\n");
    partition_scheme_t scheme = detect_partition_scheme(device);
    printf("%s uses: %s\n", device,
           scheme == SCHEME_GPT ? "GPT" :
           scheme == SCHEME_MBR ? "MBR" : "Unknown");

    return 0;
}
```

---

## Tests Moulinette

```rust
// MBR
#[test] fn test_mbr_read()              // 2.8.4.a-b
#[test] fn test_mbr_partitions()        // 2.8.4.c-d
#[test] fn test_extended_partitions()   // 2.8.4.e
#[test] fn test_active_partition()      // 2.8.4.f

// GPT
#[test] fn test_gpt_header()            // 2.8.5.c
#[test] fn test_gpt_partitions()        // 2.8.5.d
#[test] fn test_guid_parse()            // 2.8.5.e
#[test] fn test_scheme_detect()         // 2.8.5.b
```

---

## Bareme

| Critere | Points |
|---------|--------|
| MBR parsing (2.8.4.a-d) | 30 |
| Extended partitions (2.8.4.e) | 10 |
| Active/bootable (2.8.4.f-g) | 10 |
| GPT header (2.8.5.b-c) | 25 |
| GPT partitions (2.8.5.d-e) | 20 |
| Scheme detection (2.8.5.f-h) | 5 |
| **Total** | **100** |

---

## Fichiers

```
ex01/
├── partitioning.h
├── mbr.c
├── extended.c
├── gpt.c
├── guid.c
└── Makefile
```
