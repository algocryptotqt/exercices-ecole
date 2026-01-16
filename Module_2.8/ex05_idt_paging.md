# ex05: IDT Setup & Paging

**Module**: 2.8 - Boot Process & Bare Metal
**Difficulte**: Expert
**Duree**: 7h
**Score qualite**: 98/100

## Concepts Couverts

### 2.8.14: IDT Setup (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | IDT structure | Array of gates |
| b | Interrupt gate | Handler entry |
| c | Gate format | Offset, selector, flags |
| d | IDTR | IDT register |
| e | lidt | Load IDTR |
| f | Handler stub | Save regs, call C handler |
| g | ISR | Interrupt Service Routine |
| h | Exception handlers | #GP, #PF, etc. |

### 2.8.15: Enabling Paging (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Page tables | Build structure |
| b | Identity mapping | Physical = virtual |
| c | Higher-half kernel | Kernel in high memory |
| d | CR3 | Page table base |
| e | CR0.PG | Enable paging |
| f | TLB | Initialize |
| g | Page fault handler | Required |

### 2.8.16: Multiboot Specification (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Multiboot | Standard interface |
| b | Magic number | 0x1BADB002 |
| c | Flags | Required features |
| d | Header location | In first 8KB |
| e | Boot info | Passed to kernel |
| f | Memory map | Available memory |
| g | Module loading | Additional files |
| h | GRUB support | Multiboot compliant |

---

## Sujet

Configurer l'IDT, activer la pagination et implementer le support Multiboot.

### Structures

```c
// IDT entry (32-bit)
typedef struct {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t zero;
    uint8_t type_attr;
    uint16_t offset_high;
} __attribute__((packed)) idt_entry_32_t;

// IDT entry (64-bit)
typedef struct {
    uint16_t offset_low;
    uint16_t selector;
    uint8_t ist;
    uint8_t type_attr;
    uint16_t offset_mid;
    uint32_t offset_high;
    uint32_t reserved;
} __attribute__((packed)) idt_entry_64_t;

// Page directory/table entry
typedef struct {
    uint32_t present : 1;
    uint32_t rw : 1;
    uint32_t user : 1;
    uint32_t pwt : 1;
    uint32_t pcd : 1;
    uint32_t accessed : 1;
    uint32_t dirty : 1;
    uint32_t ps : 1;       // Page size (4MB if set)
    uint32_t global : 1;
    uint32_t available : 3;
    uint32_t frame : 20;   // Physical address >> 12
} __attribute__((packed)) page_entry_t;

// Multiboot header
typedef struct {
    uint32_t magic;        // 0x1BADB002
    uint32_t flags;
    uint32_t checksum;     // -(magic + flags)
} __attribute__((packed)) multiboot_header_t;

// Multiboot info (passed by bootloader)
typedef struct {
    uint32_t flags;
    uint32_t mem_lower;
    uint32_t mem_upper;
    uint32_t boot_device;
    uint32_t cmdline;
    uint32_t mods_count;
    uint32_t mods_addr;
    // ... more fields
} __attribute__((packed)) multiboot_info_t;
```

### API

```c
// IDT
void create_idt_entry(void *entry, uint64_t handler, uint16_t selector,
                      uint8_t type_attr, bool is_64bit);
void setup_idt(void);
void load_idt(void *idt, uint16_t size);

// Exception handlers
void isr_common_stub(void);  // Assembly stub
void exception_handler(int vector, uint64_t error_code);
void register_exception_handlers(void);

// Paging
void create_page_directory(uint32_t *pd);
void setup_identity_mapping(uint32_t *pd);
void enable_paging(uint32_t *pd);
void invlpg(void *addr);

// Multiboot
bool verify_multiboot_magic(uint32_t magic);
void parse_multiboot_info(multiboot_info_t *info);
void get_memory_map(multiboot_info_t *info);
```

---

## Exemple

```c
#include "idt_paging.h"

int main(void) {
    // 2.8.14: IDT Setup
    printf("=== IDT Setup ===\n");
    printf("IDT entry format (32-bit):\n");
    printf("  [0-1] Offset low (handler address bits 0-15)\n");
    printf("  [2-3] Selector (code segment)\n");
    printf("  [4]   Zero\n");
    printf("  [5]   Type/Attributes\n");
    printf("  [6-7] Offset high (handler address bits 16-31)\n");

    printf("\nType/Attributes:\n");
    printf("  0x8E - Interrupt gate (ring 0)\n");
    printf("  0x8F - Trap gate (ring 0)\n");
    printf("  0xEE - Interrupt gate (ring 3)\n");

    // 2.8.15: Paging
    printf("\n=== Paging Setup ===\n");
    printf("32-bit paging (2-level):\n");
    printf("  Page Directory -> Page Tables -> Pages (4KB)\n");
    printf("\nVirtual address split:\n");
    printf("  [31-22] PD index (10 bits, 1024 entries)\n");
    printf("  [21-12] PT index (10 bits, 1024 entries)\n");
    printf("  [11-0]  Offset (12 bits, 4KB)\n");

    printf("\nIdentity mapping: Virtual = Physical\n");
    printf("Higher-half: Kernel at 0xC0000000+\n");

    // 2.8.16: Multiboot
    printf("\n=== Multiboot ===\n");
    printf("Multiboot header (in first 8KB):\n");
    printf("  Magic: 0x1BADB002\n");
    printf("  Flags: Request features\n");
    printf("  Checksum: -(magic + flags)\n");
    printf("\nGRUB passes multiboot_info struct\n");

    return 0;
}
```

---

## Fichiers

```
ex05/
├── idt_paging.h
├── idt.c
├── isr_stubs.asm
├── paging.c
├── multiboot.c
└── Makefile
```
