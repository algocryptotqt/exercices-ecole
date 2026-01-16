# ex08: Memory Detection & Physical Memory Manager

**Module**: 2.8 - Boot Process & Bare Metal
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.8.21: Memory Detection (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | BIOS E820 | Memory map |
| b | Int 0x15, AX=0xE820 | BIOS call |
| c | Memory regions | Type, base, length |
| d | Available | Type 1 |
| e | Reserved | Type 2 |
| f | ACPI | Type 3, 4 |
| g | Multiboot info | Memory from bootloader |

### 2.8.22: Simple Physical Memory Manager (6 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Bitmap allocator | One bit per page |
| b | Initialization | Mark used regions |
| c | alloc_page | Find free page |
| d | free_page | Mark as free |
| e | Page alignment | 4KB |
| f | Memory regions | Track available |

---

## Sujet

Detecter la memoire disponible et implementer un allocateur de pages physiques.

### Structures

```c
// E820 memory region
typedef struct {
    uint64_t base;
    uint64_t length;
    uint32_t type;       // 1=available, 2=reserved, etc.
    uint32_t acpi;
} __attribute__((packed)) e820_entry_t;

// Memory types
typedef enum {
    MEM_AVAILABLE = 1,
    MEM_RESERVED = 2,
    MEM_ACPI_RECLAIMABLE = 3,
    MEM_ACPI_NVS = 4,
    MEM_BAD = 5
} mem_type_t;

// Physical memory manager
typedef struct {
    uint8_t *bitmap;        // One bit per page
    uint64_t total_pages;
    uint64_t free_pages;
    uint64_t used_pages;
    uint64_t mem_start;
    uint64_t mem_end;
} pmm_t;

#define PAGE_SIZE 4096
```

### API

```c
// Memory detection
int detect_memory_e820(e820_entry_t *entries, int max_entries);
int get_memory_from_multiboot(void *mbi, e820_entry_t *entries, int max);
void print_memory_map(e820_entry_t *entries, int count);
uint64_t get_total_memory(e820_entry_t *entries, int count);
const char *memory_type_name(uint32_t type);

// Physical memory manager
void pmm_init(e820_entry_t *entries, int count);
void *pmm_alloc_page(void);
void pmm_free_page(void *page);
uint64_t pmm_get_free_pages(void);
void pmm_mark_region_used(uint64_t base, uint64_t length);
void pmm_mark_region_free(uint64_t base, uint64_t length);
```

---

## Exemple

```c
#include "memory_detection.h"

int main(void) {
    // 2.8.21: Memory Detection
    printf("=== Memory Detection ===\n");

    // E820 call (in real mode)
    /*
    mov ax, 0xE820
    mov ebx, 0           ; continuation
    mov ecx, 24          ; buffer size
    mov edx, 0x534D4150  ; 'SMAP'
    mov di, buffer
    int 0x15
    */

    printf("E820 memory types:\n");
    printf("  1 = Available (usable RAM)\n");
    printf("  2 = Reserved (system)\n");
    printf("  3 = ACPI reclaimable\n");
    printf("  4 = ACPI NVS\n");
    printf("  5 = Bad memory\n");

    // Get memory map from multiboot
    e820_entry_t entries[32];
    int count = get_memory_from_multiboot(multiboot_info, entries, 32);

    printf("\nMemory Map:\n");
    print_memory_map(entries, count);
    /*
    Base                Length              Type
    0x0000000000000000  0x000000000009FC00  Available
    0x000000000009FC00  0x0000000000000400  Reserved
    0x00000000000E8000  0x0000000000018000  Reserved
    0x0000000000100000  0x000000001FEF0000  Available
    0x000000001FFF0000  0x0000000000010000  ACPI
    */

    uint64_t total = get_total_memory(entries, count);
    printf("\nTotal available: %llu MB\n", total / (1024 * 1024));

    // 2.8.22: Physical Memory Manager
    printf("\n=== Physical Memory Manager ===\n");

    pmm_init(entries, count);
    printf("Bitmap allocator initialized\n");
    printf("Total pages: %llu\n", pmm_get_total_pages());
    printf("Free pages: %llu\n", pmm_get_free_pages());

    // Allocate some pages
    void *page1 = pmm_alloc_page();
    void *page2 = pmm_alloc_page();
    printf("\nAllocated: 0x%lX, 0x%lX\n", (uint64_t)page1, (uint64_t)page2);
    printf("Free pages: %llu\n", pmm_get_free_pages());

    // Free a page
    pmm_free_page(page1);
    printf("After free: %llu free pages\n", pmm_get_free_pages());

    return 0;
}

// Bitmap allocator implementation
static pmm_t pmm;

void pmm_init(e820_entry_t *entries, int count) {
    // Find highest address
    uint64_t mem_end = 0;
    for (int i = 0; i < count; i++) {
        if (entries[i].type == MEM_AVAILABLE) {
            uint64_t end = entries[i].base + entries[i].length;
            if (end > mem_end) mem_end = end;
        }
    }

    pmm.total_pages = mem_end / PAGE_SIZE;
    pmm.bitmap = /* allocate bitmap */;

    // Mark all as used initially
    memset(pmm.bitmap, 0xFF, (pmm.total_pages + 7) / 8);
    pmm.free_pages = 0;

    // Mark available regions as free
    for (int i = 0; i < count; i++) {
        if (entries[i].type == MEM_AVAILABLE) {
            pmm_mark_region_free(entries[i].base, entries[i].length);
        }
    }
}

void *pmm_alloc_page(void) {
    // Find first free bit
    for (uint64_t i = 0; i < pmm.total_pages; i++) {
        uint64_t byte = i / 8;
        uint64_t bit = i % 8;
        if (!(pmm.bitmap[byte] & (1 << bit))) {
            pmm.bitmap[byte] |= (1 << bit);  // Mark used
            pmm.free_pages--;
            return (void*)(i * PAGE_SIZE);
        }
    }
    return NULL;  // Out of memory
}

void pmm_free_page(void *page) {
    uint64_t addr = (uint64_t)page;
    uint64_t index = addr / PAGE_SIZE;
    uint64_t byte = index / 8;
    uint64_t bit = index % 8;
    pmm.bitmap[byte] &= ~(1 << bit);  // Mark free
    pmm.free_pages++;
}
```

---

## Fichiers

```
ex08/
├── memory_detection.h
├── e820.c
├── pmm.c
├── bitmap.c
└── Makefile
```
