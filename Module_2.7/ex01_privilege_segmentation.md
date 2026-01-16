# ex01: Privilege Levels & Segmentation

**Module**: 2.7 - Kernel Development & OS Internals
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.7.3: Privilege Levels (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Protection rings | 0-3 |
| b | Ring 0 | Kernel mode |
| c | Ring 3 | User mode |
| d | Rings 1-2 | Rarely used |
| e | CPL | Current privilege level |
| f | DPL | Descriptor privilege level |
| g | RPL | Requested privilege level |
| h | Privilege check | CPL <= DPL |
| i | Mode switching | Via interrupts/syscalls |

### 2.7.4: Segmentation (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Segment | Memory region |
| b | Segment selector | Index into descriptor table |
| c | GDT | Global Descriptor Table |
| d | LDT | Local Descriptor Table |
| e | Segment descriptor | Base, limit, flags |
| f | Code segment | Executable |
| g | Data segment | Read/write |
| h | TSS | Task State Segment |
| i | Flat model | Modern usage |

---

## Sujet

Comprendre les niveaux de privilege et la segmentation x86.

### Structures

```c
#include <stdint.h>

// 2.7.3: Privilege levels
typedef enum {
    RING_0 = 0,              // b: Kernel
    RING_1 = 1,              // d: Drivers (unused in Linux)
    RING_2 = 2,              // d: Drivers (unused in Linux)
    RING_3 = 3               // c: User
} privilege_ring_t;

// 2.7.3.b: Segment selector
typedef struct {
    uint16_t rpl : 2;        // g: Requested Privilege Level
    uint16_t ti : 1;         // Table Indicator (0=GDT, 1=LDT)
    uint16_t index : 13;     // Descriptor index
} segment_selector_t;

// 2.7.4.e: Segment descriptor (64-bit)
typedef struct {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_mid;
    uint8_t access;          // Type, DPL, Present
    uint8_t flags_limit;     // Flags and limit high
    uint8_t base_high;
} segment_descriptor_t;

// Parsed descriptor
typedef struct {
    uint64_t base;           // Segment base address
    uint32_t limit;          // Segment limit
    uint8_t type;            // Segment type
    uint8_t dpl;             // f: Descriptor Privilege Level
    bool present;            // Present in memory
    bool granularity;        // 4KB granularity
    bool is_code;            // f: Code segment
    bool is_data;            // g: Data segment
    bool is_system;          // h: System segment (TSS, etc.)
} parsed_descriptor_t;

// 2.7.4.c: GDT structure
typedef struct {
    segment_descriptor_t *descriptors;
    int count;
    uint64_t base;           // GDT base address
    uint16_t limit;          // GDT size
} gdt_t;

// 2.7.4.h: TSS structure (simplified)
typedef struct {
    uint32_t reserved0;
    uint64_t rsp0;           // Kernel stack for ring 0
    uint64_t rsp1;           // Stack for ring 1
    uint64_t rsp2;           // Stack for ring 2
    uint64_t reserved1;
    uint64_t ist[7];         // Interrupt Stack Table
    uint64_t reserved2;
    uint16_t reserved3;
    uint16_t iopb_offset;    // I/O Permission Bitmap offset
} tss64_t;
```

### API

```c
// ============== PRIVILEGE LEVELS ==============
// 2.7.3

// 2.7.3.a-d: Ring information
privilege_ring_t get_current_ring(void);
const char *ring_name(privilege_ring_t ring);
void explain_rings(void);

// 2.7.3.e: Current Privilege Level
uint8_t get_cpl(void);
bool is_in_kernel_mode(void);

// 2.7.3.f-g: Privilege checking
bool check_privilege(uint8_t cpl, uint8_t dpl, uint8_t rpl);
void explain_privilege_check(uint8_t cpl, uint8_t dpl, uint8_t rpl);

// 2.7.3.i: Mode switching
void explain_mode_switching(void);

// ============== SEGMENT SELECTORS ==============
// 2.7.3.b

// Parse selector
void parse_selector(uint16_t selector, segment_selector_t *parsed);
void print_selector(uint16_t selector);

// Get current selectors
uint16_t get_cs_selector(void);
uint16_t get_ds_selector(void);
uint16_t get_ss_selector(void);

// ============== SEGMENTATION ==============
// 2.7.4

// 2.7.4.c: GDT operations
int gdt_read(gdt_t *gdt);
void gdt_free(gdt_t *gdt);
void gdt_print(const gdt_t *gdt);

// Get GDTR
void get_gdtr(uint64_t *base, uint16_t *limit);

// 2.7.4.d: LDT operations
int ldt_read(gdt_t *ldt);
bool ldt_exists(void);

// 2.7.4.e: Descriptor parsing
void parse_descriptor(const segment_descriptor_t *desc,
                      parsed_descriptor_t *parsed);
void print_descriptor(const parsed_descriptor_t *desc);

// Get specific descriptor
int gdt_get_descriptor(const gdt_t *gdt, int index,
                       parsed_descriptor_t *parsed);

// 2.7.4.f-g: Segment types
bool is_code_segment(const parsed_descriptor_t *desc);
bool is_data_segment(const parsed_descriptor_t *desc);
const char *segment_type_string(const parsed_descriptor_t *desc);

// 2.7.4.h: TSS
int tss_read(int selector, tss64_t *tss);
void tss_print(const tss64_t *tss);
uint64_t tss_get_kernel_stack(void);

// 2.7.4.i: Flat model explanation
void explain_flat_model(void);

// ============== ANALYSIS ==============

// Show current segmentation state
void show_segmentation_state(void);

// Verify segment setup
int verify_segment_setup(void);
```

---

## Exemple

```c
#include "privilege_segmentation.h"

int main(void) {
    // ============== PRIVILEGE LEVELS ==============
    // 2.7.3

    printf("=== Protection Rings (a) ===\n");
    explain_rings();
    /*
    Ring 0: Kernel mode - full hardware access
    Ring 1: (Unused in most OS)
    Ring 2: (Unused in most OS)
    Ring 3: User mode - restricted access
    */

    // 2.7.3.b-c: Current ring
    privilege_ring_t ring = get_current_ring();
    printf("\nCurrent ring: %d (%s)\n", ring, ring_name(ring));
    // Output: Current ring: 3 (User mode)

    // 2.7.3.e: CPL from CS register
    printf("\n=== Current Privilege Level (e) ===\n");
    uint8_t cpl = get_cpl();
    printf("CPL: %d\n", cpl);
    printf("In kernel mode: %s\n", is_in_kernel_mode() ? "Yes" : "No");

    // 2.7.3.f-g: Privilege check
    printf("\n=== Privilege Check (f-h) ===\n");
    printf("Rule: CPL <= DPL to access segment\n");
    printf("RPL overrides CPL if RPL > CPL\n\n");

    // Examples
    explain_privilege_check(0, 0, 0);  // Kernel accessing kernel
    explain_privilege_check(3, 3, 3);  // User accessing user
    explain_privilege_check(3, 0, 3);  // User trying kernel (fails)
    /*
    CPL=0, DPL=0, RPL=0: ALLOWED (kernel -> kernel)
    CPL=3, DPL=3, RPL=3: ALLOWED (user -> user)
    CPL=3, DPL=0, RPL=3: DENIED (user cannot access ring 0)
    */

    // 2.7.3.i: Mode switching
    printf("\n=== Mode Switching (i) ===\n");
    explain_mode_switching();
    /*
    User -> Kernel:
      1. Software interrupt (int instruction)
      2. syscall instruction
      3. Exception (page fault, etc.)
      4. Hardware interrupt

    Kernel -> User:
      1. iret instruction
      2. sysret instruction
    */

    // ============== SEGMENT SELECTORS ==============

    printf("\n=== Segment Selectors ===\n");

    uint16_t cs = get_cs_selector();
    uint16_t ds = get_ds_selector();
    uint16_t ss = get_ss_selector();

    printf("CS: ");
    print_selector(cs);
    printf("DS: ");
    print_selector(ds);
    printf("SS: ");
    print_selector(ss);

    /*
    CS: 0x0033 (Index=6, Table=GDT, RPL=3)
    DS: 0x002b (Index=5, Table=GDT, RPL=3)
    SS: 0x002b (Index=5, Table=GDT, RPL=3)
    */

    // Parse selector
    segment_selector_t parsed;
    parse_selector(cs, &parsed);
    printf("\nCS selector breakdown:\n");
    printf("  Index: %d\n", parsed.index);
    printf("  Table: %s\n", parsed.ti ? "LDT" : "GDT");
    printf("  RPL: %d\n", parsed.rpl);

    // ============== GDT ==============
    // 2.7.4.c

    printf("\n=== Global Descriptor Table (c) ===\n");

    uint64_t gdt_base;
    uint16_t gdt_limit;
    get_gdtr(&gdt_base, &gdt_limit);
    printf("GDTR Base: 0x%lx\n", gdt_base);
    printf("GDTR Limit: %d bytes (%d entries)\n",
           gdt_limit, (gdt_limit + 1) / 8);

    gdt_t gdt;
    gdt_read(&gdt);
    gdt_print(&gdt);

    /*
    GDT Entries:
    [0] NULL descriptor
    [1] Kernel Code 64-bit (DPL=0, base=0, limit=fffff)
    [2] Kernel Data 64-bit (DPL=0, base=0, limit=fffff)
    [3] User Code 32-bit (DPL=3, base=0, limit=fffff)
    [4] User Data 64-bit (DPL=3, base=0, limit=fffff)
    [5] User Code 64-bit (DPL=3, base=0, limit=fffff)
    [6] TSS (DPL=0)
    */

    // 2.7.4.e: Parse descriptor
    printf("\n=== Segment Descriptor (e) ===\n");
    parsed_descriptor_t desc;
    gdt_get_descriptor(&gdt, 1, &desc);  // Kernel code

    printf("Kernel Code Segment:\n");
    printf("  Base: 0x%lx\n", desc.base);
    printf("  Limit: 0x%x\n", desc.limit);
    printf("  DPL: %d\n", desc.dpl);
    printf("  Present: %s\n", desc.present ? "Yes" : "No");
    printf("  Type: %s\n", segment_type_string(&desc));

    // 2.7.4.f-g: Code vs Data
    printf("\n=== Segment Types (f-g) ===\n");
    for (int i = 1; i <= 5; i++) {
        gdt_get_descriptor(&gdt, i, &desc);
        printf("[%d] %s segment, DPL=%d\n",
               i, segment_type_string(&desc), desc.dpl);
    }

    // 2.7.4.h: TSS
    printf("\n=== Task State Segment (h) ===\n");
    tss64_t tss;
    tss_read(6 << 3, &tss);  // TSS selector
    tss_print(&tss);
    /*
    TSS:
      RSP0 (kernel stack): 0xffff880000000000
      RSP1: 0x0
      RSP2: 0x0
      IST1-7: Interrupt stacks
    */

    printf("Kernel stack (for ring 0): 0x%lx\n", tss.rsp0);

    // 2.7.4.i: Flat model
    printf("\n=== Flat Memory Model (i) ===\n");
    explain_flat_model();
    /*
    Modern x86-64 uses flat memory model:
    - All segments have base=0, limit=max
    - Segmentation effectively disabled
    - Memory protection via paging only
    - Segments still needed for privilege levels (CS.DPL)
    */

    // Full state
    printf("\n=== Current Segmentation State ===\n");
    show_segmentation_state();

    gdt_free(&gdt);
    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_rings()                 // 2.7.3.a-d
#[test] fn test_cpl()                   // 2.7.3.e
#[test] fn test_privilege_check()       // 2.7.3.f-h
#[test] fn test_mode_switch()           // 2.7.3.i
#[test] fn test_selector_parse()        // 2.7.4.b
#[test] fn test_gdt_read()              // 2.7.4.c
#[test] fn test_descriptor_parse()      // 2.7.4.e
#[test] fn test_segment_types()         // 2.7.4.f-g
#[test] fn test_tss()                   // 2.7.4.h
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Privilege levels (2.7.3.a-d) | 20 |
| CPL/DPL/RPL (2.7.3.e-h) | 20 |
| Mode switching (2.7.3.i) | 10 |
| Selectors & GDT (2.7.4.b-c) | 20 |
| Descriptors (2.7.4.e-g) | 20 |
| TSS & flat model (2.7.4.h-i) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex01/
├── privilege_segmentation.h
├── privilege.c
├── selectors.c
├── gdt.c
├── descriptors.c
├── tss.c
└── Makefile
```
