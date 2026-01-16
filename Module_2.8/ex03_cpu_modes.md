# ex03: CPU Modes (Real, Protected, Long)

**Module**: 2.8 - Boot Process & Bare Metal
**Difficulte**: Tres Difficile
**Duree**: 6h
**Score qualite**: 98/100

## Concepts Couverts

### 2.8.8: Real Mode (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | 16-bit mode | Original 8086 |
| b | Address space | 1MB |
| c | Segment:Offset | Address calculation |
| d | Physical = Segment×16 + Offset | Formula |
| e | No protection | All access allowed |
| f | Interrupt table | At 0x0000 |
| g | BIOS services | Available |
| h | Bootloader uses | Initially |

### 2.8.9: Protected Mode (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | 32-bit mode | 80386+ |
| b | Address space | 4GB |
| c | GDT required | Segment descriptors |
| d | Protection | Rings |
| e | Paging optional | Virtual memory |
| f | Switching | CR0.PE bit |
| g | Far jump | After switching |
| h | A20 line | Enable more memory |

### 2.8.10: Long Mode (64-bit) (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | 64-bit mode | x86-64 |
| b | Address space | 256TB (48-bit) |
| c | Requirements | Paging, PAE, LME |
| d | Switching | CR0.PG + CR4.PAE + EFER.LME |
| e | 4-level paging | Required |
| f | Flat model | Segment base = 0 |
| g | New registers | R8-R15 |
| h | Larger registers | 64-bit |

---

## Sujet

Comprendre les modes CPU x86 et les transitions entre eux.

### Structures

```c
// CPU mode info
typedef struct {
    const char *name;
    int bits;
    uint64_t address_space;
    bool protection;
    bool paging_required;
    const char *switch_from;
} cpu_mode_t;

// Segment descriptor (protected mode)
typedef struct {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_mid;
    uint8_t access;
    uint8_t flags_limit_high;
    uint8_t base_high;
} __attribute__((packed)) segment_descriptor_t;

// GDT pointer
typedef struct {
    uint16_t limit;
    uint64_t base;
} __attribute__((packed)) gdt_ptr_t;
```

### API

```c
// Real mode
void explain_real_mode(void);
uint32_t segment_offset_to_linear(uint16_t segment, uint16_t offset);

// Protected mode
void explain_protected_mode(void);
void create_gdt_entry(segment_descriptor_t *desc, uint32_t base,
                      uint32_t limit, uint8_t access, uint8_t flags);
void show_switch_to_protected(void);

// Long mode
void explain_long_mode(void);
void show_switch_to_long(void);
void explain_paging_requirements(void);

// Mode detection
int get_current_cpu_mode(void);
```

---

## Exemple

```c
#include "cpu_modes.h"

int main(void) {
    // 2.8.8: Real mode
    printf("=== Real Mode ===\n");
    explain_real_mode();
    /*
    Real Mode (16-bit):
      - Original 8086 mode
      - 1MB address space (20-bit)
      - Segment:Offset addressing
      - Physical = Segment × 16 + Offset
      - No memory protection
      - IVT at 0x0000
    */

    // Address calculation
    uint32_t addr = segment_offset_to_linear(0x1234, 0x5678);
    printf("0x1234:0x5678 = 0x%X\n", addr);  // 0x179B8

    // 2.8.9: Protected mode
    printf("\n=== Protected Mode ===\n");
    explain_protected_mode();
    /*
    Protected Mode (32-bit):
      - 4GB address space
      - GDT for segment descriptors
      - 4 privilege rings (0-3)
      - Paging optional

    Switch to protected:
      1. Disable interrupts (cli)
      2. Enable A20 line
      3. Load GDT (lgdt)
      4. Set CR0.PE = 1
      5. Far jump to 32-bit code
    */

    // 2.8.10: Long mode
    printf("\n=== Long Mode ===\n");
    explain_long_mode();
    /*
    Long Mode (64-bit):
      - 48-bit virtual address (256TB)
      - 4-level paging REQUIRED
      - New registers: R8-R15
      - RIP-relative addressing
      - Flat memory model

    Requirements:
      - Must be in protected mode first
      - PAE paging enabled (CR4.PAE)
      - Long mode enable (EFER.LME)
      - Then enable paging (CR0.PG)
    */

    show_switch_to_long();
    /*
    ; From protected mode to long mode:
    ; 1. Disable paging if enabled
    mov eax, cr0
    and eax, ~(1 << 31)
    mov cr0, eax

    ; 2. Enable PAE
    mov eax, cr4
    or eax, (1 << 5)
    mov cr4, eax

    ; 3. Load PML4 table
    mov eax, pml4_table
    mov cr3, eax

    ; 4. Enable long mode
    mov ecx, 0xC0000080  ; EFER MSR
    rdmsr
    or eax, (1 << 8)     ; LME bit
    wrmsr

    ; 5. Enable paging (enters long mode)
    mov eax, cr0
    or eax, (1 << 31)
    mov cr0, eax

    ; 6. Far jump to 64-bit code
    jmp 0x08:long_mode_start
    */

    return 0;
}
```

---

## Fichiers

```
ex03/
├── cpu_modes.h
├── real_mode.c
├── protected_mode.c
├── long_mode.c
├── transitions.c
└── Makefile
```
