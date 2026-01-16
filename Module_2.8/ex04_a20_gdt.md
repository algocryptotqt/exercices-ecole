# ex04: A20 Line & GDT Setup

**Module**: 2.8 - Boot Process & Bare Metal
**Difficulte**: Tres Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.8.11: A20 Line (5 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | A20 problem | Address wraparound |
| b | Historical reason | 8086 compatibility |
| c | A20 gate | Enable/disable |
| d | Enabling methods | Keyboard controller, Fast A20 |
| e | Testing | Check if enabled |

### 2.8.12: Writing a Bootloader (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Constraints | 512 bytes |
| b | Assembly | 16-bit NASM |
| c | ORG 0x7C00 | Load address |
| d | Boot signature | dw 0xAA55 |
| e | BIOS interrupts | I/O |
| f | Disk reading | Int 0x13 |
| g | Print string | Int 0x10 |
| h | Load kernel | Read sectors |

### 2.8.13: GDT Setup (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | GDT structure | Array of descriptors |
| b | Null descriptor | First entry |
| c | Code segment | Executable |
| d | Data segment | Read/write |
| e | Descriptor format | Base, limit, flags |
| f | GDTR | GDT register |
| g | lgdt | Load GDTR |
| h | Flat model | Base=0, limit=max |

---

## Sujet

Implementer l'activation A20, ecrire un bootloader simple et configurer le GDT.

### Structures

```c
// Segment descriptor
typedef struct {
    uint16_t limit_low;
    uint16_t base_low;
    uint8_t base_mid;
    uint8_t access;        // Present, Ring, Type
    uint8_t flags_limit;   // Flags + limit high
    uint8_t base_high;
} __attribute__((packed)) gdt_entry_t;

// GDT pointer for lgdt
typedef struct {
    uint16_t limit;        // Size - 1
    uint32_t base;         // GDT address
} __attribute__((packed)) gdt_ptr_t;
```

### API

```c
// A20 line
void explain_a20_problem(void);
void enable_a20_keyboard(void);    // Via 8042 controller
void enable_a20_fast(void);        // Via port 0x92
bool test_a20_enabled(void);

// GDT
void create_gdt_entry(gdt_entry_t *entry, uint32_t base, uint32_t limit,
                      uint8_t access, uint8_t flags);
void setup_flat_gdt(gdt_entry_t *gdt);
void explain_access_byte(void);
void explain_flags_byte(void);

// Bootloader code generation
void generate_bootloader_asm(char *buffer, size_t size);
void show_bootloader_example(void);
```

---

## Exemple

```c
#include "a20_gdt.h"

int main(void) {
    // 2.8.11: A20 Line
    printf("=== A20 Line ===\n");
    explain_a20_problem();
    /*
    A20 Problem:
      - 8086 had 20-bit address (1MB)
      - Address wrapping at 1MB boundary
      - Some programs relied on this
      - 80286+ broke compatibility
      - A20 gate added to emulate wrapping

    Without A20: 0x100000 wraps to 0x000000
    With A20: 0x100000 is accessible
    */

    printf("\nA20 Enable Methods:\n");
    printf("1. Keyboard controller (port 0x64)\n");
    printf("2. Fast A20 (port 0x92)\n");
    printf("3. BIOS Int 0x15, AX=0x2401\n");

    // 2.8.12: Bootloader
    printf("\n=== Writing a Bootloader ===\n");
    show_bootloader_example();
    /*
    ; bootloader.asm
    [BITS 16]
    [ORG 0x7C00]

    start:
        ; Setup segments
        xor ax, ax
        mov ds, ax
        mov es, ax
        mov ss, ax
        mov sp, 0x7C00

        ; Print message
        mov si, msg
        call print_string

        ; Halt
        cli
        hlt

    print_string:
        mov ah, 0x0E    ; Teletype
    .loop:
        lodsb
        test al, al
        jz .done
        int 0x10
        jmp .loop
    .done:
        ret

    msg: db "Hello from bootloader!", 0

    ; Pad to 510 bytes
    times 510-($-$$) db 0

    ; Boot signature
    dw 0xAA55
    */

    // 2.8.13: GDT
    printf("\n=== GDT Setup ===\n");

    // Create flat model GDT
    gdt_entry_t gdt[3];

    // Entry 0: Null descriptor (required)
    create_gdt_entry(&gdt[0], 0, 0, 0, 0);

    // Entry 1: Code segment (ring 0)
    // Base=0, Limit=4GB, Executable, Readable
    create_gdt_entry(&gdt[1], 0, 0xFFFFF, 0x9A, 0xCF);

    // Entry 2: Data segment (ring 0)
    // Base=0, Limit=4GB, Writable
    create_gdt_entry(&gdt[2], 0, 0xFFFFF, 0x92, 0xCF);

    printf("Flat model GDT:\n");
    printf("  [0] Null descriptor\n");
    printf("  [1] Code: base=0, limit=4GB, access=0x9A\n");
    printf("  [2] Data: base=0, limit=4GB, access=0x92\n");

    explain_access_byte();
    /*
    Access byte:
      Bit 7: Present (1 = valid)
      Bits 5-6: Ring (0-3)
      Bit 4: Descriptor type (1 = code/data)
      Bit 3: Executable (1 = code)
      Bit 2: Direction/Conforming
      Bit 1: Read/Write
      Bit 0: Accessed

    0x9A = 10011010b (Code, readable)
    0x92 = 10010010b (Data, writable)
    */

    return 0;
}
```

---

## Fichiers

```
ex04/
├── a20_gdt.h
├── a20.c
├── gdt.c
├── bootloader.c
└── Makefile
```
