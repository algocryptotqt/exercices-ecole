# ex02: Interrupts & Exceptions

**Module**: 2.7 - Kernel Development & OS Internals
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.7.5: Interrupts and Exceptions (11 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Interrupt | Asynchronous event |
| b | Exception | Synchronous event |
| c | IDT | Interrupt Descriptor Table |
| d | IDT entry | Handler address, DPL, type |
| e | Interrupt gate | Disables interrupts |
| f | Trap gate | Keeps interrupt state |
| g | Exception types | Fault, trap, abort |
| h | IRQ | Hardware interrupt |
| i | PIC/APIC | Interrupt controller |
| j | Interrupt handler | ISR |
| k | iret | Return from interrupt |

### 2.7.6: Common Exceptions (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Division error | #DE, vector 0 |
| b | Debug | #DB, vector 1 |
| c | Breakpoint | #BP, vector 3 |
| d | Invalid opcode | #UD, vector 6 |
| e | Double fault | #DF, vector 8 |
| f | General protection | #GP, vector 13 |
| g | Page fault | #PF, vector 14 |
| h | Error code | Pushed for some |
| i | CR2 | Page fault address |

---

## Sujet

Comprendre les mecanismes d'interruption et d'exception x86.

### Structures

```c
#include <stdint.h>

// 2.7.5.d: IDT entry (64-bit)
typedef struct {
    uint16_t offset_low;     // Handler address bits 0-15
    uint16_t segment;        // Code segment selector
    uint8_t ist;             // Interrupt Stack Table
    uint8_t type_attr;       // Type and attributes
    uint16_t offset_mid;     // Handler address bits 16-31
    uint32_t offset_high;    // Handler address bits 32-63
    uint32_t reserved;
} idt_entry_t;

// Parsed IDT entry
typedef struct {
    uint64_t handler;        // Full handler address
    uint16_t segment;        // CS selector
    uint8_t ist;             // IST index (0-7)
    uint8_t dpl;             // Descriptor privilege level
    bool present;            // Entry valid
    bool is_trap;            // f: Trap gate (vs interrupt e)
    const char *type_name;   // Gate type name
} parsed_idt_entry_t;

// 2.7.5.g: Exception info
typedef struct {
    uint8_t vector;
    const char *mnemonic;    // #DE, #GP, etc.
    const char *name;
    const char *type;        // Fault, Trap, Abort
    bool has_error_code;     // h: Error code pushed
    const char *description;
} exception_info_t;

// 2.7.5.i: Interrupt controller
typedef struct {
    const char *type;        // PIC, APIC, x2APIC
    uint32_t base_vector;
    int irq_count;
    bool is_apic;
} interrupt_controller_t;

// 2.7.6.h: Error code structure
typedef struct {
    bool external;           // External event
    bool idt;                // IDT/GDT selector
    bool ti;                 // Table indicator
    uint16_t selector_index; // Segment selector index
} selector_error_code_t;

// 2.7.6.g,i: Page fault error code
typedef struct {
    bool present;            // Page present
    bool write;              // Write access
    bool user;               // User mode
    bool reserved;           // Reserved bit violation
    bool fetch;              // Instruction fetch
    bool protection_key;     // Protection key
    bool shadow_stack;       // Shadow stack
    uint64_t address;        // i: CR2 value
} page_fault_info_t;
```

### API

```c
// ============== IDT ==============
// 2.7.5.c-f

// Read IDT
int idt_read(idt_entry_t **entries, int *count);
void idt_free(idt_entry_t *entries);

// Get IDTR
void get_idtr(uint64_t *base, uint16_t *limit);

// Parse entry
void idt_parse_entry(const idt_entry_t *entry, parsed_idt_entry_t *parsed);
void idt_print_entry(int vector, const parsed_idt_entry_t *entry);

// 2.7.5.e-f: Gate type
bool is_interrupt_gate(const parsed_idt_entry_t *entry);
bool is_trap_gate(const parsed_idt_entry_t *entry);

// Display full IDT
void idt_print(void);

// ============== EXCEPTIONS ==============
// 2.7.5.a-b, 2.7.6

// 2.7.6.a-g: Exception info
const exception_info_t *get_exception_info(uint8_t vector);
void print_exception_info(uint8_t vector);

// List all exceptions
const exception_info_t *get_all_exceptions(int *count);
void print_exception_table(void);

// 2.7.5.g: Exception types
const char *exception_type(uint8_t vector);
bool is_fault(uint8_t vector);
bool is_trap(uint8_t vector);
bool is_abort(uint8_t vector);

// 2.7.6.h: Error code parsing
void parse_selector_error(uint32_t error_code, selector_error_code_t *parsed);
void parse_page_fault_error(uint32_t error_code, page_fault_info_t *parsed);
void print_error_code(uint8_t vector, uint32_t error_code);

// ============== INTERRUPTS ==============
// 2.7.5.a,h-j

// 2.7.5.h: IRQ info
typedef struct {
    int irq;
    int vector;
    const char *device;
    bool enabled;
    uint64_t count;
} irq_info_t;

int get_irq_info(irq_info_t **irqs, int *count);
void print_irq_table(void);

// 2.7.5.i: Interrupt controller
int get_interrupt_controller(interrupt_controller_t *ic);
void print_interrupt_controller(void);

// APIC info
uint32_t get_lapic_id(void);
uint64_t get_lapic_base(void);
bool is_apic_enabled(void);

// 2.7.5.j: Handler info
typedef void (*interrupt_handler_t)(void);
interrupt_handler_t get_handler(uint8_t vector);

// 2.7.5.k: Interrupt return
void explain_iret(void);

// ============== SIMULATION ==============

// Simulate exception handling (for learning)
typedef struct {
    uint64_t rip;            // Instruction pointer
    uint64_t rsp;            // Stack pointer
    uint64_t rflags;
    uint64_t cs;
    uint64_t ss;
    uint32_t error_code;
    bool has_error;
} exception_frame_t;

void simulate_exception(uint8_t vector, exception_frame_t *frame);
void print_exception_frame(const exception_frame_t *frame);
```

---

## Exemple

```c
#include "interrupts_exceptions.h"

int main(void) {
    // ============== INTERRUPTS VS EXCEPTIONS ==============
    // 2.7.5.a-b

    printf("=== Interrupts vs Exceptions ===\n");
    printf("\nInterrupts (a):\n");
    printf("  - Asynchronous (can happen anytime)\n");
    printf("  - External source (hardware)\n");
    printf("  - Example: keyboard, timer, disk\n");

    printf("\nExceptions (b):\n");
    printf("  - Synchronous (caused by instruction)\n");
    printf("  - Internal source (CPU)\n");
    printf("  - Example: divide by zero, page fault\n");

    // ============== IDT ==============
    // 2.7.5.c-f

    printf("\n=== Interrupt Descriptor Table (c) ===\n");

    uint64_t idt_base;
    uint16_t idt_limit;
    get_idtr(&idt_base, &idt_limit);
    printf("IDTR Base: 0x%lx\n", idt_base);
    printf("IDTR Limit: %d (256 entries)\n", idt_limit);

    // Read and parse IDT entries
    idt_entry_t *entries;
    int count;
    idt_read(&entries, &count);

    printf("\nFirst 20 IDT entries:\n");
    for (int i = 0; i < 20; i++) {
        parsed_idt_entry_t parsed;
        idt_parse_entry(&entries[i], &parsed);
        if (parsed.present) {
            idt_print_entry(i, &parsed);
        }
    }

    /*
    [0x00] #DE Handler: 0xffffffff81234000 (Interrupt Gate, DPL=0)
    [0x01] #DB Handler: 0xffffffff81234100 (Interrupt Gate, DPL=0)
    [0x03] #BP Handler: 0xffffffff81234300 (Trap Gate, DPL=3)
    [0x06] #UD Handler: 0xffffffff81234600 (Interrupt Gate, DPL=0)
    [0x08] #DF Handler: 0xffffffff81234800 (Interrupt Gate, DPL=0, IST=1)
    [0x0D] #GP Handler: 0xffffffff81234d00 (Interrupt Gate, DPL=0)
    [0x0E] #PF Handler: 0xffffffff81234e00 (Interrupt Gate, DPL=0)
    */

    // 2.7.5.e-f: Gate types
    printf("\n=== Gate Types (e-f) ===\n");
    printf("Interrupt Gate (e): Clears IF flag (disables interrupts)\n");
    printf("Trap Gate (f): Preserves IF flag (keeps interrupt state)\n");

    printf("\n#BP (vector 3) uses Trap Gate:\n");
    printf("  - Allows debugging to use breakpoints\n");
    printf("  - Debugger can handle without disabling interrupts\n");

    // ============== EXCEPTION TABLE ==============
    // 2.7.6

    printf("\n=== Exception Table ===\n");
    print_exception_table();
    /*
    Vec | Mnemonic | Name                    | Type  | Error
    ----|----------|-------------------------|-------|------
    0   | #DE      | Division Error          | Fault | No
    1   | #DB      | Debug                   | F/T   | No
    3   | #BP      | Breakpoint              | Trap  | No
    6   | #UD      | Invalid Opcode          | Fault | No
    8   | #DF      | Double Fault            | Abort | Yes(0)
    13  | #GP      | General Protection      | Fault | Yes
    14  | #PF      | Page Fault              | Fault | Yes
    */

    // 2.7.5.g: Exception types
    printf("\n=== Exception Types (g) ===\n");
    printf("\nFault:\n");
    printf("  - Correctable error\n");
    printf("  - RIP points to faulting instruction\n");
    printf("  - After handling, re-execute instruction\n");
    printf("  - Example: Page fault (can load page)\n");

    printf("\nTrap:\n");
    printf("  - Intentional exception\n");
    printf("  - RIP points to next instruction\n");
    printf("  - Continue after handling\n");
    printf("  - Example: Breakpoint, syscall\n");

    printf("\nAbort:\n");
    printf("  - Unrecoverable error\n");
    printf("  - Cannot reliably determine RIP\n");
    printf("  - Usually terminate process/system\n");
    printf("  - Example: Double fault, machine check\n");

    // 2.7.6.a-g: Common exceptions
    printf("\n=== Common Exceptions ===\n");

    // Division Error
    print_exception_info(0);
    /*
    #DE (0): Division Error
    Type: Fault
    Cause: DIV/IDIV instruction with divisor 0
    Error code: None
    */

    // Page Fault
    print_exception_info(14);
    /*
    #PF (14): Page Fault
    Type: Fault
    Cause: Page not present, protection violation
    Error code: Describes fault type
    CR2: Faulting address
    */

    // 2.7.6.h-i: Error codes
    printf("\n=== Error Codes (h) ===\n");

    // Simulate page fault error
    uint32_t pf_error = 0x07;  // Present, write, user
    page_fault_info_t pf;
    parse_page_fault_error(pf_error, &pf);

    printf("Page Fault Error Code 0x%x:\n", pf_error);
    printf("  Present: %s (page was present)\n", pf.present ? "Yes" : "No");
    printf("  Write: %s (write access)\n", pf.write ? "Yes" : "No");
    printf("  User: %s (user mode)\n", pf.user ? "Yes" : "No");

    printf("\n=== CR2 Register (i) ===\n");
    printf("CR2 contains the linear address that caused page fault\n");
    printf("Example: Access to 0x0 -> CR2 = 0x0 (NULL pointer)\n");

    // ============== HARDWARE INTERRUPTS ==============
    // 2.7.5.h-i

    printf("\n=== Hardware Interrupts (h) ===\n");
    print_irq_table();
    /*
    IRQ | Vector | Device
    ----|--------|--------
    0   | 32     | Timer
    1   | 33     | Keyboard
    8   | 40     | RTC
    12  | 44     | Mouse
    14  | 46     | Primary ATA
    */

    // 2.7.5.i: Interrupt controller
    printf("\n=== Interrupt Controller (i) ===\n");
    print_interrupt_controller();
    /*
    Type: Local APIC + I/O APIC
    LAPIC ID: 0
    LAPIC Base: 0xfee00000
    I/O APIC: Handles external interrupts
    */

    // 2.7.5.k: iret
    printf("\n=== IRET Instruction (k) ===\n");
    explain_iret();
    /*
    IRET restores:
      1. RIP (return address)
      2. CS (code segment)
      3. RFLAGS (flags)
      4. RSP (if privilege change)
      5. SS (if privilege change)

    Used to return from interrupt/exception handler
    */

    // ============== EXCEPTION SIMULATION ==============

    printf("\n=== Exception Frame Simulation ===\n");
    exception_frame_t frame;
    simulate_exception(14, &frame);  // Page fault
    print_exception_frame(&frame);
    /*
    Exception Frame (Page Fault):
      RIP: 0x00007ffff7a12345 (faulting instruction)
      CS:  0x0033 (user code)
      RFLAGS: 0x00010246
      RSP: 0x00007fffffffe000
      SS:  0x002b (user stack)
      Error: 0x00000007
    */

    idt_free(entries);
    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_idt_read()              // 2.7.5.c
#[test] fn test_idt_entries()           // 2.7.5.d
#[test] fn test_gate_types()            // 2.7.5.e-f
#[test] fn test_exception_types()       // 2.7.5.g
#[test] fn test_irq_info()              // 2.7.5.h
#[test] fn test_interrupt_controller()  // 2.7.5.i
#[test] fn test_exception_table()       // 2.7.6.a-g
#[test] fn test_error_code_parse()      // 2.7.6.h
#[test] fn test_page_fault_error()      // 2.7.6.i
```

---

## Bareme

| Critere | Points |
|---------|--------|
| IDT parsing (2.7.5.c-d) | 20 |
| Gate types (2.7.5.e-f) | 15 |
| Exception types (2.7.5.g) | 15 |
| IRQ & controllers (2.7.5.h-i) | 15 |
| Exception table (2.7.6.a-g) | 20 |
| Error codes (2.7.6.h-i) | 15 |
| **Total** | **100** |

---

## Fichiers

```
ex02/
├── interrupts_exceptions.h
├── idt.c
├── exceptions.c
├── irq.c
├── error_codes.c
└── Makefile
```
