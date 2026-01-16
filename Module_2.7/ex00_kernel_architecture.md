# ex00: Kernel Concepts & x86 Architecture

**Module**: 2.7 - Kernel Development & OS Internals
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.7.1: Kernel Concepts (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Kernel | Core of OS |
| b | Kernel mode | Privileged execution |
| c | User mode | Restricted execution |
| d | Monolithic | Linux, BSD |
| e | Microkernel | Mach, L4, Minix |
| f | Hybrid | Windows NT, macOS |
| g | Kernel responsibilities | Process, memory, file, device |
| h | Kernel vs OS | Kernel is core component |

### 2.7.2: x86 Architecture Overview (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Registers | General purpose, special |
| b | RAX-RDX, RSI, RDI | GP registers |
| c | RSP, RBP | Stack and base pointer |
| d | RIP | Instruction pointer |
| e | RFLAGS | Status flags |
| f | Segment registers | CS, DS, SS, ES, FS, GS |
| g | Control registers | CR0, CR3, CR4 |
| h | MSRs | Model-specific registers |
| i | Modes | Real, protected, long |

---

## Sujet

Explorer les concepts fondamentaux du kernel et l'architecture x86-64.

### Structures

```c
#include <stdint.h>

// 2.7.1: Kernel architecture info
typedef struct {
    const char *name;
    const char *type;        // d-f: Monolithic, Microkernel, Hybrid
    const char *description;
    const char *examples[];
} kernel_arch_t;

// 2.7.2.a-e: Register set
typedef struct {
    // General purpose (b)
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;

    // Stack pointers (c)
    uint64_t rsp, rbp;

    // Instruction pointer (d)
    uint64_t rip;

    // Flags (e)
    uint64_t rflags;

    // Segment registers (f)
    uint16_t cs, ds, ss, es, fs, gs;
} cpu_registers_t;

// 2.7.2.g: Control registers
typedef struct {
    uint64_t cr0;            // Control register 0
    uint64_t cr2;            // Page fault linear address
    uint64_t cr3;            // Page table base
    uint64_t cr4;            // Extensions control
    uint64_t cr8;            // Task priority (x86-64)
} control_registers_t;

// 2.7.2.h: Model-specific registers
typedef struct {
    uint32_t msr_id;
    uint64_t value;
    const char *name;
} msr_entry_t;

// 2.7.2.i: CPU modes
typedef enum {
    CPU_MODE_REAL,           // 16-bit
    CPU_MODE_PROTECTED,      // 32-bit
    CPU_MODE_LONG,           // 64-bit
    CPU_MODE_COMPATIBILITY   // 32-bit on 64-bit
} cpu_mode_t;
```

### API

```c
// ============== KERNEL CONCEPTS ==============
// 2.7.1

// 2.7.1.a-c: Mode detection
bool is_kernel_mode(void);
bool is_user_mode(void);
int get_current_privilege_level(void);

// 2.7.1.d-f: Architecture info
const kernel_arch_t *get_kernel_architectures(int *count);
void explain_kernel_type(const char *type);

// 2.7.1.g: Kernel responsibilities
typedef struct {
    bool process_mgmt;
    bool memory_mgmt;
    bool file_systems;
    bool device_drivers;
    bool networking;
    bool security;
} kernel_responsibilities_t;

void get_kernel_responsibilities(kernel_responsibilities_t *resp);

// ============== x86 ARCHITECTURE ==============
// 2.7.2

// 2.7.2.a-e: Register access
int get_cpu_registers(cpu_registers_t *regs);
void print_registers(const cpu_registers_t *regs);

// Individual register access
uint64_t get_rax(void);
uint64_t get_rsp(void);
uint64_t get_rip(void);
uint64_t get_rflags(void);

// 2.7.2.e: RFLAGS bits
typedef struct {
    bool carry;              // CF
    bool zero;               // ZF
    bool sign;               // SF
    bool overflow;           // OF
    bool direction;          // DF
    bool interrupt;          // IF
    uint8_t iopl;            // I/O Privilege Level
} rflags_t;

void parse_rflags(uint64_t rflags, rflags_t *flags);

// 2.7.2.f: Segment registers
uint16_t get_cs(void);
uint16_t get_ds(void);
uint16_t get_ss(void);
void explain_segment_register(uint16_t selector);

// 2.7.2.g: Control registers
int get_control_registers(control_registers_t *cr);
void explain_cr0(uint64_t cr0);
void explain_cr3(uint64_t cr3);
void explain_cr4(uint64_t cr4);

// 2.7.2.h: MSRs
int read_msr(uint32_t msr_id, uint64_t *value);
int write_msr(uint32_t msr_id, uint64_t value);
const msr_entry_t *get_common_msrs(int *count);

// 2.7.2.i: CPU mode detection
cpu_mode_t get_cpu_mode(void);
const char *cpu_mode_string(cpu_mode_t mode);

// ============== SYSTEM INFO ==============

// Get current kernel info
typedef struct {
    char name[64];           // e.g., "Linux"
    char version[64];
    char arch[32];           // e.g., "x86_64"
    const char *type;        // Monolithic, etc.
} kernel_info_t;

int get_kernel_info(kernel_info_t *info);
void print_kernel_info(const kernel_info_t *info);

// CPU info
typedef struct {
    char vendor[32];
    char brand[64];
    uint32_t family, model, stepping;
    uint32_t features[4];    // CPUID features
} cpu_info_t;

int get_cpu_info(cpu_info_t *info);
```

---

## Exemple

```c
#include "kernel_arch.h"

int main(void) {
    // ============== KERNEL CONCEPTS ==============
    // 2.7.1

    printf("=== Kernel Concepts ===\n");

    // 2.7.1.a-c: Mode check
    printf("\nExecution mode:\n");
    printf("  Kernel mode: %s\n", is_kernel_mode() ? "Yes" : "No");
    printf("  User mode: %s\n", is_user_mode() ? "Yes" : "No");
    printf("  CPL (Current Privilege Level): %d\n",
           get_current_privilege_level());

    // 2.7.1.d-f: Kernel architectures
    printf("\n=== Kernel Architectures ===\n");

    int arch_count;
    const kernel_arch_t *archs = get_kernel_architectures(&arch_count);

    for (int i = 0; i < arch_count; i++) {
        printf("\n%s (%s):\n", archs[i].name, archs[i].type);
        printf("  %s\n", archs[i].description);
    }

    /*
    Monolithic (d):
      All OS services in kernel space
      Examples: Linux, BSD, Unix

    Microkernel (e):
      Minimal kernel, services in user space
      Examples: Mach, L4, MINIX, QNX

    Hybrid (f):
      Mix of both approaches
      Examples: Windows NT, macOS (XNU)
    */

    // 2.7.1.g: Responsibilities
    printf("\n=== Kernel Responsibilities (g) ===\n");
    kernel_responsibilities_t resp;
    get_kernel_responsibilities(&resp);
    printf("  Process management: %s\n", resp.process_mgmt ? "Yes" : "No");
    printf("  Memory management: %s\n", resp.memory_mgmt ? "Yes" : "No");
    printf("  File systems: %s\n", resp.file_systems ? "Yes" : "No");
    printf("  Device drivers: %s\n", resp.device_drivers ? "Yes" : "No");

    // 2.7.1.h: Kernel vs OS
    printf("\n=== Kernel vs OS (h) ===\n");
    printf("Kernel: Core component managing hardware\n");
    printf("OS: Kernel + utilities + shell + applications\n");

    // ============== x86 ARCHITECTURE ==============
    // 2.7.2

    printf("\n=== x86-64 Architecture ===\n");

    // 2.7.2.a-d: Registers
    cpu_registers_t regs;
    get_cpu_registers(&regs);

    printf("\n=== General Purpose Registers (a-b) ===\n");
    printf("  RAX: 0x%016lx  RBX: 0x%016lx\n", regs.rax, regs.rbx);
    printf("  RCX: 0x%016lx  RDX: 0x%016lx\n", regs.rcx, regs.rdx);
    printf("  RSI: 0x%016lx  RDI: 0x%016lx\n", regs.rsi, regs.rdi);

    printf("\n=== Stack Registers (c) ===\n");
    printf("  RSP (Stack Pointer): 0x%016lx\n", regs.rsp);
    printf("  RBP (Base Pointer):  0x%016lx\n", regs.rbp);

    printf("\n=== Instruction Pointer (d) ===\n");
    printf("  RIP: 0x%016lx\n", regs.rip);

    // 2.7.2.e: RFLAGS
    printf("\n=== RFLAGS (e) ===\n");
    rflags_t flags;
    parse_rflags(regs.rflags, &flags);
    printf("  RFLAGS: 0x%016lx\n", regs.rflags);
    printf("  CF (Carry):    %d\n", flags.carry);
    printf("  ZF (Zero):     %d\n", flags.zero);
    printf("  SF (Sign):     %d\n", flags.sign);
    printf("  OF (Overflow): %d\n", flags.overflow);
    printf("  IF (Interrupt):%d\n", flags.interrupt);
    printf("  IOPL:          %d\n", flags.iopl);

    // 2.7.2.f: Segment registers
    printf("\n=== Segment Registers (f) ===\n");
    printf("  CS: 0x%04x (Code Segment)\n", regs.cs);
    printf("  DS: 0x%04x (Data Segment)\n", regs.ds);
    printf("  SS: 0x%04x (Stack Segment)\n", regs.ss);
    printf("  ES: 0x%04x (Extra Segment)\n", regs.es);
    printf("  FS: 0x%04x (TLS on Linux)\n", regs.fs);
    printf("  GS: 0x%04x (Kernel data)\n", regs.gs);

    explain_segment_register(regs.cs);
    /*
    Selector 0x33:
      Index: 6
      Table: GDT
      RPL: 3 (user mode)
    */

    // 2.7.2.g: Control registers
    printf("\n=== Control Registers (g) ===\n");
    control_registers_t cr;
    get_control_registers(&cr);

    printf("  CR0: 0x%016lx\n", cr.cr0);
    explain_cr0(cr.cr0);
    /*
    CR0 flags:
      PE (Protection Enable): 1 (protected mode)
      PG (Paging): 1 (paging enabled)
      WP (Write Protect): 1
    */

    printf("  CR3: 0x%016lx (Page Table Base)\n", cr.cr3);
    printf("  CR4: 0x%016lx\n", cr.cr4);
    explain_cr4(cr.cr4);
    /*
    CR4 flags:
      PAE (Physical Address Extension): 1
      PSE (Page Size Extension): 1
      OSXSAVE: 1
    */

    // 2.7.2.h: MSRs
    printf("\n=== Model-Specific Registers (h) ===\n");
    int msr_count;
    const msr_entry_t *msrs = get_common_msrs(&msr_count);
    for (int i = 0; i < msr_count && i < 5; i++) {
        printf("  %s (0x%x): 0x%lx\n",
               msrs[i].name, msrs[i].msr_id, msrs[i].value);
    }
    /*
    Common MSRs:
      IA32_EFER (0xC0000080): Long mode enable
      IA32_STAR (0xC0000081): Syscall segments
      IA32_LSTAR (0xC0000082): Syscall entry
      IA32_FS_BASE (0xC0000100): FS segment base
      IA32_GS_BASE (0xC0000101): GS segment base
    */

    // 2.7.2.i: CPU mode
    printf("\n=== CPU Mode (i) ===\n");
    cpu_mode_t mode = get_cpu_mode();
    printf("  Current mode: %s\n", cpu_mode_string(mode));

    printf("\n  Modes:\n");
    printf("  - Real mode: 16-bit, no protection\n");
    printf("  - Protected mode: 32-bit, segmentation\n");
    printf("  - Long mode: 64-bit, paging required\n");

    // ============== SYSTEM INFO ==============

    printf("\n=== Current Kernel ===\n");
    kernel_info_t kinfo;
    get_kernel_info(&kinfo);
    printf("  Name: %s\n", kinfo.name);
    printf("  Version: %s\n", kinfo.version);
    printf("  Architecture: %s\n", kinfo.arch);
    printf("  Type: %s\n", kinfo.type);

    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_kernel_mode()           // 2.7.1.a-c
#[test] fn test_kernel_types()          // 2.7.1.d-f
#[test] fn test_responsibilities()      // 2.7.1.g
#[test] fn test_registers()             // 2.7.2.a-d
#[test] fn test_rflags()                // 2.7.2.e
#[test] fn test_segments()              // 2.7.2.f
#[test] fn test_control_regs()          // 2.7.2.g
#[test] fn test_msrs()                  // 2.7.2.h
#[test] fn test_cpu_mode()              // 2.7.2.i
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Kernel concepts (2.7.1.a-c) | 20 |
| Kernel types (2.7.1.d-h) | 15 |
| Registers (2.7.2.a-e) | 25 |
| Segments (2.7.2.f) | 15 |
| Control regs & MSRs (2.7.2.g-h) | 15 |
| CPU modes (2.7.2.i) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex00/
├── kernel_arch.h
├── kernel_concepts.c
├── registers.c
├── control_regs.c
├── cpu_mode.c
└── Makefile
```
