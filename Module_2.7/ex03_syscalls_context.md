# ex03: System Calls & Context Switching

**Module**: 2.7 - Kernel Development & OS Internals
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.7.7: System Calls (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | System call | Request kernel service |
| b | Software interrupt | int 0x80 (legacy) |
| c | syscall instruction | Fast path (x86-64) |
| d | sysenter/sysexit | Fast path (x86) |
| e | Syscall number | In RAX |
| f | Arguments | In registers |
| g | Return value | In RAX |
| h | Syscall table | Function pointers |
| i | LSTAR MSR | Handler address |

### 2.7.8: Context Switching (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Context | Process state |
| b | Context switch | Save and restore |
| c | What to save | Registers, stack, page table |
| d | Where saved | PCB, kernel stack |
| e | TSS | Task state segment |
| f | switch_to | Linux macro |
| g | Overhead | Time cost |
| h | TLB flush | May be needed |
| i | Lazy FPU | Save FPU state on use |

---

## Sujet

Comprendre les appels systeme et le changement de contexte.

### Structures

```c
#include <stdint.h>

// 2.7.7: System call info
typedef struct {
    int number;              // e: Syscall number
    const char *name;
    int argc;                // Number of arguments
    const char *arg_names[6];
    const char *description;
} syscall_info_t;

// 2.7.7.f: Syscall arguments (x86-64 convention)
typedef struct {
    uint64_t rdi;            // Arg 1
    uint64_t rsi;            // Arg 2
    uint64_t rdx;            // Arg 3
    uint64_t r10;            // Arg 4 (rcx used by syscall)
    uint64_t r8;             // Arg 5
    uint64_t r9;             // Arg 6
} syscall_args_t;

// 2.7.8.a: Process context
typedef struct {
    // General purpose registers
    uint64_t rax, rbx, rcx, rdx;
    uint64_t rsi, rdi, rbp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;

    // Stack pointer
    uint64_t rsp;

    // Instruction pointer
    uint64_t rip;

    // Flags
    uint64_t rflags;

    // Segment registers
    uint16_t cs, ss, ds, es, fs, gs;

    // Page table
    uint64_t cr3;            // h: Page table base

    // FPU state
    bool fpu_used;           // i: Lazy FPU
    uint8_t fpu_state[512];  // FXSAVE area
} process_context_t;

// 2.7.8.d: Task struct (simplified)
typedef struct {
    pid_t pid;
    process_context_t context;
    uint64_t kernel_stack;
    uint64_t user_stack;
    int state;
} task_struct_t;
```

### API

```c
// ============== SYSTEM CALLS ==============
// 2.7.7

// 2.7.7.a: Get syscall info
const syscall_info_t *get_syscall_info(int number);
int get_syscall_by_name(const char *name);
int get_syscall_count(void);

// 2.7.7.b-d: Syscall mechanisms
void explain_int80(void);
void explain_syscall(void);
void explain_sysenter(void);

// 2.7.7.e-g: Make syscall
long do_syscall(int number, ...);
void explain_syscall_convention(void);

// 2.7.7.h: Syscall table
typedef long (*syscall_fn_t)(uint64_t, uint64_t, uint64_t,
                             uint64_t, uint64_t, uint64_t);
syscall_fn_t *get_syscall_table(int *count);
void print_syscall_table(int start, int count);

// 2.7.7.i: MSRs for syscall
uint64_t get_lstar(void);   // Handler address
uint64_t get_star(void);    // Segments
uint64_t get_sfmask(void);  // RFLAGS mask

// Trace syscalls
int trace_syscalls_start(pid_t pid);
int trace_syscalls_stop(pid_t pid);

// ============== CONTEXT SWITCHING ==============
// 2.7.8

// 2.7.8.a-c: Context operations
int context_save(process_context_t *ctx);
int context_restore(const process_context_t *ctx);
void context_print(const process_context_t *ctx);

// 2.7.8.b: Perform context switch
void context_switch(task_struct_t *prev, task_struct_t *next);

// 2.7.8.c: What's saved
void explain_context_contents(void);

// 2.7.8.d: Where context is saved
void explain_context_storage(void);

// 2.7.8.e: TSS role in context switch
void explain_tss_context_switch(void);

// 2.7.8.f: Linux switch_to
void explain_switch_to(void);

// 2.7.8.g: Measure overhead
uint64_t measure_context_switch_overhead(void);
void benchmark_context_switch(int iterations);

// 2.7.8.h: TLB handling
void explain_tlb_flush(void);
bool needs_tlb_flush(task_struct_t *prev, task_struct_t *next);

// 2.7.8.i: Lazy FPU
void explain_lazy_fpu(void);
bool fpu_state_needs_save(void);

// ============== DEMONSTRATION ==============

// Step-by-step syscall demonstration
void demo_syscall_flow(int syscall_num, ...);

// Step-by-step context switch demonstration
void demo_context_switch(void);
```

---

## Exemple

```c
#include "syscalls_context.h"

int main(void) {
    // ============== SYSTEM CALLS ==============
    // 2.7.7

    printf("=== System Calls ===\n");

    // 2.7.7.a: What is a syscall
    printf("\nSystem call (a): Request kernel service\n");
    printf("  - Only way for user code to access kernel\n");
    printf("  - Controlled entry point\n");
    printf("  - Privilege transition (ring 3 -> ring 0)\n");

    // 2.7.7.b: Legacy int 0x80
    printf("\n=== int 0x80 (Legacy) (b) ===\n");
    explain_int80();
    /*
    Software interrupt approach:
      mov eax, 1          ; syscall number (exit)
      mov ebx, 0          ; argument (status)
      int 0x80            ; trigger interrupt

    Slow: Full interrupt handling overhead
    */

    // 2.7.7.c: syscall instruction
    printf("\n=== syscall Instruction (c) ===\n");
    explain_syscall();
    /*
    Fast syscall (x86-64):
      mov rax, 60         ; syscall number (exit)
      mov rdi, 0          ; argument (status)
      syscall             ; fast entry to kernel

    Fast: Optimized path, no interrupt
    Uses MSRs for handler address
    */

    // 2.7.7.d: sysenter/sysexit
    printf("\n=== sysenter/sysexit (d) ===\n");
    explain_sysenter();
    /*
    Intel fast syscall (32-bit):
      Similar to syscall but different MSRs
      SYSENTER_CS_MSR, SYSENTER_EIP_MSR, SYSENTER_ESP_MSR
    */

    // 2.7.7.e-f: Calling convention
    printf("\n=== Syscall Convention (e-f) ===\n");
    explain_syscall_convention();
    /*
    x86-64 Linux:
      RAX: syscall number (e)
      Arguments (f): RDI, RSI, RDX, R10, R8, R9
      Return (g): RAX (-errno on error)

    Example: write(1, "hello", 5)
      RAX = 1 (write)
      RDI = 1 (fd)
      RSI = address of "hello"
      RDX = 5 (count)
      syscall
      ; RAX = 5 or -errno
    */

    // 2.7.7.h: Syscall table
    printf("\n=== Syscall Table (h) ===\n");
    print_syscall_table(0, 10);
    /*
    Nr  | Name      | Args
    ----|-----------|-----
    0   | read      | 3
    1   | write     | 3
    2   | open      | 3
    3   | close     | 1
    4   | stat      | 2
    5   | fstat     | 2
    9   | mmap      | 6
    10  | mprotect  | 3
    ...
    */

    // Get specific syscall info
    const syscall_info_t *write_info = get_syscall_info(1);
    printf("\nwrite syscall:\n");
    printf("  Number: %d\n", write_info->number);
    printf("  Args: fd, buf, count\n");

    // 2.7.7.i: LSTAR MSR
    printf("\n=== LSTAR MSR (i) ===\n");
    printf("LSTAR (0xC0000082): syscall handler address\n");
    printf("  Value: 0x%lx\n", get_lstar());
    printf("\nSTAR (0xC0000081): Segment selectors\n");
    printf("SFMASK: RFLAGS bits to clear\n");

    // ============== CONTEXT SWITCHING ==============
    // 2.7.8

    printf("\n=== Context Switching ===\n");

    // 2.7.8.a: What is context
    printf("\n=== Process Context (a) ===\n");
    printf("Context = complete CPU state for a process:\n");
    printf("  - All registers\n");
    printf("  - Stack pointer\n");
    printf("  - Instruction pointer\n");
    printf("  - Flags\n");
    printf("  - Page table pointer (CR3)\n");

    // 2.7.8.b: Context switch
    printf("\n=== Context Switch (b) ===\n");
    printf("Switch from process A to B:\n");
    printf("  1. Save A's context\n");
    printf("  2. Load B's context\n");
    printf("  3. Resume B's execution\n");

    // 2.7.8.c: What to save
    printf("\n=== What to Save (c) ===\n");
    explain_context_contents();
    /*
    Must save:
      - General purpose registers (RAX-R15)
      - Stack pointer (RSP)
      - Instruction pointer (RIP)
      - Flags (RFLAGS)
      - Segment selectors
      - CR3 (page table)
      - FPU/SSE state (if used)
    */

    // 2.7.8.d: Where saved
    printf("\n=== Where Saved (d) ===\n");
    explain_context_storage();
    /*
    Context stored in:
      - Process Control Block (task_struct in Linux)
      - Kernel stack (partial)

    When syscall/interrupt:
      1. CPU pushes SS, RSP, RFLAGS, CS, RIP to kernel stack
      2. Kernel saves remaining registers
    */

    // 2.7.8.e: TSS role
    printf("\n=== TSS Role (e) ===\n");
    explain_tss_context_switch();
    /*
    TSS provides:
      - Kernel stack pointers (RSP0-2)
      - Interrupt stack table (IST1-7)

    On privilege change:
      CPU loads RSP from TSS.RSP0
    */

    // 2.7.8.f: Linux switch_to
    printf("\n=== Linux switch_to (f) ===\n");
    explain_switch_to();
    /*
    switch_to(prev, next, last):
      1. Save prev's callee-saved registers
      2. Switch stack pointers
      3. Load next's callee-saved registers
      4. Return (to next's saved return address)
    */

    // 2.7.8.g: Overhead
    printf("\n=== Context Switch Overhead (g) ===\n");
    benchmark_context_switch(1000);
    /*
    Context switch cost:
      - Direct: ~1-5 microseconds
      - Indirect: Cache/TLB misses

    Overhead includes:
      - Register save/restore
      - Kernel entry/exit
      - Scheduler decisions
      - Cache pollution
    */

    // 2.7.8.h: TLB flush
    printf("\n=== TLB Handling (h) ===\n");
    explain_tlb_flush();
    /*
    TLB (Translation Lookaside Buffer):
      Caches virtual->physical translations

    On context switch:
      - Different address space -> must flush TLB
      - Same address space -> no flush needed
      - PCID: Tag TLB entries, avoid full flush
    */

    // 2.7.8.i: Lazy FPU
    printf("\n=== Lazy FPU (i) ===\n");
    explain_lazy_fpu();
    /*
    FPU state is large (512+ bytes)
    Lazy saving:
      1. Mark FPU as "not owned" by next process
      2. On FPU use, get #NM exception
      3. Save prev's FPU, load next's
      4. Resume

    Avoids save/restore if process doesn't use FPU
    */

    // ============== DEMONSTRATION ==============

    printf("\n=== Syscall Flow Demo ===\n");
    demo_syscall_flow(1, 1, "Hello\n", 6);  // write(1, "Hello\n", 6)

    printf("\n=== Context Switch Demo ===\n");
    demo_context_switch();

    return 0;
}
```

---

## Tests Moulinette

```rust
// System calls
#[test] fn test_syscall_info()          // 2.7.7.a
#[test] fn test_syscall_mechanisms()    // 2.7.7.b-d
#[test] fn test_syscall_convention()    // 2.7.7.e-g
#[test] fn test_syscall_table()         // 2.7.7.h
#[test] fn test_syscall_msrs()          // 2.7.7.i

// Context switching
#[test] fn test_context_save()          // 2.7.8.a-c
#[test] fn test_context_storage()       // 2.7.8.d
#[test] fn test_tss_role()              // 2.7.8.e
#[test] fn test_overhead()              // 2.7.8.g
#[test] fn test_tlb_flush()             // 2.7.8.h
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Syscall mechanisms (2.7.7.b-d) | 20 |
| Syscall convention (2.7.7.e-g) | 20 |
| Syscall table/MSRs (2.7.7.h-i) | 10 |
| Context contents (2.7.8.a-d) | 20 |
| Context switch (2.7.8.e-f) | 15 |
| Overhead/optimizations (2.7.8.g-i) | 15 |
| **Total** | **100** |

---

## Fichiers

```
ex03/
├── syscalls_context.h
├── syscalls.c
├── context.c
├── switch.c
├── benchmark.c
└── Makefile
```
