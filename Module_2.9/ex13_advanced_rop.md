# ex13: Advanced ROP Techniques

**Module**: 2.9 - Computer Security
**Difficulte**: Expert
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.9.24: ret2libc (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Concept | Return to libc function |
| b | No gadgets needed | Direct function call |
| c | 32-bit | Arguments on stack |
| d | 64-bit | Arguments in registers |
| e | Need gadgets | To set registers |
| f | Leak libc base | Mandatory with ASLR |
| g | GOT leak | Read GOT entry |
| h | Calculate addresses | Base + offset |

### 2.9.25: Advanced ROP Techniques (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Stack pivot | Change RSP |
| b | xchg rax, rsp | Pivot gadget |
| c | leave; ret | Another pivot |
| d | Heap spray | Control heap layout |
| e | JOP | Jump-oriented programming |
| f | Dispatcher gadget | Central control |
| g | SROP | Sigreturn-oriented |
| h | sigreturn | Restore all registers |
| i | Fake sigframe | Control everything |

---

## Sujet

Maitriser les techniques avancees de ROP: ret2libc, stack pivot et SROP.

### API

```c
// ret2libc
rop_chain_t *build_ret2libc_32bit(uint64_t system, uint64_t exit, uint64_t binsh);
rop_chain_t *build_ret2libc_64bit(uint64_t libc_base);
uint64_t leak_got_entry(void *binary, const char *func);

// Stack pivot
void demonstrate_stack_pivot(void);
rop_chain_t *build_pivot_chain(uint64_t new_stack, rop_chain_t *real_chain);
uint64_t find_leave_ret(void *binary);
uint64_t find_xchg_rax_rsp(void *binary);

// SROP
typedef struct sigcontext_64 sigframe_t;
sigframe_t *create_fake_sigframe(void);
void sigframe_set_rip(sigframe_t *frame, uint64_t rip);
void sigframe_set_rsp(sigframe_t *frame, uint64_t rsp);
rop_chain_t *build_srop_execve(uint64_t binsh_addr);
```

---

## Exemple

```c
#include "advanced_rop.h"

int main(void) {
    // ret2libc
    printf("=== ret2libc ===\n\n");

    printf("Concept:\n");
    printf("  Instead of gadgets, return directly to libc functions\n");
    printf("  system(), execve(), mprotect(), etc.\n");
    printf("  Simpler than full ROP chains\n");

    // 32-bit ret2libc
    printf("\n\n32-bit ret2libc:\n");
    printf("  Arguments passed on STACK (cdecl)\n");
    printf("  Function expects: [ret_addr][arg1][arg2]...\n");

    printf("\n  Stack layout for system('/bin/sh'):\n");
    printf("  +------------------+\n");
    printf("  | system()         | <- Return to system\n");
    printf("  +------------------+\n");
    printf("  | exit()           | <- Return address for system\n");
    printf("  +------------------+\n");
    printf("  | '/bin/sh' addr   | <- Argument to system\n");
    printf("  +------------------+\n");

    printf("\n  Why exit()?\n");
    printf("    - Clean termination after shell\n");
    printf("    - Or can be anything (shell takes over)\n");

    // 64-bit ret2libc
    printf("\n\n64-bit ret2libc:\n");
    printf("  Arguments in REGISTERS (System V AMD64)\n");
    printf("  RDI, RSI, RDX, RCX, R8, R9, then stack\n");
    printf("  -> Need gadgets to set registers!\n");

    printf("\n  This is just ROP with libc functions:\n");
    printf("  +------------------+\n");
    printf("  | pop rdi; ret     | <- Gadget\n");
    printf("  +------------------+\n");
    printf("  | '/bin/sh' addr   | <- Loaded into RDI\n");
    printf("  +------------------+\n");
    printf("  | ret              | <- Stack alignment (16-byte)\n");
    printf("  +------------------+\n");
    printf("  | system()         | <- Call system\n");
    printf("  +------------------+\n");

    printf("\n  Stack alignment note:\n");
    printf("    x86-64 requires 16-byte stack alignment\n");
    printf("    system() may crash without alignment\n");
    printf("    Extra 'ret' gadget fixes alignment\n");

    // Leaking libc
    printf("\n\nLeaking Libc Base:\n");
    printf("  With ASLR, must leak address at runtime\n");
    printf("\n  GOT leak technique:\n");
    printf("    1. Overflow to call puts(GOT[puts])\n");
    printf("    2. Output = runtime puts() address\n");
    printf("    3. libc_base = output - puts_offset_in_libc\n");
    printf("    4. Now calculate any libc address!\n");

    printf("\n  Finding offsets:\n");
    printf("    $ readelf -s libc.so.6 | grep puts\n");
    printf("      (shows offset within libc)\n");
    printf("    Or: libc.symbols['puts'] in pwntools\n");

    // Stack Pivot
    printf("\n\n=== Stack Pivot ===\n\n");

    printf("Why Pivot?\n");
    printf("  - Limited overflow space on stack\n");
    printf("  - ROP chain too long to fit\n");
    printf("  - Need more controlled space\n");
    printf("\n  Solution: Move RSP to controlled memory\n");
    printf("    Heap, BSS, large input buffer\n");
    printf("    Then execute ROP chain from there\n");

    printf("\n\nPivot Gadgets:\n");

    printf("\n  1. leave; ret\n");
    printf("     leave = mov rsp, rbp; pop rbp\n");
    printf("     If we control RBP, we control RSP!\n");
    printf("\n     Attack:\n");
    printf("     - Overflow to set saved RBP = (target - 8)\n");
    printf("     - Overflow return addr = leave; ret\n");
    printf("     - Function epilogue: leave (RSP = old RBP)\n");
    printf("     - Our leave: RSP = (target - 8) + 8 = target\n");
    printf("     - ret: RIP = *target (our chain starts)\n");

    printf("\n  2. xchg REG, rsp; ret\n");
    printf("     Swaps REG with RSP\n");
    printf("     If REG points to controlled memory -> pivot!\n");
    printf("\n     Common: xchg rax, rsp after controlled rax\n");

    printf("\n  3. mov rsp, REG; ret\n");
    printf("     Directly set RSP from controlled register\n");

    printf("\n  4. pop rsp; ret\n");
    printf("     Load RSP from stack (if we control next value)\n");

    // Pivot example
    printf("\n\nStack Pivot Example:\n");
    printf("  Scenario:\n");
    printf("    - 64-byte overflow (not enough for full chain)\n");
    printf("    - But we have 0x1000 bytes in .bss\n");
    printf("\n  Strategy:\n");
    printf("    1. Stage 1: Small chain to pivot to .bss\n");
    printf("    2. Write full chain to .bss (via read/gets)\n");
    printf("    3. Pivot executes full chain\n");

    printf("\n  Stage 1 (fits in overflow):\n");
    printf("  +------------------+\n");
    printf("  | pop rdi; ret     |\n");
    printf("  | 0 (stdin)        |\n");
    printf("  | pop rsi; ret     |\n");
    printf("  | .bss addr        |\n");
    printf("  | pop rdx; ret     |\n");
    printf("  | 0x1000           |\n");
    printf("  | read@plt         | <- Read chain to .bss\n");
    printf("  | pop rsp; ret     |\n");
    printf("  | .bss addr        | <- PIVOT to .bss!\n");
    printf("  +------------------+\n");

    // JOP
    printf("\n\n=== JOP (Jump-Oriented Programming) ===\n\n");

    printf("Concept:\n");
    printf("  Use indirect jumps instead of returns\n");
    printf("  jmp [reg], jmp [mem], call [reg]\n");
    printf("  Bypasses some ROP detection\n");

    printf("\n  Dispatcher Gadget:\n");
    printf("  Central 'hub' that dispatches to other gadgets\n");
    printf("  add rax, 8; jmp [rax]\n");
    printf("\n  Functional gadgets end with:\n");
    printf("  jmp [rax]  <- returns to dispatcher\n");
    printf("\n  Table in memory:\n");
    printf("  [gadget1][gadget2][gadget3]...\n");
    printf("   ^rax moves through this table\n");

    printf("\n  More complex than ROP, similar power\n");

    // SROP
    printf("\n\n=== SROP (Sigreturn-Oriented Programming) ===\n\n");

    printf("Concept:\n");
    printf("  Abuse sigreturn syscall\n");
    printf("  sigreturn restores ALL registers from stack frame\n");
    printf("  Craft fake signal frame -> control everything!\n");

    printf("\n  Signal Handling:\n");
    printf("  1. Signal arrives\n");
    printf("  2. Kernel saves registers to stack (sigframe)\n");
    printf("  3. Signal handler runs\n");
    printf("  4. Handler returns, sigreturn called\n");
    printf("  5. sigreturn restores registers from sigframe\n");
    printf("  6. Original execution continues\n");

    printf("\n  Attack:\n");
    printf("  1. Create fake sigframe on stack\n");
    printf("  2. Set all registers as desired:\n");
    printf("     RAX = 59 (execve syscall)\n");
    printf("     RDI = '/bin/sh' address\n");
    printf("     RSI = 0, RDX = 0\n");
    printf("     RIP = syscall gadget\n");
    printf("     RSP = safe stack\n");
    printf("  3. Call sigreturn (syscall 15)\n");
    printf("  4. Kernel restores our fake values\n");
    printf("  5. Execution resumes at 'syscall' -> execve!\n");

    printf("\n  Sigframe structure (x86-64, ~300 bytes):\n");
    printf("  struct sigcontext {\n");
    printf("      uint64_t r8, r9, r10, r11;\n");
    printf("      uint64_t r12, r13, r14, r15;\n");
    printf("      uint64_t rdi, rsi, rbp, rbx;\n");
    printf("      uint64_t rdx, rax, rcx, rsp;\n");
    printf("      uint64_t rip, eflags;\n");
    printf("      uint64_t cs, gs, fs, ss;  // segments\n");
    printf("      // ... more fields\n");
    printf("  };\n");

    printf("\n  Minimal SROP chain:\n");
    printf("  +------------------+\n");
    printf("  | pop rax; ret     |\n");
    printf("  | 15 (rt_sigreturn)|\n");
    printf("  | syscall; ret     | <- Triggers sigreturn\n");
    printf("  +------------------+\n");
    printf("  | FAKE SIGFRAME    | <- ~300 bytes\n");
    printf("  | (RIP = syscall)  |\n");
    printf("  | (RAX = 59)       |\n");
    printf("  | (RDI = /bin/sh)  |\n");
    printf("  | (RSI, RDX = 0)   |\n");
    printf("  +------------------+\n");

    printf("\n  SROP Advantages:\n");
    printf("  - Only need: pop rax, syscall gadgets\n");
    printf("  - Control ALL registers\n");
    printf("  - Larger payload, but simpler gadget reqs\n");

    // pwntools SROP
    printf("\n\nSROP with pwntools:\n");
    printf("  from pwn import *\n");
    printf("  \n");
    printf("  frame = SigreturnFrame()\n");
    printf("  frame.rax = constants.SYS_execve\n");
    printf("  frame.rdi = binsh_addr\n");
    printf("  frame.rsi = 0\n");
    printf("  frame.rdx = 0\n");
    printf("  frame.rip = syscall_ret\n");
    printf("  frame.rsp = safe_stack\n");
    printf("  \n");
    printf("  payload = b'A' * offset\n");
    printf("  payload += p64(pop_rax)\n");
    printf("  payload += p64(15)  # rt_sigreturn\n");
    printf("  payload += p64(syscall_ret)\n");
    printf("  payload += bytes(frame)\n");

    // Summary
    printf("\n\nTechnique Summary:\n");
    printf("  +---------------+------------------+----------------+\n");
    printf("  | Technique     | When to Use      | Complexity     |\n");
    printf("  +---------------+------------------+----------------+\n");
    printf("  | ret2libc      | Simple calls     | Low            |\n");
    printf("  | Basic ROP     | General purpose  | Medium         |\n");
    printf("  | Stack Pivot   | Limited overflow | Medium         |\n");
    printf("  | JOP           | ROP detected     | High           |\n");
    printf("  | SROP          | Few gadgets      | Medium         |\n");
    printf("  +---------------+------------------+----------------+\n");

    return 0;
}
```

---

## Fichiers

```
ex13/
├── advanced_rop.h
├── ret2libc.c
├── stack_pivot.c
├── jop.c
├── srop.c
└── Makefile
```
