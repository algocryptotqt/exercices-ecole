# ex11: Protection Mechanisms

**Module**: 2.9 - Computer Security
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 97/100

## Concepts Couverts

### 2.9.21: Protection Mechanisms (12 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Stack canary | Detect overflow |
| b | Canary types | Random, terminator |
| c | ASLR | Address randomization |
| d | ASLR targets | Stack, heap, libraries, executable |
| e | PIE | Position Independent Executable |
| f | DEP/NX | Non-executable memory |
| g | W^X | Write XOR Execute |
| h | RELRO | Relocation Read-Only |
| i | Partial RELRO | Some sections read-only |
| j | Full RELRO | GOT read-only |
| k | FORTIFY_SOURCE | Runtime checks |
| l | checksec | View protections |

---

## Sujet

Comprendre les mecanismes de protection contre l'exploitation memoire.

### Structures

```c
// Security flags
typedef struct {
    bool canary;
    bool pie;
    bool nx;
    bool relro_partial;
    bool relro_full;
    bool fortify;
    int aslr_level;         // 0=off, 1=libs, 2=full
} security_flags_t;

// Memory region permissions
typedef struct {
    uint64_t start;
    uint64_t end;
    bool read;
    bool write;
    bool execute;
    char name[64];
} memory_region_t;
```

### API

```c
// Check protections
security_flags_t check_binary_security(const char *binary);
void print_security_flags(const security_flags_t *flags);

// Memory map analysis
void dump_memory_map(pid_t pid);
memory_region_t *get_region(pid_t pid, const char *name);

// ASLR demonstration
void compare_addresses_across_runs(void);
uint64_t get_stack_base(void);
uint64_t get_libc_base(void);
uint64_t get_heap_base(void);

// Canary operations
uint64_t read_canary(void);
void demonstrate_canary_bypass(void);
```

---

## Exemple

```c
#include "protection_mechanisms.h"

int main(void) {
    printf("=== Protection Mechanisms ===\n\n");

    printf("Modern binary protections defend against exploitation:\n");
    printf("  Each mechanism targets specific attack vectors\n");
    printf("  Defense in depth: Multiple layers\n");

    // Stack Canary
    printf("\n\n=== Stack Canary ===\n\n");

    printf("Purpose: Detect stack buffer overflow before return\n");
    printf("\n  Concept:\n");
    printf("  - Random value placed between buffer and return addr\n");
    printf("  - Checked before function returns\n");
    printf("  - If modified -> overflow detected -> abort\n");

    printf("\n  Stack layout with canary:\n");
    printf("  +------------------+\n");
    printf("  | Return Address   |\n");
    printf("  +------------------+\n");
    printf("  | Saved RBP        |\n");
    printf("  +------------------+\n");
    printf("  | STACK CANARY     | <- Random value\n");
    printf("  +------------------+\n");
    printf("  | Local variables  |\n");
    printf("  | Buffer           |\n");
    printf("  +------------------+\n");

    printf("\n  Canary types:\n");
    printf("  1. Random canary: 8 bytes from /dev/urandom\n");
    printf("  2. Terminator canary: 0x00 0x0d 0x0a 0xff...\n");
    printf("     Includes string terminators (null, CR, LF)\n");
    printf("     Stops string-based overflows\n");

    printf("\n  GCC implementation:\n");
    printf("  - Stored at fs:0x28 (x86-64) or gs:0x14 (x86)\n");
    printf("  - __stack_chk_fail() called on mismatch\n");
    printf("  - Enabled: -fstack-protector, -fstack-protector-all\n");

    // Canary demo
    printf("\n  Current canary: 0x%lx\n", read_canary());

    printf("\n  Bypasses:\n");
    printf("  - Leak canary (format string, info leak)\n");
    printf("  - Overwrite specific return addr (non-linear overflow)\n");
    printf("  - Brute force (32-bit, forking servers)\n");

    // ASLR
    printf("\n\n=== ASLR (Address Space Layout Randomization) ===\n\n");

    printf("Purpose: Randomize memory addresses each execution\n");
    printf("  Attacker can't hardcode addresses in exploit\n");

    printf("\n  ASLR levels (/proc/sys/kernel/randomize_va_space):\n");
    printf("  0 = Disabled (no randomization)\n");
    printf("  1 = Stack, VDSO, mmap (libraries) randomized\n");
    printf("  2 = Full (+ heap, brk randomized)\n");

    printf("\n  What's randomized (64-bit):\n");
    printf("  Stack:   ~28 bits entropy -> 2^28 possibilities\n");
    printf("  mmap:    ~28 bits entropy\n");
    printf("  Heap:    ~13 bits entropy (less!)\n");
    printf("  PIE exe: ~28 bits entropy (if PIE enabled)\n");

    // ASLR demo
    printf("\n  Current addresses (this run):\n");
    printf("    Stack:  0x%lx\n", get_stack_base());
    printf("    Heap:   0x%lx\n", get_heap_base());
    printf("    Libc:   0x%lx\n", get_libc_base());

    printf("\n  Bypasses:\n");
    printf("  - Information leak (format string, buffer over-read)\n");
    printf("  - Brute force (32-bit: only 8-16 bits entropy)\n");
    printf("  - Partial overwrite (lower bits deterministic)\n");
    printf("  - ROP (addresses relative to leaked base)\n");

    // PIE
    printf("\n\n=== PIE (Position Independent Executable) ===\n\n");

    printf("Purpose: Allow executable itself to be randomized\n");
    printf("  Without PIE, .text section at fixed address\n");
    printf("  With PIE, base address randomized by ASLR\n");

    printf("\n  Compilation:\n");
    printf("  gcc -pie -fPIE program.c\n");

    printf("\n  Impact:\n");
    printf("  - Can't use ROP gadgets from main binary\n");
    printf("  - Need leak to find gadgets\n");
    printf("  - Slight performance overhead (~1-5%%)\n");

    // DEP/NX
    printf("\n\n=== DEP/NX (Data Execution Prevention) ===\n\n");

    printf("Purpose: Mark memory regions non-executable\n");
    printf("  Stack and heap are NOT executable\n");
    printf("  Can't run injected shellcode directly\n");

    printf("\n  Hardware support:\n");
    printf("  - x86: NX bit (No-eXecute) in page table\n");
    printf("  - ARM: XN bit (eXecute Never)\n");
    printf("  - CPU enforces: Execute from NX page -> fault\n");

    printf("\n  W^X (Write XOR Execute):\n");
    printf("  - Memory is writable OR executable, never both\n");
    printf("  - Prevents runtime code modification attacks\n");
    printf("  - JIT compilers need special handling\n");

    printf("\n  Bypasses:\n");
    printf("  - ROP: Reuse existing code (doesn't execute data)\n");
    printf("  - ret2libc: Call library functions\n");
    printf("  - mprotect(): Change permissions at runtime\n");

    // RELRO
    printf("\n\n=== RELRO (Relocation Read-Only) ===\n\n");

    printf("Purpose: Protect GOT (Global Offset Table) from writes\n");
    printf("  GOT contains function pointers resolved at runtime\n");
    printf("  Prime target for attackers (overwrite -> control flow)\n");

    printf("\n  Partial RELRO (gcc default):\n");
    printf("  - .init_array, .fini_array, .dynamic read-only\n");
    printf("  - GOT still WRITABLE (for lazy binding)\n");
    printf("  - GOT overwrite attacks still work\n");

    printf("\n  Full RELRO (-Wl,-z,relro,-z,now):\n");
    printf("  - ALL relocations resolved at load time\n");
    printf("  - GOT marked READ-ONLY after init\n");
    printf("  - GOT overwrite attacks blocked!\n");
    printf("  - Slower startup (resolve all symbols)\n");

    printf("\n  Comparison:\n");
    printf("  +-------------+-------------+-------------+\n");
    printf("  | Feature     | Partial     | Full        |\n");
    printf("  +-------------+-------------+-------------+\n");
    printf("  | GOT         | Writable    | Read-only   |\n");
    printf("  | Lazy bind   | Yes         | No          |\n");
    printf("  | Startup     | Fast        | Slower      |\n");
    printf("  | GOT attack  | Possible    | Blocked     |\n");
    printf("  +-------------+-------------+-------------+\n");

    // FORTIFY_SOURCE
    printf("\n\n=== FORTIFY_SOURCE ===\n\n");

    printf("Purpose: Compile-time and runtime buffer overflow checks\n");
    printf("  Replaces unsafe functions with checking versions\n");

    printf("\n  Levels:\n");
    printf("  -D_FORTIFY_SOURCE=1: Checks when size known at compile\n");
    printf("  -D_FORTIFY_SOURCE=2: Additional runtime checks\n");
    printf("  -D_FORTIFY_SOURCE=3: Even more checks (GCC 12+)\n");

    printf("\n  Protected functions:\n");
    printf("  memcpy, memmove, memset, strcpy, strncpy, strcat,\n");
    printf("  strncat, sprintf, snprintf, vsprintf, vsnprintf,\n");
    printf("  gets (removed), read, recv, ...\n");

    printf("\n  How it works:\n");
    printf("  strcpy(dst, src) becomes:\n");
    printf("  __strcpy_chk(dst, src, __builtin_object_size(dst))\n");
    printf("  If copy exceeds object size -> abort!\n");

    printf("\n  Limitations:\n");
    printf("  - Only when compiler knows buffer size\n");
    printf("  - Dynamic allocations often not protected\n");
    printf("  - Can be bypassed with calculated sizes\n");

    // checksec
    printf("\n\n=== Using checksec ===\n\n");

    printf("checksec: Tool to view binary protections\n");
    printf("  $ checksec --file=/path/to/binary\n");
    printf("\n  Example output:\n");
    printf("  RELRO           STACK CANARY      NX            PIE\n");
    printf("  Full RELRO      Canary found      NX enabled    PIE enabled\n");
    printf("\n  Also shows: RPATH, RUNPATH, Symbols, FORTIFY\n");

    // Check current binary
    printf("\n  Checking this binary:\n");
    security_flags_t flags = check_binary_security("/proc/self/exe");
    print_security_flags(&flags);

    // Summary
    printf("\n\n=== Protection Summary ===\n\n");

    printf("  +---------------+---------------------+------------------+\n");
    printf("  | Protection    | Blocks              | Bypass           |\n");
    printf("  +---------------+---------------------+------------------+\n");
    printf("  | Canary        | Stack overflow      | Leak, brute      |\n");
    printf("  | ASLR          | Fixed addresses     | Leak, brute      |\n");
    printf("  | PIE           | Fixed exe addrs     | Leak             |\n");
    printf("  | NX            | Code injection      | ROP, ret2libc    |\n");
    printf("  | Full RELRO    | GOT overwrite       | Other targets    |\n");
    printf("  | FORTIFY       | Obvious overflows   | Dynamic sizes    |\n");
    printf("  +---------------+---------------------+------------------+\n");

    printf("\n  Modern exploit typically needs:\n");
    printf("    1. Information leak (bypass ASLR/PIE/canary)\n");
    printf("    2. ROP chain (bypass NX)\n");
    printf("    3. Arbitrary write target (bypass Full RELRO)\n");

    return 0;
}
```

---

## Fichiers

```
ex11/
├── protection_mechanisms.h
├── canary.c
├── aslr.c
├── relro.c
├── fortify.c
├── checksec.c
└── Makefile
```
