# ex07: Memory Safety & Stack Buffer Overflow

**Module**: 2.9 - Computer Security
**Difficulte**: Difficile
**Duree**: 5h
**Score qualite**: 98/100

## Concepts Couverts

### 2.9.15: Memory Safety Vulnerabilities (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Buffer overflow | Write beyond bounds |
| b | Stack overflow | Overwrite return address |
| c | Heap overflow | Corrupt heap metadata |
| d | Integer overflow | Arithmetic wraparound |
| e | Use-after-free | Access freed memory |
| f | Double free | Free same memory twice |
| g | Format string | User-controlled format |
| h | Null pointer dereference | Access null |

### 2.9.16: Stack Buffer Overflow (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Stack layout | Buffer, saved EBP, return address |
| b | Overflow | Write past buffer |
| c | Overwrite return | Control execution |
| d | Shellcode | Injected code |
| e | NOP sled | Landing pad |
| f | Finding offset | Pattern generation |
| g | Practice | Vulnerable programs |

---

## Sujet

Comprendre les vulnerabilites memoire et les attaques de debordement de pile.

### Structures

```c
// Stack frame representation
typedef struct {
    uint64_t local_vars[16];     // Local variables
    uint64_t saved_rbp;          // Previous frame pointer
    uint64_t return_addr;        // Return address
    uint64_t arguments[8];       // Function arguments (x64)
} stack_frame_t;

// Vulnerability info
typedef struct {
    char name[32];
    char description[256];
    char cwe_id[16];
    int severity;               // 1-10
    char example[512];
    char mitigation[256];
} vulnerability_t;

// Exploit payload
typedef struct {
    uint8_t *data;
    size_t length;
    size_t offset_to_ret;
    uint64_t target_addr;
} exploit_payload_t;
```

### API

```c
// Vulnerability demonstration (INTENTIONALLY VULNERABLE)
void vuln_stack_overflow(const char *input);
void vuln_heap_overflow(size_t size, const char *data);
void vuln_format_string(const char *input);
void vuln_use_after_free(void);
void vuln_integer_overflow(int a, int b);

// Analysis tools
void print_stack_layout(void);
size_t find_overflow_offset(const uint8_t *pattern, size_t len);
uint64_t find_return_address(void);

// Pattern generation (for offset finding)
void pattern_create(uint8_t *buf, size_t len);
int pattern_offset(const uint8_t *pattern, size_t len, uint32_t value);

// Shellcode utilities
void print_shellcode_hex(const uint8_t *code, size_t len);
size_t create_nop_sled(uint8_t *buf, size_t len);
```

---

## Exemple

```c
#include "memory_vulnerabilities.h"

int main(void) {
    // 2.9.15: Memory Safety Vulnerabilities
    printf("=== Memory Safety Vulnerabilities ===\n\n");

    printf("Why Memory Safety Matters:\n");
    printf("  ~70%% of security vulnerabilities are memory safety bugs\n");
    printf("  (Microsoft, Google Chrome, Android statistics)\n");
    printf("\n  C/C++ do NOT check bounds automatically\n");
    printf("  Programmer must ensure memory safety\n");

    // Buffer Overflow
    printf("\n\n1. Buffer Overflow:\n");
    printf("   Writing data beyond allocated buffer bounds\n");
    printf("\n   Example:\n");
    printf("   char buf[10];\n");
    printf("   strcpy(buf, user_input);  // No length check!\n");
    printf("   // If user_input > 10 bytes -> OVERFLOW\n");

    printf("\n   Consequences:\n");
    printf("   - Crash (segfault)\n");
    printf("   - Corrupt adjacent data\n");
    printf("   - Overwrite return address -> code execution\n");

    // Stack Overflow
    printf("\n\n2. Stack Buffer Overflow:\n");
    printf("   Buffer overflow on the stack\n");
    printf("   Can overwrite saved return address\n");
    printf("   -> Attacker controls where execution goes!\n");

    // Heap Overflow
    printf("\n\n3. Heap Buffer Overflow:\n");
    printf("   Buffer overflow on the heap\n");
    printf("   Corrupts heap metadata (chunk headers)\n");
    printf("   -> Can lead to arbitrary write primitive\n");
    printf("\n   Example:\n");
    printf("   char *p = malloc(10);\n");
    printf("   memcpy(p, input, input_len);  // No bounds check!\n");

    // Integer Overflow
    printf("\n\n4. Integer Overflow:\n");
    printf("   Arithmetic exceeds integer bounds\n");
    printf("   Signed: Undefined behavior in C\n");
    printf("   Unsigned: Wraps around (defined but dangerous)\n");
    printf("\n   Example:\n");
    printf("   size_t total = count * sizeof(item);  // Can wrap!\n");
    printf("   char *buf = malloc(total);            // Tiny allocation\n");
    printf("   for (i = 0; i < count; i++)           // But big loop\n");
    printf("       buf[i * sizeof(item)] = ...;      // OVERFLOW!\n");

    printf("\n   Classic: count = 0x40000001, sizeof = 4\n");
    printf("           total = 0x100000004 = 4 (truncated to 32-bit)\n");

    // Use-After-Free
    printf("\n\n5. Use-After-Free (UAF):\n");
    printf("   Accessing memory after it's freed\n");
    printf("   Memory may be reallocated for something else\n");
    printf("   -> Type confusion, arbitrary code execution\n");
    printf("\n   Example:\n");
    printf("   char *p = malloc(100);\n");
    printf("   free(p);\n");
    printf("   // ... more code ...\n");
    printf("   char *q = malloc(100);  // May reuse same memory!\n");
    printf("   strcpy(p, 'evil');      // WRITES TO q's MEMORY!\n");

    // Double Free
    printf("\n\n6. Double Free:\n");
    printf("   Freeing the same memory twice\n");
    printf("   Corrupts free list in allocator\n");
    printf("   -> malloc returns same address twice!\n");
    printf("\n   Example:\n");
    printf("   free(p);\n");
    printf("   free(p);  // DOUBLE FREE!\n");
    printf("   char *a = malloc(100);  // Returns old p\n");
    printf("   char *b = malloc(100);  // Also returns old p!\n");
    printf("   // a and b point to same memory\n");

    // Format String
    printf("\n\n7. Format String Vulnerability:\n");
    printf("   User input used as format string\n");
    printf("   Attacker can read/write memory!\n");
    printf("\n   Example:\n");
    printf("   printf(user_input);  // DANGEROUS!\n");
    printf("   // Should be: printf(\"%%s\", user_input);\n");
    printf("\n   Attacks:\n");
    printf("   %%x%%x%%x...  - Leak stack values\n");
    printf("   %%s         - Read string at stack address\n");
    printf("   %%n         - WRITE number of printed chars!\n");

    // Null Pointer Dereference
    printf("\n\n8. Null Pointer Dereference:\n");
    printf("   Accessing memory through NULL pointer\n");
    printf("   Usually crashes (segfault)\n");
    printf("   On some systems: exploitable (map page 0)\n");
    printf("\n   Example:\n");
    printf("   struct obj *p = get_object();  // Returns NULL on error\n");
    printf("   p->method();  // CRASH if p == NULL\n");

    // CWE Classifications
    printf("\n\nCWE Classifications:\n");
    printf("  CWE-119: Buffer Overflow\n");
    printf("  CWE-121: Stack-based Buffer Overflow\n");
    printf("  CWE-122: Heap-based Buffer Overflow\n");
    printf("  CWE-190: Integer Overflow\n");
    printf("  CWE-416: Use After Free\n");
    printf("  CWE-415: Double Free\n");
    printf("  CWE-134: Format String\n");
    printf("  CWE-476: NULL Pointer Dereference\n");

    // 2.9.16: Stack Buffer Overflow
    printf("\n\n=== Stack Buffer Overflow (Detail) ===\n\n");

    // Stack layout
    printf("Stack Layout (x86-64):\n");
    printf("  High addresses\n");
    printf("  +------------------+\n");
    printf("  | Return Address   | <- Saved by CALL instruction\n");
    printf("  +------------------+\n");
    printf("  | Saved RBP        | <- Previous frame pointer\n");
    printf("  +------------------+\n");
    printf("  | Local var N      |\n");
    printf("  | ...              |\n");
    printf("  | Local var 1      |\n");
    printf("  | Buffer[size-1]   | <- Top of buffer\n");
    printf("  | ...              |\n");
    printf("  | Buffer[0]        | <- Start of buffer\n");
    printf("  +------------------+\n");
    printf("  Low addresses (stack grows DOWN)\n");

    // Vulnerable function
    printf("\n\nVulnerable Function Example:\n");
    printf("  void vulnerable(char *input) {\n");
    printf("      char buffer[64];\n");
    printf("      strcpy(buffer, input);  // NO LENGTH CHECK!\n");
    printf("  }\n");
    printf("\n  Stack before overflow:\n");
    printf("  +------------------+\n");
    printf("  | 0x401234 (ret)   | <- Return to caller\n");
    printf("  +------------------+\n");
    printf("  | 0x7fff....(rbp)  | <- Saved frame pointer\n");
    printf("  +------------------+\n");
    printf("  | buffer[56-63]    |\n");
    printf("  | ...              |\n");
    printf("  | buffer[0-7]      |\n");
    printf("  +------------------+\n");

    // Overflow mechanism
    printf("\n\nOverflow Mechanism:\n");
    printf("  If input > 64 bytes:\n");
    printf("  - First 64 bytes fill buffer (OK)\n");
    printf("  - Next 8 bytes overwrite saved RBP\n");
    printf("  - Next 8 bytes overwrite RETURN ADDRESS!\n");
    printf("\n  Payload structure (72+ bytes):\n");
    printf("  [AAAA...64 bytes...][BBBBBBBB][TARGET_ADDR]\n");
    printf("   |                  |          |\n");
    printf("   Buffer             Saved RBP  Return addr\n");

    // Controlling execution
    printf("\n\nControlling Execution:\n");
    printf("  By overwriting return address:\n");
    printf("  - Function returns to OUR chosen address\n");
    printf("  - Execute arbitrary code!\n");
    printf("\n  Classic targets:\n");
    printf("  1. Shellcode in buffer (if executable stack)\n");
    printf("  2. Return to libc function (ret2libc)\n");
    printf("  3. ROP gadgets (modern approach)\n");

    // Shellcode
    printf("\n\nShellcode:\n");
    printf("  Machine code that spawns a shell\n");
    printf("  Injected into buffer, execution redirected there\n");
    printf("\n  Simple Linux x86-64 execve('/bin/sh') shellcode:\n");
    uint8_t shellcode[] = {
        0x48, 0x31, 0xff,                         // xor rdi, rdi
        0x48, 0x31, 0xf6,                         // xor rsi, rsi
        0x48, 0x31, 0xd2,                         // xor rdx, rdx
        0x48, 0xbf, 0x2f, 0x62, 0x69, 0x6e,       // movabs rdi, '/bin/sh'
                    0x2f, 0x73, 0x68, 0x00,
        0x57,                                      // push rdi
        0x48, 0x89, 0xe7,                         // mov rdi, rsp
        0x48, 0x31, 0xc0,                         // xor rax, rax
        0xb0, 0x3b,                               // mov al, 59 (execve)
        0x0f, 0x05                                // syscall
    };
    printf("  ");
    print_shellcode_hex(shellcode, sizeof(shellcode));
    printf("  Length: %zu bytes\n", sizeof(shellcode));

    // NOP sled
    printf("\n\nNOP Sled:\n");
    printf("  Problem: Don't know exact shellcode address\n");
    printf("  Solution: Pad with NOP instructions (0x90)\n");
    printf("\n  [NOP NOP NOP ... NOP][SHELLCODE][ADDR]\n");
    printf("   |                     |\n");
    printf("   Landing anywhere      Actual payload\n");
    printf("   here works!\n");
    printf("\n  If return addr lands in NOP sled:\n");
    printf("  - CPU slides through NOPs\n");
    printf("  - Eventually executes shellcode\n");

    // Finding offset
    printf("\n\nFinding Offset to Return Address:\n");
    printf("  Method 1: Calculate from disassembly\n");
    printf("    buffer size + saved RBP = offset\n");
    printf("    64 + 8 = 72 bytes\n");

    printf("\n  Method 2: Pattern generation\n");
    printf("    1. Create unique pattern:\n");
    printf("       Aa0Aa1Aa2...Ba0Ba1...\n");
    printf("    2. Send as input, crash program\n");
    printf("    3. Check value at crash (EIP/RIP)\n");
    printf("    4. Find that value in pattern\n");
    printf("    5. Position = offset!\n");

    // Pattern demo
    uint8_t pattern[100];
    pattern_create(pattern, 100);
    printf("\n  Pattern (first 50 bytes): ");
    for (int i = 0; i < 50; i++) printf("%c", pattern[i]);
    printf("...\n");

    // Exploit construction
    printf("\n\nConstructing an Exploit:\n");
    printf("  1. Find vulnerable function (code review/fuzzing)\n");
    printf("  2. Determine buffer size and offset to return\n");
    printf("  3. Find address to return to:\n");
    printf("     - Address of shellcode in buffer\n");
    printf("     - Or address of useful function/gadget\n");
    printf("  4. Construct payload:\n");
    printf("     [NOP sled][Shellcode][Padding][Return addr]\n");
    printf("  5. Test and adjust\n");

    printf("\n  Example payload structure:\n");
    printf("  +--------+----------+-------+---------------+\n");
    printf("  | NOPs   | Shellcode| Pad   | 0xbffff100    |\n");
    printf("  | (30)   | (27)     | (7)   | (8 bytes)     |\n");
    printf("  +--------+----------+-------+---------------+\n");
    printf("  |<------ 64 bytes -------->|  8  |    8     |\n");
    printf("                              RBP   Return\n");

    // Practice warning
    printf("\n\nPractice Safely:\n");
    printf("  Use intentionally vulnerable programs:\n");
    printf("  - Protostar/Phoenix (exploit.education)\n");
    printf("  - DVWA (Damn Vulnerable Web App)\n");
    printf("  - OverTheWire wargames\n");
    printf("  - CTF challenges\n");
    printf("\n  NEVER exploit real systems without permission!\n");
    printf("  This is a federal crime under CFAA.\n");

    // Mitigations
    printf("\n\nModern Mitigations:\n");
    printf("  Stack Canaries: Random value before return addr\n");
    printf("  ASLR: Randomize stack/heap/library addresses\n");
    printf("  DEP/NX: Mark stack non-executable\n");
    printf("  PIE: Randomize executable base address\n");
    printf("  FORTIFY_SOURCE: Replace unsafe functions\n");
    printf("\n  -> Classic stack overflow is largely mitigated\n");
    printf("  -> But ROP and heap exploits bypass many protections\n");

    return 0;
}

// Intentionally vulnerable for demonstration
// NEVER write code like this!
void vuln_stack_overflow(const char *input) {
    char buffer[64];
    strcpy(buffer, input);  // VULNERABLE!
    printf("Buffer contains: %s\n", buffer);
}
```

---

## Fichiers

```
ex07/
├── memory_vulnerabilities.h
├── vulnerabilities.c
├── stack_overflow.c
├── pattern.c
├── shellcode.c
└── Makefile
```
