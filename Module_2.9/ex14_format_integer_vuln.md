# ex14: Format String & Integer Vulnerabilities

**Module**: 2.9 - Computer Security
**Difficulte**: Difficile
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.9.26: Format String Attacks (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Vulnerability | printf(user_input) |
| b | %x | Leak stack |
| c | %s | Read string at address |
| d | %n | Write to address |
| e | Direct parameter | %7$x |
| f | Write arbitrary | Build value with %n |
| g | Write-what-where | Full control |
| h | GOT overwrite | Redirect function |

### 2.9.27: Integer Vulnerabilities (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Integer overflow | Exceeds max value |
| b | Signed overflow | Undefined behavior |
| c | Unsigned wraparound | Defined but dangerous |
| d | Truncation | Large to small |
| e | Sign extension | Signed to larger |
| f | Width conversion | Different sizes |
| g | Allocation size | n * sizeof overflow |
| h | Safe math | Check before operation |

---

## Sujet

Comprendre et exploiter les vulnerabilites de format string et d'entiers.

### API

```c
// Format string exploitation
void demonstrate_format_string_leak(void);
void demonstrate_format_string_write(void);
uint64_t format_string_read_address(const char *fmt, uint64_t addr);
void format_string_write_value(uint64_t addr, uint32_t value);

// Integer vulnerability demonstration
void demonstrate_integer_overflow(void);
void demonstrate_allocation_overflow(void);
bool safe_multiply(size_t a, size_t b, size_t *result);
bool safe_add(size_t a, size_t b, size_t *result);
```

---

## Exemple

```c
#include "format_integer_vuln.h"

int main(void) {
    // Format String Attacks
    printf("=== Format String Vulnerabilities ===\n\n");

    printf("Vulnerability: printf(user_input)\n");
    printf("  User input interpreted as format string!\n");
    printf("  Should be: printf(\"%%s\", user_input)\n");

    printf("\n  Vulnerable:\n");
    printf("    char buf[100];\n");
    printf("    gets(buf);\n");
    printf("    printf(buf);  // DANGEROUS!\n");

    // Stack leak
    printf("\n\n=== Reading Stack (%%x, %%p) ===\n\n");

    printf("Format specifiers without arguments:\n");
    printf("  printf reads from stack as if args were there\n");

    printf("\n  Example: printf('%%x %%x %%x %%x')\n");
    printf("  Output: ");
    // Demonstrate (intentionally vulnerable)
    printf("%x %x %x %x\n", 1, 2, 3, 4);  // Safe demo with args
    printf("  Leaks 4 values from stack!\n");

    printf("\n  %%p - Pointer format (includes 0x prefix)\n");
    printf("  %%lx - 64-bit hex (long)\n");

    // Direct parameter access
    printf("\n\n=== Direct Parameter Access (%%n$) ===\n\n");

    printf("Access specific argument position:\n");
    printf("  %%7$x = 7th argument as hex\n");
    printf("  %%15$lx = 15th argument as 64-bit hex\n");

    printf("\n  Useful for:\n");
    printf("  - Skipping to interesting stack positions\n");
    printf("  - Accessing arguments repeatedly\n");

    printf("\n  Example: printf('%%6$p') might leak:\n");
    printf("  - Return address\n");
    printf("  - Saved rbp\n");
    printf("  - Canary value!\n");

    // Reading memory
    printf("\n\n=== Reading Arbitrary Memory (%%s) ===\n\n");

    printf("%%s treats argument as pointer, prints string\n");
    printf("  If we can put address on stack, %%s reads it!\n");

    printf("\n  Attack:\n");
    printf("  1. Put target address in input\n");
    printf("  2. Find its stack position (say, 7th arg)\n");
    printf("  3. Use %%7$s to read string at that address\n");

    printf("\n  Payload: [target_addr][%%7$s]\n");
    printf("  printf reads our address, treats as string ptr\n");
    printf("  -> Leak arbitrary memory contents!\n");

    // Writing memory with %n
    printf("\n\n=== Writing Memory (%%n) ===\n\n");

    printf("%%n: Writes number of chars printed so far\n");
    printf("  Writes to address given as argument!\n");

    printf("\n  Example:\n");
    printf("    int count;\n");
    printf("    printf('Hello%%n', &count);\n");
    printf("    // count = 5 (length of 'Hello')\n");

    printf("\n  Attack:\n");
    printf("  1. Put target address on stack\n");
    printf("  2. Control number of chars printed\n");
    printf("  3. %%n writes that count to target!\n");

    printf("\n  Variants:\n");
    printf("  %%n  - writes int (4 bytes)\n");
    printf("  %%hn - writes short (2 bytes)\n");
    printf("  %%hhn - writes char (1 byte)\n");
    printf("  %%ln - writes long (8 bytes)\n");

    // Building arbitrary values
    printf("\n\n=== Writing Arbitrary Values ===\n\n");

    printf("Control printed count:\n");
    printf("  %%10x   = print 10 chars (padded)\n");
    printf("  %%100x  = print 100 chars\n");
    printf("  %%1000x = print 1000 chars\n");

    printf("\n  To write 0x41414141 to 0x601040:\n");
    printf("  Need to print 0x41414141 = 1094795585 chars!\n");
    printf("  Payload: [0x601040][%%1094795585x%%7$n]\n");
    printf("  (Very slow, prints millions of spaces)\n");

    printf("\n  Optimization: Write byte-by-byte with %%hhn\n");
    printf("  addr+0: write 0x41 (65 chars)\n");
    printf("  addr+1: write 0x41 (65 chars, but counter continues)\n");
    printf("  addr+2: write 0x41\n");
    printf("  addr+3: write 0x41\n");

    // GOT overwrite
    printf("\n\n=== GOT Overwrite ===\n\n");

    printf("Target: GOT entry of library function\n");
    printf("  GOT[puts] -> actual puts() address\n");
    printf("  Overwrite with system() -> puts('ls') = system('ls')!\n");

    printf("\n  Attack:\n");
    printf("  1. Leak libc address (%%p to leak GOT entry)\n");
    printf("  2. Calculate system() address\n");
    printf("  3. Format string write system to GOT[puts]\n");
    printf("  4. Next puts() call executes system()!\n");

    printf("\n  pwntools fmtstr_payload:\n");
    printf("    payload = fmtstr_payload(offset, {got_puts: system})\n");
    printf("    Automatically builds format string!\n");

    // Integer Vulnerabilities
    printf("\n\n=== Integer Vulnerabilities ===\n\n");

    // Integer overflow
    printf("Integer Overflow:\n");
    printf("  Value exceeds type's maximum\n");

    printf("\n  Signed (undefined behavior in C):\n");
    printf("    int a = INT_MAX;  // 2147483647\n");
    printf("    a = a + 1;        // UNDEFINED!\n");
    printf("    Compiler may assume this never happens\n");
    printf("    Optimizations can remove overflow checks\n");

    printf("\n  Unsigned (wraps around):\n");
    printf("    unsigned int a = UINT_MAX;  // 4294967295\n");
    printf("    a = a + 1;                   // 0 (defined!)\n");
    printf("    Still dangerous for security!\n");

    // Allocation overflow
    printf("\n\nAllocation Overflow (Critical!):\n");
    printf("  size_t total = count * element_size;\n");
    printf("  char *buf = malloc(total);\n");

    printf("\n  If count * element_size overflows:\n");
    printf("    count = 0x40000001 (1073741825)\n");
    printf("    element_size = 4\n");
    printf("    total = 0x100000004 = 4 (32-bit truncation!)\n");
    printf("\n  malloc(4) but loop writes count * 4 bytes!\n");
    printf("  -> Massive heap buffer overflow!\n");

    // Real example
    printf("\n  Real vulnerability pattern:\n");
    printf("    // User controls n\n");
    printf("    struct item *arr = malloc(n * sizeof(struct item));\n");
    printf("    for (int i = 0; i < n; i++) {\n");
    printf("        read_item(&arr[i]);  // Writes past allocation!\n");
    printf("    }\n");

    // Truncation
    printf("\n\nTruncation:\n");
    printf("  Assigning larger type to smaller:\n");
    printf("    size_t big = 0x100000010;\n");
    printf("    unsigned int small = big;  // 0x10!\n");

    printf("\n  Dangerous in length checks:\n");
    printf("    size_t len = get_user_length();\n");
    printf("    if ((unsigned short)len > MAX) return;\n");
    printf("    memcpy(buf, src, len);  // Original len used!\n");

    // Sign extension
    printf("\n\nSign Extension:\n");
    printf("  Signed value extended to larger type:\n");
    printf("    char c = -1;              // 0xFF\n");
    printf("    int i = c;                // 0xFFFFFFFF (-1)\n");
    printf("    unsigned int u = c;       // 0xFFFFFFFF (huge!)\n");

    printf("\n  Attack vector:\n");
    printf("    char len = read_byte();   // Attacker sends 0xFF\n");
    printf("    if (len > 100) return;    // -1 > 100? No!\n");
    printf("    char buf[100];\n");
    printf("    memcpy(buf, data, len);   // len as size_t = huge!\n");

    // Safe math
    printf("\n\n=== Safe Integer Operations ===\n\n");

    printf("Always check before operation:\n");

    printf("\n  Safe multiply:\n");
    printf("    if (b != 0 && a > SIZE_MAX / b) {\n");
    printf("        // Would overflow!\n");
    printf("        return ERROR;\n");
    printf("    }\n");
    printf("    result = a * b;\n");

    printf("\n  Safe add:\n");
    printf("    if (a > SIZE_MAX - b) {\n");
    printf("        // Would overflow!\n");
    printf("        return ERROR;\n");
    printf("    }\n");
    printf("    result = a + b;\n");

    printf("\n  GCC/Clang builtins:\n");
    printf("    if (__builtin_mul_overflow(a, b, &result)) {\n");
    printf("        // Overflow!\n");
    printf("    }\n");

    printf("\n  Safe allocation:\n");
    printf("    if (count > SIZE_MAX / sizeof(item)) {\n");
    printf("        return NULL;\n");
    printf("    }\n");
    printf("    return malloc(count * sizeof(item));\n");

    // Summary
    printf("\n\nVulnerability Summary:\n");
    printf("  +------------------+------------------------+\n");
    printf("  | Vulnerability    | Impact                 |\n");
    printf("  +------------------+------------------------+\n");
    printf("  | Format %%x/%%p    | Info leak (stack)      |\n");
    printf("  | Format %%s        | Arbitrary read         |\n");
    printf("  | Format %%n        | Arbitrary write        |\n");
    printf("  | Integer overflow | Buffer overflow        |\n");
    printf("  | Truncation       | Check bypass           |\n");
    printf("  | Sign extension   | Length manipulation    |\n");
    printf("  +------------------+------------------------+\n");

    return 0;
}
```

---

## Fichiers

```
ex14/
├── format_integer_vuln.h
├── format_string.c
├── format_write.c
├── integer_overflow.c
├── safe_math.c
└── Makefile
```
