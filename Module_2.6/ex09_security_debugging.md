# ex09: ELF Security & Debugging Tools

**Module**: 2.6 - ELF, Linking & Loading
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.6.18: Security Features (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | ASLR | Address randomization |
| b | PIE | Position Independent Executable |
| c | RELRO | Read-only relocations |
| d | Partial RELRO | .got writable |
| e | Full RELRO | .got.plt read-only |
| f | Stack canary | Buffer overflow protection |
| g | NX | No-execute stack |
| h | checksec | Verify protections |
| i | -z relro | Linker flag |
| j | -z now | Eager binding |

### 2.6.19: Debugging Tools (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | readelf | ELF structure |
| b | objdump | Disassembly |
| c | nm | Symbols |
| d | ldd | Dependencies |
| e | ltrace | Library calls |
| f | strace | System calls |
| g | file | File type |
| h | strings | Printable strings |
| i | objcopy | Modify ELF |
| j | strip | Remove symbols |

---

## Sujet

Analyser les protections de securite ELF et maitriser les outils de debugging.

### Structures

```c
// 2.6.18: Security check result
typedef struct {
    bool has_pie;            // b: PIE enabled
    bool has_relro;          // c: RELRO
    bool full_relro;         // e: Full RELRO
    bool has_canary;         // f: Stack canary
    bool has_nx;             // g: NX bit
    bool has_fortify;        // FORTIFY_SOURCE
    bool has_runpath;        // RUNPATH set
    bool has_rpath;          // Deprecated RPATH
    char *interpreter;       // Dynamic linker
} security_info_t;

// 2.6.18.a: ASLR info
typedef struct {
    bool enabled;
    int randomize_level;     // 0, 1, or 2
    uint64_t stack_offset;
    uint64_t mmap_offset;
    uint64_t executable_offset;
} aslr_info_t;

// 2.6.19: Tool output
typedef struct {
    char *tool_name;
    char *command;
    char *output;
    int exit_code;
} tool_result_t;
```

### API

```c
// ============== SECURITY ANALYSIS ==============
// 2.6.18

// 2.6.18.h: checksec equivalent
int security_check(const char *path, security_info_t *info);
void security_print(const security_info_t *info);

// 2.6.18.a: ASLR
int aslr_get_status(aslr_info_t *info);
void aslr_demonstrate(void);

// 2.6.18.b: PIE detection
bool elf_is_pie(const char *path);

// 2.6.18.c-e: RELRO detection
typedef enum {
    RELRO_NONE,
    RELRO_PARTIAL,           // d
    RELRO_FULL               // e
} relro_type_t;

relro_type_t elf_get_relro(const char *path);
const char *relro_type_string(relro_type_t type);

// 2.6.18.f: Stack canary detection
bool elf_has_stack_canary(const char *path);

// 2.6.18.g: NX detection
bool elf_has_nx(const char *path);

// 2.6.18.i-j: Compilation flags
void security_print_compile_flags(void);

// ============== DEBUGGING TOOLS ==============
// 2.6.19

// 2.6.19.a: readelf wrapper
int tool_readelf(const char *path, const char *options, tool_result_t *result);
int readelf_header(const char *path, char **output);
int readelf_sections(const char *path, char **output);
int readelf_symbols(const char *path, char **output);
int readelf_dynamic(const char *path, char **output);
int readelf_relocations(const char *path, char **output);

// 2.6.19.b: objdump wrapper
int tool_objdump(const char *path, const char *options, tool_result_t *result);
int objdump_disassemble(const char *path, const char *section, char **output);
int objdump_headers(const char *path, char **output);

// 2.6.19.c: nm wrapper
int tool_nm(const char *path, const char *options, tool_result_t *result);
int nm_list_symbols(const char *path, char **output);
int nm_undefined(const char *path, char ***symbols, int *count);
int nm_defined(const char *path, char ***symbols, int *count);

// 2.6.19.d: ldd wrapper
int tool_ldd(const char *path, tool_result_t *result);
int ldd_dependencies(const char *path, char ***deps, int *count);

// 2.6.19.e: ltrace
int tool_ltrace(const char *program, char **argv, tool_result_t *result);
int ltrace_functions(const char *program, char ***functions, int *count);

// 2.6.19.f: strace
int tool_strace(const char *program, char **argv, tool_result_t *result);
int strace_syscalls(const char *program, char ***syscalls, int *count);

// 2.6.19.g: file
int tool_file(const char *path, tool_result_t *result);
int file_get_type(const char *path, char **type);

// 2.6.19.h: strings
int tool_strings(const char *path, tool_result_t *result);
int strings_extract(const char *path, int min_len, char ***strings, int *count);
int strings_search(const char *path, const char *pattern,
                   char ***matches, int *count);

// 2.6.19.i: objcopy
int tool_objcopy(const char *input, const char *output, const char *options);
int objcopy_add_section(const char *elf, const char *section,
                        const char *data_file, const char *output);
int objcopy_remove_section(const char *input, const char *section,
                           const char *output);

// 2.6.19.j: strip
int tool_strip(const char *path, const char *options);
int strip_all(const char *path, const char *output);
int strip_debug(const char *path, const char *output);

// Free result
void tool_result_free(tool_result_t *result);

// ============== COMBINED ANALYSIS ==============

// Full binary analysis
typedef struct {
    security_info_t security;
    char **dependencies;
    int dep_count;
    char **symbols;
    int sym_count;
    char **strings;
    int str_count;
    char *file_type;
} binary_analysis_t;

int analyze_binary(const char *path, binary_analysis_t *analysis);
void analysis_free(binary_analysis_t *analysis);
void analysis_print(const binary_analysis_t *analysis);
```

---

## Exemple

```c
#include "security_debug.h"

int main(int argc, char *argv[]) {
    const char *binary = argv[1] ? argv[1] : "/bin/ls";

    // ============== SECURITY ANALYSIS ==============
    // 2.6.18

    printf("=== Security Analysis (checksec) ===\n");

    // 2.6.18.h: checksec equivalent
    security_info_t sec;
    security_check(binary, &sec);
    security_print(&sec);
    /*
    RELRO:       Full RELRO
    Stack Canary: Enabled
    NX:          Enabled
    PIE:         Enabled
    RUNPATH:     No
    RPATH:       No
    */

    // 2.6.18.a: ASLR
    printf("\n=== ASLR Status (a) ===\n");
    aslr_info_t aslr;
    aslr_get_status(&aslr);
    printf("ASLR: %s (level %d)\n",
           aslr.enabled ? "Enabled" : "Disabled",
           aslr.randomize_level);

    aslr_demonstrate();
    /*
    Running same program multiple times:
      Run 1: stack=0x7ffd1234..., libc=0x7f8a5678...
      Run 2: stack=0x7ffc9876..., libc=0x7f8b1234...
      Run 3: stack=0x7ffe5432..., libc=0x7f8c9999...
    Addresses randomized each time!
    */

    // 2.6.18.b: PIE
    printf("\n=== PIE Detection (b) ===\n");
    printf("PIE: %s\n", elf_is_pie(binary) ? "Yes" : "No");
    printf("PIE allows executable base randomization\n");

    // 2.6.18.c-e: RELRO
    printf("\n=== RELRO Detection (c-e) ===\n");
    relro_type_t relro = elf_get_relro(binary);
    printf("RELRO: %s\n", relro_type_string(relro));

    printf("\nRELRO levels:\n");
    printf("  None: GOT fully writable (vulnerable)\n");
    printf("  Partial (d): .got read-only, .got.plt writable\n");
    printf("  Full (e): All GOT sections read-only\n");

    // 2.6.18.f: Stack canary
    printf("\n=== Stack Canary (f) ===\n");
    printf("Stack canary: %s\n",
           elf_has_stack_canary(binary) ? "Enabled" : "Disabled");
    printf("Protects against buffer overflow attacks\n");

    // 2.6.18.g: NX
    printf("\n=== NX Bit (g) ===\n");
    printf("NX: %s\n", elf_has_nx(binary) ? "Enabled" : "Disabled");
    printf("Prevents code execution on stack/heap\n");

    // 2.6.18.i-j: Compilation flags
    printf("\n=== Compilation Flags (i-j) ===\n");
    security_print_compile_flags();
    /*
    For maximum security, compile with:
      -fPIE -pie              # PIE (b)
      -Wl,-z,relro            # Partial RELRO (c,d,i)
      -Wl,-z,now              # Full RELRO (e,j)
      -fstack-protector-strong # Stack canary (f)
      -D_FORTIFY_SOURCE=2     # Fortified functions
      -Wl,-z,noexecstack      # NX stack (g)
    */

    // ============== DEBUGGING TOOLS ==============
    // 2.6.19

    printf("\n=== Debugging Tools ===\n");

    tool_result_t result;

    // 2.6.19.a: readelf
    printf("\n--- readelf (a) ---\n");
    tool_readelf(binary, "-h", &result);  // Header
    printf("readelf -h:\n%s\n", result.output);
    tool_result_free(&result);

    char *sections;
    readelf_sections(binary, &sections);
    printf("Section count from readelf -S\n");

    // 2.6.19.b: objdump
    printf("\n--- objdump (b) ---\n");
    char *disasm;
    objdump_disassemble(binary, ".text", &disasm);
    printf("Disassembly (first 500 chars):\n%.500s...\n", disasm);

    // 2.6.19.c: nm
    printf("\n--- nm (c) ---\n");
    char **undefined;
    int undef_count;
    nm_undefined(binary, &undefined, &undef_count);
    printf("Undefined symbols: %d\n", undef_count);
    for (int i = 0; i < undef_count && i < 5; i++) {
        printf("  U %s\n", undefined[i]);
    }

    // 2.6.19.d: ldd
    printf("\n--- ldd (d) ---\n");
    char **deps;
    int dep_count;
    ldd_dependencies(binary, &deps, &dep_count);
    printf("Dependencies: %d\n", dep_count);
    for (int i = 0; i < dep_count; i++) {
        printf("  %s\n", deps[i]);
    }

    // 2.6.19.e: ltrace
    printf("\n--- ltrace (e) ---\n");
    printf("ltrace traces library calls:\n");
    printf("  $ ltrace ./program\n");
    printf("  malloc(128) = 0x...\n");
    printf("  printf(\"Hello\") = 5\n");
    printf("  free(0x...)\n");

    // 2.6.19.f: strace
    printf("\n--- strace (f) ---\n");
    printf("strace traces system calls:\n");
    printf("  $ strace ./program\n");
    printf("  execve(\"./program\", ...) = 0\n");
    printf("  brk(NULL) = 0x...\n");
    printf("  openat(AT_FDCWD, \"/lib/...\") = 3\n");
    printf("  write(1, \"Hello\", 5) = 5\n");

    // 2.6.19.g: file
    printf("\n--- file (g) ---\n");
    tool_file(binary, &result);
    printf("file %s:\n%s\n", binary, result.output);
    tool_result_free(&result);

    // 2.6.19.h: strings
    printf("\n--- strings (h) ---\n");
    char **strs;
    int str_count;
    strings_extract(binary, 8, &strs, &str_count);
    printf("Strings (min 8 chars): %d found\n", str_count);
    for (int i = 0; i < str_count && i < 5; i++) {
        printf("  %s\n", strs[i]);
    }

    // 2.6.19.i: objcopy
    printf("\n--- objcopy (i) ---\n");
    printf("objcopy can:\n");
    printf("  - Add sections:    objcopy --add-section .data=file elf\n");
    printf("  - Remove sections: objcopy --remove-section .note elf\n");
    printf("  - Convert format:  objcopy -O binary elf raw.bin\n");

    // 2.6.19.j: strip
    printf("\n--- strip (j) ---\n");
    printf("strip removes symbols for smaller binaries:\n");
    printf("  strip --strip-all binary     # Remove all symbols\n");
    printf("  strip --strip-debug binary   # Remove debug only\n");

    // ============== COMBINED ANALYSIS ==============

    printf("\n=== Full Binary Analysis ===\n");
    binary_analysis_t analysis;
    analyze_binary(binary, &analysis);
    analysis_print(&analysis);

    analysis_free(&analysis);
    return 0;
}
```

---

## Tests Moulinette

```rust
// Security
#[test] fn test_checksec()              // 2.6.18.h
#[test] fn test_aslr()                  // 2.6.18.a
#[test] fn test_pie_detection()         // 2.6.18.b
#[test] fn test_relro_detection()       // 2.6.18.c-e
#[test] fn test_canary_detection()      // 2.6.18.f
#[test] fn test_nx_detection()          // 2.6.18.g

// Tools
#[test] fn test_readelf()               // 2.6.19.a
#[test] fn test_objdump()               // 2.6.19.b
#[test] fn test_nm()                    // 2.6.19.c
#[test] fn test_ldd()                   // 2.6.19.d
#[test] fn test_file()                  // 2.6.19.g
#[test] fn test_strings()               // 2.6.19.h
#[test] fn test_strip()                 // 2.6.19.j
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Security detection (2.6.18.a-h) | 35 |
| Compile flags (2.6.18.i-j) | 10 |
| ELF tools (2.6.19.a-d) | 25 |
| Tracing tools (2.6.19.e-f) | 10 |
| Utility tools (2.6.19.g-j) | 20 |
| **Total** | **100** |

---

## Fichiers

```
ex09/
├── security_debug.h
├── security_check.c
├── aslr.c
├── tool_wrappers.c
├── analysis.c
└── Makefile
```
