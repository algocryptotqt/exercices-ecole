# ex05: Dynamic Linking & PIC

**Module**: 2.6 - ELF, Linking & Loading
**Difficulte**: Difficile
**Duree**: 7h
**Score qualite**: 97/100

## Concepts Couverts

### 2.6.10: Dynamic Linking Concepts (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Dynamic linking | Link at runtime |
| b | Shared library | .so file |
| c | Benefits | Memory sharing, updates |
| d | Costs | Slight runtime overhead |
| e | Position independence | Required for sharing |
| f | Dynamic linker | ld.so, ld-linux.so |
| g | Interpreter | PT_INTERP |
| h | ldd | List dependencies |
| i | Library search | LD_LIBRARY_PATH, /etc/ld.so.conf |
| j | ldconfig | Update cache |

### 2.6.11: Position Independent Code (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | PIC | Code works at any address |
| b | -fPIC | Compiler flag |
| c | PC-relative | Code addressing |
| d | GOT | Global Offset Table |
| e | GOT entries | Pointers to data |
| f | PLT | Procedure Linkage Table |
| g | PLT entries | Indirect jumps |
| h | Lazy binding | Resolve on first call |
| i | %rip-relative | x86-64 addressing |

---

## Sujet

Comprendre le linking dynamique et le code position-independent.

### Structures

```c
#include <elf.h>

// 2.6.10.b: Shared library info
typedef struct {
    char *path;
    char *soname;            // DT_SONAME
    uint64_t base_addr;      // Where loaded
    char **needed;           // DT_NEEDED dependencies
    int needed_count;
    char **symbols;          // Exported symbols
    int symbol_count;
    bool is_pic;             // 2.6.11.a
} shared_lib_t;

// 2.6.10.h: Dependency info (ldd)
typedef struct {
    char *name;              // Library name
    char *path;              // Resolved path
    uint64_t load_addr;      // Load address
    bool found;
} lib_dependency_t;

// 2.6.10.f: Dynamic linker info
typedef struct {
    char *interpreter;       // g: PT_INTERP
    char *search_path;       // i: LD_LIBRARY_PATH
    char **conf_paths;       // /etc/ld.so.conf paths
    int conf_count;
    char *cache_path;        // j: ld.so.cache
} dynlinker_info_t;

// 2.6.11: PIC analysis
typedef struct {
    bool is_pic;             // a: Position independent
    int got_entries;         // d-e: GOT usage
    int plt_entries;         // f-g: PLT usage
    int pc_relative_refs;    // c,i: %rip-relative
    int absolute_refs;       // Non-PIC references
} pic_analysis_t;
```

### API

```c
// ============== SHARED LIBRARY INFO ==============
// 2.6.10.a-b

int so_open(shared_lib_t *lib, const char *path);
void so_close(shared_lib_t *lib);

// Get library info
int so_get_soname(const char *path, char **soname);
int so_get_needed(const char *path, char ***needed, int *count);
int so_get_exported_symbols(const char *path, char ***symbols, int *count);

// 2.6.10.c-d: Compare static vs dynamic
typedef struct {
    size_t static_size;      // Size if statically linked
    size_t dynamic_size;     // Size of executable
    size_t total_loaded;     // Runtime memory
    size_t shared_savings;   // c: Memory shared between processes
} link_comparison_t;

int compare_linking_methods(const char *exec_static, const char *exec_dynamic,
                            link_comparison_t *cmp);

// ============== DYNAMIC LINKER ==============
// 2.6.10.f-j

// 2.6.10.g: Get interpreter from ELF
int elf_get_interpreter(const char *path, char **interp);

// 2.6.10.h: List dependencies (like ldd)
int ldd_list(const char *path, lib_dependency_t **deps, int *count);
void ldd_free(lib_dependency_t *deps, int count);
void ldd_print(const lib_dependency_t *deps, int count);

// 2.6.10.i: Library search
int dynlinker_get_search_paths(char ***paths, int *count);
int dynlinker_resolve_library(const char *name, char **resolved_path);

// 2.6.10.j: Cache info
int ldconfig_read_cache(char ***libs, int *count);
int ldconfig_find_in_cache(const char *name, char **path);

// ============== POSITION INDEPENDENT CODE ==============
// 2.6.11

// 2.6.11.a-b: Check if PIC
bool elf_is_pic(const char *path);
bool elf_check_pic_flag(const char *path);

// 2.6.11.c,i: Analyze addressing modes
int pic_analyze(const char *path, pic_analysis_t *analysis);

// 2.6.11.d-e: GOT analysis
typedef struct {
    uint64_t address;        // GOT entry address
    char *symbol;            // Symbol name
    uint64_t value;          // Current value (if resolved)
    bool is_function;        // For PLT or data
} got_entry_t;

int got_get_entries(const char *path, got_entry_t **entries, int *count);
void got_print(const got_entry_t *entries, int count);

// 2.6.11.f-h: PLT analysis
typedef struct {
    uint64_t plt_addr;       // PLT stub address
    uint64_t got_addr;       // Associated GOT entry
    char *symbol;            // Function name
    bool resolved;           // h: Has been resolved
} plt_entry_t;

int plt_get_entries(const char *path, plt_entry_t **entries, int *count);
void plt_print(const plt_entry_t *entries, int count);

// Explain lazy binding
void plt_explain_lazy_binding(void);

// ============== PIC CODE GENERATION ==============

// Show difference between PIC and non-PIC
void pic_show_code_difference(const char *symbol, bool is_function);

// Disassemble GOT/PLT access
void pic_disasm_got_access(const char *path, const char *symbol);
void pic_disasm_plt_call(const char *path, const char *function);
```

---

## Exemple

```c
#include "dynamic_linker.h"

int main(int argc, char *argv[]) {
    const char *binary = argv[1] ? argv[1] : "/bin/ls";

    // ============== INTERPRETER ==============
    // 2.6.10.f-g

    printf("=== Dynamic Linker ===\n");

    char *interp;
    elf_get_interpreter(binary, &interp);
    printf("Interpreter (PT_INTERP): %s\n", interp);  // g
    // /lib64/ld-linux-x86-64.so.2

    // ============== DEPENDENCIES ==============
    // 2.6.10.h

    printf("\n=== Dependencies (like ldd) ===\n");

    lib_dependency_t *deps;
    int dep_count;
    ldd_list(binary, &deps, &dep_count);
    ldd_print(deps, dep_count);

    /*
    linux-vdso.so.1 => (0x00007ffd...)
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f...)
    /lib64/ld-linux-x86-64.so.2 (0x00007f...)
    */

    // ============== LIBRARY SEARCH ==============
    // 2.6.10.i-j

    printf("\n=== Library Search ===\n");

    // 2.6.10.i: Search paths
    char **paths;
    int path_count;
    dynlinker_get_search_paths(&paths, &path_count);
    printf("Search paths:\n");
    for (int i = 0; i < path_count; i++) {
        printf("  %s\n", paths[i]);
    }
    // LD_LIBRARY_PATH entries, /etc/ld.so.conf, /lib, /usr/lib

    // Resolve library
    char *resolved;
    dynlinker_resolve_library("libc.so.6", &resolved);
    printf("\nlibc.so.6 resolves to: %s\n", resolved);

    // 2.6.10.j: Cache lookup
    char *cached;
    if (ldconfig_find_in_cache("libm.so.6", &cached) == 0) {
        printf("libm.so.6 in cache: %s\n", cached);
    }

    // ============== SHARED LIBRARY INFO ==============
    // 2.6.10.a-b

    printf("\n=== Shared Library Analysis ===\n");

    shared_lib_t lib;
    so_open(&lib, "/lib/x86_64-linux-gnu/libc.so.6");

    printf("Path: %s\n", lib.path);
    printf("SONAME: %s\n", lib.soname);  // b
    printf("Dependencies: %d\n", lib.needed_count);
    printf("Exported symbols: %d\n", lib.symbol_count);

    // ============== STATIC VS DYNAMIC ==============
    // 2.6.10.c-d

    printf("\n=== Static vs Dynamic Comparison ===\n");
    printf("Benefits of dynamic linking (c):\n");
    printf("  - Memory sharing between processes\n");
    printf("  - Smaller executables\n");
    printf("  - Library updates without relinking\n");
    printf("\nCosts (d):\n");
    printf("  - Symbol resolution overhead\n");
    printf("  - PLT/GOT indirection\n");
    printf("  - Startup time for loading\n");

    // ============== PIC ANALYSIS ==============
    // 2.6.11

    printf("\n=== Position Independent Code ===\n");

    // 2.6.11.a-b: Check PIC
    printf("Is PIC: %s\n", elf_is_pic(lib.path) ? "yes" : "no");

    pic_analysis_t pic;
    pic_analyze(lib.path, &pic);
    printf("\nPIC Analysis:\n");
    printf("  GOT entries: %d\n", pic.got_entries);     // d-e
    printf("  PLT entries: %d\n", pic.plt_entries);     // f-g
    printf("  PC-relative refs: %d\n", pic.pc_relative_refs);  // c,i
    printf("  Absolute refs: %d\n", pic.absolute_refs);

    // ============== GOT ==============
    // 2.6.11.d-e

    printf("\n=== Global Offset Table (GOT) ===\n");

    got_entry_t *got;
    int got_count;
    got_get_entries(binary, &got, &got_count);

    printf("GOT entries (first 5):\n");
    for (int i = 0; i < got_count && i < 5; i++) {
        printf("  [%d] %s @ 0x%lx -> 0x%lx\n",
               i, got[i].symbol, got[i].address, got[i].value);
    }

    // ============== PLT ==============
    // 2.6.11.f-h

    printf("\n=== Procedure Linkage Table (PLT) ===\n");

    plt_entry_t *plt;
    int plt_count;
    plt_get_entries(binary, &plt, &plt_count);

    printf("PLT entries:\n");
    for (int i = 0; i < plt_count && i < 5; i++) {
        printf("  %s: PLT @ 0x%lx -> GOT @ 0x%lx %s\n",
               plt[i].symbol, plt[i].plt_addr, plt[i].got_addr,
               plt[i].resolved ? "(resolved)" : "(lazy)");
    }

    // 2.6.11.h: Lazy binding explanation
    printf("\n=== Lazy Binding ===\n");
    plt_explain_lazy_binding();
    /*
    First call to printf():
    1. Jump to PLT[printf]
    2. PLT stub loads GOT[printf] (initially points to PLT stub+6)
    3. Push relocation index, jump to PLT[0]
    4. PLT[0] calls _dl_runtime_resolve
    5. Resolver finds printf, patches GOT[printf]
    6. Jump to actual printf

    Subsequent calls:
    1. Jump to PLT[printf]
    2. PLT stub loads GOT[printf] (now points to real printf)
    3. Direct jump to printf
    */

    // ============== CODE EXAMPLES ==============
    // 2.6.11.c,i

    printf("\n=== PIC vs Non-PIC Code ===\n");

    // Data access
    printf("\nAccessing global variable 'errno':\n");
    pic_show_code_difference("errno", false);
    /*
    Non-PIC (absolute addressing):
      movl errno, %eax          # Direct address

    PIC (GOT-relative, %rip-relative):
      movq errno@GOTPCREL(%rip), %rax  # Load GOT entry address
      movl (%rax), %eax                 # Dereference
    */

    // Function call
    printf("\nCalling external function 'printf':\n");
    pic_show_code_difference("printf", true);
    /*
    Non-PIC:
      call printf               # Direct call

    PIC (through PLT):
      call printf@PLT           # Call through PLT stub
    */

    ldd_free(deps, dep_count);
    so_close(&lib);
    return 0;
}
```

---

## Tests Moulinette

```rust
// Dynamic linking
#[test] fn test_get_interpreter()       // 2.6.10.f-g
#[test] fn test_ldd()                   // 2.6.10.h
#[test] fn test_library_search()        // 2.6.10.i
#[test] fn test_ldconfig_cache()        // 2.6.10.j
#[test] fn test_shared_lib_info()       // 2.6.10.a-b

// PIC
#[test] fn test_is_pic()                // 2.6.11.a-b
#[test] fn test_pc_relative()           // 2.6.11.c,i
#[test] fn test_got_entries()           // 2.6.11.d-e
#[test] fn test_plt_entries()           // 2.6.11.f-g
#[test] fn test_lazy_binding()          // 2.6.11.h
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Dynamic linker (2.6.10.f-j) | 25 |
| Library analysis (2.6.10.a-e) | 20 |
| PIC detection (2.6.11.a-c,i) | 20 |
| GOT analysis (2.6.11.d-e) | 15 |
| PLT analysis (2.6.11.f-h) | 20 |
| **Total** | **100** |

---

## Fichiers

```
ex05/
├── dynamic_linker.h
├── shared_lib.c
├── ldd.c
├── pic.c
├── got.c
├── plt.c
└── Makefile
```
