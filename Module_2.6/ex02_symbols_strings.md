# ex02: Symbol & String Tables

**Module**: 2.6 - ELF, Linking & Loading
**Difficulte**: Moyen
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.6.5: Symbol Tables (12 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Symbol | Named entity |
| b | .symtab | Full symbol table |
| c | .dynsym | Dynamic symbols only |
| d | Symbol entry | Name, value, size, type, binding |
| e | STT_FUNC | Function |
| f | STT_OBJECT | Data object |
| g | STT_SECTION | Section |
| h | STB_LOCAL | Not visible outside |
| i | STB_GLOBAL | Visible, can be used |
| j | STB_WEAK | Can be overridden |
| k | nm | View symbols |
| l | objdump -t | View symbol table |

### 2.6.6: String Tables (6 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | .strtab | Symbol names |
| b | .dynstr | Dynamic symbol names |
| c | .shstrtab | Section names |
| d | Null-terminated | Strings end with 0 |
| e | Offset | Index into table |
| f | First byte | Null (offset 0 = empty) |

---

## Sujet

Parser et manipuler les tables de symboles et de chaines d'un fichier ELF.

### Structures

```c
#include <elf.h>

// 2.6.5.a-d: Symbol wrapper
typedef struct {
    char *name;              // From string table
    uint64_t value;          // Symbol value (address)
    uint64_t size;           // Symbol size
    uint8_t type;            // e-g: STT_*
    uint8_t binding;         // h-j: STB_*
    uint8_t visibility;      // STV_*
    uint16_t shndx;          // Section index
    bool is_defined;         // Not UND
} elf_symbol_t;

// 2.6.6: String table
typedef struct {
    char *data;              // Raw string data
    size_t size;             // Table size
    const char *section_name; // .strtab, .dynstr, .shstrtab
} elf_strtab_t;

// Symbol filter options
typedef struct {
    bool include_local;      // h: Include STB_LOCAL
    bool include_global;     // i: Include STB_GLOBAL
    bool include_weak;       // j: Include STB_WEAK
    bool include_undefined;  // Include UND symbols
    bool only_functions;     // e: Only STT_FUNC
    bool only_objects;       // f: Only STT_OBJECT
    const char *name_filter; // Substring match
} symbol_filter_t;
```

### API

```c
// ============== SYMBOL TABLE ==============
// 2.6.5

// 2.6.5.b: Get all symbols from .symtab
int elf_get_symbols(elf_file_t *elf, elf_symbol_t **symbols, int *count);

// 2.6.5.c: Get dynamic symbols from .dynsym
int elf_get_dynamic_symbols(elf_file_t *elf, elf_symbol_t **symbols, int *count);

void elf_free_symbols(elf_symbol_t *symbols, int count);

// Find symbol by name
elf_symbol_t *elf_find_symbol(elf_file_t *elf, const char *name);

// Filter symbols
int elf_filter_symbols(elf_symbol_t *symbols, int count,
                       const symbol_filter_t *filter,
                       elf_symbol_t **filtered, int *fcount);

// 2.6.5.e-g: Type strings
const char *elf_symbol_type_string(uint8_t type);

// 2.6.5.h-j: Binding strings
const char *elf_symbol_binding_string(uint8_t binding);

// Visibility string
const char *elf_symbol_visibility_string(uint8_t vis);

// 2.6.5.k-l: Display like nm/objdump
void elf_print_symbols(elf_file_t *elf, bool use_nm_format);
void elf_print_symbol(const elf_symbol_t *sym, bool nm_format);

// ============== STRING TABLE ==============
// 2.6.6

// Get string table
int elf_get_strtab(elf_file_t *elf, elf_strtab_t *strtab);

// 2.6.6.a: Get symbol string table
int elf_get_symbol_strtab(elf_file_t *elf, elf_strtab_t *strtab);

// 2.6.6.b: Get dynamic string table
int elf_get_dynstr(elf_file_t *elf, elf_strtab_t *strtab);

// 2.6.6.c: Get section header string table
int elf_get_shstrtab(elf_file_t *elf, elf_strtab_t *strtab);

// 2.6.6.d-f: Get string at offset
const char *elf_strtab_get(const elf_strtab_t *strtab, size_t offset);

// Dump string table
void elf_print_strtab(const elf_strtab_t *strtab);

// ============== ANALYSIS ==============

// Count symbols by type/binding
typedef struct {
    int total;
    int functions;           // e: STT_FUNC
    int objects;             // f: STT_OBJECT
    int sections;            // g: STT_SECTION
    int local;               // h: STB_LOCAL
    int global;              // i: STB_GLOBAL
    int weak;                // j: STB_WEAK
    int undefined;           // UND
    int defined;
} symbol_stats_t;

void elf_symbol_stats(elf_symbol_t *symbols, int count, symbol_stats_t *stats);
```

---

## Exemple

```c
#include "elf_parser.h"

int main(int argc, char *argv[]) {
    elf_file_t elf;
    elf_open(&elf, argv[1]);

    // ============== SYMBOL TABLE ==============
    // 2.6.5

    printf("=== Symbol Table (.symtab) ===\n");

    elf_symbol_t *symbols;
    int count;

    // 2.6.5.b: Get all symbols
    elf_get_symbols(&elf, &symbols, &count);
    printf("Total symbols: %d\n\n", count);

    // 2.6.5.k: Print like nm
    printf("nm-style output:\n");
    elf_print_symbols(&elf, true);

    /*
    0000000000001060 T main
    0000000000004000 D global_var
    0000000000004010 B bss_var
                     U printf
    0000000000001120 t helper_func
    0000000000004008 d local_var
    ...
    */

    // 2.6.5.l: Print like objdump -t
    printf("\nobjdump-style output:\n");
    elf_print_symbols(&elf, false);

    /*
    SYMBOL TABLE:
    0000000000000000 l    df *ABS*  0000000000000000 main.c
    0000000000001060 g     F .text  0000000000000042 main
    0000000000004000 g     O .data  0000000000000004 global_var
    0000000000000000       F *UND*  0000000000000000 printf
    ...
    */

    // Filter: only global functions
    symbol_filter_t filter = {
        .include_global = true,
        .only_functions = true,
    };
    elf_symbol_t *funcs;
    int func_count;
    elf_filter_symbols(symbols, count, &filter, &funcs, &func_count);

    printf("\nGlobal functions (%d):\n", func_count);
    for (int i = 0; i < func_count; i++) {
        printf("  %s @ 0x%lx\n", funcs[i].name, funcs[i].value);
    }

    // Find specific symbol
    elf_symbol_t *main_sym = elf_find_symbol(&elf, "main");
    if (main_sym) {
        printf("\nFound 'main':\n");
        printf("  Address: 0x%lx\n", main_sym->value);
        printf("  Size: %lu bytes\n", main_sym->size);
        printf("  Type: %s\n", elf_symbol_type_string(main_sym->type));
        printf("  Binding: %s\n", elf_symbol_binding_string(main_sym->binding));
    }

    // Statistics
    symbol_stats_t stats;
    elf_symbol_stats(symbols, count, &stats);
    printf("\nSymbol Statistics:\n");
    printf("  Functions: %d\n", stats.functions);
    printf("  Objects: %d\n", stats.objects);
    printf("  Local: %d\n", stats.local);
    printf("  Global: %d\n", stats.global);
    printf("  Weak: %d\n", stats.weak);
    printf("  Undefined: %d\n", stats.undefined);

    // ============== STRING TABLE ==============
    // 2.6.6

    printf("\n=== String Tables ===\n");

    // 2.6.6.a: Symbol string table
    elf_strtab_t strtab;
    elf_get_symbol_strtab(&elf, &strtab);
    printf("\n.strtab (size: %zu bytes):\n", strtab.size);

    // 2.6.6.d-e: Get string at offset
    printf("  String at offset 0: '%s'\n", elf_strtab_get(&strtab, 0));  // f: empty
    printf("  String at offset 1: '%s'\n", elf_strtab_get(&strtab, 1));  // First string

    // 2.6.6.c: Section header string table
    elf_strtab_t shstrtab;
    elf_get_shstrtab(&elf, &shstrtab);
    printf("\n.shstrtab section names:\n");
    elf_print_strtab(&shstrtab);

    // 2.6.6.b: Dynamic string table (if exists)
    elf_strtab_t dynstr;
    if (elf_get_dynstr(&elf, &dynstr) == 0) {
        printf("\n.dynstr (size: %zu bytes):\n", dynstr.size);
    }

    // 2.6.5.c: Dynamic symbols
    elf_symbol_t *dynsyms;
    int dyncount;
    if (elf_get_dynamic_symbols(&elf, &dynsyms, &dyncount) == 0) {
        printf("\n=== Dynamic Symbols (.dynsym) ===\n");
        printf("Count: %d\n", dyncount);
        for (int i = 0; i < dyncount && i < 10; i++) {
            printf("  %s\n", dynsyms[i].name);
        }
        elf_free_symbols(dynsyms, dyncount);
    }

    elf_free_symbols(symbols, count);
    free(funcs);
    elf_close(&elf);
    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_symbol_parse()          // 2.6.5.a-d
#[test] fn test_symbol_types()          // 2.6.5.e-g
#[test] fn test_symbol_binding()        // 2.6.5.h-j
#[test] fn test_nm_output()             // 2.6.5.k
#[test] fn test_objdump_output()        // 2.6.5.l
#[test] fn test_symtab()                // 2.6.5.b
#[test] fn test_dynsym()                // 2.6.5.c
#[test] fn test_strtab()                // 2.6.6.a
#[test] fn test_dynstr()                // 2.6.6.b
#[test] fn test_shstrtab()              // 2.6.6.c
#[test] fn test_string_offset()         // 2.6.6.d-f
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Symbol parsing (2.6.5.a-d) | 25 |
| Symbol types/binding (2.6.5.e-j) | 20 |
| nm/objdump output (2.6.5.k-l) | 15 |
| String tables (2.6.6.a-c) | 25 |
| String access (2.6.6.d-f) | 15 |
| **Total** | **100** |

---

## Fichiers

```
ex02/
├── elf_parser.h
├── symbols.c
├── strtab.c
├── display.c
└── Makefile
```
