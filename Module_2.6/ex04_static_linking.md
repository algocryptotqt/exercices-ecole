# ex04: Static Linking & Linker Scripts

**Module**: 2.6 - ELF, Linking & Loading
**Difficulte**: Difficile
**Duree**: 7h
**Score qualite**: 97/100

## Concepts Couverts

### 2.6.8: Static Linking (11 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Static linking | Combine at link time |
| b | Linker | ld, collect2 |
| c | Symbol resolution | Find definitions |
| d | Strong vs weak | Resolution rules |
| e | Duplicate symbols | Error or use one |
| f | Relocation | Fix addresses |
| g | Static library | Archive (.a) |
| h | ar | Create archive |
| i | Archive extraction | Only needed objects |
| j | Link order | Matters for archives |
| k | -static | Force static linking |

### 2.6.9: Linker Scripts (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Linker script | Control layout |
| b | ENTRY | Entry point |
| c | MEMORY | Define regions |
| d | SECTIONS | Section placement |
| e | . | Location counter |
| f | OUTPUT_FORMAT | Output type |
| g | PROVIDE | Define symbol |
| h | Default script | ld --verbose |
| i | Custom script | -T script.ld |
| j | Embedded use | Memory layout control |

---

## Sujet

Comprendre le linking statique et ecrire des scripts de linker.

### Structures

```c
#include <elf.h>

// 2.6.8.c-d: Symbol resolution
typedef struct {
    char *name;
    uint64_t value;
    bool is_strong;          // d: Strong symbol
    bool is_weak;            // d: Weak symbol
    bool is_defined;
    char *source_file;       // Which object file
    char *section;
} link_symbol_t;

// 2.6.8.g: Static library
typedef struct {
    char *path;
    int object_count;
    char **object_names;     // Members
    link_symbol_t *symbols;  // Exported symbols
    int symbol_count;
} static_library_t;

// 2.6.9: Linker script memory region
typedef struct {
    char *name;              // e.g., "ROM", "RAM"
    uint64_t origin;         // Start address
    uint64_t length;         // Size
    char *attributes;        // rx, rwx, etc.
} memory_region_t;

// Linker script section mapping
typedef struct {
    char *output_section;    // e.g., ".text"
    char **input_sections;   // Input patterns
    int input_count;
    char *memory_region;     // Where to place
    uint64_t vma;            // Virtual address
    uint64_t lma;            // Load address
    uint64_t align;
} section_mapping_t;

// Parsed linker script
typedef struct {
    char *entry_point;       // b: ENTRY
    char *output_format;     // f: OUTPUT_FORMAT
    memory_region_t *regions;// c: MEMORY
    int region_count;
    section_mapping_t *sections; // d: SECTIONS
    int section_count;
    link_symbol_t *provided; // g: PROVIDE symbols
    int provided_count;
} linker_script_t;
```

### API

```c
// ============== STATIC LIBRARY ==============
// 2.6.8.g-i

// 2.6.8.h: Parse archive
int archive_open(static_library_t *lib, const char *path);
void archive_close(static_library_t *lib);

// List members
int archive_list(const static_library_t *lib, char ***names, int *count);

// 2.6.8.i: Extract specific object
int archive_extract(const static_library_t *lib, const char *member,
                    uint8_t **data, size_t *size);

// Get symbols from archive
int archive_get_symbols(const static_library_t *lib, link_symbol_t **syms,
                        int *count);

// Create archive
int archive_create(const char *path, const char **objects, int count);

// ============== SYMBOL RESOLUTION ==============
// 2.6.8.c-e

// Load symbols from object file
int link_load_symbols(const char *obj_path, link_symbol_t **symbols,
                      int *count);

// 2.6.8.c: Resolve symbol references
// Returns: symbol definition or NULL if undefined
link_symbol_t *link_resolve_symbol(const char *name,
                                   link_symbol_t *symbols, int count);

// 2.6.8.d: Handle strong/weak
// Strong + Strong = error
// Strong + Weak = use Strong
// Weak + Weak = use first
int link_resolve_conflict(link_symbol_t *existing, link_symbol_t *new_sym,
                          link_symbol_t **result);

// 2.6.8.e: Detect duplicate strong symbols
int link_check_duplicates(link_symbol_t *symbols, int count,
                          char ***duplicates, int *dup_count);

// ============== LINKING SIMULATION ==============
// 2.6.8.a-b

typedef struct {
    char **object_files;
    int object_count;
    char **libraries;        // g: Static libraries
    int library_count;
    char *output;
    char *entry_point;
    bool static_only;        // k: -static
    char *linker_script;     // 2.6.9.i
} link_config_t;

// Simulate linking process
typedef struct {
    link_symbol_t *symbols;
    int symbol_count;
    char **undefined;        // Unresolved references
    int undefined_count;
    char **objects_used;     // i: Which objects were linked
    int objects_used_count;
    uint64_t text_size;
    uint64_t data_size;
    uint64_t bss_size;
} link_result_t;

int link_simulate(const link_config_t *cfg, link_result_t *result);
void link_result_free(link_result_t *result);

// 2.6.8.j: Demonstrate link order
void link_show_order_effect(const char **libs, int count);

// ============== LINKER SCRIPT ==============
// 2.6.9

// 2.6.9.a,h: Parse linker script
int lds_parse(const char *path, linker_script_t *script);
int lds_parse_string(const char *content, linker_script_t *script);
void lds_free(linker_script_t *script);

// 2.6.9.h: Get default script
int lds_get_default(char **script_content);

// Generate linker script
int lds_generate(const linker_script_t *script, char **output);

// 2.6.9.e: Calculate addresses using location counter
uint64_t lds_calculate_address(const linker_script_t *script,
                               const char *section);

// Display parsed script
void lds_print(const linker_script_t *script);

// Validate script
int lds_validate(const linker_script_t *script, char **errors, int *error_count);

// ============== EMBEDDED EXAMPLES ==============
// 2.6.9.j

// Generate bare-metal linker script
int lds_generate_embedded(uint64_t flash_start, uint64_t flash_size,
                          uint64_t ram_start, uint64_t ram_size,
                          char **script);
```

---

## Exemple

```c
#include "linker.h"

int main(int argc, char *argv[]) {
    // ============== STATIC LIBRARY ==============
    // 2.6.8.g-i

    printf("=== Static Library Analysis ===\n");

    static_library_t lib;
    archive_open(&lib, "libexample.a");

    printf("Archive: libexample.a\n");
    printf("Members: %d\n\n", lib.object_count);

    // 2.6.8.h: List contents (like ar -t)
    for (int i = 0; i < lib.object_count; i++) {
        printf("  %s\n", lib.object_names[i]);
    }

    // Get symbols (like nm)
    link_symbol_t *symbols;
    int sym_count;
    archive_get_symbols(&lib, &symbols, &sym_count);

    printf("\nExported symbols:\n");
    for (int i = 0; i < sym_count && i < 10; i++) {
        printf("  %c %s (%s)\n",
               symbols[i].is_strong ? 'T' : 'W',
               symbols[i].name,
               symbols[i].source_file);
    }

    // ============== SYMBOL RESOLUTION ==============
    // 2.6.8.c-e

    printf("\n=== Symbol Resolution ===\n");

    // Load symbols from object files
    link_symbol_t *obj1_syms, *obj2_syms;
    int count1, count2;
    link_load_symbols("main.o", &obj1_syms, &count1);
    link_load_symbols("helper.o", &obj2_syms, &count2);

    // 2.6.8.c: Resolve undefined symbol
    link_symbol_t *printf_sym = link_resolve_symbol("printf", symbols, sym_count);
    if (printf_sym) {
        printf("Resolved 'printf' from %s\n", printf_sym->source_file);
    }

    // 2.6.8.d: Strong vs weak
    printf("\nStrong/Weak resolution:\n");
    link_symbol_t strong = {.name = "foo", .is_strong = true, .value = 0x1000};
    link_symbol_t weak = {.name = "foo", .is_weak = true, .value = 0x2000};
    link_symbol_t *winner;
    link_resolve_conflict(&strong, &weak, &winner);
    printf("  Strong(0x1000) vs Weak(0x2000) -> winner: 0x%lx\n", winner->value);

    // 2.6.8.e: Duplicate detection
    char **dups;
    int dup_count;
    // Simulated: adding same strong symbol twice would error
    printf("\nDuplicate strong symbols cause linker error!\n");

    // ============== LINK ORDER ==============
    // 2.6.8.j

    printf("\n=== Link Order Matters ===\n");
    const char *libs[] = {"libfoo.a", "libbar.a"};
    link_show_order_effect(libs, 2);
    /*
    Order 1: main.o libfoo.a libbar.a
      - main.o needs foo() from libfoo.a
      - libfoo.a's foo.o needs bar() from libbar.a
      - Result: Success

    Order 2: main.o libbar.a libfoo.a
      - main.o needs foo() -> not in libbar.a
      - libfoo.a provides foo() but bar() already scanned
      - Result: undefined reference to 'bar'
    */

    // ============== LINKER SCRIPT ==============
    // 2.6.9

    printf("\n=== Linker Script Parsing ===\n");

    // 2.6.9.h: Get default script
    char *default_script;
    lds_get_default(&default_script);
    printf("Default script length: %zu bytes\n", strlen(default_script));

    // Parse custom script
    const char *script_content =
        "/* 2.6.9.f */ OUTPUT_FORMAT(elf64-x86-64)\n"
        "/* 2.6.9.b */ ENTRY(_start)\n"
        "\n"
        "/* 2.6.9.c */ MEMORY {\n"
        "    ROM (rx)  : ORIGIN = 0x08000000, LENGTH = 256K\n"
        "    RAM (rwx) : ORIGIN = 0x20000000, LENGTH = 64K\n"
        "}\n"
        "\n"
        "/* 2.6.9.d */ SECTIONS {\n"
        "    /* 2.6.9.e: . is location counter */\n"
        "    . = 0x08000000;\n"
        "    .text : { *(.text*) } > ROM\n"
        "    .rodata : { *(.rodata*) } > ROM\n"
        "    . = 0x20000000;\n"
        "    .data : { *(.data*) } > RAM AT > ROM\n"
        "    .bss : { *(.bss*) } > RAM\n"
        "    /* 2.6.9.g */ PROVIDE(__stack_top = ORIGIN(RAM) + LENGTH(RAM));\n"
        "}\n";

    linker_script_t script;
    lds_parse_string(script_content, &script);

    printf("\nParsed Linker Script:\n");
    lds_print(&script);
    /*
    Entry Point: _start
    Output Format: elf64-x86-64

    Memory Regions:
      ROM: 0x08000000 - 0x08040000 (256K) [rx]
      RAM: 0x20000000 - 0x20010000 (64K) [rwx]

    Sections:
      .text  -> ROM @ 0x08000000
      .rodata -> ROM
      .data  -> RAM (load from ROM)
      .bss   -> RAM

    Provided Symbols:
      __stack_top = 0x20010000
    */

    // 2.6.9.e: Location counter calculation
    printf("\nSection addresses:\n");
    printf("  .text @ 0x%lx\n", lds_calculate_address(&script, ".text"));
    printf("  .data @ 0x%lx\n", lds_calculate_address(&script, ".data"));

    // 2.6.9.j: Embedded example
    printf("\n=== Embedded Linker Script ===\n");
    char *embedded_script;
    lds_generate_embedded(
        0x08000000, 256 * 1024,    // Flash
        0x20000000, 64 * 1024,     // RAM
        &embedded_script
    );
    printf("%s\n", embedded_script);

    // ============== FULL LINK SIMULATION ==============
    // 2.6.8.a

    printf("\n=== Link Simulation ===\n");

    link_config_t cfg = {
        .object_files = (char*[]){"main.o", "helper.o"},
        .object_count = 2,
        .libraries = (char*[]){"libm.a", "libc.a"},
        .library_count = 2,
        .output = "program",
        .entry_point = "main",
        .static_only = true,  // k: -static
    };

    link_result_t result;
    if (link_simulate(&cfg, &result) == 0) {
        printf("Linking successful!\n");
        printf("Total symbols: %d\n", result.symbol_count);
        printf("Objects linked: %d\n", result.objects_used_count);
        printf(".text: %lu bytes\n", result.text_size);
        printf(".data: %lu bytes\n", result.data_size);
        printf(".bss:  %lu bytes\n", result.bss_size);
    } else {
        printf("Undefined symbols:\n");
        for (int i = 0; i < result.undefined_count; i++) {
            printf("  %s\n", result.undefined[i]);
        }
    }

    archive_close(&lib);
    lds_free(&script);
    return 0;
}
```

---

## Tests Moulinette

```rust
// Static linking
#[test] fn test_archive_parse()         // 2.6.8.g-h
#[test] fn test_archive_extract()       // 2.6.8.i
#[test] fn test_symbol_resolution()     // 2.6.8.c
#[test] fn test_strong_weak()           // 2.6.8.d
#[test] fn test_duplicate_error()       // 2.6.8.e
#[test] fn test_link_order()            // 2.6.8.j
#[test] fn test_static_flag()           // 2.6.8.k

// Linker scripts
#[test] fn test_lds_parse()             // 2.6.9.a
#[test] fn test_lds_entry()             // 2.6.9.b
#[test] fn test_lds_memory()            // 2.6.9.c
#[test] fn test_lds_sections()          // 2.6.9.d
#[test] fn test_location_counter()      // 2.6.9.e
#[test] fn test_lds_provide()           // 2.6.9.g
#[test] fn test_lds_default()           // 2.6.9.h
#[test] fn test_embedded_script()       // 2.6.9.j
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Archive handling (2.6.8.g-i) | 20 |
| Symbol resolution (2.6.8.c-e) | 20 |
| Link process (2.6.8.a-b,f,j-k) | 15 |
| Script parsing (2.6.9.a-d) | 20 |
| Script features (2.6.9.e-j) | 25 |
| **Total** | **100** |

---

## Fichiers

```
ex04/
├── linker.h
├── archive.c
├── symbols.c
├── resolution.c
├── lds_parse.c
├── lds_gen.c
└── Makefile
```
