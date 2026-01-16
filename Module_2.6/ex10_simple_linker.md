# ex10: Writing a Simple Linker

**Module**: 2.6 - ELF, Linking & Loading
**Difficulte**: Tres difficile
**Duree**: 8h
**Score qualite**: 97/100

## Concepts Couverts

### 2.6.20: Writing a Simple Linker (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Read ELF header | Parse header |
| b | Read sections | Load section headers |
| c | Read symbols | Build symbol table |
| d | Symbol resolution | Match definitions |
| e | Read relocations | Get relocation entries |
| f | Apply relocations | Fix addresses |
| g | Write output | Generate executable |
| h | Minimal linker | Just .text and .data |

---

## Sujet

Implementer un linker minimal capable de lier deux fichiers objets.

### Structures

```c
#include <elf.h>

// Object file representation
typedef struct {
    char *path;
    uint8_t *data;
    size_t size;

    // Parsed data
    Elf64_Ehdr *ehdr;        // a: ELF header
    Elf64_Shdr *shdrs;       // b: Section headers
    int shnum;
    char *shstrtab;          // Section name strings

    // Content
    uint8_t *text;           // .text section
    size_t text_size;
    uint64_t text_addr;      // Virtual address

    uint8_t *data;           // .data section
    size_t data_size;
    uint64_t data_addr;

    uint8_t *rodata;         // .rodata section
    size_t rodata_size;

    uint8_t *bss;            // .bss (just size)
    size_t bss_size;
} object_file_t;

// c: Symbol entry
typedef struct {
    char *name;
    uint64_t value;          // Address or offset
    uint64_t size;
    uint8_t type;            // STT_*
    uint8_t binding;         // STB_*
    uint16_t shndx;          // Section index
    object_file_t *source;   // Which object file
    bool is_defined;
    bool is_resolved;        // d: Has been resolved
    uint64_t final_address;  // After linking
} linker_symbol_t;

// e: Relocation entry
typedef struct {
    uint64_t offset;         // Location to patch
    uint32_t type;           // R_X86_64_*
    char *symbol;            // Target symbol name
    int64_t addend;
    object_file_t *source;   // Which object file
    const char *section;     // Which section (.text, .data)
} linker_reloc_t;

// Output executable
typedef struct {
    uint8_t *text;
    size_t text_size;
    uint64_t text_vaddr;

    uint8_t *data;
    size_t data_size;
    uint64_t data_vaddr;

    size_t bss_size;
    uint64_t bss_vaddr;

    uint64_t entry;          // Entry point
} output_exe_t;
```

### API

```c
// ============== OBJECT FILE PARSING ==============

// 2.6.20.a: Read and parse ELF header
int obj_open(object_file_t *obj, const char *path);
void obj_close(object_file_t *obj);
bool obj_validate(const object_file_t *obj);

// 2.6.20.b: Read sections
int obj_read_sections(object_file_t *obj);
Elf64_Shdr *obj_find_section(object_file_t *obj, const char *name);
uint8_t *obj_section_data(object_file_t *obj, Elf64_Shdr *shdr);

// ============== SYMBOL TABLE ==============
// 2.6.20.c-d

// c: Read symbols from object file
int obj_read_symbols(object_file_t *obj, linker_symbol_t **symbols, int *count);

// d: Symbol resolution
typedef struct {
    linker_symbol_t *symbols;
    int count;
    int capacity;
} symbol_table_t;

int symtab_init(symbol_table_t *tab);
void symtab_free(symbol_table_t *tab);
int symtab_add(symbol_table_t *tab, linker_symbol_t *sym);
linker_symbol_t *symtab_find(symbol_table_t *tab, const char *name);

// Resolve all symbols
int symtab_resolve(symbol_table_t *tab, char ***undefined, int *undef_count);

// ============== RELOCATIONS ==============
// 2.6.20.e-f

// e: Read relocations
int obj_read_relocations(object_file_t *obj, linker_reloc_t **relocs, int *count);

// f: Apply relocations
int reloc_apply_all(output_exe_t *output, linker_reloc_t *relocs, int count,
                    symbol_table_t *symtab);

// Apply single relocation
int reloc_apply_one(uint8_t *target, const linker_reloc_t *reloc,
                    uint64_t symbol_value, uint64_t place);

// ============== LINKER ==============
// 2.6.20.g-h

// Main linker structure
typedef struct {
    object_file_t *objects;
    int object_count;

    symbol_table_t symtab;
    linker_reloc_t *relocs;
    int reloc_count;

    // Layout
    uint64_t text_base;
    uint64_t data_base;
    uint64_t bss_base;

    // Output
    output_exe_t output;
    char *entry_symbol;
} linker_t;

// Initialize linker
int linker_init(linker_t *ld);
void linker_cleanup(linker_t *ld);

// Add object file
int linker_add_object(linker_t *ld, const char *path);

// Set entry point
int linker_set_entry(linker_t *ld, const char *symbol);

// h: Perform linking
int linker_link(linker_t *ld);

// g: Write output executable
int linker_write_output(linker_t *ld, const char *path);

// ============== HELPER FUNCTIONS ==============

// Calculate section layout
int layout_sections(linker_t *ld);

// Merge sections from multiple objects
int merge_text_sections(linker_t *ld);
int merge_data_sections(linker_t *ld);

// Generate ELF headers for output
int generate_elf_header(output_exe_t *output, Elf64_Ehdr *ehdr);
int generate_program_headers(output_exe_t *output, Elf64_Phdr *phdrs, int *count);

// Debug output
void linker_print_symbols(linker_t *ld);
void linker_print_relocations(linker_t *ld);
void linker_print_layout(linker_t *ld);
```

---

## Exemple

```c
#include "simple_linker.h"

// Example: Link main.o and helper.o into program

/*
// main.c -> main.o
extern int helper_add(int a, int b);
extern int global_var;

int main() {
    global_var = 42;
    return helper_add(1, 2);
}

// helper.c -> helper.o
int global_var = 0;

int helper_add(int a, int b) {
    return a + b + global_var;
}
*/

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s output.elf obj1.o obj2.o ...\n", argv[0]);
        return 1;
    }

    linker_t ld;
    linker_init(&ld);

    // ============== LOAD OBJECT FILES ==============
    // 2.6.20.a-b

    printf("=== Loading Object Files ===\n");

    for (int i = 2; i < argc; i++) {
        printf("\nLoading: %s\n", argv[i]);

        if (linker_add_object(&ld, argv[i]) < 0) {
            fprintf(stderr, "Failed to load %s\n", argv[i]);
            return 1;
        }

        object_file_t *obj = &ld.objects[ld.object_count - 1];

        // a: Show ELF header info
        printf("  Type: %s\n",
               obj->ehdr->e_type == ET_REL ? "Relocatable" : "Other");
        printf("  Sections: %d\n", obj->shnum);

        // b: Show key sections
        printf("  .text: %zu bytes\n", obj->text_size);
        printf("  .data: %zu bytes\n", obj->data_size);
        printf("  .bss:  %zu bytes\n", obj->bss_size);
    }

    // ============== READ SYMBOLS ==============
    // 2.6.20.c

    printf("\n=== Symbol Table ===\n");
    linker_print_symbols(&ld);
    /*
    Symbol Table:
      main           T  main.o        (defined)
      helper_add     U  main.o        (undefined)
      global_var     U  main.o        (undefined)
      helper_add     T  helper.o      (defined)
      global_var     D  helper.o      (defined)
    */

    // ============== SYMBOL RESOLUTION ==============
    // 2.6.20.d

    printf("\n=== Symbol Resolution ===\n");

    char **undefined;
    int undef_count;
    if (symtab_resolve(&ld.symtab, &undefined, &undef_count) < 0) {
        printf("Unresolved symbols:\n");
        for (int i = 0; i < undef_count; i++) {
            printf("  undefined reference to '%s'\n", undefined[i]);
        }
        return 1;
    }

    printf("All symbols resolved!\n");

    // Show resolution
    printf("\nResolved symbols:\n");
    for (int i = 0; i < ld.symtab.count; i++) {
        linker_symbol_t *sym = &ld.symtab.symbols[i];
        if (sym->is_defined) {
            printf("  %-15s -> 0x%08lx (from %s)\n",
                   sym->name, sym->final_address,
                   sym->source->path);
        }
    }

    // ============== READ RELOCATIONS ==============
    // 2.6.20.e

    printf("\n=== Relocations ===\n");
    linker_print_relocations(&ld);
    /*
    Relocations:
      main.o .text+0x10: R_X86_64_PC32  helper_add - 4
      main.o .text+0x20: R_X86_64_PC32  global_var - 4
    */

    // ============== LAYOUT SECTIONS ==============

    printf("\n=== Section Layout ===\n");
    layout_sections(&ld);
    linker_print_layout(&ld);
    /*
    Layout:
      .text:  0x401000 - 0x401100 (256 bytes)
      .data:  0x402000 - 0x402010 (16 bytes)
      .bss:   0x402010 - 0x402020 (16 bytes)
      Entry:  0x401000 (main)
    */

    // ============== LINK ==============
    // 2.6.20.f

    printf("\n=== Linking ===\n");

    linker_set_entry(&ld, "main");

    if (linker_link(&ld) < 0) {
        fprintf(stderr, "Linking failed\n");
        return 1;
    }

    printf("Linking successful!\n");

    // Show relocation application
    printf("\nRelocations applied:\n");
    for (int i = 0; i < ld.reloc_count; i++) {
        linker_reloc_t *r = &ld.relocs[i];
        linker_symbol_t *sym = symtab_find(&ld.symtab, r->symbol);
        printf("  %s @ offset 0x%lx -> 0x%lx\n",
               r->symbol, r->offset, sym->final_address);
    }

    // ============== WRITE OUTPUT ==============
    // 2.6.20.g

    printf("\n=== Writing Output ===\n");

    if (linker_write_output(&ld, argv[1]) < 0) {
        fprintf(stderr, "Failed to write output\n");
        return 1;
    }

    printf("Output written to: %s\n", argv[1]);

    // Verify output
    printf("\nVerifying output:\n");
    printf("  $ file %s\n", argv[1]);
    printf("  $ readelf -h %s\n", argv[1]);
    printf("  $ ./%s\n", argv[1]);

    // ============== MINIMAL LINKER DEMO ==============
    // 2.6.20.h

    printf("\n=== Minimal Linker Features ===\n");
    printf("This linker handles:\n");
    printf("  - .text section (code)\n");
    printf("  - .data section (initialized data)\n");
    printf("  - .bss section (uninitialized data)\n");
    printf("  - R_X86_64_PC32 relocations\n");
    printf("  - R_X86_64_64 relocations\n");
    printf("  - Basic symbol resolution\n");

    printf("\nNot implemented (full linker would need):\n");
    printf("  - Shared library support\n");
    printf("  - Static libraries (.a)\n");
    printf("  - Linker scripts\n");
    printf("  - All relocation types\n");
    printf("  - Debug information\n");

    linker_cleanup(&ld);
    return 0;
}

// ============== RELOCATION IMPLEMENTATION ==============

int reloc_apply_one(uint8_t *target, const linker_reloc_t *reloc,
                    uint64_t S, uint64_t P) {
    int64_t A = reloc->addend;

    switch (reloc->type) {
        case R_X86_64_PC32: {
            // S + A - P
            int32_t value = (int32_t)(S + A - P);
            memcpy(target + reloc->offset, &value, 4);
            break;
        }
        case R_X86_64_64: {
            // S + A
            uint64_t value = S + A;
            memcpy(target + reloc->offset, &value, 8);
            break;
        }
        case R_X86_64_32: {
            // S + A (truncated to 32-bit)
            uint32_t value = (uint32_t)(S + A);
            memcpy(target + reloc->offset, &value, 4);
            break;
        }
        default:
            fprintf(stderr, "Unsupported relocation type: %d\n", reloc->type);
            return -1;
    }

    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_obj_parse()             // 2.6.20.a
#[test] fn test_section_read()          // 2.6.20.b
#[test] fn test_symbol_read()           // 2.6.20.c
#[test] fn test_symbol_resolution()     // 2.6.20.d
#[test] fn test_reloc_read()            // 2.6.20.e
#[test] fn test_reloc_apply()           // 2.6.20.f
#[test] fn test_output_write()          // 2.6.20.g
#[test] fn test_minimal_link()          // 2.6.20.h
#[test] fn test_link_two_objects()      // Integration
#[test] fn test_output_runs()           // Output executable works
```

---

## Bareme

| Critere | Points |
|---------|--------|
| ELF parsing (2.6.20.a-b) | 20 |
| Symbol handling (2.6.20.c-d) | 25 |
| Relocation (2.6.20.e-f) | 30 |
| Output generation (2.6.20.g) | 15 |
| Working minimal linker (2.6.20.h) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex10/
├── simple_linker.h
├── object.c
├── symbols.c
├── relocations.c
├── linker.c
├── output.c
├── test/
│   ├── main.c
│   └── helper.c
└── Makefile
```
