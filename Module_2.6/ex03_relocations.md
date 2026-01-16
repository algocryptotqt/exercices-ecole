# ex03: ELF Relocations

**Module**: 2.6 - ELF, Linking & Loading
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.6.7: Relocations (11 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Relocation | Fix addresses |
| b | Why needed | Addresses unknown at compile |
| c | .rel sections | Implicit addend |
| d | .rela sections | Explicit addend |
| e | Relocation entry | Offset, info, addend |
| f | R_X86_64_64 | 64-bit absolute |
| g | R_X86_64_PC32 | 32-bit PC-relative |
| h | R_X86_64_PLT32 | PLT-relative |
| i | R_X86_64_GOT32 | GOT-relative |
| j | readelf -r | View relocations |
| k | Relocation formula | S + A - P |

---

## Sujet

Parser les relocations d'un fichier ELF et comprendre leur application.

### Structures

```c
#include <elf.h>

// 2.6.7.e: Relocation entry wrapper
typedef struct {
    uint64_t offset;         // Location to patch
    uint32_t type;           // f-i: R_X86_64_*
    uint32_t sym_index;      // Symbol table index
    int64_t addend;          // d: Explicit addend (for .rela)
    char *sym_name;          // Resolved symbol name
    uint64_t sym_value;      // Symbol value (if known)
    const char *section;     // Which section this reloc is for
} elf_reloc_t;

// Relocation section info
typedef struct {
    char *name;              // .rel.text, .rela.dyn, etc.
    bool has_addend;         // c vs d: .rel vs .rela
    int entry_count;
    elf_reloc_t *entries;
} elf_reloc_section_t;

// For simulation
typedef struct {
    uint8_t *code;           // Code buffer
    size_t code_size;
    uint64_t code_base;      // Virtual address
    uint8_t *data;           // Data buffer
    size_t data_size;
    uint64_t data_base;
} reloc_context_t;
```

### API

```c
// ============== RELOCATION PARSING ==============
// 2.6.7

// Get all relocation sections
int elf_get_reloc_sections(elf_file_t *elf, elf_reloc_section_t **sections,
                           int *count);
void elf_free_reloc_sections(elf_reloc_section_t *sections, int count);

// Get relocations for specific section (.text, .data)
int elf_get_relocations_for(elf_file_t *elf, const char *section,
                            elf_reloc_t **relocs, int *count);
void elf_free_relocations(elf_reloc_t *relocs, int count);

// 2.6.7.f-i: Type string
const char *elf_reloc_type_string(uint32_t type);

// 2.6.7.j: Display like readelf -r
void elf_print_relocations(elf_file_t *elf);
void elf_print_reloc(const elf_reloc_t *reloc, bool rela_format);

// ============== RELOCATION PROCESSING ==============
// 2.6.7.k

// Calculate relocated value
// S = symbol value, A = addend, P = place (offset in section)
// 2.6.7.f: R_X86_64_64: S + A
// 2.6.7.g: R_X86_64_PC32: S + A - P
// 2.6.7.h: R_X86_64_PLT32: L + A - P (L = PLT entry)
// 2.6.7.i: R_X86_64_GOT32: G + A (G = GOT entry offset)

typedef struct {
    uint64_t symbol_value;   // S
    int64_t addend;          // A
    uint64_t place;          // P
    uint64_t got_offset;     // G (for GOT relocations)
    uint64_t plt_entry;      // L (for PLT relocations)
} reloc_params_t;

int64_t reloc_calculate(uint32_t type, const reloc_params_t *params);

// Apply relocation to memory
int reloc_apply(reloc_context_t *ctx, const elf_reloc_t *reloc,
                const reloc_params_t *params);

// Apply all relocations for a section
int reloc_apply_section(reloc_context_t *ctx, elf_file_t *elf,
                        const char *section, uint64_t base_addr);

// ============== ANALYSIS ==============

// Check relocation types used
typedef struct {
    int total;
    int absolute_64;         // f: R_X86_64_64
    int pc_relative;         // g: R_X86_64_PC32
    int plt_relative;        // h: R_X86_64_PLT32
    int got_relative;        // i: R_X86_64_GOT32
    int other;
} reloc_stats_t;

void elf_reloc_stats(elf_reloc_t *relocs, int count, reloc_stats_t *stats);

// Explain what a relocation does
void reloc_explain(const elf_reloc_t *reloc, char *explanation, size_t max_len);
```

---

## Exemple

```c
#include "elf_parser.h"

int main(int argc, char *argv[]) {
    elf_file_t elf;
    elf_open(&elf, argv[1]);

    // ============== RELOCATION DISPLAY ==============
    // 2.6.7.j

    printf("=== Relocations (like readelf -r) ===\n\n");
    elf_print_relocations(&elf);

    /*
    Relocation section '.rela.text' at offset 0x... contains N entries:
      Offset          Info           Type           Sym. Value    Sym. Name + Addend
    000000000004  000500000004 R_X86_64_PLT32    0000000000000000 printf - 4
    00000000001a  000600000002 R_X86_64_PC32     0000000000000000 global_var - 4
    ...

    Relocation section '.rela.dyn' at offset 0x... contains N entries:
    ...
    */

    // ============== ANALYZE RELOCATIONS ==============

    elf_reloc_section_t *sections;
    int sec_count;
    elf_get_reloc_sections(&elf, &sections, &sec_count);

    printf("\n=== Relocation Sections ===\n");
    for (int i = 0; i < sec_count; i++) {
        printf("\n%s (%s format, %d entries):\n",
               sections[i].name,
               sections[i].has_addend ? ".rela" : ".rel",  // c vs d
               sections[i].entry_count);

        for (int j = 0; j < sections[i].entry_count && j < 5; j++) {
            elf_reloc_t *r = &sections[i].entries[j];
            printf("  [%d] offset=0x%lx type=%s sym=%s addend=%ld\n",
                   j, r->offset,
                   elf_reloc_type_string(r->type),  // f-i
                   r->sym_name,
                   r->addend);  // d
        }
    }

    // ============== RELOCATION TYPES ==============
    // 2.6.7.f-i

    printf("\n=== Relocation Type Examples ===\n");

    // 2.6.7.f: R_X86_64_64 - 64-bit absolute
    printf("\nR_X86_64_64 (absolute):\n");
    printf("  Formula: S + A\n");
    printf("  Use: Data pointers, 64-bit addresses\n");

    // 2.6.7.g: R_X86_64_PC32 - 32-bit PC-relative
    printf("\nR_X86_64_PC32 (PC-relative):\n");
    printf("  Formula: S + A - P\n");
    printf("  Use: Local function calls, data references\n");

    // 2.6.7.h: R_X86_64_PLT32 - PLT entry
    printf("\nR_X86_64_PLT32 (PLT):\n");
    printf("  Formula: L + A - P\n");
    printf("  Use: External function calls\n");

    // 2.6.7.i: R_X86_64_GOT32 - GOT entry
    printf("\nR_X86_64_GOT32 (GOT):\n");
    printf("  Formula: G + A\n");
    printf("  Use: Global variable access in PIC\n");

    // ============== CALCULATION DEMO ==============
    // 2.6.7.k

    printf("\n=== Relocation Calculation Demo ===\n");

    // Example: PC-relative call
    reloc_params_t params = {
        .symbol_value = 0x1100,  // S: target function
        .addend = -4,            // A: standard adjustment
        .place = 0x1050,         // P: call instruction location
    };

    int64_t result = reloc_calculate(R_X86_64_PC32, &params);
    printf("\nR_X86_64_PC32 example:\n");
    printf("  S (symbol)  = 0x%lx\n", params.symbol_value);
    printf("  A (addend)  = %ld\n", params.addend);
    printf("  P (place)   = 0x%lx\n", params.place);
    printf("  Result = S + A - P = 0x%lx\n", (uint64_t)result);

    // Example: Absolute 64-bit
    params.symbol_value = 0x404000;
    params.addend = 8;
    result = reloc_calculate(R_X86_64_64, &params);
    printf("\nR_X86_64_64 example:\n");
    printf("  S + A = 0x%lx + %ld = 0x%lx\n",
           params.symbol_value, params.addend, (uint64_t)result);

    // ============== RELOCATION EXPLANATION ==============

    printf("\n=== Relocation Explanations ===\n");
    elf_reloc_t *relocs;
    int count;
    elf_get_relocations_for(&elf, ".text", &relocs, &count);

    char explanation[256];
    for (int i = 0; i < count && i < 3; i++) {
        reloc_explain(&relocs[i], explanation, sizeof(explanation));
        printf("\n%s\n", explanation);
    }
    /*
    At offset 0x4 in .text: Patch a 32-bit PC-relative reference to 'printf'.
    This is a function call through the PLT.
    */

    // Statistics
    reloc_stats_t stats;
    elf_reloc_stats(relocs, count, &stats);
    printf("\n=== Relocation Statistics ===\n");
    printf("Total: %d\n", stats.total);
    printf("Absolute 64-bit: %d\n", stats.absolute_64);
    printf("PC-relative: %d\n", stats.pc_relative);
    printf("PLT: %d\n", stats.plt_relative);
    printf("GOT: %d\n", stats.got_relative);

    elf_free_relocations(relocs, count);
    elf_free_reloc_sections(sections, sec_count);
    elf_close(&elf);
    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_reloc_parse()           // 2.6.7.a-b
#[test] fn test_rel_vs_rela()           // 2.6.7.c-d
#[test] fn test_reloc_entry()           // 2.6.7.e
#[test] fn test_reloc_64()              // 2.6.7.f
#[test] fn test_reloc_pc32()            // 2.6.7.g
#[test] fn test_reloc_plt32()           // 2.6.7.h
#[test] fn test_reloc_got32()           // 2.6.7.i
#[test] fn test_readelf_output()        // 2.6.7.j
#[test] fn test_reloc_formula()         // 2.6.7.k
#[test] fn test_reloc_apply()           // Apply relocations
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Relocation parsing (2.6.7.a-e) | 30 |
| Type handling (2.6.7.f-i) | 25 |
| Display (2.6.7.j) | 20 |
| Formula/calculation (2.6.7.k) | 25 |
| **Total** | **100** |

---

## Fichiers

```
ex03/
├── elf_parser.h
├── relocations.c
├── reloc_types.c
├── reloc_apply.c
└── Makefile
```
