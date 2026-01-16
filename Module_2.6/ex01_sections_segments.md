# ex01: ELF Sections & Segments

**Module**: 2.6 - ELF, Linking & Loading
**Difficulte**: Moyen
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.6.3: ELF Sections (14 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Section | Logical division |
| b | .text | Code |
| c | .data | Initialized data |
| d | .bss | Uninitialized data |
| e | .rodata | Read-only data |
| f | .symtab | Symbol table |
| g | .strtab | String table |
| h | .rel.text | Relocations for text |
| i | .rel.data | Relocations for data |
| j | .debug | Debug information |
| k | Section header | Describes section |
| l | sh_type | Section type |
| m | sh_flags | Section flags |
| n | readelf -S | View sections |

### 2.6.4: ELF Segments (12 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Segment | Runtime view |
| b | Section vs segment | Link time vs run time |
| c | Program header | Describes segment |
| d | PT_LOAD | Loadable segment |
| e | PT_DYNAMIC | Dynamic linking info |
| f | PT_INTERP | Interpreter path |
| g | PT_NOTE | Auxiliary info |
| h | PT_PHDR | Program header |
| i | PT_GNU_STACK | Stack permissions |
| j | PT_GNU_RELRO | Read-only after relocation |
| k | p_flags | PF_R, PF_W, PF_X |
| l | readelf -l | View segments |

---

## Sujet

Parser et afficher les sections et segments d'un fichier ELF.

### Structures

```c
#include <elf.h>

// 2.6.3.k: Section wrapper
typedef struct {
    char *name;
    uint32_t type;           // l: sh_type
    uint64_t flags;          // m: sh_flags
    uint64_t addr;
    uint64_t offset;
    uint64_t size;
    uint32_t link;
    uint32_t info;
    uint64_t addralign;
    uint64_t entsize;
} elf_section_t;

// 2.6.4.c: Segment wrapper
typedef struct {
    uint32_t type;           // d-j: PT_*
    uint32_t flags;          // k: PF_R, PF_W, PF_X
    uint64_t offset;
    uint64_t vaddr;
    uint64_t paddr;
    uint64_t filesz;
    uint64_t memsz;
    uint64_t align;
} elf_segment_t;
```

### API

```c
// ============== SECTIONS ==============
// 2.6.3

int elf_get_sections(elf_file_t *elf, elf_section_t **sections, int *count);
void elf_free_sections(elf_section_t *sections, int count);
elf_section_t *elf_find_section(elf_file_t *elf, const char *name);
void *elf_section_data(elf_file_t *elf, elf_section_t *section);

// Section type/flags strings
const char *elf_section_type_string(uint32_t type);
char *elf_section_flags_string(uint64_t flags);

// 2.6.3.n: Display like readelf -S
void elf_print_sections(elf_file_t *elf);

// ============== SEGMENTS ==============
// 2.6.4

int elf_get_segments(elf_file_t *elf, elf_segment_t **segments, int *count);
void elf_free_segments(elf_segment_t *segments, int count);

const char *elf_segment_type_string(uint32_t type);
char *elf_segment_flags_string(uint32_t flags);

// 2.6.4.l: Display like readelf -l
void elf_print_segments(elf_file_t *elf);

// 2.6.4.b: Section to segment mapping
void elf_print_section_to_segment_mapping(elf_file_t *elf);
```

---

## Exemple

```c
#include "elf_parser.h"

int main(int argc, char *argv[]) {
    elf_file_t elf;
    elf_open(&elf, argv[1]);

    // 2.6.3.n: Print sections like readelf -S
    printf("Section Headers:\n");
    elf_print_sections(&elf);

    /*
    [Nr] Name              Type             Address           Offset
         Size              EntSize          Flags  Link  Info  Align
    [ 0]                   NULL             0000000000000000  00000000
    [ 1] .text             PROGBITS         0000000000001060  00001060
         0000000000000185  0000000000000000  AX       0     0     16
    [ 2] .rodata           PROGBITS         0000000000002000  00002000
         0000000000000012  0000000000000000   A       0     0     4
    ...
    */

    // 2.6.4.l: Print segments like readelf -l
    printf("\nProgram Headers:\n");
    elf_print_segments(&elf);

    /*
    Type           Offset             VirtAddr           PhysAddr
                   FileSiz            MemSiz              Flags  Align
    PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040
                   0x0000000000000268 0x0000000000000268  R      0x8
    INTERP         0x00000000000002a8 0x00000000000002a8 0x00000000000002a8
                   0x000000000000001c 0x000000000000001c  R      0x1
          [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
    LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000
                   0x0000000000000628 0x0000000000000628  R      0x1000
    ...
    */

    // Section to segment mapping
    printf("\nSection to Segment mapping:\n");
    elf_print_section_to_segment_mapping(&elf);

    elf_close(&elf);
    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_section_parse()        // 2.6.3.a-k
#[test] fn test_section_types()        // 2.6.3.l
#[test] fn test_section_flags()        // 2.6.3.m
#[test] fn test_segment_parse()        // 2.6.4.a-c
#[test] fn test_segment_types()        // 2.6.4.d-j
#[test] fn test_segment_flags()        // 2.6.4.k
#[test] fn test_section_segment_map()  // 2.6.4.b
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Section parsing (2.6.3.a-j) | 30 |
| Section header (2.6.3.k-n) | 20 |
| Segment parsing (2.6.4.a-h) | 25 |
| Segment flags (2.6.4.i-l) | 15 |
| Mapping (2.6.4.b) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex01/
├── elf_parser.h
├── sections.c
├── segments.c
├── mapping.c
└── Makefile
```
