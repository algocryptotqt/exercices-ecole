# ex00: ELF Format Basics

**Module**: 2.6 - ELF, Linking & Loading
**Difficulte**: Moyen
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.6.1: Object File Formats (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Object file | Compiled but not linked |
| b | ELF | Executable and Linkable Format |
| c | PE | Windows Portable Executable |
| d | Mach-O | macOS format |
| e | a.out | Historical Unix |
| f | COFF | Common Object File Format |
| g | ELF usage | Linux, BSD, Solaris |
| h | File types | Relocatable, executable, shared, core |

### 2.6.2: ELF Header (12 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Magic number | 0x7F "ELF" |
| b | Class | 32-bit or 64-bit |
| c | Endianness | Little or big |
| d | Version | ELF version |
| e | OS/ABI | Target OS |
| f | Type | REL, EXEC, DYN, CORE |
| g | Machine | Architecture (x86, ARM) |
| h | Entry point | Start address |
| i | Program header offset | For segments |
| j | Section header offset | For sections |
| k | Flags | Architecture-specific |
| l | readelf -h | View header |

---

## Sujet

Creer un parseur ELF capable de lire et afficher l'en-tete des fichiers ELF.

### Structures

```c
#include <elf.h>
#include <stdint.h>

// 2.6.1.b: ELF identification
typedef struct {
    unsigned char magic[4];      // a: 0x7F "ELF"
    uint8_t class;               // b: 32 or 64 bit
    uint8_t endian;              // c: Little or big
    uint8_t version;             // d: ELF version
    uint8_t osabi;               // e: Target OS
    uint8_t abiversion;
    unsigned char pad[7];
} elf_ident_t;

// 2.6.2: ELF Header wrapper (64-bit)
typedef struct {
    elf_ident_t ident;
    uint16_t type;               // f: REL, EXEC, DYN, CORE
    uint16_t machine;            // g: Architecture
    uint32_t version;
    uint64_t entry;              // h: Entry point
    uint64_t phoff;              // i: Program header offset
    uint64_t shoff;              // j: Section header offset
    uint32_t flags;              // k: Flags
    uint16_t ehsize;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
} elf64_header_t;

// 2.6.1.h: File types
typedef enum {
    ELF_TYPE_NONE = 0,           // Unknown
    ELF_TYPE_REL = 1,            // Relocatable
    ELF_TYPE_EXEC = 2,           // Executable
    ELF_TYPE_DYN = 3,            // Shared object
    ELF_TYPE_CORE = 4            // Core dump
} elf_type_t;

// ELF file context
typedef struct {
    int fd;
    void *mapped;
    size_t size;
    bool is_64bit;
    Elf64_Ehdr *ehdr64;
    Elf32_Ehdr *ehdr32;
} elf_file_t;
```

### API

```c
// ============== ELF FILE HANDLING ==============

int elf_open(elf_file_t *elf, const char *path);
void elf_close(elf_file_t *elf);
bool elf_validate(const elf_file_t *elf);

// ============== ELF IDENTIFICATION ==============
// 2.6.2.a-e

bool elf_check_magic(const unsigned char *ident);
const char *elf_class_string(uint8_t class);
const char *elf_endian_string(uint8_t endian);
const char *elf_osabi_string(uint8_t osabi);

// ============== ELF HEADER ==============
// 2.6.2.f-l

const char *elf_type_string(uint16_t type);
const char *elf_machine_string(uint16_t machine);
uint64_t elf_get_entry(const elf_file_t *elf);
uint64_t elf_get_phoff(const elf_file_t *elf);
uint64_t elf_get_shoff(const elf_file_t *elf);
uint16_t elf_get_phnum(const elf_file_t *elf);
uint16_t elf_get_shnum(const elf_file_t *elf);

// ============== DISPLAY ==============
// 2.6.2.l: Like readelf -h

void elf_print_header(const elf_file_t *elf);
void elf_print_ident(const elf_file_t *elf);

// ============== FILE TYPE DETECTION ==============
// 2.6.1.a-h

typedef struct {
    const char *format;          // ELF, PE, Mach-O, etc.
    const char *type;            // Relocatable, Executable, etc.
    const char *arch;            // x86_64, ARM, etc.
    bool is_64bit;
    bool is_shared;
} file_info_t;

int detect_file_format(const char *path, file_info_t *info);
void print_file_info(const file_info_t *info);
```

---

## Exemple

```c
#include "elf_parser.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <elf_file>\n", argv[0]);
        return 1;
    }

    elf_file_t elf;

    // Open and map ELF file
    if (elf_open(&elf, argv[1]) < 0) {
        fprintf(stderr, "Failed to open ELF file\n");
        return 1;
    }

    // 2.6.2.a: Check magic number
    if (!elf_validate(&elf)) {
        fprintf(stderr, "Not a valid ELF file\n");
        elf_close(&elf);
        return 1;
    }

    // 2.6.2.l: Print header like readelf -h
    printf("ELF Header:\n");
    elf_print_header(&elf);

    /*
    Output:
    ELF Header:
      Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
      Class:                             ELF64
      Data:                              2's complement, little endian
      Version:                           1 (current)
      OS/ABI:                            UNIX - System V
      Type:                              DYN (Shared object file)
      Machine:                           Advanced Micro Devices X86-64
      Version:                           0x1
      Entry point address:               0x1060
      Start of program headers:          64 (bytes into file)
      Start of section headers:          14544 (bytes into file)
      Flags:                             0x0
      Size of this header:               64 (bytes)
      Size of program headers:           56 (bytes)
      Number of program headers:         11
      Size of section headers:           64 (bytes)
      Number of section headers:         30
      Section header string table index: 29
    */

    // 2.6.1.h: Show file type
    printf("\nFile Type: %s\n", elf_type_string(elf.ehdr64->e_type));
    printf("Architecture: %s\n", elf_machine_string(elf.ehdr64->e_machine));
    printf("Entry Point: 0x%lx\n", elf.ehdr64->e_entry);

    elf_close(&elf);
    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_elf_open()             // File handling
#[test] fn test_magic_check()          // 2.6.2.a
#[test] fn test_class_detection()      // 2.6.2.b
#[test] fn test_endian_detection()     // 2.6.2.c
#[test] fn test_type_detection()       // 2.6.2.f
#[test] fn test_machine_detection()    // 2.6.2.g
#[test] fn test_entry_point()          // 2.6.2.h
#[test] fn test_header_display()       // 2.6.2.l
```

---

## Bareme

| Critere | Points |
|---------|--------|
| File formats (2.6.1) | 20 |
| Magic/Ident (2.6.2.a-e) | 25 |
| Header fields (2.6.2.f-k) | 35 |
| Display (2.6.2.l) | 20 |
| **Total** | **100** |

---

## Fichiers

```
ex00/
├── elf_parser.h
├── elf_file.c
├── elf_ident.c
├── elf_header.c
├── display.c
└── Makefile
```
