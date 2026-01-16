# PROJET: ELF Toolkit & Linker

**Module**: 2.6 - ELF, Linking & Loading
**Difficulte**: Tres difficile
**Duree**: 20h
**Score qualite**: 98/100

## Objectif

Creer une suite d'outils ELF complete integrant tous les concepts du module 2.6.

## Concepts Couverts (PROJET 2.6)

| Ref | Concept | Implementation |
|-----|---------|----------------|
| a | ELF parser | Read and display ELF |
| b | Header display | Like readelf -h |
| c | Section display | Like readelf -S |
| d | Segment display | Like readelf -l |
| e | Symbol table | Like nm |
| f | Relocation display | Like readelf -r |
| g | Dynamic section | Like readelf -d |
| h | Disassembler | Basic x86-64 |
| i | Simple linker | Link two objects |
| j | Relocation processing | Apply relocations |
| k | Dynamic loader | dlopen implementation |
| l | LD_PRELOAD tool | Interposition |
| m | **Bonus**: Packer | Simple ELF packer |
| n | **Bonus**: Unpacker | Unpack packed ELF |

---

## Sujet

Implementer un toolkit ELF complet sous forme de commandes CLI.

### Architecture

```
elf-toolkit/
├── include/
│   ├── elf_common.h       # Shared definitions
│   ├── elf_parser.h       # ELF parsing
│   ├── elf_display.h      # Display functions
│   ├── elf_symbols.h      # Symbol handling
│   ├── elf_reloc.h        # Relocations
│   ├── elf_dynamic.h      # Dynamic linking
│   ├── linker.h           # Linker implementation
│   ├── loader.h           # Dynamic loader
│   └── disasm.h           # Disassembler
├── src/
│   ├── common/
│   │   ├── elf_file.c     # File handling, mmap
│   │   ├── elf_validate.c # Validation
│   │   └── utils.c        # Utilities
│   ├── parser/
│   │   ├── header.c       # a-b: ELF header
│   │   ├── sections.c     # c: Sections
│   │   ├── segments.c     # d: Segments
│   │   ├── symbols.c      # e: Symbol tables
│   │   ├── strings.c      # String tables
│   │   ├── relocs.c       # f: Relocations
│   │   └── dynamic.c      # g: Dynamic section
│   ├── display/
│   │   ├── readelf.c      # readelf-like output
│   │   ├── nm.c           # e: nm-like output
│   │   └── hexdump.c      # Hex dumping
│   ├── disasm/
│   │   └── x86_64.c       # h: x86-64 disassembler
│   ├── linker/
│   │   ├── object.c       # Object file handling
│   │   ├── symbols.c      # i: Symbol resolution
│   │   ├── reloc.c        # j: Relocation processing
│   │   ├── layout.c       # Section layout
│   │   └── output.c       # Write ELF output
│   ├── loader/
│   │   ├── dlopen.c       # k: dlopen implementation
│   │   ├── resolve.c      # Symbol resolution
│   │   └── relocate.c     # Runtime relocation
│   ├── tools/
│   │   ├── preload.c      # l: LD_PRELOAD generator
│   │   ├── checksec.c     # Security checks
│   │   └── compare.c      # ELF comparison
│   ├── bonus/
│   │   ├── packer.c       # m: ELF packer
│   │   └── unpacker.c     # n: ELF unpacker
│   └── main.c             # CLI dispatcher
├── tests/
│   ├── test_parser.c
│   ├── test_linker.c
│   ├── test_loader.c
│   └── ...
└── Makefile
```

### Interface CLI

```bash
# ELF Information (readelf-like)
./elftool info file.elf              # Full info
./elftool header file.elf            # b: ELF header (-h)
./elftool sections file.elf          # c: Sections (-S)
./elftool segments file.elf          # d: Segments (-l)
./elftool symbols file.elf           # e: Symbol table (-s)
./elftool relocs file.elf            # f: Relocations (-r)
./elftool dynamic file.elf           # g: Dynamic section (-d)
./elftool all file.elf               # All of the above (-a)

# nm-like
./elftool nm file.elf                # e: List symbols
./elftool nm -u file.elf             # Undefined only
./elftool nm -g file.elf             # Global only

# Disassembly
./elftool disasm file.elf            # h: Disassemble .text
./elftool disasm -s .init file.elf   # Specific section
./elftool disasm -f main file.elf    # Specific function

# Linker
./elftool link -o output main.o helper.o    # i-j: Link objects
./elftool link -e main -o prog *.o          # Set entry point
./elftool link --static -o prog *.o *.a     # Static link

# Dynamic Loader
./elftool load ./libtest.so          # k: Load and inspect
./elftool dlsym ./lib.so symbol      # Find symbol

# LD_PRELOAD Tools
./elftool preload-gen -w malloc -w free -o trace.so  # l: Generate wrapper
./elftool preload-run ./trace.so ./program           # Run with preload

# Security
./elftool checksec file.elf          # Security analysis
./elftool compare file1.elf file2.elf # Compare ELFs

# Bonus
./elftool pack file.elf packed.elf   # m: Pack ELF
./elftool unpack packed.elf orig.elf # n: Unpack ELF
```

---

## Specifications

### a-g: ELF Parser & Display

```c
// Main ELF context
typedef struct {
    int fd;
    void *mapped;
    size_t size;
    bool is_64bit;

    // Headers
    union {
        Elf64_Ehdr *ehdr64;
        Elf32_Ehdr *ehdr32;
    };

    // Parsed data
    elf_section_t *sections;
    int section_count;
    elf_segment_t *segments;
    int segment_count;
    elf_symbol_t *symbols;
    int symbol_count;
    elf_reloc_t *relocs;
    int reloc_count;
    dynamic_section_t dynamic;
} elf_context_t;

// Parser API
int elf_open(elf_context_t *ctx, const char *path);
void elf_close(elf_context_t *ctx);

// Display modes
typedef enum {
    DISPLAY_HEADER,      // b
    DISPLAY_SECTIONS,    // c
    DISPLAY_SEGMENTS,    // d
    DISPLAY_SYMBOLS,     // e
    DISPLAY_RELOCS,      // f
    DISPLAY_DYNAMIC,     // g
    DISPLAY_ALL
} display_mode_t;

void elf_display(elf_context_t *ctx, display_mode_t mode);
```

### h: Disassembler

```c
// x86-64 instruction
typedef struct {
    uint64_t address;
    uint8_t bytes[15];
    int length;
    char mnemonic[32];
    char operands[128];
} x86_instruction_t;

// Disassembler context
typedef struct {
    uint8_t *code;
    size_t size;
    uint64_t base_addr;
    elf_symbol_t *symbols;  // For annotation
    int symbol_count;
} disasm_context_t;

int disasm_init(disasm_context_t *ctx, elf_context_t *elf,
                const char *section);
int disasm_next(disasm_context_t *ctx, x86_instruction_t *instr);
void disasm_print(const x86_instruction_t *instr);
void disasm_function(disasm_context_t *ctx, const char *name);
```

### i-j: Linker

```c
// Linker configuration
typedef struct {
    char **input_files;
    int input_count;
    char **libraries;        // Static libraries
    int library_count;
    char *output_path;
    char *entry_symbol;
    uint64_t text_base;
    uint64_t data_base;
    bool emit_relocs;       // Keep relocations
    bool strip_symbols;
} linker_config_t;

// Linker context
typedef struct {
    linker_config_t config;
    object_file_t *objects;
    int object_count;
    symbol_table_t symtab;
    reloc_list_t relocs;
    section_layout_t layout;
} linker_context_t;

// Linker API
int linker_init(linker_context_t *ctx, const linker_config_t *config);
int linker_add_object(linker_context_t *ctx, const char *path);
int linker_add_library(linker_context_t *ctx, const char *path);
int linker_resolve_symbols(linker_context_t *ctx);
int linker_layout_sections(linker_context_t *ctx);
int linker_apply_relocations(linker_context_t *ctx);
int linker_write_output(linker_context_t *ctx);
void linker_cleanup(linker_context_t *ctx);
```

### k: Dynamic Loader

```c
// Loaded library
typedef struct loaded_lib {
    char *path;
    void *base;              // Load address
    size_t size;
    Elf64_Dyn *dynamic;      // .dynamic section
    elf_symbol_t *symbols;
    int symbol_count;
    struct loaded_lib **deps;// Dependencies
    int dep_count;
    int ref_count;
    bool initialized;
} loaded_lib_t;

// Loader context
typedef struct {
    loaded_lib_t **libraries;
    int lib_count;
    char **search_paths;
    int path_count;
    bool lazy_binding;
} loader_context_t;

// Custom dlopen implementation
void *my_dlopen(const char *path, int flags);
void *my_dlsym(void *handle, const char *symbol);
int my_dlclose(void *handle);
char *my_dlerror(void);

// Internal API
int loader_init(loader_context_t *ctx);
loaded_lib_t *loader_load(loader_context_t *ctx, const char *path);
void *loader_resolve(loader_context_t *ctx, const char *symbol);
int loader_relocate(loaded_lib_t *lib);
```

### l: LD_PRELOAD Generator

```c
// Wrapper specification
typedef struct {
    char *function_name;
    char *return_type;
    char **param_types;
    char **param_names;
    int param_count;
    bool log_calls;
    bool measure_time;
    char *custom_before;     // Custom code before call
    char *custom_after;      // Custom code after call
} wrapper_spec_t;

// Generator API
int preload_gen_init(const char *output_path);
int preload_gen_add_wrapper(const wrapper_spec_t *spec);
int preload_gen_finish(void);

// Built-in wrappers
int preload_gen_malloc_tracker(const char *output);
int preload_gen_file_logger(const char *output);
int preload_gen_time_wrapper(const char *output);
```

### m-n: Packer/Unpacker (Bonus)

```c
// Packer configuration
typedef struct {
    bool compress;           // Compress sections
    bool encrypt;            // Encrypt code
    char *stub_path;         // Unpacker stub
} packer_config_t;

// Packer API
int packer_pack(const char *input, const char *output,
                const packer_config_t *config);
int packer_unpack(const char *input, const char *output);
```

---

## Exemple d'Utilisation

```c
// main.c - CLI dispatcher

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    const char *cmd = argv[1];

    // ELF Information
    if (strcmp(cmd, "info") == 0) {
        return cmd_info(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "header") == 0) {
        return cmd_display(argc - 1, argv + 1, DISPLAY_HEADER);
    }
    else if (strcmp(cmd, "sections") == 0) {
        return cmd_display(argc - 1, argv + 1, DISPLAY_SECTIONS);
    }
    else if (strcmp(cmd, "segments") == 0) {
        return cmd_display(argc - 1, argv + 1, DISPLAY_SEGMENTS);
    }
    else if (strcmp(cmd, "symbols") == 0 || strcmp(cmd, "nm") == 0) {
        return cmd_symbols(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "relocs") == 0) {
        return cmd_display(argc - 1, argv + 1, DISPLAY_RELOCS);
    }
    else if (strcmp(cmd, "dynamic") == 0) {
        return cmd_display(argc - 1, argv + 1, DISPLAY_DYNAMIC);
    }
    // Disassembly
    else if (strcmp(cmd, "disasm") == 0) {
        return cmd_disasm(argc - 1, argv + 1);
    }
    // Linker
    else if (strcmp(cmd, "link") == 0) {
        return cmd_link(argc - 1, argv + 1);
    }
    // Loader
    else if (strcmp(cmd, "load") == 0) {
        return cmd_load(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "dlsym") == 0) {
        return cmd_dlsym(argc - 1, argv + 1);
    }
    // LD_PRELOAD
    else if (strcmp(cmd, "preload-gen") == 0) {
        return cmd_preload_gen(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "preload-run") == 0) {
        return cmd_preload_run(argc - 1, argv + 1);
    }
    // Security
    else if (strcmp(cmd, "checksec") == 0) {
        return cmd_checksec(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "compare") == 0) {
        return cmd_compare(argc - 1, argv + 1);
    }
    // Bonus
    else if (strcmp(cmd, "pack") == 0) {
        return cmd_pack(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "unpack") == 0) {
        return cmd_unpack(argc - 1, argv + 1);
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    return 1;
}
```

---

## Tests Moulinette

```rust
// Parser
#[test] fn test_elf_open()              // a
#[test] fn test_header_display()        // b
#[test] fn test_section_display()       // c
#[test] fn test_segment_display()       // d
#[test] fn test_symbol_display()        // e
#[test] fn test_reloc_display()         // f
#[test] fn test_dynamic_display()       // g

// Disassembler
#[test] fn test_disasm_basic()          // h
#[test] fn test_disasm_function()       // h

// Linker
#[test] fn test_link_two_objects()      // i
#[test] fn test_symbol_resolution()     // i
#[test] fn test_relocation_apply()      // j
#[test] fn test_output_runs()           // Integration

// Loader
#[test] fn test_loader_basic()          // k
#[test] fn test_loader_symbol()         // k
#[test] fn test_loader_deps()           // k

// LD_PRELOAD
#[test] fn test_preload_gen()           // l
#[test] fn test_preload_wrap()          // l

// Bonus
#[test] fn test_pack()                  // m
#[test] fn test_unpack()                // n
#[test] fn test_pack_unpack_roundtrip() // m+n

// Integration
#[test] fn test_cli_parsing()
#[test] fn test_full_workflow()
```

---

## Bareme

| Critere | Points |
|---------|--------|
| ELF Parser (a) | 10 |
| Display functions (b-g) | 20 |
| Disassembler (h) | 15 |
| Linker core (i-j) | 25 |
| Dynamic loader (k) | 15 |
| LD_PRELOAD tools (l) | 15 |
| **Base Total** | **100** |
| Bonus: Packer (m) | +10 |
| Bonus: Unpacker (n) | +10 |

---

## Fichiers

```
elf-toolkit/
├── include/
│   ├── elf_common.h
│   ├── elf_parser.h
│   ├── elf_display.h
│   ├── elf_symbols.h
│   ├── elf_reloc.h
│   ├── elf_dynamic.h
│   ├── linker.h
│   ├── loader.h
│   └── disasm.h
├── src/
│   ├── common/
│   ├── parser/
│   ├── display/
│   ├── disasm/
│   ├── linker/
│   ├── loader/
│   ├── tools/
│   ├── bonus/
│   └── main.c
├── tests/
└── Makefile
```

---

## Compilation

```makefile
CC = gcc
CFLAGS = -std=c17 -Wall -Wextra -O2 -I./include
LDFLAGS = -ldl

SRC_DIRS = src/common src/parser src/display src/disasm \
           src/linker src/loader src/tools
SRCS = $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c)) src/main.c
OBJS = $(SRCS:.c=.o)

all: elftool

elftool: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Bonus targets
bonus: elftool-full

elftool-full: $(OBJS) src/bonus/packer.o src/bonus/unpacker.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lz

test: elftool
	./run_tests.sh

.PHONY: all bonus test clean
```

---

## Criteres de Qualite

- Code C17 strict, pas de warnings
- Gestion complete des erreurs
- Pas de fuites memoire (valgrind clean)
- Support ELF32 et ELF64
- Compatible avec binaires Linux standards
- Documentation inline
- Tests automatises pour chaque composant
- Output conforme aux outils standards (readelf, nm, objdump)
