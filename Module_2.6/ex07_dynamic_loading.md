# ex07: Dynamic Section & Library Loading

**Module**: 2.6 - ELF, Linking & Loading
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.6.14: Dynamic Section (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | .dynamic | Dynamic linking info |
| b | DT_NEEDED | Required libraries |
| c | DT_SONAME | Library name |
| d | DT_SYMTAB | Symbol table |
| e | DT_STRTAB | String table |
| f | DT_PLTGOT | GOT address |
| g | DT_PLTRELSZ | PLT relocation size |
| h | DT_JMPREL | PLT relocations |
| i | DT_RELA | Other relocations |
| j | readelf -d | View dynamic section |

### 2.6.15: Library Loading (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Load sequence | Kernel then ld.so |
| b | Kernel role | Map executable, invoke interpreter |
| c | ld.so role | Load libraries, relocate, call main |
| d | Library search | Algorithm |
| e | LD_LIBRARY_PATH | User override |
| f | DT_RUNPATH | Embedded path |
| g | /etc/ld.so.cache | Cached search |
| h | Default paths | /lib, /usr/lib |
| i | Library versioning | .so.1.2.3 |
| j | Symbol versioning | @GLIBC_2.17 |

---

## Sujet

Parser la section dynamique et comprendre le processus de chargement.

### Structures

```c
#include <elf.h>

// 2.6.14: Dynamic entry
typedef struct {
    int64_t tag;             // DT_* type
    uint64_t value;          // Value or pointer
    char *tag_name;          // Human-readable name
    char *string_value;      // For string entries
} dynamic_entry_t;

// 2.6.14.a: Dynamic section
typedef struct {
    dynamic_entry_t *entries;
    int entry_count;

    // Common pointers (parsed from entries)
    char **needed;           // b: DT_NEEDED libraries
    int needed_count;
    char *soname;            // c: DT_SONAME
    uint64_t symtab;         // d: DT_SYMTAB
    uint64_t strtab;         // e: DT_STRTAB
    uint64_t strsz;
    uint64_t pltgot;         // f: DT_PLTGOT
    uint64_t pltrelsz;       // g: DT_PLTRELSZ
    uint64_t jmprel;         // h: DT_JMPREL
    uint64_t rela;           // i: DT_RELA
    uint64_t relasz;
} dynamic_section_t;

// 2.6.15: Load info
typedef struct {
    char *name;              // Library name
    char *path;              // Full path
    uint64_t load_addr;      // Where loaded
    uint64_t entry;          // Entry point (for executable)
    int load_order;          // When loaded
    char *search_method;     // How found (cache, path, default)
} load_info_t;

// Loading trace
typedef struct {
    load_info_t *libs;
    int lib_count;
    char **search_paths;     // d-h: Search paths used
    int path_count;
    double load_time_ms;
} load_trace_t;

// 2.6.15.i-j: Version info
typedef struct {
    char *library;
    char *version;           // i: .so.X.Y.Z
    char **symbol_versions;  // j: @GLIBC_2.17
    int version_count;
} version_info_t;
```

### API

```c
// ============== DYNAMIC SECTION ==============
// 2.6.14

// 2.6.14.a: Parse dynamic section
int dyn_parse(const char *path, dynamic_section_t *dyn);
void dyn_free(dynamic_section_t *dyn);

// Get specific entry
int dyn_get_entry(const dynamic_section_t *dyn, int64_t tag, uint64_t *value);
int dyn_get_string_entry(const dynamic_section_t *dyn, int64_t tag, char **str);

// 2.6.14.b: Get needed libraries
int dyn_get_needed(const char *path, char ***needed, int *count);

// 2.6.14.c: Get SONAME
int dyn_get_soname(const char *path, char **soname);

// Tag to string
const char *dyn_tag_string(int64_t tag);

// 2.6.14.j: Display like readelf -d
void dyn_print(const dynamic_section_t *dyn);
void dyn_print_file(const char *path);

// ============== LIBRARY LOADING ==============
// 2.6.15

// 2.6.15.a-c: Trace loading
int load_trace_program(const char *program, char **argv,
                       load_trace_t *trace);
void load_trace_free(load_trace_t *trace);

// Explain load sequence
void load_explain_sequence(void);

// 2.6.15.d-h: Search path handling
int load_get_search_paths(char ***paths, int *count);
int load_resolve_library(const char *name, const char *rpath,
                         char **resolved);
const char *load_get_search_method(const char *name, const char *found_path);

// 2.6.15.e: LD_LIBRARY_PATH
int load_parse_ld_library_path(char ***paths, int *count);

// 2.6.15.f: RUNPATH/RPATH
int load_get_runpath(const char *path, char **runpath);
int load_get_rpath(const char *path, char **rpath);

// 2.6.15.g: Cache operations
int load_cache_lookup(const char *name, char **path);
int load_cache_list(char ***entries, int *count);

// ============== VERSIONING ==============
// 2.6.15.i-j

// 2.6.15.i: Library version
int version_parse_soname(const char *soname, int *major, int *minor, int *patch);
int version_compare(const char *v1, const char *v2);

// 2.6.15.j: Symbol versioning
int version_get_symbol_versions(const char *path, const char *symbol,
                                char ***versions, int *count);
int version_get_needed_versions(const char *path, version_info_t **versions,
                                int *count);

// GNU version sections
int version_parse_verdef(const char *path);   // .gnu.version_d
int version_parse_verneed(const char *path);  // .gnu.version_r

// ============== ANALYSIS ==============

// Compare dynamic sections
int dyn_compare(const char *path1, const char *path2);

// Check ABI compatibility
int check_abi_compatibility(const char *executable, const char *library);
```

---

## Exemple

```c
#include "dynamic_loading.h"

int main(int argc, char *argv[]) {
    const char *binary = argv[1] ? argv[1] : "/bin/ls";

    // ============== DYNAMIC SECTION ==============
    // 2.6.14

    printf("=== Dynamic Section ===\n");

    dynamic_section_t dyn;
    dyn_parse(binary, &dyn);

    // 2.6.14.j: Print like readelf -d
    printf("\nDynamic section (readelf -d):\n");
    dyn_print(&dyn);
    /*
    Dynamic section at offset 0x2d90 contains 27 entries:
      Tag        Type                         Name/Value
     0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
     0x000000000000000c (INIT)               0x1000
     0x000000000000000d (FINI)               0x1234
     0x0000000000000019 (INIT_ARRAY)         0x3d70
     ...
    */

    // 2.6.14.b: NEEDED libraries
    printf("\n=== Required Libraries (DT_NEEDED) ===\n");
    for (int i = 0; i < dyn.needed_count; i++) {
        printf("  %s\n", dyn.needed[i]);
    }

    // 2.6.14.c: SONAME (for shared libs)
    if (dyn.soname) {
        printf("\nSONAME: %s\n", dyn.soname);
    }

    // 2.6.14.d-i: Key addresses
    printf("\n=== Dynamic Linking Addresses ===\n");
    printf("  DT_SYMTAB:   0x%lx\n", dyn.symtab);    // d
    printf("  DT_STRTAB:   0x%lx\n", dyn.strtab);    // e
    printf("  DT_PLTGOT:   0x%lx\n", dyn.pltgot);    // f
    printf("  DT_PLTRELSZ: %lu\n", dyn.pltrelsz);    // g
    printf("  DT_JMPREL:   0x%lx\n", dyn.jmprel);    // h
    printf("  DT_RELA:     0x%lx\n", dyn.rela);      // i

    // All entries
    printf("\n=== All Dynamic Entries ===\n");
    for (int i = 0; i < dyn.entry_count && i < 15; i++) {
        printf("  %-15s (0x%lx) = ",
               dyn.entries[i].tag_name, dyn.entries[i].tag);
        if (dyn.entries[i].string_value) {
            printf("%s\n", dyn.entries[i].string_value);
        } else {
            printf("0x%lx\n", dyn.entries[i].value);
        }
    }

    // ============== LOAD SEQUENCE ==============
    // 2.6.15.a-c

    printf("\n=== Loading Sequence ===\n");
    load_explain_sequence();
    /*
    1. Kernel loads executable
       - Maps ELF segments into memory
       - Sets up stack with argv, envp, auxv
       - Reads PT_INTERP to find dynamic linker

    2. Kernel invokes dynamic linker (ld.so)
       - ld.so is itself loaded by kernel

    3. Dynamic linker (ld.so) takes over
       - Reads .dynamic section
       - Loads DT_NEEDED libraries recursively
       - Performs relocations
       - Calls constructors (.init, .init_array)
       - Transfers control to entry point
    */

    // Trace actual loading
    load_trace_t trace;
    load_trace_program(binary, NULL, &trace);

    printf("\nLibraries loaded:\n");
    for (int i = 0; i < trace.lib_count; i++) {
        printf("  [%d] %s\n", trace.libs[i].load_order, trace.libs[i].path);
        printf("      @ 0x%lx (found via %s)\n",
               trace.libs[i].load_addr, trace.libs[i].search_method);
    }

    // ============== SEARCH PATHS ==============
    // 2.6.15.d-h

    printf("\n=== Library Search ===\n");

    // 2.6.15.d: Search algorithm
    printf("\nSearch order:\n");
    printf("  1. DT_RPATH (deprecated)\n");
    printf("  2. LD_LIBRARY_PATH (e)\n");
    printf("  3. DT_RUNPATH (f)\n");
    printf("  4. /etc/ld.so.cache (g)\n");
    printf("  5. Default paths: /lib, /usr/lib (h)\n");

    // 2.6.15.e: LD_LIBRARY_PATH
    char **ld_paths;
    int ld_count;
    if (load_parse_ld_library_path(&ld_paths, &ld_count) == 0) {
        printf("\nLD_LIBRARY_PATH:\n");
        for (int i = 0; i < ld_count; i++) {
            printf("  %s\n", ld_paths[i]);
        }
    }

    // 2.6.15.f: RUNPATH
    char *runpath;
    if (load_get_runpath(binary, &runpath) == 0) {
        printf("\nDT_RUNPATH: %s\n", runpath);
    }

    // 2.6.15.g: Cache lookup
    char *cached_path;
    if (load_cache_lookup("libc.so.6", &cached_path) == 0) {
        printf("\nlibc.so.6 in cache: %s\n", cached_path);
    }

    // Full search paths
    char **paths;
    int path_count;
    load_get_search_paths(&paths, &path_count);
    printf("\nComplete search paths:\n");
    for (int i = 0; i < path_count; i++) {
        printf("  %s\n", paths[i]);
    }

    // ============== VERSIONING ==============
    // 2.6.15.i-j

    printf("\n=== Library Versioning ===\n");

    // 2.6.15.i: SONAME version
    int major, minor, patch;
    version_parse_soname("libc.so.6", &major, &minor, &patch);
    printf("\nlibc.so.6 version: %d.%d.%d\n", major, minor, patch);

    // 2.6.15.j: Symbol versions
    printf("\nSymbol versioning:\n");
    version_info_t *versions;
    int ver_count;
    version_get_needed_versions(binary, &versions, &ver_count);

    for (int i = 0; i < ver_count; i++) {
        printf("\n  %s:\n", versions[i].library);
        for (int j = 0; j < versions[i].version_count; j++) {
            printf("    %s\n", versions[i].symbol_versions[j]);
        }
    }
    /*
    libc.so.6:
      GLIBC_2.2.5
      GLIBC_2.3
      GLIBC_2.17
    */

    // Specific symbol versions
    char **sym_vers;
    int sv_count;
    version_get_symbol_versions(binary, "printf", &sym_vers, &sv_count);
    printf("\nprintf versions required:\n");
    for (int i = 0; i < sv_count; i++) {
        printf("  %s\n", sym_vers[i]);  // @GLIBC_2.2.5
    }

    dyn_free(&dyn);
    load_trace_free(&trace);
    return 0;
}
```

---

## Tests Moulinette

```rust
// Dynamic section
#[test] fn test_dyn_parse()             // 2.6.14.a
#[test] fn test_dt_needed()             // 2.6.14.b
#[test] fn test_dt_soname()             // 2.6.14.c
#[test] fn test_dyn_addresses()         // 2.6.14.d-i
#[test] fn test_readelf_d()             // 2.6.14.j

// Library loading
#[test] fn test_load_trace()            // 2.6.15.a-c
#[test] fn test_search_paths()          // 2.6.15.d
#[test] fn test_ld_library_path()       // 2.6.15.e
#[test] fn test_runpath()               // 2.6.15.f
#[test] fn test_cache_lookup()          // 2.6.15.g
#[test] fn test_versioning()            // 2.6.15.i-j
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Dynamic section parsing (2.6.14.a-e) | 25 |
| Dynamic entries (2.6.14.f-j) | 20 |
| Load sequence (2.6.15.a-c) | 20 |
| Search paths (2.6.15.d-h) | 20 |
| Versioning (2.6.15.i-j) | 15 |
| **Total** | **100** |

---

## Fichiers

```
ex07/
├── dynamic_loading.h
├── dynamic_section.c
├── load_trace.c
├── search_paths.c
├── versioning.c
└── Makefile
```
