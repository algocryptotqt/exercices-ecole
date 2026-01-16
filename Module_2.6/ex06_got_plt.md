# ex06: GOT & PLT Deep Dive

**Module**: 2.6 - ELF, Linking & Loading
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.6.12: Global Offset Table (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | GOT purpose | Data indirection |
| b | .got section | For data |
| c | .got.plt section | For functions |
| d | GOT entries | Filled by dynamic linker |
| e | PIC data access | Load from GOT |
| f | GOT[0] | Dynamic section address |
| g | GOT[1] | Link map |
| h | GOT[2] | _dl_runtime_resolve |
| i | objdump -R | View GOT entries |

### 2.6.13: Procedure Linkage Table (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | PLT purpose | Function indirection |
| b | PLT entry | Small stub |
| c | PLT[0] | Resolver stub |
| d | First call | Jumps to resolver |
| e | Lazy resolution | Resolve and patch GOT |
| f | Subsequent calls | Direct jump |
| g | Eager binding | LD_BIND_NOW |
| h | objdump -d | View PLT |

---

## Sujet

Analyser en profondeur les mecanismes GOT et PLT.

### Structures

```c
#include <elf.h>

// 2.6.12: GOT structure
typedef struct {
    uint64_t address;        // GOT address in memory
    uint64_t *entries;       // GOT entries array
    int entry_count;
    // Special entries
    uint64_t dynamic_addr;   // f: GOT[0] - _DYNAMIC
    uint64_t link_map;       // g: GOT[1] - link_map
    uint64_t resolver;       // h: GOT[2] - _dl_runtime_resolve
} got_table_t;

// GOT entry details
typedef struct {
    int index;
    uint64_t address;        // Address of GOT slot
    uint64_t value;          // Current value in slot
    char *symbol;            // Associated symbol
    bool is_function;        // In .got.plt vs .got
    bool is_resolved;        // d: Has been patched
    uint64_t original_value; // Before resolution
} got_entry_detail_t;

// 2.6.13: PLT structure
typedef struct {
    uint64_t address;        // PLT base address
    int entry_count;
    uint8_t *code;           // PLT code
    size_t code_size;
    uint64_t got_plt_addr;   // Associated .got.plt
} plt_table_t;

// PLT entry details
typedef struct {
    int index;
    uint64_t address;        // PLT stub address
    char *symbol;            // Function name
    uint8_t code[16];        // b: PLT entry code
    uint64_t got_entry;      // Which GOT entry it uses
    uint64_t jmp_target;     // Where it jumps
} plt_entry_detail_t;

// Resolution state tracking
typedef struct {
    char *symbol;
    uint64_t plt_addr;
    uint64_t got_addr;
    uint64_t resolved_addr;  // Final function address
    int call_count;
    double first_call_ns;    // d: First call overhead
    double subsequent_ns;    // f: Subsequent call time
} resolution_trace_t;
```

### API

```c
// ============== GOT ANALYSIS ==============
// 2.6.12

// Parse GOT from ELF
int got_parse(const char *path, got_table_t *got);
void got_free(got_table_t *got);

// 2.6.12.a-c: Get GOT sections
int got_get_data_section(const char *path, uint64_t *addr, size_t *size);
int got_get_plt_section(const char *path, uint64_t *addr, size_t *size);

// 2.6.12.d: Get entry details
int got_get_entries(const char *path, got_entry_detail_t **entries, int *count);
void got_free_entries(got_entry_detail_t *entries, int count);

// 2.6.12.f-h: Get special entries
int got_get_special_entries(const char *path,
                            uint64_t *dynamic,    // GOT[0]
                            uint64_t *link_map,   // GOT[1]
                            uint64_t *resolver);  // GOT[2]

// 2.6.12.e: Show data access through GOT
void got_explain_data_access(const char *symbol);

// 2.6.12.i: Display like objdump -R
void got_print_relocations(const char *path);

// Read GOT entry at runtime (requires /proc/pid/mem or ptrace)
int got_read_runtime(pid_t pid, uint64_t got_addr, uint64_t *value);

// ============== PLT ANALYSIS ==============
// 2.6.13

// Parse PLT from ELF
int plt_parse(const char *path, plt_table_t *plt);
void plt_free(plt_table_t *plt);

// 2.6.13.b: Get PLT entries
int plt_get_entries(const char *path, plt_entry_detail_t **entries, int *count);
void plt_free_entries(plt_entry_detail_t *entries, int count);

// 2.6.13.c: Analyze PLT[0] resolver stub
void plt_analyze_resolver_stub(const char *path);

// 2.6.13.h: Display like objdump -d (PLT section)
void plt_disassemble(const char *path);

// Decode PLT entry
void plt_decode_entry(const plt_entry_detail_t *entry, char *description,
                      size_t max_len);

// ============== RESOLUTION TRACING ==============
// 2.6.13.d-f

// Trace lazy resolution
typedef void (*resolution_callback_t)(const char *symbol,
                                      uint64_t resolved_addr,
                                      void *user);

int trace_lazy_resolution(const char *program, char **argv,
                          resolution_callback_t callback, void *user);

// Demonstrate lazy vs eager
void demonstrate_resolution_difference(const char *program);

// 2.6.13.g: Force eager binding
void explain_ld_bind_now(void);

// ============== GOT/PLT INTERACTION ==============

// Show full call flow
void show_plt_got_interaction(const char *function_name);

// Simulate resolution
typedef struct {
    uint64_t plt_entry;
    uint64_t got_entry;
    uint64_t resolver;
    uint64_t target;
} resolution_step_t;

int simulate_resolution(const char *path, const char *function,
                        resolution_step_t *steps, int *step_count);

// ============== SECURITY IMPLICATIONS ==============

// GOT overwrite vulnerability explanation
void explain_got_overwrite(void);

// How RELRO protects GOT
void explain_relro_protection(void);
```

---

## Exemple

```c
#include "got_plt.h"

int main(int argc, char *argv[]) {
    const char *binary = argv[1] ? argv[1] : "./test_binary";

    // ============== GOT ANALYSIS ==============
    // 2.6.12

    printf("=== Global Offset Table (GOT) ===\n");

    got_table_t got;
    got_parse(binary, &got);

    printf("GOT address: 0x%lx\n", got.address);
    printf("Entry count: %d\n", got.entry_count);

    // 2.6.12.f-h: Special entries
    printf("\nSpecial GOT entries:\n");
    printf("  GOT[0] (_DYNAMIC):           0x%lx\n", got.dynamic_addr);
    printf("  GOT[1] (link_map):           0x%lx\n", got.link_map);
    printf("  GOT[2] (_dl_runtime_resolve): 0x%lx\n", got.resolver);

    // 2.6.12.d: GOT entry details
    got_entry_detail_t *entries;
    int entry_count;
    got_get_entries(binary, &entries, &entry_count);

    printf("\nGOT entries:\n");
    for (int i = 0; i < entry_count && i < 10; i++) {
        printf("  [%2d] 0x%lx: %-20s = 0x%lx %s\n",
               entries[i].index,
               entries[i].address,
               entries[i].symbol ? entries[i].symbol : "(reserved)",
               entries[i].value,
               entries[i].is_resolved ? "(resolved)" : "");
    }

    // 2.6.12.a-c: Sections
    uint64_t got_addr, got_plt_addr;
    size_t got_size, got_plt_size;
    got_get_data_section(binary, &got_addr, &got_size);
    got_get_plt_section(binary, &got_plt_addr, &got_plt_size);

    printf("\nGOT Sections:\n");
    printf("  .got     @ 0x%lx (size: %zu) - for data\n", got_addr, got_size);
    printf("  .got.plt @ 0x%lx (size: %zu) - for functions\n",
           got_plt_addr, got_plt_size);

    // 2.6.12.e: Data access
    printf("\n=== PIC Data Access (e) ===\n");
    got_explain_data_access("errno");
    /*
    Accessing 'errno' in PIC:
    1. Compiler generates: movq errno@GOTPCREL(%rip), %rax
    2. At runtime, GOT[errno] contains address of errno
    3. Code loads GOT entry, then dereferences
    */

    // 2.6.12.i: Relocations
    printf("\n=== GOT Relocations (objdump -R) ===\n");
    got_print_relocations(binary);
    /*
    DYNAMIC RELOCATION RECORDS
    OFFSET           TYPE              VALUE
    0000000000003fd8 R_X86_64_GLOB_DAT __libc_start_main@GLIBC_2.2.5
    0000000000003fe0 R_X86_64_GLOB_DAT __gmon_start__
    0000000000004000 R_X86_64_JUMP_SLOT printf@GLIBC_2.2.5
    ...
    */

    // ============== PLT ANALYSIS ==============
    // 2.6.13

    printf("\n=== Procedure Linkage Table (PLT) ===\n");

    plt_table_t plt;
    plt_parse(binary, &plt);

    printf("PLT address: 0x%lx\n", plt.address);
    printf("PLT size: %zu bytes\n", plt.code_size);
    printf("Entry count: %d\n", plt.entry_count);

    // 2.6.13.c: Resolver stub
    printf("\n=== PLT[0] Resolver Stub (c) ===\n");
    plt_analyze_resolver_stub(binary);
    /*
    PLT[0] at 0x1020:
      push   QWORD PTR [rip+0x2fe2]  # Push link_map (GOT[1])
      jmp    QWORD PTR [rip+0x2fe4]  # Jump to resolver (GOT[2])
    */

    // 2.6.13.b: PLT entries
    plt_entry_detail_t *plt_entries;
    int plt_count;
    plt_get_entries(binary, &plt_entries, &plt_count);

    printf("\n=== PLT Entries (b) ===\n");
    for (int i = 0; i < plt_count && i < 5; i++) {
        char desc[256];
        plt_decode_entry(&plt_entries[i], desc, sizeof(desc));
        printf("\n%s@plt (0x%lx):\n%s\n",
               plt_entries[i].symbol,
               plt_entries[i].address,
               desc);
    }
    /*
    printf@plt (0x1030):
      jmp    QWORD PTR [rip+0x2fd2]  # Jump to GOT[printf]
      push   0x0                      # Relocation index
      jmp    0x1020                   # Jump to PLT[0]
    */

    // 2.6.13.h: Full disassembly
    printf("\n=== PLT Disassembly (objdump -d) ===\n");
    plt_disassemble(binary);

    // ============== RESOLUTION FLOW ==============
    // 2.6.13.d-f

    printf("\n=== Lazy Resolution Flow ===\n");

    // 2.6.13.d: First call
    printf("\nFirst call to printf() (d):\n");
    printf("  1. call printf@plt         -> jump to PLT entry\n");
    printf("  2. jmp *GOT[printf]        -> GOT points back to PLT+6\n");
    printf("  3. push reloc_index        -> push relocation info\n");
    printf("  4. jmp PLT[0]              -> jump to resolver\n");
    printf("  5. push link_map           -> resolver args\n");
    printf("  6. jmp *GOT[2]             -> call _dl_runtime_resolve\n");
    printf("  7. Resolver finds printf, patches GOT[printf]\n");
    printf("  8. Jump to actual printf\n");

    // 2.6.13.f: Subsequent calls
    printf("\nSubsequent calls (f):\n");
    printf("  1. call printf@plt         -> jump to PLT entry\n");
    printf("  2. jmp *GOT[printf]        -> GOT now points to real printf\n");
    printf("  3. Direct execution of printf\n");

    // Simulate resolution
    resolution_step_t steps[10];
    int step_count;
    simulate_resolution(binary, "printf", steps, &step_count);

    // 2.6.13.g: Eager binding
    printf("\n=== Eager Binding (g) ===\n");
    explain_ld_bind_now();
    /*
    With LD_BIND_NOW=1 or RELRO Full:
    - All GOT entries resolved at load time
    - No lazy resolution overhead
    - Longer startup time
    - More secure (GOT can be read-only)
    */

    // ============== SECURITY ==============

    printf("\n=== Security Implications ===\n");

    explain_got_overwrite();
    /*
    GOT Overwrite Attack:
    - If attacker can write to GOT, they can redirect function calls
    - Example: Overwrite GOT[puts] with address of system()
    - Next call to puts("/bin/sh") actually calls system("/bin/sh")
    */

    explain_relro_protection();
    /*
    RELRO (RELocation Read-Only):
    - Partial RELRO: .got read-only, .got.plt writable
    - Full RELRO: All GOT sections read-only after resolution
    - Compile with: -Wl,-z,relro,-z,now
    */

    // ============== INTERACTION DEMO ==============

    printf("\n=== GOT/PLT Interaction ===\n");
    show_plt_got_interaction("printf");

    got_free(&got);
    plt_free(&plt);
    got_free_entries(entries, entry_count);
    plt_free_entries(plt_entries, plt_count);
    return 0;
}
```

---

## Tests Moulinette

```rust
// GOT
#[test] fn test_got_parse()             // 2.6.12.a-c
#[test] fn test_got_entries()           // 2.6.12.d
#[test] fn test_got_special()           // 2.6.12.f-h
#[test] fn test_got_relocations()       // 2.6.12.i

// PLT
#[test] fn test_plt_parse()             // 2.6.13.a-b
#[test] fn test_plt_resolver()          // 2.6.13.c
#[test] fn test_lazy_resolution()       // 2.6.13.d-e
#[test] fn test_subsequent_calls()      // 2.6.13.f
#[test] fn test_eager_binding()         // 2.6.13.g
#[test] fn test_plt_disasm()            // 2.6.13.h
```

---

## Bareme

| Critere | Points |
|---------|--------|
| GOT parsing (2.6.12.a-d) | 25 |
| GOT special entries (2.6.12.f-h) | 15 |
| PLT structure (2.6.13.a-c) | 20 |
| Resolution flow (2.6.13.d-f) | 25 |
| Eager binding & tools (2.6.13.g-h) | 15 |
| **Total** | **100** |

---

## Fichiers

```
ex06/
├── got_plt.h
├── got_parse.c
├── plt_parse.c
├── resolution.c
├── disasm.c
└── Makefile
```
