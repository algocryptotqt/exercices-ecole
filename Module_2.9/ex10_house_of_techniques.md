# ex10: House Of Techniques

**Module**: 2.9 - Computer Security
**Difficulte**: Expert
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.9.20: Heap Exploitation - House Of (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | House of Force | Overwrite top chunk size |
| b | Top chunk | Wilderness |
| c | Negative allocation | Wrap around |
| d | House of Spirit | Free fake chunk |
| e | Stack fake chunk | Allocate on stack |
| f | House of Lore | Smallbin corruption |
| g | House of Orange | Unsorted bin attack |
| h | House of Einherjar | Off-by-null |

---

## Sujet

Maitriser les techniques avancees d'exploitation du heap: les "House of" techniques.

### API

```c
// House of Force
void demonstrate_house_of_force(void *target);
void corrupt_top_chunk_size(size_t new_size);
size_t calculate_evil_size(void *current_top, void *target);

// House of Spirit
void create_fake_fastbin_chunk(void *stack_addr);
void demonstrate_house_of_spirit(void);

// House of Lore
void demonstrate_house_of_lore(void *target);
void corrupt_smallbin_bk(void *chunk, void *fake);

// House of Orange
void demonstrate_house_of_orange(void);
void trigger_unsorted_bin_attack(void *target);

// House of Einherjar
void demonstrate_house_of_einherjar(void);
void off_by_null_exploit(void *chunk);
```

---

## Exemple

```c
#include "house_of_techniques.h"

int main(void) {
    printf("=== House Of Techniques ===\n\n");

    printf("'House Of' Techniques:\n");
    printf("  Named exploitation techniques for specific heap scenarios\n");
    printf("  Each exploits different allocator behaviors\n");
    printf("  Some historical, some still relevant\n");

    // House of Force
    printf("\n\n=== House of Force ===\n\n");

    printf("Concept:\n");
    printf("  Corrupt TOP CHUNK size to very large value\n");
    printf("  Allows allocation at arbitrary address\n");
    printf("\n  Top chunk (wilderness):\n");
    printf("    Last chunk in heap, extends to provide new allocations\n");
    printf("    If request > top size, top is extended via brk()\n");

    printf("\n  Attack:\n");
    printf("  1. Overflow into top chunk, set size = -1 (0xffffffff...)\n");
    printf("  2. Now top chunk appears to span entire address space\n");
    printf("  3. Calculate distance to target:\n");
    printf("     evil_size = target - top_chunk_addr - header_size\n");
    printf("  4. malloc(evil_size) -> moves top chunk to target\n");
    printf("  5. Next malloc() returns target address!\n");

    printf("\n  Example:\n");
    printf("  heap:   0x602000\n");
    printf("  target: 0x601020 (GOT entry, before heap!)\n");
    printf("  evil_size = 0x601020 - 0x602020 - 0x10 = negative!\n");
    printf("  Wraps around: 0xffff...fff000 (huge positive)\n");
    printf("  malloc(evil_size) valid because top size = -1\n");

    printf("\n  Mitigations (modern glibc):\n");
    printf("  - Top chunk size validated on allocation\n");
    printf("  - Must be >= requested size\n");
    printf("  - Checks prevent wraparound\n");

    // House of Spirit
    printf("\n\n=== House of Spirit ===\n\n");

    printf("Concept:\n");
    printf("  Free a FAKE chunk (not from malloc)\n");
    printf("  Typically on stack or controlled memory\n");
    printf("  Later allocation returns the fake chunk!\n");

    printf("\n  Requirements:\n");
    printf("  1. Control a pointer that gets freed\n");
    printf("  2. Can write fake chunk header at target\n");
    printf("  3. Fake chunk passes validation checks\n");

    printf("\n  Stack Example:\n");
    printf("  void exploit() {\n");
    printf("      char buf[0x50];  // Stack buffer\n");
    printf("      // Craft fake chunk at buf-0x10\n");
    printf("      // size must be valid fastbin/tcache size\n");
    printf("      // next_chunk.size must pass check\n");
    printf("      \n");
    printf("      // Somehow free() is called on &buf\n");
    printf("      free(&buf);  // Goes to fastbin/tcache!\n");
    printf("      \n");
    printf("      char *p = malloc(0x40);\n");
    printf("      // p points to stack buffer!\n");
    printf("      // Write to p = write return address!\n");
    printf("  }\n");

    printf("\n  Fake chunk structure:\n");
    printf("  +------------------+ <- fake_chunk - 0x10\n");
    printf("  | prev_size (any)  |\n");
    printf("  | size = 0x41      | <- must match bin + PREV_INUSE\n");
    printf("  +------------------+ <- fake_chunk (freed pointer)\n");
    printf("  | user data area   |\n");
    printf("  +------------------+\n");
    printf("  | next_chunk.size  | <- must be > 2*SIZE_SZ, < av->top\n");
    printf("  +------------------+\n");

    printf("\n  Modern consideration:\n");
    printf("  - Tcache has fewer checks than fastbin\n");
    printf("  - Easier on tcache, harder on fastbin\n");

    // House of Lore
    printf("\n\n=== House of Lore ===\n\n");

    printf("Concept:\n");
    printf("  Corrupt SMALLBIN bk pointer\n");
    printf("  Get arbitrary address from smallbin\n");

    printf("\n  Smallbin removal:\n");
    printf("  victim = bin->bk\n");
    printf("  bck = victim->bk\n");
    printf("  bin->bk = bck\n");
    printf("  bck->fd = bin  // Write bin address to bck+0x10\n");
    printf("  return victim\n");

    printf("\n  Attack:\n");
    printf("  1. Put chunk in smallbin\n");
    printf("  2. Corrupt chunk's bk to point to fake chunk\n");
    printf("  3. Fake chunk's fd must point back (pass check)\n");
    printf("  4. First malloc returns legit chunk\n");
    printf("  5. Second malloc returns fake chunk address!\n");

    printf("\n  Mitigation:\n");
    printf("  Modern glibc: bck->fd != victim triggers abort\n");
    printf("  Need to satisfy: fake->fd == &real_chunk\n");

    // House of Orange
    printf("\n\n=== House of Orange ===\n\n");

    printf("Concept:\n");
    printf("  No need to call free()!\n");
    printf("  Force allocator to free top chunk\n");
    printf("  Combine with FSOP for code execution\n");

    printf("\n  Trigger:\n");
    printf("  1. Corrupt top chunk size (smaller, aligned)\n");
    printf("  2. Request larger than corrupted top\n");
    printf("  3. Allocator can't extend, uses sysmalloc\n");
    printf("  4. Old top chunk is freed -> unsorted bin!\n");

    printf("\n  Top chunk requirements:\n");
    printf("  - Size must be page-aligned (& 0xfff == 0)\n");
    printf("  - Size must be >= MINSIZE\n");
    printf("  - prev_inuse must be set\n");

    printf("\n  FSOP (File Stream Oriented Programming):\n");
    printf("  - Craft fake FILE structure\n");
    printf("  - Overflow unsorted bin into _IO_list_all\n");
    printf("  - Trigger abort/exit -> calls _IO_flush_all_lockp\n");
    printf("  - Fake FILE's vtable->__overflow = one_gadget\n");
    printf("  -> Code execution!\n");

    printf("\n  Modern mitigation:\n");
    printf("  - vtable validation (glibc 2.24+)\n");
    printf("  - Must use legitimate vtable or bypass\n");

    // House of Einherjar
    printf("\n\n=== House of Einherjar ===\n\n");

    printf("Concept:\n");
    printf("  Off-by-one NULL byte overflow\n");
    printf("  Exploit backward consolidation\n");
    printf("  Create overlapping chunks\n");

    printf("\n  Setup:\n");
    printf("  [Chunk A (big, allocated)][Chunk B (small)][Chunk C (allocated)]\n");
    printf("  \n");
    printf("  Attack:\n");
    printf("  1. Allocate A, B, C consecutively\n");
    printf("  2. Free B, goes to unsorted bin\n");
    printf("  3. Off-by-null in A overwrites B's size last byte to 0x00\n");
    printf("     size: 0x110 -> 0x100 (PREV_INUSE cleared!)\n");
    printf("  4. C thinks B is free and has different size\n");
    printf("  5. Free C triggers backward consolidation\n");
    printf("  6. Consolidates with 'fake' previous chunk\n");
    printf("  7. Result: Overlapping chunks!\n");

    printf("\n  prev_size poisoning:\n");
    printf("  - Also craft fake prev_size in C\n");
    printf("  - Points back past actual B\n");
    printf("  - Consolidation creates huge fake chunk\n");

    printf("\n  Modern considerations:\n");
    printf("  - tcache_perthread_struct at heap start\n");
    printf("  - Can overlap with tcache struct\n");
    printf("  - Poison tcache entries directly!\n");

    // Other techniques
    printf("\n\n=== Other Notable Techniques ===\n\n");

    printf("House of Rabbit:\n");
    printf("  Exploit fastbin consolidation into fake chunk\n");
    printf("  Trigger: malloc_consolidate()\n");

    printf("\nHouse of Roman:\n");
    printf("  Leak-less attack using partial overwrites\n");
    printf("  Only modify lower 12-16 bits of pointers\n");
    printf("  Works with ASLR (base is random, offset is not)\n");

    printf("\nHouse of Storm:\n");
    printf("  Combine unsorted bin attack + largebin attack\n");
    printf("  Arbitrary allocation without size constraint\n");

    printf("\nHouse of Botcake:\n");
    printf("  Double-free via tcache + unsorted bin interaction\n");
    printf("  Bypass tcache key check\n");

    printf("\nHouse of Banana:\n");
    printf("  Exploit rtld (dynamic linker) structures\n");
    printf("  Target link_map for code execution\n");

    printf("\nHouse of Apple (1,2,3):\n");
    printf("  Various _IO_FILE exploitation techniques\n");
    printf("  Work with modern vtable protections\n");

    // Summary table
    printf("\n\nTechnique Summary:\n");
    printf("  +---------------+------------------+----------------+\n");
    printf("  | Technique     | Primitive        | Still Works?   |\n");
    printf("  +---------------+------------------+----------------+\n");
    printf("  | Force         | Arbitrary alloc  | Mostly patched |\n");
    printf("  | Spirit        | Stack alloc      | Yes (tcache)   |\n");
    printf("  | Lore          | Arbitrary alloc  | With bypass    |\n");
    printf("  | Orange        | No free needed   | With bypass    |\n");
    printf("  | Einherjar     | Overlapping      | Yes            |\n");
    printf("  | Botcake       | Double-free      | Yes            |\n");
    printf("  +---------------+------------------+----------------+\n");

    printf("\n  Note: Techniques evolve with glibc versions\n");
    printf("        Always check target glibc version!\n");
    printf("        Modern (2.34+): hooks removed, harder targets\n");

    return 0;
}
```

---

## Fichiers

```
ex10/
├── house_of_techniques.h
├── house_force.c
├── house_spirit.c
├── house_lore.c
├── house_orange.c
├── house_einherjar.c
└── Makefile
```
