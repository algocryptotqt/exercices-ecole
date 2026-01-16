# ex09: Heap Exploitation - Tcache & Fastbin

**Module**: 2.9 - Computer Security
**Difficulte**: Expert
**Duree**: 5h
**Score qualite**: 98/100

## Concepts Couverts

### 2.9.18: Heap Exploitation - Tcache (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Tcache | Thread-local cache (glibc 2.26+) |
| b | Tcache structure | Per-thread, per-size bins |
| c | LIFO | Last freed, first allocated |
| d | No security checks | Originally |
| e | Tcache poisoning | Overwrite next pointer |
| f | Double free | Tcache allows |
| g | Arbitrary allocation | Controlled address |
| h | Mitigations | Key field (glibc 2.29+) |

### 2.9.19: Heap Exploitation - Fastbin (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Fastbin | Small chunks <= 0x80 |
| b | LIFO | Singly-linked |
| c | No coalescing | Speed optimization |
| d | Fastbin dup | Double free to duplicate |
| e | Fastbin attack | Corrupt fd pointer |
| f | Size check | Must match bin |
| g | Fake chunk | Create at target |
| h | malloc_hook | Common target |

---

## Sujet

Comprendre et exploiter les caches tcache et fastbin du heap glibc.

### Structures

```c
// Tcache per-thread structure
typedef struct tcache_perthread_struct {
    uint16_t counts[64];              // Number of chunks per bin
    void *entries[64];                // Head of each bin
} tcache_perthread_t;

// Tcache entry (in chunk)
typedef struct tcache_entry {
    struct tcache_entry *next;        // Next in list
    void *key;                        // Double-free detection (2.29+)
} tcache_entry_t;

// Fastbin array (in malloc_state)
typedef struct {
    void *fastbinsY[10];              // LIFO lists by size
} fastbins_t;
```

### API

```c
// Tcache operations
void dump_tcache_bins(void);
int tcache_count(size_t size);
void *tcache_get_entry(size_t size);
void tcache_poison(void *chunk, void *target);

// Fastbin operations
void dump_fastbins(void);
void fastbin_poison(void *chunk, void *target);
void create_fake_chunk(void *addr, size_t size);

// Exploit primitives
void demonstrate_tcache_poisoning(void);
void demonstrate_tcache_double_free(void);
void demonstrate_fastbin_dup(void);
void demonstrate_arbitrary_alloc(void *target);
```

---

## Exemple

```c
#include "heap_tcache_fastbin.h"

int main(void) {
    // 2.9.18: Tcache Exploitation
    printf("=== Tcache Exploitation ===\n\n");

    // Tcache introduction
    printf("Tcache (Thread Cache) - glibc 2.26+\n");
    printf("  Purpose: Speed up small allocations\n");
    printf("  Per-thread cache, checked BEFORE bins\n");
    printf("\n  Structure:\n");
    printf("    64 bins, sizes 0x20 to 0x410 (step 0x10)\n");
    printf("    Each bin holds up to 7 chunks (default)\n");
    printf("    LIFO: Last freed = first allocated\n");
    printf("    Singly-linked through 'next' pointer\n");

    printf("\n  Tcache Entry (in freed chunk):\n");
    printf("    +------------+\n");
    printf("    | next       | -> next free chunk (or NULL)\n");
    printf("    +------------+\n");
    printf("    | key        | -> tcache_perthread (2.29+)\n");
    printf("    +------------+\n");

    // Tcache demonstration
    printf("\n\nTcache Demonstration:\n");
    void *p1 = malloc(0x20);
    void *p2 = malloc(0x20);
    void *p3 = malloc(0x20);

    printf("  Allocated: p1=%p, p2=%p, p3=%p\n", p1, p2, p3);

    free(p1);
    printf("  free(p1) -> tcache[0x30]: p1 -> NULL\n");
    free(p2);
    printf("  free(p2) -> tcache[0x30]: p2 -> p1 -> NULL\n");
    free(p3);
    printf("  free(p3) -> tcache[0x30]: p3 -> p2 -> p1 -> NULL\n");

    dump_tcache_bins();

    void *a = malloc(0x20);
    printf("\n  malloc(0x20) returns %p (was p3)\n", a);
    void *b = malloc(0x20);
    printf("  malloc(0x20) returns %p (was p2)\n", b);

    // Original tcache vulnerabilities (pre-2.29)
    printf("\n\nOriginal Tcache Weaknesses (glibc < 2.29):\n");
    printf("  1. NO double-free check!\n");
    printf("  2. NO pointer validation!\n");
    printf("  3. Easy to exploit\n");

    // Tcache poisoning
    printf("\n\n=== Tcache Poisoning ===\n\n");

    printf("Attack Concept:\n");
    printf("  1. Allocate and free chunk (goes to tcache)\n");
    printf("  2. Use UAF/overflow to corrupt 'next' pointer\n");
    printf("  3. malloc() returns arbitrary address!\n");

    printf("\n  Exploit steps:\n");
    printf("  chunk = malloc(0x20)\n");
    printf("  free(chunk)           // tcache: chunk -> NULL\n");
    printf("  chunk->next = target  // Corrupt via UAF/overflow\n");
    printf("  malloc(0x20)          // Returns chunk\n");
    printf("  malloc(0x20)          // Returns TARGET!\n");

    // Demonstrate (simplified)
    printf("\n  Demonstration:\n");
    char *victim = malloc(0x20);
    free(victim);

    // Simulate UAF write (in real exploit, this is the bug)
    uint64_t target_addr = 0x404040;  // Example target
    printf("    Corrupting freed chunk's next to 0x%lx\n", target_addr);
    *(uint64_t*)victim = target_addr;  // UAF write

    printf("    malloc(0x20) -> returns victim\n");
    printf("    malloc(0x20) -> would return 0x%lx!\n", target_addr);

    // Tcache double-free
    printf("\n\n=== Tcache Double-Free (pre-2.29) ===\n\n");

    printf("Original behavior (no check):\n");
    printf("  chunk = malloc(0x20)\n");
    printf("  free(chunk)  // tcache: chunk -> NULL\n");
    printf("  free(chunk)  // tcache: chunk -> chunk! (loop)\n");
    printf("  a = malloc(0x20)  // Returns chunk\n");
    printf("  b = malloc(0x20)  // Returns chunk AGAIN!\n");
    printf("  // a == b, write to a affects b!\n");

    // glibc 2.29+ mitigation
    printf("\n\nglibc 2.29+ Mitigation:\n");
    printf("  Added 'key' field = tcache_perthread address\n");
    printf("  On free: chunk->key = tcache\n");
    printf("  Check: if chunk->key == tcache, abort!\n");
    printf("\n  Bypass:\n");
    printf("  - Corrupt key field before second free\n");
    printf("  - Requires write primitive to freed chunk\n");

    // 2.9.19: Fastbin Exploitation
    printf("\n\n=== Fastbin Exploitation ===\n\n");

    // Fastbin introduction
    printf("Fastbins:\n");
    printf("  Size range: 0x20 - 0x80 (64-bit)\n");
    printf("  10 bins, one per size class\n");
    printf("  LIFO: Last freed = first allocated\n");
    printf("  Singly-linked (fd pointer only)\n");
    printf("  NO COALESCING: Adjacent free chunks stay separate\n");
    printf("\n  Note: With tcache, fastbins only used after tcache full\n");

    // Fastbin dup
    printf("\n\n=== Fastbin Dup (Double-Free) ===\n\n");

    printf("Fastbin Double-Free:\n");
    printf("  Fastbin only checks if freeing same as head\n");
    printf("  Bypass: free(A), free(B), free(A)\n");

    printf("\n  Attack:\n");
    printf("  A = malloc(0x40)\n");
    printf("  B = malloc(0x40)\n");
    printf("  free(A)  // fastbin: A -> NULL\n");
    printf("  free(B)  // fastbin: B -> A -> NULL\n");
    printf("  free(A)  // fastbin: A -> B -> A (CYCLE!)\n");
    printf("  \n");
    printf("  x = malloc(0x40)  // Returns A\n");
    printf("  y = malloc(0x40)  // Returns B\n");
    printf("  z = malloc(0x40)  // Returns A again!\n");
    printf("  // x == z, overlapping allocations\n");

    // Fill tcache first (modern glibc)
    printf("\n  Modern glibc (with tcache):\n");
    printf("  Must fill tcache first (7 frees of same size)\n");
    printf("  Then chunks go to fastbin\n");

    // Fastbin attack with fake chunk
    printf("\n\n=== Fastbin Attack (Arbitrary Alloc) ===\n\n");

    printf("Goal: Get malloc() to return arbitrary address\n");
    printf("\n  Method:\n");
    printf("  1. Free chunks to get one in fastbin\n");
    printf("  2. Corrupt fd pointer to target address\n");
    printf("  3. Target must have valid-looking size!\n");
    printf("  4. malloc() eventually returns target\n");

    printf("\n  Size Check:\n");
    printf("  Fastbin verifies: chunk_size matches bin size\n");
    printf("  Must find/create fake size field at target-0x8\n");

    printf("\n  Common trick: __malloc_hook area\n");
    printf("  __malloc_hook is at libc+offset\n");
    printf("  Nearby memory often has values like 0x7f\n");
    printf("  0x7f interpreted as size 0x70 (fastbin 0x70)\n");
    printf("  Allocate 0x60, get chunk overlapping hook!\n");

    // Fake chunk demonstration
    printf("\n  Example target: __malloc_hook area\n");
    printf("  libc:    ...00 00 00 00 7f 00 00 00...\n");
    printf("                         ^^ looks like size 0x70!\n");
    printf("  Offset:  -0x23 from __malloc_hook\n");
    printf("  Get allocation, write shellcode addr to hook\n");
    printf("  Next malloc() calls our code!\n");

    // Step by step
    printf("\n  Exploitation steps:\n");
    printf("  1. Leak libc address (via unsorted bin or other)\n");
    printf("  2. Calculate fake chunk address\n");
    printf("  3. Fill tcache (7 frees)\n");
    printf("  4. Double-free in fastbin: A, B, A\n");
    printf("  5. malloc() returns A, write fake_chunk addr to fd\n");
    printf("  6. malloc() returns B\n");
    printf("  7. malloc() returns A\n");
    printf("  8. malloc() returns FAKE CHUNK!\n");
    printf("  9. Write one_gadget/system addr to __malloc_hook\n");
    printf("  10. Trigger malloc() -> shell!\n");

    // Modern mitigations
    printf("\n\n=== Modern Mitigations ===\n\n");

    printf("glibc Security Additions:\n");
    printf("\n  Tcache:\n");
    printf("    2.29: key field (double-free detect)\n");
    printf("    2.32: Safe-linking (XOR pointer with heap addr)\n");

    printf("\n  Fastbins:\n");
    printf("    2.32: Safe-linking\n");

    printf("\n  General:\n");
    printf("    2.34: Removed __malloc_hook, __free_hook!\n");
    printf("          Must find other targets\n");

    printf("\n  Safe-linking (2.32+):\n");
    printf("    next = actual_next ^ (chunk_addr >> 12)\n");
    printf("    Attacker must know/leak heap base\n");
    printf("    Bypassed with heap address leak\n");

    // Alternative targets
    printf("\n\nAlternative Targets (post-2.34):\n");
    printf("  - GOT entries (if partial RELRO)\n");
    printf("  - __exit_funcs (called at exit)\n");
    printf("  - IO_FILE vtables (file operations)\n");
    printf("  - Stack (if address known)\n");
    printf("  - Application function pointers\n");

    printf("\n\nSummary:\n");
    printf("  Tcache: Fastest, easiest to exploit\n");
    printf("    - Poison 'next' for arbitrary alloc\n");
    printf("    - Double-free (bypass key in 2.29+)\n");
    printf("  Fastbin: After tcache full\n");
    printf("    - Double-free via A-B-A pattern\n");
    printf("    - Size check requires fake chunk\n");
    printf("  Both lead to arbitrary write -> code execution\n");

    return 0;
}
```

---

## Fichiers

```
ex09/
├── heap_tcache_fastbin.h
├── tcache.c
├── fastbin.c
├── poison.c
├── double_free.c
└── Makefile
```
