# ex04: Kernel Memory Management

**Module**: 2.7 - Kernel Development & OS Internals
**Difficulte**: Difficile
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.7.9: Kernel Memory Management (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Kernel address space | High memory |
| b | Identity mapping | Physical = virtual |
| c | vmalloc | Non-contiguous allocation |
| d | kmalloc | Contiguous allocation |
| e | slab allocator | Object caching |
| f | Page allocator | Buddy system |
| g | GFP flags | Allocation flags |
| h | High memory | > 896MB (32-bit) |
| i | Memory zones | DMA, Normal, HighMem |

---

## Sujet

Comprendre la gestion memoire dans le noyau Linux.

### Structures

```c
#include <stdint.h>

// 2.7.9.i: Memory zones
typedef enum {
    ZONE_DMA,                // Below 16MB (ISA DMA)
    ZONE_DMA32,              // Below 4GB (32-bit DMA)
    ZONE_NORMAL,             // Directly mapped
    ZONE_HIGHMEM,            // h: Above direct map
    ZONE_MOVABLE             // Hotplug/migration
} zone_type_t;

// Zone information
typedef struct {
    zone_type_t type;
    const char *name;
    uint64_t start_pfn;      // Start page frame number
    uint64_t end_pfn;
    uint64_t free_pages;
    uint64_t managed_pages;
} zone_info_t;

// 2.7.9.g: GFP flags
typedef enum {
    GFP_KERNEL = 0,          // Normal allocation
    GFP_ATOMIC = 1,          // Cannot sleep
    GFP_DMA = 2,             // DMA zone
    GFP_DMA32 = 4,           // DMA32 zone
    GFP_HIGHMEM = 8,         // Highmem allowed
    GFP_ZERO = 16,           // Zero the page
    GFP_NOFAIL = 32          // Must succeed
} gfp_flags_t;

// 2.7.9.e: Slab cache info
typedef struct {
    const char *name;
    size_t object_size;
    size_t slab_size;
    int objects_per_slab;
    uint64_t active_objs;
    uint64_t total_objs;
    uint64_t active_slabs;
    uint64_t total_slabs;
} slab_cache_info_t;

// 2.7.9.f: Buddy allocator info
typedef struct {
    int order;               // 2^order pages
    uint64_t free_count;
} buddy_order_info_t;
```

### API

```c
// ============== ADDRESS SPACE ==============
// 2.7.9.a-b

// 2.7.9.a: Kernel address space layout
typedef struct {
    uint64_t user_start, user_end;
    uint64_t kernel_start;
    uint64_t direct_map_start, direct_map_end;
    uint64_t vmalloc_start, vmalloc_end;
    uint64_t modules_start, modules_end;
} kernel_layout_t;

int get_kernel_layout(kernel_layout_t *layout);
void print_kernel_layout(void);

// 2.7.9.b: Identity/direct mapping
uint64_t phys_to_virt(uint64_t phys);
uint64_t virt_to_phys(uint64_t virt);
bool is_identity_mapped(uint64_t virt);

// ============== ALLOCATORS ==============
// 2.7.9.c-f

// 2.7.9.d: kmalloc simulation
void *my_kmalloc(size_t size, gfp_flags_t flags);
void my_kfree(void *ptr);
void explain_kmalloc(void);

// 2.7.9.c: vmalloc simulation
void *my_vmalloc(size_t size);
void my_vfree(void *ptr);
void explain_vmalloc(void);

// Difference between kmalloc and vmalloc
void compare_kmalloc_vmalloc(void);

// 2.7.9.e: Slab allocator
int get_slab_caches(slab_cache_info_t **caches, int *count);
void print_slab_info(void);
void explain_slab_allocator(void);

// 2.7.9.f: Page/buddy allocator
int get_buddy_info(buddy_order_info_t *orders, int max_order);
void print_buddy_info(void);
void explain_buddy_system(void);

// ============== GFP FLAGS ==============
// 2.7.9.g

const char *gfp_flags_string(gfp_flags_t flags);
void explain_gfp_flags(void);
gfp_flags_t recommend_gfp_flags(const char *context);

// ============== MEMORY ZONES ==============
// 2.7.9.h-i

// 2.7.9.i: Zone information
int get_zone_info(zone_info_t **zones, int *count);
void print_zone_info(void);

// 2.7.9.h: High memory
void explain_highmem(void);
bool needs_highmem(uint64_t phys_addr);

// kmap/kunmap for highmem
void *kmap(void *page);
void kunmap(void *page);
```

---

## Exemple

```c
#include "kernel_memory.h"

int main(void) {
    // ============== KERNEL ADDRESS SPACE ==============
    // 2.7.9.a

    printf("=== Kernel Address Space (a) ===\n");
    print_kernel_layout();
    /*
    x86-64 Linux Layout:
    0x0000000000000000 - 0x00007fffffffffff : User space (128TB)
    0xffff800000000000 - 0xffff87ffffffffff : Guard hole
    0xffff880000000000 - 0xffffc7ffffffffff : Direct mapping (64TB)
    0xffffc90000000000 - 0xffffe8ffffffffff : vmalloc space
    0xffffffffa0000000 - 0xffffffffff5fffff : Modules
    0xffffffff80000000 - 0xffffffffa0000000 : Kernel text
    */

    // 2.7.9.b: Direct/identity mapping
    printf("\n=== Direct Mapping (b) ===\n");
    printf("Physical memory mapped starting at 0xffff880000000000\n");
    printf("phys_to_virt(0x1000) = 0x%lx\n", phys_to_virt(0x1000));
    printf("virt_to_phys(0xffff880000001000) = 0x%lx\n",
           virt_to_phys(0xffff880000001000));

    // ============== ALLOCATORS ==============
    // 2.7.9.c-d

    printf("\n=== kmalloc vs vmalloc (c-d) ===\n");
    compare_kmalloc_vmalloc();
    /*
    kmalloc (d):
      - Physically contiguous memory
      - Fast allocation
      - Limited to a few MB
      - Uses slab allocator for small objects
      - Good for: DMA buffers, small allocations

    vmalloc (c):
      - Virtually contiguous, physically scattered
      - Slower (page table manipulation)
      - Can allocate large regions
      - Not usable for DMA
      - Good for: Large buffers, module loading
    */

    // kmalloc demo
    printf("\nkmalloc example:\n");
    void *buf = my_kmalloc(4096, GFP_KERNEL);
    printf("  Allocated 4KB at %p (physically contiguous)\n", buf);
    my_kfree(buf);

    // vmalloc demo
    printf("\nvmalloc example:\n");
    void *vbuf = my_vmalloc(1024 * 1024);
    printf("  Allocated 1MB at %p (virtually contiguous)\n", vbuf);
    my_vfree(vbuf);

    // 2.7.9.e: Slab allocator
    printf("\n=== Slab Allocator (e) ===\n");
    explain_slab_allocator();
    /*
    Slab allocator:
      - Cache frequently used object sizes
      - Reduces fragmentation
      - Faster than buddy for small objects
      - Per-CPU caches for performance

    Caches like:
      - kmalloc-32, kmalloc-64, kmalloc-128...
      - task_struct, inode_cache, dentry...
    */

    print_slab_info();
    /*
    Cache Name          ObjSize  Active  Total
    kmalloc-96              96    1024   1200
    kmalloc-192            192     512    600
    kmalloc-256            256     256    300
    task_struct           6144      89    100
    inode_cache            584     234    300
    dentry                 192    1502   1800
    */

    // 2.7.9.f: Buddy allocator
    printf("\n=== Buddy System (f) ===\n");
    explain_buddy_system();
    /*
    Buddy allocator:
      - Allocates in powers of 2 pages
      - Order 0 = 1 page (4KB)
      - Order 1 = 2 pages (8KB)
      - Order 10 = 1024 pages (4MB)

    Splitting:
      Request 16KB (order 2)
      If no order 2 free, split order 3 into two order 2
      Return one, keep other as free

    Coalescing:
      When freeing, check if buddy is also free
      If yes, combine into larger block
    */

    print_buddy_info();
    /*
    Order  Pages  Free
    0      1      5432
    1      2      2341
    2      4      1234
    3      8       567
    4      16      234
    5      32      123
    ...
    */

    // ============== GFP FLAGS ==============
    // 2.7.9.g

    printf("\n=== GFP Flags (g) ===\n");
    explain_gfp_flags();
    /*
    Common GFP flags:

    GFP_KERNEL:
      - Normal kernel allocation
      - Can sleep/block
      - Can reclaim memory

    GFP_ATOMIC:
      - Interrupt context, cannot sleep
      - May fail if no memory available
      - Use in interrupt handlers

    GFP_DMA:
      - Memory below 16MB
      - For legacy ISA DMA

    GFP_DMA32:
      - Memory below 4GB
      - For 32-bit DMA devices

    GFP_ZERO:
      - Zero the allocated memory

    Combining: GFP_KERNEL | GFP_ZERO
    */

    printf("\nRecommendations:\n");
    printf("  Process context: %s\n",
           gfp_flags_string(recommend_gfp_flags("process")));
    printf("  Interrupt handler: %s\n",
           gfp_flags_string(recommend_gfp_flags("interrupt")));
    printf("  DMA buffer: %s\n",
           gfp_flags_string(recommend_gfp_flags("dma")));

    // ============== MEMORY ZONES ==============
    // 2.7.9.h-i

    printf("\n=== Memory Zones (i) ===\n");
    print_zone_info();
    /*
    Zone        Start PFN   End PFN   Free Pages
    DMA         0           4096      1234
    DMA32       4096        1048576   45678
    Normal      1048576     4194304   123456
    */

    printf("\nZone purposes:\n");
    printf("  DMA: Legacy ISA DMA (0-16MB)\n");
    printf("  DMA32: 32-bit DMA devices (0-4GB)\n");
    printf("  Normal: Regular allocations\n");
    printf("  HighMem: Memory above direct map (32-bit only)\n");

    // 2.7.9.h: High memory
    printf("\n=== High Memory (h) ===\n");
    explain_highmem();
    /*
    High Memory (32-bit systems):
      - Physical memory > ~896MB
      - Not directly mapped in kernel
      - Must use kmap() to access
      - Returns temporary virtual address

    64-bit systems:
      - No highmem problem
      - All physical memory directly mapped
      - Up to 64TB direct map on x86-64
    */

    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_kernel_layout()         // 2.7.9.a
#[test] fn test_direct_mapping()        // 2.7.9.b
#[test] fn test_vmalloc()               // 2.7.9.c
#[test] fn test_kmalloc()               // 2.7.9.d
#[test] fn test_slab_info()             // 2.7.9.e
#[test] fn test_buddy_info()            // 2.7.9.f
#[test] fn test_gfp_flags()             // 2.7.9.g
#[test] fn test_zone_info()             // 2.7.9.h-i
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Address space (2.7.9.a-b) | 20 |
| vmalloc/kmalloc (2.7.9.c-d) | 25 |
| Slab allocator (2.7.9.e) | 20 |
| Buddy system (2.7.9.f) | 15 |
| GFP flags & zones (2.7.9.g-i) | 20 |
| **Total** | **100** |

---

## Fichiers

```
ex04/
├── kernel_memory.h
├── layout.c
├── allocators.c
├── slab.c
├── buddy.c
├── zones.c
└── Makefile
```
