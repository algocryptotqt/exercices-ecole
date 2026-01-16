# [Module 2.8] - Exercise 15: Memory Detection & Heap Allocation

## Metadonnees

```yaml
module: "2.8 - System Interfaces"
exercise: "ex15"
title: "Memory Detection & Heap Allocation"
difficulty: expert
estimated_time: "5 heures"
prerequisite_exercises: ["ex13", "ex14"]
concepts_requis: ["memory management", "paging", "allocators"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.8.27: Memory Detection (9 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.8.27.a | BIOS E820 | Legacy memory map |
| 2.8.27.b | UEFI memory map | Modern memory detection |
| 2.8.27.c | `BootInfo::memory_regions` | Bootloader memory info |
| 2.8.27.d | `MemoryRegion` | Base, size, kind struct |
| 2.8.27.e | `MemoryRegionKind::Usable` | Available RAM |
| 2.8.27.f | `MemoryRegionKind::Bootloader` | Bootloader reserved |
| 2.8.27.g | Reserved regions | Hardware reserved |
| 2.8.27.h | Total memory | Summing usable regions |
| 2.8.27.i | Frame allocator init | Using memory map |

### 2.8.28: Heap Allocation (9 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.8.28.a | `#[global_allocator]` | Setting global allocator |
| 2.8.28.b | `GlobalAlloc` trait | Allocator interface |
| 2.8.28.c | `linked_list_allocator` | Common allocator choice |
| 2.8.28.d | `LockedHeap` | Thread-safe wrapper |
| 2.8.28.e | `ALLOCATOR.lock().init()` | Initialize allocator |
| 2.8.28.f | Heap region | Map pages first |
| 2.8.28.g | `Box`, `Vec`, `String` | Available after init |
| 2.8.28.h | `alloc` crate | Allocation types |
| 2.8.28.i | OOM handler | `#[alloc_error_handler]` |

---

## Partie 1: Memory Detection (2.8.27)

### Exercice 1.1: Reading Memory Map from Bootloader

```rust
use bootloader::bootinfo::{BootInfo, MemoryMap, MemoryRegionType};

/// Print the memory map provided by the bootloader
pub fn print_memory_map(memory_map: &MemoryMap) {
    crate::serial_println!("Memory Map:");
    crate::serial_println!("  {:^16} {:^16} {:^16} {}",
        "Start", "End", "Size", "Type");
    crate::serial_println!("  {:-<16} {:-<16} {:-<16} {:-<20}",
        "", "", "", "");

    let mut total_usable: u64 = 0;
    let mut total_memory: u64 = 0;

    for region in memory_map.iter() {
        let start = region.range.start_addr();
        let end = region.range.end_addr();
        let size = end - start;

        total_memory += size;
        if region.region_type == MemoryRegionType::Usable {
            total_usable += size;
        }

        let type_str = match region.region_type {
            MemoryRegionType::Usable => "Usable",
            MemoryRegionType::Reserved => "Reserved",
            MemoryRegionType::AcpiReclaimable => "ACPI Reclaimable",
            MemoryRegionType::AcpiNvs => "ACPI NVS",
            MemoryRegionType::BadMemory => "Bad Memory",
            MemoryRegionType::Bootloader => "Bootloader",
            MemoryRegionType::BootloaderReclaimable => "Bootloader Reclaimable",
            MemoryRegionType::Kernel => "Kernel",
            MemoryRegionType::KernelStack => "Kernel Stack",
            MemoryRegionType::PageTable => "Page Table",
            MemoryRegionType::FrameZero => "Frame Zero",
            _ => "Unknown",
        };

        crate::serial_println!("  {:#016x} {:#016x} {:>12} KB  {}",
            start, end, size / 1024, type_str);
    }

    crate::serial_println!();
    crate::serial_println!("Total memory:  {} MB", total_memory / 1024 / 1024);
    crate::serial_println!("Usable memory: {} MB", total_usable / 1024 / 1024);
}

/// Calculate total usable memory
pub fn total_usable_memory(memory_map: &MemoryMap) -> u64 {
    memory_map
        .iter()
        .filter(|r| r.region_type == MemoryRegionType::Usable)
        .map(|r| r.range.end_addr() - r.range.start_addr())
        .sum()
}

/// Get the highest usable address
pub fn highest_usable_address(memory_map: &MemoryMap) -> u64 {
    memory_map
        .iter()
        .filter(|r| r.region_type == MemoryRegionType::Usable)
        .map(|r| r.range.end_addr())
        .max()
        .unwrap_or(0)
}
```

### Exercice 1.2: Frame Allocator

```rust
use bootloader::bootinfo::{MemoryMap, MemoryRegionType};
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size4KiB};
use x86_64::PhysAddr;

/// A FrameAllocator that returns usable frames from the bootloader's memory map
pub struct BootInfoFrameAllocator {
    memory_map: &'static MemoryMap,
    next: usize,
}

impl BootInfoFrameAllocator {
    /// Create a FrameAllocator from the passed memory map.
    ///
    /// This function is unsafe because the caller must guarantee that the passed
    /// memory map is valid. The main requirement is that all frames that are marked
    /// as `USABLE` in it are really unused.
    pub unsafe fn init(memory_map: &'static MemoryMap) -> Self {
        BootInfoFrameAllocator {
            memory_map,
            next: 0,
        }
    }

    /// Returns an iterator over the usable frames specified in the memory map
    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> {
        // Get usable regions from memory map
        let regions = self.memory_map.iter();
        let usable_regions = regions
            .filter(|r| r.region_type == MemoryRegionType::Usable);

        // Map each region to its address range
        let addr_ranges = usable_regions
            .map(|r| r.range.start_addr()..r.range.end_addr());

        // Transform to an iterator of frame start addresses
        let frame_addresses = addr_ranges.flat_map(|r| r.step_by(4096));

        // Create `PhysFrame` types from the start addresses
        frame_addresses.map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}
```

### Exercice 1.3: Advanced Frame Allocator with Bitmap

```rust
use alloc::vec::Vec;
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size4KiB};
use x86_64::PhysAddr;
use spin::Mutex;

/// A bitmap-based frame allocator for more efficient allocation
pub struct BitmapFrameAllocator {
    bitmap: Vec<u64>,
    base_frame: u64,
    total_frames: usize,
    free_frames: usize,
}

impl BitmapFrameAllocator {
    /// Initialize from memory map after heap is available
    pub fn new(memory_map: &bootloader::bootinfo::MemoryMap) -> Self {
        // Find the largest usable region
        let (base, size) = memory_map
            .iter()
            .filter(|r| r.region_type == bootloader::bootinfo::MemoryRegionType::Usable)
            .map(|r| (r.range.start_addr(), r.range.end_addr() - r.range.start_addr()))
            .max_by_key(|(_, size)| *size)
            .expect("No usable memory regions");

        let total_frames = (size / 4096) as usize;
        let bitmap_size = (total_frames + 63) / 64;

        let mut bitmap = vec![0u64; bitmap_size];
        // Mark all frames as free (0 = free, 1 = used)

        BitmapFrameAllocator {
            bitmap,
            base_frame: base / 4096,
            total_frames,
            free_frames: total_frames,
        }
    }

    /// Allocate a specific frame
    pub fn allocate_frame_at(&mut self, frame_number: u64) -> bool {
        let index = (frame_number - self.base_frame) as usize;
        if index >= self.total_frames {
            return false;
        }

        let bitmap_idx = index / 64;
        let bit_idx = index % 64;

        if self.bitmap[bitmap_idx] & (1 << bit_idx) != 0 {
            return false; // Already allocated
        }

        self.bitmap[bitmap_idx] |= 1 << bit_idx;
        self.free_frames -= 1;
        true
    }

    /// Deallocate a frame
    pub fn deallocate_frame(&mut self, frame_number: u64) {
        let index = (frame_number - self.base_frame) as usize;
        if index >= self.total_frames {
            return;
        }

        let bitmap_idx = index / 64;
        let bit_idx = index % 64;

        self.bitmap[bitmap_idx] &= !(1 << bit_idx);
        self.free_frames += 1;
    }

    /// Get free frame count
    pub fn free_frames(&self) -> usize {
        self.free_frames
    }
}

unsafe impl FrameAllocator<Size4KiB> for BitmapFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        // Find first free frame
        for (bitmap_idx, entry) in self.bitmap.iter_mut().enumerate() {
            if *entry != !0u64 {
                // Found a bitmap entry with at least one free bit
                let bit_idx = (!*entry).trailing_zeros() as usize;
                *entry |= 1 << bit_idx;
                self.free_frames -= 1;

                let frame_number = self.base_frame + (bitmap_idx * 64 + bit_idx) as u64;
                return Some(PhysFrame::containing_address(PhysAddr::new(frame_number * 4096)));
            }
        }
        None
    }
}
```

---

## Partie 2: Heap Allocation (2.8.28)

### Exercice 2.1: Basic Heap Setup

```rust
use x86_64::{
    structures::paging::{
        mapper::MapToError, FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB,
    },
    VirtAddr,
};

pub const HEAP_START: usize = 0x_4444_4444_0000;
pub const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB

/// Initialize the heap by mapping pages and setting up the allocator
pub fn init_heap(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
    let page_range = {
        let heap_start = VirtAddr::new(HEAP_START as u64);
        let heap_end = heap_start + HEAP_SIZE - 1u64;
        let heap_start_page = Page::containing_address(heap_start);
        let heap_end_page = Page::containing_address(heap_end);
        Page::range_inclusive(heap_start_page, heap_end_page)
    };

    for page in page_range {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        unsafe {
            mapper.map_to(page, frame, flags, frame_allocator)?.flush();
        }
    }

    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    crate::serial_println!("Heap initialized:");
    crate::serial_println!("  Start: {:#x}", HEAP_START);
    crate::serial_println!("  Size:  {} KB", HEAP_SIZE / 1024);

    Ok(())
}
```

### Exercice 2.2: Global Allocator with linked_list_allocator

```rust
use linked_list_allocator::LockedHeap;

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// OOM handler - called when allocation fails
#[alloc_error_handler]
fn alloc_error_handler(layout: alloc::alloc::Layout) -> ! {
    panic!("Allocation error: {:?}", layout)
}
```

### Exercice 2.3: Custom Bump Allocator

```rust
use alloc::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use spin::Mutex;

/// A simple bump allocator
pub struct BumpAllocator {
    heap_start: usize,
    heap_end: usize,
    next: usize,
    allocations: usize,
}

impl BumpAllocator {
    /// Creates a new empty bump allocator.
    pub const fn new() -> Self {
        BumpAllocator {
            heap_start: 0,
            heap_end: 0,
            next: 0,
            allocations: 0,
        }
    }

    /// Initializes the bump allocator with the given heap bounds.
    pub unsafe fn init(&mut self, heap_start: usize, heap_size: usize) {
        self.heap_start = heap_start;
        self.heap_end = heap_start + heap_size;
        self.next = heap_start;
    }
}

unsafe impl GlobalAlloc for Locked<BumpAllocator> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut allocator = self.lock();

        let alloc_start = align_up(allocator.next, layout.align());
        let alloc_end = match alloc_start.checked_add(layout.size()) {
            Some(end) => end,
            None => return null_mut(),
        };

        if alloc_end > allocator.heap_end {
            null_mut() // Out of memory
        } else {
            allocator.next = alloc_end;
            allocator.allocations += 1;
            alloc_start as *mut u8
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        let mut allocator = self.lock();

        allocator.allocations -= 1;
        if allocator.allocations == 0 {
            allocator.next = allocator.heap_start;
        }
    }
}

/// A wrapper around spin::Mutex to permit trait implementations.
pub struct Locked<A> {
    inner: spin::Mutex<A>,
}

impl<A> Locked<A> {
    pub const fn new(inner: A) -> Self {
        Locked {
            inner: spin::Mutex::new(inner),
        }
    }

    pub fn lock(&self) -> spin::MutexGuard<A> {
        self.inner.lock()
    }
}

/// Align the given address upwards to alignment.
fn align_up(addr: usize, align: usize) -> usize {
    (addr + align - 1) & !(align - 1)
}
```

### Exercice 2.4: Fixed-Size Block Allocator

```rust
use alloc::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;

/// Block sizes to use for allocations
const BLOCK_SIZES: &[usize] = &[8, 16, 32, 64, 128, 256, 512, 1024, 2048];

struct ListNode {
    next: Option<&'static mut ListNode>,
}

pub struct FixedSizeBlockAllocator {
    list_heads: [Option<&'static mut ListNode>; BLOCK_SIZES.len()],
    fallback_allocator: linked_list_allocator::Heap,
}

impl FixedSizeBlockAllocator {
    pub const fn new() -> Self {
        const EMPTY: Option<&'static mut ListNode> = None;
        FixedSizeBlockAllocator {
            list_heads: [EMPTY; BLOCK_SIZES.len()],
            fallback_allocator: linked_list_allocator::Heap::empty(),
        }
    }

    pub unsafe fn init(&mut self, heap_start: usize, heap_size: usize) {
        self.fallback_allocator.init(heap_start as *mut u8, heap_size);
    }
}

fn list_index(layout: &Layout) -> Option<usize> {
    let required_block_size = layout.size().max(layout.align());
    BLOCK_SIZES.iter().position(|&s| s >= required_block_size)
}

unsafe impl GlobalAlloc for Locked<FixedSizeBlockAllocator> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut allocator = self.lock();
        match list_index(&layout) {
            Some(index) => {
                match allocator.list_heads[index].take() {
                    Some(node) => {
                        allocator.list_heads[index] = node.next.take();
                        node as *mut ListNode as *mut u8
                    }
                    None => {
                        // No block in list -> allocate new block
                        let block_size = BLOCK_SIZES[index];
                        let block_align = block_size;
                        let layout = Layout::from_size_align(block_size, block_align).unwrap();
                        allocator.fallback_allocator.allocate_first_fit(layout)
                            .ok()
                            .map_or(null_mut(), |a| a.as_ptr())
                    }
                }
            }
            None => allocator.fallback_allocator.allocate_first_fit(layout)
                .ok()
                .map_or(null_mut(), |a| a.as_ptr()),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let mut allocator = self.lock();
        match list_index(&layout) {
            Some(index) => {
                let new_node = ListNode {
                    next: allocator.list_heads[index].take(),
                };
                // Verify block size has room for ListNode
                assert!(core::mem::size_of::<ListNode>() <= BLOCK_SIZES[index]);
                assert!(core::mem::align_of::<ListNode>() <= BLOCK_SIZES[index]);
                let new_node_ptr = ptr as *mut ListNode;
                new_node_ptr.write(new_node);
                allocator.list_heads[index] = Some(&mut *new_node_ptr);
            }
            None => {
                let ptr = core::ptr::NonNull::new(ptr).unwrap();
                allocator.fallback_allocator.deallocate(ptr, layout);
            }
        }
    }
}
```

---

## Partie 3: Testing Allocations

### Exercice 3.1: Heap Tests

```rust
use alloc::{boxed::Box, vec, vec::Vec, rc::Rc, string::String};

#[test_case]
fn simple_allocation() {
    let heap_value_1 = Box::new(41);
    let heap_value_2 = Box::new(13);
    assert_eq!(*heap_value_1, 41);
    assert_eq!(*heap_value_2, 13);
}

#[test_case]
fn large_vec() {
    let n = 1000;
    let mut vec = Vec::new();
    for i in 0..n {
        vec.push(i);
    }
    assert_eq!(vec.iter().sum::<u64>(), (n - 1) * n / 2);
}

#[test_case]
fn many_boxes() {
    for i in 0..10_000 {
        let x = Box::new(i);
        assert_eq!(*x, i);
    }
}

#[test_case]
fn many_boxes_long_lived() {
    let long_lived = Box::new(1);
    for i in 0..10_000 {
        let x = Box::new(i);
        assert_eq!(*x, i);
    }
    assert_eq!(*long_lived, 1);
}

#[test_case]
fn string_allocation() {
    let s = String::from("Hello, ODYSSEY!");
    assert_eq!(s.len(), 15);
}

#[test_case]
fn rc_allocation() {
    let rc = Rc::new(42);
    let rc2 = rc.clone();
    assert_eq!(*rc, 42);
    assert_eq!(*rc2, 42);
    assert_eq!(Rc::strong_count(&rc), 2);
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Memory map parsing | 20 |
| Frame allocator | 20 |
| Heap initialization | 20 |
| Global allocator setup | 15 |
| Custom allocator | 15 |
| Tests | 10 |
| **Total** | **100** |

---

## Ressources

- [Heap Allocation - Writing an OS in Rust](https://os.phil-opp.com/heap-allocation/)
- [Allocator Designs](https://os.phil-opp.com/allocator-designs/)
- [linked_list_allocator crate](https://docs.rs/linked_list_allocator/)
- [bootloader crate memory map](https://docs.rs/bootloader/)
