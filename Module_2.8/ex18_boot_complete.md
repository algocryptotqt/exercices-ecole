# [Module 2.8] - Exercise 18: Complete Boot Process

## Metadonnees

```yaml
module: "2.8 - Boot Process & Bare Metal"
exercise: "ex18"
title: "Complete Boot Process"
difficulty: expert
estimated_time: "10 heures"
prerequisite_exercises: ["ex00", "ex05"]
concepts_requis: ["x86_64", "bare_metal", "UEFI"]
score_qualite: 98
```

---

## Concepts Couverts (Missing Boot Concepts)

### 2.8.6: UEFI Graphics & Input

| Ref | Concept | Implementation |
|-----|---------|----------------|
| 2.8.6.a | GOP | Graphics Output Protocol |
| 2.8.6.b | `open_protocol::<GraphicsOutput>()` | Access GOP |
| 2.8.6.c | `gop.modes()` | Available modes |
| 2.8.6.d | `gop.set_mode()` | Change mode |
| 2.8.6.e | `gop.frame_buffer()` | Framebuffer access |
| 2.8.6.f | Pixel format | BGR, RGB |
| 2.8.6.g | Input protocol | SimpleTextInput |
| 2.8.6.h | `read_key()` | Read key |

### 2.8.7: MBR Partitioning

| Ref | Concept | Implementation |
|-----|---------|----------------|
| 2.8.7.a | MBR structure | Boot code + partition table |
| 2.8.7.b | Boot code | 446 bytes |
| 2.8.7.c | Partition table | 4 entries × 16 bytes |
| 2.8.7.d | Boot signature | `0xAA55` |
| 2.8.7.e | Partition entry | Status, type, CHS, LBA |
| 2.8.7.f | Limitations | 2TB max, 4 primary |
| 2.8.7.g | `mbr` crate | Parsing in Rust |
| 2.8.7.h | `gpt` crate | GPT parsing |

### 2.8.8: GPT Partitioning

| Ref | Concept | Implementation |
|-----|---------|----------------|
| 2.8.8.a | GPT | GUID Partition Table |
| 2.8.8.b | Protective MBR | Legacy compatibility |
| 2.8.8.c | GPT header | Primary + backup |
| 2.8.8.d | Partition entries | 128 typical |
| 2.8.8.e | GUID | Unique identifier |
| 2.8.8.f | Large disks | > 2TB support |
| 2.8.8.g | `gpt` crate | Parsing in Rust |
| 2.8.8.h | `gptman` crate | GPT manipulation |

### 2.8.9-10: bootloader Crate

| Ref | Concept | Implementation |
|-----|---------|----------------|
| 2.8.9.a | `bootloader` crate | Complete Rust bootloader |
| 2.8.9.b | BIOS + UEFI | Both supported |
| 2.8.9.c | `bootloader_api` | Kernel interface |
| 2.8.9.d | `BootInfo` | Information passed |
| 2.8.9.e | `entry_point!` macro | Define entry |
| 2.8.9.f | Memory map | Memory regions |
| 2.8.9.g | Framebuffer | Graphics access |
| 2.8.9.h | Physical memory offset | Mapping |
| 2.8.10.a | Dependencies | `bootloader_api` |
| 2.8.10.b | `entry_point!(kernel_main)` | Entry macro |
| 2.8.10.c | `fn kernel_main(boot_info: &'static mut BootInfo)` | Signature |
| 2.8.10.d | `boot_info.memory_regions` | Memory map |
| 2.8.10.e | `boot_info.framebuffer` | Optional framebuffer |
| 2.8.10.f | `boot_info.physical_memory_offset` | Offset mapping |
| 2.8.10.g | `boot_info.rsdp_addr` | ACPI tables |
| 2.8.10.h | Build script | Creates bootloader |

### 2.8.11-13: CPU Modes

| Ref | Concept | Implementation |
|-----|---------|----------------|
| 2.8.11.a | 16-bit mode | Initial x86 mode |
| 2.8.11.b | Segment:Offset | Addressing |
| 2.8.11.c | Physical = Seg×16 + Offset | Calculation |
| 2.8.11.d | 1MB limit | Address space |
| 2.8.11.e | No protection | Everything accessible |
| 2.8.12.a | 32-bit mode | 80386+ |
| 2.8.12.b | 4GB address space | Extension |
| 2.8.12.c | GDT required | Segment descriptors |
| 2.8.12.d | Protection rings | 0-3 |
| 2.8.12.e | Paging optional | Virtual memory |
| 2.8.12.f | CR0.PE | Enable protected mode |
| 2.8.12.g | A20 line | Enable > 1MB |
| 2.8.12.h | Flat model | Base=0, limit=max |
| 2.8.13.a | 64-bit mode | x86-64 |
| 2.8.13.b | 48-bit virtual | 256TB address space |
| 2.8.13.c | 4-level paging | Required |
| 2.8.13.d | Canonical addresses | High/low halves |
| 2.8.13.e | EFER.LME | Enable long mode |
| 2.8.13.f | CR0.PG | Enable paging |
| 2.8.13.g | 64-bit registers | RAX, RBX, etc. |
| 2.8.13.h | New instructions | SYSCALL, etc. |

### 2.8.14-21: System Structures

| Ref | Concept | Implementation |
|-----|---------|----------------|
| 2.8.14.a | `x86_64` crate | Architecture abstractions |
| 2.8.14.b | `structures` module | GDT, IDT, etc. |
| 2.8.14.c | `registers` module | Control registers |
| 2.8.14.d | `instructions` module | CPU instructions |
| 2.8.14.e | `addr` module | Address types |
| 2.8.14.f | `VirtAddr` | Virtual address |
| 2.8.14.g | `PhysAddr` | Physical address |
| 2.8.14.h | `Page` | Page abstraction |
| 2.8.15.a | GDT | Global Descriptor Table |
| 2.8.15.b | `GlobalDescriptorTable::new()` | Create GDT |
| 2.8.15.c | `gdt.add_entry()` | Add descriptor |
| 2.8.15.d | `Descriptor::kernel_code_segment()` | Kernel code |
| 2.8.15.e | `Descriptor::kernel_data_segment()` | Kernel data |
| 2.8.15.f | `gdt.load()` | Load GDT |
| 2.8.15.g | `set_cs()`, `load_ss()` | Set segments |
| 2.8.16.a | TSS | Task State Segment |
| 2.8.16.b | `TaskStateSegment::new()` | Create TSS |
| 2.8.16.c | `tss.interrupt_stack_table` | IST |
| 2.8.16.d | IST[0..7] | Stack pointers |
| 2.8.16.e | Double fault stack | IST for safety |
| 2.8.16.f | `Descriptor::tss_segment()` | TSS descriptor |
| 2.8.16.g | `gdt.add_entry(tss)` | Add to GDT |
| 2.8.16.h | `load_tss()` | Load TSS |
| 2.8.17.a | IDT | Interrupt Descriptor Table |
| 2.8.17.b | `InterruptDescriptorTable::new()` | Create IDT |
| 2.8.17.c | `idt[n].set_handler_fn()` | Set handler |
| 2.8.17.d | `extern "x86-interrupt"` | Handler ABI |
| 2.8.17.e | `InterruptStackFrame` | Pushed by CPU |
| 2.8.17.f | 256 entries | Vector 0-255 |
| 2.8.17.g | `idt.load()` | Load IDT |
| 2.8.18.a | Handler signature | `fn handler(frame: InterruptStackFrame)` |
| 2.8.18.b | Error code | Some have error code |
| 2.8.18.c | Page fault | Vector 14 |
| 2.8.18.d | Double fault | Vector 8 |
| 2.8.18.e | General protection | Vector 13 |
| 2.8.18.f | Breakpoint | Vector 3 |
| 2.8.18.g | `iret` | Return from interrupt |
| 2.8.19.a | 4-level paging | PML4, PDPT, PD, PT |
| 2.8.19.b | Page table entry | Flags + address |
| 2.8.19.c | `PageTable` | Table type |
| 2.8.19.d | `PageTableEntry` | Entry type |
| 2.8.19.e | Mapping | Virtual → physical |
| 2.8.19.f | `OffsetPageTable` | Mapper type |
| 2.8.19.g | `map_to()` | Create mapping |
| 2.8.19.h | Page flags | Present, writable, etc. |
| 2.8.20.a | Frame allocator | Allocate physical frames |
| 2.8.20.b | Memory regions | From bootloader |
| 2.8.20.c | Usable memory | Type filtering |
| 2.8.20.d | `FrameAllocator` trait | Interface |
| 2.8.20.e | `allocate_frame()` | Get frame |
| 2.8.20.f | `PhysFrame` | Frame type |
| 2.8.20.g | Bitmap allocator | Track usage |
| 2.8.20.h | Deallocation | Return frames |
| 2.8.21.a | VGA buffer | 0xB8000 |
| 2.8.21.b | Text mode | 80×25 characters |
| 2.8.21.c | Character + attribute | 2 bytes per cell |
| 2.8.21.d | Color codes | 16 colors |
| 2.8.21.e | `volatile` access | No optimization |
| 2.8.21.f | Writer struct | Abstraction |
| 2.8.21.g | `core::fmt::Write` | Implement Write trait |

---

## Partie 1: UEFI Graphics (2.8.6)

```rust
//! UEFI Graphics Output Protocol (2.8.6)

use uefi::prelude::*;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};

/// UEFI GOP example (2.8.6.a-f)
fn gop_demo(boot_services: &BootServices) -> uefi::Result {
    // 2.8.6.b: Open Graphics Output Protocol
    let gop_handle = boot_services
        .get_handle_for_protocol::<GraphicsOutput>()?;
    let gop = boot_services
        .open_protocol_exclusive::<GraphicsOutput>(gop_handle)?;

    // 2.8.6.c: List available modes
    for (i, mode) in gop.modes().enumerate() {
        let info = mode.info();
        let (w, h) = info.resolution();
        let format = info.pixel_format();
        log::info!("Mode {}: {}x{} {:?}", i, w, h, format);
    }

    // 2.8.6.d: Set mode
    let mode = gop.modes().find(|m| {
        let (w, h) = m.info().resolution();
        w == 800 && h == 600
    });

    if let Some(mode) = mode {
        gop.set_mode(&mode)?;
    }

    // 2.8.6.e-f: Access framebuffer
    let mut fb = gop.frame_buffer();
    let info = gop.current_mode_info();
    let stride = info.stride();
    let format = info.pixel_format();  // 2.8.6.f: BGR or RGB

    // Draw a red pixel at (10, 10)
    let offset = (10 * stride + 10) * 4;
    match format {
        PixelFormat::Bgr => {
            fb.write_byte(offset, 0);       // Blue
            fb.write_byte(offset + 1, 0);   // Green
            fb.write_byte(offset + 2, 255); // Red
        }
        PixelFormat::Rgb => {
            fb.write_byte(offset, 255);     // Red
            fb.write_byte(offset + 1, 0);   // Green
            fb.write_byte(offset + 2, 0);   // Blue
        }
        _ => {}
    }

    Ok(())
}

/// UEFI Input (2.8.6.g-h)
fn input_demo(system_table: &SystemTable<Boot>) {
    let stdin = system_table.stdin();

    loop {
        // 2.8.6.h: Read key
        if let Some(key) = stdin.read_key().ok().flatten() {
            log::info!("Key pressed: {:?}", key);
            break;
        }
    }
}
```

---

## Partie 2: Partition Tables (2.8.7-8)

```rust
//! MBR and GPT Partitioning (2.8.7-8)

/// MBR structure (2.8.7.a-f)
#[repr(C, packed)]
struct MasterBootRecord {
    boot_code: [u8; 446],           // 2.8.7.b: Boot code
    partitions: [PartitionEntry; 4], // 2.8.7.c: 4 entries
    signature: u16,                  // 2.8.7.d: 0xAA55
}

#[repr(C, packed)]
struct PartitionEntry {
    status: u8,           // 2.8.7.e: Boot flag
    first_chs: [u8; 3],   // CHS of first sector
    partition_type: u8,   // Type code
    last_chs: [u8; 3],    // CHS of last sector
    first_lba: u32,       // LBA of first sector
    sector_count: u32,    // Number of sectors
}

impl MasterBootRecord {
    fn is_valid(&self) -> bool {
        self.signature == 0xAA55
    }

    fn partitions(&self) -> impl Iterator<Item = &PartitionEntry> {
        self.partitions.iter().filter(|p| p.partition_type != 0)
    }
}

/// GPT structure (2.8.8.a-f)
#[repr(C, packed)]
struct GptHeader {
    signature: [u8; 8],          // "EFI PART"
    revision: u32,               // Usually 0x00010000
    header_size: u32,            // 92 bytes
    header_crc32: u32,           // CRC32 of header
    reserved: u32,
    current_lba: u64,            // LBA of this header
    backup_lba: u64,             // 2.8.8.c: Backup header
    first_usable_lba: u64,
    last_usable_lba: u64,        // 2.8.8.f: Large disk support
    disk_guid: [u8; 16],         // 2.8.8.e: GUID
    partition_entry_lba: u64,
    num_partition_entries: u32,  // 2.8.8.d: Typically 128
    partition_entry_size: u32,
    partition_array_crc32: u32,
}

#[repr(C, packed)]
struct GptPartitionEntry {
    type_guid: [u8; 16],
    unique_guid: [u8; 16],
    starting_lba: u64,
    ending_lba: u64,
    attributes: u64,
    name: [u16; 36],  // UTF-16LE
}

/// Using crates (2.8.7.g-h, 2.8.8.g-h)
fn parse_partitions() {
    // 2.8.7.g: mbr crate
    // use mbr::MasterBootRecord;
    // let mbr = MasterBootRecord::read_from(&disk)?;

    // 2.8.8.g: gpt crate
    // use gpt::GptDisk;
    // let gpt = GptDisk::read_from(&disk)?;
}
```

---

## Partie 3: bootloader Crate (2.8.9-10)

```rust
//! bootloader crate usage (2.8.9-10)

#![no_std]
#![no_main]

use bootloader_api::{entry_point, BootInfo, BootloaderConfig};
use bootloader_api::config::Mapping;

// 2.8.9.e, 2.8.10.b: Entry point macro
entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut config = BootloaderConfig::new_default();
    config.mappings.physical_memory = Some(Mapping::Dynamic);
    config
};

// 2.8.10.c: Kernel main signature
fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // 2.8.9.f, 2.8.10.d: Memory map
    for region in boot_info.memory_regions.iter() {
        log::info!("{:?}: {:?} - {:?}",
            region.kind,
            region.start,
            region.end
        );
    }

    // 2.8.9.g, 2.8.10.e: Optional framebuffer
    if let Some(fb) = boot_info.framebuffer.as_mut() {
        let info = fb.info();
        log::info!("Framebuffer: {}x{}", info.width, info.height);

        // Clear screen to blue
        for byte in fb.buffer_mut().chunks_mut(info.bytes_per_pixel) {
            byte[0] = 255;  // Blue
            byte[1] = 0;    // Green
            byte[2] = 0;    // Red
        }
    }

    // 2.8.9.h, 2.8.10.f: Physical memory offset
    if let Some(offset) = boot_info.physical_memory_offset.into_option() {
        log::info!("Physical memory offset: {:#x}", offset);
    }

    // 2.8.10.g: RSDP for ACPI
    if let Some(rsdp) = boot_info.rsdp_addr.into_option() {
        log::info!("RSDP address: {:#x}", rsdp);
    }

    loop {
        x86_64::instructions::hlt();
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
```

---

## Partie 4: CPU Modes (2.8.11-13)

```rust
//! CPU Modes (2.8.11-13)

/// Real Mode (2.8.11)
mod real_mode {
    // 2.8.11.a-e: Real mode concepts (theoretical)

    /// Calculate physical address (2.8.11.b-c)
    pub fn segment_offset_to_physical(segment: u16, offset: u16) -> u32 {
        (segment as u32) * 16 + offset as u32
    }

    /// Example: 0x1234:0x5678 → 0x179B8
    pub fn address_example() {
        let phys = segment_offset_to_physical(0x1234, 0x5678);
        assert_eq!(phys, 0x179B8);
    }
}

/// Protected Mode (2.8.12)
mod protected_mode {
    // 2.8.12.a-h: Protected mode setup

    /// CR0 bits for protected mode
    const CR0_PE: u32 = 1 << 0;  // 2.8.12.f: Protection Enable
    const CR0_PG: u32 = 1 << 31; // Paging

    /// A20 line (2.8.12.g)
    fn enable_a20() {
        // Multiple methods: keyboard controller, fast A20, etc.
    }

    /// Flat model GDT (2.8.12.c, 2.8.12.h)
    fn setup_flat_model_gdt() {
        // Null descriptor
        // Code: base=0, limit=0xFFFFF, 32-bit, ring 0
        // Data: base=0, limit=0xFFFFF, 32-bit, ring 0
    }
}

/// Long Mode (2.8.13)
mod long_mode {
    // 2.8.13.a-h: Long mode concepts

    const EFER_LME: u64 = 1 << 8;  // 2.8.13.e: Long Mode Enable
    const EFER_LMA: u64 = 1 << 10; // Long Mode Active

    /// Long mode requires (2.8.13.c-f):
    /// 1. 4-level paging enabled
    /// 2. PAE enabled in CR4
    /// 3. LME set in EFER
    /// 4. PG set in CR0
    fn long_mode_requirements() {
        // Set up 4-level page tables
        // Enable PAE (CR4.PAE = 1)
        // Set EFER.LME = 1
        // Load CR3 with PML4 address
        // Set CR0.PG = 1
    }

    /// Canonical addresses (2.8.13.d)
    fn is_canonical(addr: u64) -> bool {
        // Upper 16 bits must all be 0 or all be 1
        let upper = addr >> 47;
        upper == 0 || upper == 0x1FFFF
    }
}
```

---

## Partie 5: x86_64 Crate & System Structures (2.8.14-21)

```rust
//! System structures with x86_64 crate (2.8.14-21)

use x86_64::structures::gdt::{GlobalDescriptorTable, Descriptor, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};
use x86_64::structures::paging::{
    PageTable, OffsetPageTable, PhysFrame, Page, PageTableFlags,
    FrameAllocator, Mapper,
};
use x86_64::{VirtAddr, PhysAddr};

// 2.8.16.a-h: TSS Setup
static mut TSS: TaskStateSegment = TaskStateSegment::new();

const DOUBLE_FAULT_IST_INDEX: u16 = 0;

fn init_tss() {
    unsafe {
        // 2.8.16.c-e: Set up interrupt stack table
        TSS.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            const STACK_SIZE: usize = 4096 * 5;
            static mut STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];
            VirtAddr::from_ptr(unsafe { &STACK }) + STACK_SIZE
        };
    }
}

// 2.8.15.a-g: GDT Setup
static mut GDT: Option<(GlobalDescriptorTable, Selectors)> = None;

struct Selectors {
    code_selector: SegmentSelector,
    tss_selector: SegmentSelector,
}

fn init_gdt() {
    let mut gdt = GlobalDescriptorTable::new();  // 2.8.15.b

    // 2.8.15.c-e: Add entries
    let code_selector = gdt.add_entry(Descriptor::kernel_code_segment());
    let tss_selector = gdt.add_entry(Descriptor::tss_segment(unsafe { &TSS }));

    unsafe {
        GDT = Some((gdt, Selectors { code_selector, tss_selector }));

        // 2.8.15.f: Load GDT
        GDT.as_ref().unwrap().0.load();

        // 2.8.15.g: Set segment registers
        x86_64::instructions::segmentation::CS::set_reg(
            GDT.as_ref().unwrap().1.code_selector
        );
        x86_64::instructions::tables::load_tss(  // 2.8.16.h
            GDT.as_ref().unwrap().1.tss_selector
        );
    }
}

// 2.8.17.a-g: IDT Setup
static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable::new();

fn init_idt() {
    unsafe {
        // 2.8.17.c-d: Set handler functions
        IDT.breakpoint.set_handler_fn(breakpoint_handler);      // 2.8.18.f
        IDT.page_fault.set_handler_fn(page_fault_handler);      // 2.8.18.c
        IDT.double_fault.set_handler_fn(double_fault_handler)   // 2.8.18.d
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
        IDT.general_protection_fault.set_handler_fn(gpf_handler); // 2.8.18.e

        // 2.8.17.g: Load IDT
        IDT.load();
    }
}

// 2.8.18.a-b: Handler signatures
extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    log::info!("BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: x86_64::structures::idt::PageFaultErrorCode,  // 2.8.18.b
) {
    log::error!("PAGE FAULT at {:?}\n{:#?}", x86_64::registers::control::Cr2::read(), stack_frame);
    loop {}
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    panic!("DOUBLE FAULT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn gpf_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    panic!("GPF error_code={}\n{:#?}", error_code, stack_frame);
}

// 2.8.19.a-h: Paging Setup
fn init_paging(phys_mem_offset: VirtAddr, memory_regions: &[MemoryRegion]) {
    // 2.8.19.f: Create mapper
    let level_4_table = unsafe {
        let (table, _) = x86_64::registers::control::Cr3::read();
        let table_ptr: *mut PageTable = (phys_mem_offset + table.start_address().as_u64()).as_mut_ptr();
        &mut *table_ptr
    };

    let mapper = unsafe { OffsetPageTable::new(level_4_table, phys_mem_offset) };

    // 2.8.20: Frame allocator
    let mut frame_allocator = BootInfoFrameAllocator::init(memory_regions);

    // 2.8.19.g: Map a page
    let page = Page::containing_address(VirtAddr::new(0xDEAD_BEEF));
    let frame = frame_allocator.allocate_frame().unwrap();
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;  // 2.8.19.h

    unsafe {
        mapper.map_to(page, frame, flags, &mut frame_allocator)
            .expect("mapping failed")
            .flush();
    }
}

// 2.8.20.a-h: Frame Allocator
struct BootInfoFrameAllocator<'a> {
    memory_regions: &'a [MemoryRegion],
    next: usize,
}

impl<'a> BootInfoFrameAllocator<'a> {
    fn init(regions: &'a [MemoryRegion]) -> Self {
        Self { memory_regions: regions, next: 0 }
    }

    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> + '_ {
        self.memory_regions.iter()
            .filter(|r| r.kind == MemoryRegionKind::Usable)
            .flat_map(|r| (r.start..r.end).step_by(4096))
            .map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

unsafe impl FrameAllocator<x86_64::structures::paging::Size4KiB>
    for BootInfoFrameAllocator<'_>
{
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}

// 2.8.21.a-g: VGA Text Mode
#[repr(C)]
struct VgaChar {
    char: u8,
    attr: u8,  // 2.8.21.d: Color codes
}

struct VgaWriter {
    col: usize,
    row: usize,
    buffer: &'static mut [[VgaChar; 80]; 25],  // 2.8.21.b: 80x25
}

impl VgaWriter {
    fn new() -> Self {
        Self {
            col: 0,
            row: 0,
            buffer: unsafe { &mut *(0xB8000 as *mut _) },  // 2.8.21.a
        }
    }

    fn write_byte(&mut self, byte: u8) {
        if byte == b'\n' {
            self.row += 1;
            self.col = 0;
            return;
        }

        // 2.8.21.e: Volatile write
        let cell = &mut self.buffer[self.row][self.col];
        unsafe {
            core::ptr::write_volatile(&mut cell.char, byte);
            core::ptr::write_volatile(&mut cell.attr, 0x0F); // White on black
        }

        self.col += 1;
        if self.col >= 80 {
            self.col = 0;
            self.row += 1;
        }
    }
}

// 2.8.21.g: Implement Write trait
impl core::fmt::Write for VgaWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| UEFI Graphics (2.8.6) | 10 |
| MBR/GPT (2.8.7-8) | 10 |
| bootloader crate (2.8.9-10) | 15 |
| CPU Modes (2.8.11-13) | 15 |
| x86_64 crate (2.8.14) | 10 |
| GDT Setup (2.8.15) | 10 |
| TSS Setup (2.8.16) | 5 |
| IDT Setup (2.8.17-18) | 10 |
| Paging (2.8.19-20) | 10 |
| VGA Text (2.8.21) | 5 |
| **Total** | **100** |

---

## Ressources

- [OSDev Wiki](https://wiki.osdev.org/)
- [x86_64 crate docs](https://docs.rs/x86_64/)
- [bootloader crate](https://docs.rs/bootloader/)
- [Writing an OS in Rust](https://os.phil-opp.com/)
