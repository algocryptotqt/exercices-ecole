# [Module 2.8] - Exercise 16: Testing Framework & Multiboot2

## Metadonnees

```yaml
module: "2.8 - System Interfaces"
exercise: "ex16"
title: "Testing Framework & Multiboot2"
difficulty: expert
estimated_time: "4 heures"
prerequisite_exercises: ["ex15"]
concepts_requis: ["testing", "boot protocol"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.8.29: Testing Framework (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.8.29.a | Custom test framework | Required in no_std |
| 2.8.29.b | `#![feature(custom_test_frameworks)]` | Enable custom framework |
| 2.8.29.c | `#![test_runner(test_runner)]` | Set test runner |
| 2.8.29.d | `#![reexport_test_harness_main = "test_main"]` | Entry point |
| 2.8.29.e | `#[test_case]` | Mark test functions |
| 2.8.29.f | Test runner | Iterate and run tests |
| 2.8.29.g | QEMU exit | `isa-debug-exit` device |
| 2.8.29.h | Exit codes | Success/failure codes |
| 2.8.29.i | Serial output | Test result output |
| 2.8.29.j | `cargo test` | Run tests command |

### 2.8.30: Multiboot2 Specification (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.8.30.a | Multiboot2 | Standard boot protocol |
| 2.8.30.b | Magic | `0xE85250D6` header magic |
| 2.8.30.c | Header | Must be in first 32KB |
| 2.8.30.d | Tags | Information request tags |
| 2.8.30.e | Boot info | Passed in EBX register |
| 2.8.30.f | `multiboot2` crate | Rust parsing library |
| 2.8.30.g | Memory map | Memory map tag type |
| 2.8.30.h | Framebuffer | Framebuffer tag type |
| 2.8.30.i | GRUB support | Multiboot2 compliant |
| 2.8.30.j | Transition | 64-bit kernel transition |

---

## Partie 1: Custom Test Framework (2.8.29)

### Exercice 1.1: Test Framework Setup

**src/lib.rs:**

```rust
#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

extern crate alloc;

pub mod serial;
pub mod vga_buffer;
// ... other modules

use core::panic::PanicInfo;

/// Trait implemented by all test functions
pub trait Testable {
    fn run(&self) -> ();
}

impl<T> Testable for T
where
    T: Fn(),
{
    fn run(&self) {
        serial_print!("{}...\t", core::any::type_name::<T>());
        self();
        serial_println!("[ok]");
    }
}

/// The test runner that iterates over all test cases
pub fn test_runner(tests: &[&dyn Testable]) {
    serial_println!("Running {} tests", tests.len());
    for test in tests {
        test.run();
    }
    exit_qemu(QemuExitCode::Success);
}

/// Panic handler for tests
pub fn test_panic_handler(info: &PanicInfo) -> ! {
    serial_println!("[failed]\n");
    serial_println!("Error: {}\n", info);
    exit_qemu(QemuExitCode::Failed);
    hlt_loop()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_qemu(exit_code: QemuExitCode) {
    use x86_64::instructions::port::Port;

    unsafe {
        let mut port = Port::new(0xf4);
        port.write(exit_code as u32);
    }
}

pub fn hlt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

/// Entry point for `cargo test`
#[cfg(test)]
bootloader::entry_point!(test_kernel_main);

#[cfg(test)]
fn test_kernel_main(_boot_info: &'static bootloader::BootInfo) -> ! {
    init();
    test_main();
    hlt_loop()
}

#[cfg(test)]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}
```

### Exercice 1.2: Writing Unit Tests

```rust
// In any module, tests are marked with #[test_case]

#[test_case]
fn trivial_assertion() {
    assert_eq!(1, 1);
}

// In src/vga_buffer.rs
#[test_case]
fn test_println_simple() {
    println!("test_println_simple output");
}

#[test_case]
fn test_println_many() {
    for _ in 0..200 {
        println!("test_println_many output");
    }
}

#[test_case]
fn test_println_output() {
    use core::fmt::Write;
    use x86_64::instructions::interrupts;

    let s = "Some test string that fits on a single line";
    interrupts::without_interrupts(|| {
        let mut writer = WRITER.lock();
        writeln!(writer, "\n{}", s).expect("writeln failed");
        for (i, c) in s.chars().enumerate() {
            let screen_char = writer.buffer.chars[BUFFER_HEIGHT - 2][i].read();
            assert_eq!(char::from(screen_char.ascii_character), c);
        }
    });
}

// In src/interrupts.rs
#[test_case]
fn test_breakpoint_exception() {
    // Invoke a breakpoint exception
    x86_64::instructions::interrupts::int3();
}
```

### Exercice 1.3: Integration Tests

**tests/basic_boot.rs:**

```rust
#![no_std]
#![no_main]
#![feature(custom_test_frameworks)]
#![test_runner(odyssey_os::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;
use odyssey_os::{println, serial_print, serial_println};

bootloader::entry_point!(test_kernel_main);

fn test_kernel_main(_boot_info: &'static bootloader::BootInfo) -> ! {
    test_main();
    loop {}
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    odyssey_os::test_panic_handler(info)
}

#[test_case]
fn test_println() {
    serial_print!("test_println... ");
    println!("test_println output");
    serial_println!("[ok]");
}

#[test_case]
fn test_boot_info_valid() {
    // Boot info validation would go here
}
```

**tests/should_panic.rs:**

```rust
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use odyssey_os::{exit_qemu, serial_print, serial_println, QemuExitCode};

bootloader::entry_point!(test_kernel_main);

fn test_kernel_main(_boot_info: &'static bootloader::BootInfo) -> ! {
    should_fail();
    serial_println!("[test did not panic]");
    exit_qemu(QemuExitCode::Failed);
    loop {}
}

fn should_fail() {
    serial_print!("should_panic::should_fail...\t");
    assert_eq!(0, 1);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    serial_println!("[ok]");
    exit_qemu(QemuExitCode::Success);
    loop {}
}
```

### Exercice 1.4: Cargo Configuration

**Cargo.toml:**

```toml
[package]
name = "odyssey_os"
version = "0.1.0"
edition = "2021"

[dependencies]
bootloader = "0.9"
volatile = "0.2.6"
spin = "0.5.2"
x86_64 = "0.14"
uart_16550 = "0.2.0"
pic8259 = "0.10.1"
pc-keyboard = "0.7"
linked_list_allocator = "0.9.0"

[dependencies.lazy_static]
version = "1.0"
features = ["spin_no_std"]

[profile.dev]
panic = "abort"

[profile.release]
panic = "abort"

[package.metadata.bootimage]
test-args = [
    "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
    "-serial", "stdio",
    "-display", "none"
]
test-success-exit-code = 33
test-timeout = 300

# Disable harness for integration tests
[[test]]
name = "basic_boot"
harness = false

[[test]]
name = "should_panic"
harness = false

[[test]]
name = "stack_overflow"
harness = false
```

---

## Partie 2: Multiboot2 Specification (2.8.30)

### Exercice 2.1: Multiboot2 Header

**boot.asm (for GRUB compatibility):**

```nasm
section .multiboot_header
header_start:
    ; Magic number
    dd 0xe85250d6                ; Multiboot2 magic
    ; Architecture
    dd 0                         ; 0 = protected mode i386
    ; Header length
    dd header_end - header_start
    ; Checksum
    dd 0x100000000 - (0xe85250d6 + 0 + (header_end - header_start))

    ; Optional tags go here

    ; Framebuffer tag (optional)
    align 8
    dw 5                         ; Type = framebuffer
    dw 0                         ; Flags
    dd 20                        ; Size
    dd 1024                      ; Width
    dd 768                       ; Height
    dd 32                        ; Depth

    ; End tag
    align 8
    dw 0                         ; Type
    dw 0                         ; Flags
    dd 8                         ; Size
header_end:

section .bss
align 16
stack_bottom:
    resb 64 * 1024              ; 64 KB stack
stack_top:

section .text
global _start
extern kernel_main

_start:
    ; Set up stack
    mov esp, stack_top

    ; Push multiboot info pointer (EBX)
    push ebx
    ; Push multiboot magic (EAX)
    push eax

    ; Call kernel
    call kernel_main

    ; Halt if kernel returns
    cli
.hang:
    hlt
    jmp .hang
```

### Exercice 2.2: Parsing Multiboot2 Info

**Cargo.toml:**

```toml
[dependencies]
multiboot2 = "0.20"
```

**src/multiboot.rs:**

```rust
use multiboot2::{BootInformation, BootInformationHeader};

const MULTIBOOT2_MAGIC: u32 = 0x36d76289;

/// Parse Multiboot2 boot information
pub fn parse_multiboot(magic: u32, info_ptr: u32) -> Option<BootInformation<'static>> {
    // Verify magic
    if magic != MULTIBOOT2_MAGIC {
        crate::serial_println!("Invalid Multiboot2 magic: {:#x}", magic);
        return None;
    }

    // Parse boot information
    let boot_info = unsafe {
        BootInformation::load(info_ptr as *const BootInformationHeader)
            .ok()?
    };

    Some(boot_info)
}

/// Print all available Multiboot2 tags
pub fn print_multiboot_info(boot_info: &BootInformation) {
    crate::serial_println!("Multiboot2 Information:");

    // Memory map
    if let Some(memory_map_tag) = boot_info.memory_map_tag() {
        crate::serial_println!("\nMemory Map:");
        for area in memory_map_tag.memory_areas() {
            crate::serial_println!(
                "  {:#016x} - {:#016x} ({} KB) - {:?}",
                area.start_address(),
                area.end_address(),
                (area.end_address() - area.start_address()) / 1024,
                area.typ()
            );
        }
    }

    // ELF sections
    if let Some(elf_sections_tag) = boot_info.elf_sections_tag() {
        crate::serial_println!("\nKernel ELF Sections:");
        for section in elf_sections_tag.sections() {
            crate::serial_println!(
                "  {} - {:#x} ({} bytes)",
                section.name().unwrap_or("<unnamed>"),
                section.start_address(),
                section.size()
            );
        }
    }

    // Framebuffer
    if let Some(fb_tag) = boot_info.framebuffer_tag() {
        crate::serial_println!("\nFramebuffer:");
        crate::serial_println!("  Address: {:#x}", fb_tag.address());
        crate::serial_println!("  Width: {}", fb_tag.width());
        crate::serial_println!("  Height: {}", fb_tag.height());
        crate::serial_println!("  Pitch: {}", fb_tag.pitch());
        crate::serial_println!("  BPP: {}", fb_tag.bpp());
    }

    // Boot loader name
    if let Some(name_tag) = boot_info.boot_loader_name_tag() {
        crate::serial_println!("\nBoot Loader: {}", name_tag.name().unwrap_or("<unknown>"));
    }

    // Command line
    if let Some(cmdline_tag) = boot_info.command_line_tag() {
        crate::serial_println!("Command Line: {}", cmdline_tag.cmdline().unwrap_or("<none>"));
    }

    // ACPI RSDP
    if let Some(rsdp) = boot_info.rsdp_v1_tag() {
        crate::serial_println!("\nACPI RSDP v1 found at {:#x}", rsdp as *const _ as usize);
    }
    if let Some(rsdp) = boot_info.rsdp_v2_tag() {
        crate::serial_println!("\nACPI RSDP v2 found at {:#x}", rsdp as *const _ as usize);
    }
}
```

### Exercice 2.3: Memory Map from Multiboot2

```rust
use multiboot2::{BootInformation, MemoryAreaType};
use x86_64::structures::paging::{PhysFrame, Size4KiB, FrameAllocator};
use x86_64::PhysAddr;

/// Frame allocator using Multiboot2 memory map
pub struct Multiboot2FrameAllocator {
    memory_areas: &'static [multiboot2::MemoryArea],
    current_area: usize,
    current_frame: u64,
}

impl Multiboot2FrameAllocator {
    pub fn new(boot_info: &'static BootInformation) -> Self {
        let memory_map = boot_info.memory_map_tag()
            .expect("Memory map tag required");

        let areas: &'static [multiboot2::MemoryArea] = unsafe {
            core::slice::from_raw_parts(
                memory_map.memory_areas().next().unwrap() as *const _,
                memory_map.memory_areas().count()
            )
        };

        Multiboot2FrameAllocator {
            memory_areas: areas,
            current_area: 0,
            current_frame: 0,
        }
    }

    fn advance_to_usable(&mut self) {
        while self.current_area < self.memory_areas.len() {
            let area = &self.memory_areas[self.current_area];
            if area.typ() == MemoryAreaType::Available {
                let start_frame = area.start_address() / 4096;
                let end_frame = area.end_address() / 4096;

                if self.current_frame < start_frame {
                    self.current_frame = start_frame;
                }

                if self.current_frame < end_frame {
                    return;
                }
            }
            self.current_area += 1;
        }
    }
}

unsafe impl FrameAllocator<Size4KiB> for Multiboot2FrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.advance_to_usable();

        if self.current_area >= self.memory_areas.len() {
            return None;
        }

        let frame = PhysFrame::containing_address(PhysAddr::new(self.current_frame * 4096));
        self.current_frame += 1;
        Some(frame)
    }
}
```

### Exercice 2.4: Framebuffer Graphics

```rust
use multiboot2::FramebufferTag;

pub struct Framebuffer {
    buffer: &'static mut [u8],
    width: u32,
    height: u32,
    pitch: u32,
    bpp: u8,
}

impl Framebuffer {
    pub fn from_multiboot(fb_tag: &FramebufferTag) -> Self {
        let size = (fb_tag.pitch() * fb_tag.height()) as usize;

        let buffer = unsafe {
            core::slice::from_raw_parts_mut(fb_tag.address() as *mut u8, size)
        };

        Framebuffer {
            buffer,
            width: fb_tag.width(),
            height: fb_tag.height(),
            pitch: fb_tag.pitch(),
            bpp: fb_tag.bpp(),
        }
    }

    pub fn put_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }

        let offset = (y * self.pitch + x * (self.bpp as u32 / 8)) as usize;

        match self.bpp {
            32 => {
                self.buffer[offset] = (color & 0xFF) as u8;         // Blue
                self.buffer[offset + 1] = ((color >> 8) & 0xFF) as u8;  // Green
                self.buffer[offset + 2] = ((color >> 16) & 0xFF) as u8; // Red
                self.buffer[offset + 3] = 0xFF;                     // Alpha
            }
            24 => {
                self.buffer[offset] = (color & 0xFF) as u8;
                self.buffer[offset + 1] = ((color >> 8) & 0xFF) as u8;
                self.buffer[offset + 2] = ((color >> 16) & 0xFF) as u8;
            }
            _ => {}
        }
    }

    pub fn clear(&mut self, color: u32) {
        for y in 0..self.height {
            for x in 0..self.width {
                self.put_pixel(x, y, color);
            }
        }
    }

    pub fn draw_rect(&mut self, x: u32, y: u32, w: u32, h: u32, color: u32) {
        for dy in 0..h {
            for dx in 0..w {
                self.put_pixel(x + dx, y + dy, color);
            }
        }
    }
}
```

### Exercice 2.5: Transition to 64-bit

**boot64.asm:**

```nasm
; Transition from 32-bit protected mode to 64-bit long mode

section .text
bits 32

global setup_long_mode
extern kernel_main_64

setup_long_mode:
    ; Disable paging first
    mov eax, cr0
    and eax, ~(1 << 31)
    mov cr0, eax

    ; Set up identity paging
    call setup_page_tables
    call enable_paging

    ; Load 64-bit GDT
    lgdt [gdt64.pointer]

    ; Jump to 64-bit code
    jmp gdt64.code:long_mode_start

setup_page_tables:
    ; Zero out page tables
    mov edi, 0x1000
    mov cr3, edi
    xor eax, eax
    mov ecx, 4096
    rep stosd
    mov edi, cr3

    ; Set up PML4
    mov DWORD [edi], 0x2003      ; PML4[0] -> PDPT
    add edi, 0x1000

    ; Set up PDPT
    mov DWORD [edi], 0x3003      ; PDPT[0] -> PD
    add edi, 0x1000

    ; Set up PD with 2MB pages (identity map first 1GB)
    mov ebx, 0x00000083          ; Present + Write + Large
    mov ecx, 512
.set_entry:
    mov DWORD [edi], ebx
    add ebx, 0x200000            ; 2MB
    add edi, 8
    loop .set_entry

    ret

enable_paging:
    ; Enable PAE
    mov eax, cr4
    or eax, 1 << 5
    mov cr4, eax

    ; Set long mode bit in EFER
    mov ecx, 0xC0000080
    rdmsr
    or eax, 1 << 8
    wrmsr

    ; Enable paging
    mov eax, cr0
    or eax, 1 << 31
    mov cr0, eax

    ret

bits 64

long_mode_start:
    ; Clear segment registers
    mov ax, 0
    mov ss, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    ; Call 64-bit kernel
    call kernel_main_64

    ; Should never return
    hlt

section .rodata
gdt64:
    dq 0                         ; Null descriptor
.code: equ $ - gdt64
    dq (1<<43) | (1<<44) | (1<<47) | (1<<53) ; Code segment
.pointer:
    dw $ - gdt64 - 1
    dq gdt64
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Custom test framework | 25 |
| Integration tests | 15 |
| Multiboot2 header | 15 |
| Boot info parsing | 20 |
| Memory map usage | 15 |
| Framebuffer support | 10 |
| **Total** | **100** |

---

## Ressources

- [Testing - Writing an OS in Rust](https://os.phil-opp.com/testing/)
- [Multiboot2 Specification](https://www.gnu.org/software/grub/manual/multiboot2/)
- [multiboot2 crate docs](https://docs.rs/multiboot2/)
- [OSDev Wiki: Multiboot](https://wiki.osdev.org/Multiboot)
