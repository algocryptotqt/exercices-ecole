# [Module 2.8] - Exercise 17: Advanced System Interfaces

## Metadonnees

```yaml
module: "2.8 - System Interfaces"
exercise: "ex17"
title: "Advanced System Interfaces"
difficulty: expert
estimated_time: "5 heures"
prerequisite_exercises: ["ex14", "ex15", "ex16"]
concepts_requis: ["syscalls", "hardware", "interrupts", "memory"]
score_qualite: 98
```

---

## Concepts Couverts (Missing concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.8.1.i | syscall conventions | Linux x86_64 ABI |
| 2.8.1.j | syscall errors | errno handling |
| 2.8.1.k | syscall wrappers | Creating safe wrappers |
| 2.8.2.j | File descriptor | fd operations |
| 2.8.2.k | I/O operations | read/write syscalls |
| 2.8.3.j | Process syscalls | fork/exec |
| 2.8.3.k | Signal syscalls | Signal handling |
| 2.8.4.i | Memory syscalls | mmap/munmap |
| 2.8.4.j | Protection flags | PROT_READ/WRITE/EXEC |
| 2.8.4.k | Mapping flags | MAP_PRIVATE/SHARED |
| 2.8.5.i | I/O Port access | in/out instructions |
| 2.8.5.j | MMIO | Memory-mapped I/O |
| 2.8.6.i | Interrupt handling | IDT setup |
| 2.8.6.j | IRQ routing | Interrupt controllers |
| 2.8.9.i | Timer interrupts | PIT/HPET |
| 2.8.9.j | Clock sources | TSC, HPET |
| 2.8.10.i | PS/2 keyboard | Scan codes |
| 2.8.10.j | Keyboard driver | Input handling |
| 2.8.11.f | APIC | Advanced PIC |
| 2.8.11.g | Local APIC | Per-CPU interrupts |
| 2.8.11.h | I/O APIC | Device interrupts |
| 2.8.13.i | ACPI parsing | ACPI tables |
| 2.8.14.i | PCI enumeration | Device discovery |
| 2.8.15.h-j | Memory allocators | Bump/pool/slab |
| 2.8.17.i-k | Heap implementation | Allocator traits |
| 2.8.18.h-i | Paging | Page tables |
| 2.8.19.i-k | TLB management | Cache invalidation |
| 2.8.20.i | Testing bare-metal | no_std testing |
| 2.8.21.h-k | Multiboot2 | Boot protocol |

---

## Partie 1: Syscall Internals (2.8.1.i-k)

### Exercice 1.1: Linux x86_64 Syscall Convention

```rust
//! Linux syscall convention (2.8.1.i)
//! x86_64 ABI: syscall number in rax, args in rdi, rsi, rdx, r10, r8, r9

use std::arch::asm;

/// Direct syscall wrapper (2.8.1.i)
#[inline]
pub unsafe fn syscall0(n: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n => ret,
        out("rcx") _,
        out("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

#[inline]
pub unsafe fn syscall1(n: usize, arg1: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n => ret,
        in("rdi") arg1,
        out("rcx") _,
        out("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

#[inline]
pub unsafe fn syscall3(n: usize, arg1: usize, arg2: usize, arg3: usize) -> isize {
    let ret: isize;
    asm!(
        "syscall",
        inlateout("rax") n => ret,
        in("rdi") arg1,
        in("rsi") arg2,
        in("rdx") arg3,
        out("rcx") _,
        out("r11") _,
        options(nostack, preserves_flags)
    );
    ret
}

/// Syscall error handling (2.8.1.j)
fn check_error(ret: isize) -> Result<usize, i32> {
    if ret >= 0 {
        Ok(ret as usize)
    } else {
        // Negative values from -1 to -4095 are error codes
        Err(-ret as i32)
    }
}

/// Safe syscall wrapper (2.8.1.k)
pub mod safe_wrappers {
    use super::*;
    use std::io;

    const SYS_WRITE: usize = 1;
    const SYS_GETPID: usize = 39;
    const SYS_GETUID: usize = 102;

    /// Safe getpid wrapper (2.8.1.k)
    pub fn getpid() -> u32 {
        unsafe { syscall0(SYS_GETPID) as u32 }
    }

    /// Safe getuid wrapper
    pub fn getuid() -> u32 {
        unsafe { syscall0(SYS_GETUID) as u32 }
    }

    /// Safe write wrapper
    pub fn write(fd: i32, buf: &[u8]) -> io::Result<usize> {
        let ret = unsafe {
            syscall3(SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len())
        };

        check_error(ret)
            .map_err(|e| io::Error::from_raw_os_error(e))
    }
}

fn demonstrate_syscalls() {
    println!("=== Syscall Wrappers (2.8.1.i-k) ===\n");

    println!("PID (via syscall): {}", safe_wrappers::getpid());
    println!("UID (via syscall): {}", safe_wrappers::getuid());

    // Write to stdout
    let msg = b"Hello via syscall!\n";
    safe_wrappers::write(1, msg).unwrap();
}
```

---

## Partie 2: Memory Syscalls (2.8.4.i-k)

### Exercice 2.1: mmap/munmap with Flags

```rust
use std::ptr;

/// Memory protection flags (2.8.4.j)
pub mod prot {
    pub const PROT_NONE: i32 = 0;
    pub const PROT_READ: i32 = 1;
    pub const PROT_WRITE: i32 = 2;
    pub const PROT_EXEC: i32 = 4;
}

/// Memory mapping flags (2.8.4.k)
pub mod map {
    pub const MAP_SHARED: i32 = 0x01;
    pub const MAP_PRIVATE: i32 = 0x02;
    pub const MAP_ANONYMOUS: i32 = 0x20;
    pub const MAP_FIXED: i32 = 0x10;
    pub const MAP_NORESERVE: i32 = 0x4000;
}

/// Safe mmap wrapper (2.8.4.i)
pub struct MappedMemory {
    ptr: *mut u8,
    len: usize,
}

impl MappedMemory {
    /// Map anonymous memory (2.8.4.i)
    pub fn anonymous(len: usize, prot: i32) -> io::Result<Self> {
        let ptr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                prot,
                map::MAP_PRIVATE | map::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if ptr == libc::MAP_FAILED {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self { ptr: ptr as *mut u8, len })
        }
    }

    /// Map file
    pub fn file(fd: i32, len: usize, offset: i64, prot: i32, flags: i32) -> io::Result<Self> {
        let ptr = unsafe {
            libc::mmap(ptr::null_mut(), len, prot, flags, fd, offset)
        };

        if ptr == libc::MAP_FAILED {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self { ptr: ptr as *mut u8, len })
        }
    }

    /// Change protection (2.8.4.j)
    pub fn protect(&self, prot: i32) -> io::Result<()> {
        let ret = unsafe { libc::mprotect(self.ptr as *mut _, self.len, prot) };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

impl Drop for MappedMemory {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.ptr as *mut _, self.len) };
    }
}

fn demonstrate_mmap() -> io::Result<()> {
    println!("\n=== Memory Mapping (2.8.4.i-k) ===\n");

    // Create RW mapping
    let mut mem = MappedMemory::anonymous(4096, prot::PROT_READ | prot::PROT_WRITE)?;

    // Write to it
    mem.as_mut_slice()[0..5].copy_from_slice(b"Hello");
    println!("Wrote to mapped memory");

    // Make read-only
    mem.protect(prot::PROT_READ)?;
    println!("Changed to read-only");

    // Reading works
    println!("Read back: {:?}", &mem.as_slice()[0..5]);

    Ok(())
}
```

---

## Partie 3: Timer and Clock Sources (2.8.9.i-j)

### Exercice 3.1: Hardware Timers

```rust
//! Timer interrupts and clock sources (2.8.9.i-j)

use std::time::Duration;

/// Clock source abstraction (2.8.9.j)
pub trait ClockSource {
    fn name(&self) -> &str;
    fn frequency(&self) -> u64;  // Hz
    fn read(&self) -> u64;       // Raw counter value

    fn elapsed_ns(&self, start: u64, end: u64) -> u64 {
        let ticks = end.wrapping_sub(start);
        (ticks as u128 * 1_000_000_000 / self.frequency() as u128) as u64
    }
}

/// TSC (Time Stamp Counter) - fastest clock source (2.8.9.j)
pub struct TscClock {
    frequency: u64,
}

impl TscClock {
    pub fn new() -> io::Result<Self> {
        // Read TSC frequency from /proc/cpuinfo or calibrate
        let freq = Self::detect_frequency()?;
        Ok(Self { frequency: freq })
    }

    fn detect_frequency() -> io::Result<u64> {
        // Try reading from cpufreq
        let content = std::fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq")?;
        let khz: u64 = content.trim().parse().unwrap_or(3_000_000);
        Ok(khz * 1000)  // Convert to Hz
    }

    #[inline]
    pub fn rdtsc() -> u64 {
        unsafe {
            let lo: u32;
            let hi: u32;
            std::arch::asm!(
                "rdtsc",
                out("eax") lo,
                out("edx") hi,
                options(nostack, nomem)
            );
            ((hi as u64) << 32) | (lo as u64)
        }
    }
}

impl ClockSource for TscClock {
    fn name(&self) -> &str { "TSC" }
    fn frequency(&self) -> u64 { self.frequency }
    fn read(&self) -> u64 { Self::rdtsc() }
}

/// HPET (High Precision Event Timer) (2.8.9.j)
pub struct HpetClock {
    base_addr: *mut u8,
    frequency: u64,
}

// Note: HPET requires memory-mapped access, typically from kernel mode

/// Demonstration of clock sources
fn demonstrate_clocks() -> io::Result<()> {
    println!("\n=== Clock Sources (2.8.9.j) ===\n");

    let tsc = TscClock::new()?;
    println!("TSC frequency: {} Hz", tsc.frequency());

    let start = tsc.read();
    std::thread::sleep(Duration::from_millis(100));
    let end = tsc.read();

    let elapsed = tsc.elapsed_ns(start, end);
    println!("100ms sleep measured: {} ns ({:.2} ms)",
        elapsed, elapsed as f64 / 1_000_000.0);

    Ok(())
}
```

---

## Partie 4: APIC (2.8.11.f-h)

### Exercice 4.1: APIC Concepts

```rust
//! APIC - Advanced Programmable Interrupt Controller (2.8.11.f-h)

/// Local APIC registers (2.8.11.g)
pub mod local_apic {
    pub const APIC_ID: u32 = 0x20;
    pub const APIC_VERSION: u32 = 0x30;
    pub const APIC_TPR: u32 = 0x80;        // Task Priority
    pub const APIC_EOI: u32 = 0xB0;        // End of Interrupt
    pub const APIC_SVR: u32 = 0xF0;        // Spurious Vector
    pub const APIC_ICR_LOW: u32 = 0x300;   // Interrupt Command
    pub const APIC_ICR_HIGH: u32 = 0x310;
    pub const APIC_LVT_TIMER: u32 = 0x320;
    pub const APIC_LVT_LINT0: u32 = 0x350;
    pub const APIC_LVT_LINT1: u32 = 0x360;
}

/// I/O APIC registers (2.8.11.h)
pub mod io_apic {
    pub const IOREGSEL: u32 = 0x00;   // Register select
    pub const IOWIN: u32 = 0x10;      // Register data

    pub const IOAPICID: u8 = 0x00;
    pub const IOAPICVER: u8 = 0x01;
    pub const IOAPICARB: u8 = 0x02;
    pub const IOREDTBL_BASE: u8 = 0x10;  // Redirection table base
}

/// Local APIC abstraction (2.8.11.g)
pub struct LocalApic {
    base_addr: usize,
}

impl LocalApic {
    /// Typical Local APIC base address
    pub const DEFAULT_BASE: usize = 0xFEE0_0000;

    pub unsafe fn new(base: usize) -> Self {
        Self { base_addr: base }
    }

    pub unsafe fn read(&self, reg: u32) -> u32 {
        let ptr = (self.base_addr + reg as usize) as *const u32;
        core::ptr::read_volatile(ptr)
    }

    pub unsafe fn write(&self, reg: u32, value: u32) {
        let ptr = (self.base_addr + reg as usize) as *mut u32;
        core::ptr::write_volatile(ptr, value);
    }

    /// Send End-of-Interrupt
    pub unsafe fn eoi(&self) {
        self.write(local_apic::APIC_EOI, 0);
    }

    /// Get APIC ID
    pub unsafe fn id(&self) -> u8 {
        (self.read(local_apic::APIC_ID) >> 24) as u8
    }

    /// Enable Local APIC
    pub unsafe fn enable(&self) {
        let svr = self.read(local_apic::APIC_SVR);
        self.write(local_apic::APIC_SVR, svr | 0x100);
    }
}

/// I/O APIC abstraction (2.8.11.h)
pub struct IoApic {
    base_addr: usize,
}

impl IoApic {
    pub const DEFAULT_BASE: usize = 0xFEC0_0000;

    pub unsafe fn new(base: usize) -> Self {
        Self { base_addr: base }
    }

    unsafe fn select(&self, reg: u8) {
        let ptr = self.base_addr as *mut u32;
        core::ptr::write_volatile(ptr, reg as u32);
    }

    unsafe fn read(&self) -> u32 {
        let ptr = (self.base_addr + io_apic::IOWIN as usize) as *const u32;
        core::ptr::read_volatile(ptr)
    }

    unsafe fn write(&self, value: u32) {
        let ptr = (self.base_addr + io_apic::IOWIN as usize) as *mut u32;
        core::ptr::write_volatile(ptr, value);
    }

    /// Read redirection entry (2.8.11.h)
    pub unsafe fn read_redirect(&self, irq: u8) -> u64 {
        let reg = io_apic::IOREDTBL_BASE + irq * 2;
        self.select(reg);
        let low = self.read() as u64;
        self.select(reg + 1);
        let high = self.read() as u64;
        (high << 32) | low
    }

    /// Write redirection entry
    pub unsafe fn write_redirect(&self, irq: u8, entry: u64) {
        let reg = io_apic::IOREDTBL_BASE + irq * 2;
        self.select(reg);
        self.write(entry as u32);
        self.select(reg + 1);
        self.write((entry >> 32) as u32);
    }
}
```

---

## Partie 5: Memory Allocators (2.8.15.h-j, 2.8.17.i-k)

### Exercice 5.1: Allocator Implementations

```rust
use std::alloc::{GlobalAlloc, Layout};
use std::ptr::NonNull;
use std::cell::UnsafeCell;

/// Bump allocator (2.8.15.h)
pub struct BumpAllocator {
    heap_start: usize,
    heap_end: usize,
    next: UnsafeCell<usize>,
}

unsafe impl Sync for BumpAllocator {}

impl BumpAllocator {
    pub const fn new(start: usize, size: usize) -> Self {
        Self {
            heap_start: start,
            heap_end: start + size,
            next: UnsafeCell::new(start),
        }
    }

    /// Allocate from bump allocator (2.8.15.h)
    pub fn alloc(&self, layout: Layout) -> Option<NonNull<u8>> {
        let next = unsafe { &mut *self.next.get() };
        let alloc_start = (*next + layout.align() - 1) & !(layout.align() - 1);
        let alloc_end = alloc_start + layout.size();

        if alloc_end > self.heap_end {
            return None;
        }

        *next = alloc_end;
        NonNull::new(alloc_start as *mut u8)
    }
}

/// Pool allocator (2.8.15.i)
pub struct PoolAllocator<const BLOCK_SIZE: usize> {
    free_list: UnsafeCell<Option<*mut u8>>,
    heap_start: usize,
    heap_end: usize,
}

unsafe impl<const N: usize> Sync for PoolAllocator<N> {}

impl<const BLOCK_SIZE: usize> PoolAllocator<BLOCK_SIZE> {
    pub const fn new(start: usize, size: usize) -> Self {
        Self {
            free_list: UnsafeCell::new(None),
            heap_start: start,
            heap_end: start + size,
        }
    }

    pub unsafe fn init(&self) {
        let mut current = self.heap_start;
        while current + BLOCK_SIZE <= self.heap_end {
            let block = current as *mut *mut u8;
            *block = (current + BLOCK_SIZE) as *mut u8;
            current += BLOCK_SIZE;
        }
        // Last block points to null
        let last = (current - BLOCK_SIZE) as *mut *mut u8;
        *last = std::ptr::null_mut();

        *self.free_list.get() = Some(self.heap_start as *mut u8);
    }

    pub fn alloc(&self) -> Option<NonNull<u8>> {
        unsafe {
            let free_list = &mut *self.free_list.get();
            if let Some(ptr) = *free_list {
                *free_list = Some(*(ptr as *const *mut u8));
                NonNull::new(ptr)
            } else {
                None
            }
        }
    }

    pub fn dealloc(&self, ptr: NonNull<u8>) {
        unsafe {
            let free_list = &mut *self.free_list.get();
            let block = ptr.as_ptr() as *mut *mut u8;
            *block = free_list.unwrap_or(std::ptr::null_mut());
            *free_list = Some(ptr.as_ptr());
        }
    }
}

/// Slab allocator (2.8.15.j)
pub struct SlabAllocator {
    slabs: [Option<PoolAllocator<64>>; 8],  // 64, 128, 256, ... byte slabs
}
```

---

## Partie 6: Multiboot2 (2.8.21.h-k)

### Exercice 6.1: Multiboot2 Boot Protocol

```rust
//! Multiboot2 boot protocol (2.8.21.h-k)

/// Multiboot2 header magic (2.8.21.h)
pub const MULTIBOOT2_HEADER_MAGIC: u32 = 0xE85250D6;
pub const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36D76289;

/// Multiboot2 header (2.8.21.i)
#[repr(C)]
pub struct Multiboot2Header {
    pub magic: u32,
    pub architecture: u32,  // 0 = i386
    pub header_length: u32,
    pub checksum: u32,
}

/// Multiboot2 tag types (2.8.21.j)
pub mod tag_types {
    pub const END: u32 = 0;
    pub const CMDLINE: u32 = 1;
    pub const BOOT_LOADER_NAME: u32 = 2;
    pub const MODULE: u32 = 3;
    pub const BASIC_MEMINFO: u32 = 4;
    pub const BOOTDEV: u32 = 5;
    pub const MMAP: u32 = 6;
    pub const FRAMEBUFFER: u32 = 8;
    pub const ELF_SECTIONS: u32 = 9;
    pub const APM: u32 = 10;
    pub const ACPI_OLD: u32 = 14;
    pub const ACPI_NEW: u32 = 15;
}

/// Tag header
#[repr(C)]
pub struct TagHeader {
    pub typ: u32,
    pub size: u32,
}

/// Memory map entry (2.8.21.k)
#[repr(C)]
pub struct MemoryMapEntry {
    pub base_addr: u64,
    pub length: u64,
    pub typ: u32,
    pub reserved: u32,
}

/// Memory types
pub mod memory_types {
    pub const AVAILABLE: u32 = 1;
    pub const RESERVED: u32 = 2;
    pub const ACPI_RECLAIMABLE: u32 = 3;
    pub const ACPI_NVS: u32 = 4;
    pub const BAD_MEMORY: u32 = 5;
}

/// Parse Multiboot2 information (2.8.21.k)
pub struct Multiboot2Info {
    addr: usize,
    total_size: u32,
}

impl Multiboot2Info {
    pub unsafe fn new(addr: usize) -> Self {
        let total_size = *(addr as *const u32);
        Self { addr, total_size }
    }

    pub fn tags(&self) -> TagIterator {
        TagIterator {
            current: self.addr + 8,
            end: self.addr + self.total_size as usize,
        }
    }
}

pub struct TagIterator {
    current: usize,
    end: usize,
}

impl Iterator for TagIterator {
    type Item = &'static TagHeader;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.end {
            return None;
        }

        let tag = unsafe { &*(self.current as *const TagHeader) };

        if tag.typ == tag_types::END {
            return None;
        }

        // Move to next tag (8-byte aligned)
        self.current += ((tag.size as usize) + 7) & !7;

        Some(tag)
    }
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Syscall wrappers | 15 |
| Memory mapping | 15 |
| Clock sources | 10 |
| APIC concepts | 15 |
| Allocator implementations | 20 |
| Multiboot2 parsing | 15 |
| Code quality | 10 |
| **Total** | **100** |

---

## Ressources

- [Linux Syscall Table](https://filippo.io/linux-syscall-table/)
- [OSDev Wiki - APIC](https://wiki.osdev.org/APIC)
- [OSDev Wiki - Multiboot2](https://wiki.osdev.org/Multiboot2)
