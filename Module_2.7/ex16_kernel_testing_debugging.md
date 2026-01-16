# [Module 2.7] - Exercise 16: Kernel Testing & Debugging

## Metadonnees

```yaml
module: "2.7 - Kernel Development"
exercise: "ex16"
title: "Testing and Debugging Kernel Code"
difficulty: expert
estimated_time: "5 heures"
prerequisite_exercises: ["ex15"]
concepts_requis: ["kernel testing", "GDB", "debugging"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.7.27: Testing Kernel Code (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.7.27.a | `#![feature(custom_test_frameworks)]` | Custom test framework |
| 2.7.27.b | `#![test_runner(...)]` | Custom test runner |
| 2.7.27.c | `#![reexport_test_harness_main]` | Entry point control |
| 2.7.27.d | `#[test_case]` | Test case marker |
| 2.7.27.e | QEMU exit | `isa-debug-exit` device |
| 2.7.27.f | Serial output | Test result output |
| 2.7.27.g | Integration tests | Separate test binaries |
| 2.7.27.h | `bootimage test` | Running tests |
| 2.7.27.i | `should_panic` | Panic tests |
| 2.7.27.j | Timeout | Detecting hangs |

### 2.7.28: Kernel Debugging (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.7.28.a | QEMU + GDB | Kernel debugging setup |
| 2.7.28.b | `-s -S` flags | GDB server mode |
| 2.7.28.c | `target remote :1234` | GDB connection |
| 2.7.28.d | Symbols | Debug info preservation |
| 2.7.28.e | Breakpoints | `break function` |
| 2.7.28.f | Serial logging | `uart_16550` crate |
| 2.7.28.g | `log` crate | Logging facade |
| 2.7.28.h | Panic messages | Informative panic output |
| 2.7.28.i | Stack traces | `unwinding` crate |
| 2.7.28.j | `addr2line` | Address to source mapping |

---

## Partie 1: Custom Test Framework (2.7.27)

### Exercice 1.1: Test Framework Setup

**src/lib.rs - Test Framework:**

```rust
#![no_std]
#![cfg_attr(test, no_main)]
#![feature(custom_test_frameworks)]
#![test_runner(crate::test_runner)]
#![reexport_test_harness_main = "test_main"]

use core::panic::PanicInfo;

// Test trait for custom output
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

// Custom test runner
pub fn test_runner(tests: &[&dyn Testable]) {
    serial_println!("Running {} tests", tests.len());
    for test in tests {
        test.run();
    }
    exit_qemu(QemuExitCode::Success);
}

// Panic handler for tests
pub fn test_panic_handler(info: &PanicInfo) -> ! {
    serial_println!("[failed]\n");
    serial_println!("Error: {}\n", info);
    exit_qemu(QemuExitCode::Failed);
    hlt_loop()
}

// QEMU exit codes
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

// Test entry point
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

**Questions:**
1. Pourquoi ne peut-on pas utiliser `#[test]` standard en no_std ?
2. Comment `reexport_test_harness_main` permet de controler le point d'entree ?
3. Que fait `isa-debug-exit` dans QEMU ?

### Exercice 1.2: Writing Unit Tests

```rust
// Unit tests in src/vga_buffer.rs

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

// Test in src/interrupts.rs
#[test_case]
fn test_breakpoint_exception() {
    // Invoke breakpoint and verify we continue
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
use odyssey_os::println;

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
    println!("test_println output");
}
```

**tests/should_panic.rs:**

```rust
#![no_std]
#![no_main]

use core::panic::PanicInfo;
use odyssey_os::{exit_qemu, serial_println, QemuExitCode};

bootloader::entry_point!(test_kernel_main);

fn test_kernel_main(_boot_info: &'static bootloader::BootInfo) -> ! {
    should_fail();
    serial_println!("[test did not panic]");
    exit_qemu(QemuExitCode::Failed);
    loop {}
}

fn should_fail() {
    serial_println!("should_panic::should_fail...\t");
    assert_eq!(0, 1);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    serial_println!("[ok]");
    exit_qemu(QemuExitCode::Success);
    loop {}
}
```

**tests/stack_overflow.rs:**

```rust
#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

use core::panic::PanicInfo;
use odyssey_os::{exit_qemu, serial_println, QemuExitCode};
use lazy_static::lazy_static;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame};

bootloader::entry_point!(test_kernel_main);

fn test_kernel_main(_boot_info: &'static bootloader::BootInfo) -> ! {
    serial_println!("stack_overflow::stack_overflow...\t");

    odyssey_os::gdt::init();
    init_test_idt();

    // Trigger stack overflow
    stack_overflow();

    panic!("Execution continued after stack overflow");
}

#[allow(unconditional_recursion)]
fn stack_overflow() {
    stack_overflow();
    volatile::Volatile::new(0).read(); // Prevent tail recursion
}

lazy_static! {
    static ref TEST_IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();
        unsafe {
            idt.double_fault
                .set_handler_fn(test_double_fault_handler)
                .set_stack_index(odyssey_os::gdt::DOUBLE_FAULT_IST_INDEX);
        }
        idt
    };
}

fn init_test_idt() {
    TEST_IDT.load();
}

extern "x86-interrupt" fn test_double_fault_handler(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    serial_println!("[ok]");
    exit_qemu(QemuExitCode::Success);
    loop {}
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    odyssey_os::test_panic_handler(info)
}
```

**Cargo.toml test configuration:**

```toml
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

## Partie 2: Kernel Debugging (2.7.28)

### Exercice 2.1: QEMU + GDB Setup

**Run QEMU with GDB server:**

```bash
# Start QEMU waiting for GDB
qemu-system-x86_64 \
    -drive format=raw,file=target/x86_64-odyssey_os/debug/bootimage-odyssey_os.bin \
    -s -S \
    -serial stdio

# -s: Start GDB server on :1234
# -S: Pause CPU at startup
```

**GDB commands:**

```gdb
# Connect to QEMU
target remote :1234

# Load symbols
symbol-file target/x86_64-odyssey_os/debug/odyssey_os

# Set breakpoint at kernel entry
break kernel_main

# Continue execution
continue

# Step through code
next
step

# Print variables
print variable_name
info registers

# Examine memory
x/10xw 0xb8000

# Backtrace
backtrace

# Continue
continue

# Quit
quit
```

**.gdbinit for automation:**

```gdb
# .gdbinit
set disassembly-flavor intel
target remote :1234
symbol-file target/x86_64-odyssey_os/debug/odyssey_os
break kernel_main
continue
```

### Exercice 2.2: Enhanced Logging

**src/logger.rs:**

```rust
use log::{Record, Level, Metadata, LevelFilter, SetLoggerError};
use crate::{serial_println, println};

static LOGGER: KernelLogger = KernelLogger;

struct KernelLogger;

impl log::Log for KernelLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level_color = match record.level() {
                Level::Error => "\x1b[31m", // Red
                Level::Warn  => "\x1b[33m", // Yellow
                Level::Info  => "\x1b[32m", // Green
                Level::Debug => "\x1b[34m", // Blue
                Level::Trace => "\x1b[90m", // Gray
            };
            let reset = "\x1b[0m";

            // Output to serial with colors
            serial_println!(
                "{}[{:5}]{} {}:{} - {}",
                level_color,
                record.level(),
                reset,
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            );

            // Also output to VGA (without colors)
            if record.level() <= Level::Info {
                println!(
                    "[{:5}] {}:{} - {}",
                    record.level(),
                    record.file().unwrap_or("unknown"),
                    record.line().unwrap_or(0),
                    record.args()
                );
            }
        }
    }

    fn flush(&self) {}
}

pub fn init() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER)?;
    log::set_max_level(LevelFilter::Trace);
    Ok(())
}

// Usage macros (from log crate)
// log::error!("Critical error: {}", err);
// log::warn!("Warning: {}", msg);
// log::info!("Info: {}", msg);
// log::debug!("Debug: {}", msg);
// log::trace!("Trace: {}", msg);
```

### Exercice 2.3: Enhanced Panic Handler

**src/panic.rs:**

```rust
use core::panic::PanicInfo;
use crate::{serial_println, println, hlt_loop};

pub fn panic_handler(info: &PanicInfo) -> ! {
    // Print to both serial and VGA
    serial_println!("\n========== KERNEL PANIC ==========");
    println!("\n========== KERNEL PANIC ==========");

    // Location info
    if let Some(location) = info.location() {
        serial_println!(
            "Location: {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
        println!(
            "Location: {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    }

    // Message
    if let Some(message) = info.message() {
        serial_println!("Message: {}", message);
        println!("Message: {}", message);
    }

    // Dump registers
    dump_registers();

    // Print stack trace if available
    #[cfg(feature = "unwinding")]
    print_stack_trace();

    serial_println!("==================================\n");
    println!("==================================");
    println!("System halted. Press reset to reboot.");

    hlt_loop()
}

fn dump_registers() {
    use x86_64::registers::control::{Cr0, Cr2, Cr3, Cr4};

    serial_println!("\n--- CPU Registers ---");
    serial_println!("CR0: {:?}", Cr0::read());
    serial_println!("CR2: {:?}", Cr2::read());
    serial_println!("CR3: {:?}", Cr3::read());
    serial_println!("CR4: {:?}", Cr4::read());
}

#[cfg(feature = "unwinding")]
fn print_stack_trace() {
    serial_println!("\n--- Stack Trace ---");

    // Walk the stack frames
    let mut rbp: usize;
    unsafe {
        core::arch::asm!("mov {}, rbp", out(reg) rbp);
    }

    let mut frame = 0;
    while rbp != 0 && frame < 20 {
        let return_addr = unsafe { *((rbp + 8) as *const usize) };
        serial_println!("  #{}: {:#x}", frame, return_addr);

        rbp = unsafe { *(rbp as *const usize) };
        frame += 1;
    }
}
```

### Exercice 2.4: addr2line Integration

**debug_symbols.sh:**

```bash
#!/bin/bash
# Convert address to source location

ELF_FILE="target/x86_64-odyssey_os/debug/odyssey_os"

if [ -z "$1" ]; then
    echo "Usage: $0 <address>"
    exit 1
fi

addr2line -e "$ELF_FILE" -f -C "$1"

# Example output:
# kernel_main
# /path/to/src/main.rs:42
```

**Makefile additions:**

```makefile
# Debug targets
debug:
	qemu-system-x86_64 \
		-drive format=raw,file=$(BOOTIMAGE) \
		-s -S \
		-serial stdio &
	gdb -x .gdbinit

symbols:
	nm $(ELF_FILE) | sort

disasm:
	objdump -d $(ELF_FILE) | less

addr2line:
	@read -p "Address: " addr; \
	addr2line -e $(ELF_FILE) -f -C $$addr
```

---

## Partie 3: Test Configuration

### Exercice 3.1: Cargo.toml Configuration

```toml
[package.metadata.bootimage]
test-args = [
    "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
    "-serial", "stdio",
    "-display", "none"
]
test-success-exit-code = 33
test-timeout = 300

# Run all tests
# cargo test

# Run specific test
# cargo test --test basic_boot

# Run with output
# cargo test -- --nocapture
```

### Exercice 3.2: CI Integration

**.github/workflows/test.yml:**

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v2

    - name: Install Rust nightly
      uses: actions-rs/toolchain@v1
      with:
        toolchain: nightly
        override: true
        components: rust-src, llvm-tools-preview

    - name: Install bootimage
      run: cargo install bootimage

    - name: Install QEMU
      run: sudo apt-get install -y qemu-system-x86

    - name: Run tests
      run: cargo test
      timeout-minutes: 10
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Custom test framework | 20 |
| Unit tests | 15 |
| Integration tests | 20 |
| GDB debugging | 20 |
| Logging system | 15 |
| Panic handling | 10 |
| **Total** | **100** |

---

## Ressources

- [Testing - Writing an OS in Rust](https://os.phil-opp.com/testing/)
- [GDB Documentation](https://www.gnu.org/software/gdb/documentation/)
- [QEMU Documentation](https://www.qemu.org/docs/master/)
- [addr2line crate](https://docs.rs/addr2line/)
