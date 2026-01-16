# [Module 2.6] - Exercise 13: Binary Analysis & Size Optimization

## Metadonnees

```yaml
module: "2.6 - Concurrency & Binary Tools"
exercise: "ex13"
title: "Binary Analysis & Size Optimization"
difficulty: avance
estimated_time: "4 heures"
prerequisite_exercises: ["ex00"]
concepts_requis: ["ELF format", "compilation", "linking"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.6.21: Binary Analysis Tools (11 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.6.21.a | `readelf` | ELF structure analysis |
| 2.6.21.b | `objdump` | Disassembly tool |
| 2.6.21.c | `nm` | Symbol listing |
| 2.6.21.d | `ldd` | Dependency analysis |
| 2.6.21.e | `file` | File type detection |
| 2.6.21.f | `strings` | String extraction |
| 2.6.21.g | `strip` | Symbol stripping |
| 2.6.21.h | `objcopy` | Binary modification |
| 2.6.21.i | `cargo-bloat` | Size analysis |
| 2.6.21.j | `cargo-binutils` | Rust wrappers |
| 2.6.21.k | `twiggy` | Code size profiler |

### 2.6.22: Binary Size Optimization (11 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.6.22.a | Release build | `--release` flag |
| 2.6.22.b | LTO | `lto = true` setting |
| 2.6.22.c | `codegen-units = 1` | Better optimization |
| 2.6.22.d | `opt-level = "z"` | Size optimization |
| 2.6.22.e | `strip = true` | Strip symbols |
| 2.6.22.f | `panic = "abort"` | Smaller panic |
| 2.6.22.g | `#![no_std]` | No stdlib |
| 2.6.22.h | `min-sized-rust` | Size guide |
| 2.6.22.i | `cargo-bloat` | Find large functions |
| 2.6.22.j | `twiggy` | Detailed analysis |
| 2.6.22.k | UPX | Binary compression |

---

## Partie 1: Binary Analysis Tools (2.6.21)

### Exercice 1.1: Basic Binary Analysis

```bash
# Create a test binary
cat > test.rs << 'EOF'
fn main() {
    let numbers: Vec<i32> = (1..100).collect();
    let sum: i32 = numbers.iter().sum();
    println!("Sum: {}", sum);
}
EOF

rustc -o test_debug test.rs
rustc -O -o test_release test.rs

# Analyze with file
file test_debug test_release

# Output:
# test_debug: ELF 64-bit LSB pie executable, x86-64...
# test_release: ELF 64-bit LSB pie executable, x86-64...
```

### Exercice 1.2: Using readelf

```bash
# View ELF header
readelf -h test_release

# View section headers
readelf -S test_release

# View program headers
readelf -l test_release

# View symbol table
readelf -s test_release | head -30

# View dynamic section
readelf -d test_release

# View relocations
readelf -r test_release | head -20
```

### Exercice 1.3: Using objdump

```bash
# Disassemble
objdump -d test_release | head -100

# With source (if debug info)
objdump -S test_debug | head -100

# Show all headers
objdump -x test_release | head -50

# Show sections
objdump -h test_release

# Disassemble specific function
objdump -d test_release --disassemble=main
```

### Exercice 1.4: Symbol Analysis with nm

```bash
# List all symbols
nm test_debug | head -50

# Sort by address
nm -n test_debug | head -50

# Show only defined symbols
nm --defined-only test_release | head -30

# Show undefined symbols (dependencies)
nm -u test_release

# Demangle Rust symbols
nm -C test_release | grep main
```

### Exercice 1.5: Dependency Analysis with ldd

```bash
# Show dynamic dependencies
ldd test_release

# Verbose output
ldd -v test_release

# Show unused direct dependencies
ldd -u test_release
```

### Exercice 1.6: String Extraction

```bash
# Extract all strings
strings test_release | head -50

# Minimum length 10
strings -n 10 test_release

# Show file offset
strings -t x test_release | head -30
```

### Exercice 1.7: Using cargo-bloat

```bash
# Install
cargo install cargo-bloat

# Analyze crate
cargo bloat --release

# Show largest functions
cargo bloat --release -n 20

# Crate-level analysis
cargo bloat --release --crates

# Filter by crate
cargo bloat --release --filter std
```

### Exercice 1.8: Using twiggy

```bash
# Install
cargo install twiggy

# Create WASM for analysis (or use ELF)
cargo build --release

# Analyze top
twiggy top target/release/myapp

# Analyze paths
twiggy paths target/release/myapp

# Analyze dominators
twiggy dominators target/release/myapp

# Compare two versions
twiggy diff old_binary new_binary
```

---

## Partie 2: Binary Size Optimization (2.6.22)

### Exercice 2.1: Cargo.toml Optimization

```toml
[package]
name = "optimized"
version = "0.1.0"
edition = "2021"

[profile.release]
# Enable Link-Time Optimization
lto = true

# Single codegen unit for better optimization
codegen-units = 1

# Optimize for size
opt-level = "z"  # or "s" for size with some speed

# Strip symbols
strip = true

# Abort on panic (smaller than unwinding)
panic = "abort"

# Reduce debug info (0 = none, 1 = limited, 2 = full)
debug = 0

[profile.release.build-override]
opt-level = "z"
codegen-units = 1
```

### Exercice 2.2: Size Comparison

```bash
# Build debug
cargo build
ls -lh target/debug/myapp

# Build release (default)
cargo build --release
ls -lh target/release/myapp

# Build with optimizations
# (After adding Cargo.toml changes above)
cargo build --release
ls -lh target/release/myapp

# Strip manually for comparison
strip target/release/myapp -o target/release/myapp_stripped
ls -lh target/release/myapp_stripped

# Compress with UPX (install first)
upx --best target/release/myapp_stripped -o target/release/myapp_upx
ls -lh target/release/myapp_upx
```

### Exercice 2.3: Minimal no_std Binary

```rust
// src/main.rs
#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Minimal program
    let x = 42;
    let y = x + 1;

    // Exit syscall (Linux x86_64)
    unsafe {
        core::arch::asm!(
            "mov rax, 60",  // syscall number for exit
            "mov rdi, {0}", // exit code
            "syscall",
            in(reg) y,
            options(noreturn)
        );
    }
}
```

```toml
# Cargo.toml for no_std
[package]
name = "minimal"
version = "0.1.0"
edition = "2021"

[profile.release]
panic = "abort"
lto = true
codegen-units = 1
opt-level = "z"
strip = true

# .cargo/config.toml
[build]
target = "x86_64-unknown-linux-gnu"

[target.x86_64-unknown-linux-gnu]
rustflags = ["-C", "link-arg=-nostartfiles"]
```

### Exercice 2.4: Analyze Size Breakdown

```rust
// Rust program to analyze its own size
use std::process::Command;

fn main() {
    let binary = std::env::current_exe().unwrap();

    println!("Binary path: {:?}", binary);
    println!("\n=== Size Analysis ===\n");

    // File size
    let metadata = std::fs::metadata(&binary).unwrap();
    println!("File size: {} bytes ({:.2} KB)",
        metadata.len(), metadata.len() as f64 / 1024.0);

    // readelf sections
    println!("\n=== Section Sizes ===\n");
    let output = Command::new("readelf")
        .args(["-S", "--wide"])
        .arg(&binary)
        .output()
        .expect("readelf failed");

    let sections = String::from_utf8_lossy(&output.stdout);
    for line in sections.lines() {
        if line.contains(".text") || line.contains(".data") ||
           line.contains(".rodata") || line.contains(".bss") {
            println!("{}", line);
        }
    }

    // Size command
    println!("\n=== size output ===\n");
    let output = Command::new("size")
        .arg(&binary)
        .output()
        .expect("size failed");
    println!("{}", String::from_utf8_lossy(&output.stdout));
}
```

### Exercice 2.5: Cargo-binutils Integration

```bash
# Install cargo-binutils
cargo install cargo-binutils
rustup component add llvm-tools-preview

# Use cargo wrappers
cargo size --release -- -A  # Section sizes
cargo nm --release | head -30  # Symbols
cargo objdump --release -- --disassemble | head -100
cargo strip --release  # Strip in place

# Compare sizes
cargo size --release -- -A > before.txt
# Make changes...
cargo size --release -- -A > after.txt
diff before.txt after.txt
```

---

## Partie 3: Practical Size Reduction

### Exercice 3.1: Step-by-Step Optimization

```bash
#!/bin/bash
# optimize_size.sh - Track size through optimization stages

PROJECT="myproject"

echo "Stage 1: Debug build"
cargo build
ls -lh target/debug/$PROJECT

echo "Stage 2: Release build"
cargo build --release
ls -lh target/release/$PROJECT

echo "Stage 3: Add LTO"
# Add lto = true to Cargo.toml
cargo build --release
ls -lh target/release/$PROJECT

echo "Stage 4: codegen-units = 1"
# Add codegen-units = 1
cargo build --release
ls -lh target/release/$PROJECT

echo "Stage 5: opt-level = z"
cargo build --release
ls -lh target/release/$PROJECT

echo "Stage 6: strip = true"
cargo build --release
ls -lh target/release/$PROJECT

echo "Stage 7: panic = abort"
cargo build --release
ls -lh target/release/$PROJECT
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Binary analysis tools | 25 |
| ELF understanding | 20 |
| Size optimization config | 25 |
| Size measurement | 15 |
| no_std binary | 15 |
| **Total** | **100** |

---

## Ressources

- [min-sized-rust](https://github.com/johnthagen/min-sized-rust)
- [cargo-bloat](https://github.com/RazrFalcon/cargo-bloat)
- [twiggy](https://github.com/nicoptere/twiggy)
- [ELF Format](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
