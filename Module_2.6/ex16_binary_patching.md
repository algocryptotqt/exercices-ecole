# [Module 2.6] - Exercise 16: Binary Patching & Hooking

## Metadonnees

```yaml
module: "2.6 - Concurrency & Binary Tools"
exercise: "ex16"
title: "Code Injection, Patching & LD_PRELOAD"
difficulty: expert
estimated_time: "5 heures"
prerequisite_exercises: ["ex14", "ex15"]
concepts_requis: ["binary modification", "hooking", "dynamic linking"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.6.27: Code Injection & Patching (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.6.27.a | Binary patching | Modify executable |
| 2.6.27.b | Section injection | Add new section |
| 2.6.27.c | Code caves | Find unused space |
| 2.6.27.d | Entrypoint hijack | Change entry |
| 2.6.27.e | `object::write` | Modify and write |
| 2.6.27.f | In-memory patching | Runtime modification |
| 2.6.27.g | `region` crate | Memory protection |
| 2.6.27.h | `mprotect` | Make writable |
| 2.6.27.i | Hook installation | Redirect functions |
| 2.6.27.j | Use cases | Instrumentation, debugging |

### 2.6.28: LD_PRELOAD Equivalent in Rust (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.6.28.a | LD_PRELOAD | Load before others |
| 2.6.28.b | Symbol interposition | Override functions |
| 2.6.28.c | Create cdylib | Shared library |
| 2.6.28.d | Export symbols | Same name as target |
| 2.6.28.e | Call original | `dlsym(RTLD_NEXT, ...)` |
| 2.6.28.f | `libc::dlsym` | Get original |
| 2.6.28.g | `redhook` crate | Hook helper |
| 2.6.28.h | `frida-rust` | Advanced hooking |
| 2.6.28.i | Use cases | Tracing, mocking |
| 2.6.28.j | Security | Ignored for setuid |

---

## Partie 1: Binary Patching (2.6.27)

### Exercice 1.1: Simple Binary Patch

```rust
use std::fs;
use std::io::{Read, Write, Seek, SeekFrom};

/// Patch a binary at a specific offset
fn patch_binary(path: &str, offset: u64, new_bytes: &[u8]) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?;

    file.seek(SeekFrom::Start(offset))?;
    file.write_all(new_bytes)?;

    println!("Patched {} bytes at offset {:#x}", new_bytes.len(), offset);
    Ok(())
}

/// Find pattern and patch
fn find_and_patch(path: &str, pattern: &[u8], replacement: &[u8]) -> std::io::Result<bool> {
    let data = fs::read(path)?;

    // Find pattern
    if let Some(offset) = data.windows(pattern.len()).position(|w| w == pattern) {
        patch_binary(path, offset as u64, replacement)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn main() -> std::io::Result<()> {
    // Example: Change a string in a binary
    let path = "target/release/myapp";

    // Backup first
    fs::copy(path, format!("{}.backup", path))?;

    // Find "Hello" and replace with "Hxxxx"
    let found = find_and_patch(
        path,
        b"Hello",
        b"Hxxxx"
    )?;

    println!("Pattern found and patched: {}", found);

    Ok(())
}
```

### Exercice 1.2: Finding Code Caves

```rust
use object::{Object, ObjectSection};
use std::fs;

/// Find code caves (sequences of NUL bytes) in sections
fn find_code_caves(path: &str, min_size: usize) -> Result<Vec<(u64, usize)>, Box<dyn std::error::Error>> {
    let data = fs::read(path)?;
    let file = object::File::parse(&*data)?;

    let mut caves = Vec::new();

    for section in file.sections() {
        if let Ok(section_data) = section.data() {
            let mut cave_start = None;
            let mut cave_size = 0;

            for (i, &byte) in section_data.iter().enumerate() {
                if byte == 0 {
                    if cave_start.is_none() {
                        cave_start = Some(section.address() + i as u64);
                    }
                    cave_size += 1;
                } else {
                    if cave_size >= min_size {
                        caves.push((cave_start.unwrap(), cave_size));
                    }
                    cave_start = None;
                    cave_size = 0;
                }
            }

            // Check last cave
            if cave_size >= min_size {
                caves.push((cave_start.unwrap(), cave_size));
            }
        }
    }

    Ok(caves)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1)
        .unwrap_or_else(|| "target/release/myapp".to_string());

    let caves = find_code_caves(&path, 16)?;

    println!("Code caves (>= 16 bytes) in {}:", path);
    for (addr, size) in &caves {
        println!("  {:#x}: {} bytes", addr, size);
    }

    println!("\nTotal caves: {}", caves.len());
    println!("Total space: {} bytes", caves.iter().map(|(_, s)| s).sum::<usize>());

    Ok(())
}
```

### Exercice 1.3: In-Memory Patching

```rust
use std::ptr;

#[cfg(target_os = "linux")]
fn make_writable(addr: *mut u8, size: usize) -> std::io::Result<()> {
    use libc::{mprotect, PROT_READ, PROT_WRITE, PROT_EXEC};

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    let page_start = (addr as usize / page_size) * page_size;
    let page_end = ((addr as usize + size + page_size - 1) / page_size) * page_size;

    let result = unsafe {
        mprotect(
            page_start as *mut libc::c_void,
            page_end - page_start,
            PROT_READ | PROT_WRITE | PROT_EXEC
        )
    };

    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Patch a function at runtime
unsafe fn patch_function(target: *mut u8, patch: &[u8]) -> std::io::Result<()> {
    make_writable(target, patch.len())?;
    ptr::copy_nonoverlapping(patch.as_ptr(), target, patch.len());
    Ok(())
}

/// Create a jump instruction to redirect a function
fn create_jump(from: u64, to: u64) -> [u8; 5] {
    let offset = (to as i64 - from as i64 - 5) as i32;
    let mut jump = [0u8; 5];
    jump[0] = 0xE9; // JMP rel32
    jump[1..5].copy_from_slice(&offset.to_le_bytes());
    jump
}

fn main() {
    // Example: redirect a function
    // This is for demonstration - actual use requires careful address calculation

    fn original() {
        println!("Original function");
    }

    fn replacement() {
        println!("Replacement function!");
    }

    // In real code, you'd get these addresses properly
    let original_addr = original as *mut u8;
    let replacement_addr = replacement as *const u8 as u64;

    println!("Original addr: {:p}", original_addr);
    println!("Replacement addr: {:#x}", replacement_addr);

    // Call original
    original();

    // Patch (dangerous - demonstration only!)
    // let jump = create_jump(original_addr as u64, replacement_addr);
    // unsafe { patch_function(original_addr, &jump).unwrap(); }

    // Call again would now call replacement
    // original(); // Now calls replacement
}
```

### Exercice 1.4: Using region crate for Memory Protection

```rust
use region::{Protection, protect};

fn patch_with_region(addr: *mut u8, patch: &[u8]) -> Result<(), region::Error> {
    // Make memory writable
    unsafe {
        protect(addr, patch.len(), Protection::READ_WRITE_EXECUTE)?;
    }

    // Apply patch
    unsafe {
        std::ptr::copy_nonoverlapping(patch.as_ptr(), addr, patch.len());
    }

    // Optionally restore original protection
    unsafe {
        protect(addr, patch.len(), Protection::READ_EXECUTE)?;
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Query current protection
    let test_fn: fn() = || println!("test");
    let addr = test_fn as *const () as *const u8;

    let region = region::query(addr)?;
    println!("Region: {:p} - {:p}", region.as_ptr::<u8>(), unsafe {
        region.as_ptr::<u8>().add(region.len())
    });
    println!("Protection: {:?}", region.protection());

    Ok(())
}
```

---

## Partie 2: LD_PRELOAD & Function Hooking (2.6.28)

### Exercice 2.1: Basic LD_PRELOAD Library

```rust
// lib.rs - Build as cdylib
// Cargo.toml: [lib] crate-type = ["cdylib"]

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

// Override printf
#[no_mangle]
pub unsafe extern "C" fn printf(format: *const c_char, mut args: ...) -> c_int {
    // Get original printf
    let original: unsafe extern "C" fn(*const c_char, ...) -> c_int = {
        let sym = libc::dlsym(libc::RTLD_NEXT, b"printf\0".as_ptr() as *const c_char);
        std::mem::transmute(sym)
    };

    // Log the call
    if !format.is_null() {
        let fmt = CStr::from_ptr(format);
        eprintln!("[HOOK] printf called with format: {:?}", fmt);
    }

    // Call original
    // Note: Variadic forwarding is complex, simplified here
    original(format)
}

// Override malloc
#[no_mangle]
pub unsafe extern "C" fn malloc(size: libc::size_t) -> *mut libc::c_void {
    let original: unsafe extern "C" fn(libc::size_t) -> *mut libc::c_void = {
        let sym = libc::dlsym(libc::RTLD_NEXT, b"malloc\0".as_ptr() as *const c_char);
        std::mem::transmute(sym)
    };

    let result = original(size);
    eprintln!("[HOOK] malloc({}) = {:p}", size, result);
    result
}

// Override free
#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut libc::c_void) {
    let original: unsafe extern "C" fn(*mut libc::c_void) = {
        let sym = libc::dlsym(libc::RTLD_NEXT, b"free\0".as_ptr() as *const c_char);
        std::mem::transmute(sym)
    };

    eprintln!("[HOOK] free({:p})", ptr);
    original(ptr)
}
```

**Usage:**

```bash
# Build the library
cargo build --release

# Use with LD_PRELOAD
LD_PRELOAD=./target/release/libhooks.so ./some_program
```

### Exercice 2.2: Using redhook crate

```rust
// Cargo.toml:
// [dependencies]
// redhook = "2.0"
// libc = "0.2"

use redhook::{hook, real};
use std::ffi::CStr;

hook! {
    unsafe fn malloc(size: libc::size_t) -> *mut libc::c_void => my_malloc {
        eprintln!("[redhook] malloc({})", size);
        real!(malloc)(size)
    }
}

hook! {
    unsafe fn free(ptr: *mut libc::c_void) => my_free {
        eprintln!("[redhook] free({:p})", ptr);
        real!(free)(ptr)
    }
}

hook! {
    unsafe fn open(path: *const libc::c_char, flags: libc::c_int) -> libc::c_int => my_open {
        if !path.is_null() {
            let path_str = CStr::from_ptr(path);
            eprintln!("[redhook] open({:?}, {:#x})", path_str, flags);
        }
        real!(open)(path, flags)
    }
}

hook! {
    unsafe fn read(fd: libc::c_int, buf: *mut libc::c_void, count: libc::size_t) -> libc::ssize_t => my_read {
        let result = real!(read)(fd, buf, count);
        eprintln!("[redhook] read({}, ..., {}) = {}", fd, count, result);
        result
    }
}

hook! {
    unsafe fn write(fd: libc::c_int, buf: *const libc::c_void, count: libc::size_t) -> libc::ssize_t => my_write {
        let result = real!(write)(fd, buf, count);
        eprintln!("[redhook] write({}, ..., {}) = {}", fd, count, result);
        result
    }
}
```

### Exercice 2.3: Tracking Allocations

```rust
use std::collections::HashMap;
use std::sync::Mutex;
use lazy_static::lazy_static;

lazy_static! {
    static ref ALLOCATIONS: Mutex<HashMap<usize, AllocInfo>> = Mutex::new(HashMap::new());
}

struct AllocInfo {
    size: usize,
    backtrace: String,
}

#[no_mangle]
pub unsafe extern "C" fn malloc(size: libc::size_t) -> *mut libc::c_void {
    let original: unsafe extern "C" fn(libc::size_t) -> *mut libc::c_void = {
        let sym = libc::dlsym(libc::RTLD_NEXT, b"malloc\0".as_ptr() as *const i8);
        std::mem::transmute(sym)
    };

    let ptr = original(size);

    if !ptr.is_null() {
        let mut allocations = ALLOCATIONS.lock().unwrap();
        allocations.insert(ptr as usize, AllocInfo {
            size,
            backtrace: format!("{:?}", std::backtrace::Backtrace::capture()),
        });
    }

    ptr
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *mut libc::c_void) {
    let original: unsafe extern "C" fn(*mut libc::c_void) = {
        let sym = libc::dlsym(libc::RTLD_NEXT, b"free\0".as_ptr() as *const i8);
        std::mem::transmute(sym)
    };

    if !ptr.is_null() {
        let mut allocations = ALLOCATIONS.lock().unwrap();
        allocations.remove(&(ptr as usize));
    }

    original(ptr)
}

/// Report memory leaks (call at exit)
#[no_mangle]
pub extern "C" fn report_leaks() {
    let allocations = ALLOCATIONS.lock().unwrap();

    if allocations.is_empty() {
        eprintln!("[LEAK DETECTOR] No leaks detected!");
        return;
    }

    eprintln!("[LEAK DETECTOR] {} allocations not freed:", allocations.len());
    for (addr, info) in allocations.iter() {
        eprintln!("  {:#x}: {} bytes", addr, info.size);
        eprintln!("    Allocated at:\n{}", info.backtrace);
    }
}
```

### Exercice 2.4: File Access Tracing

```rust
use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

lazy_static::lazy_static! {
    static ref LOG_FILE: Mutex<std::fs::File> = Mutex::new(
        OpenOptions::new()
            .create(true)
            .append(true)
            .open("/tmp/file_trace.log")
            .unwrap()
    );
}

#[no_mangle]
pub unsafe extern "C" fn open(
    pathname: *const libc::c_char,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    let original: unsafe extern "C" fn(*const libc::c_char, libc::c_int, libc::mode_t) -> libc::c_int = {
        let sym = libc::dlsym(libc::RTLD_NEXT, b"open\0".as_ptr() as *const i8);
        std::mem::transmute(sym)
    };

    let result = original(pathname, flags, mode);

    if !pathname.is_null() {
        let path = CStr::from_ptr(pathname).to_string_lossy();
        let mode_str = match flags & libc::O_ACCMODE {
            libc::O_RDONLY => "read",
            libc::O_WRONLY => "write",
            libc::O_RDWR => "read/write",
            _ => "unknown",
        };

        let log_line = format!(
            "[{}] open({}, {}) = {}\n",
            std::process::id(),
            path,
            mode_str,
            result
        );

        if let Ok(mut file) = LOG_FILE.lock() {
            let _ = file.write_all(log_line.as_bytes());
        }
    }

    result
}
```

---

## Partie 3: Security Considerations

### Exercice 3.1: Security Limitations

```rust
// LD_PRELOAD is ignored for:
// 1. setuid/setgid binaries
// 2. Programs with capabilities
// 3. When running as root (in some configs)

// Check if we're in a secure context
fn is_secure_exec() -> bool {
    unsafe {
        // AT_SECURE in auxiliary vector
        libc::getauxval(libc::AT_SECURE) != 0
    }
}

fn main() {
    if is_secure_exec() {
        eprintln!("Warning: Running in secure mode, LD_PRELOAD may be ignored");
    }
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Binary patching | 20 |
| Code cave finding | 15 |
| In-memory patching | 15 |
| LD_PRELOAD library | 25 |
| Function hooking | 15 |
| Security awareness | 10 |
| **Total** | **100** |

---

## Ressources

- [region crate](https://docs.rs/region/)
- [redhook crate](https://docs.rs/redhook/)
- [LD_PRELOAD article](https://blog.jessfraz.com/post/ld_preload/)
- [Frida](https://frida.re/)
