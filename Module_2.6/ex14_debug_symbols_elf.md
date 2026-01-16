# [Module 2.6] - Exercise 14: Debug Symbols & ELF Manipulation

## Metadonnees

```yaml
module: "2.6 - Concurrency & Binary Tools"
exercise: "ex14"
title: "Debug Symbols & ELF Manipulation in Rust"
difficulty: avance
estimated_time: "5 heures"
prerequisite_exercises: ["ex13"]
concepts_requis: ["DWARF", "ELF format", "object files"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.6.23: Debugging Symbols (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.6.23.a | DWARF | Debug info format |
| 2.6.23.b | `.debug_*` sections | Debug info sections |
| 2.6.23.c | `debug = true` | Include debug info |
| 2.6.23.d | `split-debuginfo` | Separate debug file |
| 2.6.23.e | `.dSYM` | macOS debug symbols |
| 2.6.23.f | `.pdb` | Windows debug symbols |
| 2.6.23.g | `addr2line` | Address to source |
| 2.6.23.h | `addr2line` crate | Rust implementation |
| 2.6.23.i | `gimli` crate | DWARF parser |
| 2.6.23.j | `symbolic` crate | Debug info processing |

### 2.6.24: ELF Manipulation in Rust (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.6.24.a | `goblin` | Multi-format parser |
| 2.6.24.b | `object` | Object file library |
| 2.6.24.c | `elf` crate | Pure ELF parsing |
| 2.6.24.d | `faerie` | Object file creation |
| 2.6.24.e | `object::write` | Write object files |
| 2.6.24.f | Modify sections | Read-modify-write |
| 2.6.24.g | Add sections | Custom data |
| 2.6.24.h | Patch binary | In-place modification |
| 2.6.24.i | `scroll` crate | Binary parsing |
| 2.6.24.j | `zerocopy` | Zero-copy parsing |

---

## Partie 1: Debug Symbols (2.6.23)

### Exercice 1.1: DWARF Debug Info

```toml
# Cargo.toml configurations

[profile.dev]
debug = true  # Full debug info (default)

[profile.release]
debug = true  # Add debug info to release

[profile.release-with-debug]
inherits = "release"
debug = true  # Custom profile with debug

# Split debug info (Linux)
[profile.release]
split-debuginfo = "packed"  # or "unpacked" or "off"
```

### Exercice 1.2: Using addr2line

```bash
# Build with debug info
cargo build

# Get an address from a crash or profiler
ADDR=0x55555555b2a0

# Command line tool
addr2line -e target/debug/myapp -f $ADDR

# With inlined functions
addr2line -e target/debug/myapp -f -i $ADDR

# Multiple addresses
addr2line -e target/debug/myapp -f 0x1234 0x5678 0x9abc
```

### Exercice 1.3: addr2line crate

```rust
use addr2line::Context;
use object::{Object, ObjectSection};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let binary_path = std::env::args().nth(1)
        .unwrap_or_else(|| "target/debug/myapp".to_string());
    let address: u64 = std::env::args().nth(2)
        .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
        .unwrap_or(0);

    let file = fs::read(&binary_path)?;
    let object = object::File::parse(&*file)?;
    let context = Context::new(&object)?;

    // Look up the address
    if let Some(location) = context.find_location(address)? {
        println!("File: {:?}", location.file);
        println!("Line: {:?}", location.line);
        println!("Column: {:?}", location.column);
    } else {
        println!("No debug info for address {:#x}", address);
    }

    // Get function name
    if let Some(frame) = context.find_frames(address)?.next()? {
        if let Some(function) = frame.function {
            println!("Function: {}", function.demangle()?);
        }
    }

    Ok(())
}
```

### Exercice 1.4: Using gimli for DWARF

```rust
use gimli::{
    read::{EndianSlice, LittleEndian},
    Dwarf, DwarfSections, SectionId,
};
use object::{Object, ObjectSection};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let binary = fs::read("target/debug/myapp")?;
    let object = object::File::parse(&*binary)?;

    // Load DWARF sections
    let load_section = |id: SectionId| -> Result<_, _> {
        let data = object
            .section_by_name(id.name())
            .and_then(|s| s.data().ok())
            .unwrap_or(&[]);
        Ok(EndianSlice::new(data, LittleEndian))
    };

    let dwarf = Dwarf::load(&load_section)?;

    // Iterate compilation units
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;

        // Get compilation directory and name
        if let Some(line_program) = unit.line_program.clone() {
            let header = line_program.header();
            if let Some(dir) = header.directory(0) {
                println!("Directory: {:?}", dwarf.attr_string(&unit, dir)?);
            }
        }

        // Iterate DIEs (Debug Information Entries)
        let mut entries = unit.entries();
        while let Some((_, entry)) = entries.next_dfs()? {
            // Process each entry
            if entry.tag() == gimli::DW_TAG_subprogram {
                // This is a function
                if let Some(name) = entry.attr_value(gimli::DW_AT_name)? {
                    if let Some(s) = dwarf.attr_string(&unit, name).ok() {
                        println!("Function: {:?}", s.to_string()?);
                    }
                }
            }
        }
    }

    Ok(())
}
```

### Exercice 1.5: symbolic crate for Cross-Platform Debug Info

```rust
use symbolic::debuginfo::Object;
use symbolic::demangle::demangle;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read("target/debug/myapp")?;
    let object = Object::parse(&data)?;

    println!("Debug ID: {:?}", object.debug_id());
    println!("Code ID: {:?}", object.code_id());
    println!("Arch: {:?}", object.arch());
    println!("File format: {:?}", object.file_format());
    println!("Has debug info: {}", object.has_debug_info());
    println!("Has symbols: {}", object.has_symbols());

    // List symbols
    if let Some(session) = object.debug_session().ok() {
        for function in session.functions() {
            let func = function?;
            println!("  {} @ {:#x}", demangle(&func.name), func.address);
        }
    }

    Ok(())
}
```

---

## Partie 2: ELF Manipulation (2.6.24)

### Exercice 2.1: Reading ELF with goblin

```rust
use goblin::elf::Elf;
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let binary = fs::read("target/release/myapp")?;
    let elf = Elf::parse(&binary)?;

    println!("=== ELF Header ===");
    println!("Entry point: {:#x}", elf.entry);
    println!("Type: {:?}", elf.header.e_type);
    println!("Machine: {:?}", elf.header.e_machine);

    println!("\n=== Program Headers ===");
    for phdr in &elf.program_headers {
        println!("  {:?} @ {:#x} (size: {:#x})",
            phdr.p_type, phdr.p_vaddr, phdr.p_memsz);
    }

    println!("\n=== Section Headers ===");
    for section in &elf.section_headers {
        let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("<unknown>");
        println!("  {} @ {:#x} (size: {:#x}, type: {:?})",
            name, section.sh_addr, section.sh_size, section.sh_type);
    }

    println!("\n=== Symbols (first 20) ===");
    for (i, sym) in elf.syms.iter().enumerate().take(20) {
        let name = elf.strtab.get_at(sym.st_name).unwrap_or("<unknown>");
        println!("  {} @ {:#x}", name, sym.st_value);
    }

    println!("\n=== Dynamic Libraries ===");
    for lib in &elf.libraries {
        println!("  {}", lib);
    }

    Ok(())
}
```

### Exercice 2.2: Using object crate

```rust
use object::{Object, ObjectSection, ObjectSymbol, SectionKind};
use std::fs;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let binary = fs::read("target/release/myapp")?;
    let file = object::File::parse(&*binary)?;

    println!("Format: {:?}", file.format());
    println!("Architecture: {:?}", file.architecture());
    println!("Entry: {:#x}", file.entry());

    println!("\n=== Sections ===");
    for section in file.sections() {
        println!("  {} ({:?}) @ {:#x}, size: {}",
            section.name().unwrap_or("<unnamed>"),
            section.kind(),
            section.address(),
            section.size());
    }

    println!("\n=== Symbols (first 30) ===");
    for symbol in file.symbols().take(30) {
        if let Ok(name) = symbol.name() {
            println!("  {} @ {:#x} ({:?})",
                name, symbol.address(), symbol.kind());
        }
    }

    // Read specific section data
    if let Some(text) = file.section_by_name(".text") {
        println!("\n.text section: {} bytes at {:#x}",
            text.size(), text.address());

        // First 32 bytes
        if let Ok(data) = text.data() {
            print!("First bytes: ");
            for byte in data.iter().take(32) {
                print!("{:02x} ", byte);
            }
            println!();
        }
    }

    Ok(())
}
```

### Exercice 2.3: Creating Object Files with faerie

```rust
use faerie::{ArtifactBuilder, Link, Decl};
use target_lexicon::triple;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create an artifact for Linux x86_64
    let name = "custom_object";
    let target = triple!("x86_64-unknown-linux-gnu");

    let mut artifact = ArtifactBuilder::new(target)
        .name(name.to_string())
        .finish();

    // Declare a global function
    artifact.declare("my_function", Decl::function().global())?;

    // Declare a data section
    artifact.declare("my_data", Decl::data().global())?;

    // Define the function (x86_64 machine code for: return 42)
    let code = vec![
        0xb8, 0x2a, 0x00, 0x00, 0x00,  // mov eax, 42
        0xc3,                           // ret
    ];
    artifact.define("my_function", code)?;

    // Define data
    let data = b"Hello from Rust!";
    artifact.define("my_data", data.to_vec())?;

    // Write the object file
    let file = std::fs::File::create("custom.o")?;
    artifact.write(file)?;

    println!("Created custom.o");

    // Verify with readelf
    std::process::Command::new("readelf")
        .args(["-a", "custom.o"])
        .status()?;

    Ok(())
}
```

### Exercice 2.4: Modifying ELF Files with object::write

```rust
use object::write::{Object, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a new object file
    let mut obj = Object::new(
        BinaryFormat::Elf,
        Architecture::X86_64,
        Endianness::Little,
    );

    // Add a .text section with code
    let code = vec![
        0x55,                           // push rbp
        0x48, 0x89, 0xe5,              // mov rbp, rsp
        0xb8, 0x2a, 0x00, 0x00, 0x00,  // mov eax, 42
        0x5d,                           // pop rbp
        0xc3,                           // ret
    ];

    let text_section = obj.section_id(object::write::StandardSection::Text);
    let text_offset = obj.append_section_data(text_section, &code, 16);

    // Add a symbol for the function
    obj.add_symbol(Symbol {
        name: b"answer".to_vec(),
        value: text_offset,
        size: code.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(text_section),
        flags: SymbolFlags::None,
    });

    // Add a .rodata section
    let rodata = b"The answer is 42\0";
    let rodata_section = obj.section_id(object::write::StandardSection::ReadOnlyData);
    let rodata_offset = obj.append_section_data(rodata_section, rodata, 1);

    obj.add_symbol(Symbol {
        name: b"message".to_vec(),
        value: rodata_offset,
        size: rodata.len() as u64,
        kind: SymbolKind::Data,
        scope: SymbolScope::Linkage,
        weak: false,
        section: SymbolSection::Section(rodata_section),
        flags: SymbolFlags::None,
    });

    // Write to file
    let bytes = obj.write()?;
    std::fs::write("modified.o", bytes)?;

    println!("Created modified.o");

    Ok(())
}
```

### Exercice 2.5: Adding Custom Section

```rust
use object::write::{Object, SectionId};
use object::{Architecture, BinaryFormat, Endianness, SectionKind};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read existing binary
    let input = std::fs::read("target/release/myapp")?;
    let input_obj = object::File::parse(&*input)?;

    // Create new object
    let mut obj = Object::new(
        BinaryFormat::Elf,
        Architecture::X86_64,
        Endianness::Little,
    );

    // Add a custom section
    let custom_section = obj.add_section(
        vec![],                          // No segment
        b".odyssey_data".to_vec(),       // Section name
        SectionKind::ReadOnlyData,
    );

    // Custom data to embed
    let custom_data = b"ODYSSEY_SIGNATURE_v1.0\x00";
    obj.append_section_data(custom_section, custom_data, 1);

    // Add version info
    let version_section = obj.add_section(
        vec![],
        b".odyssey_version".to_vec(),
        SectionKind::ReadOnlyData,
    );

    let version = format!(
        "{{\"version\":\"1.0.0\",\"build_time\":\"{}\"}}\0",
        chrono::Utc::now().to_rfc3339()
    );
    obj.append_section_data(version_section, version.as_bytes(), 1);

    // Write
    let bytes = obj.write()?;
    std::fs::write("with_custom_sections.o", bytes)?;

    // Verify
    println!("Created with_custom_sections.o");
    std::process::Command::new("readelf")
        .args(["-S", "with_custom_sections.o"])
        .status()?;

    Ok(())
}
```

---

## Partie 3: Binary Parsing with scroll

### Exercice 3.1: Using scroll for Binary Parsing

```rust
use scroll::{Pread, Pwrite, LE};

#[derive(Debug, Pread, Pwrite)]
struct MyHeader {
    magic: u32,
    version: u16,
    flags: u16,
    data_offset: u32,
    data_size: u32,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a header
    let header = MyHeader {
        magic: 0x4F445953,  // "ODYS" in LE
        version: 1,
        flags: 0,
        data_offset: 16,
        data_size: 100,
    };

    // Serialize
    let mut buffer = vec![0u8; 16];
    buffer.pwrite_with(header, 0, LE)?;

    println!("Serialized: {:02x?}", buffer);

    // Deserialize
    let parsed: MyHeader = buffer.pread_with(0, LE)?;
    println!("Parsed: {:?}", parsed);

    Ok(())
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| DWARF understanding | 20 |
| addr2line usage | 15 |
| gimli parsing | 15 |
| ELF reading (goblin/object) | 20 |
| Object file creation | 15 |
| Custom sections | 15 |
| **Total** | **100** |

---

## Ressources

- [gimli crate docs](https://docs.rs/gimli/)
- [object crate docs](https://docs.rs/object/)
- [goblin crate docs](https://docs.rs/goblin/)
- [DWARF Debugging Standard](http://dwarfstd.org/)
