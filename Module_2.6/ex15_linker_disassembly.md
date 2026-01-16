# [Module 2.6] - Exercise 15: Linker & Disassembly

## Metadonnees

```yaml
module: "2.6 - Concurrency & Binary Tools"
exercise: "ex15"
title: "Writing a Simple Linker & Disassembly"
difficulty: expert
estimated_time: "6 heures"
prerequisite_exercises: ["ex14"]
concepts_requis: ["linking", "relocations", "machine code"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.6.25: Writing a Simple Linker (8 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.6.25.a | Read ELF headers | Parse with `goblin` |
| 2.6.25.b | Collect sections | From all inputs |
| 2.6.25.c | Build symbol table | Resolve symbols |
| 2.6.25.d | Allocate addresses | Assign virtual addresses |
| 2.6.25.e | Apply relocations | Patch references |
| 2.6.25.f | Generate output | Write ELF |
| 2.6.25.g | Minimal linker | Link .text and .data |
| 2.6.25.h | Testing | Link simple objects |

### 2.6.26: Disassembly (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.6.26.a | `capstone` crate | Disassembly engine |
| 2.6.26.b | `Capstone::new()` | Create disassembler |
| 2.6.26.c | `cs.disasm_all(&code, addr)` | Disassemble |
| 2.6.26.d | `Insn` | Instruction struct |
| 2.6.26.e | `insn.mnemonic()` | Instruction name |
| 2.6.26.f | `insn.op_str()` | Operands string |
| 2.6.26.g | `iced-x86` crate | x86/x64 specific |
| 2.6.26.h | `bad64` crate | ARM64 disassembler |
| 2.6.26.i | `yaxpeax` | Multi-arch |
| 2.6.26.j | Formatting | Intel vs AT&T syntax |

---

## Partie 1: Simple Linker (2.6.25)

### Exercice 1.1: Linker Architecture

```rust
// src/linker/mod.rs
use goblin::elf::{Elf, reloc, sym};
use std::collections::HashMap;

/// Symbol definition
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub section_idx: usize,
    pub is_global: bool,
    pub is_defined: bool,
}

/// Section to output
#[derive(Debug)]
pub struct OutputSection {
    pub name: String,
    pub data: Vec<u8>,
    pub address: u64,
    pub alignment: u64,
}

/// Relocation entry
#[derive(Debug)]
pub struct Relocation {
    pub offset: u64,
    pub symbol: String,
    pub rel_type: u32,
    pub addend: i64,
}

/// Input object file
pub struct InputObject {
    pub path: String,
    pub data: Vec<u8>,
    pub symbols: Vec<Symbol>,
    pub relocations: Vec<Relocation>,
    pub text_data: Vec<u8>,
    pub data_data: Vec<u8>,
}

/// Simple linker
pub struct Linker {
    inputs: Vec<InputObject>,
    global_symbols: HashMap<String, Symbol>,
    output_sections: Vec<OutputSection>,
    base_address: u64,
}

impl Linker {
    pub fn new(base_address: u64) -> Self {
        Linker {
            inputs: Vec::new(),
            global_symbols: HashMap::new(),
            output_sections: Vec::new(),
            base_address,
        }
    }

    /// Add an input object file
    pub fn add_object(&mut self, path: &str) -> Result<(), String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("Failed to read {}: {}", path, e))?;

        let elf = Elf::parse(&data)
            .map_err(|e| format!("Failed to parse ELF: {}", e))?;

        let mut input = InputObject {
            path: path.to_string(),
            data: data.clone(),
            symbols: Vec::new(),
            relocations: Vec::new(),
            text_data: Vec::new(),
            data_data: Vec::new(),
        };

        // Extract symbols
        for sym_entry in elf.syms.iter() {
            let name = elf.strtab.get_at(sym_entry.st_name)
                .unwrap_or("")
                .to_string();

            input.symbols.push(Symbol {
                name,
                value: sym_entry.st_value,
                size: sym_entry.st_size,
                section_idx: sym_entry.st_shndx,
                is_global: sym_entry.st_bind() == sym::STB_GLOBAL,
                is_defined: sym_entry.st_shndx != sym::SHN_UNDEF as usize,
            });
        }

        // Extract section data
        for (idx, section) in elf.section_headers.iter().enumerate() {
            let name = elf.shdr_strtab.get_at(section.sh_name).unwrap_or("");

            match name {
                ".text" => {
                    let start = section.sh_offset as usize;
                    let end = start + section.sh_size as usize;
                    input.text_data = data[start..end].to_vec();
                }
                ".data" => {
                    let start = section.sh_offset as usize;
                    let end = start + section.sh_size as usize;
                    input.data_data = data[start..end].to_vec();
                }
                _ => {}
            }
        }

        // Extract relocations
        for reloc_section in &elf.shdr_relocs {
            for reloc_entry in reloc_section.iter() {
                let sym_idx = reloc_entry.r_sym;
                let sym_name = if sym_idx < input.symbols.len() {
                    input.symbols[sym_idx].name.clone()
                } else {
                    String::new()
                };

                input.relocations.push(Relocation {
                    offset: reloc_entry.r_offset,
                    symbol: sym_name,
                    rel_type: reloc_entry.r_type,
                    addend: reloc_entry.r_addend.unwrap_or(0),
                });
            }
        }

        self.inputs.push(input);
        Ok(())
    }

    /// Build global symbol table
    pub fn build_symbol_table(&mut self) -> Result<(), String> {
        for input in &self.inputs {
            for symbol in &input.symbols {
                if symbol.is_global && symbol.is_defined {
                    if self.global_symbols.contains_key(&symbol.name) {
                        return Err(format!("Duplicate symbol: {}", symbol.name));
                    }
                    self.global_symbols.insert(symbol.name.clone(), symbol.clone());
                }
            }
        }
        Ok(())
    }

    /// Allocate addresses for sections
    pub fn allocate_addresses(&mut self) {
        let mut current_addr = self.base_address;

        // .text section
        let mut text_data = Vec::new();
        for input in &self.inputs {
            text_data.extend_from_slice(&input.text_data);
        }

        self.output_sections.push(OutputSection {
            name: ".text".to_string(),
            data: text_data,
            address: current_addr,
            alignment: 16,
        });

        current_addr += self.output_sections.last().unwrap().data.len() as u64;
        current_addr = (current_addr + 0xFFF) & !0xFFF; // Page align

        // .data section
        let mut data_data = Vec::new();
        for input in &self.inputs {
            data_data.extend_from_slice(&input.data_data);
        }

        self.output_sections.push(OutputSection {
            name: ".data".to_string(),
            data: data_data,
            address: current_addr,
            alignment: 16,
        });
    }

    /// Apply relocations
    pub fn apply_relocations(&mut self) -> Result<(), String> {
        for section in &mut self.output_sections {
            for input in &self.inputs {
                for reloc in &input.relocations {
                    let symbol = self.global_symbols.get(&reloc.symbol)
                        .ok_or(format!("Undefined symbol: {}", reloc.symbol))?;

                    let target_addr = symbol.value + section.address;
                    let reloc_addr = reloc.offset as usize;

                    // Apply based on relocation type (simplified)
                    match reloc.rel_type {
                        1 => { // R_X86_64_64 - 64-bit absolute
                            if reloc_addr + 8 <= section.data.len() {
                                let value = target_addr.wrapping_add(reloc.addend as u64);
                                section.data[reloc_addr..reloc_addr+8]
                                    .copy_from_slice(&value.to_le_bytes());
                            }
                        }
                        2 => { // R_X86_64_PC32 - 32-bit PC-relative
                            if reloc_addr + 4 <= section.data.len() {
                                let pc = section.address + reloc_addr as u64 + 4;
                                let value = (target_addr as i64 - pc as i64 + reloc.addend) as i32;
                                section.data[reloc_addr..reloc_addr+4]
                                    .copy_from_slice(&value.to_le_bytes());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    /// Generate output ELF
    pub fn generate_output(&self, path: &str) -> Result<(), String> {
        use object::write::{Object, Symbol as WriteSymbol, SymbolSection};
        use object::{Architecture, BinaryFormat, Endianness, SymbolKind, SymbolScope, SymbolFlags};

        let mut obj = Object::new(
            BinaryFormat::Elf,
            Architecture::X86_64,
            Endianness::Little,
        );

        // Add sections
        for section in &self.output_sections {
            let section_id = match section.name.as_str() {
                ".text" => obj.section_id(object::write::StandardSection::Text),
                ".data" => obj.section_id(object::write::StandardSection::Data),
                _ => continue,
            };

            obj.append_section_data(section_id, &section.data, section.alignment as u64);
        }

        // Add global symbols
        let text_section = obj.section_id(object::write::StandardSection::Text);
        for (name, symbol) in &self.global_symbols {
            obj.add_symbol(WriteSymbol {
                name: name.as_bytes().to_vec(),
                value: symbol.value,
                size: symbol.size,
                kind: SymbolKind::Text,
                scope: SymbolScope::Dynamic,
                weak: false,
                section: SymbolSection::Section(text_section),
                flags: SymbolFlags::None,
            });
        }

        let bytes = obj.write().map_err(|e| e.to_string())?;
        std::fs::write(path, bytes).map_err(|e| e.to_string())?;

        Ok(())
    }
}
```

### Exercice 1.2: Using the Linker

```rust
fn main() -> Result<(), String> {
    let mut linker = Linker::new(0x400000);

    // Add object files
    linker.add_object("file1.o")?;
    linker.add_object("file2.o")?;

    // Link
    linker.build_symbol_table()?;
    linker.allocate_addresses();
    linker.apply_relocations()?;
    linker.generate_output("output.elf")?;

    println!("Linked successfully!");
    Ok(())
}
```

---

## Partie 2: Disassembly (2.6.26)

### Exercice 2.1: Using capstone

```rust
use capstone::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create x86_64 disassembler
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()?;

    // Some x86_64 code
    let code = [
        0x55,                           // push rbp
        0x48, 0x89, 0xe5,              // mov rbp, rsp
        0x48, 0x83, 0xec, 0x10,        // sub rsp, 0x10
        0xc7, 0x45, 0xfc, 0x2a, 0x00, 0x00, 0x00, // mov dword ptr [rbp-4], 42
        0x8b, 0x45, 0xfc,              // mov eax, [rbp-4]
        0x48, 0x83, 0xc4, 0x10,        // add rsp, 0x10
        0x5d,                           // pop rbp
        0xc3,                           // ret
    ];

    let base_addr = 0x1000u64;

    // Disassemble
    let insns = cs.disasm_all(&code, base_addr)?;

    println!("Disassembly ({} instructions):", insns.len());
    for insn in insns.iter() {
        println!("  {:#010x}: {:6} {}",
            insn.address(),
            insn.mnemonic().unwrap_or(""),
            insn.op_str().unwrap_or("")
        );

        // Print bytes
        print!("             ");
        for byte in insn.bytes() {
            print!("{:02x} ", byte);
        }
        println!();
    }

    Ok(())
}
```

### Exercice 2.2: Using iced-x86 (More Detailed)

```rust
use iced_x86::{Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter};

fn main() {
    let code = [
        0x55,                           // push rbp
        0x48, 0x89, 0xe5,              // mov rbp, rsp
        0x48, 0x8b, 0x45, 0x10,        // mov rax, [rbp+0x10]
        0x48, 0x01, 0xc8,              // add rax, rcx
        0x48, 0x89, 0x45, 0xf8,        // mov [rbp-8], rax
        0x5d,                           // pop rbp
        0xc3,                           // ret
    ];

    let mut decoder = Decoder::with_ip(64, &code, 0x1000, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    let mut output = String::new();

    println!("=== iced-x86 Disassembly ===\n");

    let mut instruction = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut instruction);

        output.clear();
        formatter.format(&instruction, &mut output);

        println!("{:016X} {:40} ; {:?}",
            instruction.ip(),
            output,
            instruction.mnemonic()
        );

        // Detailed operand info
        for i in 0..instruction.op_count() {
            let op_kind = instruction.op_kind(i);
            println!("  Operand {}: {:?}", i, op_kind);
        }
    }
}
```

### Exercice 2.3: Disassembling a Binary File

```rust
use capstone::prelude::*;
use object::{Object, ObjectSection};

fn disassemble_file(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let data = std::fs::read(path)?;
    let file = object::File::parse(&*data)?;

    // Get the architecture
    let (arch, mode) = match file.architecture() {
        object::Architecture::X86_64 => {
            (capstone::Arch::X86, capstone::Mode::Mode64)
        }
        object::Architecture::I386 => {
            (capstone::Arch::X86, capstone::Mode::Mode32)
        }
        object::Architecture::Aarch64 => {
            (capstone::Arch::ARM64, capstone::Mode::Arm)
        }
        _ => return Err("Unsupported architecture".into()),
    };

    let cs = Capstone::new_raw(arch, mode, capstone::NO_EXTRA_MODE, None)?;

    // Find .text section
    let text = file.section_by_name(".text")
        .ok_or("No .text section")?;

    let text_data = text.data()?;
    let text_addr = text.address();

    println!("Disassembling {} ({} bytes at {:#x})\n",
        path, text_data.len(), text_addr);

    // Disassemble
    let insns = cs.disasm_all(text_data, text_addr)?;

    for insn in insns.iter() {
        print!("{:016x}:  ", insn.address());

        // Bytes (padded)
        let bytes = insn.bytes();
        for (i, byte) in bytes.iter().enumerate() {
            if i < 8 {
                print!("{:02x} ", byte);
            }
        }
        for _ in bytes.len()..8 {
            print!("   ");
        }

        // Mnemonic and operands
        println!("{:7} {}",
            insn.mnemonic().unwrap_or(""),
            insn.op_str().unwrap_or("")
        );
    }

    Ok(())
}

fn main() {
    let path = std::env::args().nth(1)
        .unwrap_or_else(|| "target/release/myapp".to_string());

    if let Err(e) = disassemble_file(&path) {
        eprintln!("Error: {}", e);
    }
}
```

### Exercice 2.4: AT&T vs Intel Syntax

```rust
use iced_x86::{Decoder, DecoderOptions, Formatter, GasFormatter, IntelFormatter, MasmFormatter, NasmFormatter};

fn main() {
    let code = [
        0x48, 0x8b, 0x44, 0x24, 0x08,  // mov rax, [rsp+8]
        0x48, 0x01, 0xc8,              // add rax, rcx
        0x48, 0x89, 0x03,              // mov [rbx], rax
    ];

    let mut decoder = Decoder::with_ip(64, &code, 0, DecoderOptions::NONE);

    // Different formatters
    let mut intel = IntelFormatter::new();
    let mut gas = GasFormatter::new();
    let mut masm = MasmFormatter::new();
    let mut nasm = NasmFormatter::new();

    println!("{:40} {:40} {:40} {:40}",
        "Intel", "AT&T (GAS)", "MASM", "NASM");
    println!("{:-<160}", "");

    let mut output = String::new();

    while decoder.can_decode() {
        let instr = decoder.decode();

        output.clear();
        intel.format(&instr, &mut output);
        let intel_str = output.clone();

        output.clear();
        gas.format(&instr, &mut output);
        let gas_str = output.clone();

        output.clear();
        masm.format(&instr, &mut output);
        let masm_str = output.clone();

        output.clear();
        nasm.format(&instr, &mut output);
        let nasm_str = output.clone();

        println!("{:40} {:40} {:40} {:40}",
            intel_str, gas_str, masm_str, nasm_str);
    }
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Linker architecture | 20 |
| Symbol resolution | 15 |
| Relocation handling | 15 |
| capstone usage | 20 |
| iced-x86 usage | 15 |
| Format handling | 15 |
| **Total** | **100** |

---

## Ressources

- [capstone-rs](https://docs.rs/capstone/)
- [iced-x86](https://docs.rs/iced-x86/)
- [System V ABI](https://refspecs.linuxfoundation.org/elf/x86_64-abi-0.99.pdf)
- [Linkers and Loaders](https://linker.iecc.com/)
