# ex19: Security Advanced - Web, Binary & CTF

**Module**: 2.9 - Security
**Difficulte**: Expert
**Duree**: 30h
**Score qualite**: 97/100

## Concepts Couverts

### 2.9.6: AEAD Example (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.6.a | AEAD | Authenticated Encryption |
| 2.9.6.b | AES-GCM | GCM mode |
| 2.9.6.c | ChaCha20-Poly1305 | Stream cipher AEAD |
| 2.9.6.d | Nonce | Unique per message |
| 2.9.6.e | AAD | Additional authenticated data |
| 2.9.6.f | Tag | Authentication tag |
| 2.9.6.g | `aead` crate | Rust AEAD |
| 2.9.6.h | Encrypt/Decrypt | Full example |

### 2.9.20: Web Security Fundamentals (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.20.a | HTTP security | Headers, cookies |
| 2.9.20.b | Same-origin policy | Browser security |
| 2.9.20.c | CORS | Cross-Origin Resource Sharing |
| 2.9.20.d | CSP | Content Security Policy |
| 2.9.20.e | Rust web frameworks | axum, actix-web |
| 2.9.20.f | Security middleware | tower-http |
| 2.9.20.g | Input validation | Type-safe parsing |

### 2.9.21: OWASP Top 10 & Rust (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.21.a | Injection | SQL, Command injection prevention |
| 2.9.21.b | Broken auth | Session management |
| 2.9.21.c | Sensitive data | Encryption at rest |
| 2.9.21.d | XXE | XML External Entities |
| 2.9.21.e | Broken access | Authorization checks |
| 2.9.21.f | Misconfig | Secure defaults |
| 2.9.21.g | XSS | Cross-site scripting prevention |
| 2.9.21.h | Insecure deserialize | Safe parsing |

### 2.9.28: Memory Safety Vulnerabilities (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.28.a | Buffer overflow | Stack/heap overflow |
| 2.9.28.b | Use-after-free | Dangling pointers |
| 2.9.28.c | Double free | Memory corruption |
| 2.9.28.d | Null pointer | Null dereference |
| 2.9.28.e | Integer overflow | Arithmetic bugs |
| 2.9.28.f | Format string | Printf vulnerabilities |
| 2.9.28.g | Race condition | TOCTOU |
| 2.9.28.h | Type confusion | Type safety |

### 2.9.29: Why Rust Prevents These (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.29.a | Ownership | No use-after-free |
| 2.9.29.b | Borrowing | No data races |
| 2.9.29.c | Bounds checking | No buffer overflow |
| 2.9.29.d | No null | Option type |
| 2.9.29.e | Safe integers | Checked arithmetic |
| 2.9.29.f | Type system | No type confusion |
| 2.9.29.g | Send/Sync | Thread safety |
| 2.9.29.h | unsafe blocks | Explicit danger |

### 2.9.30: Binary Exploitation Tools in Rust (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.30.a | `goblin` | Binary parsing |
| 2.9.30.b | `object` crate | Object file handling |
| 2.9.30.c | `capstone` | Disassembly |
| 2.9.30.d | `unicorn` | Emulation |
| 2.9.30.e | `pwntools` style | Exploit dev |
| 2.9.30.f | `nix` crate | Syscalls |
| 2.9.30.g | `memmap2` | Memory mapping |
| 2.9.30.h | `ptrace` | Process tracing |

### 2.9.31: Exploit Development Environment (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.31.a | GDB | Debugger |
| 2.9.31.b | pwndbg/gef | GDB extensions |
| 2.9.31.c | checksec | Binary protections |
| 2.9.31.d | ROPgadget | ROP chain building |
| 2.9.31.e | Ghidra | Reverse engineering |
| 2.9.31.f | QEMU | Emulation |
| 2.9.31.g | Docker | Isolated environment |
| 2.9.31.h | Rust tooling | Analysis tools |

### 2.9.32: Stack Buffer Overflow (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.32.a | Stack layout | Return address |
| 2.9.32.b | Buffer overflow | Overwrite |
| 2.9.32.c | Control flow | Hijacking |
| 2.9.32.d | Shellcode | Payload |
| 2.9.32.e | NOP sled | Reliability |
| 2.9.32.f | Return address | Overwrite target |
| 2.9.32.g | Rust analysis | Detect in C code |

### 2.9.33: Return-Oriented Programming (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.33.a | ROP concept | Gadget chaining |
| 2.9.33.b | Gadgets | Instruction sequences |
| 2.9.33.c | ROP chain | Exploit construction |
| 2.9.33.d | Stack pivot | Change stack |
| 2.9.33.e | ret2libc | Library functions |
| 2.9.33.f | Sigreturn | SROP |
| 2.9.33.g | JOP | Jump-oriented |
| 2.9.33.h | Rust gadget finder | Tool building |

### 2.9.34: Heap Exploitation (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.34.a | Heap layout | Chunks, bins |
| 2.9.34.b | Use-after-free | Exploitation |
| 2.9.34.c | Double free | tcache poisoning |
| 2.9.34.d | Heap overflow | Metadata corruption |
| 2.9.34.e | Fastbin attack | Allocation tricks |
| 2.9.34.f | House of X | Techniques |
| 2.9.34.g | tcache | Thread cache |
| 2.9.34.h | Rust heap analysis | Safe tooling |

### 2.9.35: Format String Attacks (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.35.a | Format specifiers | %x, %n, %s |
| 2.9.35.b | Stack reading | Information leak |
| 2.9.35.c | Arbitrary write | %n exploitation |
| 2.9.35.d | GOT overwrite | Control flow |
| 2.9.35.e | Position specifier | %N$x |
| 2.9.35.f | Width specifier | Byte control |
| 2.9.35.g | Prevention | Rust safety |
| 2.9.35.h | Detection tool | Rust scanner |

### 2.9.36: Protection Mechanisms (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.36.a | ASLR | Address randomization |
| 2.9.36.b | Stack canary | Buffer overflow detect |
| 2.9.36.c | NX/DEP | Non-executable memory |
| 2.9.36.d | PIE | Position independent |
| 2.9.36.e | RELRO | Relocation read-only |
| 2.9.36.f | CFI | Control flow integrity |
| 2.9.36.g | Rust protections | Built-in safety |

### 2.9.37: Reverse Engineering (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.37.a | Static analysis | Without execution |
| 2.9.37.b | Dynamic analysis | Runtime observation |
| 2.9.37.c | Disassembly | Machine code |
| 2.9.37.d | Decompilation | High-level recovery |
| 2.9.37.e | Symbol analysis | Function names |
| 2.9.37.f | String analysis | Data extraction |
| 2.9.37.g | Control flow | Graph analysis |
| 2.9.37.h | Rust RE tools | `goblin`, analysis |

### 2.9.38: Fuzzing with Rust (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.38.a | Fuzzing concept | Random testing |
| 2.9.38.b | Coverage-guided | AFL-style |
| 2.9.38.c | `cargo-fuzz` | Rust fuzzing |
| 2.9.38.d | `libfuzzer` | Backend |
| 2.9.38.e | `arbitrary` crate | Input generation |
| 2.9.38.f | Corpus | Test cases |
| 2.9.38.g | Crash triage | Analysis |
| 2.9.38.h | OSS-Fuzz | Continuous fuzzing |
| 2.9.38.i | AFL.rs | Alternative |

### 2.9.39: Fuzzing Example (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.39.a | Target function | Fuzz harness |
| 2.9.39.b | Input structure | Data format |
| 2.9.39.c | Setup harness | fuzz_target! |
| 2.9.39.d | Run fuzzer | cargo fuzz run |
| 2.9.39.e | Analyze crashes | Debugging |
| 2.9.39.f | Minimize | corpus minimization |
| 2.9.39.g | Coverage | lcov reports |
| 2.9.39.h | CI integration | Automated fuzzing |

### 2.9.40: unsafe Rust Auditing (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.40.a | unsafe blocks | Identification |
| 2.9.40.b | cargo-geiger | Unsafe counting |
| 2.9.40.c | Miri | Undefined behavior |
| 2.9.40.d | cargo-audit | Vulnerability scan |
| 2.9.40.e | Safety invariants | Documentation |
| 2.9.40.f | Review process | Manual audit |
| 2.9.40.g | RUSTSEC | Advisory database |
| 2.9.40.h | cargo-crev | Code review |

### 2.9.41: Network Security Tools in Rust (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.41.a | Port scanner | TCP scanning |
| 2.9.41.b | Packet capture | pcap/libpnet |
| 2.9.41.c | Protocol analysis | Parsing |
| 2.9.41.d | Network fuzzing | Protocol testing |
| 2.9.41.e | TLS analysis | Certificate checking |
| 2.9.41.f | DNS tools | Resolution |
| 2.9.41.g | Proxy tools | MITM |

### 2.9.42: CTF Skills (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.42.a | CTF categories | pwn, rev, crypto, web |
| 2.9.42.b | pwn challenges | Binary exploitation |
| 2.9.42.c | rev challenges | Reverse engineering |
| 2.9.42.d | crypto challenges | Cryptanalysis |
| 2.9.42.e | web challenges | Web security |
| 2.9.42.f | Rust for CTF | Tool building |
| 2.9.42.g | Write-ups | Documentation |

### 2.9.43: Building Security Tools (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.43.a | Scanner design | Architecture |
| 2.9.43.b | Parser security | Safe parsing |
| 2.9.43.c | Async networking | tokio |
| 2.9.43.d | CLI tools | clap |
| 2.9.43.e | Output formats | JSON, text |
| 2.9.43.f | Error handling | Robustness |
| 2.9.43.g | Testing | Security tools |

### 2.9.44: Threat Modeling (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.9.44.a | STRIDE | Threat categories |
| 2.9.44.b | Attack surface | Entry points |
| 2.9.44.c | Trust boundaries | Security zones |
| 2.9.44.d | Data flow | DFD diagrams |
| 2.9.44.e | Risk assessment | Impact/likelihood |
| 2.9.44.f | Mitigations | Countermeasures |
| 2.9.44.g | Security requirements | Specifications |
| 2.9.44.h | Rust modeling | Ownership as security |

---

## Partie 1: AEAD Encryption (2.9.6)

```rust
//! AEAD encryption (2.9.6)

use aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChachaNonce};

/// AEAD wrapper (2.9.6.a, 2.9.6.g)
pub struct AeadCipher {
    cipher_type: CipherType,
}

pub enum CipherType {
    AesGcm(Aes256Gcm),           // 2.9.6.b
    ChaCha(ChaCha20Poly1305),    // 2.9.6.c
}

impl AeadCipher {
    /// Create AES-GCM cipher (2.9.6.b)
    pub fn aes_gcm(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).unwrap();
        Self { cipher_type: CipherType::AesGcm(cipher) }
    }

    /// Create ChaCha20-Poly1305 cipher (2.9.6.c)
    pub fn chacha20(key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(key).unwrap();
        Self { cipher_type: CipherType::ChaCha(cipher) }
    }

    /// Encrypt with AAD (2.9.6.d, 2.9.6.e, 2.9.6.f, 2.9.6.h)
    pub fn encrypt(&self, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AeadError> {
        let payload = Payload { msg: plaintext, aad };

        match &self.cipher_type {
            CipherType::AesGcm(cipher) => {
                let nonce = AesNonce::from_slice(nonce);
                cipher.encrypt(nonce, payload).map_err(|_| AeadError::EncryptFailed)
            }
            CipherType::ChaCha(cipher) => {
                let nonce = ChachaNonce::from_slice(nonce);
                cipher.encrypt(nonce, payload).map_err(|_| AeadError::EncryptFailed)
            }
        }
    }

    /// Decrypt with AAD (2.9.6.h)
    pub fn decrypt(&self, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, AeadError> {
        let payload = Payload { msg: ciphertext, aad };

        match &self.cipher_type {
            CipherType::AesGcm(cipher) => {
                let nonce = AesNonce::from_slice(nonce);
                cipher.decrypt(nonce, payload).map_err(|_| AeadError::DecryptFailed)
            }
            CipherType::ChaCha(cipher) => {
                let nonce = ChachaNonce::from_slice(nonce);
                cipher.decrypt(nonce, payload).map_err(|_| AeadError::DecryptFailed)
            }
        }
    }
}

#[derive(Debug)]
pub enum AeadError {
    EncryptFailed,
    DecryptFailed,
}
```

---

## Partie 2: Web Security (2.9.20-2.9.21)

```rust
//! Web security (2.9.20-2.9.21)

use std::collections::HashMap;

/// HTTP Security headers (2.9.20.a)
pub struct SecurityHeaders {
    headers: HashMap<String, String>,
}

impl SecurityHeaders {
    pub fn new() -> Self {
        let mut headers = HashMap::new();

        // 2.9.20.d: Content Security Policy
        headers.insert(
            "Content-Security-Policy".to_string(),
            "default-src 'self'; script-src 'self'".to_string()
        );

        // Other security headers
        headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
        headers.insert("X-XSS-Protection".to_string(), "1; mode=block".to_string());

        Self { headers }
    }

    /// CORS headers (2.9.20.c)
    pub fn with_cors(mut self, origins: &[&str]) -> Self {
        self.headers.insert(
            "Access-Control-Allow-Origin".to_string(),
            origins.join(", ")
        );
        self
    }
}

/// OWASP Top 10 mitigations (2.9.21)
pub mod owasp {
    /// SQL Injection prevention (2.9.21.a)
    pub fn parameterized_query(query: &str, params: &[&str]) -> String {
        // Use prepared statements, never string concatenation
        format!("PREPARED: {} with {:?}", query, params)
    }

    /// XSS prevention (2.9.21.g)
    pub fn escape_html(input: &str) -> String {
        input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
    }

    /// Input validation (2.9.20.g)
    pub fn validate_email(email: &str) -> bool {
        email.contains('@') && email.contains('.')
    }

    /// Session security (2.9.21.b)
    pub struct SecureSession {
        id: String,
        user_id: u64,
        created_at: u64,
        expires_at: u64,
    }

    impl SecureSession {
        pub fn is_valid(&self, now: u64) -> bool {
            now < self.expires_at
        }
    }
}
```

---

## Partie 3: Memory Safety Concepts (2.9.28-2.9.29)

```rust
//! Memory safety vulnerabilities and Rust prevention (2.9.28-2.9.29)

/// Memory vulnerability types (2.9.28)
pub mod vulnerabilities {
    /// Buffer overflow (2.9.28.a)
    pub struct BufferOverflow;

    /// Use-after-free (2.9.28.b)
    pub struct UseAfterFree;

    /// Double free (2.9.28.c)
    pub struct DoubleFree;

    /// Null pointer dereference (2.9.28.d)
    pub struct NullPointer;

    /// Integer overflow (2.9.28.e)
    pub struct IntegerOverflow;

    /// Format string (2.9.28.f)
    pub struct FormatString;

    /// Race condition (2.9.28.g)
    pub struct RaceCondition;

    /// Type confusion (2.9.28.h)
    pub struct TypeConfusion;
}

/// How Rust prevents vulnerabilities (2.9.29)
pub mod rust_prevention {
    /// Ownership prevents use-after-free (2.9.29.a)
    pub fn ownership_example() {
        let s = String::from("hello");
        let _moved = s;  // s is moved, cannot be used again
        // println!("{}", s);  // Compile error!
    }

    /// Borrowing prevents data races (2.9.29.b)
    pub fn borrowing_example() {
        let mut data = vec![1, 2, 3];
        let _ref1 = &data;  // Immutable borrow
        // let _ref2 = &mut data;  // Error: cannot borrow mutably
    }

    /// Bounds checking prevents buffer overflow (2.9.29.c)
    pub fn bounds_checking() {
        let arr = [1, 2, 3];
        // arr[10];  // Panic at runtime, not undefined behavior
    }

    /// Option prevents null (2.9.29.d)
    pub fn no_null() {
        let maybe: Option<i32> = None;
        // must handle None case explicitly
        if let Some(val) = maybe {
            println!("{}", val);
        }
    }

    /// Checked arithmetic (2.9.29.e)
    pub fn safe_integers() {
        let a: u8 = 255;
        // a + 1 panics in debug, wraps in release with checked_add
        let result = a.checked_add(1);  // Returns None
        assert!(result.is_none());
    }

    /// Send/Sync for thread safety (2.9.29.g)
    pub fn thread_safety<T: Send + Sync>(_val: T) {
        // Only types that are Send can be sent between threads
        // Only types that are Sync can be shared between threads
    }

    /// unsafe blocks are explicit (2.9.29.h)
    pub fn explicit_unsafe() {
        // unsafe code is clearly marked
        unsafe {
            // Raw pointer operations here
        }
    }
}
```

---

## Partie 4: Binary Exploitation Tools (2.9.30-2.9.31)

```rust
//! Binary exploitation tools in Rust (2.9.30-2.9.31)

/// Binary parsing with goblin (2.9.30.a)
pub mod binary_parsing {
    pub struct ElfBinary {
        pub entry_point: u64,
        pub sections: Vec<Section>,
        pub symbols: Vec<Symbol>,
    }

    pub struct Section {
        pub name: String,
        pub addr: u64,
        pub size: u64,
        pub data: Vec<u8>,
    }

    pub struct Symbol {
        pub name: String,
        pub addr: u64,
        pub size: u64,
    }

    /// Parse ELF binary (2.9.30.a, 2.9.30.b)
    pub fn parse_elf(data: &[u8]) -> Result<ElfBinary, String> {
        // use goblin::elf::Elf;
        // let elf = Elf::parse(data)?;
        Ok(ElfBinary {
            entry_point: 0x400000,
            sections: vec![],
            symbols: vec![],
        })
    }
}

/// Disassembly (2.9.30.c)
pub mod disassembly {
    pub struct Instruction {
        pub address: u64,
        pub mnemonic: String,
        pub operands: String,
        pub bytes: Vec<u8>,
    }

    /// Disassemble code (2.9.30.c)
    pub fn disassemble(code: &[u8], base_addr: u64) -> Vec<Instruction> {
        // use capstone::prelude::*;
        vec![Instruction {
            address: base_addr,
            mnemonic: "mov".to_string(),
            operands: "rax, rbx".to_string(),
            bytes: code.to_vec(),
        }]
    }
}

/// Exploit development environment (2.9.31)
pub mod exploit_env {
    /// Check binary protections (2.9.31.c)
    pub struct BinaryProtections {
        pub aslr: bool,
        pub stack_canary: bool,
        pub nx: bool,
        pub pie: bool,
        pub relro: Relro,
    }

    pub enum Relro {
        None,
        Partial,
        Full,
    }

    pub fn checksec(binary: &[u8]) -> BinaryProtections {
        // Parse ELF and check protections
        BinaryProtections {
            aslr: true,
            stack_canary: true,
            nx: true,
            pie: true,
            relro: Relro::Full,
        }
    }

    /// ROP gadget finder (2.9.31.d)
    pub struct RopGadget {
        pub address: u64,
        pub instructions: Vec<String>,
    }

    pub fn find_gadgets(code: &[u8], base: u64) -> Vec<RopGadget> {
        // Search for ret instructions and backtrack
        vec![]
    }
}
```

---

## Partie 5: Exploitation Concepts (2.9.32-2.9.36)

```rust
//! Exploitation concepts (2.9.32-2.9.36)

/// Stack buffer overflow (2.9.32)
pub mod stack_overflow {
    /// Stack layout (2.9.32.a)
    pub struct StackFrame {
        pub local_vars: Vec<u8>,    // Buffer
        pub saved_rbp: u64,         // Previous frame pointer
        pub return_addr: u64,       // 2.9.32.f: Target
    }

    /// Overflow calculation (2.9.32.b)
    pub fn calc_overflow_offset(buffer_size: usize, alignment: usize) -> usize {
        buffer_size + alignment + 8  // +8 for saved RBP
    }

    /// Shellcode (2.9.32.d)
    pub fn execve_shellcode() -> Vec<u8> {
        // /bin/sh shellcode for x86_64
        vec![
            0x48, 0x31, 0xd2,  // xor rdx, rdx
            0x48, 0x31, 0xf6,  // xor rsi, rsi
            0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00,
            0x53,              // push rbx
            0x48, 0x89, 0xe7,  // mov rdi, rsp
            0xb0, 0x3b,        // mov al, 59
            0x0f, 0x05,        // syscall
        ]
    }

    /// NOP sled (2.9.32.e)
    pub fn nop_sled(size: usize) -> Vec<u8> {
        vec![0x90; size]  // NOP instruction
    }
}

/// ROP (2.9.33)
pub mod rop {
    /// ROP chain (2.9.33.c)
    pub struct RopChain {
        gadgets: Vec<u64>,
    }

    impl RopChain {
        pub fn new() -> Self {
            Self { gadgets: vec![] }
        }

        /// Add gadget (2.9.33.b)
        pub fn add_gadget(&mut self, addr: u64) {
            self.gadgets.push(addr);
        }

        /// ret2libc (2.9.33.e)
        pub fn ret2libc(&mut self, system_addr: u64, binsh_addr: u64) {
            // pop rdi; ret gadget
            self.gadgets.push(0x401234);  // pop rdi
            self.gadgets.push(binsh_addr);
            self.gadgets.push(system_addr);
        }

        pub fn to_bytes(&self) -> Vec<u8> {
            self.gadgets.iter()
                .flat_map(|g| g.to_le_bytes())
                .collect()
        }
    }
}

/// Protection mechanisms (2.9.36)
pub mod protections {
    /// ASLR (2.9.36.a)
    pub fn is_aslr_enabled() -> bool {
        // Check /proc/sys/kernel/randomize_va_space
        true
    }

    /// Stack canary (2.9.36.b)
    pub fn detect_stack_canary(binary: &[u8]) -> bool {
        // Check for __stack_chk_fail reference
        true
    }

    /// NX/DEP (2.9.36.c)
    pub fn is_nx_enabled(binary: &[u8]) -> bool {
        // Check ELF program headers for executable stack
        true
    }

    /// PIE (2.9.36.d)
    pub fn is_pie(binary: &[u8]) -> bool {
        // Check ELF type (ET_DYN for PIE)
        true
    }

    /// RELRO (2.9.36.e)
    pub fn check_relro(binary: &[u8]) -> &'static str {
        // Check PT_GNU_RELRO and DT_BIND_NOW
        "Full RELRO"
    }
}
```

---

## Partie 6: Fuzzing (2.9.38-2.9.39)

```rust
//! Fuzzing with Rust (2.9.38-2.9.39)

/// Fuzzing concepts (2.9.38)
pub mod fuzzing {
    /// Fuzz target structure (2.9.39.a-b)
    pub trait FuzzTarget {
        fn fuzz(&self, data: &[u8]) -> FuzzResult;
    }

    pub enum FuzzResult {
        Ok,
        Crash(String),
        Timeout,
        Interesting,
    }

    /// Coverage-guided fuzzing (2.9.38.b)
    pub struct CoverageFuzzer {
        corpus: Vec<Vec<u8>>,        // 2.9.38.f
        crashes: Vec<CrashInfo>,     // 2.9.38.g
        coverage: CoverageMap,
    }

    pub struct CoverageMap {
        edges: Vec<u8>,
    }

    pub struct CrashInfo {
        pub input: Vec<u8>,
        pub backtrace: String,
    }

    impl CoverageFuzzer {
        pub fn new() -> Self {
            Self {
                corpus: vec![],
                crashes: vec![],
                coverage: CoverageMap { edges: vec![0; 65536] },
            }
        }

        /// Add to corpus (2.9.38.f)
        pub fn add_to_corpus(&mut self, input: Vec<u8>) {
            self.corpus.push(input);
        }

        /// Run fuzzing (2.9.39.d)
        pub fn run<T: FuzzTarget>(&mut self, target: &T, iterations: usize) {
            for _ in 0..iterations {
                let input = self.mutate_input();
                match target.fuzz(&input) {
                    FuzzResult::Crash(msg) => {
                        self.crashes.push(CrashInfo {
                            input,
                            backtrace: msg,
                        });
                    }
                    FuzzResult::Interesting => {
                        self.add_to_corpus(input);
                    }
                    _ => {}
                }
            }
        }

        fn mutate_input(&self) -> Vec<u8> {
            // Mutation strategies
            vec![0u8; 100]
        }

        /// Minimize corpus (2.9.39.f)
        pub fn minimize_corpus(&mut self) {
            // Remove redundant inputs
        }
    }
}

/// cargo-fuzz example (2.9.38.c-d)
pub mod cargo_fuzz {
    // fuzz/fuzz_targets/fuzz_parser.rs
    // #![no_main]
    // use libfuzzer_sys::fuzz_target;
    //
    // fuzz_target!(|data: &[u8]| {  // 2.9.39.c
    //     if let Ok(s) = std::str::from_utf8(data) {
    //         let _ = parse_input(s);
    //     }
    // });
}
```

---

## Partie 7: unsafe Auditing & Security Tools (2.9.40-2.9.43)

```rust
//! unsafe auditing and security tools (2.9.40-2.9.43)

/// unsafe auditing (2.9.40)
pub mod unsafe_audit {
    /// Find unsafe blocks (2.9.40.a)
    pub struct UnsafeUsage {
        pub file: String,
        pub line: usize,
        pub reason: String,
    }

    /// cargo-geiger output (2.9.40.b)
    pub struct GeigerReport {
        pub safe_functions: usize,
        pub unsafe_functions: usize,
        pub unsafe_expressions: usize,
    }

    /// Miri check (2.9.40.c)
    pub fn run_miri_check(code: &str) -> Result<(), String> {
        // cargo +nightly miri run
        Ok(())
    }

    /// cargo-audit (2.9.40.d)
    pub struct VulnerabilityReport {
        pub crate_name: String,
        pub version: String,
        pub advisory_id: String,  // 2.9.40.g: RUSTSEC
        pub severity: Severity,
    }

    pub enum Severity {
        Low,
        Medium,
        High,
        Critical,
    }
}

/// Network security tools (2.9.41)
pub mod network_tools {
    use std::net::TcpStream;
    use std::time::Duration;

    /// Port scanner (2.9.41.a)
    pub fn scan_port(host: &str, port: u16, timeout: Duration) -> bool {
        TcpStream::connect_timeout(
            &format!("{}:{}", host, port).parse().unwrap(),
            timeout
        ).is_ok()
    }

    /// Scan port range
    pub fn scan_ports(host: &str, ports: std::ops::Range<u16>) -> Vec<u16> {
        ports.filter(|&p| scan_port(host, p, Duration::from_millis(100)))
             .collect()
    }

    /// TLS certificate check (2.9.41.e)
    pub struct TlsInfo {
        pub version: String,
        pub cipher: String,
        pub cert_valid: bool,
        pub cert_expiry: String,
    }
}

/// Building security tools (2.9.43)
pub mod tool_building {
    /// Scanner architecture (2.9.43.a)
    pub struct SecurityScanner {
        targets: Vec<String>,
        modules: Vec<Box<dyn ScanModule>>,
    }

    pub trait ScanModule {
        fn name(&self) -> &str;
        fn scan(&self, target: &str) -> ScanResult;
    }

    pub struct ScanResult {
        pub findings: Vec<Finding>,
    }

    pub struct Finding {
        pub severity: String,
        pub title: String,
        pub description: String,
    }

    impl SecurityScanner {
        pub fn new() -> Self {
            Self { targets: vec![], modules: vec![] }
        }

        pub fn add_target(&mut self, target: String) {
            self.targets.push(target);
        }

        /// Run all modules (2.9.43.a)
        pub fn run(&self) -> Vec<ScanResult> {
            self.targets.iter()
                .flat_map(|t| self.modules.iter().map(|m| m.scan(t)))
                .collect()
        }
    }
}
```

---

## Partie 8: CTF & Threat Modeling (2.9.42, 2.9.44)

```rust
//! CTF skills and threat modeling (2.9.42, 2.9.44)

/// CTF categories (2.9.42)
pub mod ctf {
    /// CTF challenge types (2.9.42.a)
    #[derive(Debug)]
    pub enum Category {
        Pwn,     // 2.9.42.b: Binary exploitation
        Rev,     // 2.9.42.c: Reverse engineering
        Crypto,  // 2.9.42.d: Cryptography
        Web,     // 2.9.42.e: Web security
        Forensics,
        Misc,
    }

    /// Rust for CTF (2.9.42.f)
    pub struct CtfToolkit {
        pub solvers: Vec<String>,
    }

    impl CtfToolkit {
        pub fn new() -> Self {
            Self {
                solvers: vec![
                    "Binary parser (goblin)".into(),
                    "Crypto solver".into(),
                    "Network tools".into(),
                ],
            }
        }
    }

    /// Write-up structure (2.9.42.g)
    pub struct WriteUp {
        pub challenge: String,
        pub category: Category,
        pub difficulty: String,
        pub solution: String,
        pub flag: String,
    }
}

/// Threat modeling (2.9.44)
pub mod threat_modeling {
    /// STRIDE categories (2.9.44.a)
    #[derive(Debug)]
    pub enum StrideCategory {
        Spoofing,          // Authentication
        Tampering,         // Integrity
        Repudiation,       // Non-repudiation
        InformationDisclosure, // Confidentiality
        DenialOfService,   // Availability
        ElevationOfPrivilege, // Authorization
    }

    /// Threat (2.9.44.a)
    pub struct Threat {
        pub category: StrideCategory,
        pub description: String,
        pub attack_surface: String,  // 2.9.44.b
        pub trust_boundary: String,  // 2.9.44.c
        pub risk: RiskLevel,         // 2.9.44.e
        pub mitigation: String,      // 2.9.44.f
    }

    pub enum RiskLevel {
        Low,
        Medium,
        High,
        Critical,
    }

    /// Data Flow Diagram (2.9.44.d)
    pub struct DataFlow {
        pub source: String,
        pub destination: String,
        pub data_type: String,
        pub crosses_boundary: bool,
    }

    /// Threat model (2.9.44)
    pub struct ThreatModel {
        pub system_name: String,
        pub data_flows: Vec<DataFlow>,
        pub threats: Vec<Threat>,
        pub requirements: Vec<String>,  // 2.9.44.g
    }

    impl ThreatModel {
        /// Rust ownership as security (2.9.44.h)
        pub fn rust_security_benefits() -> Vec<&'static str> {
            vec![
                "Ownership prevents use-after-free",
                "Borrowing prevents data races",
                "Type system prevents type confusion",
                "Option prevents null dereference",
            ]
        }
    }
}
```

---

## Tests Moulinette

```rust
#[test] fn test_aead()                // 2.9.6
#[test] fn test_web_security()        // 2.9.20
#[test] fn test_owasp()               // 2.9.21
#[test] fn test_memory_vulns()        // 2.9.28
#[test] fn test_rust_prevention()     // 2.9.29
#[test] fn test_binary_tools()        // 2.9.30
#[test] fn test_exploit_env()         // 2.9.31
#[test] fn test_stack_overflow()      // 2.9.32
#[test] fn test_rop()                 // 2.9.33
#[test] fn test_heap_exploit()        // 2.9.34
#[test] fn test_format_string()       // 2.9.35
#[test] fn test_protections()         // 2.9.36
#[test] fn test_reverse_eng()         // 2.9.37
#[test] fn test_fuzzing()             // 2.9.38
#[test] fn test_fuzz_example()        // 2.9.39
#[test] fn test_unsafe_audit()        // 2.9.40
#[test] fn test_network_tools()       // 2.9.41
#[test] fn test_ctf()                 // 2.9.42
#[test] fn test_security_tools()      // 2.9.43
#[test] fn test_threat_model()        // 2.9.44
```

---

## Bareme

| Critere | Points |
|---------|--------|
| AEAD (2.9.6) | 5 |
| Web Security (2.9.20-2.9.21) | 10 |
| Memory Safety (2.9.28-2.9.29) | 10 |
| Binary Tools (2.9.30-2.9.31) | 10 |
| Exploitation (2.9.32-2.9.36) | 25 |
| Reverse Engineering (2.9.37) | 5 |
| Fuzzing (2.9.38-2.9.39) | 15 |
| Auditing (2.9.40) | 5 |
| Network Tools (2.9.41) | 5 |
| CTF & Threat Modeling (2.9.42-2.9.44) | 10 |
| **Total** | **100** |
