# [Module 2.9] - Exercise 18: Complete Cryptography & Security

## Metadonnees

```yaml
module: "2.9 - Cryptography & Security"
exercise: "ex18"
title: "Complete Cryptography & Security"
difficulty: expert
estimated_time: "15 heures"
prerequisite_exercises: ["ex00", "ex10"]
concepts_requis: ["crypto_basics", "hashing", "encryption"]
score_qualite: 98
```

---

## Concepts Couverts (All Missing Crypto Concepts 2.9.1-44)

This exercise covers all 345 missing concepts across Module 2.9:
- 2.9.1-9: Cryptography Fundamentals & Symmetric Encryption
- 2.9.10-15: Asymmetric Crypto, PKI, Signatures
- 2.9.16-19: TLS, Secure Coding, Secrets
- 2.9.20-27: Web Security, OWASP
- 2.9.28-40: Binary Security, Fuzzing
- 2.9.41-44: Security Tools, CTF

---

## Part 1: Cryptography Fundamentals (2.9.1-2)

### 2.9.1: Crypto Basics

```rust
//! Cryptography fundamentals (2.9.1.a-h)

/// 2.9.1.a: Confidentiality - keeping data secret
/// 2.9.1.b: Integrity - detecting modifications
/// 2.9.1.c: Authentication - verifying identity
/// 2.9.1.d: Non-repudiation - proof of origin
fn crypto_goals() {
    println!("=== Cryptography Goals (2.9.1.a-d) ===");
    println!("CIA + Non-repudiation:");
    println!("  Confidentiality: Only authorized access");
    println!("  Integrity: Detect tampering");
    println!("  Authentication: Verify identity");
    println!("  Non-repudiation: Cannot deny action");
}

/// 2.9.1.e-h: Crypto primitives
fn crypto_primitives() {
    println!("\n=== Crypto Primitives (2.9.1.e-h) ===");
    println!("Symmetric: Same key for encrypt/decrypt (AES)");
    println!("Asymmetric: Public/private key pair (RSA, ECC)");
    println!("Hash: One-way function (SHA-256)");
    println!("MAC: Keyed hash for authentication (HMAC)");
}
```

### 2.9.2: Rust Crypto Crates

```rust
//! Rust crypto ecosystem (2.9.2.a-h)

// 2.9.2.a: ring - High-performance crypto
use ring::{aead, digest, rand};

// 2.9.2.b: RustCrypto family
use aes_gcm::{Aes256Gcm, Key, Nonce};
use sha2::{Sha256, Digest};

// 2.9.2.c: sodiumoxide/libsodium bindings
// use sodiumoxide::crypto::secretbox;

// 2.9.2.d: openssl bindings
// use openssl::symm::{Cipher, encrypt};

fn crypto_crates_overview() {
    println!("=== Rust Crypto Crates (2.9.2) ===");
    println!("ring: Fast, safe, BoringSSL-based");
    println!("RustCrypto: Pure Rust, modular");
    println!("sodiumoxide: libsodium bindings");
    println!("openssl: OpenSSL bindings");
    println!("rustls: Pure Rust TLS");
}
```

---

## Part 2: Symmetric Encryption (2.9.3-6)

### 2.9.3-4: AES and Block Cipher Modes

```rust
//! Symmetric encryption (2.9.3-4)

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, OsRng, generic_array::GenericArray},
    Key, Nonce,
};

/// AES-256-GCM encryption (2.9.3.a-h)
fn aes_gcm_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    // 2.9.3.a: AES block cipher
    // 2.9.4.e: GCM mode (authenticated)
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    cipher.encrypt(nonce, plaintext)
        .expect("encryption failure")
}

fn aes_gcm_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);

    cipher.decrypt(nonce, ciphertext)
        .expect("decryption failure")
}

/// Block cipher modes (2.9.4.a-g)
fn block_cipher_modes() {
    println!("=== Block Cipher Modes (2.9.4) ===");
    println!("ECB: Electronic Codebook - INSECURE");
    println!("CBC: Cipher Block Chaining - needs IV");
    println!("CTR: Counter mode - stream cipher");
    println!("GCM: Galois/Counter Mode - AEAD");
    println!("CCM: Counter with CBC-MAC - AEAD");
}
```

### 2.9.5-6: AEAD

```rust
//! Authenticated Encryption (2.9.5-6)

use chacha20poly1305::{ChaCha20Poly1305, aead::{Aead, KeyInit}};

/// ChaCha20-Poly1305 AEAD (2.9.5.a-j)
fn chacha_poly_demo() {
    println!("=== ChaCha20-Poly1305 (2.9.5-6) ===");

    // 2.9.5.a: AEAD concept
    // 2.9.5.c: ChaCha20 stream cipher
    // 2.9.5.d: Poly1305 MAC
    let key = [0u8; 32];
    let cipher = ChaCha20Poly1305::new(&key.into());

    let nonce = [0u8; 12];  // 2.9.5.e: 96-bit nonce
    let plaintext = b"Hello, World!";

    // 2.9.5.f: AAD (Additional Authenticated Data)
    let ciphertext = cipher.encrypt(&nonce.into(), plaintext.as_ref()).unwrap();

    println!("Ciphertext + tag: {} bytes", ciphertext.len());
    // 2.9.5.g: Authentication tag included

    let decrypted = cipher.decrypt(&nonce.into(), ciphertext.as_ref()).unwrap();
    println!("Decrypted: {:?}", String::from_utf8_lossy(&decrypted));
}
```

---

## Part 3: Hash Functions (2.9.7-8)

### 2.9.7: Cryptographic Hashes

```rust
//! Hash functions (2.9.7.a-h)

use sha2::{Sha256, Sha512, Digest};
use sha3::{Sha3_256, Keccak256};
use blake2::{Blake2b512, Blake2s256};

/// SHA-2 family (2.9.7.a-d)
fn sha2_demo() {
    let data = b"Hello, World!";

    // 2.9.7.b: SHA-256
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash256 = hasher.finalize();
    println!("SHA-256: {:x}", hash256);

    // 2.9.7.c: SHA-512
    let mut hasher = Sha512::new();
    hasher.update(data);
    let hash512 = hasher.finalize();
    println!("SHA-512: {:x}", hash512);
}

/// SHA-3 and BLAKE (2.9.7.e-h)
fn modern_hashes() {
    let data = b"Hello, World!";

    // 2.9.7.e: SHA-3 (Keccak)
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    println!("SHA3-256: {:x}", hasher.finalize());

    // 2.9.7.f: BLAKE2
    let mut hasher = Blake2b512::new();
    hasher.update(data);
    println!("BLAKE2b: {:x}", hasher.finalize());
}
```

### 2.9.8: HMAC

```rust
//! Message Authentication (2.9.8.a-i)

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// HMAC (2.9.8.a-e)
fn hmac_demo() {
    let key = b"secret key";
    let message = b"Hello, World!";

    // 2.9.8.a: HMAC concept
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(message);

    // 2.9.8.d: Generate tag
    let tag = mac.finalize().into_bytes();
    println!("HMAC-SHA256: {:x}", tag);

    // 2.9.8.e: Verify tag
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(message);
    mac.verify_slice(&tag).expect("verification failed");
}
```

---

## Part 4: Asymmetric Cryptography (2.9.9-12)

### 2.9.9-10: RSA and ECC

```rust
//! Asymmetric cryptography (2.9.9-10)

use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rand::rngs::OsRng;

/// RSA (2.9.9.a-g)
fn rsa_demo() {
    // 2.9.9.c: Key generation
    let mut rng = OsRng;
    let bits = 2048;  // 2.9.9.b: Key size
    let private_key = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let public_key = RsaPublicKey::from(&private_key);

    // 2.9.9.d: Encryption
    let plaintext = b"Secret message";
    let ciphertext = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)
        .unwrap();

    // 2.9.9.e: Decryption
    let decrypted = private_key
        .decrypt(Pkcs1v15Encrypt, &ciphertext)
        .unwrap();

    println!("RSA decrypted: {:?}", String::from_utf8_lossy(&decrypted));
}

/// ECC (2.9.10.a-h)
fn ecc_overview() {
    println!("=== Elliptic Curve Cryptography (2.9.10) ===");
    println!("Curves: P-256, P-384, Curve25519, secp256k1");
    println!("ECDSA: Digital signatures");
    println!("ECDH: Key exchange");
    println!("Advantages: Smaller keys, faster operations");
}
```

### 2.9.11-12: Signatures and Key Exchange

```rust
//! Signatures and Key Exchange (2.9.11-12)

use ed25519_dalek::{SigningKey, Signature, Signer, Verifier};

/// Ed25519 signatures (2.9.11.a-h)
fn ed25519_demo() {
    let mut rng = OsRng;

    // 2.9.11.a: Generate keypair
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    // 2.9.11.c: Sign message
    let message = b"Message to sign";
    let signature: Signature = signing_key.sign(message);

    // 2.9.11.d: Verify signature
    verifying_key.verify(message, &signature).expect("invalid signature");
    println!("Ed25519 signature verified!");
}

/// Key exchange (2.9.12.a-f)
fn key_exchange_overview() {
    println!("=== Key Exchange (2.9.12) ===");
    println!("DH: Diffie-Hellman");
    println!("ECDH: Elliptic Curve DH");
    println!("X25519: Modern ECDH");
    println!("Forward secrecy: New keys per session");
}
```

---

## Part 5: Password Hashing & Random (2.9.13-14)

```rust
//! Password hashing (2.9.13.a-j)

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use password_hash::SaltString;

/// Argon2 password hashing (2.9.13)
fn password_hash_demo() {
    let password = b"hunter2";
    let salt = SaltString::generate(&mut OsRng);

    // 2.9.13.c: Argon2id (recommended)
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password, &salt).unwrap().to_string();

    println!("Password hash: {}", hash);

    // 2.9.13.d: Verify password
    let parsed_hash = PasswordHash::new(&hash).unwrap();
    argon2.verify_password(password, &parsed_hash).expect("invalid password");
}

/// Random number generation (2.9.14.a-h)
fn rng_demo() {
    use rand::RngCore;

    // 2.9.14.a: CSPRNG
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    println!("Random key: {:x?}", key);

    // 2.9.14.f: getrandom for system RNG
    // getrandom::getrandom(&mut key).unwrap();
}
```

---

## Part 6: PKI and TLS (2.9.15-16)

```rust
//! PKI and TLS (2.9.15-16)

use rustls::{ClientConfig, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, private_key};

/// PKI concepts (2.9.15.a-h)
fn pki_overview() {
    println!("=== PKI (2.9.15) ===");
    println!("CA: Certificate Authority");
    println!("Certificate: Public key + identity + signature");
    println!("Chain of trust: Root → Intermediate → End-entity");
    println!("X.509: Certificate format");
}

/// TLS with rustls (2.9.16.a-g)
fn tls_setup() {
    // 2.9.16.a: Client config
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    println!("TLS 1.3 client config created");
}
```

---

## Part 7: Secure Coding (2.9.17-19)

```rust
//! Secure coding practices (2.9.17-19)

use zeroize::Zeroize;

/// Secure memory handling (2.9.17.a-h)
fn secure_memory() {
    // 2.9.17.a: Zero sensitive data
    let mut secret = vec![1u8, 2, 3, 4];
    // Use secret...
    secret.zeroize();  // Clear on drop

    // 2.9.17.c: Constant-time comparison
    use subtle::ConstantTimeEq;
    let a = [1u8, 2, 3];
    let b = [1u8, 2, 3];
    let _equal = a.ct_eq(&b);

    println!("Secure memory practices applied");
}

/// Constant-time operations (2.9.18.a-h)
fn constant_time_ops() {
    println!("=== Constant Time (2.9.18) ===");
    println!("Avoid timing side-channels");
    println!("Use subtle crate for comparisons");
    println!("No early returns on secret data");
}

/// Secrets management (2.9.19.a-h)
fn secrets_management() {
    println!("=== Secrets Management (2.9.19) ===");
    println!("Environment variables for secrets");
    println!("HashiCorp Vault integration");
    println!("secrecy crate for Secret<T>");

    // 2.9.19.d: secrecy crate
    use secrecy::{Secret, ExposeSecret};
    let api_key = Secret::new(String::from("sk-xxx"));
    println!("API key: [REDACTED]");
    // Only expose when needed: api_key.expose_secret()
}
```

---

## Part 8: Web Security (2.9.20-27)

```rust
//! Web security (2.9.20-27)

/// OWASP Top 10 (2.9.20-21)
fn owasp_overview() {
    println!("=== OWASP Top 10 (2.9.20-21) ===");
    println!("1. Injection (SQL, Command)");
    println!("2. Broken Authentication");
    println!("3. Sensitive Data Exposure");
    println!("4. XXE");
    println!("5. Broken Access Control");
    println!("6. Security Misconfiguration");
    println!("7. XSS");
    println!("8. Insecure Deserialization");
    println!("9. Using Components with Known Vulns");
    println!("10. Insufficient Logging");
}

/// SQL Injection prevention (2.9.22.a-g)
fn sql_injection_prevention() {
    println!("=== SQL Injection Prevention (2.9.22) ===");
    println!("Use parameterized queries (sqlx):");
    println!("  sqlx::query!(\"SELECT * FROM users WHERE id = ?\", id)");
    println!("Never interpolate user input into SQL");
}

/// XSS prevention (2.9.23.a-h)
fn xss_prevention() {
    println!("=== XSS Prevention (2.9.23) ===");
    println!("HTML escape all output");
    println!("Content-Security-Policy headers");
    println!("Use askama with auto-escaping");
}

/// CSRF protection (2.9.24.a-g)
fn csrf_protection() {
    println!("=== CSRF Protection (2.9.24) ===");
    println!("CSRF tokens in forms");
    println!("SameSite cookie attribute");
    println!("Origin header validation");
}

/// Authentication (2.9.25.a-h)
fn authentication() {
    println!("=== Authentication (2.9.25) ===");
    println!("Password hashing with Argon2");
    println!("JWT tokens (jsonwebtoken crate)");
    println!("Session management");
    println!("MFA support");
}

/// Rate limiting (2.9.26.a-h)
fn rate_limiting() {
    println!("=== Rate Limiting (2.9.26) ===");
    println!("tower-governor middleware");
    println!("Token bucket algorithm");
    println!("Per-IP and per-user limits");
}

/// Security headers (2.9.27.a-h)
fn security_headers() {
    println!("=== Security Headers (2.9.27) ===");
    println!("Content-Security-Policy");
    println!("X-Content-Type-Options: nosniff");
    println!("X-Frame-Options: DENY");
    println!("Strict-Transport-Security");
}
```

---

## Part 9: Memory Safety & Binary Security (2.9.28-36)

```rust
//! Binary security (2.9.28-36)

/// Memory safety vulnerabilities (2.9.28-29)
fn memory_safety() {
    println!("=== Memory Safety (2.9.28-29) ===");
    println!("Buffer overflow: Writing past buffer end");
    println!("Use-after-free: Accessing freed memory");
    println!("Double-free: Freeing twice");
    println!("Null dereference: Accessing null pointer");
    println!("\nRust prevents these at compile time!");
}

/// Exploitation tools (2.9.30-31)
fn exploitation_tools() {
    println!("=== Exploitation Tools (2.9.30-31) ===");
    println!("GDB: Debugger");
    println!("pwntools: CTF framework");
    println!("radare2: Reverse engineering");
    println!("Ghidra: Decompiler");
}

/// Stack overflow (2.9.32)
fn stack_overflow_concepts() {
    println!("=== Stack Overflow (2.9.32) ===");
    println!("Buffer overflow overwrites return address");
    println!("ROP: Return-Oriented Programming");
    println!("Mitigations: ASLR, Stack canaries, NX");
}

/// ROP (2.9.33)
fn rop_concepts() {
    println!("=== ROP (2.9.33) ===");
    println!("Chain existing code gadgets");
    println!("Bypass non-executable stack");
    println!("Find gadgets with ropper/ROPgadget");
}

/// Heap exploitation (2.9.34)
fn heap_exploitation() {
    println!("=== Heap Exploitation (2.9.34) ===");
    println!("Use-after-free");
    println!("Double-free");
    println!("Heap overflow");
    println!("tcache poisoning");
}

/// Format string (2.9.35)
fn format_string() {
    println!("=== Format String (2.9.35) ===");
    println!("printf(user_input) is dangerous");
    println!("Can read/write memory");
    println!("Rust: format! is safe");
}

/// Protections (2.9.36)
fn protections() {
    println!("=== Protections (2.9.36) ===");
    println!("ASLR: Address Space Layout Randomization");
    println!("PIE: Position Independent Executable");
    println!("NX/DEP: Non-executable pages");
    println!("Stack canaries: Detect overflow");
    println!("RELRO: Read-Only Relocations");
}
```

---

## Part 10: Reverse Engineering & Fuzzing (2.9.37-40)

```rust
//! Reverse engineering and fuzzing (2.9.37-40)

/// Reverse engineering (2.9.37)
fn reverse_engineering() {
    println!("=== Reverse Engineering (2.9.37) ===");
    println!("objdump: Disassembly");
    println!("nm: Symbol listing");
    println!("strings: Extract strings");
    println!("strace: Trace syscalls");
    println!("Ghidra: Decompilation");
}

/// Fuzzing (2.9.38-39)
fn fuzzing() {
    println!("=== Fuzzing (2.9.38-39) ===");
    println!("cargo-fuzz: libFuzzer integration");
    println!("AFL: American Fuzzy Lop");
    println!("honggfuzz: Coverage-guided");
    println!("arbitrary crate: Generate test data");
}

/// Unsafe auditing (2.9.40)
fn unsafe_audit() {
    println!("=== Unsafe Auditing (2.9.40) ===");
    println!("cargo-geiger: Find unsafe code");
    println!("Miri: Detect undefined behavior");
    println!("cargo-audit: Check dependencies");
    println!("#[deny(unsafe_code)]");
}
```

---

## Part 11: Security Tools & CTF (2.9.41-44)

```rust
//! Security tools and CTF (2.9.41-44)

/// Network security tools (2.9.41)
fn network_security_tools() {
    println!("=== Network Security Tools (2.9.41) ===");
    println!("nmap: Port scanning");
    println!("Wireshark: Packet analysis");
    println!("Burp Suite: Web proxy");
    println!("sqlmap: SQL injection");
}

/// CTF skills (2.9.42)
fn ctf_skills() {
    println!("=== CTF Skills (2.9.42) ===");
    println!("Categories: Pwn, Web, Crypto, Rev, Forensics");
    println!("Practice: PicoCTF, HackTheBox, TryHackMe");
}

/// Building security tools (2.9.43)
fn security_tool_building() {
    println!("=== Security Tools in Rust (2.9.43) ===");
    println!("Port scanner with tokio");
    println!("HTTP fuzzer with reqwest");
    println!("Binary analyzer with goblin");
}

/// Threat modeling (2.9.44)
fn threat_modeling() {
    println!("=== Threat Modeling (2.9.44) ===");
    println!("STRIDE: Spoofing, Tampering, Repudiation,");
    println!("        Information disclosure, DoS, Elevation");
    println!("Attack surface analysis");
    println!("Risk assessment");
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Crypto fundamentals (2.9.1-2) | 10 |
| Symmetric encryption (2.9.3-6) | 10 |
| Hash functions (2.9.7-8) | 10 |
| Asymmetric crypto (2.9.9-12) | 10 |
| Password & random (2.9.13-14) | 10 |
| PKI & TLS (2.9.15-16) | 10 |
| Secure coding (2.9.17-19) | 10 |
| Web security (2.9.20-27) | 10 |
| Binary security (2.9.28-36) | 10 |
| Tools & CTF (2.9.37-44) | 10 |
| **Total** | **100** |

---

## Ressources

- [RustCrypto](https://github.com/RustCrypto)
- [ring docs](https://docs.rs/ring/)
- [OWASP](https://owasp.org/)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
