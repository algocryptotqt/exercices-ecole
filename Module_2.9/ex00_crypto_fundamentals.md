# ex00: Cryptography Fundamentals & Symmetric Encryption

**Module**: 2.9 - Computer Security
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.9.1: Cryptography Fundamentals (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Cryptography goals | Confidentiality, integrity, authentication |
| b | Plaintext | Original message |
| c | Ciphertext | Encrypted message |
| d | Key | Secret parameter |
| e | Algorithm | Encryption method |
| f | Kerckhoffs' principle | Security from key, not algorithm |
| g | Symmetric | Same key for encrypt/decrypt |
| h | Asymmetric | Different keys (public/private) |

### 2.9.2: Symmetric Encryption (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Block cipher | Fixed-size blocks |
| b | DES | Data Encryption Standard (broken) |
| c | 3DES | Triple DES |
| d | AES | Advanced Encryption Standard |
| e | AES structure | SubBytes, ShiftRows, MixColumns, AddRoundKey |
| f | AES key sizes | 128, 192, 256 bits |
| g | AES rounds | 10, 12, 14 |
| h | Stream cipher | Continuous stream |
| i | ChaCha20 | Modern stream cipher |
| j | RC4 | Broken stream cipher |

---

## Sujet

Comprendre les fondamentaux de la cryptographie et implementer des algorithmes de chiffrement symetrique.

### Structures

```c
// Cryptographic message
typedef struct {
    uint8_t *data;
    size_t length;
} crypto_buffer_t;

// Symmetric key
typedef struct {
    uint8_t key[32];     // Max 256 bits
    size_t key_len;      // 16, 24, or 32 bytes
    char algorithm[16];  // "AES", "DES", "ChaCha20"
} symmetric_key_t;

// AES context
typedef struct {
    uint8_t round_keys[240];  // Expanded key schedule
    int rounds;               // 10, 12, or 14
    int key_size;            // 128, 192, 256
} aes_context_t;

// Cipher result
typedef struct {
    uint8_t *ciphertext;
    size_t length;
    bool success;
    char error[64];
} cipher_result_t;

// Crypto algorithm info
typedef struct {
    char name[32];
    int block_size;       // 0 for stream ciphers
    int key_sizes[4];     // Supported key sizes
    bool is_secure;       // Still considered secure?
    char notes[128];
} algorithm_info_t;
```

### API

```c
// Cryptography fundamentals
const char *crypto_goal_description(int goal);  // 0=conf, 1=integrity, 2=auth
void explain_kerckhoffs(void);
void compare_symmetric_asymmetric(void);

// Key management
symmetric_key_t *generate_key(const char *algorithm, int bits);
void derive_key(const uint8_t *password, size_t pw_len,
                const uint8_t *salt, size_t salt_len,
                uint8_t *key, size_t key_len);
void secure_zero(void *ptr, size_t len);

// AES implementation
void aes_init(aes_context_t *ctx, const uint8_t *key, int bits);
void aes_encrypt_block(aes_context_t *ctx, const uint8_t in[16], uint8_t out[16]);
void aes_decrypt_block(aes_context_t *ctx, const uint8_t in[16], uint8_t out[16]);

// AES operations (educational)
void aes_sub_bytes(uint8_t state[16]);
void aes_shift_rows(uint8_t state[16]);
void aes_mix_columns(uint8_t state[16]);
void aes_add_round_key(uint8_t state[16], const uint8_t *round_key);
void aes_key_expansion(const uint8_t *key, uint8_t *w, int nk, int nr);

// Stream cipher (simplified ChaCha20)
void chacha20_init(uint32_t state[16], const uint8_t key[32],
                   const uint8_t nonce[12], uint32_t counter);
void chacha20_block(uint32_t state[16], uint8_t out[64]);
void chacha20_encrypt(const uint8_t *key, const uint8_t *nonce,
                      uint32_t counter, const uint8_t *in,
                      uint8_t *out, size_t len);

// Algorithm comparison
algorithm_info_t get_algorithm_info(const char *name);
void print_algorithm_comparison(void);
```

---

## Exemple

```c
#include "crypto_fundamentals.h"

int main(void) {
    // 2.9.1: Cryptography Fundamentals
    printf("=== Cryptography Fundamentals ===\n\n");

    // Goals of cryptography
    printf("Three pillars of security:\n");
    printf("  1. Confidentiality: %s\n", crypto_goal_description(0));
    printf("  2. Integrity: %s\n", crypto_goal_description(1));
    printf("  3. Authentication: %s\n", crypto_goal_description(2));
    /*
    Output:
      1. Confidentiality: Only authorized parties can read the data
      2. Integrity: Data has not been modified
      3. Authentication: Verify identity of parties
    */

    // Basic concepts
    printf("\nBasic Cryptographic Concepts:\n");
    printf("  Plaintext:  Original readable message\n");
    printf("  Ciphertext: Encrypted unreadable output\n");
    printf("  Key:        Secret parameter for encryption/decryption\n");
    printf("  Algorithm:  Mathematical transformation\n");

    // Kerckhoffs' principle
    printf("\nKerckhoffs' Principle (1883):\n");
    printf("  'A cryptosystem should be secure even if everything\n");
    printf("   about the system, except the key, is public knowledge.'\n");
    printf("\n  Why? Security through obscurity FAILS when:\n");
    printf("    - Algorithm is reverse-engineered\n");
    printf("    - Source code is leaked\n");
    printf("    - Insiders reveal secrets\n");
    printf("  Modern crypto algorithms (AES, ChaCha20) are public!\n");

    // Symmetric vs Asymmetric
    printf("\nSymmetric vs Asymmetric Encryption:\n");
    printf("  +--------------+----------------+------------------+\n");
    printf("  | Aspect       | Symmetric      | Asymmetric       |\n");
    printf("  +--------------+----------------+------------------+\n");
    printf("  | Keys         | Same key       | Public + Private |\n");
    printf("  | Speed        | Very fast      | 100-1000x slower |\n");
    printf("  | Key exchange | Hard problem   | Easy (public)    |\n");
    printf("  | Examples     | AES, ChaCha20  | RSA, ECC         |\n");
    printf("  | Use case     | Bulk data      | Key exchange     |\n");
    printf("  +--------------+----------------+------------------+\n");

    // 2.9.2: Symmetric Encryption
    printf("\n=== Symmetric Encryption ===\n\n");

    // Block ciphers
    printf("Block Ciphers (fixed-size blocks):\n");

    // DES (historical)
    algorithm_info_t des = get_algorithm_info("DES");
    printf("\n  DES (Data Encryption Standard, 1977):\n");
    printf("    Block size: %d bits\n", des.block_size);
    printf("    Key size:   56 bits (+ 8 parity = 64 bits)\n");
    printf("    Status:     %s\n", des.is_secure ? "Secure" : "BROKEN");
    printf("    Note:       %s\n", des.notes);
    /*
    Note: Broken in 1999 (22 hours brute force). Never use!
    */

    // 3DES
    algorithm_info_t tdes = get_algorithm_info("3DES");
    printf("\n  3DES (Triple DES):\n");
    printf("    Process:    Encrypt -> Decrypt -> Encrypt\n");
    printf("    Key size:   168 bits (112 effective)\n");
    printf("    Status:     Deprecated (slow, weak against MITM)\n");

    // AES
    printf("\n  AES (Advanced Encryption Standard, 2001):\n");
    printf("    Winner of NIST competition (Rijndael)\n");
    printf("    Block size: 128 bits\n");
    printf("    Key sizes:  128, 192, 256 bits\n");
    printf("    Rounds:     10, 12, 14 (depends on key size)\n");
    printf("    Status:     SECURE - Current standard\n");

    // AES structure
    printf("\n  AES Round Structure:\n");
    printf("    1. SubBytes    - S-box substitution (confusion)\n");
    printf("    2. ShiftRows   - Byte permutation (diffusion)\n");
    printf("    3. MixColumns  - Column mixing (diffusion)\n");
    printf("    4. AddRoundKey - XOR with round key\n");
    printf("\n    First round:  AddRoundKey only\n");
    printf("    Last round:   No MixColumns\n");

    // AES key sizes and rounds
    printf("\n  AES Variants:\n");
    printf("    +----------+------+--------+\n");
    printf("    | Key Size | Nk   | Rounds |\n");
    printf("    +----------+------+--------+\n");
    printf("    | 128 bits |  4   |   10   |\n");
    printf("    | 192 bits |  6   |   12   |\n");
    printf("    | 256 bits |  8   |   14   |\n");
    printf("    +----------+------+--------+\n");

    // AES demonstration
    printf("\n  AES-128 Encryption Demo:\n");
    uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                       0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t plaintext[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                             0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t ciphertext[16];
    uint8_t decrypted[16];

    aes_context_t ctx;
    aes_init(&ctx, key, 128);
    aes_encrypt_block(&ctx, plaintext, ciphertext);
    aes_decrypt_block(&ctx, ciphertext, decrypted);

    printf("    Key:        ");
    for (int i = 0; i < 16; i++) printf("%02x", key[i]);
    printf("\n    Plaintext:  ");
    for (int i = 0; i < 16; i++) printf("%02x", plaintext[i]);
    printf("\n    Ciphertext: ");
    for (int i = 0; i < 16; i++) printf("%02x", ciphertext[i]);
    printf("\n    Decrypted:  ");
    for (int i = 0; i < 16; i++) printf("%02x", decrypted[i]);
    printf("\n    Match: %s\n", memcmp(plaintext, decrypted, 16) == 0 ? "YES" : "NO");

    // Stream ciphers
    printf("\n\nStream Ciphers (continuous keystream):\n");
    printf("  Operation: plaintext XOR keystream = ciphertext\n");
    printf("  Advantage: Can encrypt any length, byte-by-byte\n");

    // RC4 (historical/broken)
    printf("\n  RC4 (1987):\n");
    printf("    Status:  BROKEN - Multiple vulnerabilities\n");
    printf("    Issues:  Biased output, related-key attacks\n");
    printf("    Note:    Was used in WEP, TLS (both deprecated)\n");

    // ChaCha20
    printf("\n  ChaCha20 (2008, Bernstein):\n");
    printf("    Key size:   256 bits\n");
    printf("    Nonce:      96 bits (or 64 bits original)\n");
    printf("    Counter:    32 bits\n");
    printf("    Status:     SECURE - Used in TLS 1.3\n");
    printf("    Advantage:  Constant-time, no cache-timing attacks\n");

    // ChaCha20 demonstration
    printf("\n  ChaCha20 Encryption Demo:\n");
    uint8_t cc_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t nonce[12] = {0x00, 0x00, 0x00, 0x09, 0x00, 0x00,
                         0x00, 0x4a, 0x00, 0x00, 0x00, 0x00};

    const char *message = "Hello, ChaCha20!";
    uint8_t encrypted[32];
    uint8_t decrypted_cc[32];

    chacha20_encrypt(cc_key, nonce, 1, (uint8_t*)message, encrypted, strlen(message));
    chacha20_encrypt(cc_key, nonce, 1, encrypted, decrypted_cc, strlen(message));

    printf("    Message:   %s\n", message);
    printf("    Encrypted: ");
    for (size_t i = 0; i < strlen(message); i++) printf("%02x", encrypted[i]);
    printf("\n    Decrypted: %s\n", decrypted_cc);

    // Algorithm comparison
    printf("\n\nAlgorithm Security Summary:\n");
    printf("  +------------+----------+-------------------+\n");
    printf("  | Algorithm  | Status   | Recommendation    |\n");
    printf("  +------------+----------+-------------------+\n");
    printf("  | DES        | BROKEN   | Never use         |\n");
    printf("  | 3DES       | WEAK     | Migrate to AES    |\n");
    printf("  | RC4        | BROKEN   | Never use         |\n");
    printf("  | AES-128    | SECURE   | Good for most use |\n");
    printf("  | AES-256    | SECURE   | High security     |\n");
    printf("  | ChaCha20   | SECURE   | Excellent choice  |\n");
    printf("  +------------+----------+-------------------+\n");

    // Security demonstration: why DES is broken
    printf("\n\nWhy DES is Broken:\n");
    printf("  Key space: 2^56 = 72 quadrillion keys\n");
    printf("  1999: EFF machine cracked in 22 hours\n");
    printf("  Today: Minutes with modern hardware\n");
    printf("  Lesson: 56 bits is far too small!\n");

    // Clean up sensitive data
    secure_zero(&ctx, sizeof(ctx));
    secure_zero(key, sizeof(key));
    secure_zero(cc_key, sizeof(cc_key));

    return 0;
}

// AES S-box (substitution box)
static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    // ... (full S-box implementation)
};

void aes_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = aes_sbox[state[i]];
    }
}

void aes_shift_rows(uint8_t state[16]) {
    // Row 0: no shift
    // Row 1: shift left by 1
    uint8_t temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // Row 2: shift left by 2
    uint8_t t0 = state[2], t1 = state[6];
    state[2] = state[10];
    state[6] = state[14];
    state[10] = t0;
    state[14] = t1;

    // Row 3: shift left by 3 (= right by 1)
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

// Galois field multiplication
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        bool hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) a ^= 0x1b;  // x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

void aes_mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t a[4];
        for (int i = 0; i < 4; i++) a[i] = state[c * 4 + i];

        state[c*4 + 0] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3];
        state[c*4 + 1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3];
        state[c*4 + 2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3);
        state[c*4 + 3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2);
    }
}

void aes_add_round_key(uint8_t state[16], const uint8_t *round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}
```

---

## Fichiers

```
ex00/
├── crypto_fundamentals.h
├── aes.c
├── chacha20.c
├── algorithms.c
└── Makefile
```
