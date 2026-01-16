# ex01: Block Cipher Modes & Authenticated Encryption

**Module**: 2.9 - Computer Security
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.9.3: Block Cipher Modes (11 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | ECB | Electronic Codebook (weak) |
| b | ECB penguin | Visible patterns |
| c | CBC | Cipher Block Chaining |
| d | CBC IV | Initialization Vector |
| e | CBC chaining | XOR with previous |
| f | CFB | Cipher Feedback |
| g | OFB | Output Feedback |
| h | CTR | Counter mode |
| i | CTR parallelizable | Independent blocks |
| j | Padding | PKCS#7 |
| k | Padding oracle | Attack |

### 2.9.4: Authenticated Encryption (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | AEAD | Authenticated Encryption with Associated Data |
| b | GCM | Galois/Counter Mode |
| c | GCM authentication | GHASH |
| d | CCM | Counter with CBC-MAC |
| e | ChaCha20-Poly1305 | Modern AEAD |
| f | Tag | Authentication tag |
| g | Associated data | Authenticated but not encrypted |

---

## Sujet

Implementer et comparer les modes de chiffrement par blocs et l'encryption authentifiee.

### Structures

```c
// Block cipher mode
typedef enum {
    MODE_ECB,
    MODE_CBC,
    MODE_CFB,
    MODE_OFB,
    MODE_CTR,
    MODE_GCM
} cipher_mode_t;

// AEAD context
typedef struct {
    uint8_t key[32];
    uint8_t nonce[16];
    cipher_mode_t mode;
    size_t tag_len;
} aead_context_t;

// Encryption result with tag
typedef struct {
    uint8_t *ciphertext;
    size_t ct_len;
    uint8_t tag[16];
    bool authenticated;
} aead_result_t;

// Padding info
typedef struct {
    uint8_t *padded_data;
    size_t padded_len;
    int padding_bytes;
} padding_result_t;
```

### API

```c
// Block cipher modes
void ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out, size_t len);
void ecb_decrypt(const uint8_t *key, const uint8_t *in, uint8_t *out, size_t len);

void cbc_encrypt(const uint8_t *key, const uint8_t *iv,
                 const uint8_t *in, uint8_t *out, size_t len);
void cbc_decrypt(const uint8_t *key, const uint8_t *iv,
                 const uint8_t *in, uint8_t *out, size_t len);

void ctr_encrypt(const uint8_t *key, const uint8_t *nonce,
                 const uint8_t *in, uint8_t *out, size_t len);

// Padding
padding_result_t pkcs7_pad(const uint8_t *data, size_t len, int block_size);
int pkcs7_unpad(uint8_t *data, size_t len, int block_size);
bool pkcs7_validate(const uint8_t *data, size_t len, int block_size);

// AEAD
aead_result_t gcm_encrypt(const uint8_t *key, const uint8_t *nonce,
                          const uint8_t *plaintext, size_t pt_len,
                          const uint8_t *aad, size_t aad_len);
bool gcm_decrypt(const uint8_t *key, const uint8_t *nonce,
                 const uint8_t *ciphertext, size_t ct_len,
                 const uint8_t *aad, size_t aad_len,
                 const uint8_t *tag, uint8_t *plaintext);

aead_result_t chacha20_poly1305_encrypt(const uint8_t *key, const uint8_t *nonce,
                                         const uint8_t *pt, size_t pt_len,
                                         const uint8_t *aad, size_t aad_len);
```

---

## Exemple

```c
#include "block_modes_aead.h"

int main(void) {
    // 2.9.3: Block Cipher Modes
    printf("=== Block Cipher Modes ===\n\n");

    // ECB Mode - The Insecure Mode
    printf("ECB (Electronic Codebook) Mode:\n");
    printf("  Operation: Each block encrypted independently\n");
    printf("  C[i] = E(K, P[i])\n");
    printf("\n  CRITICAL WEAKNESS: Identical plaintext = identical ciphertext!\n");

    // ECB Penguin demonstration
    printf("\n  'ECB Penguin' Problem:\n");
    printf("  Original Image:       ECB Encrypted:\n");
    printf("  +-------------+      +-------------+\n");
    printf("  |   ^   ^     |      |   ^   ^     |\n");
    printf("  |  (o   o)    |  ->  |  (x   x)    |\n");
    printf("  |    <=>      |      |    <=>      | <- Patterns visible!\n");
    printf("  |   \\___/     |      |   \\___/     |\n");
    printf("  +-------------+      +-------------+\n");
    printf("  Structure leaks through because same colors = same ciphertext\n");

    // ECB vs CBC demonstration
    uint8_t key[16] = {0};
    uint8_t repeated_data[32];
    memset(repeated_data, 'A', 32);  // Two identical blocks

    uint8_t ecb_out[32], cbc_out[32];
    uint8_t iv[16] = {0};

    ecb_encrypt(key, repeated_data, ecb_out, 32);
    cbc_encrypt(key, iv, repeated_data, cbc_out, 32);

    printf("\n  Repeating plaintext (32 'A's):\n");
    printf("  ECB block 1: ");
    for (int i = 0; i < 16; i++) printf("%02x", ecb_out[i]);
    printf("\n  ECB block 2: ");
    for (int i = 16; i < 32; i++) printf("%02x", ecb_out[i]);
    printf("\n  IDENTICAL! Patterns leak.\n");

    printf("\n  CBC block 1: ");
    for (int i = 0; i < 16; i++) printf("%02x", cbc_out[i]);
    printf("\n  CBC block 2: ");
    for (int i = 16; i < 32; i++) printf("%02x", cbc_out[i]);
    printf("\n  Different! Chaining hides patterns.\n");

    // CBC Mode
    printf("\n\nCBC (Cipher Block Chaining) Mode:\n");
    printf("  Encryption:\n");
    printf("    C[0] = E(K, P[0] XOR IV)\n");
    printf("    C[i] = E(K, P[i] XOR C[i-1])\n");
    printf("  Decryption:\n");
    printf("    P[0] = D(K, C[0]) XOR IV\n");
    printf("    P[i] = D(K, C[i]) XOR C[i-1]\n");
    printf("\n  IV (Initialization Vector) requirements:\n");
    printf("    - Random and unpredictable\n");
    printf("    - Must be unique per message\n");
    printf("    - Can be sent in clear with ciphertext\n");
    printf("\n  Advantages:\n");
    printf("    + Patterns hidden via chaining\n");
    printf("    + Widely supported\n");
    printf("  Disadvantages:\n");
    printf("    - Not parallelizable (encryption)\n");
    printf("    - Error propagation (2 blocks)\n");
    printf("    - Requires padding\n");

    // CFB and OFB
    printf("\n\nCFB (Cipher Feedback) Mode:\n");
    printf("  Turns block cipher into stream cipher\n");
    printf("  C[i] = P[i] XOR E(K, C[i-1])\n");
    printf("  No padding needed (encrypts partial blocks)\n");

    printf("\nOFB (Output Feedback) Mode:\n");
    printf("  O[i] = E(K, O[i-1])    ; Keystream\n");
    printf("  C[i] = P[i] XOR O[i]\n");
    printf("  Advantage: Keystream precomputable\n");
    printf("  Danger: Same IV = same keystream = disaster!\n");

    // CTR Mode
    printf("\n\nCTR (Counter) Mode:\n");
    printf("  Keystream: K[i] = E(K, Nonce || Counter+i)\n");
    printf("  Ciphertext: C[i] = P[i] XOR K[i]\n");
    printf("\n  Massive advantages:\n");
    printf("    + Fully parallelizable (encrypt & decrypt)\n");
    printf("    + Random access to any block\n");
    printf("    + No padding needed\n");
    printf("    + Simpler than CBC\n");
    printf("\n  Nonce/Counter format (96-bit nonce + 32-bit counter):\n");
    printf("    +----------------------------------+------------+\n");
    printf("    |        Nonce (96 bits)           | Counter    |\n");
    printf("    +----------------------------------+------------+\n");
    printf("    CRITICAL: Never reuse nonce with same key!\n");

    // CTR demonstration
    printf("\n  CTR Mode Demo:\n");
    uint8_t nonce[12] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                         0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    const char *message = "CTR mode allows random access!";
    uint8_t ctr_out[64];

    ctr_encrypt(key, nonce, (uint8_t*)message, ctr_out, strlen(message));
    printf("  Message: %s\n", message);
    printf("  CTR encrypted: ");
    for (size_t i = 0; i < strlen(message); i++) printf("%02x", ctr_out[i]);
    printf("\n");

    // Padding (PKCS#7)
    printf("\n\nPKCS#7 Padding:\n");
    printf("  Block size: 16 bytes for AES\n");
    printf("  Pad with N bytes of value N\n");
    printf("\n  Examples (showing last block):\n");
    printf("  15 bytes data: XX XX XX XX XX XX XX XX XX XX XX XX XX XX XX 01\n");
    printf("  14 bytes data: XX XX XX XX XX XX XX XX XX XX XX XX XX XX 02 02\n");
    printf("  13 bytes data: XX XX XX XX XX XX XX XX XX XX XX XX XX 03 03 03\n");
    printf("  16 bytes data: XX...XX 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10\n");
    printf("                 (16 bytes of 0x10 = full padding block)\n");

    // Padding demonstration
    uint8_t data[] = "Hello!";  // 6 bytes
    padding_result_t padded = pkcs7_pad(data, 6, 16);
    printf("\n  Padding 'Hello!' (6 bytes):\n");
    printf("  Original: ");
    for (int i = 0; i < 6; i++) printf("%02x ", data[i]);
    printf("\n  Padded:   ");
    for (size_t i = 0; i < padded.padded_len; i++)
        printf("%02x ", padded.padded_data[i]);
    printf("\n  Padding bytes: %d (value 0x%02x)\n",
           padded.padding_bytes, padded.padding_bytes);

    // Padding Oracle Attack
    printf("\n  Padding Oracle Attack:\n");
    printf("  Vulnerability: Server reveals if padding is valid\n");
    printf("  Attack: Decrypt ciphertext byte-by-byte!\n");
    printf("  1. Modify last byte of C[i-1]\n");
    printf("  2. Server checks padding after decrypt\n");
    printf("  3. 'Invalid padding' = guess was wrong\n");
    printf("  4. Try all 256 values until valid\n");
    printf("  5. Recover plaintext byte\n");
    printf("  Prevention: Use AEAD (GCM, ChaCha20-Poly1305)\n");

    // 2.9.4: Authenticated Encryption
    printf("\n\n=== Authenticated Encryption ===\n\n");

    printf("Problem with encryption alone:\n");
    printf("  Encryption provides CONFIDENTIALITY only\n");
    printf("  Attacker can MODIFY ciphertext without detection!\n");
    printf("  Example: Bit flip in CTR mode flips plaintext bit\n");

    printf("\nAEAD (Authenticated Encryption with Associated Data):\n");
    printf("  Provides: Confidentiality + Integrity + Authenticity\n");
    printf("  Output: Ciphertext + Authentication Tag\n");
    printf("  Associated Data: Authenticated but NOT encrypted\n");
    printf("    Example: Packet headers, database row IDs\n");

    // GCM Mode
    printf("\n\nGCM (Galois/Counter Mode):\n");
    printf("  Combines CTR encryption + GHASH authentication\n");
    printf("  Structure:\n");
    printf("    1. CTR mode for encryption\n");
    printf("    2. GHASH over AAD and ciphertext\n");
    printf("    3. Tag = GHASH result XOR E(K, Counter_0)\n");
    printf("\n  GHASH: Polynomial multiplication in GF(2^128)\n");
    printf("    H = E(K, 0^128)  ; Hash key\n");
    printf("    For each block: state = (state XOR block) * H\n");

    printf("\n  GCM Advantages:\n");
    printf("    + Parallelizable (like CTR)\n");
    printf("    + Single pass for auth + encryption\n");
    printf("    + Widely implemented in hardware (AES-NI)\n");
    printf("  Requirements:\n");
    printf("    - 96-bit nonce (recommended)\n");
    printf("    - NEVER reuse nonce! (catastrophic)\n");

    // GCM demonstration
    printf("\n  GCM Encryption Demo:\n");
    uint8_t gcm_key[16] = {0};
    uint8_t gcm_nonce[12] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                             0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    const char *plaintext = "Secret message!";
    const char *aad = "Header data (not encrypted)";

    aead_result_t result = gcm_encrypt(gcm_key, gcm_nonce,
                                       (uint8_t*)plaintext, strlen(plaintext),
                                       (uint8_t*)aad, strlen(aad));

    printf("  Plaintext: %s\n", plaintext);
    printf("  AAD: %s\n", aad);
    printf("  Ciphertext: ");
    for (size_t i = 0; i < result.ct_len; i++) printf("%02x", result.ciphertext[i]);
    printf("\n  Auth Tag: ");
    for (int i = 0; i < 16; i++) printf("%02x", result.tag[i]);
    printf("\n");

    // Verify decryption
    uint8_t decrypted[64];
    bool valid = gcm_decrypt(gcm_key, gcm_nonce,
                            result.ciphertext, result.ct_len,
                            (uint8_t*)aad, strlen(aad),
                            result.tag, decrypted);
    printf("  Verification: %s\n", valid ? "SUCCESS" : "FAILED");

    // Tampering detection
    result.ciphertext[0] ^= 0x01;  // Flip one bit
    bool tampered = gcm_decrypt(gcm_key, gcm_nonce,
                               result.ciphertext, result.ct_len,
                               (uint8_t*)aad, strlen(aad),
                               result.tag, decrypted);
    printf("  After tampering: %s\n", tampered ? "ERROR!" : "REJECTED (correct!)");

    // CCM Mode
    printf("\n\nCCM (Counter with CBC-MAC):\n");
    printf("  Combines CTR encryption + CBC-MAC authentication\n");
    printf("  Two passes required (unlike GCM)\n");
    printf("  Used in: WPA2 (WiFi), Bluetooth, ZigBee\n");

    // ChaCha20-Poly1305
    printf("\n\nChaCha20-Poly1305:\n");
    printf("  Modern AEAD designed by Daniel Bernstein\n");
    printf("  ChaCha20: Stream cipher (256-bit key)\n");
    printf("  Poly1305: One-time MAC\n");
    printf("\n  Advantages over AES-GCM:\n");
    printf("    + No timing side-channels (constant-time)\n");
    printf("    + Fast in software (no AES-NI needed)\n");
    printf("    + Simpler implementation\n");
    printf("  Used in: TLS 1.3, WireGuard, SSH\n");

    // ChaCha20-Poly1305 demo
    printf("\n  ChaCha20-Poly1305 Demo:\n");
    uint8_t cc_key[32] = {0};
    uint8_t cc_nonce[12] = {0};

    aead_result_t cc_result = chacha20_poly1305_encrypt(
        cc_key, cc_nonce,
        (uint8_t*)"Modern AEAD!", 12,
        (uint8_t*)"AAD", 3);

    printf("  Ciphertext: ");
    for (size_t i = 0; i < cc_result.ct_len; i++) printf("%02x", cc_result.ciphertext[i]);
    printf("\n  Tag: ");
    for (int i = 0; i < 16; i++) printf("%02x", cc_result.tag[i]);
    printf("\n");

    // Mode comparison
    printf("\n\nMode Comparison Summary:\n");
    printf("  +------------------+------+------+------+------+\n");
    printf("  | Mode             | Conf | Auth | Para | Rec  |\n");
    printf("  +------------------+------+------+------+------+\n");
    printf("  | ECB              | Yes  | No   | Yes  | NO!  |\n");
    printf("  | CBC              | Yes  | No   | No   | OK   |\n");
    printf("  | CTR              | Yes  | No   | Yes  | OK   |\n");
    printf("  | GCM              | Yes  | Yes  | Yes  | YES  |\n");
    printf("  | ChaCha20-Poly1305| Yes  | Yes  | Yes  | YES  |\n");
    printf("  +------------------+------+------+------+------+\n");
    printf("  Conf=Confidentiality, Auth=Authentication\n");
    printf("  Para=Parallelizable, Rec=Recommended\n");

    printf("\n  RULE: Always use AEAD (GCM or ChaCha20-Poly1305)\n");
    printf("        Unless you have a very specific reason not to.\n");

    return 0;
}
```

---

## Fichiers

```
ex01/
├── block_modes_aead.h
├── modes.c
├── gcm.c
├── chacha20_poly1305.c
├── padding.c
└── Makefile
```
