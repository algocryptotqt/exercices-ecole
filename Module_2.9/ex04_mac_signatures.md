# ex04: Message Authentication & Digital Signatures

**Module**: 2.9 - Computer Security
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.9.9: Message Authentication (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | MAC | Message Authentication Code |
| b | HMAC | Hash-based MAC |
| c | HMAC construction | H(K XOR opad, H(K XOR ipad, m)) |
| d | CMAC | Cipher-based MAC |
| e | Poly1305 | Fast MAC |
| f | Authenticate-then-encrypt | Order matters |
| g | Encrypt-then-MAC | Recommended |

### 2.9.10: Digital Signatures (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Purpose | Authentication, non-repudiation |
| b | Sign with private | Only owner can sign |
| c | Verify with public | Anyone can verify |
| d | RSA signatures | c = H(m)^d mod n |
| e | DSA | Digital Signature Algorithm |
| f | ECDSA | Elliptic curve DSA |
| g | Ed25519 | EdDSA with Curve25519 |
| h | Hash-then-sign | Sign hash of message |

---

## Sujet

Implementer les codes d'authentification de message et les signatures numeriques.

### Structures

```c
// HMAC context
typedef struct {
    hash_context_t inner;
    hash_context_t outer;
    uint8_t key_pad[128];
    hash_algorithm_t algo;
} hmac_context_t;

// CMAC context
typedef struct {
    uint8_t key[16];
    uint8_t k1[16];
    uint8_t k2[16];
    uint8_t state[16];
} cmac_context_t;

// Poly1305 context
typedef struct {
    uint32_t r[5];       // Clamped key
    uint32_t h[5];       // Accumulator
    uint32_t s[4];       // Secret key
} poly1305_context_t;

// Digital signature
typedef struct {
    uint8_t data[512];   // Max 4096-bit RSA
    size_t length;
    char algorithm[16];
} signature_t;
```

### API

```c
// HMAC
void hmac_init(hmac_context_t *ctx, hash_algorithm_t algo,
               const uint8_t *key, size_t key_len);
void hmac_update(hmac_context_t *ctx, const uint8_t *data, size_t len);
void hmac_final(hmac_context_t *ctx, uint8_t *mac);
void hmac(hash_algorithm_t algo, const uint8_t *key, size_t key_len,
          const uint8_t *data, size_t data_len, uint8_t *mac);

// CMAC (AES-based)
void cmac_init(cmac_context_t *ctx, const uint8_t key[16]);
void cmac_update(cmac_context_t *ctx, const uint8_t *data, size_t len);
void cmac_final(cmac_context_t *ctx, uint8_t mac[16]);

// Poly1305
void poly1305(uint8_t mac[16], const uint8_t *msg, size_t len,
              const uint8_t key[32]);

// RSA signatures
bool rsa_sign_pkcs1(signature_t *sig, const uint8_t *hash, size_t hash_len,
                    const rsa_keypair_t *priv);
bool rsa_verify_pkcs1(const signature_t *sig, const uint8_t *hash, size_t hash_len,
                      const rsa_keypair_t *pub);
bool rsa_sign_pss(signature_t *sig, const uint8_t *hash, size_t hash_len,
                  const rsa_keypair_t *priv);
bool rsa_verify_pss(const signature_t *sig, const uint8_t *hash, size_t hash_len,
                    const rsa_keypair_t *pub);

// Ed25519
void ed25519_sign(uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                  const uint8_t priv[32]);
bool ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                    const uint8_t pub[32]);
```

---

## Exemple

```c
#include "mac_signatures.h"

int main(void) {
    // 2.9.9: Message Authentication
    printf("=== Message Authentication Codes (MAC) ===\n\n");

    // MAC concept
    printf("What is a MAC?\n");
    printf("  MAC = keyed hash function\n");
    printf("  tag = MAC(key, message)\n");
    printf("  Only someone with key can compute/verify MAC\n");
    printf("\n  Provides:\n");
    printf("    - Integrity: Message not modified\n");
    printf("    - Authentication: From someone with the key\n");
    printf("  Does NOT provide:\n");
    printf("    - Confidentiality (message is NOT encrypted)\n");
    printf("    - Non-repudiation (receiver also has key)\n");

    // HMAC
    printf("\n\nHMAC (Hash-based MAC, RFC 2104):\n");
    printf("  Most widely used MAC construction\n");
    printf("\n  Construction:\n");
    printf("    HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))\n");
    printf("    where:\n");
    printf("      K' = K if |K| <= block_size, else H(K)\n");
    printf("      ipad = 0x36 repeated block_size times\n");
    printf("      opad = 0x5c repeated block_size times\n");

    printf("\n  Step by step:\n");
    printf("    1. If key > block size, hash it: K' = H(K)\n");
    printf("    2. Pad key to block size\n");
    printf("    3. Inner hash: inner = H((K' XOR ipad) || message)\n");
    printf("    4. Outer hash: MAC = H((K' XOR opad) || inner)\n");

    // HMAC demonstration
    uint8_t hmac_key[] = "secret key";
    const char *message = "Hello, World!";
    uint8_t mac[32];

    hmac(HASH_SHA256, hmac_key, strlen((char*)hmac_key),
         (uint8_t*)message, strlen(message), mac);

    printf("\n  HMAC-SHA256 Demo:\n");
    printf("    Key:     '%s'\n", hmac_key);
    printf("    Message: '%s'\n", message);
    printf("    MAC:     ");
    for (int i = 0; i < 32; i++) printf("%02x", mac[i]);
    printf("\n");

    // Verify MAC
    uint8_t verify_mac[32];
    hmac(HASH_SHA256, hmac_key, strlen((char*)hmac_key),
         (uint8_t*)message, strlen(message), verify_mac);
    printf("    Verify:  %s\n", memcmp(mac, verify_mac, 32) == 0 ? "VALID" : "INVALID");

    // Tampered message
    hmac(HASH_SHA256, hmac_key, strlen((char*)hmac_key),
         (uint8_t*)"Hello, World?", 13, verify_mac);
    printf("    Tampered: %s\n", memcmp(mac, verify_mac, 32) == 0 ? "VALID" : "INVALID (correct!)");

    // CMAC
    printf("\n\nCMAC (Cipher-based MAC, NIST SP 800-38B):\n");
    printf("  Uses block cipher (AES) instead of hash\n");
    printf("  Also called AES-CMAC or OMAC1\n");
    printf("\n  Construction:\n");
    printf("    1. Derive subkeys K1, K2 from K\n");
    printf("    2. Process message in blocks with CBC\n");
    printf("    3. XOR last block with K1 or K2\n");
    printf("    4. Final block cipher output is MAC\n");
    printf("\n  Advantage: Uses AES, often has hardware support\n");

    uint8_t cmac_key[16] = {0};
    uint8_t cmac_out[16];
    cmac_context_t cmac_ctx;
    cmac_init(&cmac_ctx, cmac_key);
    cmac_update(&cmac_ctx, (uint8_t*)message, strlen(message));
    cmac_final(&cmac_ctx, cmac_out);

    printf("\n  AES-CMAC Demo:\n");
    printf("    MAC: ");
    for (int i = 0; i < 16; i++) printf("%02x", cmac_out[i]);
    printf("\n");

    // Poly1305
    printf("\n\nPoly1305:\n");
    printf("  Designed by Daniel Bernstein (2005)\n");
    printf("  Very fast, one-time authenticator\n");
    printf("  Used with ChaCha20 in ChaCha20-Poly1305 AEAD\n");
    printf("\n  Properties:\n");
    printf("    - 256-bit key (128-bit r, 128-bit s)\n");
    printf("    - 128-bit output tag\n");
    printf("    - Key MUST be unique per message (one-time)\n");
    printf("    - Constant-time implementation\n");
    printf("\n  Math: tag = ((message as polynomial) * r mod 2^130-5) + s\n");

    uint8_t poly_key[32] = {0};
    uint8_t poly_mac[16];
    poly1305(poly_mac, (uint8_t*)message, strlen(message), poly_key);

    printf("\n  Poly1305 Demo:\n");
    printf("    MAC: ");
    for (int i = 0; i < 16; i++) printf("%02x", poly_mac[i]);
    printf("\n");

    // Encrypt-then-MAC vs MAC-then-Encrypt
    printf("\n\nMAC + Encryption Ordering:\n");
    printf("\n  MAC-then-Encrypt (MtE):\n");
    printf("    tag = MAC(K_mac, plaintext)\n");
    printf("    ciphertext = Encrypt(K_enc, plaintext || tag)\n");
    printf("    Problem: Must decrypt to verify MAC (oracle attacks)\n");

    printf("\n  Encrypt-then-MAC (EtM) - RECOMMENDED:\n");
    printf("    ciphertext = Encrypt(K_enc, plaintext)\n");
    printf("    tag = MAC(K_mac, ciphertext)\n");
    printf("    Advantages:\n");
    printf("      - Can verify MAC before decryption\n");
    printf("      - Protects against chosen-ciphertext attacks\n");
    printf("      - Provably secure\n");

    printf("\n  Encrypt-and-MAC (E&M):\n");
    printf("    ciphertext = Encrypt(K_enc, plaintext)\n");
    printf("    tag = MAC(K_mac, plaintext)\n");
    printf("    Problem: MAC may leak plaintext info\n");

    printf("\n  Best practice: Use AEAD (GCM, ChaCha20-Poly1305)\n");
    printf("                 which handles this correctly!\n");

    // 2.9.10: Digital Signatures
    printf("\n\n=== Digital Signatures ===\n\n");

    // Digital signature concept
    printf("What is a Digital Signature?\n");
    printf("  Asymmetric authentication:\n");
    printf("    - Sign with private key (only owner can sign)\n");
    printf("    - Verify with public key (anyone can verify)\n");
    printf("\n  Provides:\n");
    printf("    - Integrity: Message not modified\n");
    printf("    - Authentication: From key owner\n");
    printf("    - Non-repudiation: Signer cannot deny signing\n");

    printf("\n  MAC vs Digital Signature:\n");
    printf("    +----------------+-------------+------------------+\n");
    printf("    | Property       | MAC         | Digital Sig      |\n");
    printf("    +----------------+-------------+------------------+\n");
    printf("    | Keys           | Shared key  | Public/Private   |\n");
    printf("    | Who can sign   | Anyone      | Only key owner   |\n");
    printf("    | Who can verify | With key    | Anyone           |\n");
    printf("    | Non-repudiation| No          | Yes              |\n");
    printf("    | Speed          | Fast        | Slow             |\n");
    printf("    +----------------+-------------+------------------+\n");

    // Hash-then-sign
    printf("\n\nHash-then-Sign Paradigm:\n");
    printf("  Signature = Sign(private_key, Hash(message))\n");
    printf("\n  Why hash first?\n");
    printf("    1. RSA can only encrypt data < modulus\n");
    printf("    2. Signing raw data is slow (big exponentiation)\n");
    printf("    3. Hash provides fixed-size input\n");
    printf("    4. Hash provides collision resistance\n");

    // RSA Signatures
    printf("\n\nRSA Signatures:\n");
    printf("  Sign:   sig = H(m)^d mod n\n");
    printf("  Verify: H(m) == sig^e mod n ?\n");

    printf("\n  PKCS#1 v1.5 (Legacy):\n");
    printf("    Padding: 0x00 0x01 [0xFF...0xFF] 0x00 [DigestInfo]\n");
    printf("    DigestInfo = algorithm OID + hash\n");
    printf("    Note: Vulnerable to Bleichenbacher-style attacks\n");

    printf("\n  RSA-PSS (Probabilistic Signature Scheme):\n");
    printf("    Random salt added before signing\n");
    printf("    Provably secure in random oracle model\n");
    printf("    RECOMMENDED for new applications\n");

    // RSA signature demonstration
    rsa_keypair_t rsa;
    rsa_generate_keypair(&rsa, 2048);

    uint8_t msg_hash[32];
    sha256((uint8_t*)"Important document", 18, msg_hash);

    signature_t sig;
    rsa_sign_pss(&sig, msg_hash, 32, &rsa);

    printf("\n  RSA-PSS Demo:\n");
    printf("    Message hash: ");
    for (int i = 0; i < 16; i++) printf("%02x", msg_hash[i]);
    printf("...\n");
    printf("    Signature: ");
    for (int i = 0; i < 16; i++) printf("%02x", sig.data[i]);
    printf("... (%zu bytes)\n", sig.length);

    bool valid = rsa_verify_pss(&sig, msg_hash, 32, &rsa);
    printf("    Verification: %s\n", valid ? "VALID" : "INVALID");

    // Tamper test
    msg_hash[0] ^= 0x01;
    bool tampered = rsa_verify_pss(&sig, msg_hash, 32, &rsa);
    printf("    After tampering: %s\n", tampered ? "VALID (bad!)" : "INVALID (correct!)");

    // DSA
    printf("\n\nDSA (Digital Signature Algorithm):\n");
    printf("  FIPS 186 (1994), based on discrete log\n");
    printf("  Similar to ElGamal signatures\n");
    printf("  Signature: (r, s) pair\n");
    printf("  Key sizes: 2048-bit p, 256-bit q\n");
    printf("  Status: Mostly superseded by ECDSA\n");

    // ECDSA
    printf("\n\nECDSA (Elliptic Curve DSA):\n");
    printf("  DSA on elliptic curves\n");
    printf("  Same security, much smaller keys\n");
    printf("  Widely used: Bitcoin, TLS, X.509\n");
    printf("\n  CRITICAL: Random k per signature!\n");
    printf("    If k reused: private key leaked!\n");
    printf("    Sony PS3 hack (2010): Same k for all signatures\n");
    printf("    Recovery: d = (s1 - s2)^(-1) * (z1 - z2) mod n\n");

    // Ed25519
    printf("\n\nEd25519 (EdDSA with Curve25519):\n");
    printf("  Modern signature scheme by Daniel Bernstein\n");
    printf("  Edwards curve: -x^2 + y^2 = 1 + dx^2y^2\n");
    printf("\n  Advantages over ECDSA:\n");
    printf("    - Deterministic: k derived from private key + message\n");
    printf("    - No random k = no nonce reuse vulnerability!\n");
    printf("    - Faster signature and verification\n");
    printf("    - Simpler implementation\n");
    printf("    - Constant-time by design\n");
    printf("\n  Signature: 64 bytes\n");
    printf("  Public key: 32 bytes\n");
    printf("  Private key: 32 bytes (seed)\n");

    // Ed25519 demonstration
    uint8_t ed_priv[32], ed_pub[32];
    // Generate keypair (in real impl, use secure random)
    for (int i = 0; i < 32; i++) ed_priv[i] = i;
    ed25519_public_key(ed_pub, ed_priv);

    uint8_t ed_sig[64];
    const char *ed_msg = "Sign this message";
    ed25519_sign(ed_sig, (uint8_t*)ed_msg, strlen(ed_msg), ed_priv);

    printf("\n  Ed25519 Demo:\n");
    printf("    Public key: ");
    for (int i = 0; i < 16; i++) printf("%02x", ed_pub[i]);
    printf("...\n");
    printf("    Signature: ");
    for (int i = 0; i < 32; i++) printf("%02x", ed_sig[i]);
    printf("...\n");

    bool ed_valid = ed25519_verify(ed_sig, (uint8_t*)ed_msg, strlen(ed_msg), ed_pub);
    printf("    Verification: %s\n", ed_valid ? "VALID" : "INVALID");

    // Algorithm comparison
    printf("\n\nSignature Algorithm Comparison:\n");
    printf("  +----------+----------+----------+---------+------------+\n");
    printf("  | Algorithm| Sig Size | Pub Key  | Speed   | Recommended|\n");
    printf("  +----------+----------+----------+---------+------------+\n");
    printf("  | RSA-2048 | 256 B    | 256 B    | Slow    | Legacy     |\n");
    printf("  | RSA-4096 | 512 B    | 512 B    | V.Slow  | High-sec   |\n");
    printf("  | ECDSA-256| 64 B     | 64 B     | Fast    | Good       |\n");
    printf("  | Ed25519  | 64 B     | 32 B     | V.Fast  | Best       |\n");
    printf("  +----------+----------+----------+---------+------------+\n");

    printf("\n  Recommendation:\n");
    printf("    New projects: Ed25519\n");
    printf("    Existing systems: ECDSA P-256\n");
    printf("    Legacy/compliance: RSA-PSS 2048+\n");

    return 0;
}
```

---

## Fichiers

```
ex04/
├── mac_signatures.h
├── hmac.c
├── cmac.c
├── poly1305.c
├── rsa_sig.c
├── ed25519.c
└── Makefile
```
