# ex03: Key Exchange & Hash Functions

**Module**: 2.9 - Computer Security
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.9.7: Key Exchange (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Problem | Share secret over public channel |
| b | Diffie-Hellman | Classic algorithm |
| c | DH math | g^a mod p, g^b mod p |
| d | Shared secret | g^(ab) mod p |
| e | MITM vulnerability | Without authentication |
| f | ECDH | Elliptic curve version |
| g | X25519 | ECDH with Curve25519 |
| h | Perfect forward secrecy | Ephemeral keys |

### 2.9.8: Hash Functions (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Hash properties | Deterministic, one-way, collision-resistant |
| b | Preimage resistance | Cannot find input from hash |
| c | Collision resistance | Cannot find two inputs with same hash |
| d | MD5 | 128-bit, broken |
| e | SHA-1 | 160-bit, deprecated |
| f | SHA-2 | SHA-256, SHA-384, SHA-512 |
| g | SHA-3 | Keccak-based |
| h | BLAKE2/3 | Modern, fast |
| i | Birthday attack | O(2^(n/2)) |

---

## Sujet

Implementer l'echange de cles Diffie-Hellman et les fonctions de hachage cryptographiques.

### Structures

```c
// Diffie-Hellman parameters
typedef struct {
    bigint_t p;          // Prime modulus
    bigint_t g;          // Generator
    int bits;            // Modulus size
} dh_params_t;

// DH key pair
typedef struct {
    bigint_t private_key;
    bigint_t public_key;
    const dh_params_t *params;
} dh_keypair_t;

// X25519 key pair
typedef struct {
    uint8_t private_key[32];
    uint8_t public_key[32];
} x25519_keypair_t;

// Hash context (generic)
typedef struct {
    uint8_t state[64];
    uint8_t buffer[128];
    size_t buffer_len;
    uint64_t total_len;
    int algorithm;       // HASH_MD5, HASH_SHA1, etc.
} hash_context_t;

// Hash algorithms
typedef enum {
    HASH_MD5,
    HASH_SHA1,
    HASH_SHA256,
    HASH_SHA384,
    HASH_SHA512,
    HASH_SHA3_256,
    HASH_BLAKE2B,
    HASH_BLAKE3
} hash_algorithm_t;
```

### API

```c
// Diffie-Hellman
dh_params_t *dh_generate_params(int bits);
dh_params_t *dh_get_rfc3526_group(int group_id);  // RFC 3526 groups
void dh_generate_keypair(dh_keypair_t *kp, const dh_params_t *params);
void dh_compute_shared(bigint_t *shared, const dh_keypair_t *my_key,
                       const bigint_t *peer_public);
bool dh_validate_public_key(const bigint_t *pub, const dh_params_t *params);

// X25519
void x25519_generate_keypair(x25519_keypair_t *kp);
void x25519_compute_shared(uint8_t shared[32], const uint8_t private_key[32],
                           const uint8_t peer_public[32]);

// Hash functions
void hash_init(hash_context_t *ctx, hash_algorithm_t algo);
void hash_update(hash_context_t *ctx, const uint8_t *data, size_t len);
void hash_final(hash_context_t *ctx, uint8_t *out);
void hash_oneshot(hash_algorithm_t algo, const uint8_t *data, size_t len, uint8_t *out);

// Specific hash functions
void md5(const uint8_t *data, size_t len, uint8_t out[16]);
void sha1(const uint8_t *data, size_t len, uint8_t out[20]);
void sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void sha512(const uint8_t *data, size_t len, uint8_t out[64]);
void sha3_256(const uint8_t *data, size_t len, uint8_t out[32]);
void blake2b(const uint8_t *data, size_t len, uint8_t *out, size_t out_len);
void blake3(const uint8_t *data, size_t len, uint8_t out[32]);

// Hash utilities
int hash_output_size(hash_algorithm_t algo);
const char *hash_name(hash_algorithm_t algo);
bool hash_is_secure(hash_algorithm_t algo);
```

---

## Exemple

```c
#include "key_exchange_hashing.h"

int main(void) {
    // 2.9.7: Key Exchange
    printf("=== Key Exchange ===\n\n");

    // The problem
    printf("The Key Distribution Problem:\n");
    printf("  Alice and Bob want to communicate securely\n");
    printf("  They need a shared secret key\n");
    printf("  But: Eve is listening to ALL their communication!\n");
    printf("\n  Question: How to agree on a secret over a public channel?\n");
    printf("  Answer: Diffie-Hellman (1976) - First public key system!\n");

    // Diffie-Hellman
    printf("\n\nDiffie-Hellman Key Exchange:\n");
    printf("  Public parameters: p (large prime), g (generator)\n");
    printf("\n  Protocol:\n");
    printf("    Alice                         Bob\n");
    printf("    -----                         ---\n");
    printf("    a = random private            b = random private\n");
    printf("    A = g^a mod p                 B = g^b mod p\n");
    printf("         -------- A -------->           \n");
    printf("         <------- B --------           \n");
    printf("    s = B^a mod p                 s = A^b mod p\n");
    printf("      = g^(ba) mod p                = g^(ab) mod p\n");
    printf("      = SAME shared secret!\n");

    // DH math example
    printf("\n  Small Example (DO NOT use small values in practice!):\n");
    printf("    p = 23, g = 5\n");
    printf("    Alice: a = 6, A = 5^6 mod 23 = 8\n");
    printf("    Bob:   b = 15, B = 5^15 mod 23 = 19\n");
    printf("    Alice: s = 19^6 mod 23 = 2\n");
    printf("    Bob:   s = 8^15 mod 23 = 2\n");
    printf("    Shared secret: 2\n");

    // DH demonstration
    printf("\n  Real DH Exchange (2048-bit):\n");
    dh_params_t *params = dh_get_rfc3526_group(14);  // RFC 3526 Group 14

    dh_keypair_t alice, bob;
    dh_generate_keypair(&alice, params);
    dh_generate_keypair(&bob, params);

    bigint_t alice_shared, bob_shared;
    dh_compute_shared(&alice_shared, &alice, &bob.public_key);
    dh_compute_shared(&bob_shared, &bob, &alice.public_key);

    char alice_hex[520], bob_hex[520];
    bigint_to_hex(&alice_shared, alice_hex, sizeof(alice_hex));
    bigint_to_hex(&bob_shared, bob_hex, sizeof(bob_hex));

    printf("    Alice shared (first 32 hex): %.32s...\n", alice_hex);
    printf("    Bob shared (first 32 hex):   %.32s...\n", bob_hex);
    printf("    Match: %s\n", strcmp(alice_hex, bob_hex) == 0 ? "YES" : "NO");

    // Security of DH
    printf("\n  DH Security:\n");
    printf("    Eve sees: p, g, A = g^a mod p, B = g^b mod p\n");
    printf("    To find s, Eve must compute a or b\n");
    printf("    This is the Discrete Logarithm Problem (DLP)\n");
    printf("    Best known: Number Field Sieve, sub-exponential\n");
    printf("    2048-bit: ~112 bits security (sufficient today)\n");

    // MITM Attack
    printf("\n  MITM (Man-in-the-Middle) Vulnerability:\n");
    printf("    Without authentication, Mallory can intercept!\n");
    printf("\n    Alice        Mallory         Bob\n");
    printf("      |             |              |\n");
    printf("      |---- A ---->|              |\n");
    printf("      |<--- M -----|              |\n");
    printf("      |             |---- M' ---->|\n");
    printf("      |             |<--- B ------|\n");
    printf("\n    Alice thinks she shares key with Bob\n");
    printf("    Bob thinks he shares key with Alice\n");
    printf("    Both actually share keys with Mallory!\n");
    printf("\n    Prevention: Authenticate public keys\n");
    printf("      - Digital signatures\n");
    printf("      - Certificates\n");
    printf("      - Pre-shared trust (SSH fingerprints)\n");

    // X25519
    printf("\n\nX25519 (ECDH with Curve25519):\n");
    printf("  Modern elliptic curve key exchange\n");
    printf("  256-bit keys, ~128-bit security\n");
    printf("  Much faster than DH with same security\n");

    x25519_keypair_t alice_x, bob_x;
    x25519_generate_keypair(&alice_x);
    x25519_generate_keypair(&bob_x);

    uint8_t alice_x_shared[32], bob_x_shared[32];
    x25519_compute_shared(alice_x_shared, alice_x.private_key, bob_x.public_key);
    x25519_compute_shared(bob_x_shared, bob_x.private_key, alice_x.public_key);

    printf("\n  X25519 Demo:\n");
    printf("    Alice public: ");
    for (int i = 0; i < 8; i++) printf("%02x", alice_x.public_key[i]);
    printf("...\n");
    printf("    Bob public:   ");
    for (int i = 0; i < 8; i++) printf("%02x", bob_x.public_key[i]);
    printf("...\n");
    printf("    Shared (Alice): ");
    for (int i = 0; i < 8; i++) printf("%02x", alice_x_shared[i]);
    printf("...\n");
    printf("    Shared (Bob):   ");
    for (int i = 0; i < 8; i++) printf("%02x", bob_x_shared[i]);
    printf("...\n");
    printf("    Match: %s\n", memcmp(alice_x_shared, bob_x_shared, 32) == 0 ? "YES" : "NO");

    // Perfect Forward Secrecy
    printf("\n\nPerfect Forward Secrecy (PFS):\n");
    printf("  Problem: If long-term private key is compromised,\n");
    printf("           can attacker decrypt past traffic?\n");
    printf("\n  Without PFS (static keys):\n");
    printf("    Yes! All past messages can be decrypted.\n");
    printf("\n  With PFS (ephemeral keys):\n");
    printf("    No! Each session uses NEW random keys.\n");
    printf("    Even if long-term key leaks, past sessions safe.\n");
    printf("\n  Implementation:\n");
    printf("    - Generate fresh DH/ECDH keypair per session\n");
    printf("    - Sign ephemeral public key with long-term key\n");
    printf("    - Delete ephemeral private key after use\n");
    printf("\n  TLS 1.3: PFS is MANDATORY (DHE or ECDHE only)\n");

    // 2.9.8: Hash Functions
    printf("\n\n=== Hash Functions ===\n\n");

    // Hash function concept
    printf("Cryptographic Hash Function:\n");
    printf("  Maps arbitrary-length input to fixed-length output\n");
    printf("  h = H(m)  where |h| is fixed (e.g., 256 bits)\n");

    // Hash properties
    printf("\n  Essential Properties:\n");
    printf("  1. Deterministic: Same input always gives same output\n");
    printf("  2. Fast: Quick to compute for any input\n");
    printf("  3. One-way (Preimage resistance):\n");
    printf("       Given h, hard to find any m where H(m) = h\n");
    printf("  4. Collision resistance:\n");
    printf("       Hard to find m1 != m2 where H(m1) = H(m2)\n");
    printf("  5. Avalanche effect:\n");
    printf("       Small input change = ~50%% output bits change\n");

    // Preimage resistance
    printf("\n  Preimage Resistance Levels:\n");
    printf("    First preimage: Given h, find m: H(m) = h\n");
    printf("    Second preimage: Given m1, find m2: H(m2) = H(m1)\n");
    printf("    For n-bit hash: ~2^n work required\n");

    // Collision resistance
    printf("\n  Collision Resistance:\n");
    printf("    Find ANY m1 != m2 where H(m1) = H(m2)\n");
    printf("    Birthday paradox: Only ~2^(n/2) work needed!\n");
    printf("    For 256-bit hash: 2^128 operations\n");
    printf("    For 128-bit hash: 2^64 operations (feasible!)\n");

    // MD5
    printf("\n\nMD5 (Message Digest 5, 1992):\n");
    printf("  Output: 128 bits (32 hex chars)\n");
    printf("  Status: BROKEN - DO NOT USE FOR SECURITY!\n");
    printf("  Attacks:\n");
    printf("    - 2004: Collision found (Wang et al.)\n");
    printf("    - 2008: Rogue CA certificate created\n");
    printf("    - Collision: seconds on laptop\n");
    printf("  Still OK for: Checksums (non-security), legacy\n");

    uint8_t md5_out[16];
    md5((uint8_t*)"Hello", 5, md5_out);
    printf("\n  MD5('Hello'): ");
    for (int i = 0; i < 16; i++) printf("%02x", md5_out[i]);
    printf("\n");

    // SHA-1
    printf("\n\nSHA-1 (Secure Hash Algorithm 1, 1995):\n");
    printf("  Output: 160 bits (40 hex chars)\n");
    printf("  Status: DEPRECATED - Collision found 2017!\n");
    printf("  Attacks:\n");
    printf("    - 2017: SHAttered (Google) - first collision\n");
    printf("    - 2020: Chosen-prefix collision\n");
    printf("  Don't use for: Signatures, certificates\n");

    uint8_t sha1_out[20];
    sha1((uint8_t*)"Hello", 5, sha1_out);
    printf("\n  SHA-1('Hello'): ");
    for (int i = 0; i < 20; i++) printf("%02x", sha1_out[i]);
    printf("\n");

    // SHA-2
    printf("\n\nSHA-2 Family (2001):\n");
    printf("  SHA-224: 224 bits (truncated SHA-256)\n");
    printf("  SHA-256: 256 bits - Most common\n");
    printf("  SHA-384: 384 bits (truncated SHA-512)\n");
    printf("  SHA-512: 512 bits - Fastest on 64-bit\n");
    printf("\n  Status: SECURE - No known weaknesses\n");
    printf("  Recommendation: SHA-256 for general use\n");

    uint8_t sha256_out[32];
    sha256((uint8_t*)"Hello", 5, sha256_out);
    printf("\n  SHA-256('Hello'): ");
    for (int i = 0; i < 32; i++) printf("%02x", sha256_out[i]);
    printf("\n");

    // Avalanche effect demonstration
    printf("\n  Avalanche Effect Demo:\n");
    uint8_t h1[32], h2[32];
    sha256((uint8_t*)"Hello", 5, h1);
    sha256((uint8_t*)"Hellp", 5, h2);  // One character different

    int bits_diff = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t xor = h1[i] ^ h2[i];
        while (xor) { bits_diff += xor & 1; xor >>= 1; }
    }

    printf("    'Hello': ");
    for (int i = 0; i < 8; i++) printf("%02x", h1[i]);
    printf("...\n");
    printf("    'Hellp': ");
    for (int i = 0; i < 8; i++) printf("%02x", h2[i]);
    printf("...\n");
    printf("    Bits different: %d/256 (~%.1f%%)\n", bits_diff, bits_diff * 100.0 / 256);

    // SHA-3
    printf("\n\nSHA-3 (Keccak, 2015):\n");
    printf("  Winner of NIST SHA-3 competition\n");
    printf("  Completely different design from SHA-2\n");
    printf("  Based on sponge construction\n");
    printf("  Output sizes: 224, 256, 384, 512 bits\n");
    printf("  Status: SECURE - Alternative to SHA-2\n");
    printf("  Note: Slower in software than SHA-2\n");

    uint8_t sha3_out[32];
    sha3_256((uint8_t*)"Hello", 5, sha3_out);
    printf("\n  SHA3-256('Hello'): ");
    for (int i = 0; i < 32; i++) printf("%02x", sha3_out[i]);
    printf("\n");

    // BLAKE2/BLAKE3
    printf("\n\nBLAKE2/BLAKE3:\n");
    printf("  BLAKE2 (2012): SHA-3 finalist, faster than MD5!\n");
    printf("    BLAKE2b: 512 bits, 64-bit optimized\n");
    printf("    BLAKE2s: 256 bits, 32-bit optimized\n");
    printf("  BLAKE3 (2020): Parallelizable, even faster\n");
    printf("    Based on BLAKE2 + Merkle tree\n");
    printf("    Fixed 256-bit output, extendable\n");
    printf("  Status: SECURE - Recommended for new projects\n");

    uint8_t blake2_out[32];
    blake2b((uint8_t*)"Hello", 5, blake2_out, 32);
    printf("\n  BLAKE2b('Hello'): ");
    for (int i = 0; i < 32; i++) printf("%02x", blake2_out[i]);
    printf("\n");

    uint8_t blake3_out[32];
    blake3((uint8_t*)"Hello", 5, blake3_out);
    printf("\n  BLAKE3('Hello'): ");
    for (int i = 0; i < 32; i++) printf("%02x", blake3_out[i]);
    printf("\n");

    // Birthday attack
    printf("\n\nBirthday Attack:\n");
    printf("  Birthday paradox: 23 people, >50%% same birthday\n");
    printf("  Applied to hashes:\n");
    printf("    n-bit hash: ~2^(n/2) hashes for 50%% collision\n");
    printf("\n  Security implications:\n");
    printf("    128-bit hash: 2^64 work (feasible)\n");
    printf("    160-bit hash: 2^80 work (borderline)\n");
    printf("    256-bit hash: 2^128 work (secure)\n");
    printf("\n  Rule: For X-bit security, need 2X-bit hash\n");

    // Algorithm comparison
    printf("\n\nHash Algorithm Comparison:\n");
    printf("  +----------+------+-----------+------------------+\n");
    printf("  | Algorithm| Bits | Status    | Recommendation   |\n");
    printf("  +----------+------+-----------+------------------+\n");
    printf("  | MD5      | 128  | BROKEN    | Never use        |\n");
    printf("  | SHA-1    | 160  | BROKEN    | Never use        |\n");
    printf("  | SHA-256  | 256  | Secure    | Standard choice  |\n");
    printf("  | SHA-512  | 512  | Secure    | High security    |\n");
    printf("  | SHA3-256 | 256  | Secure    | Alternative      |\n");
    printf("  | BLAKE2b  | 512  | Secure    | Speed + security |\n");
    printf("  | BLAKE3   | 256  | Secure    | Fastest secure   |\n");
    printf("  +----------+------+-----------+------------------+\n");

    printf("\n  Use cases:\n");
    printf("    File integrity: SHA-256, BLAKE3\n");
    printf("    Password hashing: Use Argon2/bcrypt (NOT raw SHA!)\n");
    printf("    Digital signatures: SHA-256, SHA-384\n");
    printf("    Checksums (non-security): Even MD5 is fine\n");

    return 0;
}
```

---

## Fichiers

```
ex03/
├── key_exchange_hashing.h
├── diffie_hellman.c
├── x25519.c
├── md5.c
├── sha1.c
├── sha256.c
├── sha3.c
├── blake.c
└── Makefile
```
