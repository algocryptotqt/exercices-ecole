# ex05: Password Hashing & Implementing Crypto

**Module**: 2.9 - Computer Security
**Difficulte**: Difficile
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.9.11: Password Hashing (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Don't use SHA | Too fast |
| b | Salt | Random per-password value |
| c | bcrypt | Blowfish-based, adaptive |
| d | scrypt | Memory-hard |
| e | Argon2 | Modern winner |
| f | Argon2id | Hybrid variant |
| g | Work factor | Iteration count |
| h | Pepper | Server-side secret |

### 2.9.12: Implementing Crypto from Scratch (6 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | AES | Full implementation |
| b | SHA-256 | Full implementation |
| c | HMAC-SHA256 | Using SHA-256 |
| d | RSA | Key gen, encrypt, decrypt |
| e | Test vectors | NIST test cases |
| f | Warning | Educational only |

---

## Sujet

Comprendre le hachage de mots de passe et implementer des algorithmes cryptographiques.

### Structures

```c
// Password hash parameters
typedef struct {
    int time_cost;       // Iterations
    int memory_cost;     // Memory in KB
    int parallelism;     // Threads
    int hash_len;        // Output length
    int salt_len;        // Salt length
} password_params_t;

// Password hash result
typedef struct {
    uint8_t hash[64];
    uint8_t salt[32];
    char algorithm[16];
    password_params_t params;
    char encoded[256];   // PHC string format
} password_hash_t;

// AES round state
typedef struct {
    uint8_t state[4][4];
} aes_state_t;

// SHA-256 internal state
typedef struct {
    uint32_t h[8];       // Hash state
    uint8_t block[64];   // Current block
    size_t block_len;
    uint64_t total_len;
} sha256_state_t;
```

### API

```c
// Password hashing
bool password_hash_bcrypt(const char *password, password_hash_t *result, int cost);
bool password_hash_scrypt(const char *password, password_hash_t *result,
                          int N, int r, int p);
bool password_hash_argon2id(const char *password, password_hash_t *result,
                            const password_params_t *params);
bool password_verify(const char *password, const password_hash_t *hash);

// PHC string format
char *password_encode(const password_hash_t *hash);
bool password_decode(const char *encoded, password_hash_t *hash);

// AES implementation (educational)
void aes_impl_sub_bytes(aes_state_t *state);
void aes_impl_inv_sub_bytes(aes_state_t *state);
void aes_impl_shift_rows(aes_state_t *state);
void aes_impl_inv_shift_rows(aes_state_t *state);
void aes_impl_mix_columns(aes_state_t *state);
void aes_impl_inv_mix_columns(aes_state_t *state);
void aes_impl_add_round_key(aes_state_t *state, const uint8_t *rk);
void aes_impl_key_expansion(const uint8_t *key, uint8_t *w, int nk, int nr);
void aes_impl_encrypt(const uint8_t *key, const uint8_t in[16], uint8_t out[16]);
void aes_impl_decrypt(const uint8_t *key, const uint8_t in[16], uint8_t out[16]);

// SHA-256 implementation (educational)
void sha256_impl_init(sha256_state_t *state);
void sha256_impl_transform(sha256_state_t *state, const uint8_t block[64]);
void sha256_impl_update(sha256_state_t *state, const uint8_t *data, size_t len);
void sha256_impl_final(sha256_state_t *state, uint8_t hash[32]);

// Test vectors
bool test_aes_nist_vectors(void);
bool test_sha256_nist_vectors(void);
bool test_hmac_rfc_vectors(void);
```

---

## Exemple

```c
#include "password_crypto_impl.h"

int main(void) {
    // 2.9.11: Password Hashing
    printf("=== Password Hashing ===\n\n");

    // Why not SHA?
    printf("Why NOT use SHA-256 for passwords?\n");
    printf("  SHA-256 is FAST by design!\n");
    printf("    Modern GPU: ~10 billion SHA-256/sec\n");
    printf("    8-char password (lowercase): 26^8 = 208 billion\n");
    printf("    Crack time: ~20 seconds!\n");
    printf("\n  Attackers use:\n");
    printf("    - GPU clusters (massive parallelism)\n");
    printf("    - Rainbow tables (precomputed hashes)\n");
    printf("    - Dictionary attacks (common passwords)\n");
    printf("\n  Solution: Password-specific hash functions\n");
    printf("    - Intentionally SLOW\n");
    printf("    - Memory-intensive (defeats GPU)\n");
    printf("    - Salted (defeats rainbow tables)\n");

    // Salt
    printf("\n\nSalt:\n");
    printf("  Random value stored with hash\n");
    printf("  hash = H(password || salt)\n");
    printf("\n  Benefits:\n");
    printf("    - Same password = different hash (per user)\n");
    printf("    - Defeats rainbow tables\n");
    printf("    - Must crack each password individually\n");
    printf("\n  Requirements:\n");
    printf("    - Random (cryptographically secure)\n");
    printf("    - Unique per password\n");
    printf("    - At least 16 bytes (128 bits)\n");
    printf("    - Stored in clear with hash (not secret)\n");

    // bcrypt
    printf("\n\nbcrypt (1999):\n");
    printf("  Based on Blowfish cipher\n");
    printf("  Adaptive: cost parameter doubles work\n");
    printf("\n  Parameters:\n");
    printf("    cost = work factor (4-31, typically 10-12)\n");
    printf("    iterations = 2^cost\n");
    printf("\n  Format: $2b$[cost]$[22-char salt][31-char hash]\n");
    printf("  Example: $2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.J/..A8KD\n");
    printf("\n  Advantages:\n");
    printf("    - Proven security (25+ years)\n");
    printf("    - Widely supported\n");
    printf("  Limitations:\n");
    printf("    - Max 72 bytes password\n");
    printf("    - Not memory-hard (GPU can help)\n");

    const char *password = "MySecureP@ssw0rd!";
    password_hash_t bcrypt_hash;
    password_hash_bcrypt(password, &bcrypt_hash, 12);

    printf("\n  bcrypt Demo (cost=12):\n");
    printf("    Password: %s\n", password);
    printf("    Encoded:  %s\n", bcrypt_hash.encoded);

    bool verified = password_verify(password, &bcrypt_hash);
    printf("    Verify:   %s\n", verified ? "PASS" : "FAIL");

    // scrypt
    printf("\n\nscrypt (2009):\n");
    printf("  Designed by Colin Percival\n");
    printf("  Memory-hard: Requires lots of RAM\n");
    printf("  Defeats GPU/ASIC attacks\n");
    printf("\n  Parameters:\n");
    printf("    N = CPU/memory cost (power of 2)\n");
    printf("    r = block size (8 typical)\n");
    printf("    p = parallelism (1 typical)\n");
    printf("    Memory = 128 * N * r bytes\n");
    printf("\n  Example: N=2^14, r=8, p=1\n");
    printf("    Memory = 128 * 16384 * 8 = 16 MB per hash\n");
    printf("\n  Used in: Litecoin, Tarsnap, Django\n");

    password_hash_t scrypt_hash;
    password_hash_scrypt(password, &scrypt_hash, 16384, 8, 1);

    printf("\n  scrypt Demo (N=16384, r=8, p=1):\n");
    printf("    Hash: ");
    for (int i = 0; i < 16; i++) printf("%02x", scrypt_hash.hash[i]);
    printf("...\n");

    // Argon2
    printf("\n\nArgon2 (2015):\n");
    printf("  Winner of Password Hashing Competition\n");
    printf("  State-of-the-art algorithm\n");
    printf("\n  Variants:\n");
    printf("    Argon2d: Data-dependent (resistant to GPU)\n");
    printf("    Argon2i: Data-independent (resistant to side-channel)\n");
    printf("    Argon2id: Hybrid - RECOMMENDED\n");
    printf("\n  Parameters:\n");
    printf("    t = time cost (iterations)\n");
    printf("    m = memory cost (KB)\n");
    printf("    p = parallelism (threads)\n");
    printf("\n  OWASP Recommendations (2023):\n");
    printf("    Argon2id: m=19456 (19MB), t=2, p=1\n");
    printf("    Or: m=12288, t=3, p=1\n");

    password_params_t argon2_params = {
        .time_cost = 2,
        .memory_cost = 19456,  // 19 MB
        .parallelism = 1,
        .hash_len = 32,
        .salt_len = 16
    };

    password_hash_t argon2_hash;
    password_hash_argon2id(password, &argon2_hash, &argon2_params);

    printf("\n  Argon2id Demo:\n");
    printf("    Encoded: %s\n", argon2_hash.encoded);
    // Format: $argon2id$v=19$m=19456,t=2,p=1$[salt]$[hash]

    verified = password_verify(password, &argon2_hash);
    printf("    Verify: %s\n", verified ? "PASS" : "FAIL");

    // Wrong password
    verified = password_verify("WrongPassword", &argon2_hash);
    printf("    Wrong pw: %s\n", verified ? "FAIL (bad!)" : "REJECTED (correct!)");

    // Pepper
    printf("\n\nPepper:\n");
    printf("  Server-side secret (NOT stored in DB)\n");
    printf("  hash = password_hash(password || pepper)\n");
    printf("\n  Benefits:\n");
    printf("    - If DB is stolen, need pepper too\n");
    printf("    - Adds another layer of defense\n");
    printf("\n  Implementation:\n");
    printf("    - Store pepper in HSM or config (not DB)\n");
    printf("    - Same pepper for all users\n");
    printf("    - Rotate periodically (re-hash on login)\n");

    // 2.9.12: Implementing Crypto
    printf("\n\n=== Implementing Crypto from Scratch ===\n\n");

    printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
    printf("!  WARNING: EDUCATIONAL PURPOSES ONLY!            !\n");
    printf("!  NEVER use homemade crypto in production!       !\n");
    printf("!  Use established libraries: OpenSSL, libsodium  !\n");
    printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

    // AES Implementation
    printf("\n\nAES-128 Implementation:\n");
    printf("  Block size: 128 bits (16 bytes)\n");
    printf("  Key size: 128 bits (16 bytes)\n");
    printf("  Rounds: 10\n");

    printf("\n  Round Operations:\n");
    printf("  1. SubBytes: S-box substitution\n");
    printf("     Each byte replaced using lookup table\n");
    printf("     Provides confusion (non-linearity)\n\n");

    // Show S-box construction
    printf("     S-box construction:\n");
    printf("     a) Compute multiplicative inverse in GF(2^8)\n");
    printf("     b) Apply affine transformation\n");
    printf("     s[i] = inv[i] XOR (inv[i] <<< 1) XOR ... XOR 0x63\n");

    printf("\n  2. ShiftRows: Cyclic row shifts\n");
    printf("     Row 0: no shift\n");
    printf("     Row 1: shift left 1\n");
    printf("     Row 2: shift left 2\n");
    printf("     Row 3: shift left 3\n");
    printf("     Provides diffusion across columns\n");

    printf("\n  3. MixColumns: Matrix multiplication\n");
    printf("     Each column multiplied by fixed matrix:\n");
    printf("     [2 3 1 1]   [s0]   [s0']\n");
    printf("     [1 2 3 1] * [s1] = [s1']\n");
    printf("     [1 1 2 3]   [s2]   [s2']\n");
    printf("     [3 1 1 2]   [s3]   [s3']\n");
    printf("     Multiplication in GF(2^8) with x^8+x^4+x^3+x+1\n");

    printf("\n  4. AddRoundKey: XOR with round key\n");
    printf("     state[i][j] ^= round_key[round * 16 + i * 4 + j]\n");

    printf("\n  Key Schedule:\n");
    printf("     Expands 16-byte key to 176 bytes (11 round keys)\n");
    printf("     Uses RotWord, SubWord, Rcon operations\n");

    // AES test vectors
    printf("\n  NIST Test Vector (FIPS 197):\n");
    uint8_t aes_key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t aes_pt[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    uint8_t aes_ct[16], aes_dec[16];

    aes_impl_encrypt(aes_key, aes_pt, aes_ct);

    printf("    Key:        ");
    for (int i = 0; i < 16; i++) printf("%02x", aes_key[i]);
    printf("\n    Plaintext:  ");
    for (int i = 0; i < 16; i++) printf("%02x", aes_pt[i]);
    printf("\n    Ciphertext: ");
    for (int i = 0; i < 16; i++) printf("%02x", aes_ct[i]);
    printf("\n    Expected:   69c4e0d86a7b0430d8cdb78070b4c55a\n");

    aes_impl_decrypt(aes_key, aes_ct, aes_dec);
    printf("    Decrypted:  ");
    for (int i = 0; i < 16; i++) printf("%02x", aes_dec[i]);
    printf("\n    Match: %s\n", memcmp(aes_pt, aes_dec, 16) == 0 ? "YES" : "NO");

    // SHA-256 Implementation
    printf("\n\nSHA-256 Implementation:\n");
    printf("  Output: 256 bits (32 bytes)\n");
    printf("  Block size: 512 bits (64 bytes)\n");
    printf("  Rounds: 64\n");

    printf("\n  Initial hash values (first 32 bits of fractional\n");
    printf("  parts of square roots of first 8 primes):\n");
    printf("    h0 = 0x6a09e667  h1 = 0xbb67ae85\n");
    printf("    h2 = 0x3c6ef372  h3 = 0xa54ff53a\n");
    printf("    h4 = 0x510e527f  h5 = 0x9b05688c\n");
    printf("    h6 = 0x1f83d9ab  h7 = 0x5be0cd19\n");

    printf("\n  Round function:\n");
    printf("    S0 = (a >>> 2) XOR (a >>> 13) XOR (a >>> 22)\n");
    printf("    S1 = (e >>> 6) XOR (e >>> 11) XOR (e >>> 25)\n");
    printf("    ch = (e AND f) XOR ((NOT e) AND g)\n");
    printf("    maj = (a AND b) XOR (a AND c) XOR (b AND c)\n");
    printf("    temp1 = h + S1 + ch + k[i] + w[i]\n");
    printf("    temp2 = S0 + maj\n");
    printf("    h=g; g=f; f=e; e=d+temp1; d=c; c=b; b=a; a=temp1+temp2\n");

    // SHA-256 test vectors
    printf("\n  NIST Test Vectors:\n");

    uint8_t sha_out[32];
    sha256_state_t sha_state;
    sha256_impl_init(&sha_state);
    sha256_impl_update(&sha_state, (uint8_t*)"abc", 3);
    sha256_impl_final(&sha_state, sha_out);

    printf("    SHA-256('abc'): ");
    for (int i = 0; i < 32; i++) printf("%02x", sha_out[i]);
    printf("\n    Expected:       ba7816bf8f01cfea414140de5dae2223"
           "b00361a396177a9cb410ff61f20015ad\n");

    // Empty string
    sha256_impl_init(&sha_state);
    sha256_impl_final(&sha_state, sha_out);
    printf("\n    SHA-256(''): ");
    for (int i = 0; i < 32; i++) printf("%02x", sha_out[i]);
    printf("\n    Expected:    e3b0c44298fc1c149afbf4c8996fb924"
           "27ae41e4649b934ca495991b7852b855\n");

    // HMAC-SHA256
    printf("\n\nHMAC-SHA256 Implementation:\n");
    printf("  Uses SHA-256 as underlying hash\n");
    printf("  Construction:\n");
    printf("    1. If key > 64 bytes: key = SHA-256(key)\n");
    printf("    2. Pad key to 64 bytes (block size)\n");
    printf("    3. inner = SHA-256((key XOR ipad) || message)\n");
    printf("    4. outer = SHA-256((key XOR opad) || inner)\n");
    printf("    ipad = 0x36 repeated, opad = 0x5c repeated\n");

    // HMAC test vector (RFC 4231)
    uint8_t hmac_out[32];
    uint8_t hmac_key[] = "key";
    hmac(HASH_SHA256, hmac_key, 3, (uint8_t*)"The quick brown fox jumps over the lazy dog", 43, hmac_out);

    printf("\n  RFC Test Vector:\n");
    printf("    Key: 'key'\n");
    printf("    Data: 'The quick brown fox jumps over the lazy dog'\n");
    printf("    HMAC: ");
    for (int i = 0; i < 32; i++) printf("%02x", hmac_out[i]);
    printf("\n    Expected: f7bc83f430538424b13298e6aa6fb143"
           "ef4d59a14946175997479dbc2d1a3cd8\n");

    // Test all vectors
    printf("\n\nRunning Full Test Suite:\n");
    printf("  AES NIST vectors:   %s\n",
           test_aes_nist_vectors() ? "PASS" : "FAIL");
    printf("  SHA-256 NIST vectors: %s\n",
           test_sha256_nist_vectors() ? "PASS" : "FAIL");
    printf("  HMAC RFC vectors:   %s\n",
           test_hmac_rfc_vectors() ? "PASS" : "FAIL");

    // Final warning
    printf("\n\n");
    printf("+--------------------------------------------------+\n");
    printf("|  REMEMBER: This code is for LEARNING only!       |\n");
    printf("|                                                  |\n");
    printf("|  Production code should use:                     |\n");
    printf("|  - OpenSSL (widely used, audited)                |\n");
    printf("|  - libsodium (modern, easy API)                  |\n");
    printf("|  - Platform crypto (Windows CNG, macOS Security) |\n");
    printf("|                                                  |\n");
    printf("|  Rolling your own crypto = security bugs!        |\n");
    printf("+--------------------------------------------------+\n");

    return 0;
}
```

---

## Fichiers

```
ex05/
├── password_crypto_impl.h
├── bcrypt.c
├── scrypt.c
├── argon2.c
├── aes_impl.c
├── sha256_impl.c
├── test_vectors.c
└── Makefile
```
