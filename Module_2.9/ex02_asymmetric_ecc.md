# ex02: Asymmetric Cryptography & Elliptic Curves

**Module**: 2.9 - Computer Security
**Difficulte**: Difficile
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.9.5: Asymmetric Cryptography (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Public key | Shareable with anyone |
| b | Private key | Must remain secret |
| c | RSA | Rivest-Shamir-Adleman algorithm |
| d | RSA math | n=pq, e, d, phi(n) |
| e | RSA key generation | Choose p, q, compute d |
| f | RSA encrypt | c = m^e mod n |
| g | RSA decrypt | m = c^d mod n |
| h | RSA key sizes | 2048, 4096 bits |
| i | RSA padding | OAEP, PKCS#1 |
| j | RSA vs ECC | Key size comparison |

### 2.9.6: Elliptic Curve Cryptography (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Elliptic curve | y^2 = x^3 + ax + b |
| b | Point addition | Geometric operation |
| c | Scalar multiplication | Repeated addition |
| d | ECDH | Key exchange |
| e | ECDSA | Digital signatures |
| f | Common curves | P-256, P-384 |
| g | Curve25519 | Modern curve |
| h | Ed25519 | Signature scheme |
| i | Benefits | Smaller keys, same security |

---

## Sujet

Comprendre et implementer les algorithmes de cryptographie asymetrique RSA et ECC.

### Structures

```c
#include <stdint.h>
#include <stdbool.h>

// Big integer (simplified for educational purposes)
typedef struct {
    uint64_t limbs[64];  // 4096-bit max
    int size;            // Number of limbs used
    bool negative;
} bigint_t;

// RSA key pair
typedef struct {
    bigint_t n;          // Modulus (public)
    bigint_t e;          // Public exponent
    bigint_t d;          // Private exponent
    bigint_t p, q;       // Prime factors (private)
    bigint_t dp, dq;     // CRT exponents
    bigint_t qinv;       // CRT coefficient
    int bits;            // Key size in bits
} rsa_keypair_t;

// Elliptic curve point
typedef struct {
    bigint_t x;
    bigint_t y;
    bool infinity;       // Point at infinity
} ec_point_t;

// Elliptic curve parameters
typedef struct {
    bigint_t p;          // Prime field
    bigint_t a, b;       // Curve coefficients
    ec_point_t G;        // Generator point
    bigint_t n;          // Order of G
    int bits;            // Security level
    char name[32];       // Curve name
} ec_curve_t;

// ECDSA signature
typedef struct {
    bigint_t r;
    bigint_t s;
} ecdsa_signature_t;
```

### API

```c
// Big integer operations (educational)
void bigint_from_hex(bigint_t *n, const char *hex);
void bigint_to_hex(const bigint_t *n, char *hex, size_t len);
void bigint_mod_exp(bigint_t *result, const bigint_t *base,
                    const bigint_t *exp, const bigint_t *mod);
void bigint_mod_inv(bigint_t *result, const bigint_t *a, const bigint_t *mod);

// RSA operations
bool rsa_generate_keypair(rsa_keypair_t *kp, int bits);
void rsa_encrypt_raw(bigint_t *c, const bigint_t *m, const rsa_keypair_t *pub);
void rsa_decrypt_raw(bigint_t *m, const bigint_t *c, const rsa_keypair_t *priv);
bool rsa_encrypt_oaep(uint8_t *out, size_t *out_len,
                      const uint8_t *msg, size_t msg_len,
                      const rsa_keypair_t *pub);
bool rsa_decrypt_oaep(uint8_t *out, size_t *out_len,
                      const uint8_t *ct, size_t ct_len,
                      const rsa_keypair_t *priv);

// Elliptic curve operations
void ec_point_add(ec_point_t *r, const ec_point_t *p, const ec_point_t *q,
                  const ec_curve_t *curve);
void ec_point_double(ec_point_t *r, const ec_point_t *p, const ec_curve_t *curve);
void ec_scalar_mult(ec_point_t *r, const bigint_t *k, const ec_point_t *p,
                    const ec_curve_t *curve);

// ECDH key exchange
void ecdh_generate_keypair(bigint_t *priv, ec_point_t *pub, const ec_curve_t *curve);
void ecdh_compute_shared(ec_point_t *shared, const bigint_t *priv,
                         const ec_point_t *peer_pub, const ec_curve_t *curve);

// ECDSA signatures
void ecdsa_sign(ecdsa_signature_t *sig, const uint8_t *hash, size_t hash_len,
                const bigint_t *priv, const ec_curve_t *curve);
bool ecdsa_verify(const ecdsa_signature_t *sig, const uint8_t *hash, size_t hash_len,
                  const ec_point_t *pub, const ec_curve_t *curve);

// Curve definitions
const ec_curve_t *get_curve_p256(void);
const ec_curve_t *get_curve_p384(void);
const ec_curve_t *get_curve25519(void);
```

---

## Exemple

```c
#include "asymmetric_ecc.h"

int main(void) {
    // 2.9.5: Asymmetric Cryptography
    printf("=== Asymmetric Cryptography ===\n\n");

    // Key pair concept
    printf("Public/Private Key Pairs:\n");
    printf("  Public key:  Can be shared with anyone\n");
    printf("  Private key: Must NEVER be shared\n");
    printf("\n  Properties:\n");
    printf("    - Encrypt with public  -> Decrypt with private (confidentiality)\n");
    printf("    - Sign with private    -> Verify with public (authentication)\n");
    printf("    - Mathematically linked but cannot derive private from public\n");

    // RSA Algorithm
    printf("\n\nRSA (Rivest-Shamir-Adleman, 1977):\n");
    printf("  Security based on: Difficulty of factoring large numbers\n");
    printf("\n  Key Generation:\n");
    printf("    1. Choose two large primes p and q\n");
    printf("    2. Compute n = p * q (modulus)\n");
    printf("    3. Compute phi(n) = (p-1)(q-1) (Euler's totient)\n");
    printf("    4. Choose e such that gcd(e, phi(n)) = 1\n");
    printf("       Common choice: e = 65537 (0x10001)\n");
    printf("    5. Compute d = e^(-1) mod phi(n)\n");
    printf("\n  Public key:  (n, e)\n");
    printf("  Private key: (n, d) [and p, q for CRT optimization]\n");

    // RSA math demonstration
    printf("\n  RSA Math Example (tiny values):\n");
    printf("    p = 61, q = 53\n");
    printf("    n = p * q = 3233\n");
    printf("    phi(n) = (p-1)(q-1) = 60 * 52 = 3120\n");
    printf("    e = 17 (coprime with 3120)\n");
    printf("    d = e^(-1) mod 3120 = 2753\n");
    printf("    (17 * 2753 = 46801 = 15 * 3120 + 1)\n");

    printf("\n  Encryption: c = m^e mod n\n");
    printf("    Message m = 65 ('A')\n");
    printf("    c = 65^17 mod 3233 = 2790\n");

    printf("\n  Decryption: m = c^d mod n\n");
    printf("    m = 2790^2753 mod 3233 = 65\n");
    printf("    Recovered plaintext: 65 ('A') - Correct!\n");

    // RSA key generation
    printf("\n\n  Real RSA Key Generation:\n");
    rsa_keypair_t rsa;
    if (rsa_generate_keypair(&rsa, 2048)) {
        printf("    Generated 2048-bit RSA keypair\n");
        char n_hex[520];
        bigint_to_hex(&rsa.n, n_hex, sizeof(n_hex));
        printf("    n (first 64 chars): %.64s...\n", n_hex);
        printf("    e = 65537 (0x10001)\n");
    }

    // RSA encryption/decryption demo
    printf("\n  RSA Encryption Demo:\n");
    const char *message = "Hello RSA!";
    uint8_t ciphertext[256];
    uint8_t decrypted[256];
    size_t ct_len, dec_len;

    if (rsa_encrypt_oaep(ciphertext, &ct_len,
                        (uint8_t*)message, strlen(message), &rsa)) {
        printf("    Plaintext:  %s\n", message);
        printf("    Ciphertext: ");
        for (size_t i = 0; i < 32; i++) printf("%02x", ciphertext[i]);
        printf("...\n");

        if (rsa_decrypt_oaep(decrypted, &dec_len, ciphertext, ct_len, &rsa)) {
            decrypted[dec_len] = '\0';
            printf("    Decrypted:  %s\n", (char*)decrypted);
        }
    }

    // RSA Key Sizes
    printf("\n  RSA Key Size Recommendations:\n");
    printf("    +----------+------------------+----------------+\n");
    printf("    | Key Size | Security Level   | Status         |\n");
    printf("    +----------+------------------+----------------+\n");
    printf("    | 1024-bit | ~80-bit          | BROKEN         |\n");
    printf("    | 2048-bit | ~112-bit         | Minimum today  |\n");
    printf("    | 3072-bit | ~128-bit         | Recommended    |\n");
    printf("    | 4096-bit | ~152-bit         | High security  |\n");
    printf("    +----------+------------------+----------------+\n");

    // RSA Padding
    printf("\n  RSA Padding (CRITICAL!):\n");
    printf("    Raw RSA (textbook): NEVER use!\n");
    printf("      - Deterministic (same m -> same c)\n");
    printf("      - Vulnerable to many attacks\n");
    printf("\n    PKCS#1 v1.5: Legacy padding\n");
    printf("      - 0x00 0x02 [random non-zero bytes] 0x00 [message]\n");
    printf("      - Vulnerable to Bleichenbacher attack (1998)\n");
    printf("\n    OAEP (Optimal Asymmetric Encryption Padding):\n");
    printf("      - Uses hash functions for randomization\n");
    printf("      - Provably secure (in random oracle model)\n");
    printf("      - RECOMMENDED for new applications\n");

    // RSA vs ECC
    printf("\n  RSA vs ECC Key Size Comparison:\n");
    printf("    +---------------+-----------+-----------+\n");
    printf("    | Security bits | RSA       | ECC       |\n");
    printf("    +---------------+-----------+-----------+\n");
    printf("    | 80            | 1024      | 160       |\n");
    printf("    | 112           | 2048      | 224       |\n");
    printf("    | 128           | 3072      | 256       |\n");
    printf("    | 192           | 7680      | 384       |\n");
    printf("    | 256           | 15360     | 512       |\n");
    printf("    +---------------+-----------+-----------+\n");
    printf("    ECC keys are ~10x smaller for same security!\n");

    // 2.9.6: Elliptic Curve Cryptography
    printf("\n\n=== Elliptic Curve Cryptography ===\n\n");

    // Elliptic curve equation
    printf("Elliptic Curve Equation:\n");
    printf("  y^2 = x^3 + ax + b  (Weierstrass form)\n");
    printf("\n  Conditions:\n");
    printf("    - Discriminant: 4a^3 + 27b^2 != 0 (no singularities)\n");
    printf("    - Defined over finite field F_p (prime p)\n");

    printf("\n  Visual representation:\n");
    printf("        y\n");
    printf("        |     ***\n");
    printf("        |   **   **\n");
    printf("        |  *       *\n");
    printf("    ----+--*-------*---- x\n");
    printf("        |  *       *\n");
    printf("        |   **   **\n");
    printf("        |     ***\n");

    // Point addition
    printf("\n\nPoint Addition (P + Q = R):\n");
    printf("  Geometric interpretation:\n");
    printf("    1. Draw line through P and Q\n");
    printf("    2. Line intersects curve at third point\n");
    printf("    3. Reflect that point over x-axis = R\n");
    printf("\n  Algebraic formulas (P = (x1,y1), Q = (x2,y2)):\n");
    printf("    If P != Q:\n");
    printf("      lambda = (y2 - y1) / (x2 - x1)\n");
    printf("    If P == Q (point doubling):\n");
    printf("      lambda = (3*x1^2 + a) / (2*y1)\n");
    printf("    x3 = lambda^2 - x1 - x2\n");
    printf("    y3 = lambda*(x1 - x3) - y1\n");

    // Scalar multiplication
    printf("\n\nScalar Multiplication:\n");
    printf("  k * P = P + P + ... + P  (k times)\n");
    printf("  Efficient: Double-and-add algorithm O(log k)\n");
    printf("\n  Example with k = 21:\n");
    printf("    21 = 10101 (binary)\n");
    printf("    21*P = ((((P)*2 + P)*2)*2 + P)*2 + P\n");
    printf("         = 2*(2*(2*(2*P+P))+P)+P\n");

    // ECDLP - The hard problem
    printf("\n  Discrete Logarithm Problem:\n");
    printf("    Given: P, Q = k*P on curve\n");
    printf("    Find:  k\n");
    printf("    This is HARD! (exponential time best known)\n");
    printf("    Security of ECC depends on this hardness.\n");

    // Common curves
    printf("\n\nCommon Elliptic Curves:\n");

    const ec_curve_t *p256 = get_curve_p256();
    printf("\n  P-256 (secp256r1, prime256v1):\n");
    printf("    Prime: 2^256 - 2^224 + 2^192 + 2^96 - 1\n");
    printf("    Security: 128 bits\n");
    printf("    Usage: TLS, X.509, general purpose\n");
    printf("    Status: Widely supported, NIST standard\n");

    printf("\n  P-384 (secp384r1):\n");
    printf("    Security: 192 bits\n");
    printf("    Usage: Government, high security\n");

    printf("\n  Curve25519 (X25519):\n");
    printf("    y^2 = x^3 + 486662*x^2 + x\n");
    printf("    Prime: 2^255 - 19\n");
    printf("    Security: ~128 bits\n");
    printf("    Advantages:\n");
    printf("      - Designed by Daniel Bernstein\n");
    printf("      - Constant-time implementation easy\n");
    printf("      - Resistant to timing attacks\n");
    printf("      - Fast (no special primes needed)\n");
    printf("    Usage: Signal, WireGuard, SSH, TLS 1.3\n");

    printf("\n  Ed25519:\n");
    printf("    Edwards curve for signatures\n");
    printf("    -x^2 + y^2 = 1 + d*x^2*y^2\n");
    printf("    Fastest signature scheme available\n");
    printf("    Usage: SSH keys, cryptocurrency, Signal\n");

    // ECDH Key Exchange
    printf("\n\nECDH (Elliptic Curve Diffie-Hellman):\n");
    printf("  Key exchange using elliptic curves\n");
    printf("\n  Protocol:\n");
    printf("    Alice:                    Bob:\n");
    printf("    a = random               b = random\n");
    printf("    A = a*G    ---->        B = b*G\n");
    printf("               <----\n");
    printf("    S = a*B                  S = b*A\n");
    printf("    S = a*b*G                S = b*a*G\n");
    printf("    (Same shared secret!)\n");

    // ECDH demonstration
    printf("\n  ECDH Demo (P-256):\n");
    bigint_t alice_priv, bob_priv;
    ec_point_t alice_pub, bob_pub;
    ec_point_t alice_shared, bob_shared;

    ecdh_generate_keypair(&alice_priv, &alice_pub, p256);
    ecdh_generate_keypair(&bob_priv, &bob_pub, p256);

    ecdh_compute_shared(&alice_shared, &alice_priv, &bob_pub, p256);
    ecdh_compute_shared(&bob_shared, &bob_priv, &alice_pub, p256);

    char alice_x[70], bob_x[70];
    bigint_to_hex(&alice_shared.x, alice_x, sizeof(alice_x));
    bigint_to_hex(&bob_shared.x, bob_x, sizeof(bob_x));

    printf("    Alice's shared secret X: %.32s...\n", alice_x);
    printf("    Bob's shared secret X:   %.32s...\n", bob_x);
    printf("    Match: %s\n", strcmp(alice_x, bob_x) == 0 ? "YES" : "NO");

    // ECDSA
    printf("\n\nECDSA (Elliptic Curve Digital Signature Algorithm):\n");
    printf("  Digital signatures using elliptic curves\n");
    printf("\n  Signing (private key d, message hash z):\n");
    printf("    1. k = random (per-signature, CRITICAL!)\n");
    printf("    2. (x1, y1) = k * G\n");
    printf("    3. r = x1 mod n\n");
    printf("    4. s = k^(-1) * (z + r*d) mod n\n");
    printf("    Signature: (r, s)\n");
    printf("\n  Verification (public key Q, message hash z):\n");
    printf("    1. u1 = z * s^(-1) mod n\n");
    printf("    2. u2 = r * s^(-1) mod n\n");
    printf("    3. (x1, y1) = u1*G + u2*Q\n");
    printf("    4. Valid if r == x1 mod n\n");

    printf("\n  CRITICAL: k must be:\n");
    printf("    - Random and secret\n");
    printf("    - UNIQUE per signature\n");
    printf("    - If k is reused or predictable, private key is EXPOSED!\n");
    printf("    (Sony PS3 hack: same k used twice -> private key leaked)\n");

    // ECDSA demo
    printf("\n  ECDSA Demo (P-256):\n");
    bigint_t sign_priv;
    ec_point_t sign_pub;
    ecdh_generate_keypair(&sign_priv, &sign_pub, p256);

    uint8_t msg_hash[32] = "This is a 32-byte hash value!";
    ecdsa_signature_t sig;

    ecdsa_sign(&sig, msg_hash, 32, &sign_priv, p256);

    char r_hex[70], s_hex[70];
    bigint_to_hex(&sig.r, r_hex, sizeof(r_hex));
    bigint_to_hex(&sig.s, s_hex, sizeof(s_hex));

    printf("    r: %.32s...\n", r_hex);
    printf("    s: %.32s...\n", s_hex);

    bool valid = ecdsa_verify(&sig, msg_hash, 32, &sign_pub, p256);
    printf("    Verification: %s\n", valid ? "VALID" : "INVALID");

    // Tamper with message
    msg_hash[0] ^= 0x01;
    bool tampered = ecdsa_verify(&sig, msg_hash, 32, &sign_pub, p256);
    printf("    After tampering: %s\n", tampered ? "ERROR!" : "INVALID (correct!)");

    // Benefits of ECC
    printf("\n\nECC Benefits Summary:\n");
    printf("  1. Smaller keys (256-bit ECC ~ 3072-bit RSA)\n");
    printf("  2. Faster operations (especially signing)\n");
    printf("  3. Lower bandwidth (smaller signatures)\n");
    printf("  4. Less storage (key and cert size)\n");
    printf("  5. Mobile/IoT friendly (resource constrained)\n");
    printf("\n  Modern recommendation:\n");
    printf("    - Key exchange: X25519 (Curve25519)\n");
    printf("    - Signatures:   Ed25519\n");
    printf("    - Fallback:     P-256 (NIST curves)\n");

    return 0;
}
```

---

## Fichiers

```
ex02/
├── asymmetric_ecc.h
├── bigint.c
├── rsa.c
├── ecc.c
├── ecdh.c
├── ecdsa.c
└── Makefile
```
