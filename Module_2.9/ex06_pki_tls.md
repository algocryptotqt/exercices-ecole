# ex06: PKI, Certificates & TLS Protocol

**Module**: 2.9 - Computer Security
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.9.13: PKI and Certificates (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | PKI | Public Key Infrastructure |
| b | X.509 | Certificate standard |
| c | Certificate fields | Subject, issuer, validity, public key |
| d | CA | Certificate Authority |
| e | Root CA | Trust anchor |
| f | Intermediate CA | Signed by root |
| g | Chain of trust | Root -> intermediate -> end-entity |
| h | Certificate validation | Signature, expiry, revocation |
| i | CRL | Certificate Revocation List |
| j | OCSP | Online Certificate Status Protocol |

### 2.9.14: TLS Protocol (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | TLS versions | 1.0, 1.1 (deprecated), 1.2, 1.3 |
| b | Handshake | Key exchange |
| c | ClientHello | Supported versions, ciphers |
| d | ServerHello | Chosen version, cipher |
| e | Certificate | Server's cert |
| f | Key exchange | ECDHE typical |
| g | Finished | Verify handshake |
| h | Record protocol | Encrypt data |
| i | TLS 1.3 | Simplified, 1-RTT |
| j | 0-RTT | Resumption |

---

## Sujet

Comprendre l'infrastructure a cles publiques et le protocole TLS.

### Structures

```c
// X.509 Certificate
typedef struct {
    int version;              // 1, 2, or 3 (v3 most common)
    uint8_t serial[20];       // Serial number
    char issuer[256];         // Issuer DN
    char subject[256];        // Subject DN
    time_t not_before;        // Validity start
    time_t not_after;         // Validity end
    char public_key_alg[32];  // "RSA", "EC"
    uint8_t public_key[512];  // DER-encoded public key
    size_t public_key_len;
    char signature_alg[32];   // "SHA256withRSA", etc.
    uint8_t signature[512];
    size_t signature_len;
    // Extensions (v3)
    bool is_ca;               // Basic constraints
    int path_length;
    char key_usage[128];
    char san[512];            // Subject Alternative Names
} x509_cert_t;

// Certificate chain
typedef struct {
    x509_cert_t *certs;
    int count;
} cert_chain_t;

// TLS connection state
typedef struct {
    int version;              // TLS_1_2, TLS_1_3
    char cipher_suite[64];
    uint8_t master_secret[48];
    uint8_t client_random[32];
    uint8_t server_random[32];
    uint8_t session_id[32];
    bool resumed;
} tls_state_t;
```

### API

```c
// Certificate parsing
x509_cert_t *cert_parse_pem(const char *pem_data);
x509_cert_t *cert_parse_der(const uint8_t *der, size_t len);
void cert_print(const x509_cert_t *cert);

// Certificate validation
bool cert_verify_signature(const x509_cert_t *cert, const x509_cert_t *issuer);
bool cert_check_validity(const x509_cert_t *cert);
bool cert_check_name(const x509_cert_t *cert, const char *hostname);
bool cert_verify_chain(const cert_chain_t *chain, const cert_chain_t *trusted);

// Revocation checking
bool cert_check_crl(const x509_cert_t *cert, const char *crl_url);
bool cert_check_ocsp(const x509_cert_t *cert, const x509_cert_t *issuer);

// TLS simulation
void tls_explain_handshake(int version);
void tls_simulate_client_hello(tls_state_t *state);
void tls_simulate_server_hello(tls_state_t *state);
void tls_explain_cipher_suite(const char *suite);
```

---

## Exemple

```c
#include "pki_tls.h"

int main(void) {
    // 2.9.13: PKI and Certificates
    printf("=== PKI and Certificates ===\n\n");

    // PKI concept
    printf("Public Key Infrastructure (PKI):\n");
    printf("  Problem: How to trust a public key belongs to someone?\n");
    printf("  Solution: Trusted third parties (Certificate Authorities)\n");
    printf("\n  PKI Components:\n");
    printf("    - Certificate Authority (CA): Issues certificates\n");
    printf("    - Registration Authority: Verifies identities\n");
    printf("    - Certificate Repository: Stores certificates\n");
    printf("    - Revocation System: CRL, OCSP\n");

    // X.509 Certificates
    printf("\n\nX.509 Certificate Standard:\n");
    printf("  ITU-T X.509 / RFC 5280\n");
    printf("  Binds identity to public key\n");
    printf("  Signed by issuer's private key\n");

    printf("\n  Certificate Fields:\n");
    printf("  +--------------------------------------------------+\n");
    printf("  | Version:         3 (most common)                 |\n");
    printf("  | Serial Number:   Unique per CA                   |\n");
    printf("  | Signature Alg:   sha256WithRSAEncryption         |\n");
    printf("  | Issuer:          CN=Let's Encrypt Authority X3   |\n");
    printf("  | Validity:                                        |\n");
    printf("  |   Not Before:    Jan  1 00:00:00 2024 GMT        |\n");
    printf("  |   Not After:     Apr  1 00:00:00 2024 GMT        |\n");
    printf("  | Subject:         CN=example.com                  |\n");
    printf("  | Subject Public Key Info:                         |\n");
    printf("  |   Algorithm:     RSA (2048 bit)                  |\n");
    printf("  |   Public Key:    [modulus and exponent]          |\n");
    printf("  | Extensions:                                      |\n");
    printf("  |   Basic Constraints: CA:FALSE                    |\n");
    printf("  |   Key Usage: Digital Signature, Key Encipherment |\n");
    printf("  |   Subject Alt Name: DNS:example.com, DNS:*.ex... |\n");
    printf("  | Signature:       [CA's signature over above]     |\n");
    printf("  +--------------------------------------------------+\n");

    // Certificate Authority hierarchy
    printf("\n\nCertificate Authority Hierarchy:\n");
    printf("  Root CA (Trust Anchor):\n");
    printf("    - Self-signed certificate\n");
    printf("    - Stored in OS/browser trust store\n");
    printf("    - Kept offline (security)\n");
    printf("    - Valid 20-30 years\n");

    printf("\n  Intermediate CA:\n");
    printf("    - Signed by Root CA\n");
    printf("    - Issues end-entity certificates\n");
    printf("    - Can be revoked without replacing root\n");
    printf("    - Valid 5-10 years\n");

    printf("\n  End-Entity Certificate:\n");
    printf("    - Signed by Intermediate CA\n");
    printf("    - For websites, users, servers\n");
    printf("    - Valid 90 days - 1 year (shorter is better)\n");

    // Chain of trust
    printf("\n\nChain of Trust:\n");
    printf("  Root CA          (trusted, in your OS)\n");
    printf("     |\n");
    printf("     +--signs--> Intermediate CA\n");
    printf("                    |\n");
    printf("                    +--signs--> Your Server Cert\n");
    printf("\n  Server sends: [Server Cert] + [Intermediate Cert]\n");
    printf("  Client has:   [Root Cert] in trust store\n");
    printf("\n  Validation:\n");
    printf("    1. Verify server cert signed by intermediate\n");
    printf("    2. Verify intermediate signed by root\n");
    printf("    3. Root is trusted -> chain valid!\n");

    // Certificate validation
    printf("\n\nCertificate Validation Steps:\n");
    printf("  1. Parse certificate and chain\n");
    printf("  2. Build chain to trusted root\n");
    printf("  3. For each cert in chain:\n");
    printf("     a. Verify signature (parent signed it)\n");
    printf("     b. Check validity dates (not expired)\n");
    printf("     c. Check Basic Constraints (CA:TRUE if issuing)\n");
    printf("     d. Check Key Usage (allows signing)\n");
    printf("     e. Check revocation (CRL/OCSP)\n");
    printf("  4. For end-entity cert:\n");
    printf("     a. Check Subject/SAN matches hostname\n");
    printf("     b. Check Extended Key Usage (serverAuth)\n");

    // Revocation
    printf("\n\nCertificate Revocation:\n");
    printf("  Why revoke?\n");
    printf("    - Private key compromised\n");
    printf("    - CA compromised\n");
    printf("    - Domain ownership changed\n");
    printf("    - Certificate issued incorrectly\n");

    printf("\n  CRL (Certificate Revocation List):\n");
    printf("    - List of revoked serial numbers\n");
    printf("    - Signed by CA, published periodically\n");
    printf("    - Problem: Can be large, stale\n");

    printf("\n  OCSP (Online Certificate Status Protocol):\n");
    printf("    - Real-time revocation check\n");
    printf("    - Client asks CA: 'Is cert X valid?'\n");
    printf("    - CA responds: Good/Revoked/Unknown\n");
    printf("    - Problem: Privacy (CA sees all sites you visit)\n");

    printf("\n  OCSP Stapling:\n");
    printf("    - Server fetches OCSP response\n");
    printf("    - Staples it to TLS handshake\n");
    printf("    - Client doesn't contact CA directly\n");
    printf("    - Best of both worlds!\n");

    // 2.9.14: TLS Protocol
    printf("\n\n=== TLS Protocol ===\n\n");

    // TLS versions
    printf("TLS Version History:\n");
    printf("  SSL 2.0 (1995): BROKEN, never use\n");
    printf("  SSL 3.0 (1996): BROKEN (POODLE), disabled\n");
    printf("  TLS 1.0 (1999): DEPRECATED (2020)\n");
    printf("  TLS 1.1 (2006): DEPRECATED (2020)\n");
    printf("  TLS 1.2 (2008): OK, widely used\n");
    printf("  TLS 1.3 (2018): BEST, use this!\n");

    // TLS 1.2 Handshake
    printf("\n\nTLS 1.2 Full Handshake (2-RTT):\n");
    printf("  Client                              Server\n");
    printf("     |                                   |\n");
    printf("     |---- ClientHello ----------------->|\n");
    printf("     |      Version, Random,             |\n");
    printf("     |      Cipher Suites, Extensions    |\n");
    printf("     |                                   |\n");
    printf("     |<--- ServerHello ------------------|\n");
    printf("     |     Version, Random,              |\n");
    printf("     |     Chosen Cipher, Session ID     |\n");
    printf("     |<--- Certificate ------------------|\n");
    printf("     |     Server's X.509 cert chain     |\n");
    printf("     |<--- ServerKeyExchange ------------| (if DHE/ECDHE)\n");
    printf("     |     DH/ECDH parameters, signed    |\n");
    printf("     |<--- ServerHelloDone --------------|\n");
    printf("     |                                   |\n");
    printf("     |---- ClientKeyExchange ----------->|\n");
    printf("     |     Client's DH/ECDH public       |\n");
    printf("     |---- ChangeCipherSpec ------------>|\n");
    printf("     |---- Finished -------------------->|\n");
    printf("     |     Verify handshake integrity    |\n");
    printf("     |                                   |\n");
    printf("     |<--- ChangeCipherSpec -------------|\n");
    printf("     |<--- Finished --------------------|\n");
    printf("     |                                   |\n");
    printf("     |==== Encrypted Application Data ==|\n");

    // ClientHello
    printf("\n\nClientHello Message:\n");
    printf("  - Protocol version: TLS 1.2 (or supported_versions extension for 1.3)\n");
    printf("  - Client random: 32 bytes of random data\n");
    printf("  - Session ID: For resumption (optional)\n");
    printf("  - Cipher suites: List of supported algorithms\n");
    printf("  - Compression methods: [null] (compression deprecated)\n");
    printf("  - Extensions:\n");
    printf("    - server_name (SNI): Which hostname\n");
    printf("    - supported_groups: ECDH curves\n");
    printf("    - signature_algorithms: For cert validation\n");
    printf("    - supported_versions: TLS versions (1.3)\n");
    printf("    - key_share: Client's key exchange public (1.3)\n");

    // Cipher suites
    printf("\n\nCipher Suite Examples:\n");
    printf("  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:\n");
    printf("    - Key Exchange: ECDHE (ephemeral EC Diffie-Hellman)\n");
    printf("    - Authentication: RSA (server cert)\n");
    printf("    - Encryption: AES-256-GCM (AEAD)\n");
    printf("    - PRF Hash: SHA-384\n");

    printf("\n  TLS_AES_256_GCM_SHA384 (TLS 1.3):\n");
    printf("    - Key Exchange: ECDHE (required, not in name)\n");
    printf("    - Authentication: cert type (RSA/ECDSA) separate\n");
    printf("    - Encryption: AES-256-GCM\n");
    printf("    - HKDF Hash: SHA-384\n");

    printf("\n  Modern recommendations:\n");
    printf("    - TLS_AES_128_GCM_SHA256 (TLS 1.3)\n");
    printf("    - TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)\n");
    printf("    - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (TLS 1.2)\n");

    // Key exchange
    printf("\n\nKey Exchange (ECDHE):\n");
    printf("  1. Server sends ECDH parameters + signature\n");
    printf("  2. Client generates ephemeral key pair\n");
    printf("  3. Client sends public key to server\n");
    printf("  4. Both compute shared secret: premaster_secret\n");
    printf("  5. Derive master_secret:\n");
    printf("     master_secret = PRF(premaster, 'master secret',\n");
    printf("                        client_random + server_random)\n");
    printf("  6. Derive keys:\n");
    printf("     key_block = PRF(master, 'key expansion',\n");
    printf("                    server_random + client_random)\n");
    printf("     -> client_write_key, server_write_key\n");
    printf("     -> client_write_IV, server_write_IV\n");

    // TLS 1.3
    printf("\n\nTLS 1.3 Improvements:\n");
    printf("  1. Faster: 1-RTT handshake (vs 2-RTT in 1.2)\n");
    printf("  2. Simpler: Removed insecure options\n");
    printf("     - No RSA key exchange (no PFS)\n");
    printf("     - No CBC cipher suites\n");
    printf("     - No SHA-1 for signatures\n");
    printf("     - No compression\n");
    printf("  3. Encrypted handshake: Cert encrypted (privacy)\n");
    printf("  4. Mandatory PFS: Only ECDHE/DHE\n");

    printf("\n\nTLS 1.3 Handshake (1-RTT):\n");
    printf("  Client                              Server\n");
    printf("     |                                   |\n");
    printf("     |---- ClientHello ----------------->|\n");
    printf("     |     + supported_versions          |\n");
    printf("     |     + key_share (ECDH public!)    |\n");
    printf("     |                                   |\n");
    printf("     |<--- ServerHello ------------------|\n");
    printf("     |     + key_share (ECDH public)     |\n");
    printf("     |<--- EncryptedExtensions ---------|| (encrypted!)\n");
    printf("     |<--- Certificate -----------------|| (encrypted!)\n");
    printf("     |<--- CertificateVerify -----------|| (signature)\n");
    printf("     |<--- Finished --------------------|\n");
    printf("     |                                   |\n");
    printf("     |---- Finished -------------------->|\n");
    printf("     |                                   |\n");
    printf("     |==== Encrypted Application Data ==|\n");
    printf("\n  Note: Server can send data after 1 flight!\n");

    // 0-RTT
    printf("\n\n0-RTT Resumption (TLS 1.3):\n");
    printf("  Client sends data IMMEDIATELY with ClientHello!\n");
    printf("  Uses PSK (Pre-Shared Key) from previous session\n");
    printf("\n  Security trade-off:\n");
    printf("    - 0-RTT data is NOT replay-protected\n");
    printf("    - Server must handle idempotently\n");
    printf("    - Use only for safe requests (GET, not POST)\n");

    // Record protocol
    printf("\n\nTLS Record Protocol:\n");
    printf("  After handshake, data sent in records:\n");
    printf("  +-------+-------+---------+----------------+-----+\n");
    printf("  | Type  | Ver   | Length  |   Encrypted    | Tag |\n");
    printf("  | 1B    | 2B    | 2B      |   Payload      | 16B |\n");
    printf("  +-------+-------+---------+----------------+-----+\n");
    printf("  Type: 23 = Application Data\n");
    printf("  Max record: 16384 bytes (+ overhead)\n");
    printf("\n  Encryption (AES-GCM):\n");
    printf("  - Nonce = IV (4B fixed) + sequence number (8B)\n");
    printf("  - AAD = record header (type + version + length)\n");
    printf("  - Tag provides authentication\n");

    // Practical example
    printf("\n\nPractical TLS Configuration:\n");
    printf("  Nginx example:\n");
    printf("    ssl_protocols TLSv1.2 TLSv1.3;\n");
    printf("    ssl_ciphers 'ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL';\n");
    printf("    ssl_prefer_server_ciphers on;\n");
    printf("    ssl_certificate /path/to/cert.pem;\n");
    printf("    ssl_certificate_key /path/to/key.pem;\n");
    printf("    ssl_stapling on;\n");
    printf("    ssl_stapling_verify on;\n");
    printf("\n  Headers:\n");
    printf("    add_header Strict-Transport-Security 'max-age=31536000';\n");

    return 0;
}
```

---

## Fichiers

```
ex06/
├── pki_tls.h
├── x509.c
├── chain_validate.c
├── tls_handshake.c
├── cipher_suites.c
└── Makefile
```
