# PROJET: Security Analysis Toolkit

**Module**: 2.9 - Computer Security
**Difficulte**: Avance
**Duree**: 40h
**Score qualite**: 98/100

## Objectif

Developper une suite complete d'outils de securite en C comprenant:
- Un scanner de vulnerabilites binaires
- Un analyseur de trafic reseau
- Un verificateur de configurations securite
- Un generateur de rapports d'audit

Ce projet integre TOUS les 45 sous-modules du Module 2.9.

---

## Architecture

```
security_toolkit/
├── include/
│   ├── crypto/
│   │   ├── aes.h              # AES implementation
│   │   ├── sha256.h           # SHA-256
│   │   ├── hmac.h             # HMAC
│   │   ├── pbkdf2.h           # Key derivation
│   │   └── random.h           # Secure random
│   ├── analysis/
│   │   ├── binary_analyzer.h  # Binary analysis
│   │   ├── elf_parser.h       # ELF parsing
│   │   ├── protection_check.h # Check protections
│   │   ├── vuln_scanner.h     # Vulnerability patterns
│   │   └── rop_finder.h       # ROP gadget finder
│   ├── network/
│   │   ├── packet_capture.h   # Packet capture
│   │   ├── protocol_parser.h  # Protocol parsing
│   │   ├── tls_analyzer.h     # TLS inspection
│   │   └── port_scanner.h     # Port scanning
│   ├── web/
│   │   ├── http_client.h      # HTTP client
│   │   ├── header_analyzer.h  # Security headers
│   │   ├── cookie_analyzer.h  # Cookie security
│   │   └── vuln_tests.h       # Web vuln tests
│   ├── audit/
│   │   ├── config_checker.h   # Config audit
│   │   ├── password_audit.h   # Password strength
│   │   └── report_gen.h       # Report generation
│   └── common/
│       ├── types.h
│       ├── error.h
│       └── logging.h
├── src/
│   ├── crypto/
│   ├── analysis/
│   ├── network/
│   ├── web/
│   ├── audit/
│   └── main.c
├── tools/
│   ├── binscan           # Binary scanner CLI
│   ├── netscan           # Network scanner CLI
│   ├── webscan           # Web scanner CLI
│   └── auditor           # System auditor CLI
├── tests/
│   ├── test_crypto.c
│   ├── test_analysis.c
│   ├── test_network.c
│   ├── test_web.c
│   └── vulnerable_samples/
├── docs/
│   └── SECURITY_GUIDE.md
├── Makefile
└── README.md
```

---

## Partie 1: Crypto Module (2.9.1 - 2.9.14)

### 1.1 AES Implementation

```c
// include/crypto/aes.h

#ifndef CRYPTO_AES_H
#define CRYPTO_AES_H

#include <stdint.h>
#include <stddef.h>

// AES key sizes
typedef enum {
    AES_128 = 16,
    AES_192 = 24,
    AES_256 = 32
} aes_key_size_t;

// AES context
typedef struct {
    uint32_t round_keys[60];  // Expanded key schedule
    size_t   num_rounds;      // 10, 12, or 14
    size_t   key_size;
} aes_ctx_t;

// Block cipher modes
typedef enum {
    AES_MODE_ECB,
    AES_MODE_CBC,
    AES_MODE_CTR,
    AES_MODE_GCM
} aes_mode_t;

// GCM context
typedef struct {
    aes_ctx_t aes;
    uint8_t   h[16];          // Hash key
    uint8_t   j0[16];         // Pre-counter block
    uint8_t   counter[16];
    uint8_t   tag[16];
    uint64_t  aad_len;
    uint64_t  cipher_len;
} aes_gcm_ctx_t;

// Core AES operations
int aes_init(aes_ctx_t *ctx, const uint8_t *key, aes_key_size_t key_size);
void aes_encrypt_block(const aes_ctx_t *ctx, const uint8_t *in, uint8_t *out);
void aes_decrypt_block(const aes_ctx_t *ctx, const uint8_t *in, uint8_t *out);

// CBC mode
int aes_cbc_encrypt(const aes_ctx_t *ctx, const uint8_t *iv,
                    const uint8_t *plaintext, size_t len,
                    uint8_t *ciphertext);
int aes_cbc_decrypt(const aes_ctx_t *ctx, const uint8_t *iv,
                    const uint8_t *ciphertext, size_t len,
                    uint8_t *plaintext);

// CTR mode
int aes_ctr_crypt(const aes_ctx_t *ctx, const uint8_t *nonce,
                  const uint8_t *input, size_t len,
                  uint8_t *output);

// GCM mode (AEAD)
int aes_gcm_init(aes_gcm_ctx_t *ctx, const uint8_t *key, size_t key_len,
                 const uint8_t *iv, size_t iv_len);
int aes_gcm_aad(aes_gcm_ctx_t *ctx, const uint8_t *aad, size_t aad_len);
int aes_gcm_encrypt(aes_gcm_ctx_t *ctx, const uint8_t *plaintext, size_t len,
                    uint8_t *ciphertext);
int aes_gcm_decrypt(aes_gcm_ctx_t *ctx, const uint8_t *ciphertext, size_t len,
                    uint8_t *plaintext);
int aes_gcm_finish(aes_gcm_ctx_t *ctx, uint8_t *tag, size_t tag_len);
int aes_gcm_verify(aes_gcm_ctx_t *ctx, const uint8_t *tag, size_t tag_len);

// Secure memory operations
void secure_zero(void *ptr, size_t len);

#endif // CRYPTO_AES_H
```

### 1.2 SHA-256 Implementation

```c
// include/crypto/sha256.h

#ifndef CRYPTO_SHA256_H
#define CRYPTO_SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_DIGEST_SIZE 32
#define SHA256_BLOCK_SIZE  64

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[SHA256_BLOCK_SIZE];
} sha256_ctx_t;

// SHA-256 operations
void sha256_init(sha256_ctx_t *ctx);
void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void sha256_final(sha256_ctx_t *ctx, uint8_t *digest);

// Convenience function
void sha256(const uint8_t *data, size_t len, uint8_t *digest);

// HMAC-SHA256
typedef struct {
    sha256_ctx_t inner;
    sha256_ctx_t outer;
    uint8_t      key_pad[SHA256_BLOCK_SIZE];
} hmac_sha256_ctx_t;

void hmac_sha256_init(hmac_sha256_ctx_t *ctx, const uint8_t *key, size_t key_len);
void hmac_sha256_update(hmac_sha256_ctx_t *ctx, const uint8_t *data, size_t len);
void hmac_sha256_final(hmac_sha256_ctx_t *ctx, uint8_t *mac);
void hmac_sha256(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t *mac);

// HKDF (Key Derivation)
int hkdf_sha256_extract(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        uint8_t *prk);
int hkdf_sha256_expand(const uint8_t *prk, size_t prk_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len);

#endif // CRYPTO_SHA256_H
```

### 1.3 Password Hashing

```c
// include/crypto/pbkdf2.h

#ifndef CRYPTO_PBKDF2_H
#define CRYPTO_PBKDF2_H

#include <stdint.h>
#include <stddef.h>

// PBKDF2 with HMAC-SHA256
int pbkdf2_sha256(const uint8_t *password, size_t password_len,
                  const uint8_t *salt, size_t salt_len,
                  uint32_t iterations,
                  uint8_t *derived_key, size_t dk_len);

// Password verification structure
typedef struct {
    uint8_t  algorithm;       // 0=PBKDF2-SHA256
    uint32_t iterations;
    uint8_t  salt[32];
    size_t   salt_len;
    uint8_t  hash[32];
} password_hash_t;

// High-level password operations
int password_hash_create(const char *password, password_hash_t *hash);
int password_hash_verify(const char *password, const password_hash_t *hash);
int password_strength_check(const char *password, int *score, char *feedback, size_t fb_len);

// Timing-safe comparison
int constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len);

#endif // CRYPTO_PBKDF2_H
```

---

## Partie 2: Binary Analysis Module (2.9.15 - 2.9.31)

### 2.1 ELF Parser

```c
// include/analysis/elf_parser.h

#ifndef ANALYSIS_ELF_PARSER_H
#define ANALYSIS_ELF_PARSER_H

#include <elf.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Parsed ELF structure
typedef struct {
    int         fd;
    void        *map;
    size_t      size;
    bool        is_64bit;

    // Headers
    union {
        Elf32_Ehdr *ehdr32;
        Elf64_Ehdr *ehdr64;
    };

    // Program headers
    union {
        Elf32_Phdr *phdr32;
        Elf64_Phdr *phdr64;
    };
    size_t phnum;

    // Section headers
    union {
        Elf32_Shdr *shdr32;
        Elf64_Shdr *shdr64;
    };
    size_t shnum;

    // String tables
    const char *shstrtab;
    const char *strtab;
    const char *dynstr;

    // Symbol tables
    void       *symtab;
    size_t     symtab_count;
    void       *dynsym;
    size_t     dynsym_count;

} elf_file_t;

// Section info
typedef struct {
    const char *name;
    uint64_t   addr;
    uint64_t   offset;
    uint64_t   size;
    uint32_t   type;
    uint64_t   flags;
    bool       executable;
    bool       writable;
} section_info_t;

// Symbol info
typedef struct {
    const char *name;
    uint64_t   value;
    uint64_t   size;
    uint8_t    type;       // STT_FUNC, STT_OBJECT, etc.
    uint8_t    bind;       // STB_LOCAL, STB_GLOBAL, etc.
    uint16_t   section;
    bool       is_defined;
} symbol_info_t;

// Relocation info
typedef struct {
    uint64_t   offset;
    uint64_t   info;
    int64_t    addend;
    uint32_t   type;
    const char *symbol_name;
} reloc_info_t;

// ELF operations
int elf_open(const char *path, elf_file_t *elf);
void elf_close(elf_file_t *elf);

// Section operations
int elf_get_section_by_name(const elf_file_t *elf, const char *name,
                            section_info_t *info);
int elf_get_section_by_index(const elf_file_t *elf, size_t index,
                             section_info_t *info);
const void *elf_get_section_data(const elf_file_t *elf, const section_info_t *info);

// Symbol operations
int elf_get_symbol_by_name(const elf_file_t *elf, const char *name,
                           symbol_info_t *info);
int elf_iterate_symbols(const elf_file_t *elf,
                        int (*callback)(const symbol_info_t *, void *),
                        void *user_data);

// Address resolution
int elf_addr_to_symbol(const elf_file_t *elf, uint64_t addr,
                       symbol_info_t *info, int64_t *offset);
int elf_symbol_to_addr(const elf_file_t *elf, const char *name,
                       uint64_t *addr);

// Relocation iteration
int elf_iterate_relocations(const elf_file_t *elf,
                            int (*callback)(const reloc_info_t *, void *),
                            void *user_data);

// Utility
uint64_t elf_get_entry_point(const elf_file_t *elf);
uint64_t elf_get_base_address(const elf_file_t *elf);
bool elf_is_pie(const elf_file_t *elf);
bool elf_is_static(const elf_file_t *elf);

#endif // ANALYSIS_ELF_PARSER_H
```

### 2.2 Protection Checker

```c
// include/analysis/protection_check.h

#ifndef ANALYSIS_PROTECTION_CHECK_H
#define ANALYSIS_PROTECTION_CHECK_H

#include "elf_parser.h"

// Protection flags
typedef struct {
    bool has_canary;          // Stack canary
    bool has_nx;              // Non-executable stack
    bool is_pie;              // Position Independent Executable
    bool has_relro;           // RELRO
    bool full_relro;          // Full RELRO (GOT read-only)
    bool has_fortify;         // FORTIFY_SOURCE
    bool has_rpath;           // RPATH set
    bool has_runpath;         // RUNPATH set
    bool stripped;            // Symbols stripped
    bool has_debug;           // Debug info present
} protection_info_t;

// ASLR check
typedef struct {
    bool enabled;
    int  level;               // 0=off, 1=conservative, 2=full
    bool stack_randomization;
    bool mmap_randomization;
    bool heap_randomization;
    bool vdso_randomization;
} aslr_info_t;

// Check binary protections
int check_protections(const elf_file_t *elf, protection_info_t *info);

// Check system ASLR
int check_aslr(aslr_info_t *info);

// Check specific protections in detail
int check_got_writable(const elf_file_t *elf, bool *writable);
int check_stack_canary(const elf_file_t *elf, bool *has_canary);
int check_fortify_functions(const elf_file_t *elf, const char ***functions, size_t *count);

// Print protection report
void print_protection_report(const elf_file_t *elf, const protection_info_t *info);

// checksec-style output
void checksec_output(const char *path, const protection_info_t *info);

#endif // ANALYSIS_PROTECTION_CHECK_H
```

### 2.3 Vulnerability Scanner

```c
// include/analysis/vuln_scanner.h

#ifndef ANALYSIS_VULN_SCANNER_H
#define ANALYSIS_VULN_SCANNER_H

#include "elf_parser.h"
#include <stdint.h>

// Vulnerability severity
typedef enum {
    VULN_INFO = 0,
    VULN_LOW,
    VULN_MEDIUM,
    VULN_HIGH,
    VULN_CRITICAL
} vuln_severity_t;

// Vulnerability types
typedef enum {
    VULN_DANGEROUS_FUNC,      // gets(), strcpy(), etc.
    VULN_FORMAT_STRING,       // printf(user_input)
    VULN_INTEGER_OVERFLOW,    // Potential integer overflow
    VULN_BUFFER_OVERFLOW,     // Potential buffer overflow
    VULN_USE_AFTER_FREE,      // Potential UAF pattern
    VULN_DOUBLE_FREE,         // Potential double free
    VULN_HARDCODED_CREDS,     // Hardcoded credentials
    VULN_WEAK_CRYPTO,         // Weak crypto functions
    VULN_STACK_BUFFER,        // Large stack buffers
    VULN_GOT_OVERWRITE,       // Writable GOT
    VULN_CUSTOM
} vuln_type_t;

// Vulnerability finding
typedef struct {
    vuln_type_t    type;
    vuln_severity_t severity;
    uint64_t       address;
    const char     *function_name;
    const char     *description;
    const char     *recommendation;
    char           details[256];
} vulnerability_t;

// Scan results
typedef struct {
    vulnerability_t *vulns;
    size_t          count;
    size_t          capacity;
} scan_results_t;

// Dangerous function list
typedef struct {
    const char *name;
    const char *safe_alternative;
    vuln_severity_t severity;
    const char *reason;
} dangerous_func_t;

// Scanner configuration
typedef struct {
    bool check_dangerous_funcs;
    bool check_format_strings;
    bool check_integer_ops;
    bool check_crypto;
    bool check_hardcoded;
    bool deep_analysis;
    vuln_severity_t min_severity;
} scanner_config_t;

// Initialize scanner
int scanner_init(scan_results_t *results);
void scanner_cleanup(scan_results_t *results);

// Configure scanner
void scanner_default_config(scanner_config_t *config);

// Scan operations
int scan_dangerous_functions(const elf_file_t *elf, scan_results_t *results);
int scan_format_strings(const elf_file_t *elf, scan_results_t *results);
int scan_crypto_usage(const elf_file_t *elf, scan_results_t *results);
int scan_hardcoded_secrets(const elf_file_t *elf, scan_results_t *results);

// Full scan
int scan_binary(const char *path, const scanner_config_t *config,
                scan_results_t *results);

// Report generation
void print_scan_results(const scan_results_t *results);
int export_scan_json(const scan_results_t *results, const char *path);
int export_scan_sarif(const scan_results_t *results, const char *path);

// Built-in dangerous functions list
extern const dangerous_func_t DANGEROUS_FUNCTIONS[];
extern const size_t DANGEROUS_FUNCTIONS_COUNT;

#endif // ANALYSIS_VULN_SCANNER_H
```

### 2.4 ROP Gadget Finder

```c
// include/analysis/rop_finder.h

#ifndef ANALYSIS_ROP_FINDER_H
#define ANALYSIS_ROP_FINDER_H

#include "elf_parser.h"
#include <stdint.h>
#include <stdbool.h>

// Gadget types
typedef enum {
    GADGET_GENERIC,
    GADGET_POP_REG,           // pop reg; ret
    GADGET_MOV_REG,           // mov reg, reg; ret
    GADGET_ADD_REG,           // add reg, reg; ret
    GADGET_SUB_REG,           // sub reg, reg; ret
    GADGET_XOR_REG,           // xor reg, reg; ret
    GADGET_SYSCALL,           // syscall; ret
    GADGET_INT80,             // int 0x80; ret
    GADGET_CALL_REG,          // call reg
    GADGET_JMP_REG,           // jmp reg
    GADGET_LEAVE_RET,         // leave; ret
    GADGET_WRITE_MEM,         // mov [reg], reg; ret
    GADGET_READ_MEM,          // mov reg, [reg]; ret
} gadget_type_t;

// Register names (x86-64)
typedef enum {
    REG_RAX, REG_RBX, REG_RCX, REG_RDX,
    REG_RSI, REG_RDI, REG_RBP, REG_RSP,
    REG_R8,  REG_R9,  REG_R10, REG_R11,
    REG_R12, REG_R13, REG_R14, REG_R15,
    REG_RIP, REG_NONE
} reg_t;

// ROP gadget
typedef struct {
    uint64_t     address;
    uint8_t      *bytes;
    size_t       length;
    char         *disassembly;
    gadget_type_t type;
    reg_t        regs[4];     // Registers involved
    size_t       reg_count;
} rop_gadget_t;

// Gadget collection
typedef struct {
    rop_gadget_t *gadgets;
    size_t       count;
    size_t       capacity;
} gadget_list_t;

// Finder configuration
typedef struct {
    size_t max_gadget_len;    // Max instructions in gadget
    bool   include_jmp;       // Include jmp gadgets
    bool   include_call;      // Include call gadgets
    bool   color_output;      // ANSI colors
    bool   unique_only;       // Remove duplicates
    reg_t  filter_reg;        // Only gadgets with this reg
} finder_config_t;

// Initialize/cleanup
int gadget_list_init(gadget_list_t *list);
void gadget_list_cleanup(gadget_list_t *list);

// Default configuration
void finder_default_config(finder_config_t *config);

// Find gadgets
int find_gadgets(const elf_file_t *elf, const finder_config_t *config,
                 gadget_list_t *gadgets);

// Search specific gadget types
int find_pop_gadgets(const elf_file_t *elf, reg_t reg, gadget_list_t *gadgets);
int find_syscall_gadgets(const elf_file_t *elf, gadget_list_t *gadgets);
int find_write_gadgets(const elf_file_t *elf, gadget_list_t *gadgets);

// Gadget search by pattern
int search_gadget_pattern(const elf_file_t *elf, const char *pattern,
                          gadget_list_t *gadgets);

// Output
void print_gadget(const rop_gadget_t *gadget, bool color);
void print_gadget_list(const gadget_list_t *gadgets, bool color);
int export_gadgets_json(const gadget_list_t *gadgets, const char *path);

// One-gadget finder (execve gadgets)
int find_one_gadgets(const elf_file_t *libc, gadget_list_t *gadgets);

// Utility
const char *reg_name(reg_t reg);
const char *gadget_type_name(gadget_type_t type);

#endif // ANALYSIS_ROP_FINDER_H
```

---

## Partie 3: Network Module (2.9.40)

### 3.1 Port Scanner

```c
// include/network/port_scanner.h

#ifndef NETWORK_PORT_SCANNER_H
#define NETWORK_PORT_SCANNER_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

// Port states
typedef enum {
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED,
    PORT_UNKNOWN
} port_state_t;

// Scan types
typedef enum {
    SCAN_TCP_CONNECT,         // Full TCP connect
    SCAN_TCP_SYN,             // SYN scan (needs root)
    SCAN_TCP_FIN,             // FIN scan
    SCAN_TCP_XMAS,            // Xmas scan
    SCAN_TCP_NULL,            // Null scan
    SCAN_UDP                  // UDP scan
} scan_type_t;

// Service info
typedef struct {
    uint16_t     port;
    port_state_t state;
    char         service_name[64];
    char         version[128];
    bool         is_ssl;
} port_result_t;

// Scan results
typedef struct {
    char          target[256];
    struct in_addr addr;
    port_result_t *ports;
    size_t        port_count;
    uint64_t      scan_time_ms;
    bool          host_up;
} scan_result_t;

// Scanner configuration
typedef struct {
    scan_type_t type;
    uint16_t    *ports;           // NULL = default ports
    size_t      port_count;
    uint32_t    timeout_ms;
    uint32_t    retry_count;
    bool        service_detection;
    bool        version_detection;
    uint32_t    max_parallel;
    bool        randomize_ports;
} scanner_config_t;

// Port ranges
typedef struct {
    uint16_t start;
    uint16_t end;
} port_range_t;

// Initialize scanner
int port_scanner_init(void);
void port_scanner_cleanup(void);

// Configuration
void scanner_default_config(scanner_config_t *config);
int scanner_set_port_range(scanner_config_t *config, uint16_t start, uint16_t end);
int scanner_set_ports(scanner_config_t *config, const uint16_t *ports, size_t count);
int scanner_parse_ports(scanner_config_t *config, const char *spec);

// Scanning
int scan_host(const char *target, const scanner_config_t *config,
              scan_result_t *result);
int scan_network(const char *cidr, const scanner_config_t *config,
                 scan_result_t **results, size_t *count);

// Service detection
int detect_service(const char *host, uint16_t port, char *service, size_t len);
int grab_banner(const char *host, uint16_t port, char *banner, size_t len);

// Results
void print_scan_result(const scan_result_t *result);
void free_scan_result(scan_result_t *result);
int export_scan_xml(const scan_result_t *result, const char *path);

// Common port lists
extern const uint16_t TOP_100_PORTS[];
extern const uint16_t TOP_1000_PORTS[];
extern const size_t TOP_100_COUNT;
extern const size_t TOP_1000_COUNT;

// Service name lookup
const char *port_service_name(uint16_t port, const char *proto);

#endif // NETWORK_PORT_SCANNER_H
```

### 3.2 Packet Capture

```c
// include/network/packet_capture.h

#ifndef NETWORK_PACKET_CAPTURE_H
#define NETWORK_PACKET_CAPTURE_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// Packet info
typedef struct {
    struct timeval timestamp;
    uint32_t       length;
    uint32_t       caplen;
    uint8_t        *data;

    // Parsed layers
    struct {
        bool       valid;
        uint8_t    src_mac[6];
        uint8_t    dst_mac[6];
        uint16_t   ethertype;
    } eth;

    struct {
        bool       valid;
        uint8_t    version;
        uint32_t   src_ip;
        uint32_t   dst_ip;
        uint8_t    protocol;
        uint16_t   total_len;
        uint8_t    ttl;
    } ip;

    struct {
        bool       valid;
        uint16_t   src_port;
        uint16_t   dst_port;
        uint32_t   seq;
        uint32_t   ack;
        uint8_t    flags;
        uint16_t   window;
        uint8_t    *payload;
        size_t     payload_len;
    } tcp;

    struct {
        bool       valid;
        uint16_t   src_port;
        uint16_t   dst_port;
        uint16_t   length;
        uint8_t    *payload;
        size_t     payload_len;
    } udp;

} packet_t;

// Capture handle
typedef struct capture_handle capture_handle_t;

// Capture configuration
typedef struct {
    const char *interface;
    const char *filter;           // BPF filter
    bool       promiscuous;
    uint32_t   snaplen;
    uint32_t   timeout_ms;
    uint32_t   buffer_size;
} capture_config_t;

// Packet callback
typedef void (*packet_callback_t)(const packet_t *pkt, void *user_data);

// Statistics
typedef struct {
    uint64_t packets_received;
    uint64_t packets_dropped;
    uint64_t bytes_received;
} capture_stats_t;

// Initialize/cleanup
int capture_init(void);
void capture_cleanup(void);

// Capture operations
capture_handle_t *capture_open(const capture_config_t *config);
void capture_close(capture_handle_t *handle);

// Live capture
int capture_start(capture_handle_t *handle, packet_callback_t callback,
                  void *user_data);
int capture_stop(capture_handle_t *handle);
int capture_next(capture_handle_t *handle, packet_t *pkt);

// File operations
capture_handle_t *capture_open_file(const char *path);
int capture_save_file(capture_handle_t *handle, const char *path);

// Filtering
int capture_set_filter(capture_handle_t *handle, const char *filter);

// Statistics
int capture_get_stats(capture_handle_t *handle, capture_stats_t *stats);

// Packet parsing
int packet_parse(const uint8_t *data, size_t len, packet_t *pkt);
void packet_free(packet_t *pkt);

// Utility
void packet_print(const packet_t *pkt);
void packet_hexdump(const uint8_t *data, size_t len);
const char *ip_to_str(uint32_t ip);
const char *tcp_flags_str(uint8_t flags);

// Interface listing
int list_interfaces(char ***names, size_t *count);
void free_interface_list(char **names, size_t count);

#endif // NETWORK_PACKET_CAPTURE_H
```

### 3.3 TLS Analyzer

```c
// include/network/tls_analyzer.h

#ifndef NETWORK_TLS_ANALYZER_H
#define NETWORK_TLS_ANALYZER_H

#include <stdint.h>
#include <stdbool.h>

// TLS versions
typedef enum {
    TLS_VERSION_SSL30 = 0x0300,
    TLS_VERSION_TLS10 = 0x0301,
    TLS_VERSION_TLS11 = 0x0302,
    TLS_VERSION_TLS12 = 0x0303,
    TLS_VERSION_TLS13 = 0x0304
} tls_version_t;

// Certificate info
typedef struct {
    char     subject[256];
    char     issuer[256];
    char     serial[64];
    char     not_before[32];
    char     not_after[32];
    char     fingerprint_sha256[65];
    char     public_key_algo[32];
    uint32_t key_bits;
    char     signature_algo[64];
    bool     is_self_signed;
    bool     is_expired;
    bool     is_not_yet_valid;
} cert_info_t;

// Cipher suite info
typedef struct {
    uint16_t id;
    char     name[64];
    char     kx_algo[32];      // Key exchange
    char     auth_algo[32];    // Authentication
    char     enc_algo[32];     // Encryption
    char     mac_algo[32];     // MAC
    uint16_t key_bits;
    bool     is_weak;
    bool     supports_pfs;     // Perfect forward secrecy
} cipher_info_t;

// TLS analysis result
typedef struct {
    bool           connected;
    tls_version_t  version;
    char           version_str[16];

    // Certificate chain
    cert_info_t    *certs;
    size_t         cert_count;

    // Negotiated cipher
    cipher_info_t  cipher;

    // Supported versions (from server)
    tls_version_t  *supported_versions;
    size_t         version_count;

    // Supported ciphers
    cipher_info_t  *supported_ciphers;
    size_t         cipher_count;

    // Extensions
    bool           supports_sni;
    bool           supports_alpn;
    bool           supports_ocsp;
    bool           supports_scts;

    // Vulnerabilities
    bool           vulnerable_heartbleed;
    bool           vulnerable_robot;
    bool           vulnerable_crime;
    bool           vulnerable_poodle;
    bool           supports_insecure_renegotiation;

    // Ratings
    int            grade;              // A+ to F
    char           grade_str[4];
} tls_result_t;

// Configuration
typedef struct {
    uint32_t timeout_ms;
    bool     check_vulnerabilities;
    bool     enumerate_ciphers;
    const char *sni;
} tls_config_t;

// Initialize
void tls_analyzer_init(void);
void tls_analyzer_cleanup(void);

// Configuration
void tls_default_config(tls_config_t *config);

// Analysis
int tls_analyze(const char *host, uint16_t port, const tls_config_t *config,
                tls_result_t *result);
void tls_result_free(tls_result_t *result);

// Certificate operations
int tls_get_certificate(const char *host, uint16_t port, cert_info_t *cert);
int tls_verify_certificate(const cert_info_t *cert, const char *hostname);
int tls_check_certificate_chain(const cert_info_t *certs, size_t count);

// Cipher testing
int tls_test_cipher(const char *host, uint16_t port, uint16_t cipher_id,
                    bool *supported);
int tls_enumerate_ciphers(const char *host, uint16_t port,
                          cipher_info_t **ciphers, size_t *count);

// Vulnerability tests
int tls_test_heartbleed(const char *host, uint16_t port, bool *vulnerable);
int tls_test_robot(const char *host, uint16_t port, bool *vulnerable);

// Output
void tls_print_result(const tls_result_t *result);
int tls_export_json(const tls_result_t *result, const char *path);

// Utility
const char *tls_version_str(tls_version_t version);
const char *cipher_name(uint16_t id);
bool is_cipher_weak(uint16_t id);

#endif // NETWORK_TLS_ANALYZER_H
```

---

## Partie 4: Web Security Module (2.9.32 - 2.9.39)

### 4.1 HTTP Client

```c
// include/web/http_client.h

#ifndef WEB_HTTP_CLIENT_H
#define WEB_HTTP_CLIENT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// HTTP methods
typedef enum {
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_HEAD,
    HTTP_OPTIONS,
    HTTP_PATCH
} http_method_t;

// HTTP header
typedef struct {
    char *name;
    char *value;
} http_header_t;

// HTTP request
typedef struct {
    http_method_t method;
    char          *url;
    http_header_t *headers;
    size_t        header_count;
    uint8_t       *body;
    size_t        body_len;
    char          *content_type;
} http_request_t;

// HTTP response
typedef struct {
    int           status_code;
    char          *status_text;
    http_header_t *headers;
    size_t        header_count;
    uint8_t       *body;
    size_t        body_len;
    char          *content_type;
    bool          is_redirect;
    char          *redirect_url;
} http_response_t;

// HTTP client configuration
typedef struct {
    uint32_t connect_timeout_ms;
    uint32_t read_timeout_ms;
    bool     follow_redirects;
    uint32_t max_redirects;
    bool     verify_ssl;
    const char *proxy;
    const char *user_agent;
    bool     keep_alive;
} http_config_t;

// Client handle
typedef struct http_client http_client_t;

// Cookie
typedef struct {
    char     *name;
    char     *value;
    char     *domain;
    char     *path;
    bool     secure;
    bool     http_only;
    bool     same_site_strict;
    bool     same_site_lax;
    uint64_t expires;
} http_cookie_t;

// Initialize
http_client_t *http_client_new(const http_config_t *config);
void http_client_free(http_client_t *client);
void http_default_config(http_config_t *config);

// Request building
http_request_t *http_request_new(http_method_t method, const char *url);
void http_request_free(http_request_t *req);
int http_request_add_header(http_request_t *req, const char *name, const char *value);
int http_request_set_body(http_request_t *req, const void *data, size_t len,
                          const char *content_type);
int http_request_set_json(http_request_t *req, const char *json);
int http_request_set_form(http_request_t *req, const char *data);

// Request execution
int http_execute(http_client_t *client, const http_request_t *req,
                 http_response_t *resp);
void http_response_free(http_response_t *resp);

// Convenience methods
int http_get(http_client_t *client, const char *url, http_response_t *resp);
int http_post(http_client_t *client, const char *url, const char *body,
              const char *content_type, http_response_t *resp);

// Header access
const char *http_response_get_header(const http_response_t *resp, const char *name);
int http_response_get_headers(const http_response_t *resp, const char *name,
                              const char ***values, size_t *count);

// Cookie management
int http_client_set_cookie(http_client_t *client, const http_cookie_t *cookie);
int http_client_get_cookies(http_client_t *client, http_cookie_t **cookies,
                            size_t *count);
int http_parse_set_cookie(const char *header, http_cookie_t *cookie);
void http_cookie_free(http_cookie_t *cookie);

// URL utilities
int http_url_encode(const char *input, char *output, size_t out_len);
int http_url_decode(const char *input, char *output, size_t out_len);
int http_parse_url(const char *url, char *scheme, char *host, uint16_t *port,
                   char *path, char *query);

#endif // WEB_HTTP_CLIENT_H
```

### 4.2 Security Header Analyzer

```c
// include/web/header_analyzer.h

#ifndef WEB_HEADER_ANALYZER_H
#define WEB_HEADER_ANALYZER_H

#include "http_client.h"

// Header security rating
typedef enum {
    HEADER_MISSING,
    HEADER_INSECURE,
    HEADER_WEAK,
    HEADER_GOOD,
    HEADER_EXCELLENT
} header_rating_t;

// Content-Security-Policy analysis
typedef struct {
    bool     present;
    bool     has_default_src;
    bool     has_script_src;
    bool     has_style_src;
    bool     has_img_src;
    bool     has_frame_ancestors;
    bool     allows_unsafe_inline;
    bool     allows_unsafe_eval;
    bool     allows_data_uri;
    bool     report_only;
    char     *report_uri;
    header_rating_t rating;
    char     recommendation[512];
} csp_analysis_t;

// Strict-Transport-Security analysis
typedef struct {
    bool     present;
    uint32_t max_age;
    bool     include_subdomains;
    bool     preload;
    header_rating_t rating;
    char     recommendation[256];
} hsts_analysis_t;

// Cookie security analysis
typedef struct {
    char     *name;
    bool     secure;
    bool     http_only;
    bool     same_site_strict;
    bool     same_site_lax;
    bool     same_site_none;
    bool     has_expires;
    bool     session_cookie;
    header_rating_t rating;
    char     issues[256];
} cookie_security_t;

// Full header analysis
typedef struct {
    // Response info
    int      status_code;
    bool     is_https;

    // Security headers
    csp_analysis_t  csp;
    hsts_analysis_t hsts;

    struct {
        bool present;
        char value[64];
        header_rating_t rating;
    } x_frame_options;

    struct {
        bool present;
        char value[64];
        header_rating_t rating;
    } x_content_type_options;

    struct {
        bool present;
        char value[64];
        header_rating_t rating;
    } x_xss_protection;

    struct {
        bool present;
        char value[64];
        header_rating_t rating;
    } referrer_policy;

    struct {
        bool present;
        char value[256];
        header_rating_t rating;
    } permissions_policy;

    // Cookie analysis
    cookie_security_t *cookies;
    size_t            cookie_count;

    // Information disclosure
    bool     server_header_present;
    char     server_value[128];
    bool     x_powered_by_present;
    char     x_powered_by_value[128];

    // Overall rating
    int      score;           // 0-100
    char     grade;           // A-F

} header_analysis_t;

// Analyze security headers
int analyze_headers(const http_response_t *resp, bool is_https,
                    header_analysis_t *analysis);
void header_analysis_free(header_analysis_t *analysis);

// Individual header analysis
int analyze_csp(const char *value, csp_analysis_t *result);
int analyze_hsts(const char *value, hsts_analysis_t *result);
int analyze_cookie_security(const http_cookie_t *cookie, cookie_security_t *result);

// URL-based analysis
int analyze_url_headers(const char *url, header_analysis_t *analysis);

// Output
void print_header_analysis(const header_analysis_t *analysis);
int export_header_json(const header_analysis_t *analysis, const char *path);

// Recommendations
void generate_csp_recommendation(const csp_analysis_t *current, char *recommended,
                                  size_t len);
void generate_security_headers(char *headers, size_t len);

// Utility
const char *header_rating_str(header_rating_t rating);
const char *header_rating_color(header_rating_t rating);

#endif // WEB_HEADER_ANALYZER_H
```

### 4.3 Vulnerability Tests

```c
// include/web/vuln_tests.h

#ifndef WEB_VULN_TESTS_H
#define WEB_VULN_TESTS_H

#include "http_client.h"
#include <stdbool.h>

// Vulnerability types
typedef enum {
    WEB_VULN_SQLI,
    WEB_VULN_XSS_REFLECTED,
    WEB_VULN_XSS_STORED,
    WEB_VULN_CSRF,
    WEB_VULN_OPEN_REDIRECT,
    WEB_VULN_PATH_TRAVERSAL,
    WEB_VULN_SSRF,
    WEB_VULN_IDOR,
    WEB_VULN_INFO_DISCLOSURE,
    WEB_VULN_SENSITIVE_DATA,
    WEB_VULN_BROKEN_AUTH,
    WEB_VULN_INSECURE_DESERIALIZATION
} web_vuln_type_t;

// Test result
typedef struct {
    web_vuln_type_t type;
    bool            vulnerable;
    char            *url;
    char            *parameter;
    char            *payload;
    char            *evidence;
    char            *description;
    char            *remediation;
    int             confidence;   // 0-100
    int             severity;     // 1-4 (low to critical)
} vuln_test_result_t;

// Test results collection
typedef struct {
    vuln_test_result_t *results;
    size_t             count;
    size_t             capacity;
} web_scan_results_t;

// Scanner configuration
typedef struct {
    bool     test_sqli;
    bool     test_xss;
    bool     test_csrf;
    bool     test_traversal;
    bool     test_redirect;
    bool     follow_forms;
    bool     follow_links;
    uint32_t max_depth;
    uint32_t max_requests;
    const char **exclude_patterns;
    size_t   exclude_count;
} web_scanner_config_t;

// Initialize
int web_scanner_init(web_scan_results_t *results);
void web_scanner_cleanup(web_scan_results_t *results);
void web_scanner_default_config(web_scanner_config_t *config);

// Individual tests
int test_sqli(http_client_t *client, const char *url, const char *param,
              vuln_test_result_t *result);
int test_sqli_time_based(http_client_t *client, const char *url, const char *param,
                         vuln_test_result_t *result);
int test_xss_reflected(http_client_t *client, const char *url, const char *param,
                       vuln_test_result_t *result);
int test_open_redirect(http_client_t *client, const char *url,
                       vuln_test_result_t *result);
int test_path_traversal(http_client_t *client, const char *url,
                        vuln_test_result_t *result);
int test_ssrf(http_client_t *client, const char *url, const char *param,
              vuln_test_result_t *result);

// Full scan
int scan_url(http_client_t *client, const char *url,
             const web_scanner_config_t *config, web_scan_results_t *results);
int scan_form(http_client_t *client, const char *form_url,
              const web_scanner_config_t *config, web_scan_results_t *results);

// Fuzzing
typedef struct {
    const char **payloads;
    size_t     payload_count;
    const char *success_pattern;
    const char *error_pattern;
} fuzz_config_t;

int fuzz_parameter(http_client_t *client, const char *url, const char *param,
                   const fuzz_config_t *config, web_scan_results_t *results);

// Output
void print_web_results(const web_scan_results_t *results);
int export_web_results_json(const web_scan_results_t *results, const char *path);
int export_web_results_html(const web_scan_results_t *results, const char *path);

// Payload lists
extern const char *SQLI_PAYLOADS[];
extern const size_t SQLI_PAYLOAD_COUNT;
extern const char *XSS_PAYLOADS[];
extern const size_t XSS_PAYLOAD_COUNT;
extern const char *TRAVERSAL_PAYLOADS[];
extern const size_t TRAVERSAL_PAYLOAD_COUNT;

// Utility
const char *vuln_type_name(web_vuln_type_t type);
int severity_from_type(web_vuln_type_t type);

#endif // WEB_VULN_TESTS_H
```

---

## Partie 5: Audit Module (2.9.42 - 2.9.45)

### 5.1 Configuration Checker

```c
// include/audit/config_checker.h

#ifndef AUDIT_CONFIG_CHECKER_H
#define AUDIT_CONFIG_CHECKER_H

#include <stdbool.h>
#include <stddef.h>

// Check severity
typedef enum {
    CHECK_INFO,
    CHECK_LOW,
    CHECK_MEDIUM,
    CHECK_HIGH,
    CHECK_CRITICAL
} check_severity_t;

// Check result
typedef struct {
    const char      *check_id;
    const char      *title;
    const char      *description;
    check_severity_t severity;
    bool            passed;
    char            *actual_value;
    char            *expected_value;
    char            *remediation;
} check_result_t;

// Audit results
typedef struct {
    check_result_t *checks;
    size_t         count;
    size_t         capacity;
    size_t         passed;
    size_t         failed;
    int            score;         // 0-100
} audit_results_t;

// System checks
typedef struct {
    bool check_sshd;
    bool check_firewall;
    bool check_permissions;
    bool check_services;
    bool check_users;
    bool check_kernel;
    bool check_network;
    bool check_logging;
} system_check_config_t;

// Initialize
int audit_init(audit_results_t *results);
void audit_cleanup(audit_results_t *results);

// System security checks
int check_sshd_config(audit_results_t *results);
int check_firewall_config(audit_results_t *results);
int check_file_permissions(audit_results_t *results);
int check_running_services(audit_results_t *results);
int check_user_accounts(audit_results_t *results);
int check_kernel_params(audit_results_t *results);
int check_network_config(audit_results_t *results);
int check_logging_config(audit_results_t *results);

// Full system audit
int audit_system(const system_check_config_t *config, audit_results_t *results);

// SSH-specific checks
int check_ssh_root_login(check_result_t *result);
int check_ssh_password_auth(check_result_t *result);
int check_ssh_protocol_version(check_result_t *result);
int check_ssh_key_permissions(check_result_t *result);

// Firewall checks
int check_iptables_default_policy(check_result_t *result);
int check_open_ports(check_result_t *result);

// Permission checks
int check_world_writable(check_result_t *result);
int check_suid_binaries(check_result_t *result);
int check_tmp_noexec(check_result_t *result);

// User checks
int check_empty_passwords(check_result_t *result);
int check_password_aging(check_result_t *result);
int check_sudoers(check_result_t *result);

// Output
void print_audit_results(const audit_results_t *results);
int export_audit_json(const audit_results_t *results, const char *path);
int export_audit_html(const audit_results_t *results, const char *path);

// CIS benchmark style
void print_audit_summary(const audit_results_t *results);

#endif // AUDIT_CONFIG_CHECKER_H
```

### 5.2 Report Generator

```c
// include/audit/report_gen.h

#ifndef AUDIT_REPORT_GEN_H
#define AUDIT_REPORT_GEN_H

#include <stddef.h>
#include <time.h>

// Report sections
typedef enum {
    SECTION_EXECUTIVE_SUMMARY,
    SECTION_SCOPE,
    SECTION_METHODOLOGY,
    SECTION_FINDINGS,
    SECTION_RISK_ASSESSMENT,
    SECTION_RECOMMENDATIONS,
    SECTION_APPENDIX
} report_section_t;

// Finding structure
typedef struct {
    char     *id;
    char     *title;
    char     *description;
    int      severity;            // 1-4
    char     *cvss_score;
    char     *affected_component;
    char     *proof_of_concept;
    char     *impact;
    char     *remediation;
    char     **references;
    size_t   ref_count;
    char     **screenshots;
    size_t   screenshot_count;
} report_finding_t;

// Report metadata
typedef struct {
    char     *title;
    char     *client;
    char     *assessor;
    char     *version;
    time_t   start_date;
    time_t   end_date;
    char     *scope;
    char     *methodology;
} report_metadata_t;

// Full report
typedef struct {
    report_metadata_t metadata;
    char              *executive_summary;
    report_finding_t  *findings;
    size_t            finding_count;
    char              *risk_summary;
    char              **recommendations;
    size_t            rec_count;
} security_report_t;

// Report format
typedef enum {
    FORMAT_JSON,
    FORMAT_HTML,
    FORMAT_PDF,
    FORMAT_MARKDOWN,
    FORMAT_SARIF
} report_format_t;

// Initialize report
int report_init(security_report_t *report);
void report_cleanup(security_report_t *report);

// Metadata
int report_set_metadata(security_report_t *report, const report_metadata_t *meta);

// Findings
int report_add_finding(security_report_t *report, const report_finding_t *finding);
int report_sort_findings_by_severity(security_report_t *report);
int report_filter_findings(security_report_t *report, int min_severity);

// Summary generation
int report_generate_executive_summary(security_report_t *report);
int report_generate_risk_summary(security_report_t *report);

// Export
int report_export(const security_report_t *report, report_format_t format,
                  const char *path);
int report_export_json(const security_report_t *report, const char *path);
int report_export_html(const security_report_t *report, const char *path);
int report_export_markdown(const security_report_t *report, const char *path);
int report_export_sarif(const security_report_t *report, const char *path);

// Templates
int report_load_template(const char *template_path);
int report_apply_template(security_report_t *report, const char *template_name);

// Statistics
typedef struct {
    size_t critical_count;
    size_t high_count;
    size_t medium_count;
    size_t low_count;
    size_t info_count;
    double avg_cvss;
    int    overall_risk;
} report_stats_t;

int report_calculate_stats(const security_report_t *report, report_stats_t *stats);

// Utility
const char *severity_to_string(int severity);
const char *severity_to_color(int severity);
time_t report_parse_date(const char *date_str);

#endif // AUDIT_REPORT_GEN_H
```

---

## Partie 6: Main CLI

```c
// src/main.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "common/types.h"

// Tool modes
typedef enum {
    MODE_NONE,
    MODE_BINSCAN,
    MODE_NETSCAN,
    MODE_WEBSCAN,
    MODE_AUDIT,
    MODE_REPORT
} tool_mode_t;

static void print_banner(void) {
    printf("\n");
    printf("  ____                       _ _           _____           _ _    _ _   \n");
    printf(" / ___|  ___  ___ _   _ _ __(_) |_ _   _  |_   _|__   ___ | | | _(_) |_ \n");
    printf(" \\___ \\ / _ \\/ __| | | | '__| | __| | | |   | |/ _ \\ / _ \\| | |/ / | __|\n");
    printf("  ___) |  __/ (__| |_| | |  | | |_| |_| |   | | (_) | (_) | |   <| | |_ \n");
    printf(" |____/ \\___|\\___|\\__,_|_|  |_|\\__|\\__, |   |_|\\___/ \\___/|_|_|\\_\\_|\\__|\n");
    printf("                                   |___/                               \n");
    printf("\n");
    printf(" Security Analysis Toolkit - Module 2.9 Project\n");
    printf(" Version 1.0.0\n");
    printf("\n");
}

static void print_usage(const char *prog) {
    printf("Usage: %s <mode> [options]\n\n", prog);
    printf("Modes:\n");
    printf("  binscan   - Binary security analysis\n");
    printf("  netscan   - Network scanning and analysis\n");
    printf("  webscan   - Web application security testing\n");
    printf("  audit     - System security audit\n");
    printf("  report    - Generate security report\n");
    printf("\nRun '%s <mode> --help' for mode-specific options\n", prog);
}

static void print_binscan_usage(void) {
    printf("Binary Scanner Usage:\n");
    printf("  binscan [options] <binary>\n\n");
    printf("Options:\n");
    printf("  -c, --checksec      Show security protections\n");
    printf("  -g, --gadgets       Find ROP gadgets\n");
    printf("  -v, --vulns         Scan for vulnerabilities\n");
    printf("  -s, --symbols       List symbols\n");
    printf("  -a, --all           Full analysis\n");
    printf("  -o, --output FILE   Output file (JSON)\n");
}

static void print_netscan_usage(void) {
    printf("Network Scanner Usage:\n");
    printf("  netscan [options] <target>\n\n");
    printf("Options:\n");
    printf("  -p, --ports SPEC    Port specification (e.g., 1-1000,8080)\n");
    printf("  -t, --type TYPE     Scan type (tcp/syn/udp)\n");
    printf("  -T, --tls           Analyze TLS configuration\n");
    printf("  -C, --capture       Packet capture mode\n");
    printf("  -o, --output FILE   Output file\n");
}

static void print_webscan_usage(void) {
    printf("Web Scanner Usage:\n");
    printf("  webscan [options] <url>\n\n");
    printf("Options:\n");
    printf("  -H, --headers       Analyze security headers\n");
    printf("  -S, --sqli          Test for SQL injection\n");
    printf("  -X, --xss           Test for XSS\n");
    printf("  -F, --full          Full vulnerability scan\n");
    printf("  -o, --output FILE   Output file\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_banner();
        print_usage(argv[0]);
        return 1;
    }

    tool_mode_t mode = MODE_NONE;

    if (strcmp(argv[1], "binscan") == 0) {
        mode = MODE_BINSCAN;
    } else if (strcmp(argv[1], "netscan") == 0) {
        mode = MODE_NETSCAN;
    } else if (strcmp(argv[1], "webscan") == 0) {
        mode = MODE_WEBSCAN;
    } else if (strcmp(argv[1], "audit") == 0) {
        mode = MODE_AUDIT;
    } else if (strcmp(argv[1], "report") == 0) {
        mode = MODE_REPORT;
    } else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_banner();
        print_usage(argv[0]);
        return 0;
    } else {
        fprintf(stderr, "Unknown mode: %s\n", argv[1]);
        return 1;
    }

    // Shift arguments
    argc--;
    argv++;

    // Handle mode-specific help
    if (argc > 1 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        switch (mode) {
            case MODE_BINSCAN: print_binscan_usage(); break;
            case MODE_NETSCAN: print_netscan_usage(); break;
            case MODE_WEBSCAN: print_webscan_usage(); break;
            default: print_usage(argv[0]); break;
        }
        return 0;
    }

    // Execute mode
    int result = 0;
    switch (mode) {
        case MODE_BINSCAN:
            result = binscan_main(argc, argv);
            break;
        case MODE_NETSCAN:
            result = netscan_main(argc, argv);
            break;
        case MODE_WEBSCAN:
            result = webscan_main(argc, argv);
            break;
        case MODE_AUDIT:
            result = audit_main(argc, argv);
            break;
        case MODE_REPORT:
            result = report_main(argc, argv);
            break;
        default:
            result = 1;
    }

    return result;
}
```

---

## Partie 7: Makefile

```makefile
# Security Toolkit Makefile

CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c17 -O2 -fstack-protector-strong
CFLAGS += -D_FORTIFY_SOURCE=2 -fPIE
LDFLAGS = -pie -Wl,-z,relro,-z,now
LIBS = -lssl -lcrypto -lpcap -lcapstone

# Directories
SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin
TESTDIR = tests

# Source files
CRYPTO_SRC = $(wildcard $(SRCDIR)/crypto/*.c)
ANALYSIS_SRC = $(wildcard $(SRCDIR)/analysis/*.c)
NETWORK_SRC = $(wildcard $(SRCDIR)/network/*.c)
WEB_SRC = $(wildcard $(SRCDIR)/web/*.c)
AUDIT_SRC = $(wildcard $(SRCDIR)/audit/*.c)
MAIN_SRC = $(SRCDIR)/main.c

ALL_SRC = $(CRYPTO_SRC) $(ANALYSIS_SRC) $(NETWORK_SRC) $(WEB_SRC) $(AUDIT_SRC) $(MAIN_SRC)
ALL_OBJ = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(ALL_SRC))

# Target
TARGET = $(BINDIR)/sectool

# Test files
TEST_SRC = $(wildcard $(TESTDIR)/*.c)
TEST_BIN = $(patsubst $(TESTDIR)/%.c,$(BINDIR)/%,$(TEST_SRC))

.PHONY: all clean test install

all: dirs $(TARGET)

dirs:
	@mkdir -p $(OBJDIR)/crypto $(OBJDIR)/analysis $(OBJDIR)/network
	@mkdir -p $(OBJDIR)/web $(OBJDIR)/audit $(BINDIR)

$(TARGET): $(ALL_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -I$(INCDIR) -c -o $@ $<

# Tests
test: $(TEST_BIN)
	@for test in $(TEST_BIN); do \
		echo "Running $$test..."; \
		$$test || exit 1; \
	done

$(BINDIR)/test_%: $(TESTDIR)/test_%.c $(ALL_OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -I$(INCDIR) -o $@ $< \
		$(filter-out $(OBJDIR)/main.o,$(ALL_OBJ)) $(LIBS)

# Security analysis of self
analyze: $(TARGET)
	./$(TARGET) binscan --all $(TARGET)

clean:
	rm -rf $(OBJDIR) $(BINDIR)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

# Individual tools
binscan: dirs $(TARGET)
	@echo "Binary scanner ready: $(TARGET) binscan"

netscan: dirs $(TARGET)
	@echo "Network scanner ready: $(TARGET) netscan"

webscan: dirs $(TARGET)
	@echo "Web scanner ready: $(TARGET) webscan"

# Debug build
debug: CFLAGS += -g -DDEBUG -fsanitize=address
debug: LDFLAGS += -fsanitize=address
debug: all

# Documentation
docs:
	doxygen Doxyfile
```

---

## Criteres de Validation

### Fonctionnels
- [ ] Crypto module: AES, SHA-256, HMAC implementation correcte
- [ ] Binary analysis: ELF parsing, protection detection
- [ ] ROP finder: Trouve gadgets valides
- [ ] Port scanner: TCP/UDP scanning fonctionnel
- [ ] TLS analyzer: Detection des vulnerabilites
- [ ] Web scanner: Detection SQLi, XSS basique
- [ ] Audit: Checks systeme pertinents
- [ ] Reports: Export JSON/HTML/SARIF

### Securite
- [ ] Code compile avec protections (canary, PIE, RELRO)
- [ ] Pas de vulnerabilites dans le code du toolkit
- [ ] Input validation partout
- [ ] Gestion memoire securisee
- [ ] Pas de secrets hardcodes

### Qualite
- [ ] Tests unitaires pour chaque module
- [ ] Documentation complete
- [ ] Code style coherent
- [ ] Pas de memory leaks (valgrind clean)
- [ ] Gestion d'erreurs robuste

---

## Livrables

1. **Code source complet** avec structure modulaire
2. **Suite de tests** comprehensive
3. **Documentation** d'utilisation
4. **Exemples** d'utilisation pour chaque mode
5. **Samples vulnerables** pour tests

## Ressources

- libcapstone pour disassembly
- libpcap pour capture reseau
- OpenSSL pour TLS
- Documentation ELF
- OWASP Testing Guide
- CIS Benchmarks

---

## Note Pedagogique

Ce projet integre tous les concepts de securite informatique du Module 2.9:
- Cryptographie (implementation et bonnes pratiques)
- Exploitation binaire (analyse et detection)
- Securite reseau (scanning et analyse TLS)
- Securite web (detection de vulnerabilites)
- Audit de securite (verification de configurations)

L'etudiant doit demontrer une comprehension approfondie de chaque domaine pour implementer correctement ces outils.
