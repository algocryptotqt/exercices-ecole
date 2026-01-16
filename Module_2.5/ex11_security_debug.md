# ex11: Network Security & Debugging

**Module**: 2.5 - Networking
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 96/100

## Concepts Couverts

### 2.5.25: Network Security Basics (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Man-in-the-middle | Interception |
| b | ARP spoofing | Layer 2 attack |
| c | DNS spoofing | Redirect domains |
| d | IP spoofing | Fake source |
| e | SYN flood | DoS attack |
| f | Port scanning | nmap |
| g | Firewalls | Packet filtering |
| h | Network segmentation | VLANs |

### 2.5.26: TLS/SSL Overview (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | TLS | Transport Layer Security |
| b | Handshake | Key exchange |
| c | Certificates | Identity verification |
| d | Cipher suites | Algorithms |
| e | OpenSSL | Library |
| f | SSL_CTX | Context |
| g | SSL_new() | Connection |
| h | SSL_connect/accept() | Handshake |
| i | SSL_read/write() | Encrypted I/O |

### 2.5.27: Network Debugging (10+ concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | ping | ICMP echo |
| b | traceroute | Path discovery |
| c | netstat | Connection status |
| d | ss | Socket statistics |
| e | tcpdump | Packet capture |
| f | wireshark | GUI analysis |
| g | nmap | Port scanning |
| h | nc (netcat) | Swiss army knife |
| i | curl | HTTP client |
| j | dig/nslookup | DNS queries |

---

## Sujet

Comprendre la securite reseau et maitriser les outils de diagnostic.

### Structures

```c
#include <openssl/ssl.h>
#include <openssl/err.h>

// Port scan result
typedef struct {
    uint16_t port;
    bool open;
    const char *service;
    double response_time_ms;
} port_scan_result_t;

// TLS connection
typedef struct {
    int fd;
    SSL_CTX *ctx;              // f: Context
    SSL *ssl;                  // g: Connection
    char *cipher;              // d: Cipher suite
    char *cert_subject;        // c: Certificate
    bool connected;
} tls_conn_t;

// Network diagnostic
typedef struct {
    char local_addr[64];
    char remote_addr[64];
    uint16_t local_port;
    uint16_t remote_port;
    char state[32];
    pid_t pid;
    char program[256];
} connection_info_t;
```

### API

```c
// ============== SECURITY ANALYSIS ==============
// 2.5.25

// 2.5.25.f: Port scanning
int port_scan_connect(const char *host, uint16_t start, uint16_t end,
                      port_scan_result_t *results, int *count);
int port_scan_syn(const char *host, uint16_t start, uint16_t end,
                  port_scan_result_t *results, int *count);  // Requires root
const char *port_to_service(uint16_t port);

// Attack detection (defensive)
typedef struct {
    bool syn_flood_detected;
    bool arp_spoof_detected;
    int suspicious_packets;
} threat_info_t;

int monitor_threats(const char *interface, int duration_sec, threat_info_t *info);

// ============== TLS/SSL ==============
// 2.5.26

// 2.5.26.e-f: Initialize OpenSSL
int tls_init(void);
void tls_cleanup(void);
SSL_CTX *tls_ctx_create_client(void);
SSL_CTX *tls_ctx_create_server(const char *cert_file, const char *key_file);
void tls_ctx_free(SSL_CTX *ctx);

// 2.5.26.g-i: Connection
int tls_connect(tls_conn_t *conn, const char *host, uint16_t port);
int tls_accept(tls_conn_t *conn, SSL_CTX *ctx, int client_fd);
ssize_t tls_read(tls_conn_t *conn, void *buf, size_t len);
ssize_t tls_write(tls_conn_t *conn, const void *buf, size_t len);
void tls_close(tls_conn_t *conn);

// 2.5.26.c-d: Certificate info
int tls_get_cert_info(tls_conn_t *conn, char *subject, size_t slen,
                      char *issuer, size_t ilen);
const char *tls_get_cipher(tls_conn_t *conn);

// ============== DEBUGGING TOOLS ==============
// 2.5.27

// 2.5.27.c-d: Connection listing
int get_tcp_connections(connection_info_t *conns, int max, int *count);
int get_udp_connections(connection_info_t *conns, int max, int *count);
int get_listening_ports(connection_info_t *conns, int max, int *count);

// 2.5.27.h: Netcat-like functionality
int nc_connect(const char *host, uint16_t port);
int nc_listen(uint16_t port);
int nc_transfer_stdin(int fd);

// 2.5.27.i: HTTP client
int curl_get(const char *url, char *response, size_t max_len);
int curl_post(const char *url, const char *data, char *response, size_t max_len);

// 2.5.27.j: DNS lookup
int dig_query(const char *server, const char *name, uint16_t type,
              char *result, size_t max_len);

// Network statistics
typedef struct {
    uint64_t rx_bytes, tx_bytes;
    uint64_t rx_packets, tx_packets;
    uint64_t rx_errors, tx_errors;
} interface_stats_t;

int get_interface_stats(const char *iface, interface_stats_t *stats);
```

---

## Exemple

```c
#include "security_debug.h"

void demo_port_scan(void) {
    printf("=== Port Scanning ===\n");
    // 2.5.25.f

    port_scan_result_t results[100];
    int count;

    port_scan_connect("127.0.0.1", 1, 1024, results, &count);

    printf("Open ports on localhost:\n");
    for (int i = 0; i < count; i++) {
        if (results[i].open) {
            printf("  %5d/tcp  open  %s  (%.2fms)\n",
                   results[i].port,
                   results[i].service ? results[i].service : "unknown",
                   results[i].response_time_ms);
        }
    }
}

void demo_tls(void) {
    printf("\n=== TLS Connection ===\n");
    // 2.5.26

    tls_init();

    tls_conn_t conn;
    if (tls_connect(&conn, "google.com", 443) == 0) {
        printf("Connected to google.com:443\n");

        // 2.5.26.d: Cipher suite
        printf("Cipher: %s\n", tls_get_cipher(&conn));

        // 2.5.26.c: Certificate
        char subject[256], issuer[256];
        tls_get_cert_info(&conn, subject, sizeof(subject),
                          issuer, sizeof(issuer));
        printf("Subject: %s\n", subject);
        printf("Issuer: %s\n", issuer);

        // 2.5.26.i: Send HTTPS request
        const char *req = "GET / HTTP/1.1\r\nHost: google.com\r\n\r\n";
        tls_write(&conn, req, strlen(req));

        char buf[4096];
        ssize_t n = tls_read(&conn, buf, sizeof(buf) - 1);
        buf[n] = '\0';
        printf("Response (first 200 chars):\n%.200s...\n", buf);

        tls_close(&conn);
    }

    tls_cleanup();
}

void demo_connections(void) {
    printf("\n=== Active Connections ===\n");
    // 2.5.27.c-d

    connection_info_t conns[100];
    int count;

    get_tcp_connections(conns, 100, &count);

    printf("TCP Connections:\n");
    for (int i = 0; i < count && i < 10; i++) {
        printf("  %s:%d -> %s:%d [%s] %s\n",
               conns[i].local_addr, conns[i].local_port,
               conns[i].remote_addr, conns[i].remote_port,
               conns[i].state, conns[i].program);
    }
}

void demo_netcat(void) {
    printf("\n=== Netcat Mode ===\n");
    // 2.5.27.h

    printf("Client: nc_connect(\"example.com\", 80)\n");
    printf("Server: nc_listen(8080)\n");
}

void demo_curl(void) {
    printf("\n=== HTTP Client ===\n");
    // 2.5.27.i

    char response[8192];
    if (curl_get("http://httpbin.org/get", response, sizeof(response)) == 0) {
        printf("GET response:\n%s\n", response);
    }
}

int main(void) {
    demo_port_scan();
    demo_tls();
    demo_connections();
    demo_netcat();
    demo_curl();
    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_port_scan()            // 2.5.25.f
#[test] fn test_tls_connect()          // 2.5.26.h
#[test] fn test_tls_io()               // 2.5.26.i
#[test] fn test_cert_info()            // 2.5.26.c
#[test] fn test_connections_list()     // 2.5.27.c-d
#[test] fn test_netcat()               // 2.5.27.h
#[test] fn test_curl()                 // 2.5.27.i
#[test] fn test_dig()                  // 2.5.27.j
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Security concepts (2.5.25) | 25 |
| TLS/OpenSSL (2.5.26) | 35 |
| Debug tools (2.5.27) | 40 |
| **Total** | **100** |

---

## Fichiers

```
ex11/
├── security_debug.h
├── port_scan.c
├── tls_client.c
├── tls_server.c
├── connection_list.c
├── netcat.c
├── curl.c
└── Makefile
```
