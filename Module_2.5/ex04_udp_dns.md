# ex04: UDP Communication & Name Resolution

**Module**: 2.5 - Networking
**Difficulte**: Moyen
**Duree**: 5h
**Score qualite**: 96/100

## Concepts Couverts

### 2.5.9: UDP Communication (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | socket() | SOCK_DGRAM |
| b | bind() | For server |
| c | No listen/accept | Connectionless |
| d | sendto() | Send with address |
| e | recvfrom() | Receive with source |
| f | connect() on UDP | Set default destination |
| g | send/recv | After connect |
| h | Message boundaries | Preserved |

### 2.5.10: Name Resolution (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | DNS | Domain Name System |
| b | gethostbyname() | Old API (deprecated) |
| c | getaddrinfo() | Modern API |
| d | struct addrinfo | Hints and results |
| e | AI_PASSIVE | For binding |
| f | AI_CANONNAME | Get canonical name |
| g | freeaddrinfo() | Free results |
| h | getnameinfo() | Reverse lookup |
| i | /etc/hosts | Local override |
| j | /etc/resolv.conf | DNS servers |

---

## Sujet

Maitriser la communication UDP et la resolution de noms DNS.

### Structures

```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

// 2.5.9: UDP Socket
typedef struct {
    int fd;                      // a: SOCK_DGRAM
    bool bound;                  // b: Bound?
    bool connected;              // f: Connected (default dest)?
    struct sockaddr_in default_dest;
    uint64_t datagrams_sent;
    uint64_t datagrams_received;
    size_t max_datagram_size;    // h: Message size
} udp_socket_t;

// UDP Datagram info
typedef struct {
    struct sockaddr_in src_addr;
    char src_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint8_t *data;
    size_t len;
    struct timespec timestamp;
} udp_datagram_info_t;

// 2.5.10: DNS resolution result
typedef struct {
    char hostname[256];          // a: DNS name
    char canonical[256];         // f: Canonical name
    int family;                  // AF_INET or AF_INET6
    char **addresses;            // Resolved addresses
    int address_count;
} dns_result_t;

// Address info wrapper
typedef struct {
    struct addrinfo *head;       // d: Result list
    struct addrinfo *current;    // Iterator
    int count;
} addrinfo_list_t;

// DNS server config
typedef struct {
    char servers[10][64];        // j: DNS servers
    int server_count;
    char domain[256];
    char search[10][256];
    int search_count;
} dns_config_t;

// Hosts file entry
typedef struct {
    char ip[INET6_ADDRSTRLEN];
    char hostnames[10][256];
    int hostname_count;
} hosts_entry_t;
```

### API

```c
// ============== UDP SOCKET ==============
// 2.5.9

// 2.5.9.a: Create UDP socket
int udp_socket_create(udp_socket_t *sock);
int udp_socket_create6(udp_socket_t *sock);
void udp_socket_destroy(udp_socket_t *sock);

// 2.5.9.b: Bind (for receiving)
int udp_bind(udp_socket_t *sock, const char *addr, uint16_t port);
int udp_bind_any(udp_socket_t *sock, uint16_t port);

// 2.5.9.c: No listen/accept needed (connectionless)
// UDP is inherently connectionless

// 2.5.9.d: Send to specific address
ssize_t udp_sendto(udp_socket_t *sock, const void *data, size_t len,
                   const char *dest_addr, uint16_t dest_port);
ssize_t udp_sendto_addr(udp_socket_t *sock, const void *data, size_t len,
                        const struct sockaddr_in *dest);

// 2.5.9.e: Receive with source info
ssize_t udp_recvfrom(udp_socket_t *sock, void *buf, size_t len,
                     struct sockaddr_in *src, socklen_t *srclen);
ssize_t udp_recvfrom_info(udp_socket_t *sock, udp_datagram_info_t *info,
                          uint8_t *buf, size_t len);

// 2.5.9.f: Connect (set default destination)
int udp_connect(udp_socket_t *sock, const char *addr, uint16_t port);

// 2.5.9.g: Send/recv after connect
ssize_t udp_send(udp_socket_t *sock, const void *data, size_t len);
ssize_t udp_recv(udp_socket_t *sock, void *buf, size_t len);

// 2.5.9.h: Message boundaries
bool udp_is_complete_message(void);  // Always true for UDP
size_t udp_get_max_datagram_size(void);

// ============== NAME RESOLUTION ==============
// 2.5.10

// 2.5.10.b: Deprecated API (for reference)
struct hostent *my_gethostbyname(const char *name);
void print_hostent(const struct hostent *h);

// 2.5.10.c-g: Modern API
int dns_resolve(const char *hostname, const char *service,
                addrinfo_list_t *result);
int dns_resolve_with_hints(const char *hostname, const char *service,
                           const struct addrinfo *hints, addrinfo_list_t *result);

// 2.5.10.d: Hints structure
void addrinfo_hints_tcp(struct addrinfo *hints);
void addrinfo_hints_udp(struct addrinfo *hints);
void addrinfo_hints_passive(struct addrinfo *hints);  // e: For bind

// Iterate results
struct addrinfo *addrinfo_next(addrinfo_list_t *list);
void addrinfo_reset(addrinfo_list_t *list);
int addrinfo_count(addrinfo_list_t *list);

// 2.5.10.f: Get canonical name
const char *addrinfo_canonical(addrinfo_list_t *list);

// 2.5.10.g: Free
void addrinfo_free(addrinfo_list_t *list);

// 2.5.10.h: Reverse lookup
int dns_reverse_lookup(const struct sockaddr *addr, socklen_t len,
                       char *host, size_t hostlen,
                       char *service, size_t servlen);

// Higher-level API
int resolve_hostname(const char *hostname, dns_result_t *result);
void dns_result_free(dns_result_t *result);
int resolve_first_ipv4(const char *hostname, char *ip, size_t len);
int resolve_first_ipv6(const char *hostname, char *ip, size_t len);

// 2.5.10.i: Hosts file
int hosts_file_parse(hosts_entry_t **entries, int *count);
const char *hosts_file_lookup(const char *hostname);
void hosts_entries_free(hosts_entry_t *entries, int count);

// 2.5.10.j: Resolver config
int dns_config_load(dns_config_t *config);
void dns_config_print(const dns_config_t *config);

// ============== UDP SERVER/CLIENT ==============

typedef struct {
    udp_socket_t sock;
    uint16_t port;
    bool running;
} udp_server_t;

int udp_server_create(udp_server_t *server, uint16_t port);
void udp_server_run(udp_server_t *server,
                    void (*handler)(udp_server_t*, udp_datagram_info_t*));
void udp_server_stop(udp_server_t *server);
void udp_server_destroy(udp_server_t *server);

// Echo server
void udp_echo_server(uint16_t port);
void udp_echo_client(const char *host, uint16_t port, const char *msg);

// ============== DNS CLIENT ==============
// Manual DNS query building

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

typedef struct {
    char name[256];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    uint8_t *rdata;
} dns_record_t;

int dns_query_build(const char *domain, uint16_t type, uint8_t *buf, size_t *len);
int dns_response_parse(const uint8_t *buf, size_t len,
                       dns_record_t *records, int *count);
int dns_query_send(const char *domain, uint16_t type,
                   const char *server, dns_record_t *records, int *count);
```

---

## Exemple

```c
#include "udp_dns.h"

// ============== UDP Communication ==============

void demo_udp_basic(void) {
    printf("=== UDP Basic Communication ===\n");

    // 2.5.9.a: Create UDP socket
    udp_socket_t sock;
    udp_socket_create(&sock);
    printf("Created UDP socket: fd=%d\n", sock.fd);

    // 2.5.9.h: Message boundaries
    printf("Max datagram size: %zu bytes\n", udp_get_max_datagram_size());
    printf("UDP preserves message boundaries: %s\n",
           udp_is_complete_message() ? "Yes" : "No");

    udp_socket_destroy(&sock);
}

void demo_udp_server(void) {
    printf("\n=== UDP Server ===\n");

    udp_socket_t sock;
    udp_socket_create(&sock);

    // 2.5.9.b: Bind for receiving
    if (udp_bind_any(&sock, 5000) < 0) {
        perror("bind");
        return;
    }
    printf("UDP server bound to port 5000\n");

    printf("Waiting for datagrams...\n");

    uint8_t buf[1024];
    struct sockaddr_in src;
    socklen_t srclen = sizeof(src);

    // 2.5.9.e: Receive with source address
    ssize_t n = udp_recvfrom(&sock, buf, sizeof(buf), &src, &srclen);
    if (n > 0) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src.sin_addr, ip, sizeof(ip));
        printf("Received %zd bytes from %s:%d\n", n, ip, ntohs(src.sin_port));
        printf("Data: %.*s\n", (int)n, buf);

        // 2.5.9.d: Send response
        const char *reply = "ACK";
        udp_sendto_addr(&sock, reply, strlen(reply), &src);
    }

    udp_socket_destroy(&sock);
}

void demo_udp_client(void) {
    printf("\n=== UDP Client ===\n");

    udp_socket_t sock;
    udp_socket_create(&sock);

    // 2.5.9.d: Send to specific address
    const char *msg = "Hello UDP!";
    ssize_t sent = udp_sendto(&sock, msg, strlen(msg), "127.0.0.1", 5000);
    printf("Sent %zd bytes to 127.0.0.1:5000\n", sent);

    // 2.5.9.e: Receive response
    uint8_t buf[1024];
    struct sockaddr_in src;
    socklen_t srclen = sizeof(src);

    ssize_t n = udp_recvfrom(&sock, buf, sizeof(buf), &src, &srclen);
    if (n > 0) {
        printf("Received: %.*s\n", (int)n, buf);
    }

    udp_socket_destroy(&sock);
}

void demo_udp_connected(void) {
    printf("\n=== UDP Connected Mode ===\n");

    udp_socket_t sock;
    udp_socket_create(&sock);

    // 2.5.9.f: Connect sets default destination
    udp_connect(&sock, "127.0.0.1", 5000);
    printf("Connected to 127.0.0.1:5000 (default dest set)\n");

    // 2.5.9.g: Now can use send/recv
    const char *msg = "Hello via connected UDP!";
    ssize_t sent = udp_send(&sock, msg, strlen(msg));
    printf("Sent %zd bytes using send()\n", sent);

    uint8_t buf[1024];
    ssize_t n = udp_recv(&sock, buf, sizeof(buf));
    if (n > 0) {
        printf("Received: %.*s\n", (int)n, buf);
    }

    udp_socket_destroy(&sock);
}

// ============== Name Resolution ==============

void demo_dns_deprecated(void) {
    printf("\n=== DNS: Deprecated API ===\n");
    // 2.5.10.b: gethostbyname (deprecated)

    struct hostent *h = gethostbyname("google.com");
    if (h) {
        printf("gethostbyname(\"google.com\"):\n");
        printf("  Official name: %s\n", h->h_name);
        printf("  Address type: %s\n",
               h->h_addrtype == AF_INET ? "IPv4" : "IPv6");

        for (int i = 0; h->h_addr_list[i]; i++) {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, h->h_addr_list[i], ip, sizeof(ip));
            printf("  Address %d: %s\n", i + 1, ip);
        }
    }

    printf("\nWARNING: gethostbyname is deprecated!\n");
    printf("Use getaddrinfo() instead.\n");
}

void demo_dns_modern(void) {
    printf("\n=== DNS: Modern API (getaddrinfo) ===\n");
    // 2.5.10.c-g

    // 2.5.10.d: Set up hints
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;     // Both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP

    // 2.5.10.c: getaddrinfo
    struct addrinfo *result;
    int err = getaddrinfo("google.com", "https", &hints, &result);
    if (err != 0) {
        printf("getaddrinfo error: %s\n", gai_strerror(err));
        return;
    }

    printf("getaddrinfo(\"google.com\", \"https\"):\n");

    int count = 0;
    for (struct addrinfo *rp = result; rp; rp = rp->ai_next) {
        char ip[INET6_ADDRSTRLEN];
        void *addr;
        const char *family;

        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in*)rp->ai_addr;
            addr = &sin->sin_addr;
            family = "IPv4";
        } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)rp->ai_addr;
            addr = &sin6->sin6_addr;
            family = "IPv6";
        }

        inet_ntop(rp->ai_family, addr, ip, sizeof(ip));
        printf("  [%s] %s\n", family, ip);
        count++;
    }
    printf("  Total: %d addresses\n", count);

    // 2.5.10.g: Free
    freeaddrinfo(result);
}

void demo_dns_passive(void) {
    printf("\n=== DNS: AI_PASSIVE (for servers) ===\n");
    // 2.5.10.e: AI_PASSIVE

    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;  // For bind()

    struct addrinfo *result;
    int err = getaddrinfo(NULL, "8080", &hints, &result);
    if (err != 0) {
        printf("Error: %s\n", gai_strerror(err));
        return;
    }

    printf("AI_PASSIVE result for port 8080:\n");
    struct sockaddr_in *sin = (struct sockaddr_in*)result->ai_addr;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
    printf("  Address: %s (INADDR_ANY)\n", ip);
    printf("  Port: %d\n", ntohs(sin->sin_port));

    // Can directly use for bind()
    // bind(sock, result->ai_addr, result->ai_addrlen);

    freeaddrinfo(result);
}

void demo_dns_canonical(void) {
    printf("\n=== DNS: Canonical Name ===\n");
    // 2.5.10.f: AI_CANONNAME

    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_CANONNAME;  // Get canonical name

    struct addrinfo *result;
    getaddrinfo("www.google.com", NULL, &hints, &result);

    if (result && result->ai_canonname) {
        printf("www.google.com canonical: %s\n", result->ai_canonname);
    }

    freeaddrinfo(result);
}

void demo_dns_reverse(void) {
    printf("\n=== DNS: Reverse Lookup ===\n");
    // 2.5.10.h: getnameinfo

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(443)
    };
    inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

    char host[NI_MAXHOST];
    char service[NI_MAXSERV];

    int err = getnameinfo((struct sockaddr*)&addr, sizeof(addr),
                          host, sizeof(host),
                          service, sizeof(service),
                          0);

    if (err == 0) {
        printf("Reverse lookup for 8.8.8.8:443:\n");
        printf("  Host: %s\n", host);
        printf("  Service: %s\n", service);
    } else {
        printf("Error: %s\n", gai_strerror(err));
    }
}

void demo_hosts_file(void) {
    printf("\n=== Local: /etc/hosts ===\n");
    // 2.5.10.i

    hosts_entry_t *entries;
    int count;

    if (hosts_file_parse(&entries, &count) == 0) {
        printf("Hosts file entries:\n");
        for (int i = 0; i < count && i < 5; i++) {
            printf("  %s -> ", entries[i].ip);
            for (int j = 0; j < entries[i].hostname_count; j++) {
                printf("%s ", entries[i].hostnames[j]);
            }
            printf("\n");
        }
        hosts_entries_free(entries, count);
    }

    // Lookup
    const char *ip = hosts_file_lookup("localhost");
    printf("\nlocalhost -> %s\n", ip ? ip : "not found");
}

void demo_resolv_conf(void) {
    printf("\n=== DNS Config: /etc/resolv.conf ===\n");
    // 2.5.10.j

    dns_config_t config;
    if (dns_config_load(&config) == 0) {
        dns_config_print(&config);
    }
}

int main(void) {
    // UDP demos
    demo_udp_basic();
    // demo_udp_server();  // Would block
    // demo_udp_client();
    demo_udp_connected();

    // DNS demos
    demo_dns_deprecated();
    demo_dns_modern();
    demo_dns_passive();
    demo_dns_canonical();
    demo_dns_reverse();
    demo_hosts_file();
    demo_resolv_conf();

    return 0;
}
```

---

## Tests Moulinette

```rust
// UDP tests
#[test] fn test_udp_socket()           // 2.5.9.a
#[test] fn test_udp_bind()             // 2.5.9.b
#[test] fn test_udp_sendto()           // 2.5.9.d
#[test] fn test_udp_recvfrom()         // 2.5.9.e
#[test] fn test_udp_connect()          // 2.5.9.f-g
#[test] fn test_udp_boundaries()       // 2.5.9.h

// DNS tests
#[test] fn test_getaddrinfo()          // 2.5.10.c-d
#[test] fn test_ai_passive()           // 2.5.10.e
#[test] fn test_ai_canonname()         // 2.5.10.f
#[test] fn test_freeaddrinfo()         // 2.5.10.g
#[test] fn test_getnameinfo()          // 2.5.10.h
#[test] fn test_hosts_file()           // 2.5.10.i
#[test] fn test_resolv_conf()          // 2.5.10.j
```

---

## Bareme

| Critere | Points |
|---------|--------|
| UDP socket (2.5.9.a-b) | 15 |
| UDP sendto/recvfrom (2.5.9.d-e) | 20 |
| UDP connected (2.5.9.f-h) | 15 |
| getaddrinfo (2.5.10.c-d) | 20 |
| AI flags (2.5.10.e-f) | 10 |
| Reverse lookup (2.5.10.h) | 10 |
| Config files (2.5.10.i-j) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex04/
├── udp_dns.h
├── udp.c
├── udp_server.c
├── dns_resolve.c
├── dns_config.c
├── hosts_file.c
└── Makefile
```
