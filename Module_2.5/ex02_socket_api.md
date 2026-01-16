# ex02: Berkeley Sockets API

**Module**: 2.5 - Networking
**Difficulte**: Moyen
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.5.5: Berkeley Sockets API (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Socket | Communication endpoint |
| b | socket() | Create socket |
| c | AF_INET | IPv4 |
| d | AF_INET6 | IPv6 |
| e | AF_UNIX | Local |
| f | SOCK_STREAM | TCP |
| g | SOCK_DGRAM | UDP |
| h | SOCK_RAW | Raw IP |
| i | File descriptor | Socket is fd |
| j | close() | Close socket |

### 2.5.6: Socket Addresses (11 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | sockaddr | Generic address |
| b | sockaddr_in | IPv4 address |
| c | sin_family | AF_INET |
| d | sin_port | Port (network order) |
| e | sin_addr | IP address |
| f | sockaddr_in6 | IPv6 address |
| g | sockaddr_un | Unix domain |
| h | htons/htonl | Host to network byte order |
| i | ntohs/ntohl | Network to host |
| j | inet_pton() | String to binary |
| k | inet_ntop() | Binary to string |

---

## Sujet

Maitriser l'API sockets Berkeley pour creer des communications reseau.

### Structures

```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>
#include <unistd.h>

// 2.5.5.a: Socket wrapper
typedef struct {
    int fd;                      // i: File descriptor
    int domain;                  // c,d,e: AF_*
    int type;                    // f,g,h: SOCK_*
    int protocol;
    bool connected;
    bool bound;
} socket_t;

// Socket creation options
typedef struct {
    int domain;                  // AF_INET, AF_INET6, AF_UNIX
    int type;                    // SOCK_STREAM, SOCK_DGRAM, SOCK_RAW
    int protocol;                // 0 for default
    bool nonblock;               // O_NONBLOCK
    bool cloexec;                // O_CLOEXEC
    bool reuse_addr;             // SO_REUSEADDR
    bool reuse_port;             // SO_REUSEPORT
} socket_opts_t;

// 2.5.6.a-e: IPv4 address wrapper
typedef struct {
    struct sockaddr_in addr;     // b: sockaddr_in
    socklen_t len;
} addr_ipv4_t;

// 2.5.6.f: IPv6 address wrapper
typedef struct {
    struct sockaddr_in6 addr;
    socklen_t len;
} addr_ipv6_t;

// 2.5.6.g: Unix domain wrapper
typedef struct {
    struct sockaddr_un addr;
    socklen_t len;
} addr_unix_t;

// Generic address (dual-stack support)
typedef struct {
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
        struct sockaddr_un sun;
        struct sockaddr_storage ss;
    };
    socklen_t len;
    int family;
} address_t;

// Byte order demonstration
typedef struct {
    uint16_t host_short;
    uint16_t net_short;
    uint32_t host_long;
    uint32_t net_long;
} byte_order_demo_t;
```

### API

```c
// ============== SOCKET CREATION ==============
// 2.5.5.b

// 2.5.5.b: Create socket with options
int socket_create(socket_t *sock, const socket_opts_t *opts);
int socket_create_tcp4(socket_t *sock);        // c,f: IPv4 TCP
int socket_create_tcp6(socket_t *sock);        // d,f: IPv6 TCP
int socket_create_udp4(socket_t *sock);        // c,g: IPv4 UDP
int socket_create_udp6(socket_t *sock);        // d,g: IPv6 UDP
int socket_create_unix_stream(socket_t *sock); // e,f: Unix stream
int socket_create_unix_dgram(socket_t *sock);  // e,g: Unix datagram
int socket_create_raw(socket_t *sock, int protocol); // h: Raw socket

// 2.5.5.j: Close socket
int socket_close(socket_t *sock);

// Socket info
const char *socket_domain_string(int domain);
const char *socket_type_string(int type);
void socket_print_info(const socket_t *sock);

// ============== SOCKET ADDRESSES ==============
// 2.5.6

// 2.5.6.b-e: IPv4 address
int addr_ipv4_init(addr_ipv4_t *addr, const char *ip, uint16_t port);
int addr_ipv4_any(addr_ipv4_t *addr, uint16_t port);
int addr_ipv4_loopback(addr_ipv4_t *addr, uint16_t port);
const char *addr_ipv4_to_string(const addr_ipv4_t *addr, char *buf, size_t len);

// 2.5.6.f: IPv6 address
int addr_ipv6_init(addr_ipv6_t *addr, const char *ip, uint16_t port);
int addr_ipv6_any(addr_ipv6_t *addr, uint16_t port);
int addr_ipv6_loopback(addr_ipv6_t *addr, uint16_t port);
const char *addr_ipv6_to_string(const addr_ipv6_t *addr, char *buf, size_t len);

// 2.5.6.g: Unix domain address
int addr_unix_init(addr_unix_t *addr, const char *path);
int addr_unix_abstract(addr_unix_t *addr, const char *name);  // Linux abstract namespace

// Generic address operations
int address_from_string(address_t *addr, const char *host, uint16_t port);
int address_to_string(const address_t *addr, char *buf, size_t len);
int address_get_port(const address_t *addr);
int address_set_port(address_t *addr, uint16_t port);

// ============== BYTE ORDER ==============
// 2.5.6.h-i

// 2.5.6.h: Host to network
uint16_t my_htons(uint16_t hostshort);
uint32_t my_htonl(uint32_t hostlong);

// 2.5.6.i: Network to host
uint16_t my_ntohs(uint16_t netshort);
uint32_t my_ntohl(uint32_t netlong);

// Demonstrate byte order
void byte_order_demo(byte_order_demo_t *demo);
bool is_little_endian(void);
bool is_big_endian(void);

// ============== ADDRESS CONVERSION ==============
// 2.5.6.j-k

// 2.5.6.j: String to binary
int my_inet_pton(int af, const char *src, void *dst);

// 2.5.6.k: Binary to string
const char *my_inet_ntop(int af, const void *src, char *dst, socklen_t size);

// Additional conversions
int parse_address(const char *str, address_t *addr);
int format_address(const address_t *addr, char *buf, size_t len);

// ============== SOCKET OPERATIONS ==============

// Basic operations (wrapper)
int socket_bind(socket_t *sock, const address_t *addr);
int socket_listen(socket_t *sock, int backlog);
int socket_accept(socket_t *sock, socket_t *client, address_t *client_addr);
int socket_connect(socket_t *sock, const address_t *addr);

// Send/receive
ssize_t socket_send(socket_t *sock, const void *buf, size_t len, int flags);
ssize_t socket_recv(socket_t *sock, void *buf, size_t len, int flags);
ssize_t socket_sendto(socket_t *sock, const void *buf, size_t len,
                      const address_t *dest);
ssize_t socket_recvfrom(socket_t *sock, void *buf, size_t len,
                        address_t *src);

// ============== UTILITY FUNCTIONS ==============

// Check socket validity
bool socket_is_valid(const socket_t *sock);
bool socket_is_connected(const socket_t *sock);
int socket_get_error(socket_t *sock);

// Get local/peer address
int socket_get_local_addr(socket_t *sock, address_t *addr);
int socket_get_peer_addr(socket_t *sock, address_t *addr);

// Port operations
int find_free_port(void);
bool is_port_available(uint16_t port);

// ============== DEMONSTRATIONS ==============

// Show all socket types
void demo_socket_types(void);

// Show address structures
void demo_address_structures(void);

// Show byte order
void demo_byte_order(void);

// IPv4 vs IPv6 comparison
void demo_ipv4_vs_ipv6(void);
```

---

## Exemple

```c
#include "socket_api.h"

int main(void) {
    // ============== Socket Creation ==============
    printf("=== Socket Creation ===\n");

    // 2.5.5.b-h: Different socket types
    socket_t tcp_sock, udp_sock, unix_sock, raw_sock;

    // 2.5.5.c,f: IPv4 TCP socket
    socket_create_tcp4(&tcp_sock);
    printf("TCP socket: fd=%d\n", tcp_sock.fd);
    socket_print_info(&tcp_sock);

    // 2.5.5.c,g: IPv4 UDP socket
    socket_create_udp4(&udp_sock);
    printf("UDP socket: fd=%d\n", udp_sock.fd);

    // 2.5.5.e,f: Unix domain socket
    socket_create_unix_stream(&unix_sock);
    printf("Unix socket: fd=%d\n", unix_sock.fd);

    // 2.5.5.h: Raw socket (requires root)
    if (geteuid() == 0) {
        socket_create_raw(&raw_sock, IPPROTO_ICMP);
        printf("Raw socket: fd=%d\n", raw_sock.fd);
        socket_close(&raw_sock);
    }

    // ============== Socket Addresses ==============
    printf("\n=== Socket Addresses ===\n");

    // 2.5.6.b-e: IPv4 address
    addr_ipv4_t ipv4_addr;
    addr_ipv4_init(&ipv4_addr, "192.168.1.100", 8080);

    char buf[INET6_ADDRSTRLEN];
    printf("IPv4: %s\n", addr_ipv4_to_string(&ipv4_addr, buf, sizeof(buf)));

    // 2.5.6.c-e: Structure fields
    printf("  sin_family: %d (AF_INET=%d)\n",
           ipv4_addr.addr.sin_family, AF_INET);
    printf("  sin_port: %u (network order: 0x%04x)\n",
           ntohs(ipv4_addr.addr.sin_port), ipv4_addr.addr.sin_port);
    printf("  sin_addr: 0x%08x\n", ntohl(ipv4_addr.addr.sin_addr.s_addr));

    // Any address (0.0.0.0)
    addr_ipv4_any(&ipv4_addr, 80);
    printf("Any: %s\n", addr_ipv4_to_string(&ipv4_addr, buf, sizeof(buf)));

    // Loopback (127.0.0.1)
    addr_ipv4_loopback(&ipv4_addr, 3000);
    printf("Loopback: %s\n", addr_ipv4_to_string(&ipv4_addr, buf, sizeof(buf)));

    // 2.5.6.f: IPv6 address
    addr_ipv6_t ipv6_addr;
    addr_ipv6_init(&ipv6_addr, "2001:db8::1", 443);
    printf("IPv6: %s\n", addr_ipv6_to_string(&ipv6_addr, buf, sizeof(buf)));

    addr_ipv6_loopback(&ipv6_addr, 8080);
    printf("IPv6 Loopback: %s\n", addr_ipv6_to_string(&ipv6_addr, buf, sizeof(buf)));

    // 2.5.6.g: Unix domain address
    addr_unix_t unix_addr;
    addr_unix_init(&unix_addr, "/tmp/my.sock");
    printf("Unix: %s\n", unix_addr.addr.sun_path);

    addr_unix_abstract(&unix_addr, "my_abstract_socket");
    printf("Abstract: @%s\n", unix_addr.addr.sun_path + 1);

    // ============== Byte Order ==============
    printf("\n=== Byte Order ===\n");
    // 2.5.6.h-i

    byte_order_demo_t demo;
    demo.host_short = 0x1234;
    demo.host_long = 0x12345678;

    // 2.5.6.h: Host to network
    demo.net_short = htons(demo.host_short);
    demo.net_long = htonl(demo.host_long);

    printf("System: %s endian\n", is_little_endian() ? "Little" : "Big");
    printf("\nHost to Network:\n");
    printf("  0x%04x -> 0x%04x (short)\n", demo.host_short, demo.net_short);
    printf("  0x%08x -> 0x%08x (long)\n", demo.host_long, demo.net_long);

    // 2.5.6.i: Network to host
    printf("\nNetwork to Host:\n");
    printf("  0x%04x -> 0x%04x (short)\n", demo.net_short, ntohs(demo.net_short));
    printf("  0x%08x -> 0x%08x (long)\n", demo.net_long, ntohl(demo.net_long));

    // Port byte order
    uint16_t port = 80;
    uint16_t net_port = htons(port);
    printf("\nPort 80: host=0x%04x, network=0x%04x\n", port, net_port);

    // ============== Address Conversion ==============
    printf("\n=== Address Conversion ===\n");
    // 2.5.6.j-k

    // 2.5.6.j: inet_pton - string to binary
    struct in_addr ipv4_bin;
    inet_pton(AF_INET, "192.168.1.1", &ipv4_bin);
    printf("inet_pton(\"192.168.1.1\") = 0x%08x\n", ntohl(ipv4_bin.s_addr));

    struct in6_addr ipv6_bin;
    inet_pton(AF_INET6, "::1", &ipv6_bin);
    printf("inet_pton(\"::1\") = ");
    for (int i = 0; i < 16; i++) printf("%02x", ipv6_bin.s6_addr[i]);
    printf("\n");

    // 2.5.6.k: inet_ntop - binary to string
    char addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET, &ipv4_bin, addr_str, sizeof(addr_str));
    printf("inet_ntop(0x%08x) = \"%s\"\n", ntohl(ipv4_bin.s_addr), addr_str);

    inet_ntop(AF_INET6, &ipv6_bin, addr_str, sizeof(addr_str));
    printf("inet_ntop(::1) = \"%s\"\n", addr_str);

    // ============== Practical Example ==============
    printf("\n=== Practical: Create Bound Socket ===\n");

    socket_t server;
    socket_create_tcp4(&server);

    address_t bind_addr;
    address_from_string(&bind_addr, "127.0.0.1", 0);  // 0 = any available port

    if (socket_bind(&server, &bind_addr) == 0) {
        socket_get_local_addr(&server, &bind_addr);
        char addr_buf[64];
        address_to_string(&bind_addr, addr_buf, sizeof(addr_buf));
        printf("Server bound to: %s\n", addr_buf);
    }

    // 2.5.5.j: Close sockets
    socket_close(&server);
    socket_close(&tcp_sock);
    socket_close(&udp_sock);
    socket_close(&unix_sock);

    printf("\nAll sockets closed.\n");

    // ============== Demo All Types ==============
    printf("\n");
    demo_socket_types();
    demo_address_structures();
    demo_byte_order();
    demo_ipv4_vs_ipv6();

    return 0;
}
```

---

## Tests Moulinette

```rust
// Socket creation
#[test] fn test_socket_tcp4()          // 2.5.5.c,f
#[test] fn test_socket_tcp6()          // 2.5.5.d,f
#[test] fn test_socket_udp()           // 2.5.5.g
#[test] fn test_socket_unix()          // 2.5.5.e
#[test] fn test_socket_raw()           // 2.5.5.h
#[test] fn test_socket_close()         // 2.5.5.j

// Socket addresses
#[test] fn test_addr_ipv4()            // 2.5.6.b-e
#[test] fn test_addr_ipv6()            // 2.5.6.f
#[test] fn test_addr_unix()            // 2.5.6.g
#[test] fn test_byte_order()           // 2.5.6.h-i
#[test] fn test_inet_pton()            // 2.5.6.j
#[test] fn test_inet_ntop()            // 2.5.6.k
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Socket creation (2.5.5.b-h) | 25 |
| Socket fd/close (2.5.5.i-j) | 10 |
| IPv4 addresses (2.5.6.b-e) | 20 |
| IPv6 addresses (2.5.6.f) | 15 |
| Unix addresses (2.5.6.g) | 10 |
| Byte order (2.5.6.h-i) | 10 |
| Address conversion (2.5.6.j-k) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex02/
├── socket_api.h
├── socket.c
├── address_ipv4.c
├── address_ipv6.c
├── address_unix.c
├── byte_order.c
├── demo.c
└── Makefile
```
