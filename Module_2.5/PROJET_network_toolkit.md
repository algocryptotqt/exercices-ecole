# PROJET: Network Toolkit

**Module**: 2.5 - Networking
**Difficulte**: Tres difficile
**Duree**: 15h
**Score qualite**: 98/100

## Objectif

Creer une boite a outils reseau complete integrant tous les concepts du module 2.5.

## Concepts Couverts (PROJET 2.5)

| Ref | Concept | Implementation |
|-----|---------|----------------|
| a | TCP echo server | Basic server |
| b | TCP echo client | Basic client |
| c | UDP echo server/client | Datagram |
| d | HTTP server | Static file serving |
| e | HTTP client | GET/POST requests |
| f | Concurrent server | Thread pool |
| g | Event-driven server | epoll-based |
| h | ping | ICMP implementation |
| i | traceroute | TTL manipulation |
| j | Port scanner | Connect scan |
| k | Packet sniffer | libpcap |
| l | DNS resolver | Manual parsing |
| m | **Bonus**: HTTP proxy | Forward proxy |
| n | **Bonus**: TLS server | OpenSSL integration |
| o | **Bonus**: Chat server | Multi-client |

---

## Sujet

Implementer un toolkit reseau complet sous forme de commandes CLI.

### Architecture

```
network-toolkit/
├── include/
│   ├── common.h           # Shared utilities
│   ├── tcp.h              # TCP helpers
│   ├── udp.h              # UDP helpers
│   ├── http.h             # HTTP protocol
│   ├── dns.h              # DNS protocol
│   ├── icmp.h             # ICMP protocol
│   └── capture.h          # Packet capture
├── src/
│   ├── common/
│   │   ├── socket.c       # Socket utilities
│   │   ├── address.c      # Address handling
│   │   └── buffer.c       # Buffer management
│   ├── servers/
│   │   ├── echo_tcp.c     # a: TCP echo
│   │   ├── echo_udp.c     # c: UDP echo
│   │   ├── http_server.c  # d: HTTP server
│   │   └── chat_server.c  # o: Chat (bonus)
│   ├── clients/
│   │   ├── echo_client.c  # b: TCP/UDP client
│   │   ├── http_client.c  # e: HTTP client
│   │   └── dns_client.c   # l: DNS resolver
│   ├── tools/
│   │   ├── ping.c         # h: Ping
│   │   ├── traceroute.c   # i: Traceroute
│   │   ├── portscan.c     # j: Port scanner
│   │   └── sniffer.c      # k: Packet sniffer
│   ├── advanced/
│   │   ├── epoll_server.c # g: Event-driven
│   │   ├── thread_pool.c  # f: Concurrent
│   │   ├── http_proxy.c   # m: Proxy (bonus)
│   │   └── tls_server.c   # n: TLS (bonus)
│   └── main.c             # CLI dispatcher
├── tests/
│   ├── test_tcp.c
│   ├── test_udp.c
│   ├── test_http.c
│   └── ...
└── Makefile
```

### Interface CLI

```bash
# TCP Echo
./nettool echo-server --tcp --port 8080
./nettool echo-client --tcp --host localhost --port 8080

# UDP Echo
./nettool echo-server --udp --port 5000
./nettool echo-client --udp --host localhost --port 5000

# HTTP Server
./nettool http-server --port 8080 --root ./public
./nettool http-server --port 8080 --threads 4  # Thread pool
./nettool http-server --port 8080 --epoll      # Event-driven

# HTTP Client
./nettool http-get http://example.com/path
./nettool http-post http://example.com/api --data '{"key":"value"}'

# Network Tools
./nettool ping google.com
./nettool ping -c 5 -i 0.5 google.com

./nettool traceroute google.com
./nettool traceroute -m 30 google.com

./nettool portscan localhost
./nettool portscan -p 1-1024 192.168.1.1

./nettool sniff eth0
./nettool sniff -f "tcp port 80" eth0

# DNS
./nettool dns google.com
./nettool dns -t MX gmail.com
./nettool dns -s 8.8.8.8 example.com

# Bonus
./nettool proxy --port 8888                    # HTTP proxy
./nettool https-server --port 443 --cert cert.pem --key key.pem
./nettool chat-server --port 9000
./nettool chat-client --host localhost --port 9000 --nick user1
```

---

## Specifications

### a-b: TCP Echo Server/Client

```c
// Server
typedef struct {
    int listen_fd;
    uint16_t port;
    bool concurrent;           // f: Thread per client
    bool epoll_mode;           // g: epoll-based
    int max_clients;
    uint64_t bytes_echoed;
    uint64_t connections;
} echo_server_t;

int echo_server_start(echo_server_t *srv, const echo_config_t *cfg);
void echo_server_stop(echo_server_t *srv);

// Client
typedef struct {
    int fd;
    char host[256];
    uint16_t port;
    int timeout_ms;
} echo_client_t;

int echo_client_connect(echo_client_t *cli, const char *host, uint16_t port);
int echo_client_send(echo_client_t *cli, const char *msg);
int echo_client_recv(echo_client_t *cli, char *buf, size_t len);
```

### d-e: HTTP Server/Client

```c
// HTTP Server
typedef struct {
    int listen_fd;
    char root_dir[PATH_MAX];
    uint16_t port;
    int worker_threads;        // f: Thread pool size
    bool use_epoll;            // g: epoll mode
    mime_map_t mime_types;
    route_t *routes;
    int route_count;
} http_server_t;

// Required endpoints
// GET /              -> index.html or directory listing
// GET /path          -> serve static file
// POST /upload       -> receive file upload
// GET /status        -> server statistics JSON

// HTTP Client
typedef struct {
    char host[256];
    uint16_t port;
    bool use_tls;              // n: TLS support
    int timeout_ms;
    char user_agent[128];
} http_client_t;

int http_get(http_client_t *cli, const char *path,
             http_response_t *response);
int http_post(http_client_t *cli, const char *path,
              const char *content_type, const void *body, size_t len,
              http_response_t *response);
```

### h-i: Ping & Traceroute

```c
// Ping
typedef struct {
    char host[256];
    int count;                 // -c: number of pings
    double interval;           // -i: interval in seconds
    int timeout_ms;            // -W: timeout
    int ttl;                   // -t: TTL
    int packet_size;           // -s: payload size
} ping_config_t;

typedef struct {
    int packets_sent;
    int packets_received;
    double min_rtt, max_rtt, avg_rtt;
    double mdev;               // Mean deviation
} ping_stats_t;

int ping_run(const ping_config_t *cfg, ping_stats_t *stats);

// Traceroute
typedef struct {
    char host[256];
    int max_hops;              // -m: max hops
    int queries;               // -q: queries per hop
    int timeout_ms;            // -w: timeout
    bool use_icmp;             // -I: use ICMP instead of UDP
} traceroute_config_t;

typedef struct {
    int hop;
    char addresses[3][INET_ADDRSTRLEN];  // Multiple probes
    double rtts[3];
    bool reached;
} traceroute_hop_t;

int traceroute_run(const traceroute_config_t *cfg,
                   traceroute_hop_t *hops, int *hop_count);
```

### j-k: Port Scanner & Sniffer

```c
// Port Scanner
typedef struct {
    char host[256];
    uint16_t start_port;
    uint16_t end_port;
    int timeout_ms;
    int threads;               // Parallel scanning
    bool syn_scan;             // SYN scan (requires root)
} portscan_config_t;

typedef struct {
    uint16_t port;
    bool open;
    char service[64];
    char banner[256];          // Service banner grab
} port_result_t;

int portscan_run(const portscan_config_t *cfg,
                 port_result_t *results, int *count);

// Packet Sniffer
typedef struct {
    char interface[64];
    char filter[256];          // BPF filter
    int snaplen;
    bool promiscuous;
    int packet_count;          // 0 = unlimited
} sniffer_config_t;

typedef void (*packet_handler_t)(const struct pcap_pkthdr *hdr,
                                 const uint8_t *packet,
                                 void *user);

int sniffer_run(const sniffer_config_t *cfg,
                packet_handler_t handler, void *user);
```

### l: DNS Resolver

```c
typedef struct {
    char server[INET_ADDRSTRLEN];
    int timeout_ms;
    bool tcp;                  // Use TCP instead of UDP
    bool recursive;            // Request recursion
} dns_config_t;

typedef struct {
    char name[256];
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    char data[512];            // Formatted data
} dns_answer_t;

int dns_resolve(const dns_config_t *cfg, const char *name,
                uint16_t type, dns_answer_t *answers, int *count);
```

---

## Exemple d'Utilisation

```c
// main.c - CLI dispatcher

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "echo-server") == 0) {
        return cmd_echo_server(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "echo-client") == 0) {
        return cmd_echo_client(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "http-server") == 0) {
        return cmd_http_server(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "http-get") == 0) {
        return cmd_http_get(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "ping") == 0) {
        return cmd_ping(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "traceroute") == 0) {
        return cmd_traceroute(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "portscan") == 0) {
        return cmd_portscan(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "sniff") == 0) {
        return cmd_sniffer(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "dns") == 0) {
        return cmd_dns(argc - 1, argv + 1);
    }
    // Bonus commands
    else if (strcmp(cmd, "proxy") == 0) {
        return cmd_http_proxy(argc - 1, argv + 1);
    }
    else if (strcmp(cmd, "chat-server") == 0) {
        return cmd_chat_server(argc - 1, argv + 1);
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    return 1;
}
```

---

## Tests Moulinette

```rust
// Core functionality
#[test] fn test_tcp_echo()             // a-b
#[test] fn test_udp_echo()             // c
#[test] fn test_http_server_static()   // d
#[test] fn test_http_server_post()     // d
#[test] fn test_http_client_get()      // e
#[test] fn test_http_client_post()     // e
#[test] fn test_thread_pool_server()   // f
#[test] fn test_epoll_server()         // g

// Network tools
#[test] fn test_ping_localhost()       // h
#[test] fn test_ping_stats()           // h
#[test] fn test_traceroute()           // i
#[test] fn test_portscan_connect()     // j
#[test] fn test_portscan_service()     // j
#[test] fn test_sniffer_capture()      // k
#[test] fn test_sniffer_filter()       // k
#[test] fn test_dns_a_record()         // l
#[test] fn test_dns_mx_record()        // l

// Bonus
#[test] fn test_http_proxy()           // m
#[test] fn test_tls_server()           // n
#[test] fn test_chat_server()          // o

// Integration
#[test] fn test_cli_parsing()
#[test] fn test_concurrent_clients()
#[test] fn test_stress()
```

---

## Bareme

| Critere | Points |
|---------|--------|
| TCP Echo (a-b) | 10 |
| UDP Echo (c) | 5 |
| HTTP Server (d) | 15 |
| HTTP Client (e) | 10 |
| Thread Pool (f) | 10 |
| Epoll Server (g) | 10 |
| Ping (h) | 10 |
| Traceroute (i) | 10 |
| Port Scanner (j) | 10 |
| Packet Sniffer (k) | 5 |
| DNS Resolver (l) | 5 |
| **Base Total** | **100** |
| Bonus: HTTP Proxy (m) | +10 |
| Bonus: TLS Server (n) | +10 |
| Bonus: Chat Server (o) | +10 |

---

## Fichiers

```
network-toolkit/
├── include/
│   ├── common.h
│   ├── tcp.h
│   ├── udp.h
│   ├── http.h
│   ├── dns.h
│   ├── icmp.h
│   └── capture.h
├── src/
│   ├── common/
│   ├── servers/
│   ├── clients/
│   ├── tools/
│   ├── advanced/
│   └── main.c
├── tests/
└── Makefile
```

---

## Compilation

```makefile
CC = gcc
CFLAGS = -std=c17 -Wall -Wextra -O2
LDFLAGS = -lpthread -lpcap -lssl -lcrypto

# Build all tools
all: nettool

nettool: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Test targets
test: nettool
	./run_tests.sh

.PHONY: all test clean
```

---

## Criteres de Qualite

- Code C17 strict, pas de warnings
- Gestion complete des erreurs
- Pas de fuites memoire (valgrind clean)
- Documentation inline
- Tests automatises pour chaque composant
- Performance: HTTP server > 1000 req/s
- Robustesse: gestion des connexions fermees
