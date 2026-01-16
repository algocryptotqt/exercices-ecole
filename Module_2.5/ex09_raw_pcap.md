# ex09: Raw Sockets & Packet Capture

**Module**: 2.5 - Networking
**Difficulte**: Tres difficile
**Duree**: 7h
**Score qualite**: 97/100

## Concepts Couverts

### 2.5.19: Raw Sockets (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | SOCK_RAW | Raw socket |
| b | Root required | Privileged operation |
| c | IP_HDRINCL | Include IP header |
| d | Build headers | Manually construct |
| e | IP header | Version, length, TTL, protocol |
| f | ICMP | Ping implementation |
| g | TCP/UDP raw | Build transport headers |
| h | Use cases | Network tools, security |

### 2.5.20: Packet Capture (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | libpcap | Packet capture library |
| b | pcap_open_live() | Open interface |
| c | pcap_loop() | Capture packets |
| d | pcap_compile() | Compile filter |
| e | pcap_setfilter() | Apply filter |
| f | BPF | Berkeley Packet Filter |
| g | Packet parsing | Ethernet, IP, TCP/UDP |
| h | tcpdump | Command-line tool |
| i | Wireshark | GUI tool |

---

## Sujet

Implementer des outils reseau bas niveau: ping, packet sniffer.

### Structures

```c
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>

// IP Header (2.5.19.e)
typedef struct {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} ip_header_t;

// ICMP Header (2.5.19.f)
typedef struct {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t id;
    uint16_t sequence;
} icmp_header_t;

// Packet capture context
typedef struct {
    pcap_t *handle;            // a: pcap handle
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter; // f: BPF
    char interface[64];
    int snaplen;
    uint64_t packets_captured;
} capture_t;
```

### API

```c
// ============== RAW SOCKETS ==============
// 2.5.19

int raw_socket_create(int protocol);
int raw_socket_icmp(void);
void raw_set_hdrincl(int sock, bool include);

// 2.5.19.f: Ping implementation
int ping_send(int sock, const char *dest, uint16_t seq);
int ping_recv(int sock, int timeout_ms, double *rtt_ms);
void ping_run(const char *host, int count);

// Checksum calculation
uint16_t ip_checksum(const void *data, size_t len);

// ============== PACKET CAPTURE ==============
// 2.5.20

int capture_open(capture_t *cap, const char *interface, int snaplen);
void capture_close(capture_t *cap);
int capture_set_filter(capture_t *cap, const char *filter_expr);
int capture_loop(capture_t *cap, int count, pcap_handler callback, void *user);
void capture_break(capture_t *cap);

// Packet parsing
void parse_ethernet(const uint8_t *pkt, size_t len);
void parse_ip(const uint8_t *pkt, size_t len);
void parse_tcp(const uint8_t *pkt, size_t len);
void parse_udp(const uint8_t *pkt, size_t len);
void parse_icmp(const uint8_t *pkt, size_t len);

// Sniffer
void sniffer_run(const char *interface, const char *filter);
```

---

## Exemple

```c
#include "raw_pcap.h"

// ============== Ping Implementation ==============
void my_ping(const char *host) {
    printf("=== Ping Implementation ===\n");

    // 2.5.19.a-b: Raw ICMP socket (requires root)
    int sock = raw_socket_icmp();
    if (sock < 0) {
        printf("Need root privileges!\n");
        return;
    }

    ping_run(host, 4);

    close(sock);
}

// ============== Packet Sniffer ==============
void packet_handler(u_char *user, const struct pcap_pkthdr *header,
                    const u_char *packet) {
    printf("Captured packet: %d bytes\n", header->len);
    parse_ethernet(packet, header->len);
}

void my_sniffer(const char *interface) {
    printf("\n=== Packet Sniffer ===\n");

    capture_t cap;
    // 2.5.20.b: Open interface
    if (capture_open(&cap, interface, 65535) < 0) {
        return;
    }

    // 2.5.20.d-f: Set BPF filter
    capture_set_filter(&cap, "tcp port 80");

    // 2.5.20.c: Capture loop
    capture_loop(&cap, 10, packet_handler, NULL);

    capture_close(&cap);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        if (strcmp(argv[1], "ping") == 0 && argc > 2) {
            my_ping(argv[2]);
        } else if (strcmp(argv[1], "sniff") == 0) {
            my_sniffer(argc > 2 ? argv[2] : "eth0");
        }
    }
    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_raw_socket()           // 2.5.19.a-b
#[test] fn test_ip_header()            // 2.5.19.d-e
#[test] fn test_ping()                 // 2.5.19.f
#[test] fn test_checksum()
#[test] fn test_capture_open()         // 2.5.20.b
#[test] fn test_bpf_filter()           // 2.5.20.d-f
#[test] fn test_packet_parse()         // 2.5.20.g
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Raw socket creation (2.5.19.a-c) | 20 |
| IP/ICMP headers (2.5.19.d-f) | 25 |
| Ping implementation (2.5.19.f) | 15 |
| Packet capture (2.5.20.a-c) | 20 |
| BPF filters (2.5.20.d-f) | 10 |
| Packet parsing (2.5.20.g) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex09/
├── raw_pcap.h
├── raw_socket.c
├── ping.c
├── packet_capture.c
├── packet_parse.c
└── Makefile
```
