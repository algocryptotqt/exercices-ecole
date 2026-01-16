# ex10: Network Protocols (ARP, ICMP, DHCP, DNS)

**Module**: 2.5 - Networking
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 96/100

## Concepts Couverts

### 2.5.21: Network Protocols - ARP (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | ARP | Address Resolution Protocol |
| b | IP → MAC | Mapping |
| c | ARP request | Broadcast |
| d | ARP reply | Unicast response |
| e | ARP cache | arp -a |
| f | ARP spoofing | Security issue |
| g | Gratuitous ARP | Announcement |

### 2.5.22: Network Protocols - ICMP (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | ICMP | Internet Control Message Protocol |
| b | Echo request | Ping |
| c | Echo reply | Pong |
| d | Destination unreachable | Error message |
| e | Time exceeded | TTL expired |
| f | Traceroute | TTL manipulation |
| g | Path MTU discovery | Using ICMP |

### 2.5.23: Network Protocols - DHCP (6 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | DHCP | Dynamic Host Configuration |
| b | DORA | Discover, Offer, Request, Acknowledge |
| c | Lease | Temporary assignment |
| d | Renewal | Extend lease |
| e | Options | Gateway, DNS, domain |
| f | DHCP relay | Across subnets |

### 2.5.24: Network Protocols - DNS Deep Dive (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | DNS hierarchy | Root, TLD, authoritative |
| b | Record types | A, AAAA, CNAME, MX, NS, TXT |
| c | DNS message | Header, question, answer |
| d | Query | Request |
| e | Response | Answer |
| f | Recursive | Resolver follows chain |
| g | Iterative | Referrals |
| h | Caching | TTL |
| i | DNS over UDP/TCP | Port 53 |

---

## Sujet

Implementer des analyseurs et simulateurs de protocoles reseau.

### Structures

```c
// ARP
typedef struct {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;             // a: Operation
    uint8_t sha[6];            // Sender MAC
    uint32_t spa;              // Sender IP
    uint8_t tha[6];            // Target MAC
    uint32_t tpa;              // Target IP
} arp_packet_t;

// ICMP
typedef struct {
    uint8_t type;              // b-e: Message type
    uint8_t code;
    uint16_t checksum;
    union {
        struct { uint16_t id; uint16_t seq; } echo;
        struct { uint16_t unused; uint16_t mtu; } pmtu;
        uint32_t gateway;
    };
} icmp_packet_t;

// DNS
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
    uint16_t type;             // b: A, AAAA, MX, etc.
    uint16_t class;
    uint32_t ttl;              // h: TTL for caching
    uint16_t rdlength;
    uint8_t rdata[256];
} dns_record_t;
```

### API

```c
// ============== ARP ==============
// 2.5.21

int arp_request_build(arp_packet_t *arp, uint32_t src_ip, uint32_t tgt_ip,
                      const uint8_t *src_mac);
int arp_reply_build(arp_packet_t *arp, uint32_t src_ip, uint32_t tgt_ip,
                    const uint8_t *src_mac, const uint8_t *tgt_mac);
int arp_parse(const uint8_t *data, size_t len, arp_packet_t *arp);
void arp_cache_show(void);
int arp_resolve(const char *ip, uint8_t *mac);

// ============== ICMP ==============
// 2.5.22

int icmp_echo_build(icmp_packet_t *icmp, uint16_t id, uint16_t seq);
int icmp_parse(const uint8_t *data, size_t len, icmp_packet_t *icmp);
const char *icmp_type_string(uint8_t type, uint8_t code);

// Traceroute implementation
typedef struct {
    int hop;
    char ip[INET_ADDRSTRLEN];
    double rtt_ms;
    bool timeout;
} traceroute_hop_t;

int traceroute(const char *host, int max_hops, traceroute_hop_t *hops);

// ============== DHCP ==============
// 2.5.23

typedef struct {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t options[312];
} dhcp_packet_t;

int dhcp_discover_build(dhcp_packet_t *pkt, const uint8_t *mac);
int dhcp_request_build(dhcp_packet_t *pkt, uint32_t requested_ip,
                       uint32_t server_ip, const uint8_t *mac);
int dhcp_parse(const uint8_t *data, size_t len, dhcp_packet_t *pkt);
void dhcp_simulate_dora(void);

// ============== DNS ==============
// 2.5.24

int dns_query_build(const char *name, uint16_t type, uint8_t *buf, size_t *len);
int dns_response_parse(const uint8_t *buf, size_t len,
                       dns_record_t *records, int max_records, int *count);
int dns_query_send(const char *server, const char *name, uint16_t type,
                   dns_record_t *records, int *count);

// Record type constants
#define DNS_TYPE_A     1
#define DNS_TYPE_AAAA  28
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_MX    15
#define DNS_TYPE_NS    2
#define DNS_TYPE_TXT   16

const char *dns_type_string(uint16_t type);
```

---

## Exemple

```c
#include "protocols.h"

void demo_arp(void) {
    printf("=== ARP Protocol ===\n");

    // 2.5.21.e: Show ARP cache
    arp_cache_show();

    // 2.5.21.b: Resolve IP to MAC
    uint8_t mac[6];
    if (arp_resolve("192.168.1.1", mac) == 0) {
        printf("192.168.1.1 -> %02x:%02x:%02x:%02x:%02x:%02x\n",
               mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
}

void demo_icmp(void) {
    printf("\n=== ICMP Protocol ===\n");

    // 2.5.22.a-e: ICMP types
    printf("ICMP Types:\n");
    printf("  Type 0: %s\n", icmp_type_string(0, 0));   // Echo Reply
    printf("  Type 3: %s\n", icmp_type_string(3, 0));   // Dest Unreachable
    printf("  Type 8: %s\n", icmp_type_string(8, 0));   // Echo Request
    printf("  Type 11: %s\n", icmp_type_string(11, 0)); // Time Exceeded

    // 2.5.22.f: Traceroute
    traceroute_hop_t hops[30];
    int n = traceroute("google.com", 30, hops);
    printf("\nTraceroute to google.com:\n");
    for (int i = 0; i < n; i++) {
        if (hops[i].timeout) {
            printf("  %2d: * * *\n", hops[i].hop);
        } else {
            printf("  %2d: %-15s  %.2f ms\n",
                   hops[i].hop, hops[i].ip, hops[i].rtt_ms);
        }
    }
}

void demo_dhcp(void) {
    printf("\n=== DHCP Protocol ===\n");

    // 2.5.23.b: DORA process
    dhcp_simulate_dora();
}

void demo_dns(void) {
    printf("\n=== DNS Protocol ===\n");

    // 2.5.24.b: Different record types
    dns_record_t records[10];
    int count;

    // A record
    dns_query_send("8.8.8.8", "google.com", DNS_TYPE_A, records, &count);
    printf("google.com A records:\n");
    for (int i = 0; i < count; i++) {
        printf("  %s\n", inet_ntoa(*(struct in_addr*)records[i].rdata));
    }

    // MX record
    dns_query_send("8.8.8.8", "gmail.com", DNS_TYPE_MX, records, &count);
    printf("\ngmail.com MX records:\n");
    for (int i = 0; i < count; i++) {
        printf("  %s (priority: %d)\n", records[i].name,
               ntohs(*(uint16_t*)records[i].rdata));
    }
}

int main(void) {
    demo_arp();
    demo_icmp();
    demo_dhcp();
    demo_dns();
    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_arp_build_parse()      // 2.5.21.a-d
#[test] fn test_arp_cache()            // 2.5.21.e
#[test] fn test_icmp_build_parse()     // 2.5.22.a-c
#[test] fn test_traceroute()           // 2.5.22.f
#[test] fn test_dhcp_dora()            // 2.5.23.b
#[test] fn test_dns_query()            // 2.5.24.c-e
#[test] fn test_dns_records()          // 2.5.24.b
```

---

## Bareme

| Critere | Points |
|---------|--------|
| ARP (2.5.21) | 25 |
| ICMP/Traceroute (2.5.22) | 25 |
| DHCP (2.5.23) | 20 |
| DNS query/response (2.5.24) | 30 |
| **Total** | **100** |

---

## Fichiers

```
ex10/
├── protocols.h
├── arp.c
├── icmp.c
├── traceroute.c
├── dhcp.c
├── dns.c
└── Makefile
```
