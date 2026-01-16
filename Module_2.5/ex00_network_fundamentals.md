# ex00: Network Fundamentals & IP Addressing

**Module**: 2.5 - Networking
**Difficulte**: Facile
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.5.1: Network Fundamentals (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | OSI model | 7 layers |
| b | TCP/IP model | 4 layers |
| c | Physical layer | Bits on wire |
| d | Data link layer | Frames, MAC addresses |
| e | Network layer | Packets, IP addresses |
| f | Transport layer | Segments, ports |
| g | Application layer | Protocols |
| h | Encapsulation | Headers wrapping |
| i | MTU | Maximum transmission unit |
| j | Fragmentation | Breaking large packets |

### 2.5.2: IP Addressing (11 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | IPv4 address | 32 bits |
| b | Dotted decimal | 192.168.1.1 |
| c | Network/host | Split address |
| d | Subnet mask | /24, 255.255.255.0 |
| e | CIDR notation | 10.0.0.0/8 |
| f | Private ranges | 10.x, 172.16-31.x, 192.168.x |
| g | Loopback | 127.0.0.1 |
| h | Broadcast | 255.255.255.255 |
| i | IPv6 address | 128 bits |
| j | IPv6 notation | 2001:db8::1 |
| k | NAT | Network Address Translation |

---

## Sujet

Implementer une bibliotheque de manipulation d'adresses IP et d'analyse de paquets reseau.

### Structures

```c
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>

// 2.5.1: OSI/TCP-IP layer info
typedef enum {
    LAYER_PHYSICAL = 1,      // c: Physical layer
    LAYER_DATALINK = 2,      // d: Data link
    LAYER_NETWORK = 3,       // e: Network
    LAYER_TRANSPORT = 4,     // f: Transport
    LAYER_SESSION = 5,       // OSI only
    LAYER_PRESENTATION = 6,  // OSI only
    LAYER_APPLICATION = 7    // g: Application
} osi_layer_t;

typedef struct {
    const char *name;
    const char *pdu;           // Protocol Data Unit
    const char *protocols;     // Common protocols
    const char *addressing;    // Address type
} layer_info_t;

// 2.5.1.h: Encapsulated packet
typedef struct {
    // Ethernet header (Layer 2)
    uint8_t eth_dest[6];       // d: MAC dest
    uint8_t eth_src[6];        // d: MAC src
    uint16_t eth_type;

    // IP header (Layer 3)
    uint8_t ip_version;        // e: IP version
    uint8_t ip_ihl;
    uint16_t ip_total_len;     // i: Total length
    uint16_t ip_id;
    uint16_t ip_flags_frag;    // j: Fragmentation
    uint8_t ip_ttl;
    uint8_t ip_protocol;
    uint32_t ip_src;           // e: IP src
    uint32_t ip_dst;           // e: IP dst

    // Transport header (Layer 4)
    uint16_t src_port;         // f: Source port
    uint16_t dst_port;         // f: Dest port

    // Payload
    uint8_t *payload;
    size_t payload_len;
} packet_t;

// 2.5.2: IPv4 address structure
typedef struct {
    union {
        uint32_t addr;           // a: 32-bit address
        uint8_t octets[4];       // b: Dotted decimal parts
    };
} ipv4_addr_t;

// 2.5.2.c-e: Network with subnet
typedef struct {
    ipv4_addr_t network;        // c: Network part
    ipv4_addr_t mask;           // d: Subnet mask
    int prefix_len;             // e: CIDR prefix
    ipv4_addr_t broadcast;      // h: Broadcast address
    uint32_t host_count;        // Number of usable hosts
} subnet_t;

// 2.5.2.i-j: IPv6 address
typedef struct {
    union {
        uint8_t bytes[16];       // i: 128 bits
        uint16_t groups[8];      // j: 8 groups of 16 bits
    };
} ipv6_addr_t;

// Address classification
typedef enum {
    ADDR_CLASS_A,
    ADDR_CLASS_B,
    ADDR_CLASS_C,
    ADDR_CLASS_D,               // Multicast
    ADDR_CLASS_E,               // Reserved
    ADDR_PRIVATE,               // f: Private ranges
    ADDR_LOOPBACK,              // g: Loopback
    ADDR_BROADCAST,             // h: Broadcast
    ADDR_LINK_LOCAL,
    ADDR_PUBLIC
} addr_class_t;
```

### API

```c
// ============== OSI/TCP-IP LAYERS ==============
// 2.5.1

// 2.5.1.a-b: Get layer information
const layer_info_t *get_osi_layer(osi_layer_t layer);
const layer_info_t *get_tcpip_layer(int layer);  // 1-4
const char *layer_to_string(osi_layer_t layer);
int osi_to_tcpip(osi_layer_t osi_layer);

// 2.5.1.h: Encapsulation/decapsulation
int packet_parse(const uint8_t *raw, size_t len, packet_t *pkt);
int packet_build(const packet_t *pkt, uint8_t *buf, size_t *len);
void packet_print(const packet_t *pkt);

// 2.5.1.i-j: MTU and fragmentation
size_t get_mtu(const char *interface);
int packet_fragment(const packet_t *pkt, size_t mtu, packet_t **fragments, int *count);
int packet_reassemble(packet_t **fragments, int count, packet_t *result);

// ============== IPv4 ADDRESSING ==============
// 2.5.2.a-h

// 2.5.2.a-b: Address parsing/formatting
int ipv4_from_string(const char *str, ipv4_addr_t *addr);
int ipv4_to_string(const ipv4_addr_t *addr, char *buf, size_t len);

// 2.5.2.c-e: Subnet operations
int subnet_from_cidr(const char *cidr, subnet_t *sub);
int subnet_from_mask(const ipv4_addr_t *addr, const ipv4_addr_t *mask, subnet_t *sub);
int subnet_calculate(subnet_t *sub);  // Calculate broadcast, host count
bool subnet_contains(const subnet_t *sub, const ipv4_addr_t *addr);

// 2.5.2.f-h: Address classification
addr_class_t ipv4_classify(const ipv4_addr_t *addr);
bool ipv4_is_private(const ipv4_addr_t *addr);
bool ipv4_is_loopback(const ipv4_addr_t *addr);
bool ipv4_is_broadcast(const ipv4_addr_t *addr);
bool ipv4_is_multicast(const ipv4_addr_t *addr);

// Address manipulation
ipv4_addr_t ipv4_network(const ipv4_addr_t *addr, const ipv4_addr_t *mask);
ipv4_addr_t ipv4_host(const ipv4_addr_t *addr, const ipv4_addr_t *mask);
int ipv4_compare(const ipv4_addr_t *a, const ipv4_addr_t *b);

// ============== IPv6 ADDRESSING ==============
// 2.5.2.i-k

// 2.5.2.i-j: IPv6 parsing/formatting
int ipv6_from_string(const char *str, ipv6_addr_t *addr);
int ipv6_to_string(const ipv6_addr_t *addr, char *buf, size_t len);
int ipv6_to_string_full(const ipv6_addr_t *addr, char *buf, size_t len);  // No abbreviation

// IPv6 classification
bool ipv6_is_loopback(const ipv6_addr_t *addr);
bool ipv6_is_link_local(const ipv6_addr_t *addr);
bool ipv6_is_unique_local(const ipv6_addr_t *addr);
bool ipv6_is_multicast(const ipv6_addr_t *addr);

// IPv4-IPv6 mapping
void ipv4_to_ipv6_mapped(const ipv4_addr_t *v4, ipv6_addr_t *v6);
bool ipv6_is_ipv4_mapped(const ipv6_addr_t *addr);
void ipv6_to_ipv4(const ipv6_addr_t *v6, ipv4_addr_t *v4);

// ============== SUBNET CALCULATOR ==============

typedef struct {
    subnet_t *subnets;
    int count;
} subnet_list_t;

// VLSM (Variable Length Subnet Masking)
int subnet_divide(const subnet_t *network, int num_subnets, subnet_list_t *result);
int subnet_vlsm(const subnet_t *network, int *host_counts, int count, subnet_list_t *result);
void subnet_list_free(subnet_list_t *list);

// Supernetting (route aggregation)
int subnet_aggregate(const subnet_t *subnets, int count, subnet_t *result);

// ============== NAT SIMULATION ==============
// 2.5.2.k

typedef struct {
    ipv4_addr_t internal_ip;
    uint16_t internal_port;
    ipv4_addr_t external_ip;
    uint16_t external_port;
    time_t expires;
} nat_entry_t;

typedef struct {
    nat_entry_t *entries;
    int count;
    int capacity;
    ipv4_addr_t public_ip;
    uint16_t next_port;
} nat_table_t;

int nat_table_init(nat_table_t *nat, const ipv4_addr_t *public_ip);
void nat_table_destroy(nat_table_t *nat);
int nat_translate_outbound(nat_table_t *nat, packet_t *pkt);
int nat_translate_inbound(nat_table_t *nat, packet_t *pkt);
void nat_table_print(const nat_table_t *nat);
```

---

## Exemple

```c
#include "network.h"

int main(void) {
    // ============== OSI Layers ==============
    printf("=== OSI Model ===\n");

    // 2.5.1.a: OSI 7 layers
    for (int i = 1; i <= 7; i++) {
        const layer_info_t *info = get_osi_layer(i);
        printf("Layer %d: %s\n", i, info->name);
        printf("  PDU: %s\n", info->pdu);
        printf("  Protocols: %s\n", info->protocols);
    }

    // 2.5.1.b: TCP/IP 4 layers
    printf("\n=== TCP/IP Model ===\n");
    for (int i = 1; i <= 4; i++) {
        const layer_info_t *info = get_tcpip_layer(i);
        printf("Layer %d: %s\n", i, info->name);
    }

    // 2.5.1.h: Packet encapsulation
    printf("\n=== Encapsulation ===\n");
    packet_t pkt = {
        .eth_src = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
        .eth_dest = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        .eth_type = 0x0800,  // IPv4
        .ip_version = 4,
        .ip_ttl = 64,
        .ip_protocol = 6,    // TCP
        .src_port = 12345,
        .dst_port = 80
    };

    ipv4_addr_t src, dst;
    ipv4_from_string("192.168.1.100", &src);
    ipv4_from_string("10.0.0.1", &dst);
    pkt.ip_src = src.addr;
    pkt.ip_dst = dst.addr;

    uint8_t raw[1500];
    size_t len;
    packet_build(&pkt, raw, &len);
    printf("Built packet: %zu bytes\n", len);
    packet_print(&pkt);

    // ============== IPv4 Addressing ==============
    printf("\n=== IPv4 Addressing ===\n");

    // 2.5.2.a-b: Parse and format
    ipv4_addr_t addr;
    ipv4_from_string("192.168.1.100", &addr);

    char buf[INET_ADDRSTRLEN];
    ipv4_to_string(&addr, buf, sizeof(buf));
    printf("Address: %s\n", buf);
    printf("  Octets: %d.%d.%d.%d\n",
           addr.octets[0], addr.octets[1],
           addr.octets[2], addr.octets[3]);
    printf("  32-bit: 0x%08X\n", ntohl(addr.addr));

    // 2.5.2.c-e: Subnet calculation
    printf("\n=== Subnet Calculation ===\n");
    subnet_t sub;
    subnet_from_cidr("192.168.1.0/24", &sub);
    subnet_calculate(&sub);

    char net_str[INET_ADDRSTRLEN], bcast_str[INET_ADDRSTRLEN];
    ipv4_to_string(&sub.network, net_str, sizeof(net_str));
    ipv4_to_string(&sub.broadcast, bcast_str, sizeof(bcast_str));

    printf("Network: %s/%d\n", net_str, sub.prefix_len);
    printf("Broadcast: %s\n", bcast_str);
    printf("Usable hosts: %u\n", sub.host_count);

    // 2.5.2.f-h: Address classification
    printf("\n=== Address Classification ===\n");
    const char *test_addrs[] = {
        "10.0.0.1",          // f: Private (Class A)
        "172.16.0.1",        // f: Private (Class B)
        "192.168.1.1",       // f: Private (Class C)
        "127.0.0.1",         // g: Loopback
        "255.255.255.255",   // h: Broadcast
        "8.8.8.8",           // Public
        "224.0.0.1"          // Multicast
    };

    for (int i = 0; i < 7; i++) {
        ipv4_from_string(test_addrs[i], &addr);
        addr_class_t cls = ipv4_classify(&addr);
        printf("%-18s -> ", test_addrs[i]);

        if (ipv4_is_private(&addr)) printf("Private ");
        if (ipv4_is_loopback(&addr)) printf("Loopback ");
        if (ipv4_is_broadcast(&addr)) printf("Broadcast ");
        if (ipv4_is_multicast(&addr)) printf("Multicast ");
        if (cls == ADDR_PUBLIC) printf("Public");
        printf("\n");
    }

    // Check if address is in subnet
    ipv4_from_string("192.168.1.50", &addr);
    printf("\n192.168.1.50 in 192.168.1.0/24? %s\n",
           subnet_contains(&sub, &addr) ? "Yes" : "No");

    ipv4_from_string("192.168.2.50", &addr);
    printf("192.168.2.50 in 192.168.1.0/24? %s\n",
           subnet_contains(&sub, &addr) ? "Yes" : "No");

    // ============== IPv6 Addressing ==============
    // 2.5.2.i-j
    printf("\n=== IPv6 Addressing ===\n");

    ipv6_addr_t v6;
    ipv6_from_string("2001:db8::1", &v6);

    char v6_buf[INET6_ADDRSTRLEN];
    ipv6_to_string(&v6, v6_buf, sizeof(v6_buf));
    printf("Abbreviated: %s\n", v6_buf);

    ipv6_to_string_full(&v6, v6_buf, sizeof(v6_buf));
    printf("Full: %s\n", v6_buf);

    // Special addresses
    ipv6_from_string("::1", &v6);
    printf("::1 is loopback? %s\n",
           ipv6_is_loopback(&v6) ? "Yes" : "No");

    ipv6_from_string("fe80::1", &v6);
    printf("fe80::1 is link-local? %s\n",
           ipv6_is_link_local(&v6) ? "Yes" : "No");

    // 2.5.2.k: IPv4-mapped IPv6
    ipv4_from_string("192.168.1.1", &addr);
    ipv4_to_ipv6_mapped(&addr, &v6);
    ipv6_to_string(&v6, v6_buf, sizeof(v6_buf));
    printf("IPv4-mapped: %s\n", v6_buf);

    // ============== NAT Simulation ==============
    printf("\n=== NAT Simulation ===\n");

    nat_table_t nat;
    ipv4_addr_t public_ip;
    ipv4_from_string("203.0.113.1", &public_ip);
    nat_table_init(&nat, &public_ip);

    // Outbound packet (internal -> external)
    packet_t outbound = pkt;
    ipv4_from_string("192.168.1.10", &addr);
    outbound.ip_src = addr.addr;
    outbound.src_port = 54321;

    ipv4_from_string("8.8.8.8", &addr);
    outbound.ip_dst = addr.addr;
    outbound.dst_port = 53;

    printf("Before NAT:\n");
    printf("  Src: 192.168.1.10:54321 -> Dst: 8.8.8.8:53\n");

    nat_translate_outbound(&nat, &outbound);

    char src_str[INET_ADDRSTRLEN];
    ipv4_addr_t translated = { .addr = outbound.ip_src };
    ipv4_to_string(&translated, src_str, sizeof(src_str));
    printf("After NAT:\n");
    printf("  Src: %s:%d -> Dst: 8.8.8.8:53\n", src_str, outbound.src_port);

    nat_table_print(&nat);
    nat_table_destroy(&nat);

    // ============== Subnet Division ==============
    printf("\n=== Subnet Division ===\n");

    subnet_from_cidr("10.0.0.0/8", &sub);
    subnet_list_t subnets;

    // Divide into 4 equal subnets
    subnet_divide(&sub, 4, &subnets);
    printf("Divided 10.0.0.0/8 into 4 subnets:\n");
    for (int i = 0; i < subnets.count; i++) {
        ipv4_to_string(&subnets.subnets[i].network, buf, sizeof(buf));
        printf("  %s/%d\n", buf, subnets.subnets[i].prefix_len);
    }
    subnet_list_free(&subnets);

    return 0;
}
```

---

## Tests Moulinette

```rust
// Network fundamentals
#[test] fn test_osi_layers()           // 2.5.1.a
#[test] fn test_tcpip_layers()         // 2.5.1.b
#[test] fn test_layer_mapping()        // 2.5.1.c-g
#[test] fn test_encapsulation()        // 2.5.1.h
#[test] fn test_fragmentation()        // 2.5.1.i-j

// IPv4 addressing
#[test] fn test_ipv4_parse()           // 2.5.2.a-b
#[test] fn test_subnet_cidr()          // 2.5.2.c-e
#[test] fn test_private_ranges()       // 2.5.2.f
#[test] fn test_special_addresses()    // 2.5.2.g-h
#[test] fn test_ipv6_parse()           // 2.5.2.i-j
#[test] fn test_nat_simulation()       // 2.5.2.k
```

---

## Bareme

| Critere | Points |
|---------|--------|
| OSI/TCP-IP layers (2.5.1.a-g) | 20 |
| Encapsulation (2.5.1.h-j) | 15 |
| IPv4 addressing (2.5.2.a-e) | 25 |
| Address classification (2.5.2.f-h) | 15 |
| IPv6 support (2.5.2.i-j) | 15 |
| NAT simulation (2.5.2.k) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex00/
├── network.h
├── layers.c
├── ipv4.c
├── ipv6.c
├── subnet.c
├── nat.c
├── packet.c
└── Makefile
```
