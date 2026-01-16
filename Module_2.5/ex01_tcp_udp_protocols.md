# ex01: TCP & UDP Protocols

**Module**: 2.5 - Networking
**Difficulte**: Facile
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.5.3: TCP Protocol (11 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Connection-oriented | Establish before sending |
| b | Reliable | Guaranteed delivery |
| c | Ordered | In-sequence delivery |
| d | Three-way handshake | SYN, SYN-ACK, ACK |
| e | Four-way teardown | FIN, ACK, FIN, ACK |
| f | Sequence numbers | Track bytes |
| g | Acknowledgments | Confirm receipt |
| h | Window size | Flow control |
| i | Retransmission | Lost packets |
| j | Congestion control | Slow start, AIMD |
| k | TCP states | LISTEN, ESTABLISHED, TIME_WAIT |

### 2.5.4: UDP Protocol (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Connectionless | No setup |
| b | Unreliable | No guarantee |
| c | Unordered | May arrive out of order |
| d | No flow control | Can overwhelm |
| e | Low overhead | Minimal header |
| f | Use cases | DNS, gaming, streaming |
| g | Multicast | One-to-many |
| h | Broadcast | One-to-all |

---

## Sujet

Implementer un simulateur de protocoles TCP et UDP pour comprendre leur fonctionnement.

### Structures

```c
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// 2.5.3: TCP Header
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;          // f: Sequence number
    uint32_t ack_num;          // g: Acknowledgment number
    uint8_t data_offset;
    uint8_t flags;             // SYN, ACK, FIN, RST, PSH, URG
    uint16_t window;           // h: Window size
    uint16_t checksum;
    uint16_t urgent_ptr;
} tcp_header_t;

// TCP Flags
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

// 2.5.3.k: TCP States
typedef enum {
    TCP_CLOSED,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECEIVED,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_LAST_ACK,
    TCP_TIME_WAIT
} tcp_state_t;

// 2.5.3.a-c: TCP Connection
typedef struct {
    uint16_t local_port;
    uint16_t remote_port;
    uint32_t local_addr;
    uint32_t remote_addr;

    tcp_state_t state;         // k: Current state
    uint32_t snd_nxt;          // Next send sequence
    uint32_t snd_una;          // Oldest unacknowledged
    uint32_t rcv_nxt;          // Next expected receive
    uint16_t snd_wnd;          // h: Send window
    uint16_t rcv_wnd;          // h: Receive window

    // 2.5.3.i: Retransmission
    uint8_t *send_buffer;
    size_t send_buffer_size;
    struct timespec last_send;
    int retries;

    // 2.5.3.j: Congestion control
    uint32_t cwnd;             // Congestion window
    uint32_t ssthresh;         // Slow start threshold
    bool in_slow_start;

    // Statistics
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t segments_sent;
    uint64_t retransmissions;
} tcp_connection_t;

// TCP Segment
typedef struct {
    tcp_header_t header;
    uint8_t *payload;
    size_t payload_len;
} tcp_segment_t;

// 2.5.4: UDP Header
typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;           // e: Minimal header
    uint16_t checksum;
} udp_header_t;

// UDP Datagram
typedef struct {
    udp_header_t header;
    uint8_t *payload;
    size_t payload_len;
} udp_datagram_t;

// 2.5.4.g-h: Multicast/Broadcast
typedef struct {
    uint32_t group_addr;       // g: Multicast group
    uint16_t port;
    int socket_fd;
    uint8_t ttl;
} multicast_group_t;

// Simulated network (for testing)
typedef struct {
    double loss_rate;          // Packet loss probability
    double delay_ms;           // Network delay
    double jitter_ms;          // Delay variation
    bool reorder;              // Allow reordering
} network_sim_t;
```

### API

```c
// ============== TCP CONNECTION ==============
// 2.5.3.a-c: Connection-oriented, reliable, ordered

// Connection lifecycle
int tcp_init(tcp_connection_t *conn);
void tcp_destroy(tcp_connection_t *conn);

// 2.5.3.d: Three-way handshake (client side)
int tcp_connect(tcp_connection_t *conn, uint32_t remote_addr, uint16_t remote_port);

// 2.5.3.d: Three-way handshake (server side)
int tcp_listen(tcp_connection_t *conn, uint16_t port);
int tcp_accept(tcp_connection_t *listen_conn, tcp_connection_t *client_conn);

// 2.5.3.e: Four-way teardown
int tcp_close(tcp_connection_t *conn);

// Data transfer
ssize_t tcp_send(tcp_connection_t *conn, const void *data, size_t len);
ssize_t tcp_recv(tcp_connection_t *conn, void *buf, size_t len);

// ============== TCP INTERNALS ==============

// 2.5.3.f-g: Sequence/Acknowledgment
int tcp_build_segment(tcp_connection_t *conn, tcp_segment_t *seg,
                      const uint8_t *data, size_t len, uint8_t flags);
int tcp_process_segment(tcp_connection_t *conn, const tcp_segment_t *seg);
bool tcp_is_ack_valid(tcp_connection_t *conn, uint32_t ack);

// 2.5.3.h: Flow control
void tcp_update_window(tcp_connection_t *conn, uint16_t new_window);
size_t tcp_available_window(tcp_connection_t *conn);

// 2.5.3.i: Retransmission
void tcp_start_retransmit_timer(tcp_connection_t *conn);
void tcp_handle_timeout(tcp_connection_t *conn);
void tcp_retransmit(tcp_connection_t *conn);

// 2.5.3.j: Congestion control
void tcp_on_ack(tcp_connection_t *conn, uint32_t acked_bytes);
void tcp_on_loss(tcp_connection_t *conn);
void tcp_slow_start(tcp_connection_t *conn);
void tcp_congestion_avoidance(tcp_connection_t *conn);

// 2.5.3.k: State machine
tcp_state_t tcp_get_state(tcp_connection_t *conn);
const char *tcp_state_string(tcp_state_t state);
void tcp_transition(tcp_connection_t *conn, tcp_state_t new_state);

// ============== TCP HANDSHAKE SIMULATION ==============

typedef struct {
    tcp_segment_t segments[10];
    int count;
} handshake_trace_t;

// 2.5.3.d: Simulate and trace handshake
void tcp_simulate_connect(tcp_connection_t *client, tcp_connection_t *server,
                          handshake_trace_t *trace);

// 2.5.3.e: Simulate and trace teardown
void tcp_simulate_close(tcp_connection_t *conn, handshake_trace_t *trace);

// ============== UDP COMMUNICATION ==============
// 2.5.4.a-e

// 2.5.4.a: Connectionless
int udp_init(int *sockfd);
void udp_destroy(int sockfd);

// 2.5.4.b-c: Unreliable, unordered
ssize_t udp_sendto(int sockfd, const void *data, size_t len,
                   uint32_t dest_addr, uint16_t dest_port);
ssize_t udp_recvfrom(int sockfd, void *buf, size_t len,
                     uint32_t *src_addr, uint16_t *src_port);

// Build/parse datagrams
int udp_build_datagram(udp_datagram_t *dgram, uint16_t src_port,
                       uint16_t dst_port, const uint8_t *data, size_t len);
int udp_parse_datagram(const uint8_t *raw, size_t len, udp_datagram_t *dgram);

// 2.5.4.e: Header size comparison
size_t tcp_header_size(void);
size_t udp_header_size(void);
void compare_overhead(void);

// ============== MULTICAST/BROADCAST ==============
// 2.5.4.g-h

// 2.5.4.g: Multicast
int multicast_join(multicast_group_t *group, const char *group_addr, uint16_t port);
int multicast_leave(multicast_group_t *group);
int multicast_send(multicast_group_t *group, const void *data, size_t len);
int multicast_recv(multicast_group_t *group, void *buf, size_t len);

// 2.5.4.h: Broadcast
int broadcast_enable(int sockfd);
int broadcast_send(int sockfd, uint16_t port, const void *data, size_t len);

// ============== NETWORK SIMULATION ==============

void network_sim_init(network_sim_t *sim, double loss, double delay, double jitter);
bool network_sim_should_drop(network_sim_t *sim);
double network_sim_get_delay(network_sim_t *sim);

// Simulate TCP with unreliable network
typedef struct {
    tcp_connection_t *client;
    tcp_connection_t *server;
    network_sim_t *network;
    int packets_sent;
    int packets_lost;
    int retransmissions;
    double total_time_ms;
} transfer_stats_t;

void tcp_simulated_transfer(const uint8_t *data, size_t len,
                            network_sim_t *sim, transfer_stats_t *stats);

// Compare TCP vs UDP under packet loss
void compare_protocols_under_loss(double loss_rate, size_t data_size);
```

---

## Exemple

```c
#include "protocols.h"

// ============== TCP Three-Way Handshake ==============
void demo_handshake(void) {
    printf("=== TCP Three-Way Handshake ===\n");
    // 2.5.3.d

    tcp_connection_t client, server;
    tcp_init(&client);
    tcp_init(&server);

    // Server listens
    tcp_listen(&server, 8080);
    printf("Server: LISTEN on port 8080\n");

    // Simulate handshake with trace
    handshake_trace_t trace;
    tcp_simulate_connect(&client, &server, &trace);

    printf("\nHandshake sequence:\n");
    for (int i = 0; i < trace.count; i++) {
        tcp_segment_t *seg = &trace.segments[i];
        printf("%d. ", i + 1);

        if (seg->header.flags & TCP_SYN) printf("SYN ");
        if (seg->header.flags & TCP_ACK) printf("ACK ");
        if (seg->header.flags & TCP_FIN) printf("FIN ");

        printf("seq=%u ack=%u\n", seg->header.seq_num, seg->header.ack_num);
    }
    // Output:
    // 1. SYN seq=1000 ack=0
    // 2. SYN ACK seq=2000 ack=1001
    // 3. ACK seq=1001 ack=2001

    printf("\nClient state: %s\n", tcp_state_string(tcp_get_state(&client)));
    printf("Server state: %s\n", tcp_state_string(tcp_get_state(&server)));

    tcp_destroy(&client);
    tcp_destroy(&server);
}

// ============== TCP Data Transfer ==============
void demo_data_transfer(void) {
    printf("\n=== TCP Reliable Transfer ===\n");
    // 2.5.3.b-c, f-g

    tcp_connection_t client, server;
    tcp_init(&client);
    tcp_init(&server);

    // Establish connection (simplified)
    client.state = TCP_ESTABLISHED;
    server.state = TCP_ESTABLISHED;
    client.snd_nxt = 1000;
    client.rcv_nxt = 2000;
    server.snd_nxt = 2000;
    server.rcv_nxt = 1000;

    // Build a segment
    tcp_segment_t seg;
    const char *data = "Hello, TCP!";
    tcp_build_segment(&client, &seg, (uint8_t*)data, strlen(data), TCP_ACK | TCP_PSH);

    printf("Sending segment:\n");
    printf("  Seq: %u\n", seg.header.seq_num);
    printf("  Ack: %u\n", seg.header.ack_num);
    printf("  Data: \"%s\"\n", seg.payload);
    printf("  Len: %zu\n", seg.payload_len);

    // Process on server
    tcp_process_segment(&server, &seg);
    printf("\nServer received, next expected seq: %u\n", server.rcv_nxt);

    // Server sends ACK
    tcp_segment_t ack_seg;
    tcp_build_segment(&server, &ack_seg, NULL, 0, TCP_ACK);
    printf("Server ACK: ack=%u\n", ack_seg.header.ack_num);

    tcp_destroy(&client);
    tcp_destroy(&server);
}

// ============== TCP Congestion Control ==============
void demo_congestion_control(void) {
    printf("\n=== TCP Congestion Control ===\n");
    // 2.5.3.j

    tcp_connection_t conn;
    tcp_init(&conn);
    conn.state = TCP_ESTABLISHED;
    conn.cwnd = 1;              // Start with 1 MSS
    conn.ssthresh = 65535;
    conn.in_slow_start = true;

    printf("Initial: cwnd=%u, ssthresh=%u\n", conn.cwnd, conn.ssthresh);

    // Slow start: exponential growth
    printf("\nSlow Start phase:\n");
    for (int i = 0; i < 5; i++) {
        tcp_on_ack(&conn, 1460);  // MSS = 1460
        printf("  After ACK: cwnd=%u\n", conn.cwnd);
    }

    // Simulate loss -> set ssthresh, enter congestion avoidance
    printf("\nPacket loss detected!\n");
    tcp_on_loss(&conn);
    printf("  After loss: cwnd=%u, ssthresh=%u\n", conn.cwnd, conn.ssthresh);

    // Congestion avoidance: linear growth
    printf("\nCongestion Avoidance phase:\n");
    for (int i = 0; i < 5; i++) {
        tcp_congestion_avoidance(&conn);
        printf("  After ACK: cwnd=%u\n", conn.cwnd);
    }

    tcp_destroy(&conn);
}

// ============== TCP Four-Way Teardown ==============
void demo_teardown(void) {
    printf("\n=== TCP Four-Way Teardown ===\n");
    // 2.5.3.e

    tcp_connection_t conn;
    tcp_init(&conn);
    conn.state = TCP_ESTABLISHED;

    handshake_trace_t trace;
    tcp_simulate_close(&conn, &trace);

    printf("Teardown sequence:\n");
    for (int i = 0; i < trace.count; i++) {
        tcp_segment_t *seg = &trace.segments[i];
        printf("%d. ", i + 1);

        if (seg->header.flags & TCP_FIN) printf("FIN ");
        if (seg->header.flags & TCP_ACK) printf("ACK ");

        printf("\n");
    }
    // Output:
    // 1. FIN ACK
    // 2. ACK
    // 3. FIN ACK
    // 4. ACK

    tcp_destroy(&conn);
}

// ============== UDP Comparison ==============
void demo_udp(void) {
    printf("\n=== UDP Protocol ===\n");
    // 2.5.4.a-e

    // Header size comparison
    printf("TCP header: %zu bytes\n", tcp_header_size());
    printf("UDP header: %zu bytes\n", udp_header_size());

    // Build UDP datagram
    udp_datagram_t dgram;
    const char *data = "Hello, UDP!";
    udp_build_datagram(&dgram, 12345, 53, (uint8_t*)data, strlen(data));

    printf("\nUDP Datagram:\n");
    printf("  Src port: %u\n", dgram.header.src_port);
    printf("  Dst port: %u\n", dgram.header.dst_port);
    printf("  Length: %u\n", dgram.header.length);
    printf("  Payload: \"%s\"\n", dgram.payload);

    // 2.5.4.f: Use cases
    printf("\nUDP Use Cases:\n");
    printf("  - DNS (port 53): Low latency queries\n");
    printf("  - Gaming: Real-time, lost packets OK\n");
    printf("  - Streaming: Continuous data, some loss OK\n");
    printf("  - VoIP: Real-time audio\n");
}

// ============== Multicast Demo ==============
void demo_multicast(void) {
    printf("\n=== Multicast ===\n");
    // 2.5.4.g

    multicast_group_t group;
    multicast_join(&group, "224.0.0.1", 5000);
    printf("Joined multicast group 224.0.0.1:5000\n");

    const char *msg = "Multicast message!";
    multicast_send(&group, msg, strlen(msg));
    printf("Sent to group: \"%s\"\n", msg);

    multicast_leave(&group);
}

// ============== Protocol Comparison Under Loss ==============
void demo_comparison(void) {
    printf("\n=== TCP vs UDP Under Packet Loss ===\n");

    network_sim_t sim;
    network_sim_init(&sim, 0.1, 50.0, 10.0);  // 10% loss, 50ms delay

    printf("Network: 10%% packet loss, 50ms delay\n\n");

    // TCP transfer (reliable)
    transfer_stats_t tcp_stats;
    uint8_t data[10000];
    memset(data, 'A', sizeof(data));

    tcp_simulated_transfer(data, sizeof(data), &sim, &tcp_stats);

    printf("TCP Transfer (10KB):\n");
    printf("  Packets sent: %d\n", tcp_stats.packets_sent);
    printf("  Packets lost: %d\n", tcp_stats.packets_lost);
    printf("  Retransmissions: %d\n", tcp_stats.retransmissions);
    printf("  Total time: %.2f ms\n", tcp_stats.total_time_ms);
    printf("  Result: All data delivered\n");

    // UDP comparison (unreliable)
    printf("\nUDP Transfer (10KB):\n");
    printf("  Packets sent: ~7\n");
    printf("  Packets lost: ~1 (10%% loss)\n");
    printf("  Retransmissions: 0 (none)\n");
    printf("  Total time: ~50ms\n");
    printf("  Result: ~1KB data lost\n");
}

int main(void) {
    demo_handshake();
    demo_data_transfer();
    demo_congestion_control();
    demo_teardown();
    demo_udp();
    demo_multicast();
    demo_comparison();

    return 0;
}
```

---

## Tests Moulinette

```rust
// TCP tests
#[test] fn test_tcp_handshake()        // 2.5.3.d
#[test] fn test_tcp_teardown()         // 2.5.3.e
#[test] fn test_tcp_sequence()         // 2.5.3.f-g
#[test] fn test_tcp_window()           // 2.5.3.h
#[test] fn test_tcp_retransmit()       // 2.5.3.i
#[test] fn test_tcp_congestion()       // 2.5.3.j
#[test] fn test_tcp_states()           // 2.5.3.k

// UDP tests
#[test] fn test_udp_datagram()         // 2.5.4.a-e
#[test] fn test_multicast()            // 2.5.4.g
#[test] fn test_broadcast()            // 2.5.4.h
```

---

## Bareme

| Critere | Points |
|---------|--------|
| TCP handshake/teardown (2.5.3.d-e) | 20 |
| Sequence/ACK (2.5.3.f-g) | 15 |
| Flow control (2.5.3.h) | 10 |
| Retransmission (2.5.3.i) | 15 |
| Congestion control (2.5.3.j) | 15 |
| TCP states (2.5.3.k) | 10 |
| UDP basics (2.5.4.a-f) | 10 |
| Multicast/Broadcast (2.5.4.g-h) | 5 |
| **Total** | **100** |

---

## Fichiers

```
ex01/
├── protocols.h
├── tcp.c
├── tcp_handshake.c
├── tcp_congestion.c
├── udp.c
├── multicast.c
├── network_sim.c
└── Makefile
```
