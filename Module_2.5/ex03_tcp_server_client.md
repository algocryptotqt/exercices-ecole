# ex03: TCP Server & Client

**Module**: 2.5 - Networking
**Difficulte**: Moyen
**Duree**: 5h
**Score qualite**: 97/100

## Concepts Couverts

### 2.5.7: TCP Server (11 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | socket() | Create socket |
| b | setsockopt() | Set options |
| c | SO_REUSEADDR | Reuse address |
| d | bind() | Assign address |
| e | listen() | Mark as passive |
| f | Backlog | Connection queue size |
| g | accept() | Accept connection |
| h | Client socket | New fd for client |
| i | send/recv | Exchange data |
| j | close() | Close connection |
| k | Server loop | Accept in loop |

### 2.5.8: TCP Client (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | socket() | Create socket |
| b | connect() | Initiate connection |
| c | Blocking connect | Waits for handshake |
| d | send() | Send data |
| e | recv() | Receive data |
| f | Return 0 | Connection closed |
| g | close() | Close connection |
| h | Error handling | Check returns |

---

## Sujet

Implementer un serveur et client TCP complets avec gestion d'erreurs et multiples clients.

### Structures

```c
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

// 2.5.7: TCP Server
typedef struct {
    int listen_fd;              // a: Server socket
    uint16_t port;
    char bind_addr[INET_ADDRSTRLEN];
    int backlog;                // f: Connection queue
    bool running;
    int max_clients;
    int client_count;

    // Options
    bool reuse_addr;            // c: SO_REUSEADDR
    bool reuse_port;
    int recv_timeout_ms;
    int send_timeout_ms;
} tcp_server_t;

// Client connection
typedef struct {
    int fd;                     // h: Client socket
    struct sockaddr_in addr;
    char addr_str[INET_ADDRSTRLEN];
    uint16_t port;
    time_t connected_at;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    void *user_data;
} client_conn_t;

// 2.5.8: TCP Client
typedef struct {
    int fd;                     // a: Socket
    struct sockaddr_in server_addr;
    char server_host[256];
    uint16_t server_port;
    bool connected;             // b,c: Connection state
    int connect_timeout_ms;
    int recv_timeout_ms;

    // Statistics
    uint64_t bytes_sent;
    uint64_t bytes_received;
} tcp_client_t;

// Server callbacks
typedef void (*on_connect_t)(tcp_server_t *server, client_conn_t *client);
typedef void (*on_data_t)(tcp_server_t *server, client_conn_t *client,
                          const uint8_t *data, size_t len);
typedef void (*on_disconnect_t)(tcp_server_t *server, client_conn_t *client);

typedef struct {
    on_connect_t on_connect;
    on_data_t on_data;
    on_disconnect_t on_disconnect;
} server_callbacks_t;

// Error info
typedef struct {
    int code;
    const char *message;
    const char *syscall;
} net_error_t;
```

### API

```c
// ============== TCP SERVER ==============
// 2.5.7

// Lifecycle
int server_init(tcp_server_t *server, const char *bind_addr, uint16_t port);
int server_start(tcp_server_t *server);
void server_stop(tcp_server_t *server);
void server_destroy(tcp_server_t *server);

// 2.5.7.b-c: Socket options
int server_set_reuse_addr(tcp_server_t *server, bool enable);
int server_set_reuse_port(tcp_server_t *server, bool enable);
int server_set_backlog(tcp_server_t *server, int backlog);
int server_set_timeouts(tcp_server_t *server, int recv_ms, int send_ms);

// 2.5.7.d: Bind
int server_bind(tcp_server_t *server);

// 2.5.7.e-f: Listen
int server_listen(tcp_server_t *server, int backlog);

// 2.5.7.g-h: Accept
int server_accept(tcp_server_t *server, client_conn_t *client);
int server_accept_nonblock(tcp_server_t *server, client_conn_t *client);

// 2.5.7.i: Data exchange
ssize_t server_send(client_conn_t *client, const void *data, size_t len);
ssize_t server_recv(client_conn_t *client, void *buf, size_t len);
ssize_t server_send_all(client_conn_t *client, const void *data, size_t len);
ssize_t server_recv_all(client_conn_t *client, void *buf, size_t len);

// 2.5.7.j: Close
int client_close(client_conn_t *client);

// 2.5.7.k: Server loop patterns
void server_run_single(tcp_server_t *server, server_callbacks_t *callbacks);
void server_run_forking(tcp_server_t *server, server_callbacks_t *callbacks);
void server_run_threaded(tcp_server_t *server, server_callbacks_t *callbacks);

// ============== TCP CLIENT ==============
// 2.5.8

// Lifecycle
int client_init(tcp_client_t *client);
void client_destroy(tcp_client_t *client);

// 2.5.8.a-c: Connect
int client_connect(tcp_client_t *client, const char *host, uint16_t port);
int client_connect_timeout(tcp_client_t *client, const char *host,
                           uint16_t port, int timeout_ms);
int client_reconnect(tcp_client_t *client);

// 2.5.8.d: Send
ssize_t client_send(tcp_client_t *client, const void *data, size_t len);
ssize_t client_send_all(tcp_client_t *client, const void *data, size_t len);

// 2.5.8.e-f: Receive
ssize_t client_recv(tcp_client_t *client, void *buf, size_t len);
ssize_t client_recv_all(tcp_client_t *client, void *buf, size_t len);
ssize_t client_recv_until(tcp_client_t *client, void *buf, size_t max,
                          char delim);  // Read until delimiter

// 2.5.8.g: Close
int client_close(tcp_client_t *client);

// 2.5.8.h: Error handling
bool client_is_connected(tcp_client_t *client);
int client_get_error(tcp_client_t *client, net_error_t *err);

// ============== UTILITY FUNCTIONS ==============

// Address helpers
int get_client_addr_string(client_conn_t *client, char *buf, size_t len);
int get_local_addr(int fd, char *buf, size_t len, uint16_t *port);
int get_peer_addr(int fd, char *buf, size_t len, uint16_t *port);

// Timeout operations
int set_recv_timeout(int fd, int timeout_ms);
int set_send_timeout(int fd, int timeout_ms);

// Error handling
void print_socket_error(const char *msg);
const char *socket_error_string(int err);

// ============== ECHO SERVER/CLIENT ==============
// Complete example implementations

typedef struct {
    tcp_server_t server;
    uint64_t total_clients;
    uint64_t total_bytes;
} echo_server_t;

int echo_server_create(echo_server_t *srv, uint16_t port);
void echo_server_run(echo_server_t *srv);
void echo_server_destroy(echo_server_t *srv);

int echo_client_run(const char *host, uint16_t port, const char *message);

// ============== LINE-BASED PROTOCOL ==============

typedef struct {
    char *buffer;
    size_t capacity;
    size_t len;
    size_t pos;
} line_buffer_t;

int line_buffer_init(line_buffer_t *lb, size_t capacity);
void line_buffer_destroy(line_buffer_t *lb);
int line_buffer_read_line(line_buffer_t *lb, int fd, char *line, size_t max);
int line_buffer_write_line(int fd, const char *line);
```

---

## Exemple

```c
#include "tcp.h"

// ============== Simple Echo Server ==============

void on_client_connect(tcp_server_t *server, client_conn_t *client) {
    printf("Client connected: %s:%d (fd=%d)\n",
           client->addr_str, client->port, client->fd);
}

void on_client_data(tcp_server_t *server, client_conn_t *client,
                    const uint8_t *data, size_t len) {
    printf("Received %zu bytes from %s\n", len, client->addr_str);

    // Echo back
    ssize_t sent = server_send(client, data, len);
    if (sent > 0) {
        printf("Echoed %zd bytes\n", sent);
    }
}

void on_client_disconnect(tcp_server_t *server, client_conn_t *client) {
    printf("Client disconnected: %s:%d\n",
           client->addr_str, client->port);
    printf("  Bytes sent: %lu, received: %lu\n",
           client->bytes_sent, client->bytes_received);
}

void run_server(uint16_t port) {
    tcp_server_t server;
    server_init(&server, "0.0.0.0", port);

    // 2.5.7.b-c: Set socket options
    server_set_reuse_addr(&server, true);

    // 2.5.7.d: Bind
    if (server_bind(&server) < 0) {
        perror("bind");
        return;
    }

    // 2.5.7.e-f: Listen with backlog
    if (server_listen(&server, 10) < 0) {
        perror("listen");
        return;
    }

    printf("Server listening on %s:%d\n", server.bind_addr, server.port);

    // 2.5.7.k: Server loop
    server_callbacks_t callbacks = {
        .on_connect = on_client_connect,
        .on_data = on_client_data,
        .on_disconnect = on_client_disconnect
    };

    server_run_threaded(&server, &callbacks);

    server_destroy(&server);
}

// ============== Manual Server Loop ==============

void run_server_manual(uint16_t port) {
    printf("=== Manual Server Loop ===\n");

    // 2.5.7.a: Create socket
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return;
    }

    // 2.5.7.b-c: SO_REUSEADDR
    int opt = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(listen_fd);
        return;
    }

    // 2.5.7.d: Bind
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(listen_fd);
        return;
    }

    // 2.5.7.e-f: Listen
    if (listen(listen_fd, 5) < 0) {
        perror("listen");
        close(listen_fd);
        return;
    }

    printf("Listening on port %d...\n", port);

    // 2.5.7.k: Accept loop
    while (1) {
        // 2.5.7.g: Accept
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        // 2.5.7.h: New fd for client
        int client_fd = accept(listen_fd, (struct sockaddr*)&client_addr,
                               &client_len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("Client connected: %s:%d\n", client_ip, ntohs(client_addr.sin_port));

        // 2.5.7.i: Exchange data
        char buf[1024];
        ssize_t n;
        while ((n = recv(client_fd, buf, sizeof(buf), 0)) > 0) {
            printf("Received: %.*s\n", (int)n, buf);
            send(client_fd, buf, n, 0);  // Echo
        }

        // 2.5.7.j: Close
        printf("Client disconnected\n");
        close(client_fd);
    }

    close(listen_fd);
}

// ============== TCP Client ==============

void run_client(const char *host, uint16_t port) {
    printf("=== TCP Client ===\n");

    tcp_client_t client;
    client_init(&client);

    // 2.5.8.a-c: Connect
    printf("Connecting to %s:%d...\n", host, port);
    if (client_connect(&client, host, port) < 0) {
        // 2.5.8.h: Error handling
        net_error_t err;
        client_get_error(&client, &err);
        printf("Connect failed: %s (%s)\n", err.message, err.syscall);
        client_destroy(&client);
        return;
    }

    printf("Connected!\n");

    // 2.5.8.d: Send
    const char *msg = "Hello, Server!";
    ssize_t sent = client_send(&client, msg, strlen(msg));
    if (sent < 0) {
        perror("send");
    } else {
        printf("Sent: %s (%zd bytes)\n", msg, sent);
    }

    // 2.5.8.e: Receive
    char buf[1024];
    ssize_t received = client_recv(&client, buf, sizeof(buf) - 1);

    // 2.5.8.f: Check for connection closed
    if (received == 0) {
        printf("Server closed connection\n");
    } else if (received > 0) {
        buf[received] = '\0';
        printf("Received: %s (%zd bytes)\n", buf, received);
    } else {
        perror("recv");
    }

    // 2.5.8.g: Close
    client_close(&client);
    client_destroy(&client);
}

// ============== Manual Client ==============

void run_client_manual(const char *host, uint16_t port) {
    printf("=== Manual Client ===\n");

    // 2.5.8.a: Create socket
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return;
    }

    // Resolve address
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port)
    };

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid address: %s\n", host);
        close(fd);
        return;
    }

    // 2.5.8.b-c: Connect (blocking)
    printf("Connecting...\n");
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        // 2.5.8.h: Error handling
        perror("connect");
        close(fd);
        return;
    }

    printf("Connected to %s:%d\n", host, port);

    // 2.5.8.d: Send
    const char *message = "Hello from client!";
    ssize_t sent = send(fd, message, strlen(message), 0);
    if (sent < 0) {
        perror("send");
    } else {
        printf("Sent %zd bytes\n", sent);
    }

    // 2.5.8.e: Receive
    char buf[1024];
    ssize_t received = recv(fd, buf, sizeof(buf) - 1, 0);

    // 2.5.8.f: Check return value
    if (received == 0) {
        printf("Connection closed by server\n");
    } else if (received > 0) {
        buf[received] = '\0';
        printf("Received: %s\n", buf);
    } else {
        perror("recv");
    }

    // 2.5.8.g: Close
    close(fd);
}

// ============== Error Handling Demo ==============

void demo_error_handling(void) {
    printf("\n=== Error Handling ===\n");

    tcp_client_t client;
    client_init(&client);

    // Try to connect to non-existent server
    printf("Connecting to non-existent server...\n");
    int result = client_connect_timeout(&client, "192.0.2.1", 12345, 2000);

    if (result < 0) {
        net_error_t err;
        client_get_error(&client, &err);

        printf("Error code: %d\n", err.code);
        printf("Message: %s\n", err.message);
        printf("Syscall: %s\n", err.syscall);

        // Common errors
        switch (err.code) {
            case ECONNREFUSED:
                printf("-> Connection refused (no server)\n");
                break;
            case ETIMEDOUT:
                printf("-> Connection timed out\n");
                break;
            case ENETUNREACH:
                printf("-> Network unreachable\n");
                break;
            case EHOSTUNREACH:
                printf("-> Host unreachable\n");
                break;
        }
    }

    client_destroy(&client);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s server|client [port] [host]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "server") == 0) {
        uint16_t port = argc > 2 ? atoi(argv[2]) : 8080;
        run_server(port);
    } else if (strcmp(argv[1], "client") == 0) {
        const char *host = argc > 3 ? argv[3] : "127.0.0.1";
        uint16_t port = argc > 2 ? atoi(argv[2]) : 8080;
        run_client(host, port);
    } else if (strcmp(argv[1], "demo") == 0) {
        demo_error_handling();
    }

    return 0;
}
```

---

## Tests Moulinette

```rust
// Server tests
#[test] fn test_server_create()        // 2.5.7.a
#[test] fn test_server_options()       // 2.5.7.b-c
#[test] fn test_server_bind()          // 2.5.7.d
#[test] fn test_server_listen()        // 2.5.7.e-f
#[test] fn test_server_accept()        // 2.5.7.g-h
#[test] fn test_server_io()            // 2.5.7.i
#[test] fn test_server_close()         // 2.5.7.j
#[test] fn test_server_loop()          // 2.5.7.k

// Client tests
#[test] fn test_client_connect()       // 2.5.8.a-c
#[test] fn test_client_send()          // 2.5.8.d
#[test] fn test_client_recv()          // 2.5.8.e-f
#[test] fn test_client_close()         // 2.5.8.g
#[test] fn test_client_errors()        // 2.5.8.h
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Server creation (2.5.7.a-c) | 15 |
| Bind/Listen (2.5.7.d-f) | 15 |
| Accept (2.5.7.g-h) | 15 |
| Server I/O (2.5.7.i-k) | 15 |
| Client connect (2.5.8.a-c) | 15 |
| Client I/O (2.5.8.d-f) | 15 |
| Error handling (2.5.8.g-h) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex03/
├── tcp.h
├── server.c
├── client.c
├── server_loops.c
├── line_protocol.c
├── echo_server.c
├── echo_client.c
└── Makefile
```
