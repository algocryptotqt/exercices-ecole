# ex05: Socket Options & I/O Multiplexing (select)

**Module**: 2.5 - Networking
**Difficulte**: Moyen
**Duree**: 5h
**Score qualite**: 96/100

## Concepts Couverts

### 2.5.11: Socket Options (11 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | setsockopt() | Set option |
| b | getsockopt() | Get option |
| c | SOL_SOCKET | Socket level |
| d | SO_REUSEADDR | Reuse address |
| e | SO_REUSEPORT | Load balancing |
| f | SO_KEEPALIVE | Keep connection alive |
| g | SO_RCVBUF | Receive buffer size |
| h | SO_SNDBUF | Send buffer size |
| i | SO_LINGER | Linger on close |
| j | TCP_NODELAY | Disable Nagle |
| k | TCP_CORK | Cork writes |

### 2.5.12: I/O Multiplexing - select (11 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Problem | Multiple sockets |
| b | select() | Wait on multiple fds |
| c | fd_set | Set of descriptors |
| d | FD_ZERO | Clear set |
| e | FD_SET | Add fd |
| f | FD_CLR | Remove fd |
| g | FD_ISSET | Test fd |
| h | nfds | Highest fd + 1 |
| i | timeout | Wait duration |
| j | Limitations | FD_SETSIZE (1024) |
| k | O(n) scan | Check each fd |

---

## Sujet

Maitriser les options de socket et l'I/O multiplexing avec select().

### Structures

```c
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

// 2.5.11: Socket options wrapper
typedef struct {
    int fd;
    int level;           // c: SOL_SOCKET, IPPROTO_TCP
    int option;
    union {
        int int_val;
        struct linger linger_val;   // i: Linger struct
        struct timeval time_val;
    };
    socklen_t len;
} socket_option_t;

// Common option presets
typedef struct {
    bool reuse_addr;     // d: SO_REUSEADDR
    bool reuse_port;     // e: SO_REUSEPORT
    bool keepalive;      // f: SO_KEEPALIVE
    int recv_buf;        // g: SO_RCVBUF
    int send_buf;        // h: SO_SNDBUF
    bool linger;         // i: SO_LINGER
    int linger_time;
    bool nodelay;        // j: TCP_NODELAY
    bool cork;           // k: TCP_CORK
    int recv_timeout_ms;
    int send_timeout_ms;
} socket_opts_preset_t;

// 2.5.12: Select wrapper
typedef struct {
    fd_set read_fds;     // c: fd_set for reading
    fd_set write_fds;    //    fd_set for writing
    fd_set except_fds;   //    fd_set for exceptions
    fd_set read_ready;   //    Ready after select
    fd_set write_ready;
    fd_set except_ready;
    int max_fd;          // h: nfds
    int ready_count;
} select_set_t;

// Multi-client server using select
typedef struct {
    int listen_fd;
    int *client_fds;
    int client_count;
    int max_clients;
    select_set_t ss;
} select_server_t;
```

### API

```c
// ============== SOCKET OPTIONS ==============
// 2.5.11

// 2.5.11.a-b: Get/Set options
int sockopt_set_int(int fd, int level, int option, int value);
int sockopt_get_int(int fd, int level, int option, int *value);

// 2.5.11.d: SO_REUSEADDR
int sockopt_reuseaddr(int fd, bool enable);

// 2.5.11.e: SO_REUSEPORT
int sockopt_reuseport(int fd, bool enable);

// 2.5.11.f: SO_KEEPALIVE
int sockopt_keepalive(int fd, bool enable);
int sockopt_keepalive_config(int fd, int idle, int interval, int count);

// 2.5.11.g-h: Buffer sizes
int sockopt_rcvbuf(int fd, int size);
int sockopt_sndbuf(int fd, int size);
int sockopt_get_rcvbuf(int fd);
int sockopt_get_sndbuf(int fd);

// 2.5.11.i: SO_LINGER
int sockopt_linger(int fd, bool enable, int timeout_sec);

// 2.5.11.j: TCP_NODELAY (disable Nagle algorithm)
int sockopt_nodelay(int fd, bool enable);

// 2.5.11.k: TCP_CORK (cork writes)
int sockopt_cork(int fd, bool enable);

// Timeouts
int sockopt_recv_timeout(int fd, int timeout_ms);
int sockopt_send_timeout(int fd, int timeout_ms);

// Apply preset
int sockopt_apply_preset(int fd, const socket_opts_preset_t *preset);
void sockopt_preset_server(socket_opts_preset_t *preset);
void sockopt_preset_client(socket_opts_preset_t *preset);

// Debug: print all options
void sockopt_print_all(int fd);

// ============== SELECT ==============
// 2.5.12

// 2.5.12.c-d: Initialize
void select_set_init(select_set_t *ss);
void select_set_clear(select_set_t *ss);

// 2.5.12.e: Add fd
void select_add_read(select_set_t *ss, int fd);
void select_add_write(select_set_t *ss, int fd);
void select_add_except(select_set_t *ss, int fd);

// 2.5.12.f: Remove fd
void select_remove(select_set_t *ss, int fd);

// 2.5.12.b,h,i: Wait for activity
int select_wait(select_set_t *ss, int timeout_ms);
int select_wait_forever(select_set_t *ss);
int select_poll(select_set_t *ss);  // Immediate return

// 2.5.12.g: Test if ready
bool select_is_readable(select_set_t *ss, int fd);
bool select_is_writable(select_set_t *ss, int fd);
bool select_has_exception(select_set_t *ss, int fd);

// Iterate ready fds
int select_get_ready_count(select_set_t *ss);
int *select_get_readable_fds(select_set_t *ss, int *count);

// ============== SELECT SERVER ==============
// 2.5.12.a,k: Handle multiple clients

int select_server_create(select_server_t *srv, uint16_t port, int max_clients);
void select_server_destroy(select_server_t *srv);

// Main loop
typedef void (*client_handler_t)(select_server_t *srv, int client_fd,
                                 const uint8_t *data, size_t len);
void select_server_run(select_server_t *srv, client_handler_t handler);
void select_server_stop(select_server_t *srv);

// Client management
int select_server_accept(select_server_t *srv);
void select_server_disconnect(select_server_t *srv, int client_fd);
int select_server_broadcast(select_server_t *srv, const void *data, size_t len);

// ============== DEMONSTRATIONS ==============

// Show option effects
void demo_reuseaddr(void);
void demo_nodelay_effect(void);
void demo_buffer_sizes(void);
void demo_linger(void);

// Show select behavior
void demo_select_stdin(void);
void demo_select_multiple(void);
void demo_select_timeout(void);

// 2.5.12.j: Limitations demo
void demo_select_limits(void);
```

---

## Exemple

```c
#include "sockopt_select.h"

// ============== Socket Options Demo ==============

void demo_socket_options(void) {
    printf("=== Socket Options ===\n");

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    // 2.5.11.a-b: Set and get options
    printf("\n--- Get/Set Options ---\n");

    // 2.5.11.d: SO_REUSEADDR
    sockopt_reuseaddr(fd, true);
    int val;
    sockopt_get_int(fd, SOL_SOCKET, SO_REUSEADDR, &val);
    printf("SO_REUSEADDR: %d\n", val);

    // 2.5.11.g-h: Buffer sizes
    printf("\n--- Buffer Sizes ---\n");
    printf("Initial RCVBUF: %d\n", sockopt_get_rcvbuf(fd));
    printf("Initial SNDBUF: %d\n", sockopt_get_sndbuf(fd));

    sockopt_rcvbuf(fd, 65536);
    sockopt_sndbuf(fd, 65536);

    printf("After setting:\n");
    printf("  RCVBUF: %d\n", sockopt_get_rcvbuf(fd));  // May be doubled by kernel
    printf("  SNDBUF: %d\n", sockopt_get_sndbuf(fd));

    // 2.5.11.j: TCP_NODELAY
    printf("\n--- TCP_NODELAY (Nagle) ---\n");
    printf("Nagle algorithm: ON by default\n");
    printf("  -> Small writes are buffered\n");
    sockopt_nodelay(fd, true);
    printf("After TCP_NODELAY=1:\n");
    printf("  -> All writes sent immediately\n");

    // 2.5.11.k: TCP_CORK
    printf("\n--- TCP_CORK ---\n");
    printf("Cork writes until uncorked:\n");
    sockopt_cork(fd, true);
    printf("  TCP_CORK=1 (corked)\n");
    // write(fd, header, ...);
    // write(fd, body, ...);
    sockopt_cork(fd, false);
    printf("  TCP_CORK=0 (sent as one)\n");

    // 2.5.11.i: SO_LINGER
    printf("\n--- SO_LINGER ---\n");
    sockopt_linger(fd, true, 5);
    printf("SO_LINGER enabled, timeout=5s\n");
    printf("  -> close() will block up to 5s to send remaining data\n");

    // Print all options
    printf("\n--- All Options ---\n");
    sockopt_print_all(fd);

    close(fd);
}

// ============== Select Demo ==============

void demo_select_basic(void) {
    printf("\n=== Select Basic ===\n");

    // 2.5.12.c-d: Initialize fd_set
    select_set_t ss;
    select_set_init(&ss);

    // 2.5.12.e: Add stdin
    select_add_read(&ss, STDIN_FILENO);
    printf("Added stdin to read set\n");

    // 2.5.12.h: nfds is highest fd + 1
    printf("max_fd (nfds-1): %d\n", ss.max_fd);

    // 2.5.12.b,i: Wait with timeout
    printf("Waiting 3 seconds for input...\n");
    int ready = select_wait(&ss, 3000);

    if (ready > 0) {
        // 2.5.12.g: Test if ready
        if (select_is_readable(&ss, STDIN_FILENO)) {
            char buf[256];
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf) - 1);
            buf[n] = '\0';
            printf("Read: %s", buf);
        }
    } else if (ready == 0) {
        printf("Timeout!\n");
    } else {
        perror("select");
    }
}

void demo_select_multiple_fds(void) {
    printf("\n=== Select with Multiple FDs ===\n");
    // 2.5.12.a,k: Multiple sockets problem

    // Create multiple connections (simulated)
    int fds[3];
    for (int i = 0; i < 3; i++) {
        fds[i] = socket(AF_INET, SOCK_STREAM, 0);
    }

    select_set_t ss;
    select_set_init(&ss);

    // 2.5.12.e: Add all to set
    for (int i = 0; i < 3; i++) {
        select_add_read(&ss, fds[i]);
        printf("Added fd %d\n", fds[i]);
    }

    printf("Highest fd: %d\n", ss.max_fd);

    // 2.5.12.f: Remove one
    select_remove(&ss, fds[1]);
    printf("Removed fd %d\n", fds[1]);

    // 2.5.12.k: O(n) scan of results
    printf("\nNote: select() requires O(n) scan of all fds\n");
    printf("  for (fd = 0; fd <= max_fd; fd++)\n");
    printf("      if (FD_ISSET(fd, &readfds)) ...\n");

    for (int i = 0; i < 3; i++) {
        close(fds[i]);
    }
}

void demo_select_limits(void) {
    printf("\n=== Select Limitations ===\n");
    // 2.5.12.j

    printf("FD_SETSIZE: %d\n", FD_SETSIZE);
    printf("  -> Maximum fds select() can handle\n");
    printf("  -> Typically 1024 on Linux\n");

    printf("\nLimitations of select():\n");
    printf("  1. FD_SETSIZE hard limit (%d)\n", FD_SETSIZE);
    printf("  2. fd_set copied on each call\n");
    printf("  3. O(n) to scan results\n");
    printf("  4. Must rebuild fd_set after each call\n");
    printf("\nFor large scale: use poll() or epoll()\n");
}

// ============== Echo Server with Select ==============

void echo_handler(select_server_t *srv, int client_fd,
                  const uint8_t *data, size_t len) {
    printf("[Client %d] Received %zu bytes\n", client_fd, len);
    send(client_fd, data, len, 0);  // Echo back
}

void run_select_server(uint16_t port) {
    printf("\n=== Select Echo Server ===\n");

    select_server_t srv;
    if (select_server_create(&srv, port, 10) < 0) {
        perror("server create");
        return;
    }

    printf("Server listening on port %d\n", port);
    printf("Max clients: 10\n");

    // Main loop using select
    select_server_run(&srv, echo_handler);

    select_server_destroy(&srv);
}

// Manual select server implementation
void run_manual_select_server(uint16_t port) {
    printf("\n=== Manual Select Server ===\n");

    // Create listen socket
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockopt_reuseaddr(listen_fd, true);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };

    bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(listen_fd, 5);

    printf("Listening on port %d\n", port);

    // Client tracking
    int clients[FD_SETSIZE];
    int client_count = 0;

    while (1) {
        // 2.5.12.c-d: Initialize fd_set each iteration
        fd_set readfds;
        FD_ZERO(&readfds);  // d: Clear

        // 2.5.12.e: Add listen socket
        FD_SET(listen_fd, &readfds);
        int max_fd = listen_fd;

        // Add all clients
        for (int i = 0; i < client_count; i++) {
            FD_SET(clients[i], &readfds);
            if (clients[i] > max_fd) max_fd = clients[i];
        }

        // 2.5.12.i: Timeout
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};

        // 2.5.12.b,h: select()
        int ready = select(max_fd + 1, &readfds, NULL, NULL, &tv);

        if (ready < 0) {
            perror("select");
            break;
        }
        if (ready == 0) {
            continue;  // Timeout
        }

        // 2.5.12.g: Check listen socket
        if (FD_ISSET(listen_fd, &readfds)) {
            int client = accept(listen_fd, NULL, NULL);
            if (client >= 0 && client_count < FD_SETSIZE - 1) {
                clients[client_count++] = client;
                printf("New client: fd=%d, total=%d\n", client, client_count);
            }
        }

        // 2.5.12.k: Check all clients (O(n))
        for (int i = 0; i < client_count; i++) {
            if (FD_ISSET(clients[i], &readfds)) {
                char buf[1024];
                ssize_t n = recv(clients[i], buf, sizeof(buf), 0);

                if (n <= 0) {
                    printf("Client %d disconnected\n", clients[i]);
                    close(clients[i]);
                    // 2.5.12.f: Would use FD_CLR to remove
                    clients[i] = clients[--client_count];
                    i--;
                } else {
                    send(clients[i], buf, n, 0);  // Echo
                }
            }
        }
    }

    close(listen_fd);
}

int main(int argc, char *argv[]) {
    demo_socket_options();
    demo_select_basic();
    demo_select_multiple_fds();
    demo_select_limits();

    if (argc > 1 && strcmp(argv[1], "server") == 0) {
        uint16_t port = argc > 2 ? atoi(argv[2]) : 8080;
        run_manual_select_server(port);
    }

    return 0;
}
```

---

## Tests Moulinette

```rust
// Socket options
#[test] fn test_reuseaddr()            // 2.5.11.d
#[test] fn test_reuseport()            // 2.5.11.e
#[test] fn test_keepalive()            // 2.5.11.f
#[test] fn test_buffer_sizes()         // 2.5.11.g-h
#[test] fn test_linger()               // 2.5.11.i
#[test] fn test_nodelay()              // 2.5.11.j
#[test] fn test_cork()                 // 2.5.11.k

// Select
#[test] fn test_select_init()          // 2.5.12.c-d
#[test] fn test_select_add_remove()    // 2.5.12.e-f
#[test] fn test_select_isset()         // 2.5.12.g
#[test] fn test_select_timeout()       // 2.5.12.i
#[test] fn test_select_server()        // 2.5.12.a-b,k
```

---

## Bareme

| Critere | Points |
|---------|--------|
| setsockopt/getsockopt (2.5.11.a-c) | 15 |
| Common options (2.5.11.d-f) | 15 |
| Buffer/Linger (2.5.11.g-i) | 15 |
| TCP options (2.5.11.j-k) | 10 |
| fd_set operations (2.5.12.c-g) | 20 |
| select() usage (2.5.12.b,h-i) | 15 |
| Multi-client server (2.5.12.a,k) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex05/
├── sockopt_select.h
├── socket_options.c
├── select_wrapper.c
├── select_server.c
├── demos.c
└── Makefile
```
