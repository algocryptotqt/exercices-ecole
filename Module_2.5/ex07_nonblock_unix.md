# ex07: Non-Blocking I/O & Unix Domain Sockets

**Module**: 2.5 - Networking
**Difficulte**: Moyen
**Duree**: 5h
**Score qualite**: 96/100

## Concepts Couverts

### 2.5.15: Non-Blocking I/O (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Blocking | Default behavior |
| b | O_NONBLOCK | Non-blocking flag |
| c | fcntl() | Set flag |
| d | EAGAIN/EWOULDBLOCK | Would block |
| e | Partial operations | May not complete |
| f | Event loop | poll/epoll + non-blocking |
| g | State machine | Handle partial progress |

### 2.5.16: Unix Domain Sockets (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | AF_UNIX | Local communication |
| b | Socket path | Filesystem path |
| c | sockaddr_un | Address structure |
| d | Faster | No network stack |
| e | File descriptors | Can pass fds |
| f | Credentials | Can get peer credentials |
| g | Abstract namespace | Linux-specific |
| h | Datagram | SOCK_DGRAM support |
| i | Use cases | IPC, X11, Docker |

---

## Sujet

Maitriser les I/O non-bloquantes et la communication locale via Unix sockets.

### Structures

```c
#include <fcntl.h>
#include <sys/un.h>
#include <sys/socket.h>

// 2.5.15: Non-blocking connection state
typedef enum {
    CONN_CONNECTING,
    CONN_CONNECTED,
    CONN_READING,
    CONN_WRITING,
    CONN_CLOSED
} conn_state_t;

typedef struct {
    int fd;
    conn_state_t state;        // g: State machine
    uint8_t *read_buf;
    size_t read_pos;
    size_t read_target;
    uint8_t *write_buf;
    size_t write_pos;
    size_t write_len;
} nonblock_conn_t;

// 2.5.16: Unix socket wrapper
typedef struct {
    int fd;
    struct sockaddr_un addr;   // c: Address
    char path[108];            // b: Path
    bool abstract;             // g: Abstract namespace
} unix_socket_t;

// Credential passing
typedef struct {
    pid_t pid;
    uid_t uid;
    gid_t gid;
} peer_cred_t;
```

### API

```c
// ============== NON-BLOCKING I/O ==============
// 2.5.15

// 2.5.15.b-c: Set non-blocking
int set_nonblocking(int fd);
int set_blocking(int fd);
bool is_nonblocking(int fd);

// 2.5.15.d: Error handling
bool is_would_block(int err);

// 2.5.15.e: Partial I/O
ssize_t nonblock_read(int fd, void *buf, size_t len);
ssize_t nonblock_write(int fd, const void *buf, size_t len);
ssize_t nonblock_read_all(nonblock_conn_t *conn, size_t target);
ssize_t nonblock_write_all(nonblock_conn_t *conn);

// 2.5.15.f-g: Event loop with state machine
int nonblock_connect(nonblock_conn_t *conn, const char *host, uint16_t port);
int nonblock_process(nonblock_conn_t *conn, uint32_t events);

// ============== UNIX DOMAIN SOCKETS ==============
// 2.5.16

// 2.5.16.a-c: Create and bind
int unix_socket_create(unix_socket_t *sock, int type);
int unix_socket_bind(unix_socket_t *sock, const char *path);
int unix_socket_listen(unix_socket_t *sock, int backlog);
int unix_socket_accept(unix_socket_t *sock, unix_socket_t *client);
int unix_socket_connect(unix_socket_t *sock, const char *path);
void unix_socket_close(unix_socket_t *sock);

// 2.5.16.g: Abstract namespace
int unix_socket_bind_abstract(unix_socket_t *sock, const char *name);
int unix_socket_connect_abstract(unix_socket_t *sock, const char *name);

// 2.5.16.e: Pass file descriptors
int unix_send_fd(int sock, int fd_to_send);
int unix_recv_fd(int sock);

// 2.5.16.f: Get peer credentials
int unix_get_peer_cred(int sock, peer_cred_t *cred);

// 2.5.16.h: Datagram mode
int unix_dgram_send(unix_socket_t *sock, const char *dest_path,
                    const void *data, size_t len);
int unix_dgram_recv(unix_socket_t *sock, char *src_path, size_t path_len,
                    void *buf, size_t len);

// Comparison with TCP
void benchmark_unix_vs_tcp(int iterations);
```

---

## Exemple

```c
#include "nonblock_unix.h"

void demo_nonblocking(void) {
    printf("=== Non-Blocking I/O ===\n");

    int fd = socket(AF_INET, SOCK_STREAM, 0);

    // 2.5.15.a: Default is blocking
    printf("Default: blocking I/O\n");

    // 2.5.15.b-c: Set non-blocking with fcntl
    set_nonblocking(fd);
    printf("After fcntl(O_NONBLOCK): non-blocking\n");

    // 2.5.15.d: Would-block handling
    char buf[1024];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n < 0 && is_would_block(errno)) {
        printf("EAGAIN: no data available, try again later\n");
    }

    close(fd);
}

void demo_unix_socket(void) {
    printf("\n=== Unix Domain Sockets ===\n");

    // 2.5.16.a-c: Create and bind
    unix_socket_t server;
    unix_socket_create(&server, SOCK_STREAM);
    unix_socket_bind(&server, "/tmp/demo.sock");
    unix_socket_listen(&server, 5);
    printf("Server: bound to %s\n", server.path);

    // 2.5.16.d: Performance
    printf("\nUnix sockets are faster:\n");
    printf("  - No TCP/IP stack overhead\n");
    printf("  - Direct kernel memory copy\n");

    // Fork a client
    if (fork() == 0) {
        // Child: client
        unix_socket_t client;
        unix_socket_create(&client, SOCK_STREAM);
        unix_socket_connect(&client, "/tmp/demo.sock");

        const char *msg = "Hello Unix!";
        send(client.fd, msg, strlen(msg), 0);

        unix_socket_close(&client);
        exit(0);
    }

    // Parent: accept and receive
    unix_socket_t client;
    unix_socket_accept(&server, &client);

    // 2.5.16.f: Get peer credentials
    peer_cred_t cred;
    unix_get_peer_cred(client.fd, &cred);
    printf("Peer: pid=%d, uid=%d, gid=%d\n", cred.pid, cred.uid, cred.gid);

    char buf[256];
    ssize_t n = recv(client.fd, buf, sizeof(buf) - 1, 0);
    buf[n] = '\0';
    printf("Received: %s\n", buf);

    unix_socket_close(&client);
    unix_socket_close(&server);
    unlink("/tmp/demo.sock");
}

void demo_fd_passing(void) {
    printf("\n=== File Descriptor Passing ===\n");
    // 2.5.16.e

    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, sv);

    // Open a file and pass its fd
    int fd = open("/etc/hostname", O_RDONLY);
    unix_send_fd(sv[0], fd);
    close(fd);

    // Receive fd on other end
    int received_fd = unix_recv_fd(sv[1]);
    char buf[256];
    read(received_fd, buf, sizeof(buf));
    printf("Read from passed fd: %s", buf);

    close(received_fd);
    close(sv[0]);
    close(sv[1]);
}

void demo_abstract_namespace(void) {
    printf("\n=== Abstract Namespace ===\n");
    // 2.5.16.g

    unix_socket_t sock;
    unix_socket_create(&sock, SOCK_STREAM);

    // Abstract: starts with \0, no filesystem entry
    unix_socket_bind_abstract(&sock, "my_abstract_socket");
    printf("Bound to abstract socket @my_abstract_socket\n");
    printf("  - No filesystem cleanup needed\n");
    printf("  - Automatically removed on close\n");

    unix_socket_close(&sock);
}

int main(void) {
    demo_nonblocking();
    demo_unix_socket();
    demo_fd_passing();
    demo_abstract_namespace();
    benchmark_unix_vs_tcp(10000);
    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_nonblocking()          // 2.5.15.b-c
#[test] fn test_would_block()          // 2.5.15.d
#[test] fn test_partial_io()           // 2.5.15.e
#[test] fn test_unix_socket()          // 2.5.16.a-c
#[test] fn test_fd_passing()           // 2.5.16.e
#[test] fn test_peer_cred()            // 2.5.16.f
#[test] fn test_abstract()             // 2.5.16.g
#[test] fn test_unix_dgram()           // 2.5.16.h
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Non-blocking setup (2.5.15.b-c) | 15 |
| Error handling (2.5.15.d-e) | 15 |
| State machine (2.5.15.f-g) | 15 |
| Unix socket basics (2.5.16.a-d) | 20 |
| FD passing (2.5.16.e) | 15 |
| Credentials/Abstract (2.5.16.f-g) | 10 |
| Datagram mode (2.5.16.h) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex07/
├── nonblock_unix.h
├── nonblock.c
├── unix_socket.c
├── fd_passing.c
└── Makefile
```
