# ex06: I/O Multiplexing - poll & epoll

**Module**: 2.5 - Networking
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.5.13: I/O Multiplexing - poll (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | poll() | Improved select |
| b | struct pollfd | fd, events, revents |
| c | POLLIN | Ready to read |
| d | POLLOUT | Ready to write |
| e | POLLERR | Error |
| f | POLLHUP | Hung up |
| g | No fd limit | Dynamic array |
| h | Still O(n) | Scan all |
| i | ppoll() | With signal mask |

### 2.5.14: I/O Multiplexing - epoll (12 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | epoll | Linux-specific, scalable |
| b | epoll_create() | Create epoll instance |
| c | epoll_ctl() | Add/modify/remove fds |
| d | EPOLL_CTL_ADD | Add fd |
| e | EPOLL_CTL_MOD | Modify events |
| f | EPOLL_CTL_DEL | Remove fd |
| g | epoll_wait() | Wait for events |
| h | struct epoll_event | fd and events |
| i | Level-triggered | Default |
| j | Edge-triggered | EPOLLET |
| k | EPOLLONESHOT | One-shot |
| l | O(1) | Only active fds returned |

---

## Sujet

Implementer des serveurs haute performance avec poll() et epoll().

### Structures

```c
#include <poll.h>
#include <sys/epoll.h>

// 2.5.13: Poll wrapper
typedef struct {
    struct pollfd *fds;      // b: pollfd array
    nfds_t count;            // g: Dynamic size
    nfds_t capacity;
} poll_set_t;

// 2.5.14: Epoll wrapper
typedef struct {
    int epfd;                // b: epoll fd
    struct epoll_event *events;  // h: Event array
    int max_events;
    int event_count;
} epoll_set_t;

// High-performance server
typedef struct {
    int listen_fd;
    epoll_set_t epoll;
    int max_clients;
    void *user_data;
    bool running;
    uint64_t connections;
    uint64_t bytes_in;
    uint64_t bytes_out;
} hp_server_t;
```

### API

```c
// ============== POLL ==============
// 2.5.13

int poll_set_init(poll_set_t *ps, size_t initial_capacity);
void poll_set_destroy(poll_set_t *ps);
int poll_add(poll_set_t *ps, int fd, short events);
int poll_remove(poll_set_t *ps, int fd);
int poll_modify(poll_set_t *ps, int fd, short events);
int poll_wait(poll_set_t *ps, int timeout_ms);
int poll_wait_signal(poll_set_t *ps, int timeout_ms, const sigset_t *sigmask);

// Iterate results
bool poll_is_readable(poll_set_t *ps, int fd);
bool poll_is_writable(poll_set_t *ps, int fd);
bool poll_has_error(poll_set_t *ps, int fd);
bool poll_hung_up(poll_set_t *ps, int fd);

// ============== EPOLL ==============
// 2.5.14

int epoll_set_init(epoll_set_t *es, int max_events);
void epoll_set_destroy(epoll_set_t *es);
int epoll_add(epoll_set_t *es, int fd, uint32_t events, void *data);
int epoll_modify(epoll_set_t *es, int fd, uint32_t events, void *data);
int epoll_remove(epoll_set_t *es, int fd);
int epoll_wait_events(epoll_set_t *es, int timeout_ms);

// Event iteration
int epoll_get_event_count(epoll_set_t *es);
struct epoll_event *epoll_get_event(epoll_set_t *es, int index);
int epoll_event_fd(struct epoll_event *ev);
void *epoll_event_data(struct epoll_event *ev);

// Trigger modes
int epoll_add_level(epoll_set_t *es, int fd, uint32_t events);
int epoll_add_edge(epoll_set_t *es, int fd, uint32_t events);
int epoll_add_oneshot(epoll_set_t *es, int fd, uint32_t events);

// ============== HIGH-PERF SERVER ==============

typedef void (*hp_handler_t)(hp_server_t *srv, int fd, uint32_t events);

int hp_server_create(hp_server_t *srv, uint16_t port, int max_clients);
void hp_server_destroy(hp_server_t *srv);
void hp_server_run(hp_server_t *srv, hp_handler_t handler);
void hp_server_stop(hp_server_t *srv);

// Comparison benchmarks
void benchmark_select_vs_poll_vs_epoll(int num_connections, int iterations);
```

---

## Exemple

```c
#include "poll_epoll.h"

// ============== Poll Demo ==============
void demo_poll(void) {
    printf("=== Poll ===\n");

    poll_set_t ps;
    poll_set_init(&ps, 10);

    // 2.5.13.b: Add fds with events
    poll_add(&ps, STDIN_FILENO, POLLIN);  // c: POLLIN

    printf("Waiting for stdin (3 sec)...\n");

    // 2.5.13.a: poll() call
    int ready = poll_wait(&ps, 3000);

    if (ready > 0) {
        if (poll_is_readable(&ps, STDIN_FILENO)) {
            char buf[256];
            read(STDIN_FILENO, buf, sizeof(buf));
            printf("Got input!\n");
        }
    }

    // 2.5.13.g: No FD_SETSIZE limit
    printf("\npoll() advantages:\n");
    printf("  - No FD_SETSIZE limit (dynamic array)\n");
    printf("  - Separate events/revents (no rebuild)\n");

    // 2.5.13.h: Still O(n)
    printf("  - Still O(n) to scan results\n");

    poll_set_destroy(&ps);
}

// ============== Epoll Demo ==============
void demo_epoll(void) {
    printf("\n=== Epoll ===\n");

    epoll_set_t es;
    epoll_set_init(&es, 64);

    // 2.5.14.b,c,d: Create and add
    epoll_add(&es, STDIN_FILENO, EPOLLIN, NULL);

    printf("epoll_wait for stdin (3 sec)...\n");

    // 2.5.14.g: Wait
    int n = epoll_wait_events(&es, 3000);

    // 2.5.14.l: Only ready fds returned
    printf("Ready count: %d\n", n);
    for (int i = 0; i < n; i++) {
        struct epoll_event *ev = epoll_get_event(&es, i);
        printf("  fd=%d events=%u\n", epoll_event_fd(ev), ev->events);
    }

    epoll_set_destroy(&es);
}

// ============== Edge vs Level Triggered ==============
void demo_trigger_modes(void) {
    printf("\n=== Trigger Modes ===\n");

    // 2.5.14.i: Level-triggered (default)
    printf("Level-triggered (default):\n");
    printf("  - Notifies while data available\n");
    printf("  - Easier to program\n");

    // 2.5.14.j: Edge-triggered
    printf("\nEdge-triggered (EPOLLET):\n");
    printf("  - Notifies on state change only\n");
    printf("  - Must drain all data or miss events\n");
    printf("  - More efficient for high-throughput\n");

    // 2.5.14.k: One-shot
    printf("\nOne-shot (EPOLLONESHOT):\n");
    printf("  - Only one event per arm\n");
    printf("  - Must re-arm after handling\n");
    printf("  - Useful for thread pool\n");
}

// ============== High-Performance Server ==============
void hp_handler(hp_server_t *srv, int fd, uint32_t events) {
    if (fd == srv->listen_fd) {
        // New connection
        int client = accept(fd, NULL, NULL);
        if (client >= 0) {
            epoll_add_edge(&srv->epoll, client, EPOLLIN);
            srv->connections++;
        }
    } else {
        if (events & EPOLLIN) {
            char buf[4096];
            ssize_t n;
            // Edge-triggered: must read all
            while ((n = recv(fd, buf, sizeof(buf), 0)) > 0) {
                send(fd, buf, n, 0);  // Echo
                srv->bytes_in += n;
                srv->bytes_out += n;
            }
            if (n == 0 || (n < 0 && errno != EAGAIN)) {
                epoll_remove(&srv->epoll, fd);
                close(fd);
            }
        }
    }
}

void run_hp_server(uint16_t port) {
    hp_server_t srv;
    hp_server_create(&srv, port, 10000);
    printf("High-performance epoll server on port %d\n", port);
    hp_server_run(&srv, hp_handler);
    hp_server_destroy(&srv);
}

int main(void) {
    demo_poll();
    demo_epoll();
    demo_trigger_modes();
    benchmark_select_vs_poll_vs_epoll(1000, 100);
    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_poll_add_remove()      // 2.5.13.a-b
#[test] fn test_poll_events()          // 2.5.13.c-f
#[test] fn test_poll_dynamic()         // 2.5.13.g
#[test] fn test_epoll_create()         // 2.5.14.b
#[test] fn test_epoll_ctl()            // 2.5.14.c-f
#[test] fn test_epoll_wait()           // 2.5.14.g-h
#[test] fn test_epoll_modes()          // 2.5.14.i-k
#[test] fn test_epoll_scalability()    // 2.5.14.l
```

---

## Bareme

| Critere | Points |
|---------|--------|
| poll() basics (2.5.13.a-f) | 25 |
| poll() advantages (2.5.13.g-i) | 10 |
| epoll creation/ctl (2.5.14.b-f) | 25 |
| epoll_wait (2.5.14.g-h) | 15 |
| Trigger modes (2.5.14.i-k) | 15 |
| O(1) scalability (2.5.14.l) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex06/
├── poll_epoll.h
├── poll.c
├── epoll.c
├── hp_server.c
├── benchmark.c
└── Makefile
```
