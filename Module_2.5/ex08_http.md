# ex08: HTTP Protocol & Server

**Module**: 2.5 - Networking
**Difficulte**: Difficile
**Duree**: 7h
**Score qualite**: 97/100

## Concepts Couverts

### 2.5.17: HTTP Protocol Basics (12 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Request format | Method URI Version |
| b | Methods | GET, POST, PUT, DELETE |
| c | Headers | Key: Value |
| d | Body | After blank line |
| e | Response format | Version Status Reason |
| f | Status codes | 200, 404, 500 |
| g | Content-Length | Body size |
| h | Content-Type | MIME type |
| i | Connection | Keep-Alive, close |
| j | Chunked transfer | Unknown length |
| k | HTTP/1.1 | Persistent connections |
| l | HTTP/2 | Multiplexing |

### 2.5.18: Building HTTP Server (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Parse request line | Method, path, version |
| b | Parse headers | Until blank line |
| c | Handle GET | Return file |
| d | Handle POST | Process body |
| e | Build response | Status line, headers, body |
| f | Static files | Serve from directory |
| g | MIME types | Content-Type mapping |
| h | 404 handling | File not found |
| i | Concurrent | Thread per connection |
| j | Event-driven | epoll-based |

---

## Sujet

Implementer un serveur HTTP complet avec support des methodes GET/POST.

### Structures

```c
// HTTP Request
typedef struct {
    char method[16];           // b: GET, POST, etc.
    char uri[2048];
    char path[1024];
    char query[1024];
    char version[16];          // a: HTTP/1.1
    http_header_t *headers;    // c: Headers
    int header_count;
    char *body;                // d: Body
    size_t body_len;
    size_t content_length;     // g: Content-Length
} http_request_t;

// HTTP Response
typedef struct {
    int status_code;           // f: 200, 404, 500
    char status_text[64];
    http_header_t *headers;
    int header_count;
    char *body;
    size_t body_len;
    bool chunked;              // j: Chunked transfer
} http_response_t;

typedef struct {
    char name[256];
    char value[4096];
} http_header_t;

// HTTP Server
typedef struct {
    int listen_fd;
    char root_dir[1024];       // f: Static files root
    uint16_t port;
    bool running;
    bool keep_alive;           // i,k: Persistent connections
} http_server_t;
```

### API

```c
// ============== HTTP PARSING ==============
// 2.5.17.a-d

int http_request_parse(const char *raw, size_t len, http_request_t *req);
void http_request_free(http_request_t *req);
const char *http_request_header(http_request_t *req, const char *name);

// ============== HTTP RESPONSE ==============
// 2.5.17.e-j

int http_response_init(http_response_t *res, int status);
void http_response_set_header(http_response_t *res, const char *name, const char *value);
void http_response_set_body(http_response_t *res, const void *body, size_t len);
int http_response_build(http_response_t *res, char *buf, size_t *len);
void http_response_free(http_response_t *res);

// Status helpers
const char *http_status_text(int code);

// ============== HTTP SERVER ==============
// 2.5.18

int http_server_create(http_server_t *srv, uint16_t port, const char *root);
void http_server_destroy(http_server_t *srv);
void http_server_run(http_server_t *srv);

// Request handlers
typedef int (*http_handler_t)(http_request_t *req, http_response_t *res, void *ctx);
void http_server_route(http_server_t *srv, const char *path, http_handler_t handler);

// 2.5.18.c-h: Built-in handlers
int http_serve_static(http_request_t *req, http_response_t *res, const char *root);
int http_handle_get(http_server_t *srv, http_request_t *req, http_response_t *res);
int http_handle_post(http_server_t *srv, http_request_t *req, http_response_t *res);

// 2.5.18.g: MIME types
const char *mime_type_from_path(const char *path);
```

---

## Exemple

```c
#include "http.h"

// Custom handler
int hello_handler(http_request_t *req, http_response_t *res, void *ctx) {
    http_response_init(res, 200);
    http_response_set_header(res, "Content-Type", "text/plain");
    http_response_set_body(res, "Hello, World!", 13);
    return 0;
}

int main(void) {
    http_server_t srv;
    http_server_create(&srv, 8080, "./public");

    // Add routes
    http_server_route(&srv, "/hello", hello_handler);

    printf("HTTP server on port 8080\n");
    http_server_run(&srv);

    http_server_destroy(&srv);
    return 0;
}
```

---

## Tests Moulinette

```rust
#[test] fn test_request_parse()        // 2.5.17.a-d
#[test] fn test_response_build()       // 2.5.17.e-h
#[test] fn test_status_codes()         // 2.5.17.f
#[test] fn test_chunked()              // 2.5.17.j
#[test] fn test_static_files()         // 2.5.18.c,f
#[test] fn test_post_handling()        // 2.5.18.d
#[test] fn test_mime_types()           // 2.5.18.g
#[test] fn test_404()                  // 2.5.18.h
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Request parsing (2.5.17.a-d) | 25 |
| Response building (2.5.17.e-h) | 20 |
| Keep-alive/Chunked (2.5.17.i-l) | 10 |
| GET/Static files (2.5.18.c,f-h) | 25 |
| POST handling (2.5.18.d) | 10 |
| Concurrent server (2.5.18.i-j) | 10 |
| **Total** | **100** |

---

## Fichiers

```
ex08/
├── http.h
├── http_parse.c
├── http_response.c
├── http_server.c
├── static_files.c
├── mime.c
└── Makefile
```
