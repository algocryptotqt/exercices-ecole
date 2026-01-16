# [Module 2.5] - Exercise 17: Complete Networking Toolkit

## Metadonnees

```yaml
module: "2.5 - Networking in Rust"
exercise: "ex17"
title: "Complete Networking Toolkit"
difficulty: expert
estimated_time: "8 heures"
prerequisite_exercises: ["ex08", "ex09", "ex10"]
concepts_requis: ["sockets", "async", "http", "tls"]
score_qualite: 98
```

---

## Concepts Couverts (Missing Networking Concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.5.10.a | Socket options concept | SO_REUSEADDR, etc. |
| 2.5.14.a | `std::os::unix::net::UnixStream` | Sync Unix stream |
| 2.5.16.i | `.header(key, value)` | Add header to request |
| 2.5.18.a | `axum` crate | Modern web framework |
| 2.5.18.b | `Router::new()` | Create router |
| 2.5.19.g | `tower_http::compression` | Response compression |
| 2.5.19.h | Error handling | `Result<T, AppError>` |
| 2.5.20.h | `Message::Binary(b)` | Binary WebSocket message |
| 2.5.20.i | `Message::Ping`/`Pong` | Keep-alive |
| 2.5.21.f | `ClientConfig` | Client TLS config |
| 2.5.21.g | Certificates | Loading certs |
| 2.5.22.g | `UdpPacket` | UDP datagrams |
| 2.5.23.a | Ping implementation | ICMP echo |
| 2.5.23.c | `socket2` raw socket | Send/receive |
| 2.5.23.d | Traceroute | TTL manipulation |
| 2.5.23.e | Port scanner | TCP connect scan |
| 2.5.23.f | `tokio::time::timeout()` | Scan timeout |
| 2.5.24.a | Protocol parsing | Custom protocols |
| 2.5.24.f | State machine | Protocol states |
| 2.5.24.g | Frame encoding | Serialize frames |
| 2.5.24.h | Frame decoding | Deserialize frames |
| 2.5.24.i | `tokio_util::codec` | Codec trait |
| 2.5.25.a | `tcpdump` | Packet capture |
| 2.5.25.b | `wireshark` | Packet analysis |
| 2.5.25.c | `netcat` | Network Swiss army knife |
| 2.5.25.d | `curl` | HTTP testing |
| 2.5.25.e | `ss` / `netstat` | Connection listing |
| 2.5.25.g | Logging | Request/response logging |
| 2.5.25.h | Metrics | Connection metrics |
| 2.5.26.a | Connection pooling | Reuse connections |
| 2.5.26.b | Keep-alive | Persistent connections |

---

## Partie 1: Socket Options (2.5.10.a)

### Exercice 1.1: Configuring Socket Options

```rust
//! Socket options (2.5.10.a)

use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// Socket options demonstration (2.5.10.a)
fn socket_options_demo() {
    println!("=== Socket Options (2.5.10.a) ===\n");

    // Using socket2 for more control
    use socket2::{Socket, Domain, Type, Protocol};

    // Create socket with socket2
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();

    // 2.5.10.a: Common socket options
    // SO_REUSEADDR - allow binding to address in TIME_WAIT
    socket.set_reuse_address(true).unwrap();
    println!("SO_REUSEADDR: enabled");

    // SO_REUSEPORT - allow multiple sockets on same port
    #[cfg(unix)]
    {
        socket.set_reuse_port(true).unwrap();
        println!("SO_REUSEPORT: enabled");
    }

    // SO_KEEPALIVE - enable TCP keepalive
    socket.set_keepalive(true).unwrap();
    println!("SO_KEEPALIVE: enabled");

    // TCP_NODELAY - disable Nagle's algorithm
    socket.set_nodelay(true).unwrap();
    println!("TCP_NODELAY: enabled");

    // SO_RCVBUF / SO_SNDBUF - buffer sizes
    socket.set_recv_buffer_size(65536).unwrap();
    socket.set_send_buffer_size(65536).unwrap();
    println!("Buffer sizes: 64KB");

    // SO_LINGER - linger on close
    socket.set_linger(Some(std::time::Duration::from_secs(5))).unwrap();
    println!("SO_LINGER: 5 seconds");

    println!("\nSocket options configured successfully");
}
```

---

## Partie 2: Unix Domain Sockets (2.5.14.a)

### Exercice 2.1: Unix Stream Socket

```rust
//! Unix domain sockets (2.5.14.a)

#[cfg(unix)]
mod unix_sockets {
    use std::os::unix::net::{UnixStream, UnixListener};
    use std::io::{Read, Write};
    use std::thread;

    /// Unix stream socket (2.5.14.a)
    pub fn unix_stream_demo() {
        println!("\n=== Unix Domain Sockets (2.5.14.a) ===\n");

        let socket_path = "/tmp/rust_demo.sock";

        // Remove existing socket
        let _ = std::fs::remove_file(socket_path);

        // Server thread
        let path = socket_path.to_string();
        let server = thread::spawn(move || {
            // 2.5.14.a: UnixListener for sync Unix stream
            let listener = UnixListener::bind(&path).unwrap();
            println!("Server: Listening on {}", path);

            let (mut stream, _) = listener.accept().unwrap();
            println!("Server: Client connected");

            let mut buffer = [0u8; 1024];
            let n = stream.read(&mut buffer).unwrap();
            println!("Server: Received '{}'", String::from_utf8_lossy(&buffer[..n]));

            stream.write_all(b"Hello from server!").unwrap();
        });

        // Give server time to start
        thread::sleep(std::time::Duration::from_millis(100));

        // Client
        // 2.5.14.a: UnixStream for sync connection
        let mut stream = UnixStream::connect(socket_path).unwrap();
        println!("Client: Connected to {}", socket_path);

        stream.write_all(b"Hello from client!").unwrap();

        let mut buffer = [0u8; 1024];
        let n = stream.read(&mut buffer).unwrap();
        println!("Client: Received '{}'", String::from_utf8_lossy(&buffer[..n]));

        server.join().unwrap();

        // Cleanup
        let _ = std::fs::remove_file(socket_path);
    }
}
```

---

## Partie 3: HTTP Client Advanced (2.5.16.i)

### Exercice 3.1: Request Headers

```rust
//! reqwest advanced (2.5.16.i)

use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT};

/// Adding headers to requests (2.5.16.i)
async fn request_headers_demo() {
    println!("\n=== Request Headers (2.5.16.i) ===\n");

    let client = reqwest::Client::new();

    // 2.5.16.i: Add individual headers
    let response = client
        .get("https://httpbin.org/headers")
        .header(USER_AGENT, "RustClient/1.0")
        .header(CONTENT_TYPE, "application/json")
        .header("X-Custom-Header", "custom-value")
        .send()
        .await
        .unwrap();

    println!("Status: {}", response.status());
    println!("Response: {}", response.text().await.unwrap());

    // Build default headers
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, HeaderValue::from_static("RustClient/1.0"));
    headers.insert("X-API-Key", HeaderValue::from_static("secret-key"));

    let client_with_defaults = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .unwrap();

    println!("\nClient with default headers created");
}
```

---

## Partie 4: Axum Basics (2.5.18.a-b)

### Exercice 4.1: Creating an Axum Server

```rust
//! Axum basics (2.5.18.a-b)

use axum::{
    Router,
    routing::{get, post},
    response::{Json, IntoResponse},
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Clone)]
struct AppState {
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

#[derive(Deserialize)]
struct QueryParams {
    name: Option<String>,
}

#[derive(Serialize)]
struct ApiResponse {
    message: String,
    count: usize,
}

/// Basic handlers
async fn hello_handler() -> &'static str {
    "Hello, World!"
}

async fn greet_handler(Query(params): Query<QueryParams>) -> String {
    let name = params.name.unwrap_or_else(|| "Guest".to_string());
    format!("Hello, {}!", name)
}

async fn user_handler(Path(id): Path<u64>) -> Json<ApiResponse> {
    Json(ApiResponse {
        message: format!("User {}", id),
        count: 1,
    })
}

async fn counter_handler(State(state): State<AppState>) -> Json<ApiResponse> {
    let count = state.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    Json(ApiResponse {
        message: "Counter incremented".to_string(),
        count,
    })
}

/// Axum server (2.5.18.a-b)
async fn axum_demo() {
    println!("\n=== Axum Basics (2.5.18.a-b) ===\n");

    let state = AppState {
        counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    };

    // 2.5.18.a: axum crate
    // 2.5.18.b: Router::new() creates router
    let app = Router::new()
        .route("/", get(hello_handler))
        .route("/greet", get(greet_handler))
        .route("/users/:id", get(user_handler))
        .route("/counter", post(counter_handler))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:3000").await.unwrap();
    println!("Axum server running on http://127.0.0.1:3000");

    // axum::serve(listener, app).await.unwrap();
}
```

---

## Partie 5: Axum Error Handling (2.5.19.g-h)

### Exercice 5.1: Custom Error Types

```rust
//! Axum error handling (2.5.19.g-h)

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// Custom error type (2.5.19.h)
#[derive(Debug)]
pub enum AppError {
    NotFound(String),
    BadRequest(String),
    InternalError(String),
}

// 2.5.19.h: Implement IntoResponse for custom errors
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(json!({
            "error": message
        }));

        (status, body).into_response()
    }
}

/// Handler returning Result (2.5.19.h)
async fn fallible_handler(Path(id): Path<u64>) -> Result<Json<serde_json::Value>, AppError> {
    if id == 0 {
        return Err(AppError::BadRequest("ID cannot be 0".to_string()));
    }

    if id > 1000 {
        return Err(AppError::NotFound(format!("User {} not found", id)));
    }

    Ok(Json(json!({ "user_id": id })))
}

// 2.5.19.g: Compression middleware
use tower_http::compression::CompressionLayer;

fn compression_demo() {
    println!("\n=== Compression Middleware (2.5.19.g) ===\n");

    let app = Router::new()
        .route("/", get(|| async { "Hello!" }))
        .layer(CompressionLayer::new());  // 2.5.19.g: Enable compression

    println!("Compression layer added - gzip, br, deflate supported");
}
```

---

## Partie 6: WebSockets (2.5.20.h-i)

### Exercice 6.1: Binary Messages and Ping/Pong

```rust
//! WebSocket messages (2.5.20.h-i)

use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::{SinkExt, StreamExt};

async fn websocket_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(handle_socket)
}

async fn handle_socket(mut socket: WebSocket) {
    while let Some(msg) = socket.recv().await {
        match msg {
            Ok(Message::Text(text)) => {
                println!("Received text: {}", text);
                socket.send(Message::Text(format!("Echo: {}", text))).await.ok();
            }

            // 2.5.20.h: Binary messages
            Ok(Message::Binary(data)) => {
                println!("Received binary: {} bytes", data.len());
                // Echo back the binary data
                socket.send(Message::Binary(data)).await.ok();
            }

            // 2.5.20.i: Ping/Pong for keep-alive
            Ok(Message::Ping(data)) => {
                println!("Received Ping");
                // Respond with Pong
                socket.send(Message::Pong(data)).await.ok();
            }

            Ok(Message::Pong(_)) => {
                println!("Received Pong");
            }

            Ok(Message::Close(_)) => {
                println!("Client disconnected");
                break;
            }

            Err(e) => {
                eprintln!("WebSocket error: {}", e);
                break;
            }
        }
    }
}

fn websocket_demo() {
    println!("\n=== WebSocket Messages (2.5.20.h-i) ===\n");
    println!("WebSocket supports:");
    println!("  - Text messages (UTF-8 strings)");
    println!("  - Binary messages (arbitrary bytes)");
    println!("  - Ping/Pong for keep-alive");
}
```

---

## Partie 7: TLS Configuration (2.5.21.f-g)

### Exercice 7.1: TLS Client Configuration

```rust
//! TLS configuration (2.5.21.f-g)

use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

/// TLS client configuration (2.5.21.f-g)
fn tls_config_demo() {
    println!("\n=== TLS Configuration (2.5.21.f-g) ===\n");

    // 2.5.21.g: Load system root certificates
    let mut root_store = RootCertStore::empty();

    // Load from webpki-roots (bundled Mozilla certs)
    root_store.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
    );
    println!("Loaded {} root certificates", root_store.len());

    // 2.5.21.f: Create ClientConfig
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    println!("TLS ClientConfig created");
    println!("  - TLS 1.2 and 1.3 supported");
    println!("  - Server certificate verification enabled");

    // For custom certificates
    println!("\nTo load custom certificates:");
    println!("  let cert = std::fs::read(\"cert.pem\")?;");
    println!("  let certs = rustls_pemfile::certs(&mut &*cert)?;");
}
```

---

## Partie 8: Network Tools (2.5.23)

### Exercice 8.1: Port Scanner

```rust
//! Network tools (2.5.23.a,c,d,e,f)

use std::net::{TcpStream, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;

/// Port scanner (2.5.23.e-f)
async fn port_scan(host: &str, start: u16, end: u16) -> Vec<u16> {
    println!("\n=== Port Scanner (2.5.23.e-f) ===\n");

    let mut open_ports = Vec::new();

    for port in start..=end {
        let addr: SocketAddr = format!("{}:{}", host, port).parse().unwrap();

        // 2.5.23.f: Use timeout for scan
        let result = timeout(
            Duration::from_millis(100),
            tokio::net::TcpStream::connect(addr)
        ).await;

        match result {
            Ok(Ok(_)) => {
                println!("Port {} is OPEN", port);
                open_ports.push(port);
            }
            _ => {} // Closed or timeout
        }
    }

    open_ports
}

/// Traceroute concept (2.5.23.d)
fn traceroute_concept() {
    println!("\n=== Traceroute Concept (2.5.23.d) ===\n");

    println!("Traceroute works by:");
    println!("  1. Send packets with TTL=1, 2, 3, ...");
    println!("  2. Each router decrements TTL");
    println!("  3. When TTL=0, router sends ICMP Time Exceeded");
    println!("  4. Record IP of each router");

    // Implementation requires raw sockets (root)
    println!("\nRequires raw sockets (CAP_NET_RAW capability)");
}

/// Ping concept (2.5.23.a)
fn ping_concept() {
    println!("\n=== Ping Concept (2.5.23.a) ===\n");

    println!("Ping (ICMP Echo):");
    println!("  1. Send ICMP Echo Request");
    println!("  2. Target responds with ICMP Echo Reply");
    println!("  3. Measure round-trip time");

    // 2.5.23.c: socket2 for raw sockets
    println!("\nUsing socket2 for raw sockets:");
    println!("  let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;");
}
```

---

## Partie 9: Protocol Implementation (2.5.24)

### Exercice 9.1: Custom Codec

```rust
//! Protocol implementation (2.5.24.a,f,g,h,i)

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use std::io;

/// Custom message type
#[derive(Debug, Clone)]
pub struct CustomMessage {
    pub msg_type: u8,
    pub payload: Vec<u8>,
}

/// Custom codec (2.5.24.i)
pub struct CustomCodec;

// 2.5.24.h: Frame decoding
impl Decoder for CustomCodec {
    type Item = CustomMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Need at least 3 bytes: type (1) + length (2)
        if src.len() < 3 {
            return Ok(None);
        }

        let msg_type = src[0];
        let length = u16::from_be_bytes([src[1], src[2]]) as usize;

        // Wait for complete message
        if src.len() < 3 + length {
            return Ok(None);
        }

        // Consume header
        src.advance(3);

        // Extract payload
        let payload = src.split_to(length).to_vec();

        Ok(Some(CustomMessage { msg_type, payload }))
    }
}

// 2.5.24.g: Frame encoding
impl Encoder<CustomMessage> for CustomCodec {
    type Error = io::Error;

    fn encode(&mut self, item: CustomMessage, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let length = item.payload.len() as u16;

        dst.put_u8(item.msg_type);
        dst.put_u16(length);
        dst.put_slice(&item.payload);

        Ok(())
    }
}

/// Protocol state machine (2.5.24.f)
#[derive(Debug, Clone, Copy)]
pub enum ProtocolState {
    Handshake,
    Authenticated,
    Ready,
    Closed,
}

impl ProtocolState {
    pub fn transition(self, event: ProtocolEvent) -> Self {
        match (self, event) {
            (ProtocolState::Handshake, ProtocolEvent::AuthSuccess) => ProtocolState::Authenticated,
            (ProtocolState::Authenticated, ProtocolEvent::Ready) => ProtocolState::Ready,
            (_, ProtocolEvent::Close) => ProtocolState::Closed,
            _ => self,
        }
    }
}

#[derive(Debug)]
pub enum ProtocolEvent {
    AuthSuccess,
    Ready,
    Close,
}
```

---

## Partie 10: Network Debugging (2.5.25)

### Exercice 10.1: Debugging Tools

```rust
//! Network debugging (2.5.25.a-e, g-h)

/// Network debugging tools overview (2.5.25)
fn debugging_tools_demo() {
    println!("\n=== Network Debugging Tools (2.5.25) ===\n");

    // 2.5.25.a: tcpdump
    println!("tcpdump - Packet capture:");
    println!("  tcpdump -i eth0 port 80");
    println!("  tcpdump -i any host 192.168.1.1");
    println!();

    // 2.5.25.b: wireshark
    println!("Wireshark - GUI packet analysis:");
    println!("  Filter: http.request.method == \"GET\"");
    println!("  Filter: tcp.port == 443");
    println!();

    // 2.5.25.c: netcat
    println!("netcat - Network Swiss army knife:");
    println!("  nc -l 8080          # Listen on port");
    println!("  nc host 80          # Connect to port");
    println!("  echo 'GET /' | nc host 80");
    println!();

    // 2.5.25.d: curl
    println!("curl - HTTP testing:");
    println!("  curl -v https://example.com");
    println!("  curl -X POST -d '{{}}' -H 'Content-Type: application/json' url");
    println!();

    // 2.5.25.e: ss/netstat
    println!("ss - Connection listing:");
    println!("  ss -tlnp             # TCP listening ports");
    println!("  ss -tunap            # All connections with PIDs");
}

/// Logging and metrics (2.5.25.g-h)
fn logging_metrics_demo() {
    println!("\n=== Logging and Metrics (2.5.25.g-h) ===\n");

    // 2.5.25.g: Request/response logging
    println!("tower-http tracing middleware:");
    println!("  use tower_http::trace::TraceLayer;");
    println!("  app.layer(TraceLayer::new_for_http())");
    println!();

    // 2.5.25.h: Connection metrics
    println!("Metrics with prometheus:");
    println!("  - active_connections gauge");
    println!("  - request_duration_seconds histogram");
    println!("  - requests_total counter");
}
```

---

## Partie 11: Performance (2.5.26)

### Exercice 11.1: Connection Pooling

```rust
//! Performance (2.5.26.a-b)

/// Connection pooling (2.5.26.a-b)
fn performance_demo() {
    println!("\n=== Performance (2.5.26.a-b) ===\n");

    // 2.5.26.a: Connection pooling
    println!("Connection Pooling:");
    println!("  - Reuse existing connections");
    println!("  - Avoid TCP handshake overhead");
    println!("  - reqwest::Client pools connections automatically");
    println!();

    println!("reqwest connection pool:");
    println!("  let client = Client::builder()");
    println!("      .pool_max_idle_per_host(10)");
    println!("      .pool_idle_timeout(Duration::from_secs(30))");
    println!("      .build()?;");
    println!();

    // 2.5.26.b: Keep-alive
    println!("HTTP Keep-Alive (2.5.26.b):");
    println!("  - Reuse TCP connection for multiple requests");
    println!("  - Connection: keep-alive header");
    println!("  - HTTP/1.1 keep-alive by default");
    println!("  - HTTP/2 multiplexes multiple requests");
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Socket options (2.5.10) | 10 |
| Unix sockets (2.5.14) | 10 |
| HTTP client (2.5.16) | 10 |
| Axum basics (2.5.18) | 15 |
| Error handling (2.5.19) | 10 |
| WebSockets (2.5.20) | 10 |
| TLS config (2.5.21) | 10 |
| Network tools (2.5.23) | 10 |
| Protocol codec (2.5.24) | 10 |
| Debugging (2.5.25-26) | 5 |
| **Total** | **100** |

---

## Ressources

- [tokio-tungstenite](https://docs.rs/tokio-tungstenite/)
- [axum](https://docs.rs/axum/)
- [reqwest](https://docs.rs/reqwest/)
- [rustls](https://docs.rs/rustls/)
- [pnet](https://docs.rs/pnet/)
