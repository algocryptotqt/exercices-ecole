# [Module 2.5] - Exercise 14: Docker & Rust Integration

## Metadonnees

```yaml
module: "2.5 - IPC & Containers"
exercise: "ex14"
title: "Docker Essentials & Rust Optimization"
difficulty: avance
estimated_time: "5 heures"
prerequisite_exercises: ["ex11"]
concepts_requis: ["Docker", "containerization", "Rust build"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.5.29: Docker Essentials (12 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.5.29.a | Docker architecture | Daemon, client, registry |
| 2.5.29.b | Images | Layers, tags, registries |
| 2.5.29.c | Containers | Run, start, stop, rm |
| 2.5.29.d | Dockerfile | FROM, RUN, COPY, CMD |
| 2.5.29.e | Rust Dockerfile | Multi-stage builds |
| 2.5.29.f | `cargo-chef` | Docker layer caching |
| 2.5.29.g | Alpine vs Debian | Base image choice |
| 2.5.29.h | `distroless` | Minimal images |
| 2.5.29.i | `bollard` crate | Docker API client |
| 2.5.29.j | `Docker::connect_with_local_defaults()` | Connect |
| 2.5.29.k | `docker.create_container()` | Create container |
| 2.5.29.l | `docker.start_container()` | Start container |

### 2.5.30: Rust Docker Optimization (11 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.5.30.a | Multi-stage build | Compile → runtime |
| 2.5.30.b | `rust:1.75` builder | Build stage |
| 2.5.30.c | `debian:bookworm-slim` | Runtime stage |
| 2.5.30.d | Static linking | `musl` target |
| 2.5.30.e | `x86_64-unknown-linux-musl` | Target triple |
| 2.5.30.f | `cross` tool | Cross-compilation |
| 2.5.30.g | Strip binary | Reduce size |
| 2.5.30.h | `cargo build --release` | Optimized build |
| 2.5.30.i | `.dockerignore` | Exclude files |
| 2.5.30.j | Layer ordering | Dependencies first |
| 2.5.30.k | Build cache | Cargo registry caching |

---

## Partie 1: Docker Basics (2.5.29)

### Exercice 1.1: Basic Rust Dockerfile

```dockerfile
# Simple Dockerfile for Rust
FROM rust:1.75

WORKDIR /app
COPY . .

RUN cargo build --release

CMD ["./target/release/myapp"]
```

**Problems with this approach:**
- Large image size (~1.5GB+)
- All build tools in final image
- No layer caching for dependencies

### Exercice 1.2: Multi-Stage Build

```dockerfile
# Stage 1: Build
FROM rust:1.75 AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

# Stage 2: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/myapp /usr/local/bin/

CMD ["myapp"]
```

### Exercice 1.3: Optimized with cargo-chef

```dockerfile
# Stage 1: Planner - compute recipe.json
FROM rust:1.75 AS planner
WORKDIR /app
RUN cargo install cargo-chef
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# Stage 2: Cacher - build dependencies
FROM rust:1.75 AS cacher
WORKDIR /app
RUN cargo install cargo-chef
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Stage 3: Builder - build application
FROM rust:1.75 AS builder
WORKDIR /app
COPY --from=cacher /app/target target
COPY --from=cacher /usr/local/cargo /usr/local/cargo
COPY . .
RUN cargo build --release

# Stage 4: Runtime
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/myapp /usr/local/bin/

USER nobody
CMD ["myapp"]
```

### Exercice 1.4: Static Binary with musl

```dockerfile
# Build static binary with musl
FROM rust:1.75-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app
COPY . .

RUN cargo build --release --target x86_64-unknown-linux-musl

# Minimal runtime - scratch or distroless
FROM scratch

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/myapp /myapp

ENTRYPOINT ["/myapp"]
```

### Exercice 1.5: Distroless Image

```dockerfile
FROM rust:1.75 AS builder

WORKDIR /app
COPY . .
RUN cargo build --release

# Google's distroless - minimal, no shell
FROM gcr.io/distroless/cc-debian12

COPY --from=builder /app/target/release/myapp /

CMD ["/myapp"]
```

---

## Partie 2: Bollard - Docker API Client (2.5.29.i-l)

### Exercice 2.1: Connecting to Docker

```rust
use bollard::Docker;
use bollard::image::ListImagesOptions;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Connect to Docker daemon
    let docker = Docker::connect_with_local_defaults()?;

    // Get Docker version
    let version = docker.version().await?;
    println!("Docker Version: {}", version.version.unwrap_or_default());
    println!("API Version: {}", version.api_version.unwrap_or_default());

    // List images
    let options = ListImagesOptions::<String> {
        all: true,
        ..Default::default()
    };

    let images = docker.list_images(Some(options)).await?;
    println!("\nImages:");
    for image in images {
        let tags = image.repo_tags.join(", ");
        let size_mb = image.size / 1024 / 1024;
        println!("  {} ({} MB)", tags, size_mb);
    }

    Ok(())
}
```

### Exercice 2.2: Creating and Running Containers

```rust
use bollard::Docker;
use bollard::container::{
    Config, CreateContainerOptions, StartContainerOptions,
    LogsOptions, RemoveContainerOptions,
};
use futures_util::stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let docker = Docker::connect_with_local_defaults()?;

    let container_name = "rust-test-container";

    // Create container config
    let config = Config {
        image: Some("alpine:latest"),
        cmd: Some(vec!["echo", "Hello from Rust!"]),
        ..Default::default()
    };

    let options = CreateContainerOptions {
        name: container_name,
        platform: None,
    };

    // Create the container
    println!("Creating container...");
    let container = docker.create_container(Some(options), config).await?;
    println!("Container ID: {}", container.id);

    // Start the container
    println!("Starting container...");
    docker.start_container(container_name, None::<StartContainerOptions<String>>).await?;

    // Wait and get logs
    let log_options = LogsOptions::<String> {
        stdout: true,
        stderr: true,
        follow: true,
        ..Default::default()
    };

    let mut logs = docker.logs(container_name, Some(log_options));
    while let Some(log) = logs.next().await {
        match log {
            Ok(output) => print!("{}", output),
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    // Clean up
    println!("\nRemoving container...");
    let remove_options = RemoveContainerOptions {
        force: true,
        ..Default::default()
    };
    docker.remove_container(container_name, Some(remove_options)).await?;

    Ok(())
}
```

### Exercice 2.3: Building Images

```rust
use bollard::Docker;
use bollard::image::BuildImageOptions;
use futures_util::stream::StreamExt;
use std::io::Read;
use tar::Builder;

async fn build_image(docker: &Docker, tag: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Create a tar archive with Dockerfile
    let mut tar_builder = Builder::new(Vec::new());

    let dockerfile = r#"
FROM alpine:latest
RUN apk add --no-cache curl
CMD ["echo", "Built with Rust!"]
"#;

    // Add Dockerfile to tar
    let mut header = tar::Header::new_gnu();
    header.set_path("Dockerfile")?;
    header.set_size(dockerfile.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();

    tar_builder.append(&header, dockerfile.as_bytes())?;

    let tar_bytes = tar_builder.into_inner()?;

    // Build options
    let options = BuildImageOptions {
        dockerfile: "Dockerfile",
        t: tag,
        rm: true,
        ..Default::default()
    };

    // Build
    println!("Building image {}...", tag);
    let mut stream = docker.build_image(options, None, Some(tar_bytes.into()));

    while let Some(result) = stream.next().await {
        match result {
            Ok(output) => {
                if let Some(stream) = output.stream {
                    print!("{}", stream);
                }
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    println!("Build complete!");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let docker = Docker::connect_with_local_defaults()?;
    build_image(&docker, "rust-built:latest").await?;
    Ok(())
}
```

### Exercice 2.4: Container Stats and Monitoring

```rust
use bollard::Docker;
use bollard::container::StatsOptions;
use futures_util::stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let docker = Docker::connect_with_local_defaults()?;

    let container_name = std::env::args().nth(1)
        .unwrap_or_else(|| "my-container".to_string());

    let options = StatsOptions {
        stream: true,
        one_shot: false,
    };

    println!("Monitoring container: {}", container_name);
    println!("{:>10} {:>10} {:>10} {:>10}",
        "CPU %", "MEM", "MEM %", "NET I/O");

    let mut stats = docker.stats(&container_name, Some(options));

    while let Some(result) = stats.next().await {
        match result {
            Ok(stats) => {
                // Calculate CPU percentage
                let cpu_delta = stats.cpu_stats.cpu_usage.total_usage
                    - stats.precpu_stats.cpu_usage.total_usage;
                let system_delta = stats.cpu_stats.system_cpu_usage.unwrap_or(0)
                    - stats.precpu_stats.system_cpu_usage.unwrap_or(0);
                let cpu_percent = if system_delta > 0 {
                    (cpu_delta as f64 / system_delta as f64) * 100.0
                } else {
                    0.0
                };

                // Memory
                let mem_usage = stats.memory_stats.usage.unwrap_or(0);
                let mem_limit = stats.memory_stats.limit.unwrap_or(1);
                let mem_percent = (mem_usage as f64 / mem_limit as f64) * 100.0;

                // Network
                let net_rx: u64 = stats.networks.as_ref()
                    .map(|n| n.values().map(|v| v.rx_bytes).sum())
                    .unwrap_or(0);
                let net_tx: u64 = stats.networks.as_ref()
                    .map(|n| n.values().map(|v| v.tx_bytes).sum())
                    .unwrap_or(0);

                println!("{:>9.1}% {:>9} {:>9.1}% {:>5}/{:<5}",
                    cpu_percent,
                    format_bytes(mem_usage),
                    mem_percent,
                    format_bytes(net_rx),
                    format_bytes(net_tx)
                );
            }
            Err(e) => eprintln!("Error: {}", e),
        }
    }

    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}K", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}
```

---

## Partie 3: Optimization Best Practices (2.5.30)

### Exercice 3.1: .dockerignore

```gitignore
# .dockerignore
target/
.git/
.gitignore
.github/
Dockerfile*
docker-compose*.yml
*.md
!README.md
.env*
.vscode/
.idea/
*.log
```

### Exercice 3.2: Cargo.toml for Docker

```toml
[package]
name = "dockerized-app"
version = "0.1.0"
edition = "2021"

[profile.release]
lto = true
codegen-units = 1
opt-level = "z"
strip = true
panic = "abort"

[dependencies]
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
```

### Exercice 3.3: Cross-compilation Setup

```bash
# Install cross
cargo install cross

# Build for musl
cross build --release --target x86_64-unknown-linux-musl

# Build for ARM64
cross build --release --target aarch64-unknown-linux-musl

# Cross.toml configuration
cat > Cross.toml << 'EOF'
[target.x86_64-unknown-linux-musl]
image = "rust:1.75-alpine"

[target.aarch64-unknown-linux-musl]
image = "messense/rust-musl-cross:aarch64-musl"
EOF
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Basic Dockerfile | 15 |
| Multi-stage build | 20 |
| cargo-chef usage | 15 |
| Bollard integration | 25 |
| Optimization techniques | 15 |
| Static binary | 10 |
| **Total** | **100** |

---

## Ressources

- [bollard crate docs](https://docs.rs/bollard/)
- [cargo-chef](https://github.com/LukeMathWalker/cargo-chef)
- [Distroless images](https://github.com/GoogleContainerTools/distroless)
- [Docker multi-stage builds](https://docs.docker.com/develop/develop-images/multistage-build/)
