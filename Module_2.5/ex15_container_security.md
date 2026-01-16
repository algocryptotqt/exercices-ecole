# [Module 2.5] - Exercise 15: Container Security

## Metadonnees

```yaml
module: "2.5 - IPC & Containers"
exercise: "ex15"
title: "Container Security Best Practices"
difficulty: avance
estimated_time: "4 heures"
prerequisite_exercises: ["ex11", "ex14"]
concepts_requis: ["security", "capabilities", "seccomp"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.5.31: Container Security (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.5.31.a | Root vs rootless | Security implications |
| 2.5.31.b | Non-root user | `USER` directive |
| 2.5.31.c | Capabilities | `CAP_NET_ADMIN`, etc. |
| 2.5.31.d | Seccomp | System call filtering |
| 2.5.31.e | AppArmor/SELinux | MAC policies |
| 2.5.31.f | Image scanning | Trivy, Clair |
| 2.5.31.g | `cargo-audit` | Dependency audit |
| 2.5.31.h | Minimal images | Reduce attack surface |
| 2.5.31.i | Read-only rootfs | Immutable containers |
| 2.5.31.j | Network policies | Restrict communication |

---

## Partie 1: Non-Root Containers (2.5.31.a, b)

### Exercice 1.1: Running as Non-Root User

```dockerfile
# Secure Dockerfile with non-root user
FROM rust:1.75 AS builder

WORKDIR /app
COPY . .
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Create non-root user
RUN groupadd --gid 1000 appgroup && \
    useradd --uid 1000 --gid appgroup --shell /bin/false appuser

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary
COPY --from=builder /app/target/release/myapp /usr/local/bin/

# Set ownership
RUN chown appuser:appgroup /usr/local/bin/myapp

# Switch to non-root user
USER appuser

# Use numeric UID for kubernetes compatibility
# USER 1000

CMD ["myapp"]
```

### Exercice 1.2: Verifying Container User

```rust
use std::process::Command;

fn check_container_user() {
    // Get current user info
    println!("Current user:");
    println!("  UID: {}", unsafe { libc::getuid() });
    println!("  GID: {}", unsafe { libc::getgid() });
    println!("  EUID: {}", unsafe { libc::geteuid() });
    println!("  EGID: {}", unsafe { libc::getegid() });

    // Check if running as root
    if unsafe { libc::getuid() } == 0 {
        eprintln!("WARNING: Running as root!");
    } else {
        println!("OK: Running as non-root user");
    }

    // Check capabilities
    println!("\nCapabilities:");
    let output = Command::new("capsh")
        .arg("--print")
        .output();

    if let Ok(output) = output {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    }
}

fn main() {
    check_container_user();
}
```

---

## Partie 2: Linux Capabilities (2.5.31.c)

### Exercice 2.1: Understanding Capabilities

```rust
use caps::{CapSet, Capability, has_cap, drop, read};

fn list_capabilities() -> Result<(), caps::errors::CapsError> {
    println!("Current Capabilities:");

    // Effective capabilities
    let effective = read(None, CapSet::Effective)?;
    println!("\nEffective:");
    for cap in Capability::iter() {
        if effective.contains(&cap) {
            println!("  {:?}", cap);
        }
    }

    // Permitted capabilities
    let permitted = read(None, CapSet::Permitted)?;
    println!("\nPermitted:");
    for cap in Capability::iter() {
        if permitted.contains(&cap) {
            println!("  {:?}", cap);
        }
    }

    Ok(())
}

fn drop_capabilities() -> Result<(), caps::errors::CapsError> {
    println!("Dropping unnecessary capabilities...");

    // Keep only what's needed
    let keep = vec![
        Capability::CAP_NET_BIND_SERVICE, // Bind ports < 1024
    ];

    // Drop all others
    for cap in Capability::iter() {
        if !keep.contains(&cap) {
            let _ = drop(None, CapSet::Effective, cap);
            let _ = drop(None, CapSet::Permitted, cap);
        }
    }

    println!("Done.");
    list_capabilities()
}

fn main() {
    if let Err(e) = list_capabilities() {
        eprintln!("Error: {}", e);
    }
}
```

### Exercice 2.2: Docker Capability Configuration

```bash
# Run container with minimal capabilities
docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE myapp

# Check capabilities inside container
docker run --cap-drop=ALL myapp capsh --print

# Common capability combinations:
# Web server:    --cap-drop=ALL --cap-add=NET_BIND_SERVICE
# Network tool:  --cap-drop=ALL --cap-add=NET_ADMIN --cap-add=NET_RAW
# Ping:          --cap-drop=ALL --cap-add=NET_RAW
```

---

## Partie 3: Seccomp Profiles (2.5.31.d)

### Exercice 3.1: Understanding Seccomp

```rust
use seccompiler::{SeccompAction, SeccompFilter, SeccompRule};
use std::convert::TryInto;

fn create_restrictive_filter() -> Result<SeccompFilter, Box<dyn std::error::Error>> {
    // Allow only specific syscalls
    let allowed_syscalls = vec![
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_brk,
        libc::SYS_mmap,
        libc::SYS_munmap,
        libc::SYS_close,
        libc::SYS_fstat,
        libc::SYS_getrandom,
    ];

    let mut rules = vec![];
    for syscall in allowed_syscalls {
        rules.push((syscall as i64, vec![SeccompRule::new(vec![])
            .map_err(|e| format!("Rule error: {:?}", e))?]));
    }

    let filter = SeccompFilter::new(
        rules.into_iter().collect(),
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        std::env::consts::ARCH.try_into()
            .map_err(|e| format!("Arch error: {:?}", e))?,
    ).map_err(|e| format!("Filter error: {:?}", e))?;

    Ok(filter)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating seccomp filter...");

    let filter = create_restrictive_filter()?;

    // Apply filter (can't be undone!)
    // filter.apply()?;

    println!("Filter created (not applied in this demo)");
    Ok(())
}
```

### Exercice 3.2: Custom Seccomp Profile (JSON)

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "defaultErrnoRet": 1,
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86"
  ],
  "syscalls": [
    {
      "names": [
        "read",
        "write",
        "exit",
        "exit_group",
        "brk",
        "mmap",
        "munmap",
        "close",
        "fstat",
        "getrandom",
        "futex",
        "rt_sigprocmask",
        "rt_sigaction",
        "sigaltstack",
        "mprotect",
        "arch_prctl",
        "set_tid_address",
        "set_robust_list"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

```bash
# Use custom seccomp profile
docker run --security-opt seccomp=seccomp-profile.json myapp
```

---

## Partie 4: Image Security (2.5.31.f, g)

### Exercice 4.1: Scanning with Trivy

```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Scan image
trivy image myapp:latest

# Scan for HIGH and CRITICAL only
trivy image --severity HIGH,CRITICAL myapp:latest

# Scan Dockerfile
trivy config Dockerfile

# JSON output for CI/CD
trivy image --format json --output results.json myapp:latest
```

### Exercice 4.2: Rust Dependency Audit

```bash
# Install cargo-audit
cargo install cargo-audit

# Run audit
cargo audit

# Fix vulnerabilities
cargo audit fix

# JSON output
cargo audit --json
```

```rust
// Parse cargo-audit results
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct AuditReport {
    vulnerabilities: VulnerabilityInfo,
}

#[derive(Deserialize, Debug)]
struct VulnerabilityInfo {
    found: bool,
    count: u32,
    list: Vec<Vulnerability>,
}

#[derive(Deserialize, Debug)]
struct Vulnerability {
    advisory: Advisory,
    package: Package,
}

#[derive(Deserialize, Debug)]
struct Advisory {
    id: String,
    title: String,
    severity: String,
}

#[derive(Deserialize, Debug)]
struct Package {
    name: String,
    version: String,
}

fn check_vulnerabilities() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::process::Command::new("cargo")
        .args(["audit", "--json"])
        .output()?;

    let report: AuditReport = serde_json::from_slice(&output.stdout)?;

    if report.vulnerabilities.found {
        println!("WARNING: {} vulnerabilities found!", report.vulnerabilities.count);
        for vuln in &report.vulnerabilities.list {
            println!("  {} ({}): {}",
                vuln.package.name,
                vuln.advisory.severity,
                vuln.advisory.title
            );
        }
    } else {
        println!("No vulnerabilities found!");
    }

    Ok(())
}
```

---

## Partie 5: Secure Container Configuration

### Exercice 5.1: Read-Only Root Filesystem (2.5.31.i)

```dockerfile
FROM rust:1.75-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM gcr.io/distroless/cc-debian12

# Copy binary
COPY --from=builder /app/target/release/myapp /myapp

# Create writable directories for runtime needs
VOLUME ["/tmp", "/var/run"]

CMD ["/myapp"]
```

```bash
# Run with read-only root filesystem
docker run --read-only \
    --tmpfs /tmp:rw,noexec,nosuid \
    --tmpfs /var/run:rw,noexec,nosuid \
    myapp
```

### Exercice 5.2: Network Policies (2.5.31.j)

```yaml
# Kubernetes NetworkPolicy
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: myapp-network-policy
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              role: frontend
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - podSelector:
            matchLabels:
              role: database
      ports:
        - protocol: TCP
          port: 5432
```

### Exercice 5.3: Security Checklist

```rust
// Security validation for containers
struct SecurityCheck {
    name: &'static str,
    passed: bool,
    message: String,
}

fn run_security_checks() -> Vec<SecurityCheck> {
    let mut checks = Vec::new();

    // Check 1: Non-root user
    checks.push(SecurityCheck {
        name: "Non-root user",
        passed: unsafe { libc::getuid() } != 0,
        message: if unsafe { libc::getuid() } != 0 {
            "Running as non-root".to_string()
        } else {
            "WARNING: Running as root!".to_string()
        },
    });

    // Check 2: Read-only rootfs
    let rootfs_writable = std::fs::write("/test_write", "test").is_ok();
    if rootfs_writable {
        let _ = std::fs::remove_file("/test_write");
    }
    checks.push(SecurityCheck {
        name: "Read-only rootfs",
        passed: !rootfs_writable,
        message: if !rootfs_writable {
            "Root filesystem is read-only".to_string()
        } else {
            "WARNING: Root filesystem is writable!".to_string()
        },
    });

    // Check 3: No sensitive files
    let sensitive_files = vec![
        "/etc/shadow",
        "/etc/passwd",
        "/.ssh/id_rsa",
    ];

    for file in sensitive_files {
        let exists = std::path::Path::new(file).exists();
        checks.push(SecurityCheck {
            name: "Sensitive files",
            passed: !exists,
            message: if !exists {
                format!("{} not present", file)
            } else {
                format!("WARNING: {} exists!", file)
            },
        });
    }

    checks
}

fn main() {
    println!("Container Security Checks:\n");

    for check in run_security_checks() {
        let status = if check.passed { "✓" } else { "✗" };
        println!("[{}] {}: {}", status, check.name, check.message);
    }
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Non-root containers | 20 |
| Capabilities management | 20 |
| Seccomp profiles | 20 |
| Image scanning | 15 |
| Read-only rootfs | 10 |
| Network policies | 15 |
| **Total** | **100** |

---

## Ressources

- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [Trivy Scanner](https://github.com/aquasecurity/trivy)
- [cargo-audit](https://github.com/RustSec/cargo-audit)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html)
