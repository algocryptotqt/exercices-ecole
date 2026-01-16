# ex13: OCI Specification & Docker Architecture

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.24: OCI Specification (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | OCI | Open Container Initiative |
| b | Runtime spec | How to run container |
| c | Image spec | Image format |
| d | Distribution spec | How to distribute |
| e | config.json | Container config |
| f | rootfs | Container filesystem |
| g | runc | Reference implementation |

### 2.10.25: Docker Architecture (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Docker daemon | dockerd |
| b | Docker CLI | docker command |
| c | REST API | Communication |
| d | containerd | Container runtime |
| e | runc | Low-level runtime |
| f | Images | Layered filesystem |
| g | Containers | Running instances |
| h | Volumes | Persistent data |
| i | Networks | Container networking |

### 2.10.26: Docker Images (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Image layers | Stacked filesystem |
| b | Union filesystem | OverlayFS |
| c | Base image | Starting point |
| d | Dockerfile | Build instructions |
| e | FROM | Base image |
| f | RUN | Execute command |
| g | COPY/ADD | Add files |
| h | CMD/ENTRYPOINT | Default command |
| i | ENV | Environment variables |
| j | EXPOSE | Document ports |

---

## Sujet

Comprendre la specification OCI et l'architecture Docker.

---

## Exemple

```c
#include "oci_docker.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================
// OCI Specification
// ============================================

void explain_oci(void) {
    printf("=== OCI (Open Container Initiative) ===\n\n");

    printf("OCI is the industry standard for containers\n");
    printf("  - Founded 2015 by Docker, CoreOS, others\n");
    printf("  - Defines container format and runtime\n");
    printf("  - Ensures portability across implementations\n");

    printf("\nOCI Specifications:\n");

    printf("\n1. Runtime Specification:\n");
    printf("   - How to run a container\n");
    printf("   - Configuration format (config.json)\n");
    printf("   - Lifecycle operations (create, start, stop, delete)\n");
    printf("   - Reference: github.com/opencontainers/runtime-spec\n");

    printf("\n2. Image Specification:\n");
    printf("   - How container images are structured\n");
    printf("   - Manifest, config, layers\n");
    printf("   - Content-addressable storage\n");
    printf("   - Reference: github.com/opencontainers/image-spec\n");

    printf("\n3. Distribution Specification:\n");
    printf("   - How to push/pull images from registries\n");
    printf("   - API for image distribution\n");
    printf("   - Reference: github.com/opencontainers/distribution-spec\n");
}

void show_oci_bundle(void) {
    printf("\n=== OCI Runtime Bundle ===\n\n");

    printf("Bundle structure:\n");
    printf("  bundle/\n");
    printf("  ├── config.json     # Container configuration\n");
    printf("  └── rootfs/         # Container filesystem\n");
    printf("      ├── bin/\n");
    printf("      ├── etc/\n");
    printf("      ├── lib/\n");
    printf("      └── ...\n");

    printf("\nconfig.json structure:\n");
    printf("{\n");
    printf("  \"ociVersion\": \"1.0.0\",\n");
    printf("  \"process\": {\n");
    printf("    \"terminal\": true,\n");
    printf("    \"user\": { \"uid\": 0, \"gid\": 0 },\n");
    printf("    \"args\": [\"/bin/sh\"],\n");
    printf("    \"env\": [\"PATH=/usr/bin:/bin\"],\n");
    printf("    \"cwd\": \"/\",\n");
    printf("    \"capabilities\": { ... },\n");
    printf("    \"rlimits\": [ ... ]\n");
    printf("  },\n");
    printf("  \"root\": {\n");
    printf("    \"path\": \"rootfs\",\n");
    printf("    \"readonly\": false\n");
    printf("  },\n");
    printf("  \"hostname\": \"container\",\n");
    printf("  \"mounts\": [ ... ],\n");
    printf("  \"linux\": {\n");
    printf("    \"namespaces\": [ ... ],\n");
    printf("    \"cgroups\": { ... },\n");
    printf("    \"seccomp\": { ... }\n");
    printf("  }\n");
    printf("}\n");
}

void explain_runc(void) {
    printf("\n=== runc (OCI Reference Runtime) ===\n\n");

    printf("runc is the reference implementation of OCI runtime\n");
    printf("  - Created by Docker, donated to OCI\n");
    printf("  - Low-level container runtime\n");
    printf("  - Used by Docker, containerd, CRI-O, Podman\n");

    printf("\nrunc commands:\n");
    printf("  runc create <id>        Create container\n");
    printf("  runc start <id>         Start container\n");
    printf("  runc run <id>           Create + start\n");
    printf("  runc list               List containers\n");
    printf("  runc state <id>         Container state\n");
    printf("  runc kill <id> SIGNAL   Send signal\n");
    printf("  runc delete <id>        Delete container\n");
    printf("  runc spec               Generate config.json\n");

    printf("\nExample workflow:\n");
    printf("  # Create bundle directory\n");
    printf("  mkdir -p mycontainer/rootfs\n");
    printf("  \n");
    printf("  # Extract rootfs\n");
    printf("  tar -xf alpine-rootfs.tar -C mycontainer/rootfs\n");
    printf("  \n");
    printf("  # Generate config.json\n");
    printf("  cd mycontainer && runc spec\n");
    printf("  \n");
    printf("  # Run container\n");
    printf("  runc run mycontainer\n");
}

// ============================================
// Docker Architecture
// ============================================

void explain_docker_architecture(void) {
    printf("\n=== Docker Architecture ===\n\n");

    printf("Docker uses client-server architecture:\n\n");

    printf("  +-------------+\n");
    printf("  | docker CLI  |  (client)\n");
    printf("  +------+------+\n");
    printf("         | REST API\n");
    printf("         v\n");
    printf("  +------+------+\n");
    printf("  |   dockerd   |  (daemon)\n");
    printf("  +------+------+\n");
    printf("         | gRPC\n");
    printf("         v\n");
    printf("  +------+------+\n");
    printf("  |  containerd |  (container runtime)\n");
    printf("  +------+------+\n");
    printf("         | exec\n");
    printf("         v\n");
    printf("  +------+------+\n");
    printf("  |    runc     |  (OCI runtime)\n");
    printf("  +-------------+\n");

    printf("\nComponents:\n");

    printf("\ndocker CLI:\n");
    printf("  - User interface\n");
    printf("  - Sends commands to daemon\n");
    printf("  - Can connect to remote daemons\n");

    printf("\ndockerd (Docker daemon):\n");
    printf("  - Manages Docker objects\n");
    printf("  - Builds images\n");
    printf("  - Manages networks, volumes\n");
    printf("  - Exposes REST API\n");

    printf("\ncontainerd:\n");
    printf("  - Industry-standard runtime\n");
    printf("  - Image management\n");
    printf("  - Container lifecycle\n");
    printf("  - Used by Docker, Kubernetes\n");

    printf("\nrunc:\n");
    printf("  - Low-level runtime\n");
    printf("  - Actually creates/runs containers\n");
    printf("  - OCI compliant\n");
}

void explain_docker_images(void) {
    printf("\n=== Docker Images ===\n\n");

    printf("Image Structure:\n");
    printf("  Images are layered filesystems\n");
    printf("  Each layer is read-only\n");
    printf("  Layers are shared between images\n");

    printf("\n  Layer 4: Application code (4 MB)\n");
    printf("      |\n");
    printf("  Layer 3: pip install (150 MB)\n");
    printf("      |\n");
    printf("  Layer 2: apt-get install python (50 MB)\n");
    printf("      |\n");
    printf("  Layer 1: Base OS (ubuntu:22.04) (80 MB)\n");

    printf("\nContent Addressable Storage:\n");
    printf("  - Each layer identified by SHA256 hash\n");
    printf("  - Layers stored in /var/lib/docker\n");
    printf("  - Same layer used by multiple images\n");

    printf("\nUnion Filesystem (OverlayFS):\n");
    printf("  - Combines layers into single view\n");
    printf("  - Copy-on-write for modifications\n");
    printf("  - Container layer is writable\n");
}

void explain_dockerfile(void) {
    printf("\n=== Dockerfile ===\n\n");

    printf("Dockerfile Instructions:\n\n");

    printf("FROM <image>:<tag>\n");
    printf("  Base image for build\n");
    printf("  Example: FROM ubuntu:22.04\n\n");

    printf("RUN <command>\n");
    printf("  Execute command during build\n");
    printf("  Creates new layer\n");
    printf("  Example: RUN apt-get update && apt-get install -y python3\n\n");

    printf("COPY <src> <dest>\n");
    printf("  Copy files from build context\n");
    printf("  Example: COPY ./app /app\n\n");

    printf("ADD <src> <dest>\n");
    printf("  Like COPY but can extract archives and fetch URLs\n");
    printf("  Prefer COPY for simple file copying\n\n");

    printf("WORKDIR <path>\n");
    printf("  Set working directory\n");
    printf("  Example: WORKDIR /app\n\n");

    printf("ENV <key>=<value>\n");
    printf("  Set environment variable\n");
    printf("  Example: ENV NODE_ENV=production\n\n");

    printf("EXPOSE <port>\n");
    printf("  Document which ports the container listens on\n");
    printf("  Does NOT publish the port\n");
    printf("  Example: EXPOSE 8080\n\n");

    printf("CMD [\"executable\", \"arg1\", \"arg2\"]\n");
    printf("  Default command when container starts\n");
    printf("  Can be overridden at runtime\n");
    printf("  Example: CMD [\"python\", \"app.py\"]\n\n");

    printf("ENTRYPOINT [\"executable\"]\n");
    printf("  Container's main command\n");
    printf("  CMD becomes arguments to ENTRYPOINT\n");
    printf("  Example: ENTRYPOINT [\"python\"]\n\n");

    printf("USER <user>\n");
    printf("  Set user for subsequent commands and runtime\n");
    printf("  Example: USER nobody\n\n");

    printf("VOLUME [\"/data\"]\n");
    printf("  Create mount point for external storage\n");
    printf("  Example: VOLUME [\"/var/lib/mysql\"]\n");
}

void show_dockerfile_example(void) {
    printf("\n=== Dockerfile Example ===\n\n");

    printf("# Python web application\n");
    printf("FROM python:3.11-slim\n");
    printf("\n");
    printf("# Set working directory\n");
    printf("WORKDIR /app\n");
    printf("\n");
    printf("# Install dependencies first (better caching)\n");
    printf("COPY requirements.txt .\n");
    printf("RUN pip install --no-cache-dir -r requirements.txt\n");
    printf("\n");
    printf("# Copy application code\n");
    printf("COPY . .\n");
    printf("\n");
    printf("# Create non-root user\n");
    printf("RUN useradd -m appuser && chown -R appuser /app\n");
    printf("USER appuser\n");
    printf("\n");
    printf("# Document port\n");
    printf("EXPOSE 8080\n");
    printf("\n");
    printf("# Health check\n");
    printf("HEALTHCHECK CMD curl -f http://localhost:8080/health || exit 1\n");
    printf("\n");
    printf("# Default command\n");
    printf("CMD [\"python\", \"app.py\"]\n");

    printf("\n\nBuild and run:\n");
    printf("  docker build -t myapp:latest .\n");
    printf("  docker run -p 8080:8080 myapp:latest\n");
}

void show_best_practices(void) {
    printf("\n=== Dockerfile Best Practices ===\n\n");

    printf("1. Use specific base image tags\n");
    printf("   Bad:  FROM python\n");
    printf("   Good: FROM python:3.11-slim\n");

    printf("\n2. Minimize layers (combine RUN commands)\n");
    printf("   Bad:  RUN apt-get update\n");
    printf("         RUN apt-get install -y curl\n");
    printf("   Good: RUN apt-get update && apt-get install -y curl \\\n");
    printf("         && rm -rf /var/lib/apt/lists/*\n");

    printf("\n3. Order by change frequency (most stable first)\n");
    printf("   COPY requirements.txt .  # Changes rarely\n");
    printf("   RUN pip install ...\n");
    printf("   COPY . .                  # Changes often\n");

    printf("\n4. Don't run as root\n");
    printf("   RUN useradd -m appuser\n");
    printf("   USER appuser\n");

    printf("\n5. Use .dockerignore\n");
    printf("   .git\n");
    printf("   __pycache__\n");
    printf("   *.pyc\n");
    printf("   .env\n");

    printf("\n6. Multi-stage builds\n");
    printf("   FROM golang:1.21 AS builder\n");
    printf("   RUN go build -o /app\n");
    printf("   \n");
    printf("   FROM alpine:3.18\n");
    printf("   COPY --from=builder /app /app\n");
    printf("   CMD [\"/app\"]\n");
}

int main(void) {
    explain_oci();
    show_oci_bundle();
    explain_runc();

    explain_docker_architecture();
    explain_docker_images();
    explain_dockerfile();
    show_dockerfile_example();
    show_best_practices();

    return 0;
}
```

---

## Fichiers

```
ex13/
├── oci_docker.h
├── oci_spec.c
├── docker_arch.c
├── dockerfile.c
├── best_practices.c
└── Makefile
```
