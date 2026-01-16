# ex16: Container Security

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.29: Container Security (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Root in container | Risk |
| b | Rootless containers | User namespaces |
| c | Read-only rootfs | Immutable |
| d | No new privileges | Flag |
| e | Seccomp profiles | Syscall filtering |
| f | AppArmor/SELinux | MAC |
| g | Image scanning | Vulnerability check |
| h | Least privilege | Drop capabilities |

---

## Sujet

Maitriser les bonnes pratiques de securite pour les conteneurs.

---

## Exemple

```c
#include "container_security.h"
#include <stdio.h>
#include <stdlib.h>

void explain_container_risks(void) {
    printf("=== Container Security Risks ===\n\n");

    printf("Containers share the host kernel:\n");
    printf("  - Kernel vulnerability = all containers affected\n");
    printf("  - Container escape is possible\n");
    printf("  - Not as isolated as VMs\n");

    printf("\nCommon risks:\n");
    printf("  1. Running as root in container\n");
    printf("  2. Vulnerable images\n");
    printf("  3. Excessive capabilities\n");
    printf("  4. Unfiltered syscalls\n");
    printf("  5. Insecure network exposure\n");
    printf("  6. Secrets in images/env vars\n");
    printf("  7. Writable root filesystem\n");
}

// ============================================
// Rootless Containers
// ============================================

void explain_rootless(void) {
    printf("\n=== Rootless Containers ===\n\n");

    printf("Run containers without root privileges:\n");
    printf("  - Uses user namespaces\n");
    printf("  - root in container = unprivileged user outside\n");
    printf("  - Limits attack surface\n");

    printf("\nDocker rootless mode:\n");
    printf("  # Install\n");
    printf("  curl -fsSL https://get.docker.com/rootless | sh\n");
    printf("\n");
    printf("  # Run\n");
    printf("  export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock\n");
    printf("  docker run hello-world\n");

    printf("\nPodman (rootless by default):\n");
    printf("  podman run --rm alpine id\n");
    printf("  # Shows uid=0(root) but is actually mapped user\n");

    printf("\nLimitations:\n");
    printf("  - Cannot bind ports < 1024 (use port forwarding)\n");
    printf("  - Some storage drivers not available\n");
    printf("  - Overlay network limitations\n");
}

// ============================================
// Non-root User
// ============================================

void explain_nonroot_user(void) {
    printf("\n=== Running as Non-root User ===\n\n");

    printf("Even with rootless, avoid root inside container:\n\n");

    printf("Dockerfile:\n");
    printf("  FROM alpine:3.18\n");
    printf("  RUN adduser -D appuser\n");
    printf("  USER appuser\n");
    printf("  CMD [\"./app\"]\n");

    printf("\nRuntime:\n");
    printf("  docker run --user 1000:1000 alpine id\n");
    printf("  docker run --user nobody alpine id\n");

    printf("\nBenefits:\n");
    printf("  - Cannot modify system files\n");
    printf("  - Cannot install packages\n");
    printf("  - Limited damage from compromise\n");
}

// ============================================
// Read-only Filesystem
// ============================================

void explain_readonly_rootfs(void) {
    printf("\n=== Read-only Root Filesystem ===\n\n");

    printf("Prevent container from modifying its filesystem:\n");
    printf("  docker run --read-only alpine sh\n");

    printf("\nWith tmpfs for writable directories:\n");
    printf("  docker run --read-only \\\n");
    printf("    --tmpfs /tmp \\\n");
    printf("    --tmpfs /run \\\n");
    printf("    -v data:/app/data \\\n");
    printf("    myapp\n");

    printf("\nBenefits:\n");
    printf("  - Prevents malware installation\n");
    printf("  - Ensures immutable infrastructure\n");
    printf("  - Detects unauthorized changes\n");
}

// ============================================
// No New Privileges
// ============================================

void explain_no_new_privs(void) {
    printf("\n=== No New Privileges ===\n\n");

    printf("Prevent privilege escalation via setuid/setgid:\n");
    printf("  docker run --security-opt no-new-privileges:true alpine\n");

    printf("\nWhat it blocks:\n");
    printf("  - setuid binaries (su, sudo)\n");
    printf("  - setgid binaries\n");
    printf("  - Gaining capabilities through exec\n");

    printf("\nRecommendation:\n");
    printf("  Always use unless application requires setuid\n");
}

// ============================================
// Capabilities
// ============================================

void explain_capabilities_security(void) {
    printf("\n=== Capabilities ===\n\n");

    printf("Drop unnecessary capabilities:\n");
    printf("  docker run --cap-drop ALL --cap-add NET_BIND_SERVICE nginx\n");

    printf("\nDocker default capabilities:\n");
    printf("  CHOWN, DAC_OVERRIDE, FSETID, FOWNER, MKNOD,\n");
    printf("  NET_RAW, SETGID, SETUID, SETFCAP, SETPCAP,\n");
    printf("  NET_BIND_SERVICE, SYS_CHROOT, KILL, AUDIT_WRITE\n");

    printf("\nDangerous capabilities to avoid:\n");
    printf("  CAP_SYS_ADMIN   - Essentially root\n");
    printf("  CAP_NET_ADMIN   - Network manipulation\n");
    printf("  CAP_SYS_PTRACE  - Debug any process\n");
    printf("  CAP_SYS_MODULE  - Load kernel modules\n");

    printf("\nNEVER use --privileged unless absolutely necessary:\n");
    printf("  # Gives ALL capabilities + access to devices\n");
    printf("  docker run --privileged ...  # DANGEROUS\n");
}

// ============================================
// Seccomp
// ============================================

void explain_seccomp_profiles(void) {
    printf("\n=== Seccomp Profiles ===\n\n");

    printf("Docker applies default seccomp profile:\n");
    printf("  - Blocks ~44 dangerous syscalls\n");
    printf("  - Prevents kernel exploitation\n");

    printf("\nCustom profile:\n");
    printf("  docker run --security-opt seccomp=profile.json nginx\n");

    printf("\nDisable (not recommended):\n");
    printf("  docker run --security-opt seccomp=unconfined nginx\n");

    printf("\nBlocked syscalls include:\n");
    printf("  - clone with CLONE_NEWUSER\n");
    printf("  - mount, umount\n");
    printf("  - reboot\n");
    printf("  - init_module, delete_module\n");
    printf("  - acct, quotactl\n");
}

// ============================================
// AppArmor / SELinux
// ============================================

void explain_mac(void) {
    printf("\n=== Mandatory Access Control ===\n\n");

    printf("AppArmor (Ubuntu/Debian):\n");
    printf("  docker run --security-opt apparmor=docker-default nginx\n");
    printf("  docker run --security-opt apparmor=unconfined nginx  # Disable\n");

    printf("\nSELinux (RHEL/Fedora):\n");
    printf("  docker run --security-opt label=type:container_t nginx\n");
    printf("  docker run --security-opt label=disable nginx  # Disable\n");

    printf("\nBenefits:\n");
    printf("  - Additional layer of confinement\n");
    printf("  - Process isolation enforcement\n");
    printf("  - File access restrictions\n");
}

// ============================================
// Image Security
// ============================================

void explain_image_security(void) {
    printf("\n=== Image Security ===\n\n");

    printf("1. Use official/verified images:\n");
    printf("   FROM nginx:1.25-alpine\n");
    printf("   NOT FROM randomuser/nginx\n");

    printf("\n2. Use specific tags (not :latest):\n");
    printf("   FROM python:3.11-slim  # Good\n");
    printf("   FROM python:latest     # Bad\n");

    printf("\n3. Scan images for vulnerabilities:\n");
    printf("   docker scan myimage\n");
    printf("   trivy image myimage\n");
    printf("   grype myimage\n");

    printf("\n4. Use minimal base images:\n");
    printf("   alpine, distroless, scratch\n");

    printf("\n5. Don't include secrets in images:\n");
    printf("   Use runtime secrets, env vars, or volume mounts\n");

    printf("\n6. Sign and verify images:\n");
    printf("   docker trust sign myimage:1.0\n");
    printf("   DOCKER_CONTENT_TRUST=1 docker pull myimage\n");

    printf("\n7. Regular updates:\n");
    printf("   Rebuild images to get security patches\n");
}

// ============================================
// Runtime Security
// ============================================

void explain_runtime_security(void) {
    printf("\n=== Runtime Security ===\n\n");

    printf("Resource limits:\n");
    printf("  docker run --memory=512m --cpus=1 nginx\n");
    printf("  docker run --pids-limit=100 nginx\n");
    printf("  docker run --ulimit nofile=1024:1024 nginx\n");

    printf("\nNetwork security:\n");
    printf("  docker run --network none myapp  # No network\n");
    printf("  docker run -p 127.0.0.1:8080:80 nginx  # Localhost only\n");

    printf("\nMount restrictions:\n");
    printf("  docker run -v /data:/data:ro nginx  # Read-only\n");
    printf("  # Avoid mounting sensitive paths like /etc, /var/run/docker.sock\n");

    printf("\nHealth checks:\n");
    printf("  HEALTHCHECK CMD curl -f http://localhost/ || exit 1\n");
}

// ============================================
// Security Checklist
// ============================================

void show_security_checklist(void) {
    printf("\n=== Container Security Checklist ===\n\n");

    printf("[ ] Use non-root user in container\n");
    printf("[ ] Enable rootless mode or user namespaces\n");
    printf("[ ] Drop all capabilities, add only needed\n");
    printf("[ ] Use --read-only filesystem\n");
    printf("[ ] Enable no-new-privileges\n");
    printf("[ ] Use seccomp profile (keep default)\n");
    printf("[ ] Enable AppArmor/SELinux\n");
    printf("[ ] Scan images for vulnerabilities\n");
    printf("[ ] Use minimal base images\n");
    printf("[ ] Don't store secrets in images\n");
    printf("[ ] Set resource limits\n");
    printf("[ ] Don't use --privileged\n");
    printf("[ ] Don't expose Docker socket\n");
    printf("[ ] Use specific image tags\n");
    printf("[ ] Regularly update images\n");

    printf("\nSecure docker run example:\n");
    printf("  docker run -d \\\n");
    printf("    --name secure-app \\\n");
    printf("    --user 1000:1000 \\\n");
    printf("    --read-only \\\n");
    printf("    --tmpfs /tmp \\\n");
    printf("    --cap-drop ALL \\\n");
    printf("    --security-opt no-new-privileges:true \\\n");
    printf("    --security-opt seccomp=default.json \\\n");
    printf("    --memory 512m \\\n");
    printf("    --cpus 1 \\\n");
    printf("    --pids-limit 100 \\\n");
    printf("    --network mynet \\\n");
    printf("    myapp:1.0.0\n");
}

int main(void) {
    explain_container_risks();
    explain_rootless();
    explain_nonroot_user();
    explain_readonly_rootfs();
    explain_no_new_privs();
    explain_capabilities_security();
    explain_seccomp_profiles();
    explain_mac();
    explain_image_security();
    explain_runtime_security();
    show_security_checklist();

    return 0;
}
```

---

## Fichiers

```
ex16/
├── container_security.h
├── rootless.c
├── capabilities.c
├── seccomp_mac.c
├── image_security.c
├── runtime_security.c
└── Makefile
```
