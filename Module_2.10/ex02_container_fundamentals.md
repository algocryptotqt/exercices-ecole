# ex02: Container Fundamentals & Namespaces Overview

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.6: Container Concepts (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Container | Isolated process |
| b | vs VM | Shared kernel |
| c | Benefits | Lightweight, fast |
| d | Image | Filesystem snapshot |
| e | Layer | Image component |
| f | Registry | Image repository |
| g | Container runtime | Execute containers |
| h | Orchestration | Manage many containers |

### 2.10.7: Linux Namespaces Overview (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Namespace | Isolation mechanism |
| b | Purpose | Separate resources |
| c | Types | PID, NET, MNT, UTS, IPC, USER, CGROUP, TIME |
| d | clone() | Create with namespace |
| e | unshare() | Leave namespace |
| f | setns() | Join namespace |
| g | /proc/[pid]/ns | Namespace files |

---

## Sujet

Comprendre les concepts des conteneurs et le systeme de namespaces Linux.

---

## Exemple

```c
#define _GNU_SOURCE
#include "containers.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>

// Namespace types and their flags
typedef struct {
    int flag;
    const char *name;
    const char *ns_file;
    const char *description;
} namespace_info_t;

static const namespace_info_t namespaces[] = {
    { CLONE_NEWPID,    "PID",    "pid",    "Process IDs" },
    { CLONE_NEWNET,    "NET",    "net",    "Network stack" },
    { CLONE_NEWNS,     "MNT",    "mnt",    "Mount points" },
    { CLONE_NEWUTS,    "UTS",    "uts",    "Hostname" },
    { CLONE_NEWIPC,    "IPC",    "ipc",    "IPC resources" },
    { CLONE_NEWUSER,   "USER",   "user",   "User/group IDs" },
    { CLONE_NEWCGROUP, "CGROUP", "cgroup", "Cgroup hierarchy" },
#ifdef CLONE_NEWTIME
    { CLONE_NEWTIME,   "TIME",   "time",   "Monotonic/boottime" },
#endif
};

#define NUM_NAMESPACES (sizeof(namespaces) / sizeof(namespaces[0]))

// Display namespace info for a process
void show_namespaces(pid_t pid) {
    char path[256];
    char link[256];

    printf("Namespaces for PID %d:\n", pid);

    for (size_t i = 0; i < NUM_NAMESPACES; i++) {
        snprintf(path, sizeof(path), "/proc/%d/ns/%s", pid, namespaces[i].ns_file);
        ssize_t len = readlink(path, link, sizeof(link) - 1);
        if (len > 0) {
            link[len] = '\0';
            printf("  %-8s: %s\n", namespaces[i].name, link);
        } else {
            printf("  %-8s: (not available)\n", namespaces[i].name);
        }
    }
}

// Simple unshare demonstration
int demo_unshare_uts(void) {
    char hostname[256];

    printf("\n=== UTS Namespace Demo (unshare) ===\n");

    // Get current hostname
    gethostname(hostname, sizeof(hostname));
    printf("Before unshare: hostname = %s\n", hostname);

    // Unshare UTS namespace
    if (unshare(CLONE_NEWUTS) < 0) {
        perror("unshare(CLONE_NEWUTS)");
        printf("Note: Requires root or CAP_SYS_ADMIN\n");
        return -1;
    }

    // Change hostname in new namespace
    if (sethostname("container", 9) < 0) {
        perror("sethostname");
        return -1;
    }

    gethostname(hostname, sizeof(hostname));
    printf("After unshare: hostname = %s\n", hostname);
    printf("(Host system hostname unchanged)\n");

    return 0;
}

// Clone with new namespace
#define STACK_SIZE (1024 * 1024)

static int child_func(void *arg) {
    (void)arg;

    printf("\nChild process:\n");
    printf("  PID (inside namespace): %d\n", getpid());
    printf("  Parent PID: %d\n", getppid());

    // In PID namespace, we are PID 1
    // Show our namespaces
    show_namespaces(getpid());

    // Execute a command
    char *argv[] = { "/bin/sh", "-c", "echo 'Hello from container!'", NULL };
    execv("/bin/sh", argv);
    perror("execv");
    return 1;
}

int demo_clone_namespace(void) {
    printf("\n=== Clone with Namespaces ===\n");

    void *stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("malloc");
        return -1;
    }

    // Clone with new PID and UTS namespaces
    int flags = CLONE_NEWPID | CLONE_NEWUTS | SIGCHLD;

    pid_t pid = clone(child_func, stack + STACK_SIZE, flags, NULL);
    if (pid < 0) {
        perror("clone");
        printf("Note: Requires root or appropriate capabilities\n");
        free(stack);
        return -1;
    }

    printf("Parent: Created child with PID %d\n", pid);

    int status;
    waitpid(pid, &status, 0);
    printf("Parent: Child exited with status %d\n", WEXITSTATUS(status));

    free(stack);
    return 0;
}

// Join existing namespace
int demo_setns(pid_t target_pid, const char *ns_type) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/ns/%s", target_pid, ns_type);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open namespace");
        return -1;
    }

    if (setns(fd, 0) < 0) {
        perror("setns");
        close(fd);
        return -1;
    }

    close(fd);
    printf("Joined %s namespace of PID %d\n", ns_type, target_pid);
    return 0;
}

int main(void) {
    printf("=== Container Concepts ===\n\n");

    // Containers vs VMs
    printf("Containers vs Virtual Machines:\n");
    printf("  +-----------------+-----------------+\n");
    printf("  |   Virtual Machine  |   Container   |\n");
    printf("  +-----------------+-----------------+\n");
    printf("  | Full OS per VM     | Shared kernel  |\n");
    printf("  | Hardware emulation | Process isolation |\n");
    printf("  | Minutes to start   | Seconds to start |\n");
    printf("  | GBs of memory      | MBs of memory   |\n");
    printf("  | Strong isolation   | Weaker isolation |\n");
    printf("  | Hypervisor         | Container runtime |\n");
    printf("  +-----------------+-----------------+\n");

    printf("\nContainer Benefits:\n");
    printf("  - Lightweight: Share host kernel\n");
    printf("  - Fast startup: No boot sequence\n");
    printf("  - Portable: Same image runs anywhere\n");
    printf("  - Efficient: High density\n");
    printf("  - Consistent: Dev = Prod environment\n");

    // Container components
    printf("\n\nContainer Components:\n");
    printf("  Image:\n");
    printf("    - Immutable filesystem snapshot\n");
    printf("    - Built in layers (overlay)\n");
    printf("    - Defined by Dockerfile/Containerfile\n");
    printf("    - Stored in registries (Docker Hub, etc.)\n");

    printf("\n  Container:\n");
    printf("    - Running instance of image\n");
    printf("    - Has its own:\n");
    printf("      * PID namespace\n");
    printf("      * Network namespace\n");
    printf("      * Mount namespace\n");
    printf("      * User namespace (optional)\n");
    printf("    - Can have volumes for persistent data\n");

    printf("\n  Runtime:\n");
    printf("    - Low-level: runc (OCI reference)\n");
    printf("    - High-level: containerd, CRI-O\n");
    printf("    - User tools: Docker, Podman\n");

    printf("\n  Orchestration:\n");
    printf("    - Kubernetes: Industry standard\n");
    printf("    - Docker Swarm: Simpler alternative\n");
    printf("    - Nomad: HashiCorp solution\n");

    // Namespaces
    printf("\n\n=== Linux Namespaces ===\n\n");

    printf("Available Namespace Types:\n");
    for (size_t i = 0; i < NUM_NAMESPACES; i++) {
        printf("  %-8s: %s\n", namespaces[i].name, namespaces[i].description);
    }

    printf("\nNamespace System Calls:\n");
    printf("  clone(flags):    Create child in new namespace\n");
    printf("  unshare(flags):  Move current process to new namespace\n");
    printf("  setns(fd, type): Join existing namespace\n");

    printf("\nNamespace Files:\n");
    printf("  /proc/[pid]/ns/  - Namespace inode links\n");
    printf("  Can be bind-mounted to persist namespace\n");
    printf("  File descriptor can be passed to setns()\n");

    // Show current namespaces
    printf("\n\n=== Current Process Namespaces ===\n");
    show_namespaces(getpid());

    // Demos (require privileges)
    if (geteuid() == 0) {
        demo_unshare_uts();
        demo_clone_namespace();
    } else {
        printf("\nNote: Run as root to see namespace demos\n");
    }

    // Image layers explanation
    printf("\n\n=== Image Layers ===\n\n");

    printf("Layer Concept:\n");
    printf("  Base Layer: OS filesystem (alpine, ubuntu, etc.)\n");
    printf("        |\n");
    printf("  Layer 2: apt-get install python\n");
    printf("        |\n");
    printf("  Layer 3: pip install requirements\n");
    printf("        |\n");
    printf("  Layer 4: COPY application code\n");
    printf("        |\n");
    printf("  Container Layer: (read-write)\n");

    printf("\nBenefits:\n");
    printf("  - Shared base layers save disk space\n");
    printf("  - Only changed layers need downloading\n");
    printf("  - Copy-on-write for container layer\n");
    printf("  - Efficient caching during builds\n");

    printf("\nUnion Filesystem (OverlayFS):\n");
    printf("  lower/: Read-only image layers\n");
    printf("  upper/: Read-write container layer\n");
    printf("  work/:  OverlayFS work directory\n");
    printf("  merged/: Combined view\n");

    return 0;
}
```

---

## Fichiers

```
ex02/
├── containers.h
├── container_concepts.c
├── namespace_overview.c
├── image_layers.c
└── Makefile
```
