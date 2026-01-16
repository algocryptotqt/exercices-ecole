# ex04: Mount & User Namespaces

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.10: Mount Namespace (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | MNT isolation | Separate mount tree |
| b | Private mounts | Not visible outside |
| c | Shared subtrees | Propagation |
| d | MS_PRIVATE | No propagation |
| e | MS_SHARED | Bidirectional |
| f | MS_SLAVE | One-way |
| g | pivot_root | Change root |
| h | Container rootfs | Isolated filesystem |

### 2.10.11: User Namespace (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | USER isolation | UID/GID mapping |
| b | Root inside | UID 0 in namespace |
| c | Unprivileged outside | Different UID outside |
| d | /proc/[pid]/uid_map | UID mapping |
| e | /proc/[pid]/gid_map | GID mapping |
| f | Unprivileged containers | No host root |
| g | setgroups | Must deny write |

### 2.10.12: Other Namespaces (6 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | UTS namespace | Hostname isolation |
| b | IPC namespace | IPC isolation |
| c | CGROUP namespace | Cgroup view isolation |
| d | TIME namespace | Clock isolation |
| e | Combining | Multiple namespaces |
| f | Container = all | Uses all namespaces |

---

## Sujet

Maitriser les namespaces mount, user et autres pour l'isolation complete.

---

## Exemple

```c
#define _GNU_SOURCE
#include "mount_user_ns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#define STACK_SIZE (1024 * 1024)

// ============================================
// Mount Namespace
// ============================================

void show_mounts(const char *label) {
    printf("\n%s:\n", label);
    FILE *f = fopen("/proc/self/mounts", "r");
    if (!f) return;

    char line[512];
    int count = 0;
    while (fgets(line, sizeof(line), f) && count < 10) {
        printf("  %s", line);
        count++;
    }
    if (count == 10) printf("  ... (truncated)\n");
    fclose(f);
}

int demo_mount_namespace(void) {
    printf("\n=== Mount Namespace Demo ===\n");

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    }

    if (pid == 0) {
        // Child: create new mount namespace
        if (unshare(CLONE_NEWNS) < 0) {
            perror("unshare(CLONE_NEWNS)");
            exit(1);
        }

        // Make all mounts private (no propagation)
        if (mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
            perror("mount MS_PRIVATE");
        }

        // Create a tmpfs mount (only visible in this namespace)
        mkdir("/tmp/ns_test", 0755);
        if (mount("tmpfs", "/tmp/ns_test", "tmpfs", 0, "size=10M") < 0) {
            perror("mount tmpfs");
        }

        printf("\nChild namespace: /tmp/ns_test mounted as tmpfs\n");

        // Create a file
        int fd = open("/tmp/ns_test/hello.txt", O_CREAT | O_WRONLY, 0644);
        if (fd >= 0) {
            write(fd, "Hello from mount namespace!\n", 28);
            close(fd);
            printf("Created /tmp/ns_test/hello.txt\n");
        }

        system("ls -la /tmp/ns_test/");

        // Cleanup
        umount("/tmp/ns_test");
        rmdir("/tmp/ns_test");
        exit(0);
    }

    // Parent waits
    waitpid(pid, NULL, 0);

    // Check if mount is visible in parent
    printf("\nParent namespace: checking /tmp/ns_test\n");
    if (access("/tmp/ns_test", F_OK) == 0) {
        printf("  Directory exists but mount is not visible\n");
        system("ls -la /tmp/ns_test/ 2>/dev/null || echo '  (empty or not accessible)'");
    } else {
        printf("  Directory does not exist (as expected)\n");
    }

    return 0;
}

// ============================================
// Mount Propagation
// ============================================

void explain_mount_propagation(void) {
    printf("\n=== Mount Propagation ===\n\n");

    printf("Propagation Types:\n");
    printf("  MS_SHARED:  Mount events propagate both ways\n");
    printf("              A mount in NS1 appears in NS2 and vice versa\n");
    printf("\n");
    printf("  MS_PRIVATE: No propagation\n");
    printf("              Mount only visible in current namespace\n");
    printf("\n");
    printf("  MS_SLAVE:   One-way propagation from master\n");
    printf("              Receives events from master, doesn't send\n");
    printf("\n");
    printf("  MS_UNBINDABLE: Private + cannot be bind mounted\n");

    printf("\nDefault behavior:\n");
    printf("  systemd sets / as MS_SHARED by default\n");
    printf("  Containers usually set MS_PRIVATE first\n");

    printf("\nChecking propagation type:\n");
    printf("  cat /proc/self/mountinfo\n");
    printf("  Look for: shared:N, master:N, or nothing (private)\n");

    printf("\nSetting propagation:\n");
    printf("  mount --make-private /\n");
    printf("  mount --make-shared /\n");
    printf("  mount --make-slave /\n");
}

// ============================================
// User Namespace
// ============================================

int write_mapping(pid_t pid, const char *map_file, const char *mapping) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/%s", pid, map_file);

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        perror(path);
        return -1;
    }

    if (write(fd, mapping, strlen(mapping)) < 0) {
        perror("write mapping");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int deny_setgroups(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        perror(path);
        return -1;
    }

    if (write(fd, "deny", 4) < 0) {
        perror("write setgroups");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static int user_ns_child(void *arg) {
    int *pipefd = (int *)arg;

    // Close write end
    close(pipefd[1]);

    // Wait for parent to set up mappings
    char ch;
    read(pipefd[0], &ch, 1);
    close(pipefd[0]);

    printf("\n=== Inside User Namespace ===\n");
    printf("  getuid()  = %d (should be 0)\n", getuid());
    printf("  geteuid() = %d (should be 0)\n", geteuid());
    printf("  getgid()  = %d (should be 0)\n", getgid());
    printf("  getegid() = %d (should be 0)\n", getegid());

    // Try privileged operations
    printf("\nAttempting privileged operations:\n");

    if (sethostname("container", 9) == 0) {
        printf("  sethostname: SUCCESS (we're root in namespace)\n");
    } else {
        printf("  sethostname: FAILED (%s)\n", strerror(errno));
    }

    // This would fail without real root
    if (mount("proc", "/proc", "proc", 0, NULL) == 0) {
        printf("  mount /proc: SUCCESS\n");
    } else {
        printf("  mount /proc: FAILED (%s)\n", strerror(errno));
    }

    return 0;
}

int demo_user_namespace(void) {
    printf("\n=== User Namespace Demo ===\n");

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        perror("pipe");
        return -1;
    }

    void *stack = malloc(STACK_SIZE);
    if (!stack) return -1;

    // Create new user namespace (and UTS for hostname demo)
    int flags = CLONE_NEWUSER | CLONE_NEWUTS | SIGCHLD;

    pid_t pid = clone(user_ns_child, stack + STACK_SIZE, flags, pipefd);
    if (pid < 0) {
        perror("clone");
        free(stack);
        return -1;
    }

    // Close read end
    close(pipefd[0]);

    // Set up UID/GID mapping
    // Map UID 0 inside to our UID outside
    uid_t uid = getuid();
    gid_t gid = getgid();

    char uid_map[64], gid_map[64];
    snprintf(uid_map, sizeof(uid_map), "0 %d 1\n", uid);
    snprintf(gid_map, sizeof(gid_map), "0 %d 1\n", gid);

    printf("Setting up mappings:\n");
    printf("  uid_map: 0 %d 1 (inside:0 -> outside:%d, count:1)\n", uid, uid);
    printf("  gid_map: 0 %d 1 (inside:0 -> outside:%d, count:1)\n", gid, gid);

    // Must deny setgroups before writing gid_map
    deny_setgroups(pid);
    write_mapping(pid, "uid_map", uid_map);
    write_mapping(pid, "gid_map", gid_map);

    // Signal child to continue
    close(pipefd[1]);

    waitpid(pid, NULL, 0);
    free(stack);
    return 0;
}

// ============================================
// Other Namespaces
// ============================================

void explain_other_namespaces(void) {
    printf("\n=== Other Namespaces ===\n\n");

    printf("UTS Namespace:\n");
    printf("  Isolates hostname and domain name\n");
    printf("  CLONE_NEWUTS flag\n");
    printf("  sethostname() affects only this namespace\n");

    printf("\nIPC Namespace:\n");
    printf("  Isolates IPC resources:\n");
    printf("    - System V IPC (semaphores, message queues, shared memory)\n");
    printf("    - POSIX message queues\n");
    printf("  CLONE_NEWIPC flag\n");

    printf("\nCgroup Namespace:\n");
    printf("  Virtualizes cgroup filesystem view\n");
    printf("  Container sees its cgroup as root\n");
    printf("  CLONE_NEWCGROUP flag\n");

    printf("\nTime Namespace (Linux 5.6+):\n");
    printf("  Isolates CLOCK_MONOTONIC and CLOCK_BOOTTIME\n");
    printf("  Container can have different boot time\n");
    printf("  CLONE_NEWTIME flag\n");

    printf("\nComplete Container = All Namespaces:\n");
    printf("  unshare --mount --uts --ipc --net --pid --user \\\n");
    printf("          --cgroup --fork --map-root-user /bin/bash\n");
}

int main(void) {
    printf("=== Mount Namespace ===\n\n");

    printf("Mount Namespace Properties:\n");
    printf("  - Isolates mount points\n");
    printf("  - Each namespace has its own mount table\n");
    printf("  - Changes don't affect other namespaces\n");
    printf("  - Essential for container filesystem isolation\n");

    printf("\nTypical Container Mount Setup:\n");
    printf("  1. Create new mount namespace\n");
    printf("  2. Make all mounts private (no propagation)\n");
    printf("  3. Prepare container rootfs\n");
    printf("  4. Mount /proc, /sys, /dev\n");
    printf("  5. pivot_root to container rootfs\n");
    printf("  6. Unmount old root\n");

    printf("\n\n=== User Namespace ===\n\n");

    printf("User Namespace Properties:\n");
    printf("  - Maps UIDs/GIDs between namespaces\n");
    printf("  - Process can be root inside, unprivileged outside\n");
    printf("  - Enables unprivileged containers\n");
    printf("  - Provides security isolation\n");

    printf("\nUID/GID Mapping Format:\n");
    printf("  inside_id outside_id count\n");
    printf("  Examples:\n");
    printf("    0 1000 1     : UID 0 inside = UID 1000 outside\n");
    printf("    0 100000 65536 : Map 65536 UIDs starting at 100000\n");

    printf("\nMapping Files:\n");
    printf("  /proc/[pid]/uid_map : UID mapping\n");
    printf("  /proc/[pid]/gid_map : GID mapping\n");
    printf("  /proc/[pid]/setgroups : Must be 'deny' before gid_map\n");

    explain_mount_propagation();
    explain_other_namespaces();

    // Run demos
    if (geteuid() == 0) {
        demo_mount_namespace();
    }

    // User namespace can work without root
    printf("\n\n--- User Namespace Demo (works unprivileged) ---\n");
    demo_user_namespace();

    return 0;
}
```

---

## Fichiers

```
ex04/
├── mount_user_ns.h
├── mount_namespace.c
├── mount_propagation.c
├── user_namespace.c
├── other_namespaces.c
└── Makefile
```
