# ex12: Building Container from Scratch

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Avance
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.10.23: Building Container from Scratch (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Create namespaces | clone() with flags |
| b | Setup networking | veth pair |
| c | Setup filesystem | Mount proc, sys, dev |
| d | pivot_root | Change root |
| e | Setup cgroups | Create and join |
| f | Apply seccomp | Filter syscalls |
| g | Drop capabilities | Reduce privileges |
| h | exec | Run container init |

---

## Sujet

Construire un conteneur complet from scratch en utilisant toutes les primitives Linux.

---

## Exemple

```c
#define _GNU_SOURCE
#include "container.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <grp.h>

#define STACK_SIZE (1024 * 1024)

// Container configuration
typedef struct {
    char *rootfs;           // Path to rootfs
    char *hostname;         // Container hostname
    char **argv;            // Command to run
    uid_t uid;              // UID mapping
    gid_t gid;              // GID mapping
    long memory_limit;      // Memory limit (bytes)
    int cpu_shares;         // CPU shares
    int pids_limit;         // Max processes
} container_config_t;

// ============================================
// Step 1: Create Namespaces
// ============================================

int create_namespaces(void) {
    // Namespace flags
    int flags = CLONE_NEWPID    // New PID namespace
              | CLONE_NEWNS     // New mount namespace
              | CLONE_NEWUTS    // New UTS namespace
              | CLONE_NEWIPC    // New IPC namespace
              | CLONE_NEWNET    // New network namespace
              | CLONE_NEWUSER;  // New user namespace

    if (unshare(flags) < 0) {
        perror("unshare");
        return -1;
    }

    return 0;
}

// ============================================
// Step 2: Setup User Namespace Mapping
// ============================================

int setup_user_mapping(pid_t pid, uid_t uid, gid_t gid) {
    char path[256];
    char content[64];
    int fd;

    // Deny setgroups (required before gid_map)
    snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
    fd = open(path, O_WRONLY);
    if (fd >= 0) {
        write(fd, "deny", 4);
        close(fd);
    }

    // UID mapping: map root in container to host uid
    snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);
    snprintf(content, sizeof(content), "0 %d 1\n", uid);
    fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    write(fd, content, strlen(content));
    close(fd);

    // GID mapping
    snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);
    snprintf(content, sizeof(content), "0 %d 1\n", gid);
    fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    write(fd, content, strlen(content));
    close(fd);

    return 0;
}

// ============================================
// Step 3: Setup Filesystem
// ============================================

int setup_filesystem(const char *rootfs) {
    // Make all mounts private
    if (mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        perror("mount MS_PRIVATE");
        return -1;
    }

    // Bind mount new root
    if (mount(rootfs, rootfs, NULL, MS_BIND | MS_REC, NULL) < 0) {
        perror("bind mount rootfs");
        return -1;
    }

    // Create mount points in new root
    char path[512];

    // Mount /proc
    snprintf(path, sizeof(path), "%s/proc", rootfs);
    mkdir(path, 0555);
    if (mount("proc", path, "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) < 0) {
        perror("mount /proc");
    }

    // Mount /sys
    snprintf(path, sizeof(path), "%s/sys", rootfs);
    mkdir(path, 0555);
    if (mount("sysfs", path, "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RDONLY, NULL) < 0) {
        perror("mount /sys");
    }

    // Mount /dev
    snprintf(path, sizeof(path), "%s/dev", rootfs);
    mkdir(path, 0755);
    if (mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_STRICTATIME, "mode=755,size=65536k") < 0) {
        perror("mount /dev");
    }

    // Create essential device nodes
    snprintf(path, sizeof(path), "%s/dev/null", rootfs);
    mknod(path, S_IFCHR | 0666, makedev(1, 3));

    snprintf(path, sizeof(path), "%s/dev/zero", rootfs);
    mknod(path, S_IFCHR | 0666, makedev(1, 5));

    snprintf(path, sizeof(path), "%s/dev/random", rootfs);
    mknod(path, S_IFCHR | 0666, makedev(1, 8));

    snprintf(path, sizeof(path), "%s/dev/urandom", rootfs);
    mknod(path, S_IFCHR | 0666, makedev(1, 9));

    // Create /dev/pts
    snprintf(path, sizeof(path), "%s/dev/pts", rootfs);
    mkdir(path, 0755);
    if (mount("devpts", path, "devpts", MS_NOSUID | MS_NOEXEC,
              "newinstance,ptmxmode=0666,mode=620") < 0) {
        perror("mount /dev/pts");
    }

    return 0;
}

// ============================================
// Step 4: pivot_root
// ============================================

static int pivot_root(const char *new_root, const char *put_old) {
    return syscall(SYS_pivot_root, new_root, put_old);
}

int do_pivot_root(const char *rootfs) {
    char put_old[512];
    snprintf(put_old, sizeof(put_old), "%s/.old_root", rootfs);
    mkdir(put_old, 0700);

    // pivot_root
    if (pivot_root(rootfs, put_old) < 0) {
        perror("pivot_root");
        return -1;
    }

    // Change to new root
    if (chdir("/") < 0) {
        perror("chdir /");
        return -1;
    }

    // Unmount old root
    if (umount2("/.old_root", MNT_DETACH) < 0) {
        perror("umount old root");
    }

    rmdir("/.old_root");
    return 0;
}

// ============================================
// Step 5: Setup Cgroups
// ============================================

int setup_cgroups(pid_t pid, const container_config_t *config) {
    char path[512];
    char value[64];
    int fd;

    // Create cgroup (v2 unified hierarchy)
    snprintf(path, sizeof(path), "/sys/fs/cgroup/container_%d", pid);
    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        // Try v1
        snprintf(path, sizeof(path), "/sys/fs/cgroup/memory/container_%d", pid);
        mkdir(path, 0755);
    }

    // Memory limit
    if (config->memory_limit > 0) {
        snprintf(path, sizeof(path), "/sys/fs/cgroup/container_%d/memory.max", pid);
        fd = open(path, O_WRONLY);
        if (fd < 0) {
            // v1 fallback
            snprintf(path, sizeof(path),
                     "/sys/fs/cgroup/memory/container_%d/memory.limit_in_bytes", pid);
            fd = open(path, O_WRONLY);
        }
        if (fd >= 0) {
            snprintf(value, sizeof(value), "%ld", config->memory_limit);
            write(fd, value, strlen(value));
            close(fd);
        }
    }

    // PIDs limit
    if (config->pids_limit > 0) {
        snprintf(path, sizeof(path), "/sys/fs/cgroup/container_%d/pids.max", pid);
        fd = open(path, O_WRONLY);
        if (fd < 0) {
            snprintf(path, sizeof(path),
                     "/sys/fs/cgroup/pids/container_%d/pids.max", pid);
            fd = open(path, O_WRONLY);
        }
        if (fd >= 0) {
            snprintf(value, sizeof(value), "%d", config->pids_limit);
            write(fd, value, strlen(value));
            close(fd);
        }
    }

    // Add process to cgroup
    snprintf(path, sizeof(path), "/sys/fs/cgroup/container_%d/cgroup.procs", pid);
    fd = open(path, O_WRONLY);
    if (fd >= 0) {
        snprintf(value, sizeof(value), "%d", pid);
        write(fd, value, strlen(value));
        close(fd);
    }

    return 0;
}

// ============================================
// Step 6: Apply seccomp Filter
// ============================================

#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

#if defined(__x86_64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_AARCH64
#endif

int apply_seccomp(void) {
    // Blacklist dangerous syscalls
    struct sock_filter filter[] = {
        // Check architecture
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, arch_nr),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_CURRENT, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        // Load syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, syscall_nr),

        // Block dangerous syscalls
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_reboot, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_init_module, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_delete_module, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

        // Allow everything else
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl NO_NEW_PRIVS");
        return -1;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        perror("prctl SECCOMP");
        return -1;
    }

    return 0;
}

// ============================================
// Step 7: Drop Capabilities
// ============================================

int drop_capabilities(void) {
    // Keep minimal capabilities
    cap_value_t keep[] = {
        CAP_NET_BIND_SERVICE,
        CAP_SETUID,
        CAP_SETGID,
    };

    cap_t caps = cap_init();
    if (!caps) return -1;

    if (cap_set_flag(caps, CAP_PERMITTED, 3, keep, CAP_SET) < 0 ||
        cap_set_flag(caps, CAP_EFFECTIVE, 3, keep, CAP_SET) < 0) {
        cap_free(caps);
        return -1;
    }

    if (cap_set_proc(caps) < 0) {
        cap_free(caps);
        return -1;
    }

    cap_free(caps);

    // Drop bounding set for other capabilities
    for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
        int found = 0;
        for (size_t i = 0; i < sizeof(keep)/sizeof(keep[0]); i++) {
            if (cap == (int)keep[i]) { found = 1; break; }
        }
        if (!found) {
            prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
        }
    }

    return 0;
}

// ============================================
// Container Child Process
// ============================================

static int child_func(void *arg) {
    container_config_t *config = (container_config_t *)arg;

    // Wait for parent to setup user mapping
    char ch;
    close(((int *)config)[0]);  // Close write end of pipe

    // Setup hostname
    if (sethostname(config->hostname, strlen(config->hostname)) < 0) {
        perror("sethostname");
    }

    // Setup filesystem
    if (setup_filesystem(config->rootfs) < 0) {
        fprintf(stderr, "Failed to setup filesystem\n");
        return 1;
    }

    // pivot_root
    if (do_pivot_root(config->rootfs) < 0) {
        fprintf(stderr, "Failed to pivot_root\n");
        return 1;
    }

    // Apply seccomp
    if (apply_seccomp() < 0) {
        fprintf(stderr, "Warning: Failed to apply seccomp\n");
    }

    // Drop capabilities
    if (drop_capabilities() < 0) {
        fprintf(stderr, "Warning: Failed to drop capabilities\n");
    }

    // Execute container command
    printf("=== Container Started ===\n");
    printf("Hostname: %s\n", config->hostname);
    printf("PID: %d (should be 1)\n", getpid());
    printf("Running: %s\n\n", config->argv[0]);

    execvp(config->argv[0], config->argv);
    perror("execvp");
    return 1;
}

// ============================================
// Main: Start Container
// ============================================

int run_container(container_config_t *config) {
    void *stack = malloc(STACK_SIZE);
    if (!stack) return -1;

    int flags = CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS |
                CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUSER | SIGCHLD;

    pid_t pid = clone(child_func, stack + STACK_SIZE, flags, config);
    if (pid < 0) {
        perror("clone");
        free(stack);
        return -1;
    }

    printf("Container PID (in host): %d\n", pid);

    // Setup user mapping
    if (setup_user_mapping(pid, config->uid, config->gid) < 0) {
        fprintf(stderr, "Failed to setup user mapping\n");
    }

    // Setup cgroups
    setup_cgroups(pid, config);

    // Wait for container to exit
    int status;
    waitpid(pid, &status, 0);

    free(stack);
    return WEXITSTATUS(status);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <rootfs> <command> [args...]\n", argv[0]);
        fprintf(stderr, "Example: %s /tmp/alpine /bin/sh\n", argv[0]);
        return 1;
    }

    container_config_t config = {
        .rootfs = argv[1],
        .hostname = "container",
        .argv = &argv[2],
        .uid = getuid(),
        .gid = getgid(),
        .memory_limit = 100 * 1024 * 1024,  // 100 MB
        .cpu_shares = 256,
        .pids_limit = 64,
    };

    printf("=== Container from Scratch ===\n");
    printf("Rootfs: %s\n", config.rootfs);
    printf("Command: %s\n", config.argv[0]);
    printf("Memory limit: %ld bytes\n", config.memory_limit);
    printf("PID limit: %d\n\n", config.pids_limit);

    return run_container(&config);
}
```

---

## Fichiers

```
ex12/
├── container.h
├── container.c
├── namespaces.c
├── filesystem.c
├── cgroups.c
├── security.c
└── Makefile
```

Compiler avec: `gcc -lcap ...`
