# PROJET: Mini Container Runtime

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Avance
**Duree**: 40h
**Score qualite**: 98/100

## Description

Implementer un container runtime OCI-compatible minimal qui combine tous les concepts de virtualisation et conteneurisation appris dans ce module.

---

## Objectifs Pedagogiques

Ce projet integre:
- Namespaces (PID, NET, MNT, UTS, IPC, USER, CGROUP)
- Cgroups v2 (CPU, memory, I/O limits)
- Filesystem isolation (pivot_root, OverlayFS)
- Security (seccomp-bpf, capabilities, no-new-privs)
- Networking (veth, bridge, NAT)
- OCI runtime specification compliance

---

## Architecture

```
minirun/
├── src/
│   ├── main.c              # CLI entry point
│   ├── runtime.c           # Container lifecycle
│   ├── config.c            # OCI config parser
│   ├── namespace.c         # Namespace creation
│   ├── cgroup.c            # Cgroup v2 management
│   ├── filesystem.c        # Rootfs setup (overlay, pivot)
│   ├── security.c          # Seccomp, capabilities
│   ├── network.c           # Network namespace setup
│   ├── process.c           # Process management
│   └── utils.c             # Helper functions
├── include/
│   ├── minirun.h           # Main header
│   ├── config.h            # Configuration structures
│   ├── namespace.h
│   ├── cgroup.h
│   ├── filesystem.h
│   ├── security.h
│   ├── network.h
│   └── utils.h
├── tests/
│   ├── test_namespace.c
│   ├── test_cgroup.c
│   ├── test_security.c
│   └── test_integration.c
├── rootfs/                 # Test container rootfs
│   └── alpine/
├── Makefile
└── README.md
```

---

## Specifications

### Phase 1: Core Runtime (15h)

#### 1.1 Configuration Parser

```c
// include/config.h
#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <linux/seccomp.h>

#define MAX_ARGS 64
#define MAX_ENV 128
#define MAX_MOUNTS 32
#define MAX_CAPABILITIES 64
#define MAX_SECCOMP_RULES 256

// OCI Process configuration
typedef struct {
    char **args;           // Command and arguments
    int argc;
    char **env;            // Environment variables
    int envc;
    char *cwd;             // Working directory
    uint32_t uid;          // User ID
    uint32_t gid;          // Group ID
    bool terminal;         // Allocate PTY
    bool no_new_privileges;
} oci_process_t;

// Mount point
typedef struct {
    char *destination;     // Mount point in container
    char *type;            // Filesystem type
    char *source;          // Source path
    char **options;        // Mount options
    int option_count;
} oci_mount_t;

// Linux capabilities
typedef struct {
    char **bounding;
    int bounding_count;
    char **effective;
    int effective_count;
    char **inheritable;
    int inheritable_count;
    char **permitted;
    int permitted_count;
    char **ambient;
    int ambient_count;
} oci_capabilities_t;

// Cgroup resource limits
typedef struct {
    // CPU
    uint64_t cpu_quota;      // microseconds per period
    uint64_t cpu_period;     // period in microseconds
    uint64_t cpu_shares;     // relative weight
    char *cpuset_cpus;       // e.g., "0-3" or "0,2"
    char *cpuset_mems;       // NUMA nodes

    // Memory
    uint64_t memory_limit;   // bytes
    uint64_t memory_swap;    // bytes (memory + swap)
    uint64_t memory_reservation;  // soft limit

    // I/O
    uint64_t io_weight;      // 1-10000
    char **io_max;           // device limits
    int io_max_count;

    // PIDs
    int64_t pids_limit;      // -1 = unlimited
} oci_resources_t;

// Seccomp configuration
typedef struct {
    uint32_t default_action;  // SCMP_ACT_*
    char **architectures;
    int arch_count;
    struct {
        char **names;
        int name_count;
        uint32_t action;
        // Args filtering (optional)
    } rules[MAX_SECCOMP_RULES];
    int rule_count;
} oci_seccomp_t;

// Namespace configuration
typedef struct {
    bool create_pid;
    bool create_net;
    bool create_mnt;
    bool create_uts;
    bool create_ipc;
    bool create_user;
    bool create_cgroup;
    char *net_path;         // Join existing namespace
    char *pid_path;
} oci_namespaces_t;

// Root filesystem
typedef struct {
    char *path;             // rootfs path
    bool readonly;          // read-only root
} oci_root_t;

// Complete container configuration
typedef struct {
    char *oci_version;      // "1.0.2"
    char *container_id;
    char *bundle_path;

    oci_root_t root;
    oci_process_t process;
    oci_mount_t mounts[MAX_MOUNTS];
    int mount_count;

    char *hostname;

    oci_namespaces_t namespaces;
    oci_capabilities_t capabilities;
    oci_resources_t resources;
    oci_seccomp_t seccomp;

    // User namespace mappings
    struct {
        uint32_t container_id;
        uint32_t host_id;
        uint32_t size;
    } uid_mappings[16], gid_mappings[16];
    int uid_map_count, gid_map_count;
} container_config_t;

// Functions
container_config_t *config_create_default(void);
int config_parse_json(const char *path, container_config_t *config);
int config_parse_args(int argc, char **argv, container_config_t *config);
void config_free(container_config_t *config);
int config_validate(const container_config_t *config);

#endif
```

#### 1.2 Namespace Management

```c
// include/namespace.h
#ifndef NAMESPACE_H
#define NAMESPACE_H

#include "config.h"
#include <sys/types.h>

// Clone flags for namespaces
#define NS_FLAGS_PID    CLONE_NEWPID
#define NS_FLAGS_NET    CLONE_NEWNET
#define NS_FLAGS_MNT    CLONE_NEWNS
#define NS_FLAGS_UTS    CLONE_NEWUTS
#define NS_FLAGS_IPC    CLONE_NEWIPC
#define NS_FLAGS_USER   CLONE_NEWUSER
#define NS_FLAGS_CGROUP CLONE_NEWCGROUP

// Namespace handle
typedef struct {
    int flags;              // Active namespace flags
    pid_t init_pid;         // Container init PID
    int userns_fd;          // User namespace fd (for rootless)
    int netns_fd;           // Network namespace fd
    int pidns_fd;           // PID namespace fd
} namespace_handle_t;

// Create namespaces based on config
int namespace_create(const oci_namespaces_t *config, namespace_handle_t *handle);

// Join existing namespace
int namespace_join(const char *ns_path, int ns_type);

// Setup user namespace mappings
int namespace_setup_user_mapping(
    pid_t pid,
    const container_config_t *config
);

// Enter namespaces (for exec)
int namespace_enter(const namespace_handle_t *handle);

// Save namespace fds
int namespace_save_fds(pid_t pid, namespace_handle_t *handle);

// Cleanup
void namespace_cleanup(namespace_handle_t *handle);

#endif

// src/namespace.c
#define _GNU_SOURCE
#include "namespace.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <errno.h>

int namespace_create(const oci_namespaces_t *config, namespace_handle_t *handle) {
    int flags = 0;

    if (config->create_pid)    flags |= CLONE_NEWPID;
    if (config->create_net)    flags |= CLONE_NEWNET;
    if (config->create_mnt)    flags |= CLONE_NEWNS;
    if (config->create_uts)    flags |= CLONE_NEWUTS;
    if (config->create_ipc)    flags |= CLONE_NEWIPC;
    if (config->create_user)   flags |= CLONE_NEWUSER;
    if (config->create_cgroup) flags |= CLONE_NEWCGROUP;

    handle->flags = flags;

    // For user namespace, need to unshare before other namespaces
    if (config->create_user) {
        if (unshare(CLONE_NEWUSER) < 0) {
            perror("unshare NEWUSER");
            return -1;
        }
    }

    // Unshare remaining namespaces
    int remaining = flags & ~CLONE_NEWUSER;
    if (remaining) {
        if (unshare(remaining) < 0) {
            perror("unshare");
            return -1;
        }
    }

    return 0;
}

int namespace_setup_user_mapping(pid_t pid, const container_config_t *config) {
    char path[256];
    FILE *f;

    // Write uid_map
    snprintf(path, sizeof(path), "/proc/%d/uid_map", pid);
    f = fopen(path, "w");
    if (!f) {
        perror("open uid_map");
        return -1;
    }

    for (int i = 0; i < config->uid_map_count; i++) {
        fprintf(f, "%u %u %u\n",
            config->uid_mappings[i].container_id,
            config->uid_mappings[i].host_id,
            config->uid_mappings[i].size);
    }
    fclose(f);

    // Disable setgroups (required for gid_map in unprivileged)
    snprintf(path, sizeof(path), "/proc/%d/setgroups", pid);
    f = fopen(path, "w");
    if (f) {
        fprintf(f, "deny\n");
        fclose(f);
    }

    // Write gid_map
    snprintf(path, sizeof(path), "/proc/%d/gid_map", pid);
    f = fopen(path, "w");
    if (!f) {
        perror("open gid_map");
        return -1;
    }

    for (int i = 0; i < config->gid_map_count; i++) {
        fprintf(f, "%u %u %u\n",
            config->gid_mappings[i].container_id,
            config->gid_mappings[i].host_id,
            config->gid_mappings[i].size);
    }
    fclose(f);

    return 0;
}

int namespace_join(const char *ns_path, int ns_type) {
    int fd = open(ns_path, O_RDONLY);
    if (fd < 0) {
        perror("open namespace");
        return -1;
    }

    if (setns(fd, ns_type) < 0) {
        perror("setns");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int namespace_save_fds(pid_t pid, namespace_handle_t *handle) {
    char path[256];

    snprintf(path, sizeof(path), "/proc/%d/ns/net", pid);
    handle->netns_fd = open(path, O_RDONLY);

    snprintf(path, sizeof(path), "/proc/%d/ns/pid", pid);
    handle->pidns_fd = open(path, O_RDONLY);

    snprintf(path, sizeof(path), "/proc/%d/ns/user", pid);
    handle->userns_fd = open(path, O_RDONLY);

    return 0;
}

void namespace_cleanup(namespace_handle_t *handle) {
    if (handle->netns_fd >= 0) close(handle->netns_fd);
    if (handle->pidns_fd >= 0) close(handle->pidns_fd);
    if (handle->userns_fd >= 0) close(handle->userns_fd);
}
```

#### 1.3 Cgroup v2 Management

```c
// include/cgroup.h
#ifndef CGROUP_H
#define CGROUP_H

#include "config.h"

#define CGROUP2_ROOT "/sys/fs/cgroup"

typedef struct {
    char *path;             // Full cgroup path
    char *name;             // Container ID
    bool created;           // Did we create it?
} cgroup_handle_t;

// Create cgroup for container
int cgroup_create(const char *container_id, cgroup_handle_t *handle);

// Apply resource limits
int cgroup_apply_limits(const cgroup_handle_t *handle,
                        const oci_resources_t *resources);

// Add process to cgroup
int cgroup_add_process(const cgroup_handle_t *handle, pid_t pid);

// Freeze/unfreeze cgroup
int cgroup_freeze(const cgroup_handle_t *handle, bool freeze);

// Get statistics
int cgroup_get_stats(const cgroup_handle_t *handle,
                     struct cgroup_stats *stats);

// Cleanup
int cgroup_destroy(cgroup_handle_t *handle);

#endif

// src/cgroup.c
#include "cgroup.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

static int write_file(const char *path, const char *content) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;

    ssize_t len = strlen(content);
    ssize_t written = write(fd, content, len);
    close(fd);

    return (written == len) ? 0 : -1;
}

int cgroup_create(const char *container_id, cgroup_handle_t *handle) {
    char path[512];

    // Create cgroup directory: /sys/fs/cgroup/minirun/<container_id>
    snprintf(path, sizeof(path), "%s/minirun", CGROUP2_ROOT);
    mkdir(path, 0755);  // Parent directory

    snprintf(path, sizeof(path), "%s/minirun/%s", CGROUP2_ROOT, container_id);
    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        perror("mkdir cgroup");
        return -1;
    }

    handle->path = strdup(path);
    handle->name = strdup(container_id);
    handle->created = true;

    // Enable controllers in parent
    char parent[512];
    snprintf(parent, sizeof(parent), "%s/minirun/cgroup.subtree_control", CGROUP2_ROOT);
    write_file(parent, "+cpu +memory +io +pids");

    return 0;
}

int cgroup_apply_limits(const cgroup_handle_t *handle,
                        const oci_resources_t *resources) {
    char path[512];
    char value[128];

    // CPU limits
    if (resources->cpu_quota > 0 && resources->cpu_period > 0) {
        snprintf(path, sizeof(path), "%s/cpu.max", handle->path);
        snprintf(value, sizeof(value), "%lu %lu",
                 resources->cpu_quota, resources->cpu_period);
        write_file(path, value);
    }

    if (resources->cpu_shares > 0) {
        snprintf(path, sizeof(path), "%s/cpu.weight", handle->path);
        // Convert shares (2-262144) to weight (1-10000)
        uint64_t weight = (resources->cpu_shares * 100) / 1024;
        if (weight < 1) weight = 1;
        if (weight > 10000) weight = 10000;
        snprintf(value, sizeof(value), "%lu", weight);
        write_file(path, value);
    }

    // Memory limits
    if (resources->memory_limit > 0) {
        snprintf(path, sizeof(path), "%s/memory.max", handle->path);
        snprintf(value, sizeof(value), "%lu", resources->memory_limit);
        write_file(path, value);
    }

    if (resources->memory_swap >= 0) {
        snprintf(path, sizeof(path), "%s/memory.swap.max", handle->path);
        snprintf(value, sizeof(value), "%lu", resources->memory_swap);
        write_file(path, value);
    }

    // PID limit
    if (resources->pids_limit > 0) {
        snprintf(path, sizeof(path), "%s/pids.max", handle->path);
        snprintf(value, sizeof(value), "%ld", resources->pids_limit);
        write_file(path, value);
    } else if (resources->pids_limit == -1) {
        snprintf(path, sizeof(path), "%s/pids.max", handle->path);
        write_file(path, "max");
    }

    // I/O weight
    if (resources->io_weight > 0) {
        snprintf(path, sizeof(path), "%s/io.weight", handle->path);
        snprintf(value, sizeof(value), "default %lu", resources->io_weight);
        write_file(path, value);
    }

    return 0;
}

int cgroup_add_process(const cgroup_handle_t *handle, pid_t pid) {
    char path[512];
    char value[32];

    snprintf(path, sizeof(path), "%s/cgroup.procs", handle->path);
    snprintf(value, sizeof(value), "%d", pid);

    return write_file(path, value);
}

int cgroup_freeze(const cgroup_handle_t *handle, bool freeze) {
    char path[512];
    snprintf(path, sizeof(path), "%s/cgroup.freeze", handle->path);
    return write_file(path, freeze ? "1" : "0");
}

int cgroup_destroy(cgroup_handle_t *handle) {
    if (handle->created && handle->path) {
        // Move processes to parent first
        char procs_path[512];
        snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", handle->path);

        // Read PIDs and move to parent (simplified)
        rmdir(handle->path);
    }

    free(handle->path);
    free(handle->name);
    return 0;
}
```

### Phase 2: Filesystem & Security (12h)

#### 2.1 Filesystem Setup

```c
// include/filesystem.h
#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#include "config.h"

typedef struct {
    char *rootfs;           // Container rootfs path
    char *overlay_lower;    // Lower (read-only) layer
    char *overlay_upper;    // Upper (writable) layer
    char *overlay_work;     // Work directory
    char *overlay_merged;   // Merged view
    bool use_overlay;       // Using OverlayFS?
} filesystem_handle_t;

// Setup container filesystem
int filesystem_setup(const container_config_t *config,
                     filesystem_handle_t *handle);

// Setup mounts
int filesystem_setup_mounts(const container_config_t *config);

// Perform pivot_root
int filesystem_pivot_root(const char *new_root);

// Setup /dev in container
int filesystem_setup_dev(const char *rootfs);

// Setup /proc
int filesystem_setup_proc(const char *rootfs);

// Setup /sys
int filesystem_setup_sys(const char *rootfs);

// Cleanup
int filesystem_cleanup(filesystem_handle_t *handle);

#endif

// src/filesystem.c
#define _GNU_SOURCE
#include "filesystem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>

static int pivot_root(const char *new_root, const char *put_old) {
    return syscall(SYS_pivot_root, new_root, put_old);
}

int filesystem_setup(const container_config_t *config,
                     filesystem_handle_t *handle) {

    // If using overlay, set it up
    if (handle->use_overlay) {
        char options[1024];
        snprintf(options, sizeof(options),
                 "lowerdir=%s,upperdir=%s,workdir=%s",
                 handle->overlay_lower,
                 handle->overlay_upper,
                 handle->overlay_work);

        mkdir(handle->overlay_merged, 0755);

        if (mount("overlay", handle->overlay_merged, "overlay",
                  0, options) < 0) {
            perror("mount overlay");
            return -1;
        }

        handle->rootfs = handle->overlay_merged;
    } else {
        handle->rootfs = strdup(config->root.path);
    }

    return 0;
}

int filesystem_pivot_root(const char *new_root) {
    char put_old[256];
    snprintf(put_old, sizeof(put_old), "%s/.pivot_old", new_root);

    // Create put_old directory
    mkdir(put_old, 0700);

    // Make new_root a mount point
    if (mount(new_root, new_root, NULL, MS_BIND | MS_REC, NULL) < 0) {
        perror("bind mount new_root");
        return -1;
    }

    // Pivot root
    if (pivot_root(new_root, put_old) < 0) {
        perror("pivot_root");
        return -1;
    }

    // Change to new root
    if (chdir("/") < 0) {
        perror("chdir /");
        return -1;
    }

    // Unmount old root
    if (umount2("/.pivot_old", MNT_DETACH) < 0) {
        perror("umount old root");
        // Non-fatal, continue
    }

    rmdir("/.pivot_old");

    return 0;
}

int filesystem_setup_dev(const char *rootfs) {
    char path[256];

    // Create /dev as tmpfs
    snprintf(path, sizeof(path), "%s/dev", rootfs);
    mkdir(path, 0755);

    if (mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_STRICTATIME,
              "mode=755,size=65536k") < 0) {
        perror("mount /dev");
        return -1;
    }

    // Create essential device nodes
    struct {
        const char *name;
        mode_t mode;
        dev_t dev;
    } devices[] = {
        {"null",    S_IFCHR | 0666, makedev(1, 3)},
        {"zero",    S_IFCHR | 0666, makedev(1, 5)},
        {"full",    S_IFCHR | 0666, makedev(1, 7)},
        {"random",  S_IFCHR | 0666, makedev(1, 8)},
        {"urandom", S_IFCHR | 0666, makedev(1, 9)},
        {"tty",     S_IFCHR | 0666, makedev(5, 0)},
    };

    for (size_t i = 0; i < sizeof(devices)/sizeof(devices[0]); i++) {
        snprintf(path, sizeof(path), "%s/dev/%s", rootfs, devices[i].name);
        if (mknod(path, devices[i].mode, devices[i].dev) < 0 && errno != EEXIST) {
            fprintf(stderr, "mknod %s: %s\n", devices[i].name, strerror(errno));
        }
    }

    // Create symlinks
    snprintf(path, sizeof(path), "%s/dev/fd", rootfs);
    symlink("/proc/self/fd", path);

    snprintf(path, sizeof(path), "%s/dev/stdin", rootfs);
    symlink("/proc/self/fd/0", path);

    snprintf(path, sizeof(path), "%s/dev/stdout", rootfs);
    symlink("/proc/self/fd/1", path);

    snprintf(path, sizeof(path), "%s/dev/stderr", rootfs);
    symlink("/proc/self/fd/2", path);

    // Create /dev/pts
    snprintf(path, sizeof(path), "%s/dev/pts", rootfs);
    mkdir(path, 0755);
    mount("devpts", path, "devpts", MS_NOSUID | MS_NOEXEC,
          "newinstance,ptmxmode=0666,mode=620");

    // Create /dev/shm
    snprintf(path, sizeof(path), "%s/dev/shm", rootfs);
    mkdir(path, 01777);
    mount("tmpfs", path, "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
          "mode=1777,size=65536k");

    return 0;
}

int filesystem_setup_proc(const char *rootfs) {
    char path[256];
    snprintf(path, sizeof(path), "%s/proc", rootfs);
    mkdir(path, 0555);

    if (mount("proc", path, "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) < 0) {
        perror("mount /proc");
        return -1;
    }

    return 0;
}

int filesystem_setup_sys(const char *rootfs) {
    char path[256];
    snprintf(path, sizeof(path), "%s/sys", rootfs);
    mkdir(path, 0555);

    // Mount sysfs read-only for containers
    if (mount("sysfs", path, "sysfs",
              MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_RDONLY, NULL) < 0) {
        perror("mount /sys");
        return -1;
    }

    return 0;
}

int filesystem_setup_mounts(const container_config_t *config) {
    for (int i = 0; i < config->mount_count; i++) {
        const oci_mount_t *m = &config->mounts[i];
        unsigned long flags = 0;
        char *data = NULL;

        // Parse options
        for (int j = 0; j < m->option_count; j++) {
            if (strcmp(m->options[j], "ro") == 0) flags |= MS_RDONLY;
            else if (strcmp(m->options[j], "nosuid") == 0) flags |= MS_NOSUID;
            else if (strcmp(m->options[j], "nodev") == 0) flags |= MS_NODEV;
            else if (strcmp(m->options[j], "noexec") == 0) flags |= MS_NOEXEC;
            else if (strcmp(m->options[j], "bind") == 0) flags |= MS_BIND;
            else if (strcmp(m->options[j], "rbind") == 0) flags |= MS_BIND | MS_REC;
        }

        // Create mount point
        mkdir(m->destination, 0755);

        // Perform mount
        if (mount(m->source, m->destination, m->type, flags, data) < 0) {
            fprintf(stderr, "mount %s -> %s: %s\n",
                    m->source, m->destination, strerror(errno));
            return -1;
        }
    }

    return 0;
}
```

#### 2.2 Security (Seccomp & Capabilities)

```c
// include/security.h
#ifndef SECURITY_H
#define SECURITY_H

#include "config.h"
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/capability.h>

// Apply all security settings
int security_apply(const container_config_t *config);

// Setup seccomp filter
int security_setup_seccomp(const oci_seccomp_t *seccomp);

// Setup capabilities
int security_setup_capabilities(const oci_capabilities_t *caps);

// Set no-new-privileges
int security_set_no_new_privs(void);

// Drop all capabilities except specified
int security_drop_capabilities(const char **keep, int keep_count);

// Generate default seccomp profile
int security_default_seccomp(void);

#endif

// src/security.c
#define _GNU_SOURCE
#include "security.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <errno.h>

// Capability name to number mapping
static const struct {
    const char *name;
    int cap;
} cap_names[] = {
    {"CAP_CHOWN", 0},
    {"CAP_DAC_OVERRIDE", 1},
    {"CAP_DAC_READ_SEARCH", 2},
    {"CAP_FOWNER", 3},
    {"CAP_FSETID", 4},
    {"CAP_KILL", 5},
    {"CAP_SETGID", 6},
    {"CAP_SETUID", 7},
    {"CAP_SETPCAP", 8},
    {"CAP_LINUX_IMMUTABLE", 9},
    {"CAP_NET_BIND_SERVICE", 10},
    {"CAP_NET_BROADCAST", 11},
    {"CAP_NET_ADMIN", 12},
    {"CAP_NET_RAW", 13},
    {"CAP_IPC_LOCK", 14},
    {"CAP_IPC_OWNER", 15},
    {"CAP_SYS_MODULE", 16},
    {"CAP_SYS_RAWIO", 17},
    {"CAP_SYS_CHROOT", 18},
    {"CAP_SYS_PTRACE", 19},
    {"CAP_SYS_PACCT", 20},
    {"CAP_SYS_ADMIN", 21},
    {"CAP_SYS_BOOT", 22},
    {"CAP_SYS_NICE", 23},
    {"CAP_SYS_RESOURCE", 24},
    {"CAP_SYS_TIME", 25},
    {"CAP_SYS_TTY_CONFIG", 26},
    {"CAP_MKNOD", 27},
    {"CAP_LEASE", 28},
    {"CAP_AUDIT_WRITE", 29},
    {"CAP_AUDIT_CONTROL", 30},
    {"CAP_SETFCAP", 31},
    {"CAP_MAC_OVERRIDE", 32},
    {"CAP_MAC_ADMIN", 33},
    {"CAP_SYSLOG", 34},
    {"CAP_WAKE_ALARM", 35},
    {"CAP_BLOCK_SUSPEND", 36},
    {"CAP_AUDIT_READ", 37},
    {"CAP_PERFMON", 38},
    {"CAP_BPF", 39},
    {"CAP_CHECKPOINT_RESTORE", 40},
};

static int cap_from_name(const char *name) {
    for (size_t i = 0; i < sizeof(cap_names)/sizeof(cap_names[0]); i++) {
        if (strcasecmp(cap_names[i].name, name) == 0) {
            return cap_names[i].cap;
        }
    }
    return -1;
}

int security_set_no_new_privs(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl NO_NEW_PRIVS");
        return -1;
    }
    return 0;
}

int security_setup_capabilities(const oci_capabilities_t *caps) {
    // Get current capabilities
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[2] = {0};

    // Start with empty set
    uint64_t effective = 0;
    uint64_t permitted = 0;
    uint64_t inheritable = 0;
    uint64_t bounding = 0;

    // Build capability sets from config
    for (int i = 0; i < caps->effective_count; i++) {
        int cap = cap_from_name(caps->effective[i]);
        if (cap >= 0) effective |= (1ULL << cap);
    }

    for (int i = 0; i < caps->permitted_count; i++) {
        int cap = cap_from_name(caps->permitted[i]);
        if (cap >= 0) permitted |= (1ULL << cap);
    }

    for (int i = 0; i < caps->inheritable_count; i++) {
        int cap = cap_from_name(caps->inheritable[i]);
        if (cap >= 0) inheritable |= (1ULL << cap);
    }

    for (int i = 0; i < caps->bounding_count; i++) {
        int cap = cap_from_name(caps->bounding[i]);
        if (cap >= 0) bounding |= (1ULL << cap);
    }

    // Drop capabilities not in bounding set
    for (int cap = 0; cap <= 40; cap++) {
        if (!(bounding & (1ULL << cap))) {
            if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) < 0 && errno != EINVAL) {
                fprintf(stderr, "drop cap %d: %s\n", cap, strerror(errno));
            }
        }
    }

    // Set ambient capabilities
    for (int i = 0; i < caps->ambient_count; i++) {
        int cap = cap_from_name(caps->ambient[i]);
        if (cap >= 0) {
            if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0) < 0) {
                fprintf(stderr, "ambient cap %d: %s\n", cap, strerror(errno));
            }
        }
    }

    // Set capability sets
    data[0].effective = effective & 0xFFFFFFFF;
    data[1].effective = (effective >> 32) & 0xFFFFFFFF;
    data[0].permitted = permitted & 0xFFFFFFFF;
    data[1].permitted = (permitted >> 32) & 0xFFFFFFFF;
    data[0].inheritable = inheritable & 0xFFFFFFFF;
    data[1].inheritable = (inheritable >> 32) & 0xFFFFFFFF;

    if (syscall(SYS_capset, &header, data) < 0) {
        perror("capset");
        return -1;
    }

    return 0;
}

// Default seccomp filter (blocks dangerous syscalls)
int security_default_seccomp(void) {
    struct sock_filter filter[] = {
        // Load architecture
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, arch)),

        // Check architecture (x86_64)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        // Load syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 offsetof(struct seccomp_data, nr)),

        // Block dangerous syscalls
        // reboot
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_reboot, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        // kexec_load
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_kexec_load, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        // init_module
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_init_module, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        // delete_module
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_delete_module, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        // acct
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_acct, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        // Allow everything else
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        perror("seccomp");
        return -1;
    }

    return 0;
}

int security_apply(const container_config_t *config) {
    // Set no-new-privileges if requested
    if (config->process.no_new_privileges) {
        if (security_set_no_new_privs() < 0) {
            return -1;
        }
    }

    // Apply capabilities
    if (config->capabilities.bounding_count > 0) {
        if (security_setup_capabilities(&config->capabilities) < 0) {
            return -1;
        }
    }

    // Apply seccomp if configured
    if (config->seccomp.rule_count > 0) {
        if (security_setup_seccomp(&config->seccomp) < 0) {
            return -1;
        }
    } else {
        // Apply default seccomp
        security_default_seccomp();
    }

    return 0;
}
```

### Phase 3: Networking & Runtime (13h)

#### 3.1 Network Setup

```c
// include/network.h
#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <net/if.h>

typedef struct {
    char bridge_name[IFNAMSIZ];
    char veth_host[IFNAMSIZ];
    char veth_container[IFNAMSIZ];
    char container_ip[32];
    char gateway_ip[32];
    int prefix_len;
    bool created;
} network_handle_t;

// Create bridge if not exists
int network_create_bridge(const char *name);

// Create veth pair
int network_create_veth(const char *veth1, const char *veth2);

// Move interface to namespace
int network_move_to_ns(const char *ifname, pid_t pid);

// Configure interface IP
int network_configure_ip(const char *ifname, const char *ip, int prefix);

// Set interface up
int network_set_up(const char *ifname);

// Add interface to bridge
int network_add_to_bridge(const char *bridge, const char *ifname);

// Setup NAT (iptables)
int network_setup_nat(const char *bridge_ip, int prefix);

// Setup port forwarding
int network_port_forward(const char *container_ip,
                         uint16_t host_port,
                         uint16_t container_port);

// Full network setup for container
int network_setup_container(pid_t pid, network_handle_t *handle);

// Cleanup
int network_cleanup(network_handle_t *handle);

#endif

// src/network.c (simplified using system commands)
#include "network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

static int run_cmd(const char *fmt, ...) {
    char cmd[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, args);
    va_end(args);

    int ret = system(cmd);
    return WEXITSTATUS(ret);
}

int network_create_bridge(const char *name) {
    // Check if exists
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s", name);
    if (access(path, F_OK) == 0) {
        return 0;  // Already exists
    }

    if (run_cmd("ip link add %s type bridge", name) != 0) {
        return -1;
    }

    if (run_cmd("ip link set %s up", name) != 0) {
        return -1;
    }

    return 0;
}

int network_create_veth(const char *veth1, const char *veth2) {
    return run_cmd("ip link add %s type veth peer name %s", veth1, veth2);
}

int network_move_to_ns(const char *ifname, pid_t pid) {
    return run_cmd("ip link set %s netns %d", ifname, pid);
}

int network_configure_ip(const char *ifname, const char *ip, int prefix) {
    return run_cmd("ip addr add %s/%d dev %s", ip, prefix, ifname);
}

int network_set_up(const char *ifname) {
    return run_cmd("ip link set %s up", ifname);
}

int network_add_to_bridge(const char *bridge, const char *ifname) {
    return run_cmd("ip link set %s master %s", ifname, bridge);
}

int network_setup_nat(const char *bridge_ip, int prefix) {
    // Enable IP forwarding
    run_cmd("echo 1 > /proc/sys/net/ipv4/ip_forward");

    // Add NAT rule
    return run_cmd("iptables -t nat -A POSTROUTING -s %s/%d ! -o minirun0 -j MASQUERADE",
                   bridge_ip, prefix);
}

int network_setup_container(pid_t pid, network_handle_t *handle) {
    // Default values
    strcpy(handle->bridge_name, "minirun0");
    snprintf(handle->veth_host, sizeof(handle->veth_host), "veth%d", pid);
    snprintf(handle->veth_container, sizeof(handle->veth_container), "eth0");

    // Simple IP allocation (in production, use IPAM)
    snprintf(handle->container_ip, sizeof(handle->container_ip),
             "10.0.0.%d", (pid % 254) + 1);
    strcpy(handle->gateway_ip, "10.0.0.1");
    handle->prefix_len = 24;

    // Create bridge with gateway IP
    if (network_create_bridge(handle->bridge_name) < 0) {
        return -1;
    }
    network_configure_ip(handle->bridge_name, handle->gateway_ip, handle->prefix_len);

    // Create veth pair
    if (network_create_veth(handle->veth_host, handle->veth_container) < 0) {
        return -1;
    }

    // Add host end to bridge
    network_add_to_bridge(handle->bridge_name, handle->veth_host);
    network_set_up(handle->veth_host);

    // Move container end to namespace
    network_move_to_ns(handle->veth_container, pid);

    // Setup NAT
    network_setup_nat(handle->gateway_ip, handle->prefix_len);

    handle->created = true;
    return 0;
}

// Called from inside container namespace
int network_configure_container(network_handle_t *handle) {
    // Configure loopback
    network_set_up("lo");

    // Configure eth0
    network_configure_ip("eth0", handle->container_ip, handle->prefix_len);
    network_set_up("eth0");

    // Add default route
    run_cmd("ip route add default via %s", handle->gateway_ip);

    return 0;
}

int network_cleanup(network_handle_t *handle) {
    if (handle->created) {
        run_cmd("ip link del %s", handle->veth_host);
    }
    return 0;
}
```

#### 3.2 Container Runtime

```c
// include/minirun.h
#ifndef MINIRUN_H
#define MINIRUN_H

#include "config.h"
#include "namespace.h"
#include "cgroup.h"
#include "filesystem.h"
#include "security.h"
#include "network.h"

typedef enum {
    CONTAINER_CREATED,
    CONTAINER_RUNNING,
    CONTAINER_PAUSED,
    CONTAINER_STOPPED,
} container_state_t;

typedef struct {
    char id[64];
    container_config_t *config;
    container_state_t state;
    pid_t init_pid;

    namespace_handle_t ns;
    cgroup_handle_t cgroup;
    filesystem_handle_t fs;
    network_handle_t net;

    int status;             // Exit status
    char *bundle_path;
} container_t;

// Container lifecycle
container_t *container_create(const char *id, const char *bundle);
int container_start(container_t *container);
int container_exec(container_t *container, char **argv);
int container_kill(container_t *container, int signal);
int container_pause(container_t *container);
int container_resume(container_t *container);
int container_delete(container_t *container);

// Query
container_state_t container_state(container_t *container);
int container_wait(container_t *container);

// List containers
int container_list(container_t ***containers, int *count);

#endif

// src/runtime.c
#define _GNU_SOURCE
#include "minirun.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>

// Pipe for parent-child synchronization
static int sync_pipe[2];

// Child process (container init)
static int container_child(void *arg) {
    container_t *container = (container_t *)arg;
    container_config_t *config = container->config;
    char buf;

    // Wait for parent to setup cgroup and user namespace mappings
    close(sync_pipe[1]);
    if (read(sync_pipe[0], &buf, 1) != 1) {
        fprintf(stderr, "sync read failed\n");
        return 1;
    }
    close(sync_pipe[0]);

    // Setup network inside container (if network namespace)
    if (config->namespaces.create_net) {
        network_configure_container(&container->net);
    }

    // Setup hostname
    if (config->hostname && config->namespaces.create_uts) {
        sethostname(config->hostname, strlen(config->hostname));
    }

    // Setup filesystem
    filesystem_setup_dev(container->fs.rootfs);
    filesystem_setup_proc(container->fs.rootfs);
    filesystem_setup_sys(container->fs.rootfs);
    filesystem_setup_mounts(config);

    // Pivot root
    if (filesystem_pivot_root(container->fs.rootfs) < 0) {
        return 1;
    }

    // Make root read-only if configured
    if (config->root.readonly) {
        mount(NULL, "/", NULL, MS_REMOUNT | MS_RDONLY | MS_BIND, NULL);
    }

    // Apply security settings
    if (security_apply(config) < 0) {
        return 1;
    }

    // Change to working directory
    if (config->process.cwd) {
        chdir(config->process.cwd);
    }

    // Set UID/GID
    if (setgid(config->process.gid) < 0) {
        perror("setgid");
    }
    if (setuid(config->process.uid) < 0) {
        perror("setuid");
    }

    // Execute the process
    execve(config->process.args[0], config->process.args, config->process.env);
    perror("execve");
    return 1;
}

container_t *container_create(const char *id, const char *bundle) {
    container_t *container = calloc(1, sizeof(container_t));
    if (!container) return NULL;

    strncpy(container->id, id, sizeof(container->id) - 1);
    container->bundle_path = strdup(bundle);
    container->state = CONTAINER_CREATED;

    // Load configuration
    container->config = config_create_default();
    char config_path[512];
    snprintf(config_path, sizeof(config_path), "%s/config.json", bundle);

    if (config_parse_json(config_path, container->config) < 0) {
        fprintf(stderr, "Failed to parse config\n");
        // Use defaults or fail
    }

    // Create cgroup
    if (cgroup_create(id, &container->cgroup) < 0) {
        fprintf(stderr, "Failed to create cgroup\n");
    }

    // Apply resource limits
    cgroup_apply_limits(&container->cgroup, &container->config->resources);

    return container;
}

int container_start(container_t *container) {
    if (container->state != CONTAINER_CREATED) {
        fprintf(stderr, "Container not in created state\n");
        return -1;
    }

    container_config_t *config = container->config;

    // Setup sync pipe
    if (pipe(sync_pipe) < 0) {
        perror("pipe");
        return -1;
    }

    // Setup filesystem (overlay if needed)
    if (filesystem_setup(config, &container->fs) < 0) {
        return -1;
    }

    // Calculate clone flags
    int flags = SIGCHLD;
    if (config->namespaces.create_pid)    flags |= CLONE_NEWPID;
    if (config->namespaces.create_net)    flags |= CLONE_NEWNET;
    if (config->namespaces.create_mnt)    flags |= CLONE_NEWNS;
    if (config->namespaces.create_uts)    flags |= CLONE_NEWUTS;
    if (config->namespaces.create_ipc)    flags |= CLONE_NEWIPC;
    if (config->namespaces.create_user)   flags |= CLONE_NEWUSER;
    if (config->namespaces.create_cgroup) flags |= CLONE_NEWCGROUP;

    // Allocate stack for clone
    const int stack_size = 1024 * 1024;
    char *stack = malloc(stack_size);
    if (!stack) {
        perror("malloc stack");
        return -1;
    }

    // Clone with namespaces
    pid_t pid = clone(container_child, stack + stack_size, flags, container);
    if (pid < 0) {
        perror("clone");
        free(stack);
        return -1;
    }

    container->init_pid = pid;
    container->ns.init_pid = pid;

    // Setup user namespace mappings (must be done from parent)
    if (config->namespaces.create_user) {
        namespace_setup_user_mapping(pid, config);
    }

    // Add to cgroup
    cgroup_add_process(&container->cgroup, pid);

    // Setup network (create veth, move to namespace)
    if (config->namespaces.create_net) {
        network_setup_container(pid, &container->net);
    }

    // Save namespace fds for later exec
    namespace_save_fds(pid, &container->ns);

    // Signal child to continue
    close(sync_pipe[0]);
    write(sync_pipe[1], "x", 1);
    close(sync_pipe[1]);

    container->state = CONTAINER_RUNNING;

    // Don't free stack - child is using it
    // In production, use proper memory management

    return 0;
}

int container_wait(container_t *container) {
    if (container->state != CONTAINER_RUNNING) {
        return container->status;
    }

    int status;
    waitpid(container->init_pid, &status, 0);

    if (WIFEXITED(status)) {
        container->status = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        container->status = 128 + WTERMSIG(status);
    }

    container->state = CONTAINER_STOPPED;
    return container->status;
}

int container_kill(container_t *container, int signal) {
    if (container->state != CONTAINER_RUNNING) {
        return -1;
    }

    return kill(container->init_pid, signal);
}

int container_pause(container_t *container) {
    if (container->state != CONTAINER_RUNNING) {
        return -1;
    }

    if (cgroup_freeze(&container->cgroup, true) < 0) {
        return -1;
    }

    container->state = CONTAINER_PAUSED;
    return 0;
}

int container_resume(container_t *container) {
    if (container->state != CONTAINER_PAUSED) {
        return -1;
    }

    if (cgroup_freeze(&container->cgroup, false) < 0) {
        return -1;
    }

    container->state = CONTAINER_RUNNING;
    return 0;
}

int container_delete(container_t *container) {
    if (container->state == CONTAINER_RUNNING) {
        container_kill(container, SIGKILL);
        container_wait(container);
    }

    // Cleanup resources
    namespace_cleanup(&container->ns);
    cgroup_destroy(&container->cgroup);
    filesystem_cleanup(&container->fs);
    network_cleanup(&container->net);

    config_free(container->config);
    free(container->bundle_path);
    free(container);

    return 0;
}

// src/main.c
#include "minirun.h"
#include <stdio.h>
#include <string.h>
#include <getopt.h>

static void usage(const char *prog) {
    printf("Usage: %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  create <container-id> <bundle>  Create a container\n");
    printf("  start <container-id>            Start a container\n");
    printf("  run <container-id> <bundle>     Create and start\n");
    printf("  exec <container-id> <cmd...>    Execute in container\n");
    printf("  kill <container-id> [signal]    Send signal\n");
    printf("  delete <container-id>           Delete container\n");
    printf("  state <container-id>            Query state\n");
    printf("  list                            List containers\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "create") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s create <id> <bundle>\n", argv[0]);
            return 1;
        }
        container_t *c = container_create(argv[2], argv[3]);
        if (!c) {
            fprintf(stderr, "Failed to create container\n");
            return 1;
        }
        printf("Container %s created\n", argv[2]);
        return 0;
    }

    if (strcmp(cmd, "run") == 0) {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s run <id> <bundle>\n", argv[0]);
            return 1;
        }
        container_t *c = container_create(argv[2], argv[3]);
        if (!c) return 1;

        if (container_start(c) < 0) {
            container_delete(c);
            return 1;
        }

        int status = container_wait(c);
        container_delete(c);
        return status;
    }

    if (strcmp(cmd, "kill") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s kill <id> [signal]\n", argv[0]);
            return 1;
        }
        int sig = (argc > 3) ? atoi(argv[3]) : SIGTERM;
        // Load container state and send signal
        // (requires state persistence - simplified here)
        return 0;
    }

    usage(argv[0]);
    return 1;
}
```

---

## Criteres de Validation

### Tests Fonctionnels

```bash
# Test 1: Basic container
./minirun run test1 ./rootfs-bundle
# Should run and exit

# Test 2: Namespace isolation
./minirun run test2 ./rootfs-bundle
# Inside: hostname, ps, ip addr should show isolated view

# Test 3: Cgroup limits
./minirun run --memory=64M test3 ./stress-bundle
# Should be killed when exceeding memory

# Test 4: Network connectivity
./minirun run test4 ./rootfs-bundle
# Inside: ping 8.8.8.8 should work

# Test 5: Security
./minirun run test5 ./rootfs-bundle
# Inside: reboot should fail (EPERM)
# Inside: mount should fail
```

### Checklist

- [ ] All 7 namespaces working (PID, NET, MNT, UTS, IPC, USER, CGROUP)
- [ ] Cgroup v2 resource limits (CPU, memory, PIDs)
- [ ] OverlayFS for copy-on-write
- [ ] pivot_root isolation
- [ ] Seccomp filtering active
- [ ] Capabilities dropped appropriately
- [ ] Network namespace with veth/bridge
- [ ] OCI config.json parsing
- [ ] Container lifecycle (create, start, kill, delete)
- [ ] Proper cleanup on exit/error

---

## Bonus

- [ ] OCI runtime compliance tests (runtime-tools)
- [ ] State persistence (JSON file per container)
- [ ] exec command (nsenter equivalent)
- [ ] Rootless mode (user namespace first)
- [ ] Terminal/PTY support
- [ ] Checkpoint/restore (CRIU integration)
- [ ] Plugin system for hooks
- [ ] Logging (JSON format)

---

## References

- OCI Runtime Specification: https://github.com/opencontainers/runtime-spec
- runc source code: https://github.com/opencontainers/runc
- Linux namespaces(7)
- cgroups(7)
- capabilities(7)
- seccomp(2)

