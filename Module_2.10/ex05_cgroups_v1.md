# ex05: Cgroups v1

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 3h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.13: Cgroups v1 (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Cgroups | Control Groups |
| b | Purpose | Resource limiting |
| c | v1 hierarchy | Multiple hierarchies |
| d | Controllers | cpu, memory, blkio, etc. |
| e | /sys/fs/cgroup | Cgroup filesystem |
| f | Creating cgroup | mkdir |
| g | Adding process | Write to cgroup.procs |
| h | Setting limits | Write to controller files |

---

## Sujet

Comprendre et utiliser les Control Groups version 1 pour limiter les ressources.

---

## Exemple

```c
#define _GNU_SOURCE
#include "cgroups_v1.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

// Path to cgroup v1 filesystem
#define CGROUP_V1_PATH "/sys/fs/cgroup"

// Write a value to a cgroup file
int cgroup_write(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        perror(path);
        return -1;
    }

    ssize_t len = strlen(value);
    if (write(fd, value, len) != len) {
        perror("write");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

// Read a value from a cgroup file
int cgroup_read(const char *path, char *buffer, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror(path);
        return -1;
    }

    ssize_t len = read(fd, buffer, size - 1);
    if (len < 0) {
        perror("read");
        close(fd);
        return -1;
    }

    buffer[len] = '\0';
    close(fd);
    return 0;
}

// Create a cgroup
int cgroup_create(const char *controller, const char *name) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s/%s", CGROUP_V1_PATH, controller, name);

    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        perror(path);
        return -1;
    }

    printf("Created cgroup: %s\n", path);
    return 0;
}

// Add current process to cgroup
int cgroup_add_self(const char *controller, const char *name) {
    char path[512];
    char pid[32];

    snprintf(path, sizeof(path), "%s/%s/%s/cgroup.procs",
             CGROUP_V1_PATH, controller, name);
    snprintf(pid, sizeof(pid), "%d", getpid());

    return cgroup_write(path, pid);
}

// Remove cgroup (must be empty)
int cgroup_remove(const char *controller, const char *name) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s/%s", CGROUP_V1_PATH, controller, name);

    if (rmdir(path) < 0) {
        perror(path);
        return -1;
    }
    return 0;
}

// Check available controllers
void list_controllers(void) {
    printf("\nAvailable cgroup v1 controllers:\n");

    const char *controllers[] = {
        "cpu", "cpuacct", "cpuset",
        "memory", "blkio", "devices",
        "freezer", "net_cls", "net_prio",
        "pids", "perf_event", "hugetlb"
    };

    for (size_t i = 0; i < sizeof(controllers)/sizeof(controllers[0]); i++) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", CGROUP_V1_PATH, controllers[i]);

        if (access(path, F_OK) == 0) {
            printf("  [*] %s\n", controllers[i]);
        } else {
            printf("  [ ] %s (not mounted)\n", controllers[i]);
        }
    }
}

// Demo: Memory cgroup
void demo_memory_cgroup(void) {
    printf("\n=== Memory Cgroup Demo ===\n\n");

    const char *name = "demo_memory";

    // Create memory cgroup
    if (cgroup_create("memory", name) < 0) {
        printf("Cannot create memory cgroup (needs root)\n");
        return;
    }

    char path[512];
    char value[64];

    // Set memory limit (10 MB)
    snprintf(path, sizeof(path), "%s/memory/%s/memory.limit_in_bytes",
             CGROUP_V1_PATH, name);
    cgroup_write(path, "10485760");  // 10 MB

    // Read back limit
    cgroup_read(path, value, sizeof(value));
    printf("Memory limit: %s", value);

    // Show other memory controls
    printf("\nMemory cgroup files:\n");
    printf("  memory.limit_in_bytes      : Hard limit\n");
    printf("  memory.soft_limit_in_bytes : Soft limit\n");
    printf("  memory.usage_in_bytes      : Current usage\n");
    printf("  memory.max_usage_in_bytes  : Peak usage\n");
    printf("  memory.failcnt             : Limit exceed count\n");
    printf("  memory.oom_control         : OOM behavior\n");
    printf("  memory.memsw.limit_in_bytes: Memory + swap limit\n");

    // Read current usage
    snprintf(path, sizeof(path), "%s/memory/%s/memory.usage_in_bytes",
             CGROUP_V1_PATH, name);
    if (cgroup_read(path, value, sizeof(value)) == 0) {
        printf("\nCurrent usage: %s", value);
    }

    // Cleanup
    cgroup_remove("memory", name);
}

// Demo: CPU cgroup
void demo_cpu_cgroup(void) {
    printf("\n=== CPU Cgroup Demo ===\n\n");

    const char *name = "demo_cpu";

    if (cgroup_create("cpu", name) < 0) {
        printf("Cannot create CPU cgroup\n");
        return;
    }

    char path[512];

    printf("CPU cgroup files:\n");
    printf("  cpu.shares           : Relative CPU weight (default 1024)\n");
    printf("  cpu.cfs_period_us    : CFS period in microseconds\n");
    printf("  cpu.cfs_quota_us     : CFS quota in microseconds\n");
    printf("  cpu.stat             : CPU statistics\n");

    // Set CPU quota (50% of one CPU)
    // quota/period = fraction of CPU
    // 50000/100000 = 50%
    snprintf(path, sizeof(path), "%s/cpu/%s/cpu.cfs_period_us",
             CGROUP_V1_PATH, name);
    cgroup_write(path, "100000");

    snprintf(path, sizeof(path), "%s/cpu/%s/cpu.cfs_quota_us",
             CGROUP_V1_PATH, name);
    cgroup_write(path, "50000");

    printf("\nSet CPU limit: 50%% of one CPU\n");
    printf("  Period: 100000 us (100 ms)\n");
    printf("  Quota:  50000 us (50 ms per period)\n");

    // Cleanup
    cgroup_remove("cpu", name);
}

// Demo: PIDs cgroup
void demo_pids_cgroup(void) {
    printf("\n=== PIDs Cgroup Demo ===\n\n");

    const char *name = "demo_pids";

    if (cgroup_create("pids", name) < 0) {
        printf("Cannot create pids cgroup\n");
        return;
    }

    char path[512];

    printf("PIDs cgroup files:\n");
    printf("  pids.max     : Maximum number of processes\n");
    printf("  pids.current : Current number of processes\n");

    // Limit to 10 processes
    snprintf(path, sizeof(path), "%s/pids/%s/pids.max",
             CGROUP_V1_PATH, name);
    cgroup_write(path, "10");

    printf("\nSet process limit: 10\n");

    // Cleanup
    cgroup_remove("pids", name);
}

int main(void) {
    printf("=== Cgroups v1 ===\n\n");

    // What are cgroups
    printf("What are Control Groups (cgroups)?\n");
    printf("  - Kernel feature for resource management\n");
    printf("  - Limit, account, and isolate resources\n");
    printf("  - Foundation for containers\n");
    printf("  - Organized as hierarchical groups\n");

    printf("\nCgroup v1 vs v2:\n");
    printf("  v1: Multiple hierarchies, per-controller\n");
    printf("  v2: Single unified hierarchy, all controllers together\n");
    printf("  (Many systems use v1, or hybrid mode)\n");

    // List controllers
    list_controllers();

    // Cgroup operations
    printf("\n\n=== Basic Cgroup Operations ===\n\n");

    printf("Creating a cgroup:\n");
    printf("  mkdir /sys/fs/cgroup/memory/my_group\n");

    printf("\nAdding a process:\n");
    printf("  echo $PID > /sys/fs/cgroup/memory/my_group/cgroup.procs\n");

    printf("\nSetting a limit:\n");
    printf("  echo 100M > /sys/fs/cgroup/memory/my_group/memory.limit_in_bytes\n");

    printf("\nRemoving a cgroup:\n");
    printf("  rmdir /sys/fs/cgroup/memory/my_group\n");
    printf("  (must be empty - no processes)\n");

    printf("\nReading current cgroups for a process:\n");
    printf("  cat /proc/$PID/cgroup\n");

    // Show current process cgroups
    printf("\n\nCurrent process cgroups:\n");
    FILE *f = fopen("/proc/self/cgroup", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            printf("  %s", line);
        }
        fclose(f);
    }

    // Run demos if root
    if (geteuid() == 0) {
        demo_memory_cgroup();
        demo_cpu_cgroup();
        demo_pids_cgroup();
    } else {
        printf("\n\nNote: Run as root to execute cgroup demos\n");
        printf("Example commands:\n");
        printf("  sudo mkdir /sys/fs/cgroup/memory/test\n");
        printf("  echo $$ | sudo tee /sys/fs/cgroup/memory/test/cgroup.procs\n");
        printf("  echo 50M | sudo tee /sys/fs/cgroup/memory/test/memory.limit_in_bytes\n");
    }

    return 0;
}
```

---

## Fichiers

```
ex05/
├── cgroups_v1.h
├── cgroup_basics.c
├── memory_cgroup.c
├── cpu_cgroup.c
├── pids_cgroup.c
└── Makefile
```
