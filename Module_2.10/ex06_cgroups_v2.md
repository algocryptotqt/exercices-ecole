# ex06: Cgroups v2

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 3h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.14: Cgroups v2 (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Unified hierarchy | Single tree |
| b | Controllers | Attached to subtree |
| c | cgroup.controllers | Available controllers |
| d | cgroup.subtree_control | Enable for children |
| e | Delegation | Unprivileged control |
| f | Pressure Stall Information | PSI |
| g | Migration | v1 to v2 |

---

## Sujet

Maitriser les Control Groups version 2 avec la hierarchie unifiee.

---

## Exemple

```c
#define _GNU_SOURCE
#include "cgroups_v2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>

// Cgroup v2 unified hierarchy path
#define CGROUP_V2_PATH "/sys/fs/cgroup"

// Write value to cgroup file
int cg2_write(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        perror(path);
        return -1;
    }

    if (write(fd, value, strlen(value)) < 0) {
        perror("write");
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

// Read value from cgroup file
int cg2_read(const char *path, char *buf, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    ssize_t n = read(fd, buf, size - 1);
    close(fd);

    if (n < 0) return -1;
    buf[n] = '\0';
    return 0;
}

// Check if cgroup v2 is mounted
int check_cgroup_v2(void) {
    char type[64];
    FILE *f = fopen("/proc/filesystems", "r");
    if (!f) return 0;

    int found = 0;
    while (fscanf(f, "%*s %63s", type) == 1) {
        if (strcmp(type, "cgroup2") == 0) {
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

// Show available controllers
void show_controllers(const char *cgroup_path) {
    char path[512];
    char controllers[256];

    snprintf(path, sizeof(path), "%s/cgroup.controllers", cgroup_path);
    if (cg2_read(path, controllers, sizeof(controllers)) == 0) {
        printf("Available controllers: %s", controllers);
    }

    snprintf(path, sizeof(path), "%s/cgroup.subtree_control", cgroup_path);
    if (cg2_read(path, controllers, sizeof(controllers)) == 0) {
        printf("Enabled for subtree: %s", controllers);
    }
}

// Create cgroup v2
int cg2_create(const char *name) {
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", CGROUP_V2_PATH, name);

    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        perror(path);
        return -1;
    }
    return 0;
}

// Enable controller for subtree
int cg2_enable_controller(const char *cgroup, const char *controller) {
    char path[512];
    char value[64];

    snprintf(path, sizeof(path), "%s/%s/cgroup.subtree_control",
             CGROUP_V2_PATH, cgroup[0] ? cgroup : ".");
    snprintf(value, sizeof(value), "+%s", controller);

    return cg2_write(path, value);
}

// Demo: Memory controller in cgroup v2
void demo_memory_v2(void) {
    printf("\n=== Memory Controller (v2) ===\n\n");

    const char *name = "demo_v2";

    // Enable memory controller at root
    cg2_enable_controller("", "memory");

    if (cg2_create(name) < 0) {
        printf("Cannot create cgroup\n");
        return;
    }

    char path[512];
    char value[128];

    // Memory files in v2
    printf("Memory controller files:\n");
    printf("  memory.max      : Hard limit (bytes or 'max')\n");
    printf("  memory.high     : Soft limit (throttling)\n");
    printf("  memory.low      : Best-effort protection\n");
    printf("  memory.min      : Hard protection\n");
    printf("  memory.current  : Current usage\n");
    printf("  memory.events   : Event counters\n");
    printf("  memory.stat     : Detailed statistics\n");

    // Set memory.max
    snprintf(path, sizeof(path), "%s/%s/memory.max", CGROUP_V2_PATH, name);
    cg2_write(path, "10485760");  // 10 MB
    printf("\nSet memory.max = 10M\n");

    // Set memory.high (soft limit)
    snprintf(path, sizeof(path), "%s/%s/memory.high", CGROUP_V2_PATH, name);
    cg2_write(path, "8388608");   // 8 MB
    printf("Set memory.high = 8M (soft limit)\n");

    // Read memory.stat
    snprintf(path, sizeof(path), "%s/%s/memory.stat", CGROUP_V2_PATH, name);
    if (cg2_read(path, value, sizeof(value)) == 0) {
        printf("\nmemory.stat (partial):\n%s", value);
    }

    // Cleanup
    rmdir(path);
}

// Demo: CPU controller in cgroup v2
void demo_cpu_v2(void) {
    printf("\n=== CPU Controller (v2) ===\n\n");

    const char *name = "demo_cpu_v2";

    cg2_enable_controller("", "cpu");

    if (cg2_create(name) < 0) return;

    char path[512];

    printf("CPU controller files:\n");
    printf("  cpu.max         : Bandwidth limit (quota period)\n");
    printf("  cpu.weight      : Relative weight (1-10000, default 100)\n");
    printf("  cpu.stat        : CPU usage statistics\n");
    printf("  cpu.pressure    : CPU pressure (PSI)\n");

    // Set cpu.max (50% of one CPU)
    snprintf(path, sizeof(path), "%s/%s/cpu.max", CGROUP_V2_PATH, name);
    cg2_write(path, "50000 100000");  // 50ms quota, 100ms period
    printf("\nSet cpu.max = 50000 100000 (50%% of one CPU)\n");

    // Set weight
    snprintf(path, sizeof(path), "%s/%s/cpu.weight", CGROUP_V2_PATH, name);
    cg2_write(path, "50");  // Half of default (100)
    printf("Set cpu.weight = 50 (half of default)\n");

    // Cleanup
    snprintf(path, sizeof(path), "%s/%s", CGROUP_V2_PATH, name);
    rmdir(path);
}

// Demo: I/O controller
void demo_io_v2(void) {
    printf("\n=== I/O Controller (v2) ===\n\n");

    printf("I/O controller files:\n");
    printf("  io.max      : Bandwidth/IOPS limits per device\n");
    printf("  io.weight   : Relative weight (1-10000)\n");
    printf("  io.stat     : I/O statistics\n");
    printf("  io.pressure : I/O pressure (PSI)\n");

    printf("\nio.max format:\n");
    printf("  MAJOR:MINOR rbps=BYTES wbps=BYTES riops=OPS wiops=OPS\n");
    printf("  Example: 8:0 rbps=10485760 wbps=5242880\n");
    printf("  (Limit /dev/sda to 10MB/s read, 5MB/s write)\n");
}

// PSI (Pressure Stall Information)
void demo_psi(void) {
    printf("\n=== Pressure Stall Information (PSI) ===\n\n");

    printf("PSI measures resource pressure:\n");
    printf("  - How long tasks are delayed due to resource shortage\n");
    printf("  - Available for CPU, memory, I/O\n");
    printf("  - 'some' = some tasks stalled\n");
    printf("  - 'full' = all tasks stalled\n");

    printf("\nPSI files:\n");
    printf("  /proc/pressure/cpu     : System-wide CPU pressure\n");
    printf("  /proc/pressure/memory  : System-wide memory pressure\n");
    printf("  /proc/pressure/io      : System-wide I/O pressure\n");
    printf("  cgroup/cpu.pressure    : Per-cgroup CPU pressure\n");
    printf("  cgroup/memory.pressure : Per-cgroup memory pressure\n");
    printf("  cgroup/io.pressure     : Per-cgroup I/O pressure\n");

    // Read system PSI
    char buf[256];
    printf("\nSystem pressure:\n");

    if (cg2_read("/proc/pressure/cpu", buf, sizeof(buf)) == 0)
        printf("  CPU:\n    %s", buf);
    if (cg2_read("/proc/pressure/memory", buf, sizeof(buf)) == 0)
        printf("  Memory:\n    %s", buf);
    if (cg2_read("/proc/pressure/io", buf, sizeof(buf)) == 0)
        printf("  I/O:\n    %s", buf);
}

// Delegation
void explain_delegation(void) {
    printf("\n=== Cgroup Delegation ===\n\n");

    printf("Delegation allows unprivileged cgroup control:\n");
    printf("  1. Create cgroup as root\n");
    printf("  2. Change ownership to unprivileged user\n");
    printf("  3. User can create sub-cgroups\n");

    printf("\nDelegatable files:\n");
    printf("  cgroup.procs         : Add/remove processes\n");
    printf("  cgroup.subtree_control: Enable controllers\n");
    printf("  cgroup.threads       : Add/remove threads\n");

    printf("\nDelegation example:\n");
    printf("  # As root:\n");
    printf("  mkdir /sys/fs/cgroup/user/alice\n");
    printf("  chown -R alice:alice /sys/fs/cgroup/user/alice\n");
    printf("\n");
    printf("  # As alice:\n");
    printf("  mkdir /sys/fs/cgroup/user/alice/myapp\n");
    printf("  echo $$ > /sys/fs/cgroup/user/alice/myapp/cgroup.procs\n");
}

int main(void) {
    printf("=== Cgroups v2 ===\n\n");

    // Check availability
    if (!check_cgroup_v2()) {
        printf("Warning: cgroup2 filesystem not available\n");
        printf("Check: mount -t cgroup2 none /sys/fs/cgroup\n\n");
    }

    // v1 vs v2
    printf("Cgroup v2 vs v1:\n");
    printf("  v1: Multiple hierarchies (one per controller)\n");
    printf("  v2: Single unified hierarchy\n");
    printf("      - Simpler model\n");
    printf("      - Better resource control\n");
    printf("      - PSI (Pressure Stall Information)\n");
    printf("      - Better delegation model\n");

    printf("\nUnified Hierarchy:\n");
    printf("  /sys/fs/cgroup/\n");
    printf("  ├── cgroup.controllers      # Available controllers\n");
    printf("  ├── cgroup.subtree_control  # Enabled for children\n");
    printf("  ├── cgroup.procs            # Processes in this cgroup\n");
    printf("  ├── cpu.max                 # CPU limits\n");
    printf("  ├── memory.max              # Memory limits\n");
    printf("  └── mygroup/                # Child cgroup\n");
    printf("      ├── cgroup.procs\n");
    printf("      ├── cpu.max\n");
    printf("      └── memory.max\n");

    // Show current controllers
    printf("\n\nRoot cgroup:\n");
    show_controllers(CGROUP_V2_PATH);

    // Enabling controllers
    printf("\n\nEnabling controllers for subtree:\n");
    printf("  # Enable memory and cpu for children\n");
    printf("  echo '+memory +cpu' > /sys/fs/cgroup/cgroup.subtree_control\n");
    printf("\n");
    printf("  # Disable memory\n");
    printf("  echo '-memory' > /sys/fs/cgroup/cgroup.subtree_control\n");

    // Demos
    if (geteuid() == 0) {
        demo_memory_v2();
        demo_cpu_v2();
    } else {
        printf("\nNote: Run as root for cgroup manipulation demos\n");
    }

    demo_io_v2();
    demo_psi();
    explain_delegation();

    return 0;
}
```

---

## Fichiers

```
ex06/
├── cgroups_v2.h
├── cgroup_v2_basics.c
├── memory_v2.c
├── cpu_v2.c
├── psi.c
└── Makefile
```
