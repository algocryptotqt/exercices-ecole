# ex07: CPU & Memory Cgroups

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.15: CPU Cgroup (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | cpu.shares | Relative weight (v1) |
| b | cpu.cfs_period_us | Period length |
| c | cpu.cfs_quota_us | Quota in period |
| d | cpu.max | v2 format "quota period" |
| e | cpuset | Pin to CPUs |
| f | cpuset.cpus | Allowed CPUs |
| g | cpuset.mems | Allowed memory nodes |

### 2.10.16: Memory Cgroup (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | memory.limit_in_bytes | Hard limit (v1) |
| b | memory.max | Hard limit (v2) |
| c | memory.soft_limit_in_bytes | Soft limit |
| d | memory.memsw.limit_in_bytes | Memory + swap |
| e | memory.oom_control | OOM behavior |
| f | memory.stat | Usage statistics |
| g | memory.current | Current usage |
| h | OOM killer | Kill on exceed |

---

## Sujet

Maitriser le controle des ressources CPU et memoire avec les cgroups.

---

## Exemple

```c
#define _GNU_SOURCE
#include "cpu_memory_cgroups.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>
#include <sched.h>

#define CGROUP_PATH "/sys/fs/cgroup"

// Helper to write to cgroup file
int cg_write(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    write(fd, value, strlen(value));
    close(fd);
    return 0;
}

// Helper to read from cgroup file
int cg_read(const char *path, char *buf, size_t size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, size - 1);
    close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    return 0;
}

// ============================================
// CPU Control
// ============================================

void explain_cpu_control(void) {
    printf("=== CPU Cgroup Control ===\n\n");

    printf("CFS Bandwidth Control (v1):\n");
    printf("  cpu.cfs_period_us: Time period (default 100000 = 100ms)\n");
    printf("  cpu.cfs_quota_us:  Allowed CPU time per period\n");
    printf("    -1 = unlimited (default)\n");
    printf("    50000 = 50ms per 100ms period = 50%% of one CPU\n");
    printf("    200000 = 200ms per 100ms = 2 CPUs worth\n");

    printf("\nCPU Shares (v1):\n");
    printf("  cpu.shares: Relative weight (default 1024)\n");
    printf("    Only matters under contention\n");
    printf("    Group A (1024) vs Group B (512) = A gets 2x CPU\n");

    printf("\nv2 Format (cpu.max):\n");
    printf("  cpu.max: \"QUOTA PERIOD\" or \"max PERIOD\"\n");
    printf("  Example: \"50000 100000\" = 50%% of one CPU\n");

    printf("\nCPU Pinning (cpuset):\n");
    printf("  cpuset.cpus: Allowed CPUs (e.g., \"0-3\" or \"0,2\")\n");
    printf("  cpuset.mems: Allowed NUMA nodes\n");
    printf("  Useful for:\n");
    printf("    - Cache isolation\n");
    printf("    - Real-time tasks\n");
    printf("    - NUMA optimization\n");
}

// CPU stress function
void cpu_stress(int seconds) {
    time_t end = time(NULL) + seconds;
    while (time(NULL) < end) {
        volatile double x = 0.5;
        for (int i = 0; i < 100000; i++) {
            x = x * 1.00001;
        }
    }
}

void demo_cpu_limit(void) {
    printf("\n=== CPU Limit Demo ===\n");

    const char *cgroup_name = "demo_cpu_limit";
    char path[512];

    // Create cgroup
    snprintf(path, sizeof(path), "%s/cpu/%s", CGROUP_PATH, cgroup_name);
    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        printf("Cannot create cgroup (need root)\n");
        return;
    }

    // Set 50% CPU limit
    snprintf(path, sizeof(path), "%s/cpu/%s/cpu.cfs_period_us",
             CGROUP_PATH, cgroup_name);
    cg_write(path, "100000");

    snprintf(path, sizeof(path), "%s/cpu/%s/cpu.cfs_quota_us",
             CGROUP_PATH, cgroup_name);
    cg_write(path, "50000");

    printf("Created cgroup with 50%% CPU limit\n");

    // Fork and add child to cgroup
    pid_t pid = fork();
    if (pid == 0) {
        // Add self to cgroup
        snprintf(path, sizeof(path), "%s/cpu/%s/cgroup.procs",
                 CGROUP_PATH, cgroup_name);
        char pidbuf[16];
        snprintf(pidbuf, sizeof(pidbuf), "%d", getpid());
        cg_write(path, pidbuf);

        printf("Child (PID %d) in cgroup, stressing CPU for 5s...\n", getpid());
        cpu_stress(5);
        printf("Child finished (was limited to 50%%)\n");
        exit(0);
    }

    waitpid(pid, NULL, 0);

    // Cleanup
    snprintf(path, sizeof(path), "%s/cpu/%s", CGROUP_PATH, cgroup_name);
    rmdir(path);
}

// ============================================
// Memory Control
// ============================================

void explain_memory_control(void) {
    printf("\n=== Memory Cgroup Control ===\n\n");

    printf("Hard Limits:\n");
    printf("  v1: memory.limit_in_bytes\n");
    printf("  v2: memory.max\n");
    printf("  Exceeding triggers OOM killer\n");

    printf("\nSoft Limits:\n");
    printf("  v1: memory.soft_limit_in_bytes\n");
    printf("  v2: memory.high\n");
    printf("  System tries to keep usage below\n");
    printf("  Memory can be reclaimed when system needs it\n");

    printf("\nMemory + Swap (v1):\n");
    printf("  memory.memsw.limit_in_bytes: Memory + swap combined\n");
    printf("  To disable swap: set equal to memory.limit_in_bytes\n");

    printf("\nProtection (v2):\n");
    printf("  memory.low: Best-effort protection\n");
    printf("  memory.min: Hard protection (not reclaimed)\n");

    printf("\nOOM Control (v1):\n");
    printf("  memory.oom_control:\n");
    printf("    oom_kill_disable: Suspend instead of kill\n");
    printf("    under_oom: Currently under OOM\n");

    printf("\nOOM Events (v2):\n");
    printf("  memory.events:\n");
    printf("    max: Hard limit exceeded count\n");
    printf("    oom: OOM occurred\n");
    printf("    oom_kill: Process killed count\n");
}

void show_memory_stats(const char *cgroup_path) {
    char path[512];
    char buf[4096];

    // v1 format
    snprintf(path, sizeof(path), "%s/memory.stat", cgroup_path);
    if (cg_read(path, buf, sizeof(buf)) == 0) {
        printf("\nmemory.stat:\n%s", buf);
        return;
    }

    // v2 format
    snprintf(path, sizeof(path), "%s/memory.current", cgroup_path);
    if (cg_read(path, buf, sizeof(buf)) == 0) {
        printf("\nmemory.current: %s", buf);
    }
}

// Memory stress function
void memory_stress(size_t mb) {
    size_t size = mb * 1024 * 1024;
    char *mem = malloc(size);
    if (!mem) {
        printf("malloc failed\n");
        return;
    }

    // Touch all pages to actually allocate
    memset(mem, 'A', size);
    printf("Allocated and touched %zu MB\n", mb);

    sleep(2);
    free(mem);
}

void demo_memory_limit(void) {
    printf("\n=== Memory Limit Demo ===\n");

    const char *cgroup_name = "demo_mem_limit";
    char path[512];

    // Create cgroup (v2 unified)
    snprintf(path, sizeof(path), "%s/%s", CGROUP_PATH, cgroup_name);
    if (mkdir(path, 0755) < 0 && errno != EEXIST) {
        // Try v1
        snprintf(path, sizeof(path), "%s/memory/%s", CGROUP_PATH, cgroup_name);
        if (mkdir(path, 0755) < 0 && errno != EEXIST) {
            printf("Cannot create cgroup\n");
            return;
        }
    }

    // Set 50 MB limit
    snprintf(path, sizeof(path), "%s/%s/memory.max", CGROUP_PATH, cgroup_name);
    if (cg_write(path, "52428800") < 0) {
        // v1 fallback
        snprintf(path, sizeof(path), "%s/memory/%s/memory.limit_in_bytes",
                 CGROUP_PATH, cgroup_name);
        cg_write(path, "52428800");
    }

    printf("Set memory limit: 50 MB\n");

    pid_t pid = fork();
    if (pid == 0) {
        // Add to cgroup
        snprintf(path, sizeof(path), "%s/%s/cgroup.procs",
                 CGROUP_PATH, cgroup_name);
        if (cg_write(path, "0") < 0) {
            snprintf(path, sizeof(path), "%s/memory/%s/cgroup.procs",
                     CGROUP_PATH, cgroup_name);
            char pidbuf[16];
            snprintf(pidbuf, sizeof(pidbuf), "%d", getpid());
            cg_write(path, pidbuf);
        }

        printf("Child (PID %d) trying to allocate 30 MB (should succeed)...\n",
               getpid());
        memory_stress(30);

        printf("Trying to allocate 60 MB (may be OOM killed)...\n");
        memory_stress(60);

        exit(0);
    }

    int status;
    waitpid(pid, &status, 0);

    if (WIFSIGNALED(status)) {
        printf("Child was killed by signal %d", WTERMSIG(status));
        if (WTERMSIG(status) == 9)
            printf(" (OOM killed)\n");
        else
            printf("\n");
    }

    // Cleanup
    snprintf(path, sizeof(path), "%s/%s", CGROUP_PATH, cgroup_name);
    rmdir(path);
    snprintf(path, sizeof(path), "%s/memory/%s", CGROUP_PATH, cgroup_name);
    rmdir(path);
}

// ============================================
// CPU Set (Pinning)
// ============================================

void explain_cpuset(void) {
    printf("\n=== CPU Set (Pinning) ===\n\n");

    printf("cpuset controller pins processes to CPUs/NUMA nodes\n\n");

    printf("Files:\n");
    printf("  cpuset.cpus: Allowed CPUs (e.g., \"0-3,8-11\")\n");
    printf("  cpuset.mems: Allowed NUMA nodes (e.g., \"0-1\")\n");
    printf("  cpuset.cpu_exclusive: Exclusive use of CPUs\n");
    printf("  cpuset.mem_exclusive: Exclusive use of memory nodes\n");

    printf("\nUse cases:\n");
    printf("  - Real-time tasks: Isolate from other processes\n");
    printf("  - Cache optimization: Tasks on same socket share L3\n");
    printf("  - NUMA optimization: Memory near processing CPU\n");
    printf("  - Security: Prevent side-channel attacks\n");

    // Show current CPU info
    printf("\nSystem CPUs:\n");
    system("cat /proc/cpuinfo | grep 'processor' | wc -l");
    system("lscpu 2>/dev/null | grep -E '^CPU\\(s\\)|Thread|Core|Socket' | head -4");
}

int main(void) {
    explain_cpu_control();
    explain_memory_control();
    explain_cpuset();

    if (geteuid() == 0) {
        demo_cpu_limit();
        demo_memory_limit();
    } else {
        printf("\n\nNote: Run as root for cgroup demos\n");
        printf("\nExample commands:\n");
        printf("  # CPU limit\n");
        printf("  sudo cgcreate -g cpu:test\n");
        printf("  sudo cgset -r cpu.cfs_quota_us=50000 test\n");
        printf("  sudo cgexec -g cpu:test stress --cpu 1 --timeout 10\n");
        printf("\n");
        printf("  # Memory limit\n");
        printf("  sudo cgcreate -g memory:test\n");
        printf("  sudo cgset -r memory.limit_in_bytes=100M test\n");
        printf("  sudo cgexec -g memory:test stress --vm 1 --vm-bytes 200M\n");
    }

    return 0;
}
```

---

## Fichiers

```
ex07/
├── cpu_memory_cgroups.h
├── cpu_control.c
├── memory_control.c
├── cpuset.c
├── demos.c
└── Makefile
```
