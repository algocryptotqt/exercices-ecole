# ex08: I/O Cgroups

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 3h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.17: I/O Cgroup (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | blkio controller | Block I/O |
| b | blkio.weight | Relative weight |
| c | blkio.throttle.read_bps_device | Read limit |
| d | blkio.throttle.write_bps_device | Write limit |
| e | io.max (v2) | Combined limits |
| f | io.weight | Proportional weight |
| g | Device format | major:minor |

---

## Sujet

Controler les acces I/O disque avec les cgroups blkio/io.

---

## Exemple

```c
#define _GNU_SOURCE
#include "io_cgroups.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <dirent.h>
#include <errno.h>

#define CGROUP_V1_PATH "/sys/fs/cgroup/blkio"
#define CGROUP_V2_PATH "/sys/fs/cgroup"

// Get device major:minor
int get_device_id(const char *path, unsigned int *major, unsigned int *minor) {
    struct stat st;
    if (stat(path, &st) < 0) {
        perror(path);
        return -1;
    }

    *major = major(st.st_dev);
    *minor = minor(st.st_dev);
    return 0;
}

// Write to cgroup file
int cg_write(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    write(fd, value, strlen(value));
    close(fd);
    return 0;
}

// Read cgroup file
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
// blkio Controller (v1)
// ============================================

void explain_blkio_v1(void) {
    printf("=== blkio Controller (v1) ===\n\n");

    printf("Weight-based Control:\n");
    printf("  blkio.weight: Default weight (10-1000, default 500)\n");
    printf("  blkio.weight_device: Per-device weight\n");
    printf("    Format: MAJOR:MINOR WEIGHT\n");
    printf("    Example: 8:0 100  (low priority for /dev/sda)\n");

    printf("\nThrottling (absolute limits):\n");
    printf("  blkio.throttle.read_bps_device:  Max read bytes/sec\n");
    printf("  blkio.throttle.write_bps_device: Max write bytes/sec\n");
    printf("  blkio.throttle.read_iops_device:  Max read IOPS\n");
    printf("  blkio.throttle.write_iops_device: Max write IOPS\n");
    printf("    Format: MAJOR:MINOR VALUE\n");
    printf("    Example: 8:0 1048576  (1 MB/s)\n");

    printf("\nStatistics:\n");
    printf("  blkio.io_service_bytes: Bytes transferred per device\n");
    printf("  blkio.io_serviced: Operations per device\n");
    printf("  blkio.io_wait_time: Time waiting for I/O\n");
}

void show_block_devices(void) {
    printf("\n=== Block Devices ===\n\n");

    DIR *dir = opendir("/sys/block");
    if (!dir) {
        perror("/sys/block");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char path[256];
        struct stat st;

        snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
        if (stat(path, &st) == 0 && S_ISBLK(st.st_mode)) {
            printf("  %s: %u:%u\n", entry->d_name,
                   major(st.st_rdev), minor(st.st_rdev));
        }
    }
    closedir(dir);
}

// ============================================
// io Controller (v2)
// ============================================

void explain_io_v2(void) {
    printf("\n=== io Controller (v2) ===\n\n");

    printf("Weight-based Control:\n");
    printf("  io.weight: Default weight (1-10000, default 100)\n");
    printf("  io.bfq.weight: BFQ scheduler weight (v5.0+)\n");

    printf("\nAbsolute Limits (io.max):\n");
    printf("  Format: MAJOR:MINOR [rbps=N] [wbps=N] [riops=N] [wiops=N]\n");
    printf("  rbps: Read bytes per second\n");
    printf("  wbps: Write bytes per second\n");
    printf("  riops: Read IOPS\n");
    printf("  wiops: Write IOPS\n");
    printf("  Use 'max' for unlimited\n");

    printf("\nExamples:\n");
    printf("  # 10 MB/s read, 5 MB/s write on /dev/sda (8:0)\n");
    printf("  echo '8:0 rbps=10485760 wbps=5242880' > io.max\n");
    printf("\n");
    printf("  # 100 IOPS on /dev/nvme0n1 (259:0)\n");
    printf("  echo '259:0 riops=100 wiops=100' > io.max\n");
    printf("\n");
    printf("  # Remove all limits\n");
    printf("  echo '8:0 rbps=max wbps=max riops=max wiops=max' > io.max\n");

    printf("\nStatistics (io.stat):\n");
    printf("  MAJOR:MINOR rbytes=N wbytes=N rios=N wios=N dbytes=N dios=N\n");
    printf("  rbytes/wbytes: Bytes read/written\n");
    printf("  rios/wios: Read/write operations\n");
    printf("  dbytes/dios: Discard bytes/operations\n");

    printf("\nPressure (io.pressure):\n");
    printf("  Shows I/O stall information (PSI)\n");
}

// Demo: Set I/O limit
void demo_io_limit(void) {
    printf("\n=== I/O Limit Demo ===\n\n");

    // Find the root filesystem device
    unsigned int major_num, minor_num;
    if (get_device_id("/", &major_num, &minor_num) < 0) {
        printf("Cannot get device ID\n");
        return;
    }

    printf("Root filesystem device: %u:%u\n", major_num, minor_num);

    // Create cgroup
    char cgroup_path[256];
    snprintf(cgroup_path, sizeof(cgroup_path), "%s/demo_io", CGROUP_V2_PATH);

    if (mkdir(cgroup_path, 0755) < 0 && errno != EEXIST) {
        // Try v1
        snprintf(cgroup_path, sizeof(cgroup_path), "%s/demo_io", CGROUP_V1_PATH);
        if (mkdir(cgroup_path, 0755) < 0 && errno != EEXIST) {
            printf("Cannot create cgroup (need root)\n");
            return;
        }
    }

    // Set I/O limit
    char path[512];
    char value[64];

    // Try v2 format first
    snprintf(path, sizeof(path), "%s/io.max", cgroup_path);
    snprintf(value, sizeof(value), "%u:%u rbps=1048576 wbps=1048576",
             major_num, minor_num);  // 1 MB/s

    if (cg_write(path, value) < 0) {
        // v1 format
        snprintf(path, sizeof(path), "%s/blkio.throttle.read_bps_device",
                 cgroup_path);
        snprintf(value, sizeof(value), "%u:%u 1048576", major_num, minor_num);
        cg_write(path, value);

        snprintf(path, sizeof(path), "%s/blkio.throttle.write_bps_device",
                 cgroup_path);
        cg_write(path, value);
    }

    printf("Set I/O limit: 1 MB/s read and write\n");
    printf("Cgroup path: %s\n", cgroup_path);

    printf("\nTo test:\n");
    printf("  echo $$ > %s/cgroup.procs\n", cgroup_path);
    printf("  dd if=/dev/zero of=/tmp/test bs=1M count=10\n");
    printf("  (Should take ~10 seconds due to 1 MB/s limit)\n");

    // Cleanup
    rmdir(cgroup_path);
}

// Show I/O statistics
void show_io_stats(void) {
    printf("\n=== I/O Statistics ===\n\n");

    char buf[4096];

    // v2 io.stat
    if (cg_read("/sys/fs/cgroup/io.stat", buf, sizeof(buf)) == 0) {
        printf("io.stat:\n%s\n", buf);
        return;
    }

    // v1 blkio stats
    if (cg_read("/sys/fs/cgroup/blkio/blkio.io_service_bytes", buf, sizeof(buf)) == 0) {
        printf("blkio.io_service_bytes:\n%s\n", buf);
    }
}

// Show I/O pressure
void show_io_pressure(void) {
    printf("\n=== I/O Pressure ===\n\n");

    char buf[256];
    if (cg_read("/proc/pressure/io", buf, sizeof(buf)) == 0) {
        printf("System I/O pressure:\n%s\n", buf);
    }
}

int main(void) {
    explain_blkio_v1();
    explain_io_v2();
    show_block_devices();

    if (geteuid() == 0) {
        demo_io_limit();
    } else {
        printf("\nNote: Run as root for I/O limit demo\n");
    }

    show_io_stats();
    show_io_pressure();

    printf("\n=== Practical Examples ===\n\n");

    printf("Limit container to 10 MB/s:\n");
    printf("  docker run --device-write-bps /dev/sda:10mb ...\n");
    printf("  docker run --device-read-bps /dev/sda:10mb ...\n");

    printf("\nLimit container to 100 IOPS:\n");
    printf("  docker run --device-read-iops /dev/sda:100 ...\n");
    printf("  docker run --device-write-iops /dev/sda:100 ...\n");

    printf("\nUsing systemd-run:\n");
    printf("  systemd-run --scope -p IOReadBandwidthMax='/dev/sda 1M' \\\n");
    printf("              dd if=/dev/sda of=/dev/null bs=1M count=100\n");

    return 0;
}
```

---

## Fichiers

```
ex08/
├── io_cgroups.h
├── blkio_v1.c
├── io_v2.c
├── io_stats.c
├── demo_limits.c
└── Makefile
```
