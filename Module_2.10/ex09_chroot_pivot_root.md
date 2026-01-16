# ex09: chroot & pivot_root

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 3h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.18: chroot (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | chroot() | Change root directory |
| b | Purpose | Isolate filesystem |
| c | Limitations | Root can escape |
| d | Escape | fchdir before chroot |
| e | Not security | Don't rely on it |
| f | Use cases | Build environments |
| g | debootstrap | Create chroot |

### 2.10.19: pivot_root (6 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | pivot_root() | Swap root filesystems |
| b | More secure | Than chroot |
| c | Requirements | new_root must be mount point |
| d | put_old | Where old root goes |
| e | Container usage | Change to container rootfs |
| f | Unmount old | After pivot |

---

## Sujet

Comprendre chroot et pivot_root pour l'isolation du systeme de fichiers.

---

## Exemple

```c
#define _GNU_SOURCE
#include "chroot_pivot.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sched.h>
#include <errno.h>
#include <dirent.h>

// ============================================
// chroot
// ============================================

void explain_chroot(void) {
    printf("=== chroot ===\n\n");

    printf("chroot() changes the root directory for a process\n");
    printf("  - All path resolution starts from new root\n");
    printf("  - Process cannot access files outside new root\n");
    printf("  - '/' refers to the chroot directory\n");

    printf("\nLimitations:\n");
    printf("  - Root can escape (multiple methods)\n");
    printf("  - Not a security mechanism!\n");
    printf("  - No namespace isolation\n");
    printf("  - Process still in host's PID/NET/etc namespaces\n");

    printf("\nLegitimate Use Cases:\n");
    printf("  - Build environments (debootstrap)\n");
    printf("  - Recovery systems\n");
    printf("  - Package builds\n");
    printf("  - Testing with different root filesystems\n");
}

// Demonstrate chroot escape
void show_chroot_escape(void) {
    printf("\n=== chroot Escape Methods ===\n\n");

    printf("Method 1: Using fchdir() (classic)\n");
    printf("  1. Open a directory outside chroot: int fd = open('/', O_RDONLY)\n");
    printf("  2. chroot() to restricted directory\n");
    printf("  3. fchdir(fd) - changes to old root\n");
    printf("  4. chdir('..') repeatedly until real root\n");
    printf("  5. chroot('.') - back to real root\n");

    printf("\nMethod 2: Double chroot\n");
    printf("  1. mkdir('escape')\n");
    printf("  2. chroot('escape')\n");
    printf("  3. chdir('..')\n");
    printf("  4. chroot('.')\n");

    printf("\nMethod 3: /proc access (if mounted)\n");
    printf("  Access /proc/1/root or /proc/self/root\n");

    printf("\nMethod 4: Device access\n");
    printf("  If /dev is accessible, mknod and access raw disk\n");

    printf("\nPrevention:\n");
    printf("  - Drop privileges before/after chroot\n");
    printf("  - Use namespaces (proper containers)\n");
    printf("  - Don't rely on chroot for security\n");
}

// Simple chroot demo
int demo_chroot(const char *new_root) {
    printf("\n=== chroot Demo ===\n");

    // Verify new_root exists
    struct stat st;
    if (stat(new_root, &st) < 0 || !S_ISDIR(st.st_mode)) {
        printf("Error: %s is not a directory\n", new_root);
        return -1;
    }

    printf("Changing root to: %s\n", new_root);

    // chroot and chdir
    if (chroot(new_root) < 0) {
        perror("chroot");
        return -1;
    }

    if (chdir("/") < 0) {
        perror("chdir");
        return -1;
    }

    printf("Now in chroot environment\n");
    printf("Root directory contents:\n");

    DIR *dir = opendir("/");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            printf("  %s\n", entry->d_name);
        }
        closedir(dir);
    }

    return 0;
}

// ============================================
// pivot_root
// ============================================

void explain_pivot_root(void) {
    printf("\n=== pivot_root ===\n\n");

    printf("pivot_root() swaps the root filesystem\n");
    printf("  - Puts old root at a specified location\n");
    printf("  - More secure than chroot\n");
    printf("  - Used by actual container runtimes\n");

    printf("\nFunction signature:\n");
    printf("  int pivot_root(const char *new_root, const char *put_old)\n");

    printf("\nRequirements:\n");
    printf("  - new_root must be a mount point\n");
    printf("  - put_old must be under new_root\n");
    printf("  - Must be in new mount namespace\n");
    printf("  - Caller must be root (CAP_SYS_ADMIN)\n");

    printf("\nTypical usage:\n");
    printf("  1. Create mount namespace (unshare CLONE_NEWNS)\n");
    printf("  2. Make mounts private (MS_PRIVATE)\n");
    printf("  3. Mount new rootfs\n");
    printf("  4. Create put_old directory under new root\n");
    printf("  5. pivot_root(new_root, put_old)\n");
    printf("  6. chdir('/')\n");
    printf("  7. Unmount old root (umount -l put_old)\n");
    printf("  8. rmdir put_old\n");
}

// pivot_root syscall wrapper
int pivot_root(const char *new_root, const char *put_old) {
    return syscall(SYS_pivot_root, new_root, put_old);
}

// Full pivot_root demonstration
int demo_pivot_root(const char *rootfs_path) {
    printf("\n=== pivot_root Demo ===\n");

    // Must be root
    if (geteuid() != 0) {
        printf("Error: Need root privileges\n");
        return -1;
    }

    printf("Preparing to pivot_root to: %s\n", rootfs_path);

    // Create new mount namespace
    if (unshare(CLONE_NEWNS) < 0) {
        perror("unshare CLONE_NEWNS");
        return -1;
    }
    printf("Created new mount namespace\n");

    // Make all mounts private
    if (mount("", "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        perror("mount MS_PRIVATE");
        return -1;
    }
    printf("Made mounts private\n");

    // Bind mount new root to itself (required for pivot_root)
    if (mount(rootfs_path, rootfs_path, NULL, MS_BIND | MS_REC, NULL) < 0) {
        perror("bind mount new root");
        return -1;
    }
    printf("Bind mounted new root\n");

    // Create put_old directory
    char put_old[512];
    snprintf(put_old, sizeof(put_old), "%s/.old_root", rootfs_path);
    mkdir(put_old, 0755);

    // pivot_root
    if (pivot_root(rootfs_path, put_old) < 0) {
        perror("pivot_root");
        return -1;
    }
    printf("pivot_root successful\n");

    // Change to new root
    if (chdir("/") < 0) {
        perror("chdir /");
        return -1;
    }

    // Unmount old root
    if (umount2("/.old_root", MNT_DETACH) < 0) {
        perror("umount old root");
        // Continue anyway
    }

    // Remove old root directory
    rmdir("/.old_root");

    printf("Now in new root filesystem\n");
    printf("/ contains:\n");
    system("ls -la /");

    return 0;
}

// Create minimal rootfs
void show_minimal_rootfs(void) {
    printf("\n=== Creating Minimal Rootfs ===\n\n");

    printf("Using debootstrap (Debian/Ubuntu):\n");
    printf("  debootstrap --variant=minbase stable ./rootfs\n");

    printf("\nUsing Alpine (smaller):\n");
    printf("  wget alpine-minirootfs-*.tar.gz\n");
    printf("  mkdir rootfs && tar -xf alpine*.tar.gz -C rootfs\n");

    printf("\nMinimal manual setup:\n");
    printf("  mkdir -p rootfs/{bin,lib,lib64,proc,sys,dev,tmp}\n");
    printf("  cp /bin/busybox rootfs/bin/\n");
    printf("  cd rootfs/bin && ln -s busybox sh\n");
    printf("  # Copy needed libraries (use ldd to find them)\n");

    printf("\nAfter pivot_root, mount essential filesystems:\n");
    printf("  mount -t proc proc /proc\n");
    printf("  mount -t sysfs sys /sys\n");
    printf("  mount -t devtmpfs dev /dev\n");
}

// ============================================
// Comparison
// ============================================

void compare_chroot_pivot(void) {
    printf("\n=== chroot vs pivot_root ===\n\n");

    printf("+-----------------+-------------------+-------------------+\n");
    printf("|   Feature       |      chroot       |    pivot_root     |\n");
    printf("+-----------------+-------------------+-------------------+\n");
    printf("| Security        | Escapable         | More secure       |\n");
    printf("| Old root        | Still accessible  | Can be unmounted  |\n");
    printf("| Mount namespace | Not required      | Required          |\n");
    printf("| Complexity      | Simple            | More complex      |\n");
    printf("| Container use   | Not recommended   | Standard method   |\n");
    printf("| Privileges      | Root to setup     | Root + namespace  |\n");
    printf("+-----------------+-------------------+-------------------+\n");

    printf("\nContainer runtime sequence:\n");
    printf("  1. unshare(CLONE_NEWNS | CLONE_NEWPID | ...)\n");
    printf("  2. Setup rootfs with overlayfs\n");
    printf("  3. Mount /proc, /sys, /dev\n");
    printf("  4. pivot_root() to new rootfs\n");
    printf("  5. Unmount old root\n");
    printf("  6. Apply seccomp filters\n");
    printf("  7. Drop capabilities\n");
    printf("  8. exec() container process\n");
}

int main(void) {
    explain_chroot();
    show_chroot_escape();
    explain_pivot_root();
    show_minimal_rootfs();
    compare_chroot_pivot();

    printf("\n=== Practical Examples ===\n\n");

    printf("chroot example:\n");
    printf("  sudo debootstrap stable /tmp/chroot\n");
    printf("  sudo chroot /tmp/chroot /bin/bash\n");

    printf("\npivot_root example:\n");
    printf("  sudo unshare --mount --fork /bin/bash\n");
    printf("  # In new shell:\n");
    printf("  mount --bind /tmp/rootfs /tmp/rootfs\n");
    printf("  mkdir /tmp/rootfs/.old\n");
    printf("  pivot_root /tmp/rootfs /tmp/rootfs/.old\n");
    printf("  umount -l /.old && rmdir /.old\n");

    // Run demo if root and rootfs exists
    if (geteuid() == 0 && access("/tmp/test_rootfs", F_OK) == 0) {
        demo_chroot("/tmp/test_rootfs");
    }

    return 0;
}
```

---

## Fichiers

```
ex09/
├── chroot_pivot.h
├── chroot_basics.c
├── chroot_escape.c
├── pivot_root.c
├── rootfs_setup.c
└── Makefile
```
