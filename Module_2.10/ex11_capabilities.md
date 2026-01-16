# ex11: Linux Capabilities

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 3h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.22: Linux Capabilities (11 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Capabilities | Fine-grained privileges |
| b | CAP_CHOWN | Change file ownership |
| c | CAP_DAC_OVERRIDE | Bypass DAC |
| d | CAP_NET_ADMIN | Network admin |
| e | CAP_NET_BIND_SERVICE | Bind < 1024 |
| f | CAP_NET_RAW | Raw sockets |
| g | CAP_SYS_ADMIN | Various admin ops |
| h | CAP_SETUID | setuid() |
| i | Capability sets | Permitted, inheritable, effective, bounding, ambient |
| j | capset()/capget() | System calls |
| k | setcap/getcap | File capabilities |

---

## Sujet

Comprendre et utiliser les Linux capabilities pour le principe du moindre privilege.

---

## Exemple

```c
#define _GNU_SOURCE
#include "capabilities.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <linux/capability.h>

// ============================================
// Capabilities Overview
// ============================================

void explain_capabilities(void) {
    printf("=== Linux Capabilities ===\n\n");

    printf("What are capabilities?\n");
    printf("  - Fine-grained privileges (replace all-or-nothing root)\n");
    printf("  - Each capability grants specific permissions\n");
    printf("  - Process can have subset of root powers\n");
    printf("  - More secure than full root\n");

    printf("\nWhy capabilities?\n");
    printf("  Traditional Unix: UID 0 = god mode\n");
    printf("  Problem: Most programs don't need ALL privileges\n");
    printf("  Solution: Split root into ~40 distinct capabilities\n");
}

void list_common_capabilities(void) {
    printf("\n=== Common Capabilities ===\n\n");

    printf("Network:\n");
    printf("  CAP_NET_BIND_SERVICE: Bind ports < 1024\n");
    printf("  CAP_NET_RAW:          Raw sockets (ping, tcpdump)\n");
    printf("  CAP_NET_ADMIN:        Network configuration\n");

    printf("\nFilesystem:\n");
    printf("  CAP_CHOWN:            Change file ownership\n");
    printf("  CAP_DAC_OVERRIDE:     Bypass read/write/execute checks\n");
    printf("  CAP_DAC_READ_SEARCH:  Bypass read checks\n");
    printf("  CAP_FOWNER:           Bypass permission checks for owner\n");
    printf("  CAP_MKNOD:            Create device nodes\n");

    printf("\nProcess:\n");
    printf("  CAP_SETUID:           setuid(), setfsuid()\n");
    printf("  CAP_SETGID:           setgid(), setfsgid()\n");
    printf("  CAP_KILL:             Send signals to any process\n");
    printf("  CAP_SYS_PTRACE:       ptrace() any process\n");

    printf("\nSystem:\n");
    printf("  CAP_SYS_ADMIN:        \"New root\" - many operations\n");
    printf("  CAP_SYS_BOOT:         reboot()\n");
    printf("  CAP_SYS_TIME:         Set system time\n");
    printf("  CAP_SYS_MODULE:       Load kernel modules\n");
    printf("  CAP_SYS_RAWIO:        Raw I/O (iopl, ioperm)\n");
    printf("  CAP_SYS_CHROOT:       chroot()\n");

    printf("\nCAP_SYS_ADMIN is dangerous:\n");
    printf("  - mount, umount\n");
    printf("  - sethostname, setdomainname\n");
    printf("  - Namespace operations\n");
    printf("  - quotactl, swapon/swapoff\n");
    printf("  - Many ioctl operations\n");
}

void explain_capability_sets(void) {
    printf("\n=== Capability Sets ===\n\n");

    printf("Each thread has 5 capability sets:\n\n");

    printf("Permitted (P):\n");
    printf("  - Upper limit of capabilities thread can have\n");
    printf("  - Can be reduced, never increased\n");
    printf("  - Caps can move from P to E or I\n");

    printf("\nEffective (E):\n");
    printf("  - Actually used for permission checks\n");
    printf("  - Must be subset of Permitted\n");
    printf("  - Can be raised/lowered (within P)\n");

    printf("\nInheritable (I):\n");
    printf("  - Preserved across execve()\n");
    printf("  - Combined with file capabilities\n");

    printf("\nBounding set (B):\n");
    printf("  - Upper limit that can be in P after execve()\n");
    printf("  - Can only be dropped, never raised\n");
    printf("  - Limits file capabilities\n");

    printf("\nAmbient set (A):\n");
    printf("  - Preserved across execve() for non-setuid programs\n");
    printf("  - Easier capability inheritance\n");
    printf("  - Must be in both P and I\n");

    printf("\nAfter execve():\n");
    printf("  P' = (P & B) | (file_P & B) | A\n");
    printf("  E' = file_E ? (P' & file_E) : A\n");
    printf("  I' = I\n");
}

// ============================================
// Using Capabilities API
// ============================================

void show_current_caps(void) {
    printf("\n=== Current Process Capabilities ===\n\n");

    cap_t caps = cap_get_proc();
    if (!caps) {
        perror("cap_get_proc");
        return;
    }

    char *text = cap_to_text(caps, NULL);
    if (text) {
        printf("Capabilities: %s\n", text);
        cap_free(text);
    }

    cap_free(caps);

    // Also show raw values
    printf("\nUID: %d, EUID: %d\n", getuid(), geteuid());
}

int drop_capability(cap_value_t cap) {
    cap_t caps = cap_get_proc();
    if (!caps) return -1;

    // Clear from all sets
    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, CAP_CLEAR) < 0 ||
        cap_set_flag(caps, CAP_PERMITTED, 1, &cap, CAP_CLEAR) < 0 ||
        cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_CLEAR) < 0) {
        cap_free(caps);
        return -1;
    }

    if (cap_set_proc(caps) < 0) {
        cap_free(caps);
        return -1;
    }

    cap_free(caps);
    return 0;
}

int keep_only_capability(cap_value_t cap) {
    cap_t caps = cap_init();  // Empty set
    if (!caps) return -1;

    // Add only the specified capability
    if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, CAP_SET) < 0 ||
        cap_set_flag(caps, CAP_PERMITTED, 1, &cap, CAP_SET) < 0) {
        cap_free(caps);
        return -1;
    }

    if (cap_set_proc(caps) < 0) {
        cap_free(caps);
        return -1;
    }

    cap_free(caps);
    return 0;
}

void demo_capabilities(void) {
    printf("\n=== Capability Demo ===\n\n");

    if (geteuid() != 0) {
        printf("Note: Run as root to see full demo\n");
        show_current_caps();
        return;
    }

    printf("Before dropping capabilities:\n");
    show_current_caps();

    // Drop CAP_CHOWN
    printf("\nDropping CAP_CHOWN...\n");
    if (drop_capability(CAP_CHOWN) == 0) {
        printf("Dropped successfully\n");
    }

    printf("\nAfter dropping CAP_CHOWN:\n");
    show_current_caps();

    // Try chown (should fail)
    if (chown("/tmp", 0, 0) < 0) {
        printf("\nchown() failed as expected: %s\n", strerror(errno));
    }
}

// ============================================
// File Capabilities
// ============================================

void explain_file_capabilities(void) {
    printf("\n=== File Capabilities ===\n\n");

    printf("Files can have capabilities (like setuid but granular)\n\n");

    printf("Setting file capabilities:\n");
    printf("  setcap CAP_NET_BIND_SERVICE=+ep /path/to/binary\n");
    printf("\n");
    printf("  =+ep means:\n");
    printf("    +e : Add to Effective set\n");
    printf("    +p : Add to Permitted set\n");

    printf("\nViewing file capabilities:\n");
    printf("  getcap /path/to/binary\n");
    printf("  getcap -r /  # Recursive search\n");

    printf("\nRemoving file capabilities:\n");
    printf("  setcap -r /path/to/binary\n");

    printf("\nExamples:\n");
    printf("  # Allow ping without root\n");
    printf("  setcap CAP_NET_RAW=+ep /bin/ping\n");
    printf("\n");
    printf("  # Allow web server to bind port 80\n");
    printf("  setcap CAP_NET_BIND_SERVICE=+ep /usr/bin/nginx\n");
}

// ============================================
// Container Usage
// ============================================

void show_container_caps(void) {
    printf("\n=== Capabilities in Containers ===\n\n");

    printf("Docker default capabilities (dropped from full root):\n");
    printf("  Kept: CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FSETID,\n");
    printf("        CAP_FOWNER, CAP_MKNOD, CAP_NET_RAW,\n");
    printf("        CAP_SETGID, CAP_SETUID, CAP_SETFCAP,\n");
    printf("        CAP_SETPCAP, CAP_NET_BIND_SERVICE,\n");
    printf("        CAP_SYS_CHROOT, CAP_KILL, CAP_AUDIT_WRITE\n");

    printf("\nDropped by default:\n");
    printf("  CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_MODULE,\n");
    printf("  CAP_SYS_BOOT, CAP_NET_ADMIN, CAP_SYS_TIME, etc.\n");

    printf("\nDocker capability flags:\n");
    printf("  --cap-add CAP_SYS_ADMIN    Add capability\n");
    printf("  --cap-drop CAP_NET_RAW     Drop capability\n");
    printf("  --cap-drop ALL             Drop all capabilities\n");
    printf("  --privileged               Add ALL capabilities\n");

    printf("\nExample:\n");
    printf("  docker run --cap-add SYS_TIME alpine date -s '2024-01-01'\n");
    printf("  docker run --cap-drop ALL --cap-add CHOWN alpine chown ...\n");
}

// Drop capabilities and privileges safely
void demo_privilege_drop(void) {
    printf("\n=== Safe Privilege Drop Pattern ===\n\n");

    printf("Pattern for network daemons:\n\n");

    printf("1. Start as root\n");
    printf("2. Bind privileged port (e.g., 80)\n");
    printf("3. Drop to unprivileged user:\n");
    printf("   a. Keep only needed capabilities in bounding set\n");
    printf("   b. setgroups() - clear supplementary groups\n");
    printf("   c. setgid() - change GID\n");
    printf("   d. setuid() - change UID\n");
    printf("   e. Clear remaining capabilities\n");
    printf("4. Never get root back\n");

    printf("\nCode pattern:\n");
    printf("  // After binding port 80\n");
    printf("  prctl(PR_SET_KEEPCAPS, 1);  // Keep caps across setuid\n");
    printf("  setgid(nobody_gid);\n");
    printf("  setuid(nobody_uid);\n");
    printf("  prctl(PR_SET_KEEPCAPS, 0);\n");
    printf("  // Drop all capabilities\n");
    printf("  cap_t empty = cap_init();\n");
    printf("  cap_set_proc(empty);\n");
}

int main(void) {
    explain_capabilities();
    list_common_capabilities();
    explain_capability_sets();

    demo_capabilities();

    explain_file_capabilities();
    show_container_caps();
    demo_privilege_drop();

    printf("\n=== Useful Commands ===\n\n");
    printf("  getpcaps PID       # Show process capabilities\n");
    printf("  capsh --print      # Show current shell capabilities\n");
    printf("  getcap -r /        # Find files with capabilities\n");
    printf("  filecap /path      # Alternative to getcap\n");

    return 0;
}
```

---

## Fichiers

```
ex11/
├── capabilities.h
├── cap_basics.c
├── cap_sets.c
├── file_caps.c
├── cap_demo.c
└── Makefile
```

Compiler avec: `gcc -lcap ...`
