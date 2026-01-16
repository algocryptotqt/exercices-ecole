# ex10: seccomp & seccomp-BPF

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.20: seccomp (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | seccomp | Secure Computing Mode |
| b | SECCOMP_MODE_STRICT | Only exit, read, write, sigreturn |
| c | SECCOMP_MODE_FILTER | BPF filter |
| d | prctl() | Enable seccomp |
| e | seccomp() | System call |
| f | BPF program | Filter rules |
| g | Actions | ALLOW, KILL, ERRNO, TRACE |
| h | libseccomp | High-level API |

### 2.10.21: seccomp-BPF (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | sock_filter | BPF instruction |
| b | sock_fprog | BPF program |
| c | BPF_STMT | Statement |
| d | BPF_JUMP | Conditional jump |
| e | seccomp_data | Syscall info |
| f | nr | Syscall number |
| g | args | Syscall arguments |
| h | arch | Architecture |

---

## Sujet

Maitriser seccomp pour filtrer les appels systeme et renforcer la securite.

---

## Exemple

```c
#define _GNU_SOURCE
#include "seccomp.h"
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <errno.h>
#include <signal.h>

// ============================================
// seccomp Basics
// ============================================

void explain_seccomp(void) {
    printf("=== seccomp (Secure Computing Mode) ===\n\n");

    printf("What is seccomp?\n");
    printf("  - Kernel feature to restrict syscalls\n");
    printf("  - Process specifies allowed syscalls\n");
    printf("  - Violations can kill, return error, or trace\n");
    printf("  - Irreversible once enabled\n");

    printf("\nModes:\n");
    printf("  SECCOMP_MODE_STRICT:\n");
    printf("    - Only read(), write(), _exit(), sigreturn()\n");
    printf("    - Very restrictive, rarely used\n");
    printf("\n");
    printf("  SECCOMP_MODE_FILTER:\n");
    printf("    - Custom BPF filter program\n");
    printf("    - Flexible rule definition\n");
    printf("    - Most common mode\n");

    printf("\nActions:\n");
    printf("  SECCOMP_RET_KILL_PROCESS: Kill entire process\n");
    printf("  SECCOMP_RET_KILL_THREAD:  Kill calling thread\n");
    printf("  SECCOMP_RET_TRAP:         Send SIGSYS signal\n");
    printf("  SECCOMP_RET_ERRNO:        Return error code\n");
    printf("  SECCOMP_RET_USER_NOTIF:   Notify userspace supervisor\n");
    printf("  SECCOMP_RET_TRACE:        Allow ptracer to handle\n");
    printf("  SECCOMP_RET_LOG:          Allow and log\n");
    printf("  SECCOMP_RET_ALLOW:        Allow syscall\n");
}

// ============================================
// Strict Mode
// ============================================

void demo_strict_mode(void) {
    printf("\n=== SECCOMP_MODE_STRICT Demo ===\n");

    // Enable strict mode
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) < 0) {
        perror("prctl SECCOMP_MODE_STRICT");
        return;
    }

    printf("Strict mode enabled\n");
    printf("Can only use: read, write, _exit, sigreturn\n");

    // write() works
    write(STDOUT_FILENO, "write() works!\n", 15);

    // read() would work
    // _exit() works

    // Any other syscall kills the process
    // getpid();  // Would kill us!

    _exit(0);
}

// ============================================
// BPF Filter
// ============================================

// Helper macro for seccomp BPF
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

#if defined(__x86_64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_X86_64
#elif defined(__i386__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_I386
#elif defined(__aarch64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_AARCH64
#else
#error "Unsupported architecture"
#endif

// Install seccomp filter
int install_seccomp_filter(struct sock_filter *filter, size_t len) {
    struct sock_fprog prog = {
        .len = len,
        .filter = filter,
    };

    // Allow process to install seccomp filter
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        perror("prctl NO_NEW_PRIVS");
        return -1;
    }

    // Install filter
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0) {
        perror("prctl SECCOMP_MODE_FILTER");
        return -1;
    }

    return 0;
}

void demo_filter_mode(void) {
    printf("\n=== SECCOMP_MODE_FILTER Demo ===\n");

    // Filter that blocks getpid() syscall
    struct sock_filter filter[] = {
        // Load architecture
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, arch_nr),

        // Verify architecture (kill if wrong)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_CURRENT, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        // Load syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, syscall_nr),

        // Block getpid() - return EPERM
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),

        // Allow everything else
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    printf("Installing filter that blocks getpid()...\n");

    if (install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0])) < 0) {
        return;
    }

    printf("Filter installed\n");

    // Test getpid()
    pid_t pid = getpid();
    if (pid < 0) {
        printf("getpid() blocked! errno=%d (%s)\n", errno, strerror(errno));
    } else {
        printf("getpid() returned: %d (should have been blocked)\n", pid);
    }

    // Other syscalls still work
    printf("getuid() = %d (still works)\n", getuid());
}

// ============================================
// Whitelist filter
// ============================================

void demo_whitelist(void) {
    printf("\n=== Whitelist Filter Demo ===\n");

    // Only allow specific syscalls (whitelist approach)
    struct sock_filter filter[] = {
        // Check architecture
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, arch_nr),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_CURRENT, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        // Load syscall number
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, syscall_nr),

        // Allow list (jump over KILL if match)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 6, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 5, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 4, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 3, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_brk, 2, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fstat, 1, 0),

        // Not in whitelist - KILL
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        // Allowed
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    printf("Whitelist: read, write, exit, exit_group, brk, fstat\n");
    printf("All other syscalls will kill the process\n");

    // Would enable filter here (commented to not break demo)
    // install_seccomp_filter(filter, sizeof(filter)/sizeof(filter[0]));
}

// ============================================
// seccomp_data structure
// ============================================

void explain_seccomp_data(void) {
    printf("\n=== seccomp_data Structure ===\n\n");

    printf("struct seccomp_data {\n");
    printf("    int   nr;           // Syscall number\n");
    printf("    __u32 arch;         // AUDIT_ARCH_*\n");
    printf("    __u64 instruction_pointer;\n");
    printf("    __u64 args[6];      // Syscall arguments\n");
    printf("};\n");

    printf("\nAccessing fields with BPF:\n");
    printf("  Load syscall number:\n");
    printf("    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ");
    printf("offsetof(struct seccomp_data, nr))\n");
    printf("\n");
    printf("  Load first argument:\n");
    printf("    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, ");
    printf("offsetof(struct seccomp_data, args[0]))\n");

    printf("\nExample: Block write() to fd > 2:\n");
    printf("  1. Load syscall number\n");
    printf("  2. Check if SYS_write\n");
    printf("  3. Load args[0] (fd)\n");
    printf("  4. Check if fd > 2\n");
    printf("  5. KILL or ALLOW\n");
}

// ============================================
// BPF Instructions
// ============================================

void explain_bpf_instructions(void) {
    printf("\n=== BPF Instructions ===\n\n");

    printf("BPF_STMT(code, k)  - Statement with constant k\n");
    printf("BPF_JUMP(code, k, jt, jf) - Jump true/false offsets\n");

    printf("\nLoad instructions:\n");
    printf("  BPF_LD | BPF_W | BPF_ABS  - Load word from absolute offset\n");
    printf("  BPF_LD | BPF_H | BPF_ABS  - Load half-word\n");
    printf("  BPF_LD | BPF_B | BPF_ABS  - Load byte\n");

    printf("\nJump instructions:\n");
    printf("  BPF_JMP | BPF_JEQ | BPF_K  - Jump if A == k\n");
    printf("  BPF_JMP | BPF_JGE | BPF_K  - Jump if A >= k\n");
    printf("  BPF_JMP | BPF_JGT | BPF_K  - Jump if A > k\n");
    printf("  BPF_JMP | BPF_JSET | BPF_K - Jump if A & k\n");

    printf("\nReturn instructions:\n");
    printf("  BPF_RET | BPF_K  - Return constant (seccomp action)\n");
}

// ============================================
// libseccomp high-level API
// ============================================

void show_libseccomp_example(void) {
    printf("\n=== libseccomp (High-Level API) ===\n\n");

    printf("Much easier than raw BPF!\n\n");

    printf("#include <seccomp.h>\n\n");

    printf("// Create filter (default: KILL)\n");
    printf("scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);\n\n");

    printf("// Add rules to allow syscalls\n");
    printf("seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);\n");
    printf("seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);\n");
    printf("seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);\n\n");

    printf("// Allow write() only to stdout/stderr\n");
    printf("seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1,\n");
    printf("                 SCMP_A0(SCMP_CMP_LE, 2));\n\n");

    printf("// Load filter\n");
    printf("seccomp_load(ctx);\n\n");

    printf("// Free context\n");
    printf("seccomp_release(ctx);\n");

    printf("\nCompile with: gcc -lseccomp ...\n");
}

int main(void) {
    explain_seccomp();
    explain_bpf_instructions();
    explain_seccomp_data();

    demo_filter_mode();
    demo_whitelist();

    show_libseccomp_example();

    printf("\n=== Container Usage ===\n\n");
    printf("Docker default seccomp profile blocks ~44 syscalls:\n");
    printf("  - clone with CLONE_NEWUSER (without CAP_SYS_ADMIN)\n");
    printf("  - mount, umount\n");
    printf("  - reboot, swapon, swapoff\n");
    printf("  - init_module, delete_module\n");
    printf("  - acct, quotactl\n");
    printf("  - ... and more\n");

    printf("\nRun Docker without seccomp (dangerous!):\n");
    printf("  docker run --security-opt seccomp=unconfined ...\n");

    return 0;
}
```

---

## Fichiers

```
ex10/
├── seccomp.h
├── seccomp_basics.c
├── strict_mode.c
├── bpf_filter.c
├── libseccomp_example.c
└── Makefile
```
