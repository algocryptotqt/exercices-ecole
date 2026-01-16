# ex03: PID & Network Namespaces

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.8: PID Namespace (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | PID isolation | Separate PID space |
| b | PID 1 | Init in namespace |
| c | Nested namespaces | Hierarchical |
| d | Parent can see | All child PIDs |
| e | Child can't see | Parent PIDs |
| f | /proc | Shows namespace PIDs |
| g | Signals | Cross-namespace restricted |

### 2.10.9: Network Namespace (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | NET isolation | Separate network stack |
| b | Own interfaces | lo, eth0, etc. |
| c | Own routing | Routing table |
| d | Own firewall | iptables rules |
| e | veth pairs | Virtual ethernet |
| f | Connecting | veth between namespaces |
| g | Bridge | Connect multiple |
| h | ip netns | Management tool |

---

## Sujet

Maitriser les namespaces PID et reseau pour l'isolation des conteneurs.

---

## Exemple

```c
#define _GNU_SOURCE
#include "pid_net_ns.h"
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
#include <signal.h>

#define STACK_SIZE (1024 * 1024)

// ============================================
// PID Namespace Demo
// ============================================

static int pid_child_func(void *arg) {
    (void)arg;

    printf("\n=== Inside PID Namespace ===\n");
    printf("getpid() = %d (should be 1 in new namespace)\n", getpid());
    printf("getppid() = %d\n", getppid());

    // Mount new /proc to see only our processes
    if (mount("proc", "/proc", "proc", 0, NULL) < 0) {
        perror("mount /proc");
        // Continue anyway, /proc might not be available
    }

    printf("\nProcesses visible in namespace:\n");
    system("ps aux 2>/dev/null || echo 'ps not available'");

    printf("\nPID 1 responsibilities:\n");
    printf("  - Reap zombie processes\n");
    printf("  - Forward signals\n");
    printf("  - If PID 1 dies, namespace is destroyed\n");

    // Fork a child to demonstrate
    pid_t child = fork();
    if (child == 0) {
        printf("\nForked child: PID = %d, PPID = %d\n", getpid(), getppid());
        sleep(1);
        exit(0);
    } else if (child > 0) {
        int status;
        waitpid(child, &status, 0);
        printf("Reaped child %d\n", child);
    }

    return 0;
}

int demo_pid_namespace(void) {
    printf("\n=== PID Namespace Demo ===\n");

    void *stack = malloc(STACK_SIZE);
    if (!stack) return -1;

    // CLONE_NEWPID creates new PID namespace
    // CLONE_NEWNS creates new mount namespace (for /proc)
    int flags = CLONE_NEWPID | CLONE_NEWNS | SIGCHLD;

    pid_t pid = clone(pid_child_func, stack + STACK_SIZE, flags, NULL);
    if (pid < 0) {
        perror("clone");
        free(stack);
        return -1;
    }

    printf("Parent sees child as PID: %d\n", pid);

    int status;
    waitpid(pid, &status, 0);

    free(stack);
    return 0;
}

// ============================================
// Network Namespace Demo
// ============================================

void run_in_netns(const char *cmd) {
    printf("$ %s\n", cmd);
    system(cmd);
    printf("\n");
}

int demo_network_namespace(void) {
    printf("\n=== Network Namespace Demo ===\n");
    printf("Creating and configuring network namespace...\n\n");

    // Create a network namespace using ip netns
    printf("1. Create network namespace 'test_ns':\n");
    run_in_netns("ip netns add test_ns 2>/dev/null || echo 'Namespace exists or no permissions'");

    // Show current namespaces
    printf("2. List network namespaces:\n");
    run_in_netns("ip netns list");

    // Show interfaces in new namespace
    printf("3. Interfaces in new namespace (only lo, down):\n");
    run_in_netns("ip netns exec test_ns ip link show 2>/dev/null || echo 'Cannot exec in namespace'");

    // Create veth pair
    printf("4. Create veth pair (veth0 <-> veth1):\n");
    run_in_netns("ip link add veth0 type veth peer name veth1 2>/dev/null || echo 'Cannot create veth'");

    // Move one end to namespace
    printf("5. Move veth1 to namespace:\n");
    run_in_netns("ip link set veth1 netns test_ns 2>/dev/null || echo 'Cannot move interface'");

    // Configure interfaces
    printf("6. Configure IP addresses:\n");
    run_in_netns("ip addr add 192.168.100.1/24 dev veth0 2>/dev/null");
    run_in_netns("ip link set veth0 up 2>/dev/null");
    run_in_netns("ip netns exec test_ns ip addr add 192.168.100.2/24 dev veth1 2>/dev/null");
    run_in_netns("ip netns exec test_ns ip link set veth1 up 2>/dev/null");
    run_in_netns("ip netns exec test_ns ip link set lo up 2>/dev/null");

    // Show configuration
    printf("7. Host veth0 configuration:\n");
    run_in_netns("ip addr show veth0 2>/dev/null || echo 'No veth0'");

    printf("8. Namespace veth1 configuration:\n");
    run_in_netns("ip netns exec test_ns ip addr show 2>/dev/null || echo 'Cannot show'");

    // Test connectivity
    printf("9. Ping from host to namespace:\n");
    run_in_netns("ping -c 1 192.168.100.2 2>/dev/null || echo 'Ping failed'");

    printf("10. Ping from namespace to host:\n");
    run_in_netns("ip netns exec test_ns ping -c 1 192.168.100.1 2>/dev/null || echo 'Ping failed'");

    // Show routing in namespace
    printf("11. Routing table in namespace:\n");
    run_in_netns("ip netns exec test_ns ip route 2>/dev/null || echo 'Cannot show routes'");

    // Cleanup
    printf("12. Cleanup:\n");
    run_in_netns("ip link delete veth0 2>/dev/null");
    run_in_netns("ip netns delete test_ns 2>/dev/null");

    return 0;
}

// ============================================
// Bridge networking demo
// ============================================

int demo_bridge_networking(void) {
    printf("\n=== Bridge Networking ===\n\n");

    printf("Bridge connects multiple namespaces:\n\n");
    printf("  +---------+     +---------+\n");
    printf("  |  NS1    |     |  NS2    |\n");
    printf("  | veth1a  |     | veth2a  |\n");
    printf("  +----+----+     +----+----+\n");
    printf("       |              |\n");
    printf("   veth1b         veth2b\n");
    printf("       |              |\n");
    printf("  +----+--------------+----+\n");
    printf("  |        bridge0         |\n");
    printf("  +------------------------+\n");
    printf("             |\n");
    printf("         Host network\n");

    printf("\nSetup commands:\n");
    printf("  # Create bridge\n");
    printf("  ip link add bridge0 type bridge\n");
    printf("  ip link set bridge0 up\n");
    printf("  ip addr add 10.0.0.1/24 dev bridge0\n");
    printf("\n");
    printf("  # Create namespace and veth\n");
    printf("  ip netns add ns1\n");
    printf("  ip link add veth1a type veth peer name veth1b\n");
    printf("  ip link set veth1a netns ns1\n");
    printf("  ip link set veth1b master bridge0\n");
    printf("  ip link set veth1b up\n");
    printf("\n");
    printf("  # Configure namespace\n");
    printf("  ip netns exec ns1 ip addr add 10.0.0.2/24 dev veth1a\n");
    printf("  ip netns exec ns1 ip link set veth1a up\n");
    printf("  ip netns exec ns1 ip route add default via 10.0.0.1\n");

    return 0;
}

int main(void) {
    printf("=== PID Namespace ===\n\n");

    // PID namespace concepts
    printf("PID Namespace Properties:\n");
    printf("  - First process gets PID 1\n");
    printf("  - Acts as init for the namespace\n");
    printf("  - Other PIDs are renumbered\n");
    printf("  - Parent namespace sees all PIDs\n");
    printf("  - Child namespace only sees own PIDs\n");

    printf("\nPID 1 Responsibilities:\n");
    printf("  1. Adopt orphaned processes\n");
    printf("  2. Reap zombie children\n");
    printf("  3. Handle SIGTERM/SIGKILL for namespace\n");
    printf("  4. If PID 1 dies, all namespace processes die\n");

    printf("\nNested PID Namespaces:\n");
    printf("  Parent NS:  PID 100 -> PID 200 -> PID 300\n");
    printf("                 |          |\n");
    printf("  Child NS:      |       PID 1 -> PID 2\n");
    printf("                 |                  |\n");
    printf("  Grandchild:                    PID 1\n");

    printf("\nSignals across namespaces:\n");
    printf("  - SIGKILL and SIGSTOP to PID 1: Special handling\n");
    printf("  - Other signals: Normal delivery\n");
    printf("  - Parent can signal child namespace PIDs\n");
    printf("  - Child cannot signal parent namespace\n");

    // Network namespace concepts
    printf("\n\n=== Network Namespace ===\n\n");

    printf("Network Namespace Isolation:\n");
    printf("  Each namespace has:\n");
    printf("    - Own network interfaces (lo, eth0, etc.)\n");
    printf("    - Own IP addresses\n");
    printf("    - Own routing table\n");
    printf("    - Own firewall rules (iptables)\n");
    printf("    - Own /proc/net\n");

    printf("\nveth (Virtual Ethernet):\n");
    printf("  - Virtual network cable\n");
    printf("  - Two ends, connected like a pipe\n");
    printf("  - One end in each namespace\n");
    printf("  - Packets sent on one appear on other\n");

    printf("\nip netns commands:\n");
    printf("  ip netns add NAME       Create namespace\n");
    printf("  ip netns list           List namespaces\n");
    printf("  ip netns exec NAME CMD  Run command in namespace\n");
    printf("  ip netns delete NAME    Delete namespace\n");
    printf("  ip link set DEV netns NAME  Move interface\n");

    // Run demos if root
    if (geteuid() == 0) {
        demo_pid_namespace();
        demo_network_namespace();
        demo_bridge_networking();
    } else {
        printf("\n\nNote: Run as root to execute namespace demos\n");
        printf("Example commands to try:\n");
        printf("  sudo unshare --pid --fork --mount-proc /bin/bash\n");
        printf("  sudo ip netns add test && sudo ip netns list\n");
    }

    return 0;
}
```

---

## Fichiers

```
ex03/
├── pid_net_ns.h
├── pid_namespace.c
├── net_namespace.c
├── veth_pairs.c
├── bridge_networking.c
└── Makefile
```
