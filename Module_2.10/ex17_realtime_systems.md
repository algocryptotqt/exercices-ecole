# ex17: Real-Time Systems

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.30: Real-Time Systems Concepts (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Real-time | Timing constraints |
| b | Hard real-time | Miss = failure |
| c | Soft real-time | Miss = degradation |
| d | Deadline | Must complete by |
| e | Latency | Response time |
| f | Jitter | Latency variation |
| g | Determinism | Predictable timing |

### 2.10.31: Real-Time Scheduling (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Priority | Higher runs first |
| b | Priority inversion | Low blocks high |
| c | Priority inheritance | Boost low temporarily |
| d | Priority ceiling | Max priority of resource |
| e | Rate Monotonic | Shorter period = higher priority |
| f | Earliest Deadline First | Dynamic priority |
| g | Schedulability | Can meet all deadlines |
| h | WCET | Worst-Case Execution Time |

### 2.10.32: Linux Real-Time (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | PREEMPT_RT | Real-time patch |
| b | Fully preemptible | Kernel can be preempted |
| c | SCHED_FIFO | Real-time FIFO |
| d | SCHED_RR | Real-time round-robin |
| e | SCHED_DEADLINE | EDF scheduler |
| f | RT priority | 1-99 (99 highest) |
| g | mlockall() | Lock memory |
| h | CPU isolation | isolcpus |

---

## Sujet

Comprendre les concepts temps-reel et leur implementation sous Linux.

---

## Exemple

```c
#define _GNU_SOURCE
#include "realtime.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <errno.h>

// ============================================
// Real-Time Concepts
// ============================================

void explain_realtime_concepts(void) {
    printf("=== Real-Time Systems ===\n\n");

    printf("Real-time = correctness depends on timing\n");
    printf("  Not just \"fast\", but \"predictable\"\n");

    printf("\nTypes of real-time:\n");

    printf("\nHard Real-Time:\n");
    printf("  - Missing deadline = system failure\n");
    printf("  - Examples:\n");
    printf("    * Airbag deployment\n");
    printf("    * Pacemaker\n");
    printf("    * Industrial robots\n");
    printf("    * Flight control\n");

    printf("\nSoft Real-Time:\n");
    printf("  - Missing deadline = degraded performance\n");
    printf("  - Examples:\n");
    printf("    * Video streaming\n");
    printf("    * Audio playback\n");
    printf("    * Gaming\n");
    printf("    * VoIP\n");

    printf("\nFirm Real-Time:\n");
    printf("  - Late result is worthless (but not dangerous)\n");
    printf("  - Example: Financial transactions\n");
}

void explain_timing_metrics(void) {
    printf("\n=== Timing Metrics ===\n\n");

    printf("Latency:\n");
    printf("  Time from event to response\n");
    printf("  Types:\n");
    printf("    - Interrupt latency: IRQ to handler start\n");
    printf("    - Scheduling latency: Ready to running\n");
    printf("    - End-to-end latency: Event to completion\n");

    printf("\nJitter:\n");
    printf("  Variation in latency\n");
    printf("  Low jitter = predictable timing\n");
    printf("  Example: Audio needs < 1ms jitter\n");

    printf("\nDeadline:\n");
    printf("  Maximum acceptable latency\n");
    printf("  Must complete before deadline\n");

    printf("\nWCET (Worst-Case Execution Time):\n");
    printf("  Maximum time task can take\n");
    printf("  Used for schedulability analysis\n");
    printf("  Hard to determine accurately\n");
}

// ============================================
// Scheduling
// ============================================

void explain_scheduling(void) {
    printf("\n=== Real-Time Scheduling ===\n\n");

    printf("Priority-based Scheduling:\n");
    printf("  Higher priority task preempts lower\n");
    printf("  Linux RT priorities: 1-99 (99 = highest)\n");

    printf("\nScheduling Policies (Linux):\n");

    printf("\nSCHED_FIFO:\n");
    printf("  - First In, First Out\n");
    printf("  - Runs until blocks or higher priority arrives\n");
    printf("  - No time slicing\n");

    printf("\nSCHED_RR:\n");
    printf("  - Round Robin with time quantum\n");
    printf("  - Same priority tasks share CPU\n");
    printf("  - Default quantum: 100ms\n");

    printf("\nSCHED_DEADLINE:\n");
    printf("  - Earliest Deadline First\n");
    printf("  - Parameters: runtime, deadline, period\n");
    printf("  - Best for periodic tasks\n");

    printf("\nSCHED_OTHER (default):\n");
    printf("  - Normal time-sharing (CFS)\n");
    printf("  - Not real-time\n");
}

void explain_priority_inversion(void) {
    printf("\n=== Priority Inversion ===\n\n");

    printf("Problem:\n");
    printf("  High priority task blocked by low priority task\n");
    printf("  Famous example: Mars Pathfinder (1997)\n");

    printf("\nScenario:\n");
    printf("  1. Low (L) acquires mutex\n");
    printf("  2. High (H) preempts L\n");
    printf("  3. H tries to acquire mutex, blocks\n");
    printf("  4. Medium (M) preempts L\n");
    printf("  5. H is blocked by M! (inversion)\n");

    printf("\nSolutions:\n");

    printf("\nPriority Inheritance:\n");
    printf("  - L temporarily gets H's priority\n");
    printf("  - L can't be preempted by M\n");
    printf("  - Linux: PTHREAD_PRIO_INHERIT\n");

    printf("\nPriority Ceiling:\n");
    printf("  - Mutex has maximum priority\n");
    printf("  - Task inherits ceiling when holding mutex\n");
    printf("  - Linux: PTHREAD_PRIO_PROTECT\n");
}

// ============================================
// Linux Real-Time
// ============================================

void explain_linux_rt(void) {
    printf("\n=== Linux Real-Time ===\n\n");

    printf("Standard Linux is NOT hard real-time:\n");
    printf("  - Kernel sections non-preemptible\n");
    printf("  - Interrupt handlers run to completion\n");
    printf("  - Priority inversion in kernel\n");
    printf("  - Unpredictable latency (up to milliseconds)\n");

    printf("\nPREEMPT_RT Patch:\n");
    printf("  - Makes kernel fully preemptible\n");
    printf("  - Converts spinlocks to mutexes\n");
    printf("  - Threaded interrupt handlers\n");
    printf("  - Achieves microsecond latencies\n");

    printf("\nCheck RT kernel:\n");
    printf("  uname -a  # Look for PREEMPT_RT\n");
    printf("  cat /sys/kernel/realtime  # Should be 1\n");
}

// Set real-time scheduling
int set_realtime_priority(int policy, int priority) {
    struct sched_param param;
    param.sched_priority = priority;

    if (sched_setscheduler(0, policy, &param) < 0) {
        perror("sched_setscheduler");
        return -1;
    }

    printf("Set policy=%d priority=%d\n", policy, priority);
    return 0;
}

// Lock memory
int lock_memory(void) {
    if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0) {
        perror("mlockall");
        return -1;
    }
    printf("Memory locked\n");
    return 0;
}

// Stack prefault
void prefault_stack(void) {
    unsigned char stack[8192];
    memset(stack, 0, sizeof(stack));
    printf("Stack prefaulted\n");
}

// Set CPU affinity
int set_cpu_affinity(int cpu) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    if (sched_setaffinity(0, sizeof(cpuset), &cpuset) < 0) {
        perror("sched_setaffinity");
        return -1;
    }

    printf("Pinned to CPU %d\n", cpu);
    return 0;
}

// Demo: RT periodic task
void demo_periodic_task(void) {
    printf("\n=== Periodic RT Task Demo ===\n\n");

    // Check if we can set RT priority
    if (geteuid() != 0) {
        printf("Need root for RT scheduling\n");
        printf("Or set: /etc/security/limits.conf\n");
        printf("  @realtime - rtprio 99\n");
        printf("  @realtime - memlock unlimited\n");
        return;
    }

    // Setup RT
    lock_memory();
    prefault_stack();
    set_cpu_affinity(0);
    set_realtime_priority(SCHED_FIFO, 80);

    // Periodic loop
    struct timespec next, period;
    period.tv_sec = 0;
    period.tv_nsec = 1000000;  // 1ms period

    clock_gettime(CLOCK_MONOTONIC, &next);

    printf("Running 1ms periodic loop for 10 iterations...\n");
    for (int i = 0; i < 10; i++) {
        // Add period
        next.tv_nsec += period.tv_nsec;
        if (next.tv_nsec >= 1000000000) {
            next.tv_sec++;
            next.tv_nsec -= 1000000000;
        }

        // Do work
        printf("  Iteration %d\n", i);

        // Sleep until next period
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL);
    }

    printf("Done\n");
}

// Priority inheritance mutex
void demo_priority_inheritance(void) {
    printf("\n=== Priority Inheritance Mutex ===\n\n");

    pthread_mutexattr_t attr;
    pthread_mutex_t mutex;

    pthread_mutexattr_init(&attr);

    // Set priority inheritance protocol
    if (pthread_mutexattr_setprotocol(&attr, PTHREAD_PRIO_INHERIT) < 0) {
        perror("setprotocol");
        return;
    }

    pthread_mutex_init(&mutex, &attr);
    pthread_mutexattr_destroy(&attr);

    printf("Created mutex with priority inheritance\n");
    printf("Low priority task will inherit high priority when holding mutex\n");

    pthread_mutex_destroy(&mutex);
}

void show_rt_best_practices(void) {
    printf("\n=== Real-Time Best Practices ===\n\n");

    printf("1. Lock memory:\n");
    printf("   mlockall(MCL_CURRENT | MCL_FUTURE);\n");

    printf("\n2. Prefault stack:\n");
    printf("   unsigned char stack[STACK_SIZE];\n");
    printf("   memset(stack, 0, sizeof(stack));\n");

    printf("\n3. Pre-allocate all memory:\n");
    printf("   Avoid malloc/free in RT path\n");

    printf("\n4. Pin to CPU:\n");
    printf("   sched_setaffinity(...);\n");
    printf("   Or boot with isolcpus=1,2\n");

    printf("\n5. Use clock_nanosleep for periodic tasks:\n");
    printf("   Use CLOCK_MONOTONIC + TIMER_ABSTIME\n");

    printf("\n6. Avoid priority inversion:\n");
    printf("   Use PTHREAD_PRIO_INHERIT\n");

    printf("\n7. Disable CPU frequency scaling:\n");
    printf("   cpupower frequency-set -g performance\n");

    printf("\n8. Disable hyperthreading (optional):\n");
    printf("   echo off > /sys/devices/system/cpu/smt/control\n");
}

int main(void) {
    explain_realtime_concepts();
    explain_timing_metrics();
    explain_scheduling();
    explain_priority_inversion();
    explain_linux_rt();

    if (geteuid() == 0) {
        demo_periodic_task();
    }

    demo_priority_inheritance();
    show_rt_best_practices();

    return 0;
}
```

---

## Fichiers

```
ex17/
├── realtime.h
├── rt_concepts.c
├── scheduling.c
├── priority_inversion.c
├── linux_rt.c
├── rt_demo.c
└── Makefile
```
