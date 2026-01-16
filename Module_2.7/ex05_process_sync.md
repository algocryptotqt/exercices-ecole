# ex05: Process Management & Kernel Synchronization

**Module**: 2.7 - Kernel Development & OS Internals
**Difficulte**: Difficile
**Duree**: 6h
**Score qualite**: 97/100

## Concepts Couverts

### 2.7.10: Process Management in Kernel (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | task_struct | Process descriptor |
| b | current | Current process macro |
| c | Process list | Linked list |
| d | PID hash | Fast lookup |
| e | Kernel thread | No user space |
| f | kthreadd | Kernel thread parent |
| g | Idle process | PID 0 |
| h | Init process | PID 1 |

### 2.7.11: Kernel Synchronization (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Atomic operations | atomic_t |
| b | Spinlocks | spin_lock/spin_unlock |
| c | Read-write spinlocks | Multiple readers |
| d | Semaphores | down/up |
| e | Mutexes | mutex_lock/unlock |
| f | RCU | Read-Copy-Update |
| g | Per-CPU data | No locking needed |
| h | Memory barriers | Ordering |
| i | Preemption control | preempt_disable |

---

## Sujet

Comprendre la gestion des processus et la synchronisation dans le noyau.

### Structures

```c
#include <stdint.h>

// 2.7.10.a: task_struct (simplified)
typedef struct task_struct {
    volatile int state;
    void *stack;
    pid_t pid;
    pid_t tgid;
    struct task_struct *parent;
    struct task_struct *children;
    struct task_struct *sibling;
    struct task_struct *group_leader;
    char comm[16];           // Task name
    // Memory
    void *mm;                // Memory descriptor
    // Scheduling
    int prio;
    uint64_t utime, stime;
    // Files
    void *files;
    // Links
    struct task_struct *next;
    struct task_struct *prev;
} task_struct_t;

// 2.7.11.a: Atomic types
typedef struct {
    volatile int counter;
} atomic_t;

typedef struct {
    volatile long counter;
} atomic64_t;

// 2.7.11.b: Spinlock
typedef struct {
    volatile int locked;
    // Debug info
    const char *owner;
    uint64_t lock_time;
} spinlock_t;

// 2.7.11.c: RW spinlock
typedef struct {
    volatile int readers;
    volatile int writer;
} rwlock_t;

// 2.7.11.d: Semaphore
typedef struct {
    int count;
    spinlock_t lock;
    void *wait_list;
} semaphore_t;

// 2.7.11.e: Mutex
typedef struct {
    atomic_t count;
    spinlock_t wait_lock;
    void *owner;
    void *wait_list;
} mutex_t;
```

### API

```c
// ============== PROCESS MANAGEMENT ==============
// 2.7.10

// 2.7.10.a: task_struct access
task_struct_t *get_task_by_pid(pid_t pid);
void print_task_struct(const task_struct_t *task);

// 2.7.10.b: Current process
task_struct_t *get_current(void);
pid_t current_pid(void);
const char *current_comm(void);

// 2.7.10.c: Process list
int get_all_tasks(task_struct_t ***tasks, int *count);
void for_each_process(void (*callback)(task_struct_t *));

// 2.7.10.d: PID lookup
task_struct_t *find_task_by_vpid(pid_t pid);

// 2.7.10.e-f: Kernel threads
int get_kernel_threads(task_struct_t ***threads, int *count);
bool is_kernel_thread(const task_struct_t *task);
void print_kernel_threads(void);

// 2.7.10.g-h: Special processes
task_struct_t *get_idle_task(void);
task_struct_t *get_init_task(void);
void explain_special_processes(void);

// ============== ATOMIC OPERATIONS ==============
// 2.7.11.a

void atomic_set(atomic_t *v, int i);
int atomic_read(const atomic_t *v);
void atomic_add(int i, atomic_t *v);
void atomic_sub(int i, atomic_t *v);
void atomic_inc(atomic_t *v);
void atomic_dec(atomic_t *v);
int atomic_dec_and_test(atomic_t *v);
int atomic_cmpxchg(atomic_t *v, int old, int new);

// ============== SPINLOCKS ==============
// 2.7.11.b-c

void spin_lock_init(spinlock_t *lock);
void spin_lock(spinlock_t *lock);
void spin_unlock(spinlock_t *lock);
int spin_trylock(spinlock_t *lock);
void spin_lock_irq(spinlock_t *lock);
void spin_unlock_irq(spinlock_t *lock);

// 2.7.11.c: Read-write spinlocks
void rwlock_init(rwlock_t *lock);
void read_lock(rwlock_t *lock);
void read_unlock(rwlock_t *lock);
void write_lock(rwlock_t *lock);
void write_unlock(rwlock_t *lock);

// ============== SEMAPHORES & MUTEXES ==============
// 2.7.11.d-e

void sema_init(semaphore_t *sem, int val);
void down(semaphore_t *sem);
int down_trylock(semaphore_t *sem);
void up(semaphore_t *sem);

void mutex_init(mutex_t *mutex);
void mutex_lock(mutex_t *mutex);
void mutex_unlock(mutex_t *mutex);
int mutex_trylock(mutex_t *mutex);

// Compare locking mechanisms
void compare_locks(void);

// ============== RCU ==============
// 2.7.11.f

void rcu_read_lock(void);
void rcu_read_unlock(void);
void synchronize_rcu(void);
void explain_rcu(void);

// ============== PER-CPU & BARRIERS ==============
// 2.7.11.g-i

// 2.7.11.g: Per-CPU data
void *alloc_percpu(size_t size);
void free_percpu(void *ptr);
void *get_cpu_ptr(void *percpu);
void put_cpu_ptr(void *percpu);
void explain_percpu(void);

// 2.7.11.h: Memory barriers
void smp_mb(void);           // Full barrier
void smp_rmb(void);          // Read barrier
void smp_wmb(void);          // Write barrier
void explain_barriers(void);

// 2.7.11.i: Preemption
void preempt_disable(void);
void preempt_enable(void);
int preemptible(void);
void explain_preemption(void);
```

---

## Exemple

```c
#include "process_sync.h"

int main(void) {
    // ============== PROCESS MANAGEMENT ==============
    // 2.7.10

    printf("=== Process Management in Kernel ===\n");

    // 2.7.10.a: task_struct
    printf("\n=== task_struct (a) ===\n");
    printf("task_struct is the process descriptor containing:\n");
    printf("  - State, PID, TGID\n");
    printf("  - Parent/children/sibling pointers\n");
    printf("  - Memory descriptor (mm)\n");
    printf("  - File descriptors (files)\n");
    printf("  - Scheduling info\n");

    task_struct_t *task = get_task_by_pid(1);
    if (task) {
        print_task_struct(task);
    }

    // 2.7.10.b: current
    printf("\n=== current Macro (b) ===\n");
    printf("current = pointer to current task's task_struct\n");
    printf("  PID: %d\n", current_pid());
    printf("  Comm: %s\n", current_comm());

    // 2.7.10.c: Process list
    printf("\n=== Process List (c) ===\n");
    task_struct_t **all_tasks;
    int count;
    get_all_tasks(&all_tasks, &count);
    printf("Total processes: %d\n", count);

    // 2.7.10.d: PID lookup
    printf("\n=== PID Hash (d) ===\n");
    printf("Kernel uses hash table for O(1) PID lookup\n");
    task_struct_t *found = find_task_by_vpid(1);
    printf("PID 1: %s\n", found ? found->comm : "not found");

    // 2.7.10.e-f: Kernel threads
    printf("\n=== Kernel Threads (e-f) ===\n");
    print_kernel_threads();
    /*
    PID   Name
    2     kthreadd (f: kernel thread parent)
    3     rcu_gp
    4     rcu_par_gp
    ...
    */
    printf("\nKernel threads (e) have no user space (mm = NULL)\n");
    printf("kthreadd (f) is parent of all kernel threads\n");

    // 2.7.10.g-h: Special processes
    printf("\n=== Special Processes (g-h) ===\n");
    explain_special_processes();
    /*
    PID 0 - Idle/Swapper (g):
      - Not a real process
      - Runs when no other task ready
      - One per CPU

    PID 1 - Init (h):
      - First user process
      - Parent of orphaned processes
      - systemd on modern Linux
    */

    // ============== KERNEL SYNCHRONIZATION ==============
    // 2.7.11

    printf("\n=== Kernel Synchronization ===\n");

    // 2.7.11.a: Atomic operations
    printf("\n=== Atomic Operations (a) ===\n");
    atomic_t counter = {0};
    atomic_set(&counter, 10);
    atomic_inc(&counter);
    atomic_add(5, &counter);
    printf("Counter: %d\n", atomic_read(&counter));  // 16

    printf("\nAtomic operations:\n");
    printf("  atomic_inc: Increment atomically\n");
    printf("  atomic_dec_and_test: Decrement and return true if zero\n");
    printf("  atomic_cmpxchg: Compare and exchange\n");

    // 2.7.11.b: Spinlocks
    printf("\n=== Spinlocks (b) ===\n");
    printf("Spinlock: Busy-wait lock for short critical sections\n");
    printf("  spin_lock(): Acquire, spin if contended\n");
    printf("  spin_unlock(): Release\n");
    printf("  spin_lock_irq(): Disable interrupts + acquire\n");
    printf("\nUse when: Short critical section, cannot sleep\n");

    // 2.7.11.c: RW spinlocks
    printf("\n=== Read-Write Spinlocks (c) ===\n");
    printf("Multiple readers OR one writer:\n");
    printf("  read_lock(): Acquire for reading\n");
    printf("  write_lock(): Acquire for writing\n");
    printf("\nUse when: Reads >> writes\n");

    // 2.7.11.d-e: Semaphores vs Mutexes
    printf("\n=== Semaphores vs Mutexes (d-e) ===\n");
    compare_locks();
    /*
    Semaphore (d):
      - Can have count > 1
      - down()/up()
      - Can sleep
      - No ownership tracking

    Mutex (e):
      - Binary only (count = 0 or 1)
      - mutex_lock()/mutex_unlock()
      - Can sleep
      - Owner tracking, debugging support
      - Preferred for mutual exclusion
    */

    // 2.7.11.f: RCU
    printf("\n=== Read-Copy-Update (f) ===\n");
    explain_rcu();
    /*
    RCU for read-mostly data:
      - Readers: rcu_read_lock() (very cheap)
      - Writers: Copy, modify, update pointer
      - Wait for readers: synchronize_rcu()
      - Free old data after grace period

    Benefits:
      - Readers never block
      - Almost zero overhead for reads
    */

    // 2.7.11.g: Per-CPU data
    printf("\n=== Per-CPU Data (g) ===\n");
    explain_percpu();
    /*
    Per-CPU variables:
      - One copy per CPU
      - No locking needed (each CPU accesses its own)
      - Must disable preemption during access

    DEFINE_PER_CPU(int, counter);
    get_cpu_var(counter)++;
    put_cpu_var(counter);
    */

    // 2.7.11.h: Memory barriers
    printf("\n=== Memory Barriers (h) ===\n");
    explain_barriers();
    /*
    CPU/compiler may reorder memory operations
    Barriers ensure ordering:
      smp_mb(): Full memory barrier
      smp_rmb(): Read barrier (loads)
      smp_wmb(): Write barrier (stores)

    Example:
      x = 1;
      smp_wmb();  // Ensure x=1 visible before flag=1
      flag = 1;
    */

    // 2.7.11.i: Preemption control
    printf("\n=== Preemption Control (i) ===\n");
    explain_preemption();
    /*
    Preemption = scheduler can switch tasks anytime
    Disable when accessing per-CPU data:
      preempt_disable();
      // Access per-CPU variable
      preempt_enable();

    Spinlocks implicitly disable preemption
    */

    return 0;
}
```

---

## Tests Moulinette

```rust
// Process management
#[test] fn test_task_struct()           // 2.7.10.a
#[test] fn test_current()               // 2.7.10.b
#[test] fn test_process_list()          // 2.7.10.c
#[test] fn test_pid_lookup()            // 2.7.10.d
#[test] fn test_kernel_threads()        // 2.7.10.e-f
#[test] fn test_special_processes()     // 2.7.10.g-h

// Synchronization
#[test] fn test_atomic_ops()            // 2.7.11.a
#[test] fn test_spinlocks()             // 2.7.11.b-c
#[test] fn test_semaphores()            // 2.7.11.d
#[test] fn test_mutexes()               // 2.7.11.e
#[test] fn test_rcu()                   // 2.7.11.f
#[test] fn test_percpu()                // 2.7.11.g
```

---

## Bareme

| Critere | Points |
|---------|--------|
| task_struct/current (2.7.10.a-b) | 15 |
| Process list/lookup (2.7.10.c-d) | 10 |
| Kernel threads (2.7.10.e-h) | 10 |
| Atomic/spinlocks (2.7.11.a-c) | 25 |
| Semaphores/mutexes (2.7.11.d-e) | 15 |
| RCU/percpu/barriers (2.7.11.f-i) | 25 |
| **Total** | **100** |

---

## Fichiers

```
ex05/
├── process_sync.h
├── process.c
├── atomic.c
├── spinlock.c
├── semaphore.c
├── mutex.c
├── rcu.c
└── Makefile
```
