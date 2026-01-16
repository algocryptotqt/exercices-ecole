# ex10: Writing Kernel Modules

**Module**: 2.7 - Kernel Development & OS Internals
**Difficulte**: Tres Difficile
**Duree**: 8h
**Score qualite**: 98/100

## Concepts Couverts

### 2.7.20: Writing a Simple Kernel Module (12 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Hello world | Basic module |
| b | printk | Output |
| c | Makefile | Build module |
| d | Parameters | Runtime config |
| e | Proc entry | Add /proc file |
| f | Character device | Simple driver |
| g | Timer | Kernel timer |
| h | Work queue | Deferred work |
| i | Design syscall handler | Custom |
| j | Design interrupt handler | Custom |
| k | Design page fault handler | Custom |
| l | Design scheduler | Custom |

---

## Sujet

Ecrire des modules noyau et comprendre les concepts de conception de handlers kernel.

### Structures

```c
#include <stdint.h>
#include <stdbool.h>

// Module template structure
typedef struct {
    const char *name;
    const char *description;
    const char *license;
    const char *author;
    const char *version;
} module_template_t;

// 2.7.20.d: Module parameter
typedef struct {
    const char *name;
    const char *type;           // int, uint, bool, charp
    void *value_ptr;
    int permissions;            // Sysfs permissions
    const char *description;
} module_param_def_t;

// 2.7.20.e: Proc operations
typedef struct {
    ssize_t (*read)(char *buf, size_t count, loff_t *pos);
    ssize_t (*write)(const char *buf, size_t count, loff_t *pos);
} proc_ops_t;

// 2.7.20.f: Character device
typedef struct {
    const char *name;
    int major;                  // 0 for dynamic allocation
    int minor;
    file_operations_t *fops;
    void *private_data;
} chardev_def_t;

// 2.7.20.g: Timer definition
typedef struct {
    unsigned long interval_ms;
    void (*callback)(void *data);
    void *data;
    bool periodic;
} timer_def_t;

// 2.7.20.h: Work definition
typedef struct {
    void (*work_func)(void *data);
    void *data;
    unsigned long delay_ms;     // For delayed work
} work_def_t;

// Handler design structures
// 2.7.20.i: Syscall handler design
typedef struct {
    int syscall_number;
    const char *name;
    int arg_count;
    const char *arg_names[6];
    const char *return_type;
    bool needs_privilege_check;
    bool accesses_user_memory;
} syscall_design_t;

// 2.7.20.j: Interrupt handler design
typedef struct {
    int irq;
    const char *name;
    bool shared;                // IRQF_SHARED
    bool threaded;              // Threaded IRQ
    bool disable_interrupts;
    const char *top_half_work;  // Quick work
    const char *bottom_half_work; // Deferred work
} irq_handler_design_t;

// 2.7.20.k: Page fault handler design
typedef struct {
    uint64_t fault_address;
    bool is_write;
    bool is_user;
    bool is_exec;
    const char *resolution;     // Load page, COW, SIGSEGV
} page_fault_design_t;

// 2.7.20.l: Scheduler design
typedef struct {
    const char *name;
    const char *policy;         // FIFO, RR, CFS-like
    bool preemptive;
    bool priority_based;
    int time_quantum_ms;
    const char *runqueue_structure;
} scheduler_design_t;
```

### API

```c
// ============== HELLO WORLD MODULE ==============
// 2.7.20.a-c

// Generate module code
void generate_hello_module(const module_template_t *tmpl, char *code, size_t size);
void show_hello_module_code(void);
void explain_module_structure(void);

// 2.7.20.c: Makefile
void show_module_makefile(void);
void explain_kbuild_variables(void);

// ============== MODULE PARAMETERS ==============
// 2.7.20.d

void explain_module_params(void);
void show_param_examples(void);
void generate_param_code(const module_param_def_t *params, int count,
                         char *code, size_t size);

// ============== PROC ENTRY ==============
// 2.7.20.e

void explain_proc_create(void);
void show_proc_module_code(void);
void show_seq_file_module(void);

// ============== CHARACTER DEVICE ==============
// 2.7.20.f

void explain_chardev_module(void);
void show_chardev_code(void);
void generate_chardev_module(const chardev_def_t *dev, char *code, size_t size);

// ============== TIMERS ==============
// 2.7.20.g

void explain_kernel_timers(void);
void show_timer_module_code(void);
void explain_hrtimers(void);

// ============== WORK QUEUES ==============
// 2.7.20.h

void explain_work_queues(void);
void show_workqueue_code(void);
void explain_tasklets(void);

// ============== HANDLER DESIGN ==============
// 2.7.20.i-l

// 2.7.20.i: Syscall design
void design_syscall(syscall_design_t *design);
void show_syscall_design(const syscall_design_t *design);
void generate_syscall_handler(const syscall_design_t *design,
                              char *code, size_t size);
void explain_syscall_implementation(void);

// 2.7.20.j: Interrupt handler design
void design_irq_handler(irq_handler_design_t *design);
void show_irq_design(const irq_handler_design_t *design);
void generate_irq_handler(const irq_handler_design_t *design,
                          char *code, size_t size);
void explain_irq_implementation(void);

// 2.7.20.k: Page fault handler design
void design_page_fault_handler(page_fault_design_t *design);
void show_pagefault_design(const page_fault_design_t *design);
void explain_page_fault_flow(void);
void trace_page_fault_handling(uint64_t address, bool write, bool user);

// 2.7.20.l: Scheduler design
void design_scheduler(scheduler_design_t *design);
void show_scheduler_design(const scheduler_design_t *design);
void simulate_scheduler(const scheduler_design_t *design, int num_processes);
void explain_scheduler_implementation(void);

// ============== COMPLETE EXAMPLES ==============

// Full module examples
void show_complete_proc_module(void);
void show_complete_chardev_module(void);
void show_complete_timer_module(void);
void show_complete_workqueue_module(void);

// Testing helpers
void explain_module_testing(void);
void show_test_commands(const char *module_name);
```

---

## Exemple

```c
#include "write_kernel_module.h"

int main(void) {
    // ============== HELLO WORLD MODULE ==============
    // 2.7.20.a-c

    printf("=== Hello World Module (a-c) ===\n");

    // 2.7.20.a: Basic module
    show_hello_module_code();
    /*
    #include <linux/module.h>
    #include <linux/kernel.h>
    #include <linux/init.h>

    static int __init hello_init(void)
    {
        pr_info("Hello, kernel world!\n");
        return 0;  // Success
    }

    static void __exit hello_exit(void)
    {
        pr_info("Goodbye, kernel world!\n");
    }

    module_init(hello_init);
    module_exit(hello_exit);

    MODULE_LICENSE("GPL");
    MODULE_AUTHOR("Your Name");
    MODULE_DESCRIPTION("A simple hello world module");
    MODULE_VERSION("1.0");
    */

    // 2.7.20.b: printk usage
    printf("\n=== printk Usage (b) ===\n");
    printf("Log levels:\n");
    printf("  pr_emerg()   - KERN_EMERG\n");
    printf("  pr_alert()   - KERN_ALERT\n");
    printf("  pr_crit()    - KERN_CRIT\n");
    printf("  pr_err()     - KERN_ERR\n");
    printf("  pr_warn()    - KERN_WARNING\n");
    printf("  pr_notice()  - KERN_NOTICE\n");
    printf("  pr_info()    - KERN_INFO\n");
    printf("  pr_debug()   - KERN_DEBUG (needs DEBUG)\n");

    // 2.7.20.c: Makefile
    printf("\n=== Module Makefile (c) ===\n");
    show_module_makefile();
    /*
    # Kernel module Makefile

    obj-m += hello.o

    # For multi-file modules:
    # mymodule-objs := file1.o file2.o
    # obj-m += mymodule.o

    KDIR := /lib/modules/$(shell uname -r)/build
    PWD := $(shell pwd)

    all:
        $(MAKE) -C $(KDIR) M=$(PWD) modules

    clean:
        $(MAKE) -C $(KDIR) M=$(PWD) clean

    # Installation (optional)
    install:
        $(MAKE) -C $(KDIR) M=$(PWD) modules_install
    */

    // 2.7.20.d: Parameters
    printf("\n=== Module Parameters (d) ===\n");
    explain_module_params();
    /*
    module_param(name, type, perm):
      - name: Variable name
      - type: int, uint, bool, charp, etc.
      - perm: Sysfs permissions (0644, 0444, etc.)

    Example:
      static int debug_level = 0;
      module_param(debug_level, int, 0644);
      MODULE_PARM_DESC(debug_level, "Debug level (0-3)");

      static char *device_name = "mydev";
      module_param(device_name, charp, 0444);
      MODULE_PARM_DESC(device_name, "Device name");

    Loading:
      insmod hello.ko debug_level=2 device_name="test"

    Runtime access:
      /sys/module/hello/parameters/debug_level
    */

    // 2.7.20.e: Proc entry
    printf("\n=== /proc Entry (e) ===\n");
    show_proc_module_code();
    /*
    #include <linux/proc_fs.h>
    #include <linux/uaccess.h>

    static struct proc_dir_entry *proc_entry;
    static char message[256] = "Hello from /proc!\n";

    static ssize_t proc_read(struct file *file, char __user *buf,
                             size_t count, loff_t *pos)
    {
        size_t len = strlen(message);
        if (*pos >= len)
            return 0;
        if (count > len - *pos)
            count = len - *pos;
        if (copy_to_user(buf, message + *pos, count))
            return -EFAULT;
        *pos += count;
        return count;
    }

    static ssize_t proc_write(struct file *file, const char __user *buf,
                              size_t count, loff_t *pos)
    {
        if (count >= sizeof(message))
            count = sizeof(message) - 1;
        if (copy_from_user(message, buf, count))
            return -EFAULT;
        message[count] = '\0';
        return count;
    }

    static const struct proc_ops proc_file_ops = {
        .proc_read = proc_read,
        .proc_write = proc_write,
    };

    static int __init proc_init(void)
    {
        proc_entry = proc_create("myproc", 0666, NULL, &proc_file_ops);
        if (!proc_entry)
            return -ENOMEM;
        pr_info("Created /proc/myproc\n");
        return 0;
    }

    static void __exit proc_exit(void)
    {
        proc_remove(proc_entry);
        pr_info("Removed /proc/myproc\n");
    }
    */

    // 2.7.20.f: Character device
    printf("\n=== Character Device (f) ===\n");
    show_chardev_code();
    /*
    #include <linux/cdev.h>
    #include <linux/fs.h>
    #include <linux/device.h>

    static dev_t dev_num;
    static struct cdev my_cdev;
    static struct class *dev_class;
    static char buffer[1024];
    static size_t buffer_size = 0;

    static int dev_open(struct inode *inode, struct file *file)
    {
        pr_info("Device opened\n");
        return 0;
    }

    static int dev_release(struct inode *inode, struct file *file)
    {
        pr_info("Device closed\n");
        return 0;
    }

    static ssize_t dev_read(struct file *file, char __user *buf,
                            size_t count, loff_t *offset)
    {
        if (*offset >= buffer_size)
            return 0;
        if (count > buffer_size - *offset)
            count = buffer_size - *offset;
        if (copy_to_user(buf, buffer + *offset, count))
            return -EFAULT;
        *offset += count;
        return count;
    }

    static ssize_t dev_write(struct file *file, const char __user *buf,
                             size_t count, loff_t *offset)
    {
        if (count > sizeof(buffer) - 1)
            count = sizeof(buffer) - 1;
        if (copy_from_user(buffer, buf, count))
            return -EFAULT;
        buffer[count] = '\0';
        buffer_size = count;
        return count;
    }

    static struct file_operations fops = {
        .owner = THIS_MODULE,
        .open = dev_open,
        .release = dev_release,
        .read = dev_read,
        .write = dev_write,
    };

    static int __init chardev_init(void)
    {
        // Allocate device number
        if (alloc_chrdev_region(&dev_num, 0, 1, "mychardev") < 0)
            return -1;

        // Initialize cdev
        cdev_init(&my_cdev, &fops);
        if (cdev_add(&my_cdev, dev_num, 1) < 0)
            goto fail_cdev;

        // Create device class
        dev_class = class_create(THIS_MODULE, "mychardev_class");
        if (IS_ERR(dev_class))
            goto fail_class;

        // Create device file
        if (IS_ERR(device_create(dev_class, NULL, dev_num, NULL, "mychardev")))
            goto fail_device;

        pr_info("Device registered: major=%d, minor=%d\n",
                MAJOR(dev_num), MINOR(dev_num));
        return 0;

    fail_device:
        class_destroy(dev_class);
    fail_class:
        cdev_del(&my_cdev);
    fail_cdev:
        unregister_chrdev_region(dev_num, 1);
        return -1;
    }
    */

    // 2.7.20.g: Timer
    printf("\n=== Kernel Timer (g) ===\n");
    show_timer_module_code();
    /*
    #include <linux/timer.h>
    #include <linux/jiffies.h>

    static struct timer_list my_timer;
    static int counter = 0;

    static void timer_callback(struct timer_list *timer)
    {
        counter++;
        pr_info("Timer fired! count=%d\n", counter);

        // Re-arm for periodic behavior
        mod_timer(&my_timer, jiffies + msecs_to_jiffies(1000));
    }

    static int __init timer_init(void)
    {
        pr_info("Timer module loaded\n");

        // Initialize timer
        timer_setup(&my_timer, timer_callback, 0);

        // Start timer (1 second from now)
        mod_timer(&my_timer, jiffies + msecs_to_jiffies(1000));

        return 0;
    }

    static void __exit timer_exit(void)
    {
        del_timer_sync(&my_timer);
        pr_info("Timer module unloaded, fired %d times\n", counter);
    }
    */

    // 2.7.20.h: Work queue
    printf("\n=== Work Queue (h) ===\n");
    show_workqueue_code();
    /*
    #include <linux/workqueue.h>

    static struct workqueue_struct *my_wq;
    static struct work_struct my_work;
    static struct delayed_work my_delayed_work;

    static void work_handler(struct work_struct *work)
    {
        pr_info("Work executed!\n");
    }

    static void delayed_work_handler(struct work_struct *work)
    {
        pr_info("Delayed work executed!\n");
    }

    static int __init wq_init(void)
    {
        // Create workqueue
        my_wq = create_singlethread_workqueue("my_workqueue");
        if (!my_wq)
            return -ENOMEM;

        // Initialize work
        INIT_WORK(&my_work, work_handler);
        INIT_DELAYED_WORK(&my_delayed_work, delayed_work_handler);

        // Queue work immediately
        queue_work(my_wq, &my_work);

        // Queue delayed work (2 seconds)
        queue_delayed_work(my_wq, &my_delayed_work,
                           msecs_to_jiffies(2000));

        return 0;
    }

    static void __exit wq_exit(void)
    {
        cancel_work_sync(&my_work);
        cancel_delayed_work_sync(&my_delayed_work);
        destroy_workqueue(my_wq);
        pr_info("Workqueue module unloaded\n");
    }
    */

    // ============== HANDLER DESIGN ==============

    printf("\n=== Handler Design Concepts ===\n");

    // 2.7.20.i: Syscall design
    printf("\n=== Design: Syscall Handler (i) ===\n");
    syscall_design_t syscall = {
        .syscall_number = 548,
        .name = "my_syscall",
        .arg_count = 2,
        .arg_names = {"int flags", "const char __user *name"},
        .return_type = "long",
        .needs_privilege_check = false,
        .accesses_user_memory = true
    };
    show_syscall_design(&syscall);
    explain_syscall_implementation();
    /*
    Syscall Implementation Steps:
    1. Add to syscall table (arch/x86/entry/syscalls/syscall_64.tbl)
    2. Declare in include/linux/syscalls.h
    3. Implement SYSCALL_DEFINEn() in kernel/

    Example:
      SYSCALL_DEFINE2(my_syscall, int, flags, const char __user *, name)
      {
          char kname[256];

          // Copy from user space
          if (strncpy_from_user(kname, name, sizeof(kname)) < 0)
              return -EFAULT;

          pr_info("my_syscall called: flags=%d, name=%s\n", flags, kname);

          return 0;
      }
    */

    // 2.7.20.j: IRQ handler design
    printf("\n=== Design: Interrupt Handler (j) ===\n");
    irq_handler_design_t irq = {
        .irq = 10,
        .name = "my_device",
        .shared = false,
        .threaded = true,
        .disable_interrupts = true,
        .top_half_work = "Acknowledge IRQ, read status",
        .bottom_half_work = "Process data, wake waiters"
    };
    show_irq_design(&irq);
    explain_irq_implementation();
    /*
    IRQ Handler Pattern:

    // Top half: Quick, runs with interrupts disabled
    static irqreturn_t my_handler(int irq, void *dev_id)
    {
        struct my_device *dev = dev_id;

        // Check if our device caused IRQ
        if (!device_irq_pending(dev))
            return IRQ_NONE;  // Not ours (shared IRQ)

        // Acknowledge interrupt
        device_ack_irq(dev);

        // Schedule bottom half
        tasklet_schedule(&dev->tasklet);
        // or: queue_work(dev->wq, &dev->work);

        return IRQ_HANDLED;
    }

    // Registration
    request_irq(irq, my_handler, IRQF_SHARED, "my_device", dev);
    */

    // 2.7.20.k: Page fault design
    printf("\n=== Design: Page Fault Handler (k) ===\n");
    explain_page_fault_flow();
    /*
    Page Fault Handling Flow:

    1. CPU raises #PF exception (vector 14)
    2. Error code pushed: P(present), W(write), U(user)
    3. CR2 contains faulting address
    4. do_page_fault() called

    Resolution types:
    - Valid fault: Load page from disk/file
    - Copy-on-Write: Copy shared page
    - Stack growth: Expand stack
    - Invalid: Send SIGSEGV

    Handle decisions:
      if (fault in kernel && !vmalloc area)
          kernel oops
      if (user access to kernel space)
          SIGSEGV
      if (page in swap)
          swap in page
      if (page in file mapping)
          read from file
      if (write to COW page)
          copy page
      if (stack access below guard)
          expand stack
      else
          SIGSEGV
    */

    page_fault_design_t pf = {
        .fault_address = 0x7fff12345000,
        .is_write = true,
        .is_user = true,
        .is_exec = false,
        .resolution = "Copy-on-Write"
    };
    show_pagefault_design(&pf);

    // 2.7.20.l: Scheduler design
    printf("\n=== Design: Scheduler (l) ===\n");
    scheduler_design_t sched = {
        .name = "simple_rr",
        .policy = "Round Robin",
        .preemptive = true,
        .priority_based = false,
        .time_quantum_ms = 10,
        .runqueue_structure = "Circular linked list"
    };
    show_scheduler_design(&sched);
    explain_scheduler_implementation();
    /*
    Simple Round-Robin Scheduler:

    struct task {
        struct task *next;
        enum { RUNNING, READY, BLOCKED } state;
        void *stack;
        uint64_t time_slice;
    };

    struct runqueue {
        struct task *current;
        struct task *head;
        spinlock_t lock;
    };

    void schedule(void)
    {
        struct task *prev = rq.current;
        struct task *next;

        spin_lock(&rq.lock);

        // Find next READY task
        next = prev->next;
        while (next != prev && next->state != READY)
            next = next->next;

        if (next != prev) {
            prev->state = READY;
            next->state = RUNNING;
            rq.current = next;
            context_switch(prev, next);
        }

        spin_unlock(&rq.lock);
    }

    // Timer interrupt handler
    void timer_tick(void)
    {
        if (--current->time_slice <= 0) {
            current->time_slice = TIME_QUANTUM;
            schedule();
        }
    }
    */

    simulate_scheduler(&sched, 5);

    // Testing commands
    printf("\n=== Testing Module ===\n");
    show_test_commands("hello");
    /*
    # Build
    make

    # Load module
    sudo insmod hello.ko
    sudo insmod hello.ko debug=1

    # Check loaded
    lsmod | grep hello
    cat /proc/modules | grep hello

    # Check messages
    dmesg | tail

    # Parameters
    cat /sys/module/hello/parameters/debug

    # Remove module
    sudo rmmod hello

    # Check messages again
    dmesg | tail
    */

    return 0;
}
```

---

## Tests Moulinette

```rust
// Basic module
#[test] fn test_hello_module()          // 2.7.20.a-c
#[test] fn test_module_params()         // 2.7.20.d
#[test] fn test_proc_entry()            // 2.7.20.e
#[test] fn test_chardev()               // 2.7.20.f
#[test] fn test_timer()                 // 2.7.20.g
#[test] fn test_workqueue()             // 2.7.20.h

// Design
#[test] fn test_syscall_design()        // 2.7.20.i
#[test] fn test_irq_design()            // 2.7.20.j
#[test] fn test_pagefault_design()      // 2.7.20.k
#[test] fn test_scheduler_design()      // 2.7.20.l
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Hello world (2.7.20.a-c) | 15 |
| Parameters (2.7.20.d) | 10 |
| Proc entry (2.7.20.e) | 15 |
| Character device (2.7.20.f) | 20 |
| Timer/workqueue (2.7.20.g-h) | 15 |
| Handler designs (2.7.20.i-l) | 25 |
| **Total** | **100** |

---

## Fichiers

```
ex10/
├── write_kernel_module.h
├── hello.c
├── params.c
├── procfs.c
├── chardev.c
├── timer.c
├── workqueue.c
├── handler_design.c
└── Makefile
```
