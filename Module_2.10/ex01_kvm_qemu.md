# ex01: KVM Architecture & QEMU

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.4: KVM Architecture (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | KVM module | Kernel module |
| b | /dev/kvm | Device interface |
| c | ioctl interface | Control VMs |
| d | KVM_CREATE_VM | Create VM |
| e | KVM_CREATE_VCPU | Create virtual CPU |
| f | KVM_RUN | Execute guest |
| g | Memory regions | Guest memory |
| h | MMIO | Memory-mapped I/O |
| i | PIO | Port I/O |

### 2.10.5: QEMU (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | QEMU | Quick Emulator |
| b | Full emulation | Without KVM |
| c | KVM acceleration | With KVM |
| d | Device emulation | Virtual hardware |
| e | virtio | Paravirtualized I/O |
| f | QEMU monitor | Control interface |
| g | Disk images | qcow2 format |
| h | Snapshots | VM state save |

---

## Sujet

Maitriser l'architecture KVM et l'utilisation de QEMU.

---

## Exemple

```c
#include "kvm_qemu.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/kvm.h>

// Simple KVM VM example
typedef struct {
    int kvm_fd;
    int vm_fd;
    int vcpu_fd;
    void *mem;
    size_t mem_size;
    struct kvm_run *run;
    size_t run_size;
} simple_vm_t;

// Minimal 16-bit code: in al, dx; hlt
static const uint8_t guest_code[] = {
    0xba, 0xf8, 0x03,  // mov dx, 0x3f8 (COM1)
    0xb0, 'H',         // mov al, 'H'
    0xee,              // out dx, al
    0xb0, 'i',         // mov al, 'i'
    0xee,              // out dx, al
    0xb0, '!',         // mov al, '!'
    0xee,              // out dx, al
    0xb0, '\n',        // mov al, '\n'
    0xee,              // out dx, al
    0xf4,              // hlt
};

int vm_create(simple_vm_t *vm) {
    // Open /dev/kvm
    vm->kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (vm->kvm_fd < 0) {
        perror("open /dev/kvm");
        return -1;
    }

    // Check API version
    int api_ver = ioctl(vm->kvm_fd, KVM_GET_API_VERSION, 0);
    if (api_ver != KVM_API_VERSION) {
        fprintf(stderr, "KVM API version mismatch: %d vs %d\n",
                api_ver, KVM_API_VERSION);
        return -1;
    }

    // Create VM
    vm->vm_fd = ioctl(vm->kvm_fd, KVM_CREATE_VM, 0);
    if (vm->vm_fd < 0) {
        perror("KVM_CREATE_VM");
        return -1;
    }

    // Allocate guest memory (1 MB)
    vm->mem_size = 0x100000;
    vm->mem = mmap(NULL, vm->mem_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (vm->mem == MAP_FAILED) {
        perror("mmap guest memory");
        return -1;
    }

    // Load guest code at 0x1000
    memcpy((uint8_t *)vm->mem + 0x1000, guest_code, sizeof(guest_code));

    // Register memory with KVM
    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .flags = 0,
        .guest_phys_addr = 0,
        .memory_size = vm->mem_size,
        .userspace_addr = (uint64_t)vm->mem,
    };

    if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        perror("KVM_SET_USER_MEMORY_REGION");
        return -1;
    }

    // Create vCPU
    vm->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vm->vcpu_fd < 0) {
        perror("KVM_CREATE_VCPU");
        return -1;
    }

    // Get vCPU mmap size
    vm->run_size = ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (vm->run_size < sizeof(struct kvm_run)) {
        fprintf(stderr, "KVM_GET_VCPU_MMAP_SIZE too small\n");
        return -1;
    }

    // mmap the kvm_run structure
    vm->run = mmap(NULL, vm->run_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED, vm->vcpu_fd, 0);
    if (vm->run == MAP_FAILED) {
        perror("mmap kvm_run");
        return -1;
    }

    return 0;
}

int vm_setup_regs(simple_vm_t *vm) {
    // Set up segment registers for real mode
    struct kvm_sregs sregs;

    if (ioctl(vm->vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
        perror("KVM_GET_SREGS");
        return -1;
    }

    // Code segment: base 0, limit 0xFFFF
    sregs.cs.base = 0;
    sregs.cs.limit = 0xFFFF;
    sregs.cs.selector = 0;

    // Data segment
    sregs.ds.base = 0;
    sregs.ds.limit = 0xFFFF;
    sregs.ds.selector = 0;

    sregs.es = sregs.ds;
    sregs.fs = sregs.ds;
    sregs.gs = sregs.ds;
    sregs.ss = sregs.ds;

    if (ioctl(vm->vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
        perror("KVM_SET_SREGS");
        return -1;
    }

    // Set up general purpose registers
    struct kvm_regs regs = {
        .rip = 0x1000,    // Start at our code
        .rflags = 0x2,    // Required bit
    };

    if (ioctl(vm->vcpu_fd, KVM_SET_REGS, &regs) < 0) {
        perror("KVM_SET_REGS");
        return -1;
    }

    return 0;
}

int vm_run(simple_vm_t *vm) {
    printf("Starting VM execution...\n");

    while (1) {
        if (ioctl(vm->vcpu_fd, KVM_RUN, 0) < 0) {
            perror("KVM_RUN");
            return -1;
        }

        switch (vm->run->exit_reason) {
            case KVM_EXIT_HLT:
                printf("\nVM halted (HLT instruction)\n");
                return 0;

            case KVM_EXIT_IO:
                if (vm->run->io.direction == KVM_EXIT_IO_OUT &&
                    vm->run->io.port == 0x3f8) {  // COM1
                    // Get the data
                    char *data = (char *)vm->run +
                                 vm->run->io.data_offset;
                    for (uint32_t i = 0; i < vm->run->io.count; i++) {
                        putchar(data[i]);
                    }
                    fflush(stdout);
                }
                break;

            case KVM_EXIT_MMIO:
                printf("MMIO: addr=0x%llx len=%d is_write=%d\n",
                       vm->run->mmio.phys_addr,
                       vm->run->mmio.len,
                       vm->run->mmio.is_write);
                break;

            case KVM_EXIT_FAIL_ENTRY:
                printf("KVM_EXIT_FAIL_ENTRY: reason=0x%llx\n",
                       vm->run->fail_entry.hardware_entry_failure_reason);
                return -1;

            case KVM_EXIT_INTERNAL_ERROR:
                printf("KVM_EXIT_INTERNAL_ERROR: suberror=%d\n",
                       vm->run->internal.suberror);
                return -1;

            default:
                printf("Unhandled exit: %d\n", vm->run->exit_reason);
                return -1;
        }
    }
}

void vm_destroy(simple_vm_t *vm) {
    if (vm->run) munmap(vm->run, vm->run_size);
    if (vm->mem) munmap(vm->mem, vm->mem_size);
    if (vm->vcpu_fd >= 0) close(vm->vcpu_fd);
    if (vm->vm_fd >= 0) close(vm->vm_fd);
    if (vm->kvm_fd >= 0) close(vm->kvm_fd);
}

int main(void) {
    printf("=== KVM Architecture ===\n\n");

    // KVM overview
    printf("KVM Components:\n");
    printf("  /dev/kvm: Main interface\n");
    printf("  kvm-intel.ko / kvm-amd.ko: CPU-specific modules\n");
    printf("  kvm.ko: Core module\n");

    printf("\n  KVM ioctl API:\n");
    printf("    System ioctls on /dev/kvm:\n");
    printf("      KVM_GET_API_VERSION\n");
    printf("      KVM_CREATE_VM\n");
    printf("      KVM_CHECK_EXTENSION\n");
    printf("    VM ioctls on vm fd:\n");
    printf("      KVM_CREATE_VCPU\n");
    printf("      KVM_SET_USER_MEMORY_REGION\n");
    printf("      KVM_CREATE_IRQCHIP\n");
    printf("    vCPU ioctls on vcpu fd:\n");
    printf("      KVM_RUN\n");
    printf("      KVM_GET_REGS / KVM_SET_REGS\n");
    printf("      KVM_GET_SREGS / KVM_SET_SREGS\n");

    // Memory management
    printf("\n\n=== KVM Memory Management ===\n\n");

    printf("Guest Memory Setup:\n");
    printf("  1. Allocate memory in userspace (mmap)\n");
    printf("  2. Register with KVM_SET_USER_MEMORY_REGION\n");
    printf("  3. KVM maps guest physical to host virtual\n");

    printf("\n  Memory Region Structure:\n");
    printf("    slot: Region identifier\n");
    printf("    flags: KVM_MEM_LOG_DIRTY_PAGES, etc.\n");
    printf("    guest_phys_addr: Guest physical address\n");
    printf("    memory_size: Size in bytes\n");
    printf("    userspace_addr: Host virtual address\n");

    printf("\n  Memory Types:\n");
    printf("    Regular RAM: Normal guest memory\n");
    printf("    MMIO: Memory-mapped I/O (device registers)\n");
    printf("    ROM: Read-only (BIOS, firmware)\n");

    // QEMU
    printf("\n\n=== QEMU ===\n\n");

    printf("QEMU (Quick Emulator):\n");
    printf("  Full system emulator\n");
    printf("  Can run without KVM (pure emulation)\n");
    printf("  With KVM: Uses hardware acceleration\n");

    printf("\n  Device Emulation:\n");
    printf("    - Serial ports (UART)\n");
    printf("    - Storage (IDE, SCSI, NVMe)\n");
    printf("    - Network (e1000, rtl8139)\n");
    printf("    - Graphics (VGA, virtio-gpu)\n");
    printf("    - USB\n");

    printf("\n  virtio (Paravirtualized I/O):\n");
    printf("    Guest-aware devices\n");
    printf("    Much better performance\n");
    printf("    Types:\n");
    printf("      - virtio-blk: Block devices\n");
    printf("      - virtio-net: Network\n");
    printf("      - virtio-console: Console\n");
    printf("      - virtio-balloon: Memory management\n");
    printf("      - virtio-gpu: Graphics\n");

    // QEMU usage
    printf("\n\n=== QEMU Usage ===\n\n");

    printf("Basic Commands:\n");
    printf("  # Create disk image\n");
    printf("  qemu-img create -f qcow2 disk.qcow2 10G\n");
    printf("\n");
    printf("  # Run VM with KVM\n");
    printf("  qemu-system-x86_64 \\\n");
    printf("    -enable-kvm \\\n");
    printf("    -m 2G \\\n");
    printf("    -smp 2 \\\n");
    printf("    -drive file=disk.qcow2,format=qcow2 \\\n");
    printf("    -cdrom install.iso\n");
    printf("\n");
    printf("  # With virtio\n");
    printf("  qemu-system-x86_64 \\\n");
    printf("    -enable-kvm \\\n");
    printf("    -m 2G \\\n");
    printf("    -drive file=disk.qcow2,if=virtio \\\n");
    printf("    -netdev user,id=net0 \\\n");
    printf("    -device virtio-net,netdev=net0\n");

    printf("\nQEMU Monitor:\n");
    printf("  Ctrl+Alt+2: Switch to monitor\n");
    printf("  Commands:\n");
    printf("    info status: VM status\n");
    printf("    info cpus: CPU info\n");
    printf("    info mem: Memory mappings\n");
    printf("    savevm name: Save snapshot\n");
    printf("    loadvm name: Load snapshot\n");
    printf("    stop: Pause VM\n");
    printf("    cont: Resume VM\n");
    printf("    quit: Exit QEMU\n");

    printf("\nDisk Images:\n");
    printf("  qcow2: QEMU native format\n");
    printf("    - Sparse (grows on demand)\n");
    printf("    - Snapshots\n");
    printf("    - Compression\n");
    printf("    - Encryption\n");
    printf("  raw: Direct disk image\n");
    printf("  vmdk: VMware format\n");
    printf("  vdi: VirtualBox format\n");

    // Run simple VM
    printf("\n\n=== Simple KVM VM ===\n\n");

    simple_vm_t vm = {
        .kvm_fd = -1,
        .vm_fd = -1,
        .vcpu_fd = -1,
    };

    if (vm_create(&vm) < 0) {
        printf("Failed to create VM\n");
        vm_destroy(&vm);
        return 1;
    }

    if (vm_setup_regs(&vm) < 0) {
        printf("Failed to setup registers\n");
        vm_destroy(&vm);
        return 1;
    }

    printf("Guest output: ");
    if (vm_run(&vm) < 0) {
        printf("VM execution failed\n");
    }

    vm_destroy(&vm);
    printf("VM destroyed\n");

    return 0;
}
```

---

## Fichiers

```
ex01/
├── kvm_qemu.h
├── kvm_simple.c
├── kvm_memory.c
├── qemu_basics.c
└── Makefile
```
