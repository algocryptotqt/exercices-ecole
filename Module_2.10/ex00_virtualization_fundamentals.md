# ex00: Virtualization Fundamentals

**Module**: 2.10 - Containers, Virtualization & Advanced
**Difficulte**: Intermediaire
**Duree**: 4h
**Score qualite**: 96/100

## Concepts Couverts

### 2.10.1: Virtualization Concepts (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Virtualization | Abstract hardware |
| b | Virtual machine | Simulated computer |
| c | Guest OS | OS in VM |
| d | Host OS | OS running hypervisor |
| e | Hypervisor | VM manager |
| f | Full virtualization | Complete simulation |
| g | Paravirtualization | Modified guest |
| h | Hardware virtualization | CPU support |

### 2.10.2: Hypervisor Types (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Type 1 | Bare-metal |
| b | Type 1 examples | VMware ESXi, Xen, Hyper-V |
| c | Type 2 | Hosted |
| d | Type 2 examples | VirtualBox, VMware Workstation |
| e | KVM | Kernel-based VM |
| f | KVM type | Hybrid (Type 1.5) |
| g | QEMU | Hardware emulator |
| h | KVM + QEMU | Common combination |

### 2.10.3: Hardware Virtualization Extensions (10 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| a | Intel VT-x | Intel extension |
| b | AMD-V | AMD extension |
| c | VMX | Virtual Machine Extensions |
| d | Root mode | Hypervisor mode |
| e | Non-root mode | Guest mode |
| f | VMCS | VM Control Structure |
| g | VM entry | Enter guest |
| h | VM exit | Return to hypervisor |
| i | EPT | Extended Page Tables |
| j | NPT | Nested Page Tables (AMD) |

---

## Sujet

Comprendre les concepts fondamentaux de la virtualisation et les extensions materiel.

---

## Exemple

```c
#include "virtualization.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/kvm.h>
#include <cpuid.h>

// Check if CPU supports virtualization
int check_virtualization_support(void) {
    unsigned int eax, ebx, ecx, edx;

    // Check CPUID for VMX (Intel) or SVM (AMD)
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        if (ecx & (1 << 5)) {
            printf("Intel VT-x (VMX) supported\n");
            return 1;
        }
    }

    // Check for AMD SVM
    if (__get_cpuid(0x80000001, &eax, &ebx, &ecx, &edx)) {
        if (ecx & (1 << 2)) {
            printf("AMD-V (SVM) supported\n");
            return 2;
        }
    }

    printf("No hardware virtualization support\n");
    return 0;
}

// Check KVM availability
int check_kvm_available(void) {
    int kvm_fd = open("/dev/kvm", O_RDWR);
    if (kvm_fd < 0) {
        perror("Cannot open /dev/kvm");
        printf("KVM not available. Reasons:\n");
        printf("  - Module not loaded (modprobe kvm_intel or kvm_amd)\n");
        printf("  - Virtualization disabled in BIOS\n");
        printf("  - Insufficient permissions\n");
        return -1;
    }

    // Get KVM API version
    int version = ioctl(kvm_fd, KVM_GET_API_VERSION, 0);
    printf("KVM API version: %d\n", version);

    // Check for required extensions
    int extensions[] = {
        KVM_CAP_USER_MEMORY,
        KVM_CAP_SET_TSS_ADDR,
        KVM_CAP_EXT_CPUID,
        KVM_CAP_NR_VCPUS,
        KVM_CAP_MAX_VCPUS
    };
    const char *ext_names[] = {
        "USER_MEMORY",
        "SET_TSS_ADDR",
        "EXT_CPUID",
        "NR_VCPUS",
        "MAX_VCPUS"
    };

    printf("\nKVM Capabilities:\n");
    for (size_t i = 0; i < sizeof(extensions)/sizeof(extensions[0]); i++) {
        int cap = ioctl(kvm_fd, KVM_CHECK_EXTENSION, extensions[i]);
        printf("  %s: %s", ext_names[i], cap ? "supported" : "not supported");
        if (cap > 1) printf(" (value: %d)", cap);
        printf("\n");
    }

    close(kvm_fd);
    return 0;
}

int main(void) {
    printf("=== Virtualization Concepts ===\n\n");

    // What is virtualization
    printf("What is Virtualization?\n");
    printf("  Running multiple OS/environments on single hardware\n");
    printf("  Abstraction layer between hardware and software\n");
    printf("  Resource sharing and isolation\n");

    printf("\nKey Components:\n");
    printf("  Host: Physical machine running hypervisor\n");
    printf("  Guest: Virtual machine (OS + applications)\n");
    printf("  Hypervisor: Software managing VMs\n");

    // Virtualization types
    printf("\n\n=== Virtualization Types ===\n\n");

    printf("Full Virtualization:\n");
    printf("  Complete hardware simulation\n");
    printf("  Guest OS unmodified\n");
    printf("  Binary translation or hardware assist\n");
    printf("  Examples: VMware, VirtualBox, KVM\n");

    printf("\nParavirtualization:\n");
    printf("  Guest OS modified for virtualization\n");
    printf("  Hypercalls instead of privileged instructions\n");
    printf("  Better performance, less compatibility\n");
    printf("  Examples: Xen (PV mode), virtio\n");

    printf("\nHardware-Assisted Virtualization:\n");
    printf("  CPU provides virtualization instructions\n");
    printf("  Intel VT-x, AMD-V\n");
    printf("  Best of both worlds\n");
    printf("  Most modern VMs use this\n");

    // Hypervisor types
    printf("\n\n=== Hypervisor Types ===\n\n");

    printf("Type 1 (Bare-metal):\n");
    printf("  Runs directly on hardware\n");
    printf("  No host OS\n");
    printf("  Better performance and security\n");
    printf("  Examples:\n");
    printf("    - VMware ESXi\n");
    printf("    - Microsoft Hyper-V\n");
    printf("    - Xen\n");
    printf("    - KVM (often considered Type 1.5)\n");

    printf("\nType 2 (Hosted):\n");
    printf("  Runs on top of host OS\n");
    printf("  Uses host OS for hardware access\n");
    printf("  Easier to install/use\n");
    printf("  Examples:\n");
    printf("    - VirtualBox\n");
    printf("    - VMware Workstation\n");
    printf("    - QEMU (without KVM)\n");
    printf("    - Parallels Desktop\n");

    printf("\nKVM (Kernel-based Virtual Machine):\n");
    printf("  Linux kernel module\n");
    printf("  Turns Linux into Type 1 hypervisor\n");
    printf("  Uses hardware virtualization\n");
    printf("  Often paired with QEMU for device emulation\n");

    // Hardware extensions
    printf("\n\n=== Hardware Virtualization Extensions ===\n\n");

    printf("Intel VT-x (VMX):\n");
    printf("  VMX root mode: Hypervisor runs here\n");
    printf("  VMX non-root mode: Guest runs here\n");
    printf("  VMCS: Control structure for VM state\n");
    printf("  VMXON: Enable VMX operation\n");
    printf("  VMLAUNCH/VMRESUME: Enter guest\n");
    printf("  VMEXIT: Return to hypervisor\n");

    printf("\nAMD-V (SVM):\n");
    printf("  Similar to VT-x\n");
    printf("  VMCB: VM Control Block\n");
    printf("  VMRUN: Enter guest\n");
    printf("  #VMEXIT: Exit to host\n");

    printf("\nExtended Page Tables (EPT/NPT):\n");
    printf("  Hardware-assisted memory virtualization\n");
    printf("  Two-level address translation:\n");
    printf("    Guest virtual -> Guest physical -> Host physical\n");
    printf("  Eliminates shadow page table overhead\n");
    printf("  EPT (Intel), NPT (AMD)\n");

    // VMCS structure
    printf("\n\n=== VMCS Structure ===\n\n");

    printf("VMCS (Virtual Machine Control Structure):\n");
    printf("  Guest State Area:\n");
    printf("    - CR0, CR3, CR4\n");
    printf("    - Segment registers\n");
    printf("    - RSP, RIP, RFLAGS\n");
    printf("    - GDTR, IDTR\n");

    printf("\n  Host State Area:\n");
    printf("    - CR0, CR3, CR4\n");
    printf("    - Segment selectors\n");
    printf("    - RSP, RIP\n");

    printf("\n  VM-Execution Control Fields:\n");
    printf("    - Pin-based controls\n");
    printf("    - Processor-based controls\n");
    printf("    - Exception bitmap\n");
    printf("    - I/O bitmap\n");
    printf("    - MSR bitmaps\n");

    printf("\n  VM-Exit Control Fields:\n");
    printf("    - What causes exit\n");
    printf("    - What to save\n");

    printf("\n  VM-Entry Control Fields:\n");
    printf("    - What to inject\n");
    printf("    - What to load\n");

    // VM Exit reasons
    printf("\n\n=== VM Exit Reasons ===\n\n");

    printf("Common VM Exit Causes:\n");
    printf("  - External interrupt\n");
    printf("  - Triple fault\n");
    printf("  - CPUID instruction\n");
    printf("  - HLT instruction\n");
    printf("  - I/O instruction\n");
    printf("  - RDMSR/WRMSR\n");
    printf("  - CR access\n");
    printf("  - Exception (if configured)\n");
    printf("  - EPT violation\n");
    printf("  - VMCALL (hypercall)\n");

    // Check actual support
    printf("\n\n=== System Check ===\n\n");

    check_virtualization_support();
    printf("\n");
    check_kvm_available();

    return 0;
}
```

---

## Fichiers

```
ex00/
├── virtualization.h
├── virt_concepts.c
├── check_support.c
├── hypervisor_types.c
└── Makefile
```
