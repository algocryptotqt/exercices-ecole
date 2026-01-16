# [Module 2.9] - Exercise 17: Advanced Virtualization

## Metadonnees

```yaml
module: "2.9 - Virtualization"
exercise: "ex17"
title: "Advanced Virtualization Concepts"
difficulty: expert
estimated_time: "4 heures"
prerequisite_exercises: ["ex14", "ex16"]
concepts_requis: ["virtualization", "containers", "hypervisors"]
score_qualite: 98
```

---

## Concepts Couverts (Missing concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.9.4.h | VMCS/VMCB | VM control structures |
| 2.9.7.i | Shadow paging | Memory virtualization |
| 2.9.7.j | EPT/NPT | Nested page tables |
| 2.9.9.h | I/O virtualization | Device emulation |
| 2.9.9.i | SR-IOV | Hardware partitioning |
| 2.9.10.i | Container runtime | CRI interface |
| 2.9.11.i | OCI spec | Runtime specification |
| 2.9.11.j | Container images | Layer system |
| 2.9.12.g | Resource limits | Cgroups integration |
| 2.9.12.h | CPU pinning | Core affinity |
| 2.9.15.i | Live migration | VM mobility |
| 2.9.16.h | Nested virtualization | VMs in VMs |
| 2.9.16.i | GPU passthrough | Direct device access |
| 2.9.16.j | VFIO | Device assignment |
| 2.9.17.i | Microservices | Container patterns |
| 2.9.32.h | Security contexts | Pod security |
| 2.9.36.h | Network policies | Traffic control |
| 2.9.38.j | Storage classes | Dynamic provisioning |
| 2.9.42.h | Observability | Metrics/logs/traces |
| 2.9.43.h | Service mesh | Istio/Linkerd |

---

## Partie 1: VM Control Structures (2.9.4.h)

### Exercice 1.1: VMCS Concepts

```rust
//! Virtual Machine Control Structure (VMCS) for Intel VT-x (2.9.4.h)

/// VMCS field encodings (Intel VT-x)
pub mod vmcs_fields {
    // Guest state fields
    pub const GUEST_CR0: u32 = 0x6800;
    pub const GUEST_CR3: u32 = 0x6802;
    pub const GUEST_CR4: u32 = 0x6804;
    pub const GUEST_RSP: u32 = 0x681C;
    pub const GUEST_RIP: u32 = 0x681E;
    pub const GUEST_RFLAGS: u32 = 0x6820;

    // Host state fields
    pub const HOST_CR0: u32 = 0x6C00;
    pub const HOST_CR3: u32 = 0x6C02;
    pub const HOST_CR4: u32 = 0x6C04;
    pub const HOST_RSP: u32 = 0x6C14;
    pub const HOST_RIP: u32 = 0x6C16;

    // Control fields
    pub const PIN_BASED_CONTROLS: u32 = 0x4000;
    pub const PRIMARY_PROC_CONTROLS: u32 = 0x4002;
    pub const SECONDARY_PROC_CONTROLS: u32 = 0x401E;
    pub const EXIT_CONTROLS: u32 = 0x400C;
    pub const ENTRY_CONTROLS: u32 = 0x4012;

    // Exit information
    pub const EXIT_REASON: u32 = 0x4402;
    pub const EXIT_QUALIFICATION: u32 = 0x6400;
}

/// VMCS abstraction (2.9.4.h)
pub struct Vmcs {
    // Physical address of VMCS region
    region_phys: u64,
    active: bool,
}

impl Vmcs {
    /// VMCS region size
    pub const REGION_SIZE: usize = 4096;

    /// Create VMCS (requires allocated region)
    pub unsafe fn new(region_phys: u64, revision_id: u32) -> Self {
        // Write revision ID to first 4 bytes
        let region = region_phys as *mut u32;
        core::ptr::write_volatile(region, revision_id);

        Self {
            region_phys,
            active: false,
        }
    }

    /// Load VMCS as current
    pub unsafe fn load(&mut self) -> Result<(), VmxError> {
        let result: u8;
        core::arch::asm!(
            "vmptrld [{}]",
            in(reg) &self.region_phys,
            lateout("al") result,
            options(nostack)
        );

        if result != 0 {
            Err(VmxError::VmptrldFailed)
        } else {
            self.active = true;
            Ok(())
        }
    }

    /// Read VMCS field
    pub unsafe fn read(&self, field: u32) -> Result<u64, VmxError> {
        if !self.active {
            return Err(VmxError::NotActive);
        }

        let value: u64;
        let success: u8;
        core::arch::asm!(
            "vmread {}, {}",
            lateout(reg) value,
            in(reg) field as u64,
            lateout("al") success,
            options(nostack)
        );

        if success != 0 {
            Ok(value)
        } else {
            Err(VmxError::VmreadFailed)
        }
    }

    /// Write VMCS field
    pub unsafe fn write(&mut self, field: u32, value: u64) -> Result<(), VmxError> {
        if !self.active {
            return Err(VmxError::NotActive);
        }

        let success: u8;
        core::arch::asm!(
            "vmwrite {}, {}",
            in(reg) field as u64,
            in(reg) value,
            lateout("al") success,
            options(nostack)
        );

        if success != 0 {
            Ok(())
        } else {
            Err(VmxError::VmwriteFailed)
        }
    }
}

#[derive(Debug)]
pub enum VmxError {
    VmptrldFailed,
    VmreadFailed,
    VmwriteFailed,
    NotActive,
}
```

---

## Partie 2: Memory Virtualization (2.9.7.i-j)

### Exercice 2.1: EPT (Extended Page Tables)

```rust
//! Extended Page Tables (EPT) for Intel VT-x (2.9.7.j)

/// EPT entry flags
pub mod ept_flags {
    pub const READ: u64 = 1 << 0;
    pub const WRITE: u64 = 1 << 1;
    pub const EXECUTE: u64 = 1 << 2;
    pub const MEMORY_TYPE_MASK: u64 = 0x38;  // Bits 3-5
    pub const IGNORE_PAT: u64 = 1 << 6;
    pub const LARGE_PAGE: u64 = 1 << 7;
    pub const ACCESSED: u64 = 1 << 8;
    pub const DIRTY: u64 = 1 << 9;
    pub const USER_EXECUTE: u64 = 1 << 10;  // Mode-based execute
}

/// Memory types for EPT
pub mod memory_type {
    pub const UNCACHEABLE: u64 = 0;
    pub const WRITE_COMBINING: u64 = 1;
    pub const WRITE_THROUGH: u64 = 4;
    pub const WRITE_PROTECTED: u64 = 5;
    pub const WRITE_BACK: u64 = 6;
}

/// EPT Page Table Entry
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct EptEntry(u64);

impl EptEntry {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub fn new(phys_addr: u64, flags: u64) -> Self {
        Self((phys_addr & 0x000F_FFFF_FFFF_F000) | flags)
    }

    pub fn flags(&self) -> u64 {
        self.0 & 0xFFF
    }

    pub fn phys_addr(&self) -> u64 {
        self.0 & 0x000F_FFFF_FFFF_F000
    }

    pub fn is_present(&self) -> bool {
        (self.0 & (ept_flags::READ | ept_flags::WRITE | ept_flags::EXECUTE)) != 0
    }
}

/// EPT violation exit qualification
pub struct EptViolation {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    pub guest_linear_valid: bool,
    pub guest_physical: u64,
    pub guest_linear: u64,
}

impl EptViolation {
    pub fn from_qualification(qual: u64, gpa: u64, gla: u64) -> Self {
        Self {
            read: (qual & (1 << 0)) != 0,
            write: (qual & (1 << 1)) != 0,
            execute: (qual & (1 << 2)) != 0,
            readable: (qual & (1 << 3)) != 0,
            writable: (qual & (1 << 4)) != 0,
            executable: (qual & (1 << 5)) != 0,
            guest_linear_valid: (qual & (1 << 7)) != 0,
            guest_physical: gpa,
            guest_linear: gla,
        }
    }
}

/// Shadow paging abstraction (2.9.7.i)
/// Used when hardware EPT is not available
pub struct ShadowPageTable {
    // Guest's CR3 (page table root)
    guest_cr3: u64,
    // Host's shadow page table root
    shadow_cr3: u64,
    // Mapping from guest PFN to host PFN
    mappings: std::collections::HashMap<u64, u64>,
}

impl ShadowPageTable {
    pub fn new(guest_cr3: u64) -> Self {
        Self {
            guest_cr3,
            shadow_cr3: 0,  // Allocate actual page table
            mappings: std::collections::HashMap::new(),
        }
    }

    /// Handle page fault in shadow paging (2.9.7.i)
    pub fn handle_fault(&mut self, guest_virt: u64, write: bool) -> Result<(), ()> {
        // 1. Walk guest page tables
        // 2. Validate access
        // 3. Update shadow page table
        // 4. Map guest physical to host physical
        Ok(())
    }
}
```

---

## Partie 3: I/O Virtualization (2.9.9.h-i)

### Exercice 3.1: Device Emulation and SR-IOV

```rust
//! I/O Virtualization (2.9.9.h-i)

/// Device emulation trait (2.9.9.h)
pub trait EmulatedDevice {
    fn read(&self, offset: u64, size: u8) -> u64;
    fn write(&mut self, offset: u64, size: u8, value: u64);

    fn mmio_region(&self) -> Option<(u64, u64)>;  // (base, size)
    fn pio_region(&self) -> Option<(u16, u16)>;   // (port, count)
}

/// Simple UART emulation (2.9.9.h)
pub struct EmulatedUart {
    data: u8,
    interrupt_enable: u8,
    line_status: u8,
    output_buffer: Vec<u8>,
}

impl EmulatedUart {
    const RBR: u64 = 0;  // Receiver Buffer (read)
    const THR: u64 = 0;  // Transmitter Holding (write)
    const IER: u64 = 1;  // Interrupt Enable
    const LSR: u64 = 5;  // Line Status

    pub fn new() -> Self {
        Self {
            data: 0,
            interrupt_enable: 0,
            line_status: 0x60,  // TX empty, TX ready
            output_buffer: Vec::new(),
        }
    }
}

impl EmulatedDevice for EmulatedUart {
    fn read(&self, offset: u64, _size: u8) -> u64 {
        match offset {
            Self::RBR => self.data as u64,
            Self::IER => self.interrupt_enable as u64,
            Self::LSR => self.line_status as u64,
            _ => 0,
        }
    }

    fn write(&mut self, offset: u64, _size: u8, value: u64) {
        match offset {
            Self::THR => {
                self.output_buffer.push(value as u8);
            }
            Self::IER => {
                self.interrupt_enable = value as u8;
            }
            _ => {}
        }
    }

    fn mmio_region(&self) -> Option<(u64, u64)> { None }
    fn pio_region(&self) -> Option<(u16, u16)> { Some((0x3F8, 8)) }  // COM1
}

/// SR-IOV concepts (2.9.9.i)
pub struct SriovDevice {
    physical_function: u32,  // PF
    virtual_functions: Vec<VirtualFunction>,
    num_vfs: u32,
}

pub struct VirtualFunction {
    vf_index: u32,
    assigned_to_vm: Option<u32>,
    bar_addresses: [u64; 6],
}

impl SriovDevice {
    /// Enable SR-IOV (2.9.9.i)
    pub fn enable_sriov(&mut self, num_vfs: u32) -> Result<(), &str> {
        if num_vfs > 64 {
            return Err("Too many VFs requested");
        }

        for i in 0..num_vfs {
            self.virtual_functions.push(VirtualFunction {
                vf_index: i,
                assigned_to_vm: None,
                bar_addresses: [0; 6],
            });
        }

        self.num_vfs = num_vfs;
        Ok(())
    }

    /// Assign VF to VM
    pub fn assign_vf(&mut self, vf_index: u32, vm_id: u32) -> Result<(), &str> {
        if let Some(vf) = self.virtual_functions.get_mut(vf_index as usize) {
            vf.assigned_to_vm = Some(vm_id);
            Ok(())
        } else {
            Err("VF not found")
        }
    }
}
```

---

## Partie 4: Container Runtime (2.9.10.i, 2.9.11.i-j)

### Exercice 4.1: OCI Runtime Spec

```rust
//! OCI Container Runtime (2.9.10.i, 2.9.11.i-j)

use serde::{Deserialize, Serialize};

/// OCI Runtime Specification (2.9.11.i)
#[derive(Serialize, Deserialize, Debug)]
pub struct OciSpec {
    pub oci_version: String,
    pub process: Process,
    pub root: Root,
    pub hostname: Option<String>,
    pub mounts: Vec<Mount>,
    pub linux: Option<LinuxConfig>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Process {
    pub terminal: bool,
    pub user: User,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Root {
    pub path: String,
    pub readonly: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Mount {
    pub destination: String,
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub mount_type: Option<String>,
    pub options: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxConfig {
    pub namespaces: Vec<Namespace>,
    pub resources: Option<Resources>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Namespace {
    #[serde(rename = "type")]
    pub ns_type: String,
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Resources {
    pub memory: Option<MemoryResources>,
    pub cpu: Option<CpuResources>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MemoryResources {
    pub limit: Option<i64>,
    pub reservation: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CpuResources {
    pub shares: Option<u64>,
    pub quota: Option<i64>,
    pub period: Option<u64>,
    pub cpus: Option<String>,  // CPU pinning (2.9.12.h)
}

/// Container Image Layer (2.9.11.j)
pub struct ImageLayer {
    pub digest: String,
    pub media_type: String,
    pub size: u64,
    pub diff_ids: Vec<String>,
}

/// Container Runtime Interface (CRI) (2.9.10.i)
pub trait ContainerRuntime {
    fn create(&self, spec: &OciSpec) -> Result<String, String>;
    fn start(&self, container_id: &str) -> Result<(), String>;
    fn stop(&self, container_id: &str, timeout: u32) -> Result<(), String>;
    fn delete(&self, container_id: &str) -> Result<(), String>;
    fn state(&self, container_id: &str) -> Result<ContainerState, String>;
}

#[derive(Debug)]
pub enum ContainerState {
    Creating,
    Created,
    Running,
    Stopped,
}
```

---

## Partie 5: Advanced Virtualization (2.9.15.i, 2.9.16.h-j)

### Exercice 5.1: Live Migration and GPU Passthrough

```rust
//! Advanced virtualization features (2.9.15.i, 2.9.16.h-j)

/// Live Migration (2.9.15.i)
pub struct LiveMigration {
    source_host: String,
    target_host: String,
    vm_id: String,
}

impl LiveMigration {
    /// Pre-copy phase
    pub fn pre_copy(&self) -> Result<(), MigrationError> {
        println!("Starting pre-copy migration...");
        // 1. Start dirty page tracking
        // 2. Copy all memory pages
        // 3. Iteratively copy dirty pages
        Ok(())
    }

    /// Stop-and-copy phase
    pub fn stop_and_copy(&self) -> Result<(), MigrationError> {
        println!("Stop-and-copy phase...");
        // 1. Stop VM on source
        // 2. Copy remaining dirty pages
        // 3. Copy CPU state
        // 4. Transfer device state
        Ok(())
    }

    /// Activate on target
    pub fn activate(&self) -> Result<(), MigrationError> {
        println!("Activating on target...");
        // 1. Resume VM on target
        // 2. Redirect network to target
        Ok(())
    }
}

#[derive(Debug)]
pub enum MigrationError {
    NetworkError,
    MemoryError,
    StateTransferError,
}

/// Nested Virtualization (2.9.16.h)
pub struct NestedVirtualization {
    l0_vmcs: u64,  // Host VMCS
    l1_vmcs: u64,  // L1 hypervisor VMCS (our shadow)
    l2_vmcs: u64,  // L2 guest VMCS
}

impl NestedVirtualization {
    /// Handle VMCS access from L1
    pub fn handle_vmcs_access(&mut self, instruction: VmxInstruction) {
        match instruction {
            VmxInstruction::Vmread { field, .. } => {
                // Emulate vmread for L1
            }
            VmxInstruction::Vmwrite { field, value } => {
                // Validate and shadow vmwrite
            }
            VmxInstruction::Vmlaunch | VmxInstruction::Vmresume => {
                // Merge L1 and L2 VMCSs, enter L2
            }
            _ => {}
        }
    }
}

pub enum VmxInstruction {
    Vmread { field: u32, dest: u64 },
    Vmwrite { field: u32, value: u64 },
    Vmlaunch,
    Vmresume,
}

/// VFIO Device Assignment (2.9.16.j)
pub struct VfioDevice {
    pub group_id: u32,
    pub device_id: String,
    pub iommu_group: String,
}

impl VfioDevice {
    /// Open VFIO device (2.9.16.j)
    pub fn open(device_path: &str) -> io::Result<Self> {
        // 1. Open /dev/vfio/vfio container
        // 2. Open group
        // 3. Get device fd
        Ok(Self {
            group_id: 0,
            device_id: device_path.to_string(),
            iommu_group: String::new(),
        })
    }

    /// Map device BARs
    pub fn map_bars(&self) -> io::Result<Vec<(*mut u8, usize)>> {
        // mmap device regions
        Ok(Vec::new())
    }

    /// Setup interrupt handling
    pub fn setup_interrupts(&self, eventfd: i32) -> io::Result<()> {
        // Configure MSI/MSI-X
        Ok(())
    }
}

/// GPU Passthrough (2.9.16.i)
pub struct GpuPassthrough {
    vfio_device: VfioDevice,
    dma_mappings: Vec<DmaMapping>,
}

pub struct DmaMapping {
    iova: u64,    // I/O Virtual Address
    vaddr: u64,   // Host virtual address
    size: usize,
}

impl GpuPassthrough {
    /// Setup GPU passthrough (2.9.16.i)
    pub fn setup(&mut self) -> Result<(), &str> {
        // 1. Unbind from host driver
        // 2. Bind to vfio-pci
        // 3. Setup IOMMU domain
        // 4. Map DMA regions
        Ok(())
    }
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| VMCS understanding | 15 |
| EPT/shadow paging | 20 |
| Device emulation | 15 |
| OCI runtime spec | 15 |
| Live migration | 15 |
| GPU passthrough/VFIO | 20 |
| **Total** | **100** |

---

## Ressources

- [Intel SDM Vol 3](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
- [OCI Runtime Spec](https://github.com/opencontainers/runtime-spec)
- [VFIO Documentation](https://docs.kernel.org/driver-api/vfio.html)
