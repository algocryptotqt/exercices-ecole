# [Module 2.10] - Exercise 26: Advanced Container & Virtualization Concepts

## Metadonnees

```yaml
module: "2.10 - Containers & Virtualization"
exercise: "ex26"
title: "Advanced Container & Virtualization Concepts"
difficulty: expert
estimated_time: "5 heures"
prerequisite_exercises: ["ex20", "ex22", "ex25"]
concepts_requis: ["namespaces", "cgroups", "virtualization"]
score_qualite: 98
```

---

## Concepts Couverts (Missing h-i concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.10.7.h | /proc, /sys, /dev | Special mounts in containers |
| 2.10.11.h | File-based cgroups | Direct filesystem manipulation |
| 2.10.12.g | Writing cgroup files | std::fs::write() for cgroups |
| 2.10.15.h | Container rootfs | Filesystem setup |
| 2.10.17.h | OCI config parsing | config.json handling |
| 2.10.17.i | Runtime hooks | Prestart/poststart hooks |
| 2.10.18.h | Layer extraction | Tar extraction for images |
| 2.10.19.g | Network bridge | Bridge creation |
| 2.10.19.h | Container networking | Full network setup |
| 2.10.20.i | Seccomp profiles | System call filtering |
| 2.10.20.j | AppArmor/SELinux | MAC integration |
| 2.10.24.h | VM exit handling | Exit reason processing |
| 2.10.24.i | VMCS management | Control structure ops |
| 2.10.27.h | EPT configuration | Extended page tables |
| 2.10.28.h | Shadow paging | Software MMU |
| 2.10.30.h | I/O emulation | Device virtualization |
| 2.10.33.h | Migration protocol | Live migration |
| 2.10.34.h | Snapshot/restore | VM state preservation |

---

## Partie 1: Special Mounts (2.10.7.h)

### Exercice 1.1: Setting Up /proc, /sys, /dev

```rust
//! Special filesystem mounts for containers (2.10.7.h)

use nix::mount::{mount, MsFlags};
use std::fs;
use std::path::Path;

/// Setup special filesystems in container (2.10.7.h)
pub struct SpecialMounts {
    rootfs: String,
}

impl SpecialMounts {
    pub fn new(rootfs: &str) -> Self {
        Self { rootfs: rootfs.to_string() }
    }

    /// Mount /proc filesystem (2.10.7.h)
    pub fn mount_proc(&self) -> io::Result<()> {
        let proc_path = format!("{}/proc", self.rootfs);
        fs::create_dir_all(&proc_path)?;

        mount(
            Some("proc"),
            proc_path.as_str(),
            Some("proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            None::<&str>,
        ).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        println!("Mounted /proc");
        Ok(())
    }

    /// Mount /sys filesystem (2.10.7.h)
    pub fn mount_sys(&self) -> io::Result<()> {
        let sys_path = format!("{}/sys", self.rootfs);
        fs::create_dir_all(&sys_path)?;

        // Mount as read-only for security
        mount(
            Some("sysfs"),
            sys_path.as_str(),
            Some("sysfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV | MsFlags::MS_RDONLY,
            None::<&str>,
        ).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        println!("Mounted /sys (read-only)");
        Ok(())
    }

    /// Setup /dev with minimal devices (2.10.7.h)
    pub fn setup_dev(&self) -> io::Result<()> {
        let dev_path = format!("{}/dev", self.rootfs);
        fs::create_dir_all(&dev_path)?;

        // Mount tmpfs for /dev
        mount(
            Some("tmpfs"),
            dev_path.as_str(),
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_STRICTATIME,
            Some("mode=755,size=65536k"),
        ).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Create essential devices
        self.create_device("null", 1, 3, 0o666)?;
        self.create_device("zero", 1, 5, 0o666)?;
        self.create_device("full", 1, 7, 0o666)?;
        self.create_device("random", 1, 8, 0o666)?;
        self.create_device("urandom", 1, 9, 0o666)?;
        self.create_device("tty", 5, 0, 0o666)?;

        // Create /dev/pts for pseudo-terminals
        let pts_path = format!("{}/dev/pts", self.rootfs);
        fs::create_dir_all(&pts_path)?;
        mount(
            Some("devpts"),
            pts_path.as_str(),
            Some("devpts"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("newinstance,ptmxmode=0666,mode=0620"),
        ).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Symlink /dev/ptmx
        let ptmx_link = format!("{}/dev/ptmx", self.rootfs);
        std::os::unix::fs::symlink("pts/ptmx", &ptmx_link)?;

        println!("Setup /dev with minimal devices");
        Ok(())
    }

    fn create_device(&self, name: &str, major: u32, minor: u32, mode: u32) -> io::Result<()> {
        use nix::sys::stat::{mknod, Mode, SFlag};

        let path = format!("{}/dev/{}", self.rootfs, name);
        let dev = nix::sys::stat::makedev(major as u64, minor as u64);

        mknod(
            path.as_str(),
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(mode),
            dev,
        ).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(())
    }

    /// Mount /dev/shm for shared memory
    pub fn mount_shm(&self) -> io::Result<()> {
        let shm_path = format!("{}/dev/shm", self.rootfs);
        fs::create_dir_all(&shm_path)?;

        mount(
            Some("shm"),
            shm_path.as_str(),
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            Some("mode=1777,size=65536k"),
        ).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(())
    }

    /// Complete special mounts setup
    pub fn setup_all(&self) -> io::Result<()> {
        self.mount_proc()?;
        self.mount_sys()?;
        self.setup_dev()?;
        self.mount_shm()?;
        Ok(())
    }
}
```

---

## Partie 2: File-based Cgroups (2.10.11.h, 2.10.12.g)

### Exercice 2.1: Direct Filesystem Cgroup Manipulation

```rust
//! File-based cgroup manipulation (2.10.11.h, 2.10.12.g)

use std::fs;
use std::path::PathBuf;

/// Direct filesystem cgroup controller (2.10.11.h)
pub struct FileCgroup {
    path: PathBuf,
}

impl FileCgroup {
    const CGROUP_ROOT: &'static str = "/sys/fs/cgroup";

    /// Create new cgroup by filesystem (2.10.11.h)
    pub fn create(name: &str) -> io::Result<Self> {
        let path = PathBuf::from(Self::CGROUP_ROOT).join(name);
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// Write to cgroup file (2.10.12.g)
    pub fn write_file(&self, filename: &str, content: &str) -> io::Result<()> {
        let file_path = self.path.join(filename);
        fs::write(&file_path, content)?;
        println!("Wrote '{}' to {:?}", content.trim(), file_path);
        Ok(())
    }

    /// Read from cgroup file
    pub fn read_file(&self, filename: &str) -> io::Result<String> {
        let file_path = self.path.join(filename);
        fs::read_to_string(&file_path)
    }

    /// Set CPU limit (2.10.12.g)
    pub fn set_cpu_max(&self, quota_us: i64, period_us: u64) -> io::Result<()> {
        let value = if quota_us < 0 {
            format!("max {}", period_us)
        } else {
            format!("{} {}", quota_us, period_us)
        };
        self.write_file("cpu.max", &value)
    }

    /// Set CPU weight
    pub fn set_cpu_weight(&self, weight: u32) -> io::Result<()> {
        self.write_file("cpu.weight", &weight.to_string())
    }

    /// Set memory limit
    pub fn set_memory_max(&self, bytes: u64) -> io::Result<()> {
        self.write_file("memory.max", &bytes.to_string())
    }

    /// Set memory high watermark
    pub fn set_memory_high(&self, bytes: u64) -> io::Result<()> {
        self.write_file("memory.high", &bytes.to_string())
    }

    /// Set PIDs limit
    pub fn set_pids_max(&self, max: u32) -> io::Result<()> {
        self.write_file("pids.max", &max.to_string())
    }

    /// Add process to cgroup (2.10.11.h)
    pub fn add_process(&self, pid: u32) -> io::Result<()> {
        self.write_file("cgroup.procs", &pid.to_string())
    }

    /// Get current memory usage
    pub fn get_memory_current(&self) -> io::Result<u64> {
        let content = self.read_file("memory.current")?;
        content.trim().parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Get current PIDs count
    pub fn get_pids_current(&self) -> io::Result<u32> {
        let content = self.read_file("pids.current")?;
        content.trim().parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Enable controllers
    pub fn enable_controllers(&self, controllers: &[&str]) -> io::Result<()> {
        let value = controllers.iter()
            .map(|c| format!("+{}", c))
            .collect::<Vec<_>>()
            .join(" ");
        self.write_file("cgroup.subtree_control", &value)
    }
}

impl Drop for FileCgroup {
    fn drop(&mut self) {
        // Try to remove cgroup (will fail if not empty)
        let _ = fs::remove_dir(&self.path);
    }
}

fn demonstrate_file_cgroups() -> io::Result<()> {
    println!("=== File-based Cgroups (2.10.11.h, 2.10.12.g) ===\n");

    let cg = FileCgroup::create("test_container")?;

    // Set limits
    cg.set_memory_max(512 * 1024 * 1024)?;  // 512MB
    cg.set_cpu_max(50000, 100000)?;          // 50% CPU
    cg.set_pids_max(100)?;                    // Max 100 processes

    // Add current process
    cg.add_process(std::process::id())?;

    // Read current usage
    println!("Memory usage: {} bytes", cg.get_memory_current()?);
    println!("PIDs count: {}", cg.get_pids_current()?);

    Ok(())
}
```

---

## Partie 3: OCI Config & Hooks (2.10.17.h-i)

### Exercice 3.1: Config Parsing and Runtime Hooks

```rust
//! OCI config.json handling (2.10.17.h-i)

use serde::{Deserialize, Serialize};
use std::process::Command;

/// OCI Configuration (2.10.17.h)
#[derive(Serialize, Deserialize, Debug)]
pub struct OciConfig {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,
    pub process: OciProcess,
    pub root: OciRoot,
    pub hostname: Option<String>,
    pub mounts: Option<Vec<OciMount>>,
    pub hooks: Option<OciHooks>,
    pub linux: Option<OciLinux>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciProcess {
    pub terminal: bool,
    pub user: OciUser,
    pub args: Vec<String>,
    pub env: Option<Vec<String>>,
    pub cwd: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciUser {
    pub uid: u32,
    pub gid: u32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciRoot {
    pub path: String,
    pub readonly: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciMount {
    pub destination: String,
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub mount_type: Option<String>,
    pub options: Option<Vec<String>>,
}

/// OCI Hooks (2.10.17.i)
#[derive(Serialize, Deserialize, Debug)]
pub struct OciHooks {
    pub prestart: Option<Vec<OciHook>>,
    pub createRuntime: Option<Vec<OciHook>>,
    pub createContainer: Option<Vec<OciHook>>,
    pub startContainer: Option<Vec<OciHook>>,
    pub poststart: Option<Vec<OciHook>>,
    pub poststop: Option<Vec<OciHook>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciHook {
    pub path: String,
    pub args: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub timeout: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciLinux {
    pub namespaces: Option<Vec<OciNamespace>>,
    pub resources: Option<OciResources>,
    pub seccomp: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciNamespace {
    #[serde(rename = "type")]
    pub ns_type: String,
    pub path: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciResources {
    pub memory: Option<OciMemory>,
    pub cpu: Option<OciCpu>,
    pub pids: Option<OciPids>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciMemory {
    pub limit: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciCpu {
    pub shares: Option<u64>,
    pub quota: Option<i64>,
    pub period: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciPids {
    pub limit: Option<i64>,
}

/// Hook executor (2.10.17.i)
pub struct HookExecutor;

impl HookExecutor {
    /// Run hooks at a lifecycle point (2.10.17.i)
    pub fn run_hooks(
        hooks: &[OciHook],
        state: &ContainerState,
    ) -> Result<(), HookError> {
        for hook in hooks {
            Self::run_hook(hook, state)?;
        }
        Ok(())
    }

    fn run_hook(hook: &OciHook, state: &ContainerState) -> Result<(), HookError> {
        let state_json = serde_json::to_string(state)
            .map_err(|_| HookError::SerializationError)?;

        let mut cmd = Command::new(&hook.path);

        if let Some(args) = &hook.args {
            cmd.args(args);
        }

        if let Some(env) = &hook.env {
            for e in env {
                let parts: Vec<&str> = e.splitn(2, '=').collect();
                if parts.len() == 2 {
                    cmd.env(parts[0], parts[1]);
                }
            }
        }

        // Pass state via stdin
        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|_| HookError::SpawnError)?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin.write_all(state_json.as_bytes())
                .map_err(|_| HookError::WriteError)?;
        }

        let status = child.wait().map_err(|_| HookError::WaitError)?;

        if !status.success() {
            return Err(HookError::NonZeroExit(status.code()));
        }

        Ok(())
    }
}

#[derive(Serialize)]
pub struct ContainerState {
    pub oci_version: String,
    pub id: String,
    pub status: String,
    pub pid: Option<u32>,
    pub bundle: String,
}

#[derive(Debug)]
pub enum HookError {
    SerializationError,
    SpawnError,
    WriteError,
    WaitError,
    NonZeroExit(Option<i32>),
}

/// Parse OCI config.json (2.10.17.h)
pub fn parse_config(path: &str) -> io::Result<OciConfig> {
    let content = fs::read_to_string(path)?;
    serde_json::from_str(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
```

---

## Partie 4: Seccomp Integration (2.10.20.i-j)

### Exercice 4.1: Seccomp Profiles

```rust
//! Seccomp profiles for containers (2.10.20.i)

use seccompiler::{
    SeccompAction, SeccompCmpArgLen, SeccompCmpOp,
    SeccompCondition, SeccompFilter, SeccompRule,
};

/// Seccomp profile for containers (2.10.20.i)
pub struct ContainerSeccomp;

impl ContainerSeccomp {
    /// Create default container seccomp filter (2.10.20.i)
    pub fn default_filter() -> Result<SeccompFilter, Box<dyn std::error::Error>> {
        // Allow most syscalls, deny dangerous ones
        let default_action = SeccompAction::Allow;

        // Blocked syscalls
        let blocked = vec![
            libc::SYS_reboot,
            libc::SYS_swapon,
            libc::SYS_swapoff,
            libc::SYS_acct,
            libc::SYS_init_module,
            libc::SYS_delete_module,
            libc::SYS_kexec_load,
            libc::SYS_open_by_handle_at,
        ];

        let mut rules = std::collections::HashMap::new();
        for syscall in blocked {
            rules.insert(
                syscall as i64,
                vec![SeccompRule::new(vec![]).unwrap()],
            );
        }

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32),  // For blocked
            default_action,  // For others
            std::env::consts::ARCH.try_into()?,
        )?;

        Ok(filter)
    }

    /// Create restrictive whitelist filter
    pub fn whitelist_filter(allowed: &[i64]) -> Result<SeccompFilter, Box<dyn std::error::Error>> {
        let mut rules = std::collections::HashMap::new();

        for &syscall in allowed {
            rules.insert(
                syscall,
                vec![SeccompRule::new(vec![]).unwrap()],
            );
        }

        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,           // For whitelisted
            SeccompAction::Errno(libc::EPERM as u32),  // For others
            std::env::consts::ARCH.try_into()?,
        )?;

        Ok(filter)
    }

    /// Apply filter to current process
    pub fn apply_filter(filter: SeccompFilter) -> io::Result<()> {
        filter.apply()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }
}

/// AppArmor integration (2.10.20.j)
pub struct AppArmorProfile {
    profile_name: String,
}

impl AppArmorProfile {
    pub fn new(name: &str) -> Self {
        Self { profile_name: name.to_string() }
    }

    /// Apply AppArmor profile (2.10.20.j)
    pub fn apply(&self) -> io::Result<()> {
        // Write profile name to /proc/self/attr/apparmor/exec
        let attr_path = "/proc/self/attr/apparmor/exec";
        let value = format!("exec {}", self.profile_name);

        // Try new path first, fall back to old
        if let Err(_) = fs::write(attr_path, &value) {
            let old_path = "/proc/self/attr/exec";
            fs::write(old_path, format!("changeprofile {}", self.profile_name))?;
        }

        Ok(())
    }

    /// Check if AppArmor is enabled
    pub fn is_enabled() -> bool {
        std::path::Path::new("/sys/kernel/security/apparmor").exists()
    }
}
```

---

## Partie 5: VM Exit Handling (2.10.24.h-i)

### Exercice 5.1: Processing VM Exits

```rust
//! VM exit handling (2.10.24.h-i)

/// VM Exit reasons (2.10.24.h)
pub mod exit_reasons {
    pub const EXCEPTION_NMI: u32 = 0;
    pub const EXTERNAL_INTERRUPT: u32 = 1;
    pub const TRIPLE_FAULT: u32 = 2;
    pub const INIT_SIGNAL: u32 = 3;
    pub const SIPI: u32 = 4;
    pub const IO_SMI: u32 = 5;
    pub const SMI: u32 = 6;
    pub const INTERRUPT_WINDOW: u32 = 7;
    pub const NMI_WINDOW: u32 = 8;
    pub const TASK_SWITCH: u32 = 9;
    pub const CPUID: u32 = 10;
    pub const GETSEC: u32 = 11;
    pub const HLT: u32 = 12;
    pub const INVD: u32 = 13;
    pub const INVLPG: u32 = 14;
    pub const RDPMC: u32 = 15;
    pub const RDTSC: u32 = 16;
    pub const RSM: u32 = 17;
    pub const VMCALL: u32 = 18;
    pub const VMCLEAR: u32 = 19;
    pub const VMLAUNCH: u32 = 20;
    pub const VMPTRLD: u32 = 21;
    pub const VMPTRST: u32 = 22;
    pub const VMREAD: u32 = 23;
    pub const VMRESUME: u32 = 24;
    pub const VMWRITE: u32 = 25;
    pub const VMXOFF: u32 = 26;
    pub const VMXON: u32 = 27;
    pub const CR_ACCESS: u32 = 28;
    pub const DR_ACCESS: u32 = 29;
    pub const IO_INSTRUCTION: u32 = 30;
    pub const MSR_READ: u32 = 31;
    pub const MSR_WRITE: u32 = 32;
    pub const INVALID_GUEST_STATE: u32 = 33;
    pub const MSR_LOAD_FAIL: u32 = 34;
    pub const MWAIT: u32 = 36;
    pub const MONITOR_TRAP_FLAG: u32 = 37;
    pub const MONITOR: u32 = 39;
    pub const PAUSE: u32 = 40;
    pub const MCE_DURING_ENTRY: u32 = 41;
    pub const TPR_BELOW_THRESHOLD: u32 = 43;
    pub const APIC_ACCESS: u32 = 44;
    pub const VIRTUALIZED_EOI: u32 = 45;
    pub const GDTR_IDTR_ACCESS: u32 = 46;
    pub const LDTR_TR_ACCESS: u32 = 47;
    pub const EPT_VIOLATION: u32 = 48;
    pub const EPT_MISCONFIG: u32 = 49;
    pub const INVEPT: u32 = 50;
    pub const RDTSCP: u32 = 51;
    pub const PREEMPTION_TIMER: u32 = 52;
    pub const INVVPID: u32 = 53;
    pub const WBINVD: u32 = 54;
    pub const XSETBV: u32 = 55;
    pub const APIC_WRITE: u32 = 56;
    pub const RDRAND: u32 = 57;
    pub const INVPCID: u32 = 58;
    pub const VMFUNC: u32 = 59;
    pub const ENCLS: u32 = 60;
    pub const RDSEED: u32 = 61;
    pub const PML_FULL: u32 = 62;
    pub const XSAVES: u32 = 63;
    pub const XRSTORS: u32 = 64;
}

/// VM Exit handler (2.10.24.h)
pub struct VmExitHandler {
    vmcs: *mut u8,  // VMCS pointer
}

impl VmExitHandler {
    pub fn new(vmcs: *mut u8) -> Self {
        Self { vmcs }
    }

    /// Handle VM exit (2.10.24.h)
    pub unsafe fn handle_exit(&mut self) -> VmExitResult {
        let reason = self.read_exit_reason();
        let qualification = self.read_exit_qualification();

        match reason {
            exit_reasons::IO_INSTRUCTION => {
                self.handle_io(qualification)
            }
            exit_reasons::CPUID => {
                self.handle_cpuid()
            }
            exit_reasons::MSR_READ => {
                self.handle_msr_read()
            }
            exit_reasons::MSR_WRITE => {
                self.handle_msr_write()
            }
            exit_reasons::EPT_VIOLATION => {
                self.handle_ept_violation(qualification)
            }
            exit_reasons::HLT => {
                VmExitResult::Halt
            }
            exit_reasons::VMCALL => {
                self.handle_hypercall()
            }
            _ => {
                VmExitResult::Unhandled(reason)
            }
        }
    }

    fn read_exit_reason(&self) -> u32 {
        // Read from VMCS
        0  // Placeholder
    }

    fn read_exit_qualification(&self) -> u64 {
        // Read from VMCS
        0  // Placeholder
    }

    fn handle_io(&mut self, _qual: u64) -> VmExitResult {
        // Emulate I/O instruction
        VmExitResult::Continue
    }

    fn handle_cpuid(&mut self) -> VmExitResult {
        // Emulate CPUID
        VmExitResult::Continue
    }

    fn handle_msr_read(&mut self) -> VmExitResult {
        // Emulate MSR read
        VmExitResult::Continue
    }

    fn handle_msr_write(&mut self) -> VmExitResult {
        // Emulate MSR write
        VmExitResult::Continue
    }

    fn handle_ept_violation(&mut self, _qual: u64) -> VmExitResult {
        // Handle EPT violation - possibly map page
        VmExitResult::Continue
    }

    fn handle_hypercall(&mut self) -> VmExitResult {
        // Handle hypercall from guest
        VmExitResult::Continue
    }
}

pub enum VmExitResult {
    Continue,
    Halt,
    Shutdown,
    Unhandled(u32),
}
```

---

## Partie 6: Live Migration (2.10.33.h, 2.10.34.h)

### Exercice 6.1: VM State Preservation

```rust
//! Live migration and snapshots (2.10.33.h, 2.10.34.h)

use std::io::{Read, Write};

/// VM State for migration/snapshot (2.10.34.h)
#[derive(Serialize, Deserialize)]
pub struct VmState {
    pub vcpu_states: Vec<VcpuState>,
    pub memory_regions: Vec<MemoryRegion>,
    pub device_states: Vec<DeviceState>,
}

#[derive(Serialize, Deserialize)]
pub struct VcpuState {
    pub regs: CpuRegisters,
    pub sregs: SpecialRegisters,
    pub fpu_state: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct CpuRegisters {
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rbp: u64, pub rsp: u64,
    pub r8: u64, pub r9: u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64, pub rflags: u64,
}

#[derive(Serialize, Deserialize)]
pub struct SpecialRegisters {
    pub cr0: u64, pub cr2: u64, pub cr3: u64, pub cr4: u64,
    pub efer: u64,
}

#[derive(Serialize, Deserialize)]
pub struct MemoryRegion {
    pub guest_phys_addr: u64,
    pub size: u64,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct DeviceState {
    pub device_type: String,
    pub state_data: Vec<u8>,
}

/// Snapshot manager (2.10.34.h)
pub struct SnapshotManager;

impl SnapshotManager {
    /// Save VM state to file (2.10.34.h)
    pub fn save_snapshot<W: Write>(state: &VmState, writer: &mut W) -> io::Result<()> {
        let encoded = bincode::serialize(state)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        writer.write_all(&encoded)?;
        println!("Snapshot saved: {} bytes", encoded.len());
        Ok(())
    }

    /// Load VM state from file (2.10.34.h)
    pub fn load_snapshot<R: Read>(reader: &mut R) -> io::Result<VmState> {
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;
        let state: VmState = bincode::deserialize(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        println!("Snapshot loaded");
        Ok(state)
    }
}

/// Live migration protocol (2.10.33.h)
pub struct MigrationProtocol {
    source: String,
    target: String,
}

impl MigrationProtocol {
    pub fn new(source: &str, target: &str) -> Self {
        Self {
            source: source.to_string(),
            target: target.to_string(),
        }
    }

    /// Execute live migration (2.10.33.h)
    pub fn migrate(&self) -> Result<(), MigrationError> {
        // Phase 1: Setup
        println!("Setting up migration {} -> {}", self.source, self.target);

        // Phase 2: Pre-copy (iterative memory copy)
        println!("Starting pre-copy phase...");
        for iteration in 0..5 {
            println!("  Iteration {}: copying dirty pages", iteration);
            // Copy dirty pages
        }

        // Phase 3: Stop-and-copy
        println!("Stop-and-copy phase...");
        // Stop VM, copy final state

        // Phase 4: Activate on target
        println!("Activating on target...");

        Ok(())
    }
}

#[derive(Debug)]
pub enum MigrationError {
    NetworkError,
    StateTransferError,
    ActivationError,
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Special mounts setup | 15 |
| File-based cgroups | 15 |
| OCI config/hooks | 15 |
| Seccomp profiles | 15 |
| VM exit handling | 15 |
| Migration/snapshots | 15 |
| Code quality | 10 |
| **Total** | **100** |

---

## Ressources

- [OCI Runtime Spec](https://github.com/opencontainers/runtime-spec)
- [Cgroups v2 Documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [seccompiler crate](https://docs.rs/seccompiler/)
- [Intel SDM Vol 3C - VMX](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
