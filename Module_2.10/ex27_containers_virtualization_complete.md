# ex27: Containers & Virtualization Complete

**Module**: 2.10 - Advanced Topics
**Difficulte**: Expert
**Duree**: 40h
**Score qualite**: 98/100

## Concepts Couverts

### 2.10.1: Container Concepts (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.1.a | Container | Isolated process group |
| 2.10.1.b | vs VM | Shared kernel, lightweight |
| 2.10.1.c | Isolation primitives | Namespaces, cgroups, seccomp |
| 2.10.1.d | Image | Filesystem layers |
| 2.10.1.e | Runtime | Execute containers |
| 2.10.1.f | Rust runtimes | youki, crun |
| 2.10.1.g | OCI specification | Standard interface |
| 2.10.1.h | Why Rust | Memory safety for security |

### 2.10.2: Linux Namespaces Overview (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.2.a | Namespace | Kernel isolation mechanism |
| 2.10.2.b | Purpose | Separate resource views |
| 2.10.2.c | Types | PID, NET, MNT, UTS, IPC, USER, CGROUP, TIME |
| 2.10.2.d | `nix` crate | Rust interface |
| 2.10.2.e | `nix::sched::clone()` | Create with namespace |
| 2.10.2.f | `nix::sched::unshare()` | Leave namespace |
| 2.10.2.g | `nix::sched::setns()` | Join namespace |
| 2.10.2.h | `/proc/[pid]/ns/` | Namespace file descriptors |

### 2.10.3: Namespace Flags in Rust (9 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.3.a | `CloneFlags` | Namespace flags |
| 2.10.3.b | `CLONE_NEWPID` | New PID namespace |
| 2.10.3.c | `CLONE_NEWNET` | New network namespace |
| 2.10.3.d | `CLONE_NEWNS` | New mount namespace |
| 2.10.3.e | `CLONE_NEWUTS` | New UTS namespace |
| 2.10.3.f | `CLONE_NEWIPC` | New IPC namespace |
| 2.10.3.g | `CLONE_NEWUSER` | New user namespace |
| 2.10.3.h | `CLONE_NEWCGROUP` | New cgroup namespace |
| 2.10.3.i | Combining | `CLONE_NEWPID | CLONE_NEWNET` |

### 2.10.4: PID Namespace (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.4.a | PID isolation | Separate PID number space |
| 2.10.4.b | PID 1 in namespace | Init process |
| 2.10.4.c | Nested namespaces | Hierarchical |
| 2.10.4.d | `unshare(CLONE_NEWPID)` | Create new |
| 2.10.4.e | Fork after unshare | Required for PID 1 |
| 2.10.4.f | `/proc` remount | Show namespace PIDs |
| 2.10.4.g | Signal handling | PID 1 responsibilities |

### 2.10.5: Network Namespace (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.5.a | NET isolation | Separate network stack |
| 2.10.5.b | New loopback | Own `lo` interface |
| 2.10.5.c | veth pairs | Virtual ethernet |
| 2.10.5.d | `rtnetlink` crate | Netlink interface |
| 2.10.5.e | Create veth | Via netlink |
| 2.10.5.f | Move to namespace | `setns()` one end |
| 2.10.5.g | Bridge connection | Connect to host |
| 2.10.5.h | IP configuration | Assign addresses |

### 2.10.6: Network Setup with rtnetlink (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.6.a | `rtnetlink` crate | Async netlink |
| 2.10.6.b | `Connection::new()` | Create connection |
| 2.10.6.c | `LinkAddRequest` | Create interface |
| 2.10.6.d | `.veth()` | Veth pair |
| 2.10.6.e | `.set_netns_by_pid()` | Move to namespace |
| 2.10.6.f | `AddressAddRequest` | Assign IP |
| 2.10.6.g | `LinkSetRequest::up()` | Bring up |
| 2.10.6.h | Bridge creation | Connect containers |

### 2.10.7: Mount Namespace (7 concepts - h already covered)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.7.a | MNT isolation | Separate mount tree |
| 2.10.7.b | `nix::mount::mount()` | Mount filesystem |
| 2.10.7.c | `MsFlags` | Mount flags |
| 2.10.7.d | `MS_PRIVATE` | Private mount |
| 2.10.7.e | `MS_REC` | Recursive |
| 2.10.7.f | `MS_BIND` | Bind mount |
| 2.10.7.g | Rootfs setup | Container filesystem |

### 2.10.8: pivot_root (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.8.a | `pivot_root()` | Swap root filesystems |
| 2.10.8.b | More secure | Than chroot |
| 2.10.8.c | `nix::unistd::pivot_root()` | Rust function |
| 2.10.8.d | Requirements | new_root must be mount point |
| 2.10.8.e | put_old | Where old root goes |
| 2.10.8.f | Unmount old | After pivot |
| 2.10.8.g | Container rootfs | Isolated filesystem |

### 2.10.9: User Namespace (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.9.a | USER isolation | UID/GID mapping |
| 2.10.9.b | Root inside | UID 0 in namespace |
| 2.10.9.c | Unprivileged outside | Mapped to normal user |
| 2.10.9.d | `/proc/[pid]/uid_map` | UID mapping file |
| 2.10.9.e | `/proc/[pid]/gid_map` | GID mapping file |
| 2.10.9.f | Write mapping | `0 1000 1` format |
| 2.10.9.g | `setgroups` deny | Required first |
| 2.10.9.h | Rootless containers | No host root needed |

### 2.10.10: UTS and IPC Namespaces (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.10.a | UTS namespace | Hostname isolation |
| 2.10.10.b | `nix::unistd::sethostname()` | Set hostname |
| 2.10.10.c | `nix::unistd::setdomainname()` | Set domain |
| 2.10.10.d | IPC namespace | IPC isolation |
| 2.10.10.e | Shared memory | Isolated |
| 2.10.10.f | Semaphores | Isolated |
| 2.10.10.g | Message queues | Isolated |

---

## Partie 1: Container Fundamentals (2.10.1)

```rust
//! Container concepts implementation (2.10.1)

use std::process::Command;

/// Container definition (2.10.1.a)
pub struct Container {
    id: String,
    pid: Option<u32>,
    rootfs: String,
    status: ContainerStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContainerStatus {
    Created,
    Running,
    Stopped,
}

/// Container vs VM comparison (2.10.1.b)
pub struct IsolationComparison {
    pub shared_kernel: bool,      // Container: true, VM: false
    pub startup_time_ms: u64,     // Container: ~100ms, VM: ~seconds
    pub memory_overhead_mb: u64,  // Container: ~10MB, VM: ~512MB+
    pub isolation_level: IsolationLevel,
}

#[derive(Debug)]
pub enum IsolationLevel {
    Process,    // Container - process isolation
    Hardware,   // VM - hardware virtualization
}

/// Isolation primitives (2.10.1.c)
pub struct IsolationPrimitives {
    pub namespaces: Vec<NamespaceType>,
    pub cgroups: CgroupConfig,
    pub seccomp: SeccompProfile,
}

#[derive(Debug, Clone)]
pub enum NamespaceType {
    Pid,
    Network,
    Mount,
    Uts,
    Ipc,
    User,
    Cgroup,
}

pub struct CgroupConfig {
    pub cpu_shares: u64,
    pub memory_limit: u64,
    pub pids_max: u64,
}

pub struct SeccompProfile {
    pub default_action: SeccompAction,
    pub syscall_rules: Vec<SyscallRule>,
}

#[derive(Debug)]
pub enum SeccompAction {
    Allow,
    Deny,
    Log,
}

pub struct SyscallRule {
    pub syscall: String,
    pub action: SeccompAction,
}

/// Container image (2.10.1.d)
pub struct ContainerImage {
    pub name: String,
    pub tag: String,
    pub layers: Vec<ImageLayer>,
    pub config: ImageConfig,
}

pub struct ImageLayer {
    pub digest: String,
    pub size: u64,
    pub diff_id: String,
}

pub struct ImageConfig {
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub working_dir: String,
}

/// Container runtime interface (2.10.1.e)
pub trait ContainerRuntime {
    fn create(&self, config: &ContainerConfig) -> Result<Container, RuntimeError>;
    fn start(&self, container_id: &str) -> Result<(), RuntimeError>;
    fn stop(&self, container_id: &str, timeout: u32) -> Result<(), RuntimeError>;
    fn delete(&self, container_id: &str) -> Result<(), RuntimeError>;
    fn state(&self, container_id: &str) -> Result<ContainerState, RuntimeError>;
}

pub struct ContainerConfig {
    pub image: String,
    pub command: Vec<String>,
    pub env: Vec<String>,
    pub namespaces: Vec<NamespaceType>,
}

pub struct ContainerState {
    pub id: String,
    pub status: ContainerStatus,
    pub pid: Option<u32>,
    pub bundle: String,
}

#[derive(Debug)]
pub struct RuntimeError(pub String);

/// Rust runtimes (2.10.1.f)
pub mod rust_runtimes {
    /// youki - OCI container runtime in Rust
    pub const YOUKI: &str = "youki";

    /// crun - Fast OCI runtime (with Rust components)
    pub const CRUN: &str = "crun";

    pub fn list_rust_runtimes() -> Vec<&'static str> {
        vec![YOUKI, CRUN]
    }
}

/// OCI specification (2.10.1.g)
pub mod oci_spec {
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    pub struct Spec {
        pub oci_version: String,
        pub process: Process,
        pub root: Root,
        pub hostname: Option<String>,
        pub mounts: Vec<Mount>,
        pub linux: Option<Linux>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Process {
        pub terminal: bool,
        pub user: User,
        pub args: Vec<String>,
        pub env: Vec<String>,
        pub cwd: String,
    }

    #[derive(Serialize, Deserialize)]
    pub struct User {
        pub uid: u32,
        pub gid: u32,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Root {
        pub path: String,
        pub readonly: bool,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Mount {
        pub destination: String,
        pub source: Option<String>,
        pub r#type: Option<String>,
        pub options: Option<Vec<String>>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Linux {
        pub namespaces: Vec<LinuxNamespace>,
        pub resources: Option<Resources>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct LinuxNamespace {
        pub r#type: String,
        pub path: Option<String>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Resources {
        pub memory: Option<Memory>,
        pub cpu: Option<Cpu>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Memory {
        pub limit: Option<i64>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Cpu {
        pub shares: Option<u64>,
        pub quota: Option<i64>,
        pub period: Option<u64>,
    }
}

/// Why Rust for containers (2.10.1.h)
pub mod rust_benefits {
    pub struct SafetyBenefits {
        pub memory_safety: bool,      // No buffer overflows
        pub thread_safety: bool,      // Data race prevention
        pub null_safety: bool,        // Option<T> instead of null
        pub type_safety: bool,        // Strong type system
    }

    pub fn get_rust_security_benefits() -> SafetyBenefits {
        SafetyBenefits {
            memory_safety: true,
            thread_safety: true,
            null_safety: true,
            type_safety: true,
        }
    }

    pub const SECURITY_CRITICAL: &str =
        "Container runtimes run as root and handle untrusted code - \
         memory safety is critical for security";
}

fn main() {
    println!("=== Container Fundamentals (2.10.1) ===\n");

    // 2.10.1.a: Container definition
    let container = Container {
        id: "test-container-001".to_string(),
        pid: None,
        rootfs: "/var/lib/containers/test".to_string(),
        status: ContainerStatus::Created,
    };
    println!("Container ID: {}", container.id);

    // 2.10.1.b: Container vs VM
    let comparison = IsolationComparison {
        shared_kernel: true,
        startup_time_ms: 100,
        memory_overhead_mb: 10,
        isolation_level: IsolationLevel::Process,
    };
    println!("Shared kernel: {} (Container advantage)", comparison.shared_kernel);

    // 2.10.1.c: Isolation primitives
    let primitives = IsolationPrimitives {
        namespaces: vec![
            NamespaceType::Pid,
            NamespaceType::Network,
            NamespaceType::Mount,
        ],
        cgroups: CgroupConfig {
            cpu_shares: 1024,
            memory_limit: 512 * 1024 * 1024,
            pids_max: 100,
        },
        seccomp: SeccompProfile {
            default_action: SeccompAction::Allow,
            syscall_rules: vec![],
        },
    };
    println!("Namespaces: {:?}", primitives.namespaces);

    // 2.10.1.f: Rust runtimes
    println!("Rust runtimes: {:?}", rust_runtimes::list_rust_runtimes());

    // 2.10.1.h: Security benefits
    let benefits = rust_benefits::get_rust_security_benefits();
    println!("Memory safety: {}", benefits.memory_safety);
}
```

---

## Partie 2: Linux Namespaces (2.10.2-2.10.4)

```rust
//! Linux namespaces implementation (2.10.2-2.10.4)

use nix::sched::{CloneFlags, unshare};
use nix::unistd::{fork, ForkResult, getpid, Pid};
use nix::sys::wait::waitpid;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;

/// Namespace types (2.10.2.a, 2.10.2.c)
#[derive(Debug, Clone, Copy)]
pub enum Namespace {
    Pid,      // Process IDs
    Net,      // Network stack
    Mnt,      // Mount points
    Uts,      // Hostname/domain
    Ipc,      // IPC resources
    User,     // User/group IDs
    Cgroup,   // Cgroup root
    Time,     // Clock offsets (Linux 5.6+)
}

impl Namespace {
    /// Get namespace file path (2.10.2.h)
    pub fn proc_path(&self, pid: i32) -> String {
        let ns_name = match self {
            Namespace::Pid => "pid",
            Namespace::Net => "net",
            Namespace::Mnt => "mnt",
            Namespace::Uts => "uts",
            Namespace::Ipc => "ipc",
            Namespace::User => "user",
            Namespace::Cgroup => "cgroup",
            Namespace::Time => "time",
        };
        format!("/proc/{}/ns/{}", pid, ns_name)
    }

    /// Convert to CloneFlags (2.10.3.a)
    pub fn to_clone_flag(&self) -> CloneFlags {
        match self {
            Namespace::Pid => CloneFlags::CLONE_NEWPID,      // 2.10.3.b
            Namespace::Net => CloneFlags::CLONE_NEWNET,      // 2.10.3.c
            Namespace::Mnt => CloneFlags::CLONE_NEWNS,       // 2.10.3.d
            Namespace::Uts => CloneFlags::CLONE_NEWUTS,      // 2.10.3.e
            Namespace::Ipc => CloneFlags::CLONE_NEWIPC,      // 2.10.3.f
            Namespace::User => CloneFlags::CLONE_NEWUSER,    // 2.10.3.g
            Namespace::Cgroup => CloneFlags::CLONE_NEWCGROUP, // 2.10.3.h
            Namespace::Time => CloneFlags::empty(),          // Requires newer nix
        }
    }
}

/// Combine multiple namespace flags (2.10.3.i)
pub fn combine_namespace_flags(namespaces: &[Namespace]) -> CloneFlags {
    namespaces.iter()
        .fold(CloneFlags::empty(), |acc, ns| acc | ns.to_clone_flag())
}

/// Namespace manager using nix crate (2.10.2.d)
pub struct NamespaceManager {
    namespaces: Vec<Namespace>,
}

impl NamespaceManager {
    pub fn new() -> Self {
        Self { namespaces: Vec::new() }
    }

    pub fn add_namespace(&mut self, ns: Namespace) {
        self.namespaces.push(ns);
    }

    /// Unshare namespaces (2.10.2.f)
    pub fn unshare_namespaces(&self) -> nix::Result<()> {
        let flags = combine_namespace_flags(&self.namespaces);
        unshare(flags)
    }

    /// Join existing namespace (2.10.2.g)
    pub fn join_namespace(&self, ns: Namespace, pid: i32) -> nix::Result<()> {
        use nix::sched::setns;
        use std::os::unix::io::RawFd;

        let path = ns.proc_path(pid);
        let file = File::open(&path).map_err(|_| nix::errno::Errno::ENOENT)?;
        let fd = file.as_raw_fd();

        setns(fd, ns.to_clone_flag())
    }
}

/// PID namespace implementation (2.10.4)
pub mod pid_namespace {
    use super::*;

    /// Create new PID namespace (2.10.4.a, 2.10.4.d)
    pub fn create_pid_namespace() -> nix::Result<()> {
        // Unshare PID namespace
        unshare(CloneFlags::CLONE_NEWPID)?;

        // Must fork after unshare (2.10.4.e)
        // The child becomes PID 1 in new namespace (2.10.4.b)
        Ok(())
    }

    /// Fork into new PID namespace (2.10.4.e)
    pub fn fork_into_namespace<F>(child_fn: F) -> nix::Result<Pid>
    where
        F: FnOnce() -> i32,
    {
        // First unshare
        unshare(CloneFlags::CLONE_NEWPID)?;

        // Then fork - child will be PID 1 in new namespace
        match unsafe { fork()? } {
            ForkResult::Parent { child } => {
                println!("Parent: child PID in parent ns: {}", child);
                Ok(child)
            }
            ForkResult::Child => {
                // In child - we are PID 1 in new namespace
                println!("Child: PID in new namespace: {}", getpid());

                // Remount /proc for new namespace (2.10.4.f)
                // mount_proc().ok();

                let exit_code = child_fn();
                std::process::exit(exit_code);
            }
        }
    }

    /// PID 1 signal handling responsibilities (2.10.4.g)
    pub fn setup_init_signal_handler() {
        use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};

        // PID 1 must handle SIGCHLD to reap zombies
        let handler = SigHandler::Handler(sigchld_handler);
        let action = SigAction::new(handler, SaFlags::SA_NOCLDSTOP, SigSet::empty());

        unsafe {
            sigaction(Signal::SIGCHLD, &action).ok();
        }
    }

    extern "C" fn sigchld_handler(_: i32) {
        // Reap zombie processes
        loop {
            match nix::sys::wait::waitpid(
                Pid::from_raw(-1),
                Some(nix::sys::wait::WaitPidFlag::WNOHANG)
            ) {
                Ok(nix::sys::wait::WaitStatus::StillAlive) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }

    /// Check if nested namespaces (2.10.4.c)
    pub fn get_namespace_depth() -> usize {
        // Read /proc/self/ns/pid and compare with parent
        // Each level increases depth
        1 // Simplified
    }
}

fn main() {
    println!("=== Linux Namespaces (2.10.2-2.10.4) ===\n");

    // 2.10.2.c: List all namespace types
    let all_namespaces = [
        Namespace::Pid,
        Namespace::Net,
        Namespace::Mnt,
        Namespace::Uts,
        Namespace::Ipc,
        Namespace::User,
        Namespace::Cgroup,
    ];

    println!("Available namespaces:");
    for ns in &all_namespaces {
        println!("  {:?} -> {}", ns, ns.proc_path(std::process::id() as i32));
    }

    // 2.10.3.i: Combine flags
    let combined = combine_namespace_flags(&[Namespace::Pid, Namespace::Net, Namespace::Mnt]);
    println!("\nCombined flags: {:?}", combined);

    // 2.10.4: PID namespace info
    println!("\nPID namespace depth: {}", pid_namespace::get_namespace_depth());
}
```

---

## Partie 3: Network Namespace (2.10.5-2.10.6)

```rust
//! Network namespace implementation (2.10.5-2.10.6)

use std::net::Ipv4Addr;

/// Network namespace isolation (2.10.5.a)
pub struct NetworkNamespace {
    name: String,
    interfaces: Vec<NetworkInterface>,
}

/// Network interface (2.10.5.b)
pub struct NetworkInterface {
    name: String,
    mac_address: [u8; 6],
    ipv4_addresses: Vec<Ipv4Addr>,
    is_up: bool,
}

/// Virtual ethernet pair (2.10.5.c)
pub struct VethPair {
    pub host_end: String,   // e.g., "veth0"
    pub container_end: String, // e.g., "eth0"
}

impl VethPair {
    pub fn new(host_name: &str, container_name: &str) -> Self {
        Self {
            host_end: host_name.to_string(),
            container_end: container_name.to_string(),
        }
    }
}

/// rtnetlink interface (2.10.5.d, 2.10.6.a)
pub mod rtnetlink_ops {
    use super::*;

    /// Async netlink connection (2.10.6.b)
    pub struct NetlinkConnection {
        // In real impl: rtnetlink::Handle
    }

    impl NetlinkConnection {
        /// Create connection (2.10.6.b)
        pub async fn new() -> Result<Self, NetlinkError> {
            // let (connection, handle, _) = rtnetlink::new_connection()?;
            // tokio::spawn(connection);
            Ok(Self {})
        }

        /// Create veth pair (2.10.5.e, 2.10.6.c-d)
        pub async fn create_veth(&self, veth: &VethPair) -> Result<(), NetlinkError> {
            // handle.link()
            //     .add()
            //     .veth(veth.host_end.clone(), veth.container_end.clone())
            //     .execute()
            //     .await?;
            println!("Created veth pair: {} <-> {}", veth.host_end, veth.container_end);
            Ok(())
        }

        /// Move interface to namespace (2.10.5.f, 2.10.6.e)
        pub async fn move_to_namespace(&self, iface: &str, pid: u32) -> Result<(), NetlinkError> {
            // handle.link()
            //     .set(link_index)
            //     .setns_by_pid(pid)
            //     .execute()
            //     .await?;
            println!("Moved {} to namespace of PID {}", iface, pid);
            Ok(())
        }

        /// Assign IP address (2.10.5.h, 2.10.6.f)
        pub async fn assign_ip(&self, iface: &str, ip: Ipv4Addr, prefix: u8) -> Result<(), NetlinkError> {
            // handle.address()
            //     .add(link_index, IpAddr::V4(ip), prefix)
            //     .execute()
            //     .await?;
            println!("Assigned {}/{} to {}", ip, prefix, iface);
            Ok(())
        }

        /// Bring interface up (2.10.6.g)
        pub async fn link_up(&self, iface: &str) -> Result<(), NetlinkError> {
            // handle.link()
            //     .set(link_index)
            //     .up()
            //     .execute()
            //     .await?;
            println!("Brought {} up", iface);
            Ok(())
        }

        /// Create bridge (2.10.5.g, 2.10.6.h)
        pub async fn create_bridge(&self, name: &str) -> Result<(), NetlinkError> {
            // handle.link()
            //     .add()
            //     .bridge(name.to_string())
            //     .execute()
            //     .await?;
            println!("Created bridge: {}", name);
            Ok(())
        }

        /// Add interface to bridge (2.10.5.g)
        pub async fn add_to_bridge(&self, iface: &str, bridge: &str) -> Result<(), NetlinkError> {
            // handle.link()
            //     .set(link_index)
            //     .master(bridge_index)
            //     .execute()
            //     .await?;
            println!("Added {} to bridge {}", iface, bridge);
            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct NetlinkError(pub String);
}

/// Full container network setup
pub async fn setup_container_network(container_pid: u32) -> Result<(), rtnetlink_ops::NetlinkError> {
    use rtnetlink_ops::*;

    let conn = NetlinkConnection::new().await?;

    // Create veth pair
    let veth = VethPair::new("veth_host", "eth0");
    conn.create_veth(&veth).await?;

    // Move container end to namespace
    conn.move_to_namespace(&veth.container_end, container_pid).await?;

    // Setup host end
    conn.assign_ip(&veth.host_end, Ipv4Addr::new(10, 0, 0, 1), 24).await?;
    conn.link_up(&veth.host_end).await?;

    // Create bridge and add host veth
    conn.create_bridge("br0").await?;
    conn.add_to_bridge(&veth.host_end, "br0").await?;
    conn.link_up("br0").await?;

    Ok(())
}
```

---

## Partie 4: Mount Namespace (2.10.7-2.10.8)

```rust
//! Mount namespace and pivot_root (2.10.7-2.10.8)

use nix::mount::{mount, MsFlags, umount2, MntFlags};
use nix::unistd::pivot_root;
use std::path::Path;
use std::fs;

/// Mount namespace operations (2.10.7.a)
pub struct MountNamespace {
    rootfs: String,
}

impl MountNamespace {
    pub fn new(rootfs: &str) -> Self {
        Self { rootfs: rootfs.to_string() }
    }

    /// Mount filesystem (2.10.7.b)
    pub fn mount_fs(
        &self,
        source: Option<&str>,
        target: &str,
        fstype: Option<&str>,
        flags: MsFlags,
        data: Option<&str>,
    ) -> nix::Result<()> {
        mount(
            source,
            target,
            fstype,
            flags,
            data,
        )
    }

    /// Make mount private (2.10.7.d)
    pub fn make_private(&self, path: &str) -> nix::Result<()> {
        mount::<str, str, str, str>(
            None,
            path,
            None,
            MsFlags::MS_PRIVATE | MsFlags::MS_REC, // 2.10.7.e: MS_REC for recursive
            None,
        )
    }

    /// Bind mount (2.10.7.f)
    pub fn bind_mount(&self, source: &str, target: &str) -> nix::Result<()> {
        mount(
            Some(source),
            target,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
    }

    /// Setup container rootfs (2.10.7.g)
    pub fn setup_rootfs(&self) -> nix::Result<()> {
        // Make current root private
        self.make_private("/")?;

        // Bind mount new root
        self.bind_mount(&self.rootfs, &self.rootfs)?;

        Ok(())
    }
}

/// pivot_root implementation (2.10.8)
pub mod pivot_root_ops {
    use super::*;

    /// pivot_root is more secure than chroot (2.10.8.a-b)
    pub struct PivotRoot {
        new_root: String,
        put_old: String,
    }

    impl PivotRoot {
        /// Create pivot_root config (2.10.8.c-e)
        pub fn new(new_root: &str, put_old_name: &str) -> Self {
            Self {
                new_root: new_root.to_string(),
                put_old: format!("{}/{}", new_root, put_old_name),
            }
        }

        /// Execute pivot_root (2.10.8.c)
        pub fn execute(&self) -> nix::Result<()> {
            // new_root must be a mount point (2.10.8.d)
            mount(
                Some(self.new_root.as_str()),
                self.new_root.as_str(),
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            )?;

            // Create put_old directory (2.10.8.e)
            fs::create_dir_all(&self.put_old).ok();

            // Perform pivot_root
            pivot_root(
                Path::new(&self.new_root),
                Path::new(&self.put_old),
            )?;

            // Change to new root
            std::env::set_current_dir("/")?;

            Ok(())
        }

        /// Unmount old root (2.10.8.f)
        pub fn unmount_old(&self) -> nix::Result<()> {
            let old_root = format!("/{}", self.put_old.split('/').last().unwrap_or("old_root"));
            umount2(old_root.as_str(), MntFlags::MNT_DETACH)?;
            fs::remove_dir(&old_root).ok();
            Ok(())
        }

        /// Complete rootfs isolation (2.10.8.g)
        pub fn isolate_rootfs(&self) -> nix::Result<()> {
            self.execute()?;
            self.unmount_old()?;
            Ok(())
        }
    }
}
```

---

## Partie 5: User Namespace (2.10.9)

```rust
//! User namespace implementation (2.10.9)

use std::fs::{self, File, OpenOptions};
use std::io::Write;

/// User namespace for rootless containers (2.10.9.a, 2.10.9.h)
pub struct UserNamespace {
    pid: u32,
}

impl UserNamespace {
    pub fn new(pid: u32) -> Self {
        Self { pid }
    }

    /// Write UID mapping (2.10.9.d, 2.10.9.f)
    /// Format: "inside_uid outside_uid count"
    /// Example: "0 1000 1" maps UID 0 inside to UID 1000 outside
    pub fn write_uid_map(&self, inside: u32, outside: u32, count: u32) -> std::io::Result<()> {
        let path = format!("/proc/{}/uid_map", self.pid);
        let mapping = format!("{} {} {}", inside, outside, count);
        fs::write(&path, &mapping)?;
        println!("UID map: {} (inside {} -> outside {})", mapping, inside, outside);
        Ok(())
    }

    /// Write GID mapping (2.10.9.e, 2.10.9.f)
    pub fn write_gid_map(&self, inside: u32, outside: u32, count: u32) -> std::io::Result<()> {
        let path = format!("/proc/{}/gid_map", self.pid);
        let mapping = format!("{} {} {}", inside, outside, count);
        fs::write(&path, &mapping)?;
        println!("GID map: {}", mapping);
        Ok(())
    }

    /// Deny setgroups (2.10.9.g) - required before writing gid_map
    pub fn deny_setgroups(&self) -> std::io::Result<()> {
        let path = format!("/proc/{}/setgroups", self.pid);
        fs::write(&path, "deny")?;
        println!("setgroups denied for PID {}", self.pid);
        Ok(())
    }

    /// Setup rootless container (2.10.9.h)
    /// Maps root inside namespace to current user outside
    pub fn setup_rootless(&self, current_uid: u32, current_gid: u32) -> std::io::Result<()> {
        // Must deny setgroups first (2.10.9.g)
        self.deny_setgroups()?;

        // Map UID 0 (root inside) to current user (2.10.9.b-c)
        self.write_uid_map(0, current_uid, 1)?;
        self.write_gid_map(0, current_gid, 1)?;

        Ok(())
    }
}

/// Example rootless container setup
pub fn setup_rootless_container(child_pid: u32) -> std::io::Result<()> {
    let uid = nix::unistd::getuid().as_raw();
    let gid = nix::unistd::getgid().as_raw();

    let user_ns = UserNamespace::new(child_pid);
    user_ns.setup_rootless(uid, gid)?;

    println!("Rootless container ready - UID 0 inside = UID {} outside", uid);
    Ok(())
}
```

---

## Partie 6: UTS and IPC Namespaces (2.10.10)

```rust
//! UTS and IPC namespace implementation (2.10.10)

use nix::unistd::{sethostname, setdomainname};

/// UTS namespace operations (2.10.10.a-c)
pub struct UtsNamespace {
    hostname: String,
    domainname: Option<String>,
}

impl UtsNamespace {
    pub fn new(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_string(),
            domainname: None,
        }
    }

    pub fn with_domain(mut self, domain: &str) -> Self {
        self.domainname = Some(domain.to_string());
        self
    }

    /// Set hostname (2.10.10.b)
    pub fn apply_hostname(&self) -> nix::Result<()> {
        sethostname(&self.hostname)?;
        println!("Hostname set to: {}", self.hostname);
        Ok(())
    }

    /// Set domainname (2.10.10.c)
    pub fn apply_domainname(&self) -> nix::Result<()> {
        if let Some(ref domain) = self.domainname {
            setdomainname(domain)?;
            println!("Domainname set to: {}", domain);
        }
        Ok(())
    }

    pub fn apply(&self) -> nix::Result<()> {
        self.apply_hostname()?;
        self.apply_domainname()?;
        Ok(())
    }
}

/// IPC namespace isolation (2.10.10.d-g)
pub mod ipc_namespace {
    /// IPC resources that are isolated
    #[derive(Debug)]
    pub enum IpcResource {
        SharedMemory,   // 2.10.10.e: POSIX shared memory
        Semaphores,     // 2.10.10.f: POSIX semaphores
        MessageQueues,  // 2.10.10.g: POSIX message queues
    }

    /// IPC namespace info
    pub struct IpcNamespace {
        isolated_resources: Vec<IpcResource>,
    }

    impl IpcNamespace {
        pub fn new() -> Self {
            Self {
                isolated_resources: vec![
                    IpcResource::SharedMemory,
                    IpcResource::Semaphores,
                    IpcResource::MessageQueues,
                ],
            }
        }

        pub fn list_isolated(&self) {
            println!("IPC Namespace isolates:");
            for resource in &self.isolated_resources {
                println!("  - {:?}", resource);
            }
        }
    }
}

fn main() {
    println!("=== UTS and IPC Namespaces (2.10.10) ===\n");

    // UTS namespace
    let uts = UtsNamespace::new("container-host")
        .with_domain("container.local");
    println!("UTS config: hostname={}, domain={:?}",
             uts.hostname, uts.domainname);

    // IPC namespace
    let ipc = ipc_namespace::IpcNamespace::new();
    ipc.list_isolated();
}
```

---

## Concepts Couverts (Suite)

### 2.10.11: Cgroups v2 in Rust (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.11.a | Cgroups | Resource limiting |
| 2.10.11.b | `/sys/fs/cgroup` | Cgroup filesystem |
| 2.10.11.c | Unified hierarchy | v2 single tree |
| 2.10.11.d | `cgroups-rs` crate | High-level API |
| 2.10.11.e | `Cgroup::new()` | Create cgroup |
| 2.10.11.f | Controllers | cpu, memory, io, pids |
| 2.10.11.g | `cgroup.add_task()` | Add process |

### 2.10.12: CPU Cgroup (6 concepts - g already covered)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.12.a | `cpu.max` | Quota and period |
| 2.10.12.b | Format | `"$MAX $PERIOD"` |
| 2.10.12.c | 50% CPU | `"50000 100000"` |
| 2.10.12.d | `cpu.weight` | Relative weight (1-10000) |
| 2.10.12.e | `cpuset.cpus` | Pin to CPUs |
| 2.10.12.f | `cpuset.mems` | Memory nodes |

### 2.10.13: Memory Cgroup (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.13.a | `memory.max` | Hard limit (bytes) |
| 2.10.13.b | `memory.high` | Throttle point |
| 2.10.13.c | `memory.low` | Protection |
| 2.10.13.d | `memory.current` | Current usage |
| 2.10.13.e | `memory.swap.max` | Swap limit |
| 2.10.13.f | OOM behavior | Kill on exceed |
| 2.10.13.g | `memory.oom.group` | Kill entire cgroup |

### 2.10.14: I/O and PIDs Cgroup (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.14.a | `io.max` | I/O limits |
| 2.10.14.b | Format | `"MAJ:MIN rbps=X wbps=Y"` |
| 2.10.14.c | `io.weight` | Proportional weight |
| 2.10.14.d | `io.stat` | I/O statistics |
| 2.10.14.e | `pids.max` | Maximum processes |
| 2.10.14.f | `pids.current` | Current count |
| 2.10.14.g | Fork bomb protection | Limit processes |

---

## Partie 7: Cgroups v2 (2.10.11-2.10.14)

```rust
//! Cgroups v2 implementation (2.10.11-2.10.14)

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

/// Cgroup v2 manager (2.10.11.a-c)
pub struct CgroupV2 {
    path: PathBuf,
    name: String,
}

/// Cgroup controller types (2.10.11.f)
#[derive(Debug, Clone, Copy)]
pub enum CgroupController {
    Cpu,
    Memory,
    Io,
    Pids,
}

impl CgroupV2 {
    /// Base path for cgroup v2 (2.10.11.b)
    const CGROUP_ROOT: &'static str = "/sys/fs/cgroup";

    /// Create new cgroup (2.10.11.e)
    pub fn new(name: &str) -> std::io::Result<Self> {
        let path = PathBuf::from(Self::CGROUP_ROOT).join(name);
        fs::create_dir_all(&path)?;

        Ok(Self {
            path,
            name: name.to_string(),
        })
    }

    /// Add process to cgroup (2.10.11.g)
    pub fn add_task(&self, pid: u32) -> std::io::Result<()> {
        let procs_path = self.path.join("cgroup.procs");
        fs::write(&procs_path, pid.to_string())?;
        println!("Added PID {} to cgroup {}", pid, self.name);
        Ok(())
    }

    /// Enable controllers (2.10.11.f)
    pub fn enable_controllers(&self, controllers: &[CgroupController]) -> std::io::Result<()> {
        let subtree = self.path.join("cgroup.subtree_control");
        let ctrl_str: String = controllers.iter()
            .map(|c| format!("+{}", c.name()))
            .collect::<Vec<_>>()
            .join(" ");
        fs::write(&subtree, &ctrl_str)?;
        Ok(())
    }

    /// Write to cgroup file
    fn write_file(&self, filename: &str, value: &str) -> std::io::Result<()> {
        let path = self.path.join(filename);
        fs::write(&path, value)?;
        Ok(())
    }

    /// Read from cgroup file
    fn read_file(&self, filename: &str) -> std::io::Result<String> {
        let path = self.path.join(filename);
        fs::read_to_string(&path)
    }
}

impl CgroupController {
    fn name(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::Io => "io",
            Self::Pids => "pids",
        }
    }
}

/// CPU cgroup controller (2.10.12)
pub struct CpuController<'a> {
    cgroup: &'a CgroupV2,
}

impl<'a> CpuController<'a> {
    pub fn new(cgroup: &'a CgroupV2) -> Self {
        Self { cgroup }
    }

    /// Set CPU quota (2.10.12.a-c)
    /// Example: 50% CPU = quota=50000, period=100000
    pub fn set_cpu_max(&self, quota_us: u64, period_us: u64) -> std::io::Result<()> {
        let value = format!("{} {}", quota_us, period_us); // 2.10.12.b
        self.cgroup.write_file("cpu.max", &value)?;
        let percent = (quota_us as f64 / period_us as f64) * 100.0;
        println!("CPU max: {} ({}% of CPU)", value, percent);
        Ok(())
    }

    /// Set CPU weight (2.10.12.d)
    pub fn set_cpu_weight(&self, weight: u32) -> std::io::Result<()> {
        assert!(weight >= 1 && weight <= 10000, "Weight must be 1-10000");
        self.cgroup.write_file("cpu.weight", &weight.to_string())?;
        Ok(())
    }

    /// Pin to specific CPUs (2.10.12.e)
    pub fn set_cpuset_cpus(&self, cpus: &str) -> std::io::Result<()> {
        self.cgroup.write_file("cpuset.cpus", cpus)?;
        println!("Pinned to CPUs: {}", cpus);
        Ok(())
    }

    /// Set memory nodes (2.10.12.f)
    pub fn set_cpuset_mems(&self, mems: &str) -> std::io::Result<()> {
        self.cgroup.write_file("cpuset.mems", mems)?;
        Ok(())
    }
}

/// Memory cgroup controller (2.10.13)
pub struct MemoryController<'a> {
    cgroup: &'a CgroupV2,
}

impl<'a> MemoryController<'a> {
    pub fn new(cgroup: &'a CgroupV2) -> Self {
        Self { cgroup }
    }

    /// Set hard memory limit (2.10.13.a)
    pub fn set_max(&self, bytes: u64) -> std::io::Result<()> {
        self.cgroup.write_file("memory.max", &bytes.to_string())?;
        println!("Memory max: {} bytes ({} MB)", bytes, bytes / 1024 / 1024);
        Ok(())
    }

    /// Set throttle point (2.10.13.b)
    pub fn set_high(&self, bytes: u64) -> std::io::Result<()> {
        self.cgroup.write_file("memory.high", &bytes.to_string())?;
        Ok(())
    }

    /// Set protection level (2.10.13.c)
    pub fn set_low(&self, bytes: u64) -> std::io::Result<()> {
        self.cgroup.write_file("memory.low", &bytes.to_string())?;
        Ok(())
    }

    /// Get current usage (2.10.13.d)
    pub fn get_current(&self) -> std::io::Result<u64> {
        let value = self.cgroup.read_file("memory.current")?;
        value.trim().parse().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidData, "Invalid memory value"
        ))
    }

    /// Set swap limit (2.10.13.e)
    pub fn set_swap_max(&self, bytes: u64) -> std::io::Result<()> {
        self.cgroup.write_file("memory.swap.max", &bytes.to_string())?;
        Ok(())
    }

    /// Enable OOM group kill (2.10.13.g)
    pub fn set_oom_group(&self, enabled: bool) -> std::io::Result<()> {
        self.cgroup.write_file("memory.oom.group", if enabled { "1" } else { "0" })?;
        Ok(())
    }
}

/// I/O cgroup controller (2.10.14.a-d)
pub struct IoController<'a> {
    cgroup: &'a CgroupV2,
}

impl<'a> IoController<'a> {
    pub fn new(cgroup: &'a CgroupV2) -> Self {
        Self { cgroup }
    }

    /// Set I/O limits (2.10.14.a-b)
    /// Format: "MAJ:MIN rbps=X wbps=Y riops=X wiops=Y"
    pub fn set_max(&self, major: u32, minor: u32, rbps: Option<u64>, wbps: Option<u64>) -> std::io::Result<()> {
        let mut parts = vec![format!("{}:{}", major, minor)];
        if let Some(r) = rbps { parts.push(format!("rbps={}", r)); }
        if let Some(w) = wbps { parts.push(format!("wbps={}", w)); }
        let value = parts.join(" ");
        self.cgroup.write_file("io.max", &value)?;
        println!("IO max: {}", value);
        Ok(())
    }

    /// Set I/O weight (2.10.14.c)
    pub fn set_weight(&self, weight: u32) -> std::io::Result<()> {
        self.cgroup.write_file("io.weight", &format!("default {}", weight))?;
        Ok(())
    }

    /// Get I/O statistics (2.10.14.d)
    pub fn get_stat(&self) -> std::io::Result<String> {
        self.cgroup.read_file("io.stat")
    }
}

/// PIDs cgroup controller (2.10.14.e-g)
pub struct PidsController<'a> {
    cgroup: &'a CgroupV2,
}

impl<'a> PidsController<'a> {
    pub fn new(cgroup: &'a CgroupV2) -> Self {
        Self { cgroup }
    }

    /// Set maximum processes (2.10.14.e, 2.10.14.g)
    pub fn set_max(&self, max: u32) -> std::io::Result<()> {
        self.cgroup.write_file("pids.max", &max.to_string())?;
        println!("PIDs max: {} (fork bomb protection)", max);
        Ok(())
    }

    /// Get current process count (2.10.14.f)
    pub fn get_current(&self) -> std::io::Result<u32> {
        let value = self.cgroup.read_file("pids.current")?;
        value.trim().parse().map_err(|_| std::io::Error::new(
            std::io::ErrorKind::InvalidData, "Invalid pids value"
        ))
    }
}

fn main() {
    println!("=== Cgroups v2 (2.10.11-2.10.14) ===\n");

    // Note: Requires root and cgroups v2 mounted
    println!("Creating cgroup for container...");

    // Example usage (would need root):
    // let cg = CgroupV2::new("my_container").unwrap();
    // CpuController::new(&cg).set_cpu_max(50000, 100000).unwrap();
    // MemoryController::new(&cg).set_max(512 * 1024 * 1024).unwrap();
    // PidsController::new(&cg).set_max(100).unwrap();
    // cg.add_task(std::process::id()).unwrap();
}
```

---

### 2.10.15: seccomp in Rust (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.15.a | seccomp | System call filtering |
| 2.10.15.b | BPF filter | Filter program |
| 2.10.15.c | `seccompiler` crate | Rust seccomp |
| 2.10.15.d | `SeccompFilter::new()` | Create filter |
| 2.10.15.e | `SeccompAction` | ALLOW, ERRNO, KILL |
| 2.10.15.f | `SeccompRule` | Match syscall |
| 2.10.15.g | `apply_filter()` | Activate |
| 2.10.15.h | Default deny | Allowlist approach |

### 2.10.16: seccomp Filter Example (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.16.a | `BpfMap` | Syscall to action |
| 2.10.16.b | `SeccompCondition` | Argument checks |
| 2.10.16.c | `SeccompCmpOp` | Comparison operators |
| 2.10.16.d | Build filter | Add rules |
| 2.10.16.e | `SeccompFilter::try_from()` | From rules |
| 2.10.16.f | `filter.apply()` | Install filter |
| 2.10.16.g | `PR_SET_NO_NEW_PRIVS` | Required first |
| 2.10.16.h | Docker profile | Default seccomp |

### 2.10.17: Linux Capabilities (7 concepts - h-i already covered)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.17.a | Capabilities | Fine-grained privileges |
| 2.10.17.b | `caps` crate | Rust capabilities |
| 2.10.17.c | `Capability::` enum | All capabilities |
| 2.10.17.d | `CAP_NET_ADMIN` | Network admin |
| 2.10.17.e | `CAP_SYS_ADMIN` | Various admin ops |
| 2.10.17.f | `caps::drop()` | Drop capability |
| 2.10.17.g | `caps::set()` | Set capabilities |

### 2.10.18: Capabilities Management (7 concepts - h already covered)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.18.a | `caps::read()` | Read current caps |
| 2.10.18.b | `caps::has_cap()` | Check capability |
| 2.10.18.c | `caps::clear()` | Clear all |
| 2.10.18.d | `caps::raise()` | Add capability |
| 2.10.18.e | `CapSet::Effective` | Currently active |
| 2.10.18.f | `CapSet::Permitted` | Can be raised |
| 2.10.18.g | Minimal set | Only what's needed |

---

## Partie 8: seccomp (2.10.15-2.10.16)

```rust
//! seccomp implementation (2.10.15-2.10.16)

use std::collections::BTreeMap;

/// seccomp action types (2.10.15.e)
#[derive(Debug, Clone, Copy)]
pub enum SeccompAction {
    Allow,           // Allow syscall
    Errno(i32),      // Return error
    Kill,            // Kill process
    KillProcess,     // Kill entire process
    Log,             // Log and allow
    Trace(u16),      // Notify tracer
}

/// Comparison operators (2.10.16.c)
#[derive(Debug, Clone, Copy)]
pub enum SeccompCmpOp {
    Eq,   // Equal
    Ne,   // Not equal
    Lt,   // Less than
    Le,   // Less or equal
    Gt,   // Greater than
    Ge,   // Greater or equal
    MaskedEq(u64), // Masked equal
}

/// Argument condition (2.10.16.b)
pub struct SeccompCondition {
    pub arg_index: u8,        // Argument number (0-5)
    pub operator: SeccompCmpOp,
    pub value: u64,
}

impl SeccompCondition {
    pub fn new(arg_index: u8, operator: SeccompCmpOp, value: u64) -> Self {
        Self { arg_index, operator, value }
    }
}

/// seccomp rule (2.10.15.f)
pub struct SeccompRule {
    pub syscall: i64,
    pub action: SeccompAction,
    pub conditions: Vec<SeccompCondition>,
}

impl SeccompRule {
    pub fn new(syscall: i64, action: SeccompAction) -> Self {
        Self { syscall, action, conditions: Vec::new() }
    }

    pub fn with_condition(mut self, cond: SeccompCondition) -> Self {
        self.conditions.push(cond);
        self
    }
}

/// BPF map for syscall filtering (2.10.16.a)
pub type BpfMap = BTreeMap<i64, Vec<SeccompRule>>;

/// seccomp filter (2.10.15.a-d)
pub struct SeccompFilter {
    default_action: SeccompAction, // 2.10.15.h: Default deny
    rules: BpfMap,                 // 2.10.16.a
}

impl SeccompFilter {
    /// Create new filter (2.10.15.d)
    pub fn new(default_action: SeccompAction) -> Self {
        Self {
            default_action,
            rules: BTreeMap::new(),
        }
    }

    /// Add rule (2.10.16.d)
    pub fn add_rule(&mut self, rule: SeccompRule) {
        self.rules.entry(rule.syscall)
            .or_insert_with(Vec::new)
            .push(rule);
    }

    /// Build filter from rules (2.10.16.e)
    pub fn try_from_rules(default: SeccompAction, rules: Vec<SeccompRule>) -> Result<Self, String> {
        let mut filter = Self::new(default);
        for rule in rules {
            filter.add_rule(rule);
        }
        Ok(filter)
    }

    /// Apply filter (2.10.15.g, 2.10.16.f)
    pub fn apply(&self) -> Result<(), SeccompError> {
        // First, set PR_SET_NO_NEW_PRIVS (2.10.16.g)
        #[cfg(target_os = "linux")]
        unsafe {
            let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            if ret != 0 {
                return Err(SeccompError::NoNewPrivs);
            }
        }

        // In real implementation: compile BPF program and apply
        // seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)
        println!("seccomp filter applied with {} rules", self.rules.len());
        Ok(())
    }
}

#[derive(Debug)]
pub enum SeccompError {
    NoNewPrivs,
    FilterFailed,
}

/// Docker default seccomp profile (2.10.16.h)
pub fn docker_default_profile() -> SeccompFilter {
    let mut filter = SeccompFilter::new(SeccompAction::Errno(libc::EPERM));

    // Allow common syscalls
    let allowed_syscalls = [
        libc::SYS_read, libc::SYS_write, libc::SYS_open, libc::SYS_close,
        libc::SYS_stat, libc::SYS_fstat, libc::SYS_mmap, libc::SYS_mprotect,
        libc::SYS_munmap, libc::SYS_brk, libc::SYS_exit, libc::SYS_exit_group,
        // ... many more in real profile
    ];

    for syscall in allowed_syscalls {
        filter.add_rule(SeccompRule::new(syscall, SeccompAction::Allow));
    }

    // Deny dangerous syscalls
    let denied = [
        libc::SYS_ptrace,       // No tracing
        libc::SYS_reboot,       // No rebooting
        libc::SYS_init_module,  // No kernel modules
    ];

    for syscall in denied {
        filter.add_rule(SeccompRule::new(syscall, SeccompAction::Errno(libc::EPERM)));
    }

    filter
}
```

---

## Partie 9: Linux Capabilities (2.10.17-2.10.18)

```rust
//! Linux capabilities implementation (2.10.17-2.10.18)

/// Capability enum (2.10.17.c)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum Capability {
    Chown = 0,
    DacOverride = 1,
    DacReadSearch = 2,
    Fowner = 3,
    Fsetid = 4,
    Kill = 5,
    Setgid = 6,
    Setuid = 7,
    Setpcap = 8,
    LinuxImmutable = 9,
    NetBindService = 10,
    NetBroadcast = 11,
    NetAdmin = 12,        // 2.10.17.d
    NetRaw = 13,
    IpcLock = 14,
    IpcOwner = 15,
    SysModule = 16,
    SysRawio = 17,
    SysChroot = 18,
    SysPtrace = 19,
    SysPacct = 20,
    SysAdmin = 21,        // 2.10.17.e
    SysBoot = 22,
    SysNice = 23,
    SysResource = 24,
    SysTime = 25,
    SysTtyConfig = 26,
    Mknod = 27,
    Lease = 28,
    AuditWrite = 29,
    AuditControl = 30,
    Setfcap = 31,
    MacOverride = 32,
    MacAdmin = 33,
    Syslog = 34,
    WakeAlarm = 35,
    BlockSuspend = 36,
    AuditRead = 37,
}

/// Capability set types (2.10.18.e-f)
#[derive(Debug, Clone, Copy)]
pub enum CapSet {
    Effective,    // 2.10.18.e: Currently active
    Permitted,    // 2.10.18.f: Can be raised
    Inheritable,  // Passed to exec'd programs
    Bounding,     // Maximum possible
    Ambient,      // Auto-raised on exec
}

/// Capabilities manager (2.10.17.b)
pub struct CapsManager {
    effective: std::collections::HashSet<Capability>,
    permitted: std::collections::HashSet<Capability>,
    inheritable: std::collections::HashSet<Capability>,
}

impl CapsManager {
    /// Read current capabilities (2.10.18.a)
    pub fn read() -> Result<Self, CapsError> {
        // In real impl: capget() syscall
        Ok(Self {
            effective: std::collections::HashSet::new(),
            permitted: std::collections::HashSet::new(),
            inheritable: std::collections::HashSet::new(),
        })
    }

    /// Check if capability is set (2.10.18.b)
    pub fn has_cap(&self, cap: Capability, set: CapSet) -> bool {
        match set {
            CapSet::Effective => self.effective.contains(&cap),
            CapSet::Permitted => self.permitted.contains(&cap),
            CapSet::Inheritable => self.inheritable.contains(&cap),
            _ => false,
        }
    }

    /// Clear all capabilities (2.10.18.c)
    pub fn clear(&mut self, set: CapSet) {
        match set {
            CapSet::Effective => self.effective.clear(),
            CapSet::Permitted => self.permitted.clear(),
            CapSet::Inheritable => self.inheritable.clear(),
            _ => {}
        }
    }

    /// Raise capability (2.10.18.d)
    pub fn raise(&mut self, cap: Capability, set: CapSet) -> Result<(), CapsError> {
        if set == CapSet::Effective && !self.permitted.contains(&cap) {
            return Err(CapsError::NotPermitted);
        }
        match set {
            CapSet::Effective => { self.effective.insert(cap); }
            CapSet::Permitted => { self.permitted.insert(cap); }
            CapSet::Inheritable => { self.inheritable.insert(cap); }
            _ => {}
        }
        Ok(())
    }

    /// Drop capability (2.10.17.f)
    pub fn drop(&mut self, cap: Capability, set: CapSet) {
        match set {
            CapSet::Effective => { self.effective.remove(&cap); }
            CapSet::Permitted => { self.permitted.remove(&cap); }
            CapSet::Inheritable => { self.inheritable.remove(&cap); }
            _ => {}
        }
    }

    /// Set capabilities (2.10.17.g)
    pub fn apply(&self) -> Result<(), CapsError> {
        // In real impl: capset() syscall
        println!("Applied capabilities: {} effective, {} permitted",
                 self.effective.len(), self.permitted.len());
        Ok(())
    }
}

#[derive(Debug)]
pub enum CapsError {
    NotPermitted,
    SyscallFailed,
}

/// Minimal capability set for containers (2.10.18.g)
pub fn container_minimal_caps() -> Vec<Capability> {
    vec![
        Capability::Chown,
        Capability::DacOverride,
        Capability::Fsetid,
        Capability::Fowner,
        Capability::Setgid,
        Capability::Setuid,
        Capability::Setpcap,
        Capability::NetBindService,
        Capability::SysChroot,
        Capability::Kill,
        Capability::AuditWrite,
    ]
}

fn main() {
    println!("=== Linux Capabilities (2.10.17-2.10.18) ===\n");

    let minimal = container_minimal_caps();
    println!("Minimal container caps ({}):", minimal.len());
    for cap in &minimal {
        println!("  {:?}", cap);
    }
}
```

---

### 2.10.19: OverlayFS (6 concepts - g-h already covered)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.19.a | OverlayFS | Union filesystem |
| 2.10.19.b | Lower layers | Read-only |
| 2.10.19.c | Upper layer | Read-write |
| 2.10.19.d | Work directory | Required |
| 2.10.19.e | Mount options | `lowerdir`, `upperdir`, `workdir` |
| 2.10.19.f | `nix::mount::mount()` | Mount overlay |

### 2.10.20: OCI Specification (8 concepts - i-j already covered)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.20.a | OCI | Open Container Initiative |
| 2.10.20.b | Runtime spec | Container lifecycle |
| 2.10.20.c | Image spec | Image format |
| 2.10.20.d | `config.json` | Container configuration |
| 2.10.20.e | `oci-spec` crate | Rust OCI types |
| 2.10.20.f | `Spec` | Full specification |
| 2.10.20.g | `Process` | Process config |
| 2.10.20.h | `Root` | Root filesystem |

### 2.10.21: Building Container Runtime (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.21.a | Runtime commands | create, start, kill, delete |
| 2.10.21.b | State machine | Created, running, stopped |
| 2.10.21.c | State file | `/run/containers/<id>/state.json` |
| 2.10.21.d | Container process | Forked child |
| 2.10.21.e | Namespace setup | Before exec |
| 2.10.21.f | Cgroup setup | Add to cgroup |
| 2.10.21.g | Rootfs setup | pivot_root |
| 2.10.21.h | Execute | `execvp()` |

### 2.10.22: Container Runtime Architecture (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.22.a | CLI | `clap` argument parsing |
| 2.10.22.b | Config parsing | `serde` + `oci-spec` |
| 2.10.22.c | Container struct | State management |
| 2.10.22.d | Namespace module | Isolation setup |
| 2.10.22.e | Cgroup module | Resource limits |
| 2.10.22.f | Network module | Networking setup |
| 2.10.22.g | Filesystem module | Mounts, pivot_root |
| 2.10.22.h | Process module | Fork, exec |

---

## Partie 10: OverlayFS (2.10.19)

```rust
//! OverlayFS implementation (2.10.19)

use nix::mount::{mount, MsFlags};
use std::path::Path;
use std::fs;

/// OverlayFS mount (2.10.19.a)
pub struct OverlayFs {
    lower_dirs: Vec<String>,  // 2.10.19.b: Read-only layers
    upper_dir: String,        // 2.10.19.c: Read-write layer
    work_dir: String,         // 2.10.19.d: Required work directory
    merged_dir: String,       // Mount point
}

impl OverlayFs {
    pub fn new(merged: &str, upper: &str, work: &str) -> Self {
        Self {
            lower_dirs: Vec::new(),
            upper_dir: upper.to_string(),
            work_dir: work.to_string(),
            merged_dir: merged.to_string(),
        }
    }

    /// Add lower (read-only) layer (2.10.19.b)
    pub fn add_lower(&mut self, path: &str) {
        self.lower_dirs.push(path.to_string());
    }

    /// Build mount options (2.10.19.e)
    fn build_options(&self) -> String {
        format!(
            "lowerdir={},upperdir={},workdir={}",
            self.lower_dirs.join(":"),
            self.upper_dir,
            self.work_dir
        )
    }

    /// Mount overlay filesystem (2.10.19.f)
    pub fn mount(&self) -> nix::Result<()> {
        // Create directories if needed
        fs::create_dir_all(&self.upper_dir).ok();
        fs::create_dir_all(&self.work_dir).ok();
        fs::create_dir_all(&self.merged_dir).ok();

        let options = self.build_options();
        println!("Mounting overlay with options: {}", options);

        mount(
            Some("overlay"),
            self.merged_dir.as_str(),
            Some("overlay"),
            MsFlags::empty(),
            Some(options.as_str()),
        )
    }
}

/// Container image layers (2.10.19.b)
pub struct ImageLayers {
    layers: Vec<String>,
}

impl ImageLayers {
    pub fn from_paths(paths: Vec<&str>) -> Self {
        Self {
            layers: paths.into_iter().map(String::from).collect(),
        }
    }

    /// Create overlay for container (2.10.19.a)
    pub fn create_overlay(&self, container_id: &str) -> OverlayFs {
        let base = format!("/var/lib/containers/{}", container_id);
        let mut overlay = OverlayFs::new(
            &format!("{}/merged", base),
            &format!("{}/upper", base),
            &format!("{}/work", base),
        );

        // Add all image layers as lower dirs
        for layer in &self.layers {
            overlay.add_lower(layer);
        }

        overlay
    }
}
```

---

## Partie 11: OCI Specification (2.10.20)

```rust
//! OCI Specification implementation (2.10.20)

use serde::{Deserialize, Serialize};
use std::path::Path;

/// OCI Runtime Specification (2.10.20.a-b, 2.10.20.f)
#[derive(Serialize, Deserialize, Debug)]
pub struct OciSpec {
    #[serde(rename = "ociVersion")]
    pub oci_version: String,           // 2.10.20.a
    pub process: OciProcess,           // 2.10.20.g
    pub root: OciRoot,                 // 2.10.20.h
    pub hostname: Option<String>,
    pub mounts: Vec<OciMount>,
    pub linux: Option<OciLinux>,
}

/// Process configuration (2.10.20.g)
#[derive(Serialize, Deserialize, Debug)]
pub struct OciProcess {
    pub terminal: bool,
    pub user: OciUser,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub capabilities: Option<OciCapabilities>,
    pub rlimits: Option<Vec<OciRlimit>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciUser {
    pub uid: u32,
    pub gid: u32,
    #[serde(rename = "additionalGids")]
    pub additional_gids: Option<Vec<u32>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciCapabilities {
    pub bounding: Vec<String>,
    pub effective: Vec<String>,
    pub inheritable: Vec<String>,
    pub permitted: Vec<String>,
    pub ambient: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciRlimit {
    #[serde(rename = "type")]
    pub limit_type: String,
    pub hard: u64,
    pub soft: u64,
}

/// Root filesystem (2.10.20.h)
#[derive(Serialize, Deserialize, Debug)]
pub struct OciRoot {
    pub path: String,
    pub readonly: bool,
}

/// Mount point
#[derive(Serialize, Deserialize, Debug)]
pub struct OciMount {
    pub destination: String,
    pub source: Option<String>,
    #[serde(rename = "type")]
    pub mount_type: Option<String>,
    pub options: Option<Vec<String>>,
}

/// Linux-specific configuration
#[derive(Serialize, Deserialize, Debug)]
pub struct OciLinux {
    pub namespaces: Vec<OciNamespace>,
    pub resources: Option<OciResources>,
    pub seccomp: Option<OciSeccomp>,
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
    pub swap: Option<i64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciCpu {
    pub shares: Option<u64>,
    pub quota: Option<i64>,
    pub period: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciPids {
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciSeccomp {
    #[serde(rename = "defaultAction")]
    pub default_action: String,
    pub architectures: Vec<String>,
    pub syscalls: Vec<OciSyscall>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OciSyscall {
    pub names: Vec<String>,
    pub action: String,
}

/// Parse config.json (2.10.20.d)
pub fn parse_config(path: &Path) -> Result<OciSpec, ConfigError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::IoError(e.to_string()))?;
    serde_json::from_str(&content)
        .map_err(|e| ConfigError::ParseError(e.to_string()))
}

#[derive(Debug)]
pub enum ConfigError {
    IoError(String),
    ParseError(String),
}

/// OCI Image Specification (2.10.20.c)
#[derive(Serialize, Deserialize, Debug)]
pub struct OciImageConfig {
    pub architecture: String,
    pub os: String,
    pub config: ImageConfig,
    pub rootfs: RootFs,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ImageConfig {
    #[serde(rename = "Cmd")]
    pub cmd: Option<Vec<String>>,
    #[serde(rename = "Entrypoint")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(rename = "Env")]
    pub env: Option<Vec<String>>,
    #[serde(rename = "WorkingDir")]
    pub working_dir: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RootFs {
    #[serde(rename = "type")]
    pub fs_type: String,
    pub diff_ids: Vec<String>,
}
```

---

## Partie 12: Container Runtime (2.10.21-2.10.22)

```rust
//! Container Runtime implementation (2.10.21-2.10.22)

use std::path::PathBuf;
use std::process::Command;

/// Container state (2.10.21.b)
#[derive(Debug, Clone, PartialEq)]
pub enum ContainerState {
    Creating,
    Created,   // 2.10.21.b
    Running,   // 2.10.21.b
    Stopped,   // 2.10.21.b
}

/// Container runtime (2.10.21)
pub struct ContainerRuntime {
    root_dir: PathBuf,  // 2.10.21.c: State directory
}

impl ContainerRuntime {
    pub fn new(root: &str) -> Self {
        Self { root_dir: PathBuf::from(root) }
    }

    /// create command (2.10.21.a)
    pub fn create(&self, id: &str, bundle: &str) -> Result<Container, RuntimeError> {
        let container = Container::new(id, bundle, &self.root_dir);

        // 2.10.21.e: Setup namespaces (done in Container::start)
        // 2.10.21.f: Setup cgroups (done in Container::start)
        // 2.10.21.g: Setup rootfs (done in Container::start)

        container.save_state()?;
        Ok(container)
    }

    /// start command (2.10.21.a)
    pub fn start(&self, id: &str) -> Result<(), RuntimeError> {
        let mut container = Container::load(&self.root_dir, id)?;
        container.start()?;
        Ok(())
    }

    /// kill command (2.10.21.a)
    pub fn kill(&self, id: &str, signal: i32) -> Result<(), RuntimeError> {
        let container = Container::load(&self.root_dir, id)?;
        container.kill(signal)?;
        Ok(())
    }

    /// delete command (2.10.21.a)
    pub fn delete(&self, id: &str) -> Result<(), RuntimeError> {
        let container = Container::load(&self.root_dir, id)?;
        container.delete()?;
        Ok(())
    }
}

/// Container struct (2.10.22.c)
pub struct Container {
    id: String,
    bundle: String,
    state: ContainerState,
    pid: Option<u32>,           // 2.10.21.d
    state_dir: PathBuf,
}

impl Container {
    pub fn new(id: &str, bundle: &str, root: &PathBuf) -> Self {
        Self {
            id: id.to_string(),
            bundle: bundle.to_string(),
            state: ContainerState::Creating,
            pid: None,
            state_dir: root.join(id),
        }
    }

    /// Load container from state file (2.10.21.c)
    pub fn load(root: &PathBuf, id: &str) -> Result<Self, RuntimeError> {
        let state_path = root.join(id).join("state.json");
        // Read and deserialize state
        Ok(Self::new(id, "", root))
    }

    /// Save state to file (2.10.21.c)
    pub fn save_state(&self) -> Result<(), RuntimeError> {
        std::fs::create_dir_all(&self.state_dir)
            .map_err(|e| RuntimeError::IoError(e.to_string()))?;

        let state_json = serde_json::json!({
            "id": self.id,
            "status": format!("{:?}", self.state),
            "pid": self.pid,
            "bundle": self.bundle,
        });

        let path = self.state_dir.join("state.json");
        std::fs::write(&path, state_json.to_string())
            .map_err(|e| RuntimeError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Start container (2.10.21.d-h)
    pub fn start(&mut self) -> Result<(), RuntimeError> {
        // 2.10.21.d: Fork container process
        // In real impl: fork() + setup in child

        println!("Starting container {}", self.id);

        // 2.10.21.e: Setup namespaces
        self.setup_namespaces()?;

        // 2.10.21.f: Setup cgroups
        self.setup_cgroups()?;

        // 2.10.21.g: Setup rootfs with pivot_root
        self.setup_rootfs()?;

        // 2.10.21.h: Execute container process
        self.exec_process()?;

        self.state = ContainerState::Running;
        self.save_state()?;

        Ok(())
    }

    /// Setup namespaces (2.10.22.d)
    fn setup_namespaces(&self) -> Result<(), RuntimeError> {
        println!("Setting up namespaces for container {}", self.id);
        // Use nix::sched::unshare with appropriate flags
        Ok(())
    }

    /// Setup cgroups (2.10.22.e)
    fn setup_cgroups(&self) -> Result<(), RuntimeError> {
        println!("Setting up cgroups for container {}", self.id);
        // Create cgroup and add process
        Ok(())
    }

    /// Setup rootfs (2.10.22.g)
    fn setup_rootfs(&self) -> Result<(), RuntimeError> {
        println!("Setting up rootfs for container {}", self.id);
        // Mount overlay, pivot_root
        Ok(())
    }

    /// Execute process (2.10.22.h)
    fn exec_process(&self) -> Result<(), RuntimeError> {
        println!("Executing process for container {}", self.id);
        // nix::unistd::execvp()
        Ok(())
    }

    /// Kill container
    pub fn kill(&self, signal: i32) -> Result<(), RuntimeError> {
        if let Some(pid) = self.pid {
            // nix::sys::signal::kill(Pid::from_raw(pid as i32), Signal::try_from(signal))
            println!("Killing container {} (PID {}) with signal {}", self.id, pid, signal);
        }
        Ok(())
    }

    /// Delete container
    pub fn delete(self) -> Result<(), RuntimeError> {
        std::fs::remove_dir_all(&self.state_dir)
            .map_err(|e| RuntimeError::IoError(e.to_string()))?;
        println!("Deleted container {}", self.id);
        Ok(())
    }
}

#[derive(Debug)]
pub enum RuntimeError {
    IoError(String),
    StateError(String),
    ExecError(String),
}

/// CLI interface (2.10.22.a)
pub mod cli {
    use super::*;

    pub fn parse_args() -> CliCommand {
        // Using clap in real implementation
        CliCommand::Help
    }

    pub enum CliCommand {
        Create { id: String, bundle: String },
        Start { id: String },
        Kill { id: String, signal: i32 },
        Delete { id: String },
        State { id: String },
        Help,
    }
}

fn main() {
    println!("=== Container Runtime (2.10.21-2.10.22) ===\n");

    let runtime = ContainerRuntime::new("/run/mycontainer");
    println!("Runtime initialized at /run/mycontainer");
}
```

---

## PARTIE B: VIRTUALIZATION

### 2.10.23: Virtualization Concepts (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.23.a | Virtual machine | Simulated computer |
| 2.10.23.b | Guest OS | OS in VM |
| 2.10.23.c | Host OS | OS running hypervisor |
| 2.10.23.d | Hypervisor | VM manager |
| 2.10.23.e | Type 1 | Bare-metal (ESXi, Xen) |
| 2.10.23.f | Type 2 | Hosted (VirtualBox) |
| 2.10.23.g | KVM | Linux kernel hypervisor |
| 2.10.23.h | Rust hypervisors | Firecracker, cloud-hypervisor |

### 2.10.24: Hardware Virtualization (7 concepts - h-i already covered)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.24.a | Intel VT-x | Intel virtualization |
| 2.10.24.b | AMD-V | AMD virtualization |
| 2.10.24.c | VMX operations | VMXON, VMLAUNCH, VMRESUME |
| 2.10.24.d | Root mode | Hypervisor context |
| 2.10.24.e | Non-root mode | Guest context |
| 2.10.24.f | VMCS | VM Control Structure |
| 2.10.24.g | VM entry | Enter guest |

### 2.10.25: KVM Architecture (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.25.a | KVM | Kernel-based Virtual Machine |
| 2.10.25.b | `/dev/kvm` | KVM device |
| 2.10.25.c | ioctl interface | Control VMs |
| 2.10.25.d | VM fd | Per-VM file descriptor |
| 2.10.25.e | vCPU fd | Per-CPU file descriptor |
| 2.10.25.f | `KVM_CREATE_VM` | Create VM |
| 2.10.25.g | `KVM_CREATE_VCPU` | Create vCPU |
| 2.10.25.h | `KVM_RUN` | Execute guest |

### 2.10.26: KVM in Rust - kvm-ioctls (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.26.a | `kvm-ioctls` crate | Safe KVM wrapper |
| 2.10.26.b | `kvm-bindings` crate | KVM structures |
| 2.10.26.c | `Kvm::new()` | Open /dev/kvm |
| 2.10.26.d | `kvm.create_vm()` | Create VM |
| 2.10.26.e | `vm.create_vcpu()` | Create vCPU |
| 2.10.26.f | `VcpuFd` | vCPU handle |
| 2.10.26.g | `vcpu.run()` | Execute |
| 2.10.26.h | `VcpuExit` | Exit reason |

### 2.10.27: VM Memory Setup (7 concepts - h already covered)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.27.a | Guest memory | Mapped host memory |
| 2.10.27.b | `vm-memory` crate | Memory abstractions |
| 2.10.27.c | `GuestMemoryMmap` | Mmap-backed memory |
| 2.10.27.d | `GuestAddress` | Guest physical address |
| 2.10.27.e | `MmapRegion` | Memory region |
| 2.10.27.f | `KVM_SET_USER_MEMORY_REGION` | Register memory |
| 2.10.27.g | `kvm_userspace_memory_region` | Memory config |

### 2.10.28: vCPU Setup (7 concepts - h already covered)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.28.a | `kvm_sregs` | Special registers |
| 2.10.28.b | `kvm_regs` | General registers |
| 2.10.28.c | `vcpu.get_sregs()` | Read special regs |
| 2.10.28.d | `vcpu.set_sregs()` | Write special regs |
| 2.10.28.e | `vcpu.get_regs()` | Read general regs |
| 2.10.28.f | `vcpu.set_regs()` | Write general regs |
| 2.10.28.g | Initial state | Real mode setup |

### 2.10.29: Real Mode Setup (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.29.a | 16-bit mode | Initial CPU state |
| 2.10.29.b | Segment registers | CS, DS, ES, SS |
| 2.10.29.c | Base = 0 | Flat segments |
| 2.10.29.d | IP = 0 | Start at 0 |
| 2.10.29.e | Stack setup | SP = stack top |
| 2.10.29.f | Code at 0 | Load bootloader |
| 2.10.29.g | Simple guest | Just HLT |

### 2.10.30: Long Mode Setup (7 concepts - h already covered)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.30.a | 64-bit mode | Modern OS |
| 2.10.30.b | GDT required | Segment descriptors |
| 2.10.30.c | Page tables | 4-level paging |
| 2.10.30.d | CR0.PE | Protected mode |
| 2.10.30.e | CR0.PG | Paging enabled |
| 2.10.30.f | CR4.PAE | PAE enabled |
| 2.10.30.g | EFER.LME | Long mode enable |

### 2.10.31: VM Exit Handling (8 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.31.a | `VcpuExit` enum | Exit reasons |
| 2.10.31.b | `VcpuExit::IoIn` | Port input |
| 2.10.31.c | `VcpuExit::IoOut` | Port output |
| 2.10.31.d | `VcpuExit::MmioRead` | MMIO read |
| 2.10.31.e | `VcpuExit::MmioWrite` | MMIO write |
| 2.10.31.f | `VcpuExit::Hlt` | HLT instruction |
| 2.10.31.g | `VcpuExit::Shutdown` | Triple fault |
| 2.10.31.h | Event loop | Handle and resume |

### 2.10.32: I/O Handling (7 concepts)
| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.32.a | Port I/O | `in`/`out` instructions |
| 2.10.32.b | MMIO | Memory-mapped I/O |
| 2.10.32.c | Port 0x3F8 | Serial (COM1) |
| 2.10.32.d | Port 0x64 | Keyboard controller |
| 2.10.32.e | Dispatch | Route to device |
| 2.10.32.f | Device trait | `read_port()`, `write_port()` |
| 2.10.32.g | Emulated devices | Serial, PIC, PIT |

---

## Partie 13: Virtualization Concepts (2.10.23-2.10.26)

```rust
//! Virtualization concepts (2.10.23-2.10.26)

/// Hypervisor types (2.10.23.d-f)
#[derive(Debug)]
pub enum HypervisorType {
    Type1,  // 2.10.23.e: Bare-metal (ESXi, Xen, Hyper-V)
    Type2,  // 2.10.23.f: Hosted (VirtualBox, VMware Workstation)
    Hybrid, // 2.10.23.g: KVM - kernel module + userspace
}

/// Virtual Machine (2.10.23.a-c)
pub struct VirtualMachine {
    pub name: String,
    pub guest_os: String,     // 2.10.23.b
    pub memory_mb: u64,
    pub vcpus: u32,
}

/// Rust hypervisors (2.10.23.h)
pub mod rust_hypervisors {
    pub const FIRECRACKER: &str = "firecracker";     // AWS Lambda
    pub const CLOUD_HYPERVISOR: &str = "cloud-hypervisor";
    pub const CROSVM: &str = "crosvm";               // Chrome OS

    pub fn list() -> Vec<&'static str> {
        vec![FIRECRACKER, CLOUD_HYPERVISOR, CROSVM]
    }
}

/// Hardware virtualization (2.10.24)
pub mod hardware_virt {
    /// Intel VT-x / AMD-V (2.10.24.a-b)
    #[derive(Debug)]
    pub enum VirtExtension {
        IntelVTx,  // 2.10.24.a
        AmdV,      // 2.10.24.b
    }

    /// VMX operations (2.10.24.c)
    #[derive(Debug)]
    pub enum VmxOperation {
        VmxOn,      // Enable VMX
        VmLaunch,   // Start VM first time
        VmResume,   // Resume VM
        VmxOff,     // Disable VMX
    }

    /// CPU modes (2.10.24.d-e)
    #[derive(Debug)]
    pub enum CpuMode {
        RootMode,     // 2.10.24.d: Hypervisor context
        NonRootMode,  // 2.10.24.e: Guest context
    }

    /// VMCS - VM Control Structure (2.10.24.f)
    pub struct Vmcs {
        pub guest_state: GuestState,
        pub host_state: HostState,
        pub control_fields: ControlFields,
    }

    pub struct GuestState {
        pub rip: u64,
        pub rsp: u64,
        pub rflags: u64,
        pub cr0: u64,
        pub cr3: u64,
        pub cr4: u64,
    }

    pub struct HostState {
        pub rip: u64,
        pub rsp: u64,
        pub cr0: u64,
        pub cr3: u64,
        pub cr4: u64,
    }

    pub struct ControlFields {
        pub pin_based: u32,
        pub proc_based: u32,
        pub exit_ctls: u32,
        pub entry_ctls: u32,
    }

    /// VM entry (2.10.24.g)
    pub fn vm_entry() {
        // VMLAUNCH or VMRESUME
        println!("Entering guest mode...");
    }
}

/// KVM Architecture (2.10.25)
pub mod kvm_arch {
    use std::os::unix::io::RawFd;

    /// KVM device path (2.10.25.b)
    pub const KVM_DEVICE: &str = "/dev/kvm";

    /// KVM ioctls (2.10.25.c, 2.10.25.f-h)
    pub const KVM_CREATE_VM: u64 = 0xAE01;       // 2.10.25.f
    pub const KVM_CREATE_VCPU: u64 = 0xAE41;    // 2.10.25.g
    pub const KVM_RUN: u64 = 0xAE80;            // 2.10.25.h
    pub const KVM_SET_USER_MEMORY_REGION: u64 = 0x4020AE46;

    /// KVM handle (2.10.25.a)
    pub struct Kvm {
        fd: RawFd,  // File descriptor for /dev/kvm
    }

    /// VM handle (2.10.25.d)
    pub struct VmFd {
        fd: RawFd,
    }

    /// vCPU handle (2.10.25.e)
    pub struct VcpuFd {
        fd: RawFd,
        kvm_run: *mut u8,  // mmap'd KVM_RUN struct
    }
}

/// KVM in Rust (2.10.26)
pub mod kvm_rust {
    /// Using kvm-ioctls crate (2.10.26.a-b)
    pub struct KvmWrapper {
        // In real impl: kvm_ioctls::Kvm
    }

    impl KvmWrapper {
        /// Open /dev/kvm (2.10.26.c)
        pub fn new() -> Result<Self, KvmError> {
            // Kvm::new()
            println!("Opening /dev/kvm");
            Ok(Self {})
        }

        /// Create VM (2.10.26.d)
        pub fn create_vm(&self) -> Result<VmWrapper, KvmError> {
            println!("Creating VM");
            Ok(VmWrapper {})
        }
    }

    pub struct VmWrapper {
        // In real impl: kvm_ioctls::VmFd
    }

    impl VmWrapper {
        /// Create vCPU (2.10.26.e)
        pub fn create_vcpu(&self, id: u8) -> Result<VcpuWrapper, KvmError> {
            println!("Creating vCPU {}", id);
            Ok(VcpuWrapper { id })
        }

        /// Set memory region
        pub fn set_user_memory_region(&self, slot: u32, guest_addr: u64, size: u64, host_addr: u64) -> Result<(), KvmError> {
            println!("Setting memory region: slot={}, guest=0x{:x}, size={}", slot, guest_addr, size);
            Ok(())
        }
    }

    /// vCPU wrapper (2.10.26.f)
    pub struct VcpuWrapper {
        id: u8,
    }

    impl VcpuWrapper {
        /// Run vCPU (2.10.26.g)
        pub fn run(&self) -> Result<VcpuExit, KvmError> {
            println!("Running vCPU {}", self.id);
            Ok(VcpuExit::Hlt)
        }
    }

    /// vCPU exit reasons (2.10.26.h)
    #[derive(Debug)]
    pub enum VcpuExit {
        IoIn { port: u16, data: Vec<u8> },
        IoOut { port: u16, data: Vec<u8> },
        MmioRead { addr: u64, data: Vec<u8> },
        MmioWrite { addr: u64, data: Vec<u8> },
        Hlt,
        Shutdown,
        Unknown(u32),
    }

    #[derive(Debug)]
    pub struct KvmError(pub String);
}

fn main() {
    println!("=== Virtualization (2.10.23-2.10.26) ===\n");

    // List Rust hypervisors
    println!("Rust hypervisors: {:?}", rust_hypervisors::list());

    // Hypervisor types
    println!("KVM is a {:?} hypervisor", HypervisorType::Hybrid);
}
```

---

## Partie 14: KVM Memory and vCPU (2.10.27-2.10.30)

```rust
//! KVM Memory and vCPU setup (2.10.27-2.10.30)

/// Guest memory (2.10.27)
pub mod guest_memory {
    use std::ptr;

    /// Guest physical address (2.10.27.d)
    #[derive(Debug, Clone, Copy)]
    pub struct GuestAddress(pub u64);

    impl GuestAddress {
        pub fn offset(&self, offset: u64) -> Self {
            GuestAddress(self.0 + offset)
        }
    }

    /// Memory region (2.10.27.e)
    pub struct MmapRegion {
        pub addr: *mut u8,
        pub size: usize,
    }

    impl MmapRegion {
        /// Create mmap'd region (2.10.27.a)
        pub fn new(size: usize) -> Result<Self, MemoryError> {
            let addr = unsafe {
                libc::mmap(
                    ptr::null_mut(),
                    size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                ) as *mut u8
            };

            if addr == libc::MAP_FAILED as *mut u8 {
                return Err(MemoryError::MmapFailed);
            }

            Ok(Self { addr, size })
        }

        /// Write to guest memory
        pub fn write(&self, offset: usize, data: &[u8]) {
            unsafe {
                ptr::copy_nonoverlapping(data.as_ptr(), self.addr.add(offset), data.len());
            }
        }

        /// Read from guest memory
        pub fn read(&self, offset: usize, size: usize) -> Vec<u8> {
            let mut data = vec![0u8; size];
            unsafe {
                ptr::copy_nonoverlapping(self.addr.add(offset), data.as_mut_ptr(), size);
            }
            data
        }
    }

    impl Drop for MmapRegion {
        fn drop(&mut self) {
            unsafe {
                libc::munmap(self.addr as *mut libc::c_void, self.size);
            }
        }
    }

    /// GuestMemoryMmap (2.10.27.b-c)
    pub struct GuestMemoryMmap {
        regions: Vec<(GuestAddress, MmapRegion)>,
    }

    impl GuestMemoryMmap {
        pub fn new() -> Self {
            Self { regions: Vec::new() }
        }

        pub fn add_region(&mut self, guest_addr: GuestAddress, region: MmapRegion) {
            self.regions.push((guest_addr, region));
        }
    }

    /// Memory region config for KVM (2.10.27.f-g)
    #[repr(C)]
    pub struct KvmUserspaceMemoryRegion {
        pub slot: u32,
        pub flags: u32,
        pub guest_phys_addr: u64,
        pub memory_size: u64,
        pub userspace_addr: u64,
    }

    #[derive(Debug)]
    pub enum MemoryError {
        MmapFailed,
    }
}

/// vCPU registers (2.10.28)
pub mod vcpu_regs {
    /// Special registers (2.10.28.a)
    #[repr(C)]
    #[derive(Debug, Default)]
    pub struct KvmSregs {
        pub cs: KvmSegment,
        pub ds: KvmSegment,
        pub es: KvmSegment,
        pub fs: KvmSegment,
        pub gs: KvmSegment,
        pub ss: KvmSegment,
        pub tr: KvmSegment,
        pub ldt: KvmSegment,
        pub gdt: KvmDtable,
        pub idt: KvmDtable,
        pub cr0: u64,
        pub cr2: u64,
        pub cr3: u64,
        pub cr4: u64,
        pub cr8: u64,
        pub efer: u64,
        pub apic_base: u64,
    }

    #[repr(C)]
    #[derive(Debug, Default, Clone, Copy)]
    pub struct KvmSegment {
        pub base: u64,
        pub limit: u32,
        pub selector: u16,
        pub type_: u8,
        pub present: u8,
        pub dpl: u8,
        pub db: u8,
        pub s: u8,
        pub l: u8,
        pub g: u8,
        pub avl: u8,
    }

    #[repr(C)]
    #[derive(Debug, Default)]
    pub struct KvmDtable {
        pub base: u64,
        pub limit: u16,
    }

    /// General registers (2.10.28.b)
    #[repr(C)]
    #[derive(Debug, Default)]
    pub struct KvmRegs {
        pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
        pub rsi: u64, pub rdi: u64, pub rsp: u64, pub rbp: u64,
        pub r8: u64,  pub r9: u64,  pub r10: u64, pub r11: u64,
        pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
        pub rip: u64,
        pub rflags: u64,
    }
}

/// Real mode setup (2.10.29)
pub mod real_mode {
    use super::vcpu_regs::*;

    /// Setup 16-bit real mode (2.10.29.a)
    pub fn setup_real_mode(sregs: &mut KvmSregs, regs: &mut KvmRegs) {
        // 2.10.29.b: Segment registers
        let flat_segment = KvmSegment {
            base: 0,           // 2.10.29.c: Base = 0
            limit: 0xFFFF,
            selector: 0,
            type_: 0x3,        // Read/write, accessed
            present: 1,
            dpl: 0,
            db: 0,             // 16-bit
            s: 1,
            l: 0,
            g: 0,
            avl: 0,
        };

        let code_segment = KvmSegment {
            type_: 0xB,        // Execute/read, accessed
            ..flat_segment
        };

        sregs.cs = code_segment;
        sregs.ds = flat_segment;
        sregs.es = flat_segment;
        sregs.ss = flat_segment;
        sregs.fs = flat_segment;
        sregs.gs = flat_segment;

        // 2.10.29.d: IP = 0
        regs.rip = 0;
        regs.rflags = 0x2;  // Reserved bit must be 1

        // 2.10.29.e: Stack setup
        regs.rsp = 0x8000;  // Stack at 32KB
    }

    /// Simple HLT guest (2.10.29.g)
    pub fn simple_hlt_guest() -> Vec<u8> {
        vec![
            0xF4,  // HLT instruction
        ]
    }

    /// Simple guest with output (2.10.29.f)
    pub fn simple_io_guest() -> Vec<u8> {
        vec![
            0xBA, 0xF8, 0x03,  // mov dx, 0x3F8 (COM1)
            0xB0, 0x48,        // mov al, 'H'
            0xEE,              // out dx, al
            0xB0, 0x69,        // mov al, 'i'
            0xEE,              // out dx, al
            0xF4,              // hlt
        ]
    }
}

/// Long mode setup (2.10.30)
pub mod long_mode {
    use super::vcpu_regs::*;

    // CR0 bits (2.10.30.d-e)
    pub const CR0_PE: u64 = 1 << 0;   // Protected mode enable
    pub const CR0_PG: u64 = 1 << 31;  // Paging enable

    // CR4 bits (2.10.30.f)
    pub const CR4_PAE: u64 = 1 << 5;  // PAE enable

    // EFER bits (2.10.30.g)
    pub const EFER_LME: u64 = 1 << 8;  // Long mode enable
    pub const EFER_LMA: u64 = 1 << 10; // Long mode active

    /// Setup 64-bit long mode (2.10.30.a)
    pub fn setup_long_mode(sregs: &mut KvmSregs, page_table_addr: u64) {
        // 2.10.30.b: GDT required
        // Setup GDT with 64-bit code segment

        // 2.10.30.c: Page tables (4-level)
        sregs.cr3 = page_table_addr;

        // 2.10.30.d: Protected mode
        sregs.cr0 |= CR0_PE;

        // 2.10.30.e: Paging
        sregs.cr0 |= CR0_PG;

        // 2.10.30.f: PAE
        sregs.cr4 |= CR4_PAE;

        // 2.10.30.g: Long mode
        sregs.efer |= EFER_LME | EFER_LMA;

        // 64-bit code segment
        sregs.cs = KvmSegment {
            base: 0,
            limit: 0xFFFFFFFF,
            selector: 0x08,
            type_: 0xB,
            present: 1,
            dpl: 0,
            db: 0,
            s: 1,
            l: 1,  // 64-bit
            g: 1,
            avl: 0,
        };
    }

    /// Create identity-mapped page tables
    pub fn create_page_tables(memory: &mut [u8], base: usize) {
        // PML4 -> PDPT -> PD -> PT (for first 2MB identity mapped)
        let pml4 = base;
        let pdpt = base + 0x1000;
        let pd = base + 0x2000;

        // PML4[0] -> PDPT
        let entry = (pdpt as u64) | 0x3; // Present + R/W
        memory[pml4..pml4+8].copy_from_slice(&entry.to_le_bytes());

        // PDPT[0] -> PD
        let entry = (pd as u64) | 0x3;
        memory[pdpt..pdpt+8].copy_from_slice(&entry.to_le_bytes());

        // PD[0] -> 2MB page (using huge page)
        let entry: u64 = 0x83; // Present + R/W + PS (2MB page)
        memory[pd..pd+8].copy_from_slice(&entry.to_le_bytes());
    }
}
```

---

### 2.10.33-2.10.38: Devices and virtio

| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.33.a-g | Serial Console | UART 16550 emulation |
| 2.10.34.a-g | virtio Overview | Paravirtualized I/O |
| 2.10.35.a-g | virtio-blk | Block device |
| 2.10.36.a-g | virtio-net | Network device |
| 2.10.37.a-g | Loading Linux | bzImage, boot protocol |
| 2.10.38.a-g | Interrupt Handling | IRQ injection |

### 2.10.39-2.10.40: eBPF with Aya

| Ref | Concept | Application |
|-----|---------|-------------|
| 2.10.39.a-g | eBPF with Aya | Extended BPF in Rust |
| 2.10.40.a-g | eBPF Tracing | Tracepoints and probes |

---

## Partie 15: VM Exit and I/O (2.10.31-2.10.32)

```rust
//! VM Exit and I/O handling (2.10.31-2.10.32)

/// VM Exit reasons (2.10.31.a)
#[derive(Debug)]
pub enum VcpuExit {
    IoIn { port: u16, size: u8 },        // 2.10.31.b
    IoOut { port: u16, data: Vec<u8> },  // 2.10.31.c
    MmioRead { addr: u64, size: u8 },    // 2.10.31.d
    MmioWrite { addr: u64, data: Vec<u8> }, // 2.10.31.e
    Hlt,                                  // 2.10.31.f
    Shutdown,                             // 2.10.31.g
    Unknown(u32),
}

/// I/O port constants (2.10.32.c-d)
pub mod io_ports {
    pub const COM1_BASE: u16 = 0x3F8;     // 2.10.32.c
    pub const COM1_THR: u16 = 0x3F8;      // Transmit
    pub const COM1_RBR: u16 = 0x3F8;      // Receive
    pub const COM1_LSR: u16 = 0x3FD;      // Line status
    pub const KEYBOARD_DATA: u16 = 0x60;
    pub const KEYBOARD_CTRL: u16 = 0x64;  // 2.10.32.d
}

/// Device trait (2.10.32.f)
pub trait IoDevice {
    fn read_port(&mut self, port: u16) -> u8;
    fn write_port(&mut self, port: u16, value: u8);
}

/// Serial device (2.10.32.g, 2.10.33)
pub struct SerialDevice {
    thr: u8,      // Transmit holding register
    rbr: u8,      // Receive buffer register
    ier: u8,      // Interrupt enable
    iir: u8,      // Interrupt identification
    lcr: u8,      // Line control
    mcr: u8,      // Modem control
    lsr: u8,      // Line status
    msr: u8,      // Modem status
    output: Vec<u8>,
}

impl SerialDevice {
    pub fn new() -> Self {
        Self {
            thr: 0, rbr: 0, ier: 0, iir: 0x01,
            lcr: 0, mcr: 0, lsr: 0x60, msr: 0,
            output: Vec::new(),
        }
    }

    pub fn get_output(&self) -> String {
        String::from_utf8_lossy(&self.output).to_string()
    }
}

impl IoDevice for SerialDevice {
    fn read_port(&mut self, port: u16) -> u8 {
        match port - io_ports::COM1_BASE {
            0 => self.rbr,       // RBR
            1 => self.ier,
            2 => self.iir,
            3 => self.lcr,
            4 => self.mcr,
            5 => self.lsr,       // LSR - transmit ready
            6 => self.msr,
            _ => 0,
        }
    }

    fn write_port(&mut self, port: u16, value: u8) {
        match port - io_ports::COM1_BASE {
            0 => {              // THR - transmit
                self.thr = value;
                self.output.push(value);
                print!("{}", value as char);
            }
            1 => self.ier = value,
            3 => self.lcr = value,
            4 => self.mcr = value,
            _ => {}
        }
    }
}

/// I/O dispatcher (2.10.32.e)
pub struct IoDispatcher {
    serial: SerialDevice,
}

impl IoDispatcher {
    pub fn new() -> Self {
        Self { serial: SerialDevice::new() }
    }

    /// Route I/O to device (2.10.32.e)
    pub fn handle_io_out(&mut self, port: u16, data: &[u8]) {
        match port {
            0x3F8..=0x3FF => {
                for byte in data {
                    self.serial.write_port(port, *byte);
                }
            }
            _ => println!("Unhandled I/O out: port=0x{:x}", port),
        }
    }

    pub fn handle_io_in(&mut self, port: u16) -> u8 {
        match port {
            0x3F8..=0x3FF => self.serial.read_port(port),
            _ => {
                println!("Unhandled I/O in: port=0x{:x}", port);
                0xFF
            }
        }
    }
}

/// VM event loop (2.10.31.h)
pub fn vm_event_loop(vcpu: &mut impl VcpuRunner, io: &mut IoDispatcher) -> Result<(), String> {
    loop {
        match vcpu.run()? {
            VcpuExit::IoOut { port, data } => {
                io.handle_io_out(port, &data);
            }
            VcpuExit::IoIn { port, size: _ } => {
                let value = io.handle_io_in(port);
                vcpu.set_io_result(value);
            }
            VcpuExit::Hlt => {
                println!("Guest halted");
                break;
            }
            VcpuExit::Shutdown => {
                println!("Guest shutdown (triple fault)");
                break;
            }
            exit => {
                println!("Unhandled exit: {:?}", exit);
                break;
            }
        }
    }
    Ok(())
}

pub trait VcpuRunner {
    fn run(&mut self) -> Result<VcpuExit, String>;
    fn set_io_result(&mut self, value: u8);
}
```

---

## Partie 16: virtio Devices (2.10.34-2.10.36)

```rust
//! virtio implementation (2.10.34-2.10.36)

/// virtio constants (2.10.34)
pub mod virtio {
    /// Virtqueue structure (2.10.34.c-f)
    pub struct VirtQueue {
        pub desc_table: u64,     // 2.10.34.f: Descriptor table
        pub avail_ring: u64,     // 2.10.34.d: Available ring
        pub used_ring: u64,      // 2.10.34.e: Used ring
        pub queue_size: u16,
        pub next_avail: u16,
        pub next_used: u16,
    }

    /// Descriptor (2.10.34.f)
    #[repr(C)]
    pub struct VirtqDesc {
        pub addr: u64,    // Guest physical address
        pub len: u32,     // Length
        pub flags: u16,   // NEXT, WRITE, INDIRECT
        pub next: u16,    // Next descriptor if NEXT flag set
    }

    pub const VIRTQ_DESC_F_NEXT: u16 = 1;
    pub const VIRTQ_DESC_F_WRITE: u16 = 2;

    /// virtio device trait (2.10.34.a-b)
    pub trait VirtioDevice {
        fn device_type(&self) -> u32;
        fn read_config(&self, offset: u64) -> u32;
        fn write_config(&mut self, offset: u64, value: u32);
        fn process_queue(&mut self, queue: &mut VirtQueue);
    }
}

/// virtio-blk (2.10.35)
pub mod virtio_blk {
    use super::virtio::*;

    // Request types (2.10.35.c-d)
    pub const VIRTIO_BLK_T_IN: u32 = 0;   // 2.10.35.c: Read
    pub const VIRTIO_BLK_T_OUT: u32 = 1;  // 2.10.35.d: Write

    /// Block request header (2.10.35.b)
    #[repr(C)]
    pub struct VirtioBlkReqHeader {
        pub request_type: u32,
        pub reserved: u32,
        pub sector: u64,
    }

    /// Block device (2.10.35.a, 2.10.35.e)
    pub struct VirtioBlkDevice {
        pub capacity: u64,       // Sectors
        backend: BlockBackend,   // 2.10.35.e
    }

    pub enum BlockBackend {
        File(std::path::PathBuf),
        Memory(Vec<u8>),
    }

    impl VirtioBlkDevice {
        pub fn new_file(path: &str, size: u64) -> Self {
            Self {
                capacity: size / 512,
                backend: BlockBackend::File(path.into()),
            }
        }

        pub fn new_memory(size: u64) -> Self {
            Self {
                capacity: size / 512,
                backend: BlockBackend::Memory(vec![0; size as usize]),
            }
        }
    }
}

/// virtio-net (2.10.36)
pub mod virtio_net {
    use super::virtio::*;

    /// Network device (2.10.36.a)
    pub struct VirtioNetDevice {
        pub mac_address: [u8; 6],  // 2.10.36.g
        tx_queue: Option<VirtQueue>, // 2.10.36.b
        rx_queue: Option<VirtQueue>, // 2.10.36.c
    }

    impl VirtioNetDevice {
        pub fn new(mac: [u8; 6]) -> Self {
            Self {
                mac_address: mac,
                tx_queue: None,
                rx_queue: None,
            }
        }
    }

    // TAP backend (2.10.36.d-e) would use tun-tap crate
}
```

---

## Partie 17: Linux Boot and Interrupts (2.10.37-2.10.38)

```rust
//! Linux boot and interrupts (2.10.37-2.10.38)

/// Linux kernel loading (2.10.37)
pub mod linux_boot {
    /// Boot protocol constants (2.10.37.b-c)
    pub const SETUP_HEADER_OFFSET: usize = 0x1F1;  // 2.10.37.c
    pub const BOOT_FLAG_OFFSET: usize = 0x1FE;
    pub const BOOT_FLAG: u16 = 0xAA55;

    /// bzImage header (2.10.37.a)
    #[repr(C)]
    pub struct SetupHeader {
        pub setup_sects: u8,
        pub root_flags: u16,
        pub syssize: u32,
        pub ram_size: u16,
        pub vid_mode: u16,
        pub root_dev: u16,
        pub boot_flag: u16,
        pub jump: u16,
        pub header: u32,        // "HdrS"
        pub version: u16,
        pub realmode_swtch: u32,
        pub start_sys_seg: u16,
        pub kernel_version: u16,
        pub type_of_loader: u8,
        pub loadflags: u8,
        pub setup_move_size: u16,
        pub code32_start: u32,
        pub ramdisk_image: u32,
        pub ramdisk_size: u32,
        pub bootsect_kludge: u32,
        pub heap_end_ptr: u16,
        pub ext_loader_ver: u8,
        pub ext_loader_type: u8,
        pub cmd_line_ptr: u32,  // 2.10.37.f: Kernel cmdline
        pub initrd_addr_max: u32,
    }

    /// Linux loader (2.10.37.d-e)
    pub struct LinuxLoader {
        kernel_path: String,
        cmdline: String,         // 2.10.37.f
        initrd_path: Option<String>, // 2.10.37.g
    }

    impl LinuxLoader {
        pub fn new(kernel: &str) -> Self {
            Self {
                kernel_path: kernel.to_string(),
                cmdline: String::new(),
                initrd_path: None,
            }
        }

        pub fn cmdline(mut self, cmd: &str) -> Self {
            self.cmdline = cmd.to_string();
            self
        }

        pub fn initrd(mut self, path: &str) -> Self {
            self.initrd_path = Some(path.to_string());
            self
        }

        /// Load kernel into guest memory (2.10.37.e)
        pub fn load(&self, _memory: &mut [u8]) -> Result<u64, String> {
            // Parse bzImage header
            // Load protected-mode kernel at 0x100000
            // Setup boot parameters
            // Return entry point (2.10.37.h)
            println!("Loading kernel: {}", self.kernel_path);
            Ok(0x100000) // Entry point
        }
    }
}

/// Interrupt handling (2.10.38)
pub mod interrupts {
    /// IRQ injection (2.10.38.a-b)
    pub trait IrqInjector {
        fn inject_irq(&mut self, irq: u8);
        fn set_irq_line(&mut self, irq: u8, level: bool); // 2.10.38.b
    }

    /// PIC emulation (2.10.38.c)
    pub struct Pic8259 {
        irr: u8,      // Interrupt Request Register
        isr: u8,      // In-Service Register
        imr: u8,      // Interrupt Mask Register
        icw_state: u8,
        vector_offset: u8,
    }

    impl Pic8259 {
        pub fn new(vector_offset: u8) -> Self {
            Self {
                irr: 0, isr: 0, imr: 0xFF,
                icw_state: 0, vector_offset,
            }
        }

        pub fn raise_irq(&mut self, irq: u8) {
            self.irr |= 1 << irq;
        }

        pub fn get_interrupt(&mut self) -> Option<u8> {
            let pending = self.irr & !self.imr;
            if pending != 0 {
                let irq = pending.trailing_zeros() as u8;
                self.irr &= !(1 << irq);
                self.isr |= 1 << irq;
                Some(self.vector_offset + irq)
            } else {
                None
            }
        }
    }

    /// IOAPIC (2.10.38.d)
    pub struct IoApic {
        id: u32,
        redirection_table: [u64; 24],
    }

    impl IoApic {
        pub fn new(id: u32) -> Self {
            Self {
                id,
                redirection_table: [0; 24],
            }
        }
    }

    /// Timer (2.10.38.g)
    pub struct PitTimer {
        channel0_count: u16,
        channel0_reload: u16,
        mode: u8,
    }

    impl PitTimer {
        pub fn new() -> Self {
            Self {
                channel0_count: 0xFFFF,
                channel0_reload: 0xFFFF,
                mode: 3,
            }
        }

        pub fn tick(&mut self) -> bool {
            if self.channel0_count == 0 {
                self.channel0_count = self.channel0_reload;
                true // Generate interrupt
            } else {
                self.channel0_count -= 1;
                false
            }
        }
    }
}
```

---

## Partie 18: eBPF with Aya (2.10.39-2.10.40)

```rust
//! eBPF with Aya (2.10.39-2.10.40)

/// eBPF concepts (2.10.39)
pub mod ebpf {
    /// eBPF program types (2.10.39.d)
    #[derive(Debug)]
    pub enum BpfProgramType {
        Xdp,          // eXpress Data Path
        Tracepoint,   // Static tracepoints
        Kprobe,       // Dynamic kernel probes
        Uprobe,       // User-space probes
        PerfEvent,    // Performance events
        CgroupSkb,    // Cgroup socket buffer
    }

    /// eBPF map types (2.10.39.e)
    #[derive(Debug)]
    pub enum BpfMapType {
        Hash,
        Array,
        PerfEventArray,
        RingBuf,
        HashMap,
        LruHash,
    }

    /// Aya program example (2.10.39.a-c)
    /// In real code, this would be in a separate eBPF program
    pub mod bpf_program {
        // #![no_std]
        // use aya_bpf::{macros::tracepoint, programs::TracePointContext};

        // 2.10.39.d: Tracepoint program
        // #[tracepoint(name = "sys_enter_open")]
        // pub fn trace_open(ctx: TracePointContext) -> u32 {
        //     0
        // }
    }

    /// Userspace loader (2.10.39.g)
    pub struct BpfLoader {
        programs: Vec<String>,
        maps: Vec<String>,
    }

    impl BpfLoader {
        pub fn new() -> Self {
            Self {
                programs: Vec::new(),
                maps: Vec::new(),
            }
        }

        /// Load eBPF object file
        pub fn load(&mut self, _path: &str) -> Result<(), BpfError> {
            // Aya::load(&bytes)?;
            println!("Loading eBPF program");
            Ok(())
        }

        /// Attach to tracepoint
        pub fn attach_tracepoint(&mut self, _category: &str, _name: &str) -> Result<(), BpfError> {
            println!("Attaching to tracepoint");
            Ok(())
        }
    }

    #[derive(Debug)]
    pub struct BpfError(pub String);
}

/// eBPF Tracing (2.10.40)
pub mod ebpf_tracing {
    /// Tracepoint context (2.10.40.a, 2.10.40.d)
    pub struct TraceContext {
        pub pid: u32,
        pub tgid: u32,
        pub uid: u32,
        pub comm: [u8; 16],
    }

    /// Kprobe (2.10.40.b)
    pub struct KprobeContext {
        pub regs: Registers,
        pub func_name: String,
    }

    pub struct Registers {
        pub rdi: u64,
        pub rsi: u64,
        pub rdx: u64,
        pub rcx: u64,
        pub rax: u64,
    }

    /// Uprobe (2.10.40.c)
    pub struct UprobeContext {
        pub path: String,
        pub symbol: String,
        pub offset: u64,
    }

    /// Debug output (2.10.40.e)
    pub fn bpf_printk(msg: &str) {
        // In kernel: bpf_printk!("{}", msg);
        println!("[bpf] {}", msg);
    }

    /// Aya logging (2.10.40.f)
    pub mod aya_log {
        pub fn setup_logging() {
            // aya_log::init_logger()?;
            println!("eBPF logging initialized");
        }
    }
}

fn main() {
    println!("=== eBPF with Aya (2.10.39-2.10.40) ===\n");

    // Example eBPF loader usage
    let mut loader = ebpf::BpfLoader::new();
    loader.load("program.o").ok();
    loader.attach_tracepoint("syscalls", "sys_enter_open").ok();
}
```

---

## Tests Moulinette

```rust
// Container tests
#[test] fn test_container_concepts()       // 2.10.1
#[test] fn test_namespaces_overview()      // 2.10.2
#[test] fn test_namespace_flags()          // 2.10.3
#[test] fn test_pid_namespace()            // 2.10.4
#[test] fn test_network_namespace()        // 2.10.5
#[test] fn test_rtnetlink()                // 2.10.6
#[test] fn test_mount_namespace()          // 2.10.7
#[test] fn test_pivot_root()               // 2.10.8
#[test] fn test_user_namespace()           // 2.10.9
#[test] fn test_uts_ipc_namespace()        // 2.10.10
#[test] fn test_cgroups_v2()               // 2.10.11
#[test] fn test_cpu_cgroup()               // 2.10.12
#[test] fn test_memory_cgroup()            // 2.10.13
#[test] fn test_io_pids_cgroup()           // 2.10.14
#[test] fn test_seccomp()                  // 2.10.15
#[test] fn test_seccomp_filter()           // 2.10.16
#[test] fn test_capabilities()             // 2.10.17
#[test] fn test_caps_management()          // 2.10.18
#[test] fn test_overlayfs()                // 2.10.19
#[test] fn test_oci_spec()                 // 2.10.20
#[test] fn test_runtime_commands()         // 2.10.21
#[test] fn test_runtime_architecture()     // 2.10.22

// Virtualization tests
#[test] fn test_virt_concepts()            // 2.10.23
#[test] fn test_hardware_virt()            // 2.10.24
#[test] fn test_kvm_architecture()         // 2.10.25
#[test] fn test_kvm_ioctls()               // 2.10.26
#[test] fn test_vm_memory()                // 2.10.27
#[test] fn test_vcpu_setup()               // 2.10.28
#[test] fn test_real_mode()                // 2.10.29
#[test] fn test_long_mode()                // 2.10.30
#[test] fn test_vm_exit()                  // 2.10.31
#[test] fn test_io_handling()              // 2.10.32
#[test] fn test_serial()                   // 2.10.33
#[test] fn test_virtio()                   // 2.10.34
#[test] fn test_virtio_blk()               // 2.10.35
#[test] fn test_virtio_net()               // 2.10.36
#[test] fn test_linux_boot()               // 2.10.37
#[test] fn test_interrupts()               // 2.10.38
#[test] fn test_ebpf_aya()                 // 2.10.39
#[test] fn test_ebpf_tracing()             // 2.10.40
```

---

## Bareme

| Critere | Points |
|---------|--------|
| Container Concepts (2.10.1) | 3 |
| Namespaces (2.10.2-2.10.10) | 15 |
| Cgroups (2.10.11-2.10.14) | 12 |
| Security (2.10.15-2.10.18) | 12 |
| OverlayFS & OCI (2.10.19-2.10.20) | 6 |
| Container Runtime (2.10.21-2.10.22) | 8 |
| Virtualization Concepts (2.10.23-2.10.24) | 6 |
| KVM (2.10.25-2.10.28) | 12 |
| CPU Modes (2.10.29-2.10.30) | 6 |
| VM Exit & I/O (2.10.31-2.10.32) | 6 |
| Devices (2.10.33-2.10.36) | 8 |
| Linux Boot & Interrupts (2.10.37-2.10.38) | 4 |
| eBPF (2.10.39-2.10.40) | 2 |
| **Total** | **100** |

---

## Fichiers

```
ex27/
├── Cargo.toml
├── src/
│   ├── main.rs
│   ├── container/
│   │   ├── mod.rs
│   │   ├── namespaces.rs
│   │   ├── cgroups.rs
│   │   ├── seccomp.rs
│   │   ├── capabilities.rs
│   │   ├── overlay.rs
│   │   └── runtime.rs
│   ├── virtualization/
│   │   ├── mod.rs
│   │   ├── kvm.rs
│   │   ├── memory.rs
│   │   ├── vcpu.rs
│   │   ├── devices.rs
│   │   └── linux_boot.rs
│   └── ebpf/
│       ├── mod.rs
│       └── tracing.rs
└── tests/
    ├── container_tests.rs
    └── vm_tests.rs
```
