# [Module 2.5] - Exercise 13: Container Fundamentals

## Metadonnees

```yaml
module: "2.5 - IPC & Containers"
exercise: "ex13"
title: "Container Fundamentals & Linux Namespaces"
difficulty: avance
estimated_time: "5 heures"
prerequisite_exercises: ["ex00"]
concepts_requis: ["Linux namespaces", "cgroups", "process isolation"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.5.28: Container Fundamentals (9 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.5.28.a | Container vs VM | Process isolation vs hardware virtualization |
| 2.5.28.b | Namespaces | PID, NET, MNT, UTS, IPC, USER |
| 2.5.28.c | Cgroups | Resource limits (CPU, memory, I/O) |
| 2.5.28.d | Union filesystems | OverlayFS, layers |
| 2.5.28.e | Container runtime | runc, containerd |
| 2.5.28.f | OCI spec | Open Container Initiative |
| 2.5.28.g | `nix` crate | Namespace/cgroup syscalls |
| 2.5.28.h | `unshare()` | Create namespaces |
| 2.5.28.i | `clone()` flags | CLONE_NEWPID, etc. |

---

## Partie 1: Understanding Containers vs VMs

### Exercice 1.1: Architecture Comparison

```
┌─────────────────────────────────────────────────────────────────┐
│                    Virtual Machines                             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────┐   ┌─────────┐   ┌─────────┐                       │
│  │  App A  │   │  App B  │   │  App C  │                       │
│  ├─────────┤   ├─────────┤   ├─────────┤                       │
│  │Guest OS │   │Guest OS │   │Guest OS │  ← Full OS per VM     │
│  └─────────┘   └─────────┘   └─────────┘                       │
│  ┌─────────────────────────────────────┐                       │
│  │           Hypervisor                │  ← Hardware emulation │
│  ├─────────────────────────────────────┤                       │
│  │            Host OS                  │                       │
│  ├─────────────────────────────────────┤                       │
│  │           Hardware                  │                       │
│  └─────────────────────────────────────┘                       │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                       Containers                                │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────┐   ┌─────────┐   ┌─────────┐                       │
│  │  App A  │   │  App B  │   │  App C  │                       │
│  └─────────┘   └─────────┘   └─────────┘                       │
│  ┌─────────────────────────────────────┐                       │
│  │      Container Runtime (Docker)     │  ← Process isolation  │
│  ├─────────────────────────────────────┤                       │
│  │      Host OS (Shared Kernel)        │  ← Same kernel!       │
│  ├─────────────────────────────────────┤                       │
│  │           Hardware                  │                       │
│  └─────────────────────────────────────┘                       │
└─────────────────────────────────────────────────────────────────┘
```

**Questions:**
1. Why are containers more lightweight than VMs?
2. What security implications does sharing a kernel have?
3. When would you choose VMs over containers?

---

## Partie 2: Linux Namespaces (2.5.28.b, g, h, i)

### Exercice 2.1: Understanding Namespaces

```rust
// List namespace types
use nix::sched::CloneFlags;

fn list_namespace_types() {
    println!("Linux Namespace Types:");
    println!("  PID   - Process ID isolation");
    println!("  NET   - Network stack isolation");
    println!("  MNT   - Mount point isolation");
    println!("  UTS   - Hostname/domain isolation");
    println!("  IPC   - Inter-process communication isolation");
    println!("  USER  - User/group ID mapping");
    println!("  CGROUP - Cgroup root isolation");
    println!("  TIME  - Clock isolation (Linux 5.6+)");

    println!("\nCloneFlags:");
    println!("  CLONE_NEWPID  = {:?}", CloneFlags::CLONE_NEWPID);
    println!("  CLONE_NEWNET  = {:?}", CloneFlags::CLONE_NEWNET);
    println!("  CLONE_NEWNS   = {:?}", CloneFlags::CLONE_NEWNS);
    println!("  CLONE_NEWUTS  = {:?}", CloneFlags::CLONE_NEWUTS);
    println!("  CLONE_NEWIPC  = {:?}", CloneFlags::CLONE_NEWIPC);
    println!("  CLONE_NEWUSER = {:?}", CloneFlags::CLONE_NEWUSER);
}
```

### Exercice 2.2: Creating New Namespaces with unshare

```rust
use nix::sched::{unshare, CloneFlags};
use nix::unistd::{fork, ForkResult, gethostname, sethostname};
use std::ffi::CString;

fn create_uts_namespace() -> nix::Result<()> {
    // Create new UTS namespace
    unshare(CloneFlags::CLONE_NEWUTS)?;

    // Now we can change hostname without affecting host
    let new_hostname = CString::new("container").unwrap();
    sethostname(&new_hostname)?;

    // Verify
    let mut buf = [0u8; 64];
    let hostname = gethostname(&mut buf)?;
    println!("Hostname in container: {:?}", hostname);

    Ok(())
}

fn create_pid_namespace() -> nix::Result<()> {
    // Create new PID namespace (requires root)
    unshare(CloneFlags::CLONE_NEWPID)?;

    // After unshare, we need to fork for PID 1
    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            println!("Parent: child PID = {}", child);
        }
        ForkResult::Child => {
            println!("Child: I am PID {} in the new namespace",
                std::process::id());
            // In new PID namespace, this process is PID 1
        }
    }

    Ok(())
}

fn main() {
    // Check if running as root
    if nix::unistd::geteuid().as_raw() != 0 {
        eprintln!("Some namespace operations require root");
    }

    if let Err(e) = create_uts_namespace() {
        eprintln!("UTS namespace error: {}", e);
    }
}
```

### Exercice 2.3: Exploring Current Namespaces

```rust
use std::fs;

fn show_namespaces(pid: u32) -> std::io::Result<()> {
    let ns_dir = format!("/proc/{}/ns", pid);

    println!("Namespaces for PID {}:", pid);

    for entry in fs::read_dir(&ns_dir)? {
        let entry = entry?;
        let path = entry.path();
        let link = fs::read_link(&path)?;

        println!("  {:10} -> {}",
            entry.file_name().to_string_lossy(),
            link.display()
        );
    }

    Ok(())
}

fn main() -> std::io::Result<()> {
    // Show current process namespaces
    show_namespaces(std::process::id())?;

    // Compare with init (PID 1)
    println!();
    show_namespaces(1)?;

    Ok(())
}
```

### Exercice 2.4: Simple Container with Namespaces

```rust
use nix::sched::{clone, CloneFlags};
use nix::sys::wait::waitpid;
use nix::unistd::{chdir, chroot, sethostname};
use std::ffi::CString;

const STACK_SIZE: usize = 1024 * 1024; // 1 MB

fn container_main() -> isize {
    println!("[Container] Starting...");
    println!("[Container] PID: {}", std::process::id());

    // Set hostname
    let hostname = CString::new("mini-container").unwrap();
    sethostname(&hostname).expect("sethostname failed");

    // Change root (requires prepared rootfs)
    // chroot("/path/to/rootfs").expect("chroot failed");
    // chdir("/").expect("chdir failed");

    // Run shell or command
    println!("[Container] Running...");

    // Simulate work
    std::thread::sleep(std::time::Duration::from_secs(2));

    println!("[Container] Exiting");
    0
}

fn run_container() -> nix::Result<()> {
    let mut stack = vec![0u8; STACK_SIZE];

    let flags = CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWIPC;

    // Clone with new namespaces
    let child_pid = clone(
        Box::new(container_main),
        &mut stack,
        flags,
        None,
    )?;

    println!("[Host] Container PID: {}", child_pid);

    // Wait for container to finish
    waitpid(child_pid, None)?;

    println!("[Host] Container exited");
    Ok(())
}

fn main() {
    if nix::unistd::geteuid().as_raw() != 0 {
        eprintln!("Must run as root");
        return;
    }

    if let Err(e) = run_container() {
        eprintln!("Error: {}", e);
    }
}
```

---

## Partie 3: Cgroups (2.5.28.c)

### Exercice 3.1: Reading Cgroup Information

```rust
use std::fs;
use std::path::Path;

fn read_cgroup_info() -> std::io::Result<()> {
    // cgroups v2 mount point
    let cgroup_path = Path::new("/sys/fs/cgroup");

    if cgroup_path.exists() {
        println!("Cgroups v2 controllers:");

        // Read available controllers
        let controllers = fs::read_to_string(
            cgroup_path.join("cgroup.controllers")
        )?;
        println!("  Available: {}", controllers.trim());

        // Read current process cgroup
        let proc_cgroup = fs::read_to_string("/proc/self/cgroup")?;
        println!("\nCurrent process cgroup:");
        println!("  {}", proc_cgroup.trim());

        // Memory stats (if in a cgroup with memory controller)
        let memory_current = cgroup_path.join("memory.current");
        if memory_current.exists() {
            let mem = fs::read_to_string(memory_current)?;
            println!("\nMemory usage: {} bytes", mem.trim());
        }
    }

    Ok(())
}

fn main() -> std::io::Result<()> {
    read_cgroup_info()
}
```

### Exercice 3.2: Setting Cgroup Limits

```rust
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

struct CgroupManager {
    path: PathBuf,
}

impl CgroupManager {
    fn create(name: &str) -> std::io::Result<Self> {
        let path = PathBuf::from("/sys/fs/cgroup").join(name);
        fs::create_dir_all(&path)?;

        Ok(CgroupManager { path })
    }

    fn set_memory_limit(&self, bytes: u64) -> std::io::Result<()> {
        let mut file = File::create(self.path.join("memory.max"))?;
        writeln!(file, "{}", bytes)?;
        Ok(())
    }

    fn set_cpu_limit(&self, period_us: u64, quota_us: u64) -> std::io::Result<()> {
        let mut file = File::create(self.path.join("cpu.max"))?;
        writeln!(file, "{} {}", quota_us, period_us)?;
        Ok(())
    }

    fn add_process(&self, pid: u32) -> std::io::Result<()> {
        let mut file = File::create(self.path.join("cgroup.procs"))?;
        writeln!(file, "{}", pid)?;
        Ok(())
    }

    fn get_memory_usage(&self) -> std::io::Result<u64> {
        let content = fs::read_to_string(self.path.join("memory.current"))?;
        Ok(content.trim().parse().unwrap_or(0))
    }
}

impl Drop for CgroupManager {
    fn drop(&mut self) {
        // Clean up cgroup
        let _ = fs::remove_dir(&self.path);
    }
}

fn main() -> std::io::Result<()> {
    let cg = CgroupManager::create("odyssey-test")?;

    // Set limits
    cg.set_memory_limit(100 * 1024 * 1024)?; // 100 MB
    cg.set_cpu_limit(100_000, 50_000)?; // 50% CPU

    // Add current process
    cg.add_process(std::process::id())?;

    println!("Memory usage: {} bytes", cg.get_memory_usage()?);

    Ok(())
}
```

---

## Partie 4: Union Filesystems (2.5.28.d)

### Exercice 4.1: Understanding OverlayFS

```bash
#!/bin/bash
# Create OverlayFS structure

# Create directories
mkdir -p /tmp/overlay/{lower,upper,work,merged}

# Add files to lower (read-only) layer
echo "Base file content" > /tmp/overlay/lower/file.txt
mkdir /tmp/overlay/lower/dir
echo "Dir content" > /tmp/overlay/lower/dir/nested.txt

# Mount overlay
sudo mount -t overlay overlay \
    -o lowerdir=/tmp/overlay/lower,upperdir=/tmp/overlay/upper,workdir=/tmp/overlay/work \
    /tmp/overlay/merged

# Now merged/ shows union of lower/ and upper/
ls -la /tmp/overlay/merged/

# Modify a file (copy-on-write to upper)
echo "Modified" >> /tmp/overlay/merged/file.txt

# Check where the modification went
cat /tmp/overlay/upper/file.txt  # Modified version
cat /tmp/overlay/lower/file.txt  # Original unchanged

# Cleanup
sudo umount /tmp/overlay/merged
rm -rf /tmp/overlay
```

### Exercice 4.2: OverlayFS in Rust

```rust
use nix::mount::{mount, MsFlags};
use std::path::Path;
use std::fs;

fn setup_overlay(
    lower: &Path,
    upper: &Path,
    work: &Path,
    merged: &Path,
) -> nix::Result<()> {
    let options = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower.display(),
        upper.display(),
        work.display()
    );

    mount(
        Some("overlay"),
        merged,
        Some("overlay"),
        MsFlags::empty(),
        Some(options.as_str()),
    )?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = Path::new("/tmp/rust_overlay");

    // Create directories
    fs::create_dir_all(base.join("lower"))?;
    fs::create_dir_all(base.join("upper"))?;
    fs::create_dir_all(base.join("work"))?;
    fs::create_dir_all(base.join("merged"))?;

    // Add content to lower
    fs::write(base.join("lower/hello.txt"), "Hello from lower layer")?;

    // Mount (requires root)
    setup_overlay(
        &base.join("lower"),
        &base.join("upper"),
        &base.join("work"),
        &base.join("merged"),
    )?;

    println!("OverlayFS mounted at {:?}", base.join("merged"));

    Ok(())
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Container vs VM understanding | 15 |
| Namespace manipulation | 30 |
| Cgroup management | 25 |
| Union filesystem concepts | 15 |
| Mini-container implementation | 15 |
| **Total** | **100** |

---

## Ressources

- [nix crate docs](https://docs.rs/nix/)
- [Linux Namespaces](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [Cgroups v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
- [OverlayFS](https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html)
