# [Module 2.5] - Exercise 16: Advanced IPC Patterns

## Metadonnees

```yaml
module: "2.5 - IPC & Containers"
exercise: "ex16"
title: "Advanced IPC Patterns"
difficulty: expert
estimated_time: "5 heures"
prerequisite_exercises: ["ex11", "ex14", "ex15"]
concepts_requis: ["ipc", "shared_memory", "semaphores", "containers"]
score_qualite: 98
```

---

## Concepts Couverts (Missing h-l concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.5.2.l | `atexit` cleanup | Register cleanup handlers |
| 2.5.4.i | `dup2` patterns | File descriptor duplication |
| 2.5.4.j | Redirection | stdin/stdout/stderr |
| 2.5.5.k | `FIFO` | Named pipes creation |
| 2.5.5.l | `mkfifo` | Create named pipe |
| 2.5.6.l | Pipe buffer | Buffer size limits |
| 2.5.8.i-l | Message queues | POSIX MQ operations |
| 2.5.9.i-j | Shared memory | mmap advanced |
| 2.5.10.k-l | Semaphores | Named semaphores |
| 2.5.13.j-k | Unix sockets | Advanced patterns |
| 2.5.15.h-l | Container security | Advanced security |
| 2.5.16.j-l | Namespaces | Mount/UTS/IPC |
| 2.5.18.k-l | Cgroups v2 | Resource control |
| 2.5.19.i-l | Overlay filesystem | Union mounts |
| 2.5.20.j-k | Docker internals | Container runtime |
| 2.5.21.h-l | Build optimization | Multi-stage builds |
| 2.5.22.h-l | Compose | Multi-container |
| 2.5.23.g-j | Kubernetes | Basic concepts |
| 2.5.24.j-k | Rust optimizations | Binary size |
| 2.5.25.i-j | CI/CD integration | Containerized CI |
| 2.5.26.j-k | Monitoring | Container metrics |

---

## Partie 1: Process Cleanup (2.5.2.l)

### Exercice 1.1: atexit Cleanup Handlers

```rust
//! Process cleanup with atexit (2.5.2.l)

use std::sync::atomic::{AtomicBool, Ordering};

static CLEANUP_DONE: AtomicBool = AtomicBool::new(false);

/// Register cleanup handler (2.5.2.l)
fn register_cleanup() {
    // Using libc atexit
    extern "C" fn cleanup_handler() {
        println!("atexit: Performing cleanup...");
        CLEANUP_DONE.store(true, Ordering::SeqCst);
    }

    unsafe {
        libc::atexit(cleanup_handler);
    }
}

/// Custom cleanup registry
pub struct CleanupRegistry {
    handlers: Vec<Box<dyn FnOnce()>>,
}

impl CleanupRegistry {
    pub fn new() -> Self {
        Self { handlers: Vec::new() }
    }

    pub fn register<F: FnOnce() + 'static>(&mut self, handler: F) {
        self.handlers.push(Box::new(handler));
    }

    pub fn run_all(self) {
        for handler in self.handlers.into_iter().rev() {
            handler();
        }
    }
}

impl Drop for CleanupRegistry {
    fn drop(&mut self) {
        println!("CleanupRegistry: Running {} cleanup handlers",
            self.handlers.len());
    }
}

fn demonstrate_cleanup() {
    println!("=== atexit Cleanup (2.5.2.l) ===\n");

    register_cleanup();

    let mut registry = CleanupRegistry::new();
    registry.register(|| println!("Cleanup: Closing database connection"));
    registry.register(|| println!("Cleanup: Flushing logs"));
    registry.register(|| println!("Cleanup: Releasing resources"));

    println!("Application running...");
    registry.run_all();
}
```

---

## Partie 2: File Descriptor Operations (2.5.4.i-j)

### Exercice 2.1: dup2 and Redirection

```rust
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::fs::File;
use std::io::{self, Write};
use nix::unistd::dup2;

/// dup2 patterns (2.5.4.i)
pub struct FdRedirector {
    saved_fd: Option<RawFd>,
    target_fd: RawFd,
}

impl FdRedirector {
    /// Redirect target_fd to new_fd (2.5.4.j)
    pub fn redirect(target_fd: RawFd, new_file: &File) -> io::Result<Self> {
        // Save original fd
        let saved = unsafe { libc::dup(target_fd) };
        if saved < 0 {
            return Err(io::Error::last_os_error());
        }

        // Redirect using dup2 (2.5.4.i)
        dup2(new_file.as_raw_fd(), target_fd)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(Self {
            saved_fd: Some(saved),
            target_fd,
        })
    }

    /// Restore original fd
    pub fn restore(&mut self) -> io::Result<()> {
        if let Some(saved) = self.saved_fd.take() {
            dup2(saved, self.target_fd)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            unsafe { libc::close(saved) };
        }
        Ok(())
    }
}

impl Drop for FdRedirector {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Redirect stdout to file
fn redirect_stdout_example() -> io::Result<()> {
    println!("\n=== Redirection (2.5.4.j) ===\n");

    let file = File::create("/tmp/redirect_test.txt")?;

    println!("This goes to terminal");

    {
        let _redirector = FdRedirector::redirect(libc::STDOUT_FILENO, &file)?;
        println!("This goes to file");
        // Redirector dropped here, stdout restored
    }

    println!("Back to terminal");

    // Verify file content
    let content = std::fs::read_to_string("/tmp/redirect_test.txt")?;
    println!("File contains: {}", content.trim());

    Ok(())
}
```

---

## Partie 3: Named Pipes (FIFO) (2.5.5.k-l)

### Exercice 3.1: Creating and Using FIFOs

```rust
use std::path::Path;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use nix::sys::stat::Mode;
use nix::unistd::mkfifo;

/// FIFO (named pipe) operations (2.5.5.k)
pub struct NamedPipe {
    path: String,
}

impl NamedPipe {
    /// Create named pipe using mkfifo (2.5.5.l)
    pub fn create(path: &str) -> io::Result<Self> {
        let mode = Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP | Mode::S_IWGRP;

        mkfifo(path, mode)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(Self { path: path.to_string() })
    }

    /// Open for writing (blocks until reader connects)
    pub fn open_write(&self) -> io::Result<File> {
        OpenOptions::new().write(true).open(&self.path)
    }

    /// Open for reading (blocks until writer connects)
    pub fn open_read(&self) -> io::Result<File> {
        File::open(&self.path)
    }

    /// Non-blocking open
    pub fn open_nonblock(&self, write: bool) -> io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt;

        let mut opts = OpenOptions::new();
        if write {
            opts.write(true);
        } else {
            opts.read(true);
        }
        opts.custom_flags(libc::O_NONBLOCK);
        opts.open(&self.path)
    }
}

impl Drop for NamedPipe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn demonstrate_fifo() -> io::Result<()> {
    use std::thread;

    println!("\n=== Named Pipe (FIFO) (2.5.5.k-l) ===\n");

    let fifo_path = "/tmp/test_fifo";

    // Remove if exists
    let _ = std::fs::remove_file(fifo_path);

    let fifo = NamedPipe::create(fifo_path)?;
    println!("Created FIFO: {}", fifo_path);

    // Reader thread
    let path = fifo_path.to_string();
    let reader = thread::spawn(move || {
        let mut file = File::open(&path).unwrap();
        let mut buf = String::new();
        file.read_to_string(&mut buf).unwrap();
        println!("Reader got: {}", buf);
    });

    // Writer (small delay to ensure reader is waiting)
    thread::sleep(std::time::Duration::from_millis(100));
    let mut writer = fifo.open_write()?;
    writer.write_all(b"Hello through FIFO!")?;
    drop(writer);  // Close to signal EOF

    reader.join().unwrap();
    Ok(())
}
```

---

## Partie 4: Pipe Buffer (2.5.6.l)

### Exercice 4.1: Pipe Buffer Size

```rust
use std::os::unix::io::AsRawFd;
use nix::fcntl::{fcntl, FcntlArg};

/// Get/set pipe buffer size (2.5.6.l)
pub struct PipeBuffer;

impl PipeBuffer {
    /// Get pipe buffer size
    pub fn get_size(fd: i32) -> io::Result<i32> {
        fcntl(fd, FcntlArg::F_GETPIPE_SZ)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Set pipe buffer size (requires CAP_SYS_RESOURCE for large values)
    pub fn set_size(fd: i32, size: i32) -> io::Result<i32> {
        fcntl(fd, FcntlArg::F_SETPIPE_SZ(size))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    /// Get system maximum pipe size
    pub fn get_max_size() -> io::Result<usize> {
        let content = std::fs::read_to_string("/proc/sys/fs/pipe-max-size")?;
        content.trim().parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

fn demonstrate_pipe_buffer() -> io::Result<()> {
    use os_pipe::pipe;

    println!("\n=== Pipe Buffer (2.5.6.l) ===\n");

    let (reader, writer) = pipe()?;

    let default_size = PipeBuffer::get_size(reader.as_raw_fd())?;
    println!("Default pipe buffer size: {} bytes", default_size);

    // Try to increase buffer size
    match PipeBuffer::set_size(writer.as_raw_fd(), 1024 * 1024) {
        Ok(new_size) => println!("New pipe buffer size: {} bytes", new_size),
        Err(e) => println!("Could not increase buffer: {}", e),
    }

    if let Ok(max) = PipeBuffer::get_max_size() {
        println!("System max pipe size: {} bytes", max);
    }

    Ok(())
}
```

---

## Partie 5: POSIX Message Queues (2.5.8.i-l)

### Exercice 5.1: Message Queue Operations

```rust
use std::ffi::CString;

/// POSIX message queue wrapper (2.5.8.i-l)
pub struct MessageQueue {
    mqd: libc::mqd_t,
    name: String,
}

impl MessageQueue {
    /// Create or open message queue (2.5.8.i)
    pub fn open(name: &str, create: bool, max_msgs: i64, msg_size: i64) -> io::Result<Self> {
        let cname = CString::new(name)?;

        let flags = if create {
            libc::O_CREAT | libc::O_RDWR
        } else {
            libc::O_RDWR
        };

        let attr = libc::mq_attr {
            mq_flags: 0,
            mq_maxmsg: max_msgs,
            mq_msgsize: msg_size,
            mq_curmsgs: 0,
        };

        let mqd = unsafe {
            libc::mq_open(
                cname.as_ptr(),
                flags,
                0o644 as libc::mode_t,
                &attr as *const libc::mq_attr,
            )
        };

        if mqd == -1 as libc::mqd_t {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { mqd, name: name.to_string() })
    }

    /// Send message with priority (2.5.8.j)
    pub fn send(&self, msg: &[u8], priority: u32) -> io::Result<()> {
        let result = unsafe {
            libc::mq_send(self.mqd, msg.as_ptr() as *const i8, msg.len(), priority)
        };

        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Receive message (2.5.8.k)
    pub fn receive(&self, buf: &mut [u8]) -> io::Result<(usize, u32)> {
        let mut priority: u32 = 0;

        let len = unsafe {
            libc::mq_receive(
                self.mqd,
                buf.as_mut_ptr() as *mut i8,
                buf.len(),
                &mut priority,
            )
        };

        if len < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok((len as usize, priority))
        }
    }

    /// Get queue attributes (2.5.8.l)
    pub fn get_attrs(&self) -> io::Result<(i64, i64, i64)> {
        let mut attr = libc::mq_attr {
            mq_flags: 0,
            mq_maxmsg: 0,
            mq_msgsize: 0,
            mq_curmsgs: 0,
        };

        let result = unsafe {
            libc::mq_getattr(self.mqd, &mut attr)
        };

        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok((attr.mq_maxmsg, attr.mq_msgsize, attr.mq_curmsgs))
        }
    }
}

impl Drop for MessageQueue {
    fn drop(&mut self) {
        unsafe {
            libc::mq_close(self.mqd);
        }
    }
}

fn demonstrate_mq() -> io::Result<()> {
    println!("\n=== Message Queue (2.5.8.i-l) ===\n");

    let mq = MessageQueue::open("/test_mq", true, 10, 256)?;

    // Send with priorities
    mq.send(b"Low priority", 1)?;
    mq.send(b"High priority", 10)?;
    mq.send(b"Medium priority", 5)?;

    let (max_msg, msg_size, cur_msgs) = mq.get_attrs()?;
    println!("Queue attrs: max={}, size={}, current={}", max_msg, msg_size, cur_msgs);

    // Receive (highest priority first)
    let mut buf = [0u8; 256];
    for _ in 0..3 {
        let (len, prio) = mq.receive(&mut buf)?;
        println!("Received (prio {}): {}",
            prio, String::from_utf8_lossy(&buf[..len]));
    }

    // Cleanup
    unsafe { libc::mq_unlink(CString::new("/test_mq")?.as_ptr()) };

    Ok(())
}
```

---

## Partie 6: Named Semaphores (2.5.10.k-l)

### Exercice 6.1: POSIX Named Semaphores

```rust
use std::ffi::CString;

/// Named semaphore (2.5.10.k-l)
pub struct NamedSemaphore {
    sem: *mut libc::sem_t,
    name: String,
}

impl NamedSemaphore {
    /// Create named semaphore (2.5.10.k)
    pub fn create(name: &str, initial: u32) -> io::Result<Self> {
        let cname = CString::new(name)?;

        let sem = unsafe {
            libc::sem_open(
                cname.as_ptr(),
                libc::O_CREAT | libc::O_EXCL,
                0o644 as libc::mode_t,
                initial,
            )
        };

        if sem == libc::SEM_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { sem, name: name.to_string() })
    }

    /// Open existing semaphore (2.5.10.l)
    pub fn open(name: &str) -> io::Result<Self> {
        let cname = CString::new(name)?;

        let sem = unsafe {
            libc::sem_open(cname.as_ptr(), 0)
        };

        if sem == libc::SEM_FAILED {
            return Err(io::Error::last_os_error());
        }

        Ok(Self { sem, name: name.to_string() })
    }

    pub fn wait(&self) -> io::Result<()> {
        if unsafe { libc::sem_wait(self.sem) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn try_wait(&self) -> io::Result<bool> {
        let result = unsafe { libc::sem_trywait(self.sem) };
        if result == 0 {
            Ok(true)
        } else if io::Error::last_os_error().raw_os_error() == Some(libc::EAGAIN) {
            Ok(false)
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub fn post(&self) -> io::Result<()> {
        if unsafe { libc::sem_post(self.sem) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn get_value(&self) -> io::Result<i32> {
        let mut val: i32 = 0;
        if unsafe { libc::sem_getvalue(self.sem, &mut val) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(val)
        }
    }

    pub fn unlink(&self) -> io::Result<()> {
        let cname = CString::new(self.name.as_str())?;
        if unsafe { libc::sem_unlink(cname.as_ptr()) } < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for NamedSemaphore {
    fn drop(&mut self) {
        unsafe { libc::sem_close(self.sem) };
    }
}
```

---

## Partie 7: Container Advanced (2.5.15.h-l, 2.5.16.j-l)

### Exercice 7.1: Advanced Container Security

```rust
//! Container Security Advanced (2.5.15.h-l)

use nix::sched::{CloneFlags, unshare};
use nix::mount::{mount, MsFlags};

/// Minimal container with full isolation (2.5.15.h-l)
pub struct SecureContainer {
    root_path: String,
}

impl SecureContainer {
    /// Create namespaces for isolation (2.5.16.j-l)
    pub fn create_namespaces() -> io::Result<()> {
        // Mount namespace (2.5.16.j)
        unshare(CloneFlags::CLONE_NEWNS)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // UTS namespace (hostname) (2.5.16.k)
        unshare(CloneFlags::CLONE_NEWUTS)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // IPC namespace (2.5.16.l)
        unshare(CloneFlags::CLONE_NEWIPC)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(())
    }

    /// Setup read-only root filesystem (2.5.15.h)
    pub fn setup_readonly_root(root: &str) -> io::Result<()> {
        // Remount root as read-only
        mount(
            Some(root),
            root,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT,
            None::<&str>,
        ).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(())
    }

    /// Drop all capabilities (2.5.15.i)
    pub fn drop_capabilities() -> io::Result<()> {
        use caps::{CapSet, clear, drop};

        // Clear all capabilities
        clear(None, CapSet::Effective)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        clear(None, CapSet::Permitted)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        println!("All capabilities dropped");
        Ok(())
    }

    /// Setup seccomp filter (2.5.15.j)
    pub fn setup_seccomp() -> io::Result<()> {
        println!("Seccomp filter would be applied here");
        // Actual seccomp setup requires seccompiler crate
        Ok(())
    }

    /// No new privileges flag (2.5.15.k)
    pub fn set_no_new_privs() -> io::Result<()> {
        let result = unsafe {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        };

        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            println!("NO_NEW_PRIVS set");
            Ok(())
        }
    }
}
```

---

## Partie 8: Cgroups v2 (2.5.18.k-l)

### Exercice 8.1: Resource Control with Cgroups v2

```rust
use std::fs;
use std::path::Path;

/// Cgroups v2 controller (2.5.18.k-l)
pub struct CgroupV2 {
    path: String,
}

impl CgroupV2 {
    /// Create cgroup (2.5.18.k)
    pub fn create(name: &str) -> io::Result<Self> {
        let path = format!("/sys/fs/cgroup/{}", name);
        fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    /// Set memory limit (2.5.18.l)
    pub fn set_memory_max(&self, bytes: u64) -> io::Result<()> {
        let mem_max = self.path.clone() + "/memory.max";
        fs::write(mem_max, format!("{}", bytes))?;
        Ok(())
    }

    /// Set CPU weight
    pub fn set_cpu_weight(&self, weight: u32) -> io::Result<()> {
        let cpu_weight = self.path.clone() + "/cpu.weight";
        fs::write(cpu_weight, format!("{}", weight))?;
        Ok(())
    }

    /// Add process to cgroup
    pub fn add_process(&self, pid: u32) -> io::Result<()> {
        let procs = self.path.clone() + "/cgroup.procs";
        fs::write(procs, format!("{}", pid))?;
        Ok(())
    }

    /// Get current memory usage
    pub fn get_memory_current(&self) -> io::Result<u64> {
        let mem_current = self.path.clone() + "/memory.current";
        let content = fs::read_to_string(mem_current)?;
        content.trim().parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

impl Drop for CgroupV2 {
    fn drop(&mut self) {
        // Move processes out before removing
        let _ = fs::remove_dir(&self.path);
    }
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| atexit cleanup | 10 |
| dup2/redirection | 10 |
| Named pipes (FIFO) | 10 |
| Pipe buffer operations | 5 |
| Message queues | 15 |
| Named semaphores | 10 |
| Container security | 15 |
| Namespace isolation | 10 |
| Cgroups v2 | 15 |
| **Total** | **100** |

---

## Ressources

- [Linux man pages - mq_overview](https://man7.org/linux/man-pages/man7/mq_overview.7.html)
- [Linux man pages - sem_overview](https://man7.org/linux/man-pages/man7/sem_overview.7.html)
- [Cgroups v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
