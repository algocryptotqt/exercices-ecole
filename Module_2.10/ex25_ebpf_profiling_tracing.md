# [Module 2.10] - Exercise 25: eBPF Networking, Profiling & Tracing

## Metadonnees

```yaml
module: "2.10 - Advanced Topics"
exercise: "ex25"
title: "eBPF Networking, Profiling & System Tracing"
difficulty: expert
estimated_time: "6 heures"
prerequisite_exercises: ["ex24"]
concepts_requis: ["eBPF", "profiling", "ptrace"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.10.41: eBPF Networking (8 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.10.41.a | XDP | eXpress Data Path |
| 2.10.41.b | `#[xdp]` | XDP program attribute |
| 2.10.41.c | `XdpContext` | Packet context |
| 2.10.41.d | `xdp_action` | PASS, DROP, TX, REDIRECT |
| 2.10.41.e | Packet parsing | Ethernet, IP, TCP/UDP |
| 2.10.41.f | Packet modification | Rewrite headers |
| 2.10.41.g | Load balancing | XDP-based LB |
| 2.10.41.h | Firewall | XDP filtering |

### 2.10.42: System Performance - Profiling (7 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.10.42.a | `perf` | Linux profiler |
| 2.10.42.b | `flamegraph` crate | Generate flame graphs |
| 2.10.42.c | `cargo flamegraph` | Easy profiling |
| 2.10.42.d | `tracing` crate | Instrumentation |
| 2.10.42.e | `tracing-flame` | Flame graph output |
| 2.10.42.f | CPU profiling | Hot functions |
| 2.10.42.g | Memory profiling | Allocations |

### 2.10.43: System Tracing (7 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.10.43.a | `strace` | System call tracing |
| 2.10.43.b | `ltrace` | Library call tracing |
| 2.10.43.c | `ptrace` in Rust | `nix::sys::ptrace` |
| 2.10.43.d | `PTRACE_TRACEME` | Enable tracing |
| 2.10.43.e | `PTRACE_SYSCALL` | Stop on syscall |
| 2.10.43.f | `PTRACE_GETREGS` | Get registers |
| 2.10.43.g | Build tracer | Custom strace |

### 2.10.44: Real-Time Systems (8 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.10.44.a | Real-time | Timing constraints |
| 2.10.44.b | PREEMPT_RT | Linux RT patch |
| 2.10.44.c | `SCHED_FIFO` | RT scheduling |
| 2.10.44.d | `sched_setscheduler()` | Set scheduler |
| 2.10.44.e | `nix::sched::sched_setscheduler()` | Rust API |
| 2.10.44.f | `mlockall()` | Lock memory |
| 2.10.44.g | CPU isolation | `isolcpus` |
| 2.10.44.h | Latency reduction | Best practices |

### 2.10.45: Storage & LVM (8 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.10.45.a | Block devices | `/dev/sd*`, `/dev/nvme*` |
| 2.10.45.b | LVM | Logical Volume Manager |
| 2.10.45.c | `lvm2` crate | LVM bindings |
| 2.10.45.d | Device mapper | Kernel subsystem |
| 2.10.45.e | `devicemapper` crate | DM interface |
| 2.10.45.f | Thin provisioning | Overcommit |
| 2.10.45.g | Snapshots | Point-in-time |
| 2.10.45.h | RAID | Software RAID |

---

## Partie 1: eBPF Networking (2.10.41)

### Exercice 1.1: XDP Firewall

```rust
// eBPF program - xdp_firewall.rs
#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::{map, xdp}, maps::HashMap, programs::XdpContext};
use core::mem;
use network_types::{eth::{EthHdr, EtherType}, ip::Ipv4Hdr, tcp::TcpHdr, udp::UdpHdr};

// Blocked IPs map
#[map]
static BLOCKED_IPS: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

// Blocked ports map
#[map]
static BLOCKED_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(256, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_firewall(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // Parse Ethernet header
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Parse IPv4 header
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let src_ip = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    // Check blocked IPs
    if unsafe { BLOCKED_IPS.get(&src_ip).is_some() } {
        return Ok(xdp_action::XDP_DROP);
    }

    // Check blocked ports for TCP/UDP
    let protocol = unsafe { (*ipv4hdr).proto };
    let ihl = unsafe { (*ipv4hdr).ihl() } as usize * 4;

    let dst_port = match protocol {
        6 => { // TCP
            let tcphdr: *const TcpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + ihl)? };
            u16::from_be(unsafe { (*tcphdr).dest })
        }
        17 => { // UDP
            let udphdr: *const UdpHdr = unsafe { ptr_at(&ctx, EthHdr::LEN + ihl)? };
            u16::from_be(unsafe { (*udphdr).dest })
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    if unsafe { BLOCKED_PORTS.get(&dst_port).is_some() } {
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start + offset + len > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

### Exercice 1.2: XDP Load Balancer

```rust
// Simple round-robin load balancer
#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::{map, xdp}, maps::{Array, HashMap}, programs::XdpContext};

// Backend servers (IP addresses)
#[map]
static BACKENDS: Array<u32> = Array::with_max_entries(16, 0);

// Number of backends
#[map]
static BACKEND_COUNT: Array<u32> = Array::with_max_entries(1, 0);

// Round-robin counter
#[map]
static RR_COUNTER: Array<u32> = Array::with_max_entries(1, 0);

#[xdp]
pub fn xdp_lb(ctx: XdpContext) -> u32 {
    match try_lb(ctx) {
        Ok(action) => action,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_lb(ctx: XdpContext) -> Result<u32, ()> {
    // Get backend count
    let count = unsafe { BACKEND_COUNT.get(0).copied().unwrap_or(0) };
    if count == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // Get and increment RR counter
    let counter_ptr = unsafe { RR_COUNTER.get_ptr_mut(0).ok_or(())? };
    let idx = unsafe { (*counter_ptr) % count };
    unsafe { *counter_ptr = (*counter_ptr).wrapping_add(1) };

    // Get backend IP
    let backend_ip = unsafe { BACKENDS.get(idx as u32).copied().ok_or(())? };

    // Rewrite destination IP (simplified - would need full packet rewrite)
    // In practice, use XDP_TX or XDP_REDIRECT

    Ok(xdp_action::XDP_PASS)
}
```

---

## Partie 2: Profiling (2.10.42)

### Exercice 2.1: Using cargo-flamegraph

```bash
# Install
cargo install flamegraph

# Profile your application
cargo flamegraph --bin myapp

# With specific arguments
cargo flamegraph --bin myapp -- arg1 arg2

# Output to specific file
cargo flamegraph -o profile.svg --bin myapp
```

### Exercice 2.2: Tracing Instrumentation

```rust
use tracing::{info, instrument, span, Level};
use tracing_subscriber::{fmt, prelude::*};

#[instrument]
fn process_data(data: &[u8]) -> usize {
    info!(data_len = data.len(), "Processing data");

    let span = span!(Level::DEBUG, "inner_processing");
    let _guard = span.enter();

    // Simulate work
    let result = data.iter().map(|&b| b as usize).sum();

    info!(result = result, "Processing complete");
    result
}

#[instrument(skip(large_data))]
async fn async_process(id: u32, large_data: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting async process");

    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let _ = process_data(&large_data);

    info!("Async process complete");
    Ok(())
}

fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(fmt::layer())
        .init();

    let data = vec![1u8; 1000];
    let result = process_data(&data);
    println!("Result: {}", result);
}
```

### Exercice 2.3: Memory Profiling with DHAT

```rust
// Cargo.toml: dhat = { version = "0.3", optional = true }
// Run with: cargo run --release --features dhat

#[cfg(feature = "dhat")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() {
    #[cfg(feature = "dhat")]
    let _profiler = dhat::Profiler::new_heap();

    // Your code here
    let mut vecs: Vec<Vec<u8>> = Vec::new();
    for i in 0..1000 {
        vecs.push(vec![0u8; i * 10]);
    }

    // dhat will output allocation statistics when _profiler is dropped
}
```

---

## Partie 3: System Tracing (2.10.43)

### Exercice 3.1: Simple strace in Rust

```rust
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::ffi::CString;
use std::os::unix::process::CommandExt;

fn trace_syscalls(pid: Pid) -> nix::Result<()> {
    // Wait for initial stop
    waitpid(pid, None)?;

    // Set ptrace options
    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)?;

    loop {
        // Continue until next syscall
        ptrace::syscall(pid, None)?;

        match waitpid(pid, None)? {
            WaitStatus::Exited(_, code) => {
                println!("Process exited with code {}", code);
                break;
            }
            WaitStatus::PtraceSyscall(_) => {
                // Get syscall number from registers
                let regs = ptrace::getregs(pid)?;

                // On x86_64: orig_rax is syscall number
                let syscall_num = regs.orig_rax;
                let arg1 = regs.rdi;
                let arg2 = regs.rsi;
                let arg3 = regs.rdx;

                println!("syscall({}, {:#x}, {:#x}, {:#x})",
                    syscall_name(syscall_num), arg1, arg2, arg3);

                // Continue to syscall exit
                ptrace::syscall(pid, None)?;
                waitpid(pid, None)?;

                // Get return value
                let regs = ptrace::getregs(pid)?;
                println!("  = {}", regs.rax as i64);
            }
            status => {
                println!("Unexpected status: {:?}", status);
            }
        }
    }

    Ok(())
}

fn syscall_name(num: u64) -> &'static str {
    match num {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        9 => "mmap",
        11 => "munmap",
        12 => "brk",
        60 => "exit",
        231 => "exit_group",
        _ => "unknown",
    }
}

fn main() -> nix::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <program> [args...]", args[0]);
        std::process::exit(1);
    }

    match unsafe { fork()? } {
        ForkResult::Parent { child } => {
            trace_syscalls(child)?;
        }
        ForkResult::Child => {
            // Enable tracing
            ptrace::traceme()?;

            // Execute the target program
            let program = CString::new(args[1].as_str()).unwrap();
            let args: Vec<CString> = args[1..].iter()
                .map(|s| CString::new(s.as_str()).unwrap())
                .collect();

            std::process::Command::new(&args[1])
                .args(&args[2..])
                .exec();
        }
    }

    Ok(())
}
```

---

## Partie 4: Real-Time Systems (2.10.44)

### Exercice 4.1: RT Scheduling

```rust
use nix::sched::{sched_setscheduler, CpuSet};
use nix::sys::mman::{mlockall, MlockAllFlags};
use nix::unistd::Pid;

fn setup_realtime() -> nix::Result<()> {
    // Lock all memory to prevent page faults
    mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE)?;

    // Set SCHED_FIFO with priority 99
    let param = libc::sched_param { sched_priority: 99 };

    unsafe {
        let ret = libc::sched_setscheduler(0, libc::SCHED_FIFO, &param);
        if ret != 0 {
            return Err(nix::errno::Errno::last());
        }
    }

    // Set CPU affinity to isolate on CPU 1
    let mut cpuset = CpuSet::new();
    cpuset.set(1)?;
    nix::sched::sched_setaffinity(Pid::from_raw(0), &cpuset)?;

    println!("Real-time setup complete:");
    println!("  Scheduler: SCHED_FIFO");
    println!("  Priority: 99");
    println!("  CPU affinity: CPU 1");
    println!("  Memory locked: yes");

    Ok(())
}

fn realtime_loop() {
    let period = std::time::Duration::from_micros(1000); // 1ms period

    loop {
        let start = std::time::Instant::now();

        // RT task work here
        do_rt_work();

        // Sleep for remaining period
        let elapsed = start.elapsed();
        if elapsed < period {
            std::thread::sleep(period - elapsed);
        } else {
            eprintln!("WARNING: RT deadline missed by {:?}", elapsed - period);
        }
    }
}

fn do_rt_work() {
    // Simulate RT work
    let mut sum = 0u64;
    for i in 0..1000 {
        sum = sum.wrapping_add(i);
    }
    std::hint::black_box(sum);
}

fn main() {
    if nix::unistd::geteuid().as_raw() != 0 {
        eprintln!("Must run as root for RT scheduling");
        return;
    }

    if let Err(e) = setup_realtime() {
        eprintln!("Failed to setup RT: {}", e);
        return;
    }

    realtime_loop();
}
```

---

## Partie 5: Storage & LVM (2.10.45)

### Exercice 5.1: Block Device Information

```rust
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

fn list_block_devices() -> std::io::Result<()> {
    println!("Block Devices:");

    for entry in fs::read_dir("/sys/block")? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();

        // Get size
        let size_path = entry.path().join("size");
        let size: u64 = fs::read_to_string(&size_path)?
            .trim()
            .parse()
            .unwrap_or(0);
        let size_gb = (size * 512) / (1024 * 1024 * 1024);

        // Get model (if available)
        let model_path = entry.path().join("device/model");
        let model = fs::read_to_string(&model_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "N/A".to_string());

        println!("  /dev/{}: {} GB - {}", name, size_gb, model);

        // List partitions
        for part in fs::read_dir(entry.path())? {
            let part = part?;
            let part_name = part.file_name();
            let part_name = part_name.to_string_lossy();
            if part_name.starts_with(&*name) && part_name != *name {
                let part_size_path = part.path().join("size");
                if let Ok(part_size) = fs::read_to_string(&part_size_path) {
                    let part_size: u64 = part_size.trim().parse().unwrap_or(0);
                    let part_size_mb = (part_size * 512) / (1024 * 1024);
                    println!("    /dev/{}: {} MB", part_name, part_size_mb);
                }
            }
        }
    }

    Ok(())
}

fn read_block_device(path: &str, offset: u64, size: usize) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(offset))?;

    let mut buffer = vec![0u8; size];
    file.read_exact(&mut buffer)?;

    Ok(buffer)
}

fn main() -> std::io::Result<()> {
    list_block_devices()?;

    // Read MBR from first disk (requires root)
    if nix::unistd::geteuid().as_raw() == 0 {
        if let Ok(mbr) = read_block_device("/dev/sda", 0, 512) {
            println!("\nMBR signature: {:02x}{:02x}", mbr[510], mbr[511]);
        }
    }

    Ok(())
}
```

### Exercice 5.2: Device Mapper Interaction

```rust
use std::process::Command;

fn list_dm_devices() -> std::io::Result<()> {
    let output = Command::new("dmsetup")
        .arg("ls")
        .output()?;

    println!("Device Mapper devices:");
    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}

fn list_lvm_info() -> std::io::Result<()> {
    // Volume Groups
    println!("Volume Groups:");
    let output = Command::new("vgs")
        .args(["--noheadings", "-o", "vg_name,vg_size,vg_free"])
        .output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));

    // Logical Volumes
    println!("\nLogical Volumes:");
    let output = Command::new("lvs")
        .args(["--noheadings", "-o", "lv_name,vg_name,lv_size"])
        .output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));

    // Physical Volumes
    println!("\nPhysical Volumes:");
    let output = Command::new("pvs")
        .args(["--noheadings", "-o", "pv_name,vg_name,pv_size,pv_free"])
        .output()?;
    println!("{}", String::from_utf8_lossy(&output.stdout));

    Ok(())
}

fn main() -> std::io::Result<()> {
    if nix::unistd::geteuid().as_raw() != 0 {
        eprintln!("Must run as root");
        return Ok(());
    }

    list_dm_devices()?;
    println!();
    list_lvm_info()?;

    Ok(())
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| eBPF XDP programs | 20 |
| Profiling tools | 20 |
| ptrace tracing | 20 |
| RT scheduling | 20 |
| Storage/LVM | 20 |
| **Total** | **100** |

---

## Ressources

- [Aya XDP Tutorial](https://aya-rs.dev/book/programs/xdp/)
- [cargo-flamegraph](https://github.com/flamegraph-rs/flamegraph)
- [tracing crate](https://docs.rs/tracing/)
- [ptrace man page](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [PREEMPT_RT](https://wiki.linuxfoundation.org/realtime/start)
