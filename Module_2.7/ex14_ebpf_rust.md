# [Module 2.7] - Exercise 14: eBPF Programming with Rust

## Metadonnees

```yaml
module: "2.7 - Kernel Development"
exercise: "ex14"
title: "eBPF Programming with Aya"
difficulty: expert
estimated_time: "6 heures"
prerequisite_exercises: ["ex00", "ex13"]
concepts_requis: ["eBPF", "kernel tracing", "networking"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.7.23: eBPF with Rust (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.7.23.a | eBPF | Extended Berkeley Packet Filter |
| 2.7.23.b | `aya` crate | Rust eBPF framework |
| 2.7.23.c | eBPF programs | Programs running in kernel |
| 2.7.23.d | User-space loader | Loading and managing programs |
| 2.7.23.e | Program types | XDP, tracepoint, kprobe |
| 2.7.23.f | Maps | Kernel-user communication |
| 2.7.23.g | `aya-bpf` | Writing eBPF programs in Rust |
| 2.7.23.h | `aya` | User-space management library |
| 2.7.23.i | `#![no_std]` | eBPF program constraints |
| 2.7.23.j | Verifier | BPF verifier safety checks |

### 2.7.24: Writing eBPF Programs (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.7.24.a | `aya_bpf::programs` | Program type definitions |
| 2.7.24.b | `#[xdp]` | XDP program attribute |
| 2.7.24.c | `#[tracepoint]` | Tracepoint program attribute |
| 2.7.24.d | `#[kprobe]` | Kernel probe attribute |
| 2.7.24.e | `aya_bpf::maps` | Map type definitions |
| 2.7.24.f | `HashMap` | Key-value BPF map |
| 2.7.24.g | `PerfEventArray` | Perf event buffer |
| 2.7.24.h | `RingBuf` | Ring buffer for events |
| 2.7.24.i | Context | Program context types |
| 2.7.24.j | Return codes | XDP_PASS, XDP_DROP, etc |

---

## Partie 1: Introduction to eBPF (2.7.23)

### Exercice 1.1: Project Setup

```bash
# Install aya tools
cargo install bpf-linker
cargo install cargo-generate

# Generate new aya project
cargo generate https://github.com/aya-rs/aya-template

# Project structure:
# my-ebpf-project/
# ├── Cargo.toml
# ├── my-ebpf-project/         # User-space application
# │   ├── Cargo.toml
# │   └── src/
# │       └── main.rs
# ├── my-ebpf-project-ebpf/    # eBPF program (no_std)
# │   ├── Cargo.toml
# │   └── src/
# │       └── main.rs
# └── xtask/                    # Build helpers
```

### Exercice 1.2: Simple XDP Program

**eBPF Program (my-project-ebpf/src/main.rs):**

```rust
#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::xdp,
    programs::XdpContext,
};
use aya_log_ebpf::info;

#[xdp]
pub fn xdp_pass(ctx: XdpContext) -> u32 {
    match try_xdp_pass(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_pass(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

**User-space Loader (my-project/src/main.rs):**

```rust
use anyhow::Context;
use aya::{include_bytes_aligned, Bpf};
use aya::programs::{Xdp, XdpFlags};
use aya_log::BpfLogger;
use log::{info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // Load the eBPF program
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/my-project"
    ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/my-project"
    ))?;

    // Initialize logging from eBPF
    if let Err(e) = BpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    // Get the XDP program
    let program: &mut Xdp = bpf
        .program_mut("xdp_pass")
        .unwrap()
        .try_into()?;

    // Load and attach to interface
    program.load()?;
    program.attach("eth0", XdpFlags::default())
        .context("failed to attach XDP program")?;

    info!("XDP program attached. Press Ctrl-C to exit.");

    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
```

**Questions:**
1. Pourquoi le programme eBPF est-il `#![no_std]` ?
2. Que fait le verifier BPF avant le chargement ?
3. Expliquez les différents `XdpFlags` disponibles ?

### Exercice 1.3: eBPF Maps

```rust
// eBPF side - declare map
#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

// Packet counter map: IP -> count
#[map]
static PACKET_COUNT: HashMap<u32, u64> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_counter(ctx: XdpContext) -> u32 {
    match try_xdp_counter(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_counter(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let src_ip = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    // Update counter
    let count = unsafe {
        let ptr = PACKET_COUNT.get_ptr_mut(&src_ip).ok_or(())?;
        *ptr += 1;
        *ptr
    };

    info!(&ctx, "packet from {:i}, count: {}", src_ip, count);

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
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

**User-space reading the map:**

```rust
use aya::maps::HashMap;
use std::net::Ipv4Addr;

// In main after attaching:
let packet_count: HashMap<_, u32, u64> =
    HashMap::try_from(bpf.map_mut("PACKET_COUNT").unwrap())?;

// Read periodically
loop {
    for item in packet_count.iter() {
        let (ip, count) = item?;
        let addr = Ipv4Addr::from(ip);
        println!("{}: {} packets", addr, count);
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
}
```

**Questions:**
1. Comment fonctionne la communication via maps ?
2. Pourquoi `with_max_entries` est obligatoire ?
3. Quels types de maps BPF existent ?

---

## Partie 2: Advanced eBPF Programs (2.7.24)

### Exercice 2.1: Tracepoint Program

```rust
// eBPF program tracing syscalls
#![no_std]
#![no_main]

use aya_bpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
    BpfContext,
};
use aya_log_ebpf::info;

#[repr(C)]
pub struct SyscallEvent {
    pub pid: u32,
    pub syscall_nr: i64,
    pub timestamp: u64,
}

#[map]
static EVENTS: PerfEventArray<SyscallEvent> = PerfEventArray::new(0);

#[tracepoint(name = "sys_enter")]
pub fn trace_syscall(ctx: TracePointContext) -> u32 {
    match try_trace_syscall(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_trace_syscall(ctx: TracePointContext) -> Result<u32, i64> {
    let syscall_nr: i64 = unsafe { ctx.read_at(8)? };

    let event = SyscallEvent {
        pid: ctx.pid(),
        syscall_nr,
        timestamp: unsafe { aya_bpf::helpers::bpf_ktime_get_ns() },
    };

    EVENTS.output(&ctx, &event, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

**User-space event handling:**

```rust
use aya::maps::perf::AsyncPerfEventArray;
use bytes::BytesMut;

async fn process_events(bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    let mut perf_array = AsyncPerfEventArray::try_from(
        bpf.take_map("EVENTS").unwrap()
    )?;

    for cpu_id in aya::util::online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        tokio::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let event: &SyscallEvent = unsafe {
                        &*(buf.as_ptr() as *const SyscallEvent)
                    };
                    println!(
                        "PID {} called syscall {} at {}",
                        event.pid, event.syscall_nr, event.timestamp
                    );
                }
            }
        });
    }

    Ok(())
}
```

### Exercice 2.2: Kprobe Program

```rust
// Trace function calls with kprobe
#![no_std]
#![no_main]

use aya_bpf::{
    macros::{kprobe, map},
    maps::RingBuf,
    programs::ProbeContext,
    BpfContext,
};

#[repr(C)]
pub struct FnCallEvent {
    pub pid: u32,
    pub comm: [u8; 16],
    pub ip: u64,
}

#[map]
static RING_BUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[kprobe]
pub fn kprobe_tcp_connect(ctx: ProbeContext) -> u32 {
    match try_kprobe(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_kprobe(ctx: ProbeContext) -> Result<u32, i64> {
    if let Some(mut entry) = RING_BUF.reserve::<FnCallEvent>(0) {
        let event = entry.as_mut_ptr();

        unsafe {
            (*event).pid = ctx.pid();
            (*event).ip = ctx.regs().unwrap().ip;

            let comm = ctx.command()?;
            (*event).comm.copy_from_slice(&comm);
        }

        entry.submit(0);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

### Exercice 2.3: XDP Packet Filter

```rust
// XDP firewall - block specific IPs
#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

// Blocklist: IP -> 1 (blocked)
#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let src_ip = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    // Check blocklist
    if unsafe { BLOCKLIST.get(&src_ip).is_some() } {
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
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

**User-space to manage blocklist:**

```rust
use std::net::Ipv4Addr;

fn manage_blocklist(bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    let mut blocklist: HashMap<_, u32, u32> =
        HashMap::try_from(bpf.map_mut("BLOCKLIST").unwrap())?;

    // Block an IP
    let ip = Ipv4Addr::new(192, 168, 1, 100);
    blocklist.insert(u32::from(ip), 1, 0)?;

    // Unblock
    blocklist.remove(&u32::from(ip))?;

    Ok(())
}
```

---

## Partie 3: Projet Pratique

### Exercice 3.1: Network Monitor

Implementez un moniteur reseau eBPF complet:

```rust
// TODO: Implement network monitor that:
// 1. Counts packets per source IP
// 2. Tracks bandwidth usage per connection
// 3. Detects port scans (many ports from same IP)
// 4. Logs suspicious activity via PerfEventArray
// 5. Allows runtime blocklist management
```

**Components:**
- `monitor-ebpf/` - eBPF programs
- `monitor/` - User-space CLI with real-time dashboard
- Shared types between eBPF and user-space

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| eBPF fundamentals | 20 |
| XDP programs | 20 |
| Tracepoint/kprobe | 20 |
| Maps usage | 20 |
| User-space integration | 20 |
| **Total** | **100** |

---

## Ressources

- [Aya Book](https://aya-rs.dev/book/)
- [eBPF.io](https://ebpf.io/)
- [BPF Performance Tools](https://www.brendangregg.com/bpf-performance-tools-book.html)
- [Linux BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/)
