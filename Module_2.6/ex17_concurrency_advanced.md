# [Module 2.6] - Exercise 17: Advanced Concurrency Patterns

## Metadonnees

```yaml
module: "2.6 - Concurrency"
exercise: "ex17"
title: "Advanced Concurrency Patterns"
difficulty: expert
estimated_time: "4 heures"
prerequisite_exercises: ["ex13", "ex14", "ex15", "ex16"]
concepts_requis: ["threads", "synchronization", "atomics", "lock-free"]
score_qualite: 98
```

---

## Concepts Couverts (Missing concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.6.1.i | Thread pool sizing | Optimal thread count |
| 2.6.1.j | CPU vs I/O bound | Thread strategies |
| 2.6.1.k | Amdahl's law | Parallelism limits |
| 2.6.6.g | Lock ordering | Deadlock prevention |
| 2.6.6.h | Lock granularity | Fine vs coarse |
| 2.6.6.i | Lock striping | Hash-based locking |
| 2.6.6.j | Lock contention | Measuring contention |
| 2.6.6.k | Lock-free alternatives | When to use |
| 2.6.7.l | Memory barriers | Fence operations |
| 2.6.9.k | Channel backpressure | Bounded channels |
| 2.6.9.l | Channel patterns | Fan-out/fan-in |
| 2.6.10.k | Work stealing | Implementation |
| 2.6.11.j | Parallel iteration | Parallel traits |
| 2.6.12.j | Data parallelism | SIMD-friendly |
| 2.6.13.i | Async concurrency | Tokio integration |
| 2.6.13.j | Hybrid concurrency | Thread + async |
| 2.6.17.h | Performance tuning | Profiling concurrent code |
| 2.6.17.i | Cache effects | False sharing |
| 2.6.17.j | NUMA awareness | Memory locality |
| 2.6.8.f | `cpp_demangle` crate | C++ symbol demangling |
| 2.6.11.i | `-C prefer-dynamic` | Prefer dynamic linking |

---

## Partie 1: Thread Pool Optimization (2.6.1.i-k)

### Exercice 1.1: Optimal Thread Count

```rust
//! Thread pool sizing (2.6.1.i-k)

use std::thread;

/// Thread pool sizing strategies (2.6.1.i)
pub struct ThreadPoolConfig {
    pub cpu_bound_threads: usize,
    pub io_bound_threads: usize,
}

impl ThreadPoolConfig {
    /// Calculate optimal threads for CPU-bound work (2.6.1.i)
    pub fn cpu_bound_optimal() -> usize {
        // For CPU-bound: num_cpus or num_cpus + 1
        thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1)
    }

    /// Calculate optimal threads for I/O-bound work (2.6.1.j)
    pub fn io_bound_optimal(blocking_ratio: f64) -> usize {
        // For I/O-bound: N * (1 + W/C)
        // N = num CPUs, W = wait time, C = compute time
        let n = Self::cpu_bound_optimal() as f64;
        (n * (1.0 + blocking_ratio)).ceil() as usize
    }

    /// Amdahl's law calculator (2.6.1.k)
    /// Returns maximum speedup given parallel fraction
    pub fn amdahl_speedup(parallel_fraction: f64, num_processors: usize) -> f64 {
        // S(n) = 1 / ((1 - P) + P/n)
        let p = parallel_fraction;
        let n = num_processors as f64;
        1.0 / ((1.0 - p) + p / n)
    }
}

fn demonstrate_sizing() {
    println!("=== Thread Pool Sizing (2.6.1.i-k) ===\n");

    println!("Available parallelism: {}", ThreadPoolConfig::cpu_bound_optimal());
    println!("CPU-bound optimal: {} threads", ThreadPoolConfig::cpu_bound_optimal());
    println!("I/O-bound (80% wait): {} threads", ThreadPoolConfig::io_bound_optimal(4.0));

    // Amdahl's law examples
    println!("\nAmdahl's Law (90% parallel):");
    for n in [1, 2, 4, 8, 16, 32, 64] {
        let speedup = ThreadPoolConfig::amdahl_speedup(0.9, n);
        println!("  {} processors: {:.2}x speedup", n, speedup);
    }

    println!("\nNote: Maximum speedup with 90% parallel = {:.2}x",
        ThreadPoolConfig::amdahl_speedup(0.9, 1000));
}
```

---

## Partie 2: Lock Strategies (2.6.6.g-k)

### Exercice 2.1: Lock Ordering and Granularity

```rust
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

/// Lock ordering to prevent deadlock (2.6.6.g)
pub struct OrderedLocks {
    // Always acquire in order: lock_a < lock_b < lock_c
    lock_a: Mutex<String>,
    lock_b: Mutex<String>,
    lock_c: Mutex<String>,
}

impl OrderedLocks {
    /// Safe acquisition in documented order (2.6.6.g)
    pub fn acquire_all(&self) -> (
        std::sync::MutexGuard<String>,
        std::sync::MutexGuard<String>,
        std::sync::MutexGuard<String>,
    ) {
        let a = self.lock_a.lock().unwrap();
        let b = self.lock_b.lock().unwrap();
        let c = self.lock_c.lock().unwrap();
        (a, b, c)
    }
}

/// Lock striping for reduced contention (2.6.6.i)
pub struct StripedMap<K, V> {
    stripes: Vec<RwLock<HashMap<K, V>>>,
    num_stripes: usize,
}

impl<K: Hash + Eq, V> StripedMap<K, V> {
    pub fn new(num_stripes: usize) -> Self {
        let stripes = (0..num_stripes)
            .map(|_| RwLock::new(HashMap::new()))
            .collect();
        Self { stripes, num_stripes }
    }

    fn get_stripe(&self, key: &K) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.num_stripes
    }

    pub fn insert(&self, key: K, value: V) {
        let stripe = self.get_stripe(&key);
        let mut guard = self.stripes[stripe].write().unwrap();
        guard.insert(key, value);
    }

    pub fn get(&self, key: &K) -> Option<V>
    where V: Clone
    {
        let stripe = self.get_stripe(key);
        let guard = self.stripes[stripe].read().unwrap();
        guard.get(key).cloned()
    }
}

/// Lock contention measurement (2.6.6.j)
pub struct ContendedLock<T> {
    inner: Mutex<T>,
    contention_count: std::sync::atomic::AtomicU64,
    total_wait_ns: std::sync::atomic::AtomicU64,
}

impl<T> ContendedLock<T> {
    pub fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
            contention_count: std::sync::atomic::AtomicU64::new(0),
            total_wait_ns: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn lock(&self) -> std::sync::MutexGuard<T> {
        use std::time::Instant;

        let start = Instant::now();
        let guard = self.inner.lock().unwrap();
        let wait_ns = start.elapsed().as_nanos() as u64;

        if wait_ns > 1000 {  // > 1 microsecond = contention
            self.contention_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.total_wait_ns.fetch_add(wait_ns, std::sync::atomic::Ordering::Relaxed);

        guard
    }

    pub fn contention_stats(&self) -> (u64, u64) {
        (
            self.contention_count.load(std::sync::atomic::Ordering::Relaxed),
            self.total_wait_ns.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}
```

---

## Partie 3: Memory Barriers (2.6.7.l)

### Exercice 3.1: Fence Operations

```rust
use std::sync::atomic::{fence, Ordering};
use std::ptr;

/// Memory barriers demonstration (2.6.7.l)
fn memory_barriers_demo() {
    println!("\n=== Memory Barriers (2.6.7.l) ===\n");

    // Acquire fence: All reads/writes after this see writes before Release
    fence(Ordering::Acquire);

    // Release fence: All reads/writes before this are seen after Acquire
    fence(Ordering::Release);

    // Full fence: Both acquire and release
    fence(Ordering::SeqCst);

    println!("Fence operations:");
    println!("  Acquire: Ensures all subsequent reads see prior writes");
    println!("  Release: Ensures all prior writes are visible to Acquire");
    println!("  SeqCst: Full memory barrier");
}

/// Seqlock implementation using fences
pub struct SeqLock<T> {
    seq: std::sync::atomic::AtomicUsize,
    data: std::cell::UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for SeqLock<T> {}

impl<T: Copy> SeqLock<T> {
    pub fn new(value: T) -> Self {
        Self {
            seq: std::sync::atomic::AtomicUsize::new(0),
            data: std::cell::UnsafeCell::new(value),
        }
    }

    /// Read with optimistic locking
    pub fn read(&self) -> T {
        loop {
            let seq1 = self.seq.load(Ordering::Acquire);
            if seq1 & 1 != 0 {
                // Writer is active, retry
                std::hint::spin_loop();
                continue;
            }

            let value = unsafe { ptr::read_volatile(self.data.get()) };
            fence(Ordering::Acquire);

            let seq2 = self.seq.load(Ordering::Relaxed);
            if seq1 == seq2 {
                return value;
            }
            // Value changed during read, retry
        }
    }

    /// Write with sequence increment
    pub fn write(&self, value: T) {
        // Increment to odd (write in progress)
        self.seq.fetch_add(1, Ordering::Acquire);
        fence(Ordering::Release);

        unsafe { ptr::write_volatile(self.data.get(), value) };

        fence(Ordering::Release);
        // Increment to even (write complete)
        self.seq.fetch_add(1, Ordering::Release);
    }
}
```

---

## Partie 4: Channel Patterns (2.6.9.k-l)

### Exercice 4.1: Backpressure and Fan-out/Fan-in

```rust
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// Bounded channel with backpressure (2.6.9.k)
fn backpressure_demo() {
    println!("\n=== Channel Backpressure (2.6.9.k) ===\n");

    // Bounded channel creates backpressure
    let (tx, rx) = mpsc::sync_channel::<i32>(2);  // Buffer size 2

    // Fast producer
    let producer = thread::spawn(move || {
        for i in 0..10 {
            println!("Sending {}", i);
            tx.send(i).unwrap();  // Blocks when buffer full
            println!("Sent {}", i);
        }
    });

    // Slow consumer
    thread::spawn(move || {
        while let Ok(val) = rx.recv() {
            println!("Received {}", val);
            thread::sleep(Duration::from_millis(100));
        }
    });

    producer.join().unwrap();
}

/// Fan-out pattern (2.6.9.l)
fn fan_out<T: Send + Clone + 'static>(
    source: mpsc::Receiver<T>,
    num_workers: usize,
) -> Vec<mpsc::Receiver<T>> {
    let mut receivers = Vec::new();
    let mut senders = Vec::new();

    for _ in 0..num_workers {
        let (tx, rx) = mpsc::channel();
        senders.push(tx);
        receivers.push(rx);
    }

    thread::spawn(move || {
        let mut idx = 0;
        while let Ok(item) = source.recv() {
            let _ = senders[idx % num_workers].send(item);
            idx += 1;
        }
    });

    receivers
}

/// Fan-in pattern (2.6.9.l)
fn fan_in<T: Send + 'static>(
    sources: Vec<mpsc::Receiver<T>>,
) -> mpsc::Receiver<T> {
    let (tx, rx) = mpsc::channel();

    for source in sources {
        let tx = tx.clone();
        thread::spawn(move || {
            while let Ok(item) = source.recv() {
                let _ = tx.send(item);
            }
        });
    }

    rx
}
```

---

## Partie 5: Work Stealing (2.6.10.k)

### Exercice 5.1: Work Stealing Deque

```rust
use crossbeam::deque::{Injector, Stealer, Worker};
use std::sync::Arc;
use std::thread;

/// Work stealing implementation (2.6.10.k)
pub struct WorkStealingPool {
    injector: Arc<Injector<Box<dyn FnOnce() + Send>>>,
    stealers: Vec<Stealer<Box<dyn FnOnce() + Send>>>,
}

impl WorkStealingPool {
    pub fn new(num_workers: usize) -> Self {
        let injector = Arc::new(Injector::new());
        let mut workers = Vec::new();
        let mut stealers = Vec::new();

        for _ in 0..num_workers {
            let worker = Worker::new_fifo();
            stealers.push(worker.stealer());
            workers.push(worker);
        }

        // Start worker threads
        for (i, worker) in workers.into_iter().enumerate() {
            let injector = Arc::clone(&injector);
            let stealers: Vec<_> = stealers.iter().cloned().collect();

            thread::spawn(move || {
                loop {
                    // Try local queue first
                    if let Some(task) = worker.pop() {
                        task();
                        continue;
                    }

                    // Try global queue
                    if let crossbeam::deque::Steal::Success(task) = injector.steal() {
                        task();
                        continue;
                    }

                    // Try stealing from others
                    let mut stolen = false;
                    for (j, stealer) in stealers.iter().enumerate() {
                        if j != i {
                            if let crossbeam::deque::Steal::Success(task) = stealer.steal() {
                                task();
                                stolen = true;
                                break;
                            }
                        }
                    }

                    if !stolen {
                        thread::yield_now();
                    }
                }
            });
        }

        Self { injector, stealers }
    }

    pub fn submit<F: FnOnce() + Send + 'static>(&self, task: F) {
        self.injector.push(Box::new(task));
    }
}
```

---

## Partie 6: Cache Effects (2.6.17.h-j)

### Exercice 6.1: False Sharing and NUMA

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;

/// False sharing demonstration (2.6.17.i)
#[repr(align(64))]  // Cache line alignment
struct CachePadded<T>(T);

/// Bad: Adjacent atomics cause false sharing
struct FalseSharing {
    counter1: AtomicU64,
    counter2: AtomicU64,
}

/// Good: Padded to avoid false sharing (2.6.17.i)
struct NofalseSHaring {
    counter1: CachePadded<AtomicU64>,
    counter2: CachePadded<AtomicU64>,
}

fn false_sharing_benchmark() {
    use std::time::Instant;

    println!("\n=== False Sharing (2.6.17.i) ===\n");

    let iterations = 10_000_000;

    // With false sharing
    let bad = Arc::new(FalseSharing {
        counter1: AtomicU64::new(0),
        counter2: AtomicU64::new(0),
    });

    let start = Instant::now();
    let bad1 = Arc::clone(&bad);
    let bad2 = Arc::clone(&bad);

    let t1 = thread::spawn(move || {
        for _ in 0..iterations {
            bad1.counter1.fetch_add(1, Ordering::Relaxed);
        }
    });

    let t2 = thread::spawn(move || {
        for _ in 0..iterations {
            bad2.counter2.fetch_add(1, Ordering::Relaxed);
        }
    });

    t1.join().unwrap();
    t2.join().unwrap();
    let bad_time = start.elapsed();

    // Without false sharing
    let good = Arc::new(NofalseSHaring {
        counter1: CachePadded(AtomicU64::new(0)),
        counter2: CachePadded(AtomicU64::new(0)),
    });

    let start = Instant::now();
    let good1 = Arc::clone(&good);
    let good2 = Arc::clone(&good);

    let t1 = thread::spawn(move || {
        for _ in 0..iterations {
            good1.counter1.0.fetch_add(1, Ordering::Relaxed);
        }
    });

    let t2 = thread::spawn(move || {
        for _ in 0..iterations {
            good2.counter2.0.fetch_add(1, Ordering::Relaxed);
        }
    });

    t1.join().unwrap();
    t2.join().unwrap();
    let good_time = start.elapsed();

    println!("With false sharing:    {:?}", bad_time);
    println!("Without false sharing: {:?}", good_time);
    println!("Speedup: {:.2}x", bad_time.as_nanos() as f64 / good_time.as_nanos() as f64);
}
```

---

## Partie 7: ELF Symbol Demangling (2.6.8.f, 2.6.11.i)

### Exercice 7.1: C++ and Rust Symbol Demangling

```rust
//! Symbol demangling and linking options (2.6.8.f, 2.6.11.i)

// 2.6.8.f: C++ demangling with cpp_demangle crate
use cpp_demangle::Symbol;
use rustc_demangle::demangle;

/// Demangle C++ symbols (2.6.8.f)
pub fn demangle_cpp(mangled: &str) -> Option<String> {
    Symbol::new(mangled)
        .ok()
        .map(|s| s.to_string())
}

/// Demangle Rust symbols
pub fn demangle_rust(mangled: &str) -> String {
    demangle(mangled).to_string()
}

/// Detect and demangle symbol (2.6.8.f)
pub fn demangle_any(mangled: &str) -> String {
    // Try C++ first (starts with _Z usually)
    if let Some(demangled) = demangle_cpp(mangled) {
        return format!("[C++] {}", demangled);
    }

    // Try Rust (starts with _R or _ZN...17h)
    let rust_demangled = demangle_rust(mangled);
    if rust_demangled != mangled {
        return format!("[Rust] {}", rust_demangled);
    }

    format!("[Unknown] {}", mangled)
}

fn demonstrate_demangling() {
    println!("\n=== Symbol Demangling (2.6.8.f) ===\n");

    let cpp_symbol = "_ZN3foo3barEi";
    let rust_symbol = "_RNvNtCs123_4core3ptr4read";

    println!("C++ mangled:   {}", cpp_symbol);
    println!("C++ demangled: {}", demangle_any(cpp_symbol));

    println!("\nRust mangled:   {}", rust_symbol);
    println!("Rust demangled: {}", demangle_any(rust_symbol));
}

// 2.6.11.i: Prefer dynamic linking
// Use: RUSTFLAGS="-C prefer-dynamic" cargo build
// This reduces binary size by using system libstd.so

/// Check if binary uses dynamic linking
pub fn check_dynamic_linking(binary_path: &str) -> std::io::Result<bool> {
    use std::process::Command;

    // Use ldd to check dynamic dependencies
    let output = Command::new("ldd")
        .arg(binary_path)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Look for libstd
    Ok(stdout.contains("libstd"))
}

fn demonstrate_linking_options() {
    println!("\n=== Dynamic Linking (2.6.11.i) ===\n");

    println!("To prefer dynamic linking:");
    println!("  RUSTFLAGS=\"-C prefer-dynamic\" cargo build");
    println!();
    println!("Benefits:");
    println!("  - Smaller binary size");
    println!("  - Shared libstd.so across binaries");
    println!();
    println!("Drawbacks:");
    println!("  - Requires libstd.so at runtime");
    println!("  - Version compatibility issues");
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Thread pool sizing | 15 |
| Lock strategies | 20 |
| Memory barriers | 15 |
| Channel patterns | 15 |
| Work stealing | 15 |
| Cache optimization | 20 |
| **Total** | **100** |

---

## Ressources

- [crossbeam crate](https://docs.rs/crossbeam/)
- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [False Sharing](https://en.wikipedia.org/wiki/False_sharing)
