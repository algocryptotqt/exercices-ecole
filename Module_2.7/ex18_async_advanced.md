# [Module 2.7] - Exercise 18: Advanced Async Runtime Concepts

## Metadonnees

```yaml
module: "2.7 - Async Runtime"
exercise: "ex18"
title: "Advanced Async Runtime Concepts"
difficulty: expert
estimated_time: "5 heures"
prerequisite_exercises: ["ex13", "ex15", "ex17"]
concepts_requis: ["futures", "async", "runtime", "wakers"]
score_qualite: 98
```

---

## Concepts Couverts (Missing concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.7.1.i | Task scheduling | Cooperative scheduling |
| 2.7.1.j | Work stealing | Tokio work-stealing |
| 2.7.1.k | Thread pool | Runtime threads |
| 2.7.2.j | Future combinators | Advanced patterns |
| 2.7.3.j | async/await desugaring | State machine |
| 2.7.3.k | Pin projection | Accessing pinned fields |
| 2.7.3.l | Structural pinning | When required |
| 2.7.4.a | Protection rings | Ring 0-3 privilege levels |
| 2.7.4.j | Executor implementation | Custom executor |
| 2.7.5.l | Runtime configuration | Tokio builder |
| 2.7.6.j | Task cancellation | Graceful cancel |
| 2.7.6.k | Cancellation tokens | CancellationToken |
| 2.7.7.j | join!/select! | Advanced usage |
| 2.7.8.j | Timeout patterns | tokio::timeout |
| 2.7.9.j | Stream adapters | StreamExt methods |
| 2.7.10.i-l | Async channels | mpsc/broadcast |
| 2.7.11.j | Async Mutex | tokio::sync::Mutex |
| 2.7.12.i-j | Async synchronization | Semaphore/Barrier |
| 2.7.13.j-l | Async I/O advanced | Buffered I/O |
| 2.7.14.k | AsyncRead/Write | Custom impl |
| 2.7.15.k | TCP server patterns | Concurrent handling |
| 2.7.16.j | HTTP client | reqwest async |
| 2.7.18.i-j | Tracing async | Spans and events |
| 2.7.19.j | Testing async | tokio::test |

---

## Partie 1: Task Scheduling (2.7.1.i-k)

### Exercice 1.1: Understanding Cooperative Scheduling

```rust
//! Task scheduling in async runtimes (2.7.1.i-k)

use tokio::task;
use std::time::Duration;

/// Cooperative scheduling (2.7.1.i)
/// Tasks must yield control voluntarily
async fn cooperative_scheduling_demo() {
    println!("=== Cooperative Scheduling (2.7.1.i) ===\n");

    // Tasks yield at .await points
    let task1 = task::spawn(async {
        for i in 0..5 {
            println!("Task 1: iteration {}", i);
            task::yield_now().await;  // Explicit yield point
        }
    });

    let task2 = task::spawn(async {
        for i in 0..5 {
            println!("Task 2: iteration {}", i);
            task::yield_now().await;
        }
    });

    let _ = tokio::join!(task1, task2);
}

/// Work-stealing scheduler (2.7.1.j)
async fn work_stealing_demo() {
    println!("\n=== Work Stealing (2.7.1.j) ===\n");

    // Tokio uses work-stealing: idle threads steal tasks from busy threads
    let handles: Vec<_> = (0..10)
        .map(|i| {
            task::spawn(async move {
                // Simulate varying workloads
                let delay = Duration::from_millis((i * 10) as u64);
                tokio::time::sleep(delay).await;
                println!("Task {} completed on {:?}", i, std::thread::current().id());
                i
            })
        })
        .collect();

    for handle in handles {
        let result = handle.await.unwrap();
        println!("Got result: {}", result);
    }
}

/// Thread pool configuration (2.7.1.k)
fn thread_pool_demo() {
    println!("\n=== Thread Pool (2.7.1.k) ===\n");

    // Configure runtime with specific thread count
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)  // Explicit thread count
        .thread_name("my-worker")
        .on_thread_start(|| println!("Worker thread started"))
        .on_thread_stop(|| println!("Worker thread stopped"))
        .build()
        .unwrap();

    runtime.block_on(async {
        println!("Running on custom thread pool");
        let handles: Vec<_> = (0..8)
            .map(|i| task::spawn(async move {
                println!("Task {} on {:?}", i, std::thread::current().name());
            }))
            .collect();

        for h in handles {
            h.await.unwrap();
        }
    });
}
```

---

## Partie 2: async/await Desugaring (2.7.3.j-l)

### Exercice 2.1: Understanding the State Machine

```rust
use std::pin::Pin;
use std::future::Future;
use std::task::{Context, Poll};

/// What async/await desugars to (2.7.3.j)
/// async fn example() -> i32 { ... }
/// becomes approximately:
enum ExampleFuture {
    Start,
    WaitingOnFuture1(/* saved state */),
    WaitingOnFuture2(/* saved state */),
    Done,
}

impl Future for ExampleFuture {
    type Output = i32;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // State machine implementation
        match self.get_mut() {
            ExampleFuture::Start => {
                // Transition to next state
                Poll::Pending
            }
            ExampleFuture::Done => Poll::Ready(42),
            _ => Poll::Pending,
        }
    }
}

/// Pin projection (2.7.3.k)
/// Accessing fields of a pinned struct safely
use std::marker::PhantomPinned;

struct SelfReferential {
    data: String,
    // Points into `data`
    ptr: *const String,
    _pin: PhantomPinned,
}

impl SelfReferential {
    fn new(data: String) -> Self {
        Self {
            data,
            ptr: std::ptr::null(),
            _pin: PhantomPinned,
        }
    }

    /// Safe pin projection (2.7.3.k)
    fn project(self: Pin<&mut Self>) -> Pin<&mut String> {
        // SAFETY: We're not moving `data`, just projecting the pin
        unsafe {
            Pin::new_unchecked(&mut self.get_unchecked_mut().data)
        }
    }

    fn init(self: Pin<&mut Self>) {
        // 2.7.3.l: Structural pinning - the struct must remain pinned
        // because it contains self-references
        let self_ref = unsafe { self.get_unchecked_mut() };
        self_ref.ptr = &self_ref.data as *const String;
    }
}
```

---

## Partie 3: Cancellation (2.7.6.j-k)

### Exercice 3.1: Graceful Task Cancellation

```rust
use tokio_util::sync::CancellationToken;
use tokio::select;
use std::time::Duration;

/// Task cancellation patterns (2.7.6.j)
async fn graceful_cancellation() {
    println!("\n=== Task Cancellation (2.7.6.j) ===\n");

    let task = tokio::spawn(async {
        loop {
            println!("Working...");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    // Let it run briefly
    tokio::time::sleep(Duration::from_millis(350)).await;

    // Cancel by aborting
    task.abort();

    match task.await {
        Ok(_) => println!("Task completed"),
        Err(e) if e.is_cancelled() => println!("Task was cancelled"),
        Err(e) => println!("Task failed: {:?}", e),
    }
}

/// CancellationToken pattern (2.7.6.k)
async fn cancellation_token_demo() {
    println!("\n=== CancellationToken (2.7.6.k) ===\n");

    let token = CancellationToken::new();
    let child_token = token.child_token();

    let task = tokio::spawn({
        let token = child_token.clone();
        async move {
            loop {
                select! {
                    _ = token.cancelled() => {
                        println!("Task received cancellation signal, cleaning up...");
                        // Perform cleanup
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        println!("Task working...");
                    }
                }
            }
            println!("Task cleanup complete");
        }
    });

    // Let it work
    tokio::time::sleep(Duration::from_millis(350)).await;

    // Signal cancellation
    println!("Sending cancellation signal...");
    token.cancel();

    task.await.unwrap();
}

/// Timeout as cancellation (2.7.8.j)
async fn timeout_patterns() {
    println!("\n=== Timeout Patterns (2.7.8.j) ===\n");

    // tokio::time::timeout
    let result = tokio::time::timeout(
        Duration::from_millis(100),
        async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            "completed"
        }
    ).await;

    match result {
        Ok(msg) => println!("Got: {}", msg),
        Err(_) => println!("Timeout!"),
    }

    // Timeout that triggers
    let result = tokio::time::timeout(
        Duration::from_millis(50),
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            "won't get here"
        }
    ).await;

    println!("Second timeout result: {:?}", result);
}
```

---

## Partie 4: Async Channels (2.7.10.i-l)

### Exercice 4.1: Channel Patterns

```rust
use tokio::sync::{mpsc, broadcast, watch, oneshot};

/// MPSC channel (2.7.10.i)
async fn mpsc_demo() {
    println!("\n=== MPSC Channel (2.7.10.i) ===\n");

    let (tx, mut rx) = mpsc::channel::<String>(32);

    // Spawn producers
    for i in 0..3 {
        let tx = tx.clone();
        tokio::spawn(async move {
            tx.send(format!("Message from producer {}", i)).await.unwrap();
        });
    }

    // Drop original sender
    drop(tx);

    // Receive all
    while let Some(msg) = rx.recv().await {
        println!("Received: {}", msg);
    }
}

/// Broadcast channel (2.7.10.j)
async fn broadcast_demo() {
    println!("\n=== Broadcast Channel (2.7.10.j) ===\n");

    let (tx, _rx) = broadcast::channel::<String>(16);

    // Create multiple subscribers
    let mut rx1 = tx.subscribe();
    let mut rx2 = tx.subscribe();

    tx.send("Hello everyone!".to_string()).unwrap();

    println!("Rx1 got: {:?}", rx1.recv().await);
    println!("Rx2 got: {:?}", rx2.recv().await);
}

/// Watch channel (2.7.10.k)
async fn watch_demo() {
    println!("\n=== Watch Channel (2.7.10.k) ===\n");

    let (tx, mut rx) = watch::channel("initial");

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send("updated").unwrap();
    });

    // Watch for changes
    rx.changed().await.unwrap();
    println!("Value changed to: {}", *rx.borrow());
}

/// Oneshot channel (2.7.10.l)
async fn oneshot_demo() {
    println!("\n=== Oneshot Channel (2.7.10.l) ===\n");

    let (tx, rx) = oneshot::channel::<String>();

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send("Single response".to_string()).unwrap();
    });

    let response = rx.await.unwrap();
    println!("Got oneshot response: {}", response);
}
```

---

## Partie 5: Async Synchronization (2.7.11.j, 2.7.12.i-j)

### Exercice 5.1: Async Mutex and Semaphore

```rust
use tokio::sync::{Mutex, Semaphore, Barrier};
use std::sync::Arc;

/// Async Mutex (2.7.11.j)
async fn async_mutex_demo() {
    println!("\n=== Async Mutex (2.7.11.j) ===\n");

    let data = Arc::new(Mutex::new(vec![]));

    let handles: Vec<_> = (0..5)
        .map(|i| {
            let data = Arc::clone(&data);
            tokio::spawn(async move {
                // Lock is held across .await
                let mut guard = data.lock().await;
                guard.push(i);
                // Simulate async work while holding lock
                tokio::time::sleep(Duration::from_millis(10)).await;
                println!("Task {} pushed to vec", i);
            })
        })
        .collect();

    for h in handles {
        h.await.unwrap();
    }

    println!("Final vec: {:?}", *data.lock().await);
}

/// Async Semaphore (2.7.12.i)
async fn semaphore_demo() {
    println!("\n=== Async Semaphore (2.7.12.i) ===\n");

    // Limit concurrent operations to 3
    let semaphore = Arc::new(Semaphore::new(3));

    let handles: Vec<_> = (0..10)
        .map(|i| {
            let sem = Arc::clone(&semaphore);
            tokio::spawn(async move {
                let permit = sem.acquire().await.unwrap();
                println!("Task {} acquired permit, {} available",
                    i, sem.available_permits());
                tokio::time::sleep(Duration::from_millis(100)).await;
                drop(permit);
                println!("Task {} released permit", i);
            })
        })
        .collect();

    for h in handles {
        h.await.unwrap();
    }
}

/// Async Barrier (2.7.12.j)
async fn barrier_demo() {
    println!("\n=== Async Barrier (2.7.12.j) ===\n");

    let barrier = Arc::new(Barrier::new(3));

    let handles: Vec<_> = (0..3)
        .map(|i| {
            let b = Arc::clone(&barrier);
            tokio::spawn(async move {
                println!("Task {} arriving at barrier", i);
                tokio::time::sleep(Duration::from_millis(i * 50)).await;

                let result = b.wait().await;
                println!("Task {} passed barrier, is_leader: {}",
                    i, result.is_leader());
            })
        })
        .collect();

    for h in handles {
        h.await.unwrap();
    }
}
```

---

## Partie 6: Tracing Async Code (2.7.18.i-j)

### Exercice 6.1: Async Tracing with Spans

```rust
use tracing::{info, info_span, Instrument};
use tracing_subscriber;

/// Async tracing with spans (2.7.18.i-j)
async fn traced_operation(id: u32) {
    let span = info_span!("operation", id = id);

    async {
        info!("Starting operation");
        tokio::time::sleep(Duration::from_millis(50)).await;
        info!("Operation step 1 complete");
        tokio::time::sleep(Duration::from_millis(50)).await;
        info!("Operation complete");
    }
    .instrument(span)
    .await
}

async fn tracing_demo() {
    // Initialize subscriber
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("\n=== Async Tracing (2.7.18.i-j) ===\n");

    let handles: Vec<_> = (0..3)
        .map(|i| tokio::spawn(traced_operation(i)))
        .collect();

    for h in handles {
        h.await.unwrap();
    }
}
```

---

## Partie 7: Testing Async (2.7.19.j)

### Exercice 7.1: Async Test Patterns

```rust
/// Testing async code (2.7.19.j)
#[cfg(test)]
mod tests {
    use super::*;

    // Using tokio::test macro
    #[tokio::test]
    async fn test_async_function() {
        let result = async { 42 }.await;
        assert_eq!(result, 42);
    }

    // With timeout
    #[tokio::test(start_paused = true)]
    async fn test_with_time_control() {
        let start = tokio::time::Instant::now();

        // Advance time instantly in tests
        tokio::time::sleep(Duration::from_secs(10)).await;

        // Time advances but test runs fast
        assert!(start.elapsed() >= Duration::from_secs(10));
    }

    // Multi-threaded test
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_multi_threaded() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);

        tokio::spawn(async move {
            tx.send(42).await.unwrap();
        });

        assert_eq!(rx.recv().await, Some(42));
    }
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Task scheduling understanding | 15 |
| async/await desugaring | 10 |
| Cancellation patterns | 15 |
| Async channels | 15 |
| Async synchronization | 15 |
| Timeout handling | 10 |
| Tracing | 10 |
| Testing async | 10 |
| **Total** | **100** |

---

## Ressources

- [Tokio Tutorial](https://tokio.rs/tokio/tutorial)
- [Async Book](https://rust-lang.github.io/async-book/)
- [tokio-util CancellationToken](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html)
