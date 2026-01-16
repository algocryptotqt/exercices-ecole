# [Module 2.7] - Exercise 17: Async in Kernel & Real-World OS Projects

## Metadonnees

```yaml
module: "2.7 - Kernel Development"
exercise: "ex17"
title: "Async in Kernel & Real-World Rust OS Projects"
difficulty: expert
estimated_time: "5 heures"
prerequisite_exercises: ["ex15", "ex16"]
concepts_requis: ["async/await", "executors", "OS design"]
score_qualite: 98
```

---

## Concepts Couverts

### 2.7.29: Async in Kernel (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.7.29.a | Async without std | Async works in no_std |
| 2.7.29.b | `Future` trait | Available in `core` |
| 2.7.29.c | `async`/`.await` | Works in no_std |
| 2.7.29.d | Executor | Custom implementation |
| 2.7.29.e | Waker | Wake mechanism |
| 2.7.29.f | Task queue | Storing futures |
| 2.7.29.g | Cooperative | Yield points |
| 2.7.29.h | Keyboard async | Async keyboard example |
| 2.7.29.i | Timer async | Async timer example |
| 2.7.29.j | No heap | `pin!` macro usage |

### 2.7.30: Real-World Rust OS Projects (10 concepts)

| Ref Curriculum | Concept | Implementation |
|----------------|---------|----------------|
| 2.7.30.a | Redox OS | Full Rust microkernel OS |
| 2.7.30.b | Theseus | Research OS |
| 2.7.30.c | Tock | Embedded OS |
| 2.7.30.d | Hubris | Oxide Computer OS |
| 2.7.30.e | Asterinas | Linux-compatible |
| 2.7.30.f | Hermit | Unikernel |
| 2.7.30.g | `r9` | Plan 9 in Rust |
| 2.7.30.h | Educational | moros, blog_os |
| 2.7.30.i | Hypervisors | RustyHermit |
| 2.7.30.j | Contributions | How to contribute |

---

## Partie 1: Async in Kernel (2.7.29)

### Exercice 1.1: Understanding Async in no_std

```rust
// Async works in no_std because Future is in core!
#![no_std]

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

// A simple future that yields once then completes
struct YieldOnce {
    yielded: bool,
}

impl YieldOnce {
    fn new() -> Self {
        YieldOnce { yielded: false }
    }
}

impl Future for YieldOnce {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            Poll::Ready(())
        } else {
            self.yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

// Async function works in no_std!
async fn example_async_fn() -> u32 {
    YieldOnce::new().await;
    42
}
```

**Questions:**
1. Pourquoi `Future` peut fonctionner sans std ?
2. Quelle est la difference entre `poll` et `await` ?
3. Pourquoi le Waker est-il necessaire ?

### Exercice 1.2: Simple Executor

**src/task/simple_executor.rs:**

```rust
use super::Task;
use alloc::collections::VecDeque;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

pub struct SimpleExecutor {
    task_queue: VecDeque<Task>,
}

impl SimpleExecutor {
    pub fn new() -> SimpleExecutor {
        SimpleExecutor {
            task_queue: VecDeque::new(),
        }
    }

    pub fn spawn(&mut self, task: Task) {
        self.task_queue.push_back(task)
    }

    pub fn run(&mut self) {
        while let Some(mut task) = self.task_queue.pop_front() {
            let waker = dummy_waker();
            let mut context = Context::from_waker(&waker);

            match task.poll(&mut context) {
                Poll::Ready(()) => {} // Task done
                Poll::Pending => self.task_queue.push_back(task),
            }
        }
    }
}

// Dummy waker that does nothing
fn dummy_waker() -> Waker {
    unsafe { Waker::from_raw(dummy_raw_waker()) }
}

fn dummy_raw_waker() -> RawWaker {
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        dummy_raw_waker()
    }

    let vtable = &RawWakerVTable::new(clone, no_op, no_op, no_op);
    RawWaker::new(core::ptr::null(), vtable)
}
```

**src/task/mod.rs:**

```rust
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

pub mod simple_executor;
pub mod executor;
pub mod keyboard;

pub struct Task {
    future: Pin<Box<dyn Future<Output = ()>>>,
}

impl Task {
    pub fn new(future: impl Future<Output = ()> + 'static) -> Task {
        Task {
            future: Box::pin(future),
        }
    }

    fn poll(&mut self, context: &mut Context) -> Poll<()> {
        self.future.as_mut().poll(context)
    }
}
```

### Exercice 1.3: Efficient Executor with Waker

**src/task/executor.rs:**

```rust
use super::Task;
use alloc::{collections::BTreeMap, sync::Arc, task::Wake};
use core::task::{Context, Poll, Waker};
use crossbeam_queue::ArrayQueue;

pub struct Executor {
    tasks: BTreeMap<TaskId, Task>,
    task_queue: Arc<ArrayQueue<TaskId>>,
    waker_cache: BTreeMap<TaskId, Waker>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TaskId(u64);

impl TaskId {
    fn new() -> Self {
        use core::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        TaskId(NEXT_ID.fetch_add(1, Ordering::Relaxed))
    }
}

struct TaskWaker {
    task_id: TaskId,
    task_queue: Arc<ArrayQueue<TaskId>>,
}

impl TaskWaker {
    fn new(task_id: TaskId, task_queue: Arc<ArrayQueue<TaskId>>) -> Waker {
        Waker::from(Arc::new(TaskWaker {
            task_id,
            task_queue,
        }))
    }

    fn wake_task(&self) {
        self.task_queue.push(self.task_id).expect("task_queue full");
    }
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_task();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wake_task();
    }
}

impl Executor {
    pub fn new() -> Self {
        Executor {
            tasks: BTreeMap::new(),
            task_queue: Arc::new(ArrayQueue::new(100)),
            waker_cache: BTreeMap::new(),
        }
    }

    pub fn spawn(&mut self, task: Task) {
        let task_id = TaskId::new();
        if self.tasks.insert(task_id, task).is_some() {
            panic!("task with same ID already in tasks");
        }
        self.task_queue.push(task_id).expect("queue full");
    }

    pub fn run(&mut self) -> ! {
        loop {
            self.run_ready_tasks();
            self.sleep_if_idle();
        }
    }

    fn run_ready_tasks(&mut self) {
        while let Some(task_id) = self.task_queue.pop() {
            let task = match self.tasks.get_mut(&task_id) {
                Some(task) => task,
                None => continue, // Task no longer exists
            };

            let waker = self.waker_cache
                .entry(task_id)
                .or_insert_with(|| TaskWaker::new(task_id, self.task_queue.clone()));

            let mut context = Context::from_waker(waker);
            match task.poll(&mut context) {
                Poll::Ready(()) => {
                    // Task done, remove it and its cached waker
                    self.tasks.remove(&task_id);
                    self.waker_cache.remove(&task_id);
                }
                Poll::Pending => {}
            }
        }
    }

    fn sleep_if_idle(&self) {
        use x86_64::instructions::interrupts;

        interrupts::disable();
        if self.task_queue.is_empty() {
            interrupts::enable_and_hlt();
        } else {
            interrupts::enable();
        }
    }
}
```

### Exercice 1.4: Async Keyboard Driver

**src/task/keyboard.rs:**

```rust
use conquer_once::spin::OnceCell;
use crossbeam_queue::ArrayQueue;
use core::{pin::Pin, task::{Context, Poll}};
use futures_util::stream::{Stream, StreamExt};
use futures_util::task::AtomicWaker;
use pc_keyboard::{layouts, DecodedKey, HandleControl, Keyboard, ScancodeSet1};

static SCANCODE_QUEUE: OnceCell<ArrayQueue<u8>> = OnceCell::uninit();
static WAKER: AtomicWaker = AtomicWaker::new();

/// Called by keyboard interrupt handler
pub(crate) fn add_scancode(scancode: u8) {
    if let Ok(queue) = SCANCODE_QUEUE.try_get() {
        if queue.push(scancode).is_err() {
            crate::serial_println!("WARNING: scancode queue full; dropping keyboard input");
        } else {
            WAKER.wake();
        }
    } else {
        crate::serial_println!("WARNING: scancode queue uninitialized");
    }
}

pub struct ScancodeStream {
    _private: (),
}

impl ScancodeStream {
    pub fn new() -> Self {
        SCANCODE_QUEUE
            .try_init_once(|| ArrayQueue::new(100))
            .expect("ScancodeStream::new should only be called once");
        ScancodeStream { _private: () }
    }
}

impl Stream for ScancodeStream {
    type Item = u8;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<u8>> {
        let queue = SCANCODE_QUEUE
            .try_get()
            .expect("scancode queue not initialized");

        // Fast path: try to pop without registering waker
        if let Some(scancode) = queue.pop() {
            return Poll::Ready(Some(scancode));
        }

        WAKER.register(cx.waker());
        match queue.pop() {
            Some(scancode) => {
                WAKER.take();
                Poll::Ready(Some(scancode))
            }
            None => Poll::Pending,
        }
    }
}

pub async fn print_keypresses() {
    let mut scancodes = ScancodeStream::new();
    let mut keyboard = Keyboard::new(
        ScancodeSet1::new(),
        layouts::Us104Key,
        HandleControl::Ignore,
    );

    while let Some(scancode) = scancodes.next().await {
        if let Ok(Some(key_event)) = keyboard.add_byte(scancode) {
            if let Some(key) = keyboard.process_keyevent(key_event) {
                match key {
                    DecodedKey::Unicode(character) => crate::print!("{}", character),
                    DecodedKey::RawKey(key) => crate::print!("{:?}", key),
                }
            }
        }
    }
}
```

### Exercice 1.5: Async Without Heap (using pin!)

```rust
use core::pin::pin;
use core::future::Future;
use core::task::{Context, Poll};

// Future without heap allocation
async fn compute_value() -> u32 {
    // Some async computation
    42
}

pub fn run_without_heap() {
    // pin! macro creates a pinned future on stack
    let mut future = pin!(compute_value());

    // Manual polling
    let waker = dummy_waker();
    let mut cx = Context::from_waker(&waker);

    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => {
                crate::println!("Result: {}", value);
                break;
            }
            Poll::Pending => {
                // In real code, would wait for wake
                continue;
            }
        }
    }
}
```

---

## Partie 2: Real-World Rust OS Projects (2.7.30)

### Exercice 2.1: Overview of Major Rust OS Projects

| Project | Type | Description | Link |
|---------|------|-------------|------|
| **Redox OS** | General-purpose microkernel | Unix-like, everything in Rust | [redox-os.org](https://www.redox-os.org/) |
| **Theseus** | Research OS | Safe resource management | [github.com/theseus-os](https://github.com/theseus-os/Theseus) |
| **Tock** | Embedded OS | IoT and microcontrollers | [tockos.org](https://www.tockos.org/) |
| **Hubris** | Embedded OS | Oxide Computer's OS | [github.com/oxidecomputer/hubris](https://github.com/oxidecomputer/hubris) |
| **Asterinas** | Linux-compatible | Aims for Linux ABI compatibility | [asterinas.github.io](https://asterinas.github.io/) |
| **Hermit** | Unikernel | Single-application OS | [github.com/hermit-os](https://github.com/hermit-os/kernel) |
| **r9** | Research | Plan 9 reimagined in Rust | [github.com/r9os/r9](https://github.com/r9os/r9) |

### Exercice 2.2: Redox OS Architecture Study

```
Redox OS Architecture:
┌─────────────────────────────────────────┐
│              Applications               │
├─────────────────────────────────────────┤
│           Orbital (GUI)                 │
│           Ion (Shell)                   │
│           NetStack                      │
├─────────────────────────────────────────┤
│     Scheme-based VFS (everything is     │
│         a URL: disk:, tcp:, etc.)       │
├─────────────────────────────────────────┤
│           relibc (C library)            │
├─────────────────────────────────────────┤
│         Microkernel (minimal)           │
│  - Memory management                    │
│  - Process scheduling                   │
│  - IPC (message passing)                │
│  - Interrupt handling                   │
└─────────────────────────────────────────┘

Key Features:
- Microkernel design (< 30k lines)
- Everything is a scheme URL
- Memory-safe drivers (run in userspace)
- Orbital GUI in pure Rust
- Self-hosting (can compile itself)
```

**Questions:**
1. Quels avantages offre un microkernel par rapport a un monolithique ?
2. Comment Redox utilise les URLs pour l'abstraction du systeme ?
3. Pourquoi les drivers en userspace sont-ils plus surs ?

### Exercice 2.3: Tock Embedded OS Study

```rust
// Tock kernel component structure
// Capsules are the main abstraction

// Example: LED driver capsule
pub struct Led<'a, L: led::Led> {
    leds: &'a [&'a L],
    // ...
}

impl<'a, L: led::Led> Led<'a, L> {
    pub fn new(leds: &'a [&'a L]) -> Led<'a, L> {
        Led { leds }
    }
}

impl<'a, L: led::Led> SyscallDriver for Led<'a, L> {
    fn command(
        &self,
        command_num: usize,
        data: usize,
        _: usize,
        _: ProcessId,
    ) -> CommandReturn {
        match command_num {
            0 => CommandReturn::success(),
            1 => {  // Turn on LED
                if data < self.leds.len() {
                    self.leds[data].on();
                    CommandReturn::success()
                } else {
                    CommandReturn::failure(ErrorCode::INVAL)
                }
            }
            2 => {  // Turn off LED
                if data < self.leds.len() {
                    self.leds[data].off();
                    CommandReturn::success()
                } else {
                    CommandReturn::failure(ErrorCode::INVAL)
                }
            }
            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }
}
```

**Tock Key Concepts:**
- **Capsules**: Rust modules that provide OS services
- **Grants**: Per-process dynamic memory allocation
- **Process loading**: Tock Binary Format (TBF)
- **Hardware abstraction**: HIL traits
- **Safety**: MPU-enforced isolation

### Exercice 2.4: Contributing to Rust OS Projects

**How to contribute:**

1. **Start with blog_os:**
   ```bash
   # Fork and clone
   git clone https://github.com/YOUR_USERNAME/blog_os
   cd blog_os

   # Find issues labeled "good first issue"
   # Make changes, test, submit PR
   ```

2. **Join Redox OS:**
   ```bash
   # Read contribution guide
   # Join Matrix chat: #redox:matrix.org
   # Look for "help wanted" issues
   # Start with relibc (C library) - easier entry point
   ```

3. **Contribute to Tock:**
   ```bash
   # Read CONTRIBUTING.md
   # Join Slack workspace
   # Work on capsule implementations
   # Hardware board support
   ```

**Areas to contribute:**
- Documentation improvements
- Bug fixes
- New drivers/capsules
- Test coverage
- Architecture support
- Performance optimization

### Exercice 2.5: Build Your Own Contribution

**Project: Add a feature to blog_os**

```rust
// Example: Add a simple shell to blog_os

use alloc::string::String;
use alloc::vec::Vec;

pub struct Shell {
    history: Vec<String>,
    prompt: &'static str,
}

impl Shell {
    pub fn new() -> Self {
        Shell {
            history: Vec::new(),
            prompt: "odyssey> ",
        }
    }

    pub async fn run(&mut self) {
        use crate::task::keyboard::ScancodeStream;
        use futures_util::stream::StreamExt;

        crate::print!("{}", self.prompt);

        let mut input = String::new();
        let mut scancodes = ScancodeStream::new();

        while let Some(scancode) = scancodes.next().await {
            if let Some(key) = decode_key(scancode) {
                match key {
                    '\n' => {
                        crate::println!();
                        self.execute(&input).await;
                        self.history.push(input.clone());
                        input.clear();
                        crate::print!("{}", self.prompt);
                    }
                    '\x08' => { // Backspace
                        if !input.is_empty() {
                            input.pop();
                            crate::print!("\x08 \x08");
                        }
                    }
                    c => {
                        input.push(c);
                        crate::print!("{}", c);
                    }
                }
            }
        }
    }

    async fn execute(&self, cmd: &str) {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        match parts.first() {
            Some(&"help") => self.cmd_help(),
            Some(&"clear") => self.cmd_clear(),
            Some(&"echo") => self.cmd_echo(&parts[1..]),
            Some(&"history") => self.cmd_history(),
            Some(&"mem") => self.cmd_mem(),
            Some(cmd) => crate::println!("Unknown command: {}", cmd),
            None => {}
        }
    }

    fn cmd_help(&self) {
        crate::println!("Available commands:");
        crate::println!("  help    - Show this help");
        crate::println!("  clear   - Clear screen");
        crate::println!("  echo    - Echo text");
        crate::println!("  history - Show command history");
        crate::println!("  mem     - Show memory info");
    }

    fn cmd_clear(&self) {
        // Clear VGA buffer
        for _ in 0..25 {
            crate::println!();
        }
    }

    fn cmd_echo(&self, args: &[&str]) {
        crate::println!("{}", args.join(" "));
    }

    fn cmd_history(&self) {
        for (i, cmd) in self.history.iter().enumerate() {
            crate::println!("{}: {}", i + 1, cmd);
        }
    }

    fn cmd_mem(&self) {
        // Would show heap usage, etc.
        crate::println!("Memory info not implemented");
    }
}
```

---

## Criteres d'Evaluation

| Critere | Points |
|---------|--------|
| Async concepts understanding | 20 |
| Executor implementation | 20 |
| Async keyboard driver | 20 |
| OS projects knowledge | 20 |
| Contribution readiness | 20 |
| **Total** | **100** |

---

## Ressources

- [Async/Await - Writing an OS in Rust](https://os.phil-opp.com/async-await/)
- [Redox OS](https://www.redox-os.org/)
- [Tock OS](https://www.tockos.org/)
- [Theseus OS Paper](https://www.usenix.org/conference/osdi20/presentation/boos)
- [Hubris OS](https://hubris.oxide.computer/)
- [Awesome Rust OS](https://github.com/phodal/awesome-rust-os)
