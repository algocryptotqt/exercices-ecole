# Exercice 2.4.15-synth : async_orchestrator

**Module :**
2.4.15 — Synchronisation Async Avancée

**Concept :**
synth — Synthèse Async (Mutex, Semaphore, Select, Channels, Cancellation)

**Difficulte :**
★★★★★★★☆☆☆ (7/10)

**Type :**
complet

**Tiers :**
3 — Synthese (tous concepts async)

**Langage :**
Rust (Edition 2024)

**Prerequis :**
- async/await basics
- tokio runtime
- ownership & borrowing
- Arc, Mutex

**Domaines :**
Process, Net, Struct

**Duree estimee :**
180 min

**XP Base :**
350

**Complexite :**
T3 O(n) x S2 O(n)

---

## 1. PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichier a rendre :** `async_orchestrator.rs`

**Fonctions autorisees :**
- `tokio::sync::*` (Mutex, RwLock, Semaphore, Notify, mpsc, oneshot, broadcast, watch)
- `tokio::select!`, `tokio::join!`, `tokio::try_join!`
- `tokio::time::*` (timeout, sleep, Duration)
- `tokio_util::sync::CancellationToken`
- `futures::stream::*` (FuturesUnordered, StreamExt)
- `std::sync::Arc`

**Fonctions interdites :**
- `std::sync::Mutex` (utiliser tokio::sync::Mutex)
- `std::thread::spawn` (utiliser tokio::spawn)
- `unsafe`

### 1.2 Consigne

**The Matrix Reloaded : L'Architecte des Processus Async**

Dans la Matrice, l'Architecte controle des milliers de processus simultanement. Chaque programme (Agent, Seraph, Oracle) doit etre orchestre avec precision. Neo doit apprendre a maitriser cette symphonie asynchrone pour sauver Zion.

Tu es Neo. Ta mission est de creer un **orchestrateur de taches async** capable de :
1. Limiter le nombre de taches concurrentes (comme les Agents limites a un nombre)
2. Permettre l'annulation gracieuse (quand l'Oracle dit "stop")
3. Diffuser des messages a tous les workers (broadcast de la prophetie)
4. Collecter les resultats au fur et a mesure (FuturesUnordered)

**Ta mission :**

Ecrire une structure `MatrixOrchestrator` qui gere des taches asynchrones avec :
- Un semaphore pour limiter la concurrence
- Un canal broadcast pour les notifications globales
- Un systeme de cancellation cooperative
- La collecte des resultats dans l'ordre de completion

**Entree :**
- `max_concurrent: usize` : nombre max de taches simultanees
- `tasks: Vec<AsyncTask>` : liste des taches a executer

**Sortie :**
- `Vec<TaskResult>` : resultats dans l'ordre de completion
- Erreur si timeout global depasse

**Contraintes :**
- Les taches doivent respecter la limite de concurrence
- L'annulation doit etre cooperative (verifier le token)
- Les resultats arrivent dans l'ordre de completion, pas de soumission
- Timeout global de 30 secondes

**Exemples :**

| Appel | Retour | Explication |
|-------|--------|-------------|
| `orchestrator.run(tasks, Duration::from_secs(30)).await` | `Ok(vec![...])` | Toutes taches completees |
| `orchestrator.cancel().await` | `()` | Annulation gracieuse |
| `orchestrator.run(tasks, Duration::from_millis(10)).await` | `Err(Timeout)` | Timeout global |

### 1.3 Prototype

```rust
use tokio::sync::{Mutex, Semaphore, broadcast, mpsc, oneshot};
use tokio::time::{timeout, Duration};
use tokio_util::sync::CancellationToken;
use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct TaskResult {
    pub task_id: u32,
    pub result: String,
    pub duration_ms: u64,
}

#[derive(Debug)]
pub enum OrchestratorError {
    Timeout,
    Cancelled,
    TaskFailed(String),
}

pub struct MatrixOrchestrator {
    max_concurrent: usize,
    semaphore: Arc<Semaphore>,
    cancel_token: CancellationToken,
    broadcast_tx: broadcast::Sender<String>,
}

impl MatrixOrchestrator {
    pub fn new(max_concurrent: usize) -> Self;

    pub async fn run<F, Fut>(
        &self,
        tasks: Vec<F>,
        global_timeout: Duration,
    ) -> Result<Vec<TaskResult>, OrchestratorError>
    where
        F: FnOnce(u32, CancellationToken) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<String, String>> + Send;

    pub fn cancel(&self);

    pub fn broadcast(&self, message: String) -> Result<usize, broadcast::error::SendError<String>>;

    pub fn subscribe(&self) -> broadcast::Receiver<String>;
}
```

---

## 2. LE SAVIEZ-VOUS ?

### 2.1 L'async/await : La Revolution du Non-Bloquant

L'async/await n'est pas du multithreading classique. C'est de la **concurrence cooperative** : chaque tache cede volontairement le controle au runtime quand elle attend (I/O, timer, etc.).

Dans la Matrice, c'est comme si chaque programme pouvait se "mettre en pause" quand il attend quelque chose, permettant a d'autres de s'executer sur le meme processeur.

**Fun fact :** Tokio peut gerer 1 million de connexions concurrentes avec seulement quelques threads !

### 2.2 DANS LA VRAIE VIE

| Metier | Cas d'usage |
|--------|-------------|
| **Backend Developer** | Serveur HTTP async gerant 100k connexions |
| **DevOps** | Orchestration de containers (comme Kubernetes) |
| **Game Developer** | Gestion des events et I/O reseau |
| **Data Engineer** | Pipeline de traitement de donnees streaming |

---

## 3. EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ ls
async_orchestrator.rs  main.rs  Cargo.toml

$ cargo build --release
   Compiling matrix_orchestrator v0.1.0
    Finished release [optimized] target(s) in 2.34s

$ cargo run --release
Starting Matrix Orchestrator with 3 concurrent slots...
Task 0 started (Agent Smith)
Task 1 started (Agent Brown)
Task 2 started (Agent Jones)
Task 1 completed in 150ms
Task 3 started (Seraph)
Task 0 completed in 200ms
Task 4 started (Oracle)
...
All tasks completed: 10 results
Broadcast message sent to 5 subscribers
Graceful shutdown initiated
```

### 3.1 BONUS EXPERT (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★★★★☆ (9/10)

**Recompense :**
XP x4

**Time Complexity attendue :**
O(n log n) pour le scheduling prioritaire

**Space Complexity attendue :**
O(n)

**Domaines Bonus :**
`DP, Struct`

#### 3.1.1 Consigne Bonus

**The Matrix Revolutions : Le Scheduling Predictif de l'Oracle**

L'Oracle peut predire l'avenir. Implemente un **scheduler predictif** qui :
1. Estime la duree des taches
2. Priorise les taches courtes (Shortest Job First)
3. Implemente du **work stealing** entre workers
4. Gere les deadlines avec preemption

**Ta mission :**

Etendre `MatrixOrchestrator` avec :
- Un systeme de priorite dynamique
- Work stealing entre workers inactifs
- Respect des deadlines avec preemption soft

**Contraintes :**
```
1 <= tasks <= 10^4
1 ms <= task_duration <= 60s
Priority: 1 (highest) to 10 (lowest)
Deadline miss tolerance: 5%
```

#### 3.1.2 Prototype Bonus

```rust
#[derive(Debug, Clone)]
pub struct PrioritizedTask {
    pub id: u32,
    pub priority: u8,
    pub estimated_duration: Duration,
    pub deadline: Option<Duration>,
}

impl MatrixOrchestrator {
    pub async fn run_with_priority(
        &self,
        tasks: Vec<PrioritizedTask>,
        executor: impl Fn(PrioritizedTask) -> BoxFuture<'static, TaskResult>,
    ) -> Result<Vec<TaskResult>, OrchestratorError>;

    pub fn enable_work_stealing(&mut self, enabled: bool);
}
```

#### 3.1.3 Ce qui change par rapport a l'exercice de base

| Aspect | Base | Bonus |
|--------|------|-------|
| Scheduling | FIFO | Shortest Job First + Priority |
| Concurrence | Semaphore simple | Work stealing |
| Deadlines | Non | Oui avec preemption soft |
| Complexite | O(n) | O(n log n) |

---

## 4. ZONE CORRECTION

### 4.1 Moulinette

| Test | Entree | Sortie Attendue | Points |
|------|--------|-----------------|--------|
| `test_basic_execution` | 5 taches, max 2 | 5 resultats | 15 |
| `test_semaphore_limit` | 10 taches, max 3 | jamais >3 concurrent | 20 |
| `test_cancellation` | cancel apres 100ms | Cancelled error | 15 |
| `test_timeout` | timeout 10ms, tache 1s | Timeout error | 15 |
| `test_broadcast` | 5 subscribers | tous recoivent | 10 |
| `test_futures_unordered` | ordre completion | correct | 15 |
| `test_graceful_shutdown` | shutdown propre | no panic | 10 |

### 4.2 main.rs de test

```rust
use async_orchestrator::*;
use tokio::time::{sleep, Duration};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

#[tokio::test]
async fn test_basic_execution() {
    let orchestrator = MatrixOrchestrator::new(3);

    let tasks: Vec<_> = (0..5).map(|i| {
        move |id: u32, _cancel: CancellationToken| async move {
            sleep(Duration::from_millis(50)).await;
            Ok(format!("Task {} completed", id))
        }
    }).collect();

    let results = orchestrator.run(tasks, Duration::from_secs(10)).await;
    assert!(results.is_ok());
    assert_eq!(results.unwrap().len(), 5);
}

#[tokio::test]
async fn test_semaphore_limit() {
    let orchestrator = MatrixOrchestrator::new(3);
    let concurrent_count = Arc::new(AtomicU32::new(0));
    let max_concurrent = Arc::new(AtomicU32::new(0));

    let tasks: Vec<_> = (0..10).map(|_| {
        let cc = Arc::clone(&concurrent_count);
        let mc = Arc::clone(&max_concurrent);
        move |_id: u32, _cancel: CancellationToken| async move {
            let current = cc.fetch_add(1, Ordering::SeqCst) + 1;
            mc.fetch_max(current, Ordering::SeqCst);
            sleep(Duration::from_millis(100)).await;
            cc.fetch_sub(1, Ordering::SeqCst);
            Ok("done".to_string())
        }
    }).collect();

    let _ = orchestrator.run(tasks, Duration::from_secs(10)).await;
    assert!(max_concurrent.load(Ordering::SeqCst) <= 3);
}

#[tokio::test]
async fn test_cancellation() {
    let orchestrator = MatrixOrchestrator::new(2);

    let tasks: Vec<_> = (0..5).map(|_| {
        move |_id: u32, cancel: CancellationToken| async move {
            tokio::select! {
                _ = cancel.cancelled() => Err("cancelled".to_string()),
                _ = sleep(Duration::from_secs(10)) => Ok("done".to_string()),
            }
        }
    }).collect();

    let orchestrator_clone = orchestrator.clone();
    tokio::spawn(async move {
        sleep(Duration::from_millis(100)).await;
        orchestrator_clone.cancel();
    });

    let result = orchestrator.run(tasks, Duration::from_secs(30)).await;
    assert!(matches!(result, Err(OrchestratorError::Cancelled)));
}

#[tokio::test]
async fn test_timeout() {
    let orchestrator = MatrixOrchestrator::new(1);

    let tasks: Vec<_> = vec![
        move |_id: u32, _cancel: CancellationToken| async move {
            sleep(Duration::from_secs(10)).await;
            Ok("done".to_string())
        }
    ];

    let result = orchestrator.run(tasks, Duration::from_millis(50)).await;
    assert!(matches!(result, Err(OrchestratorError::Timeout)));
}

#[tokio::test]
async fn test_broadcast() {
    let orchestrator = MatrixOrchestrator::new(2);
    let received = Arc::new(AtomicU32::new(0));

    let mut handles = vec![];
    for _ in 0..5 {
        let mut rx = orchestrator.subscribe();
        let recv = Arc::clone(&received);
        handles.push(tokio::spawn(async move {
            if rx.recv().await.is_ok() {
                recv.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    sleep(Duration::from_millis(10)).await;
    orchestrator.broadcast("Oracle says: It's time".to_string()).unwrap();

    for h in handles {
        h.await.unwrap();
    }

    assert_eq!(received.load(Ordering::SeqCst), 5);
}
```

### 4.3 Solution de reference

```rust
use tokio::sync::{Mutex, Semaphore, broadcast, mpsc};
use tokio::time::{timeout, Duration, Instant};
use tokio_util::sync::CancellationToken;
use futures::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct TaskResult {
    pub task_id: u32,
    pub result: String,
    pub duration_ms: u64,
}

#[derive(Debug)]
pub enum OrchestratorError {
    Timeout,
    Cancelled,
    TaskFailed(String),
}

#[derive(Clone)]
pub struct MatrixOrchestrator {
    max_concurrent: usize,
    semaphore: Arc<Semaphore>,
    cancel_token: CancellationToken,
    broadcast_tx: broadcast::Sender<String>,
}

impl MatrixOrchestrator {
    pub fn new(max_concurrent: usize) -> Self {
        let (broadcast_tx, _) = broadcast::channel(100);
        Self {
            max_concurrent,
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            cancel_token: CancellationToken::new(),
            broadcast_tx,
        }
    }

    pub async fn run<F, Fut>(
        &self,
        tasks: Vec<F>,
        global_timeout: Duration,
    ) -> Result<Vec<TaskResult>, OrchestratorError>
    where
        F: FnOnce(u32, CancellationToken) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<String, String>> + Send,
    {
        let mut futures = FuturesUnordered::new();
        let mut results = Vec::new();

        for (id, task) in tasks.into_iter().enumerate() {
            let semaphore = Arc::clone(&self.semaphore);
            let cancel_token = self.cancel_token.clone();
            let task_id = id as u32;

            futures.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let start = Instant::now();

                let result = task(task_id, cancel_token.clone()).await;
                let duration_ms = start.elapsed().as_millis() as u64;

                TaskResult {
                    task_id,
                    result: result.unwrap_or_else(|e| e),
                    duration_ms,
                }
            }));
        }

        let collect_results = async {
            while let Some(result) = futures.next().await {
                if self.cancel_token.is_cancelled() {
                    return Err(OrchestratorError::Cancelled);
                }
                match result {
                    Ok(task_result) => results.push(task_result),
                    Err(e) => return Err(OrchestratorError::TaskFailed(e.to_string())),
                }
            }
            Ok(results)
        };

        match timeout(global_timeout, collect_results).await {
            Ok(Ok(results)) => Ok(results),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(OrchestratorError::Timeout),
        }
    }

    pub fn cancel(&self) {
        self.cancel_token.cancel();
    }

    pub fn broadcast(&self, message: String) -> Result<usize, broadcast::error::SendError<String>> {
        self.broadcast_tx.send(message)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.broadcast_tx.subscribe()
    }
}
```

### 4.4 Solutions alternatives acceptees

```rust
// Alternative 1: Avec mpsc pour la collecte
impl MatrixOrchestrator {
    pub async fn run_with_mpsc<F, Fut>(
        &self,
        tasks: Vec<F>,
        global_timeout: Duration,
    ) -> Result<Vec<TaskResult>, OrchestratorError>
    where
        F: FnOnce(u32, CancellationToken) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<String, String>> + Send,
    {
        let (tx, mut rx) = mpsc::channel(tasks.len());
        let task_count = tasks.len();

        for (id, task) in tasks.into_iter().enumerate() {
            let semaphore = Arc::clone(&self.semaphore);
            let cancel_token = self.cancel_token.clone();
            let tx = tx.clone();
            let task_id = id as u32;

            tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let start = Instant::now();
                let result = task(task_id, cancel_token).await;
                let _ = tx.send(TaskResult {
                    task_id,
                    result: result.unwrap_or_else(|e| e),
                    duration_ms: start.elapsed().as_millis() as u64,
                }).await;
            });
        }

        drop(tx);

        let mut results = Vec::new();
        let collect = async {
            while let Some(result) = rx.recv().await {
                results.push(result);
            }
            results
        };

        timeout(global_timeout, collect)
            .await
            .map_err(|_| OrchestratorError::Timeout)
    }
}

// Alternative 2: Avec tokio::select! pour la cancellation
impl MatrixOrchestrator {
    pub async fn run_with_select<F, Fut>(
        &self,
        tasks: Vec<F>,
        global_timeout: Duration,
    ) -> Result<Vec<TaskResult>, OrchestratorError>
    where
        F: FnOnce(u32, CancellationToken) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<String, String>> + Send,
    {
        tokio::select! {
            result = self.execute_all(tasks) => result,
            _ = tokio::time::sleep(global_timeout) => Err(OrchestratorError::Timeout),
            _ = self.cancel_token.cancelled() => Err(OrchestratorError::Cancelled),
        }
    }
}
```

### 4.5 Solutions refusees

```rust
// REFUSE 1: Pas de limite de concurrence
impl MatrixOrchestrator {
    pub async fn run_no_limit<F, Fut>(&self, tasks: Vec<F>, _: Duration)
    -> Result<Vec<TaskResult>, OrchestratorError>
    where F: FnOnce(u32, CancellationToken) -> Fut + Send + 'static,
          Fut: std::future::Future<Output = Result<String, String>> + Send,
    {
        // ERREUR: Lance toutes les taches sans semaphore!
        let futures: Vec<_> = tasks.into_iter().enumerate().map(|(id, task)| {
            tokio::spawn(task(id as u32, self.cancel_token.clone()))
        }).collect();

        let results = futures::future::join_all(futures).await;
        // Pas de respect de max_concurrent!
        Ok(vec![])
    }
}
// Pourquoi refuse: Ignore completement le semaphore, peut surcharger le systeme

// REFUSE 2: Blocking au lieu de async
impl MatrixOrchestrator {
    pub async fn run_blocking<F, Fut>(&self, tasks: Vec<F>, _: Duration)
    -> Result<Vec<TaskResult>, OrchestratorError>
    where F: FnOnce(u32, CancellationToken) -> Fut + Send + 'static,
          Fut: std::future::Future<Output = Result<String, String>> + Send,
    {
        // ERREUR: Utilise std::thread au lieu de tokio::spawn!
        let handles: Vec<_> = tasks.into_iter().enumerate().map(|(id, task)| {
            std::thread::spawn(move || {
                // Bloque un thread OS pour chaque tache!
                tokio::runtime::Runtime::new().unwrap().block_on(
                    task(id as u32, CancellationToken::new())
                )
            })
        }).collect();
        Ok(vec![])
    }
}
// Pourquoi refuse: Utilise des threads OS bloquants, defait le but de l'async

// REFUSE 3: Ignore la cancellation
impl MatrixOrchestrator {
    pub async fn run_no_cancel<F, Fut>(&self, tasks: Vec<F>, timeout_dur: Duration)
    -> Result<Vec<TaskResult>, OrchestratorError>
    where F: FnOnce(u32, CancellationToken) -> Fut + Send + 'static,
          Fut: std::future::Future<Output = Result<String, String>> + Send,
    {
        let mut futures = FuturesUnordered::new();
        for (id, task) in tasks.into_iter().enumerate() {
            // ERREUR: Ne passe pas le cancel_token aux taches!
            futures.push(tokio::spawn(task(id as u32, CancellationToken::new())));
        }
        // Les taches ne peuvent jamais etre annulees proprement!
        Ok(vec![])
    }
}
// Pourquoi refuse: Chaque tache a son propre token, cancel() n'a aucun effet
```

### 4.6 Solution bonus de reference

```rust
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct PrioritizedTask {
    pub id: u32,
    pub priority: u8,
    pub estimated_duration: Duration,
    pub deadline: Option<Duration>,
}

impl Ord for PrioritizedTask {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Lower priority number = higher priority
        // Shorter duration = higher priority (SJF)
        (self.priority, self.estimated_duration)
            .cmp(&(other.priority, other.estimated_duration))
    }
}

impl PartialOrd for PrioritizedTask {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for PrioritizedTask {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for PrioritizedTask {}

pub struct PriorityOrchestrator {
    base: MatrixOrchestrator,
    task_queue: Arc<Mutex<BinaryHeap<Reverse<PrioritizedTask>>>>,
    work_stealing_enabled: bool,
}

impl PriorityOrchestrator {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            base: MatrixOrchestrator::new(max_concurrent),
            task_queue: Arc::new(Mutex::new(BinaryHeap::new())),
            work_stealing_enabled: false,
        }
    }

    pub fn enable_work_stealing(&mut self, enabled: bool) {
        self.work_stealing_enabled = enabled;
    }

    pub async fn run_with_priority<F>(
        &self,
        tasks: Vec<PrioritizedTask>,
        executor: F,
    ) -> Result<Vec<TaskResult>, OrchestratorError>
    where
        F: Fn(PrioritizedTask) -> BoxFuture<'static, TaskResult> + Send + Sync + 'static,
    {
        let executor = Arc::new(executor);
        let start_time = Instant::now();

        // Populate priority queue
        {
            let mut queue = self.task_queue.lock().await;
            for task in tasks {
                queue.push(Reverse(task));
            }
        }

        let mut futures = FuturesUnordered::new();
        let mut results = Vec::new();

        // Worker loop
        loop {
            // Try to spawn more tasks if under limit
            while futures.len() < self.base.max_concurrent {
                let task = {
                    let mut queue = self.task_queue.lock().await;
                    queue.pop().map(|Reverse(t)| t)
                };

                match task {
                    Some(task) => {
                        // Check deadline
                        if let Some(deadline) = task.deadline {
                            if start_time.elapsed() > deadline {
                                continue; // Skip expired tasks
                            }
                        }

                        let semaphore = Arc::clone(&self.base.semaphore);
                        let cancel_token = self.base.cancel_token.clone();
                        let exec = Arc::clone(&executor);

                        futures.push(tokio::spawn(async move {
                            let _permit = semaphore.acquire().await.unwrap();

                            tokio::select! {
                                result = exec(task) => result,
                                _ = cancel_token.cancelled() => TaskResult {
                                    task_id: 0,
                                    result: "cancelled".to_string(),
                                    duration_ms: 0,
                                },
                            }
                        }));
                    }
                    None => break,
                }
            }

            if futures.is_empty() {
                break;
            }

            // Wait for next completion
            if let Some(result) = futures.next().await {
                match result {
                    Ok(task_result) => results.push(task_result),
                    Err(e) => return Err(OrchestratorError::TaskFailed(e.to_string())),
                }
            }
        }

        Ok(results)
    }
}
```

### 4.7 Solutions alternatives bonus

```rust
// Alternative avec work-stealing explicite
impl PriorityOrchestrator {
    pub async fn run_with_work_stealing<F>(
        &self,
        tasks: Vec<PrioritizedTask>,
        executor: F,
        num_workers: usize,
    ) -> Result<Vec<TaskResult>, OrchestratorError>
    where
        F: Fn(PrioritizedTask) -> BoxFuture<'static, TaskResult> + Send + Sync + 'static,
    {
        let executor = Arc::new(executor);
        let (result_tx, mut result_rx) = mpsc::channel(tasks.len());

        // Per-worker queues for work stealing
        let worker_queues: Vec<_> = (0..num_workers)
            .map(|_| Arc::new(Mutex::new(VecDeque::new())))
            .collect();

        // Distribute tasks round-robin initially
        for (i, task) in tasks.into_iter().enumerate() {
            worker_queues[i % num_workers].lock().await.push_back(task);
        }

        // Spawn workers
        let mut handles = vec![];
        for worker_id in 0..num_workers {
            let my_queue = Arc::clone(&worker_queues[worker_id]);
            let all_queues = worker_queues.clone();
            let tx = result_tx.clone();
            let exec = Arc::clone(&executor);
            let cancel = self.base.cancel_token.clone();

            handles.push(tokio::spawn(async move {
                loop {
                    // Try own queue first
                    let task = my_queue.lock().await.pop_front();

                    let task = match task {
                        Some(t) => t,
                        None => {
                            // Work stealing: try other queues
                            let mut stolen = None;
                            for (i, queue) in all_queues.iter().enumerate() {
                                if i != worker_id {
                                    if let Some(t) = queue.lock().await.pop_back() {
                                        stolen = Some(t);
                                        break;
                                    }
                                }
                            }
                            match stolen {
                                Some(t) => t,
                                None => break, // No more work
                            }
                        }
                    };

                    if cancel.is_cancelled() {
                        break;
                    }

                    let result = exec(task).await;
                    let _ = tx.send(result).await;
                }
            }));
        }

        drop(result_tx);

        let mut results = vec![];
        while let Some(r) = result_rx.recv().await {
            results.push(r);
        }

        for h in handles {
            h.await.unwrap();
        }

        Ok(results)
    }
}
```

### 4.8 Solutions refusees bonus

```rust
// REFUSE: Tri O(n^2) au lieu de heap
impl PriorityOrchestrator {
    pub async fn run_slow_sort(&self, mut tasks: Vec<PrioritizedTask>)
    -> Result<Vec<TaskResult>, OrchestratorError> {
        // ERREUR: Tri O(n^2) a chaque extraction!
        loop {
            tasks.sort_by(|a, b| a.priority.cmp(&b.priority));
            if tasks.is_empty() { break; }
            let task = tasks.remove(0); // O(n) removal!
            // ...
        }
        Ok(vec![])
    }
}
// Pourquoi refuse: O(n^2) au lieu de O(n log n), inefficace pour beaucoup de taches
```

### 4.9 spec.json

```json
{
  "name": "async_orchestrator",
  "language": "rust",
  "type": "code",
  "tier": 3,
  "tier_info": "Synthese async",
  "tags": ["async", "tokio", "concurrency", "channels", "phase2"],
  "passing_score": 70,

  "function": {
    "name": "MatrixOrchestrator::run",
    "prototype": "pub async fn run<F, Fut>(&self, tasks: Vec<F>, global_timeout: Duration) -> Result<Vec<TaskResult>, OrchestratorError>",
    "return_type": "Result<Vec<TaskResult>, OrchestratorError>",
    "parameters": [
      {"name": "tasks", "type": "Vec<F>"},
      {"name": "global_timeout", "type": "Duration"}
    ]
  },

  "driver": {
    "reference": "impl MatrixOrchestrator { pub fn new(max_concurrent: usize) -> Self { let (broadcast_tx, _) = broadcast::channel(100); Self { max_concurrent, semaphore: Arc::new(Semaphore::new(max_concurrent)), cancel_token: CancellationToken::new(), broadcast_tx } } pub async fn run<F, Fut>(&self, tasks: Vec<F>, global_timeout: Duration) -> Result<Vec<TaskResult>, OrchestratorError> where F: FnOnce(u32, CancellationToken) -> Fut + Send + 'static, Fut: std::future::Future<Output = Result<String, String>> + Send { let mut futures = FuturesUnordered::new(); let mut results = Vec::new(); for (id, task) in tasks.into_iter().enumerate() { let semaphore = Arc::clone(&self.semaphore); let cancel_token = self.cancel_token.clone(); let task_id = id as u32; futures.push(tokio::spawn(async move { let _permit = semaphore.acquire().await.unwrap(); let start = Instant::now(); let result = task(task_id, cancel_token.clone()).await; TaskResult { task_id, result: result.unwrap_or_else(|e| e), duration_ms: start.elapsed().as_millis() as u64 } })); } let collect_results = async { while let Some(result) = futures.next().await { if self.cancel_token.is_cancelled() { return Err(OrchestratorError::Cancelled); } match result { Ok(task_result) => results.push(task_result), Err(e) => return Err(OrchestratorError::TaskFailed(e.to_string())) } } Ok(results) }; match timeout(global_timeout, collect_results).await { Ok(Ok(results)) => Ok(results), Ok(Err(e)) => Err(e), Err(_) => Err(OrchestratorError::Timeout) } } pub fn cancel(&self) { self.cancel_token.cancel(); } pub fn broadcast(&self, message: String) -> Result<usize, broadcast::error::SendError<String>> { self.broadcast_tx.send(message) } pub fn subscribe(&self) -> broadcast::Receiver<String> { self.broadcast_tx.subscribe() } }",

    "edge_cases": [
      {
        "name": "empty_tasks",
        "args": ["[]", "Duration::from_secs(10)"],
        "expected": "Ok([])",
        "is_trap": true,
        "trap_explanation": "Liste vide doit retourner Ok vide, pas d'erreur"
      },
      {
        "name": "single_task",
        "args": ["[task]", "Duration::from_secs(10)"],
        "expected": "Ok([result])"
      },
      {
        "name": "timeout_zero",
        "args": ["[task]", "Duration::ZERO"],
        "expected": "Err(Timeout)",
        "is_trap": true,
        "trap_explanation": "Timeout de zero doit timeout immediatement"
      },
      {
        "name": "max_concurrent_one",
        "args": ["[t1, t2, t3]", "Duration::from_secs(30)"],
        "expected": "Ok([...])",
        "is_trap": true,
        "trap_explanation": "Avec max_concurrent=1, doit executer sequentiellement"
      },
      {
        "name": "cancel_during_execution",
        "args": ["[long_tasks]", "Duration::from_secs(30)"],
        "expected": "Err(Cancelled)"
      },
      {
        "name": "broadcast_no_subscribers",
        "args": ["message"],
        "expected": "Ok(0)"
      }
    ],

    "fuzzing": {
      "enabled": true,
      "iterations": 500,
      "generators": [
        {
          "type": "int",
          "param_index": 0,
          "params": {"min": 0, "max": 100}
        },
        {
          "type": "int",
          "param_index": 1,
          "params": {"min": 1, "max": 10000}
        }
      ]
    }
  },

  "norm": {
    "allowed_functions": ["tokio::sync::*", "tokio::time::*", "tokio::spawn", "tokio::select!", "futures::stream::*", "Arc::*"],
    "forbidden_functions": ["std::sync::Mutex", "std::thread::spawn", "unsafe"],
    "check_security": true,
    "check_memory": true,
    "blocking": true
  }
}
```

### 4.10 Solutions Mutantes

```rust
/* Mutant A (Boundary) : Semaphore avec 0 permits */
pub struct MatrixOrchestratorMutantA {
    max_concurrent: usize,
    semaphore: Arc<Semaphore>,
    cancel_token: CancellationToken,
    broadcast_tx: broadcast::Sender<String>,
}

impl MatrixOrchestratorMutantA {
    pub fn new(max_concurrent: usize) -> Self {
        let (broadcast_tx, _) = broadcast::channel(100);
        Self {
            max_concurrent,
            // BUG: Cree un semaphore avec 0 permits au lieu de max_concurrent!
            semaphore: Arc::new(Semaphore::new(0)),
            cancel_token: CancellationToken::new(),
            broadcast_tx,
        }
    }

    pub async fn run<F, Fut>(
        &self,
        tasks: Vec<F>,
        global_timeout: Duration,
    ) -> Result<Vec<TaskResult>, OrchestratorError>
    where
        F: FnOnce(u32, CancellationToken) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<String, String>> + Send,
    {
        let mut futures = FuturesUnordered::new();

        for (id, task) in tasks.into_iter().enumerate() {
            let semaphore = Arc::clone(&self.semaphore);
            let cancel_token = self.cancel_token.clone();
            let task_id = id as u32;

            futures.push(tokio::spawn(async move {
                // BUG: Bloquera indefiniment car 0 permits!
                let _permit = semaphore.acquire().await.unwrap();
                let start = Instant::now();
                let result = task(task_id, cancel_token.clone()).await;
                TaskResult {
                    task_id,
                    result: result.unwrap_or_else(|e| e),
                    duration_ms: start.elapsed().as_millis() as u64,
                }
            }));
        }

        // Timeout car aucune tache ne peut jamais obtenir un permit
        match timeout(global_timeout, async {
            let mut results = vec![];
            while let Some(r) = futures.next().await {
                results.push(r.unwrap());
            }
            results
        }).await {
            Ok(results) => Ok(results),
            Err(_) => Err(OrchestratorError::Timeout),
        }
    }
}
// Pourquoi c'est faux: Le semaphore avec 0 permits bloque toutes les taches
// Ce qui etait pense: "0 permits = illimite" (confusion avec bounded(0) qui est rendezvous)

/* Mutant B (Safety) : Oubli du clone du CancellationToken */
impl MatrixOrchestratorMutantB {
    pub async fn run<F, Fut>(
        &self,
        tasks: Vec<F>,
        global_timeout: Duration,
    ) -> Result<Vec<TaskResult>, OrchestratorError>
    where
        F: FnOnce(u32, CancellationToken) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<String, String>> + Send,
    {
        let mut futures = FuturesUnordered::new();

        for (id, task) in tasks.into_iter().enumerate() {
            let semaphore = Arc::clone(&self.semaphore);
            // BUG: Cree un nouveau token au lieu de cloner celui de l'orchestrateur!
            let cancel_token = CancellationToken::new();
            let task_id = id as u32;

            futures.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let start = Instant::now();
                let result = task(task_id, cancel_token.clone()).await;
                TaskResult {
                    task_id,
                    result: result.unwrap_or_else(|e| e),
                    duration_ms: start.elapsed().as_millis() as u64,
                }
            }));
        }

        // cancel() n'aura aucun effet sur les taches!
        Ok(vec![])
    }
}
// Pourquoi c'est faux: Chaque tache a son propre token, cancel() global ne fonctionne pas
// Ce qui etait pense: "new() et clone() c'est pareil" (non, new cree un token independant)

/* Mutant C (Resource) : Oubli du drop du permit */
impl MatrixOrchestratorMutantC {
    pub async fn run<F, Fut>(
        &self,
        tasks: Vec<F>,
        global_timeout: Duration,
    ) -> Result<Vec<TaskResult>, OrchestratorError>
    where
        F: FnOnce(u32, CancellationToken) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<String, String>> + Send,
    {
        let mut futures = FuturesUnordered::new();
        // BUG: Stocke les permits au lieu de les liberer automatiquement!
        let permits: Arc<Mutex<Vec<tokio::sync::OwnedSemaphorePermit>>> =
            Arc::new(Mutex::new(Vec::new()));

        for (id, task) in tasks.into_iter().enumerate() {
            let semaphore = Arc::clone(&self.semaphore);
            let cancel_token = self.cancel_token.clone();
            let permits = Arc::clone(&permits);
            let task_id = id as u32;

            futures.push(tokio::spawn(async move {
                let permit = semaphore.clone().acquire_owned().await.unwrap();
                // BUG: Stocke le permit au lieu de le laisser se liberer!
                permits.lock().await.push(permit);

                let start = Instant::now();
                let result = task(task_id, cancel_token.clone()).await;
                TaskResult {
                    task_id,
                    result: result.unwrap_or_else(|e| e),
                    duration_ms: start.elapsed().as_millis() as u64,
                }
                // Le permit n'est jamais libere car il est dans permits!
            }));
        }

        Ok(vec![])
    }
}
// Pourquoi c'est faux: Les permits ne sont jamais liberes, le semaphore se vide
// Ce qui etait pense: "Je dois garder le permit actif" (non, il doit etre drop apres usage)

/* Mutant D (Logic) : Ordre inverse dans select! */
impl MatrixOrchestratorMutantD {
    pub async fn run<F, Fut>(
        &self,
        tasks: Vec<F>,
        global_timeout: Duration,
    ) -> Result<Vec<TaskResult>, OrchestratorError>
    where
        F: FnOnce(u32, CancellationToken) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<String, String>> + Send,
    {
        let mut futures = FuturesUnordered::new();

        for (id, task) in tasks.into_iter().enumerate() {
            let semaphore = Arc::clone(&self.semaphore);
            let cancel_token = self.cancel_token.clone();
            let task_id = id as u32;

            futures.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let start = Instant::now();
                let result = task(task_id, cancel_token.clone()).await;
                TaskResult {
                    task_id,
                    result: result.unwrap_or_else(|e| e),
                    duration_ms: start.elapsed().as_millis() as u64,
                }
            }));
        }

        let mut results = vec![];

        // BUG: Verifie le timeout AVANT de collecter!
        tokio::select! {
            biased;  // Le premier branch est toujours teste d'abord

            // Le sleep sera toujours pret si timeout est passe
            _ = tokio::time::sleep(global_timeout) => {
                return Err(OrchestratorError::Timeout);
            }
            // Ce branch ne sera jamais atteint si timeout est court!
            _ = async {
                while let Some(r) = futures.next().await {
                    results.push(r.unwrap());
                }
            } => {
                return Ok(results);
            }
        }
    }
}
// Pourquoi c'est faux: Avec biased, le timeout gagne toujours si le temps est ecoule
// Ce qui etait pense: "biased c'est juste pour la performance" (non, ca change la semantique)

/* Mutant E (Return) : Retourne toujours Ok meme en cas d'erreur */
impl MatrixOrchestratorMutantE {
    pub async fn run<F, Fut>(
        &self,
        tasks: Vec<F>,
        global_timeout: Duration,
    ) -> Result<Vec<TaskResult>, OrchestratorError>
    where
        F: FnOnce(u32, CancellationToken) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = Result<String, String>> + Send,
    {
        let mut futures = FuturesUnordered::new();
        let mut results = Vec::new();

        for (id, task) in tasks.into_iter().enumerate() {
            let semaphore = Arc::clone(&self.semaphore);
            let cancel_token = self.cancel_token.clone();
            let task_id = id as u32;

            futures.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let start = Instant::now();
                let result = task(task_id, cancel_token.clone()).await;
                TaskResult {
                    task_id,
                    result: result.unwrap_or_else(|e| e),
                    duration_ms: start.elapsed().as_millis() as u64,
                }
            }));
        }

        // BUG: Ignore le timeout et retourne toujours Ok!
        match timeout(global_timeout, async {
            while let Some(result) = futures.next().await {
                if let Ok(task_result) = result {
                    results.push(task_result);
                }
                // Ignore les erreurs de join!
            }
        }).await {
            Ok(_) => Ok(results),
            Err(_) => Ok(results),  // BUG: Devrait retourner Err(Timeout)!
        }
    }
}
// Pourquoi c'est faux: Le timeout est ignore, on retourne toujours Ok
// Ce qui etait pense: "On veut retourner ce qu'on a meme en timeout" (non, timeout = erreur)
```

---

## 5. COMPRENDRE

### 5.1 Ce que cet exercice enseigne

1. **Async synchronization** : Comment coordonner des taches async avec Semaphore, Mutex async, et Notify
2. **Channels async** : broadcast, mpsc, oneshot, watch - quand utiliser lequel
3. **Patterns async** : select!, join!, FuturesUnordered pour gerer plusieurs futures
4. **Cancellation cooperative** : Comment implementer un arret propre avec CancellationToken
5. **Timeout et resilience** : Gerer les cas ou les taches prennent trop de temps

### 5.2 LDA - Traduction Litterale

```
STRUCTURE MatrixOrchestrator CONTENANT:
    - max_concurrent: ENTIER NON SIGNE
    - semaphore: POINTEUR PARTAGE VERS UN SEMAPHORE
    - cancel_token: JETON D'ANNULATION
    - broadcast_tx: EMETTEUR DE CANAL BROADCAST

FONCTION new QUI PREND max_concurrent COMME ENTIER ET RETOURNE MatrixOrchestrator
DEBUT FONCTION
    CREER UN CANAL BROADCAST AVEC CAPACITE 100
    RETOURNER UNE NOUVELLE STRUCTURE AVEC:
        - max_concurrent: LA VALEUR FOURNIE
        - semaphore: NOUVEAU SEMAPHORE AVEC max_concurrent PERMITS
        - cancel_token: NOUVEAU JETON D'ANNULATION
        - broadcast_tx: L'EMETTEUR DU CANAL
FIN FONCTION

FONCTION ASYNC run QUI PREND self, tasks, global_timeout ET RETOURNE RESULTAT
DEBUT FONCTION
    DECLARER futures COMME ENSEMBLE NON ORDONNE DE FUTURES
    DECLARER results COMME VECTEUR VIDE

    POUR CHAQUE (id, task) DANS tasks FAIRE
        CLONER semaphore, cancel_token
        DECLARER task_id COMME id CONVERTI EN u32

        AJOUTER A futures UNE NOUVELLE TACHE SPAWNED:
            ACQUERIR UN PERMIT DU SEMAPHORE (ATTENDRE)
            DECLARER start COMME INSTANT COURANT
            EXECUTER task AVEC task_id ET cancel_token
            CREER TaskResult AVEC task_id, resultat, duree
    FIN POUR

    DECLARER collect_results COMME CLOSURE ASYNC:
        TANT QUE futures A DES ELEMENTS FAIRE
            SI cancel_token EST ANNULE ALORS
                RETOURNER ERREUR Cancelled
            FIN SI
            RECUPERER LE PROCHAIN RESULTAT
            SI RESULTAT OK ALORS
                AJOUTER A results
            SINON
                RETOURNER ERREUR TaskFailed
            FIN SI
        FIN TANT QUE
        RETOURNER results
    FIN CLOSURE

    EXECUTER collect_results AVEC TIMEOUT global_timeout
    SI TIMEOUT ALORS
        RETOURNER ERREUR Timeout
    SINON
        RETOURNER results
    FIN SI
FIN FONCTION

FONCTION cancel QUI PREND self
DEBUT FONCTION
    ANNULER cancel_token
FIN FONCTION

FONCTION broadcast QUI PREND self ET message COMME STRING
DEBUT FONCTION
    ENVOYER message VIA broadcast_tx
    RETOURNER LE NOMBRE DE RECEPTEURS
FIN FONCTION
```

### 5.2.2 Style Academique

```
ALGORITHME : Orchestrateur de Taches Async
ENTREES : max_concurrent (entier), tasks (liste de fonctions async), timeout (duree)
SORTIE : Liste de resultats ou erreur

DEBUT
    INITIALISER semaphore avec max_concurrent permits
    INITIALISER cancel_token comme jeton d'annulation
    INITIALISER futures comme ensemble vide de futures en cours
    INITIALISER results comme liste vide

    POUR i DE 0 A longueur(tasks) - 1 FAIRE
        permit <- ACQUERIR_PERMIT(semaphore)  // Bloque si max atteint
        LANCER_ASYNC(tasks[i]) avec:
            - id = i
            - cancel_token = copie du jeton
            - liberation automatique du permit a la fin
        AJOUTER la future a futures
    FIN POUR

    // Collecte avec timeout global
    debut_collecte <- TEMPS_COURANT()
    TANT QUE futures non vide ET TEMPS_ECOULE() < timeout FAIRE
        SI cancel_token.est_annule() ALORS
            RETOURNER ERREUR("Cancelled")
        FIN SI

        resultat <- ATTENDRE_PROCHAINE(futures)
        AJOUTER resultat a results
    FIN TANT QUE

    SI TEMPS_ECOULE() >= timeout ALORS
        RETOURNER ERREUR("Timeout")
    FIN SI

    RETOURNER results
FIN
```

### 5.2.2.1 Logic Flow (Structured English)

```
ALGORITHM: Matrix Task Orchestrator
---
1. INITIALIZE orchestrator with:
   - Semaphore(max_concurrent) for concurrency control
   - CancellationToken for graceful shutdown
   - Broadcast channel for global notifications

2. FOR each task in task_list:
   a. SPAWN async task wrapper:
      - ACQUIRE semaphore permit (blocks if at limit)
      - RECORD start time
      - EXECUTE user task with (id, cancel_token)
      - RECORD duration
      - RETURN TaskResult
      - RELEASE permit automatically on drop
   b. ADD spawned future to FuturesUnordered

3. COLLECTION LOOP with timeout:
   a. SELECT on:
      - next completed future -> add result to list
      - cancellation token -> return Cancelled error
      - timeout elapsed -> return Timeout error
   b. CONTINUE until all futures complete

4. RETURN collected results in completion order
```

### 5.2.3 Representation Algorithmique avec Gardes

```
FONCTION : run(tasks, timeout)
---
INIT semaphore = Semaphore(max_concurrent)
INIT futures = FuturesUnordered::new()
INIT results = []

1. POUR CHAQUE task DANS tasks :
   |
   |-- SPAWN une tache async :
   |     |
   |     |-- ACQUERIR permit du semaphore (await)
   |     |     SI echec d'acquisition :
   |     |       RETOURNER Erreur("Semaphore closed")
   |     |
   |     |-- EXECUTER task avec cancel_token
   |     |
   |     |-- RETOURNER TaskResult
   |     |     (permit libere automatiquement au drop)
   |
   |-- AJOUTER future a futures

2. BOUCLE DE COLLECTE :
   |
   |-- VERIFIER cancel_token.is_cancelled() :
   |     SI vrai : RETOURNER Erreur(Cancelled)
   |
   |-- ATTENDRE avec timeout sur futures.next() :
   |     |
   |     |-- SI timeout : RETOURNER Erreur(Timeout)
   |     |
   |     |-- SI Some(result) :
   |     |     AJOUTER result a results
   |     |
   |     |-- SI None (toutes terminees) :
   |           SORTIR de la boucle

3. RETOURNER Ok(results)
```

### 5.2.3.1 Diagramme Mermaid

```mermaid
graph TD
    A[Start: run] --> B{tasks empty?}
    B -- Yes --> C[Return Ok(empty)]
    B -- No --> D[Create Semaphore]

    D --> E[For each task]
    E --> F[Spawn async wrapper]
    F --> G[Acquire permit]
    G --> H[Execute task]
    H --> I[Create TaskResult]
    I --> J[Add to FuturesUnordered]
    J --> E

    E -- All spawned --> K[Collection Loop]

    K --> L{cancel_token cancelled?}
    L -- Yes --> M[Return Err Cancelled]

    L -- No --> N[timeout futures.next]
    N --> O{Timeout elapsed?}
    O -- Yes --> P[Return Err Timeout]

    O -- No --> Q{Result?}
    Q -- Some result --> R[Add to results]
    R --> K

    Q -- None --> S[Return Ok results]

    subgraph "Worker Task"
        G --> |await permit| H
        H --> |await task| I
    end
```

### 5.3 Visualisation ASCII

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     MATRIX ORCHESTRATOR                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌─────────────┐                                                       │
│   │  SEMAPHORE  │  Permits: ●●●○○  (3 used, 2 available of 5)          │
│   └─────────────┘                                                       │
│         │                                                               │
│         ▼                                                               │
│   ┌─────────────────────────────────────────────────────────────┐       │
│   │                    TASK QUEUE                                │       │
│   │  [Task 0] [Task 1] [Task 2] [Task 3] [Task 4] ...           │       │
│   └─────────────────────────────────────────────────────────────┘       │
│                          │                                              │
│                          ▼                                              │
│   ┌─────────────────────────────────────────────────────────────┐       │
│   │              FUTURES UNORDERED                               │       │
│   │                                                              │       │
│   │    ┌──────┐  ┌──────┐  ┌──────┐                             │       │
│   │    │ F0   │  │ F1   │  │ F2   │   (running concurrently)    │       │
│   │    │ 80%  │  │ 30%  │  │ done │                             │       │
│   │    └──────┘  └──────┘  └──────┘                             │       │
│   │                           │                                  │       │
│   │                           ▼                                  │       │
│   │                    ┌──────────┐                              │       │
│   │                    │ RESULTS  │                              │       │
│   │                    │ [R2]     │  (completion order!)         │       │
│   │                    └──────────┘                              │       │
│   └─────────────────────────────────────────────────────────────┘       │
│                                                                         │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐              │
│   │ BROADCAST   │────►│ Subscriber1 │     │ CANCEL      │              │
│   │ "Prophecy!" │────►│ Subscriber2 │     │ TOKEN       │              │
│   │             │────►│ Subscriber3 │     │ [ACTIVE]    │              │
│   └─────────────┘     └─────────────┘     └─────────────┘              │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

Timeline d'execution (max_concurrent = 3):
═══════════════════════════════════════════════════════════════════════════

Time:   0ms    100ms   200ms   300ms   400ms   500ms
        │       │       │       │       │       │
Task 0: ████████████████████                      (200ms)
Task 1: ██████████████████████████████████████    (400ms)
Task 2: ████████                                  (100ms) ✓ First done!
Task 3:         ████████████████                  (150ms)
Task 4:                 ████████████████████████  (250ms)
        │       │       │       │       │       │
Permits: 3      3       3       3       3       2
```

### 5.4 Les pieges en detail

#### Piege 1 : Semaphore avec permits incorrects
```rust
// MAUVAIS: 0 permits = bloque tout!
Semaphore::new(0)

// MAUVAIS: Oubli de cloner le semaphore
let sem = Semaphore::new(5);
for _ in 0..10 {
    tokio::spawn(async {
        sem.acquire().await;  // Erreur: sem moved!
    });
}

// BON: Arc pour partager
let sem = Arc::new(Semaphore::new(5));
for _ in 0..10 {
    let sem = Arc::clone(&sem);
    tokio::spawn(async move {
        let _permit = sem.acquire().await.unwrap();
    });
}
```

#### Piege 2 : CancellationToken non partage
```rust
// MAUVAIS: Nouveau token a chaque iteration
for task in tasks {
    let token = CancellationToken::new();  // Token different!
    tokio::spawn(async move {
        select! {
            _ = token.cancelled() => {}  // cancel() global n'affecte pas celui-ci!
            _ = task => {}
        }
    });
}

// BON: Clone du token partage
let token = CancellationToken::new();
for task in tasks {
    let token = token.clone();  // Meme token!
    tokio::spawn(async move {
        select! {
            _ = token.cancelled() => {}
            _ = task => {}
        }
    });
}
```

#### Piege 3 : select! biased mal utilise
```rust
// MAUVAIS: biased favorise le premier branch
select! {
    biased;
    _ = sleep(Duration::ZERO) => { /* Toujours ici! */ }
    result = task => { /* Jamais atteint */ }
}

// BON: Sans biased pour fairness
select! {
    _ = sleep(timeout) => return Err(Timeout),
    result = task => return Ok(result),
}
```

### 5.5 Cours Complet

#### Introduction a l'Async Rust

L'async/await en Rust est fondamentalement different du multithreading classique. C'est un modele de **concurrence cooperative** ou les taches cedent volontairement le controle.

```rust
// Synchrone: Bloque le thread
fn sync_request() -> String {
    std::thread::sleep(Duration::from_secs(1));
    "done".to_string()
}

// Async: Cede le controle pendant l'attente
async fn async_request() -> String {
    tokio::time::sleep(Duration::from_secs(1)).await;  // Le .await cede!
    "done".to_string()
}
```

#### Le Runtime Tokio

Tokio est un runtime async qui fournit:
- Un scheduler multi-threaded (work-stealing)
- Des I/O async (TCP, UDP, files)
- Des primitives de synchronisation async

```rust
#[tokio::main]
async fn main() {
    // Cree un runtime avec thread pool
    // Par defaut: autant de threads que de CPU cores
}

// Ou manuellement:
let rt = tokio::runtime::Builder::new_multi_thread()
    .worker_threads(4)
    .enable_all()
    .build()
    .unwrap();
```

#### Primitives de Synchronisation Async

##### 1. tokio::sync::Mutex vs std::sync::Mutex

```rust
use tokio::sync::Mutex;

// Async Mutex: le lock est awaitable
let mutex = Arc::new(Mutex::new(0));
let mut guard = mutex.lock().await;  // Ne bloque pas le thread!
*guard += 1;
// guard drop ici, libere le lock
```

**Quand utiliser quoi?**
- `tokio::sync::Mutex`: Lock tenu a travers des .await
- `std::sync::Mutex`: Lock tres court, pas de .await pendant le lock

##### 2. Semaphore

```rust
let sem = Arc::new(Semaphore::new(3));  // 3 permits

let permit = sem.acquire().await.unwrap();  // Prend 1 permit
// ... travail ...
drop(permit);  // Rend le permit

// Ou avec scope automatique:
let _permit = sem.acquire().await.unwrap();
// permit rendu a la fin du scope
```

##### 3. Channels Async

```rust
// mpsc: Multi-producer, single-consumer
let (tx, mut rx) = mpsc::channel(100);
tx.send(42).await.unwrap();
let val = rx.recv().await;

// broadcast: Multi-producer, multi-consumer
let (tx, _) = broadcast::channel(100);
let mut rx1 = tx.subscribe();
let mut rx2 = tx.subscribe();
tx.send("hello").unwrap();  // rx1 et rx2 recoivent

// oneshot: One-time response
let (tx, rx) = oneshot::channel();
tx.send(42).unwrap();  // Ne peut envoyer qu'une fois
let val = rx.await.unwrap();

// watch: Single value, latest wins
let (tx, mut rx) = watch::channel("initial");
tx.send("updated").unwrap();
let val = *rx.borrow();  // Toujours la derniere valeur
```

#### Patterns Async Avances

##### select! - Premier gagnant
```rust
tokio::select! {
    val = async_op1() => println!("op1: {}", val),
    val = async_op2() => println!("op2: {}", val),
    _ = tokio::time::sleep(timeout) => println!("timeout!"),
}
// Seul le premier a completer execute son branch
// Les autres sont annules (dropped)
```

##### join! - Tous ensemble
```rust
let (a, b, c) = tokio::join!(
    async_op1(),
    async_op2(),
    async_op3(),
);
// Attend que les trois completent
// S'execute en parallele
```

##### FuturesUnordered - Ordre de completion
```rust
let mut futures = FuturesUnordered::new();
futures.push(task1());
futures.push(task2());
futures.push(task3());

while let Some(result) = futures.next().await {
    // Resultats dans l'ordre de COMPLETION, pas d'ajout
    println!("Got: {:?}", result);
}
```

#### Cancellation Cooperative

En Rust async, l'annulation est **cooperative**. Dropper une future l'annule, mais le code doit verifier regulierement.

```rust
use tokio_util::sync::CancellationToken;

let token = CancellationToken::new();
let token_clone = token.clone();

let task = tokio::spawn(async move {
    loop {
        tokio::select! {
            _ = token_clone.cancelled() => {
                println!("Cancelled!");
                break;
            }
            _ = do_work() => {
                println!("Work done");
            }
        }
    }
});

// Plus tard...
token.cancel();  // Signal d'annulation
task.await.unwrap();
```

### 5.6 Normes avec explications pedagogiques

```
┌─────────────────────────────────────────────────────────────────┐
│ ❌ HORS NORME                                                    │
├─────────────────────────────────────────────────────────────────┤
│ async fn run(&self) {                                           │
│     let mutex = Mutex::new(0);  // std::sync::Mutex!           │
│     let guard = mutex.lock().unwrap();                          │
│     some_async_op().await;  // .await while holding lock!      │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ ✅ CONFORME                                                     │
├─────────────────────────────────────────────────────────────────┤
│ async fn run(&self) {                                           │
│     let mutex = tokio::sync::Mutex::new(0);                    │
│     let guard = mutex.lock().await;                             │
│     some_async_op().await;  // OK avec tokio Mutex             │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ POURQUOI ?                                                      │
│                                                                 │
│ std::sync::Mutex bloque le thread entier pendant le lock.      │
│ Si vous .await pendant le lock, vous bloquez le worker thread  │
│ de Tokio, causant des deadlocks ou pertes de performance.      │
│                                                                 │
│ tokio::sync::Mutex est concu pour etre tenu a travers .await   │
│ sans bloquer le thread sous-jacent.                            │
└─────────────────────────────────────────────────────────────────┘
```

### 5.7 Simulation avec trace d'execution

**Scenario**: Orchestrateur avec max_concurrent=2, 4 taches de 100ms chacune, timeout 1s

```
┌───────┬──────────────────────────────────────────────┬──────────┬───────────────────────────┐
│ Etape │ Instruction                                  │ Permits  │ Explication               │
├───────┼──────────────────────────────────────────────┼──────────┼───────────────────────────┤
│   1   │ CREER Semaphore(2)                           │ 2/2      │ 2 permits disponibles     │
├───────┼──────────────────────────────────────────────┼──────────┼───────────────────────────┤
│   2   │ SPAWN Task0, acquire permit                  │ 1/2      │ Task0 demarre             │
├───────┼──────────────────────────────────────────────┼──────────┼───────────────────────────┤
│   3   │ SPAWN Task1, acquire permit                  │ 0/2      │ Task1 demarre             │
├───────┼──────────────────────────────────────────────┼──────────┼───────────────────────────┤
│   4   │ SPAWN Task2, await permit                    │ 0/2      │ Task2 en attente!         │
├───────┼──────────────────────────────────────────────┼──────────┼───────────────────────────┤
│   5   │ SPAWN Task3, await permit                    │ 0/2      │ Task3 en attente!         │
├───────┼──────────────────────────────────────────────┼──────────┼───────────────────────────┤
│   6   │ [100ms] Task0 complete, drop permit          │ 1/2      │ Permit libere             │
├───────┼──────────────────────────────────────────────┼──────────┼───────────────────────────┤
│   7   │ Task2 acquire permit                         │ 0/2      │ Task2 demarre enfin!      │
├───────┼──────────────────────────────────────────────┼──────────┼───────────────────────────┤
│   8   │ FuturesUnordered: Result{id:0} ready         │ 0/2      │ Premier resultat          │
├───────┼──────────────────────────────────────────────┼──────────┼───────────────────────────┤
│   9   │ [100ms] Task1 complete, drop permit          │ 1/2      │ Permit libere             │
├───────┼──────────────────────────────────────────────┼──────────┼───────────────────────────┤
│  10   │ Task3 acquire permit                         │ 0/2      │ Task3 demarre enfin!      │
├───────┼──────────────────────────────────────────────┼──────────┼───────────────────────────┤
│  11   │ FuturesUnordered: Result{id:1} ready         │ 0/2      │ Deuxieme resultat         │
├───────┼──────────────────────────────────────────────┼──────────┼───────────────────────────┤
│  12   │ [100ms] Task2 complete                       │ 1/2      │ Troisieme resultat        │
├───────┼──────────────────────────────────────────────┼──────────┼───────────────────────────┤
│  13   │ [100ms] Task3 complete                       │ 2/2      │ Quatrieme resultat        │
├───────┼──────────────────────────────────────────────┼──────────┼───────────────────────────┤
│  14   │ RETOURNER Ok([R0, R1, R2, R3])              │ 2/2      │ Ordre de completion!      │
└───────┴──────────────────────────────────────────────┴──────────┴───────────────────────────┘

Temps total: ~200ms (2 vagues de 2 taches paralleles)
Sans semaphore: ~100ms mais potentielle surcharge systeme
```

### 5.8 Mnemotechniques

#### MEME : "This is fine" - Le Semaphore Vide

![This is fine](meme_this_is_fine.jpg)

Comme le chien qui dit "This is fine" alors que tout brule, un developpeur qui cree un `Semaphore::new(0)` pense que ca va marcher. Spoiler: toutes les taches vont attendre... indefiniment.

```rust
// This is NOT fine
let sem = Semaphore::new(0);
sem.acquire().await;  // Attend pour toujours
```

#### MEME : "One Does Not Simply..." - La Cancellation

> "One does not simply... cancel an async task"

En Rust async, vous ne pouvez pas "tuer" une tache de force. Vous devez lui demander poliment de s'arreter et elle doit cooperer. C'est comme demander a un collegue de partir d'une reunion: vous envoyez le signal, mais il decide quand il quitte.

```rust
// Le Token c'est comme envoyer un message "la reunion est finie"
token.cancel();

// La tache doit VERIFIER si elle doit partir
select! {
    _ = token.cancelled() => return,  // "Ok je pars"
    _ = important_work => {},          // "Attends je finis ca"
}
```

#### MEME : "Y U No Drop?" - Le Permit Stocke

```
         ┌─────────────┐
         │   Y U NO    │
         │             │
         │  DROP THE   │
         │   PERMIT?   │
         └─────────────┘
              │
              ▼
        permits.push(permit);  // NOOOOO!
```

Un permit de semaphore DOIT etre drop pour etre libere. Si vous le stockez dans un Vec... il ne sera jamais libere, et votre semaphore est bloque.

### 5.9 Applications pratiques

| Application | Utilisation |
|-------------|-------------|
| **Web Server** | Semaphore pour limiter les connexions simultanees |
| **API Gateway** | Rate limiting avec Semaphore |
| **Job Queue** | Channels mpsc pour distribuer le travail |
| **Live Dashboard** | broadcast pour pousser les updates a tous les clients |
| **Request/Response** | oneshot pour obtenir la reponse d'un worker |
| **Config Hot Reload** | watch pour propager les changements de config |
| **Graceful Shutdown** | CancellationToken pour arreter proprement |

---

## 6. PIEGES - RECAPITULATIF

| Piege | Description | Solution |
|-------|-------------|----------|
| Semaphore(0) | Bloque toutes les taches | Utiliser max_concurrent > 0 |
| Token non clone | cancel() n'affecte pas les taches | Cloner le meme token |
| std::sync::Mutex avec await | Bloque le worker thread | Utiliser tokio::sync::Mutex |
| select! biased | Premier branch toujours favorise | Utiliser sans biased ou savoir pourquoi |
| Permit non drop | Semaphore se vide | Laisser le permit se drop automatiquement |
| timeout ignore | Pas d'erreur en cas de timeout | Propager l'erreur Timeout |

---

## 7. QCM

### Question 1
Quelle est la difference entre `std::sync::Mutex` et `tokio::sync::Mutex`?

A) Aucune difference, ils sont interchangeables
B) `tokio::sync::Mutex` est plus rapide
C) `tokio::sync::Mutex` peut etre tenu a travers des `.await` sans bloquer le thread
D) `std::sync::Mutex` est async, `tokio::sync::Mutex` est sync
E) `tokio::sync::Mutex` ne supporte pas le poisoning
F) `std::sync::Mutex` est deprecated
G) `tokio::sync::Mutex` utilise spinlock
H) `std::sync::Mutex` ne peut pas etre dans un Arc
I) `tokio::sync::Mutex` est pour les cas mono-thread uniquement
J) `std::sync::Mutex` est uniquement pour les variables globales

**Reponse : C**

### Question 2
Que se passe-t-il si vous creez un `Semaphore::new(0)`?

A) Il a une capacite illimitee
B) Il refuse toutes les acquisitions immediatement
C) Toutes les taches qui tentent d'acquerir un permit attendent indefiniment
D) Il panique a la creation
E) Il se comporte comme un Mutex
F) Il autorise exactement 1 permit
G) C'est equivalent a bounded(0) (rendezvous)
H) Il retourne toujours Err
I) Il cree un semaphore avec INT_MAX permits
J) Il fonctionne normalement

**Reponse : C**

### Question 3
Dans `tokio::select!`, que se passe-t-il avec les futures non selectionnees?

A) Elles continuent en arriere-plan
B) Elles sont mises en pause
C) Elles sont droppees (annulees)
D) Elles sont mises dans une queue
E) Elles retournent None
F) Elles paniquent
G) Elles sont converties en threads
H) Elles sont executees sequentiellement apres
I) Rien, elles attendent le prochain select
J) Elles sont movees vers un autre runtime

**Reponse : C**

### Question 4
Quel est le but de `FuturesUnordered`?

A) Trier les futures par priorite
B) Executer les futures dans un ordre aleatoire
C) Collecter les resultats dans l'ordre de completion
D) Garantir l'ordre FIFO des resultats
E) Optimiser la memoire des futures
F) Permettre l'ajout dynamique de futures pendant l'execution
G) C et F sont correctes
H) Paralleliser les futures sur plusieurs threads
I) Serialiser les futures en JSON
J) Annuler toutes les futures en une fois

**Reponse : G**

### Question 5
Comment fonctionne le `CancellationToken`?

A) Il tue immediatement les taches
B) Il envoie un signal SIGTERM aux taches
C) Il permet une annulation cooperative - les taches doivent verifier
D) Il droppe toutes les futures associees
E) Il panique toutes les taches
F) Il bloque jusqu'a ce que toutes les taches s'arretent
G) Il fonctionne comme Ctrl+C
H) Il utilise des threads pour interrompre
I) Il est verifie automatiquement a chaque await
J) Il transforme les erreurs en Ok

**Reponse : C**

### Question 6
Quelle est la difference entre `broadcast` et `mpsc`?

A) broadcast est plus rapide
B) broadcast permet plusieurs recepteurs, mpsc un seul
C) mpsc est async, broadcast est sync
D) broadcast garantit l'ordre, mpsc non
E) mpsc est bounded, broadcast est unbounded
F) broadcast est pour les strings uniquement
G) mpsc peut avoir plusieurs emetteurs, broadcast un seul
H) Il n'y a pas de difference
I) broadcast necessite Clone sur T, mpsc non
J) B et I sont correctes

**Reponse : J**

### Question 7
Que fait `select! { biased; ... }`?

A) Randomise l'ordre des branches
B) Donne priorite aux branches dans l'ordre de declaration
C) Optimise les performances
D) Permet des branches avec des types differents
E) Active le mode debug
F) Garantit l'equite entre les branches
G) Permet plus de branches que sans biased
H) Desactive l'annulation des futures non selectionnees
I) Rend le select deterministe
J) B et I sont correctes

**Reponse : J**

### Question 8
Comment obtenir un permit de Semaphore et etre sur qu'il sera libere?

A) Appeler release() manuellement
B) Utiliser drop(permit) explicitement
C) Laisser le permit sortir du scope (drop automatique)
D) Appeler sem.add_permits(1)
E) Utiliser try_acquire au lieu de acquire
F) Stocker le permit dans un Arc
G) Utiliser mem::forget sur le permit
H) C est la methode recommandee
I) Appeler permit.forget()
J) Utiliser un wrapper RAII custom

**Reponse : H**

### Question 9
Quel channel utiliser pour une requete/reponse unique?

A) mpsc
B) broadcast
C) watch
D) oneshot
E) unbounded
F) rendezvous
G) bounded(1)
H) Mutex avec Condvar
I) Semaphore
J) RwLock

**Reponse : D**

### Question 10
Pourquoi `tokio::spawn` requiert `'static` sur la closure?

A) Pour des raisons de performance
B) La tache peut survivre a la fonction qui l'a creee
C) C'est un bug de Tokio
D) Pour eviter les fuites memoire
E) Pour permettre le Send
F) Pour le work-stealing
G) C'est optionnel avec #[allow]
H) Pour la compatibilite avec std::thread
I) Pour eviter les cycles de references
J) B est la raison principale

**Reponse : J**

---

## 8. RECAPITULATIF

| Aspect | Valeur |
|--------|--------|
| **Concept principal** | Orchestration de taches async avec limites et cancellation |
| **Prerequis** | async/await, tokio basics, Arc, ownership |
| **Difficulte** | 7/10 |
| **Temps estime** | 180 min |
| **Points cles** | Semaphore, CancellationToken, FuturesUnordered, Channels |

**Competences acquises:**
- Limiter la concurrence avec Semaphore
- Implementer une cancellation cooperative
- Collecter des resultats dans l'ordre de completion
- Utiliser les channels async appropriees

---

## 9. DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "2.4.15-synth-async-orchestrator",
    "generated_at": "2026-01-17 10:00:00",

    "metadata": {
      "exercise_id": "2.4.15-synth",
      "exercise_name": "async_orchestrator",
      "module": "2.4.15",
      "module_name": "Synchronisation Async Avancee",
      "concept": "synth",
      "concept_name": "Synthese Async",
      "type": "complet",
      "tier": 3,
      "tier_info": "Synthese",
      "phase": 2,
      "difficulty": 7,
      "difficulty_stars": "★★★★★★★☆☆☆",
      "language": "rust",
      "duration_minutes": 180,
      "xp_base": 350,
      "xp_bonus_multiplier": 4,
      "bonus_tier": "EXPERT",
      "bonus_icon": "💀",
      "complexity_time": "T3 O(n)",
      "complexity_space": "S2 O(n)",
      "prerequisites": ["async/await", "tokio", "Arc"],
      "domains": ["Process", "Net", "Struct"],
      "domains_bonus": ["DP"],
      "tags": ["async", "tokio", "semaphore", "channels", "cancellation"],
      "meme_reference": "The Matrix Reloaded"
    },

    "files": {
      "spec.json": "/* Section 4.9 */",
      "references/ref_solution.rs": "/* Section 4.3 */",
      "references/ref_solution_bonus.rs": "/* Section 4.6 */",
      "alternatives/alt_mpsc.rs": "/* Section 4.4 */",
      "mutants/mutant_a_boundary.rs": "/* Section 4.10 */",
      "mutants/mutant_b_safety.rs": "/* Section 4.10 */",
      "mutants/mutant_c_resource.rs": "/* Section 4.10 */",
      "mutants/mutant_d_logic.rs": "/* Section 4.10 */",
      "mutants/mutant_e_return.rs": "/* Section 4.10 */",
      "tests/main.rs": "/* Section 4.2 */"
    },

    "validation": {
      "expected_pass": [
        "references/ref_solution.rs",
        "references/ref_solution_bonus.rs",
        "alternatives/alt_mpsc.rs"
      ],
      "expected_fail": [
        "mutants/mutant_a_boundary.rs",
        "mutants/mutant_b_safety.rs",
        "mutants/mutant_c_resource.rs",
        "mutants/mutant_d_logic.rs",
        "mutants/mutant_e_return.rs"
      ]
    },

    "commands": {
      "validate_spec": "python3 hackbrain_engine_v22.py --validate-spec spec.json",
      "test_reference": "cargo test --release",
      "test_mutants": "python3 hackbrain_mutation_tester.py -r references/ref_solution.rs -s spec.json --validate"
    }
  }
}
```
