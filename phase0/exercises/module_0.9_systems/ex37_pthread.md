# Exercice 0.9.37 : pthread_master

**Module :**
0.9 — Systems Programming

**Concept :**
pthread_create, pthread_join, mutex, threads in C

**Difficulte :**
6/10

**Type :**
code

**Tiers :**
2 — Multi-concepts

**Langage :**
C (c17)

**Prerequis :**
- Syntaxe C de base
- Pointeurs et memoire
- Notion de concurrence

**Domaines :**
Thread, Unix, Sync

**Duree estimee :**
75 min

**XP Base :**
180

**Complexite :**
T2 O(n) x S2 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `pthread_utils.c`, `pthread_utils.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | `pthread_create`, `pthread_join`, `pthread_detach`, `pthread_self`, `pthread_mutex_init`, `pthread_mutex_lock`, `pthread_mutex_unlock`, `pthread_mutex_destroy`, `pthread_cond_init`, `pthread_cond_wait`, `pthread_cond_signal`, `pthread_cond_broadcast`, `pthread_cond_destroy`, `malloc`, `free` |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| C | `fork` (on fait du threading, pas du multiprocessing !) |

---

### 1.2 Consigne

#### Section Culture : "The Army of Clones"

**STAR WARS - "This is where the fun begins... with pthreads"**

Comme l'armee de clones qui execute des taches en parallele sous un commandement unifie, les pthreads sont des unites d'execution qui partagent le meme espace memoire. Mais attention : sans synchronisation, c'est Order 66 - le chaos total !

*"I have waited a long time for this moment, my little green thread."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une bibliotheque de threading avec pool de threads :

1. **thread_create** : Cree un thread avec une fonction
2. **thread_join** : Attend la fin d'un thread
3. **mutex_lock/unlock** : Synchronisation basique
4. **thread_pool** : Pool de threads reutilisables

**Entree (C) :**

```c
#ifndef PTHREAD_UTILS_H
# define PTHREAD_UTILS_H

# include <pthread.h>
# include <stddef.h>

// Type pour les fonctions de thread
typedef void *(*thread_func_t)(void *arg);

// Structure de thread wrapper
typedef struct s_thread {
    pthread_t       handle;
    thread_func_t   func;
    void            *arg;
    void            *result;
    int             joined;
} t_thread;

// Cree et demarre un thread
// Retourne NULL en cas d'erreur
t_thread *thread_create(thread_func_t func, void *arg);

// Attend la fin du thread et recupere le resultat
// Retourne 0 en cas de succes, -1 en cas d'erreur
int thread_join(t_thread *thread, void **result);

// Detache un thread (ne peut plus etre join)
int thread_detach(t_thread *thread);

// Libere les ressources du thread
void thread_destroy(t_thread *thread);

// Structure de mutex wrapper
typedef struct s_mutex {
    pthread_mutex_t handle;
    int             initialized;
} t_mutex;

t_mutex *mutex_create(void);
int mutex_lock(t_mutex *mutex);
int mutex_unlock(t_mutex *mutex);
void mutex_destroy(t_mutex *mutex);

// Thread pool
typedef struct s_thread_pool t_thread_pool;

t_thread_pool *pool_create(size_t num_threads);
int pool_submit(t_thread_pool *pool, thread_func_t func, void *arg);
void pool_wait(t_thread_pool *pool);
void pool_destroy(t_thread_pool *pool);

#endif
```

**Sortie :**
- `thread_create` : Pointeur vers t_thread ou NULL
- `thread_join` : 0 succes, -1 erreur
- `pool_submit` : 0 si tache acceptee, -1 si pool plein/erreur

**Contraintes :**
- Pas de data races (utiliser mutex)
- Pas de deadlocks
- Liberer toutes les ressources
- Le pool doit reutiliser les threads (pas creer/detruire a chaque tache)

**Exemples :**

| Operation | Input | Output | Explication |
|-----------|-------|--------|-------------|
| `thread_create(add_one, &val)` | val=41 | result=42 | Thread execute add_one |
| `mutex_lock(m); counter++; mutex_unlock(m)` | - | Atomique | Pas de race |
| `pool_submit(p, task, arg)` x 100 | - | All done | Pool execute 100 taches |

---

### 1.3 Prototype

**C :**
```c
#include <pthread.h>

typedef void *(*thread_func_t)(void *arg);

typedef struct s_thread {
    pthread_t       handle;
    thread_func_t   func;
    void            *arg;
    void            *result;
    int             joined;
} t_thread;

t_thread *thread_create(thread_func_t func, void *arg);
int thread_join(t_thread *thread, void **result);
int thread_detach(t_thread *thread);
void thread_destroy(t_thread *thread);
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Thread vs Process :**

| Aspect | Thread | Process |
|--------|--------|---------|
| Memoire | Partagee | Separee |
| Creation | Rapide (~10us) | Lent (~1ms) |
| Contexte | Leger | Lourd |
| Communication | Variables partagees | IPC (pipes, sockets) |
| Crash | Tue tout le processus | Isole |

**Le cout d'un mutex lock**

Un mutex non-conteste coute environ 25 nanosecondes sur un CPU moderne. Mais un mutex conteste peut couter plusieurs microsecondes a cause du context switch !

**pthread_create limite**

Sur Linux, le nombre max de threads par processus est limite par `/proc/sys/kernel/threads-max` (souvent ~30000) et la stack par thread (8MB par defaut).

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Game Developer** | Threads pour physics, render, audio |
| **Web Server Developer** | Thread pool pour connections HTTP |
| **Scientific Computing** | Parallelisation de calculs |
| **Database Developer** | Threads pour queries concurrentes |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cat main.c
#include "pthread_utils.h"
#include <stdio.h>

void *increment(void *arg) {
    int *val = (int *)arg;
    (*val)++;
    return arg;
}

t_mutex *g_mutex;
int g_counter = 0;

void *safe_increment(void *arg) {
    (void)arg;
    for (int i = 0; i < 100000; i++) {
        mutex_lock(g_mutex);
        g_counter++;
        mutex_unlock(g_mutex);
    }
    return NULL;
}

int main(void) {
    // Basic thread test
    int value = 41;
    t_thread *t = thread_create(increment, &value);
    void *result;
    thread_join(t, &result);
    printf("Result: %d\n", *(int *)result); // 42
    thread_destroy(t);

    // Mutex test with multiple threads
    g_mutex = mutex_create();
    t_thread *threads[10];

    for (int i = 0; i < 10; i++) {
        threads[i] = thread_create(safe_increment, NULL);
    }

    for (int i = 0; i < 10; i++) {
        thread_join(threads[i], NULL);
        thread_destroy(threads[i]);
    }

    printf("Counter: %d (expected: 1000000)\n", g_counter);
    mutex_destroy(g_mutex);

    return 0;
}

$ gcc -Wall -Wextra -Werror -pthread pthread_utils.c main.c -o test
$ ./test
Result: 42
Counter: 1000000 (expected: 1000000)
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
7/10

**Recompense :**
XP x2.5

**Consigne Bonus :**

Implementer un thread pool complet avec queue de taches :

```c
typedef struct s_task {
    thread_func_t   func;
    void            *arg;
    struct s_task   *next;
} t_task;

typedef struct s_thread_pool {
    pthread_t       *threads;
    size_t          num_threads;
    t_task          *task_head;
    t_task          *task_tail;
    pthread_mutex_t queue_mutex;
    pthread_cond_t  queue_cond;
    int             shutdown;
} t_thread_pool;

// Les threads du pool attendent des taches avec pthread_cond_wait
// pool_submit ajoute a la queue et signal avec pthread_cond_signal
// pool_destroy signal tous les threads et attend leur terminaison
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | create_basic | Simple func | Thread runs | 10 | Basic |
| 2 | join_result | Return value | Value retrieved | 10 | Join |
| 3 | mutex_basic | Lock/unlock | No crash | 10 | Mutex |
| 4 | race_protected | 10 threads, mutex | Correct count | 15 | Sync |
| 5 | race_unprotected | 10 threads, no mutex | Wrong count | 5 | Verify |
| 6 | detach | Detached thread | No zombie | 10 | Detach |
| 7 | pool_basic | 4 threads, 100 tasks | All complete | 15 | Pool |
| 8 | pool_stress | 1000 tasks | All complete | 10 | Pool |
| 9 | no_leak | Valgrind | No leaks | 10 | Memory |
| 10 | no_deadlock | Complex lock | Completes | 5 | Safety |

**Total : 100 points**

---

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "pthread_utils.h"

void *simple_task(void *arg) {
    int *val = (int *)arg;
    return (void *)(long)(*val * 2);
}

void test_basic_thread(void) {
    int val = 21;
    t_thread *t = thread_create(simple_task, &val);
    assert(t != NULL);

    void *result;
    assert(thread_join(t, &result) == 0);
    assert((long)result == 42);

    thread_destroy(t);
    printf("Test basic_thread: OK\n");
}

static t_mutex *test_mutex;
static int test_counter = 0;

void *counter_task(void *arg) {
    (void)arg;
    for (int i = 0; i < 10000; i++) {
        mutex_lock(test_mutex);
        test_counter++;
        mutex_unlock(test_mutex);
    }
    return NULL;
}

void test_mutex_sync(void) {
    test_mutex = mutex_create();
    test_counter = 0;

    t_thread *threads[10];
    for (int i = 0; i < 10; i++) {
        threads[i] = thread_create(counter_task, NULL);
    }

    for (int i = 0; i < 10; i++) {
        thread_join(threads[i], NULL);
        thread_destroy(threads[i]);
    }

    assert(test_counter == 100000);
    mutex_destroy(test_mutex);
    printf("Test mutex_sync: OK\n");
}

void test_thread_pool(void) {
    t_thread_pool *pool = pool_create(4);
    assert(pool != NULL);

    static int values[100];
    for (int i = 0; i < 100; i++) {
        values[i] = i;
        pool_submit(pool, simple_task, &values[i]);
    }

    pool_wait(pool);
    pool_destroy(pool);
    printf("Test thread_pool: OK\n");
}

int main(void) {
    test_basic_thread();
    test_mutex_sync();
    test_thread_pool();

    printf("\nAll tests passed!\n");
    return 0;
}
```

---

### 4.3 Solution de reference (C)

```c
#include "pthread_utils.h"
#include <stdlib.h>
#include <string.h>

// Thread wrapper implementation
t_thread *thread_create(thread_func_t func, void *arg) {
    t_thread *thread = malloc(sizeof(t_thread));
    if (!thread) {
        return NULL;
    }

    thread->func = func;
    thread->arg = arg;
    thread->result = NULL;
    thread->joined = 0;

    if (pthread_create(&thread->handle, NULL, func, arg) != 0) {
        free(thread);
        return NULL;
    }

    return thread;
}

int thread_join(t_thread *thread, void **result) {
    if (!thread || thread->joined) {
        return -1;
    }

    void *thread_result;
    if (pthread_join(thread->handle, &thread_result) != 0) {
        return -1;
    }

    thread->result = thread_result;
    thread->joined = 1;

    if (result) {
        *result = thread_result;
    }

    return 0;
}

int thread_detach(t_thread *thread) {
    if (!thread || thread->joined) {
        return -1;
    }
    return pthread_detach(thread->handle);
}

void thread_destroy(t_thread *thread) {
    if (thread) {
        free(thread);
    }
}

// Mutex implementation
t_mutex *mutex_create(void) {
    t_mutex *mutex = malloc(sizeof(t_mutex));
    if (!mutex) {
        return NULL;
    }

    if (pthread_mutex_init(&mutex->handle, NULL) != 0) {
        free(mutex);
        return NULL;
    }

    mutex->initialized = 1;
    return mutex;
}

int mutex_lock(t_mutex *mutex) {
    if (!mutex || !mutex->initialized) {
        return -1;
    }
    return pthread_mutex_lock(&mutex->handle);
}

int mutex_unlock(t_mutex *mutex) {
    if (!mutex || !mutex->initialized) {
        return -1;
    }
    return pthread_mutex_unlock(&mutex->handle);
}

void mutex_destroy(t_mutex *mutex) {
    if (mutex) {
        if (mutex->initialized) {
            pthread_mutex_destroy(&mutex->handle);
        }
        free(mutex);
    }
}

// Thread pool implementation
typedef struct s_task {
    thread_func_t   func;
    void            *arg;
    struct s_task   *next;
} t_task;

struct s_thread_pool {
    pthread_t       *threads;
    size_t          num_threads;
    t_task          *task_head;
    t_task          *task_tail;
    pthread_mutex_t queue_mutex;
    pthread_cond_t  queue_cond;
    int             shutdown;
    size_t          pending_tasks;
    pthread_cond_t  done_cond;
};

static void *pool_worker(void *arg) {
    t_thread_pool *pool = (t_thread_pool *)arg;

    while (1) {
        pthread_mutex_lock(&pool->queue_mutex);

        while (pool->task_head == NULL && !pool->shutdown) {
            pthread_cond_wait(&pool->queue_cond, &pool->queue_mutex);
        }

        if (pool->shutdown && pool->task_head == NULL) {
            pthread_mutex_unlock(&pool->queue_mutex);
            break;
        }

        // Get task from queue
        t_task *task = pool->task_head;
        pool->task_head = task->next;
        if (pool->task_head == NULL) {
            pool->task_tail = NULL;
        }

        pthread_mutex_unlock(&pool->queue_mutex);

        // Execute task
        task->func(task->arg);
        free(task);

        // Signal completion
        pthread_mutex_lock(&pool->queue_mutex);
        pool->pending_tasks--;
        if (pool->pending_tasks == 0) {
            pthread_cond_broadcast(&pool->done_cond);
        }
        pthread_mutex_unlock(&pool->queue_mutex);
    }

    return NULL;
}

t_thread_pool *pool_create(size_t num_threads) {
    t_thread_pool *pool = malloc(sizeof(t_thread_pool));
    if (!pool) return NULL;

    pool->threads = malloc(sizeof(pthread_t) * num_threads);
    if (!pool->threads) {
        free(pool);
        return NULL;
    }

    pool->num_threads = num_threads;
    pool->task_head = NULL;
    pool->task_tail = NULL;
    pool->shutdown = 0;
    pool->pending_tasks = 0;

    pthread_mutex_init(&pool->queue_mutex, NULL);
    pthread_cond_init(&pool->queue_cond, NULL);
    pthread_cond_init(&pool->done_cond, NULL);

    for (size_t i = 0; i < num_threads; i++) {
        pthread_create(&pool->threads[i], NULL, pool_worker, pool);
    }

    return pool;
}

int pool_submit(t_thread_pool *pool, thread_func_t func, void *arg) {
    if (!pool || pool->shutdown) return -1;

    t_task *task = malloc(sizeof(t_task));
    if (!task) return -1;

    task->func = func;
    task->arg = arg;
    task->next = NULL;

    pthread_mutex_lock(&pool->queue_mutex);

    if (pool->task_tail) {
        pool->task_tail->next = task;
    } else {
        pool->task_head = task;
    }
    pool->task_tail = task;
    pool->pending_tasks++;

    pthread_cond_signal(&pool->queue_cond);
    pthread_mutex_unlock(&pool->queue_mutex);

    return 0;
}

void pool_wait(t_thread_pool *pool) {
    pthread_mutex_lock(&pool->queue_mutex);
    while (pool->pending_tasks > 0) {
        pthread_cond_wait(&pool->done_cond, &pool->queue_mutex);
    }
    pthread_mutex_unlock(&pool->queue_mutex);
}

void pool_destroy(t_thread_pool *pool) {
    if (!pool) return;

    pthread_mutex_lock(&pool->queue_mutex);
    pool->shutdown = 1;
    pthread_cond_broadcast(&pool->queue_cond);
    pthread_mutex_unlock(&pool->queue_mutex);

    for (size_t i = 0; i < pool->num_threads; i++) {
        pthread_join(pool->threads[i], NULL);
    }

    // Free remaining tasks
    t_task *task = pool->task_head;
    while (task) {
        t_task *next = task->next;
        free(task);
        task = next;
    }

    pthread_mutex_destroy(&pool->queue_mutex);
    pthread_cond_destroy(&pool->queue_cond);
    pthread_cond_destroy(&pool->done_cond);
    free(pool->threads);
    free(pool);
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Race) : Pas de mutex sur counter**

```c
/* Mutant A (Race) : Data race sur counter */
void *bad_increment(void *arg) {
    int *counter = (int *)arg;
    for (int i = 0; i < 100000; i++) {
        (*counter)++; // Data race !
    }
    return NULL;
}
// Pourquoi c'est faux : Resultat non-deterministe a cause du data race
```

**Mutant B (Deadlock) : Double lock**

```c
/* Mutant B (Deadlock) : Self-deadlock */
void bad_nested(t_mutex *m) {
    mutex_lock(m);
    // ... some code ...
    mutex_lock(m); // DEADLOCK: deja lock par ce thread !
    mutex_unlock(m);
    mutex_unlock(m);
}
// Pourquoi c'est faux : Un mutex non-recursif ne peut pas etre lock deux fois
```

**Mutant C (Resource) : Pas de pthread_join**

```c
/* Mutant C (Resource) : Thread leak */
void create_thread_leak(void) {
    t_thread *t = thread_create(some_func, NULL);
    // OUBLI: thread_join(t, NULL);
    // OUBLI: thread_destroy(t);
    // Le thread devient "perdu"
}
// Pourquoi c'est faux : Fuite de ressources thread
```

**Mutant D (Logic) : Signal avant unlock**

```c
/* Mutant D (Logic) : Signal sans donnees */
int bad_pool_submit(t_thread_pool *pool, thread_func_t func, void *arg) {
    pthread_cond_signal(&pool->queue_cond); // Signal AVANT d'ajouter !

    pthread_mutex_lock(&pool->queue_mutex);
    // ... add task ...
    pthread_mutex_unlock(&pool->queue_mutex);
    return 0;
}
// Pourquoi c'est faux : Le worker peut se reveiller et ne rien trouver
```

**Mutant E (Return) : Mauvais check d'erreur**

```c
/* Mutant E (Return) : Ignore l'erreur de pthread_create */
t_thread *bad_create(thread_func_t func, void *arg) {
    t_thread *thread = malloc(sizeof(t_thread));
    pthread_create(&thread->handle, NULL, func, arg);
    // OUBLI: verifier le retour de pthread_create !
    return thread; // Peut retourner un thread invalide
}
// Pourquoi c'est faux : Si pthread_create echoue, le thread est invalide
```

---

## SECTION 5 : COMPRENDRE

### 5.3 Visualisation ASCII

```
Thread vs Process Memory
========================

Process 1                    Process 2
┌────────────────────┐      ┌────────────────────┐
│ ┌────────────────┐ │      │ ┌────────────────┐ │
│ │    Code        │ │      │ │    Code        │ │
│ ├────────────────┤ │      │ ├────────────────┤ │
│ │    Heap        │ │      │ │    Heap        │ │
│ ├────────────────┤ │      │ ├────────────────┤ │
│ │    Data        │ │      │ │    Data        │ │
│ ├────────────────┤ │      │ ├────────────────┤ │
│ │   Stack T1     │ │      │ │   Stack        │ │
│ ├────────────────┤ │      └────────────────────┘
│ │   Stack T2     │ │        Memoire SEPAREE
│ └────────────────┘ │
└────────────────────┘
  Heap/Data PARTAGES


Thread Pool Pattern
===================

    Main Thread                 Worker Threads
         │                    ┌───┐┌───┐┌───┐┌───┐
         │                    │ W1││ W2││ W3││ W4│
         │                    └─┬─┘└─┬─┘└─┬─┘└─┬─┘
         │                      │    │    │    │
    pool_submit()──────►┌───────────────────────────┐
         │              │       Task Queue          │
         │              │  ┌──┬──┬──┬──┬──┬──┐     │
         │              │  │T1│T2│T3│T4│T5│T6│     │
         │              │  └──┴──┴──┴──┴──┴──┘     │
         │              └───────────────────────────┘
         │                      │    │    │    │
         │               cond_wait  cond_wait  ...
         │                      │    │    │    │
    pool_wait()◄────────────────┴────┴────┴────┘
         │                    All done signal
         ▼
```

---

## SECTION 6 : PIEGES - RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Data race | Resultat aleatoire | Mutex |
| 2 | Deadlock | Programme bloque | Ordre de lock |
| 3 | Thread leak | Fuite ressources | Join ou detach |
| 4 | Signal sans data | Race condition | Signal apres add |
| 5 | Spurious wakeup | Logic error | while loop sur cond |

---

## SECTION 7 : QCM

### Question 1 (4 points)
Qu'est-ce qu'un data race ?

- A) Une course entre deux programmes
- B) Acces concurrent non-synchronise a une variable partagee
- C) Un thread qui va trop vite
- D) Une erreur de compilation

**Reponse : B** - Un data race est un acces concurrent sans synchronisation.

### Question 2 (3 points)
Pourquoi utiliser while() au lieu de if() avec pthread_cond_wait ?

- A) C'est plus rapide
- B) Pour gerer les spurious wakeups
- C) if() ne compile pas
- D) C'est une convention

**Reponse : B** - pthread_cond_wait peut se reveiller sans signal (spurious wakeup).

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.9.37 |
| **Nom** | pthread_master |
| **Difficulte** | 6/10 |
| **Duree** | 75 min |
| **XP Base** | 180 |
| **Langage** | C (c17) |
| **Concepts cles** | pthread, mutex, cond, pool |

---

*Document genere selon HACKBRAIN v5.5.2*
