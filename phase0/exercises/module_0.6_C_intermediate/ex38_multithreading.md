# Exercice 0.6.15-a : multithreading

**Module :**
0.6.15 — Programmation Concurrente

**Concept :**
a-c — pthread_create, mutex, race conditions

**Difficulte :**
★★★★★★★☆☆☆ (7/10)

**Type :**
code

**Tiers :**
3 — Integration avancee

**Langage :**
C17

**Prerequis :**
0.6.1 (malloc), 0.6.10 (error handling), pointeurs de fonctions

**Domaines :**
Concurrence, Threads, Synchronisation

**Duree estimee :**
360 min

**XP Base :**
500

**Complexite :**
T1 O(n/p) avec p threads x S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `multithreading.c`
- `multithreading.h`

**Headers autorises :**
- `<stdio.h>`, `<stdlib.h>`, `<pthread.h>`, `<stdbool.h>`, `<unistd.h>`

**Fonctions autorisees :**
- `pthread_create()`, `pthread_join()`, `pthread_exit()`
- `pthread_mutex_init()`, `pthread_mutex_lock()`, `pthread_mutex_unlock()`, `pthread_mutex_destroy()`
- `malloc()`, `free()`, `printf()`, `usleep()`

### 1.2 Consigne

Implementer des patterns de programmation multithread securises avec gestion des race conditions.

**Ta mission :**

Creer des fonctions utilisant les threads POSIX (pthreads) avec une synchronisation correcte pour eviter les race conditions.

**Prototypes :**
```c
// Structure pour compteur thread-safe
typedef struct {
    int value;
    pthread_mutex_t mutex;
} safe_counter_t;

// Initialise un compteur thread-safe
int safe_counter_init(safe_counter_t *counter, int initial);

// Incremente le compteur de maniere thread-safe
int safe_counter_increment(safe_counter_t *counter);

// Decremente le compteur de maniere thread-safe
int safe_counter_decrement(safe_counter_t *counter);

// Retourne la valeur actuelle
int safe_counter_get(safe_counter_t *counter);

// Detruit le compteur (libere le mutex)
void safe_counter_destroy(safe_counter_t *counter);

// Structure pour travail parallele
typedef struct {
    void *data;
    size_t start;
    size_t end;
    void (*process)(void *item);
} thread_work_t;

// Execute une fonction sur chaque element d'un tableau en parallele
// arr: tableau de pointeurs void*
// count: nombre d'elements
// num_threads: nombre de threads a utiliser
// process: fonction a appliquer a chaque element
int parallel_foreach(void **arr, size_t count, int num_threads,
                     void (*process)(void *item));

// Calcule la somme d'un tableau d'entiers en parallele
long parallel_sum(int *arr, size_t count, int num_threads);

// Structure pour producteur-consommateur
typedef struct {
    int *buffer;
    size_t size;
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t mutex;
    pthread_cond_t not_full;
    pthread_cond_t not_empty;
} bounded_buffer_t;

// Initialise un buffer borne
int buffer_init(bounded_buffer_t *buf, size_t size);

// Ajoute un element (bloque si plein)
int buffer_put(bounded_buffer_t *buf, int item);

// Retire un element (bloque si vide)
int buffer_get(bounded_buffer_t *buf, int *item);

// Detruit le buffer
void buffer_destroy(bounded_buffer_t *buf);
```

**Comportement :**
- `safe_counter_*` doit etre utilisable par plusieurs threads simultanement
- `parallel_foreach` divise le travail equitablement entre les threads
- `parallel_sum` retourne la somme correcte meme avec plusieurs threads
- `buffer_*` implemente un buffer circulaire thread-safe

**Exemples :**
```c
// Compteur thread-safe
safe_counter_t counter;
safe_counter_init(&counter, 0);
// 10 threads incrementent 1000 fois chacun
// Resultat final: exactement 10000

// Somme parallele
int arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
long sum = parallel_sum(arr, 10, 4);  // sum = 55

// Buffer borne
bounded_buffer_t buf;
buffer_init(&buf, 5);
buffer_put(&buf, 42);
int item;
buffer_get(&buf, &item);  // item = 42
```

**Contraintes :**
- Pas de race conditions (utiliser mutex)
- Pas de deadlocks
- Liberer toutes les ressources
- Compiler avec `gcc -Wall -Werror -std=c17 -pthread`

### 1.3 Prototype

```c
// multithreading.h
#ifndef MULTITHREADING_H
#define MULTITHREADING_H

#include <pthread.h>
#include <stddef.h>
#include <stdbool.h>

typedef struct {
    int value;
    pthread_mutex_t mutex;
} safe_counter_t;

int safe_counter_init(safe_counter_t *counter, int initial);
int safe_counter_increment(safe_counter_t *counter);
int safe_counter_decrement(safe_counter_t *counter);
int safe_counter_get(safe_counter_t *counter);
void safe_counter_destroy(safe_counter_t *counter);

int parallel_foreach(void **arr, size_t count, int num_threads,
                     void (*process)(void *item));
long parallel_sum(int *arr, size_t count, int num_threads);

typedef struct {
    int *buffer;
    size_t size;
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t mutex;
    pthread_cond_t not_full;
    pthread_cond_t not_empty;
} bounded_buffer_t;

int buffer_init(bounded_buffer_t *buf, size_t size);
int buffer_put(bounded_buffer_t *buf, int item);
int buffer_get(bounded_buffer_t *buf, int *item);
void buffer_destroy(bounded_buffer_t *buf);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Race Condition

Une race condition se produit quand le resultat depend de l'ordre d'execution des threads:

```c
// DANGER: Race condition!
int counter = 0;

void *increment(void *arg) {
    for (int i = 0; i < 1000000; i++)
        counter++;  // Read-Modify-Write non-atomique!
    return NULL;
}

// Avec 2 threads: resultat imprevisible (pas 2000000)
```

### 2.2 Amdahl's Law

Le speedup maximal avec N processeurs est limite par la partie sequentielle:
```
Speedup = 1 / (S + P/N)
```
- S = fraction sequentielle
- P = fraction parallelisable (P = 1 - S)
- N = nombre de processeurs

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Backend Developer**

Le multithreading est crucial pour:
- Serveurs web (un thread par requete)
- Traitement de files (message queues)
- Calcul parallele (map-reduce)

**Metier : Game Developer**

Applications:
- Rendering (multi-threaded)
- Physics simulation
- Asset loading en background

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -pthread -o test_mt test_main.c multithreading.c
$ ./test_mt
=== Multithreading Tests ===

Testing safe_counter...
  Creating 10 threads, each incrementing 10000 times...
  Expected: 100000
  Got: 100000 - PASS

Testing parallel_sum...
  Array: [1..1000000]
  Sequential sum: 500000500000
  Parallel sum (4 threads): 500000500000 - PASS

Testing parallel_foreach...
  Processing 1000 items with 4 threads...
  All items processed - PASS

Testing bounded_buffer...
  Starting 2 producers and 2 consumers...
  Produced: 1000 items
  Consumed: 1000 items
  Buffer empty at end - PASS

All tests passed!
$ echo $?
0
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★★★☆☆ (8/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Implementer un thread pool pour reutiliser les threads.

```c
typedef struct thread_pool thread_pool_t;

// Cree un pool avec N threads worker
thread_pool_t *thread_pool_create(int num_threads);

// Soumet une tache au pool
int thread_pool_submit(thread_pool_t *pool, void (*fn)(void*), void *arg);

// Attend que toutes les taches soient terminees
int thread_pool_wait(thread_pool_t *pool);

// Detruit le pool
void thread_pool_destroy(thread_pool_t *pool);
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Input | Expected | Points |
|---------|-------------|-------|----------|--------|
| T01 | safe_counter single thread | 1000 incr | 1000 | 10 |
| T02 | safe_counter multi thread | 10 threads x 10000 | 100000 | 20 |
| T03 | parallel_sum correct | [1..100] | 5050 | 15 |
| T04 | parallel_sum large | [1..1000000] | 500000500000 | 10 |
| T05 | parallel_foreach | 100 items | all processed | 15 |
| T06 | buffer single thread | put/get | correct | 10 |
| T07 | buffer producer-consumer | 2P/2C | no loss | 20 |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "multithreading.h"

#define NUM_THREADS 10
#define ITERATIONS 10000

// Thread function for counter test
void *counter_thread(void *arg)
{
    safe_counter_t *counter = (safe_counter_t *)arg;
    for (int i = 0; i < ITERATIONS; i++)
    {
        safe_counter_increment(counter);
    }
    return NULL;
}

// Process function for parallel_foreach test
void process_item(void *item)
{
    int *val = (int *)item;
    *val = *val * 2;
}

int main(void)
{
    int pass = 0, fail = 0;

    printf("=== Multithreading Tests ===\n\n");

    // T01 & T02: safe_counter
    printf("Testing safe_counter...\n");
    safe_counter_t counter;
    safe_counter_init(&counter, 0);

    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_create(&threads[i], NULL, counter_thread, &counter);
    }
    for (int i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], NULL);
    }

    int expected = NUM_THREADS * ITERATIONS;
    int actual = safe_counter_get(&counter);
    printf("  Expected: %d, Got: %d\n", expected, actual);

    if (actual == expected)
    {
        printf("  T02 PASS: safe_counter multi-thread\n");
        pass++;
    }
    else
    {
        printf("  T02 FAIL: race condition detected!\n");
        fail++;
    }
    safe_counter_destroy(&counter);

    // T03 & T04: parallel_sum
    printf("\nTesting parallel_sum...\n");
    int small_arr[100];
    for (int i = 0; i < 100; i++) small_arr[i] = i + 1;
    long sum = parallel_sum(small_arr, 100, 4);
    if (sum == 5050)
    {
        printf("  T03 PASS: parallel_sum [1..100] = %ld\n", sum);
        pass++;
    }
    else
    {
        printf("  T03 FAIL: expected 5050, got %ld\n", sum);
        fail++;
    }

    // T05: parallel_foreach
    printf("\nTesting parallel_foreach...\n");
    int items[100];
    void *ptrs[100];
    for (int i = 0; i < 100; i++)
    {
        items[i] = i + 1;
        ptrs[i] = &items[i];
    }
    parallel_foreach(ptrs, 100, 4, process_item);
    int foreach_ok = 1;
    for (int i = 0; i < 100; i++)
    {
        if (items[i] != (i + 1) * 2)
        {
            foreach_ok = 0;
            break;
        }
    }
    if (foreach_ok)
    {
        printf("  T05 PASS: parallel_foreach\n");
        pass++;
    }
    else
    {
        printf("  T05 FAIL: items not processed correctly\n");
        fail++;
    }

    // T06 & T07: bounded_buffer
    printf("\nTesting bounded_buffer...\n");
    bounded_buffer_t buf;
    buffer_init(&buf, 10);

    // Single thread test
    buffer_put(&buf, 42);
    int item;
    buffer_get(&buf, &item);
    if (item == 42)
    {
        printf("  T06 PASS: single thread put/get\n");
        pass++;
    }
    else
    {
        printf("  T06 FAIL: got %d instead of 42\n", item);
        fail++;
    }

    buffer_destroy(&buf);

    printf("\nResults: %d passed, %d failed\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
```

### 4.3 Solution de reference

```c
/*
 * multithreading.c
 * Programmation concurrente avec pthreads
 * Exercice ex38_multithreading
 */

#include "multithreading.h"
#include <stdlib.h>
#include <stdio.h>

// ==================== SAFE COUNTER ====================

int safe_counter_init(safe_counter_t *counter, int initial)
{
    if (counter == NULL)
        return -1;

    counter->value = initial;
    if (pthread_mutex_init(&counter->mutex, NULL) != 0)
        return -1;

    return 0;
}

int safe_counter_increment(safe_counter_t *counter)
{
    if (counter == NULL)
        return -1;

    pthread_mutex_lock(&counter->mutex);
    counter->value++;
    int val = counter->value;
    pthread_mutex_unlock(&counter->mutex);

    return val;
}

int safe_counter_decrement(safe_counter_t *counter)
{
    if (counter == NULL)
        return -1;

    pthread_mutex_lock(&counter->mutex);
    counter->value--;
    int val = counter->value;
    pthread_mutex_unlock(&counter->mutex);

    return val;
}

int safe_counter_get(safe_counter_t *counter)
{
    if (counter == NULL)
        return 0;

    pthread_mutex_lock(&counter->mutex);
    int val = counter->value;
    pthread_mutex_unlock(&counter->mutex);

    return val;
}

void safe_counter_destroy(safe_counter_t *counter)
{
    if (counter == NULL)
        return;

    pthread_mutex_destroy(&counter->mutex);
}

// ==================== PARALLEL FOREACH ====================

typedef struct {
    void **arr;
    size_t start;
    size_t end;
    void (*process)(void *item);
} foreach_arg_t;

static void *foreach_worker(void *arg)
{
    foreach_arg_t *work = (foreach_arg_t *)arg;

    for (size_t i = work->start; i < work->end; i++)
    {
        work->process(work->arr[i]);
    }

    return NULL;
}

int parallel_foreach(void **arr, size_t count, int num_threads,
                     void (*process)(void *item))
{
    if (arr == NULL || process == NULL || num_threads <= 0)
        return -1;

    if (count == 0)
        return 0;

    // Limiter le nombre de threads
    if ((size_t)num_threads > count)
        num_threads = count;

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    foreach_arg_t *args = malloc(num_threads * sizeof(foreach_arg_t));

    if (threads == NULL || args == NULL)
    {
        free(threads);
        free(args);
        return -1;
    }

    // Diviser le travail
    size_t chunk_size = count / num_threads;
    size_t remainder = count % num_threads;

    size_t start = 0;
    for (int i = 0; i < num_threads; i++)
    {
        args[i].arr = arr;
        args[i].start = start;
        args[i].end = start + chunk_size + (i < (int)remainder ? 1 : 0);
        args[i].process = process;
        start = args[i].end;

        pthread_create(&threads[i], NULL, foreach_worker, &args[i]);
    }

    // Attendre tous les threads
    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
    }

    free(threads);
    free(args);
    return 0;
}

// ==================== PARALLEL SUM ====================

typedef struct {
    int *arr;
    size_t start;
    size_t end;
    long partial_sum;
} sum_arg_t;

static void *sum_worker(void *arg)
{
    sum_arg_t *work = (sum_arg_t *)arg;
    work->partial_sum = 0;

    for (size_t i = work->start; i < work->end; i++)
    {
        work->partial_sum += work->arr[i];
    }

    return NULL;
}

long parallel_sum(int *arr, size_t count, int num_threads)
{
    if (arr == NULL || num_threads <= 0)
        return 0;

    if (count == 0)
        return 0;

    if ((size_t)num_threads > count)
        num_threads = count;

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    sum_arg_t *args = malloc(num_threads * sizeof(sum_arg_t));

    if (threads == NULL || args == NULL)
    {
        free(threads);
        free(args);
        return 0;
    }

    size_t chunk_size = count / num_threads;
    size_t remainder = count % num_threads;

    size_t start = 0;
    for (int i = 0; i < num_threads; i++)
    {
        args[i].arr = arr;
        args[i].start = start;
        args[i].end = start + chunk_size + (i < (int)remainder ? 1 : 0);
        args[i].partial_sum = 0;
        start = args[i].end;

        pthread_create(&threads[i], NULL, sum_worker, &args[i]);
    }

    long total = 0;
    for (int i = 0; i < num_threads; i++)
    {
        pthread_join(threads[i], NULL);
        total += args[i].partial_sum;
    }

    free(threads);
    free(args);
    return total;
}

// ==================== BOUNDED BUFFER ====================

int buffer_init(bounded_buffer_t *buf, size_t size)
{
    if (buf == NULL || size == 0)
        return -1;

    buf->buffer = malloc(size * sizeof(int));
    if (buf->buffer == NULL)
        return -1;

    buf->size = size;
    buf->head = 0;
    buf->tail = 0;
    buf->count = 0;

    pthread_mutex_init(&buf->mutex, NULL);
    pthread_cond_init(&buf->not_full, NULL);
    pthread_cond_init(&buf->not_empty, NULL);

    return 0;
}

int buffer_put(bounded_buffer_t *buf, int item)
{
    if (buf == NULL)
        return -1;

    pthread_mutex_lock(&buf->mutex);

    // Attendre si buffer plein
    while (buf->count == buf->size)
    {
        pthread_cond_wait(&buf->not_full, &buf->mutex);
    }

    // Ajouter l'element
    buf->buffer[buf->tail] = item;
    buf->tail = (buf->tail + 1) % buf->size;
    buf->count++;

    // Signaler qu'il y a des elements
    pthread_cond_signal(&buf->not_empty);

    pthread_mutex_unlock(&buf->mutex);
    return 0;
}

int buffer_get(bounded_buffer_t *buf, int *item)
{
    if (buf == NULL || item == NULL)
        return -1;

    pthread_mutex_lock(&buf->mutex);

    // Attendre si buffer vide
    while (buf->count == 0)
    {
        pthread_cond_wait(&buf->not_empty, &buf->mutex);
    }

    // Retirer l'element
    *item = buf->buffer[buf->head];
    buf->head = (buf->head + 1) % buf->size;
    buf->count--;

    // Signaler qu'il y a de la place
    pthread_cond_signal(&buf->not_full);

    pthread_mutex_unlock(&buf->mutex);
    return 0;
}

void buffer_destroy(bounded_buffer_t *buf)
{
    if (buf == NULL)
        return;

    pthread_mutex_destroy(&buf->mutex);
    pthread_cond_destroy(&buf->not_full);
    pthread_cond_destroy(&buf->not_empty);
    free(buf->buffer);
}
```

### 4.4 Solutions alternatives acceptees

```c
// Alternative 1: Atomics au lieu de mutex pour compteur
#include <stdatomic.h>

typedef struct {
    atomic_int value;
} safe_counter_atomic_t;

int safe_counter_increment(safe_counter_atomic_t *counter)
{
    return atomic_fetch_add(&counter->value, 1) + 1;
}

// Alternative 2: Spinlock au lieu de mutex
// (Acceptable pour sections critiques tres courtes)
```

### 4.5 Solutions refusees (avec explications)

```c
// REFUSE 1: Pas de mutex (race condition)
int safe_counter_increment(safe_counter_t *counter)
{
    counter->value++;  // Race condition!
    return counter->value;
}
// Raison: Read-modify-write non atomique

// REFUSE 2: Unlock avant modification
int safe_counter_increment(safe_counter_t *counter)
{
    pthread_mutex_lock(&counter->mutex);
    pthread_mutex_unlock(&counter->mutex);  // Unlock trop tot!
    counter->value++;
    return counter->value;
}
// Raison: Section critique non protegee

// REFUSE 3: Deadlock potentiel
void transfer(account_t *from, account_t *to, int amount)
{
    pthread_mutex_lock(&from->mutex);
    pthread_mutex_lock(&to->mutex);  // Deadlock si autre thread fait inverse!
    // ...
}
// Raison: Ordre de verrouillage non deterministe
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.15-a",
  "name": "multithreading",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["multithreading.c", "multithreading.h"],
    "test": ["test_multithreading.c"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17", "-pthread"],
    "output": "test_mt"
  },
  "tests": {
    "type": "unit",
    "valgrind": true,
    "helgrind": true,
    "timeout": 30
  },
  "scoring": {
    "total": 100,
    "compilation": 10,
    "functionality": 50,
    "thread_safety": 30,
    "memory_safety": 10
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```c
// MUTANT 1 (Race): Pas de mutex
int safe_counter_increment(safe_counter_t *counter)
{
    counter->value++;  // Race condition!
    return counter->value;
}
// Detection: Valeur finale incorrecte avec multi-threads

// MUTANT 2 (Deadlock): Lock sans unlock
int safe_counter_increment(safe_counter_t *counter)
{
    pthread_mutex_lock(&counter->mutex);
    counter->value++;
    // Manque pthread_mutex_unlock!
    return counter->value;
}
// Detection: Programme bloque au 2eme appel

// MUTANT 3 (Logic): Mauvais calcul de partitionnement
long parallel_sum(int *arr, size_t count, int num_threads)
{
    size_t chunk_size = count / num_threads;
    // Oublie remainder -> elements ignores!
}
// Detection: Somme incorrecte

// MUTANT 4 (Memory): Pas de join (threads zombies)
int parallel_foreach(...)
{
    for (int i = 0; i < num_threads; i++)
        pthread_create(&threads[i], NULL, worker, &args[i]);
    // Manque pthread_join!
    free(threads);
}
// Detection: Crash ou resultats incomplets

// MUTANT 5 (Sync): Signal avant unlock
int buffer_put(bounded_buffer_t *buf, int item)
{
    pthread_mutex_lock(&buf->mutex);
    // ... ajouter element ...
    pthread_cond_signal(&buf->not_empty);  // OK
    pthread_mutex_unlock(&buf->mutex);     // OK
    // Ordre correct, mais si inverse...
}
// Detection: Perte de signal (cas subtil)
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **fondamentaux du multithreading** en C:

1. **pthread_create** - Creer un nouveau thread
2. **mutex** - Exclusion mutuelle pour sections critiques
3. **race conditions** - Comprendre et eviter les bugs de concurrence

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION incrementer_thread_safe(compteur):
DEBUT
    verrouiller(compteur.mutex)

    compteur.valeur <- compteur.valeur + 1
    resultat <- compteur.valeur

    deverrouiller(compteur.mutex)

    RETOURNER resultat
FIN

FONCTION somme_parallele(tableau, taille, nb_threads):
DEBUT
    taille_portion <- taille / nb_threads

    POUR i DE 0 A nb_threads - 1 FAIRE
        creer_thread(worker, tableau, i * taille_portion, (i+1) * taille_portion)
    FIN POUR

    total <- 0
    POUR i DE 0 A nb_threads - 1 FAIRE
        attendre_thread(i)
        total <- total + resultat_partiel[i]
    FIN POUR

    RETOURNER total
FIN
```

### 5.3 Visualisation ASCII

```
CREATION DE THREADS
===================

Thread principal (main)
        |
        | pthread_create()
        +---------------------------+
        |                           |
        v                           v
    [Main thread]              [Worker thread]
        |                           |
        | (continue)                | (execute fn)
        |                           |
        |   pthread_join()          |
        |<--------------------------+
        |
        v
    (continue apres join)


RACE CONDITION
==============

Sans mutex:                    Avec mutex:

Thread A    Thread B           Thread A    Thread B
--------    --------           --------    --------
read(x=0)                      lock()
            read(x=0)                      lock() WAIT
x=0+1                          read(x=0)
            x=0+1              x=0+1
write(1)                       write(1)
            write(1)           unlock()
                                           lock() OK
Resultat: x=1 (FAUX!)                      read(x=1)
                                           x=1+1
                                           write(2)
                                           unlock()
                               Resultat: x=2 (CORRECT!)


BOUNDED BUFFER (Producteur-Consommateur)
========================================

Buffer circulaire:
+---+---+---+---+---+
| 1 | 2 |   |   |   |
+---+---+---+---+---+
  ^       ^
head    tail

put(3):
+---+---+---+---+---+
| 1 | 2 | 3 |   |   |
+---+---+---+---+---+
  ^           ^
head        tail

get() -> 1:
+---+---+---+---+---+
|   | 2 | 3 |   |   |
+---+---+---+---+---+
      ^       ^
    head    tail
```

### 5.4 Les pieges en detail

#### Piege 1: Race condition
```c
// FAUX - Race condition!
int counter = 0;
void *thread_fn(void *arg) {
    for (int i = 0; i < 1000000; i++)
        counter++;  // Pas atomique!
    return NULL;
}

// CORRECT - Avec mutex
pthread_mutex_t mutex;
void *thread_fn(void *arg) {
    for (int i = 0; i < 1000000; i++) {
        pthread_mutex_lock(&mutex);
        counter++;
        pthread_mutex_unlock(&mutex);
    }
    return NULL;
}
```

#### Piege 2: Deadlock
```c
// DANGER - Deadlock possible!
void transfer(account_t *a, account_t *b) {
    pthread_mutex_lock(&a->mutex);
    pthread_mutex_lock(&b->mutex);  // Deadlock si autre thread fait b->a
    // ...
}

// CORRECT - Ordre de verrouillage fixe
void transfer(account_t *a, account_t *b) {
    account_t *first = (a < b) ? a : b;
    account_t *second = (a < b) ? b : a;
    pthread_mutex_lock(&first->mutex);
    pthread_mutex_lock(&second->mutex);
    // ...
}
```

### 5.5 Cours Complet

#### 5.5.1 Creation de threads

```c
#include <pthread.h>

void *thread_function(void *arg) {
    // Code execute par le thread
    return result;
}

pthread_t thread;
pthread_create(&thread, NULL, thread_function, arg);
pthread_join(thread, &result);  // Attendre fin
```

#### 5.5.2 Mutex

```c
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
// ou
pthread_mutex_t mutex;
pthread_mutex_init(&mutex, NULL);

pthread_mutex_lock(&mutex);    // Verrouiller
// Section critique
pthread_mutex_unlock(&mutex);  // Deverrouiller

pthread_mutex_destroy(&mutex);
```

#### 5.5.3 Condition variables

```c
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

// Thread en attente
pthread_mutex_lock(&mutex);
while (!condition)
    pthread_cond_wait(&cond, &mutex);  // Libere mutex et attend
// condition est vraie
pthread_mutex_unlock(&mutex);

// Thread qui signale
pthread_mutex_lock(&mutex);
condition = true;
pthread_cond_signal(&cond);  // Reveille un thread
pthread_mutex_unlock(&mutex);
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| Toujours lock avant acces | Evite race condition | `lock(); x++; unlock();` |
| Unlock dans tous les chemins | Evite deadlock | Attention aux return |
| Join tous les threads | Evite leaks/zombies | `pthread_join()` |
| Ordre de lock fixe | Evite deadlock | Toujours meme ordre |

### 5.7 Simulation avec trace d'execution

```
Programme: safe_counter avec 2 threads, 3 iterations chacun

T1: lock()
T1: value = 0, value++ = 1
T1: unlock()
T2: lock()
T2: value = 1, value++ = 2
T2: unlock()
T1: lock()
T1: value = 2, value++ = 3
T1: unlock()
T2: lock()
T2: value = 3, value++ = 4
T2: unlock()
T1: lock()
T1: value = 4, value++ = 5
T1: unlock()
T2: lock()
T2: value = 5, value++ = 6
T2: unlock()

Resultat final: 6 (correct!)
```

### 5.8 Mnemotechniques

**"CJLD" - Cycle de vie thread**
- **C**reate (pthread_create)
- **J**oin (pthread_join)
- **L**ock (pthread_mutex_lock)
- **D**estroy (pthread_mutex_destroy)

**"LUL" - Pattern mutex**
- **L**ock
- **U**se (section critique)
- un**L**ock

### 5.9 Applications pratiques

1. **Serveurs**: Thread par connexion
2. **Calcul**: Parallelisation de boucles
3. **GUI**: Thread UI + threads background
4. **I/O**: Async avec threads

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Race condition | Resultat imprevisible | Mutex |
| Deadlock | Programme bloque | Ordre de lock fixe |
| Oubli join | Threads zombies | Toujours join |
| Lock sans unlock | Programme bloque | Verifier tous chemins |
| Oubli init/destroy | Undefined behavior | init avant, destroy apres |

---

## SECTION 7 : QCM

### Question 1
Qu'est-ce qu'une race condition ?

A) Un bug de performance
B) Un bug ou le resultat depend de l'ordre d'execution des threads
C) Un deadlock
D) Une erreur de compilation
E) Un memory leak

**Reponse correcte: B**

### Question 2
Que fait pthread_join ?

A) Cree un nouveau thread
B) Detruit un thread
C) Attend la fin d'un thread
D) Verrouille un mutex
E) Envoie un signal

**Reponse correcte: C**

### Question 3
Comment eviter une race condition ?

A) Utiliser plus de threads
B) Utiliser un mutex
C) Utiliser malloc
D) Compiler avec -O2
E) Ajouter des sleep

**Reponse correcte: B**

### Question 4
Qu'est-ce qu'un deadlock ?

A) Un crash
B) Une situation ou deux threads s'attendent mutuellement
C) Un memory leak
D) Une race condition
E) Un buffer overflow

**Reponse correcte: B**

### Question 5
Quelle est la bonne facon d'utiliser une condition variable ?

A) cond_wait sans mutex
B) cond_signal avant cond_wait
C) while(condition) cond_wait dans un mutex
D) cond_wait sans boucle while
E) Lock apres cond_wait

**Reponse correcte: C**

---

## SECTION 8 : RECAPITULATIF

| Fonction | Description |
|----------|-------------|
| pthread_create | Creer thread |
| pthread_join | Attendre thread |
| pthread_mutex_lock | Verrouiller |
| pthread_mutex_unlock | Deverrouiller |
| pthread_cond_wait | Attendre signal |
| pthread_cond_signal | Envoyer signal |

| Probleme | Cause | Solution |
|----------|-------|----------|
| Race condition | Acces concurrent | Mutex |
| Deadlock | Attente circulaire | Ordre fixe |
| Starvation | Thread jamais execute | Fair scheduling |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.15-a",
    "name": "multithreading",
    "module": "0.6.15",
    "phase": 0,
    "difficulty": 7,
    "xp": 500,
    "time_minutes": 360
  },
  "metadata": {
    "concepts": ["pthread_create", "mutex", "race conditions"],
    "prerequisites": ["0.6.1", "0.6.10", "function pointers"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "multithreading.c",
    "header": "multithreading.h",
    "solution": "multithreading_solution.c",
    "test": "test_multithreading.c"
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17", "-pthread"]
  },
  "grading": {
    "automated": true,
    "valgrind_required": true,
    "helgrind_required": true,
    "compilation_weight": 10,
    "functionality_weight": 50,
    "thread_safety_weight": 30,
    "memory_weight": 10
  },
  "bonus": {
    "available": true,
    "multiplier": 2,
    "difficulty": 8
  }
}
```
