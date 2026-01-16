# Exercice 0.6.6-a : queue_impl

**Module :**
0.6.6 — Implementation de File (Queue)

**Concept :**
a-e — enqueue(), dequeue(), front(), isEmpty(), FIFO

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
2 — Integration concepts

**Langage :**
C17

**Prerequis :**
0.6.4 (linked_list), 0.6.5 (stack_impl)

**Domaines :**
Structures, Algo, Mem

**Duree estimee :**
150 min

**XP Base :**
200

**Complexite :**
T1 O(1) x S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `queue.c`
- `queue.h`

**Headers autorises :**
- `<stdio.h>`, `<stdlib.h>`, `<stdbool.h>`

**Fonctions autorisees :**
- `malloc()`, `free()`, `printf()`

### 1.2 Consigne

Implementer une file (queue) utilisant une liste chainee avec enqueue et dequeue en O(1).

**Ta mission :**

Creer une structure de file complete suivant le principe FIFO (First In, First Out).

**Structures :**
```c
typedef struct QueueNode {
    int data;
    struct QueueNode *next;
} QueueNode;

typedef struct {
    QueueNode *front;  // Premier element (sortie)
    QueueNode *rear;   // Dernier element (entree)
    size_t size;
} Queue;
```

**Prototypes :**
```c
// Creation et destruction
Queue *queue_create(void);
void queue_destroy(Queue *queue);

// Operations principales
bool queue_enqueue(Queue *queue, int value);
int queue_dequeue(Queue *queue, bool *success);
int queue_front(const Queue *queue, bool *success);
int queue_rear(const Queue *queue, bool *success);

// Utilitaires
bool queue_is_empty(const Queue *queue);
size_t queue_size(const Queue *queue);
void queue_clear(Queue *queue);
void queue_print(const Queue *queue);
```

**Comportement :**
- `queue_create` alloue et initialise une file vide
- `queue_destroy` libere tous les noeuds et la structure
- `queue_enqueue` ajoute a l'arriere (rear) en O(1)
- `queue_dequeue` retire et retourne le devant (front) en O(1)
- `queue_front` retourne le premier element sans le retirer
- `queue_rear` retourne le dernier element sans le retirer
- `queue_dequeue/front/rear` sur file vide: *success = false, retourne 0
- `queue_print` affiche: [front] 1 <- 2 <- 3 [rear]

**Exemples :**
```
Queue *q = queue_create();     // []
queue_is_empty(q);             // true
queue_enqueue(q, 10);          // [10]
queue_enqueue(q, 20);          // [10, 20]
queue_enqueue(q, 30);          // [10, 20, 30]
queue_front(q, &ok);           // returns 10
queue_rear(q, &ok);            // returns 30
queue_dequeue(q, &ok);         // returns 10, [20, 30]
queue_size(q);                 // returns 2
queue_dequeue(q, &ok);         // returns 20, [30]
queue_dequeue(q, &ok);         // returns 30, []
queue_dequeue(q, &ok);         // returns 0, ok=false
queue_destroy(q);
```

**Contraintes :**
- Enqueue et dequeue doivent etre O(1)
- Utiliser deux pointeurs (front et rear) pour O(1)
- Gerer le cas file vide gracieusement
- Pas de memory leaks

### 1.3 Prototype

```c
// queue.h
#ifndef QUEUE_H
#define QUEUE_H

#include <stddef.h>
#include <stdbool.h>

typedef struct QueueNode {
    int data;
    struct QueueNode *next;
} QueueNode;

typedef struct {
    QueueNode *front;
    QueueNode *rear;
    size_t size;
} Queue;

Queue *queue_create(void);
void queue_destroy(Queue *queue);

bool queue_enqueue(Queue *queue, int value);
int queue_dequeue(Queue *queue, bool *success);
int queue_front(const Queue *queue, bool *success);
int queue_rear(const Queue *queue, bool *success);

bool queue_is_empty(const Queue *queue);
size_t queue_size(const Queue *queue);
void queue_clear(Queue *queue);
void queue_print(const Queue *queue);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 FIFO - First In, First Out

La file fonctionne comme une file d'attente au supermarche:
- Le premier arrive est le premier servi
- Les nouveaux arrivent a l'arriere
- On sert par l'avant

### 2.2 Pile vs File

| Aspect | Pile (Stack) | File (Queue) |
|--------|--------------|--------------|
| Principe | LIFO | FIFO |
| Ajout | Sommet (top) | Arriere (rear) |
| Retrait | Sommet (top) | Devant (front) |
| Analogie | Pile d'assiettes | File d'attente |

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Systems Programmer**

Les files sont essentielles pour:
- Scheduler de processus (run queue)
- Buffer d'I/O
- Message queues (IPC)

**Metier : Backend Developer**

Utilisation courante:
- Message brokers (RabbitMQ, Kafka)
- Task queues (Celery)
- Event loops

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o test_queue test_main.c queue.c
$ ./test_queue
Creating queue...
  queue_is_empty: true
  queue_size: 0

Enqueuing 10, 20, 30...
  queue_print: [front] 10 <- 20 <- 30 [rear]
  queue_size: 3

Testing front and rear...
  queue_front: 10 (queue unchanged)
  queue_rear: 30 (queue unchanged)

Testing dequeue...
  queue_dequeue: 10
  queue_dequeue: 20
  queue_dequeue: 30
  queue_is_empty: true

Testing dequeue on empty queue...
  queue_dequeue: failed (ok=false)

All tests passed!
$ valgrind --leak-check=full ./test_queue
==12345== All heap blocks were freed -- no leaks are possible
```

### 3.1 Application: BFS (Breadth-First Search)

```c
void bfs(Graph *g, int start)
{
    bool *visited = calloc(g->vertices, sizeof(bool));
    Queue *q = queue_create();

    visited[start] = true;
    queue_enqueue(q, start);

    while (!queue_is_empty(q))
    {
        bool ok;
        int current = queue_dequeue(q, &ok);
        printf("Visiting: %d\n", current);

        // Pour chaque voisin non visite
        for (Node *adj = g->adj[current]; adj; adj = adj->next)
        {
            if (!visited[adj->vertex])
            {
                visited[adj->vertex] = true;
                queue_enqueue(q, adj->vertex);
            }
        }
    }

    queue_destroy(q);
    free(visited);
}
```

### 3.2 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★☆☆☆☆☆☆ (4/10)

**Recompense :**
XP x2

#### 3.2.1 Consigne Bonus

Implementer une file circulaire avec tableau de taille fixe.

```c
typedef struct {
    int *data;
    size_t capacity;
    size_t front;
    size_t rear;
    size_t size;
} CircularQueue;

CircularQueue *cqueue_create(size_t capacity);
bool cqueue_enqueue(CircularQueue *q, int value);  // false si pleine
int cqueue_dequeue(CircularQueue *q, bool *success);
bool cqueue_is_full(const CircularQueue *q);
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Expected | Points |
|---------|-------------|----------|--------|
| T01 | create returns non-NULL | Valid ptr | 10 |
| T02 | empty queue size = 0 | 0 | 10 |
| T03 | enqueue increases size | size++ | 10 |
| T04 | dequeue returns front | Correct FIFO | 15 |
| T05 | front doesn't remove | Size unchanged | 10 |
| T06 | dequeue empty fails | success=false | 10 |
| T07 | FIFO order correct | 1,2,3 -> dequeue 1,2,3 | 15 |
| T08 | rear pointer updated | After enqueue | 10 |
| T09 | destroy frees all | No leaks | 10 |

### 4.2 main.c de test

```c
#include <stdio.h>
#include "queue.h"

int main(void)
{
    int pass = 0, fail = 0;
    bool ok;

    // T01: create
    Queue *queue = queue_create();
    if (queue != NULL)
    {
        printf("T01 PASS: queue_create returned non-NULL\n");
        pass++;
    }
    else
    {
        printf("T01 FAIL\n");
        fail++;
        return 1;
    }

    // T02: empty queue
    if (queue_size(queue) == 0 && queue_is_empty(queue))
    {
        printf("T02 PASS: empty queue size=0, is_empty=true\n");
        pass++;
    }
    else
    {
        printf("T02 FAIL\n");
        fail++;
    }

    // T03: enqueue
    queue_enqueue(queue, 10);
    queue_enqueue(queue, 20);
    queue_enqueue(queue, 30);
    if (queue_size(queue) == 3)
    {
        printf("T03 PASS: enqueue increases size\n");
        pass++;
    }
    else
    {
        printf("T03 FAIL\n");
        fail++;
    }

    // T04: dequeue returns front
    int val = queue_dequeue(queue, &ok);
    if (ok && val == 10)
    {
        printf("T04 PASS: dequeue returns front (10)\n");
        pass++;
    }
    else
    {
        printf("T04 FAIL: expected 10, got %d\n", val);
        fail++;
    }

    // T05: front doesn't remove
    val = queue_front(queue, &ok);
    size_t size_before = queue_size(queue);
    queue_front(queue, &ok);
    size_t size_after = queue_size(queue);
    if (val == 20 && size_before == size_after)
    {
        printf("T05 PASS: front doesn't remove (20)\n");
        pass++;
    }
    else
    {
        printf("T05 FAIL\n");
        fail++;
    }

    // Vider la queue
    queue_dequeue(queue, &ok);  // 20
    queue_dequeue(queue, &ok);  // 30

    // T06: dequeue empty
    val = queue_dequeue(queue, &ok);
    if (!ok)
    {
        printf("T06 PASS: dequeue empty returns success=false\n");
        pass++;
    }
    else
    {
        printf("T06 FAIL\n");
        fail++;
    }

    // T07: FIFO order
    queue_enqueue(queue, 1);
    queue_enqueue(queue, 2);
    queue_enqueue(queue, 3);
    int v1 = queue_dequeue(queue, &ok);
    int v2 = queue_dequeue(queue, &ok);
    int v3 = queue_dequeue(queue, &ok);
    if (v1 == 1 && v2 == 2 && v3 == 3)
    {
        printf("T07 PASS: FIFO order correct (1,2,3)\n");
        pass++;
    }
    else
    {
        printf("T07 FAIL: got %d,%d,%d\n", v1, v2, v3);
        fail++;
    }

    // T08: rear pointer
    queue_enqueue(queue, 100);
    queue_enqueue(queue, 200);
    val = queue_rear(queue, &ok);
    if (ok && val == 200)
    {
        printf("T08 PASS: rear returns last enqueued (200)\n");
        pass++;
    }
    else
    {
        printf("T08 FAIL\n");
        fail++;
    }

    // T09: destroy
    queue_destroy(queue);
    printf("T09 PASS: destroy completed (check valgrind)\n");
    pass++;

    printf("\nResults: %d passed, %d failed\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
```

### 4.3 Solution de reference

```c
/*
 * queue.c
 * Implementation de file (queue) avec liste chainee
 * Exercice ex29_queue_impl
 */

#include "queue.h"
#include <stdio.h>
#include <stdlib.h>

static QueueNode *create_node(int value)
{
    QueueNode *node = malloc(sizeof(*node));
    if (node != NULL)
    {
        node->data = value;
        node->next = NULL;
    }
    return node;
}

Queue *queue_create(void)
{
    Queue *queue = malloc(sizeof(*queue));
    if (queue != NULL)
    {
        queue->front = NULL;
        queue->rear = NULL;
        queue->size = 0;
    }
    return queue;
}

void queue_destroy(Queue *queue)
{
    if (queue == NULL)
    {
        return;
    }
    queue_clear(queue);
    free(queue);
}

bool queue_enqueue(Queue *queue, int value)
{
    if (queue == NULL)
    {
        return false;
    }

    QueueNode *node = create_node(value);
    if (node == NULL)
    {
        return false;
    }

    if (queue->rear == NULL)
    {
        // File vide: front et rear pointent vers le meme noeud
        queue->front = node;
        queue->rear = node;
    }
    else
    {
        // Ajouter a l'arriere
        queue->rear->next = node;
        queue->rear = node;
    }

    queue->size++;
    return true;
}

int queue_dequeue(Queue *queue, bool *success)
{
    if (queue == NULL || queue->front == NULL)
    {
        if (success) *success = false;
        return 0;
    }

    QueueNode *old_front = queue->front;
    int value = old_front->data;

    queue->front = old_front->next;

    // Si la file devient vide, mettre rear a NULL aussi
    if (queue->front == NULL)
    {
        queue->rear = NULL;
    }

    queue->size--;
    free(old_front);

    if (success) *success = true;
    return value;
}

int queue_front(const Queue *queue, bool *success)
{
    if (queue == NULL || queue->front == NULL)
    {
        if (success) *success = false;
        return 0;
    }

    if (success) *success = true;
    return queue->front->data;
}

int queue_rear(const Queue *queue, bool *success)
{
    if (queue == NULL || queue->rear == NULL)
    {
        if (success) *success = false;
        return 0;
    }

    if (success) *success = true;
    return queue->rear->data;
}

bool queue_is_empty(const Queue *queue)
{
    return queue == NULL || queue->size == 0;
}

size_t queue_size(const Queue *queue)
{
    return queue ? queue->size : 0;
}

void queue_clear(Queue *queue)
{
    if (queue == NULL)
    {
        return;
    }

    while (queue->front != NULL)
    {
        QueueNode *next = queue->front->next;
        free(queue->front);
        queue->front = next;
    }

    queue->rear = NULL;
    queue->size = 0;
}

void queue_print(const Queue *queue)
{
    printf("[front] ");
    if (queue != NULL)
    {
        QueueNode *current = queue->front;
        while (current != NULL)
        {
            printf("%d", current->data);
            if (current->next != NULL)
            {
                printf(" <- ");
            }
            current = current->next;
        }
    }
    printf(" [rear]\n");
}
```

### 4.5 Solutions refusees (avec explications)

```c
// REFUSE 1: Enqueue en O(n) - parcours pour trouver la fin
bool queue_enqueue(Queue *queue, int value)
{
    QueueNode *node = create_node(value);
    if (queue->front == NULL)
    {
        queue->front = node;
    }
    else
    {
        QueueNode *curr = queue->front;
        while (curr->next != NULL)  // O(n)!
        {
            curr = curr->next;
        }
        curr->next = node;
    }
    return true;
}
// Raison: Doit utiliser pointeur rear pour O(1)

// REFUSE 2: Dequeue ne met pas a jour rear si file vide
int queue_dequeue(Queue *queue, bool *success)
{
    if (queue->front == NULL)
    {
        *success = false;
        return 0;
    }
    QueueNode *old = queue->front;
    int val = old->data;
    queue->front = old->next;
    // Oubli: if (queue->front == NULL) queue->rear = NULL;
    free(old);
    *success = true;
    return val;
}
// Raison: rear pointe vers memoire liberee apres vidage

// REFUSE 3: File qui fonctionne comme une pile (LIFO)
bool queue_enqueue(Queue *queue, int value)
{
    QueueNode *node = create_node(value);
    node->next = queue->front;  // Ajoute devant!
    queue->front = node;
    return true;
}
// Raison: FIFO, pas LIFO

// REFUSE 4: Pas de pointeur rear (impossible O(1) enqueue)
typedef struct {
    QueueNode *front;
    // Manque: QueueNode *rear;
    size_t size;
} Queue;
// Raison: Enqueue sera O(n) sans pointeur rear
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.6-a",
  "name": "queue_impl",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["queue.c", "queue.h"],
    "test": ["test_queue.c"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"],
    "output": "test_queue"
  },
  "tests": {
    "type": "unit",
    "valgrind": true,
    "complexity": {
      "enqueue": "O(1)",
      "dequeue": "O(1)",
      "front": "O(1)"
    }
  },
  "scoring": {
    "total": 100,
    "compilation": 10,
    "functionality": 60,
    "memory_safety": 20,
    "complexity": 10
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```c
// MUTANT 1 (Memory): Dequeue ne libere pas le noeud
int queue_dequeue(Queue *queue, bool *success)
{
    if (queue->front == NULL)
    {
        *success = false;
        return 0;
    }
    int value = queue->front->data;
    queue->front = queue->front->next;  // Oubli free!
    if (queue->front == NULL) queue->rear = NULL;
    queue->size--;
    *success = true;
    return value;
}
// Detection: Valgrind memory leak

// MUTANT 2 (Logic): Enqueue au front au lieu de rear (LIFO)
bool queue_enqueue(Queue *queue, int value)
{
    QueueNode *node = create_node(value);
    node->next = queue->front;
    queue->front = node;
    if (queue->rear == NULL) queue->rear = node;
    queue->size++;
    return true;
}
// Detection: FIFO order test fails

// MUTANT 3 (Logic): Ne met pas a jour rear quand file se vide
int queue_dequeue(Queue *queue, bool *success)
{
    QueueNode *old = queue->front;
    int value = old->data;
    queue->front = old->next;
    // Oubli: if (queue->front == NULL) queue->rear = NULL;
    queue->size--;
    free(old);
    *success = true;
    return value;
}
// Detection: queue_rear apres vidage retourne garbage/crash

// MUTANT 4 (Boundary): Enqueue sur file vide ne met pas front
bool queue_enqueue(Queue *queue, int value)
{
    QueueNode *node = create_node(value);
    if (queue->rear != NULL)
    {
        queue->rear->next = node;
    }
    queue->rear = node;
    // Oubli: if (queue->front == NULL) queue->front = node;
    queue->size++;
    return true;
}
// Detection: Dequeue apres premier enqueue echoue

// MUTANT 5 (Logic): Size non decremente dans dequeue
int queue_dequeue(Queue *queue, bool *success)
{
    if (queue->front == NULL)
    {
        *success = false;
        return 0;
    }
    QueueNode *old = queue->front;
    int value = old->data;
    queue->front = old->next;
    if (queue->front == NULL) queue->rear = NULL;
    // Oubli: queue->size--;
    free(old);
    *success = true;
    return value;
}
// Detection: queue_size() retourne mauvaise valeur
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **fondamentaux des files (queues)**:

1. **enqueue()** - Ajouter un element a l'arriere
2. **dequeue()** - Retirer et retourner l'element du devant
3. **front()** - Observer le devant sans retirer
4. **isEmpty()** - Verifier si la file est vide
5. **FIFO** - First In, First Out (principe fondamental)

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION enqueue(file, valeur):
DEBUT
    noeud <- creer_noeud(valeur)

    SI file.arriere est NULL ALORS
        // File vide
        file.devant <- noeud
        file.arriere <- noeud
    SINON
        file.arriere.suivant <- noeud
        file.arriere <- noeud
    FIN SI

    file.taille <- file.taille + 1
    RETOURNER SUCCES
FIN

FONCTION dequeue(file):
DEBUT
    SI file.devant est NULL ALORS
        RETOURNER ECHEC
    FIN SI

    ancien_devant <- file.devant
    valeur <- ancien_devant.donnee
    file.devant <- ancien_devant.suivant

    SI file.devant est NULL ALORS
        file.arriere <- NULL
    FIN SI

    file.taille <- file.taille - 1
    liberer(ancien_devant)
    RETOURNER valeur
FIN
```

### 5.3 Visualisation ASCII

```
File vide:
Queue
+-------+-------+------+
| front | rear  | size |
| NULL  | NULL  |  0   |
+-------+-------+------+

Apres enqueue(10):
Queue
+-------+-------+------+
| front | rear  | size |
|   *   |   *   |  1   |
+---+---+---+---+------+
    |       |
    +---+---+
        |
        v
    [10|NULL]

Apres enqueue(20), enqueue(30):
Queue
+-------+-------+------+
| front | rear  | size |
|   *   |   *   |  3   |
+---+---+---+---+------+
    |       |
    v       +------------------+
    [10|*]->[20|*]->[30|NULL]  |
                    ^          |
                    +----------+

Dequeue (retire 10):
Queue
+-------+-------+------+
| front | rear  | size |
|   *   |   *   |  2   |
+---+---+---+---+------+
    |       |
    v       +----------+
    [20|*]->[30|NULL]  |
            ^          |
            +----------+
```

### 5.4 Les pieges en detail

#### Piege 1: Oublier de mettre a jour rear quand la file se vide
```c
// FAUX
int queue_dequeue(Queue *q, bool *success)
{
    QueueNode *old = q->front;
    q->front = old->next;
    // Si front == NULL, rear pointe toujours vers l'ancien noeud!
    free(old);
    return old->data;
}

// CORRECT
int queue_dequeue(Queue *q, bool *success)
{
    QueueNode *old = q->front;
    int val = old->data;
    q->front = old->next;
    if (q->front == NULL)
    {
        q->rear = NULL;  // File vide!
    }
    free(old);
    return val;
}
```

#### Piege 2: Enqueue sans gerer le cas file vide
```c
// FAUX - crash si file vide
bool queue_enqueue(Queue *q, int value)
{
    QueueNode *node = create_node(value);
    q->rear->next = node;  // Crash si rear == NULL!
    q->rear = node;
    return true;
}

// CORRECT
bool queue_enqueue(Queue *q, int value)
{
    QueueNode *node = create_node(value);
    if (q->rear == NULL)
    {
        q->front = node;
        q->rear = node;
    }
    else
    {
        q->rear->next = node;
        q->rear = node;
    }
    return true;
}
```

### 5.5 Cours Complet

#### 5.5.1 Pourquoi deux pointeurs ?

Avec un seul pointeur (front):
- **enqueue**: O(n) - parcourir jusqu'a la fin
- **dequeue**: O(1) - retirer du debut

Avec deux pointeurs (front + rear):
- **enqueue**: O(1) - ajout direct a rear
- **dequeue**: O(1) - retrait direct de front

#### 5.5.2 Complexite des operations

| Operation | Complexite | Explication |
|-----------|------------|-------------|
| enqueue | O(1) | Ajout via pointeur rear |
| dequeue | O(1) | Retrait via pointeur front |
| front | O(1) | Lecture de front->data |
| rear | O(1) | Lecture de rear->data |
| isEmpty | O(1) | Verification front == NULL |
| size | O(1) | Lecture du compteur |
| clear | O(n) | Parcours pour free |

#### 5.5.3 Applications des files

1. **Scheduler**: File des processus prets
2. **Buffers**: Producteur-consommateur
3. **BFS**: Parcours en largeur de graphes
4. **Impression**: File d'attente d'impression

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| Deux pointeurs | O(1) pour enqueue | `front` et `rear` |
| MAJ rear sur vide | Evite dangling pointer | `if (!front) rear = NULL` |
| MAJ front sur vide | Premier enqueue | `if (!rear) front = node` |
| Free dans dequeue | Evite memory leak | `free(old_front)` |

### 5.7 Simulation avec trace d'execution

```
queue_enqueue(q, 10): (file vide)
1. create_node(10) -> 0x1000 {data=10, next=NULL}
2. q->rear == NULL donc:
   q->front = 0x1000
   q->rear = 0x1000
3. q->size = 1

Etat: front=rear -> [10|NULL], size=1

queue_enqueue(q, 20):
1. create_node(20) -> 0x2000 {data=20, next=NULL}
2. q->rear != NULL donc:
   q->rear->next = 0x2000
   q->rear = 0x2000
3. q->size = 2

Etat: front -> [10|*] -> [20|NULL] <- rear, size=2

queue_dequeue(q):
1. old_front = q->front (0x1000)
2. value = 10
3. q->front = old_front->next (0x2000)
4. q->front != NULL, donc rear inchange
5. q->size = 1
6. free(0x1000)
7. return 10

Etat: front=rear -> [20|NULL], size=1
```

### 5.8 Mnemotechniques

**"FIFO" - First In, First Out**
- Le premier entre est le premier sorti
- Comme une file d'attente

**"FR" - Front et Rear**
- **F**ront: ou on sort (dequeue)
- **R**ear: ou on entre (enqueue)

### 5.9 Applications pratiques

1. **Print queue**: Gestion d'imprimantes
2. **Task scheduling**: Ordonnancement CPU
3. **Message passing**: Communication inter-processus
4. **Streaming**: Buffers de donnees
5. **BFS algorithm**: Parcours de graphes niveau par niveau

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| rear non NULL apres vide | Use-after-free | `if (!front) rear = NULL` |
| Enqueue sans check vide | Crash | Gerer cas `rear == NULL` |
| Oubli free dequeue | Memory leak | Free ancien front |
| Un seul pointeur | O(n) enqueue | Utiliser front ET rear |
| LIFO au lieu FIFO | Mauvais ordre | Enqueue a rear, dequeue de front |

---

## SECTION 7 : QCM

### Question 1
Quel principe definit le fonctionnement d'une file ?

A) LIFO - Last In, First Out
B) FIFO - First In, First Out
C) Priority-based
D) Random access
E) Stack-based

**Reponse correcte: B**

### Question 2
Pourquoi utilise-t-on deux pointeurs (front et rear) dans une file ?

A) Pour economiser de la memoire
B) Pour avoir enqueue et dequeue en O(1)
C) C'est une convention
D) Pour simplifier le code
E) Ce n'est pas necessaire

**Reponse correcte: B**

### Question 3
Que faut-il faire quand dequeue vide completement la file ?

A) Rien de special
B) Mettre front a NULL seulement
C) Mettre front ET rear a NULL
D) Liberer la structure Queue
E) Reinitialiser size a -1

**Reponse correcte: C**

### Question 4
Quelle est la difference entre une pile et une file ?

A) La pile est plus rapide
B) La file utilise plus de memoire
C) La pile est LIFO, la file est FIFO
D) Il n'y a pas de difference
E) La pile ne peut stocker que des entiers

**Reponse correcte: C**

### Question 5
Dans quel algorithme de graphe utilise-t-on typiquement une file ?

A) DFS (Depth-First Search)
B) BFS (Breadth-First Search)
C) Dijkstra
D) Bellman-Ford
E) Kruskal

**Reponse correcte: B**

---

## SECTION 8 : RECAPITULATIF

| Operation | Description | Complexite |
|-----------|-------------|------------|
| enqueue(val) | Ajoute val a l'arriere | O(1) |
| dequeue() | Retire et retourne le devant | O(1) |
| front() | Retourne devant sans retirer | O(1) |
| rear() | Retourne arriere sans retirer | O(1) |
| isEmpty() | Verifie si file vide | O(1) |
| size() | Nombre d'elements | O(1) |

| Principe | Description |
|----------|-------------|
| FIFO | First In, First Out |
| Front | Element de sortie |
| Rear | Element d'entree |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.6-a",
    "name": "queue_impl",
    "module": "0.6.6",
    "phase": 0,
    "difficulty": 3,
    "xp": 200,
    "time_minutes": 150
  },
  "metadata": {
    "concepts": ["enqueue", "dequeue", "front", "isEmpty", "FIFO"],
    "prerequisites": ["0.6.4", "0.6.5"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "queue.c",
    "header": "queue.h",
    "solution": "queue_solution.c",
    "test": "test_queue.c"
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"]
  },
  "grading": {
    "automated": true,
    "valgrind_required": true,
    "complexity_check": {
      "enqueue": "O(1)",
      "dequeue": "O(1)"
    }
  }
}
```
