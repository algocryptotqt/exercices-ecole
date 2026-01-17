# Exercice D.25 : heap

**Module :**
D — Algorithmique

**Concept :**
25 — Heap (Tas) - Structure de donnees et tri

**Difficulte :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
code

**Tiers :**
2 — Integration de concepts

**Langage :**
C17

**Prerequis :**
- Tableaux dynamiques (malloc/realloc)
- Recursivite
- Pointeurs
- Complexite algorithmique O(log n)

**Domaines :**
Algo, DataStruct

**Duree estimee :**
120 min

**XP Base :**
200

**Complexite :**
T[N] O(log n) x S[N] O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `heap.c`, `heap.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | malloc, free, realloc, memcpy |

---

### 1.2 Consigne

#### Section Culture : "Le Tas - Une Structure Arborescente Efficace"

Un **heap** (tas) est un arbre binaire complet stocke dans un tableau. Cette structure permet d'acceder au plus grand (max-heap) ou plus petit (min-heap) element en O(1) et de maintenir cette propriete en O(log n) apres chaque modification.

Les heaps sont utilises partout :
- Files de priorite (processus systeme, evenements)
- Algorithme de Dijkstra (plus courts chemins)
- Tri par tas (HeapSort) - tri en place O(n log n)
- Median dynamique (avec deux heaps)
- Algorithme de Huffman (compression)

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une structure de heap generique supportant min-heap et max-heap, avec les operations fondamentales : insert, extract, peek, heapify, et heap sort.

**Proprietes du Heap :**

```
MAX-HEAP: parent >= enfants
MIN-HEAP: parent <= enfants

Pour un noeud a l'index i:
- Parent:        (i - 1) / 2
- Enfant gauche: 2 * i + 1
- Enfant droit:  2 * i + 2
```

**Prototypes :**

```c
// heap.h

#ifndef HEAP_H
#define HEAP_H

#include <stddef.h>
#include <stdbool.h>

typedef enum {
    HEAP_MIN,
    HEAP_MAX
} heap_type_t;

typedef struct {
    int         *data;      // Tableau des elements
    size_t      size;       // Nombre d'elements actuels
    size_t      capacity;   // Capacite allouee
    heap_type_t type;       // MIN ou MAX heap
} heap_t;

// Creation et destruction
heap_t  *heap_create(heap_type_t type, size_t initial_capacity);
void    heap_destroy(heap_t *heap);

// Operations de base
bool    heap_insert(heap_t *heap, int value);
int     heap_extract(heap_t *heap);
int     heap_peek(const heap_t *heap);
bool    heap_is_empty(const heap_t *heap);
size_t  heap_size(const heap_t *heap);

// Heapify - Transformer un tableau en heap
void    heapify_up(heap_t *heap, size_t index);
void    heapify_down(heap_t *heap, size_t index);
void    build_heap(heap_t *heap, int *arr, size_t n);

// Heap Sort
void    heap_sort(int *arr, size_t n, bool ascending);

// Priority Queue interface
typedef heap_t priority_queue_t;

priority_queue_t *pq_create(bool min_priority);
void    pq_destroy(priority_queue_t *pq);
bool    pq_enqueue(priority_queue_t *pq, int priority);
int     pq_dequeue(priority_queue_t *pq);
int     pq_front(const priority_queue_t *pq);

#endif
```

**Comportements attendus :**

| Operation | Exemple | Resultat | Complexite |
|-----------|---------|----------|------------|
| heap_create(HEAP_MAX, 10) | - | Heap vide, capacite 10 | O(1) |
| heap_insert(h, 5) | [3,1] -> | [5,3,1] (max-heap) | O(log n) |
| heap_extract(h) | [5,3,1] | 5, heap = [3,1] | O(log n) |
| heap_peek(h) | [5,3,1] | 5 (sans modifier) | O(1) |
| build_heap(h, arr, n) | [4,1,3,2] | [4,2,3,1] (max) | O(n) |
| heap_sort(arr, n, true) | [3,1,4,2] | [1,2,3,4] | O(n log n) |

**Exemples :**

```
MAX-HEAP Insertion de 15 dans [10, 5, 3, 2, 4]:

Avant:          10              Apres:          15
               /  \                            /  \
              5    3                         10    3
             / \                            /  \
            2   4                          2    4
                                              \
                                               5

Tableau: [10,5,3,2,4] -> [10,5,3,2,4,15] -> [15,10,3,2,4,5]
                                  ^bubble up
```

---

### 1.3 Prototype

```c
// heap.h - Interface complete

#ifndef HEAP_H
#define HEAP_H

#include <stddef.h>
#include <stdbool.h>

/**
 * Type de heap : min-heap ou max-heap
 */
typedef enum {
    HEAP_MIN,   // Le plus petit element est a la racine
    HEAP_MAX    // Le plus grand element est a la racine
} heap_type_t;

/**
 * Structure du heap
 * Stocke un arbre binaire complet dans un tableau
 */
typedef struct {
    int         *data;      // Tableau dynamique des elements
    size_t      size;       // Nombre d'elements actuels
    size_t      capacity;   // Capacite allouee
    heap_type_t type;       // Type de heap (MIN ou MAX)
} heap_t;

/**
 * Cree un nouveau heap
 *
 * @param type: HEAP_MIN ou HEAP_MAX
 * @param initial_capacity: capacite initiale (>= 1)
 * @return: pointeur vers le heap, NULL si erreur
 *
 * Complexity: O(1)
 */
heap_t *heap_create(heap_type_t type, size_t initial_capacity);

/**
 * Libere toute la memoire du heap
 *
 * @param heap: le heap a detruire
 *
 * Complexity: O(1)
 */
void heap_destroy(heap_t *heap);

/**
 * Insere une valeur dans le heap
 *
 * @param heap: le heap
 * @param value: valeur a inserer
 * @return: true si succes, false si erreur allocation
 *
 * Complexity: O(log n)
 */
bool heap_insert(heap_t *heap, int value);

/**
 * Extrait l'element racine (min ou max selon le type)
 *
 * @param heap: le heap
 * @return: valeur extraite, INT_MIN si vide
 *
 * Complexity: O(log n)
 */
int heap_extract(heap_t *heap);

/**
 * Retourne l'element racine sans l'extraire
 *
 * @param heap: le heap
 * @return: valeur au sommet, INT_MIN si vide
 *
 * Complexity: O(1)
 */
int heap_peek(const heap_t *heap);

/**
 * Verifie si le heap est vide
 *
 * @param heap: le heap
 * @return: true si vide
 *
 * Complexity: O(1)
 */
bool heap_is_empty(const heap_t *heap);

/**
 * Retourne le nombre d'elements
 *
 * @param heap: le heap
 * @return: nombre d'elements
 *
 * Complexity: O(1)
 */
size_t heap_size(const heap_t *heap);

/**
 * Remonte un element jusqu'a sa position correcte
 *
 * @param heap: le heap
 * @param index: index de l'element a remonter
 *
 * Complexity: O(log n)
 */
void heapify_up(heap_t *heap, size_t index);

/**
 * Descend un element jusqu'a sa position correcte
 *
 * @param heap: le heap
 * @param index: index de l'element a descendre
 *
 * Complexity: O(log n)
 */
void heapify_down(heap_t *heap, size_t index);

/**
 * Construit un heap a partir d'un tableau
 *
 * @param heap: le heap (doit etre cree avec capacite suffisante)
 * @param arr: tableau source
 * @param n: taille du tableau
 *
 * Complexity: O(n)
 */
void build_heap(heap_t *heap, int *arr, size_t n);

/**
 * Trie un tableau en utilisant HeapSort
 *
 * @param arr: tableau a trier
 * @param n: taille du tableau
 * @param ascending: true pour croissant, false pour decroissant
 *
 * Complexity: O(n log n)
 */
void heap_sort(int *arr, size_t n, bool ascending);

// ============================================
// Priority Queue - Interface haut niveau
// ============================================

typedef heap_t priority_queue_t;

priority_queue_t *pq_create(bool min_priority);
void pq_destroy(priority_queue_t *pq);
bool pq_enqueue(priority_queue_t *pq, int priority);
int pq_dequeue(priority_queue_t *pq);
int pq_front(const priority_queue_t *pq);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**HeapSort vs QuickSort**

HeapSort garantit O(n log n) dans le pire cas, contrairement a QuickSort qui peut atteindre O(n^2). Cependant, QuickSort est souvent plus rapide en pratique grace a une meilleure localite de cache.

**Binary Heap vs Fibonacci Heap**

Le binary heap a des operations en O(log n), mais le Fibonacci heap permet decrease-key en O(1) amorti, ce qui accelere Dijkstra de O(E log V) a O(E + V log V).

**L'astuce du Build Heap**

Construire un heap en inserant n elements un par un = O(n log n). Mais build_heap avec heapify_down depuis les feuilles = O(n) ! La majorite des noeuds sont pres des feuilles ou heapify_down fait peu de travail.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **OS Developer** | Ordonnanceur de processus (priority scheduling) |
| **Network Engineer** | Gestion des paquets par priorite (QoS) |
| **Game Developer** | Pathfinding A* avec min-heap |
| **Database Engineer** | Merge de fichiers tries, Top-K queries |
| **Embedded Systems** | Gestion d'evenements temps reel |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Wextra -Werror -std=c17 heap.c main.c -o heap_demo
$ ./heap_demo

# Test Max-Heap
Creating max-heap...
Inserting: 3, 1, 4, 1, 5, 9, 2, 6
Heap state: [9, 6, 4, 3, 5, 1, 2, 1]
Peek: 9
Extract: 9, heap = [6, 5, 4, 3, 1, 1, 2]
Extract: 6, heap = [5, 3, 4, 2, 1, 1]

# Test Min-Heap
Creating min-heap...
Inserting: 3, 1, 4, 1, 5, 9, 2, 6
Heap state: [1, 1, 2, 3, 5, 9, 4, 6]
Peek: 1

# Test Heap Sort
Array before: [64, 34, 25, 12, 22, 11, 90]
After heap_sort (ascending): [11, 12, 22, 25, 34, 64, 90]

# Test Priority Queue
Task queue (min priority = highest):
Enqueue tasks with priorities: 5, 2, 8, 1, 3
Dequeue order: 1, 2, 3, 5, 8
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | create_max | heap_create(MAX, 10) | heap non NULL | 5 | Create |
| 2 | create_min | heap_create(MIN, 10) | heap non NULL | 5 | Create |
| 3 | insert_single | insert(h, 42) | size=1, peek=42 | 10 | Insert |
| 4 | insert_max_order | insert 3,1,4,1,5 | max au sommet | 15 | Insert |
| 5 | insert_min_order | insert 3,1,4,1,5 | min au sommet | 15 | Insert |
| 6 | extract_max | [5,3,1] extract | 5, valid heap | 15 | Extract |
| 7 | extract_min | [1,3,5] extract | 1, valid heap | 15 | Extract |
| 8 | extract_empty | extract on [] | INT_MIN | 5 | Edge |
| 9 | peek_no_modify | peek, size | same size | 5 | Peek |
| 10 | build_heap | arr=[4,1,3,2] | valid heap | 15 | Build |
| 11 | heap_sort_asc | [3,1,4,2] | [1,2,3,4] | 20 | Sort |
| 12 | heap_sort_desc | [3,1,4,2] | [4,3,2,1] | 15 | Sort |
| 13 | pq_operations | enqueue/dequeue | correct order | 15 | PQueue |
| 14 | large_dataset | 10000 elements | correct extract order | 20 | Stress |
| 15 | memory_check | valgrind | no leaks | 25 | Memory |

**Total : 200 points**

---

### 4.2 Tests unitaires

```c
#include <stdio.h>
#include <assert.h>
#include <limits.h>
#include "heap.h"

void test_heap_create(void)
{
    heap_t *h = heap_create(HEAP_MAX, 10);
    assert(h != NULL);
    assert(heap_is_empty(h));
    assert(heap_size(h) == 0);
    heap_destroy(h);
    printf("test_heap_create: PASSED\n");
}

void test_heap_insert_max(void)
{
    heap_t *h = heap_create(HEAP_MAX, 10);
    heap_insert(h, 3);
    heap_insert(h, 1);
    heap_insert(h, 4);
    heap_insert(h, 1);
    heap_insert(h, 5);

    assert(heap_peek(h) == 5);
    assert(heap_size(h) == 5);
    heap_destroy(h);
    printf("test_heap_insert_max: PASSED\n");
}

void test_heap_insert_min(void)
{
    heap_t *h = heap_create(HEAP_MIN, 10);
    heap_insert(h, 3);
    heap_insert(h, 1);
    heap_insert(h, 4);
    heap_insert(h, 1);
    heap_insert(h, 5);

    assert(heap_peek(h) == 1);
    heap_destroy(h);
    printf("test_heap_insert_min: PASSED\n");
}

void test_heap_extract_max(void)
{
    heap_t *h = heap_create(HEAP_MAX, 10);
    heap_insert(h, 3);
    heap_insert(h, 1);
    heap_insert(h, 4);

    assert(heap_extract(h) == 4);
    assert(heap_extract(h) == 3);
    assert(heap_extract(h) == 1);
    assert(heap_is_empty(h));
    heap_destroy(h);
    printf("test_heap_extract_max: PASSED\n");
}

void test_heap_extract_empty(void)
{
    heap_t *h = heap_create(HEAP_MAX, 10);
    assert(heap_extract(h) == INT_MIN);
    heap_destroy(h);
    printf("test_heap_extract_empty: PASSED\n");
}

void test_heap_sort_ascending(void)
{
    int arr[] = {64, 34, 25, 12, 22, 11, 90};
    size_t n = sizeof(arr) / sizeof(arr[0]);

    heap_sort(arr, n, true);

    for (size_t i = 0; i < n - 1; i++)
        assert(arr[i] <= arr[i + 1]);

    printf("test_heap_sort_ascending: PASSED\n");
}

void test_heap_sort_descending(void)
{
    int arr[] = {64, 34, 25, 12, 22, 11, 90};
    size_t n = sizeof(arr) / sizeof(arr[0]);

    heap_sort(arr, n, false);

    for (size_t i = 0; i < n - 1; i++)
        assert(arr[i] >= arr[i + 1]);

    printf("test_heap_sort_descending: PASSED\n");
}

void test_priority_queue(void)
{
    priority_queue_t *pq = pq_create(true);  // min priority
    pq_enqueue(pq, 5);
    pq_enqueue(pq, 2);
    pq_enqueue(pq, 8);
    pq_enqueue(pq, 1);

    assert(pq_dequeue(pq) == 1);
    assert(pq_dequeue(pq) == 2);
    assert(pq_dequeue(pq) == 5);
    assert(pq_dequeue(pq) == 8);

    pq_destroy(pq);
    printf("test_priority_queue: PASSED\n");
}

int main(void)
{
    test_heap_create();
    test_heap_insert_max();
    test_heap_insert_min();
    test_heap_extract_max();
    test_heap_extract_empty();
    test_heap_sort_ascending();
    test_heap_sort_descending();
    test_priority_queue();

    printf("\nAll tests PASSED!\n");
    return 0;
}
```

---

### 4.3 Solution de reference

```c
// heap.c - Implementation complete

#include "heap.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

// ============================================
// Fonctions utilitaires internes
// ============================================

static inline size_t parent(size_t i)
{
    return (i - 1) / 2;
}

static inline size_t left_child(size_t i)
{
    return 2 * i + 1;
}

static inline size_t right_child(size_t i)
{
    return 2 * i + 2;
}

static inline void swap(int *a, int *b)
{
    int temp = *a;
    *a = *b;
    *b = temp;
}

static bool should_swap(heap_t *heap, int parent_val, int child_val)
{
    if (heap->type == HEAP_MAX)
        return parent_val < child_val;  // Parent doit etre plus grand
    else
        return parent_val > child_val;  // Parent doit etre plus petit
}

static bool ensure_capacity(heap_t *heap)
{
    if (heap->size < heap->capacity)
        return true;

    size_t new_capacity = heap->capacity * 2;
    int *new_data = realloc(heap->data, new_capacity * sizeof(int));
    if (new_data == NULL)
        return false;

    heap->data = new_data;
    heap->capacity = new_capacity;
    return true;
}

// ============================================
// Creation et destruction
// ============================================

heap_t *heap_create(heap_type_t type, size_t initial_capacity)
{
    if (initial_capacity == 0)
        initial_capacity = 16;

    heap_t *heap = malloc(sizeof(heap_t));
    if (heap == NULL)
        return NULL;

    heap->data = malloc(initial_capacity * sizeof(int));
    if (heap->data == NULL)
    {
        free(heap);
        return NULL;
    }

    heap->size = 0;
    heap->capacity = initial_capacity;
    heap->type = type;

    return heap;
}

void heap_destroy(heap_t *heap)
{
    if (heap == NULL)
        return;

    free(heap->data);
    free(heap);
}

// ============================================
// Operations Heapify
// ============================================

void heapify_up(heap_t *heap, size_t index)
{
    while (index > 0)
    {
        size_t parent_idx = parent(index);

        if (!should_swap(heap, heap->data[parent_idx], heap->data[index]))
            break;

        swap(&heap->data[parent_idx], &heap->data[index]);
        index = parent_idx;
    }
}

void heapify_down(heap_t *heap, size_t index)
{
    while (true)
    {
        size_t target = index;
        size_t left = left_child(index);
        size_t right = right_child(index);

        // Comparer avec l'enfant gauche
        if (left < heap->size &&
            should_swap(heap, heap->data[target], heap->data[left]))
        {
            target = left;
        }

        // Comparer avec l'enfant droit
        if (right < heap->size &&
            should_swap(heap, heap->data[target], heap->data[right]))
        {
            target = right;
        }

        // Si aucun swap necessaire, on a termine
        if (target == index)
            break;

        swap(&heap->data[index], &heap->data[target]);
        index = target;
    }
}

// ============================================
// Operations de base
// ============================================

bool heap_insert(heap_t *heap, int value)
{
    if (heap == NULL)
        return false;

    if (!ensure_capacity(heap))
        return false;

    // Inserer a la fin
    heap->data[heap->size] = value;
    heap->size++;

    // Remonter pour maintenir la propriete du heap
    heapify_up(heap, heap->size - 1);

    return true;
}

int heap_extract(heap_t *heap)
{
    if (heap == NULL || heap->size == 0)
        return INT_MIN;

    // Sauvegarder la racine
    int root = heap->data[0];

    // Deplacer le dernier element a la racine
    heap->size--;
    if (heap->size > 0)
    {
        heap->data[0] = heap->data[heap->size];
        heapify_down(heap, 0);
    }

    return root;
}

int heap_peek(const heap_t *heap)
{
    if (heap == NULL || heap->size == 0)
        return INT_MIN;

    return heap->data[0];
}

bool heap_is_empty(const heap_t *heap)
{
    return heap == NULL || heap->size == 0;
}

size_t heap_size(const heap_t *heap)
{
    if (heap == NULL)
        return 0;
    return heap->size;
}

// ============================================
// Build Heap - O(n)
// ============================================

void build_heap(heap_t *heap, int *arr, size_t n)
{
    if (heap == NULL || arr == NULL || n == 0)
        return;

    // S'assurer qu'on a assez de capacite
    if (heap->capacity < n)
    {
        int *new_data = realloc(heap->data, n * sizeof(int));
        if (new_data == NULL)
            return;
        heap->data = new_data;
        heap->capacity = n;
    }

    // Copier les donnees
    memcpy(heap->data, arr, n * sizeof(int));
    heap->size = n;

    // Heapify depuis le dernier noeud interne vers la racine
    // Le dernier noeud interne est a l'index (n/2 - 1)
    for (size_t i = n / 2; i > 0; i--)
    {
        heapify_down(heap, i - 1);
    }
    heapify_down(heap, 0);
}

// ============================================
// Heap Sort - O(n log n)
// ============================================

void heap_sort(int *arr, size_t n, bool ascending)
{
    if (arr == NULL || n <= 1)
        return;

    // Pour tri croissant, on utilise un max-heap
    // Pour tri decroissant, on utilise un min-heap
    heap_type_t type = ascending ? HEAP_MAX : HEAP_MIN;

    heap_t *heap = heap_create(type, n);
    if (heap == NULL)
        return;

    // Construire le heap
    build_heap(heap, arr, n);

    // Extraire les elements un par un
    for (size_t i = n; i > 0; i--)
    {
        arr[i - 1] = heap_extract(heap);
    }

    // Pour tri croissant avec max-heap, on doit inverser
    if (ascending)
    {
        for (size_t i = 0; i < n / 2; i++)
        {
            swap(&arr[i], &arr[n - 1 - i]);
        }
    }

    heap_destroy(heap);
}

// ============================================
// Priority Queue
// ============================================

priority_queue_t *pq_create(bool min_priority)
{
    return heap_create(min_priority ? HEAP_MIN : HEAP_MAX, 16);
}

void pq_destroy(priority_queue_t *pq)
{
    heap_destroy(pq);
}

bool pq_enqueue(priority_queue_t *pq, int priority)
{
    return heap_insert(pq, priority);
}

int pq_dequeue(priority_queue_t *pq)
{
    return heap_extract(pq);
}

int pq_front(const priority_queue_t *pq)
{
    return heap_peek(pq);
}
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : Heap Sort In-Place (sans allocation supplementaire)**

```c
// Version in-place du heap sort
static void heapify_inplace(int *arr, size_t n, size_t i, bool max_heap)
{
    size_t target = i;
    size_t left = 2 * i + 1;
    size_t right = 2 * i + 2;

    if (max_heap)
    {
        if (left < n && arr[left] > arr[target])
            target = left;
        if (right < n && arr[right] > arr[target])
            target = right;
    }
    else
    {
        if (left < n && arr[left] < arr[target])
            target = left;
        if (right < n && arr[right] < arr[target])
            target = right;
    }

    if (target != i)
    {
        swap(&arr[i], &arr[target]);
        heapify_inplace(arr, n, target, max_heap);
    }
}

void heap_sort_inplace(int *arr, size_t n, bool ascending)
{
    // Build max-heap pour tri croissant
    for (size_t i = n / 2; i > 0; i--)
        heapify_inplace(arr, n, i - 1, ascending);

    // Extraire elements un par un
    for (size_t i = n - 1; i > 0; i--)
    {
        swap(&arr[0], &arr[i]);
        heapify_inplace(arr, i, 0, ascending);
    }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Index) : Calcul d'index incorrect**

```c
// MUTANT A: Index enfant incorrect
static inline size_t left_child(size_t i)
{
    return 2 * i;  // ERREUR: devrait etre 2*i + 1
}

static inline size_t right_child(size_t i)
{
    return 2 * i + 1;  // ERREUR: devrait etre 2*i + 2
}
```
**Pourquoi faux :** Avec ces index, l'arbre n'est pas correctement mappe sur le tableau. L'index 0 aurait son enfant gauche a 0 (lui-meme), causant une boucle infinie.

**Mutant B (Heapify) : Heapify_up ne remonte pas assez**

```c
// MUTANT B: S'arrete trop tot
void heapify_up(heap_t *heap, size_t index)
{
    if (index == 0)
        return;

    size_t parent_idx = parent(index);

    if (should_swap(heap, heap->data[parent_idx], heap->data[index]))
    {
        swap(&heap->data[parent_idx], &heap->data[index]);
        // ERREUR: pas de recursion/boucle - ne remonte qu'une fois
    }
}
```
**Pourquoi faux :** L'element ne remonte que d'un niveau, meme s'il devrait remonter jusqu'a la racine. Le heap devient invalide.

**Mutant C (Extract) : Oublie de heapify apres extract**

```c
// MUTANT C: Pas de heapify_down
int heap_extract(heap_t *heap)
{
    if (heap == NULL || heap->size == 0)
        return INT_MIN;

    int root = heap->data[0];
    heap->size--;

    if (heap->size > 0)
    {
        heap->data[0] = heap->data[heap->size];
        // ERREUR: heapify_down(heap, 0) manquant
    }

    return root;
}
```
**Pourquoi faux :** Apres avoir mis le dernier element a la racine, il faut le faire descendre a sa position correcte. Sans cela, le heap perd sa propriete.

**Mutant D (Comparison) : Comparaison inversee pour max-heap**

```c
// MUTANT D: Logique de comparaison inversee
static bool should_swap(heap_t *heap, int parent_val, int child_val)
{
    if (heap->type == HEAP_MAX)
        return parent_val > child_val;  // ERREUR: inversee, cree un min-heap
    else
        return parent_val < child_val;  // ERREUR: inversee, cree un max-heap
}
```
**Pourquoi faux :** Les conditions sont inversees. Un HEAP_MAX se comportera comme un HEAP_MIN et vice versa.

**Mutant E (Build) : Build heap dans le mauvais sens**

```c
// MUTANT E: Heapify dans le mauvais sens
void build_heap(heap_t *heap, int *arr, size_t n)
{
    memcpy(heap->data, arr, n * sizeof(int));
    heap->size = n;

    // ERREUR: heapify_up depuis le debut au lieu de heapify_down depuis la fin
    for (size_t i = 0; i < n; i++)
    {
        heapify_up(heap, i);
    }
}
```
**Pourquoi faux :** Bien que cette approche fonctionne, elle est O(n log n) au lieu de O(n). L'algorithme optimal utilise heapify_down depuis n/2 vers 0.

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Le **heap** combine les avantages d'un arbre binaire et d'un tableau :

1. **Acces O(1)** au min ou max (racine = index 0)
2. **Insertion/Extraction O(log n)** grace a heapify
3. **Stockage compact** - pas de pointeurs, juste un tableau
4. **Build heap O(n)** - plus rapide que n insertions

### 5.2 Propriete du Heap

```
MAX-HEAP: Chaque parent >= ses enfants
          Le maximum est a la racine

MIN-HEAP: Chaque parent <= ses enfants
          Le minimum est a la racine

ATTENTION: Ce n'est PAS un arbre binaire de recherche !
           Les enfants ne sont pas ordonnes gauche < droite
```

### 5.3 Visualisation ASCII

```
STRUCTURE DU HEAP DANS UN TABLEAU:
==================================

Tableau: [100, 19, 36, 17, 3, 25, 1, 2, 7]
          [0]  [1] [2] [3][4] [5][6][7][8]

Arbre correspondant (Max-Heap):

                    100 [0]
                   /    \
               19 [1]    36 [2]
              /   \      /   \
          17 [3]  3 [4] 25 [5] 1 [6]
          /   \
       2 [7]  7 [8]

Formules d'index:
  Parent(i)     = (i - 1) / 2
  LeftChild(i)  = 2 * i + 1
  RightChild(i) = 2 * i + 2


INSERTION (heapify_up):
=======================

Inserer 50 dans le max-heap [100, 19, 36, 17, 3]:

1. Ajouter a la fin:     [100, 19, 36, 17, 3, 50]
                                               ^

2. Comparer avec parent (36): 50 > 36, swap
                         [100, 19, 50, 17, 3, 36]
                               ^-------^

3. Comparer avec parent (100): 50 < 100, STOP

   Resultat:             [100, 19, 50, 17, 3, 36]

        100                      100
       /   \                    /   \
     19    36      -->        19    50
    /  \   /                 /  \   /
   17  3  50                17  3  36


EXTRACTION (heapify_down):
==========================

Extraire max de [100, 50, 36, 17, 3, 25]:

1. Sauver racine: max = 100

2. Deplacer dernier a la racine: [25, 50, 36, 17, 3]
                                  ^------------------^

3. Heapify_down:
   - 25 vs enfants (50, 36): 50 > 25, swap avec 50
     [50, 25, 36, 17, 3]

   - 25 vs enfants (17, 3): 25 > 17 et 25 > 3, STOP

   Resultat: [50, 25, 36, 17, 3], retourne 100

       100                25                 50
      /   \              /  \               /  \
    50    36   -->     50   36    -->     25   36
   /  \   /           /  \               /  \
  17  3  25          17  3              17  3


BUILD HEAP - O(n):
==================

Transformer [4, 10, 3, 5, 1] en max-heap:

1. Commencer par le dernier parent (index 1)

   Index 1 (10): enfants = 5, 1
                 10 > 5 et 10 > 1, OK

   Index 0 (4):  enfants = 10, 3
                 10 > 4, swap
                 [10, 4, 3, 5, 1]
                     ^
                 4 vs enfants 5, 1
                 5 > 4, swap
                 [10, 5, 3, 4, 1]

   Resultat: [10, 5, 3, 4, 1]

       4                  10                 10
      / \                /  \               /  \
    10   3    -->       4    3    -->      5    3
   /  \                / \                / \
  5    1              5   1              4   1


HEAP SORT:
==========

Trier [4, 10, 3, 5, 1] en ordre croissant:

1. Build max-heap: [10, 5, 3, 4, 1]

2. Extraire et placer a la fin:

   Extract 10: [5, 4, 3, 1] + [10]
   Extract 5:  [4, 1, 3] + [5, 10]
   Extract 4:  [3, 1] + [4, 5, 10]
   Extract 3:  [1] + [3, 4, 5, 10]
   Extract 1:  [] + [1, 3, 4, 5, 10]

   Resultat: [1, 3, 4, 5, 10]
```

### 5.4 Comparaison des Complexites

```
+-------------------+----------+----------+----------+
| Operation         | Heap     | Tableau  | BST      |
+-------------------+----------+----------+----------+
| Get min/max       | O(1)     | O(n)     | O(log n) |
| Insert            | O(log n) | O(1)*    | O(log n) |
| Extract min/max   | O(log n) | O(n)     | O(log n) |
| Build from array  | O(n)     | O(1)     | O(n log n)|
| Search            | O(n)     | O(n)     | O(log n) |
+-------------------+----------+----------+----------+
* amorti pour tableau dynamique
```

---

## SECTION 6 : PIEGES

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Index base 1 vs base 0 | Acces hors limites | Formules: (i-1)/2, 2i+1, 2i+2 |
| 2 | Oublier heapify apres extract | Heap invalide | Toujours heapify_down(0) |
| 3 | Heapify_up une seule fois | Element mal place | Boucle jusqu'a la racine |
| 4 | Confondre avec BST | Ordre incorrect | Heap: parent vs enfants seulement |
| 5 | Ne pas verifier heap vide | Crash/undefined | Verifier size > 0 avant extract |
| 6 | Oublier realloc | Buffer overflow | ensure_capacity avant insert |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Dans un max-heap stocke dans un tableau, si un element est a l'index 5, quel est l'index de son parent ?

- A) 2
- B) 3
- C) 4
- D) 10
- E) 11

**Reponse correcte : A**

**Explication :** La formule pour trouver le parent est `(i - 1) / 2`. Pour i = 5 : (5 - 1) / 2 = 4 / 2 = 2. Le parent est a l'index 2.

---

### Question 2 (3 points)
Quelle est la complexite temporelle de la construction d'un heap a partir d'un tableau de n elements en utilisant l'algorithme optimal (heapify_down depuis les feuilles) ?

- A) O(n^2)
- B) O(n log n)
- C) O(n)
- D) O(log n)
- E) O(1)

**Reponse correcte : C**

**Explication :** L'algorithme build_heap avec heapify_down depuis le dernier noeud interne est O(n). La plupart des noeuds sont pres des feuilles et font peu de travail. Mathematiquement, la somme des hauteurs de tous les noeuds est O(n).

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | D.25 |
| **Nom** | heap |
| **Difficulte** | 6/10 |
| **Duree** | 120 min |
| **XP Base** | 200 |
| **Langage** | C17 |
| **Concepts cles** | Heap, Heapify, HeapSort, Priority Queue |
| **Complexite temps** | O(log n) pour insert/extract |
| **Complexite espace** | O(n) |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.25",
  "name": "heap",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "difficulty": 6,
  "xp_base": 200,
  "estimated_time_minutes": 120,
  "complexity": {
    "time": "O(log n)",
    "space": "O(n)"
  },
  "files": {
    "required": ["heap.c", "heap.h"],
    "provided": ["main.c", "Makefile"],
    "tests": ["test_heap.c"]
  },
  "compilation": {
    "command": "gcc -Wall -Wextra -Werror -std=c17 -o heap heap.c main.c",
    "flags": ["-Wall", "-Wextra", "-Werror", "-std=c17"]
  },
  "tests": {
    "unit_tests": "test_heap.c",
    "moulinette": {
      "timeout_seconds": 10,
      "memory_check": true,
      "valgrind_flags": ["--leak-check=full", "--error-exitcode=1"]
    }
  },
  "topics": [
    "heap",
    "binary_heap",
    "min_heap",
    "max_heap",
    "heapify",
    "heap_sort",
    "priority_queue",
    "data_structures"
  ],
  "prerequisites": [
    "D.16",
    "D.17",
    "0.6.3"
  ],
  "learning_objectives": [
    "Comprendre la structure de donnees heap",
    "Implementer les operations heapify_up et heapify_down",
    "Maitriser l'algorithme HeapSort",
    "Utiliser un heap comme file de priorite"
  ],
  "grading": {
    "auto_grade": true,
    "total_points": 200,
    "categories": {
      "basic_operations": 50,
      "heapify": 40,
      "heap_sort": 50,
      "priority_queue": 30,
      "memory_management": 30
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
