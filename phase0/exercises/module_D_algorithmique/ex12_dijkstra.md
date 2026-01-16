# Exercice D.0.12-a : dijkstra

**Module :**
D.0.12 — Algorithme de Dijkstra

**Concept :**
a-d — Shortest path weighted, priority queue, relaxation, non-negative weights

**Difficulte :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
code

**Tiers :**
2 — Melange concepts

**Langage :**
C17

**Prerequis :**
D.0.11 (bfs), 0.6.28 (heap)

**Domaines :**
Algo, Structures

**Duree estimee :**
240 min

**XP Base :**
320

**Complexite :**
T4 O((V+E) log V) x S2 O(V)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `dijkstra.c`
- `dijkstra.h`

### 1.2 Consigne

Implementer l'algorithme de Dijkstra pour le plus court chemin pondere.

**Ta mission :**

```c
// Structure pour le resultat
typedef struct dijkstra_result {
    int *dist;      // Distances depuis la source
    int *parent;    // Parent dans le chemin optimal
    int source;
} dijkstra_result;

// Dijkstra depuis un sommet source
dijkstra_result *dijkstra(graph_list *g, int source);

// Liberer le resultat
void free_dijkstra_result(dijkstra_result *result);

// Obtenir le chemin vers une destination
int *get_path(dijkstra_result *result, int dest, int *path_len);

// Obtenir la distance vers une destination
int get_distance(dijkstra_result *result, int dest);

// Version avec min-heap explicite
dijkstra_result *dijkstra_heap(graph_list *g, int source);

// Dijkstra avec arret precoce (une seule destination)
int dijkstra_single(graph_list *g, int source, int dest);
```

**Comportement:**

1. `dijkstra(g, 0)` -> distances depuis sommet 0 vers tous
2. `get_path(result, 5, &len)` -> chemin optimal de 0 a 5
3. `get_distance(result, 3)` -> distance minimale de 0 a 3

**Exemples:**
```
Graphe pondere:
    0 --5-- 1
    |       |
    2       3
    |       |
    3 --1-- 2

dijkstra(g, 0):
  dist[0] = 0
  dist[1] = 5
  dist[2] = 6  (0 -> 3 -> 2)
  dist[3] = 2

get_path(result, 2) -> [0, 3, 2]
get_distance(result, 2) -> 6
```

### 1.3 Prototype

```c
// dijkstra.h
#ifndef DIJKSTRA_H
#define DIJKSTRA_H

#include "graph_basics.h"

typedef struct dijkstra_result {
    int *dist;
    int *parent;
    int source;
    int num_vertices;
} dijkstra_result;

dijkstra_result *dijkstra(graph_list *g, int source);
void free_dijkstra_result(dijkstra_result *result);
int *get_path(dijkstra_result *result, int dest, int *path_len);
int get_distance(dijkstra_result *result, int dest);
dijkstra_result *dijkstra_heap(graph_list *g, int source);
int dijkstra_single(graph_list *g, int source, int dest);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | dijkstra simple | correct distances | 15 |
| T02 | dijkstra complex | all paths optimal | 20 |
| T03 | get_path | correct path | 15 |
| T04 | get_distance | correct | 10 |
| T05 | unreachable | INT_MAX | 10 |
| T06 | dijkstra_single | optimal | 15 |
| T07 | negative weights | handled/rejected | 10 |
| T08 | memory cleanup | no leaks | 5 |

### 4.3 Solution de reference

```c
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include "dijkstra.h"

// Min-heap pour priority queue
typedef struct heap_node {
    int vertex;
    int dist;
} heap_node;

typedef struct min_heap {
    heap_node *nodes;
    int *pos;      // Position de chaque vertex dans le heap
    int size;
    int capacity;
} min_heap;

static min_heap *create_min_heap(int capacity)
{
    min_heap *h = malloc(sizeof(min_heap));
    h->nodes = malloc(capacity * sizeof(heap_node));
    h->pos = malloc(capacity * sizeof(int));
    h->size = 0;
    h->capacity = capacity;
    return h;
}

static void swap_nodes(min_heap *h, int i, int j)
{
    h->pos[h->nodes[i].vertex] = j;
    h->pos[h->nodes[j].vertex] = i;

    heap_node tmp = h->nodes[i];
    h->nodes[i] = h->nodes[j];
    h->nodes[j] = tmp;
}

static void heapify_up(min_heap *h, int idx)
{
    while (idx > 0)
    {
        int parent = (idx - 1) / 2;
        if (h->nodes[parent].dist <= h->nodes[idx].dist)
            break;
        swap_nodes(h, parent, idx);
        idx = parent;
    }
}

static void heapify_down(min_heap *h, int idx)
{
    int smallest = idx;

    while (1)
    {
        int left = 2 * idx + 1;
        int right = 2 * idx + 2;

        if (left < h->size && h->nodes[left].dist < h->nodes[smallest].dist)
            smallest = left;
        if (right < h->size && h->nodes[right].dist < h->nodes[smallest].dist)
            smallest = right;

        if (smallest == idx)
            break;

        swap_nodes(h, idx, smallest);
        idx = smallest;
    }
}

static heap_node extract_min(min_heap *h)
{
    heap_node min = h->nodes[0];
    h->nodes[0] = h->nodes[--h->size];
    h->pos[h->nodes[0].vertex] = 0;
    heapify_down(h, 0);
    return min;
}

static void decrease_key(min_heap *h, int vertex, int new_dist)
{
    int idx = h->pos[vertex];
    h->nodes[idx].dist = new_dist;
    heapify_up(h, idx);
}

static int is_in_heap(min_heap *h, int vertex)
{
    return h->pos[vertex] < h->size;
}

static void free_min_heap(min_heap *h)
{
    free(h->nodes);
    free(h->pos);
    free(h);
}

dijkstra_result *dijkstra(graph_list *g, int source)
{
    if (!g || source < 0 || source >= g->num_vertices)
        return NULL;

    int V = g->num_vertices;

    dijkstra_result *result = malloc(sizeof(dijkstra_result));
    result->dist = malloc(V * sizeof(int));
    result->parent = malloc(V * sizeof(int));
    result->source = source;
    result->num_vertices = V;

    // Initialiser
    for (int i = 0; i < V; i++)
    {
        result->dist[i] = INT_MAX;
        result->parent[i] = -1;
    }
    result->dist[source] = 0;

    // Creer min-heap
    min_heap *h = create_min_heap(V);
    for (int i = 0; i < V; i++)
    {
        h->nodes[i].vertex = i;
        h->nodes[i].dist = result->dist[i];
        h->pos[i] = i;
    }
    h->size = V;

    // Mettre source en premier
    swap_nodes(h, 0, source);

    while (h->size > 0)
    {
        heap_node min = extract_min(h);
        int u = min.vertex;

        if (result->dist[u] == INT_MAX)
            break;  // Tous les restants sont inatteignables

        // Relaxation des voisins
        adj_node *curr = g->adj[u];
        while (curr)
        {
            int v = curr->vertex;
            int weight = curr->weight;

            if (is_in_heap(h, v) && result->dist[u] != INT_MAX)
            {
                int new_dist = result->dist[u] + weight;
                if (new_dist < result->dist[v])
                {
                    result->dist[v] = new_dist;
                    result->parent[v] = u;
                    decrease_key(h, v, new_dist);
                }
            }
            curr = curr->next;
        }
    }

    free_min_heap(h);
    return result;
}

void free_dijkstra_result(dijkstra_result *result)
{
    if (result)
    {
        free(result->dist);
        free(result->parent);
        free(result);
    }
}

int *get_path(dijkstra_result *result, int dest, int *path_len)
{
    *path_len = 0;
    if (!result || dest < 0 || dest >= result->num_vertices)
        return NULL;

    if (result->dist[dest] == INT_MAX)
        return NULL;  // Inatteignable

    // Compter la longueur du chemin
    int len = 0;
    int v = dest;
    while (v != -1)
    {
        len++;
        v = result->parent[v];
    }

    // Construire le chemin
    int *path = malloc(len * sizeof(int));
    v = dest;
    for (int i = len - 1; i >= 0; i--)
    {
        path[i] = v;
        v = result->parent[v];
    }

    *path_len = len;
    return path;
}

int get_distance(dijkstra_result *result, int dest)
{
    if (!result || dest < 0 || dest >= result->num_vertices)
        return INT_MAX;
    return result->dist[dest];
}

int dijkstra_single(graph_list *g, int source, int dest)
{
    dijkstra_result *result = dijkstra(g, source);
    if (!result)
        return INT_MAX;

    int distance = get_distance(result, dest);
    free_dijkstra_result(result);
    return distance;
}

dijkstra_result *dijkstra_heap(graph_list *g, int source)
{
    return dijkstra(g, source);  // Meme implementation
}
```

### 4.10 Solutions Mutantes

```rust
// MUTANT 1: N'initialise pas dist a INT_MAX
for (int i = 0; i < V; i++)
{
    result->dist[i] = 0;  // Devrait etre INT_MAX
    result->parent[i] = -1;
}

// MUTANT 2: Relaxation avec mauvaise condition
if (new_dist <= result->dist[v])  // <= au lieu de <
{
    result->dist[v] = new_dist;
    // Boucle infinie possible
}

// MUTANT 3: Oublie de verifier overflow
int new_dist = result->dist[u] + weight;
// Si dist[u] = INT_MAX, overflow!

// MUTANT 4: get_path reconstruit a l'envers
int *path = malloc(len * sizeof(int));
v = dest;
for (int i = 0; i < len; i++)  // Mauvais ordre
{
    path[i] = v;
    v = result->parent[v];
}

// MUTANT 5: dijkstra_single ne libere pas result
int dijkstra_single(graph_list *g, int source, int dest)
{
    dijkstra_result *result = dijkstra(g, source);
    return get_distance(result, dest);
    // Memory leak!
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

L'**algorithme de Dijkstra**:

1. **Plus court chemin pondere** - Trouve le chemin optimal
2. **Greedy** - Toujours explore le sommet le plus proche
3. **Priority Queue** - Min-heap pour efficacite
4. **Relaxation** - Met a jour les distances si meilleur chemin trouve

### 5.3 Visualisation ASCII

```
DIJKSTRA EXECUTION:

Graphe:
    0 --5-- 1
    |       |
    2       3
    |       |
    3 --1-- 2

Initial: dist = [0, INF, INF, INF]
         heap = [(0,0), (1,INF), (2,INF), (3,INF)]

Step 1: Extract (0,0)
  Relax 0->1 (w=5): dist[1] = min(INF, 0+5) = 5
  Relax 0->3 (w=2): dist[3] = min(INF, 0+2) = 2
  dist = [0, 5, INF, 2]

Step 2: Extract (3,2)  (plus petit!)
  Relax 3->2 (w=1): dist[2] = min(INF, 2+1) = 3
  dist = [0, 5, 3, 2]

Step 3: Extract (2,3)
  Relax 2->1 (w=3): dist[1] = min(5, 3+3) = 5 (pas change)
  dist = [0, 5, 3, 2]

Step 4: Extract (1,5)
  Pas de meilleur chemin
  dist = [0, 5, 3, 2]

FINAL: dist = [0, 5, 3, 2]
       Chemin 0->2: 0 -> 3 -> 2 (cout 3)
```

### 5.5 Limitations

```
DIJKSTRA NE FONCTIONNE PAS AVEC:
- Poids negatifs (utiliser Bellman-Ford)
- Cycles negatifs (detection necessaire)

COMPLEXITE:
- Avec tableau simple: O(V^2)
- Avec binary heap: O((V+E) log V)
- Avec Fibonacci heap: O(E + V log V)
```

---

## SECTION 7 : QCM

### Question 1
Dijkstra fonctionne-t-il avec des poids negatifs ?

A) Oui, toujours
B) Non, jamais
C) Seulement sans cycles negatifs
D) Avec modification mineure
E) Depend de l'implementation

**Reponse correcte: B**

### Question 2
Quelle structure est utilisee pour optimiser Dijkstra ?

A) Stack
B) Queue
C) Priority Queue (Min-Heap)
D) Linked List
E) Hash Table

**Reponse correcte: C**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.12-a",
  "name": "dijkstra",
  "language": "c",
  "language_version": "c17",
  "files": ["dijkstra.c", "dijkstra.h"],
  "depends": ["graph_basics"],
  "tests": {
    "shortest_path": "dijkstra_shortest_path_tests",
    "path_reconstruction": "path_reconstruction_tests"
  }
}
```
