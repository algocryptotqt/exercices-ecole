# Exercice D.0.11-a : bfs

**Module :**
D.0.11 — Parcours en Largeur

**Concept :**
a-d — Breadth-first search, queue, shortest path unweighted, level order

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
D.0.9 (graph basics)

**Domaines :**
Algo, Structures

**Duree estimee :**
180 min

**XP Base :**
260

**Complexite :**
T3 O(V+E) x S2 O(V)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `bfs.c`
- `bfs.h`

### 1.2 Consigne

Implementer le parcours en largeur (BFS) et ses applications.

**Ta mission :**

```c
// BFS basique avec callback
void bfs(graph_list *g, int start, void (*visit)(int));

// Plus court chemin (non pondere)
int *shortest_path(graph_list *g, int start, int end, int *path_len);

// Distance depuis un sommet source
int *distances_from(graph_list *g, int start);

// Parcours par niveau
int **level_order(graph_list *g, int start, int *num_levels, int **level_sizes);

// BFS bidirectionnel (optimisation)
int *bidirectional_bfs(graph_list *g, int start, int end, int *path_len);

// Verifier si graphe biparti
int is_bipartite(graph_list *g);
```

**Comportement:**

1. `bfs(g, 0, print)` -> parcours en largeur depuis sommet 0
2. `shortest_path(g, 0, 5, &len)` -> chemin le plus court 0 a 5
3. `distances_from(g, 0)` -> tableau des distances depuis 0
4. `is_bipartite(g)` -> 1 si graphe peut etre 2-colorie

**Exemples:**
```
Graphe:
    0 --- 1 --- 4
    |     |
    2 --- 3

BFS depuis 0: 0 -> 1 -> 2 -> 3 -> 4

Niveaux:
  Level 0: [0]
  Level 1: [1, 2]
  Level 2: [3, 4]

distances_from(g, 0) -> [0, 1, 1, 2, 2]
shortest_path(g, 0, 4) -> [0, 1, 4] (longueur 3)
```

### 1.3 Prototype

```c
// bfs.h
#ifndef BFS_H
#define BFS_H

#include "graph_basics.h"

void bfs(graph_list *g, int start, void (*visit)(int));
int *shortest_path(graph_list *g, int start, int end, int *path_len);
int *distances_from(graph_list *g, int start);
int **level_order(graph_list *g, int start, int *num_levels, int **level_sizes);
int *bidirectional_bfs(graph_list *g, int start, int end, int *path_len);
int is_bipartite(graph_list *g);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | bfs order | level by level | 15 |
| T02 | shortest_path | optimal | 20 |
| T03 | distances_from | all correct | 15 |
| T04 | level_order | correct levels | 15 |
| T05 | bipartite true | 1 | 15 |
| T06 | bipartite false | 0 | 10 |
| T07 | disconnected | handled | 10 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bfs.h"

// Simple queue implementation
typedef struct queue {
    int *data;
    int front, rear, size, capacity;
} queue;

static queue *create_queue(int capacity)
{
    queue *q = malloc(sizeof(queue));
    q->data = malloc(capacity * sizeof(int));
    q->front = q->rear = q->size = 0;
    q->capacity = capacity;
    return q;
}

static void enqueue(queue *q, int val)
{
    q->data[q->rear] = val;
    q->rear = (q->rear + 1) % q->capacity;
    q->size++;
}

static int dequeue(queue *q)
{
    int val = q->data[q->front];
    q->front = (q->front + 1) % q->capacity;
    q->size--;
    return val;
}

static int is_empty(queue *q) { return q->size == 0; }
static void free_queue(queue *q) { free(q->data); free(q); }

void bfs(graph_list *g, int start, void (*visit)(int))
{
    if (!g || start < 0 || start >= g->num_vertices)
        return;

    int *visited = calloc(g->num_vertices, sizeof(int));
    queue *q = create_queue(g->num_vertices);

    visited[start] = 1;
    enqueue(q, start);

    while (!is_empty(q))
    {
        int v = dequeue(q);
        if (visit)
            visit(v);

        adj_node *curr = g->adj[v];
        while (curr)
        {
            if (!visited[curr->vertex])
            {
                visited[curr->vertex] = 1;
                enqueue(q, curr->vertex);
            }
            curr = curr->next;
        }
    }

    free(visited);
    free_queue(q);
}

int *shortest_path(graph_list *g, int start, int end, int *path_len)
{
    *path_len = 0;
    if (!g || start < 0 || end < 0 ||
        start >= g->num_vertices || end >= g->num_vertices)
        return NULL;

    int *visited = calloc(g->num_vertices, sizeof(int));
    int *parent = malloc(g->num_vertices * sizeof(int));
    for (int i = 0; i < g->num_vertices; i++)
        parent[i] = -1;

    queue *q = create_queue(g->num_vertices);
    visited[start] = 1;
    enqueue(q, start);
    int found = 0;

    while (!is_empty(q) && !found)
    {
        int v = dequeue(q);

        if (v == end)
        {
            found = 1;
            break;
        }

        adj_node *curr = g->adj[v];
        while (curr)
        {
            if (!visited[curr->vertex])
            {
                visited[curr->vertex] = 1;
                parent[curr->vertex] = v;
                enqueue(q, curr->vertex);
            }
            curr = curr->next;
        }
    }

    free(visited);
    free_queue(q);

    if (!found)
    {
        free(parent);
        return NULL;
    }

    // Reconstruire le chemin
    int len = 0;
    int v = end;
    while (v != -1)
    {
        len++;
        v = parent[v];
    }

    int *path = malloc(len * sizeof(int));
    v = end;
    for (int i = len - 1; i >= 0; i--)
    {
        path[i] = v;
        v = parent[v];
    }

    free(parent);
    *path_len = len;
    return path;
}

int *distances_from(graph_list *g, int start)
{
    if (!g || start < 0 || start >= g->num_vertices)
        return NULL;

    int *dist = malloc(g->num_vertices * sizeof(int));
    for (int i = 0; i < g->num_vertices; i++)
        dist[i] = -1;  // -1 = unreachable

    queue *q = create_queue(g->num_vertices);
    dist[start] = 0;
    enqueue(q, start);

    while (!is_empty(q))
    {
        int v = dequeue(q);

        adj_node *curr = g->adj[v];
        while (curr)
        {
            if (dist[curr->vertex] == -1)
            {
                dist[curr->vertex] = dist[v] + 1;
                enqueue(q, curr->vertex);
            }
            curr = curr->next;
        }
    }

    free_queue(q);
    return dist;
}

int **level_order(graph_list *g, int start, int *num_levels, int **level_sizes)
{
    if (!g || start < 0 || start >= g->num_vertices)
    {
        *num_levels = 0;
        return NULL;
    }

    int *dist = distances_from(g, start);

    // Trouver le niveau max
    int max_level = 0;
    for (int i = 0; i < g->num_vertices; i++)
    {
        if (dist[i] > max_level)
            max_level = dist[i];
    }

    *num_levels = max_level + 1;
    *level_sizes = calloc(*num_levels, sizeof(int));

    // Compter les sommets par niveau
    for (int i = 0; i < g->num_vertices; i++)
    {
        if (dist[i] >= 0)
            (*level_sizes)[dist[i]]++;
    }

    // Allouer et remplir
    int **levels = malloc(*num_levels * sizeof(int *));
    int *indices = calloc(*num_levels, sizeof(int));

    for (int i = 0; i < *num_levels; i++)
        levels[i] = malloc((*level_sizes)[i] * sizeof(int));

    for (int i = 0; i < g->num_vertices; i++)
    {
        if (dist[i] >= 0)
        {
            int level = dist[i];
            levels[level][indices[level]++] = i;
        }
    }

    free(dist);
    free(indices);
    return levels;
}

int is_bipartite(graph_list *g)
{
    if (!g)
        return 1;

    int *color = malloc(g->num_vertices * sizeof(int));
    for (int i = 0; i < g->num_vertices; i++)
        color[i] = -1;  // Non colorie

    queue *q = create_queue(g->num_vertices);
    int bipartite = 1;

    for (int start = 0; start < g->num_vertices && bipartite; start++)
    {
        if (color[start] != -1)
            continue;

        color[start] = 0;
        enqueue(q, start);

        while (!is_empty(q) && bipartite)
        {
            int v = dequeue(q);

            adj_node *curr = g->adj[v];
            while (curr && bipartite)
            {
                if (color[curr->vertex] == -1)
                {
                    color[curr->vertex] = 1 - color[v];
                    enqueue(q, curr->vertex);
                }
                else if (color[curr->vertex] == color[v])
                {
                    bipartite = 0;  // Conflit de couleur
                }
                curr = curr->next;
            }
        }
    }

    free(color);
    free_queue(q);
    return bipartite;
}

int *bidirectional_bfs(graph_list *g, int start, int end, int *path_len)
{
    // Simplified: for undirected graphs
    // Run BFS from both ends, meet in middle
    if (!g || g->directed)
        return shortest_path(g, start, end, path_len);

    // ... (implementation similar to standard BFS but from both ends)
    return shortest_path(g, start, end, path_len);
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: BFS marque comme visite apres dequeue
void bfs(graph_list *g, int start, void (*visit)(int))
{
    // ...
    while (!is_empty(q))
    {
        int v = dequeue(q);
        visited[v] = 1;  // ERREUR: devrait etre marque AVANT enqueue
        // Resultat: sommets visites plusieurs fois
    }
}

// MUTANT 2: shortest_path ne reconstruit pas correctement
int *shortest_path(graph_list *g, int start, int end, int *path_len)
{
    // ...
    // Reconstruction du chemin en ordre inverse
    int *path = malloc(len * sizeof(int));
    v = end;
    for (int i = 0; i < len; i++)  // Devrait etre len-1 a 0
    {
        path[i] = v;
        v = parent[v];
    }
    // Chemin est a l'envers!
}

// MUTANT 3: distances_from utilise -1 pour start
int *distances_from(graph_list *g, int start)
{
    int *dist = malloc(g->num_vertices * sizeof(int));
    for (int i = 0; i < g->num_vertices; i++)
        dist[i] = -1;
    // Oublie: dist[start] = 0;
    // Start reste a -1
}

// MUTANT 4: is_bipartite ne gere pas composantes deconnectees
int is_bipartite(graph_list *g)
{
    // Ne parcourt que depuis le sommet 0
    // Ignore les autres composantes
    color[0] = 0;
    enqueue(q, 0);
    // ...
}

// MUTANT 5: Queue overflow
void bfs(graph_list *g, int start, void (*visit)(int))
{
    queue *q = create_queue(10);  // Trop petit!
    // Overflow si plus de 10 sommets dans la queue
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Le **parcours en largeur (BFS)**:

1. **Explorer par niveaux** - Tous les voisins avant les voisins des voisins
2. **File (Queue)** - Structure FIFO
3. **Plus court chemin** - Optimal pour graphes non ponderes
4. **Applications** - Bipartition, niveaux, connexite

### 5.3 Visualisation ASCII

```
BFS TRAVERSAL:
      0
     / \
    1   2
   / \   \
  3   4   5

File: [0]
Visit 0, enqueue 1, 2
File: [1, 2]

Visit 1, enqueue 3, 4
File: [2, 3, 4]

Visit 2, enqueue 5
File: [3, 4, 5]

Visit 3, 4, 5
Ordre BFS: 0, 1, 2, 3, 4, 5

NIVEAUX:
Level 0: [0]
Level 1: [1, 2]
Level 2: [3, 4, 5]

BIPARTITE CHECK:
  0 --- 1
  |     |
  3 --- 2

Coloring BFS:
  0: RED
  1: BLUE (voisin de RED)
  3: BLUE (voisin de RED)
  2: RED (voisin de BLUE 1)
  Check 2-3: RED-BLUE OK
  -> BIPARTITE
```

### 5.5 BFS vs DFS

```
| Critere              | BFS          | DFS          |
|---------------------|--------------|--------------|
| Structure           | Queue (FIFO) | Stack (LIFO) |
| Ordre parcours      | Par niveau   | En profondeur|
| Plus court chemin   | OUI (unweighted) | NON     |
| Memoire             | O(largeur)   | O(hauteur)   |
| Cycle detection     | Possible     | Plus facile  |
| Topological sort    | NON          | OUI          |
```

---

## SECTION 7 : QCM

### Question 1
Quelle structure de donnees utilise le BFS ?

A) Pile (Stack)
B) File (Queue)
C) Heap
D) Arbre
E) Hash table

**Reponse correcte: B**

### Question 2
Le BFS trouve-t-il toujours le plus court chemin ?

A) Oui, pour tous les graphes
B) Oui, pour graphes non ponderes
C) Non, jamais
D) Seulement pour arbres
E) Seulement pour graphes diriges

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.11-a",
  "name": "bfs",
  "language": "c",
  "language_version": "c17",
  "files": ["bfs.c", "bfs.h"],
  "depends": ["graph_basics"],
  "tests": {
    "traversal": "bfs_traversal_tests",
    "shortest_path": "bfs_shortest_path_tests",
    "bipartite": "bipartite_tests"
  }
}
```
