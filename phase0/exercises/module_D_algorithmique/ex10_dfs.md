# Exercice D.0.10-a : dfs

**Module :**
D.0.10 — Parcours en Profondeur

**Concept :**
a-d — Depth-first search, stack, visited array, recursive vs iterative

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
- `dfs.c`
- `dfs.h`

### 1.2 Consigne

Implementer le parcours en profondeur (DFS) et ses applications.

**Ta mission :**

```c
// DFS recursif
void dfs_recursive(graph_list *g, int start, int *visited, void (*visit)(int));

// DFS iteratif avec pile explicite
void dfs_iterative(graph_list *g, int start, void (*visit)(int));

// Verifier si le graphe est connexe
int is_connected(graph_list *g);

// Trouver un chemin entre deux sommets
int *find_path_dfs(graph_list *g, int start, int end, int *path_len);

// Detecter un cycle dans un graphe dirige
int has_cycle_directed(graph_list *g);

// Detecter un cycle dans un graphe non-dirige
int has_cycle_undirected(graph_list *g);

// Tri topologique (graphe dirige acyclique)
int *topological_sort(graph_list *g, int *result_size);

// Compter les composantes connexes
int count_connected_components(graph_list *g);
```

**Comportement:**

1. `dfs_recursive(g, 0, visited, print)` -> parcours depuis sommet 0
2. `is_connected(g)` -> 1 si tous les sommets sont atteignables
3. `find_path_dfs(g, 0, 3, &len)` -> chemin de 0 a 3
4. `has_cycle_directed(g)` -> 1 si cycle detecte

**Exemples:**
```
Graphe:
    0 --- 1
    |     |
    3 --- 2

DFS depuis 0: 0 -> 1 -> 2 -> 3
(ou 0 -> 3 -> 2 -> 1 selon l'ordre des adjacences)

Graphe dirige avec cycle:
    0 -> 1 -> 2
    ^         |
    |_________|

has_cycle_directed -> 1

Tri topologique de DAG:
    0 -> 1
    |    |
    v    v
    2 -> 3

Resultat: [0, 1, 2, 3] ou [0, 2, 1, 3]
```

### 1.3 Prototype

```c
// dfs.h
#ifndef DFS_H
#define DFS_H

#include "graph_basics.h"

void dfs_recursive(graph_list *g, int start, int *visited, void (*visit)(int));
void dfs_iterative(graph_list *g, int start, void (*visit)(int));
int is_connected(graph_list *g);
int *find_path_dfs(graph_list *g, int start, int end, int *path_len);
int has_cycle_directed(graph_list *g);
int has_cycle_undirected(graph_list *g);
int *topological_sort(graph_list *g, int *result_size);
int count_connected_components(graph_list *g);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | dfs_recursive order | correct | 10 |
| T02 | dfs_iterative order | correct | 10 |
| T03 | is_connected true | 1 | 10 |
| T04 | is_connected false | 0 | 10 |
| T05 | find_path exists | valid path | 15 |
| T06 | has_cycle directed | correct | 15 |
| T07 | topological_sort | valid order | 15 |
| T08 | count_components | correct | 15 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dfs.h"

void dfs_recursive(graph_list *g, int v, int *visited, void (*visit)(int))
{
    visited[v] = 1;
    if (visit)
        visit(v);

    adj_node *curr = g->adj[v];
    while (curr)
    {
        if (!visited[curr->vertex])
            dfs_recursive(g, curr->vertex, visited, visit);
        curr = curr->next;
    }
}

void dfs_iterative(graph_list *g, int start, void (*visit)(int))
{
    int *visited = calloc(g->num_vertices, sizeof(int));
    int *stack = malloc(g->num_vertices * sizeof(int));
    int top = 0;

    stack[top++] = start;

    while (top > 0)
    {
        int v = stack[--top];

        if (visited[v])
            continue;

        visited[v] = 1;
        if (visit)
            visit(v);

        // Ajouter les voisins non visites a la pile
        adj_node *curr = g->adj[v];
        while (curr)
        {
            if (!visited[curr->vertex])
                stack[top++] = curr->vertex;
            curr = curr->next;
        }
    }

    free(visited);
    free(stack);
}

int is_connected(graph_list *g)
{
    if (!g || g->num_vertices == 0)
        return 1;

    int *visited = calloc(g->num_vertices, sizeof(int));
    dfs_recursive(g, 0, visited, NULL);

    int connected = 1;
    for (int i = 0; i < g->num_vertices; i++)
    {
        if (!visited[i])
        {
            connected = 0;
            break;
        }
    }

    free(visited);
    return connected;
}

int *find_path_dfs(graph_list *g, int start, int end, int *path_len)
{
    *path_len = 0;
    if (!g || start < 0 || end < 0 ||
        start >= g->num_vertices || end >= g->num_vertices)
        return NULL;

    int *visited = calloc(g->num_vertices, sizeof(int));
    int *parent = malloc(g->num_vertices * sizeof(int));
    for (int i = 0; i < g->num_vertices; i++)
        parent[i] = -1;

    // DFS pour trouver le chemin
    int *stack = malloc(g->num_vertices * sizeof(int));
    int top = 0;
    stack[top++] = start;
    visited[start] = 1;
    int found = 0;

    while (top > 0 && !found)
    {
        int v = stack[--top];

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
                stack[top++] = curr->vertex;
            }
            curr = curr->next;
        }
    }

    free(stack);
    free(visited);

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

static int dfs_cycle_directed(graph_list *g, int v, int *visited, int *rec_stack)
{
    visited[v] = 1;
    rec_stack[v] = 1;

    adj_node *curr = g->adj[v];
    while (curr)
    {
        if (!visited[curr->vertex])
        {
            if (dfs_cycle_directed(g, curr->vertex, visited, rec_stack))
                return 1;
        }
        else if (rec_stack[curr->vertex])
        {
            return 1;  // Back edge found
        }
        curr = curr->next;
    }

    rec_stack[v] = 0;
    return 0;
}

int has_cycle_directed(graph_list *g)
{
    if (!g)
        return 0;

    int *visited = calloc(g->num_vertices, sizeof(int));
    int *rec_stack = calloc(g->num_vertices, sizeof(int));
    int has_cycle = 0;

    for (int i = 0; i < g->num_vertices; i++)
    {
        if (!visited[i])
        {
            if (dfs_cycle_directed(g, i, visited, rec_stack))
            {
                has_cycle = 1;
                break;
            }
        }
    }

    free(visited);
    free(rec_stack);
    return has_cycle;
}

static int dfs_cycle_undirected(graph_list *g, int v, int parent, int *visited)
{
    visited[v] = 1;

    adj_node *curr = g->adj[v];
    while (curr)
    {
        if (!visited[curr->vertex])
        {
            if (dfs_cycle_undirected(g, curr->vertex, v, visited))
                return 1;
        }
        else if (curr->vertex != parent)
        {
            return 1;  // Back edge (not to parent)
        }
        curr = curr->next;
    }

    return 0;
}

int has_cycle_undirected(graph_list *g)
{
    if (!g)
        return 0;

    int *visited = calloc(g->num_vertices, sizeof(int));
    int has_cycle = 0;

    for (int i = 0; i < g->num_vertices; i++)
    {
        if (!visited[i])
        {
            if (dfs_cycle_undirected(g, i, -1, visited))
            {
                has_cycle = 1;
                break;
            }
        }
    }

    free(visited);
    return has_cycle;
}

static void dfs_topo(graph_list *g, int v, int *visited, int *stack, int *top)
{
    visited[v] = 1;

    adj_node *curr = g->adj[v];
    while (curr)
    {
        if (!visited[curr->vertex])
            dfs_topo(g, curr->vertex, visited, stack, top);
        curr = curr->next;
    }

    stack[(*top)++] = v;
}

int *topological_sort(graph_list *g, int *result_size)
{
    *result_size = 0;
    if (!g || !g->directed)
        return NULL;

    if (has_cycle_directed(g))
        return NULL;

    int *visited = calloc(g->num_vertices, sizeof(int));
    int *stack = malloc(g->num_vertices * sizeof(int));
    int top = 0;

    for (int i = 0; i < g->num_vertices; i++)
    {
        if (!visited[i])
            dfs_topo(g, i, visited, stack, &top);
    }

    // Inverser le resultat
    int *result = malloc(g->num_vertices * sizeof(int));
    for (int i = 0; i < g->num_vertices; i++)
        result[i] = stack[g->num_vertices - 1 - i];

    free(visited);
    free(stack);
    *result_size = g->num_vertices;
    return result;
}

int count_connected_components(graph_list *g)
{
    if (!g)
        return 0;

    int *visited = calloc(g->num_vertices, sizeof(int));
    int count = 0;

    for (int i = 0; i < g->num_vertices; i++)
    {
        if (!visited[i])
        {
            dfs_recursive(g, i, visited, NULL);
            count++;
        }
    }

    free(visited);
    return count;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: DFS ne marque pas comme visite avant recursion
void dfs_recursive(graph_list *g, int v, int *visited, void (*visit)(int))
{
    if (visit)
        visit(v);
    // visited[v] = 1;  // Devrait etre AVANT la recursion

    adj_node *curr = g->adj[v];
    while (curr)
    {
        if (!visited[curr->vertex])
            dfs_recursive(g, curr->vertex, visited, visit);
        curr = curr->next;
    }
    visited[v] = 1;  // Trop tard, peut causer des revisites
}

// MUTANT 2: Cycle detection ignore back edges
int has_cycle_directed(graph_list *g)
{
    int *visited = calloc(g->num_vertices, sizeof(int));
    // Manque rec_stack pour detecter les back edges
    // Resultat: ne detecte pas les cycles
}

// MUTANT 3: Topological sort n'inverse pas
int *topological_sort(graph_list *g, int *result_size)
{
    // ... DFS pushes to stack ...
    return stack;  // Ordre inverse! Devrait inverser
}

// MUTANT 4: Cycle undirected compte parent comme cycle
static int dfs_cycle_undirected(graph_list *g, int v, int parent, int *visited)
{
    visited[v] = 1;
    adj_node *curr = g->adj[v];
    while (curr)
    {
        if (!visited[curr->vertex])
        {
            if (dfs_cycle_undirected(g, curr->vertex, v, visited))
                return 1;
        }
        else  // Manque: && curr->vertex != parent
        {
            return 1;  // False positive avec le parent
        }
        curr = curr->next;
    }
    return 0;
}

// MUTANT 5: is_connected commence a 0 seulement
int is_connected(graph_list *g)
{
    int *visited = calloc(g->num_vertices, sizeof(int));
    dfs_recursive(g, 0, visited, NULL);
    // Ne verifie pas si tous sont visites
    free(visited);
    return 1;  // Toujours vrai!
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Le **parcours en profondeur (DFS)**:

1. **Explorer en profondeur** - Aller le plus loin possible avant de revenir
2. **Pile (implicite ou explicite)** - Structure LIFO
3. **Applications** - Connexite, cycles, tri topologique
4. **Complexite O(V+E)** - Chaque sommet et arete visite une fois

### 5.3 Visualisation ASCII

```
DFS TRAVERSAL:
      0
     / \
    1   2
   / \   \
  3   4   5

Ordre DFS depuis 0: 0 -> 1 -> 3 -> 4 -> 2 -> 5

RECURSION STACK:
  0 (start)
  |-> 1
  |   |-> 3 (backtrack)
  |   |-> 4 (backtrack)
  |-> 2
      |-> 5 (backtrack)
      (backtrack)
  (done)

CYCLE DETECTION (directed):
  0 -> 1 -> 2
  ^         |
  |_________|

visited = [1, 1, 1]
rec_stack au sommet 2 = [1, 1, 1]
Edge 2->0: 0 est dans rec_stack -> CYCLE!

TRI TOPOLOGIQUE:
  Tasks: 0 depends on nothing
         1 depends on 0
         2 depends on 0, 1
         3 depends on 2

  0 -> 1
  |    |
  v    v
  +->  2 -> 3

  Ordre: 0, 1, 2, 3
```

---

## SECTION 7 : QCM

### Question 1
Quelle structure de donnees est utilisee (implicitement) par le DFS recursif ?

A) File (Queue)
B) Pile (Stack)
C) Heap
D) Liste chainee
E) Tableau

**Reponse correcte: B**

### Question 2
Quelle est la complexite temporelle du DFS ?

A) O(V)
B) O(E)
C) O(V + E)
D) O(V * E)
E) O(V^2)

**Reponse correcte: C**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.10-a",
  "name": "dfs",
  "language": "c",
  "language_version": "c17",
  "files": ["dfs.c", "dfs.h"],
  "depends": ["graph_basics"],
  "tests": {
    "traversal": "dfs_traversal_tests",
    "connectivity": "connectivity_tests",
    "cycles": "cycle_detection_tests",
    "topo": "topological_sort_tests"
  }
}
```
