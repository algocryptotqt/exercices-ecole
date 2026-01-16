# Exercice D.0.9-a : graph_basics

**Module :**
D.0.9 — Structures de Graphes

**Concept :**
a-e — Adjacency list, adjacency matrix, directed/undirected, weighted

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.6.27 (linked lists), 0.5.15 (matrices)

**Domaines :**
Algo, Structures

**Duree estimee :**
200 min

**XP Base :**
280

**Complexite :**
T2 O(V+E) x S3 O(V+E) ou O(V^2)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `graph_basics.c`
- `graph_basics.h`

### 1.2 Consigne

Implementer des structures de graphes et operations de base.

**Ta mission :**

```c
// Structure pour liste d'adjacence
typedef struct adj_node {
    int vertex;
    int weight;
    struct adj_node *next;
} adj_node;

typedef struct graph_list {
    int num_vertices;
    int directed;
    adj_node **adj;  // Tableau de listes
} graph_list;

// Structure pour matrice d'adjacence
typedef struct graph_matrix {
    int num_vertices;
    int directed;
    int **matrix;  // Matrice V x V
} graph_matrix;

// Creation/destruction
graph_list *create_graph_list(int vertices, int directed);
graph_matrix *create_graph_matrix(int vertices, int directed);
void free_graph_list(graph_list *g);
void free_graph_matrix(graph_matrix *g);

// Ajouter/supprimer aretes
void add_edge_list(graph_list *g, int src, int dst, int weight);
void add_edge_matrix(graph_matrix *g, int src, int dst, int weight);
void remove_edge_list(graph_list *g, int src, int dst);
void remove_edge_matrix(graph_matrix *g, int src, int dst);

// Requetes
int has_edge_list(graph_list *g, int src, int dst);
int has_edge_matrix(graph_matrix *g, int src, int dst);
int degree_list(graph_list *g, int vertex);
int degree_matrix(graph_matrix *g, int vertex);

// Conversion
graph_matrix *list_to_matrix(graph_list *g);
graph_list *matrix_to_list(graph_matrix *g);

// Affichage
void print_graph_list(graph_list *g);
void print_graph_matrix(graph_matrix *g);
```

**Comportement:**

1. `create_graph_list(5, 0)` -> graphe non-dirige a 5 sommets
2. `add_edge_list(g, 0, 1, 10)` -> arete 0-1 de poids 10
3. `has_edge_list(g, 0, 1)` -> 1
4. `degree_list(g, 0)` -> nombre d'aretes adjacentes

**Exemples:**
```
Graphe non-dirige:
    0 --- 1
    |     |
    3 --- 2

Liste d'adjacence:
0: -> 1 -> 3
1: -> 0 -> 2
2: -> 1 -> 3
3: -> 0 -> 2

Matrice d'adjacence:
    0  1  2  3
0 [ 0  1  0  1 ]
1 [ 1  0  1  0 ]
2 [ 0  1  0  1 ]
3 [ 1  0  1  0 ]
```

### 1.3 Prototype

```c
// graph_basics.h
#ifndef GRAPH_BASICS_H
#define GRAPH_BASICS_H

typedef struct adj_node {
    int vertex;
    int weight;
    struct adj_node *next;
} adj_node;

typedef struct graph_list {
    int num_vertices;
    int directed;
    adj_node **adj;
} graph_list;

typedef struct graph_matrix {
    int num_vertices;
    int directed;
    int **matrix;
} graph_matrix;

graph_list *create_graph_list(int vertices, int directed);
graph_matrix *create_graph_matrix(int vertices, int directed);
void free_graph_list(graph_list *g);
void free_graph_matrix(graph_matrix *g);

void add_edge_list(graph_list *g, int src, int dst, int weight);
void add_edge_matrix(graph_matrix *g, int src, int dst, int weight);
void remove_edge_list(graph_list *g, int src, int dst);
void remove_edge_matrix(graph_matrix *g, int src, int dst);

int has_edge_list(graph_list *g, int src, int dst);
int has_edge_matrix(graph_matrix *g, int src, int dst);
int degree_list(graph_list *g, int vertex);
int degree_matrix(graph_matrix *g, int vertex);

graph_matrix *list_to_matrix(graph_list *g);
graph_list *matrix_to_list(graph_matrix *g);

void print_graph_list(graph_list *g);
void print_graph_matrix(graph_matrix *g);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | create_graph_list | valid | 10 |
| T02 | add_edge undirected | both directions | 15 |
| T03 | add_edge directed | one direction | 10 |
| T04 | has_edge | correct | 10 |
| T05 | degree | correct count | 15 |
| T06 | remove_edge | removed | 10 |
| T07 | list_to_matrix | equivalent | 15 |
| T08 | memory cleanup | no leaks | 15 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include <stdlib.h>
#include "graph_basics.h"

graph_list *create_graph_list(int vertices, int directed)
{
    graph_list *g = malloc(sizeof(graph_list));
    g->num_vertices = vertices;
    g->directed = directed;
    g->adj = calloc(vertices, sizeof(adj_node *));
    return g;
}

graph_matrix *create_graph_matrix(int vertices, int directed)
{
    graph_matrix *g = malloc(sizeof(graph_matrix));
    g->num_vertices = vertices;
    g->directed = directed;
    g->matrix = malloc(vertices * sizeof(int *));

    for (int i = 0; i < vertices; i++)
    {
        g->matrix[i] = calloc(vertices, sizeof(int));
    }

    return g;
}

void free_graph_list(graph_list *g)
{
    if (!g) return;

    for (int i = 0; i < g->num_vertices; i++)
    {
        adj_node *curr = g->adj[i];
        while (curr)
        {
            adj_node *tmp = curr;
            curr = curr->next;
            free(tmp);
        }
    }

    free(g->adj);
    free(g);
}

void free_graph_matrix(graph_matrix *g)
{
    if (!g) return;

    for (int i = 0; i < g->num_vertices; i++)
        free(g->matrix[i]);

    free(g->matrix);
    free(g);
}

static adj_node *create_node(int vertex, int weight)
{
    adj_node *node = malloc(sizeof(adj_node));
    node->vertex = vertex;
    node->weight = weight;
    node->next = NULL;
    return node;
}

void add_edge_list(graph_list *g, int src, int dst, int weight)
{
    if (!g || src < 0 || src >= g->num_vertices ||
        dst < 0 || dst >= g->num_vertices)
        return;

    // Ajouter src -> dst
    adj_node *node = create_node(dst, weight);
    node->next = g->adj[src];
    g->adj[src] = node;

    // Si non-dirige, ajouter aussi dst -> src
    if (!g->directed)
    {
        node = create_node(src, weight);
        node->next = g->adj[dst];
        g->adj[dst] = node;
    }
}

void add_edge_matrix(graph_matrix *g, int src, int dst, int weight)
{
    if (!g || src < 0 || src >= g->num_vertices ||
        dst < 0 || dst >= g->num_vertices)
        return;

    g->matrix[src][dst] = weight ? weight : 1;

    if (!g->directed)
        g->matrix[dst][src] = weight ? weight : 1;
}

void remove_edge_list(graph_list *g, int src, int dst)
{
    if (!g || src < 0 || src >= g->num_vertices)
        return;

    // Supprimer de la liste src
    adj_node **curr = &g->adj[src];
    while (*curr)
    {
        if ((*curr)->vertex == dst)
        {
            adj_node *tmp = *curr;
            *curr = (*curr)->next;
            free(tmp);
            break;
        }
        curr = &(*curr)->next;
    }

    // Si non-dirige, supprimer aussi de dst
    if (!g->directed && dst >= 0 && dst < g->num_vertices)
    {
        curr = &g->adj[dst];
        while (*curr)
        {
            if ((*curr)->vertex == src)
            {
                adj_node *tmp = *curr;
                *curr = (*curr)->next;
                free(tmp);
                break;
            }
            curr = &(*curr)->next;
        }
    }
}

void remove_edge_matrix(graph_matrix *g, int src, int dst)
{
    if (!g || src < 0 || src >= g->num_vertices ||
        dst < 0 || dst >= g->num_vertices)
        return;

    g->matrix[src][dst] = 0;

    if (!g->directed)
        g->matrix[dst][src] = 0;
}

int has_edge_list(graph_list *g, int src, int dst)
{
    if (!g || src < 0 || src >= g->num_vertices)
        return 0;

    adj_node *curr = g->adj[src];
    while (curr)
    {
        if (curr->vertex == dst)
            return 1;
        curr = curr->next;
    }
    return 0;
}

int has_edge_matrix(graph_matrix *g, int src, int dst)
{
    if (!g || src < 0 || src >= g->num_vertices ||
        dst < 0 || dst >= g->num_vertices)
        return 0;

    return g->matrix[src][dst] != 0;
}

int degree_list(graph_list *g, int vertex)
{
    if (!g || vertex < 0 || vertex >= g->num_vertices)
        return 0;

    int count = 0;
    adj_node *curr = g->adj[vertex];
    while (curr)
    {
        count++;
        curr = curr->next;
    }
    return count;
}

int degree_matrix(graph_matrix *g, int vertex)
{
    if (!g || vertex < 0 || vertex >= g->num_vertices)
        return 0;

    int count = 0;
    for (int i = 0; i < g->num_vertices; i++)
    {
        if (g->matrix[vertex][i] != 0)
            count++;
    }
    return count;
}

graph_matrix *list_to_matrix(graph_list *g)
{
    if (!g) return NULL;

    graph_matrix *m = create_graph_matrix(g->num_vertices, g->directed);

    for (int i = 0; i < g->num_vertices; i++)
    {
        adj_node *curr = g->adj[i];
        while (curr)
        {
            m->matrix[i][curr->vertex] = curr->weight ? curr->weight : 1;
            curr = curr->next;
        }
    }

    return m;
}

graph_list *matrix_to_list(graph_matrix *g)
{
    if (!g) return NULL;

    graph_list *l = create_graph_list(g->num_vertices, g->directed);

    for (int i = 0; i < g->num_vertices; i++)
    {
        for (int j = 0; j < g->num_vertices; j++)
        {
            if (g->matrix[i][j] != 0)
            {
                // Pour non-dirige, n'ajouter qu'une fois
                if (g->directed || i <= j)
                {
                    adj_node *node = create_node(j, g->matrix[i][j]);
                    node->next = l->adj[i];
                    l->adj[i] = node;

                    if (!g->directed && i != j)
                    {
                        node = create_node(i, g->matrix[i][j]);
                        node->next = l->adj[j];
                        l->adj[j] = node;
                    }
                }
            }
        }
    }

    return l;
}

void print_graph_list(graph_list *g)
{
    if (!g) return;

    printf("Graph (adjacency list, %s):\n",
           g->directed ? "directed" : "undirected");

    for (int i = 0; i < g->num_vertices; i++)
    {
        printf("%d: ", i);
        adj_node *curr = g->adj[i];
        while (curr)
        {
            printf("-> %d(%d) ", curr->vertex, curr->weight);
            curr = curr->next;
        }
        printf("\n");
    }
}

void print_graph_matrix(graph_matrix *g)
{
    if (!g) return;

    printf("Graph (adjacency matrix, %s):\n",
           g->directed ? "directed" : "undirected");

    printf("   ");
    for (int i = 0; i < g->num_vertices; i++)
        printf("%3d", i);
    printf("\n");

    for (int i = 0; i < g->num_vertices; i++)
    {
        printf("%3d", i);
        for (int j = 0; j < g->num_vertices; j++)
            printf("%3d", g->matrix[i][j]);
        printf("\n");
    }
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: add_edge non-dirige n'ajoute pas l'arete inverse
void add_edge_list(graph_list *g, int src, int dst, int weight)
{
    adj_node *node = create_node(dst, weight);
    node->next = g->adj[src];
    g->adj[src] = node;
    // Oublie d'ajouter dst -> src pour graphe non-dirige
}

// MUTANT 2: Memory leak dans remove_edge
void remove_edge_list(graph_list *g, int src, int dst)
{
    adj_node **curr = &g->adj[src];
    while (*curr)
    {
        if ((*curr)->vertex == dst)
        {
            *curr = (*curr)->next;  // Oublie free()
            break;
        }
        curr = &(*curr)->next;
    }
}

// MUTANT 3: has_edge ne verifie pas les bornes
int has_edge_list(graph_list *g, int src, int dst)
{
    // Pas de verification de src < 0 || src >= num_vertices
    adj_node *curr = g->adj[src];  // Potential segfault
    // ...
}

// MUTANT 4: degree compte les aretes deux fois
int degree_matrix(graph_matrix *g, int vertex)
{
    int count = 0;
    for (int i = 0; i < g->num_vertices; i++)
    {
        if (g->matrix[vertex][i] != 0)
            count++;
        if (g->matrix[i][vertex] != 0)  // Compte deux fois
            count++;
    }
    return count;
}

// MUTANT 5: free_graph_list incomplet
void free_graph_list(graph_list *g)
{
    free(g->adj);  // Ne libere pas les noeuds individuels
    free(g);
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **structures de graphes**:

1. **Sommet (vertex)** - Un noeud du graphe
2. **Arete (edge)** - Une connexion entre deux sommets
3. **Liste d'adjacence** - Efficace en memoire pour graphes sparse
4. **Matrice d'adjacence** - Acces O(1) pour graphes denses

### 5.3 Visualisation ASCII

```
GRAPHE NON-DIRIGE:
     0
    / \
   1---2
    \ /
     3

LISTE D'ADJACENCE:          MATRICE D'ADJACENCE:
0: -> 1 -> 2                    0  1  2  3
1: -> 0 -> 2 -> 3            0 [0  1  1  0]
2: -> 0 -> 1 -> 3            1 [1  0  1  1]
3: -> 1 -> 2                 2 [1  1  0  1]
                             3 [0  1  1  0]

COMPARAISON:
| Operation      | Liste    | Matrice |
|----------------|----------|---------|
| Ajouter arete  | O(1)     | O(1)    |
| Supprimer      | O(degree)| O(1)    |
| Has edge       | O(degree)| O(1)    |
| Espace         | O(V + E) | O(V^2)  |
| Parcourir adj  | O(degree)| O(V)    |
```

---

## SECTION 7 : QCM

### Question 1
Quelle representation est meilleure pour un graphe sparse (peu d'aretes) ?

A) Matrice d'adjacence
B) Liste d'adjacence
C) Equivalent
D) Depend du nombre de sommets
E) Aucune

**Reponse correcte: B**

### Question 2
Quelle est la complexite spatiale d'une matrice d'adjacence ?

A) O(V)
B) O(E)
C) O(V + E)
D) O(V^2)
E) O(V * E)

**Reponse correcte: D**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.9-a",
  "name": "graph_basics",
  "language": "c",
  "language_version": "c17",
  "files": ["graph_basics.c", "graph_basics.h"],
  "tests": {
    "create": "graph_creation_tests",
    "edges": "edge_manipulation_tests",
    "conversion": "list_matrix_conversion_tests"
  }
}
```
