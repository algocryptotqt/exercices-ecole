# Exercice D.0.32-a : shortest_paths

**Module :**
D.0.32 — All-Pairs Shortest Paths

**Concept :**
a-e — Bellman-Ford, Floyd-Warshall, negative cycle detection, path reconstruction, Johnson's algorithm

**Difficulte :**
★★★★★★★☆☆☆ (7/10)

**Type :**
code

**Tiers :**
3 — Algorithmes avances

**Langage :**
C17

**Prerequis :**
D.0.9 (graph basics), D.0.12 (dijkstra), D.0.13 (dynamic programming)

**Domaines :**
Algo, Structures, Graphes, Optimisation

**Duree estimee :**
300 min

**XP Base :**
225

**Complexite :**
T[N] O(V^3) x S[N] O(V^2)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `shortest_paths.c`
- `shortest_paths.h`

### 1.2 Consigne

Implementer les algorithmes de plus courts chemins entre toutes les paires de sommets, incluant la gestion des poids negatifs et la detection de cycles negatifs.

**Ta mission :**

```c
// Structure pour representer un graphe pondere avec aretes
typedef struct edge {
    int src;
    int dest;
    int weight;
} edge;

typedef struct weighted_graph {
    int num_vertices;
    int num_edges;
    edge *edges;          // Liste d'aretes pour Bellman-Ford
    int **adj_matrix;     // Matrice d'adjacence pour Floyd-Warshall
} weighted_graph;

// Structure pour le resultat des plus courts chemins
typedef struct shortest_path_result {
    int **dist;           // dist[i][j] = distance de i a j
    int **next;           // next[i][j] = prochain sommet sur le chemin i->j
    int num_vertices;
    int has_negative_cycle;
} shortest_path_result;

// Bellman-Ford depuis un sommet source unique
// Gere les poids negatifs et detecte les cycles negatifs
int *bellman_ford(weighted_graph *g, int source, int *has_neg_cycle);

// Floyd-Warshall pour toutes les paires
// Retourne la matrice des distances et des predecesseurs
shortest_path_result *floyd_warshall(weighted_graph *g);

// Detection de cycle negatif
int detect_negative_cycle(weighted_graph *g);

// Reconstruction du chemin entre deux sommets
int *reconstruct_path(shortest_path_result *result, int src, int dest, int *path_len);

// Johnson's algorithm pour graphes creux
shortest_path_result *johnson(weighted_graph *g);

// Liberer le resultat
void free_shortest_path_result(shortest_path_result *result);

// Utilitaires de graphe
weighted_graph *create_weighted_graph(int vertices, int edges);
void add_weighted_edge(weighted_graph *g, int idx, int src, int dest, int weight);
void free_weighted_graph(weighted_graph *g);
```

**Comportement:**

1. `bellman_ford(g, 0, &neg)` -> distances depuis sommet 0
2. `floyd_warshall(g)` -> matrice complete des distances
3. `detect_negative_cycle(g)` -> 1 si cycle negatif existe
4. `reconstruct_path(result, 0, 4, &len)` -> chemin de 0 a 4
5. `johnson(g)` -> APSP efficace pour graphes creux

**Exemples:**
```
Graphe pondere (5 sommets):

    0 --3--> 1 --2--> 2
    |        |        |
    7        -4       1
    |        |        |
    v        v        v
    3 <--6-- 4 <--5-- 2

Aretes: (0,1,3), (0,3,7), (1,2,2), (1,4,-4), (2,4,5), (4,3,6), (2,4,1)

Bellman-Ford depuis 0:
  dist[0] = 0
  dist[1] = 3
  dist[2] = 5
  dist[3] = 5  (0 -> 1 -> 4 -> 3 = 3 + (-4) + 6 = 5)
  dist[4] = -1 (0 -> 1 -> 4 = 3 + (-4) = -1)

Floyd-Warshall:
  Matrice dist[][] apres completion:
       0    1    2    3    4
  0 [  0    3    5    5   -1 ]
  1 [ INF   0    2    2   -4 ]
  2 [ INF  INF   0    6    1 ]
  3 [ INF  INF  INF   0  INF ]
  4 [ INF  INF  INF   6    0 ]

Reconstruction chemin 0 -> 3:
  Chemin: [0, 1, 4, 3]
  Cout total: 5
```

### 1.3 Prototype

```c
// shortest_paths.h
#ifndef SHORTEST_PATHS_H
#define SHORTEST_PATHS_H

#include <limits.h>

#define INF INT_MAX

typedef struct edge {
    int src;
    int dest;
    int weight;
} edge;

typedef struct weighted_graph {
    int num_vertices;
    int num_edges;
    edge *edges;
    int **adj_matrix;
} weighted_graph;

typedef struct shortest_path_result {
    int **dist;
    int **next;
    int num_vertices;
    int has_negative_cycle;
} shortest_path_result;

// Creation et destruction de graphe
weighted_graph *create_weighted_graph(int vertices, int edges);
void add_weighted_edge(weighted_graph *g, int idx, int src, int dest, int weight);
void set_matrix_edge(weighted_graph *g, int src, int dest, int weight);
void free_weighted_graph(weighted_graph *g);

// Algorithmes de plus courts chemins
int *bellman_ford(weighted_graph *g, int source, int *has_neg_cycle);
shortest_path_result *floyd_warshall(weighted_graph *g);
shortest_path_result *johnson(weighted_graph *g);

// Detection et reconstruction
int detect_negative_cycle(weighted_graph *g);
int *reconstruct_path(shortest_path_result *result, int src, int dest, int *path_len);

// Liberation memoire
void free_shortest_path_result(shortest_path_result *result);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | bellman_ford simple | correct distances | 10 |
| T02 | bellman_ford negative weights | handles correctly | 10 |
| T03 | bellman_ford negative cycle | detects cycle | 10 |
| T04 | floyd_warshall simple | all pairs correct | 15 |
| T05 | floyd_warshall with negatives | handles correctly | 10 |
| T06 | detect_negative_cycle positive | returns 1 | 10 |
| T07 | detect_negative_cycle negative | returns 0 | 5 |
| T08 | reconstruct_path | correct path | 10 |
| T09 | johnson sparse graph | optimal distances | 15 |
| T10 | memory cleanup | no leaks | 5 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shortest_paths.h"

// ============================================
// CREATION ET DESTRUCTION DE GRAPHE
// ============================================

weighted_graph *create_weighted_graph(int vertices, int edges)
{
    weighted_graph *g = malloc(sizeof(weighted_graph));
    g->num_vertices = vertices;
    g->num_edges = edges;

    // Allouer liste d'aretes
    g->edges = malloc(edges * sizeof(edge));

    // Allouer et initialiser matrice d'adjacence
    g->adj_matrix = malloc(vertices * sizeof(int *));
    for (int i = 0; i < vertices; i++)
    {
        g->adj_matrix[i] = malloc(vertices * sizeof(int));
        for (int j = 0; j < vertices; j++)
        {
            g->adj_matrix[i][j] = (i == j) ? 0 : INF;
        }
    }

    return g;
}

void add_weighted_edge(weighted_graph *g, int idx, int src, int dest, int weight)
{
    if (idx < g->num_edges)
    {
        g->edges[idx].src = src;
        g->edges[idx].dest = dest;
        g->edges[idx].weight = weight;
        g->adj_matrix[src][dest] = weight;
    }
}

void set_matrix_edge(weighted_graph *g, int src, int dest, int weight)
{
    g->adj_matrix[src][dest] = weight;
}

void free_weighted_graph(weighted_graph *g)
{
    if (!g)
        return;
    free(g->edges);
    for (int i = 0; i < g->num_vertices; i++)
        free(g->adj_matrix[i]);
    free(g->adj_matrix);
    free(g);
}

// ============================================
// BELLMAN-FORD ALGORITHM
// ============================================

int *bellman_ford(weighted_graph *g, int source, int *has_neg_cycle)
{
    *has_neg_cycle = 0;

    if (!g || source < 0 || source >= g->num_vertices)
        return NULL;

    int V = g->num_vertices;
    int E = g->num_edges;

    int *dist = malloc(V * sizeof(int));

    // Initialisation
    for (int i = 0; i < V; i++)
        dist[i] = INF;
    dist[source] = 0;

    // Relaxation: V-1 iterations
    for (int i = 0; i < V - 1; i++)
    {
        int updated = 0;

        for (int j = 0; j < E; j++)
        {
            int u = g->edges[j].src;
            int v = g->edges[j].dest;
            int w = g->edges[j].weight;

            // Relaxation de l'arete (u, v)
            if (dist[u] != INF && dist[u] + w < dist[v])
            {
                dist[v] = dist[u] + w;
                updated = 1;
            }
        }

        // Optimisation: arret precoce si aucune mise a jour
        if (!updated)
            break;
    }

    // Detection de cycle negatif: V-ieme iteration
    for (int j = 0; j < E; j++)
    {
        int u = g->edges[j].src;
        int v = g->edges[j].dest;
        int w = g->edges[j].weight;

        if (dist[u] != INF && dist[u] + w < dist[v])
        {
            *has_neg_cycle = 1;
            break;
        }
    }

    return dist;
}

// ============================================
// FLOYD-WARSHALL ALGORITHM
// ============================================

shortest_path_result *floyd_warshall(weighted_graph *g)
{
    if (!g)
        return NULL;

    int V = g->num_vertices;

    shortest_path_result *result = malloc(sizeof(shortest_path_result));
    result->num_vertices = V;
    result->has_negative_cycle = 0;

    // Allouer matrices dist et next
    result->dist = malloc(V * sizeof(int *));
    result->next = malloc(V * sizeof(int *));

    for (int i = 0; i < V; i++)
    {
        result->dist[i] = malloc(V * sizeof(int));
        result->next[i] = malloc(V * sizeof(int));
    }

    // Initialisation depuis la matrice d'adjacence
    for (int i = 0; i < V; i++)
    {
        for (int j = 0; j < V; j++)
        {
            result->dist[i][j] = g->adj_matrix[i][j];

            if (i == j || g->adj_matrix[i][j] == INF)
                result->next[i][j] = -1;
            else
                result->next[i][j] = j;  // Prochain sommet sur le chemin i->j
        }
    }

    // Algorithme Floyd-Warshall: triple boucle
    for (int k = 0; k < V; k++)
    {
        for (int i = 0; i < V; i++)
        {
            for (int j = 0; j < V; j++)
            {
                // Eviter overflow avec INF
                if (result->dist[i][k] != INF && result->dist[k][j] != INF)
                {
                    int new_dist = result->dist[i][k] + result->dist[k][j];

                    if (new_dist < result->dist[i][j])
                    {
                        result->dist[i][j] = new_dist;
                        result->next[i][j] = result->next[i][k];
                    }
                }
            }
        }
    }

    // Detection de cycle negatif: diagonale negative
    for (int i = 0; i < V; i++)
    {
        if (result->dist[i][i] < 0)
        {
            result->has_negative_cycle = 1;
            break;
        }
    }

    return result;
}

// ============================================
// DETECTION DE CYCLE NEGATIF
// ============================================

int detect_negative_cycle(weighted_graph *g)
{
    if (!g || g->num_vertices == 0)
        return 0;

    // Utiliser Bellman-Ford depuis le sommet 0
    // Note: pour graphe non connexe, il faudrait tester depuis tous les sommets
    int has_neg;
    int *dist = bellman_ford(g, 0, &has_neg);

    if (dist)
        free(dist);

    if (has_neg)
        return 1;

    // Pour graphes non connexes, verifier avec Floyd-Warshall
    shortest_path_result *fw = floyd_warshall(g);
    int result = fw->has_negative_cycle;
    free_shortest_path_result(fw);

    return result;
}

// ============================================
// RECONSTRUCTION DE CHEMIN
// ============================================

int *reconstruct_path(shortest_path_result *result, int src, int dest, int *path_len)
{
    *path_len = 0;

    if (!result || src < 0 || dest < 0 ||
        src >= result->num_vertices || dest >= result->num_vertices)
        return NULL;

    // Pas de chemin
    if (result->dist[src][dest] == INF)
        return NULL;

    // Meme sommet
    if (src == dest)
    {
        int *path = malloc(sizeof(int));
        path[0] = src;
        *path_len = 1;
        return path;
    }

    // Compter la longueur du chemin
    int len = 0;
    int curr = src;
    while (curr != dest && curr != -1)
    {
        len++;
        curr = result->next[curr][dest];

        // Protection contre boucle infinie
        if (len > result->num_vertices)
            return NULL;
    }
    len++;  // Ajouter destination

    // Construire le chemin
    int *path = malloc(len * sizeof(int));
    curr = src;
    for (int i = 0; i < len - 1 && curr != -1; i++)
    {
        path[i] = curr;
        curr = result->next[curr][dest];
    }
    path[len - 1] = dest;

    *path_len = len;
    return path;
}

// ============================================
// JOHNSON'S ALGORITHM
// ============================================

// Min-heap pour Dijkstra
typedef struct heap_node {
    int vertex;
    int dist;
} heap_node;

typedef struct min_heap {
    heap_node *nodes;
    int *pos;
    int size;
    int capacity;
} min_heap;

static min_heap *create_heap(int capacity)
{
    min_heap *h = malloc(sizeof(min_heap));
    h->nodes = malloc(capacity * sizeof(heap_node));
    h->pos = malloc(capacity * sizeof(int));
    h->size = 0;
    h->capacity = capacity;
    return h;
}

static void swap_heap_nodes(min_heap *h, int i, int j)
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
        swap_heap_nodes(h, parent, idx);
        idx = parent;
    }
}

static void heapify_down(min_heap *h, int idx)
{
    while (1)
    {
        int smallest = idx;
        int left = 2 * idx + 1;
        int right = 2 * idx + 2;

        if (left < h->size && h->nodes[left].dist < h->nodes[smallest].dist)
            smallest = left;
        if (right < h->size && h->nodes[right].dist < h->nodes[smallest].dist)
            smallest = right;

        if (smallest == idx)
            break;

        swap_heap_nodes(h, idx, smallest);
        idx = smallest;
    }
}

static heap_node extract_min_heap(min_heap *h)
{
    heap_node min = h->nodes[0];
    h->pos[h->nodes[0].vertex] = h->size - 1;
    h->nodes[0] = h->nodes[--h->size];
    h->pos[h->nodes[0].vertex] = 0;
    heapify_down(h, 0);
    return min;
}

static void decrease_key_heap(min_heap *h, int vertex, int new_dist)
{
    int idx = h->pos[vertex];
    h->nodes[idx].dist = new_dist;
    heapify_up(h, idx);
}

static int is_in_heap(min_heap *h, int vertex)
{
    return h->pos[vertex] < h->size;
}

static void free_heap(min_heap *h)
{
    free(h->nodes);
    free(h->pos);
    free(h);
}

// Dijkstra modifie avec poids reponderes
static int *dijkstra_johnson(weighted_graph *g, int source, int *h_values)
{
    int V = g->num_vertices;
    int *dist = malloc(V * sizeof(int));

    for (int i = 0; i < V; i++)
        dist[i] = INF;
    dist[source] = 0;

    min_heap *heap = create_heap(V);
    for (int i = 0; i < V; i++)
    {
        heap->nodes[i].vertex = i;
        heap->nodes[i].dist = dist[i];
        heap->pos[i] = i;
    }
    heap->size = V;
    swap_heap_nodes(heap, 0, source);

    while (heap->size > 0)
    {
        heap_node min = extract_min_heap(heap);
        int u = min.vertex;

        if (dist[u] == INF)
            break;

        // Relaxer les aretes adjacentes
        for (int v = 0; v < V; v++)
        {
            if (g->adj_matrix[u][v] != INF && g->adj_matrix[u][v] != 0)
            {
                // Poids reponderer: w'(u,v) = w(u,v) + h(u) - h(v)
                int reweighted = g->adj_matrix[u][v] + h_values[u] - h_values[v];

                if (is_in_heap(heap, v) && dist[u] + reweighted < dist[v])
                {
                    dist[v] = dist[u] + reweighted;
                    decrease_key_heap(heap, v, dist[v]);
                }
            }
        }
    }

    free_heap(heap);

    // Restaurer les poids originaux dans les distances
    for (int v = 0; v < V; v++)
    {
        if (dist[v] != INF)
        {
            dist[v] = dist[v] - h_values[source] + h_values[v];
        }
    }

    return dist;
}

shortest_path_result *johnson(weighted_graph *g)
{
    if (!g)
        return NULL;

    int V = g->num_vertices;
    int E = g->num_edges;

    // Etape 1: Ajouter un sommet fictif s connecte a tous les sommets avec poids 0
    weighted_graph *g_prime = create_weighted_graph(V + 1, E + V);

    // Copier les aretes originales
    for (int i = 0; i < E; i++)
    {
        add_weighted_edge(g_prime, i, g->edges[i].src, g->edges[i].dest, g->edges[i].weight);
    }

    // Ajouter aretes depuis le sommet fictif V vers tous les autres sommets
    for (int i = 0; i < V; i++)
    {
        add_weighted_edge(g_prime, E + i, V, i, 0);
    }

    // Etape 2: Bellman-Ford depuis le sommet fictif pour calculer h[]
    int has_neg_cycle;
    int *h_values = bellman_ford(g_prime, V, &has_neg_cycle);

    if (has_neg_cycle)
    {
        free(h_values);
        free_weighted_graph(g_prime);

        // Retourner resultat avec flag de cycle negatif
        shortest_path_result *result = malloc(sizeof(shortest_path_result));
        result->num_vertices = V;
        result->has_negative_cycle = 1;
        result->dist = NULL;
        result->next = NULL;
        return result;
    }

    // Etape 3: Reponderer les aretes
    // w'(u,v) = w(u,v) + h(u) - h(v) >= 0
    // (deja fait dans dijkstra_johnson)

    // Etape 4: Executer Dijkstra depuis chaque sommet
    shortest_path_result *result = malloc(sizeof(shortest_path_result));
    result->num_vertices = V;
    result->has_negative_cycle = 0;

    result->dist = malloc(V * sizeof(int *));
    result->next = malloc(V * sizeof(int *));

    for (int i = 0; i < V; i++)
    {
        result->dist[i] = dijkstra_johnson(g, i, h_values);
        result->next[i] = malloc(V * sizeof(int));

        // Initialiser next pour reconstruction de chemin
        for (int j = 0; j < V; j++)
        {
            if (i == j || result->dist[i][j] == INF)
                result->next[i][j] = -1;
            else
            {
                // Trouver le premier sommet sur le chemin optimal
                for (int k = 0; k < V; k++)
                {
                    if (g->adj_matrix[i][k] != INF &&
                        result->dist[i][k] + result->dist[k][j] == result->dist[i][j] - g->adj_matrix[i][k] + result->dist[i][k])
                    {
                        // Verifier si k est sur le chemin
                        int edge_weight = g->adj_matrix[i][k];
                        if (result->dist[i][j] == edge_weight + result->dist[k][j])
                        {
                            result->next[i][j] = k;
                            break;
                        }
                    }
                }
            }
        }
    }

    free(h_values);
    free_weighted_graph(g_prime);

    return result;
}

// ============================================
// LIBERATION MEMOIRE
// ============================================

void free_shortest_path_result(shortest_path_result *result)
{
    if (!result)
        return;

    if (result->dist)
    {
        for (int i = 0; i < result->num_vertices; i++)
            free(result->dist[i]);
        free(result->dist);
    }

    if (result->next)
    {
        for (int i = 0; i < result->num_vertices; i++)
            free(result->next[i]);
        free(result->next);
    }

    free(result);
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Bellman-Ford n'effectue que V-2 iterations
int *bellman_ford(weighted_graph *g, int source, int *has_neg_cycle)
{
    // ...
    // ERREUR: V-2 au lieu de V-1
    for (int i = 0; i < V - 2; i++)  // Manque une iteration!
    {
        for (int j = 0; j < E; j++)
        {
            // relaxation...
        }
    }
    // Certains chemins ne seront pas trouves
}

// MUTANT 2: Floyd-Warshall avec ordre de boucles incorrect
shortest_path_result *floyd_warshall(weighted_graph *g)
{
    // ERREUR: k doit etre la boucle EXTERNE
    for (int i = 0; i < V; i++)
    {
        for (int j = 0; j < V; j++)
        {
            for (int k = 0; k < V; k++)  // k en interne = FAUX
            {
                if (result->dist[i][k] + result->dist[k][j] < result->dist[i][j])
                    result->dist[i][j] = result->dist[i][k] + result->dist[k][j];
            }
        }
    }
    // Ne trouve pas tous les chemins optimaux
}

// MUTANT 3: Ne detecte pas overflow avec INF
shortest_path_result *floyd_warshall(weighted_graph *g)
{
    for (int k = 0; k < V; k++)
    {
        for (int i = 0; i < V; i++)
        {
            for (int j = 0; j < V; j++)
            {
                // ERREUR: pas de verification INF
                int new_dist = result->dist[i][k] + result->dist[k][j];
                // Si dist[i][k]=INF et dist[k][j]=INF, overflow!
                if (new_dist < result->dist[i][j])
                    result->dist[i][j] = new_dist;
            }
        }
    }
}

// MUTANT 4: reconstruct_path retourne chemin inverse
int *reconstruct_path(shortest_path_result *result, int src, int dest, int *path_len)
{
    // ... calcul de longueur ...

    // ERREUR: part de dest au lieu de src
    int *path = malloc(len * sizeof(int));
    int curr = dest;  // Devrait etre src!
    for (int i = 0; i < len; i++)
    {
        path[i] = curr;
        curr = result->next[dest][curr];  // Mauvaise direction
    }
    // Chemin a l'envers
}

// MUTANT 5: Johnson ne restaure pas les distances originales
shortest_path_result *johnson(weighted_graph *g)
{
    // ... Bellman-Ford pour h[] ...
    // ... Dijkstra avec poids reponderes ...

    // ERREUR: oublie de restaurer les vrais poids
    for (int u = 0; u < V; u++)
    {
        result->dist[u] = dijkstra_johnson(g, u, h_values);
        // Manque: dist[u][v] = dist'[u][v] - h[u] + h[v]
    }
    // Les distances retournees sont reponderes, pas originales!
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **algorithmes de plus courts chemins**:

1. **Bellman-Ford** - Single-source, gere poids negatifs, O(VE)
2. **Floyd-Warshall** - All-pairs, programmation dynamique, O(V^3)
3. **Johnson** - All-pairs efficace pour graphes creux, O(V^2 log V + VE)
4. **Detection de cycles negatifs** - Essentielle pour la validite
5. **Reconstruction de chemin** - Utilisation de la matrice predecesseur

### 5.3 Visualisation ASCII

```
BELLMAN-FORD - RELAXATION STEP BY STEP:
==============================================

Graphe:
         3          2
    0 -------> 1 -------> 2
    |          |          |
    | 7        | -4       | 1
    v          v          v
    3 <------- 4 <--------+
          6          5

Aretes: (0,1,3), (0,3,7), (1,2,2), (1,4,-4), (2,4,5), (4,3,6)

Initial:
    dist = [0, INF, INF, INF, INF]
            ^
            source

Iteration 1 - Relaxation de toutes les aretes:
    (0,1,3): dist[1] = min(INF, 0+3) = 3
    (0,3,7): dist[3] = min(INF, 0+7) = 7
    (1,2,2): dist[2] = min(INF, 3+2) = 5   (dist[1]=3 deja mis a jour)
    (1,4,-4): dist[4] = min(INF, 3+(-4)) = -1
    (2,4,5): dist[4] = min(-1, 5+5) = -1   (pas d'amelioration)
    (4,3,6): dist[3] = min(7, -1+6) = 5    (amelioration!)

    dist = [0, 3, 5, 5, -1]

Iteration 2 - Verification:
    Toutes les aretes: aucune amelioration possible
    dist = [0, 3, 5, 5, -1] (final)

Detection cycle negatif (iteration V):
    Aucune amelioration -> PAS de cycle negatif


FLOYD-WARSHALL - MATRICE EVOLUTION:
==============================================

Graphe (matrice initiale):
         0    1    2    3
    0 [  0    5  INF   10 ]
    1 [INF    0    3  INF ]
    2 [INF  INF    0    1 ]
    3 [INF  INF  INF    0 ]

k=0 (chemins passant par sommet 0):
    Aucun nouveau chemin via 0

k=1 (chemins passant par sommet 1):
    dist[0][2] = min(INF, dist[0][1]+dist[1][2])
               = min(INF, 5+3) = 8

         0    1    2    3
    0 [  0    5    8   10 ]
    1 [INF    0    3  INF ]
    2 [INF  INF    0    1 ]
    3 [INF  INF  INF    0 ]

k=2 (chemins passant par sommet 2):
    dist[0][3] = min(10, dist[0][2]+dist[2][3])
               = min(10, 8+1) = 9
    dist[1][3] = min(INF, dist[1][2]+dist[2][3])
               = min(INF, 3+1) = 4

         0    1    2    3
    0 [  0    5    8    9 ]
    1 [INF    0    3    4 ]
    2 [INF  INF    0    1 ]
    3 [INF  INF  INF    0 ]

k=3 (chemins passant par sommet 3):
    Aucune amelioration

MATRICE FINALE:
         0    1    2    3
    0 [  0    5    8    9 ]
    1 [INF    0    3    4 ]
    2 [INF  INF    0    1 ]
    3 [INF  INF  INF    0 ]


DETECTION CYCLE NEGATIF:
==============================================

Graphe avec cycle negatif:
        2
    0 -----> 1
    ^        |
    |   -3   |
    +--------+

dist initial: [0, INF]

Iteration 1:
    (0,1,2): dist[1] = 2
    (1,0,-3): dist[0] = 2+(-3) = -1   <- dist[0] diminue!

Iteration 2 (V-1):
    (0,1,2): dist[1] = -1+2 = 1
    (1,0,-3): dist[0] = 1+(-3) = -2   <- continue a diminuer!

Iteration V (detection):
    (0,1,2): dist[1] = -2+2 = 0 < 1
    -> CYCLE NEGATIF DETECTE!

En Floyd-Warshall: dist[i][i] < 0 indique cycle


JOHNSON'S ALGORITHM:
==============================================

Etape 1: Ajouter sommet fictif s
                      0
    s ----------------+
    |  0              |
    +-------> 0 --3-> 1
              |       |
              7      -2
              |       |
              v       v
              2 <--4-- 3

Etape 2: Bellman-Ford depuis s
    h = [0, 0, 0, 0]  (tous accessibles depuis s avec cout 0)

    Puis relaxation:
    h[1] = min(0, h[0]+3) = 3... non, aretes sont 0->1
    h = [0, 3, 7, 1] (exemple)

Etape 3: Reponderer
    w'(u,v) = w(u,v) + h[u] - h[v]

    Exemple: w'(1,3) = -2 + h[1] - h[3]
                     = -2 + 3 - 1 = 0 >= 0

    Tous les poids deviennent non-negatifs!

Etape 4: Dijkstra depuis chaque sommet
    Plus efficace que Floyd-Warshall pour graphes creux
    O(V * (V log V + E)) vs O(V^3)


COMPARAISON COMPLEXITES:
==============================================

| Algorithme      | Temps       | Espace  | Poids neg | Cycle neg |
|-----------------|-------------|---------|-----------|-----------|
| Bellman-Ford    | O(VE)       | O(V)    | Oui       | Detecte   |
| Floyd-Warshall  | O(V^3)      | O(V^2)  | Oui       | Detecte   |
| Johnson         | O(V^2logV+VE)| O(V^2) | Oui       | Detecte   |
| Dijkstra        | O((V+E)logV)| O(V)    | Non       | Non       |

Choix:
- Single-source, poids negatifs: Bellman-Ford
- All-pairs, graphe dense: Floyd-Warshall
- All-pairs, graphe creux: Johnson
- Single-source, poids positifs: Dijkstra
```

---

## SECTION 7 : QCM

### Question 1
Pourquoi l'algorithme de Bellman-Ford necessite-t-il exactement V-1 iterations de relaxation ?

A) Pour garantir une complexite O(V^2)
B) Car le plus long chemin simple a au maximum V-1 aretes
C) Pour detecter les cycles negatifs
D) Car il y a V-1 aretes dans un arbre
E) Pour equilibrer la charge de calcul

**Reponse correcte: B**

**Explication:**
Dans un graphe de V sommets, le plus long chemin simple (sans cycle) contient au maximum V-1 aretes. A chaque iteration, Bellman-Ford garantit de trouver les chemins optimaux utilisant une arete de plus. Apres V-1 iterations, tous les chemins optimaux sont trouves. Une V-ieme iteration qui ameliore encore une distance indique qu'un chemin avec V aretes ou plus existe, ce qui implique necessairement un cycle negatif.

### Question 2
Dans l'algorithme de Floyd-Warshall, pourquoi la variable k (sommet intermediaire) doit-elle etre dans la boucle externe ?

A) Pour optimiser l'utilisation du cache
B) Car les sous-problemes dependent des iterations precedentes de k
C) Pour faciliter la parallelisation
D) Pour reduire la complexite memoire
E) L'ordre des boucles n'a pas d'importance

**Reponse correcte: B**

**Explication:**
Floyd-Warshall utilise la programmation dynamique avec la recurrence: dist_k[i][j] = min(dist_{k-1}[i][j], dist_{k-1}[i][k] + dist_{k-1}[k][j]). Cette recurrence indique que pour calculer les chemins passant par les sommets {0,...,k}, on a besoin des chemins passant par {0,...,k-1}. Si k n'est pas dans la boucle externe, on utiliserait des valeurs dist[i][k] et dist[k][j] qui n'ont pas encore ete calculees avec tous les sommets intermediaires precedents, produisant des resultats incorrects.

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.32-a",
  "name": "shortest_paths",
  "language": "c",
  "language_version": "c17",
  "difficulty": 7,
  "xp": 225,
  "complexity": {
    "time": "O(V^3)",
    "space": "O(V^2)"
  },
  "files": ["shortest_paths.c", "shortest_paths.h"],
  "depends": ["graph_basics", "dijkstra", "dynamic_programming"],
  "tests": {
    "bellman_ford": "bellman_ford_tests",
    "floyd_warshall": "floyd_warshall_tests",
    "negative_cycle": "negative_cycle_tests",
    "path_reconstruction": "path_reconstruction_tests",
    "johnson": "johnson_tests"
  },
  "topics": [
    "bellman_ford",
    "floyd_warshall",
    "johnson_algorithm",
    "negative_cycle_detection",
    "path_reconstruction",
    "all_pairs_shortest_paths",
    "dynamic_programming",
    "graph_algorithms",
    "edge_relaxation"
  ],
  "learning_objectives": [
    "Comprendre et implementer l'algorithme de Bellman-Ford",
    "Maitriser l'algorithme de Floyd-Warshall et sa logique DP",
    "Detecter les cycles negatifs dans un graphe pondere",
    "Reconstruire les chemins optimaux a partir de la matrice predecesseur",
    "Comprendre le fonctionnement de l'algorithme de Johnson",
    "Choisir l'algorithme approprie selon les caracteristiques du graphe"
  ]
}
```
