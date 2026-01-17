# Exercice D.0.27-a : topological_sort

**Module :**
D.0.27 — Tri Topologique

**Concept :**
a-e — Topological ordering, DAG, Kahn's algorithm, DFS-based sort, dependency resolution

**Difficulte :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
code

**Tiers :**
2 — Concept compose

**Langage :**
C17

**Prerequis :**
D.0.9 (graph basics), D.0.10 (dfs), D.0.11 (bfs)

**Domaines :**
Algo, Structures, Graphes

**Duree estimee :**
210 min

**XP Base :**
200

**Complexite :**
T[N] O(V+E) x S[N] O(V)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `topological_sort.c`
- `topological_sort.h`

### 1.2 Consigne

Implementer plusieurs algorithmes de tri topologique et leurs applications pratiques.

Le tri topologique ordonne les sommets d'un graphe dirige acyclique (DAG) tel que pour chaque arete (u, v), u apparait avant v dans l'ordre.

**Ta mission :**

```c
// Structure pour representer un graphe dirige
typedef struct adj_node {
    int vertex;
    struct adj_node *next;
} adj_node;

typedef struct graph {
    int num_vertices;
    adj_node **adj;
} graph;

// Algorithme de Kahn (BFS-based)
// Retourne l'ordre topologique ou NULL si cycle detecte
int *kahn_topological_sort(graph *g, int *result_size);

// Tri topologique base sur DFS
// Retourne l'ordre topologique ou NULL si cycle detecte
int *dfs_topological_sort(graph *g, int *result_size);

// Detection de cycle dans graphe dirige
int has_cycle(graph *g);

// Resolution de dependances (retourne ordre d'execution)
// tasks: tableau de noms de taches
// deps: matrice d'adjacence des dependances (deps[i][j]=1 si i depend de j)
char **resolve_dependencies(char **tasks, int **deps, int num_tasks, int *order_size);

// Probleme d'ordonnancement de cours
// prereqs[i] contient la liste des prerequis du cours i
// Retourne un ordre valide pour suivre tous les cours
int *course_schedule(int num_courses, int **prereqs, int *prereq_counts, int *order_size);

// Verifier si un ordre donne est un tri topologique valide
int is_valid_topological_order(graph *g, int *order, int order_size);

// Compter le nombre de tris topologiques possibles
long count_topological_sorts(graph *g);

// Lexicographiquement plus petit tri topologique
int *lexicographic_topological_sort(graph *g, int *result_size);
```

**Comportement:**

1. `kahn_topological_sort(g, &size)` -> ordre topologique via BFS
2. `dfs_topological_sort(g, &size)` -> ordre topologique via DFS
3. `has_cycle(g)` -> 1 si le graphe contient un cycle
4. `course_schedule(4, prereqs, counts, &size)` -> ordre des cours

**Exemples:**
```
DAG de dependances de compilation:
    main.c -> utils.h -> types.h
       |
       v
    io.c -> utils.h

Sommets: 0=types.h, 1=utils.h, 2=main.c, 3=io.c

Aretes (x depend de y, donc y -> x):
    0 -> 1 (utils.h depend de types.h)
    1 -> 2 (main.c depend de utils.h)
    1 -> 3 (io.c depend de utils.h)

Tri topologique: [0, 1, 2, 3] ou [0, 1, 3, 2]

Probleme de cours:
    Cours 0: pas de prerequis
    Cours 1: prerequis [0]
    Cours 2: prerequis [0, 1]
    Cours 3: prerequis [1]

    0 -> 1 -> 2
         |
         v
         3

    Ordre valide: [0, 1, 2, 3] ou [0, 1, 3, 2]
```

### 1.3 Prototype

```c
// topological_sort.h
#ifndef TOPOLOGICAL_SORT_H
#define TOPOLOGICAL_SORT_H

typedef struct adj_node {
    int vertex;
    struct adj_node *next;
} adj_node;

typedef struct graph {
    int num_vertices;
    adj_node **adj;
} graph;

// Creation et destruction de graphe
graph *create_graph(int vertices);
void add_edge(graph *g, int src, int dest);
void free_graph(graph *g);

// Algorithmes de tri topologique
int *kahn_topological_sort(graph *g, int *result_size);
int *dfs_topological_sort(graph *g, int *result_size);

// Detection de cycle
int has_cycle(graph *g);

// Applications
char **resolve_dependencies(char **tasks, int **deps, int num_tasks, int *order_size);
int *course_schedule(int num_courses, int **prereqs, int *prereq_counts, int *order_size);

// Utilitaires
int is_valid_topological_order(graph *g, int *order, int order_size);
long count_topological_sorts(graph *g);
int *lexicographic_topological_sort(graph *g, int *result_size);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | kahn simple DAG | valid order | 10 |
| T02 | dfs simple DAG | valid order | 10 |
| T03 | kahn with cycle | NULL | 10 |
| T04 | dfs with cycle | NULL | 10 |
| T05 | has_cycle positive | 1 | 10 |
| T06 | has_cycle negative | 0 | 10 |
| T07 | course_schedule valid | valid order | 15 |
| T08 | course_schedule impossible | NULL | 10 |
| T09 | is_valid_topological true | 1 | 5 |
| T10 | is_valid_topological false | 0 | 5 |
| T11 | lexicographic order | smallest | 5 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "topological_sort.h"

// ============================================
// STRUCTURES ET UTILITAIRES
// ============================================

graph *create_graph(int vertices)
{
    graph *g = malloc(sizeof(graph));
    g->num_vertices = vertices;
    g->adj = calloc(vertices, sizeof(adj_node *));
    return g;
}

void add_edge(graph *g, int src, int dest)
{
    adj_node *node = malloc(sizeof(adj_node));
    node->vertex = dest;
    node->next = g->adj[src];
    g->adj[src] = node;
}

void free_graph(graph *g)
{
    if (!g)
        return;
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

// File simple pour Kahn
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
    q->data[q->rear++] = val;
    q->size++;
}

static int dequeue(queue *q)
{
    q->size--;
    return q->data[q->front++];
}

static int queue_empty(queue *q) { return q->size == 0; }
static void free_queue(queue *q) { free(q->data); free(q); }

// ============================================
// ALGORITHME DE KAHN (BFS-BASED)
// ============================================

int *kahn_topological_sort(graph *g, int *result_size)
{
    *result_size = 0;
    if (!g || g->num_vertices == 0)
        return NULL;

    int n = g->num_vertices;
    int *in_degree = calloc(n, sizeof(int));

    // Calculer le degre entrant de chaque sommet
    for (int u = 0; u < n; u++)
    {
        adj_node *curr = g->adj[u];
        while (curr)
        {
            in_degree[curr->vertex]++;
            curr = curr->next;
        }
    }

    // Ajouter tous les sommets avec degre entrant 0 a la file
    queue *q = create_queue(n);
    for (int i = 0; i < n; i++)
    {
        if (in_degree[i] == 0)
            enqueue(q, i);
    }

    int *result = malloc(n * sizeof(int));
    int count = 0;

    while (!queue_empty(q))
    {
        int u = dequeue(q);
        result[count++] = u;

        // Reduire le degre entrant des voisins
        adj_node *curr = g->adj[u];
        while (curr)
        {
            in_degree[curr->vertex]--;
            if (in_degree[curr->vertex] == 0)
                enqueue(q, curr->vertex);
            curr = curr->next;
        }
    }

    free(in_degree);
    free_queue(q);

    // Si tous les sommets ne sont pas inclus, il y a un cycle
    if (count != n)
    {
        free(result);
        return NULL;
    }

    *result_size = count;
    return result;
}

// ============================================
// TRI TOPOLOGIQUE BASE SUR DFS
// ============================================

// Etats de visite: 0 = non visite, 1 = en cours, 2 = termine
static int dfs_topo_helper(graph *g, int v, int *state, int *stack, int *top)
{
    state[v] = 1;  // En cours de visite

    adj_node *curr = g->adj[v];
    while (curr)
    {
        if (state[curr->vertex] == 1)
        {
            // Back edge detecte -> cycle
            return 0;
        }
        if (state[curr->vertex] == 0)
        {
            if (!dfs_topo_helper(g, curr->vertex, state, stack, top))
                return 0;
        }
        curr = curr->next;
    }

    state[v] = 2;  // Termine
    stack[(*top)++] = v;
    return 1;
}

int *dfs_topological_sort(graph *g, int *result_size)
{
    *result_size = 0;
    if (!g || g->num_vertices == 0)
        return NULL;

    int n = g->num_vertices;
    int *state = calloc(n, sizeof(int));
    int *stack = malloc(n * sizeof(int));
    int top = 0;

    // Lancer DFS depuis chaque sommet non visite
    for (int i = 0; i < n; i++)
    {
        if (state[i] == 0)
        {
            if (!dfs_topo_helper(g, i, state, stack, &top))
            {
                // Cycle detecte
                free(state);
                free(stack);
                return NULL;
            }
        }
    }

    // Inverser le resultat (post-order -> topological order)
    int *result = malloc(n * sizeof(int));
    for (int i = 0; i < n; i++)
        result[i] = stack[n - 1 - i];

    free(state);
    free(stack);
    *result_size = n;
    return result;
}

// ============================================
// DETECTION DE CYCLE
// ============================================

static int dfs_cycle_helper(graph *g, int v, int *state)
{
    state[v] = 1;  // En cours

    adj_node *curr = g->adj[v];
    while (curr)
    {
        if (state[curr->vertex] == 1)
            return 1;  // Back edge -> cycle
        if (state[curr->vertex] == 0)
        {
            if (dfs_cycle_helper(g, curr->vertex, state))
                return 1;
        }
        curr = curr->next;
    }

    state[v] = 2;  // Termine
    return 0;
}

int has_cycle(graph *g)
{
    if (!g || g->num_vertices == 0)
        return 0;

    int *state = calloc(g->num_vertices, sizeof(int));

    for (int i = 0; i < g->num_vertices; i++)
    {
        if (state[i] == 0)
        {
            if (dfs_cycle_helper(g, i, state))
            {
                free(state);
                return 1;
            }
        }
    }

    free(state);
    return 0;
}

// ============================================
// RESOLUTION DE DEPENDANCES
// ============================================

char **resolve_dependencies(char **tasks, int **deps, int num_tasks, int *order_size)
{
    *order_size = 0;
    if (!tasks || !deps || num_tasks <= 0)
        return NULL;

    // Construire le graphe a partir de la matrice de dependances
    graph *g = create_graph(num_tasks);

    for (int i = 0; i < num_tasks; i++)
    {
        for (int j = 0; j < num_tasks; j++)
        {
            if (deps[i][j])
            {
                // i depend de j, donc j -> i
                add_edge(g, j, i);
            }
        }
    }

    // Tri topologique
    int result_count;
    int *order = kahn_topological_sort(g, &result_count);
    free_graph(g);

    if (!order)
        return NULL;

    // Construire le resultat avec les noms des taches
    char **result = malloc(result_count * sizeof(char *));
    for (int i = 0; i < result_count; i++)
    {
        result[i] = strdup(tasks[order[i]]);
    }

    free(order);
    *order_size = result_count;
    return result;
}

// ============================================
// PROBLEME D'ORDONNANCEMENT DE COURS
// ============================================

int *course_schedule(int num_courses, int **prereqs, int *prereq_counts, int *order_size)
{
    *order_size = 0;
    if (num_courses <= 0)
        return NULL;

    // Construire le graphe des prerequis
    graph *g = create_graph(num_courses);

    for (int course = 0; course < num_courses; course++)
    {
        if (prereq_counts && prereqs && prereqs[course])
        {
            for (int j = 0; j < prereq_counts[course]; j++)
            {
                int prereq = prereqs[course][j];
                // prereq -> course (prereq doit etre avant course)
                add_edge(g, prereq, course);
            }
        }
    }

    // Tri topologique
    int *result = kahn_topological_sort(g, order_size);
    free_graph(g);

    return result;
}

// ============================================
// VERIFICATION D'ORDRE TOPOLOGIQUE
// ============================================

int is_valid_topological_order(graph *g, int *order, int order_size)
{
    if (!g || !order || order_size != g->num_vertices)
        return 0;

    // Creer un mapping position[v] = index de v dans l'ordre
    int *position = malloc(g->num_vertices * sizeof(int));
    for (int i = 0; i < order_size; i++)
    {
        if (order[i] < 0 || order[i] >= g->num_vertices)
        {
            free(position);
            return 0;
        }
        position[order[i]] = i;
    }

    // Verifier que pour chaque arete u->v, position[u] < position[v]
    for (int u = 0; u < g->num_vertices; u++)
    {
        adj_node *curr = g->adj[u];
        while (curr)
        {
            if (position[u] >= position[curr->vertex])
            {
                free(position);
                return 0;
            }
            curr = curr->next;
        }
    }

    free(position);
    return 1;
}

// ============================================
// COMPTAGE DES TRIS TOPOLOGIQUES
// ============================================

static void count_topo_helper(graph *g, int *in_degree, int *visited,
                              int count, long *total)
{
    int n = g->num_vertices;
    int found = 0;

    for (int v = 0; v < n; v++)
    {
        if (!visited[v] && in_degree[v] == 0)
        {
            found = 1;
            visited[v] = 1;

            // Reduire degre entrant des voisins
            adj_node *curr = g->adj[v];
            while (curr)
            {
                in_degree[curr->vertex]--;
                curr = curr->next;
            }

            count_topo_helper(g, in_degree, visited, count + 1, total);

            // Backtrack
            visited[v] = 0;
            curr = g->adj[v];
            while (curr)
            {
                in_degree[curr->vertex]++;
                curr = curr->next;
            }
        }
    }

    if (!found && count == n)
        (*total)++;
}

long count_topological_sorts(graph *g)
{
    if (!g || g->num_vertices == 0)
        return 0;

    if (has_cycle(g))
        return 0;

    int n = g->num_vertices;
    int *in_degree = calloc(n, sizeof(int));
    int *visited = calloc(n, sizeof(int));

    // Calculer degres entrants
    for (int u = 0; u < n; u++)
    {
        adj_node *curr = g->adj[u];
        while (curr)
        {
            in_degree[curr->vertex]++;
            curr = curr->next;
        }
    }

    long total = 0;
    count_topo_helper(g, in_degree, visited, 0, &total);

    free(in_degree);
    free(visited);
    return total;
}

// ============================================
// TRI TOPOLOGIQUE LEXICOGRAPHIQUE
// ============================================

// Min-heap pour garder le plus petit sommet disponible
typedef struct min_heap {
    int *data;
    int size;
    int capacity;
} min_heap;

static min_heap *create_heap(int capacity)
{
    min_heap *h = malloc(sizeof(min_heap));
    h->data = malloc(capacity * sizeof(int));
    h->size = 0;
    h->capacity = capacity;
    return h;
}

static void heap_push(min_heap *h, int val)
{
    int i = h->size++;
    h->data[i] = val;

    // Sift up
    while (i > 0)
    {
        int parent = (i - 1) / 2;
        if (h->data[parent] <= h->data[i])
            break;
        int tmp = h->data[parent];
        h->data[parent] = h->data[i];
        h->data[i] = tmp;
        i = parent;
    }
}

static int heap_pop(min_heap *h)
{
    int result = h->data[0];
    h->data[0] = h->data[--h->size];

    // Sift down
    int i = 0;
    while (1)
    {
        int smallest = i;
        int left = 2 * i + 1;
        int right = 2 * i + 2;

        if (left < h->size && h->data[left] < h->data[smallest])
            smallest = left;
        if (right < h->size && h->data[right] < h->data[smallest])
            smallest = right;

        if (smallest == i)
            break;

        int tmp = h->data[i];
        h->data[i] = h->data[smallest];
        h->data[smallest] = tmp;
        i = smallest;
    }

    return result;
}

static int heap_empty(min_heap *h) { return h->size == 0; }
static void free_heap(min_heap *h) { free(h->data); free(h); }

int *lexicographic_topological_sort(graph *g, int *result_size)
{
    *result_size = 0;
    if (!g || g->num_vertices == 0)
        return NULL;

    int n = g->num_vertices;
    int *in_degree = calloc(n, sizeof(int));

    // Calculer degres entrants
    for (int u = 0; u < n; u++)
    {
        adj_node *curr = g->adj[u];
        while (curr)
        {
            in_degree[curr->vertex]++;
            curr = curr->next;
        }
    }

    // Utiliser un min-heap au lieu d'une queue
    min_heap *h = create_heap(n);
    for (int i = 0; i < n; i++)
    {
        if (in_degree[i] == 0)
            heap_push(h, i);
    }

    int *result = malloc(n * sizeof(int));
    int count = 0;

    while (!heap_empty(h))
    {
        int u = heap_pop(h);
        result[count++] = u;

        adj_node *curr = g->adj[u];
        while (curr)
        {
            in_degree[curr->vertex]--;
            if (in_degree[curr->vertex] == 0)
                heap_push(h, curr->vertex);
            curr = curr->next;
        }
    }

    free(in_degree);
    free_heap(h);

    if (count != n)
    {
        free(result);
        return NULL;
    }

    *result_size = count;
    return result;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Kahn ne detecte pas les cycles
int *kahn_topological_sort(graph *g, int *result_size)
{
    // ... calcul in_degree et BFS ...

    int *result = malloc(n * sizeof(int));
    int count = 0;

    while (!queue_empty(q))
    {
        int u = dequeue(q);
        result[count++] = u;
        // ... mise a jour in_degree ...
    }

    // ERREUR: ne verifie pas count != n
    *result_size = count;
    return result;  // Retourne resultat incomplet si cycle existe
}

// MUTANT 2: DFS n'inverse pas le resultat
int *dfs_topological_sort(graph *g, int *result_size)
{
    // ... DFS met les sommets dans stack en post-order ...

    // ERREUR: retourne stack directement sans inverser
    *result_size = n;
    return stack;  // Ordre inverse du tri topologique!
}

// MUTANT 3: Detection de cycle utilise visited au lieu de state
int has_cycle(graph *g)
{
    int *visited = calloc(g->num_vertices, sizeof(int));

    for (int i = 0; i < g->num_vertices; i++)
    {
        if (!visited[i])
        {
            // ERREUR: utilise seulement visited, pas de distinction
            // entre "en cours" et "termine"
            // Ne detecte pas tous les cycles
        }
    }
}

// MUTANT 4: Resolution dependances inverse le sens des aretes
char **resolve_dependencies(char **tasks, int **deps, int num_tasks, int *order_size)
{
    graph *g = create_graph(num_tasks);

    for (int i = 0; i < num_tasks; i++)
    {
        for (int j = 0; j < num_tasks; j++)
        {
            if (deps[i][j])
            {
                // ERREUR: i depend de j, mais on fait i -> j au lieu de j -> i
                add_edge(g, i, j);  // Mauvais sens!
            }
        }
    }
    // Resultat: ordre inverse des dependances
}

// MUTANT 5: is_valid ne verifie pas toutes les aretes
int is_valid_topological_order(graph *g, int *order, int order_size)
{
    int *position = malloc(g->num_vertices * sizeof(int));
    for (int i = 0; i < order_size; i++)
        position[order[i]] = i;

    // ERREUR: verifie seulement la premiere arete de chaque sommet
    for (int u = 0; u < g->num_vertices; u++)
    {
        adj_node *curr = g->adj[u];
        if (curr && position[u] >= position[curr->vertex])
        {
            free(position);
            return 0;
        }
        // Manque: while (curr) pour verifier TOUTES les aretes
    }

    free(position);
    return 1;  // Peut retourner true meme si invalide
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Le **tri topologique** ordonne les sommets d'un DAG:

1. **Ordre de dependances** - Respecter les contraintes d'ordre
2. **Detection de cycles** - Un cycle rend le tri impossible
3. **Deux approches** - Kahn (BFS) vs DFS post-order
4. **Applications pratiques** - Compilation, cours, taches

### 5.3 Visualisation ASCII

```
TRI TOPOLOGIQUE - VISUALISATION DAG:

Graphe de dependances de compilation:
===========================================

    +----------+     +----------+     +----------+
    | types.h  |---->| utils.h  |---->| main.c   |
    |   (0)    |     |   (1)    |     |   (2)    |
    +----------+     +----+-----+     +----------+
                          |
                          |
                          v
                     +----------+
                     |  io.c    |
                     |   (3)    |
                     +----------+

Aretes: 0->1, 1->2, 1->3

ALGORITHME DE KAHN (BFS):
===========================================

Etape 0: Calculer degres entrants
    in_degree = [0, 1, 1, 1]
                 ^
                 |
    Sommet 0 a degre 0 -> ajouter a la file

Etape 1: Traiter sommet 0
    File: [0] -> dequeue 0
    Resultat: [0]
    Reduire voisins: in_degree[1]-- = 0
    File: [1]

    in_degree = [0, 0, 1, 1]

Etape 2: Traiter sommet 1
    File: [1] -> dequeue 1
    Resultat: [0, 1]
    Reduire voisins: in_degree[2]-- = 0, in_degree[3]-- = 0
    File: [2, 3]

    in_degree = [0, 0, 0, 0]

Etape 3: Traiter sommets 2 et 3
    File: [2, 3] -> dequeue 2
    Resultat: [0, 1, 2]
    File: [3] -> dequeue 3
    Resultat: [0, 1, 2, 3]

Resultat final: [0, 1, 2, 3]


ALGORITHME DFS:
===========================================

DFS depuis chaque sommet non visite:

    Appel dfs(0):
        state[0] = EN_COURS
        -> dfs(1):
            state[1] = EN_COURS
            -> dfs(2):
                state[2] = EN_COURS
                pas de voisins
                state[2] = TERMINE
                stack.push(2)    stack = [2]
            -> dfs(3):
                state[3] = EN_COURS
                pas de voisins
                state[3] = TERMINE
                stack.push(3)    stack = [2, 3]
            state[1] = TERMINE
            stack.push(1)        stack = [2, 3, 1]
        state[0] = TERMINE
        stack.push(0)            stack = [2, 3, 1, 0]

    Inverser stack: [0, 1, 3, 2]

Les deux ordres [0,1,2,3] et [0,1,3,2] sont valides!


DETECTION DE CYCLE:
===========================================

Graphe AVEC cycle:

    0 -----> 1
    ^        |
    |        v
    3 <----- 2

Aretes: 0->1, 1->2, 2->3, 3->0

DFS cycle detection:
    dfs(0): state[0] = EN_COURS
        dfs(1): state[1] = EN_COURS
            dfs(2): state[2] = EN_COURS
                dfs(3): state[3] = EN_COURS
                    voisin 0: state[0] == EN_COURS
                    -> BACK EDGE DETECTE -> CYCLE!


PROBLEME DE COURS:
===========================================

Cours disponibles: CS101, CS201, CS301, CS401

Prerequis:
    CS101 (0): aucun
    CS201 (1): [CS101]
    CS301 (2): [CS101, CS201]
    CS401 (3): [CS201]

    +-------+     +-------+     +-------+
    | CS101 |---->| CS201 |---->| CS301 |
    |  (0)  |     |  (1)  +---->|  (2)  |
    +-------+     +---+---+     +-------+
                      |
                      v
                  +-------+
                  | CS401 |
                  |  (3)  |
                  +-------+

Ordre valide: CS101 -> CS201 -> CS301 -> CS401
          ou: CS101 -> CS201 -> CS401 -> CS301


COMPARAISON KAHN vs DFS:
===========================================

| Critere            | Kahn (BFS)      | DFS             |
|--------------------|-----------------|-----------------|
| Structure          | Queue + degres  | Stack recursif  |
| Detection cycle    | count != V      | back edge       |
| Complexite temps   | O(V + E)        | O(V + E)        |
| Complexite espace  | O(V)            | O(V)            |
| Parallelisation    | Facile          | Difficile       |
| Ordres multiples   | Niveau par niv. | Post-order      |
```

---

## SECTION 7 : QCM

### Question 1
Quelle condition rend le tri topologique impossible ?

A) Le graphe est non connexe
B) Le graphe contient un cycle
C) Le graphe a des aretes multiples
D) Le graphe a plus de sommets que d'aretes
E) Le graphe est non dirige

**Reponse correcte: B**

**Explication:**
Le tri topologique n'est possible que pour les graphes diriges acycliques (DAG). Un cycle cree une dependance circulaire: si A depend de B et B depend de A, il est impossible de placer l'un avant l'autre. L'algorithme de Kahn detecte cela quand le nombre de sommets traites est inferieur au total, et l'algorithme DFS detecte les back edges qui indiquent un cycle.

### Question 2
Dans l'algorithme de Kahn, quel sommet est traite en premier ?

A) Le sommet avec le plus grand degre sortant
B) Le sommet avec le plus petit indice
C) Un sommet avec degre entrant egal a zero
D) Le sommet le plus connecte
E) Un sommet choisi aleatoirement

**Reponse correcte: C**

**Explication:**
L'algorithme de Kahn commence par les sommets sans predecesseurs (degre entrant = 0). Ces sommets n'ont aucune dependance, donc ils peuvent etre places en premier dans l'ordre topologique. Apres les avoir traites, leurs successeurs peuvent avoir leur degre entrant reduit a zero et devenir eligibles pour le traitement.

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.27-a",
  "name": "topological_sort",
  "language": "c",
  "language_version": "c17",
  "difficulty": 6,
  "xp": 200,
  "complexity": {
    "time": "O(V+E)",
    "space": "O(V)"
  },
  "files": ["topological_sort.c", "topological_sort.h"],
  "depends": ["graph_basics", "dfs", "bfs"],
  "tests": {
    "kahn": "kahn_topological_tests",
    "dfs": "dfs_topological_tests",
    "cycle": "cycle_detection_tests",
    "applications": "application_tests",
    "validation": "validation_tests"
  },
  "topics": [
    "topological_sort",
    "dag",
    "kahn_algorithm",
    "dfs_postorder",
    "cycle_detection",
    "dependency_resolution",
    "course_scheduling"
  ],
  "learning_objectives": [
    "Comprendre le concept d'ordre topologique",
    "Implementer l'algorithme de Kahn (BFS)",
    "Implementer le tri topologique par DFS",
    "Detecter les cycles dans un graphe dirige",
    "Appliquer le tri topologique a des problemes pratiques"
  ]
}
```
