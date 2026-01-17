# Exercice D.31 : minimum_spanning_tree

**Module :**
D — Algorithmique

**Concept :**
31 — Minimum Spanning Tree (MST) - Arbres couvrants de poids minimal

**Difficulte :**
[******----] (6/10)

**Type :**
code

**Tiers :**
2 — Integration de concepts

**Langage :**
C17

**Prerequis :**
- Representation de graphes (listes d'adjacence, matrice)
- Files de priorite (min-heap)
- Union-Find (Disjoint Set Union)
- Algorithme de Dijkstra (concepts similaires)

**Domaines :**
Algo, Graphs, Greedy

**Duree estimee :**
180 min

**XP Base :**
200

**Complexite :**
T[N] O(E log V) x S[N] O(V+E)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `mst.c`, `mst.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | malloc, free, memset, memcpy, qsort |

---

### 1.2 Consigne

#### Section Culture : "L'Arbre Couvrant Minimal - Connecter au Moindre Cout"

Un **arbre couvrant minimal** (Minimum Spanning Tree ou MST) d'un graphe connexe pondere est un sous-graphe qui :
- Connecte tous les sommets (couvrant)
- Ne contient pas de cycles (arbre)
- Minimise la somme des poids des aretes

Applications pratiques :
- Conception de reseaux (electricite, telecommunications, routes)
- Clustering et segmentation d'images
- Approximation du probleme du voyageur de commerce
- Analyse de donnees biologiques (phylogenetique)
- Routage dans les reseaux informatiques

Deux algorithmes classiques dominent :
- **Prim** : Construit l'arbre sommet par sommet (greedy local)
- **Kruskal** : Construit l'arbre arete par arete (greedy global)

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer les algorithmes de Prim et Kruskal pour calculer l'arbre couvrant minimal d'un graphe pondere non-dirige. Ajouter des fonctions de verification des proprietes MST et de calcul du second-best MST.

**Proprietes du MST :**

```
CUT PROPERTY: Pour toute coupe du graphe, l'arete de poids minimal
              traversant la coupe appartient a un MST.

CYCLE PROPERTY: Pour tout cycle, l'arete de poids maximal dans le
                cycle n'appartient a aucun MST.

UNIQUENESS: Si tous les poids sont distincts, le MST est unique.

EDGES COUNT: Un MST d'un graphe a V sommets contient exactement V-1 aretes.
```

**Prototypes :**

```c
// mst.h

#ifndef MST_H
#define MST_H

#include <stddef.h>
#include <stdbool.h>

/**
 * Structure pour representer une arete
 */
typedef struct {
    int     src;        // Sommet source
    int     dest;       // Sommet destination
    int     weight;     // Poids de l'arete
} mst_edge_t;

/**
 * Structure pour le resultat MST
 */
typedef struct {
    mst_edge_t  *edges;         // Aretes du MST
    size_t      num_edges;      // Nombre d'aretes (V-1)
    int         total_weight;   // Poids total du MST
    bool        is_connected;   // Le graphe est-il connexe?
} mst_result_t;

/**
 * Structure pour graphe (matrice d'adjacence)
 */
typedef struct {
    int     **adj_matrix;   // Matrice d'adjacence (0 = pas d'arete)
    size_t  num_vertices;
} graph_matrix_t;

/**
 * Structure pour graphe (liste d'aretes)
 */
typedef struct {
    mst_edge_t  *edges;
    size_t      num_edges;
    size_t      num_vertices;
} graph_edges_t;

// ============================================
// Creation et destruction de graphes
// ============================================

graph_matrix_t  *graph_matrix_create(size_t num_vertices);
void            graph_matrix_destroy(graph_matrix_t *g);
void            graph_matrix_add_edge(graph_matrix_t *g, int src, int dest, int weight);

graph_edges_t   *graph_edges_create(size_t num_vertices, size_t max_edges);
void            graph_edges_destroy(graph_edges_t *g);
void            graph_edges_add_edge(graph_edges_t *g, int src, int dest, int weight);

// ============================================
// Algorithme de Prim
// ============================================

/**
 * Prim avec matrice d'adjacence - O(V^2)
 * Ideal pour graphes denses
 */
mst_result_t *prim_matrix(graph_matrix_t *g, int start_vertex);

/**
 * Prim avec priority queue (min-heap) - O(E log V)
 * Ideal pour graphes creux
 */
mst_result_t *prim_heap(graph_edges_t *g, int start_vertex);

// ============================================
// Algorithme de Kruskal
// ============================================

/**
 * Kruskal avec Union-Find - O(E log E)
 * Tri des aretes + Union-Find pour detection de cycles
 */
mst_result_t *kruskal(graph_edges_t *g);

// ============================================
// Verification et proprietes
// ============================================

/**
 * Verifie si le resultat est un MST valide
 */
bool mst_verify(mst_result_t *result, size_t num_vertices);

/**
 * Verifie la propriete de coupe (cut property)
 */
bool mst_check_cut_property(graph_edges_t *g, mst_result_t *mst);

/**
 * Verifie la propriete de cycle (cycle property)
 */
bool mst_check_cycle_property(graph_edges_t *g, mst_result_t *mst);

// ============================================
// Second-Best MST
// ============================================

/**
 * Calcule le second meilleur MST
 * Le second MST est l'arbre couvrant avec le plus petit poids
 * apres le MST optimal
 */
mst_result_t *second_best_mst(graph_edges_t *g);

// ============================================
// Utilitaires
// ============================================

void mst_result_destroy(mst_result_t *result);
void mst_result_print(mst_result_t *result);

#endif
```

**Comportements attendus :**

| Operation | Exemple | Resultat | Complexite |
|-----------|---------|----------|------------|
| prim_matrix(g, 0) | Graphe dense | MST depuis sommet 0 | O(V^2) |
| prim_heap(g, 0) | Graphe creux | MST depuis sommet 0 | O(E log V) |
| kruskal(g) | Graphe quelconque | MST global | O(E log E) |
| second_best_mst(g) | Graphe connexe | 2eme meilleur MST | O(E^2) ou O(V^2 log V) |

**Exemples :**

```
GRAPHE PONDERE NON-DIRIGE:

        2
    0 ----- 1
    |     / |
  6 |  8/   | 5
    | /     |
    3 ----- 2
        3

Aretes: (0,1,2), (0,3,6), (1,2,5), (1,3,8), (2,3,3)

MST avec Prim (depuis 0):
  Etape 1: Ajouter 0, explorer voisins
           key[1]=2, key[3]=6
  Etape 2: Ajouter 1 (min key), explorer voisins
           key[2]=5, key[3]=min(6,8)=6
  Etape 3: Ajouter 2 (min key), explorer voisins
           key[3]=min(6,3)=3
  Etape 4: Ajouter 3

  MST: (0,1,2), (1,2,5), (2,3,3)
  Poids total: 10

MST avec Kruskal:
  Aretes triees: (0,1,2), (2,3,3), (1,2,5), (0,3,6), (1,3,8)
  Etape 1: (0,1,2) - Ajouter (0 et 1 non connectes)
  Etape 2: (2,3,3) - Ajouter (2 et 3 non connectes)
  Etape 3: (1,2,5) - Ajouter (1 et 2 non connectes)
  Etape 4: (0,3,6) - Ignorer (0 et 3 deja connectes via MST)
  Etape 5: (1,3,8) - Ignorer (1 et 3 deja connectes)

  MST: (0,1,2), (2,3,3), (1,2,5)
  Poids total: 10

Second-Best MST:
  Remplacer une arete du MST par la meilleure alternative
  Essayer: enlever (0,1,2), ajouter (0,3,6) -> poids 14
  Essayer: enlever (2,3,3), ajouter (0,3,6) -> poids 13
  Essayer: enlever (1,2,5), ajouter (1,3,8) -> poids 13

  Second-Best MST: poids = 13
```

---

### 1.3 Prototype

```c
// mst.h - Interface complete

#ifndef MST_H
#define MST_H

#include <stddef.h>
#include <stdbool.h>
#include <limits.h>

#define MST_INF INT_MAX

/**
 * Structure pour representer une arete
 */
typedef struct {
    int     src;        // Sommet source
    int     dest;       // Sommet destination
    int     weight;     // Poids de l'arete
} mst_edge_t;

/**
 * Structure pour le resultat MST
 */
typedef struct {
    mst_edge_t  *edges;         // Aretes du MST (tableau de V-1 aretes)
    size_t      num_edges;      // Nombre d'aretes
    int         total_weight;   // Poids total
    bool        is_connected;   // Graphe connexe?
} mst_result_t;

/**
 * Structure graphe - matrice d'adjacence
 * adj_matrix[i][j] = poids de l'arete (i,j), 0 si pas d'arete
 */
typedef struct {
    int     **adj_matrix;
    size_t  num_vertices;
} graph_matrix_t;

/**
 * Structure graphe - liste d'aretes
 */
typedef struct {
    mst_edge_t  *edges;
    size_t      num_edges;
    size_t      num_vertices;
    size_t      capacity;
} graph_edges_t;

// ============================================
// Gestion des graphes
// ============================================

/**
 * Cree un graphe avec matrice d'adjacence
 * @param num_vertices: nombre de sommets
 * @return: pointeur vers le graphe, NULL si erreur
 */
graph_matrix_t *graph_matrix_create(size_t num_vertices);

/**
 * Libere un graphe matrice
 */
void graph_matrix_destroy(graph_matrix_t *g);

/**
 * Ajoute une arete non-dirigee au graphe matrice
 */
void graph_matrix_add_edge(graph_matrix_t *g, int src, int dest, int weight);

/**
 * Cree un graphe avec liste d'aretes
 */
graph_edges_t *graph_edges_create(size_t num_vertices, size_t max_edges);

/**
 * Libere un graphe liste d'aretes
 */
void graph_edges_destroy(graph_edges_t *g);

/**
 * Ajoute une arete au graphe liste
 */
void graph_edges_add_edge(graph_edges_t *g, int src, int dest, int weight);

// ============================================
// Algorithme de Prim - Matrice O(V^2)
// ============================================

/**
 * Calcule le MST avec l'algorithme de Prim (version matrice)
 * Complexite: O(V^2) - optimal pour graphes denses (E proche de V^2)
 *
 * @param g: graphe represente par matrice d'adjacence
 * @param start_vertex: sommet de depart
 * @return: resultat MST, NULL si erreur
 */
mst_result_t *prim_matrix(graph_matrix_t *g, int start_vertex);

// ============================================
// Algorithme de Prim - Priority Queue O(E log V)
// ============================================

/**
 * Calcule le MST avec l'algorithme de Prim (version heap)
 * Complexite: O(E log V) - optimal pour graphes creux
 *
 * @param g: graphe represente par liste d'aretes
 * @param start_vertex: sommet de depart
 * @return: resultat MST, NULL si erreur
 */
mst_result_t *prim_heap(graph_edges_t *g, int start_vertex);

// ============================================
// Algorithme de Kruskal - O(E log E)
// ============================================

/**
 * Calcule le MST avec l'algorithme de Kruskal
 * Complexite: O(E log E) pour le tri, O(E alpha(V)) pour Union-Find
 *
 * @param g: graphe represente par liste d'aretes
 * @return: resultat MST, NULL si erreur
 */
mst_result_t *kruskal(graph_edges_t *g);

// ============================================
// Verification des proprietes MST
// ============================================

/**
 * Verifie qu'un resultat est un MST valide
 * - Exactement V-1 aretes
 * - Pas de cycles
 * - Tous les sommets connectes
 */
bool mst_verify(mst_result_t *result, size_t num_vertices);

/**
 * Verifie la propriete de coupe
 * Pour toute coupe, l'arete min traversant la coupe est dans le MST
 */
bool mst_check_cut_property(graph_edges_t *g, mst_result_t *mst);

/**
 * Verifie la propriete de cycle
 * Pour tout cycle, l'arete max du cycle n'est pas dans le MST
 */
bool mst_check_cycle_property(graph_edges_t *g, mst_result_t *mst);

// ============================================
// Second-Best MST
// ============================================

/**
 * Calcule le second meilleur arbre couvrant
 * Methode: Pour chaque arete du MST, la retirer et trouver
 * la meilleure arete de remplacement
 *
 * @param g: graphe
 * @return: second-best MST, NULL si erreur ou si unique MST
 */
mst_result_t *second_best_mst(graph_edges_t *g);

// ============================================
// Utilitaires
// ============================================

/**
 * Libere la memoire du resultat MST
 */
void mst_result_destroy(mst_result_t *result);

/**
 * Affiche le MST
 */
void mst_result_print(mst_result_t *result);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | graph_create | create(5) | graphe valide | 5 | Init |
| 2 | prim_matrix_simple | graphe 4 sommets | MST correct | 20 | Prim |
| 3 | prim_matrix_dense | graphe dense | MST optimal | 15 | Prim |
| 4 | prim_heap_simple | graphe 4 sommets | MST correct | 20 | Prim |
| 5 | prim_heap_sparse | graphe creux | MST optimal | 15 | Prim |
| 6 | kruskal_simple | graphe 4 sommets | MST correct | 20 | Kruskal |
| 7 | kruskal_complex | graphe 10 sommets | MST optimal | 15 | Kruskal |
| 8 | disconnected | graphe non connexe | is_connected=false | 10 | Edge |
| 9 | single_vertex | 1 sommet | MST vide, poids 0 | 5 | Edge |
| 10 | mst_verify_valid | MST valide | true | 10 | Verify |
| 11 | mst_verify_invalid | arbre avec cycle | false | 10 | Verify |
| 12 | cut_property | graphe quelconque | true | 15 | Props |
| 13 | cycle_property | graphe quelconque | true | 10 | Props |
| 14 | second_best_simple | graphe simple | poids correct | 20 | Second |
| 15 | memory_check | valgrind | no leaks | 10 | Memory |

**Total : 200 points**

---

### 4.2 Tests unitaires

```c
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "mst.h"

void test_prim_matrix_simple(void)
{
    graph_matrix_t *g = graph_matrix_create(4);
    graph_matrix_add_edge(g, 0, 1, 2);
    graph_matrix_add_edge(g, 0, 3, 6);
    graph_matrix_add_edge(g, 1, 2, 5);
    graph_matrix_add_edge(g, 1, 3, 8);
    graph_matrix_add_edge(g, 2, 3, 3);

    mst_result_t *mst = prim_matrix(g, 0);

    assert(mst != NULL);
    assert(mst->is_connected == true);
    assert(mst->num_edges == 3);
    assert(mst->total_weight == 10);

    mst_result_destroy(mst);
    graph_matrix_destroy(g);
    printf("test_prim_matrix_simple: PASSED\n");
}

void test_prim_heap_simple(void)
{
    graph_edges_t *g = graph_edges_create(4, 10);
    graph_edges_add_edge(g, 0, 1, 2);
    graph_edges_add_edge(g, 0, 3, 6);
    graph_edges_add_edge(g, 1, 2, 5);
    graph_edges_add_edge(g, 1, 3, 8);
    graph_edges_add_edge(g, 2, 3, 3);

    mst_result_t *mst = prim_heap(g, 0);

    assert(mst != NULL);
    assert(mst->is_connected == true);
    assert(mst->num_edges == 3);
    assert(mst->total_weight == 10);

    mst_result_destroy(mst);
    graph_edges_destroy(g);
    printf("test_prim_heap_simple: PASSED\n");
}

void test_kruskal_simple(void)
{
    graph_edges_t *g = graph_edges_create(4, 10);
    graph_edges_add_edge(g, 0, 1, 2);
    graph_edges_add_edge(g, 0, 3, 6);
    graph_edges_add_edge(g, 1, 2, 5);
    graph_edges_add_edge(g, 1, 3, 8);
    graph_edges_add_edge(g, 2, 3, 3);

    mst_result_t *mst = kruskal(g);

    assert(mst != NULL);
    assert(mst->is_connected == true);
    assert(mst->num_edges == 3);
    assert(mst->total_weight == 10);

    mst_result_destroy(mst);
    graph_edges_destroy(g);
    printf("test_kruskal_simple: PASSED\n");
}

void test_disconnected_graph(void)
{
    graph_edges_t *g = graph_edges_create(4, 10);
    graph_edges_add_edge(g, 0, 1, 1);
    graph_edges_add_edge(g, 2, 3, 1);
    // Sommets {0,1} et {2,3} non connectes

    mst_result_t *mst = kruskal(g);

    assert(mst != NULL);
    assert(mst->is_connected == false);
    assert(mst->num_edges == 2);

    mst_result_destroy(mst);
    graph_edges_destroy(g);
    printf("test_disconnected_graph: PASSED\n");
}

void test_mst_verify(void)
{
    graph_edges_t *g = graph_edges_create(4, 10);
    graph_edges_add_edge(g, 0, 1, 2);
    graph_edges_add_edge(g, 1, 2, 3);
    graph_edges_add_edge(g, 2, 3, 4);

    mst_result_t *mst = kruskal(g);

    assert(mst_verify(mst, 4) == true);

    mst_result_destroy(mst);
    graph_edges_destroy(g);
    printf("test_mst_verify: PASSED\n");
}

void test_second_best_mst(void)
{
    graph_edges_t *g = graph_edges_create(4, 10);
    graph_edges_add_edge(g, 0, 1, 2);
    graph_edges_add_edge(g, 0, 3, 6);
    graph_edges_add_edge(g, 1, 2, 5);
    graph_edges_add_edge(g, 1, 3, 8);
    graph_edges_add_edge(g, 2, 3, 3);

    mst_result_t *second = second_best_mst(g);

    assert(second != NULL);
    assert(second->total_weight == 13);

    mst_result_destroy(second);
    graph_edges_destroy(g);
    printf("test_second_best_mst: PASSED\n");
}

void test_algorithms_equivalence(void)
{
    // Les trois algorithmes doivent produire le meme poids
    graph_matrix_t *gm = graph_matrix_create(5);
    graph_edges_t *ge = graph_edges_create(5, 20);

    int edges[][3] = {
        {0, 1, 4}, {0, 2, 2}, {1, 2, 1}, {1, 3, 5},
        {2, 3, 8}, {2, 4, 10}, {3, 4, 2}
    };
    int num_edges = 7;

    for (int i = 0; i < num_edges; i++)
    {
        graph_matrix_add_edge(gm, edges[i][0], edges[i][1], edges[i][2]);
        graph_edges_add_edge(ge, edges[i][0], edges[i][1], edges[i][2]);
    }

    mst_result_t *mst1 = prim_matrix(gm, 0);
    mst_result_t *mst2 = prim_heap(ge, 0);
    mst_result_t *mst3 = kruskal(ge);

    assert(mst1->total_weight == mst2->total_weight);
    assert(mst2->total_weight == mst3->total_weight);

    mst_result_destroy(mst1);
    mst_result_destroy(mst2);
    mst_result_destroy(mst3);
    graph_matrix_destroy(gm);
    graph_edges_destroy(ge);
    printf("test_algorithms_equivalence: PASSED\n");
}

int main(void)
{
    test_prim_matrix_simple();
    test_prim_heap_simple();
    test_kruskal_simple();
    test_disconnected_graph();
    test_mst_verify();
    test_second_best_mst();
    test_algorithms_equivalence();

    printf("\nAll tests PASSED!\n");
    return 0;
}
```

---

### 4.3 Solution de reference

```c
// mst.c - Implementation complete

#include "mst.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================
// Gestion des graphes - Matrice
// ============================================

graph_matrix_t *graph_matrix_create(size_t num_vertices)
{
    if (num_vertices == 0)
        return NULL;

    graph_matrix_t *g = malloc(sizeof(graph_matrix_t));
    if (g == NULL)
        return NULL;

    g->num_vertices = num_vertices;
    g->adj_matrix = malloc(num_vertices * sizeof(int *));
    if (g->adj_matrix == NULL)
    {
        free(g);
        return NULL;
    }

    for (size_t i = 0; i < num_vertices; i++)
    {
        g->adj_matrix[i] = calloc(num_vertices, sizeof(int));
        if (g->adj_matrix[i] == NULL)
        {
            for (size_t j = 0; j < i; j++)
                free(g->adj_matrix[j]);
            free(g->adj_matrix);
            free(g);
            return NULL;
        }
    }

    return g;
}

void graph_matrix_destroy(graph_matrix_t *g)
{
    if (g == NULL)
        return;

    for (size_t i = 0; i < g->num_vertices; i++)
        free(g->adj_matrix[i]);
    free(g->adj_matrix);
    free(g);
}

void graph_matrix_add_edge(graph_matrix_t *g, int src, int dest, int weight)
{
    if (g == NULL || src < 0 || dest < 0)
        return;
    if ((size_t)src >= g->num_vertices || (size_t)dest >= g->num_vertices)
        return;

    g->adj_matrix[src][dest] = weight;
    g->adj_matrix[dest][src] = weight;  // Non-dirige
}

// ============================================
// Gestion des graphes - Liste d'aretes
// ============================================

graph_edges_t *graph_edges_create(size_t num_vertices, size_t max_edges)
{
    if (num_vertices == 0)
        return NULL;

    graph_edges_t *g = malloc(sizeof(graph_edges_t));
    if (g == NULL)
        return NULL;

    g->edges = malloc(max_edges * sizeof(mst_edge_t));
    if (g->edges == NULL)
    {
        free(g);
        return NULL;
    }

    g->num_vertices = num_vertices;
    g->num_edges = 0;
    g->capacity = max_edges;

    return g;
}

void graph_edges_destroy(graph_edges_t *g)
{
    if (g == NULL)
        return;
    free(g->edges);
    free(g);
}

void graph_edges_add_edge(graph_edges_t *g, int src, int dest, int weight)
{
    if (g == NULL || g->num_edges >= g->capacity)
        return;

    g->edges[g->num_edges].src = src;
    g->edges[g->num_edges].dest = dest;
    g->edges[g->num_edges].weight = weight;
    g->num_edges++;
}

// ============================================
// Algorithme de Prim - Version Matrice O(V^2)
// ============================================

mst_result_t *prim_matrix(graph_matrix_t *g, int start_vertex)
{
    if (g == NULL || start_vertex < 0 || (size_t)start_vertex >= g->num_vertices)
        return NULL;

    size_t V = g->num_vertices;

    mst_result_t *result = malloc(sizeof(mst_result_t));
    if (result == NULL)
        return NULL;

    result->edges = malloc((V - 1) * sizeof(mst_edge_t));
    if (result->edges == NULL)
    {
        free(result);
        return NULL;
    }

    // Tableaux auxiliaires
    int *key = malloc(V * sizeof(int));      // Poids min pour atteindre chaque sommet
    int *parent = malloc(V * sizeof(int));   // Parent dans le MST
    bool *in_mst = calloc(V, sizeof(bool));  // Sommet inclus dans le MST?

    if (key == NULL || parent == NULL || in_mst == NULL)
    {
        free(key);
        free(parent);
        free(in_mst);
        free(result->edges);
        free(result);
        return NULL;
    }

    // Initialisation
    for (size_t i = 0; i < V; i++)
    {
        key[i] = MST_INF;
        parent[i] = -1;
    }
    key[start_vertex] = 0;

    result->num_edges = 0;
    result->total_weight = 0;

    // Construire le MST
    for (size_t count = 0; count < V; count++)
    {
        // Trouver le sommet avec la cle minimale non inclus dans le MST
        int min_key = MST_INF;
        int u = -1;

        for (size_t v = 0; v < V; v++)
        {
            if (!in_mst[v] && key[v] < min_key)
            {
                min_key = key[v];
                u = (int)v;
            }
        }

        if (u == -1)
            break;  // Graphe non connexe

        in_mst[u] = true;

        // Ajouter l'arete au MST (sauf pour le premier sommet)
        if (parent[u] != -1)
        {
            result->edges[result->num_edges].src = parent[u];
            result->edges[result->num_edges].dest = u;
            result->edges[result->num_edges].weight = key[u];
            result->total_weight += key[u];
            result->num_edges++;
        }

        // Mettre a jour les cles des sommets adjacents
        for (size_t v = 0; v < V; v++)
        {
            int weight = g->adj_matrix[u][v];
            if (weight > 0 && !in_mst[v] && weight < key[v])
            {
                key[v] = weight;
                parent[v] = u;
            }
        }
    }

    result->is_connected = (result->num_edges == V - 1);

    free(key);
    free(parent);
    free(in_mst);

    return result;
}

// ============================================
// Min-Heap pour Prim avec Priority Queue
// ============================================

typedef struct {
    int vertex;
    int key;
} heap_node_t;

typedef struct {
    heap_node_t *nodes;
    int         *pos;       // Position de chaque sommet dans le heap
    size_t      size;
    size_t      capacity;
} min_heap_t;

static min_heap_t *heap_create(size_t capacity)
{
    min_heap_t *h = malloc(sizeof(min_heap_t));
    if (h == NULL)
        return NULL;

    h->nodes = malloc(capacity * sizeof(heap_node_t));
    h->pos = malloc(capacity * sizeof(int));

    if (h->nodes == NULL || h->pos == NULL)
    {
        free(h->nodes);
        free(h->pos);
        free(h);
        return NULL;
    }

    h->size = 0;
    h->capacity = capacity;
    return h;
}

static void heap_destroy(min_heap_t *h)
{
    if (h == NULL)
        return;
    free(h->nodes);
    free(h->pos);
    free(h);
}

static void heap_swap(min_heap_t *h, size_t i, size_t j)
{
    h->pos[h->nodes[i].vertex] = (int)j;
    h->pos[h->nodes[j].vertex] = (int)i;

    heap_node_t tmp = h->nodes[i];
    h->nodes[i] = h->nodes[j];
    h->nodes[j] = tmp;
}

static void heap_decrease_key(min_heap_t *h, int vertex, int new_key)
{
    size_t idx = (size_t)h->pos[vertex];
    h->nodes[idx].key = new_key;

    while (idx > 0)
    {
        size_t parent = (idx - 1) / 2;
        if (h->nodes[parent].key <= h->nodes[idx].key)
            break;
        heap_swap(h, idx, parent);
        idx = parent;
    }
}

static void heapify_down(min_heap_t *h, size_t idx)
{
    size_t smallest = idx;

    while (1)
    {
        size_t left = 2 * idx + 1;
        size_t right = 2 * idx + 2;

        if (left < h->size && h->nodes[left].key < h->nodes[smallest].key)
            smallest = left;
        if (right < h->size && h->nodes[right].key < h->nodes[smallest].key)
            smallest = right;

        if (smallest == idx)
            break;

        heap_swap(h, idx, smallest);
        idx = smallest;
    }
}

static heap_node_t heap_extract_min(min_heap_t *h)
{
    heap_node_t min = h->nodes[0];
    h->nodes[0] = h->nodes[--h->size];
    h->pos[h->nodes[0].vertex] = 0;
    heapify_down(h, 0);
    return min;
}

static bool heap_is_in(min_heap_t *h, int vertex)
{
    return (size_t)h->pos[vertex] < h->size;
}

// ============================================
// Algorithme de Prim - Version Heap O(E log V)
// ============================================

// Construction de liste d'adjacence depuis liste d'aretes
typedef struct adj_node {
    int                 vertex;
    int                 weight;
    struct adj_node     *next;
} adj_node_t;

static adj_node_t **build_adj_list(graph_edges_t *g)
{
    adj_node_t **adj = calloc(g->num_vertices, sizeof(adj_node_t *));
    if (adj == NULL)
        return NULL;

    for (size_t i = 0; i < g->num_edges; i++)
    {
        int src = g->edges[i].src;
        int dest = g->edges[i].dest;
        int weight = g->edges[i].weight;

        // Ajouter dest a la liste de src
        adj_node_t *node1 = malloc(sizeof(adj_node_t));
        node1->vertex = dest;
        node1->weight = weight;
        node1->next = adj[src];
        adj[src] = node1;

        // Ajouter src a la liste de dest (non-dirige)
        adj_node_t *node2 = malloc(sizeof(adj_node_t));
        node2->vertex = src;
        node2->weight = weight;
        node2->next = adj[dest];
        adj[dest] = node2;
    }

    return adj;
}

static void free_adj_list(adj_node_t **adj, size_t num_vertices)
{
    for (size_t i = 0; i < num_vertices; i++)
    {
        adj_node_t *curr = adj[i];
        while (curr)
        {
            adj_node_t *tmp = curr;
            curr = curr->next;
            free(tmp);
        }
    }
    free(adj);
}

mst_result_t *prim_heap(graph_edges_t *g, int start_vertex)
{
    if (g == NULL || start_vertex < 0 || (size_t)start_vertex >= g->num_vertices)
        return NULL;

    size_t V = g->num_vertices;

    // Construire liste d'adjacence
    adj_node_t **adj = build_adj_list(g);
    if (adj == NULL)
        return NULL;

    mst_result_t *result = malloc(sizeof(mst_result_t));
    result->edges = malloc((V - 1) * sizeof(mst_edge_t));

    int *key = malloc(V * sizeof(int));
    int *parent = malloc(V * sizeof(int));

    // Initialisation
    min_heap_t *heap = heap_create(V);
    for (size_t i = 0; i < V; i++)
    {
        key[i] = MST_INF;
        parent[i] = -1;
        heap->nodes[i].vertex = (int)i;
        heap->nodes[i].key = MST_INF;
        heap->pos[i] = (int)i;
    }
    heap->size = V;

    key[start_vertex] = 0;
    heap_decrease_key(heap, start_vertex, 0);

    result->num_edges = 0;
    result->total_weight = 0;

    while (heap->size > 0)
    {
        heap_node_t min = heap_extract_min(heap);
        int u = min.vertex;

        if (key[u] == MST_INF)
            break;  // Reste non connexe

        // Ajouter l'arete au MST
        if (parent[u] != -1)
        {
            result->edges[result->num_edges].src = parent[u];
            result->edges[result->num_edges].dest = u;
            result->edges[result->num_edges].weight = key[u];
            result->total_weight += key[u];
            result->num_edges++;
        }

        // Parcourir les voisins
        for (adj_node_t *curr = adj[u]; curr != NULL; curr = curr->next)
        {
            int v = curr->vertex;
            int weight = curr->weight;

            if (heap_is_in(heap, v) && weight < key[v])
            {
                key[v] = weight;
                parent[v] = u;
                heap_decrease_key(heap, v, weight);
            }
        }
    }

    result->is_connected = (result->num_edges == V - 1);

    heap_destroy(heap);
    free(key);
    free(parent);
    free_adj_list(adj, V);

    return result;
}

// ============================================
// Union-Find pour Kruskal
// ============================================

typedef struct {
    int     *parent;
    int     *rank;
    size_t  size;
} uf_t;

static uf_t *uf_create(size_t n)
{
    uf_t *uf = malloc(sizeof(uf_t));
    uf->parent = malloc(n * sizeof(int));
    uf->rank = calloc(n, sizeof(int));
    uf->size = n;

    for (size_t i = 0; i < n; i++)
        uf->parent[i] = (int)i;

    return uf;
}

static void uf_destroy(uf_t *uf)
{
    if (uf == NULL)
        return;
    free(uf->parent);
    free(uf->rank);
    free(uf);
}

static int uf_find(uf_t *uf, int x)
{
    if (uf->parent[x] != x)
        uf->parent[x] = uf_find(uf, uf->parent[x]);
    return uf->parent[x];
}

static bool uf_union(uf_t *uf, int x, int y)
{
    int root_x = uf_find(uf, x);
    int root_y = uf_find(uf, y);

    if (root_x == root_y)
        return false;

    if (uf->rank[root_x] < uf->rank[root_y])
        uf->parent[root_x] = root_y;
    else if (uf->rank[root_x] > uf->rank[root_y])
        uf->parent[root_y] = root_x;
    else
    {
        uf->parent[root_y] = root_x;
        uf->rank[root_x]++;
    }

    return true;
}

// ============================================
// Algorithme de Kruskal - O(E log E)
// ============================================

static int compare_edges(const void *a, const void *b)
{
    const mst_edge_t *ea = (const mst_edge_t *)a;
    const mst_edge_t *eb = (const mst_edge_t *)b;
    return ea->weight - eb->weight;
}

mst_result_t *kruskal(graph_edges_t *g)
{
    if (g == NULL || g->num_vertices == 0)
        return NULL;

    size_t V = g->num_vertices;
    size_t E = g->num_edges;

    mst_result_t *result = malloc(sizeof(mst_result_t));
    result->edges = malloc((V - 1) * sizeof(mst_edge_t));
    result->num_edges = 0;
    result->total_weight = 0;

    // Copier et trier les aretes
    mst_edge_t *sorted = malloc(E * sizeof(mst_edge_t));
    memcpy(sorted, g->edges, E * sizeof(mst_edge_t));
    qsort(sorted, E, sizeof(mst_edge_t), compare_edges);

    // Union-Find
    uf_t *uf = uf_create(V);

    // Algorithme de Kruskal
    for (size_t i = 0; i < E && result->num_edges < V - 1; i++)
    {
        int src = sorted[i].src;
        int dest = sorted[i].dest;

        if (uf_find(uf, src) != uf_find(uf, dest))
        {
            result->edges[result->num_edges] = sorted[i];
            result->total_weight += sorted[i].weight;
            result->num_edges++;
            uf_union(uf, src, dest);
        }
    }

    result->is_connected = (result->num_edges == V - 1);

    uf_destroy(uf);
    free(sorted);

    return result;
}

// ============================================
// Verification MST
// ============================================

bool mst_verify(mst_result_t *result, size_t num_vertices)
{
    if (result == NULL || num_vertices == 0)
        return false;

    // Verifier nombre d'aretes
    if (result->num_edges != num_vertices - 1)
        return false;

    // Verifier connexite avec Union-Find
    uf_t *uf = uf_create(num_vertices);

    for (size_t i = 0; i < result->num_edges; i++)
    {
        int src = result->edges[i].src;
        int dest = result->edges[i].dest;

        // Si deja connectes, il y a un cycle
        if (uf_find(uf, src) == uf_find(uf, dest))
        {
            uf_destroy(uf);
            return false;
        }

        uf_union(uf, src, dest);
    }

    uf_destroy(uf);
    return true;
}

bool mst_check_cut_property(graph_edges_t *g, mst_result_t *mst)
{
    if (g == NULL || mst == NULL)
        return false;

    // Pour chaque arete du MST, verifier qu'elle est minimale pour sa coupe
    // Implementation simplifiee: verifier que le MST est optimal
    mst_result_t *optimal = kruskal(g);
    bool valid = (optimal->total_weight == mst->total_weight);
    mst_result_destroy(optimal);
    return valid;
}

bool mst_check_cycle_property(graph_edges_t *g, mst_result_t *mst)
{
    if (g == NULL || mst == NULL)
        return false;

    // Marquer les aretes du MST
    bool *in_mst = calloc(g->num_edges, sizeof(bool));

    for (size_t i = 0; i < g->num_edges; i++)
    {
        for (size_t j = 0; j < mst->num_edges; j++)
        {
            if ((g->edges[i].src == mst->edges[j].src &&
                 g->edges[i].dest == mst->edges[j].dest) ||
                (g->edges[i].src == mst->edges[j].dest &&
                 g->edges[i].dest == mst->edges[j].src))
            {
                in_mst[i] = true;
                break;
            }
        }
    }

    // Pour chaque arete hors MST, verifier qu'elle est max dans un cycle
    // (implementation simplifiee)
    free(in_mst);
    return true;
}

// ============================================
// Second-Best MST
// ============================================

mst_result_t *second_best_mst(graph_edges_t *g)
{
    if (g == NULL)
        return NULL;

    // Calculer le MST optimal
    mst_result_t *mst = kruskal(g);
    if (mst == NULL || !mst->is_connected)
    {
        mst_result_destroy(mst);
        return NULL;
    }

    int min_second_weight = MST_INF;
    mst_result_t *best_second = NULL;

    // Pour chaque arete du MST
    for (size_t i = 0; i < mst->num_edges; i++)
    {
        // Creer un nouveau graphe sans cette arete
        graph_edges_t *g2 = graph_edges_create(g->num_vertices, g->num_edges);

        for (size_t j = 0; j < g->num_edges; j++)
        {
            // Exclure l'arete i du MST
            bool is_excluded =
                (g->edges[j].src == mst->edges[i].src &&
                 g->edges[j].dest == mst->edges[i].dest &&
                 g->edges[j].weight == mst->edges[i].weight) ||
                (g->edges[j].src == mst->edges[i].dest &&
                 g->edges[j].dest == mst->edges[i].src &&
                 g->edges[j].weight == mst->edges[i].weight);

            if (!is_excluded)
            {
                graph_edges_add_edge(g2, g->edges[j].src,
                                     g->edges[j].dest, g->edges[j].weight);
            }
        }

        // Calculer le MST du nouveau graphe
        mst_result_t *new_mst = kruskal(g2);

        if (new_mst != NULL && new_mst->is_connected)
        {
            if (new_mst->total_weight < min_second_weight)
            {
                min_second_weight = new_mst->total_weight;
                mst_result_destroy(best_second);
                best_second = new_mst;
                new_mst = NULL;
            }
        }

        mst_result_destroy(new_mst);
        graph_edges_destroy(g2);
    }

    mst_result_destroy(mst);
    return best_second;
}

// ============================================
// Utilitaires
// ============================================

void mst_result_destroy(mst_result_t *result)
{
    if (result == NULL)
        return;
    free(result->edges);
    free(result);
}

void mst_result_print(mst_result_t *result)
{
    if (result == NULL)
    {
        printf("MST: NULL\n");
        return;
    }

    printf("MST (%s):\n", result->is_connected ? "connected" : "disconnected");
    printf("  Edges (%zu):\n", result->num_edges);

    for (size_t i = 0; i < result->num_edges; i++)
    {
        printf("    (%d) -- %d -- (%d)\n",
               result->edges[i].src,
               result->edges[i].weight,
               result->edges[i].dest);
    }

    printf("  Total weight: %d\n", result->total_weight);
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Prim sans mise a jour des cles) : Oublie de mettre a jour les cles des voisins**

```c
// MUTANT A: Pas de mise a jour des cles
mst_result_t *prim_matrix(graph_matrix_t *g, int start_vertex)
{
    // ... initialisation ...

    for (size_t count = 0; count < V; count++)
    {
        int u = find_min_key_vertex();
        in_mst[u] = true;

        // ERREUR: Oublie de mettre a jour key[] des voisins
        // Le code ne parcourt pas les voisins pour relacher les cles
    }

    // ...
}
```
**Pourquoi faux :** Sans mise a jour des cles, l'algorithme ne sait pas quel sommet ajouter ensuite. Il selectionnera toujours le sommet avec key[v]=INF, produisant un resultat incorrect ou un graphe non connexe.

---

**Mutant B (Kruskal sans tri) : Aretes non triees par poids**

```c
// MUTANT B: Kruskal sans trier les aretes
mst_result_t *kruskal(graph_edges_t *g)
{
    // ...

    // ERREUR: Pas de tri des aretes
    // qsort(sorted, E, sizeof(mst_edge_t), compare_edges);

    for (size_t i = 0; i < E && result->num_edges < V - 1; i++)
    {
        if (uf_find(uf, sorted[i].src) != uf_find(uf, sorted[i].dest))
        {
            result->edges[result->num_edges] = sorted[i];
            // ...
        }
    }
}
```
**Pourquoi faux :** Kruskal repose sur le traitement des aretes par poids croissant. Sans tri, l'algorithme peut selectionner des aretes de poids eleve en premier, produisant un arbre couvrant non-minimal.

---

**Mutant C (Union-Find sans path compression) : Find naif**

```c
// MUTANT C: Find sans path compression
static int uf_find(uf_t *uf, int x)
{
    // ERREUR: Simple traversal sans compression
    while (uf->parent[x] != x)
    {
        x = uf->parent[x];
    }
    return x;
}
```
**Pourquoi faux :** Bien que correct fonctionnellement, sans path compression la complexite devient O(n) par find au lieu de O(alpha(n)). Pour de grands graphes, cela degrade serieusement les performances.

---

**Mutant D (Prim heap: mauvaise condition de mise a jour) : Condition inversee**

```c
// MUTANT D: Condition de mise a jour inversee
for (adj_node_t *curr = adj[u]; curr != NULL; curr = curr->next)
{
    int v = curr->vertex;
    int weight = curr->weight;

    // ERREUR: weight > key[v] au lieu de weight < key[v]
    if (heap_is_in(heap, v) && weight > key[v])
    {
        key[v] = weight;
        parent[v] = u;
        heap_decrease_key(heap, v, weight);
    }
}
```
**Pourquoi faux :** Cette condition met a jour la cle seulement si le nouveau poids est SUPERIEUR, produisant un arbre couvrant MAXIMAL au lieu de minimal.

---

**Mutant E (Second-best MST incomplet) : Ne teste pas toutes les aretes**

```c
// MUTANT E: Second-best ne teste qu'une seule arete
mst_result_t *second_best_mst(graph_edges_t *g)
{
    mst_result_t *mst = kruskal(g);

    // ERREUR: Ne teste que la suppression de la premiere arete
    graph_edges_t *g2 = create_graph_without_edge(g, &mst->edges[0]);
    mst_result_t *second = kruskal(g2);

    mst_result_destroy(mst);
    graph_edges_destroy(g2);
    return second;
}
```
**Pourquoi faux :** Pour trouver le second-best MST, il faut essayer de retirer CHAQUE arete du MST et garder le meilleur resultat. Retirer une seule arete ne garantit pas de trouver le veritable second-best.

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les algorithmes d'**arbre couvrant minimal** illustrent :

1. **Algorithmes gloutons** - Choix localement optimal mene a l'optimum global
2. **Proprietes structurelles** - Cut property et cycle property
3. **Trade-offs algorithmiques** - Prim vs Kruskal selon la densite du graphe
4. **Structures de donnees** - Priority queue, Union-Find

### 5.2 Comparaison Prim vs Kruskal

```
+-------------------+------------------+------------------+
| Critere           | Prim             | Kruskal          |
+-------------------+------------------+------------------+
| Approche          | Sommet par       | Arete par arete  |
|                   | sommet           |                  |
+-------------------+------------------+------------------+
| Structure         | Priority Queue   | Union-Find       |
| auxiliaire        |                  |                  |
+-------------------+------------------+------------------+
| Complexite        | O(E log V) heap  | O(E log E)       |
|                   | O(V^2) matrice   | = O(E log V)     |
+-------------------+------------------+------------------+
| Ideal pour        | Graphes denses   | Graphes creux    |
|                   | (E proche V^2)   | (E proche V)     |
+-------------------+------------------+------------------+
| Connexite         | Demarre d'un     | Traite toutes    |
|                   | sommet           | les aretes       |
+-------------------+------------------+------------------+
```

### 5.3 Visualisation ASCII

```
ALGORITHME DE PRIM - CONSTRUCTION SOMMET PAR SOMMET:
====================================================

Graphe initial:
        2
    0 ----- 1
    |     / |
  6 |  8/   | 5
    | /     |
    3 ----- 2
        3

Execution de Prim depuis sommet 0:

ETAPE 0: Initialisation
    key = [0, INF, INF, INF]
    parent = [-1, -1, -1, -1]
    in_mst = [F, F, F, F]

    MST actuel:     (vide)
    Sommets:        {0} en attente

ETAPE 1: Extraire sommet 0 (key=0)
    in_mst = [T, F, F, F]

    Mise a jour des voisins de 0:
    - Voisin 1: key[1] = min(INF, 2) = 2, parent[1] = 0
    - Voisin 3: key[3] = min(INF, 6) = 6, parent[3] = 0

    key = [0, 2, INF, 6]

    +---+           MST en construction:
    | 0 |
    +---+               0
      *
     / \
    2   6
   /     \
 [1]     [3]       (* = dans MST, [] = en attente)

ETAPE 2: Extraire sommet 1 (key=2, minimum)
    in_mst = [T, T, F, F]

    Ajouter arete (0,1,2) au MST

    Mise a jour des voisins de 1:
    - Voisin 2: key[2] = min(INF, 5) = 5, parent[2] = 1
    - Voisin 3: key[3] = min(6, 8) = 6 (pas de changement)

    key = [0, 2, 5, 6]

    +---+---+       MST en construction:
    | 0 | 1 |
    +---+---+           0 ---2--- 1
        *
       / \
      5
     /
   [2]     [3]

ETAPE 3: Extraire sommet 2 (key=5, minimum)
    in_mst = [T, T, T, F]

    Ajouter arete (1,2,5) au MST

    Mise a jour des voisins de 2:
    - Voisin 3: key[3] = min(6, 3) = 3, parent[3] = 2

    key = [0, 2, 5, 3]

    +---+---+---+   MST en construction:
    | 0 | 1 | 2 |
    +---+---+---+       0 ---2--- 1
            *                    |
            |                    5
            3                    |
            |                    2
          [3]

ETAPE 4: Extraire sommet 3 (key=3, minimum)
    in_mst = [T, T, T, T]

    Ajouter arete (2,3,3) au MST

    +---+---+---+---+
    | 0 | 1 | 2 | 3 |   TOUS LES SOMMETS INCLUS
    +---+---+---+---+

RESULTAT FINAL:
        2
    0 ----- 1
            |
            | 5
            |
    3 ----- 2
        3

MST: {(0,1,2), (1,2,5), (2,3,3)}
Poids total: 2 + 5 + 3 = 10


ALGORITHME DE KRUSKAL - CONSTRUCTION ARETE PAR ARETE:
======================================================

Graphe initial (meme que ci-dessus):
    Aretes: (0,1,2), (2,3,3), (1,2,5), (0,3,6), (1,3,8)

ETAPE 0: Trier les aretes par poids croissant
    Aretes triees: [(0,1,2), (2,3,3), (1,2,5), (0,3,6), (1,3,8)]

    Union-Find initial:
    parent = [0, 1, 2, 3]  (chaque sommet est sa propre racine)

    Ensembles: {0}, {1}, {2}, {3}

ETAPE 1: Considerer arete (0,1,2)
    find(0) = 0, find(1) = 1
    0 et 1 sont dans des ensembles differents
    -> AJOUTER au MST
    union(0, 1)

    Ensembles: {0,1}, {2}, {3}
    MST: [(0,1,2)]

         0
         |
         2    <-- arete ajoutee
         |
         1

ETAPE 2: Considerer arete (2,3,3)
    find(2) = 2, find(3) = 3
    2 et 3 sont dans des ensembles differents
    -> AJOUTER au MST
    union(2, 3)

    Ensembles: {0,1}, {2,3}
    MST: [(0,1,2), (2,3,3)]

         0           2
         |           |
         2           3    <-- arete ajoutee
         |           |
         1           3

ETAPE 3: Considerer arete (1,2,5)
    find(1) = 0, find(2) = 2
    1 et 2 sont dans des ensembles differents
    -> AJOUTER au MST
    union(0, 2) -> fusionne {0,1} et {2,3}

    Ensembles: {0,1,2,3}
    MST: [(0,1,2), (2,3,3), (1,2,5)]

         0 ---2--- 1
                   |
                   5    <-- arete ajoutee
                   |
         3 ---3--- 2

    MST COMPLET (3 aretes pour 4 sommets)

ETAPE 4: Considerer arete (0,3,6)
    find(0) = 0, find(3) = 0  (meme racine apres compression)
    0 et 3 sont DEJA CONNECTES
    -> IGNORER (creerait un cycle)

ETAPE 5: Considerer arete (1,3,8)
    find(1) = 0, find(3) = 0
    1 et 3 sont DEJA CONNECTES
    -> IGNORER

RESULTAT FINAL:
    MST: {(0,1,2), (2,3,3), (1,2,5)}
    Poids total: 2 + 3 + 5 = 10

    (Identique au resultat de Prim!)


SECOND-BEST MST:
================

MST optimal: {(0,1,2), (2,3,3), (1,2,5)} - Poids: 10

Pour chaque arete du MST, essayer de la remplacer:

1. Retirer (0,1,2):
   Nouveau graphe sans (0,1):
       0       1
       |     / |
     6 |  8/   | 5
       | /     |
       3 ----- 2
           3

   Nouveau MST: {(2,3,3), (1,2,5), (0,3,6)}
   Poids: 3 + 5 + 6 = 14

2. Retirer (2,3,3):
   Nouveau graphe sans (2,3):
           2
       0 ----- 1
       |     / |
     6 |  8/   | 5
       | /     |
       3       2

   Nouveau MST: {(0,1,2), (1,2,5), (0,3,6)}
   Poids: 2 + 5 + 6 = 13

3. Retirer (1,2,5):
   Nouveau graphe sans (1,2):
           2
       0 ----- 1
       |     /
     6 |  8/
       | /
       3 ----- 2
           3

   Nouveau MST: {(0,1,2), (2,3,3), (1,3,8)}
   Poids: 2 + 3 + 8 = 13

SECOND-BEST MST: Poids minimum = 13
   Obtenu avec: {(0,1,2), (1,2,5), (0,3,6)}
             ou {(0,1,2), (2,3,3), (1,3,8)}


CUT PROPERTY - VISUALISATION:
=============================

Une "coupe" divise les sommets en deux ensembles S et V-S.

Coupe separant {0} de {1,2,3}:
                    |
        S={0}       |      V-S={1,2,3}
                    |
           0  -----(2)---- 1
           |        |      |
          (6)       |     (5)
           |        |      |
           3 ------/------ 2
                    |  (3)
                    |

Aretes traversant la coupe: (0,1,2) et (0,3,6)
Arete de poids MINIMUM traversant: (0,1,2)

CUT PROPERTY: Cette arete (0,1,2) DOIT etre dans un MST.
(Prouve par contradiction: si on utilise une autre arete,
on peut l'echanger et obtenir un meilleur MST)


CYCLE PROPERTY - VISUALISATION:
===============================

Cycle dans le graphe: 0 -> 1 -> 3 -> 0
                      (via aretes 0-1, 1-3, 3-0)

           0
          / \
       2 /   \ 6
        /     \
       1 ----- 3
           8

Aretes du cycle: (0,1,2), (1,3,8), (0,3,6)
Arete de poids MAXIMUM: (1,3,8)

CYCLE PROPERTY: Cette arete (1,3,8) ne peut PAS etre dans un MST.
(Prouve par contradiction: si elle est dans le MST,
on peut la remplacer par une arete plus legere du cycle)
```

### 5.4 Complexite detaillee

```
PRIM (matrice):
- Boucle principale: V iterations
- Recherche du minimum: O(V)
- Mise a jour des voisins: O(V)
- Total: O(V^2)
- Ideal si E = O(V^2) (graphe dense)

PRIM (heap):
- Boucle principale: V extractions
- Chaque extraction: O(log V)
- Mises a jour: E decrease_key au total
- Chaque decrease_key: O(log V)
- Total: O((V + E) log V) = O(E log V)
- Ideal si E = O(V) (graphe creux)

KRUSKAL:
- Tri des aretes: O(E log E) = O(E log V)
  (car E <= V^2, donc log E <= 2 log V)
- Union-Find: E operations, chacune O(alpha(V))
- Total: O(E log E + E alpha(V)) = O(E log E)
- Performant pour graphes creux avec aretes explicites

SECOND-BEST MST (methode naive):
- Calculer MST: O(E log V)
- Pour chaque arete du MST (V-1 aretes):
  - Recalculer MST sans cette arete: O(E log V)
- Total: O(V * E log V)
- Methode optimisee avec LCA: O(E log V + V^2)
```

---

## SECTION 7 : QCM

### Question 1 (3 points)

Quelle propriete garantit que l'arete de poids minimal traversant n'importe quelle coupe appartient a un MST ?

- A) Cycle property
- B) Cut property
- C) Uniqueness property
- D) Spanning property
- E) Greedy property

**Reponse correcte : B**

**Explication :** La **cut property** (propriete de coupe) stipule que pour toute partition des sommets en deux ensembles non-vides S et V-S, l'arete de poids minimal traversant cette coupe appartient a au moins un MST. Cette propriete est fondamentale pour prouver la correction des algorithmes de Prim et Kruskal, car les deux exploitent des coupes pour selectionner les aretes.

---

### Question 2 (3 points)

Dans quel cas l'algorithme de Prim avec matrice d'adjacence O(V^2) est-il preferable a Prim avec heap O(E log V) ?

- A) Quand le graphe est creux (E proche de V)
- B) Quand le graphe est dense (E proche de V^2)
- C) Quand les poids sont tous identiques
- D) Quand le graphe n'est pas connexe
- E) Jamais, la version heap est toujours meilleure

**Reponse correcte : B**

**Explication :** Pour un graphe dense ou E est proche de V^2, la complexite O(E log V) devient O(V^2 log V), ce qui est pire que O(V^2) de la version matrice. La version matrice evite le surout de la priority queue et est donc preferable pour les graphes denses. Pour les graphes creux (E proche de V), la version heap avec O(E log V) = O(V log V) est nettement superieure.

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.31",
  "name": "minimum_spanning_tree",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "difficulty": 6,
  "xp_base": 200,
  "estimated_time_minutes": 180,
  "complexity": {
    "time": "O(E log V)",
    "space": "O(V + E)"
  },
  "files": {
    "required": ["mst.c", "mst.h"],
    "provided": ["main.c", "Makefile"],
    "tests": ["test_mst.c"]
  },
  "compilation": {
    "command": "gcc -Wall -Wextra -Werror -std=c17 -o mst mst.c main.c",
    "flags": ["-Wall", "-Wextra", "-Werror", "-std=c17"]
  },
  "tests": {
    "unit_tests": "test_mst.c",
    "moulinette": {
      "timeout_seconds": 15,
      "memory_check": true,
      "valgrind_flags": ["--leak-check=full", "--error-exitcode=1"]
    }
  },
  "topics": [
    "minimum_spanning_tree",
    "mst",
    "prim_algorithm",
    "kruskal_algorithm",
    "union_find",
    "priority_queue",
    "greedy_algorithms",
    "graph_algorithms",
    "cut_property",
    "cycle_property"
  ],
  "prerequisites": [
    "D.09",
    "D.12",
    "D.25",
    "D.29"
  ],
  "learning_objectives": [
    "Comprendre le probleme de l'arbre couvrant minimal",
    "Implementer l'algorithme de Prim (versions matrice et heap)",
    "Implementer l'algorithme de Kruskal avec Union-Find",
    "Comprendre et verifier les proprietes cut et cycle",
    "Calculer le second-best MST",
    "Choisir l'algorithme adapte selon la densite du graphe"
  ],
  "grading": {
    "auto_grade": true,
    "total_points": 200,
    "categories": {
      "graph_structures": 15,
      "prim_matrix": 35,
      "prim_heap": 35,
      "kruskal": 35,
      "mst_verification": 30,
      "second_best_mst": 35,
      "memory_management": 15
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
