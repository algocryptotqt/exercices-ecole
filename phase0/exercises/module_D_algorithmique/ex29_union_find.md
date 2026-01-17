# Exercice D.29 : union_find

**Module :**
D — Algorithmique

**Concept :**
29 — Union-Find (Disjoint Set Union) - Structure de donnees pour ensembles disjoints

**Difficulte :**
[******----] (6/10)

**Type :**
code

**Tiers :**
2 — Integration de concepts

**Langage :**
C17

**Prerequis :**
- Tableaux dynamiques (malloc/free)
- Pointeurs
- Recursivite
- Notion de graphes et composantes connexes

**Domaines :**
Algo, DataStruct, Graphs

**Duree estimee :**
150 min

**XP Base :**
200

**Complexite :**
T[N] O(alpha(n)) x S[N] O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `union_find.c`, `union_find.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | malloc, free, memset |

---

### 1.2 Consigne

#### Section Culture : "Union-Find - Une Structure Elegante pour les Ensembles Disjoints"

La structure **Union-Find** (aussi appelee Disjoint Set Union ou DSU) est une structure de donnees qui maintient une collection d'ensembles disjoints. Elle supporte deux operations principales : trouver le representant d'un ensemble (find) et fusionner deux ensembles (union).

Cette structure est fondamentale en algorithmique :
- Detection de cycles dans les graphes
- Algorithme de Kruskal pour l'arbre couvrant minimal
- Composantes connexes dynamiques
- Percolation (physique statistique)
- Segmentation d'images
- Equivalence de variables (compilateurs)

Les deux optimisations cles - **union by rank** et **path compression** - reduisent la complexite amortie a O(alpha(n)), ou alpha est la fonction inverse d'Ackermann, pratiquement constante pour toute taille realiste.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une structure Union-Find complete avec les optimisations union by rank et path compression. La structure doit supporter les operations find, union, et permettre de determiner les composantes connexes d'un graphe.

**Proprietes de Union-Find :**

```
REPRESENTANT: Chaque ensemble a un element representant (racine)
FIND: Retourne le representant de l'ensemble contenant x
UNION: Fusionne les ensembles contenant x et y

OPTIMISATIONS:
- Path Compression: Lors de find, attacher chaque noeud directement a la racine
- Union by Rank: Attacher l'arbre moins profond sous l'arbre plus profond
```

**Prototypes :**

```c
// union_find.h

#ifndef UNION_FIND_H
#define UNION_FIND_H

#include <stddef.h>
#include <stdbool.h>

/**
 * Structure Union-Find (Disjoint Set Union)
 */
typedef struct {
    int     *parent;    // parent[i] = parent de l'element i
    int     *rank;      // rank[i] = borne superieure de la hauteur du sous-arbre
    size_t  size;       // Nombre d'elements
    size_t  num_sets;   // Nombre d'ensembles disjoints actuels
} union_find_t;

// Creation et destruction
union_find_t    *uf_create(size_t n);
void            uf_destroy(union_find_t *uf);

// Operations de base
int             uf_find(union_find_t *uf, int x);
bool            uf_union(union_find_t *uf, int x, int y);
bool            uf_connected(union_find_t *uf, int x, int y);

// Informations
size_t          uf_count_sets(const union_find_t *uf);
size_t          uf_set_size(union_find_t *uf, int x);

// Version sans path compression (pour comparaison)
int             uf_find_no_compression(union_find_t *uf, int x);

// Reset
void            uf_reset(union_find_t *uf);

// Applications
typedef struct {
    int src;
    int dest;
    int weight;
} edge_t;

// Kruskal's MST using Union-Find
edge_t  *kruskal_mst(edge_t *edges, size_t num_edges, size_t num_vertices,
                      size_t *mst_size, int *total_weight);

// Detection de cycle dans un graphe
bool    has_cycle(edge_t *edges, size_t num_edges, size_t num_vertices);

// Nombre de composantes connexes
size_t  count_components(edge_t *edges, size_t num_edges, size_t num_vertices);

#endif
```

**Comportements attendus :**

| Operation | Exemple | Resultat | Complexite |
|-----------|---------|----------|------------|
| uf_create(5) | - | {0}, {1}, {2}, {3}, {4} | O(n) |
| uf_find(uf, 3) | - | 3 (representant) | O(alpha(n)) |
| uf_union(uf, 0, 1) | {0}, {1} | {0, 1} | O(alpha(n)) |
| uf_connected(uf, 0, 1) | apres union | true | O(alpha(n)) |
| uf_count_sets(uf) | {0,1}, {2}, {3,4} | 3 | O(1) |
| kruskal_mst(...) | graphe pondere | arbre couvrant minimal | O(E log E) |

**Exemples :**

```
UNION-FIND avec 5 elements (0-4):

Initial:
  parent: [0, 1, 2, 3, 4]  (chaque element est sa propre racine)
  rank:   [0, 0, 0, 0, 0]
  sets:   {0}, {1}, {2}, {3}, {4}
  num_sets: 5

Apres union(0, 1):
  parent: [0, 0, 2, 3, 4]  (1 pointe vers 0)
  rank:   [1, 0, 0, 0, 0]  (rang de 0 augmente)
  sets:   {0, 1}, {2}, {3}, {4}
  num_sets: 4

Apres union(2, 3):
  parent: [0, 0, 2, 2, 4]
  rank:   [1, 0, 1, 0, 0]
  sets:   {0, 1}, {2, 3}, {4}
  num_sets: 3

Apres union(0, 2):
  parent: [0, 0, 0, 2, 4]  (2 pointe vers 0, car rang egal)
  rank:   [2, 0, 1, 0, 0]
  sets:   {0, 1, 2, 3}, {4}
  num_sets: 2

find(3) avec path compression:
  Avant: 3 -> 2 -> 0
  Apres: 3 -> 0 (compression)
  parent: [0, 0, 0, 0, 4]
```

---

### 1.3 Prototype

```c
// union_find.h - Interface complete

#ifndef UNION_FIND_H
#define UNION_FIND_H

#include <stddef.h>
#include <stdbool.h>

/**
 * Structure Union-Find (Disjoint Set Union)
 * Maintient une partition d'elements en ensembles disjoints
 */
typedef struct {
    int     *parent;    // parent[i] = parent de l'element i (-1 si racine dans certaines implementations)
    int     *rank;      // rank[i] = borne superieure de la hauteur
    size_t  size;       // Nombre total d'elements
    size_t  num_sets;   // Nombre d'ensembles disjoints actuels
} union_find_t;

/**
 * Cree une nouvelle structure Union-Find avec n elements
 * Initialement, chaque element forme son propre ensemble
 *
 * @param n: nombre d'elements (indices 0 a n-1)
 * @return: pointeur vers la structure, NULL si erreur
 *
 * Complexity: O(n)
 */
union_find_t *uf_create(size_t n);

/**
 * Libere toute la memoire de la structure
 *
 * @param uf: la structure a detruire
 *
 * Complexity: O(1)
 */
void uf_destroy(union_find_t *uf);

/**
 * Trouve le representant (racine) de l'ensemble contenant x
 * Applique la path compression pour optimiser les requetes futures
 *
 * @param uf: la structure union-find
 * @param x: l'element a chercher
 * @return: le representant de l'ensemble, -1 si x invalide
 *
 * Complexity: O(alpha(n)) amortized
 */
int uf_find(union_find_t *uf, int x);

/**
 * Fusionne les ensembles contenant x et y
 * Utilise union by rank pour garder les arbres equilibres
 *
 * @param uf: la structure union-find
 * @param x: premier element
 * @param y: deuxieme element
 * @return: true si fusion effectuee, false si deja dans le meme ensemble
 *
 * Complexity: O(alpha(n)) amortized
 */
bool uf_union(union_find_t *uf, int x, int y);

/**
 * Verifie si deux elements sont dans le meme ensemble
 *
 * @param uf: la structure union-find
 * @param x: premier element
 * @param y: deuxieme element
 * @return: true si connectes
 *
 * Complexity: O(alpha(n)) amortized
 */
bool uf_connected(union_find_t *uf, int x, int y);

/**
 * Retourne le nombre d'ensembles disjoints
 *
 * @param uf: la structure union-find
 * @return: nombre d'ensembles
 *
 * Complexity: O(1)
 */
size_t uf_count_sets(const union_find_t *uf);

/**
 * Retourne la taille de l'ensemble contenant x
 *
 * @param uf: la structure union-find
 * @param x: l'element
 * @return: taille de l'ensemble
 *
 * Complexity: O(n) dans le pire cas
 */
size_t uf_set_size(union_find_t *uf, int x);

/**
 * Find sans path compression (pour comparaison pedagogique)
 *
 * @param uf: la structure union-find
 * @param x: l'element a chercher
 * @return: le representant de l'ensemble
 *
 * Complexity: O(log n) avec union by rank, O(n) sans
 */
int uf_find_no_compression(union_find_t *uf, int x);

/**
 * Reinitialise la structure (chaque element redevient son propre ensemble)
 *
 * @param uf: la structure union-find
 *
 * Complexity: O(n)
 */
void uf_reset(union_find_t *uf);

// ============================================
// Applications
// ============================================

/**
 * Structure pour representer une arete
 */
typedef struct {
    int src;        // Sommet source
    int dest;       // Sommet destination
    int weight;     // Poids de l'arete
} edge_t;

/**
 * Calcule l'arbre couvrant minimal avec l'algorithme de Kruskal
 * Utilise Union-Find pour detecter les cycles efficacement
 *
 * @param edges: tableau des aretes
 * @param num_edges: nombre d'aretes
 * @param num_vertices: nombre de sommets
 * @param mst_size: [out] nombre d'aretes dans le MST
 * @param total_weight: [out] poids total du MST
 * @return: tableau des aretes du MST (a liberer), NULL si erreur
 *
 * Complexity: O(E log E) pour le tri + O(E alpha(V)) pour Union-Find
 */
edge_t *kruskal_mst(edge_t *edges, size_t num_edges, size_t num_vertices,
                    size_t *mst_size, int *total_weight);

/**
 * Detecte si un graphe non-dirige contient un cycle
 *
 * @param edges: tableau des aretes
 * @param num_edges: nombre d'aretes
 * @param num_vertices: nombre de sommets
 * @return: true si un cycle existe
 *
 * Complexity: O(E alpha(V))
 */
bool has_cycle(edge_t *edges, size_t num_edges, size_t num_vertices);

/**
 * Compte le nombre de composantes connexes
 *
 * @param edges: tableau des aretes
 * @param num_edges: nombre d'aretes
 * @param num_vertices: nombre de sommets
 * @return: nombre de composantes connexes
 *
 * Complexity: O(E alpha(V))
 */
size_t count_components(edge_t *edges, size_t num_edges, size_t num_vertices);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | create_basic | uf_create(10) | uf non NULL, 10 sets | 10 | Create |
| 2 | find_initial | find(uf, 5) sur uf frais | 5 | 10 | Find |
| 3 | union_simple | union(0,1), union(2,3) | 2 sets fusionnes | 15 | Union |
| 4 | connected_same | connected(0,1) apres union | true | 10 | Connected |
| 5 | connected_diff | connected(0,2) sans union | false | 10 | Connected |
| 6 | path_compression | find apres chaine longue | arbre aplati | 20 | Compression |
| 7 | union_by_rank | unions multiples | arbres equilibres | 15 | Rank |
| 8 | count_sets | apres plusieurs unions | compte correct | 10 | Count |
| 9 | kruskal_basic | graphe simple | MST correct | 25 | Kruskal |
| 10 | kruskal_weight | graphe pondere | poids minimal | 20 | Kruskal |
| 11 | has_cycle_yes | graphe avec cycle | true | 15 | Cycle |
| 12 | has_cycle_no | arbre (sans cycle) | false | 10 | Cycle |
| 13 | components | graphe disjoint | compte correct | 15 | Components |
| 14 | stress_test | 100000 elements | performance OK | 10 | Stress |
| 15 | memory_check | valgrind | no leaks | 5 | Memory |

**Total : 200 points**

---

### 4.2 Tests unitaires

```c
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include "union_find.h"

void test_uf_create(void)
{
    union_find_t *uf = uf_create(5);
    assert(uf != NULL);
    assert(uf_count_sets(uf) == 5);

    for (int i = 0; i < 5; i++)
        assert(uf_find(uf, i) == i);

    uf_destroy(uf);
    printf("test_uf_create: PASSED\n");
}

void test_uf_union_find(void)
{
    union_find_t *uf = uf_create(5);

    // Union 0 et 1
    assert(uf_union(uf, 0, 1) == true);
    assert(uf_connected(uf, 0, 1) == true);
    assert(uf_count_sets(uf) == 4);

    // Union 2 et 3
    assert(uf_union(uf, 2, 3) == true);
    assert(uf_connected(uf, 2, 3) == true);
    assert(uf_count_sets(uf) == 3);

    // Deja connectes
    assert(uf_union(uf, 0, 1) == false);

    // Connecter les deux groupes
    assert(uf_union(uf, 1, 2) == true);
    assert(uf_connected(uf, 0, 3) == true);
    assert(uf_count_sets(uf) == 2);

    uf_destroy(uf);
    printf("test_uf_union_find: PASSED\n");
}

void test_path_compression(void)
{
    union_find_t *uf = uf_create(10);

    // Creer une chaine: 0 <- 1 <- 2 <- 3 <- 4
    for (int i = 0; i < 4; i++)
        uf_union(uf, i, i + 1);

    // find(4) devrait compresser le chemin
    int root = uf_find(uf, 4);

    // Apres compression, tous doivent pointer vers la racine
    for (int i = 0; i <= 4; i++)
        assert(uf_find(uf, i) == root);

    uf_destroy(uf);
    printf("test_path_compression: PASSED\n");
}

void test_kruskal(void)
{
    // Graphe:
    //   0 --1-- 1
    //   |       |
    //   4       2
    //   |       |
    //   3 --3-- 2
    //     \   /
    //      \ /
    //       5 (poids 6 et 5)

    edge_t edges[] = {
        {0, 1, 1},
        {0, 3, 4},
        {1, 2, 2},
        {2, 3, 3},
        {2, 3, 5},  // Arete supplementaire
        {0, 2, 6}   // Arete supplementaire
    };
    size_t num_edges = 6;
    size_t num_vertices = 4;

    size_t mst_size;
    int total_weight;
    edge_t *mst = kruskal_mst(edges, num_edges, num_vertices, &mst_size, &total_weight);

    assert(mst != NULL);
    assert(mst_size == 3);  // n-1 aretes
    assert(total_weight == 6);  // 1 + 2 + 3

    free(mst);
    printf("test_kruskal: PASSED\n");
}

void test_has_cycle(void)
{
    // Sans cycle (arbre)
    edge_t tree[] = {
        {0, 1, 1},
        {1, 2, 1},
        {2, 3, 1}
    };
    assert(has_cycle(tree, 3, 4) == false);

    // Avec cycle
    edge_t cycle[] = {
        {0, 1, 1},
        {1, 2, 1},
        {2, 0, 1}  // Cree un cycle
    };
    assert(has_cycle(cycle, 3, 3) == true);

    printf("test_has_cycle: PASSED\n");
}

void test_count_components(void)
{
    // Deux composantes: {0,1,2} et {3,4}
    edge_t edges[] = {
        {0, 1, 1},
        {1, 2, 1},
        {3, 4, 1}
    };

    assert(count_components(edges, 3, 5) == 2);

    printf("test_count_components: PASSED\n");
}

int main(void)
{
    test_uf_create();
    test_uf_union_find();
    test_path_compression();
    test_kruskal();
    test_has_cycle();
    test_count_components();

    printf("\nAll tests PASSED!\n");
    return 0;
}
```

---

### 4.3 Solution de reference

```c
// union_find.c - Implementation complete

#include "union_find.h"
#include <stdlib.h>
#include <string.h>

// ============================================
// Creation et destruction
// ============================================

union_find_t *uf_create(size_t n)
{
    if (n == 0)
        return NULL;

    union_find_t *uf = malloc(sizeof(union_find_t));
    if (uf == NULL)
        return NULL;

    uf->parent = malloc(n * sizeof(int));
    uf->rank = malloc(n * sizeof(int));

    if (uf->parent == NULL || uf->rank == NULL)
    {
        free(uf->parent);
        free(uf->rank);
        free(uf);
        return NULL;
    }

    // Initialiser: chaque element est sa propre racine
    for (size_t i = 0; i < n; i++)
    {
        uf->parent[i] = (int)i;
        uf->rank[i] = 0;
    }

    uf->size = n;
    uf->num_sets = n;

    return uf;
}

void uf_destroy(union_find_t *uf)
{
    if (uf == NULL)
        return;

    free(uf->parent);
    free(uf->rank);
    free(uf);
}

// ============================================
// Find avec Path Compression
// ============================================

int uf_find(union_find_t *uf, int x)
{
    if (uf == NULL || x < 0 || (size_t)x >= uf->size)
        return -1;

    // Path compression: remonter jusqu'a la racine
    // puis attacher tous les noeuds du chemin directement a la racine
    if (uf->parent[x] != x)
    {
        uf->parent[x] = uf_find(uf, uf->parent[x]);
    }

    return uf->parent[x];
}

int uf_find_no_compression(union_find_t *uf, int x)
{
    if (uf == NULL || x < 0 || (size_t)x >= uf->size)
        return -1;

    // Simple traversal sans modification
    while (uf->parent[x] != x)
    {
        x = uf->parent[x];
    }

    return x;
}

// ============================================
// Union by Rank
// ============================================

bool uf_union(union_find_t *uf, int x, int y)
{
    if (uf == NULL)
        return false;

    int root_x = uf_find(uf, x);
    int root_y = uf_find(uf, y);

    if (root_x == -1 || root_y == -1)
        return false;

    // Deja dans le meme ensemble
    if (root_x == root_y)
        return false;

    // Union by rank: attacher l'arbre moins profond sous le plus profond
    if (uf->rank[root_x] < uf->rank[root_y])
    {
        uf->parent[root_x] = root_y;
    }
    else if (uf->rank[root_x] > uf->rank[root_y])
    {
        uf->parent[root_y] = root_x;
    }
    else
    {
        // Rangs egaux: choisir arbitrairement et incrementer le rang
        uf->parent[root_y] = root_x;
        uf->rank[root_x]++;
    }

    uf->num_sets--;
    return true;
}

// ============================================
// Queries
// ============================================

bool uf_connected(union_find_t *uf, int x, int y)
{
    if (uf == NULL)
        return false;

    int root_x = uf_find(uf, x);
    int root_y = uf_find(uf, y);

    return (root_x != -1 && root_x == root_y);
}

size_t uf_count_sets(const union_find_t *uf)
{
    if (uf == NULL)
        return 0;
    return uf->num_sets;
}

size_t uf_set_size(union_find_t *uf, int x)
{
    if (uf == NULL)
        return 0;

    int root = uf_find(uf, x);
    if (root == -1)
        return 0;

    size_t count = 0;
    for (size_t i = 0; i < uf->size; i++)
    {
        if (uf_find(uf, (int)i) == root)
            count++;
    }

    return count;
}

void uf_reset(union_find_t *uf)
{
    if (uf == NULL)
        return;

    for (size_t i = 0; i < uf->size; i++)
    {
        uf->parent[i] = (int)i;
        uf->rank[i] = 0;
    }
    uf->num_sets = uf->size;
}

// ============================================
// Comparateur pour qsort (Kruskal)
// ============================================

static int compare_edges(const void *a, const void *b)
{
    const edge_t *ea = (const edge_t *)a;
    const edge_t *eb = (const edge_t *)b;
    return ea->weight - eb->weight;
}

// ============================================
// Kruskal's MST Algorithm
// ============================================

edge_t *kruskal_mst(edge_t *edges, size_t num_edges, size_t num_vertices,
                    size_t *mst_size, int *total_weight)
{
    if (edges == NULL || num_vertices == 0 || mst_size == NULL || total_weight == NULL)
        return NULL;

    *mst_size = 0;
    *total_weight = 0;

    // Creer une copie des aretes pour le tri
    edge_t *sorted_edges = malloc(num_edges * sizeof(edge_t));
    if (sorted_edges == NULL)
        return NULL;

    memcpy(sorted_edges, edges, num_edges * sizeof(edge_t));

    // Trier les aretes par poids croissant
    qsort(sorted_edges, num_edges, sizeof(edge_t), compare_edges);

    // Allouer le MST (au plus n-1 aretes)
    edge_t *mst = malloc((num_vertices - 1) * sizeof(edge_t));
    if (mst == NULL)
    {
        free(sorted_edges);
        return NULL;
    }

    // Creer Union-Find
    union_find_t *uf = uf_create(num_vertices);
    if (uf == NULL)
    {
        free(sorted_edges);
        free(mst);
        return NULL;
    }

    // Algorithme de Kruskal
    for (size_t i = 0; i < num_edges && *mst_size < num_vertices - 1; i++)
    {
        int src = sorted_edges[i].src;
        int dest = sorted_edges[i].dest;

        // Si ajouter cette arete ne cree pas de cycle
        if (!uf_connected(uf, src, dest))
        {
            mst[*mst_size] = sorted_edges[i];
            (*mst_size)++;
            *total_weight += sorted_edges[i].weight;
            uf_union(uf, src, dest);
        }
    }

    uf_destroy(uf);
    free(sorted_edges);

    return mst;
}

// ============================================
// Detection de cycle
// ============================================

bool has_cycle(edge_t *edges, size_t num_edges, size_t num_vertices)
{
    if (edges == NULL || num_vertices == 0)
        return false;

    union_find_t *uf = uf_create(num_vertices);
    if (uf == NULL)
        return false;

    bool cycle_found = false;

    for (size_t i = 0; i < num_edges && !cycle_found; i++)
    {
        int src = edges[i].src;
        int dest = edges[i].dest;

        // Si les deux sommets sont deja connectes, ajouter l'arete cree un cycle
        if (uf_connected(uf, src, dest))
        {
            cycle_found = true;
        }
        else
        {
            uf_union(uf, src, dest);
        }
    }

    uf_destroy(uf);
    return cycle_found;
}

// ============================================
// Comptage de composantes connexes
// ============================================

size_t count_components(edge_t *edges, size_t num_edges, size_t num_vertices)
{
    if (num_vertices == 0)
        return 0;

    union_find_t *uf = uf_create(num_vertices);
    if (uf == NULL)
        return 0;

    // Ajouter toutes les aretes
    for (size_t i = 0; i < num_edges; i++)
    {
        uf_union(uf, edges[i].src, edges[i].dest);
    }

    size_t components = uf_count_sets(uf);

    uf_destroy(uf);
    return components;
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (No Path Compression) : Find sans compression de chemin**

```c
// MUTANT A: Pas de path compression
int uf_find(union_find_t *uf, int x)
{
    if (uf == NULL || x < 0 || (size_t)x >= uf->size)
        return -1;

    // ERREUR: simple traversal sans compression
    while (uf->parent[x] != x)
    {
        x = uf->parent[x];
    }
    return x;
}
```
**Pourquoi faux :** Sans path compression, l'arbre peut devenir tres profond (hauteur O(n) dans le pire cas). La complexite devient O(n) par operation au lieu de O(alpha(n)).

---

**Mutant B (No Union by Rank) : Union sans consideration du rang**

```c
// MUTANT B: Union naive sans rank
bool uf_union(union_find_t *uf, int x, int y)
{
    int root_x = uf_find(uf, x);
    int root_y = uf_find(uf, y);

    if (root_x == root_y)
        return false;

    // ERREUR: toujours attacher x sous y, sans considerer le rang
    uf->parent[root_x] = root_y;

    uf->num_sets--;
    return true;
}
```
**Pourquoi faux :** Sans union by rank, l'arbre peut devenir une chaine lineaire de hauteur O(n), degradant la performance a O(n) par find.

---

**Mutant C (Wrong Rank Update) : Mise a jour incorrecte du rang**

```c
// MUTANT C: Toujours incrementer le rang
bool uf_union(union_find_t *uf, int x, int y)
{
    int root_x = uf_find(uf, x);
    int root_y = uf_find(uf, y);

    if (root_x == root_y)
        return false;

    if (uf->rank[root_x] < uf->rank[root_y])
    {
        uf->parent[root_x] = root_y;
        uf->rank[root_y]++;  // ERREUR: ne pas incrementer si rang different
    }
    else
    {
        uf->parent[root_y] = root_x;
        uf->rank[root_x]++;  // ERREUR: incrementer meme si rang different
    }

    uf->num_sets--;
    return true;
}
```
**Pourquoi faux :** Le rang ne doit etre incremente que lorsque deux arbres de meme rang sont fusionnes. Sinon, le rang perd sa signification de borne superieure de hauteur.

---

**Mutant D (Kruskal Without Sort) : Kruskal sans trier les aretes**

```c
// MUTANT D: Kruskal sans tri
edge_t *kruskal_mst(edge_t *edges, size_t num_edges, size_t num_vertices,
                    size_t *mst_size, int *total_weight)
{
    *mst_size = 0;
    *total_weight = 0;

    edge_t *mst = malloc((num_vertices - 1) * sizeof(edge_t));
    union_find_t *uf = uf_create(num_vertices);

    // ERREUR: pas de tri des aretes par poids
    for (size_t i = 0; i < num_edges && *mst_size < num_vertices - 1; i++)
    {
        if (!uf_connected(uf, edges[i].src, edges[i].dest))
        {
            mst[*mst_size] = edges[i];
            (*mst_size)++;
            *total_weight += edges[i].weight;
            uf_union(uf, edges[i].src, edges[i].dest);
        }
    }

    uf_destroy(uf);
    return mst;
}
```
**Pourquoi faux :** Sans trier les aretes par poids croissant, Kruskal ne produit pas l'arbre couvrant minimal. L'ordre des aretes determine le resultat, qui sera incorrect.

---

**Mutant E (Cycle Detection Off-by-One) : Detection de cycle avec erreur logique**

```c
// MUTANT E: Verifie apres union au lieu d'avant
bool has_cycle(edge_t *edges, size_t num_edges, size_t num_vertices)
{
    union_find_t *uf = uf_create(num_vertices);
    bool cycle_found = false;

    for (size_t i = 0; i < num_edges; i++)
    {
        // ERREUR: union d'abord, puis verification
        uf_union(uf, edges[i].src, edges[i].dest);

        // Cette verification est maintenant inutile
        if (uf_connected(uf, edges[i].src, edges[i].dest))
        {
            cycle_found = true;
        }
    }

    uf_destroy(uf);
    return cycle_found;
}
```
**Pourquoi faux :** Apres uf_union, les deux sommets sont toujours connectes. La verification doit etre faite AVANT l'union pour detecter si l'arete cree un cycle.

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

La structure **Union-Find** illustre plusieurs concepts fondamentaux :

1. **Complexite amortie** - O(alpha(n)) grace aux optimisations
2. **Trade-offs espace/temps** - Path compression echange des writes contre des reads rapides
3. **Arbres implicites** - Representer un arbre avec un simple tableau de parents
4. **Optimisations combinables** - Union by rank + path compression se renforcent

### 5.2 La fonction alpha inverse d'Ackermann

```
alpha(n) est la fonction inverse d'Ackermann
- alpha(n) <= 4 pour tout n <= 10^80 (nombre d'atomes dans l'univers)
- Pratiquement constante pour toute application reelle
- La croissance d'Ackermann est astronomiquement rapide:
  A(4,2) a deja plus de 10^19728 chiffres
```

### 5.3 Visualisation ASCII

```
PATH COMPRESSION - APLATISSEMENT DE L'ARBRE:
=============================================

Etat initial (apres unions sans compression):

    union(0,1), union(1,2), union(2,3), union(3,4)

    Arbre non compresse:

        0                parent: [0, 0, 1, 2, 3]
        |
        1                Profondeur: 4
        |
        2
        |
        3
        |
        4

    Appel: find(4)

    Chemin parcouru: 4 -> 3 -> 2 -> 1 -> 0 (racine trouvee)

    APPLICATION DE LA PATH COMPRESSION:

    Pendant la remontee recursive, chaque noeud est
    rattache directement a la racine:

    Etape 1: find(4) appelle find(3)
    Etape 2: find(3) appelle find(2)
    Etape 3: find(2) appelle find(1)
    Etape 4: find(1) appelle find(0) -> retourne 0
    Etape 5: parent[1] = 0 (deja le cas)
    Etape 6: parent[2] = 0 (compression!)
    Etape 7: parent[3] = 0 (compression!)
    Etape 8: parent[4] = 0 (compression!)

    Arbre APRES compression:

        0                parent: [0, 0, 0, 0, 0]
       /|\\
      1 2 3 4            Profondeur: 1

    Prochain find(4): O(1) directement!


UNION BY RANK - EQUILIBRAGE DES ARBRES:
=======================================

Sans union by rank:

    union(0,1), union(2,3), union(0,2)

    Si on attache toujours le premier sous le second:

        3           Profondeur maximale: 3
        |
        2
        |
        0
        |
        1

Avec union by rank:

    Initial: rank = [0, 0, 0, 0]

    union(0,1): rangs egaux, 1 sous 0, rank[0]++

        0 (rank=1)      parent: [0, 0, 2, 3]
        |               rank:   [1, 0, 0, 0]
        1

    union(2,3): rangs egaux, 3 sous 2, rank[2]++

        2 (rank=1)      parent: [0, 0, 2, 2]
        |               rank:   [1, 0, 1, 0]
        3

    union(0,2): rangs egaux, 2 sous 0, rank[0]++

          0 (rank=2)    parent: [0, 0, 0, 2]
         / \            rank:   [2, 0, 1, 0]
        1   2
            |
            3

    Profondeur maximale: 2 (au lieu de 3)


KRUSKAL'S MST AVEC UNION-FIND:
==============================

Graphe:
           1
    0 -------- 1
    |  \       |
  4 |   \ 3    | 2
    |    \     |
    3 -------- 2
          5

Aretes triees par poids:
    (0,1,1), (1,2,2), (0,2,3), (0,3,4), (2,3,5)

Execution:

1. Arete (0,1,1): find(0)=0, find(1)=1
   Pas connectes -> AJOUTER au MST
   union(0,1)
   MST: {(0,1,1)}

2. Arete (1,2,2): find(1)=0, find(2)=2
   Pas connectes -> AJOUTER au MST
   union(0,2)
   MST: {(0,1,1), (1,2,2)}

3. Arete (0,2,3): find(0)=0, find(2)=0
   DEJA CONNECTES -> IGNORER (creerait un cycle)

4. Arete (0,3,4): find(0)=0, find(3)=3
   Pas connectes -> AJOUTER au MST
   union(0,3)
   MST: {(0,1,1), (1,2,2), (0,3,4)}

   MST complet (3 aretes pour 4 sommets)!

5. Arete (2,3,5): IGNOREE (MST complet)

Resultat:
           1
    0 -------- 1
    |          |
  4 |          | 2
    |          |
    3          2

Poids total: 1 + 2 + 4 = 7


DETECTION DE CYCLE:
===================

Graphe avec cycle:
    0 --- 1
    |     |
    +--2--+

Aretes: (0,1), (1,2), (0,2)

Execution:
1. Arete (0,1): find(0)=0, find(1)=1
   Pas connectes -> union(0,1)

2. Arete (1,2): find(1)=0, find(2)=2
   Pas connectes -> union(0,2)

3. Arete (0,2): find(0)=0, find(2)=0
   DEJA CONNECTES!
   -> L'arete (0,2) formerait un CYCLE

Resultat: CYCLE DETECTE
```

### 5.4 Comparaison des Complexites

```
+-------------------+------------------+------------------+------------------+
| Operation         | Naive            | Union by Rank    | Rank + Path Comp |
+-------------------+------------------+------------------+------------------+
| find              | O(n)             | O(log n)         | O(alpha(n))      |
| union             | O(n)             | O(log n)         | O(alpha(n))      |
| m operations      | O(m * n)         | O(m * log n)     | O(m * alpha(n))  |
+-------------------+------------------+------------------+------------------+

Ou alpha(n) < 5 pour tout n pratique
```

---

## SECTION 7 : QCM

### Question 1 (3 points)

Quelle est la complexite amortie de l'operation find dans un Union-Find avec path compression ET union by rank ?

- A) O(1)
- B) O(log n)
- C) O(log* n)
- D) O(alpha(n))
- E) O(n)

**Reponse correcte : D**

**Explication :** Avec les deux optimisations combinees, la complexite amortie est O(alpha(n)), ou alpha est la fonction inverse d'Ackermann. Cette fonction croit si lentement qu'elle est inferieure a 5 pour toute valeur pratique de n (meme pour n = nombre d'atomes dans l'univers). C'est effectivement presque constant, mais theoriquement different de O(1).

---

### Question 2 (3 points)

Dans l'algorithme de Kruskal utilisant Union-Find, pourquoi verifie-t-on si deux sommets sont deja connectes avant d'ajouter une arete au MST ?

- A) Pour optimiser la performance
- B) Pour eviter les aretes dupliquees
- C) Pour detecter et eviter la creation de cycles
- D) Pour maintenir l'ordre des aretes
- E) Pour calculer le poids total

**Reponse correcte : C**

**Explication :** Si deux sommets sont deja dans le meme ensemble (connectes), ajouter une arete entre eux creerait un cycle dans l'arbre couvrant. Un arbre par definition ne contient pas de cycle, donc Kruskal doit ignorer ces aretes. La verification uf_connected(src, dest) detecte exactement cette situation.

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.29",
  "name": "union_find",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "difficulty": 6,
  "xp_base": 200,
  "estimated_time_minutes": 150,
  "complexity": {
    "time": "O(alpha(n)) amortized",
    "space": "O(n)"
  },
  "files": {
    "required": ["union_find.c", "union_find.h"],
    "provided": ["main.c", "Makefile"],
    "tests": ["test_union_find.c"]
  },
  "compilation": {
    "command": "gcc -Wall -Wextra -Werror -std=c17 -o union_find union_find.c main.c",
    "flags": ["-Wall", "-Wextra", "-Werror", "-std=c17"]
  },
  "tests": {
    "unit_tests": "test_union_find.c",
    "moulinette": {
      "timeout_seconds": 10,
      "memory_check": true,
      "valgrind_flags": ["--leak-check=full", "--error-exitcode=1"]
    }
  },
  "topics": [
    "union_find",
    "disjoint_set_union",
    "dsu",
    "path_compression",
    "union_by_rank",
    "kruskal",
    "mst",
    "connected_components",
    "cycle_detection",
    "graph_algorithms"
  ],
  "prerequisites": [
    "D.09",
    "D.16",
    "0.6.3"
  ],
  "learning_objectives": [
    "Comprendre la structure Union-Find et ses applications",
    "Implementer path compression et union by rank",
    "Appliquer Union-Find pour detecter des cycles",
    "Implementer l'algorithme de Kruskal pour le MST",
    "Analyser la complexite amortie avec la fonction inverse d'Ackermann"
  ],
  "grading": {
    "auto_grade": true,
    "total_points": 200,
    "categories": {
      "basic_operations": 50,
      "path_compression": 30,
      "union_by_rank": 25,
      "kruskal_mst": 45,
      "cycle_detection": 25,
      "memory_management": 25
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
