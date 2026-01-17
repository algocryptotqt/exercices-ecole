# Exercice D.26 : avl_tree

**Module :**
D -- Algorithmique

**Concept :**
26 -- AVL Tree (Arbre binaire de recherche auto-equilibre)

**Difficulte :**
7/10

**Type :**
code

**Tiers :**
3 -- Maitrise avancee

**Langage :**
C17

**Prerequis :**
- Arbres binaires de recherche (BST)
- Recursivite
- Pointeurs et allocation dynamique
- Complexite algorithmique O(log n)

**Domaines :**
Algo, DataStruct

**Duree estimee :**
150 min

**XP Base :**
225

**Complexite :**
T[N] O(log n) x S[N] O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| C | `avl_tree.c`, `avl_tree.h` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| C | malloc, free, memcpy |

---

### 1.2 Consigne

#### Section Culture : "L'Arbre AVL - L'Equilibre Parfait"

L'arbre **AVL** (nomme d'apres ses inventeurs Adelson-Velsky et Landis, 1962) est le premier arbre binaire de recherche auto-equilibre. Sa propriete fondamentale : pour tout noeud, la difference de hauteur entre ses sous-arbres gauche et droit (facteur d'equilibre) est au plus 1.

Cette propriete garantit une hauteur maximale de 1.44 * log2(n), assurant des operations en O(log n) meme dans le pire cas, contrairement aux BST classiques qui peuvent degenerer en liste chainee O(n).

Les arbres AVL sont utilises dans :
- Bases de donnees (index)
- Systemes de fichiers
- Compilateurs (tables de symboles)
- Implementations de std::set et std::map (variante Red-Black)

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une structure d'arbre AVL complete avec les rotations necessaires au reequilibrage apres insertion et suppression.

**Propriete AVL :**

```
Pour tout noeud N:
  |hauteur(N.gauche) - hauteur(N.droite)| <= 1

Facteur d'equilibre (Balance Factor):
  BF(N) = hauteur(N.gauche) - hauteur(N.droite)

Valeurs valides: -1, 0, +1
Si BF < -1 ou BF > +1 : reequilibrage necessaire
```

**Prototypes :**

```c
// avl_tree.h

#ifndef AVL_TREE_H
#define AVL_TREE_H

#include <stddef.h>
#include <stdbool.h>

/**
 * Structure d'un noeud AVL
 * Stocke la hauteur pour calcul efficace du facteur d'equilibre
 */
typedef struct s_avl_node {
    int                 value;      // Valeur stockee
    int                 height;     // Hauteur du sous-arbre
    struct s_avl_node   *left;      // Enfant gauche
    struct s_avl_node   *right;     // Enfant droit
} avl_node_t;

/**
 * Structure de l'arbre AVL
 */
typedef struct {
    avl_node_t  *root;      // Racine de l'arbre
    size_t      size;       // Nombre de noeuds
} avl_tree_t;

// ============================================
// Creation et destruction
// ============================================

/**
 * Cree un nouvel arbre AVL vide
 * @return: pointeur vers l'arbre, NULL si erreur
 */
avl_tree_t *avl_create(void);

/**
 * Libere toute la memoire de l'arbre
 * @param tree: l'arbre a detruire
 */
void avl_destroy(avl_tree_t *tree);

// ============================================
// Operations de base
// ============================================

/**
 * Insere une valeur dans l'arbre AVL
 * Reequilibre automatiquement si necessaire
 *
 * @param tree: l'arbre AVL
 * @param value: valeur a inserer
 * @return: true si insertion reussie, false si doublon ou erreur
 *
 * Complexity: O(log n)
 */
bool avl_insert(avl_tree_t *tree, int value);

/**
 * Supprime une valeur de l'arbre AVL
 * Reequilibre automatiquement si necessaire
 *
 * @param tree: l'arbre AVL
 * @param value: valeur a supprimer
 * @return: true si suppression reussie, false si non trouve
 *
 * Complexity: O(log n)
 */
bool avl_delete(avl_tree_t *tree, int value);

/**
 * Recherche une valeur dans l'arbre
 *
 * @param tree: l'arbre AVL
 * @param value: valeur a rechercher
 * @return: true si trouve, false sinon
 *
 * Complexity: O(log n)
 */
bool avl_search(const avl_tree_t *tree, int value);

/**
 * Retourne la valeur minimale de l'arbre
 *
 * @param tree: l'arbre AVL
 * @param result: pointeur pour stocker le resultat
 * @return: true si arbre non vide, false sinon
 *
 * Complexity: O(log n)
 */
bool avl_min(const avl_tree_t *tree, int *result);

/**
 * Retourne la valeur maximale de l'arbre
 *
 * @param tree: l'arbre AVL
 * @param result: pointeur pour stocker le resultat
 * @return: true si arbre non vide, false sinon
 *
 * Complexity: O(log n)
 */
bool avl_max(const avl_tree_t *tree, int *result);

// ============================================
// Fonctions utilitaires
// ============================================

/**
 * Retourne la hauteur d'un noeud
 * @param node: le noeud (peut etre NULL)
 * @return: hauteur (-1 si NULL)
 */
int avl_node_height(const avl_node_t *node);

/**
 * Calcule le facteur d'equilibre d'un noeud
 * @param node: le noeud
 * @return: BF = hauteur(gauche) - hauteur(droite)
 */
int avl_balance_factor(const avl_node_t *node);

/**
 * Verifie si l'arbre respecte la propriete AVL
 * @param tree: l'arbre a verifier
 * @return: true si arbre AVL valide
 */
bool avl_is_valid(const avl_tree_t *tree);

/**
 * Retourne le nombre de noeuds
 * @param tree: l'arbre
 * @return: nombre de noeuds
 */
size_t avl_size(const avl_tree_t *tree);

/**
 * Retourne la hauteur de l'arbre
 * @param tree: l'arbre
 * @return: hauteur (-1 si vide)
 */
int avl_height(const avl_tree_t *tree);

// ============================================
// Rotations (exposees pour tests)
// ============================================

/**
 * Rotation simple a droite
 * @param y: noeud desequilibre
 * @return: nouvelle racine du sous-arbre
 */
avl_node_t *avl_rotate_right(avl_node_t *y);

/**
 * Rotation simple a gauche
 * @param x: noeud desequilibre
 * @return: nouvelle racine du sous-arbre
 */
avl_node_t *avl_rotate_left(avl_node_t *x);

// ============================================
// Parcours (pour debug/tests)
// ============================================

/**
 * Parcours inorder - produit les valeurs triees
 * @param tree: l'arbre
 * @param result: tableau pour stocker les valeurs
 * @param max_size: taille maximale du tableau
 * @return: nombre d'elements stockes
 */
int avl_inorder(const avl_tree_t *tree, int *result, int max_size);

#endif
```

**Comportements attendus :**

| Operation | Exemple | Resultat | Complexite |
|-----------|---------|----------|------------|
| avl_create() | - | Arbre vide | O(1) |
| avl_insert(t, 10) | [] | [10], size=1 | O(log n) |
| avl_insert(t, 20) | [10] | [10,20], equilibre | O(log n) |
| avl_insert(t, 30) | [10,20] | rotation gauche | O(log n) |
| avl_delete(t, 10) | [10,20,30] | [20,30], reequilibre | O(log n) |
| avl_search(t, 20) | [10,20,30] | true | O(log n) |

**Cas de rotation :**

```
CAS 1: Left-Left (LL) -> Rotation droite
    z                y
   /                / \
  y       =>       x   z
 /
x

CAS 2: Right-Right (RR) -> Rotation gauche
  z                  y
   \                / \
    y       =>     z   x
     \
      x

CAS 3: Left-Right (LR) -> Rotation gauche puis droite
    z               z               x
   /               /               / \
  y       =>      x       =>      y   z
   \             /
    x           y

CAS 4: Right-Left (RL) -> Rotation droite puis gauche
  z               z                 x
   \               \               / \
    y       =>      x       =>    z   y
   /                 \
  x                   y
```

---

### 1.3 Prototype

```c
// avl_tree.h - Interface complete

#ifndef AVL_TREE_H
#define AVL_TREE_H

#include <stddef.h>
#include <stdbool.h>

typedef struct s_avl_node {
    int                 value;
    int                 height;
    struct s_avl_node   *left;
    struct s_avl_node   *right;
} avl_node_t;

typedef struct {
    avl_node_t  *root;
    size_t      size;
} avl_tree_t;

// Creation et destruction
avl_tree_t  *avl_create(void);
void        avl_destroy(avl_tree_t *tree);

// Operations principales
bool        avl_insert(avl_tree_t *tree, int value);
bool        avl_delete(avl_tree_t *tree, int value);
bool        avl_search(const avl_tree_t *tree, int value);
bool        avl_min(const avl_tree_t *tree, int *result);
bool        avl_max(const avl_tree_t *tree, int *result);

// Utilitaires
int         avl_node_height(const avl_node_t *node);
int         avl_balance_factor(const avl_node_t *node);
bool        avl_is_valid(const avl_tree_t *tree);
size_t      avl_size(const avl_tree_t *tree);
int         avl_height(const avl_tree_t *tree);

// Rotations
avl_node_t  *avl_rotate_right(avl_node_t *y);
avl_node_t  *avl_rotate_left(avl_node_t *x);

// Parcours
int         avl_inorder(const avl_tree_t *tree, int *result, int max_size);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**AVL vs Red-Black Trees**

Les arbres AVL sont plus strictement equilibres que les Red-Black trees : hauteur maximale 1.44*log(n) vs 2*log(n). Les AVL sont donc plus rapides pour les recherches, mais les Red-Black sont plus rapides pour les insertions/suppressions frequentes (moins de rotations).

**La premiere structure auto-equilibree**

L'arbre AVL (1962) est la toute premiere structure de donnees auto-equilibree inventee. Il a inspire de nombreuses autres structures : Red-Black trees, B-trees, Splay trees, etc.

**Nombre de rotations**

Une insertion necessite au plus 2 rotations (une double rotation), tandis qu'une suppression peut necessiter O(log n) rotations dans le pire cas.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Database Developer** | Index de base de donnees pour requetes rapides |
| **Compiler Engineer** | Tables de symboles pour resolution de noms |
| **OS Developer** | Gestion de la memoire virtuelle (page tables) |
| **Game Developer** | Spatial indexing, collision detection |
| **Financial Systems** | Order books pour trading haute frequence |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Wextra -Werror -std=c17 avl_tree.c main.c -o avl_demo
$ ./avl_demo

# Test insertions avec reequilibrage
Creating AVL tree...
Inserting: 10, 20, 30 (triggers Left rotation)
Tree after insertions:
    20
   /  \
  10  30
Height: 1, Size: 3, Valid AVL: true

Inserting: 5, 4 (triggers Right rotation at node 10)
Tree after insertions:
      20
     /  \
    5   30
   / \
  4  10
Height: 2, Size: 5, Valid AVL: true

Inserting: 6 (triggers Left-Right rotation)
Tree after insertion:
      20
     /  \
    6   30
   / \
  5  10
 /
4
Height: 3, Size: 6, Valid AVL: true

# Test recherche
Search 10: found
Search 15: not found

# Test suppression
Deleting 20...
Tree after deletion:
      10
     /  \
    6   30
   /
  5
 /
4
Height: 3, Size: 5, Valid AVL: true

# Parcours inorder (valeurs triees)
Inorder: [4, 5, 6, 10, 30]
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette - Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | create_empty | avl_create() | tree non NULL, size=0 | 5 | Create |
| 2 | insert_single | insert(t, 42) | size=1, root->value=42 | 10 | Insert |
| 3 | insert_ll_rotation | insert 30,20,10 | rotation droite, root=20 | 20 | Rotation |
| 4 | insert_rr_rotation | insert 10,20,30 | rotation gauche, root=20 | 20 | Rotation |
| 5 | insert_lr_rotation | insert 30,10,20 | double rotation, root=20 | 20 | Rotation |
| 6 | insert_rl_rotation | insert 10,30,20 | double rotation, root=20 | 20 | Rotation |
| 7 | insert_no_duplicate | insert 10,10 | size=1, return false | 10 | Insert |
| 8 | delete_leaf | delete leaf node | removed, valid AVL | 15 | Delete |
| 9 | delete_one_child | delete node with 1 child | relinked, valid AVL | 15 | Delete |
| 10 | delete_two_children | delete node with 2 children | successor replaces, valid | 20 | Delete |
| 11 | delete_rebalance | delete causing imbalance | rotations applied | 20 | Delete |
| 12 | search_exists | search existing value | true | 5 | Search |
| 13 | search_not_exists | search non-existing | false | 5 | Search |
| 14 | min_max | get min and max | correct values | 10 | Query |
| 15 | is_valid_check | avl_is_valid on valid tree | true | 5 | Valid |
| 16 | large_dataset | 1000 insertions | height <= 1.44*log(n) | 15 | Stress |
| 17 | memory_check | valgrind | no leaks | 10 | Memory |

**Total : 225 points**

---

### 4.2 Tests unitaires

```c
#include <stdio.h>
#include <assert.h>
#include <math.h>
#include "avl_tree.h"

void test_avl_create(void)
{
    avl_tree_t *tree = avl_create();
    assert(tree != NULL);
    assert(tree->root == NULL);
    assert(avl_size(tree) == 0);
    assert(avl_height(tree) == -1);
    avl_destroy(tree);
    printf("test_avl_create: PASSED\n");
}

void test_avl_insert_single(void)
{
    avl_tree_t *tree = avl_create();
    assert(avl_insert(tree, 42) == true);
    assert(avl_size(tree) == 1);
    assert(tree->root->value == 42);
    assert(tree->root->height == 0);
    avl_destroy(tree);
    printf("test_avl_insert_single: PASSED\n");
}

void test_avl_rr_rotation(void)
{
    // Right-Right case: 10, 20, 30 -> rotation gauche
    avl_tree_t *tree = avl_create();
    avl_insert(tree, 10);
    avl_insert(tree, 20);
    avl_insert(tree, 30);

    // Apres rotation, 20 doit etre la racine
    assert(tree->root->value == 20);
    assert(tree->root->left->value == 10);
    assert(tree->root->right->value == 30);
    assert(avl_is_valid(tree) == true);

    avl_destroy(tree);
    printf("test_avl_rr_rotation: PASSED\n");
}

void test_avl_ll_rotation(void)
{
    // Left-Left case: 30, 20, 10 -> rotation droite
    avl_tree_t *tree = avl_create();
    avl_insert(tree, 30);
    avl_insert(tree, 20);
    avl_insert(tree, 10);

    assert(tree->root->value == 20);
    assert(tree->root->left->value == 10);
    assert(tree->root->right->value == 30);
    assert(avl_is_valid(tree) == true);

    avl_destroy(tree);
    printf("test_avl_ll_rotation: PASSED\n");
}

void test_avl_lr_rotation(void)
{
    // Left-Right case: 30, 10, 20 -> double rotation
    avl_tree_t *tree = avl_create();
    avl_insert(tree, 30);
    avl_insert(tree, 10);
    avl_insert(tree, 20);

    assert(tree->root->value == 20);
    assert(tree->root->left->value == 10);
    assert(tree->root->right->value == 30);
    assert(avl_is_valid(tree) == true);

    avl_destroy(tree);
    printf("test_avl_lr_rotation: PASSED\n");
}

void test_avl_rl_rotation(void)
{
    // Right-Left case: 10, 30, 20 -> double rotation
    avl_tree_t *tree = avl_create();
    avl_insert(tree, 10);
    avl_insert(tree, 30);
    avl_insert(tree, 20);

    assert(tree->root->value == 20);
    assert(tree->root->left->value == 10);
    assert(tree->root->right->value == 30);
    assert(avl_is_valid(tree) == true);

    avl_destroy(tree);
    printf("test_avl_rl_rotation: PASSED\n");
}

void test_avl_no_duplicate(void)
{
    avl_tree_t *tree = avl_create();
    assert(avl_insert(tree, 10) == true);
    assert(avl_insert(tree, 10) == false);
    assert(avl_size(tree) == 1);
    avl_destroy(tree);
    printf("test_avl_no_duplicate: PASSED\n");
}

void test_avl_delete_leaf(void)
{
    avl_tree_t *tree = avl_create();
    avl_insert(tree, 20);
    avl_insert(tree, 10);
    avl_insert(tree, 30);

    assert(avl_delete(tree, 10) == true);
    assert(avl_size(tree) == 2);
    assert(avl_search(tree, 10) == false);
    assert(avl_is_valid(tree) == true);

    avl_destroy(tree);
    printf("test_avl_delete_leaf: PASSED\n");
}

void test_avl_delete_with_rebalance(void)
{
    avl_tree_t *tree = avl_create();
    // Creer un arbre qui necessitere reequilibrage apres suppression
    avl_insert(tree, 50);
    avl_insert(tree, 25);
    avl_insert(tree, 75);
    avl_insert(tree, 10);
    avl_insert(tree, 30);
    avl_insert(tree, 60);
    avl_insert(tree, 80);
    avl_insert(tree, 5);
    avl_insert(tree, 15);

    // Supprimer 80, devrait declencher un reequilibrage
    avl_delete(tree, 80);
    avl_delete(tree, 75);

    assert(avl_is_valid(tree) == true);

    avl_destroy(tree);
    printf("test_avl_delete_with_rebalance: PASSED\n");
}

void test_avl_search(void)
{
    avl_tree_t *tree = avl_create();
    avl_insert(tree, 20);
    avl_insert(tree, 10);
    avl_insert(tree, 30);
    avl_insert(tree, 5);
    avl_insert(tree, 15);

    assert(avl_search(tree, 15) == true);
    assert(avl_search(tree, 5) == true);
    assert(avl_search(tree, 25) == false);
    assert(avl_search(tree, 0) == false);

    avl_destroy(tree);
    printf("test_avl_search: PASSED\n");
}

void test_avl_min_max(void)
{
    avl_tree_t *tree = avl_create();
    avl_insert(tree, 20);
    avl_insert(tree, 10);
    avl_insert(tree, 30);
    avl_insert(tree, 5);
    avl_insert(tree, 25);

    int min_val, max_val;
    assert(avl_min(tree, &min_val) == true);
    assert(min_val == 5);
    assert(avl_max(tree, &max_val) == true);
    assert(max_val == 30);

    avl_destroy(tree);
    printf("test_avl_min_max: PASSED\n");
}

void test_avl_height_property(void)
{
    avl_tree_t *tree = avl_create();

    // Inserer 1000 elements
    for (int i = 0; i < 1000; i++)
        avl_insert(tree, i);

    // Verifier que la hauteur respecte la propriete AVL
    // Hauteur maximale AVL: 1.44 * log2(n)
    int h = avl_height(tree);
    double max_height = 1.45 * log2(1000);

    assert(h <= (int)max_height);
    assert(avl_is_valid(tree) == true);

    avl_destroy(tree);
    printf("test_avl_height_property: PASSED\n");
}

int main(void)
{
    test_avl_create();
    test_avl_insert_single();
    test_avl_rr_rotation();
    test_avl_ll_rotation();
    test_avl_lr_rotation();
    test_avl_rl_rotation();
    test_avl_no_duplicate();
    test_avl_delete_leaf();
    test_avl_delete_with_rebalance();
    test_avl_search();
    test_avl_min_max();
    test_avl_height_property();

    printf("\nAll tests PASSED!\n");
    return 0;
}
```

---

### 4.3 Solution de reference

```c
// avl_tree.c - Implementation complete

#include "avl_tree.h"
#include <stdlib.h>
#include <string.h>

// ============================================
// Fonctions utilitaires internes
// ============================================

static int max(int a, int b)
{
    return (a > b) ? a : b;
}

int avl_node_height(const avl_node_t *node)
{
    if (node == NULL)
        return -1;
    return node->height;
}

int avl_balance_factor(const avl_node_t *node)
{
    if (node == NULL)
        return 0;
    return avl_node_height(node->left) - avl_node_height(node->right);
}

static void update_height(avl_node_t *node)
{
    if (node != NULL)
        node->height = 1 + max(avl_node_height(node->left),
                               avl_node_height(node->right));
}

static avl_node_t *create_node(int value)
{
    avl_node_t *node = malloc(sizeof(avl_node_t));
    if (node == NULL)
        return NULL;

    node->value = value;
    node->height = 0;
    node->left = NULL;
    node->right = NULL;

    return node;
}

// ============================================
// Rotations
// ============================================

/**
 * Rotation droite (Right Rotation)
 *
 *       y                x
 *      / \              / \
 *     x   T3    =>     T1  y
 *    / \                  / \
 *   T1  T2               T2  T3
 */
avl_node_t *avl_rotate_right(avl_node_t *y)
{
    avl_node_t *x = y->left;
    avl_node_t *T2 = x->right;

    // Effectuer la rotation
    x->right = y;
    y->left = T2;

    // Mettre a jour les hauteurs
    update_height(y);
    update_height(x);

    return x;  // Nouvelle racine
}

/**
 * Rotation gauche (Left Rotation)
 *
 *     x                  y
 *    / \                / \
 *   T1  y      =>      x   T3
 *      / \            / \
 *     T2  T3         T1  T2
 */
avl_node_t *avl_rotate_left(avl_node_t *x)
{
    avl_node_t *y = x->right;
    avl_node_t *T2 = y->left;

    // Effectuer la rotation
    y->left = x;
    x->right = T2;

    // Mettre a jour les hauteurs
    update_height(x);
    update_height(y);

    return y;  // Nouvelle racine
}

// ============================================
// Reequilibrage
// ============================================

static avl_node_t *rebalance(avl_node_t *node)
{
    if (node == NULL)
        return NULL;

    update_height(node);
    int balance = avl_balance_factor(node);

    // Cas Left-Left: BF > 1 et insertion dans sous-arbre gauche de gauche
    if (balance > 1 && avl_balance_factor(node->left) >= 0)
        return avl_rotate_right(node);

    // Cas Right-Right: BF < -1 et insertion dans sous-arbre droit de droit
    if (balance < -1 && avl_balance_factor(node->right) <= 0)
        return avl_rotate_left(node);

    // Cas Left-Right: BF > 1 et insertion dans sous-arbre droit de gauche
    if (balance > 1 && avl_balance_factor(node->left) < 0)
    {
        node->left = avl_rotate_left(node->left);
        return avl_rotate_right(node);
    }

    // Cas Right-Left: BF < -1 et insertion dans sous-arbre gauche de droit
    if (balance < -1 && avl_balance_factor(node->right) > 0)
    {
        node->right = avl_rotate_right(node->right);
        return avl_rotate_left(node);
    }

    return node;  // Pas de reequilibrage necessaire
}

// ============================================
// Creation et destruction
// ============================================

avl_tree_t *avl_create(void)
{
    avl_tree_t *tree = malloc(sizeof(avl_tree_t));
    if (tree == NULL)
        return NULL;

    tree->root = NULL;
    tree->size = 0;

    return tree;
}

static void destroy_node(avl_node_t *node)
{
    if (node == NULL)
        return;

    destroy_node(node->left);
    destroy_node(node->right);
    free(node);
}

void avl_destroy(avl_tree_t *tree)
{
    if (tree == NULL)
        return;

    destroy_node(tree->root);
    free(tree);
}

// ============================================
// Insertion
// ============================================

static avl_node_t *insert_node(avl_node_t *node, int value, bool *inserted)
{
    // Cas de base: inserer le nouveau noeud
    if (node == NULL)
    {
        avl_node_t *new_node = create_node(value);
        if (new_node != NULL)
            *inserted = true;
        return new_node;
    }

    // Insertion BST standard
    if (value < node->value)
        node->left = insert_node(node->left, value, inserted);
    else if (value > node->value)
        node->right = insert_node(node->right, value, inserted);
    else
    {
        // Doublon: pas d'insertion
        *inserted = false;
        return node;
    }

    // Reequilibrer le noeud si necessaire
    return rebalance(node);
}

bool avl_insert(avl_tree_t *tree, int value)
{
    if (tree == NULL)
        return false;

    bool inserted = false;
    tree->root = insert_node(tree->root, value, &inserted);

    if (inserted)
        tree->size++;

    return inserted;
}

// ============================================
// Suppression
// ============================================

static avl_node_t *find_min_node(avl_node_t *node)
{
    avl_node_t *current = node;
    while (current->left != NULL)
        current = current->left;
    return current;
}

static avl_node_t *delete_node(avl_node_t *node, int value, bool *deleted)
{
    if (node == NULL)
    {
        *deleted = false;
        return NULL;
    }

    // Recherche BST standard
    if (value < node->value)
        node->left = delete_node(node->left, value, deleted);
    else if (value > node->value)
        node->right = delete_node(node->right, value, deleted);
    else
    {
        // Noeud trouve
        *deleted = true;

        // Cas 1: Pas d'enfant ou un seul enfant
        if (node->left == NULL || node->right == NULL)
        {
            avl_node_t *temp = node->left ? node->left : node->right;

            if (temp == NULL)
            {
                // Pas d'enfant
                free(node);
                return NULL;
            }
            else
            {
                // Un enfant: remplacer le noeud par son enfant
                avl_node_t *to_free = node;
                node = temp;
                free(to_free);
            }
        }
        else
        {
            // Cas 2: Deux enfants
            // Trouver le successeur inorder (plus petit du sous-arbre droit)
            avl_node_t *successor = find_min_node(node->right);

            // Copier la valeur du successeur
            node->value = successor->value;

            // Supprimer le successeur
            bool temp_deleted = false;
            node->right = delete_node(node->right, successor->value, &temp_deleted);
        }
    }

    // Reequilibrer
    return rebalance(node);
}

bool avl_delete(avl_tree_t *tree, int value)
{
    if (tree == NULL || tree->root == NULL)
        return false;

    bool deleted = false;
    tree->root = delete_node(tree->root, value, &deleted);

    if (deleted)
        tree->size--;

    return deleted;
}

// ============================================
// Recherche et requetes
// ============================================

bool avl_search(const avl_tree_t *tree, int value)
{
    if (tree == NULL)
        return false;

    avl_node_t *current = tree->root;
    while (current != NULL)
    {
        if (value == current->value)
            return true;
        else if (value < current->value)
            current = current->left;
        else
            current = current->right;
    }

    return false;
}

bool avl_min(const avl_tree_t *tree, int *result)
{
    if (tree == NULL || tree->root == NULL || result == NULL)
        return false;

    avl_node_t *current = tree->root;
    while (current->left != NULL)
        current = current->left;

    *result = current->value;
    return true;
}

bool avl_max(const avl_tree_t *tree, int *result)
{
    if (tree == NULL || tree->root == NULL || result == NULL)
        return false;

    avl_node_t *current = tree->root;
    while (current->right != NULL)
        current = current->right;

    *result = current->value;
    return true;
}

// ============================================
// Validation
// ============================================

static bool is_valid_avl_node(const avl_node_t *node, int *height)
{
    if (node == NULL)
    {
        *height = -1;
        return true;
    }

    int left_height, right_height;

    // Verifier recursivement les sous-arbres
    if (!is_valid_avl_node(node->left, &left_height))
        return false;
    if (!is_valid_avl_node(node->right, &right_height))
        return false;

    // Verifier la propriete AVL
    int balance = left_height - right_height;
    if (balance < -1 || balance > 1)
        return false;

    // Verifier la propriete BST
    if (node->left != NULL && node->left->value >= node->value)
        return false;
    if (node->right != NULL && node->right->value <= node->value)
        return false;

    // Verifier la hauteur stockee
    int expected_height = 1 + max(left_height, right_height);
    if (node->height != expected_height)
        return false;

    *height = expected_height;
    return true;
}

bool avl_is_valid(const avl_tree_t *tree)
{
    if (tree == NULL)
        return false;

    int height;
    return is_valid_avl_node(tree->root, &height);
}

size_t avl_size(const avl_tree_t *tree)
{
    if (tree == NULL)
        return 0;
    return tree->size;
}

int avl_height(const avl_tree_t *tree)
{
    if (tree == NULL || tree->root == NULL)
        return -1;
    return tree->root->height;
}

// ============================================
// Parcours
// ============================================

static int inorder_helper(const avl_node_t *node, int *result, int idx, int max_size)
{
    if (node == NULL || idx >= max_size)
        return idx;

    idx = inorder_helper(node->left, result, idx, max_size);
    if (idx < max_size)
        result[idx++] = node->value;
    idx = inorder_helper(node->right, result, idx, max_size);

    return idx;
}

int avl_inorder(const avl_tree_t *tree, int *result, int max_size)
{
    if (tree == NULL || result == NULL || max_size <= 0)
        return 0;

    return inorder_helper(tree->root, result, 0, max_size);
}
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : Stockage du facteur d'equilibre au lieu de la hauteur**

```c
// Structure alternative avec balance factor
typedef struct s_avl_node_alt {
    int                     value;
    int                     bf;     // Balance factor: -1, 0, +1
    struct s_avl_node_alt   *left;
    struct s_avl_node_alt   *right;
} avl_node_alt_t;

// Mise a jour du BF apres rotation droite
static void update_bf_after_rotate_right(avl_node_alt_t *new_root)
{
    // Calcul base sur les changements de structure
    // Plus complexe mais economise de la memoire (int vs recalcul hauteur)
}
```

**Alternative 2 : Implementation iterative de l'insertion**

```c
// Version iterative avec pile explicite
bool avl_insert_iterative(avl_tree_t *tree, int value)
{
    if (tree == NULL)
        return false;

    if (tree->root == NULL)
    {
        tree->root = create_node(value);
        tree->size++;
        return tree->root != NULL;
    }

    // Pile pour stocker le chemin
    avl_node_t *path[64];
    int path_len = 0;

    avl_node_t *current = tree->root;
    avl_node_t *parent = NULL;

    // Descendre jusqu'a la position d'insertion
    while (current != NULL)
    {
        path[path_len++] = current;
        parent = current;

        if (value < current->value)
            current = current->left;
        else if (value > current->value)
            current = current->right;
        else
            return false;  // Doublon
    }

    // Creer et inserer le nouveau noeud
    avl_node_t *new_node = create_node(value);
    if (new_node == NULL)
        return false;

    if (value < parent->value)
        parent->left = new_node;
    else
        parent->right = new_node;

    tree->size++;

    // Remonter et reequilibrer
    while (path_len > 0)
    {
        avl_node_t *node = path[--path_len];
        update_height(node);

        avl_node_t *rebalanced = rebalance(node);

        // Reconnecter si reequilibrage a change la racine du sous-arbre
        if (rebalanced != node)
        {
            if (path_len > 0)
            {
                avl_node_t *grand = path[path_len - 1];
                if (grand->left == node)
                    grand->left = rebalanced;
                else
                    grand->right = rebalanced;
            }
            else
            {
                tree->root = rebalanced;
            }
        }
    }

    return true;
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Rotation) : Oublie de mettre a jour les hauteurs apres rotation**

```c
// MUTANT A: Hauteurs non mises a jour
avl_node_t *avl_rotate_right_mutant(avl_node_t *y)
{
    avl_node_t *x = y->left;
    avl_node_t *T2 = x->right;

    x->right = y;
    y->left = T2;

    // ERREUR: pas d'update_height(y) ni update_height(x)

    return x;
}
```
**Pourquoi faux :** Les hauteurs restent incorrectes, ce qui fausse le calcul du balance factor pour les operations suivantes. L'arbre semble equilibre mais les rotations futures seront basees sur des donnees erronees.

**Mutant B (Balance) : Calcul du balance factor inverse**

```c
// MUTANT B: BF calcule a l'envers
int avl_balance_factor_mutant(const avl_node_t *node)
{
    if (node == NULL)
        return 0;
    // ERREUR: droite - gauche au lieu de gauche - droite
    return avl_node_height(node->right) - avl_node_height(node->left);
}
```
**Pourquoi faux :** Les cas de rotation sont inverses. Un cas LL sera traite comme RR et vice versa, causant des rotations dans la mauvaise direction et corrompant l'arbre.

**Mutant C (Rebalance) : Verification du balance factor des enfants incorrecte**

```c
// MUTANT C: Mauvaise condition pour double rotation
static avl_node_t *rebalance_mutant(avl_node_t *node)
{
    update_height(node);
    int balance = avl_balance_factor(node);

    // Cas Left-Left
    if (balance > 1 && avl_balance_factor(node->left) >= 0)
        return avl_rotate_right(node);

    // Cas Right-Right
    if (balance < -1 && avl_balance_factor(node->right) <= 0)
        return avl_rotate_left(node);

    // ERREUR: conditions > 0 et < 0 au lieu de < 0 et > 0
    // Cas Left-Right
    if (balance > 1 && avl_balance_factor(node->left) > 0)  // ERREUR
    {
        node->left = avl_rotate_left(node->left);
        return avl_rotate_right(node);
    }

    // Cas Right-Left
    if (balance < -1 && avl_balance_factor(node->right) < 0)  // ERREUR
    {
        node->right = avl_rotate_right(node->right);
        return avl_rotate_left(node);
    }

    return node;
}
```
**Pourquoi faux :** Les cas LR et RL ne sont jamais detectes car les conditions sont inversees. Ces cas ne seront pas traites correctement, laissant l'arbre desequilibre.

**Mutant D (Delete) : Oublie de reequilibrer apres suppression**

```c
// MUTANT D: Pas de reequilibrage apres suppression
static avl_node_t *delete_node_mutant(avl_node_t *node, int value, bool *deleted)
{
    if (node == NULL)
    {
        *deleted = false;
        return NULL;
    }

    if (value < node->value)
        node->left = delete_node_mutant(node->left, value, deleted);
    else if (value > node->value)
        node->right = delete_node_mutant(node->right, value, deleted);
    else
    {
        *deleted = true;

        if (node->left == NULL || node->right == NULL)
        {
            avl_node_t *temp = node->left ? node->left : node->right;
            if (temp == NULL)
            {
                free(node);
                return NULL;
            }
            else
            {
                avl_node_t *to_free = node;
                node = temp;
                free(to_free);
            }
        }
        else
        {
            avl_node_t *successor = find_min_node(node->right);
            node->value = successor->value;
            bool temp_deleted = false;
            node->right = delete_node_mutant(node->right, successor->value, &temp_deleted);
        }
    }

    // ERREUR: return node au lieu de return rebalance(node)
    return node;
}
```
**Pourquoi faux :** Apres suppression, l'arbre peut devenir desequilibre (BF > 1 ou < -1). Sans reequilibrage, la propriete AVL n'est plus garantie et les performances degradent vers O(n).

**Mutant E (Insert) : Double insertion possible**

```c
// MUTANT E: Pas de verification des doublons
static avl_node_t *insert_node_mutant(avl_node_t *node, int value, bool *inserted)
{
    if (node == NULL)
    {
        avl_node_t *new_node = create_node(value);
        if (new_node != NULL)
            *inserted = true;
        return new_node;
    }

    // ERREUR: pas de else pour le cas value == node->value
    if (value < node->value)
        node->left = insert_node_mutant(node->left, value, inserted);
    if (value > node->value)  // ERREUR: devrait etre "else if"
        node->right = insert_node_mutant(node->right, value, inserted);
    // Doublon silencieusement ignore mais *inserted reste true du if precedent

    return rebalance(node);
}
```
**Pourquoi faux :** La logique est cassee car les deux conditions peuvent s'executer. De plus, les doublons ne sont pas correctement rejetes, pouvant corrompre la propriete BST.

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

L'arbre **AVL** illustre des concepts fondamentaux :

1. **Auto-equilibrage** - Maintenir une structure optimale automatiquement
2. **Garanties de performance** - O(log n) dans le pire cas, pas seulement en moyenne
3. **Rotations** - Transformation locale preservant les proprietes globales
4. **Compromis** - Plus de travail a l'insertion/suppression pour des recherches rapides

### 5.2 Propriete AVL et Balance Factor

```
PROPRIETE AVL:
Pour tout noeud N dans l'arbre:
    |hauteur(sous-arbre_gauche) - hauteur(sous-arbre_droit)| <= 1

BALANCE FACTOR (BF):
    BF(N) = hauteur(N.gauche) - hauteur(N.droite)

Valeurs possibles pour un arbre AVL valide:
    BF = -1 : sous-arbre droit plus haut d'une unite
    BF =  0 : sous-arbres de meme hauteur
    BF = +1 : sous-arbre gauche plus haut d'une unite

Si BF < -1 ou BF > +1 : VIOLATION -> reequilibrage necessaire
```

### 5.3 Visualisation ASCII des Rotations

```
===============================================================================
ROTATION DROITE (Right Rotation) - Cas Left-Left (LL)
===============================================================================

Situation: Insertion dans le sous-arbre gauche de l'enfant gauche
           Balance factor de Z devient +2

AVANT:                              APRES:
       Z  (BF=+2)                        Y  (BF=0)
      / \                               / \
     Y   T4  (h)                       X   Z
    / \                               /   / \
   X   T3  (h)                      T1  T3  T4
  / \                               (h) (h) (h)
 T1  T2
(h)  (h-1)

Code:
    avl_node_t *avl_rotate_right(avl_node_t *z)
    {
        avl_node_t *y = z->left;
        avl_node_t *T3 = y->right;

        y->right = z;       // Y devient parent de Z
        z->left = T3;       // T3 devient enfant gauche de Z

        update_height(z);   // Z d'abord (maintenant enfant)
        update_height(y);   // Y ensuite (maintenant parent)

        return y;           // Nouvelle racine du sous-arbre
    }

Verification BST preservee:
    - T1 < X < T2  (inchange)
    - X < Y < T3   (inchange)
    - T3 < Z < T4  (T3 passe de droite de Y a gauche de Z, toujours < Z)

===============================================================================
ROTATION GAUCHE (Left Rotation) - Cas Right-Right (RR)
===============================================================================

Situation: Insertion dans le sous-arbre droit de l'enfant droit
           Balance factor de X devient -2

AVANT:                              APRES:
   X  (BF=-2)                            Y  (BF=0)
  / \                                   / \
 T1  Y                                 X   Z
    / \                               / \   \
   T2  Z                             T1 T2  T3
      / \
     T3  T4

Code:
    avl_node_t *avl_rotate_left(avl_node_t *x)
    {
        avl_node_t *y = x->right;
        avl_node_t *T2 = y->left;

        y->left = x;        // Y devient parent de X
        x->right = T2;      // T2 devient enfant droit de X

        update_height(x);   // X d'abord
        update_height(y);   // Y ensuite

        return y;
    }

===============================================================================
DOUBLE ROTATION GAUCHE-DROITE (Left-Right) - Cas LR
===============================================================================

Situation: Insertion dans le sous-arbre DROIT de l'enfant GAUCHE
           Simple rotation droite ne suffit pas

AVANT:                 APRES rot. gauche      APRES rot. droite
       Z (BF=+2)       sur Y:                 sur Z:
      / \                    Z                      X
     Y   T4                 / \                    / \
    / \                    X   T4                 Y   Z
   T1  X                  / \                    / \ / \
      / \                Y  T3                  T1 T2 T3 T4
     T2  T3             / \
                       T1 T2

Etapes:
1. Rotation gauche sur Y (enfant gauche de Z)
2. Rotation droite sur Z

Code:
    if (balance > 1 && avl_balance_factor(node->left) < 0)
    {
        node->left = avl_rotate_left(node->left);   // Etape 1
        return avl_rotate_right(node);               // Etape 2
    }

===============================================================================
DOUBLE ROTATION DROITE-GAUCHE (Right-Left) - Cas RL
===============================================================================

Situation: Insertion dans le sous-arbre GAUCHE de l'enfant DROIT

AVANT:                 APRES rot. droite      APRES rot. gauche
   X (BF=-2)           sur Y:                 sur X:
  / \                       X                      Y
 T1  Y                     / \                    / \
    / \                   T1  Y                  X   Z
   Z   T4                    / \                / \ / \
  / \                       Z   T4             T1 T2 T3 T4
 T2  T3                    / \
                          T2  T3

Etapes:
1. Rotation droite sur Y (enfant droit de X)
2. Rotation gauche sur X

Code:
    if (balance < -1 && avl_balance_factor(node->right) > 0)
    {
        node->right = avl_rotate_right(node->right); // Etape 1
        return avl_rotate_left(node);                 // Etape 2
    }

===============================================================================
EXEMPLE COMPLET D'INSERTION AVEC REEQUILIBRAGE
===============================================================================

Insertion de la sequence: 10, 20, 30, 25, 28, 27

1. Insert 10:           2. Insert 20:           3. Insert 30:
                                                   (RR rotation)
      10                     10                      20
                              \                     /  \
                              20                   10  30

4. Insert 25:           5. Insert 28:           6. Insert 27:
                           (RL rotation)           (RL rotation)
      20                     20                      20
     /  \                   /  \                    /  \
    10  30                 10  28                  10  27
        /                     /  \                    /  \
       25                   25   30                 25   28
                                                         \
                                                         30

Detail etape 5 (RL rotation apres insertion 28):

AVANT:                      Rotation droite         Rotation gauche
      30 (BF=+2)            sur 25:                sur 30:
      /                          30                     28
     25 (BF=-1)                 /                      /  \
      \                        28                     25  30
      28                      /
                             25

===============================================================================
SUPPRESSION AVEC REEQUILIBRAGE
===============================================================================

Supprimer 10 de:            Apres suppression:      Apres rotation (LL):
      20                          20                      27
     /  \                          \                     /  \
    10  27                         27                   20  28
       /  \                       /  \                      \
      25  28                     25  28                     30
           \                          \
           30                         30

La suppression de 10 cause BF(20) = 0 - 2 = -2
L'enfant droit 27 a BF = 0 ou -1 -> Rotation gauche simple

===============================================================================
HAUTEUR MAXIMALE D'UN AVL
===============================================================================

Pour un arbre AVL de n noeuds:
    hauteur_max = 1.44 * log2(n)

Nombre minimum de noeuds pour une hauteur h (arbres de Fibonacci):
    N(h) = N(h-1) + N(h-2) + 1
    N(0) = 1
    N(1) = 2
    N(2) = 4
    N(3) = 7
    N(4) = 12
    N(5) = 20
    ...

Cela garantit O(log n) pour toutes les operations.
```

### 5.4 Comparaison des Complexites

```
+-------------------+------------+------------+------------+
| Operation         | AVL        | BST (avg)  | BST (worst)|
+-------------------+------------+------------+------------+
| Search            | O(log n)   | O(log n)   | O(n)       |
| Insert            | O(log n)   | O(log n)   | O(n)       |
| Delete            | O(log n)   | O(log n)   | O(n)       |
| Min/Max           | O(log n)   | O(log n)   | O(n)       |
+-------------------+------------+------------+------------+
| Rotations/Insert  | 0-2        | 0          | 0          |
| Rotations/Delete  | 0-O(log n) | 0          | 0          |
+-------------------+------------+------------+------------+

AVL vs Red-Black:
+-------------------+------------+------------+
| Propriete         | AVL        | Red-Black  |
+-------------------+------------+------------+
| Hauteur max       | 1.44*log n | 2*log n    |
| Recherche         | Plus rapide| Plus lent  |
| Insert/Delete     | Plus lent  | Plus rapide|
| Rotations/Insert  | 0-2        | 0-2        |
| Rotations/Delete  | 0-O(log n) | 0-3        |
+-------------------+------------+------------+
```

---

## SECTION 6 : PIEGES

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Oublier update_height apres rotation | Balance factor incorrect | Toujours mettre a jour les hauteurs |
| 2 | Ordre incorrect des update_height | Hauteur du parent fausse | Enfant d'abord, puis parent |
| 3 | Balance factor inverse | Rotations dans le mauvais sens | BF = gauche - droite |
| 4 | Pas de reequilibrage apres delete | Arbre desequilibre | Appeler rebalance dans delete |
| 5 | Conditions LR/RL incorrectes | Double rotations manquees | Verifier BF de l'enfant |
| 6 | Reconnexion au parent oubliee | Sous-arbre perdu | Assigner le retour de rotation |
| 7 | Memory leak sur delete | Fuite memoire | free() avant de remplacer |
| 8 | Hauteur de NULL non geree | Crash ou BF faux | Retourner -1 pour NULL |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Apres l'insertion des valeurs 30, 20, 10 dans un arbre AVL initialement vide, quelle sera la racine de l'arbre ?

- A) 30
- B) 20
- C) 10
- D) L'arbre sera desequilibre
- E) Impossible a determiner

**Reponse correcte : B**

**Explication :** L'insertion de 30, puis 20, puis 10 cree un desequilibre Left-Left (LL). Le balance factor de 30 devient +2. Une rotation droite est effectuee, faisant de 20 la nouvelle racine avec 10 a gauche et 30 a droite.

```
Insert 30:     Insert 20:     Insert 10:     Rotation droite:
   30             30             30 (BF=+2)        20
                 /              /                 /  \
                20             20                10  30
                              /
                             10
```

---

### Question 2 (3 points)
Dans quel cas une double rotation (Left-Right ou Right-Left) est-elle necessaire dans un arbre AVL ?

- A) Quand le balance factor de la racine est +3 ou -3
- B) Quand l'insertion se fait dans le sous-arbre interieur (droit de gauche ou gauche de droit)
- C) Quand l'arbre a plus de 3 niveaux
- D) Quand on supprime la racine
- E) Quand le balance factor de tous les noeuds est 0

**Reponse correcte : B**

**Explication :** Une double rotation est necessaire quand l'insertion se fait dans le sous-arbre "interieur" :
- Cas Left-Right (LR) : insertion dans le sous-arbre DROIT de l'enfant GAUCHE
- Cas Right-Left (RL) : insertion dans le sous-arbre GAUCHE de l'enfant DROIT

Une simple rotation ne suffit pas car elle ne repositionne pas correctement le noeud insere. La double rotation (rotation sur l'enfant puis sur le noeud desequilibre) amene le noeud du milieu a la position de racine.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | D.26 |
| **Nom** | avl_tree |
| **Difficulte** | 7/10 |
| **Duree** | 150 min |
| **XP Base** | 225 |
| **Langage** | C17 |
| **Concepts cles** | AVL, Rotations, Balance Factor, Auto-equilibrage |
| **Complexite temps** | O(log n) pour toutes operations |
| **Complexite espace** | O(n) |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.26",
  "name": "avl_tree",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "difficulty": 7,
  "xp_base": 225,
  "estimated_time_minutes": 150,
  "complexity": {
    "time": "O(log n)",
    "space": "O(n)"
  },
  "files": {
    "required": ["avl_tree.c", "avl_tree.h"],
    "provided": ["main.c", "Makefile"],
    "tests": ["test_avl_tree.c"]
  },
  "compilation": {
    "command": "gcc -Wall -Wextra -Werror -std=c17 -o avl_tree avl_tree.c main.c -lm",
    "flags": ["-Wall", "-Wextra", "-Werror", "-std=c17", "-lm"]
  },
  "tests": {
    "unit_tests": "test_avl_tree.c",
    "moulinette": {
      "timeout_seconds": 15,
      "memory_check": true,
      "valgrind_flags": ["--leak-check=full", "--error-exitcode=1"]
    }
  },
  "topics": [
    "avl_tree",
    "self_balancing_bst",
    "rotations",
    "balance_factor",
    "binary_search_tree",
    "data_structures",
    "tree_algorithms"
  ],
  "prerequisites": [
    "D.24",
    "D.25",
    "0.5.11"
  ],
  "learning_objectives": [
    "Comprendre la propriete d'equilibre AVL",
    "Implementer les quatre types de rotations",
    "Maitriser l'insertion avec reequilibrage automatique",
    "Maitriser la suppression avec reequilibrage automatique",
    "Calculer et utiliser le balance factor"
  ],
  "grading": {
    "auto_grade": true,
    "total_points": 225,
    "categories": {
      "create_destroy": 15,
      "rotations": 80,
      "insert": 40,
      "delete": 55,
      "search_queries": 20,
      "memory_management": 15
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
