# Exercice 0.6.8-a : binary_tree

**Module :**
0.6.8 — Arbres Binaires

**Concept :**
a-c — node structure, insert, traversal

**Difficulte :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
code

**Tiers :**
2 — Combinaison de concepts

**Langage :**
C17

**Prerequis :**
0.6.1 (malloc), recursion, pointeurs

**Domaines :**
Structures, Algorithmes, Recursion

**Duree estimee :**
300 min

**XP Base :**
450

**Complexite :**
T1 O(log n) moyenne / O(n) pire cas x S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `binary_tree.c`
- `binary_tree.h`

**Headers autorises :**
- `<stdio.h>`, `<stdlib.h>`, `<stdbool.h>`, `<stddef.h>`

**Fonctions autorisees :**
- `malloc()`, `calloc()`, `free()`, `printf()`

### 1.2 Consigne

Implementer un arbre binaire de recherche (BST - Binary Search Tree) avec les operations fondamentales.

**Ta mission :**

Creer une structure de donnees arbre binaire permettant l'insertion, la recherche et le parcours ordonne des elements.

**Prototypes :**
```c
// Structure d'un noeud
typedef struct bt_node {
    int value;
    struct bt_node *left;
    struct bt_node *right;
} bt_node_t;

// Structure de l'arbre
typedef struct binary_tree {
    bt_node_t *root;
    size_t count;
} binary_tree_t;

// Cree un nouvel arbre vide
binary_tree_t *bt_create(void);

// Insere une valeur dans l'arbre (BST)
bool bt_insert(binary_tree_t *tree, int value);

// Recherche une valeur dans l'arbre
bool bt_search(binary_tree_t *tree, int value);

// Parcours in-order (gauche, racine, droite) - affiche les valeurs
void bt_inorder(binary_tree_t *tree);

// Parcours pre-order (racine, gauche, droite)
void bt_preorder(binary_tree_t *tree);

// Parcours post-order (gauche, droite, racine)
void bt_postorder(binary_tree_t *tree);

// Retourne la hauteur de l'arbre
int bt_height(binary_tree_t *tree);

// Retourne la valeur minimale
int bt_min(binary_tree_t *tree);

// Retourne la valeur maximale
int bt_max(binary_tree_t *tree);

// Libere tout l'arbre
void bt_destroy(binary_tree_t *tree);
```

**Comportement :**
- `bt_create` retourne un arbre avec root = NULL et count = 0
- `bt_insert` place les valeurs inferieures a gauche, superieures a droite
- `bt_insert` retourne false si la valeur existe deja (pas de doublons)
- `bt_search` retourne true si la valeur est trouvee
- `bt_inorder` affiche les valeurs dans l'ordre croissant
- `bt_height` retourne -1 pour un arbre vide, 0 pour un seul noeud
- `bt_min`/`bt_max` retournent INT_MIN/INT_MAX si arbre vide

**Exemples :**
```
bt_create()         -> arbre vide
bt_insert(tree, 5)  -> true (root = 5)
bt_insert(tree, 3)  -> true (5->left = 3)
bt_insert(tree, 7)  -> true (5->right = 7)
bt_insert(tree, 5)  -> false (doublon)
bt_search(tree, 3)  -> true
bt_search(tree, 4)  -> false
bt_inorder(tree)    -> affiche: 3 5 7
bt_height(tree)     -> 1
bt_min(tree)        -> 3
bt_max(tree)        -> 7
```

**Contraintes :**
- Pas de doublons dans l'arbre
- Toutes les fonctions de parcours doivent etre recursives
- Gerer le cas de l'arbre vide
- Compiler avec `gcc -Wall -Werror -std=c17`

### 1.3 Prototype

```c
// binary_tree.h
#ifndef BINARY_TREE_H
#define BINARY_TREE_H

#include <stddef.h>
#include <stdbool.h>

typedef struct bt_node {
    int value;
    struct bt_node *left;
    struct bt_node *right;
} bt_node_t;

typedef struct binary_tree {
    bt_node_t *root;
    size_t count;
} binary_tree_t;

binary_tree_t *bt_create(void);
bool bt_insert(binary_tree_t *tree, int value);
bool bt_search(binary_tree_t *tree, int value);
void bt_inorder(binary_tree_t *tree);
void bt_preorder(binary_tree_t *tree);
void bt_postorder(binary_tree_t *tree);
int bt_height(binary_tree_t *tree);
int bt_min(binary_tree_t *tree);
int bt_max(binary_tree_t *tree);
void bt_destroy(binary_tree_t *tree);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 BST vs Arbres equilibres

Un BST classique peut degenerer en liste chainee (O(n)) si les insertions sont ordonnees. Les arbres equilibres (AVL, Red-Black) garantissent O(log n).

### 2.2 Parcours et applications

- **In-order**: Tri croissant (BST)
- **Pre-order**: Copie de l'arbre, serialisation
- **Post-order**: Liberation memoire (enfants avant parent)

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Database Engineer**

Les arbres B et B+ sont utilises pour:
- Index de bases de donnees
- Systemes de fichiers (NTFS, ext4)
- Stockage SSD optimise

**Metier : Game Developer**

Les arbres sont essentiels pour:
- Spatial partitioning (Quadtree, Octree)
- Scene graphs
- Decision trees pour l'IA

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o test_bt test_main.c binary_tree.c
$ ./test_bt
Creating binary tree...
  OK: Tree created (root=NULL, count=0)

Inserting values: 50, 30, 70, 20, 40, 60, 80
  bt_insert(50): OK (root)
  bt_insert(30): OK (left of 50)
  bt_insert(70): OK (right of 50)
  bt_insert(20): OK (left of 30)
  bt_insert(40): OK (right of 30)
  bt_insert(60): OK (left of 70)
  bt_insert(80): OK (right of 70)
  Count: 7

Testing traversals...
  In-order:   20 30 40 50 60 70 80 (sorted!)
  Pre-order:  50 30 20 40 70 60 80
  Post-order: 20 40 30 60 80 70 50

Testing search...
  bt_search(40): true - OK
  bt_search(45): false - OK

Testing properties...
  bt_height(): 2 - OK
  bt_min(): 20 - OK
  bt_max(): 80 - OK

Testing duplicate rejection...
  bt_insert(50): false - OK (duplicate rejected)

Destroying tree...
  OK: All memory freed

All tests passed!
$ echo $?
0
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★★☆☆☆ (7/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Implementer la suppression de noeuds dans le BST.

```c
// Supprime un noeud par valeur
bool bt_delete(binary_tree_t *tree, int value);

// Verifie si l'arbre est un BST valide
bool bt_is_valid_bst(binary_tree_t *tree);

// Retourne le successeur in-order d'une valeur
int bt_successor(binary_tree_t *tree, int value);

// Retourne le predecesseur in-order d'une valeur
int bt_predecessor(binary_tree_t *tree, int value);
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Input | Expected | Points |
|---------|-------------|-------|----------|--------|
| T01 | bt_create | - | non-NULL, count=0 | 10 |
| T02 | bt_insert root | 5 | true, root->value=5 | 10 |
| T03 | bt_insert left | 3 (apres 5) | true, left child | 10 |
| T04 | bt_insert right | 7 (apres 5) | true, right child | 10 |
| T05 | bt_insert duplicate | 5 (existe) | false | 10 |
| T06 | bt_search found | 3 | true | 10 |
| T07 | bt_search not found | 4 | false | 10 |
| T08 | bt_inorder sorted | 3,5,7 | "3 5 7" | 10 |
| T09 | bt_height | 3 levels | 2 | 10 |
| T10 | bt_min/bt_max | - | correct values | 10 |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include "binary_tree.h"

int main(void)
{
    int pass = 0, fail = 0;

    // T01: bt_create
    binary_tree_t *tree = bt_create();
    if (tree != NULL && tree->root == NULL && tree->count == 0) {
        printf("T01 PASS: bt_create works\n");
        pass++;
    } else {
        printf("T01 FAIL: bt_create failed\n");
        fail++;
    }

    // T02: bt_insert root
    if (bt_insert(tree, 50) && tree->root != NULL &&
        tree->root->value == 50) {
        printf("T02 PASS: bt_insert root works\n");
        pass++;
    } else {
        printf("T02 FAIL: bt_insert root failed\n");
        fail++;
    }

    // T03: bt_insert left
    if (bt_insert(tree, 30) && tree->root->left != NULL &&
        tree->root->left->value == 30) {
        printf("T03 PASS: bt_insert left works\n");
        pass++;
    } else {
        printf("T03 FAIL: bt_insert left failed\n");
        fail++;
    }

    // T04: bt_insert right
    if (bt_insert(tree, 70) && tree->root->right != NULL &&
        tree->root->right->value == 70) {
        printf("T04 PASS: bt_insert right works\n");
        pass++;
    } else {
        printf("T04 FAIL: bt_insert right failed\n");
        fail++;
    }

    // T05: bt_insert duplicate
    if (!bt_insert(tree, 50)) {
        printf("T05 PASS: bt_insert duplicate rejected\n");
        pass++;
    } else {
        printf("T05 FAIL: bt_insert duplicate should fail\n");
        fail++;
    }

    // T06: bt_search found
    if (bt_search(tree, 30)) {
        printf("T06 PASS: bt_search found works\n");
        pass++;
    } else {
        printf("T06 FAIL: bt_search found failed\n");
        fail++;
    }

    // T07: bt_search not found
    if (!bt_search(tree, 45)) {
        printf("T07 PASS: bt_search not found works\n");
        pass++;
    } else {
        printf("T07 FAIL: bt_search not found failed\n");
        fail++;
    }

    // T08: bt_inorder
    printf("T08: bt_inorder output: ");
    bt_inorder(tree);
    printf(" (expected: 30 50 70)\n");
    pass++;  // Manual verification needed

    // T09: bt_height
    bt_insert(tree, 20);
    bt_insert(tree, 40);
    if (bt_height(tree) == 2) {
        printf("T09 PASS: bt_height works\n");
        pass++;
    } else {
        printf("T09 FAIL: bt_height returned %d, expected 2\n",
               bt_height(tree));
        fail++;
    }

    // T10: bt_min/bt_max
    if (bt_min(tree) == 20 && bt_max(tree) == 70) {
        printf("T10 PASS: bt_min/bt_max work\n");
        pass++;
    } else {
        printf("T10 FAIL: bt_min=%d bt_max=%d\n",
               bt_min(tree), bt_max(tree));
        fail++;
    }

    bt_destroy(tree);

    printf("\nResults: %d passed, %d failed\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
```

### 4.3 Solution de reference

```c
/*
 * binary_tree.c
 * Implementation d'un arbre binaire de recherche
 * Exercice ex31_binary_tree
 */

#include "binary_tree.h"
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

// Cree un nouveau noeud
static bt_node_t *bt_node_create(int value)
{
    bt_node_t *node = malloc(sizeof(*node));
    if (node == NULL)
    {
        return NULL;
    }
    node->value = value;
    node->left = NULL;
    node->right = NULL;
    return node;
}

binary_tree_t *bt_create(void)
{
    binary_tree_t *tree = malloc(sizeof(*tree));
    if (tree == NULL)
    {
        return NULL;
    }
    tree->root = NULL;
    tree->count = 0;
    return tree;
}

// Helper recursif pour insert
static bt_node_t *bt_insert_recursive(bt_node_t *node, int value, bool *success)
{
    if (node == NULL)
    {
        *success = true;
        return bt_node_create(value);
    }

    if (value < node->value)
    {
        node->left = bt_insert_recursive(node->left, value, success);
    }
    else if (value > node->value)
    {
        node->right = bt_insert_recursive(node->right, value, success);
    }
    else
    {
        *success = false;  // Doublon
    }

    return node;
}

bool bt_insert(binary_tree_t *tree, int value)
{
    if (tree == NULL)
    {
        return false;
    }

    bool success = false;
    tree->root = bt_insert_recursive(tree->root, value, &success);

    if (success)
    {
        tree->count++;
    }

    return success;
}

// Helper recursif pour search
static bool bt_search_recursive(bt_node_t *node, int value)
{
    if (node == NULL)
    {
        return false;
    }

    if (value == node->value)
    {
        return true;
    }
    else if (value < node->value)
    {
        return bt_search_recursive(node->left, value);
    }
    else
    {
        return bt_search_recursive(node->right, value);
    }
}

bool bt_search(binary_tree_t *tree, int value)
{
    if (tree == NULL)
    {
        return false;
    }
    return bt_search_recursive(tree->root, value);
}

// Helper recursif pour inorder
static void bt_inorder_recursive(bt_node_t *node)
{
    if (node == NULL)
    {
        return;
    }
    bt_inorder_recursive(node->left);
    printf("%d ", node->value);
    bt_inorder_recursive(node->right);
}

void bt_inorder(binary_tree_t *tree)
{
    if (tree != NULL)
    {
        bt_inorder_recursive(tree->root);
    }
}

// Helper recursif pour preorder
static void bt_preorder_recursive(bt_node_t *node)
{
    if (node == NULL)
    {
        return;
    }
    printf("%d ", node->value);
    bt_preorder_recursive(node->left);
    bt_preorder_recursive(node->right);
}

void bt_preorder(binary_tree_t *tree)
{
    if (tree != NULL)
    {
        bt_preorder_recursive(tree->root);
    }
}

// Helper recursif pour postorder
static void bt_postorder_recursive(bt_node_t *node)
{
    if (node == NULL)
    {
        return;
    }
    bt_postorder_recursive(node->left);
    bt_postorder_recursive(node->right);
    printf("%d ", node->value);
}

void bt_postorder(binary_tree_t *tree)
{
    if (tree != NULL)
    {
        bt_postorder_recursive(tree->root);
    }
}

// Helper recursif pour height
static int bt_height_recursive(bt_node_t *node)
{
    if (node == NULL)
    {
        return -1;
    }

    int left_height = bt_height_recursive(node->left);
    int right_height = bt_height_recursive(node->right);

    return 1 + (left_height > right_height ? left_height : right_height);
}

int bt_height(binary_tree_t *tree)
{
    if (tree == NULL)
    {
        return -1;
    }
    return bt_height_recursive(tree->root);
}

int bt_min(binary_tree_t *tree)
{
    if (tree == NULL || tree->root == NULL)
    {
        return INT_MIN;
    }

    bt_node_t *current = tree->root;
    while (current->left != NULL)
    {
        current = current->left;
    }
    return current->value;
}

int bt_max(binary_tree_t *tree)
{
    if (tree == NULL || tree->root == NULL)
    {
        return INT_MAX;
    }

    bt_node_t *current = tree->root;
    while (current->right != NULL)
    {
        current = current->right;
    }
    return current->value;
}

// Helper recursif pour destroy
static void bt_destroy_recursive(bt_node_t *node)
{
    if (node == NULL)
    {
        return;
    }
    bt_destroy_recursive(node->left);
    bt_destroy_recursive(node->right);
    free(node);
}

void bt_destroy(binary_tree_t *tree)
{
    if (tree == NULL)
    {
        return;
    }
    bt_destroy_recursive(tree->root);
    free(tree);
}
```

### 4.4 Solutions alternatives acceptees

```c
// Alternative 1: Insert iteratif
bool bt_insert_iterative(binary_tree_t *tree, int value)
{
    if (tree == NULL) return false;

    bt_node_t *new_node = bt_node_create(value);
    if (new_node == NULL) return false;

    if (tree->root == NULL)
    {
        tree->root = new_node;
        tree->count++;
        return true;
    }

    bt_node_t *current = tree->root;
    bt_node_t *parent = NULL;

    while (current != NULL)
    {
        parent = current;
        if (value < current->value)
            current = current->left;
        else if (value > current->value)
            current = current->right;
        else
        {
            free(new_node);
            return false;  // Doublon
        }
    }

    if (value < parent->value)
        parent->left = new_node;
    else
        parent->right = new_node;

    tree->count++;
    return true;
}
```

### 4.5 Solutions refusees (avec explications)

```c
// REFUSE 1: Insert qui accepte les doublons
bool bt_insert(binary_tree_t *tree, int value)
{
    // ... insertion sans verification de doublon
    if (value <= node->value)  // <= accepte les doublons!
        node->left = ...
}
// Raison: BST ne doit pas avoir de doublons

// REFUSE 2: Parcours non recursif sans stack
void bt_inorder(binary_tree_t *tree)
{
    bt_node_t *node = tree->root;
    while (node->left) node = node->left;
    printf("%d ", node->value);
    // Impossible de remonter sans stack!
}
// Raison: Parcours incomplet

// REFUSE 3: Height qui retourne 0 pour arbre vide
int bt_height(binary_tree_t *tree)
{
    if (tree->root == NULL)
        return 0;  // Devrait etre -1!
}
// Raison: Convention: arbre vide = -1, un noeud = 0
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.8-a",
  "name": "binary_tree",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["binary_tree.c", "binary_tree.h"],
    "test": ["test_binary_tree.c"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"],
    "output": "test_bt"
  },
  "tests": {
    "type": "unit",
    "valgrind": true,
    "leak_check": true
  },
  "scoring": {
    "total": 100,
    "compilation": 10,
    "functionality": 65,
    "memory_safety": 25
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```c
// MUTANT 1 (Logic): Comparaison inversee
static bt_node_t *bt_insert_recursive(bt_node_t *node, int value, bool *success)
{
    if (value > node->value)  // > au lieu de <
        node->left = bt_insert_recursive(node->left, value, success);
    // Arbre inverse!
}
// Detection: bt_inorder donne ordre decroissant

// MUTANT 2 (Memory): Pas de free dans destroy
static void bt_destroy_recursive(bt_node_t *node)
{
    if (node == NULL) return;
    bt_destroy_recursive(node->left);
    bt_destroy_recursive(node->right);
    // Manque free(node)!
}
// Detection: Valgrind definitely lost

// MUTANT 3 (Logic): Height retourne mauvaise valeur
static int bt_height_recursive(bt_node_t *node)
{
    if (node == NULL) return 0;  // Devrait etre -1
    // ...
}
// Detection: Height off by one

// MUTANT 4 (Recursion): Manque cas de base
static bool bt_search_recursive(bt_node_t *node, int value)
{
    // Manque: if (node == NULL) return false;
    if (value == node->value) return true;
    // Stack overflow si non trouve!
}
// Detection: Crash sur recherche inexistante

// MUTANT 5 (Logic): count pas incremente
bool bt_insert(binary_tree_t *tree, int value)
{
    bool success = false;
    tree->root = bt_insert_recursive(tree->root, value, &success);
    // Manque: if (success) tree->count++;
    return success;
}
// Detection: tree->count toujours 0
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **fondamentaux des arbres binaires de recherche** en C:

1. **Node structure** - Valeur + pointeurs left/right
2. **Insert** - Placement recursif selon comparaison
3. **Traversal** - Parcours in-order, pre-order, post-order

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION inserer(arbre, valeur):
DEBUT
    SI arbre.racine EST NULL ALORS
        arbre.racine <- nouveau_noeud(valeur)
        RETOURNER VRAI
    FIN SI

    RETOURNER inserer_recursif(arbre.racine, valeur)
FIN

FONCTION inserer_recursif(noeud, valeur):
DEBUT
    SI valeur EGALE noeud.valeur ALORS
        RETOURNER FAUX  // Doublon
    FIN SI

    SI valeur < noeud.valeur ALORS
        SI noeud.gauche EST NULL ALORS
            noeud.gauche <- nouveau_noeud(valeur)
            RETOURNER VRAI
        SINON
            RETOURNER inserer_recursif(noeud.gauche, valeur)
        FIN SI
    SINON
        SI noeud.droit EST NULL ALORS
            noeud.droit <- nouveau_noeud(valeur)
            RETOURNER VRAI
        SINON
            RETOURNER inserer_recursif(noeud.droit, valeur)
        FIN SI
    FIN SI
FIN
```

### 5.3 Visualisation ASCII

```
ARBRE BINAIRE DE RECHERCHE
==========================

Insertions: 50, 30, 70, 20, 40, 60, 80

             50              <- racine
           /    \
         30      70          <- niveau 1
        /  \    /  \
       20  40  60  80        <- niveau 2 (feuilles)

Propriete BST:
- Tous les noeuds a gauche < parent
- Tous les noeuds a droite > parent

PARCOURS:
=========

In-order (Gauche, Racine, Droite):
20 -> 30 -> 40 -> 50 -> 60 -> 70 -> 80
       (resultat trie!)

Pre-order (Racine, Gauche, Droite):
50 -> 30 -> 20 -> 40 -> 70 -> 60 -> 80
       (utile pour copier l'arbre)

Post-order (Gauche, Droite, Racine):
20 -> 40 -> 30 -> 60 -> 80 -> 70 -> 50
       (utile pour liberer la memoire)

RECHERCHE de 40:
================
50: 40 < 50, aller a gauche
30: 40 > 30, aller a droite
40: trouve!

Complexite: O(h) ou h = hauteur
- Arbre equilibre: h = log(n) -> O(log n)
- Arbre degenere: h = n -> O(n)
```

### 5.4 Les pieges en detail

#### Piege 1: Oublier le cas de base dans la recursion
```c
// FAUX - Stack overflow
static void bt_inorder_recursive(bt_node_t *node)
{
    bt_inorder_recursive(node->left);  // Crash si node->left = NULL!
    printf("%d ", node->value);
    bt_inorder_recursive(node->right);
}

// CORRECT
static void bt_inorder_recursive(bt_node_t *node)
{
    if (node == NULL) return;  // Cas de base!
    bt_inorder_recursive(node->left);
    printf("%d ", node->value);
    bt_inorder_recursive(node->right);
}
```

#### Piege 2: Liberer parent avant enfants
```c
// FAUX - Perd l'acces aux enfants
static void bt_destroy_recursive(bt_node_t *node)
{
    free(node);  // Trop tot!
    bt_destroy_recursive(node->left);  // node deja libere!
}

// CORRECT - Post-order pour destroy
static void bt_destroy_recursive(bt_node_t *node)
{
    if (node == NULL) return;
    bt_destroy_recursive(node->left);
    bt_destroy_recursive(node->right);
    free(node);  // Enfants liberes en premier
}
```

### 5.5 Cours Complet

#### 5.5.1 Structure d'un noeud BST

```c
typedef struct bt_node {
    int value;              // Donnee stockee
    struct bt_node *left;   // Sous-arbre gauche (valeurs < value)
    struct bt_node *right;  // Sous-arbre droit (valeurs > value)
} bt_node_t;
```

#### 5.5.2 Propriete BST

Pour tout noeud N:
- Toutes les valeurs dans N->left sont < N->value
- Toutes les valeurs dans N->right sont > N->value

#### 5.5.3 Les trois parcours

| Parcours | Ordre | Utilisation |
|----------|-------|-------------|
| In-order | G-R-D | Tri croissant |
| Pre-order | R-G-D | Copie/serialisation |
| Post-order | G-D-R | Liberation memoire |

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| Cas de base NULL | Evite recursion infinie | `if (node == NULL) return;` |
| Post-order pour free | Libere enfants avant parent | `left; right; free(node);` |
| Pas de doublons | BST standard | `if (value == node->value) return false;` |
| Helper static | Cache implementation | `static void helper(...)` |

### 5.7 Simulation avec trace d'execution

```
Programme: bt_insert(tree, 40) sur arbre {50, 30, 70}

1. bt_insert appelle bt_insert_recursive(root=50, value=40)
2. 40 < 50 -> appel bt_insert_recursive(node=30, value=40)
3. 40 > 30 -> appel bt_insert_recursive(node=NULL, value=40)
4. node == NULL -> cree noeud(40), retourne
5. Remonte: 30->right = noeud(40)
6. Remonte: 50->left = 30 (inchange)
7. success = true, count = 3 -> 4

Arbre apres:
       50
      /  \
    30    70
      \
      40
```

### 5.8 Mnemotechniques

**"LRD" pour les parcours**
- In-order: **L**eft, **R**oot, **D**roit (alphabetique = tri!)
- Pre-order: **R**oot first
- Post-order: **R**oot last

**"SCAN" pour la recherche**
- **S**tart at root
- **C**ompare value
- **A**ller left si <, right si >
- **N**ull = pas trouve

### 5.9 Applications pratiques

1. **Bases de donnees**: Index pour recherche rapide
2. **Systemes de fichiers**: Organisation hierarchique
3. **Compression**: Arbres de Huffman
4. **Expression parsing**: Arbres syntaxiques

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Pas de cas de base | Stack overflow | `if (node == NULL) return;` |
| free avant enfants | Memory leak | Post-order destroy |
| Accepter doublons | BST invalide | Check `value == node->value` |
| Comparaison inversee | Arbre inverse | `<` pour left, `>` pour right |
| count pas mis a jour | Mauvais count | `count++` si success |

---

## SECTION 7 : QCM

### Question 1
Quel parcours donne les elements d'un BST dans l'ordre croissant ?

A) Pre-order
B) Post-order
C) In-order
D) Level-order
E) Aucun

**Reponse correcte: C**

### Question 2
Quelle est la complexite de recherche dans un BST equilibre ?

A) O(1)
B) O(log n)
C) O(n)
D) O(n log n)
E) O(n^2)

**Reponse correcte: B**

### Question 3
Pourquoi utilise-t-on post-order pour liberer un arbre ?

A) C'est plus rapide
B) Pour avoir les elements tries
C) Pour liberer les enfants avant le parent
D) C'est la seule methode possible
E) Pour eviter les doublons

**Reponse correcte: C**

### Question 4
Que se passe-t-il si on insere des elements deja tries dans un BST ?

A) L'arbre est parfaitement equilibre
B) L'arbre degenere en liste chainee
C) L'insertion echoue
D) Les elements sont refuses
E) L'arbre se reequilibre automatiquement

**Reponse correcte: B**

### Question 5
Ou se trouve la valeur minimale dans un BST ?

A) A la racine
B) Dans le noeud le plus a droite
C) Dans le noeud le plus a gauche
D) Dans une feuille quelconque
E) Au milieu de l'arbre

**Reponse correcte: C**

---

## SECTION 8 : RECAPITULATIF

| Operation | Complexite Moyenne | Complexite Pire Cas |
|-----------|-------------------|---------------------|
| insert | O(log n) | O(n) |
| search | O(log n) | O(n) |
| min/max | O(log n) | O(n) |
| traversal | O(n) | O(n) |

| Parcours | Ordre | Application |
|----------|-------|-------------|
| In-order | G-R-D | Tri |
| Pre-order | R-G-D | Copie |
| Post-order | G-D-R | Destruction |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.8-a",
    "name": "binary_tree",
    "module": "0.6.8",
    "phase": 0,
    "difficulty": 6,
    "xp": 450,
    "time_minutes": 300
  },
  "metadata": {
    "concepts": ["node structure", "insert", "traversal"],
    "prerequisites": ["0.6.1", "recursion", "pointers"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "binary_tree.c",
    "header": "binary_tree.h",
    "solution": "binary_tree_solution.c",
    "test": "test_binary_tree.c"
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"]
  },
  "grading": {
    "automated": true,
    "valgrind_required": true,
    "compilation_weight": 10,
    "functionality_weight": 65,
    "memory_weight": 25
  },
  "bonus": {
    "available": true,
    "multiplier": 2,
    "difficulty": 7
  }
}
```
