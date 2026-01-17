# Exercice D.0.24-a : tree_traversal

**Module :**
D.0.24 — Tree Traversal Algorithms

**Concept :**
a-e — Inorder, Preorder, Postorder, Level Order (BFS), Morris Traversal

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
2 — Combinaison de concepts

**Langage :**
C17

**Prerequis :**
0.5.11 (recursion), D.0.17 (linked list), D.0.18 (stack)

**Domaines :**
Algo, Data Structures

**Duree estimee :**
150 min

**XP Base :**
175

**Complexite :**
T[N] O(n) x S[N] O(h)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `tree_traversal.c`
- `tree_traversal.h`

### 1.2 Consigne

Implementer les algorithmes de parcours d'arbres binaires.

**Ta mission :**

```c
// Structure du noeud d'arbre binaire
typedef struct s_tree_node {
    int                  value;
    struct s_tree_node  *left;
    struct s_tree_node  *right;
} t_tree_node;

// Creation et liberation
t_tree_node *tree_create_node(int value);
void         tree_free(t_tree_node *root);

// Parcours recursifs (stockent dans un tableau, retournent la taille)
int  tree_inorder(t_tree_node *root, int *result, int max_size);
int  tree_preorder(t_tree_node *root, int *result, int max_size);
int  tree_postorder(t_tree_node *root, int *result, int max_size);

// Parcours iteratif niveau par niveau (BFS)
int  tree_level_order(t_tree_node *root, int *result, int max_size);

// Morris traversal (inorder sans recursion ni stack - O(1) espace)
int  tree_morris_inorder(t_tree_node *root, int *result, int max_size);

// Proprietes de l'arbre
int  tree_height(t_tree_node *root);
int  tree_depth(t_tree_node *root, int value);

// Lowest Common Ancestor
t_tree_node *tree_lca(t_tree_node *root, int val1, int val2);
```

**Comportement:**

1. `tree_inorder` - Parcours gauche, racine, droite
2. `tree_preorder` - Parcours racine, gauche, droite
3. `tree_postorder` - Parcours gauche, droite, racine
4. `tree_level_order` - Parcours par niveaux (BFS avec queue)
5. `tree_morris_inorder` - Inorder sans espace supplementaire
6. `tree_height` - Hauteur de l'arbre (nombre d'aretes du chemin le plus long)
7. `tree_depth` - Profondeur d'un noeud (distance depuis la racine)
8. `tree_lca` - Plus petit ancetre commun de deux noeuds

**Exemples:**
```
Arbre:
        1
       / \
      2   3
     / \   \
    4   5   6

tree_inorder:    [4, 2, 5, 1, 3, 6]
tree_preorder:   [1, 2, 4, 5, 3, 6]
tree_postorder:  [4, 5, 2, 6, 3, 1]
tree_level_order:[1, 2, 3, 4, 5, 6]

tree_height(root):     2
tree_depth(root, 4):   2
tree_depth(root, 1):   0
tree_lca(root, 4, 5):  noeud avec valeur 2
tree_lca(root, 4, 6):  noeud avec valeur 1
```

### 1.3 Prototype

```c
// tree_traversal.h
#ifndef TREE_TRAVERSAL_H
#define TREE_TRAVERSAL_H

typedef struct s_tree_node {
    int                  value;
    struct s_tree_node  *left;
    struct s_tree_node  *right;
} t_tree_node;

// Creation et liberation
t_tree_node *tree_create_node(int value);
void         tree_free(t_tree_node *root);

// Parcours recursifs
int  tree_inorder(t_tree_node *root, int *result, int max_size);
int  tree_preorder(t_tree_node *root, int *result, int max_size);
int  tree_postorder(t_tree_node *root, int *result, int max_size);

// Parcours BFS
int  tree_level_order(t_tree_node *root, int *result, int max_size);

// Morris traversal
int  tree_morris_inorder(t_tree_node *root, int *result, int max_size);

// Proprietes
int  tree_height(t_tree_node *root);
int  tree_depth(t_tree_node *root, int value);

// LCA
t_tree_node *tree_lca(t_tree_node *root, int val1, int val2);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | tree_inorder on sample tree | [4,2,5,1,3,6] | 10 |
| T02 | tree_preorder on sample tree | [1,2,4,5,3,6] | 10 |
| T03 | tree_postorder on sample tree | [4,5,2,6,3,1] | 10 |
| T04 | tree_level_order on sample tree | [1,2,3,4,5,6] | 15 |
| T05 | tree_morris_inorder on sample tree | [4,2,5,1,3,6] | 15 |
| T06 | tree_height(root) | 2 | 10 |
| T07 | tree_depth(root, 4) | 2 | 10 |
| T08 | tree_lca(root, 4, 5) | node with value 2 | 10 |
| T09 | edge cases (NULL, single node) | handled | 10 |

### 4.3 Solution de reference

```c
#include <stdlib.h>
#include "tree_traversal.h"

t_tree_node *tree_create_node(int value)
{
    t_tree_node *node = malloc(sizeof(t_tree_node));
    if (!node)
        return NULL;
    node->value = value;
    node->left = NULL;
    node->right = NULL;
    return node;
}

void tree_free(t_tree_node *root)
{
    if (!root)
        return;
    tree_free(root->left);
    tree_free(root->right);
    free(root);
}

// Helper pour inorder
static int inorder_helper(t_tree_node *node, int *result, int idx, int max_size)
{
    if (!node || idx >= max_size)
        return idx;

    idx = inorder_helper(node->left, result, idx, max_size);
    if (idx < max_size)
        result[idx++] = node->value;
    idx = inorder_helper(node->right, result, idx, max_size);

    return idx;
}

int tree_inorder(t_tree_node *root, int *result, int max_size)
{
    if (!root || !result || max_size <= 0)
        return 0;
    return inorder_helper(root, result, 0, max_size);
}

// Helper pour preorder
static int preorder_helper(t_tree_node *node, int *result, int idx, int max_size)
{
    if (!node || idx >= max_size)
        return idx;

    result[idx++] = node->value;
    idx = preorder_helper(node->left, result, idx, max_size);
    idx = preorder_helper(node->right, result, idx, max_size);

    return idx;
}

int tree_preorder(t_tree_node *root, int *result, int max_size)
{
    if (!root || !result || max_size <= 0)
        return 0;
    return preorder_helper(root, result, 0, max_size);
}

// Helper pour postorder
static int postorder_helper(t_tree_node *node, int *result, int idx, int max_size)
{
    if (!node || idx >= max_size)
        return idx;

    idx = postorder_helper(node->left, result, idx, max_size);
    idx = postorder_helper(node->right, result, idx, max_size);
    if (idx < max_size)
        result[idx++] = node->value;

    return idx;
}

int tree_postorder(t_tree_node *root, int *result, int max_size)
{
    if (!root || !result || max_size <= 0)
        return 0;
    return postorder_helper(root, result, 0, max_size);
}

// Level order avec une queue manuelle
int tree_level_order(t_tree_node *root, int *result, int max_size)
{
    if (!root || !result || max_size <= 0)
        return 0;

    // Queue simple avec tableau
    t_tree_node **queue = malloc(max_size * sizeof(t_tree_node *));
    if (!queue)
        return 0;

    int front = 0;
    int rear = 0;
    int count = 0;

    queue[rear++] = root;

    while (front < rear && count < max_size)
    {
        t_tree_node *current = queue[front++];
        result[count++] = current->value;

        if (current->left && rear < max_size)
            queue[rear++] = current->left;
        if (current->right && rear < max_size)
            queue[rear++] = current->right;
    }

    free(queue);
    return count;
}

// Morris Inorder Traversal - O(1) espace supplementaire
int tree_morris_inorder(t_tree_node *root, int *result, int max_size)
{
    if (!root || !result || max_size <= 0)
        return 0;

    int count = 0;
    t_tree_node *current = root;

    while (current && count < max_size)
    {
        if (!current->left)
        {
            // Pas de sous-arbre gauche: visiter et aller a droite
            result[count++] = current->value;
            current = current->right;
        }
        else
        {
            // Trouver le predecesseur inorder
            t_tree_node *predecessor = current->left;
            while (predecessor->right && predecessor->right != current)
                predecessor = predecessor->right;

            if (!predecessor->right)
            {
                // Creer le lien temporaire
                predecessor->right = current;
                current = current->left;
            }
            else
            {
                // Supprimer le lien temporaire
                predecessor->right = NULL;
                result[count++] = current->value;
                current = current->right;
            }
        }
    }

    return count;
}

// Hauteur: nombre d'aretes sur le plus long chemin
int tree_height(t_tree_node *root)
{
    if (!root)
        return -1;  // Convention: arbre vide = hauteur -1

    int left_height = tree_height(root->left);
    int right_height = tree_height(root->right);

    return 1 + (left_height > right_height ? left_height : right_height);
}

// Profondeur d'un noeud avec une valeur donnee
static int depth_helper(t_tree_node *node, int value, int current_depth)
{
    if (!node)
        return -1;  // Non trouve

    if (node->value == value)
        return current_depth;

    int left_result = depth_helper(node->left, value, current_depth + 1);
    if (left_result != -1)
        return left_result;

    return depth_helper(node->right, value, current_depth + 1);
}

int tree_depth(t_tree_node *root, int value)
{
    return depth_helper(root, value, 0);
}

// Helper pour verifier si une valeur existe dans le sous-arbre
static int exists_in_tree(t_tree_node *root, int value)
{
    if (!root)
        return 0;
    if (root->value == value)
        return 1;
    return exists_in_tree(root->left, value) || exists_in_tree(root->right, value);
}

// Lowest Common Ancestor
t_tree_node *tree_lca(t_tree_node *root, int val1, int val2)
{
    if (!root)
        return NULL;

    // Si la racine est l'une des valeurs, c'est le LCA
    if (root->value == val1 || root->value == val2)
        return root;

    // Chercher dans les sous-arbres
    t_tree_node *left_lca = tree_lca(root->left, val1, val2);
    t_tree_node *right_lca = tree_lca(root->right, val1, val2);

    // Si trouve dans les deux sous-arbres, root est le LCA
    if (left_lca && right_lca)
        return root;

    // Sinon retourner celui qui n'est pas NULL
    return left_lca ? left_lca : right_lca;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: inorder avec mauvais ordre (gauche et droite inverses)
static int inorder_helper_mutant(t_tree_node *node, int *result, int idx, int max_size)
{
    if (!node || idx >= max_size)
        return idx;

    idx = inorder_helper_mutant(node->right, result, idx, max_size);  // ERREUR: droite d'abord
    if (idx < max_size)
        result[idx++] = node->value;
    idx = inorder_helper_mutant(node->left, result, idx, max_size);   // ERREUR: gauche ensuite

    return idx;
    // Produit: [6, 3, 1, 5, 2, 4] au lieu de [4, 2, 5, 1, 3, 6]
}

// MUTANT 2: level_order sans gestion de la queue
int tree_level_order_mutant(t_tree_node *root, int *result, int max_size)
{
    if (!root || !result || max_size <= 0)
        return 0;

    t_tree_node **queue = malloc(max_size * sizeof(t_tree_node *));
    int rear = 0;
    int count = 0;

    queue[rear++] = root;

    while (rear > 0 && count < max_size)  // ERREUR: utilise rear au lieu de front < rear
    {
        t_tree_node *current = queue[--rear];  // ERREUR: LIFO au lieu de FIFO -> devient DFS!
        result[count++] = current->value;

        if (current->left && rear < max_size)
            queue[rear++] = current->left;
        if (current->right && rear < max_size)
            queue[rear++] = current->right;
    }

    free(queue);
    return count;
    // Produit DFS preorder: [1, 3, 6, 2, 5, 4] au lieu de BFS: [1, 2, 3, 4, 5, 6]
}

// MUTANT 3: Morris traversal sans restauration des liens
int tree_morris_inorder_mutant(t_tree_node *root, int *result, int max_size)
{
    int count = 0;
    t_tree_node *current = root;

    while (current && count < max_size)
    {
        if (!current->left)
        {
            result[count++] = current->value;
            current = current->right;
        }
        else
        {
            t_tree_node *predecessor = current->left;
            while (predecessor->right && predecessor->right != current)
                predecessor = predecessor->right;

            predecessor->right = current;  // ERREUR: toujours creer le lien
            // Jamais supprimer -> boucle infinie!
            current = current->left;
        }
    }
    return count;
    // Corrompt l'arbre et peut boucler indefiniment
}

// MUTANT 4: tree_height retourne nombre de noeuds au lieu d'aretes
int tree_height_mutant(t_tree_node *root)
{
    if (!root)
        return 0;  // ERREUR: devrait etre -1 pour la convention aretes

    int left_height = tree_height_mutant(root->left);
    int right_height = tree_height_mutant(root->right);

    return 1 + (left_height > right_height ? left_height : right_height);
    // Retourne 3 au lieu de 2 pour l'exemple
}

// MUTANT 5: LCA sans verifier les deux cotes
t_tree_node *tree_lca_mutant(t_tree_node *root, int val1, int val2)
{
    if (!root)
        return NULL;

    if (root->value == val1 || root->value == val2)
        return root;

    t_tree_node *left_lca = tree_lca_mutant(root->left, val1, val2);

    if (left_lca)
        return left_lca;  // ERREUR: retourne immediatement sans chercher a droite

    return tree_lca_mutant(root->right, val1, val2);
    // Echoue pour lca(4, 6) -> retourne 4 au lieu de 1
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **parcours d'arbres binaires** sont fondamentaux:

1. **Recursion sur structures** - L'arbre est une structure recursive naturelle
2. **DFS vs BFS** - Profondeur d'abord vs largeur d'abord
3. **Espace memoire** - Stack implicite vs queue explicite
4. **Morris Traversal** - Technique avancee O(1) espace

### 5.3 Visualisation ASCII

```
ARBRE EXEMPLE:
              1
            /   \
           2     3
          / \     \
         4   5     6

==========================================
INORDER (Gauche -> Racine -> Droite)
==========================================

Ordre de visite:
    4 -> 2 -> 5 -> 1 -> 3 -> 6

Trace d'execution:
    inorder(1)
      |-> inorder(2)
      |     |-> inorder(4)
      |     |     |-> inorder(NULL) return
      |     |     VISITE 4
      |     |     |-> inorder(NULL) return
      |     VISITE 2
      |     |-> inorder(5)
      |           |-> inorder(NULL) return
      |           VISITE 5
      |           |-> inorder(NULL) return
      VISITE 1
      |-> inorder(3)
            |-> inorder(NULL) return
            VISITE 3
            |-> inorder(6)
                  |-> inorder(NULL) return
                  VISITE 6
                  |-> inorder(NULL) return

Resultat: [4, 2, 5, 1, 3, 6]

==========================================
PREORDER (Racine -> Gauche -> Droite)
==========================================

Ordre de visite:
    1 -> 2 -> 4 -> 5 -> 3 -> 6

    VISITE 1
      |-> VISITE 2
      |     |-> VISITE 4
      |     |-> VISITE 5
      |-> VISITE 3
            |-> VISITE 6

Resultat: [1, 2, 4, 5, 3, 6]

==========================================
POSTORDER (Gauche -> Droite -> Racine)
==========================================

Ordre de visite:
    4 -> 5 -> 2 -> 6 -> 3 -> 1

          VISITE 4
          VISITE 5
      VISITE 2
              VISITE 6
          VISITE 3
    VISITE 1

Resultat: [4, 5, 2, 6, 3, 1]

==========================================
LEVEL ORDER (BFS - Niveau par niveau)
==========================================

Niveau 0:    [1]           -> Visite: 1
Niveau 1:    [2, 3]        -> Visite: 2, 3
Niveau 2:    [4, 5, 6]     -> Visite: 4, 5, 6

Queue evolution:
    Initial:    [1]
    Dequeue 1:  [] -> Enqueue 2,3 -> [2, 3]
    Dequeue 2:  [3] -> Enqueue 4,5 -> [3, 4, 5]
    Dequeue 3:  [4, 5] -> Enqueue 6 -> [4, 5, 6]
    Dequeue 4:  [5, 6]
    Dequeue 5:  [6]
    Dequeue 6:  []

Resultat: [1, 2, 3, 4, 5, 6]

==========================================
MORRIS TRAVERSAL (Inorder sans stack)
==========================================

Idee: Utiliser les pointeurs NULL des feuilles
      pour creer des liens temporaires vers le successeur.

Etat initial:          Apres lien 4->2:       Apres visite 4:
      1                      1                      1
     / \                    / \                    / \
    2   3                  2   3                  2   3
   / \   \                / \   \                / \   \
  4   5   6              4   5   6              4   5   6
                          \                      |
                           2 (lien temporaire)   (lien supprime)

Principe:
1. Si pas d'enfant gauche -> visiter, aller a droite
2. Si enfant gauche existe:
   a. Trouver le predecesseur (rightmost du sous-arbre gauche)
   b. Si predecesseur.right == NULL: creer lien, aller a gauche
   c. Si predecesseur.right == current: supprimer lien, visiter, aller a droite

==========================================
TREE HEIGHT vs DEPTH
==========================================

              1        <- Depth 0, Height = 2
            /   \
           2     3     <- Depth 1
          / \     \
         4   5     6   <- Depth 2

Height(root) = 2 (aretes du plus long chemin: 1->2->4 ou 1->2->5 ou 1->3->6)
Height(node 2) = 1
Height(node 4) = 0

Depth(1) = 0  (racine)
Depth(2) = 1
Depth(4) = 2

==========================================
LOWEST COMMON ANCESTOR (LCA)
==========================================

              1
            /   \
           2     3
          / \     \
         4   5     6

LCA(4, 5) = 2    (4 et 5 sont dans le meme sous-arbre de 2)
LCA(4, 6) = 1    (4 dans sous-arbre gauche, 6 dans sous-arbre droit)
LCA(2, 4) = 2    (2 est ancetre de 4)
LCA(4, 4) = 4    (un noeud est son propre LCA)

Algorithme:
1. Si root == val1 ou val2, retourner root
2. Chercher LCA dans sous-arbre gauche
3. Chercher LCA dans sous-arbre droit
4. Si trouve des deux cotes -> root est le LCA
5. Sinon retourner le cote non-NULL
```

---

## SECTION 7 : QCM

### Question 1
Quel parcours d'arbre produit les noeuds dans l'ordre trie pour un BST (Binary Search Tree)?

A) Preorder
B) Postorder
C) Inorder
D) Level order
E) Morris preorder

**Reponse correcte: C**

*Explication: Dans un BST, les noeuds a gauche sont plus petits et ceux a droite sont plus grands. Le parcours inorder (gauche, racine, droite) visite donc les noeuds dans l'ordre croissant.*

### Question 2
Quelle est la complexite spatiale du Morris traversal par rapport aux parcours recursifs classiques?

A) Morris: O(n), Recursif: O(n)
B) Morris: O(h), Recursif: O(n)
C) Morris: O(1), Recursif: O(h)
D) Morris: O(log n), Recursif: O(1)
E) Morris: O(n), Recursif: O(h)

**Reponse correcte: C**

*Explication: Morris traversal utilise O(1) espace supplementaire en modifiant temporairement l'arbre (liens vers les predecesseurs). Les parcours recursifs utilisent O(h) espace pour la pile d'appels, ou h est la hauteur de l'arbre.*

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.24-a",
  "name": "tree_traversal",
  "language": "c",
  "language_version": "c17",
  "difficulty": 5,
  "xp_base": 175,
  "complexity": {
    "time": "O(n)",
    "space": "O(h)"
  },
  "files": ["tree_traversal.c", "tree_traversal.h"],
  "tests": {
    "inorder": "test_tree_inorder",
    "preorder": "test_tree_preorder",
    "postorder": "test_tree_postorder",
    "level_order": "test_tree_level_order",
    "morris": "test_morris_inorder",
    "height": "test_tree_height",
    "depth": "test_tree_depth",
    "lca": "test_tree_lca",
    "edge_cases": "test_edge_cases"
  },
  "tags": ["trees", "traversal", "recursion", "bfs", "dfs", "morris", "lca"],
  "prerequisites": ["recursion", "linked_list", "stack"]
}
```
