# Exercice D.0.20-a : search_basics

**Module :**
D.0.20 — Recherche Basique

**Concept :**
a-d — Linear search, sentinel search, two pointers, comparisons

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.14 (arrays)

**Domaines :**
Algo

**Duree estimee :**
120 min

**XP Base :**
180

**Complexite :**
T2 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `search_basics.c`
- `search_basics.h`

### 1.2 Consigne

Implementer des algorithmes de recherche lineaire.

**Ta mission :**

```c
// Recherche lineaire simple
int linear_search(int *arr, int n, int target);

// Recherche avec sentinelle (optimisation)
int sentinel_search(int *arr, int n, int target);

// Trouver le minimum
int find_min(int *arr, int n);

// Trouver le maximum
int find_max(int *arr, int n);

// Trouver min et max en une passe
void find_min_max(int *arr, int n, int *min, int *max);

// Compter les occurrences
int count_occurrences(int *arr, int n, int target);

// Trouver tous les indices
int *find_all_indices(int *arr, int n, int target, int *count);

// Recherche dans tableau 2D
int search_2d(int **matrix, int rows, int cols, int target, int *row, int *col);
```

**Comportement:**

1. `linear_search({5,2,8,1}, 4, 8)` -> 2
2. `linear_search({5,2,8,1}, 4, 9)` -> -1
3. `find_min({5,2,8,1}, 4)` -> 1 (valeur minimum)
4. `count_occurrences({1,2,1,3,1}, 5, 1)` -> 3

**Exemples:**
```
Linear Search de 8 dans {5, 2, 8, 1}:
Index 0: 5 != 8, continue
Index 1: 2 != 8, continue
Index 2: 8 == 8, TROUVE! retourne 2

Sentinel Search (optimisation):
- Place target a la fin du tableau
- Parcourt sans verifier les bornes
- Verifie a la fin si c'est le vrai element
```

### 1.3 Prototype

```c
// search_basics.h
#ifndef SEARCH_BASICS_H
#define SEARCH_BASICS_H

int linear_search(int *arr, int n, int target);
int sentinel_search(int *arr, int n, int target);
int find_min(int *arr, int n);
int find_max(int *arr, int n);
void find_min_max(int *arr, int n, int *min, int *max);
int count_occurrences(int *arr, int n, int target);
int *find_all_indices(int *arr, int n, int target, int *count);
int search_2d(int **matrix, int rows, int cols, int target, int *row, int *col);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | linear_search found | correct index | 15 |
| T02 | linear_search not found | -1 | 10 |
| T03 | find_min | minimum value | 15 |
| T04 | find_max | maximum value | 15 |
| T05 | count_occurrences | correct count | 15 |
| T06 | find_all_indices | all indices | 15 |
| T07 | empty array | handled | 15 |

### 4.3 Solution de reference

```c
#include <stdlib.h>
#include <limits.h>
#include "search_basics.h"

int linear_search(int *arr, int n, int target)
{
    for (int i = 0; i < n; i++)
    {
        if (arr[i] == target)
            return i;
    }
    return -1;
}

int sentinel_search(int *arr, int n, int target)
{
    if (n == 0)
        return -1;

    // Sauvegarder le dernier element
    int last = arr[n - 1];

    // Placer la sentinelle
    arr[n - 1] = target;

    int i = 0;
    while (arr[i] != target)
        i++;

    // Restaurer le dernier element
    arr[n - 1] = last;

    // Verifier si trouve
    if (i < n - 1 || arr[n - 1] == target)
        return i;

    return -1;
}

int find_min(int *arr, int n)
{
    if (n == 0)
        return INT_MAX;

    int min = arr[0];
    for (int i = 1; i < n; i++)
    {
        if (arr[i] < min)
            min = arr[i];
    }
    return min;
}

int find_max(int *arr, int n)
{
    if (n == 0)
        return INT_MIN;

    int max = arr[0];
    for (int i = 1; i < n; i++)
    {
        if (arr[i] > max)
            max = arr[i];
    }
    return max;
}

void find_min_max(int *arr, int n, int *min, int *max)
{
    if (n == 0)
    {
        *min = INT_MAX;
        *max = INT_MIN;
        return;
    }

    *min = arr[0];
    *max = arr[0];

    for (int i = 1; i < n; i++)
    {
        if (arr[i] < *min)
            *min = arr[i];
        if (arr[i] > *max)
            *max = arr[i];
    }
}

int count_occurrences(int *arr, int n, int target)
{
    int count = 0;
    for (int i = 0; i < n; i++)
    {
        if (arr[i] == target)
            count++;
    }
    return count;
}

int *find_all_indices(int *arr, int n, int target, int *count)
{
    *count = count_occurrences(arr, n, target);

    if (*count == 0)
        return NULL;

    int *indices = malloc(*count * sizeof(int));
    int idx = 0;

    for (int i = 0; i < n; i++)
    {
        if (arr[i] == target)
            indices[idx++] = i;
    }

    return indices;
}

int search_2d(int **matrix, int rows, int cols, int target, int *row, int *col)
{
    for (int i = 0; i < rows; i++)
    {
        for (int j = 0; j < cols; j++)
        {
            if (matrix[i][j] == target)
            {
                *row = i;
                *col = j;
                return 1;
            }
        }
    }

    *row = -1;
    *col = -1;
    return 0;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: linear_search commence a 1
int linear_search(int *arr, int n, int target)
{
    for (int i = 1; i < n; i++)  // Commence a 1, rate arr[0]
    {
        if (arr[i] == target)
            return i;
    }
    return -1;
}

// MUTANT 2: sentinel_search ne restaure pas
int sentinel_search(int *arr, int n, int target)
{
    int last = arr[n - 1];
    arr[n - 1] = target;
    int i = 0;
    while (arr[i] != target)
        i++;
    // Oublie de restaurer arr[n-1] = last
    return (i < n - 1 || last == target) ? i : -1;
}

// MUTANT 3: find_min initialise a 0
int find_min(int *arr, int n)
{
    int min = 0;  // Devrait etre arr[0]
    for (int i = 0; i < n; i++)
    {
        if (arr[i] < min)
            min = arr[i];
    }
    return min;  // Retourne 0 si tous positifs
}

// MUTANT 4: count_occurrences retourne premier index
int count_occurrences(int *arr, int n, int target)
{
    for (int i = 0; i < n; i++)
    {
        if (arr[i] == target)
            return i;  // Retourne index, pas count
    }
    return 0;
}

// MUTANT 5: find_all_indices memory leak potentiel
int *find_all_indices(int *arr, int n, int target, int *count)
{
    int *indices = malloc(n * sizeof(int));  // Alloue trop
    // *count pas initialise
    // ...
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

La **recherche lineaire**:

1. **Simplicite** - Parcourir tous les elements
2. **Pas de precondition** - Fonctionne sur tableau non trie
3. **O(n)** - Proportionnel a la taille
4. **Sentinelle** - Optimisation pour eviter check de bornes

### 5.3 Visualisation ASCII

```
LINEAR SEARCH de 8 dans [5, 2, 8, 1]:

[5, 2, 8, 1]
 ^
 i=0: 5 != 8, continue

[5, 2, 8, 1]
    ^
 i=1: 2 != 8, continue

[5, 2, 8, 1]
       ^
 i=2: 8 == 8, TROUVE! return 2

SENTINEL SEARCH:

Original:    [5, 2, 8, 1]
With sentinel:[5, 2, 8, TARGET]  <- Garantit de trouver

while (arr[i] != TARGET)  <- Pas de check i < n!
    i++;

Si i == n-1 et original[n-1] != target -> pas trouve
Sinon -> trouve a i
```

### 5.5 Quand utiliser

```
RECHERCHE LINEAIRE:
- Petit tableau (< 100 elements)
- Tableau non trie
- Recherche unique (pas repetee)
- Donnees en streaming

RECHERCHE BINAIRE (preferable si):
- Grand tableau
- Tableau trie
- Recherches multiples
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite de la recherche lineaire ?

A) O(1)
B) O(log n)
C) O(n)
D) O(n log n)
E) O(n^2)

**Reponse correcte: C**

### Question 2
Avantage de la recherche sentinelle ?

A) Meilleure complexite
B) Moins de comparaisons dans la boucle
C) Fonctionne sur tableau non trie
D) Utilise moins de memoire
E) Plus stable

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.20-a",
  "name": "search_basics",
  "language": "c",
  "language_version": "c17",
  "files": ["search_basics.c", "search_basics.h"],
  "tests": {
    "linear": "linear_search_tests",
    "minmax": "minmax_tests"
  }
}
```
