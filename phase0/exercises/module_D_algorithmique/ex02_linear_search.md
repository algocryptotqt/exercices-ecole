# Exercice D.0.2-a : linear_search

**Module :**
D.0.2 — Recherche Lineaire

**Concept :**
a-e — Sequential search, sentinel search, find first/last/all

**Difficulte :**
★★☆☆☆☆☆☆☆☆ (2/10)

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
90 min

**XP Base :**
100

**Complexite :**
T3 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `linear_search.c`
- `linear_search.h`

### 1.2 Consigne

Implementer differentes variantes de la recherche lineaire.

**Ta mission :**

```c
// Recherche simple - retourne index ou -1
int linear_search(int *arr, int n, int target);

// Recherche avec sentinelle (optimisation)
int sentinel_search(int *arr, int n, int target);

// Trouver premiere occurrence
int find_first(int *arr, int n, int target);

// Trouver derniere occurrence
int find_last(int *arr, int n, int target);

// Compter toutes les occurrences
int count_occurrences(int *arr, int n, int target);

// Trouver toutes les positions (retourne nombre trouve)
int find_all(int *arr, int n, int target, int *positions, int max_pos);

// Recherche dans tableau 2D
int search_2d(int **matrix, int rows, int cols, int target);

// Recherche de minimum et maximum
int find_min(int *arr, int n);
int find_max(int *arr, int n);
void find_min_max(int *arr, int n, int *min, int *max);
```

**Comportement:**

1. `linear_search({5,2,8,2,1}, 5, 2)` -> 1 (premier index)
2. `find_last({5,2,8,2,1}, 5, 2)` -> 3 (dernier index)
3. `count_occurrences({5,2,8,2,1}, 5, 2)` -> 2
4. `find_min({5,2,8,1,9}, 5)` -> 1

**Exemples:**
```
linear_search({5, 2, 8, 2, 1}, target=2):
  i=0: 5 != 2, continue
  i=1: 2 == 2, return 1

sentinel_search optimization:
  - Place target at end (sentinel)
  - Loop without bounds check
  - Check if found position is original or sentinel

find_all({1,2,3,2,4,2}, target=2):
  positions = {1, 3, 5}
  return 3 (nombre trouve)
```

### 1.3 Prototype

```c
// linear_search.h
#ifndef LINEAR_SEARCH_H
#define LINEAR_SEARCH_H

int linear_search(int *arr, int n, int target);
int sentinel_search(int *arr, int n, int target);
int find_first(int *arr, int n, int target);
int find_last(int *arr, int n, int target);
int count_occurrences(int *arr, int n, int target);
int find_all(int *arr, int n, int target, int *positions, int max_pos);
int search_2d(int **matrix, int rows, int cols, int target);
int find_min(int *arr, int n);
int find_max(int *arr, int n);
void find_min_max(int *arr, int n, int *min, int *max);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | linear_search found | correct index | 10 |
| T02 | linear_search not found | -1 | 10 |
| T03 | find_first/last | correct indices | 15 |
| T04 | count_occurrences | correct count | 10 |
| T05 | find_all | all positions | 15 |
| T06 | find_min/max | correct values | 15 |
| T07 | empty array | handled | 10 |
| T08 | sentinel_search | same as linear | 15 |

### 4.3 Solution de reference

```c
#include "linear_search.h"
#include <limits.h>

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
    if (n <= 0)
        return -1;

    // Sauvegarder le dernier element
    int last = arr[n - 1];
    arr[n - 1] = target;  // Sentinelle

    int i = 0;
    while (arr[i] != target)
        i++;

    // Restaurer
    arr[n - 1] = last;

    // Verifier si trouve avant la sentinelle
    if (i < n - 1 || last == target)
        return i;
    return -1;
}

int find_first(int *arr, int n, int target)
{
    for (int i = 0; i < n; i++)
    {
        if (arr[i] == target)
            return i;
    }
    return -1;
}

int find_last(int *arr, int n, int target)
{
    for (int i = n - 1; i >= 0; i--)
    {
        if (arr[i] == target)
            return i;
    }
    return -1;
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

int find_all(int *arr, int n, int target, int *positions, int max_pos)
{
    int found = 0;
    for (int i = 0; i < n && found < max_pos; i++)
    {
        if (arr[i] == target)
        {
            positions[found] = i;
            found++;
        }
    }
    return found;
}

int search_2d(int **matrix, int rows, int cols, int target)
{
    for (int i = 0; i < rows; i++)
    {
        for (int j = 0; j < cols; j++)
        {
            if (matrix[i][j] == target)
                return i * cols + j;  // Index linearise
        }
    }
    return -1;
}

int find_min(int *arr, int n)
{
    if (n <= 0)
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
    if (n <= 0)
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
    if (n <= 0)
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
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Off-by-one dans linear_search
int linear_search(int *arr, int n, int target)
{
    for (int i = 0; i <= n; i++)  // <= au lieu de <
    {
        if (arr[i] == target)
            return i;
    }
    return -1;
}

// MUTANT 2: find_last parcourt dans le mauvais sens
int find_last(int *arr, int n, int target)
{
    for (int i = 0; i < n; i++)  // Devrait aller de n-1 vers 0
    {
        if (arr[i] == target)
            return i;  // Retourne first, pas last
    }
    return -1;
}

// MUTANT 3: count_occurrences incremente mal
int count_occurrences(int *arr, int n, int target)
{
    int count = 0;
    for (int i = 0; i < n; i++)
    {
        if (arr[i] == target)
            count = 1;  // = au lieu de ++
    }
    return count;
}

// MUTANT 4: sentinel_search ne restaure pas
int sentinel_search(int *arr, int n, int target)
{
    int last = arr[n - 1];
    arr[n - 1] = target;

    int i = 0;
    while (arr[i] != target)
        i++;

    // Oublie de restaurer arr[n-1] = last;

    if (i < n - 1 || last == target)
        return i;
    return -1;
}

// MUTANT 5: find_min ne gere pas tableau vide
int find_min(int *arr, int n)
{
    int min = arr[0];  // Crash si n == 0
    for (int i = 1; i < n; i++)
    {
        if (arr[i] < min)
            min = arr[i];
    }
    return min;
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

La **recherche lineaire**:

1. **Simple et universelle** - Fonctionne sur tout tableau
2. **O(n)** - Parcourt tous les elements
3. **Variantes** - First, last, all, count
4. **Sentinel** - Optimisation pour eviter bounds check

### 5.3 Visualisation ASCII

```
RECHERCHE LINEAIRE de target=8:

arr = [5, 2, 8, 1, 9]
       ^
       |
       i=0: 5 != 8

arr = [5, 2, 8, 1, 9]
          ^
          |
          i=1: 2 != 8

arr = [5, 2, 8, 1, 9]
             ^
             |
             i=2: 8 == 8 -> FOUND!
             return 2

SENTINEL SEARCH:
Original: [5, 2, 3, 1, 9]  target=7
With sentinel: [5, 2, 3, 1, 7]  <- 7 remplace 9
               Loop jusqu'a trouver 7
               i=4: trouve, mais c'est la sentinelle
               -> NOT FOUND
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite de la recherche lineaire ?

A) O(1)
B) O(log n)
C) O(n)
D) O(n^2)
E) O(n log n)

**Reponse correcte: C**

### Question 2
Quel est l'avantage de la recherche avec sentinelle ?

A) Complexite reduite
B) Moins de comparaisons de bornes
C) Fonctionne sur tableaux non tries
D) Trouve tous les elements
E) Aucun avantage

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.2-a",
  "name": "linear_search",
  "language": "c",
  "language_version": "c17",
  "files": ["linear_search.c", "linear_search.h"],
  "tests": {
    "basic": "linear_search_tests",
    "variants": "search_variants_tests",
    "edge": "edge_case_tests"
  }
}
```
