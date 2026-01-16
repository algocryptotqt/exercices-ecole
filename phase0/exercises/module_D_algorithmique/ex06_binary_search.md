# Exercice D.0.6-a : binary_search

**Module :**
D.0.6 — Recherche Binaire

**Concept :**
a-d — Binary search, lower_bound, upper_bound, O(log n)

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
D.0.5 (sorting)

**Domaines :**
Algo

**Duree estimee :**
150 min

**XP Base :**
220

**Complexite :**
T3 O(log n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `binary_search.c`
- `binary_search.h`

### 1.2 Consigne

Implementer des fonctions de recherche binaire.

**Ta mission :**

```c
// Recherche binaire classique
// Retourne l'index si trouve, -1 sinon
int binary_search(int *arr, int size, int target);

// Recherche binaire recursive
int binary_search_recursive(int *arr, int left, int right, int target);

// Lower bound: premier element >= target
int lower_bound(int *arr, int size, int target);

// Upper bound: premier element > target
int upper_bound(int *arr, int size, int target);

// Compter les occurrences d'un element
int count_occurrences(int *arr, int size, int target);

// Trouver le point d'insertion
int find_insert_position(int *arr, int size, int target);
```

**Comportement:**

1. `binary_search({1,3,5,7,9}, 5, 5)` -> 2
2. `binary_search({1,3,5,7,9}, 5, 4)` -> -1
3. `lower_bound({1,2,2,3}, 4, 2)` -> 1
4. `upper_bound({1,2,2,3}, 4, 2)` -> 3
5. `count_occurrences({1,2,2,2,3}, 5, 2)` -> 3

**Exemples:**
```
arr = {1, 3, 5, 7, 9, 11, 13}
       0  1  2  3  4  5   6

binary_search(arr, 7, 7)  -> 3
binary_search(arr, 7, 8)  -> -1

arr = {1, 2, 2, 2, 3, 4}
       0  1  2  3  4  5

lower_bound(arr, 6, 2)    -> 1 (premier 2)
upper_bound(arr, 6, 2)    -> 4 (premier apres 2)
count_occurrences(arr, 6, 2) -> 3

find_insert_position({1,3,5}, 3, 4) -> 2
```

### 1.3 Prototype

```c
// binary_search.h
#ifndef BINARY_SEARCH_H
#define BINARY_SEARCH_H

int binary_search(int *arr, int size, int target);
int binary_search_recursive(int *arr, int left, int right, int target);
int lower_bound(int *arr, int size, int target);
int upper_bound(int *arr, int size, int target);
int count_occurrences(int *arr, int size, int target);
int find_insert_position(int *arr, int size, int target);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | search found | correct index | 15 |
| T02 | search not found | -1 | 10 |
| T03 | lower_bound | first >= | 15 |
| T04 | upper_bound | first > | 15 |
| T05 | count_occurrences | correct count | 15 |
| T06 | empty array | handled | 10 |
| T07 | single element | correct | 10 |
| T08 | all same elements | correct | 10 |

### 4.3 Solution de reference

```c
#include "binary_search.h"

int binary_search(int *arr, int size, int target)
{
    int left = 0;
    int right = size - 1;

    while (left <= right)
    {
        int mid = left + (right - left) / 2;  // Evite overflow

        if (arr[mid] == target)
            return mid;
        else if (arr[mid] < target)
            left = mid + 1;
        else
            right = mid - 1;
    }

    return -1;
}

int binary_search_recursive(int *arr, int left, int right, int target)
{
    if (left > right)
        return -1;

    int mid = left + (right - left) / 2;

    if (arr[mid] == target)
        return mid;
    else if (arr[mid] < target)
        return binary_search_recursive(arr, mid + 1, right, target);
    else
        return binary_search_recursive(arr, left, mid - 1, target);
}

int lower_bound(int *arr, int size, int target)
{
    int left = 0;
    int right = size;

    while (left < right)
    {
        int mid = left + (right - left) / 2;

        if (arr[mid] < target)
            left = mid + 1;
        else
            right = mid;
    }

    return left;
}

int upper_bound(int *arr, int size, int target)
{
    int left = 0;
    int right = size;

    while (left < right)
    {
        int mid = left + (right - left) / 2;

        if (arr[mid] <= target)
            left = mid + 1;
        else
            right = mid;
    }

    return left;
}

int count_occurrences(int *arr, int size, int target)
{
    int lb = lower_bound(arr, size, target);
    int ub = upper_bound(arr, size, target);
    return ub - lb;
}

int find_insert_position(int *arr, int size, int target)
{
    return lower_bound(arr, size, target);
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Overflow dans le calcul de mid
int binary_search(int *arr, int size, int target)
{
    int left = 0, right = size - 1;
    while (left <= right)
    {
        int mid = (left + right) / 2;  // Overflow si left+right > INT_MAX!
        // ...
    }
}

// MUTANT 2: Condition de boucle incorrecte
int binary_search(int *arr, int size, int target)
{
    int left = 0, right = size - 1;
    while (left < right)  // Devrait etre <=, rate le cas left==right
    {
        // ...
    }
}

// MUTANT 3: lower_bound utilise <= au lieu de <
int lower_bound(int *arr, int size, int target)
{
    int left = 0, right = size;
    while (left < right)
    {
        int mid = left + (right - left) / 2;
        if (arr[mid] <= target)  // Devrait etre <
            left = mid + 1;
        else
            right = mid;
    }
    return left;  // Retourne upper_bound!
}

// MUTANT 4: Off-by-one dans right
int binary_search(int *arr, int size, int target)
{
    int left = 0;
    int right = size;  // Devrait etre size - 1
    while (left <= right)
    {
        int mid = left + (right - left) / 2;
        // arr[mid] peut etre hors limites!
    }
}

// MUTANT 5: Recursion infinie
int binary_search_recursive(int *arr, int left, int right, int target)
{
    if (left > right)
        return -1;
    int mid = left + (right - left) / 2;
    if (arr[mid] == target)
        return mid;
    else if (arr[mid] < target)
        return binary_search_recursive(arr, mid, right, target);  // mid au lieu de mid+1
    else
        return binary_search_recursive(arr, left, mid, target);  // mid au lieu de mid-1
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

La **recherche binaire**:

1. **Precondition** - Le tableau DOIT etre trie
2. **Diviser pour regner** - On divise l'espace de recherche par 2 a chaque iteration
3. **Complexite O(log n)** - 1 million d'elements = ~20 comparaisons max
4. **Variantes** - lower_bound, upper_bound pour les doublons

### 5.3 Visualisation ASCII

```
Recherche de 7 dans {1, 3, 5, 7, 9, 11, 13}

Iteration 1:
[1  3  5  7  9  11  13]
 ^        ^          ^
left     mid       right
mid=3, arr[3]=7, TROUVE!

Recherche de 6:
[1  3  5  7  9  11  13]
 ^        ^          ^
left     mid       right
arr[3]=7 > 6, chercher a gauche

[1  3  5]
 ^  ^  ^
left mid right
arr[1]=3 < 6, chercher a droite

[5]
 ^
left=mid=right
arr[2]=5 < 6, left = mid+1

left > right -> NON TROUVE, return -1

LOWER_BOUND vs UPPER_BOUND:
arr = {1, 2, 2, 2, 3}
          ^     ^
          |     |
    lower_bound upper_bound
          (1)     (4)
```

### 5.5 Piege du calcul de mid

```c
// DANGEREUX pour grands tableaux:
int mid = (left + right) / 2;
// Si left = 2 milliards et right = 2 milliards
// left + right = 4 milliards > INT_MAX = overflow!

// CORRECT:
int mid = left + (right - left) / 2;
// Calcul intermediate toujours < right, pas d'overflow
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite temporelle de la recherche binaire ?

A) O(1)
B) O(log n)
C) O(n)
D) O(n log n)
E) O(n^2)

**Reponse correcte: B**

### Question 2
Que retourne lower_bound({1,2,2,3}, 4, 2) ?

A) 0
B) 1
C) 2
D) 3
E) -1

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.6-a",
  "name": "binary_search",
  "language": "c",
  "language_version": "c17",
  "files": ["binary_search.c", "binary_search.h"],
  "tests": {
    "search": "binary_search_tests",
    "bounds": "lower_upper_bound_tests"
  }
}
```
