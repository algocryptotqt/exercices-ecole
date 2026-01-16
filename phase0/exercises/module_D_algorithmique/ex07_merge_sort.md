# Exercice D.0.7-a : merge_sort

**Module :**
D.0.7 — Tri Fusion

**Concept :**
a-d — Divide and conquer, merge operation, stable sort, O(n log n)

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
D.0.6 (recursion)

**Domaines :**
Algo

**Duree estimee :**
180 min

**XP Base :**
250

**Complexite :**
T4 O(n log n) x S3 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `merge_sort.c`
- `merge_sort.h`

### 1.2 Consigne

Implementer le tri fusion (merge sort).

**Ta mission :**

```c
// Fusionner deux sous-tableaux tries
void merge(int *arr, int left, int mid, int right);

// Tri fusion recursif
void merge_sort(int *arr, int left, int right);

// Wrapper simple
void sort_array(int *arr, int size);

// Version iterative (bottom-up)
void merge_sort_iterative(int *arr, int size);

// Compter le nombre d'inversions pendant le tri
long count_inversions(int *arr, int size);
```

**Comportement:**

1. `sort_array({5,2,8,1,9}, 5)` -> {1,2,5,8,9}
2. `count_inversions({2,4,1,3,5}, 5)` -> 3 (inversions: (2,1), (4,1), (4,3))

**Exemples:**
```
Tri de {38, 27, 43, 3, 9, 82, 10}:

Diviser:
[38, 27, 43, 3, 9, 82, 10]
        /           \
[38, 27, 43, 3]  [9, 82, 10]
    /    \          /    \
[38, 27] [43, 3]  [9, 82] [10]
  /  \     /  \     /  \
[38][27] [43][3]  [9][82] [10]

Fusionner:
[27, 38] [3, 43]  [9, 82] [10]
    \    /            \    /
[3, 27, 38, 43]    [9, 10, 82]
        \            /
   [3, 9, 10, 27, 38, 43, 82]
```

### 1.3 Prototype

```c
// merge_sort.h
#ifndef MERGE_SORT_H
#define MERGE_SORT_H

void merge(int *arr, int left, int mid, int right);
void merge_sort(int *arr, int left, int right);
void sort_array(int *arr, int size);
void merge_sort_iterative(int *arr, int size);
long count_inversions(int *arr, int size);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | random array | sorted | 15 |
| T02 | already sorted | unchanged | 10 |
| T03 | reverse sorted | sorted | 10 |
| T04 | duplicates | stable sort | 15 |
| T05 | single element | unchanged | 5 |
| T06 | empty array | handled | 5 |
| T07 | inversions count | correct | 20 |
| T08 | iterative version | sorted | 20 |

### 4.3 Solution de reference

```c
#include <stdlib.h>
#include <string.h>
#include "merge_sort.h"

void merge(int *arr, int left, int mid, int right)
{
    int n1 = mid - left + 1;
    int n2 = right - mid;

    // Allouer tableaux temporaires
    int *L = malloc(n1 * sizeof(int));
    int *R = malloc(n2 * sizeof(int));

    // Copier les donnees
    for (int i = 0; i < n1; i++)
        L[i] = arr[left + i];
    for (int j = 0; j < n2; j++)
        R[j] = arr[mid + 1 + j];

    // Fusionner
    int i = 0, j = 0, k = left;

    while (i < n1 && j < n2)
    {
        if (L[i] <= R[j])  // <= pour stabilite
            arr[k++] = L[i++];
        else
            arr[k++] = R[j++];
    }

    // Copier les elements restants
    while (i < n1)
        arr[k++] = L[i++];
    while (j < n2)
        arr[k++] = R[j++];

    free(L);
    free(R);
}

void merge_sort(int *arr, int left, int right)
{
    if (left < right)
    {
        int mid = left + (right - left) / 2;

        merge_sort(arr, left, mid);
        merge_sort(arr, mid + 1, right);
        merge(arr, left, mid, right);
    }
}

void sort_array(int *arr, int size)
{
    if (size > 1)
        merge_sort(arr, 0, size - 1);
}

void merge_sort_iterative(int *arr, int size)
{
    for (int width = 1; width < size; width *= 2)
    {
        for (int i = 0; i < size; i += 2 * width)
        {
            int left = i;
            int mid = (i + width - 1 < size - 1) ? i + width - 1 : size - 1;
            int right = (i + 2 * width - 1 < size - 1) ? i + 2 * width - 1 : size - 1;

            if (mid < right)
                merge(arr, left, mid, right);
        }
    }
}

// Helper pour count_inversions
static long merge_count(int *arr, int left, int mid, int right)
{
    long inv = 0;
    int n1 = mid - left + 1;
    int n2 = right - mid;

    int *L = malloc(n1 * sizeof(int));
    int *R = malloc(n2 * sizeof(int));

    for (int i = 0; i < n1; i++)
        L[i] = arr[left + i];
    for (int j = 0; j < n2; j++)
        R[j] = arr[mid + 1 + j];

    int i = 0, j = 0, k = left;

    while (i < n1 && j < n2)
    {
        if (L[i] <= R[j])
            arr[k++] = L[i++];
        else
        {
            arr[k++] = R[j++];
            inv += (n1 - i);  // Tous les elements restants de L sont > R[j]
        }
    }

    while (i < n1)
        arr[k++] = L[i++];
    while (j < n2)
        arr[k++] = R[j++];

    free(L);
    free(R);
    return inv;
}

static long merge_sort_count(int *arr, int left, int right)
{
    long inv = 0;
    if (left < right)
    {
        int mid = left + (right - left) / 2;
        inv += merge_sort_count(arr, left, mid);
        inv += merge_sort_count(arr, mid + 1, right);
        inv += merge_count(arr, left, mid, right);
    }
    return inv;
}

long count_inversions(int *arr, int size)
{
    if (size <= 1)
        return 0;

    // Faire une copie pour ne pas modifier l'original
    int *copy = malloc(size * sizeof(int));
    memcpy(copy, arr, size * sizeof(int));

    long result = merge_sort_count(copy, 0, size - 1);

    free(copy);
    return result;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: merge non stable
void merge(int *arr, int left, int mid, int right)
{
    // ...
    if (L[i] < R[j])  // < au lieu de <=, perd la stabilite
        arr[k++] = L[i++];
    // ...
}

// MUTANT 2: merge_sort indices incorrects
void merge_sort(int *arr, int left, int right)
{
    if (left < right)
    {
        int mid = (left + right) / 2;
        merge_sort(arr, left, mid - 1);  // mid-1 au lieu de mid
        merge_sort(arr, mid, right);     // mid au lieu de mid+1
        // Resulte en recursion infinie ou tri incorrect
    }
}

// MUTANT 3: merge oublie de copier les restes
void merge(int *arr, int left, int mid, int right)
{
    // ...
    while (i < n1 && j < n2)
    {
        // fusion normale
    }
    // Manque: while (i < n1) et while (j < n2)
    // Elements restants non copies!
}

// MUTANT 4: Memory leak
void merge(int *arr, int left, int mid, int right)
{
    int *L = malloc(n1 * sizeof(int));
    int *R = malloc(n2 * sizeof(int));
    // ...
    // Oubli de free(L) et free(R)
}

// MUTANT 5: count_inversions modifie l'original
long count_inversions(int *arr, int size)
{
    // Oubli de faire une copie
    return merge_sort_count(arr, 0, size - 1);
    // arr est maintenant trie!
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Le **tri fusion (merge sort)**:

1. **Diviser pour regner** - Diviser le probleme, resoudre recursively, combiner
2. **Stabilite** - Les elements egaux gardent leur ordre relatif
3. **Complexite garantie** - O(n log n) dans TOUS les cas
4. **Compromis espace** - Necessite O(n) memoire supplementaire

### 5.3 Visualisation ASCII

```
MERGE de [3, 27] et [9, 10]:

L = [3, 27]    R = [9, 10]
     ^              ^
     i              j

Comparer L[0]=3 et R[0]=9: 3 < 9
Result = [3]

L = [3, 27]    R = [9, 10]
        ^           ^
        i           j

Comparer L[1]=27 et R[0]=9: 27 > 9
Result = [3, 9]

L = [3, 27]    R = [9, 10]
        ^              ^
        i              j

Comparer L[1]=27 et R[1]=10: 27 > 10
Result = [3, 9, 10]

L = [3, 27]    R = [9, 10]
        ^                  ^
        i                  j (fin)

Copier reste de L:
Result = [3, 9, 10, 27]
```

### 5.5 Comparaison avec autres tris

```
| Algorithme   | Temps moyen | Temps pire | Espace | Stable |
|--------------|-------------|------------|--------|--------|
| Merge Sort   | O(n log n)  | O(n log n) | O(n)   | Oui    |
| Quick Sort   | O(n log n)  | O(n^2)     | O(1)*  | Non    |
| Heap Sort    | O(n log n)  | O(n log n) | O(1)   | Non    |
| Insertion    | O(n^2)      | O(n^2)     | O(1)   | Oui    |

* Quick Sort: O(log n) pour la pile de recursion
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite spatiale du tri fusion ?

A) O(1)
B) O(log n)
C) O(n)
D) O(n log n)
E) O(n^2)

**Reponse correcte: C**

### Question 2
Le tri fusion est-il stable ?

A) Oui, toujours
B) Non, jamais
C) Seulement si implemente correctement (avec <=)
D) Depend des donnees
E) Depend du compilateur

**Reponse correcte: C**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.7-a",
  "name": "merge_sort",
  "language": "c",
  "language_version": "c17",
  "files": ["merge_sort.c", "merge_sort.h"],
  "tests": {
    "sorting": "merge_sort_tests",
    "inversions": "inversion_count_tests"
  }
}
```
