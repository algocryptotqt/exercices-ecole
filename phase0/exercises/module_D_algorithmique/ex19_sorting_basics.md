# Exercice D.0.19-a : sorting_basics

**Module :**
D.0.19 — Tris Simples

**Concept :**
a-e — Bubble sort, selection sort, insertion sort, stability, in-place

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
D.0.5 (complexity)

**Domaines :**
Algo

**Duree estimee :**
150 min

**XP Base :**
220

**Complexite :**
T3 O(n^2) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `sorting_basics.c`
- `sorting_basics.h`

### 1.2 Consigne

Implementer les algorithmes de tri simples.

**Ta mission :**

```c
// Bubble Sort
void bubble_sort(int *arr, int n);

// Selection Sort
void selection_sort(int *arr, int n);

// Insertion Sort
void insertion_sort(int *arr, int n);

// Compter les comparaisons (pour analyse)
int bubble_sort_count(int *arr, int n);
int selection_sort_count(int *arr, int n);
int insertion_sort_count(int *arr, int n);

// Versions optimisees
void bubble_sort_optimized(int *arr, int n);  // Arret si aucun swap
void insertion_sort_binary(int *arr, int n);  // Recherche binaire pour position

// Verifier si trie
int is_sorted(int *arr, int n);
```

**Comportement:**

1. `bubble_sort({5,2,8,1}, 4)` -> {1,2,5,8}
2. `selection_sort({5,2,8,1}, 4)` -> {1,2,5,8}
3. `insertion_sort({5,2,8,1}, 4)` -> {1,2,5,8}
4. `is_sorted({1,2,3}, 3)` -> 1

**Exemples:**
```
Bubble Sort de {5, 2, 8, 1}:
Pass 1: [2,5,1,8] (swap 5-2, swap 8-1)
Pass 2: [2,1,5,8] (swap 5-1)
Pass 3: [1,2,5,8] (swap 2-1)
Done: [1,2,5,8]

Selection Sort de {5, 2, 8, 1}:
Find min (1), swap with pos 0: [1,2,8,5]
Find min (2), already at pos 1: [1,2,8,5]
Find min (5), swap with pos 2: [1,2,5,8]
Done: [1,2,5,8]
```

### 1.3 Prototype

```c
// sorting_basics.h
#ifndef SORTING_BASICS_H
#define SORTING_BASICS_H

void bubble_sort(int *arr, int n);
void selection_sort(int *arr, int n);
void insertion_sort(int *arr, int n);

int bubble_sort_count(int *arr, int n);
int selection_sort_count(int *arr, int n);
int insertion_sort_count(int *arr, int n);

void bubble_sort_optimized(int *arr, int n);
void insertion_sort_binary(int *arr, int n);

int is_sorted(int *arr, int n);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | bubble_sort | sorted | 15 |
| T02 | selection_sort | sorted | 15 |
| T03 | insertion_sort | sorted | 15 |
| T04 | already sorted | unchanged | 10 |
| T05 | reverse sorted | sorted | 10 |
| T06 | duplicates | stable | 10 |
| T07 | empty/single | handled | 10 |
| T08 | is_sorted | correct | 15 |

### 4.3 Solution de reference

```c
#include "sorting_basics.h"

static void swap(int *a, int *b)
{
    int temp = *a;
    *a = *b;
    *b = temp;
}

void bubble_sort(int *arr, int n)
{
    for (int i = 0; i < n - 1; i++)
    {
        for (int j = 0; j < n - 1 - i; j++)
        {
            if (arr[j] > arr[j + 1])
            {
                swap(&arr[j], &arr[j + 1]);
            }
        }
    }
}

void bubble_sort_optimized(int *arr, int n)
{
    for (int i = 0; i < n - 1; i++)
    {
        int swapped = 0;
        for (int j = 0; j < n - 1 - i; j++)
        {
            if (arr[j] > arr[j + 1])
            {
                swap(&arr[j], &arr[j + 1]);
                swapped = 1;
            }
        }
        if (!swapped)
            break;  // Deja trie
    }
}

void selection_sort(int *arr, int n)
{
    for (int i = 0; i < n - 1; i++)
    {
        int min_idx = i;
        for (int j = i + 1; j < n; j++)
        {
            if (arr[j] < arr[min_idx])
                min_idx = j;
        }
        if (min_idx != i)
            swap(&arr[i], &arr[min_idx]);
    }
}

void insertion_sort(int *arr, int n)
{
    for (int i = 1; i < n; i++)
    {
        int key = arr[i];
        int j = i - 1;

        while (j >= 0 && arr[j] > key)
        {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

static int binary_search_insert(int *arr, int key, int low, int high)
{
    while (low < high)
    {
        int mid = low + (high - low) / 2;
        if (arr[mid] <= key)
            low = mid + 1;
        else
            high = mid;
    }
    return low;
}

void insertion_sort_binary(int *arr, int n)
{
    for (int i = 1; i < n; i++)
    {
        int key = arr[i];
        int pos = binary_search_insert(arr, key, 0, i);

        // Decaler les elements
        for (int j = i; j > pos; j--)
            arr[j] = arr[j - 1];

        arr[pos] = key;
    }
}

int bubble_sort_count(int *arr, int n)
{
    int comparisons = 0;
    for (int i = 0; i < n - 1; i++)
    {
        for (int j = 0; j < n - 1 - i; j++)
        {
            comparisons++;
            if (arr[j] > arr[j + 1])
                swap(&arr[j], &arr[j + 1]);
        }
    }
    return comparisons;
}

int selection_sort_count(int *arr, int n)
{
    int comparisons = 0;
    for (int i = 0; i < n - 1; i++)
    {
        int min_idx = i;
        for (int j = i + 1; j < n; j++)
        {
            comparisons++;
            if (arr[j] < arr[min_idx])
                min_idx = j;
        }
        if (min_idx != i)
            swap(&arr[i], &arr[min_idx]);
    }
    return comparisons;
}

int insertion_sort_count(int *arr, int n)
{
    int comparisons = 0;
    for (int i = 1; i < n; i++)
    {
        int key = arr[i];
        int j = i - 1;

        while (j >= 0)
        {
            comparisons++;
            if (arr[j] > key)
            {
                arr[j + 1] = arr[j];
                j--;
            }
            else
            {
                break;
            }
        }
        arr[j + 1] = key;
    }
    return comparisons;
}

int is_sorted(int *arr, int n)
{
    for (int i = 0; i < n - 1; i++)
    {
        if (arr[i] > arr[i + 1])
            return 0;
    }
    return 1;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Bubble sort avec mauvaises bornes
void bubble_sort(int *arr, int n)
{
    for (int i = 0; i < n; i++)  // Devrait etre n-1
    {
        for (int j = 0; j < n - 1; j++)  // Devrait etre n-1-i
        {
            // ...
        }
    }
}

// MUTANT 2: Selection sort ne swap pas
void selection_sort(int *arr, int n)
{
    for (int i = 0; i < n - 1; i++)
    {
        int min_idx = i;
        for (int j = i + 1; j < n; j++)
        {
            if (arr[j] < arr[min_idx])
                min_idx = j;
        }
        // Oublie swap!
    }
}

// MUTANT 3: Insertion sort instable
void insertion_sort(int *arr, int n)
{
    for (int i = 1; i < n; i++)
    {
        int key = arr[i];
        int j = i - 1;
        while (j >= 0 && arr[j] >= key)  // >= au lieu de >, pas stable
        {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

// MUTANT 4: is_sorted strict
int is_sorted(int *arr, int n)
{
    for (int i = 0; i < n - 1; i++)
    {
        if (arr[i] >= arr[i + 1])  // >= au lieu de >, rejette doublons
            return 0;
    }
    return 1;
}

// MUTANT 5: bubble_sort_optimized initialise swapped a 1
void bubble_sort_optimized(int *arr, int n)
{
    for (int i = 0; i < n - 1; i++)
    {
        int swapped = 1;  // Devrait etre 0
        // Ne s'arrete jamais tot
    }
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **tris simples** O(n^2):

1. **Bubble Sort** - Compare et echange adjacents
2. **Selection Sort** - Trouve le min et place
3. **Insertion Sort** - Insere a la bonne position
4. **Stabilite** - Preserve l'ordre des egaux

### 5.3 Visualisation ASCII

```
BUBBLE SORT:
[5, 2, 8, 1]
 ^  ^
 |  |
 compare, swap -> [2, 5, 8, 1]
    ^  ^
    |  |
    compare, no swap
       ^  ^
       |  |
       compare, swap -> [2, 5, 1, 8]

SELECTION SORT:
[5, 2, 8, 1]
 ^        ^
 i       min
 swap -> [1, 2, 8, 5]
    ^     ^
    i    min(=i, deja en place)
         ^  ^
         i  min
         swap -> [1, 2, 5, 8]

INSERTION SORT:
[5, 2, 8, 1]
    ^
    key=2, insert avant 5 -> [2, 5, 8, 1]
       ^
       key=8, deja en place
          ^
          key=1, insert au debut -> [1, 2, 5, 8]
```

### 5.5 Comparaison

```
| Algorithme    | Meilleur | Moyen   | Pire    | Stable | In-place |
|---------------|----------|---------|---------|--------|----------|
| Bubble        | O(n)     | O(n^2)  | O(n^2)  | Oui    | Oui      |
| Selection     | O(n^2)   | O(n^2)  | O(n^2)  | Non    | Oui      |
| Insertion     | O(n)     | O(n^2)  | O(n^2)  | Oui    | Oui      |

Quand utiliser Insertion Sort:
- Petits tableaux (< 10-20 elements)
- Tableaux presque tries
- Tri hybride (switch depuis quicksort)
```

---

## SECTION 7 : QCM

### Question 1
Quel tri est le plus efficace sur un tableau deja trie ?

A) Bubble Sort
B) Selection Sort
C) Insertion Sort
D) Tous pareils
E) Depend de n

**Reponse correcte: C** (O(n) pour insertion)

### Question 2
Quel tri est stable ?

A) Selection Sort seulement
B) Bubble Sort et Insertion Sort
C) Tous les trois
D) Aucun
E) Depend de l'implementation

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.19-a",
  "name": "sorting_basics",
  "language": "c",
  "language_version": "c17",
  "files": ["sorting_basics.c", "sorting_basics.h"],
  "tests": {
    "bubble": "bubble_sort_tests",
    "selection": "selection_sort_tests",
    "insertion": "insertion_sort_tests"
  }
}
```
