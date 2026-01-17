# Exercice D.0.3-a : array_algorithms

**Module :**
D.0.3 — Algorithmes sur Tableaux

**Concept :**
a-e — Reverse, rotate, shuffle, partition, two pointers

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.14 (arrays), 0.5.16 (pointers)

**Domaines :**
Algo

**Duree estimee :**
120 min

**XP Base :**
150

**Complexite :**
T2 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `array_algorithms.c`
- `array_algorithms.h`

### 1.2 Consigne

Implementer des algorithmes classiques de manipulation de tableaux.

**Ta mission :**

```c
// Inverser un tableau in-place
void reverse(int *arr, int n);

// Inverser une portion [start, end]
void reverse_range(int *arr, int start, int end);

// Rotation a gauche de k positions
void rotate_left(int *arr, int n, int k);

// Rotation a droite de k positions
void rotate_right(int *arr, int n, int k);

// Melanger aleatoirement (Fisher-Yates)
void shuffle(int *arr, int n);

// Partition: elements < pivot a gauche, >= a droite
int partition(int *arr, int n, int pivot);

// Retirer les doublons (tableau trie)
int remove_duplicates(int *arr, int n);

// Two pointers: trouver paire avec somme cible
int find_pair_sum(int *arr, int n, int target, int *i, int *j);

// Fusionner deux tableaux tries
void merge_sorted(int *a, int na, int *b, int nb, int *result);
```

**Comportement:**

1. `reverse({1,2,3,4,5}, 5)` -> {5,4,3,2,1}
2. `rotate_left({1,2,3,4,5}, 5, 2)` -> {3,4,5,1,2}
3. `partition({3,1,4,1,5,9,2,6}, 8, 5)` -> {3,1,4,1,2,|5,9,6}
4. `remove_duplicates({1,1,2,2,3}, 5)` -> {1,2,3}, returns 3

**Exemples:**
```
rotate_left({1,2,3,4,5}, k=2):
  Step 1: Reverse all -> {5,4,3,2,1}
  Step 2: Reverse [0,n-k-1] -> {3,4,5,2,1}
  Step 3: Reverse [n-k,n-1] -> {3,4,5,1,2}

partition({3,1,4,1,5,9,2,6}, pivot=5):
  i=0, j=7
  Process: elements <5 go left, >=5 go right
  Result: {3,1,4,1,2,9,5,6} with partition at index 5
```

### 1.3 Prototype

```c
// array_algorithms.h
#ifndef ARRAY_ALGORITHMS_H
#define ARRAY_ALGORITHMS_H

void reverse(int *arr, int n);
void reverse_range(int *arr, int start, int end);
void rotate_left(int *arr, int n, int k);
void rotate_right(int *arr, int n, int k);
void shuffle(int *arr, int n);
int partition(int *arr, int n, int pivot);
int remove_duplicates(int *arr, int n);
int find_pair_sum(int *arr, int n, int target, int *i, int *j);
void merge_sorted(int *a, int na, int *b, int nb, int *result);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | reverse | inverted array | 10 |
| T02 | rotate_left | correct rotation | 15 |
| T03 | rotate_right | correct rotation | 15 |
| T04 | partition | valid partition | 15 |
| T05 | remove_duplicates | no dups, count | 15 |
| T06 | find_pair_sum | correct pair | 15 |
| T07 | merge_sorted | sorted result | 15 |

### 4.3 Solution de reference

```c
#include "array_algorithms.h"
#include <stdlib.h>
#include <time.h>

static void swap(int *a, int *b)
{
    int temp = *a;
    *a = *b;
    *b = temp;
}

void reverse(int *arr, int n)
{
    int left = 0;
    int right = n - 1;

    while (left < right)
    {
        swap(&arr[left], &arr[right]);
        left++;
        right--;
    }
}

void reverse_range(int *arr, int start, int end)
{
    while (start < end)
    {
        swap(&arr[start], &arr[end]);
        start++;
        end--;
    }
}

void rotate_left(int *arr, int n, int k)
{
    if (n <= 0)
        return;
    k = k % n;  // Handle k > n
    if (k == 0)
        return;

    // Methode des 3 inversions
    reverse_range(arr, 0, k - 1);
    reverse_range(arr, k, n - 1);
    reverse(arr, n);
}

void rotate_right(int *arr, int n, int k)
{
    if (n <= 0)
        return;
    k = k % n;
    if (k == 0)
        return;

    // Rotation droite = rotation gauche de (n-k)
    rotate_left(arr, n, n - k);
}

void shuffle(int *arr, int n)
{
    static int seeded = 0;
    if (!seeded)
    {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }

    // Fisher-Yates shuffle
    for (int i = n - 1; i > 0; i--)
    {
        int j = rand() % (i + 1);
        swap(&arr[i], &arr[j]);
    }
}

int partition(int *arr, int n, int pivot)
{
    int i = 0;
    int j = n - 1;

    while (i <= j)
    {
        while (i <= j && arr[i] < pivot)
            i++;
        while (i <= j && arr[j] >= pivot)
            j--;

        if (i < j)
        {
            swap(&arr[i], &arr[j]);
            i++;
            j--;
        }
    }
    return i;  // Premier index >= pivot
}

int remove_duplicates(int *arr, int n)
{
    if (n <= 1)
        return n;

    int write = 1;
    for (int read = 1; read < n; read++)
    {
        if (arr[read] != arr[write - 1])
        {
            arr[write] = arr[read];
            write++;
        }
    }
    return write;
}

int find_pair_sum(int *arr, int n, int target, int *i, int *j)
{
    // Assume arr is sorted
    int left = 0;
    int right = n - 1;

    while (left < right)
    {
        int sum = arr[left] + arr[right];
        if (sum == target)
        {
            *i = left;
            *j = right;
            return 1;
        }
        else if (sum < target)
        {
            left++;
        }
        else
        {
            right--;
        }
    }
    return 0;  // Not found
}

void merge_sorted(int *a, int na, int *b, int nb, int *result)
{
    int i = 0, j = 0, k = 0;

    while (i < na && j < nb)
    {
        if (a[i] <= b[j])
            result[k++] = a[i++];
        else
            result[k++] = b[j++];
    }

    while (i < na)
        result[k++] = a[i++];

    while (j < nb)
        result[k++] = b[j++];
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: reverse off-by-one
void reverse(int *arr, int n)
{
    int left = 0;
    int right = n;  // Devrait etre n-1
    while (left < right)
    {
        swap(&arr[left], &arr[right]);  // Buffer overflow
        left++;
        right--;
    }
}

// MUTANT 2: rotate_left sans modulo
void rotate_left(int *arr, int n, int k)
{
    // k = k % n;  // Oublie le modulo
    reverse_range(arr, 0, k - 1);  // Crash si k > n
    reverse_range(arr, k, n - 1);
    reverse(arr, n);
}

// MUTANT 3: remove_duplicates compare mauvais elements
int remove_duplicates(int *arr, int n)
{
    if (n <= 1)
        return n;

    int write = 1;
    for (int read = 1; read < n; read++)
    {
        if (arr[read] != arr[read - 1])  // Devrait etre arr[write - 1]
        {
            arr[write] = arr[read];
            write++;
        }
    }
    return write;
}

// MUTANT 4: find_pair_sum mauvaise direction
int find_pair_sum(int *arr, int n, int target, int *i, int *j)
{
    int left = 0;
    int right = n - 1;

    while (left < right)
    {
        int sum = arr[left] + arr[right];
        if (sum == target)
        {
            *i = left;
            *j = right;
            return 1;
        }
        else if (sum < target)
        {
            right--;  // Devrait etre left++
        }
        else
        {
            left++;   // Devrait etre right--
        }
    }
    return 0;
}

// MUTANT 5: merge_sorted n'est pas stable
void merge_sorted(int *a, int na, int *b, int nb, int *result)
{
    int i = 0, j = 0, k = 0;

    while (i < na && j < nb)
    {
        if (a[i] < b[j])  // < au lieu de <=, pas stable
            result[k++] = a[i++];
        else
            result[k++] = b[j++];
    }
    // ... reste
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **algorithmes sur tableaux**:

1. **In-place** - Modification sans memoire supplementaire
2. **Two pointers** - Technique avec deux indices
3. **Rotation** - Via trois inversions
4. **Partition** - Base du quicksort

### 5.3 Visualisation ASCII

```
ROTATION GAUCHE de {1,2,3,4,5} par k=2:

Methode des 3 inversions:

Initial:    [1, 2, 3, 4, 5]
             ^--^  ^-----^
             k=2   reste

Step 1: Reverse [0,k-1]:
            [2, 1, 3, 4, 5]

Step 2: Reverse [k,n-1]:
            [2, 1, 5, 4, 3]

Step 3: Reverse all:
            [3, 4, 5, 1, 2]  <- Resultat!

TWO POINTERS pour pair sum=9 dans {1,2,4,5,7}:

[1, 2, 4, 5, 7]
 ^           ^
left       right
1+7=8 < 9, left++

[1, 2, 4, 5, 7]
    ^        ^
   left    right
2+7=9 == 9, FOUND!
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite de la rotation par 3 inversions ?

A) O(1)
B) O(k)
C) O(n)
D) O(n*k)
E) O(n^2)

**Reponse correcte: C**

### Question 2
Pourquoi utiliser two pointers pour find_pair_sum ?

A) Fonctionne sur tableaux non tries
B) Complexite O(n) au lieu de O(n^2)
C) Plus simple a implementer
D) Utilise moins de memoire
E) B et D

**Reponse correcte: E**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.3-a",
  "name": "array_algorithms",
  "language": "c",
  "language_version": "c17",
  "files": ["array_algorithms.c", "array_algorithms.h"],
  "tests": {
    "reverse": "reverse_tests",
    "rotate": "rotate_tests",
    "partition": "partition_tests"
  }
}
```
