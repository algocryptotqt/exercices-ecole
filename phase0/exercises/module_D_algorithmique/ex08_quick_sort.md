# Exercice D.0.8-a : quick_sort

**Module :**
D.0.8 — Tri Rapide

**Concept :**
a-e — Pivot selection, partition, in-place, worst case O(n^2)

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
T4 O(n log n) moyen x S2 O(log n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `quick_sort.c`
- `quick_sort.h`

### 1.2 Consigne

Implementer le tri rapide (quick sort).

**Ta mission :**

```c
// Echanger deux elements
void swap(int *a, int *b);

// Partition avec pivot a droite (Lomuto)
int partition_lomuto(int *arr, int low, int high);

// Partition avec deux pointeurs (Hoare)
int partition_hoare(int *arr, int low, int high);

// Quick sort recursif
void quick_sort(int *arr, int low, int high);

// Wrapper simple
void sort_array(int *arr, int size);

// Version avec pivot median de 3
void quick_sort_median3(int *arr, int low, int high);

// Trouver le k-ieme plus petit element (Quick Select)
int quick_select(int *arr, int size, int k);
```

**Comportement:**

1. `sort_array({5,2,8,1,9}, 5)` -> {1,2,5,8,9}
2. `quick_select({3,1,4,1,5,9}, 6, 3)` -> 3 (3eme plus petit)

**Exemples:**
```
Partition de {5, 2, 8, 1, 9} avec pivot = 9 (dernier):

Initial: [5, 2, 8, 1, 9]
          ^           ^
          i          pivot

i pointe vers premier element > pivot (a echanger)

Apres partition:
[5, 2, 8, 1, 9]  (ici pivot est deja a sa place)
              ^
        pivot final position = 4

Exemple plus interessant avec pivot = 5:
[5, 2, 8, 1, 9] -> partition autour de 5
[2, 1, 5, 8, 9]
       ^
 elements <= 5 a gauche, > 5 a droite
```

### 1.3 Prototype

```c
// quick_sort.h
#ifndef QUICK_SORT_H
#define QUICK_SORT_H

void swap(int *a, int *b);
int partition_lomuto(int *arr, int low, int high);
int partition_hoare(int *arr, int low, int high);
void quick_sort(int *arr, int low, int high);
void sort_array(int *arr, int size);
void quick_sort_median3(int *arr, int low, int high);
int quick_select(int *arr, int size, int k);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | random array | sorted | 15 |
| T02 | already sorted | sorted (no quadratic) | 10 |
| T03 | reverse sorted | sorted | 10 |
| T04 | all same elements | handled | 10 |
| T05 | quick_select k=1 | min element | 15 |
| T06 | quick_select k=n | max element | 15 |
| T07 | partition correctness | verified | 15 |
| T08 | median3 version | sorted | 10 |

### 4.3 Solution de reference

```c
#include "quick_sort.h"

void swap(int *a, int *b)
{
    int temp = *a;
    *a = *b;
    *b = temp;
}

int partition_lomuto(int *arr, int low, int high)
{
    int pivot = arr[high];  // Pivot = dernier element
    int i = low - 1;        // Index du plus petit element

    for (int j = low; j < high; j++)
    {
        if (arr[j] <= pivot)
        {
            i++;
            swap(&arr[i], &arr[j]);
        }
    }

    swap(&arr[i + 1], &arr[high]);
    return i + 1;  // Position finale du pivot
}

int partition_hoare(int *arr, int low, int high)
{
    int pivot = arr[low + (high - low) / 2];  // Pivot au milieu
    int i = low - 1;
    int j = high + 1;

    while (1)
    {
        do {
            i++;
        } while (arr[i] < pivot);

        do {
            j--;
        } while (arr[j] > pivot);

        if (i >= j)
            return j;

        swap(&arr[i], &arr[j]);
    }
}

void quick_sort(int *arr, int low, int high)
{
    if (low < high)
    {
        int pi = partition_lomuto(arr, low, high);
        quick_sort(arr, low, pi - 1);
        quick_sort(arr, pi + 1, high);
    }
}

void sort_array(int *arr, int size)
{
    if (size > 1)
        quick_sort(arr, 0, size - 1);
}

// Median of three: choisit le median de arr[low], arr[mid], arr[high]
static int median_of_three(int *arr, int low, int high)
{
    int mid = low + (high - low) / 2;

    if (arr[low] > arr[mid])
        swap(&arr[low], &arr[mid]);
    if (arr[low] > arr[high])
        swap(&arr[low], &arr[high]);
    if (arr[mid] > arr[high])
        swap(&arr[mid], &arr[high]);

    // Placer le median a high-1 pour utiliser comme pivot
    swap(&arr[mid], &arr[high - 1]);
    return arr[high - 1];
}

void quick_sort_median3(int *arr, int low, int high)
{
    if (high - low < 2)
    {
        if (low < high && arr[low] > arr[high])
            swap(&arr[low], &arr[high]);
        return;
    }

    int pivot = median_of_three(arr, low, high);
    int i = low;
    int j = high - 1;

    while (1)
    {
        while (arr[++i] < pivot) {}
        while (arr[--j] > pivot) {}

        if (i >= j)
            break;
        swap(&arr[i], &arr[j]);
    }

    swap(&arr[i], &arr[high - 1]);  // Restaurer pivot

    quick_sort_median3(arr, low, i - 1);
    quick_sort_median3(arr, i + 1, high);
}

int quick_select(int *arr, int size, int k)
{
    if (k < 1 || k > size)
        return -1;  // Erreur: k hors limites

    int low = 0;
    int high = size - 1;

    while (low <= high)
    {
        int pi = partition_lomuto(arr, low, high);

        if (pi == k - 1)
            return arr[pi];
        else if (pi > k - 1)
            high = pi - 1;
        else
            low = pi + 1;
    }

    return arr[low];
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Partition ne place pas le pivot correctement
int partition_lomuto(int *arr, int low, int high)
{
    int pivot = arr[high];
    int i = low;  // Devrait etre low - 1
    for (int j = low; j < high; j++)
    {
        if (arr[j] <= pivot)
            swap(&arr[i++], &arr[j]);
    }
    swap(&arr[i], &arr[high]);
    return i;
}

// MUTANT 2: Quick sort avec mauvais indices recursifs
void quick_sort(int *arr, int low, int high)
{
    if (low < high)
    {
        int pi = partition_lomuto(arr, low, high);
        quick_sort(arr, low, pi);      // Devrait etre pi - 1
        quick_sort(arr, pi, high);     // Devrait etre pi + 1
        // Resulte en recursion infinie
    }
}

// MUTANT 3: Partition avec off-by-one
int partition_lomuto(int *arr, int low, int high)
{
    // ...
    for (int j = low; j <= high; j++)  // <= au lieu de <
    {
        // Compare le pivot avec lui-meme
    }
}

// MUTANT 4: quick_select ne gere pas k=1
int quick_select(int *arr, int size, int k)
{
    // Oublie que k est 1-indexed
    int low = 0, high = size - 1;
    while (low <= high)
    {
        int pi = partition_lomuto(arr, low, high);
        if (pi == k)  // Devrait etre k - 1
            return arr[pi];
        // ...
    }
}

// MUTANT 5: swap incorrecte
void swap(int *a, int *b)
{
    *a = *b;
    *b = *a;  // Copie la nouvelle valeur de *a, pas l'ancienne!
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Le **tri rapide (quick sort)**:

1. **In-place** - Ne necessite pas O(n) memoire supplementaire
2. **Partition** - Placer le pivot a sa position finale
3. **Choix du pivot** - Crucial pour eviter O(n^2)
4. **Quick Select** - Trouver le k-ieme element en O(n) moyen

### 5.3 Visualisation ASCII

```
PARTITION de [5, 2, 8, 1, 9, 3] avec pivot = 3:

Initial:
[5, 2, 8, 1, 9, 3]
 ^              ^
 j            pivot
i = -1

j=0: arr[0]=5 > 3, skip
j=1: arr[1]=2 <= 3, i++, swap(arr[0], arr[1])
[2, 5, 8, 1, 9, 3]
    ^
    i

j=2: arr[2]=8 > 3, skip
j=3: arr[3]=1 <= 3, i++, swap(arr[1], arr[3])
[2, 1, 8, 5, 9, 3]
       ^
       i

j=4: arr[4]=9 > 3, skip

Final: swap(arr[i+1], arr[high])
[2, 1, 3, 5, 9, 8]
       ^
    pivot en place

Elements <= 3 a gauche, > 3 a droite
```

### 5.5 Pire cas et optimisations

```
PIRE CAS: O(n^2)
- Tableau deja trie + pivot = dernier element
- Chaque partition ne reduit que d'1 element

OPTIMISATIONS:
1. Median of three: pivot = median(first, mid, last)
2. Random pivot: pivot = arr[random(low, high)]
3. Introsort: switch to heapsort si recursion trop profonde
4. Insertion sort pour petits sous-tableaux (< 10 elements)
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite du quick sort dans le pire cas ?

A) O(n)
B) O(n log n)
C) O(n^2)
D) O(2^n)
E) O(log n)

**Reponse correcte: C**

### Question 2
Quel est l'avantage principal du quick sort sur le merge sort ?

A) Toujours plus rapide
B) In-place (O(1) memoire supplementaire)
C) Stable
D) Complexite garantie
E) Plus simple a implementer

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.8-a",
  "name": "quick_sort",
  "language": "c",
  "language_version": "c17",
  "files": ["quick_sort.c", "quick_sort.h"],
  "tests": {
    "sorting": "quick_sort_tests",
    "select": "quick_select_tests"
  }
}
```
