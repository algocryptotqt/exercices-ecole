# Exercice D.0.5-a : two_pointers

**Module :**
D.0.5 — Technique Two Pointers

**Concept :**
a-e — Two pointers, sliding window, fast-slow pointers

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.16 (pointers), D.0.2 (linear_search)

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
- `two_pointers.c`
- `two_pointers.h`

### 1.2 Consigne

Implementer des algorithmes utilisant la technique two pointers.

**Ta mission :**

```c
// Two pointers basique: trouver paire avec somme donnee (array trie)
int pair_with_sum(int *arr, int n, int target, int *i, int *j);

// Triplet avec somme zero
int triplet_sum_zero(int *arr, int n, int result[3]);

// Container with most water
int max_water(int *heights, int n);

// Remove element in-place
int remove_element(int *arr, int n, int val);

// Move zeros to end
void move_zeros(int *arr, int n);

// Sliding window: max sum of k consecutive elements
int max_sum_subarray(int *arr, int n, int k);

// Sliding window: minimum length subarray with sum >= target
int min_subarray_sum(int *arr, int n, int target);

// Fast-slow pointers: detect cycle in linked list (simulated with array)
int has_cycle(int *next, int n, int start);

// Dutch national flag (sort 0, 1, 2)
void dutch_flag(int *arr, int n);
```

**Comportement:**

1. `pair_with_sum({1,2,3,4,6}, 5, 6)` -> i=1, j=3 (2+4=6)
2. `max_water({1,8,6,2,5,4,8,3,7}, 9)` -> 49
3. `move_zeros({0,1,0,3,12}, 5)` -> {1,3,12,0,0}
4. `max_sum_subarray({1,4,2,10,2,3,1,0,20}, 9, 4)` -> 24

**Exemples:**
```
pair_with_sum({1, 2, 3, 4, 6}, target=6):
  left=0, right=4: 1+6=7 > 6, right--
  left=0, right=3: 1+4=5 < 6, left++
  left=1, right=3: 2+4=6 == 6, FOUND!

max_water({1,8,6,2,5,4,8,3,7}):
  |       |
  |   |   |   |
  | | | | | | | |
  | | | | | | | | |
  0 1 2 3 4 5 6 7 8

  Area = min(height[i], height[j]) * (j - i)
  Max area entre i=1 et j=8: min(8,7)*7 = 49
```

### 1.3 Prototype

```c
// two_pointers.h
#ifndef TWO_POINTERS_H
#define TWO_POINTERS_H

int pair_with_sum(int *arr, int n, int target, int *i, int *j);
int triplet_sum_zero(int *arr, int n, int result[3]);
int max_water(int *heights, int n);
int remove_element(int *arr, int n, int val);
void move_zeros(int *arr, int n);
int max_sum_subarray(int *arr, int n, int k);
int min_subarray_sum(int *arr, int n, int target);
int has_cycle(int *next, int n, int start);
void dutch_flag(int *arr, int n);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | pair_with_sum | correct pair | 10 |
| T02 | triplet_sum_zero | valid triplet | 15 |
| T03 | max_water | max area | 15 |
| T04 | remove_element | correct count | 10 |
| T05 | move_zeros | zeros at end | 10 |
| T06 | max_sum_subarray | max sum | 15 |
| T07 | has_cycle | detect cycle | 15 |
| T08 | dutch_flag | sorted 0,1,2 | 10 |

### 4.3 Solution de reference

```c
#include "two_pointers.h"

static void swap(int *a, int *b)
{
    int temp = *a;
    *a = *b;
    *b = temp;
}

int pair_with_sum(int *arr, int n, int target, int *i, int *j)
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
            left++;
        else
            right--;
    }
    return 0;
}

// Helper: sort for triplet
static void insertion_sort(int *arr, int n)
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

int triplet_sum_zero(int *arr, int n, int result[3])
{
    if (n < 3)
        return 0;

    // Trier d'abord
    insertion_sort(arr, n);

    for (int i = 0; i < n - 2; i++)
    {
        // Skip duplicates
        if (i > 0 && arr[i] == arr[i - 1])
            continue;

        int left = i + 1;
        int right = n - 1;
        int target = -arr[i];

        while (left < right)
        {
            int sum = arr[left] + arr[right];
            if (sum == target)
            {
                result[0] = arr[i];
                result[1] = arr[left];
                result[2] = arr[right];
                return 1;
            }
            else if (sum < target)
                left++;
            else
                right--;
        }
    }
    return 0;
}

int max_water(int *heights, int n)
{
    if (n < 2)
        return 0;

    int left = 0;
    int right = n - 1;
    int max_area = 0;

    while (left < right)
    {
        int h = heights[left] < heights[right] ? heights[left] : heights[right];
        int area = h * (right - left);
        if (area > max_area)
            max_area = area;

        if (heights[left] < heights[right])
            left++;
        else
            right--;
    }

    return max_area;
}

int remove_element(int *arr, int n, int val)
{
    int write = 0;
    for (int read = 0; read < n; read++)
    {
        if (arr[read] != val)
        {
            arr[write] = arr[read];
            write++;
        }
    }
    return write;
}

void move_zeros(int *arr, int n)
{
    int write = 0;

    // D'abord, copier tous les non-zeros
    for (int read = 0; read < n; read++)
    {
        if (arr[read] != 0)
        {
            arr[write] = arr[read];
            write++;
        }
    }

    // Remplir le reste avec des zeros
    while (write < n)
    {
        arr[write] = 0;
        write++;
    }
}

int max_sum_subarray(int *arr, int n, int k)
{
    if (k > n || k <= 0)
        return 0;

    // Calculer la somme de la premiere fenetre
    int window_sum = 0;
    for (int i = 0; i < k; i++)
        window_sum += arr[i];

    int max_sum = window_sum;

    // Faire glisser la fenetre
    for (int i = k; i < n; i++)
    {
        window_sum += arr[i] - arr[i - k];
        if (window_sum > max_sum)
            max_sum = window_sum;
    }

    return max_sum;
}

int min_subarray_sum(int *arr, int n, int target)
{
    int min_len = n + 1;  // Impossible length
    int left = 0;
    int sum = 0;

    for (int right = 0; right < n; right++)
    {
        sum += arr[right];

        while (sum >= target)
        {
            int len = right - left + 1;
            if (len < min_len)
                min_len = len;
            sum -= arr[left];
            left++;
        }
    }

    return (min_len == n + 1) ? 0 : min_len;
}

int has_cycle(int *next, int n, int start)
{
    if (start < 0 || start >= n)
        return 0;

    int slow = start;
    int fast = start;

    while (fast >= 0 && fast < n && next[fast] >= 0 && next[fast] < n)
    {
        slow = next[slow];
        fast = next[next[fast]];

        if (slow == fast)
            return 1;
    }

    return 0;
}

void dutch_flag(int *arr, int n)
{
    int low = 0;
    int mid = 0;
    int high = n - 1;

    while (mid <= high)
    {
        if (arr[mid] == 0)
        {
            swap(&arr[low], &arr[mid]);
            low++;
            mid++;
        }
        else if (arr[mid] == 1)
        {
            mid++;
        }
        else  // arr[mid] == 2
        {
            swap(&arr[mid], &arr[high]);
            high--;
        }
    }
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: pair_with_sum mauvaise direction
int pair_with_sum(int *arr, int n, int target, int *i, int *j)
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
            right--;  // Devrait etre left++
        else
            left++;   // Devrait etre right--
    }
    return 0;
}

// MUTANT 2: max_water calcule mal l'aire
int max_water(int *heights, int n)
{
    int left = 0, right = n - 1;
    int max_area = 0;

    while (left < right)
    {
        int area = heights[left] * (right - left);  // Pas min(h[l], h[r])
        if (area > max_area)
            max_area = area;
        left++;
    }
    return max_area;
}

// MUTANT 3: move_zeros ne preserve pas l'ordre
void move_zeros(int *arr, int n)
{
    int left = 0, right = n - 1;
    while (left < right)
    {
        if (arr[left] == 0 && arr[right] != 0)
            swap(&arr[left], &arr[right]);  // Ne preserve pas l'ordre
        if (arr[left] != 0) left++;
        if (arr[right] == 0) right--;
    }
}

// MUTANT 4: max_sum_subarray off-by-one
int max_sum_subarray(int *arr, int n, int k)
{
    int window_sum = 0;
    for (int i = 0; i <= k; i++)  // <= au lieu de <
        window_sum += arr[i];     // Buffer overflow
    // ...
}

// MUTANT 5: dutch_flag n'avance pas mid
void dutch_flag(int *arr, int n)
{
    int low = 0, mid = 0, high = n - 1;

    while (mid <= high)
    {
        if (arr[mid] == 0)
        {
            swap(&arr[low], &arr[mid]);
            low++;
            // Oublie mid++;
        }
        else if (arr[mid] == 1)
            mid++;
        else
        {
            swap(&arr[mid], &arr[high]);
            high--;
        }
    }
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

La **technique two pointers**:

1. **Converging pointers** - De chaque extremite vers le centre
2. **Sliding window** - Fenetre de taille fixe ou variable
3. **Fast-slow pointers** - Detection de cycles
4. **Partitioning** - Dutch national flag

### 5.3 Visualisation ASCII

```
TWO POINTERS CONVERGING:
target_sum = 9

[1, 2, 3, 4, 5, 6, 7]
 L                 R
 1 + 7 = 8 < 9, L++

[1, 2, 3, 4, 5, 6, 7]
    L              R
    2 + 7 = 9 == 9, FOUND!

SLIDING WINDOW (fixed size k=3):
[1, 4, 2, 10, 2, 3, 1]
 |-----|
 sum = 7

[1, 4, 2, 10, 2, 3, 1]
    |-----|
    sum = 7 - 1 + 10 = 16

DUTCH FLAG:
[2, 0, 2, 1, 1, 0]
 L,M           H

arr[M]=2, swap(M,H), H--
[0, 0, 2, 1, 1, 2]
 L,M        H

arr[M]=0, swap(L,M), L++, M++
[0, 0, 2, 1, 1, 2]
    L,M     H
...
Final: [0, 0, 1, 1, 2, 2]
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite de pair_with_sum avec two pointers ?

A) O(n^2)
B) O(n log n)
C) O(n)
D) O(log n)
E) O(1)

**Reponse correcte: C**

### Question 2
Quelle technique est utilisee pour detecter un cycle ?

A) Two converging pointers
B) Sliding window
C) Fast-slow pointers (tortoise and hare)
D) Partitioning
E) Binary search

**Reponse correcte: C**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.5-a",
  "name": "two_pointers",
  "language": "c",
  "language_version": "c17",
  "files": ["two_pointers.c", "two_pointers.h"],
  "tests": {
    "converging": "converging_tests",
    "sliding": "sliding_window_tests",
    "partition": "partition_tests"
  }
}
```
