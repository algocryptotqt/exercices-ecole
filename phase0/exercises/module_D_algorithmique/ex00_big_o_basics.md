# Exercice D.0.0-a : big_o_basics

**Module :**
D.0.0 — Introduction a la Complexite

**Concept :**
a-e — Big O notation, time complexity, space complexity, asymptotic analysis

**Difficulte :**
★★☆☆☆☆☆☆☆☆ (2/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.8 (loops)

**Domaines :**
Algo

**Duree estimee :**
90 min

**XP Base :**
120

**Complexite :**
Variable

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `big_o_basics.c`
- `big_o_basics.h`

### 1.2 Consigne

Implementer des fonctions avec differentes complexites temporelles pour comprendre Big O.

**Ta mission :**

```c
// O(1) - Temps constant
int constant_op(int *arr, int n);

// O(n) - Temps lineaire
int linear_sum(int *arr, int n);

// O(n^2) - Temps quadratique
int quadratic_pairs(int *arr, int n);

// O(log n) - Temps logarithmique
int log_countdown(int n);

// O(n log n) - Linearithmique
void merge_sort_count(int *arr, int n, int *count);

// Compter les operations
int count_operations_linear(int n);
int count_operations_quadratic(int n);
int count_operations_logarithmic(int n);
```

**Comportement:**

1. `constant_op({1,2,3}, 3)` -> 1 (premier element)
2. `linear_sum({1,2,3,4}, 4)` -> 10
3. `count_operations_linear(100)` -> 100
4. `count_operations_quadratic(10)` -> 100

**Exemples:**
```
O(1) - Constant:
arr[0] -> toujours 1 operation

O(n) - Linear:
for (i = 0; i < n; i++)  -> n operations
  sum += arr[i];

O(n^2) - Quadratic:
for (i = 0; i < n; i++)      -> n * n operations
  for (j = 0; j < n; j++)
    count++;

O(log n) - Logarithmic:
while (n > 0)  -> log2(n) operations
  n = n / 2;
```

### 1.3 Prototype

```c
// big_o_basics.h
#ifndef BIG_O_BASICS_H
#define BIG_O_BASICS_H

int constant_op(int *arr, int n);
int linear_sum(int *arr, int n);
int quadratic_pairs(int *arr, int n);
int log_countdown(int n);
void merge_sort_count(int *arr, int n, int *count);
int count_operations_linear(int n);
int count_operations_quadratic(int n);
int count_operations_logarithmic(int n);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | constant_op | O(1) | 10 |
| T02 | linear_sum | correct sum | 15 |
| T03 | quadratic_pairs | n*(n-1)/2 | 15 |
| T04 | log_countdown | log2(n) | 15 |
| T05 | count_linear(1000) | 1000 | 15 |
| T06 | count_quadratic(100) | 10000 | 15 |
| T07 | count_logarithmic(1024) | 10 | 15 |

### 4.3 Solution de reference

```c
#include "big_o_basics.h"

// O(1) - Acces direct
int constant_op(int *arr, int n)
{
    (void)n;  // n n'affecte pas le temps
    if (arr == NULL)
        return 0;
    return arr[0];
}

// O(n) - Parcours lineaire
int linear_sum(int *arr, int n)
{
    int sum = 0;
    for (int i = 0; i < n; i++)
    {
        sum += arr[i];
    }
    return sum;
}

// O(n^2) - Toutes les paires
int quadratic_pairs(int *arr, int n)
{
    int count = 0;
    for (int i = 0; i < n; i++)
    {
        for (int j = i + 1; j < n; j++)
        {
            if (arr[i] != arr[j])
                count++;
        }
    }
    return count;
}

// O(log n) - Division successive
int log_countdown(int n)
{
    int steps = 0;
    while (n > 0)
    {
        n = n / 2;
        steps++;
    }
    return steps;
}

// Helper pour merge sort
static void merge(int *arr, int l, int m, int r, int *count)
{
    int n1 = m - l + 1;
    int n2 = r - m;
    int L[n1], R[n2];

    for (int i = 0; i < n1; i++)
        L[i] = arr[l + i];
    for (int j = 0; j < n2; j++)
        R[j] = arr[m + 1 + j];

    int i = 0, j = 0, k = l;
    while (i < n1 && j < n2)
    {
        (*count)++;
        if (L[i] <= R[j])
            arr[k++] = L[i++];
        else
            arr[k++] = R[j++];
    }

    while (i < n1)
        arr[k++] = L[i++];
    while (j < n2)
        arr[k++] = R[j++];
}

static void merge_sort_helper(int *arr, int l, int r, int *count)
{
    if (l < r)
    {
        int m = l + (r - l) / 2;
        merge_sort_helper(arr, l, m, count);
        merge_sort_helper(arr, m + 1, r, count);
        merge(arr, l, m, r, count);
    }
}

// O(n log n)
void merge_sort_count(int *arr, int n, int *count)
{
    *count = 0;
    if (n > 1)
        merge_sort_helper(arr, 0, n - 1, count);
}

int count_operations_linear(int n)
{
    int ops = 0;
    for (int i = 0; i < n; i++)
    {
        ops++;
    }
    return ops;
}

int count_operations_quadratic(int n)
{
    int ops = 0;
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            ops++;
        }
    }
    return ops;
}

int count_operations_logarithmic(int n)
{
    int ops = 0;
    while (n > 0)
    {
        ops++;
        n = n / 2;
    }
    return ops;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: linear_sum overflow
int linear_sum(int *arr, int n)
{
    int sum = 0;
    for (int i = 0; i <= n; i++)  // <= au lieu de <
    {
        sum += arr[i];  // Buffer overflow!
    }
    return sum;
}

// MUTANT 2: log_countdown boucle infinie
int log_countdown(int n)
{
    int steps = 0;
    while (n >= 0)  // >= au lieu de >, boucle infinie quand n=0
    {
        n = n / 2;
        steps++;
    }
    return steps;
}

// MUTANT 3: quadratic compte mal
int quadratic_pairs(int *arr, int n)
{
    int count = 0;
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)  // j=0 au lieu de j=i+1
        {
            count++;  // Compte aussi (i,i) et doublons
        }
    }
    return count;
}

// MUTANT 4: constant_op pas constant
int constant_op(int *arr, int n)
{
    int sum = 0;
    for (int i = 0; i < n; i++)  // O(n) au lieu de O(1)!
        sum += arr[i];
    return sum;
}

// MUTANT 5: count_logarithmic arrondi
int count_operations_logarithmic(int n)
{
    int ops = 0;
    while (n > 1)  // > 1 au lieu de > 0, manque une iteration
    {
        ops++;
        n = n / 2;
    }
    return ops;
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

La **notation Big O**:

1. **O(1)** - Temps constant, independant de n
2. **O(log n)** - Logarithmique, divise le probleme
3. **O(n)** - Lineaire, proportionnel a n
4. **O(n^2)** - Quadratique, boucles imbriquees

### 5.3 Visualisation ASCII

```
CROISSANCE DES COMPLEXITES:

Operations
    ^
    |                           O(n^2)
    |                        ..'
    |                     ..'
    |                  ..'
    |              ..''        O(n)
    |         ...''       ...''
    |     ..''       ...''
    |  .''      ...''          O(log n)
    |.'    ...''    ___________O(1)
    +---------------------------------> n
    1    10   100  1000

Pour n = 1000:
O(1)     = 1 operation
O(log n) = 10 operations
O(n)     = 1000 operations
O(n^2)   = 1000000 operations
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite de l'acces a un element d'un tableau par indice ?

A) O(n)
B) O(log n)
C) O(1)
D) O(n^2)
E) O(n log n)

**Reponse correcte: C**

### Question 2
Si un algorithme fait n iterations, et chaque iteration fait n operations, quelle est sa complexite ?

A) O(n)
B) O(2n)
C) O(n + n)
D) O(n^2)
E) O(n * 2)

**Reponse correcte: D**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.0-a",
  "name": "big_o_basics",
  "language": "c",
  "language_version": "c17",
  "files": ["big_o_basics.c", "big_o_basics.h"],
  "tests": {
    "constant": "constant_tests",
    "linear": "linear_tests",
    "quadratic": "quadratic_tests"
  }
}
```
