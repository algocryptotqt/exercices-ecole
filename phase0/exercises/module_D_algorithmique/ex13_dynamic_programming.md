# Exercice D.0.13-a : dynamic_programming

**Module :**
D.0.13 — Programmation Dynamique

**Concept :**
a-e — Memoization, tabulation, optimal substructure, overlapping subproblems

**Difficulte :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
code

**Tiers :**
2 — Melange concepts

**Langage :**
C17

**Prerequis :**
D.0.6 (recursion)

**Domaines :**
Algo

**Duree estimee :**
240 min

**XP Base :**
320

**Complexite :**
Variable selon probleme

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `dynamic_programming.c`
- `dynamic_programming.h`

### 1.2 Consigne

Implementer des algorithmes de programmation dynamique classiques.

**Ta mission :**

```c
// Fibonacci avec memoization
long fib_memo(int n);

// Fibonacci avec tabulation
long fib_tab(int n);

// Plus longue sous-sequence commune (LCS)
int lcs_length(const char *s1, const char *s2);
char *lcs_string(const char *s1, const char *s2);

// Plus longue sous-sequence croissante (LIS)
int lis_length(int *arr, int n);
int *lis_sequence(int *arr, int n, int *result_len);

// Probleme du sac a dos (0/1 Knapsack)
int knapsack(int *weights, int *values, int n, int capacity);

// Edit distance (Levenshtein)
int edit_distance(const char *s1, const char *s2);

// Nombre de chemins dans une grille
long grid_paths(int m, int n);

// Somme maximale de sous-tableau (Kadane)
int max_subarray_sum(int *arr, int n);
```

**Comportement:**

1. `fib_memo(50)` -> 12586269025 (en O(n), pas O(2^n))
2. `lcs_length("ABCDGH", "AEDFHR")` -> 3 ("ADH")
3. `edit_distance("kitten", "sitting")` -> 3
4. `max_subarray_sum({-2,1,-3,4,-1,2,1,-5,4}, 9)` -> 6

**Exemples:**
```
Fibonacci:
fib_tab(10) = 55

LCS de "ABCBDAB" et "BDCAB":
LCS = "BCAB" (longueur 4)

Edit distance "cat" -> "car":
cat -> car (remplacer t par r) = 1

Knapsack:
weights = [10, 20, 30], values = [60, 100, 120]
capacity = 50
max_value = 220 (items 2 et 3)
```

### 1.3 Prototype

```c
// dynamic_programming.h
#ifndef DYNAMIC_PROGRAMMING_H
#define DYNAMIC_PROGRAMMING_H

long fib_memo(int n);
long fib_tab(int n);
int lcs_length(const char *s1, const char *s2);
char *lcs_string(const char *s1, const char *s2);
int lis_length(int *arr, int n);
int *lis_sequence(int *arr, int n, int *result_len);
int knapsack(int *weights, int *values, int n, int capacity);
int edit_distance(const char *s1, const char *s2);
long grid_paths(int m, int n);
int max_subarray_sum(int *arr, int n);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | fib_memo(50) | correct | 10 |
| T02 | fib_tab(50) | correct | 10 |
| T03 | lcs_length | correct | 15 |
| T04 | edit_distance | correct | 15 |
| T05 | knapsack | optimal | 15 |
| T06 | lis_length | correct | 10 |
| T07 | grid_paths | correct | 10 |
| T08 | max_subarray_sum | correct | 15 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dynamic_programming.h"

// Fibonacci avec memoization
static long fib_helper(int n, long *memo)
{
    if (memo[n] != -1)
        return memo[n];

    if (n <= 1)
        memo[n] = n;
    else
        memo[n] = fib_helper(n - 1, memo) + fib_helper(n - 2, memo);

    return memo[n];
}

long fib_memo(int n)
{
    if (n < 0)
        return 0;

    long *memo = malloc((n + 1) * sizeof(long));
    for (int i = 0; i <= n; i++)
        memo[i] = -1;

    long result = fib_helper(n, memo);
    free(memo);
    return result;
}

// Fibonacci avec tabulation
long fib_tab(int n)
{
    if (n < 0)
        return 0;
    if (n <= 1)
        return n;

    long *dp = malloc((n + 1) * sizeof(long));
    dp[0] = 0;
    dp[1] = 1;

    for (int i = 2; i <= n; i++)
        dp[i] = dp[i - 1] + dp[i - 2];

    long result = dp[n];
    free(dp);
    return result;
}

// LCS length
int lcs_length(const char *s1, const char *s2)
{
    int m = strlen(s1);
    int n = strlen(s2);

    int **dp = malloc((m + 1) * sizeof(int *));
    for (int i = 0; i <= m; i++)
    {
        dp[i] = calloc(n + 1, sizeof(int));
    }

    for (int i = 1; i <= m; i++)
    {
        for (int j = 1; j <= n; j++)
        {
            if (s1[i - 1] == s2[j - 1])
                dp[i][j] = dp[i - 1][j - 1] + 1;
            else
                dp[i][j] = (dp[i - 1][j] > dp[i][j - 1]) ? dp[i - 1][j] : dp[i][j - 1];
        }
    }

    int result = dp[m][n];

    for (int i = 0; i <= m; i++)
        free(dp[i]);
    free(dp);

    return result;
}

// Edit distance (Levenshtein)
int edit_distance(const char *s1, const char *s2)
{
    int m = strlen(s1);
    int n = strlen(s2);

    int **dp = malloc((m + 1) * sizeof(int *));
    for (int i = 0; i <= m; i++)
    {
        dp[i] = malloc((n + 1) * sizeof(int));
    }

    // Base cases
    for (int i = 0; i <= m; i++)
        dp[i][0] = i;
    for (int j = 0; j <= n; j++)
        dp[0][j] = j;

    // Fill DP table
    for (int i = 1; i <= m; i++)
    {
        for (int j = 1; j <= n; j++)
        {
            if (s1[i - 1] == s2[j - 1])
            {
                dp[i][j] = dp[i - 1][j - 1];
            }
            else
            {
                int insert = dp[i][j - 1];
                int delete = dp[i - 1][j];
                int replace = dp[i - 1][j - 1];

                int min = insert < delete ? insert : delete;
                min = min < replace ? min : replace;
                dp[i][j] = 1 + min;
            }
        }
    }

    int result = dp[m][n];

    for (int i = 0; i <= m; i++)
        free(dp[i]);
    free(dp);

    return result;
}

// Knapsack 0/1
int knapsack(int *weights, int *values, int n, int capacity)
{
    int **dp = malloc((n + 1) * sizeof(int *));
    for (int i = 0; i <= n; i++)
        dp[i] = calloc(capacity + 1, sizeof(int));

    for (int i = 1; i <= n; i++)
    {
        for (int w = 0; w <= capacity; w++)
        {
            if (weights[i - 1] <= w)
            {
                int include = values[i - 1] + dp[i - 1][w - weights[i - 1]];
                int exclude = dp[i - 1][w];
                dp[i][w] = (include > exclude) ? include : exclude;
            }
            else
            {
                dp[i][w] = dp[i - 1][w];
            }
        }
    }

    int result = dp[n][capacity];

    for (int i = 0; i <= n; i++)
        free(dp[i]);
    free(dp);

    return result;
}

// LIS length
int lis_length(int *arr, int n)
{
    if (n == 0)
        return 0;

    int *dp = malloc(n * sizeof(int));
    for (int i = 0; i < n; i++)
        dp[i] = 1;

    int max_len = 1;
    for (int i = 1; i < n; i++)
    {
        for (int j = 0; j < i; j++)
        {
            if (arr[j] < arr[i] && dp[j] + 1 > dp[i])
                dp[i] = dp[j] + 1;
        }
        if (dp[i] > max_len)
            max_len = dp[i];
    }

    free(dp);
    return max_len;
}

// Grid paths
long grid_paths(int m, int n)
{
    long **dp = malloc(m * sizeof(long *));
    for (int i = 0; i < m; i++)
        dp[i] = malloc(n * sizeof(long));

    // First row and column
    for (int i = 0; i < m; i++)
        dp[i][0] = 1;
    for (int j = 0; j < n; j++)
        dp[0][j] = 1;

    // Fill rest
    for (int i = 1; i < m; i++)
    {
        for (int j = 1; j < n; j++)
        {
            dp[i][j] = dp[i - 1][j] + dp[i][j - 1];
        }
    }

    long result = dp[m - 1][n - 1];

    for (int i = 0; i < m; i++)
        free(dp[i]);
    free(dp);

    return result;
}

// Kadane's algorithm
int max_subarray_sum(int *arr, int n)
{
    if (n == 0)
        return 0;

    int max_ending_here = arr[0];
    int max_so_far = arr[0];

    for (int i = 1; i < n; i++)
    {
        max_ending_here = (arr[i] > max_ending_here + arr[i]) ? arr[i] : max_ending_here + arr[i];
        max_so_far = (max_so_far > max_ending_here) ? max_so_far : max_ending_here;
    }

    return max_so_far;
}

// LCS string (bonus)
char *lcs_string(const char *s1, const char *s2)
{
    int m = strlen(s1);
    int n = strlen(s2);

    // Build DP table
    int **dp = malloc((m + 1) * sizeof(int *));
    for (int i = 0; i <= m; i++)
        dp[i] = calloc(n + 1, sizeof(int));

    for (int i = 1; i <= m; i++)
    {
        for (int j = 1; j <= n; j++)
        {
            if (s1[i - 1] == s2[j - 1])
                dp[i][j] = dp[i - 1][j - 1] + 1;
            else
                dp[i][j] = (dp[i - 1][j] > dp[i][j - 1]) ? dp[i - 1][j] : dp[i][j - 1];
        }
    }

    // Backtrack to find LCS
    int len = dp[m][n];
    char *lcs = malloc(len + 1);
    lcs[len] = '\0';

    int i = m, j = n;
    while (i > 0 && j > 0)
    {
        if (s1[i - 1] == s2[j - 1])
        {
            lcs[--len] = s1[i - 1];
            i--;
            j--;
        }
        else if (dp[i - 1][j] > dp[i][j - 1])
        {
            i--;
        }
        else
        {
            j--;
        }
    }

    for (int k = 0; k <= m; k++)
        free(dp[k]);
    free(dp);

    return lcs;
}

// LIS sequence (bonus)
int *lis_sequence(int *arr, int n, int *result_len)
{
    if (n == 0)
    {
        *result_len = 0;
        return NULL;
    }

    int *dp = malloc(n * sizeof(int));
    int *parent = malloc(n * sizeof(int));

    for (int i = 0; i < n; i++)
    {
        dp[i] = 1;
        parent[i] = -1;
    }

    int max_len = 1;
    int max_idx = 0;

    for (int i = 1; i < n; i++)
    {
        for (int j = 0; j < i; j++)
        {
            if (arr[j] < arr[i] && dp[j] + 1 > dp[i])
            {
                dp[i] = dp[j] + 1;
                parent[i] = j;
            }
        }
        if (dp[i] > max_len)
        {
            max_len = dp[i];
            max_idx = i;
        }
    }

    // Reconstruct sequence
    *result_len = max_len;
    int *result = malloc(max_len * sizeof(int));
    int idx = max_idx;
    for (int k = max_len - 1; k >= 0; k--)
    {
        result[k] = arr[idx];
        idx = parent[idx];
    }

    free(dp);
    free(parent);
    return result;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: fib_memo sans memo (recursion naive)
long fib_memo(int n)
{
    if (n <= 1)
        return n;
    return fib_memo(n - 1) + fib_memo(n - 2);
    // O(2^n) au lieu de O(n)!
}

// MUTANT 2: LCS ne gere pas cas de base
int lcs_length(const char *s1, const char *s2)
{
    int m = strlen(s1);
    int n = strlen(s2);
    // Manque initialisation dp[0][j] = 0 et dp[i][0] = 0
}

// MUTANT 3: edit_distance mauvais min
int edit_distance(const char *s1, const char *s2)
{
    // ...
    dp[i][j] = 1 + insert + delete + replace;  // Somme au lieu de min!
}

// MUTANT 4: Kadane ne gere pas tous negatifs
int max_subarray_sum(int *arr, int n)
{
    int max_so_far = 0;  // Devrait etre arr[0]
    // Si tous negatifs, retourne 0
}

// MUTANT 5: knapsack permet reutilisation
int knapsack(int *weights, int *values, int n, int capacity)
{
    // Utilise dp[i][w] = dp[i][w-weights[i-1]] au lieu de dp[i-1][...]
    // Permet d'utiliser le meme item plusieurs fois
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

La **programmation dynamique**:

1. **Optimal substructure** - Solution optimale contient sous-solutions optimales
2. **Overlapping subproblems** - Memes sous-problemes resolus plusieurs fois
3. **Memoization** - Top-down avec cache
4. **Tabulation** - Bottom-up avec tableau

### 5.3 Visualisation ASCII

```
FIBONACCI RECURSION vs DP:

Recursion naive fib(5):
                fib(5)
               /      \
          fib(4)      fib(3)     <- fib(3) calcule 2x!
         /    \        /   \
      fib(3) fib(2)  fib(2) fib(1)
       ...    ...      ...

Avec memoization:
fib(5) -> cache miss -> calcule
  fib(4) -> cache miss -> calcule
    fib(3) -> cache miss -> calcule
      fib(2) -> cache miss -> calcule
      fib(1) -> cache miss -> calcule
    fib(2) -> CACHE HIT!
  fib(3) -> CACHE HIT!

DP TABLE POUR LCS("ABCD", "ACD"):

     ""  A  C  D
""   0   0  0  0
A    0   1  1  1
B    0   1  1  1
C    0   1  2  2
D    0   1  2  3

LCS = "ACD", length = 3
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la difference entre memoization et tabulation ?

A) Pas de difference
B) Memoization = top-down, Tabulation = bottom-up
C) Tabulation est plus rapide
D) Memoization utilise plus de memoire
E) Tabulation ne fonctionne que pour Fibonacci

**Reponse correcte: B**

### Question 2
Quelle est la complexite de l'edit distance pour deux chaines de longueur n ?

A) O(n)
B) O(n log n)
C) O(n^2)
D) O(2^n)
E) O(n!)

**Reponse correcte: C**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.13-a",
  "name": "dynamic_programming",
  "language": "c",
  "language_version": "c17",
  "files": ["dynamic_programming.c", "dynamic_programming.h"],
  "tests": {
    "fibonacci": "fib_tests",
    "lcs": "lcs_tests",
    "edit_distance": "edit_distance_tests",
    "knapsack": "knapsack_tests"
  }
}
```
