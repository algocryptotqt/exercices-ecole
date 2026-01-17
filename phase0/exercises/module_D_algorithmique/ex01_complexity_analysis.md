# Exercice D.0.1-a : complexity_analysis

**Module :**
D.0.1 — Analyse de Complexite

**Concept :**
a-e — Worst case, best case, average case, amortized analysis

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
D.0.0 (big_o_basics)

**Domaines :**
Algo

**Duree estimee :**
120 min

**XP Base :**
150

**Complexite :**
Variable

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `complexity_analysis.c`
- `complexity_analysis.h`

### 1.2 Consigne

Analyser et mesurer la complexite de differents algorithmes.

**Ta mission :**

```c
// Recherche lineaire - mesure operations
typedef struct {
    int comparisons;
    int result;
} search_result_t;

search_result_t linear_search_analyzed(int *arr, int n, int target);

// Insertion sort avec comptage
typedef struct {
    int comparisons;
    int swaps;
} sort_stats_t;

sort_stats_t insertion_sort_analyzed(int *arr, int n);

// Analyser complexite d'une fonction
// Retourne le nombre d'operations pour une taille n
int analyze_nested_loops(int n);
int analyze_log_loop(int n);
int analyze_linear_log(int n);

// Verifier si complexite est dans les bornes attendues
int verify_complexity_linear(int ops, int n);
int verify_complexity_quadratic(int ops, int n);
int verify_complexity_logarithmic(int ops, int n);
```

**Comportement:**

1. `linear_search_analyzed({1,2,3,4,5}, 5, 3)` -> {comparisons: 3, result: 2}
2. `analyze_nested_loops(10)` -> 100 (n^2)
3. `verify_complexity_linear(100, 100)` -> 1 (valid)

**Exemples:**
```
linear_search_analyzed pour target=3 dans {1,2,3,4,5}:
  Compare 1 != 3 (1 comparison)
  Compare 2 != 3 (2 comparisons)
  Compare 3 == 3 (3 comparisons) -> FOUND at index 2

Best case: O(1) - element au debut
Worst case: O(n) - element a la fin ou absent
Average case: O(n/2) = O(n)
```

### 1.3 Prototype

```c
// complexity_analysis.h
#ifndef COMPLEXITY_ANALYSIS_H
#define COMPLEXITY_ANALYSIS_H

typedef struct {
    int comparisons;
    int result;
} search_result_t;

typedef struct {
    int comparisons;
    int swaps;
} sort_stats_t;

search_result_t linear_search_analyzed(int *arr, int n, int target);
sort_stats_t insertion_sort_analyzed(int *arr, int n);

int analyze_nested_loops(int n);
int analyze_log_loop(int n);
int analyze_linear_log(int n);

int verify_complexity_linear(int ops, int n);
int verify_complexity_quadratic(int ops, int n);
int verify_complexity_logarithmic(int ops, int n);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | linear_search best | 1 comparison | 10 |
| T02 | linear_search worst | n comparisons | 15 |
| T03 | insertion_sort sorted | O(n) comps | 15 |
| T04 | insertion_sort reverse | O(n^2) comps | 15 |
| T05 | analyze_nested(100) | 10000 | 15 |
| T06 | analyze_log(1024) | ~10 | 15 |
| T07 | verify functions | correct bounds | 15 |

### 4.3 Solution de reference

```c
#include "complexity_analysis.h"

search_result_t linear_search_analyzed(int *arr, int n, int target)
{
    search_result_t res = {0, -1};

    for (int i = 0; i < n; i++)
    {
        res.comparisons++;
        if (arr[i] == target)
        {
            res.result = i;
            return res;
        }
    }
    return res;
}

sort_stats_t insertion_sort_analyzed(int *arr, int n)
{
    sort_stats_t stats = {0, 0};

    for (int i = 1; i < n; i++)
    {
        int key = arr[i];
        int j = i - 1;

        while (j >= 0)
        {
            stats.comparisons++;
            if (arr[j] > key)
            {
                arr[j + 1] = arr[j];
                stats.swaps++;
                j--;
            }
            else
            {
                break;
            }
        }
        arr[j + 1] = key;
    }
    return stats;
}

int analyze_nested_loops(int n)
{
    int ops = 0;
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            ops++;
        }
    }
    return ops;  // n^2
}

int analyze_log_loop(int n)
{
    int ops = 0;
    while (n > 0)
    {
        ops++;
        n = n / 2;
    }
    return ops;  // log2(n) + 1
}

int analyze_linear_log(int n)
{
    int ops = 0;
    for (int i = 0; i < n; i++)
    {
        int temp = n;
        while (temp > 0)
        {
            ops++;
            temp = temp / 2;
        }
    }
    return ops;  // n * log2(n)
}

int verify_complexity_linear(int ops, int n)
{
    // ops devrait etre proche de n (tolerance 10%)
    return (ops >= n * 0.9 && ops <= n * 1.1);
}

int verify_complexity_quadratic(int ops, int n)
{
    int expected = n * n;
    // Tolerance de 10%
    return (ops >= expected * 0.9 && ops <= expected * 1.1);
}

int verify_complexity_logarithmic(int ops, int n)
{
    // Calcul log2 approximatif
    int log_n = 0;
    int temp = n;
    while (temp > 0)
    {
        log_n++;
        temp = temp / 2;
    }
    // Tolerance: ops entre log_n - 1 et log_n + 1
    return (ops >= log_n - 1 && ops <= log_n + 1);
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Ne compte pas toutes les comparaisons
search_result_t linear_search_analyzed(int *arr, int n, int target)
{
    search_result_t res = {0, -1};
    for (int i = 0; i < n; i++)
    {
        if (arr[i] == target)
        {
            res.comparisons++;  // Compte seulement quand trouve
            res.result = i;
            return res;
        }
    }
    return res;
}

// MUTANT 2: insertion_sort ne compte pas les swaps correctement
sort_stats_t insertion_sort_analyzed(int *arr, int n)
{
    sort_stats_t stats = {0, 0};
    for (int i = 1; i < n; i++)
    {
        int key = arr[i];
        int j = i - 1;
        while (j >= 0 && arr[j] > key)
        {
            arr[j + 1] = arr[j];
            // Oublie: stats.swaps++;
            j--;
        }
        arr[j + 1] = key;
    }
    return stats;
}

// MUTANT 3: analyze_log_loop off-by-one
int analyze_log_loop(int n)
{
    int ops = 0;
    while (n > 1)  // > 1 au lieu de > 0
    {
        ops++;
        n = n / 2;
    }
    return ops;  // Manque une iteration
}

// MUTANT 4: verify avec mauvaises bornes
int verify_complexity_linear(int ops, int n)
{
    return (ops == n);  // Trop strict, pas de tolerance
}

// MUTANT 5: analyze_nested_loops mauvais comptage
int analyze_nested_loops(int n)
{
    int ops = 0;
    for (int i = 0; i < n; i++)
    {
        for (int j = i; j < n; j++)  // j=i au lieu de j=0
        {
            ops++;  // Compte n*(n+1)/2, pas n^2
        }
    }
    return ops;
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

L'**analyse de complexite**:

1. **Best case** - Scenario le plus favorable
2. **Worst case** - Scenario le plus defavorable
3. **Average case** - Comportement moyen
4. **Mesure empirique** - Compter les operations

### 5.3 Visualisation ASCII

```
INSERTION SORT - Cas extremes:

BEST CASE (deja trie): [1, 2, 3, 4, 5]
i=1: 2 > 1? Non, 0 swap  (1 comparison)
i=2: 3 > 2? Non, 0 swap  (1 comparison)
...
Total: n-1 comparisons, 0 swaps = O(n)

WORST CASE (inverse): [5, 4, 3, 2, 1]
i=1: 4 < 5, 1 swap       (1 comparison)
i=2: 3 < 4 < 5, 2 swaps  (2 comparisons)
i=3: 2 < 3 < 4 < 5       (3 comparisons)
i=4: 1 < 2 < 3 < 4 < 5   (4 comparisons)
Total: n(n-1)/2 comparisons = O(n^2)

GRAPHE COMPARAISONS:
     ^
comps|         /  <- worst (n^2)
     |       /
     |     /
     |   /______ <- best (n)
     +-----------> n
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite worst-case de la recherche lineaire ?

A) O(1)
B) O(log n)
C) O(n)
D) O(n^2)
E) O(n log n)

**Reponse correcte: C**

### Question 2
Pour insertion sort, quel input produit le best case ?

A) Tableau aleatoire
B) Tableau trie en ordre inverse
C) Tableau deja trie
D) Tableau avec tous elements identiques
E) C ou D

**Reponse correcte: E**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.1-a",
  "name": "complexity_analysis",
  "language": "c",
  "language_version": "c17",
  "files": ["complexity_analysis.c", "complexity_analysis.h"],
  "tests": {
    "search": "search_analysis_tests",
    "sort": "sort_analysis_tests",
    "verify": "verify_tests"
  }
}
```
