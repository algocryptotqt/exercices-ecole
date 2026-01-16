# Exercice 0.6.11-a : function_pointers

**Module :**
0.6.11 — Pointeurs de Fonctions

**Concept :**
a-c — typedef, callback, qsort

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
2 — Combinaison de concepts

**Langage :**
C17

**Prerequis :**
0.5 (bases C), pointeurs, fonctions

**Domaines :**
Pointeurs, Callbacks, Algorithmes

**Duree estimee :**
240 min

**XP Base :**
350

**Complexite :**
T1 O(n log n) pour tri x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `function_pointers.c`
- `function_pointers.h`

**Headers autorises :**
- `<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<stdbool.h>`

**Fonctions autorisees :**
- `qsort()`, `bsearch()`, `printf()`, `strcmp()`, `strlen()`

### 1.2 Consigne

Maitriser les pointeurs de fonctions en C: declaration, typedef, et utilisation comme callbacks.

**Ta mission :**

Creer un ensemble de fonctions utilisant des pointeurs de fonctions pour implementer des patterns generiques comme le tri, le filtrage et le mapping.

**Prototypes :**
```c
// Types de pointeurs de fonctions
typedef int (*compare_fn)(const void *, const void *);
typedef bool (*predicate_fn)(const void *);
typedef void (*transform_fn)(void *);
typedef void (*foreach_fn)(void *, void *);

// Comparateurs pour qsort/bsearch
int compare_int_asc(const void *a, const void *b);
int compare_int_desc(const void *a, const void *b);
int compare_string_asc(const void *a, const void *b);
int compare_string_desc(const void *a, const void *b);

// Tri generique utilisant qsort
void array_sort(void *base, size_t nmemb, size_t size, compare_fn cmp);

// Recherche binaire utilisant bsearch
void *array_search(const void *key, const void *base, size_t nmemb,
                   size_t size, compare_fn cmp);

// Filtre un tableau (retourne nouveau tableau alloue)
void *array_filter(const void *base, size_t nmemb, size_t size,
                   predicate_fn pred, size_t *out_count);

// Applique une transformation a chaque element (in-place)
void array_map(void *base, size_t nmemb, size_t size, transform_fn fn);

// Applique une fonction a chaque element avec contexte
void array_foreach(void *base, size_t nmemb, size_t size,
                   foreach_fn fn, void *context);

// Trouve le premier element satisfaisant le predicat
void *array_find(const void *base, size_t nmemb, size_t size,
                 predicate_fn pred);

// Compte les elements satisfaisant le predicat
size_t array_count_if(const void *base, size_t nmemb, size_t size,
                      predicate_fn pred);

// Verifie si tous les elements satisfont le predicat
bool array_all(const void *base, size_t nmemb, size_t size,
               predicate_fn pred);

// Verifie si au moins un element satisfait le predicat
bool array_any(const void *base, size_t nmemb, size_t size,
               predicate_fn pred);
```

**Comportement :**
- `array_sort` est un wrapper autour de qsort
- `array_filter` alloue un nouveau tableau (appelant doit free)
- `array_map` modifie le tableau en place
- `array_find` retourne NULL si non trouve
- Les predicats retournent true pour les elements a garder/compter

**Exemples :**
```
int arr[] = {3, 1, 4, 1, 5, 9, 2, 6};

array_sort(arr, 8, sizeof(int), compare_int_asc);
// arr = {1, 1, 2, 3, 4, 5, 6, 9}

bool is_even(const void *p) { return (*(int*)p) % 2 == 0; }
int *evens = array_filter(arr, 8, sizeof(int), is_even, &count);
// evens = {2, 4, 6}, count = 3

void double_it(void *p) { *(int*)p *= 2; }
array_map(arr, 8, sizeof(int), double_it);
// arr = {2, 2, 4, 6, 8, 10, 12, 18}
```

**Contraintes :**
- Utiliser typedef pour les types de pointeurs de fonctions
- Les fonctions doivent etre generiques (void*)
- Gerer les cas limites (tableau vide, NULL)
- Compiler avec `gcc -Wall -Werror -std=c17`

### 1.3 Prototype

```c
// function_pointers.h
#ifndef FUNCTION_POINTERS_H
#define FUNCTION_POINTERS_H

#include <stddef.h>
#include <stdbool.h>

typedef int (*compare_fn)(const void *, const void *);
typedef bool (*predicate_fn)(const void *);
typedef void (*transform_fn)(void *);
typedef void (*foreach_fn)(void *, void *);

int compare_int_asc(const void *a, const void *b);
int compare_int_desc(const void *a, const void *b);
int compare_string_asc(const void *a, const void *b);
int compare_string_desc(const void *a, const void *b);

void array_sort(void *base, size_t nmemb, size_t size, compare_fn cmp);
void *array_search(const void *key, const void *base, size_t nmemb,
                   size_t size, compare_fn cmp);
void *array_filter(const void *base, size_t nmemb, size_t size,
                   predicate_fn pred, size_t *out_count);
void array_map(void *base, size_t nmemb, size_t size, transform_fn fn);
void array_foreach(void *base, size_t nmemb, size_t size,
                   foreach_fn fn, void *context);
void *array_find(const void *base, size_t nmemb, size_t size,
                 predicate_fn pred);
size_t array_count_if(const void *base, size_t nmemb, size_t size,
                      predicate_fn pred);
bool array_all(const void *base, size_t nmemb, size_t size, predicate_fn pred);
bool array_any(const void *base, size_t nmemb, size_t size, predicate_fn pred);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Syntaxe des pointeurs de fonctions

Sans typedef:
```c
int (*compare)(const void *, const void *);  // Declaration
compare = &strcmp;  // Assignation
int result = compare("a", "b");  // Appel (ou (*compare)(...))
```

Avec typedef:
```c
typedef int (*compare_fn)(const void *, const void *);
compare_fn compare = strcmp;
```

### 2.2 qsort de la libc

```c
void qsort(void *base, size_t nmemb, size_t size,
           int (*compar)(const void *, const void *));
```
- Tri generique O(n log n) en moyenne
- Instable (elements egaux peuvent etre reordonnes)
- Le comparateur retourne: <0, 0, >0

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Embedded Developer**

Les pointeurs de fonctions sont utilises pour:
- Tables de dispatch (state machines)
- Callbacks d'interruption
- Plugins et extensions

**Metier : Game Developer**

Applications courantes:
- Systemes d'evenements
- Command pattern
- Scripting callbacks

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o test_fp test_main.c function_pointers.c
$ ./test_fp
Testing comparators...
  compare_int_asc(3, 5): -2 (negative) - OK
  compare_int_asc(5, 3): 2 (positive) - OK
  compare_int_asc(3, 3): 0 - OK
  compare_string_asc("apple", "banana"): negative - OK

Testing array_sort...
  Before: [3, 1, 4, 1, 5, 9, 2, 6]
  After (asc): [1, 1, 2, 3, 4, 5, 6, 9] - OK
  After (desc): [9, 6, 5, 4, 3, 2, 1, 1] - OK

Testing array_search...
  Searching for 5: found at index 5 - OK
  Searching for 7: not found - OK

Testing array_filter (even numbers)...
  Input: [1, 2, 3, 4, 5, 6, 7, 8]
  Output: [2, 4, 6, 8], count=4 - OK

Testing array_map (double)...
  Before: [1, 2, 3, 4, 5]
  After: [2, 4, 6, 8, 10] - OK

Testing array_foreach (sum)...
  Array: [1, 2, 3, 4, 5]
  Sum: 15 - OK

Testing array_find...
  Finding first even in [1, 3, 5, 6, 7]: 6 - OK

Testing array_count_if...
  Count evens in [1, 2, 3, 4, 5, 6]: 3 - OK

Testing array_all/any...
  all positive [1, 2, 3]: true - OK
  any negative [1, -2, 3]: true - OK

All tests passed!
$ echo $?
0
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★☆☆☆☆ (6/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Implementer des fonctions avancees avec pointeurs de fonctions.

```c
// Reduce (fold) sur un tableau
typedef void (*reduce_fn)(void *acc, const void *elem);
void *array_reduce(const void *base, size_t nmemb, size_t size,
                   reduce_fn fn, void *initial, size_t acc_size);

// Partition: separe en deux selon predicat
void array_partition(void *base, size_t nmemb, size_t size,
                     predicate_fn pred, size_t *pivot_idx);

// Table de dispatch
typedef void (*handler_fn)(void *data);
typedef struct {
    int code;
    handler_fn handler;
} dispatch_entry_t;

void dispatch(dispatch_entry_t *table, size_t count, int code, void *data);
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Input | Expected | Points |
|---------|-------------|-------|----------|--------|
| T01 | compare_int_asc | 3, 5 | negative | 10 |
| T02 | compare_int_desc | 3, 5 | positive | 5 |
| T03 | array_sort asc | unsorted | sorted asc | 15 |
| T04 | array_sort desc | unsorted | sorted desc | 10 |
| T05 | array_search found | exists | pointer | 10 |
| T06 | array_search missing | not exists | NULL | 5 |
| T07 | array_filter | mixed | filtered | 15 |
| T08 | array_map | array | transformed | 10 |
| T09 | array_find | array | first match | 10 |
| T10 | array_all/any | array | correct bool | 10 |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "function_pointers.h"

// Predicats de test
bool is_even(const void *p) { return (*(const int*)p) % 2 == 0; }
bool is_positive(const void *p) { return *(const int*)p > 0; }
bool is_negative(const void *p) { return *(const int*)p < 0; }

// Transform de test
void double_int(void *p) { *(int*)p *= 2; }

// Foreach de test (sum)
void sum_int(void *elem, void *ctx) { *(int*)ctx += *(int*)elem; }

int main(void)
{
    int pass = 0, fail = 0;

    // T01: compare_int_asc
    int a = 3, b = 5;
    if (compare_int_asc(&a, &b) < 0) {
        printf("T01 PASS: compare_int_asc(3, 5) < 0\n");
        pass++;
    } else {
        printf("T01 FAIL\n");
        fail++;
    }

    // T02: compare_int_desc
    if (compare_int_desc(&a, &b) > 0) {
        printf("T02 PASS: compare_int_desc(3, 5) > 0\n");
        pass++;
    } else {
        printf("T02 FAIL\n");
        fail++;
    }

    // T03: array_sort asc
    int arr[] = {3, 1, 4, 1, 5, 9, 2, 6};
    array_sort(arr, 8, sizeof(int), compare_int_asc);
    if (arr[0] == 1 && arr[7] == 9) {
        printf("T03 PASS: array_sort ascending\n");
        pass++;
    } else {
        printf("T03 FAIL\n");
        fail++;
    }

    // T04: array_sort desc
    array_sort(arr, 8, sizeof(int), compare_int_desc);
    if (arr[0] == 9 && arr[7] == 1) {
        printf("T04 PASS: array_sort descending\n");
        pass++;
    } else {
        printf("T04 FAIL\n");
        fail++;
    }

    // T05: array_search found
    array_sort(arr, 8, sizeof(int), compare_int_asc);  // Must be sorted
    int key = 5;
    int *found = array_search(&key, arr, 8, sizeof(int), compare_int_asc);
    if (found != NULL && *found == 5) {
        printf("T05 PASS: array_search found\n");
        pass++;
    } else {
        printf("T05 FAIL\n");
        fail++;
    }

    // T06: array_search missing
    key = 7;
    found = array_search(&key, arr, 8, sizeof(int), compare_int_asc);
    if (found == NULL) {
        printf("T06 PASS: array_search missing\n");
        pass++;
    } else {
        printf("T06 FAIL\n");
        fail++;
    }

    // T07: array_filter
    int nums[] = {1, 2, 3, 4, 5, 6, 7, 8};
    size_t count;
    int *evens = array_filter(nums, 8, sizeof(int), is_even, &count);
    if (evens != NULL && count == 4 && evens[0] == 2 && evens[3] == 8) {
        printf("T07 PASS: array_filter\n");
        pass++;
    } else {
        printf("T07 FAIL: count=%zu\n", count);
        fail++;
    }
    free(evens);

    // T08: array_map
    int to_double[] = {1, 2, 3, 4, 5};
    array_map(to_double, 5, sizeof(int), double_int);
    if (to_double[0] == 2 && to_double[4] == 10) {
        printf("T08 PASS: array_map\n");
        pass++;
    } else {
        printf("T08 FAIL\n");
        fail++;
    }

    // T09: array_find
    int mixed[] = {1, 3, 5, 6, 7};
    int *first_even = array_find(mixed, 5, sizeof(int), is_even);
    if (first_even != NULL && *first_even == 6) {
        printf("T09 PASS: array_find\n");
        pass++;
    } else {
        printf("T09 FAIL\n");
        fail++;
    }

    // T10: array_all/any
    int positives[] = {1, 2, 3};
    int with_neg[] = {1, -2, 3};
    if (array_all(positives, 3, sizeof(int), is_positive) &&
        array_any(with_neg, 3, sizeof(int), is_negative)) {
        printf("T10 PASS: array_all/any\n");
        pass++;
    } else {
        printf("T10 FAIL\n");
        fail++;
    }

    printf("\nResults: %d passed, %d failed\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
```

### 4.3 Solution de reference

```c
/*
 * function_pointers.c
 * Manipulation de pointeurs de fonctions
 * Exercice ex34_function_pointers
 */

#include "function_pointers.h"
#include <stdlib.h>
#include <string.h>

// Comparateurs
int compare_int_asc(const void *a, const void *b)
{
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    return ia - ib;
}

int compare_int_desc(const void *a, const void *b)
{
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    return ib - ia;
}

int compare_string_asc(const void *a, const void *b)
{
    const char *sa = *(const char **)a;
    const char *sb = *(const char **)b;
    return strcmp(sa, sb);
}

int compare_string_desc(const void *a, const void *b)
{
    const char *sa = *(const char **)a;
    const char *sb = *(const char **)b;
    return strcmp(sb, sa);
}

// Wrapper qsort
void array_sort(void *base, size_t nmemb, size_t size, compare_fn cmp)
{
    if (base == NULL || cmp == NULL || nmemb == 0)
    {
        return;
    }
    qsort(base, nmemb, size, cmp);
}

// Wrapper bsearch
void *array_search(const void *key, const void *base, size_t nmemb,
                   size_t size, compare_fn cmp)
{
    if (key == NULL || base == NULL || cmp == NULL || nmemb == 0)
    {
        return NULL;
    }
    return bsearch(key, base, nmemb, size, cmp);
}

// Filter
void *array_filter(const void *base, size_t nmemb, size_t size,
                   predicate_fn pred, size_t *out_count)
{
    if (base == NULL || pred == NULL || out_count == NULL)
    {
        if (out_count) *out_count = 0;
        return NULL;
    }

    // Premier passage: compter
    size_t count = 0;
    const char *ptr = base;
    for (size_t i = 0; i < nmemb; i++)
    {
        if (pred(ptr + i * size))
        {
            count++;
        }
    }

    if (count == 0)
    {
        *out_count = 0;
        return NULL;
    }

    // Allouer le resultat
    void *result = malloc(count * size);
    if (result == NULL)
    {
        *out_count = 0;
        return NULL;
    }

    // Deuxieme passage: copier
    char *dest = result;
    for (size_t i = 0; i < nmemb; i++)
    {
        if (pred(ptr + i * size))
        {
            memcpy(dest, ptr + i * size, size);
            dest += size;
        }
    }

    *out_count = count;
    return result;
}

// Map (in-place)
void array_map(void *base, size_t nmemb, size_t size, transform_fn fn)
{
    if (base == NULL || fn == NULL)
    {
        return;
    }

    char *ptr = base;
    for (size_t i = 0; i < nmemb; i++)
    {
        fn(ptr + i * size);
    }
}

// Foreach avec contexte
void array_foreach(void *base, size_t nmemb, size_t size,
                   foreach_fn fn, void *context)
{
    if (base == NULL || fn == NULL)
    {
        return;
    }

    char *ptr = base;
    for (size_t i = 0; i < nmemb; i++)
    {
        fn(ptr + i * size, context);
    }
}

// Find
void *array_find(const void *base, size_t nmemb, size_t size,
                 predicate_fn pred)
{
    if (base == NULL || pred == NULL)
    {
        return NULL;
    }

    const char *ptr = base;
    for (size_t i = 0; i < nmemb; i++)
    {
        if (pred(ptr + i * size))
        {
            return (void *)(ptr + i * size);
        }
    }

    return NULL;
}

// Count if
size_t array_count_if(const void *base, size_t nmemb, size_t size,
                      predicate_fn pred)
{
    if (base == NULL || pred == NULL)
    {
        return 0;
    }

    size_t count = 0;
    const char *ptr = base;
    for (size_t i = 0; i < nmemb; i++)
    {
        if (pred(ptr + i * size))
        {
            count++;
        }
    }

    return count;
}

// All
bool array_all(const void *base, size_t nmemb, size_t size, predicate_fn pred)
{
    if (base == NULL || pred == NULL || nmemb == 0)
    {
        return true;  // Vacuously true
    }

    const char *ptr = base;
    for (size_t i = 0; i < nmemb; i++)
    {
        if (!pred(ptr + i * size))
        {
            return false;
        }
    }

    return true;
}

// Any
bool array_any(const void *base, size_t nmemb, size_t size, predicate_fn pred)
{
    if (base == NULL || pred == NULL || nmemb == 0)
    {
        return false;
    }

    const char *ptr = base;
    for (size_t i = 0; i < nmemb; i++)
    {
        if (pred(ptr + i * size))
        {
            return true;
        }
    }

    return false;
}
```

### 4.4 Solutions alternatives acceptees

```c
// Alternative 1: compare_int sans soustraction (evite overflow)
int compare_int_asc(const void *a, const void *b)
{
    int ia = *(const int *)a;
    int ib = *(const int *)b;
    if (ia < ib) return -1;
    if (ia > ib) return 1;
    return 0;
}

// Alternative 2: filter en un seul passage avec realloc
void *array_filter(const void *base, size_t nmemb, size_t size,
                   predicate_fn pred, size_t *out_count)
{
    void *result = NULL;
    size_t count = 0;
    size_t capacity = 0;

    const char *ptr = base;
    for (size_t i = 0; i < nmemb; i++)
    {
        if (pred(ptr + i * size))
        {
            if (count >= capacity)
            {
                capacity = capacity == 0 ? 4 : capacity * 2;
                result = realloc(result, capacity * size);
            }
            memcpy((char*)result + count * size, ptr + i * size, size);
            count++;
        }
    }

    *out_count = count;
    return result;
}
```

### 4.5 Solutions refusees (avec explications)

```c
// REFUSE 1: Cast incorrect pour strings
int compare_string_asc(const void *a, const void *b)
{
    return strcmp(a, b);  // a et b sont char**, pas char*!
}
// Raison: qsort passe des pointeurs vers les elements

// REFUSE 2: Overflow dans compare_int
int compare_int_asc(const void *a, const void *b)
{
    return *(int*)a - *(int*)b;  // Overflow si INT_MAX - INT_MIN!
}
// Raison: Peut produire un resultat incorrect

// REFUSE 3: Pas de validation NULL
void array_map(void *base, size_t nmemb, size_t size, transform_fn fn)
{
    char *ptr = base;
    for (size_t i = 0; i < nmemb; i++)
        fn(ptr + i * size);  // Crash si base ou fn NULL!
}
// Raison: Segfault sur NULL
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.11-a",
  "name": "function_pointers",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["function_pointers.c", "function_pointers.h"],
    "test": ["test_function_pointers.c"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"],
    "output": "test_fp"
  },
  "tests": {
    "type": "unit",
    "valgrind": true,
    "leak_check": true
  },
  "scoring": {
    "total": 100,
    "compilation": 10,
    "functionality": 70,
    "memory_safety": 20
  }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```c
// MUTANT 1 (Logic): Compare inverse
int compare_int_asc(const void *a, const void *b)
{
    return *(int*)b - *(int*)a;  // Inverse!
}
// Detection: Tri decroissant au lieu de croissant

// MUTANT 2 (Logic): Cast string incorrect
int compare_string_asc(const void *a, const void *b)
{
    return strcmp((char*)a, (char*)b);  // Mauvais cast
}
// Detection: Crash ou mauvais tri

// MUTANT 3 (Memory): Filter ne free pas en erreur
void *array_filter(...)
{
    void *result = malloc(count * size);
    // ... erreur ...
    return NULL;  // result pas free!
}
// Detection: Valgrind leak

// MUTANT 4 (Logic): array_all retourne false pour vide
bool array_all(...)
{
    if (nmemb == 0) return false;  // Devrait etre true
}
// Detection: Echec sur tableau vide

// MUTANT 5 (Boundary): Off-by-one dans boucle
void array_map(void *base, size_t nmemb, size_t size, transform_fn fn)
{
    for (size_t i = 0; i <= nmemb; i++)  // <= au lieu de <
        fn(ptr + i * size);
}
// Detection: Acces hors limites
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **fondamentaux des pointeurs de fonctions** en C:

1. **typedef** - Simplifier la declaration
2. **callback** - Passer une fonction en argument
3. **qsort** - Tri generique avec comparateur

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION filtrer_tableau(tableau, taille, taille_elem, predicat):
DEBUT
    compte <- 0

    POUR i DE 0 A taille - 1 FAIRE
        SI predicat(tableau[i]) EST VRAI ALORS
            compte <- compte + 1
        FIN SI
    FIN POUR

    resultat <- allouer(compte * taille_elem)

    j <- 0
    POUR i DE 0 A taille - 1 FAIRE
        SI predicat(tableau[i]) EST VRAI ALORS
            copier(resultat[j], tableau[i])
            j <- j + 1
        FIN SI
    FIN POUR

    RETOURNER resultat
FIN
```

### 5.3 Visualisation ASCII

```
POINTEUR DE FONCTION
====================

Declaration sans typedef:
    int (*compare)(const void *, const void *)
         ^^^^^^^  ^^^^^^^^^^^^^^^^^^^^^^^^^^^
         nom      signature (params)

Avec typedef:
    typedef int (*compare_fn)(const void *, const void *);
    compare_fn cmp = compare_int_asc;

Memoire:
+------------------+       +------------------------+
| cmp = 0x401234   | ----> | compare_int_asc:       |
+------------------+       |   push rbp             |
                          |   mov rbp, rsp         |
                          |   ...                  |
                          |   ret                  |
                          +------------------------+

QSORT AVEC CALLBACK
===================

qsort(arr, 5, sizeof(int), compare_int_asc)

arr = [3, 1, 4, 1, 5]

1. qsort compare arr[0] et arr[1]:
   compare_int_asc(&arr[0], &arr[1])
   compare_int_asc(&3, &1) -> 2 (3 > 1)
   -> swap

2. arr = [1, 3, 4, 1, 5]
   ... continue jusqu'a tri complet ...

3. arr = [1, 1, 3, 4, 5]

PATTERN GENERIQUE
=================

void *base ---> [elem0][elem1][elem2][elem3]
                |<-sz->|

Acces a element i:
    void *elem = (char*)base + i * size;

Cast pour predicat:
    bool is_even(const void *p) {
        int val = *(const int*)p;
        return val % 2 == 0;
    }
```

### 5.4 Les pieges en detail

#### Piege 1: Cast incorrect pour qsort avec strings
```c
// FAUX - qsort passe char**, pas char*
int compare_str(const void *a, const void *b)
{
    return strcmp(a, b);  // WRONG!
}

// CORRECT
int compare_str(const void *a, const void *b)
{
    return strcmp(*(char**)a, *(char**)b);
}
```

#### Piege 2: Overflow dans comparateur
```c
// FAUX - INT_MAX - INT_MIN = overflow
int compare_int(const void *a, const void *b)
{
    return *(int*)a - *(int*)b;
}

// CORRECT
int compare_int(const void *a, const void *b)
{
    int ia = *(int*)a, ib = *(int*)b;
    if (ia < ib) return -1;
    if (ia > ib) return 1;
    return 0;
}
```

### 5.5 Cours Complet

#### 5.5.1 Declaration de pointeur de fonction

```c
// Sans typedef
return_type (*name)(param_types);

// Avec typedef
typedef return_type (*type_name)(param_types);
type_name name;
```

#### 5.5.2 Assignation et appel

```c
int add(int a, int b) { return a + b; }

// Assignation (& optionnel)
int (*op)(int, int) = add;
int (*op)(int, int) = &add;  // Equivalent

// Appel (* optionnel)
int result = op(1, 2);
int result = (*op)(1, 2);  // Equivalent
```

#### 5.5.3 Comme parametre

```c
void process(int *arr, size_t n, int (*fn)(int))
{
    for (size_t i = 0; i < n; i++)
        arr[i] = fn(arr[i]);
}
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| typedef pour lisibilite | Syntaxe complexe | `typedef int (*cmp_fn)(...)` |
| void* pour genericite | Type-agnostic | `void *base` |
| Valider NULL | Eviter crash | `if (fn == NULL) return;` |
| Documenter signature | Clarifier usage | `// returns <0, 0, >0` |

### 5.7 Simulation avec trace d'execution

```
Programme: array_filter([1,2,3,4,5], 5, sizeof(int), is_even, &count)

1. Verifier base != NULL, pred != NULL -> OK
2. Premier passage - compter:
   - is_even(&1) -> false
   - is_even(&2) -> true, count=1
   - is_even(&3) -> false
   - is_even(&4) -> true, count=2
   - is_even(&5) -> false
   Total: count = 2

3. Allouer result = malloc(2 * 4) = malloc(8)
   result = 0x5500001000

4. Deuxieme passage - copier:
   - is_even(&1) -> false, skip
   - is_even(&2) -> true, copy 2 to result[0]
   - is_even(&3) -> false, skip
   - is_even(&4) -> true, copy 4 to result[1]
   - is_even(&5) -> false, skip

5. *out_count = 2
6. return result

Resultat: [2, 4]
```

### 5.8 Mnemotechniques

**"TRSA" - Declaration pointeur fonction**
- **T**ype de retour
- **R**etour: (*nom)
- **S**ignature (params)
- **A**ssigner fonction

**"CVA" - Utilisation avec qsort**
- **C**omparateur: retourne <0, 0, >0
- **V**oid*: cast necessaire
- **A**dresse: qsort passe &element

### 5.9 Applications pratiques

1. **Tri personnalise**: qsort avec comparateur custom
2. **Callbacks**: Event handlers, async operations
3. **Plugins**: Chargement dynamique (dlopen)
4. **State machines**: Tables de dispatch

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Cast string incorrect | Crash/mauvais tri | `*(char**)a` |
| Overflow comparateur | Mauvais ordre | Comparaison explicite |
| NULL non verifie | Crash | Check avant appel |
| Oubli size param | Boucle infinie | Toujours passer size |
| Leak dans filter | Memory leak | Free en cas d'erreur |

---

## SECTION 7 : QCM

### Question 1
Comment declarer un pointeur vers une fonction retournant int et prenant deux int ?

A) `int *fn(int, int)`
B) `int (*fn)(int, int)`
C) `int fn*(int, int)`
D) `(*int)(fn)(int, int)`
E) `int *(fn)(int, int)`

**Reponse correcte: B**

### Question 2
Que doit retourner un comparateur pour qsort si a < b ?

A) -1 ou valeur negative
B) 0
C) 1 ou valeur positive
D) true
E) NULL

**Reponse correcte: A**

### Question 3
Pourquoi utiliser void* dans les fonctions generiques ?

A) C'est plus rapide
B) Pour accepter n'importe quel type de pointeur
C) C'est obligatoire en C17
D) Pour eviter les warnings
E) Ca utilise moins de memoire

**Reponse correcte: B**

### Question 4
Quelle est la complexite de qsort en moyenne ?

A) O(n)
B) O(n log n)
C) O(n^2)
D) O(log n)
E) O(1)

**Reponse correcte: B**

### Question 5
Pourquoi est-il dangereux de faire `return *(int*)a - *(int*)b` dans un comparateur ?

A) C'est trop lent
B) Ca peut causer un overflow
C) Ce n'est pas portable
D) Ca ne compile pas
E) Il n'y a pas de danger

**Reponse correcte: B**

---

## SECTION 8 : RECAPITULATIF

| Pattern | Syntaxe |
|---------|---------|
| Declaration | `return_type (*name)(params)` |
| Typedef | `typedef ret (*type)(params)` |
| Assignation | `fn_ptr = function_name` |
| Appel | `result = fn_ptr(args)` |

| Fonction stdlib | Description |
|-----------------|-------------|
| qsort | Tri generique |
| bsearch | Recherche binaire |
| atexit | Callback a la fin |
| signal | Handler de signaux |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.11-a",
    "name": "function_pointers",
    "module": "0.6.11",
    "phase": 0,
    "difficulty": 5,
    "xp": 350,
    "time_minutes": 240
  },
  "metadata": {
    "concepts": ["typedef", "callback", "qsort"],
    "prerequisites": ["0.5", "pointers", "functions"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "function_pointers.c",
    "header": "function_pointers.h",
    "solution": "function_pointers_solution.c",
    "test": "test_function_pointers.c"
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"]
  },
  "grading": {
    "automated": true,
    "valgrind_required": true,
    "compilation_weight": 10,
    "functionality_weight": 70,
    "memory_weight": 20
  },
  "bonus": {
    "available": true,
    "multiplier": 2,
    "difficulty": 6
  }
}
```
