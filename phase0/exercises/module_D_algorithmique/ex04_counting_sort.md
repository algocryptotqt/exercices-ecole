# Exercice D.0.4-a : counting_sort

**Module :**
D.0.4 — Tri par Comptage

**Concept :**
a-e — Counting sort, bucket sort, radix sort, non-comparison sorts

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.14 (arrays), 0.6.24 (malloc)

**Domaines :**
Algo

**Duree estimee :**
120 min

**XP Base :**
160

**Complexite :**
T2 O(n+k) x S2 O(k)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `counting_sort.c`
- `counting_sort.h`

### 1.2 Consigne

Implementer des algorithmes de tri sans comparaison.

**Ta mission :**

```c
// Counting sort basique (valeurs 0 a max_val)
void counting_sort(int *arr, int n, int max_val);

// Counting sort stable (preserve l'ordre des egaux)
void counting_sort_stable(int *arr, int n, int max_val);

// Bucket sort pour valeurs [0, 1) (floats)
void bucket_sort(float *arr, int n);

// Radix sort (tri par base)
void radix_sort(int *arr, int n);

// Compter les occurrences
void count_frequencies(int *arr, int n, int *freq, int max_val);

// Tri de caracteres (alphabetique)
void sort_chars(char *str);

// Trouver le k-ieme plus petit sans tri complet
int kth_smallest_counting(int *arr, int n, int k, int max_val);
```

**Comportement:**

1. `counting_sort({4,2,2,8,3,3,1}, 7, 9)` -> {1,2,2,3,3,4,8}
2. `sort_chars("dcba")` -> "abcd"
3. `radix_sort({170,45,75,90,802,24,2,66}, 8)` -> sorted
4. `kth_smallest_counting({4,2,1,3,5}, 5, 2, 5)` -> 2

**Exemples:**
```
counting_sort({4, 2, 2, 8, 3}, max_val=9):

Step 1: Compter les occurrences
count[0]=0, count[1]=0, count[2]=2, count[3]=1, count[4]=1, ..., count[8]=1

Step 2: Reconstruire
Output: {2, 2, 3, 4, 8}

radix_sort({170, 45, 75, 90}):
Sort by units:   {170, 90, 45, 75}
Sort by tens:    {45, 75, 170, 90}
Sort by hundreds:{45, 75, 90, 170}
```

### 1.3 Prototype

```c
// counting_sort.h
#ifndef COUNTING_SORT_H
#define COUNTING_SORT_H

void counting_sort(int *arr, int n, int max_val);
void counting_sort_stable(int *arr, int n, int max_val);
void bucket_sort(float *arr, int n);
void radix_sort(int *arr, int n);
void count_frequencies(int *arr, int n, int *freq, int max_val);
void sort_chars(char *str);
int kth_smallest_counting(int *arr, int n, int k, int max_val);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | counting_sort basic | sorted | 15 |
| T02 | counting_sort_stable | stable sort | 15 |
| T03 | radix_sort | sorted | 20 |
| T04 | bucket_sort floats | sorted | 15 |
| T05 | sort_chars | alphabetical | 10 |
| T06 | kth_smallest | correct value | 15 |
| T07 | edge cases | handled | 10 |

### 4.3 Solution de reference

```c
#include <stdlib.h>
#include <string.h>
#include "counting_sort.h"

void count_frequencies(int *arr, int n, int *freq, int max_val)
{
    for (int i = 0; i <= max_val; i++)
        freq[i] = 0;

    for (int i = 0; i < n; i++)
        freq[arr[i]]++;
}

void counting_sort(int *arr, int n, int max_val)
{
    int *count = calloc(max_val + 1, sizeof(int));
    if (!count)
        return;

    // Compter les occurrences
    for (int i = 0; i < n; i++)
        count[arr[i]]++;

    // Reconstruire le tableau
    int idx = 0;
    for (int i = 0; i <= max_val; i++)
    {
        while (count[i] > 0)
        {
            arr[idx++] = i;
            count[i]--;
        }
    }

    free(count);
}

void counting_sort_stable(int *arr, int n, int max_val)
{
    int *count = calloc(max_val + 1, sizeof(int));
    int *output = malloc(n * sizeof(int));
    if (!count || !output)
    {
        free(count);
        free(output);
        return;
    }

    // Compter
    for (int i = 0; i < n; i++)
        count[arr[i]]++;

    // Somme cumulative
    for (int i = 1; i <= max_val; i++)
        count[i] += count[i - 1];

    // Construire output (parcours inverse pour stabilite)
    for (int i = n - 1; i >= 0; i--)
    {
        output[count[arr[i]] - 1] = arr[i];
        count[arr[i]]--;
    }

    // Copier resultat
    memcpy(arr, output, n * sizeof(int));

    free(count);
    free(output);
}

void bucket_sort(float *arr, int n)
{
    if (n <= 1)
        return;

    // Creer n buckets
    typedef struct node {
        float val;
        struct node *next;
    } node_t;

    node_t **buckets = calloc(n, sizeof(node_t *));
    if (!buckets)
        return;

    // Distribuer dans les buckets
    for (int i = 0; i < n; i++)
    {
        int bi = (int)(n * arr[i]);  // Index du bucket
        if (bi >= n) bi = n - 1;

        node_t *new_node = malloc(sizeof(node_t));
        new_node->val = arr[i];
        new_node->next = buckets[bi];
        buckets[bi] = new_node;
    }

    // Trier chaque bucket (insertion sort) et concatener
    int idx = 0;
    for (int i = 0; i < n; i++)
    {
        // Extraire les valeurs du bucket
        int count = 0;
        for (node_t *p = buckets[i]; p; p = p->next)
            count++;

        if (count > 0)
        {
            float *temp = malloc(count * sizeof(float));
            int j = 0;
            for (node_t *p = buckets[i]; p; p = p->next)
                temp[j++] = p->val;

            // Insertion sort sur temp
            for (int k = 1; k < count; k++)
            {
                float key = temp[k];
                int l = k - 1;
                while (l >= 0 && temp[l] > key)
                {
                    temp[l + 1] = temp[l];
                    l--;
                }
                temp[l + 1] = key;
            }

            // Copier dans arr
            for (int k = 0; k < count; k++)
                arr[idx++] = temp[k];

            free(temp);
        }

        // Liberer bucket
        node_t *p = buckets[i];
        while (p)
        {
            node_t *next = p->next;
            free(p);
            p = next;
        }
    }

    free(buckets);
}

// Helper pour radix sort
static int get_max(int *arr, int n)
{
    int max = arr[0];
    for (int i = 1; i < n; i++)
        if (arr[i] > max)
            max = arr[i];
    return max;
}

static void counting_sort_digit(int *arr, int n, int exp)
{
    int *output = malloc(n * sizeof(int));
    int count[10] = {0};

    for (int i = 0; i < n; i++)
        count[(arr[i] / exp) % 10]++;

    for (int i = 1; i < 10; i++)
        count[i] += count[i - 1];

    for (int i = n - 1; i >= 0; i--)
    {
        output[count[(arr[i] / exp) % 10] - 1] = arr[i];
        count[(arr[i] / exp) % 10]--;
    }

    memcpy(arr, output, n * sizeof(int));
    free(output);
}

void radix_sort(int *arr, int n)
{
    if (n <= 1)
        return;

    int max = get_max(arr, n);

    for (int exp = 1; max / exp > 0; exp *= 10)
        counting_sort_digit(arr, n, exp);
}

void sort_chars(char *str)
{
    int count[256] = {0};
    int len = strlen(str);

    for (int i = 0; i < len; i++)
        count[(unsigned char)str[i]]++;

    int idx = 0;
    for (int i = 0; i < 256; i++)
    {
        while (count[i] > 0)
        {
            str[idx++] = (char)i;
            count[i]--;
        }
    }
}

int kth_smallest_counting(int *arr, int n, int k, int max_val)
{
    int *count = calloc(max_val + 1, sizeof(int));
    if (!count)
        return -1;

    for (int i = 0; i < n; i++)
        count[arr[i]]++;

    int seen = 0;
    for (int i = 0; i <= max_val; i++)
    {
        seen += count[i];
        if (seen >= k)
        {
            free(count);
            return i;
        }
    }

    free(count);
    return -1;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: counting_sort off-by-one
void counting_sort(int *arr, int n, int max_val)
{
    int *count = calloc(max_val, sizeof(int));  // max_val au lieu de max_val+1
    // count[max_val] n'existe pas -> buffer overflow
}

// MUTANT 2: counting_sort_stable pas stable
void counting_sort_stable(int *arr, int n, int max_val)
{
    // ...
    for (int i = 0; i < n; i++)  // i=0 vers n au lieu de n-1 vers 0
    {
        output[count[arr[i]] - 1] = arr[i];
        count[arr[i]]--;
    }
    // L'ordre des egaux n'est pas preserve
}

// MUTANT 3: radix_sort mauvais exp
void radix_sort(int *arr, int n)
{
    int max = get_max(arr, n);
    for (int exp = 1; max / exp > 0; exp += 10)  // += au lieu de *=
        counting_sort_digit(arr, n, exp);
}

// MUTANT 4: kth_smallest off-by-one
int kth_smallest_counting(int *arr, int n, int k, int max_val)
{
    // ...
    int seen = 0;
    for (int i = 0; i <= max_val; i++)
    {
        seen += count[i];
        if (seen > k)  // > au lieu de >=
        {
            return i;
        }
    }
    return -1;
}

// MUTANT 5: sort_chars ne gere pas caracteres negatifs
void sort_chars(char *str)
{
    int count[128] = {0};  // 128 au lieu de 256
    // Caracteres > 127 causeront buffer overflow
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **tris sans comparaison**:

1. **Counting sort** - O(n+k) pour valeurs [0, k]
2. **Radix sort** - O(d*(n+b)) pour d digits en base b
3. **Bucket sort** - O(n) en moyenne pour distribution uniforme
4. **Quand les utiliser** - Quand k ou d sont petits

### 5.3 Visualisation ASCII

```
COUNTING SORT de {4, 2, 2, 8, 3}:

Step 1: Compter
arr:   [4, 2, 2, 8, 3]

count: [0, 0, 2, 1, 1, 0, 0, 0, 1]
index:  0  1  2  3  4  5  6  7  8
              ^  ^  ^        ^
              2x 1x 1x       1x

Step 2: Reconstruire
i=2: output 2, 2
i=3: output 3
i=4: output 4
i=8: output 8

Result: [2, 2, 3, 4, 8]

RADIX SORT de {170, 45, 75, 90}:

Tri par unites (exp=1):
170 -> 0
 45 -> 5
 75 -> 5
 90 -> 0
=> [170, 90, 45, 75]

Tri par dizaines (exp=10):
170 -> 7
 90 -> 9
 45 -> 4
 75 -> 7
=> [45, 170, 75, 90]

Tri par centaines (exp=100):
=> [45, 75, 90, 170]
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite du counting sort ?

A) O(n log n)
B) O(n^2)
C) O(n + k)
D) O(k log k)
E) O(n * k)

**Reponse correcte: C**

### Question 2
Quand counting sort est-il preferable a quicksort ?

A) Toujours
B) Quand k (max value) est petit par rapport a n
C) Quand le tableau est deja trie
D) Quand on veut un tri stable
E) Jamais, quicksort est toujours meilleur

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.4-a",
  "name": "counting_sort",
  "language": "c",
  "language_version": "c17",
  "files": ["counting_sort.c", "counting_sort.h"],
  "tests": {
    "counting": "counting_sort_tests",
    "radix": "radix_sort_tests",
    "bucket": "bucket_sort_tests"
  }
}
```
