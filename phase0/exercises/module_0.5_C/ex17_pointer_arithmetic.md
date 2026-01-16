# Exercice 0.5.17-a : pointer_arithmetic

**Module :**
0.5.17 — Arithmetique des Pointeurs

**Concept :**
a-c — p++, p + n, p - q

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.16 (pointer_intro)

**Domaines :**
Algo, Systeme

**Duree estimee :**
180 min

**XP Base :**
200

**Complexite :**
T2 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `pointer_arithmetic.c`
- `pointer_arithmetic.h`

**Fonctions autorisees :**
- Aucune fonction de bibliotheque requise

### 1.2 Consigne

Implementer des fonctions utilisant l'arithmetique des pointeurs.

**Ta mission :**

```c
// Obtenir le n-ieme element via pointeur
int get_nth(int *arr, int n);

// Parcourir avec pointeur et compter les positifs
int count_positive(int *start, int *end);

// Distance entre deux pointeurs (nombre d'elements)
int ptr_distance(int *start, int *end);

// Trouver un element, retourner son pointeur
int *find_element(int *arr, int size, int target);

// Somme en utilisant uniquement l'arithmetique de pointeurs
int sum_with_ptr(int *arr, int size);

// Copier un tableau en utilisant des pointeurs
void copy_with_ptr(int *dest, int *src, int count);

// Inverser un tableau avec deux pointeurs
void reverse_with_ptr(int *arr, int size);

// Avancer un pointeur de n positions et retourner la valeur
int advance_and_read(int **ptr, int n);
```

**Comportement:**

1. `get_nth(arr, 3)`: Retourne *(arr + 3)
2. `count_positive(start, end)`: Compte positifs de start a end (exclu)
3. `ptr_distance(start, end)`: Retourne end - start
4. `find_element(arr, 5, 42)`: Retourne pointeur vers 42 ou NULL
5. `sum_with_ptr(arr, 5)`: Somme sans utiliser arr[i]
6. `reverse_with_ptr(arr, 5)`: Inverse le tableau

**Exemples:**
```
int arr[] = {10, 20, 30, 40, 50};

get_nth(arr, 2)              -> 30

int *start = arr;
int *end = arr + 5;
ptr_distance(start, end)     -> 5

int data[] = {-1, 2, -3, 4, -5};
count_positive(data, data + 5) -> 2

sum_with_ptr(arr, 5)         -> 150

find_element(arr, 5, 30)     -> &arr[2]
find_element(arr, 5, 99)     -> NULL

reverse_with_ptr(arr, 5);
// arr = {50, 40, 30, 20, 10}
```

### 1.3 Prototype

```c
// pointer_arithmetic.h
#ifndef POINTER_ARITHMETIC_H
#define POINTER_ARITHMETIC_H

int get_nth(int *arr, int n);
int count_positive(int *start, int *end);
int ptr_distance(int *start, int *end);
int *find_element(int *arr, int size, int target);
int sum_with_ptr(int *arr, int size);
void copy_with_ptr(int *dest, int *src, int count);
void reverse_with_ptr(int *arr, int size);
int advance_and_read(int **ptr, int n);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | get_nth(arr, 2) | 30 | 10 |
| T02 | get_nth(arr, 0) | 10 | 5 |
| T03 | ptr_distance(arr, arr+5) | 5 | 10 |
| T04 | count_positive({-1,2,-3,4}) | 2 | 10 |
| T05 | sum_with_ptr({1,2,3,4,5}, 5) | 15 | 10 |
| T06 | find_element found | correct ptr | 10 |
| T07 | find_element not found | NULL | 10 |
| T08 | copy_with_ptr test | identical | 10 |
| T09 | reverse_with_ptr test | reversed | 15 |
| T10 | Compilation | No warnings | 10 |

### 4.3 Solution de reference

```c
#include "pointer_arithmetic.h"
#include <stddef.h>

int get_nth(int *arr, int n)
{
    return *(arr + n);
}

int count_positive(int *start, int *end)
{
    int count = 0;
    int *p = start;

    while (p < end)
    {
        if (*p > 0)
            count++;
        p++;
    }
    return count;
}

int ptr_distance(int *start, int *end)
{
    return (int)(end - start);
}

int *find_element(int *arr, int size, int target)
{
    int *p = arr;
    int *end = arr + size;

    while (p < end)
    {
        if (*p == target)
            return p;
        p++;
    }
    return NULL;
}

int sum_with_ptr(int *arr, int size)
{
    int sum = 0;
    int *p = arr;
    int *end = arr + size;

    while (p < end)
    {
        sum += *p;
        p++;
    }
    return sum;
}

void copy_with_ptr(int *dest, int *src, int count)
{
    int *d = dest;
    int *s = src;
    int *end = src + count;

    while (s < end)
    {
        *d = *s;
        d++;
        s++;
    }
}

void reverse_with_ptr(int *arr, int size)
{
    int *left = arr;
    int *right = arr + size - 1;

    while (left < right)
    {
        int temp = *left;
        *left = *right;
        *right = temp;
        left++;
        right--;
    }
}

int advance_and_read(int **ptr, int n)
{
    *ptr = *ptr + n;
    return **ptr;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Oubli que p+n ajoute n*sizeof(int)
int get_nth(int *arr, int n)
{
    // Faux: pense que chaque element = 1 byte
    return *((char *)arr + n);  // Lit un seul octet!
}

// MUTANT 2: Distance en bytes au lieu d'elements
int ptr_distance(int *start, int *end)
{
    return (int)((char *)end - (char *)start);  // Retourne bytes!
}

// MUTANT 3: Condition <= au lieu de <
int count_positive(int *start, int *end)
{
    int count = 0;
    int *p = start;

    while (p <= end)  // Accede un element de trop!
    {
        if (*p > 0)
            count++;
        p++;
    }
    return count;
}

// MUTANT 4: Reverse qui ne fonctionne pas
void reverse_with_ptr(int *arr, int size)
{
    int *left = arr;
    int *right = arr + size;  // Devrait etre size - 1

    while (left < right)
    {
        int temp = *left;
        *left = *right;  // Acces hors limites!
        *right = temp;
        left++;
        right--;
    }
}

// MUTANT 5: advance_and_read modifie le mauvais niveau
int advance_and_read(int **ptr, int n)
{
    ptr = ptr + n;  // Modifie la copie locale, pas le pointeur original
    return **ptr;
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

L'**arithmetique des pointeurs** en C:
- **p++** : avance au prochain element (pas au prochain byte)
- **p + n** : pointe n elements plus loin
- **p - q** : nombre d'elements entre deux pointeurs
- C ajuste automatiquement selon la taille du type

### 5.3 Visualisation ASCII

```
int arr[5] = {10, 20, 30, 40, 50};
int *p = arr;

Memoire (int = 4 bytes):
Adresse: 0x100   0x104   0x108   0x10C   0x110
       +-------+-------+-------+-------+-------+
       |  10   |  20   |  30   |  40   |  50   |
       +-------+-------+-------+-------+-------+
          ^       ^               ^
          |       |               |
          p      p+1            p+3
        arr    arr+1           arr+3

Arithmetique:
  p + 1     -> 0x104 (pas 0x101!)
  p + 3     -> 0x10C
  *(p + 2)  -> 30

Soustraction:
  int *end = arr + 5;  // 0x114
  end - arr  -> 5 (elements, pas 20 bytes)

Parcours:
  while (p < end)
  {
      process(*p);
      p++;  // Avance de sizeof(int) bytes
  }
```

### 5.5 Cours Complet

#### Addition sur pointeurs

```c
int arr[5] = {10, 20, 30, 40, 50};
int *p = arr;

// Ces deux sont equivalents:
arr[3]      // 40
*(arr + 3)  // 40
*(p + 3)    // 40
```

#### Incrementation

```c
int *p = arr;
p++;        // p pointe maintenant vers arr[1]
++p;        // p pointe maintenant vers arr[2]
```

#### Difference de pointeurs

```c
int *start = arr;
int *end = arr + 5;

ptrdiff_t diff = end - start;  // 5 (elements)
// Note: end - start est du type ptrdiff_t
```

#### Comparaison de pointeurs

```c
int *p = arr;
int *end = arr + 5;

while (p < end)  // Comparaison valide sur meme tableau
{
    // ...
    p++;
}
```

---

## SECTION 7 : QCM

### Question 1
Si `int *p = arr;` et `int` fait 4 bytes, que vaut `p + 1` par rapport a `p` ?

A) p + 1 byte
B) p + 4 bytes
C) p + 8 bytes
D) Depend du compilateur
E) Erreur de compilation

**Reponse correcte: B**

### Question 2
Que retourne `end - start` si les deux pointent dans le meme tableau ?

A) Difference en bytes
B) Difference en elements
C) Toujours 0
D) Undefined behavior
E) Adresse moyenne

**Reponse correcte: B**

### Question 3
`*(arr + 3)` est equivalent a:

A) arr + 3
B) &arr[3]
C) arr[3]
D) *arr + 3
E) arr * 3

**Reponse correcte: C**

### Question 4
Apres `int *p = arr; p++;`, que vaut *p ?

A) Premier element
B) Deuxieme element
C) Dernier element
D) NULL
E) L'adresse de arr

**Reponse correcte: B**

### Question 5
Peut-on faire `p1 - p2` si p1 et p2 pointent vers des tableaux differents ?

A) Oui, toujours
B) Non, jamais
C) Resultat indefini / non garanti
D) Seulement si meme type
E) Compile mais crash

**Reponse correcte: C**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.17-a",
  "name": "pointer_arithmetic",
  "language": "c",
  "language_version": "c17",
  "files": ["pointer_arithmetic.c", "pointer_arithmetic.h"],
  "tests": {
    "get_nth": [[0], [2], [4]],
    "distance": [[0,5], [1,4], [2,2]],
    "find": [[42, true], [99, false]],
    "sum": [[1,2,3,4,5], [0], [-1,-2,-3]]
  }
}
```
