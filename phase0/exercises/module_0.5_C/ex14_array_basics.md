# Exercice 0.5.14-a : array_basics

**Module :**
0.5.14 — Tableaux

**Concept :**
a-e — int arr[10], arr[0], Initialization {}, Fixed size, No bounds check

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.10 (scope_lifetime)

**Domaines :**
Algo

**Duree estimee :**
150 min

**XP Base :**
180

**Complexite :**
T2 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `array_basics.c`
- `array_basics.h`

**Fonctions autorisees :**
- Aucune fonction de bibliotheque requise

### 1.2 Consigne

Implementer des fonctions de manipulation de tableaux unidimensionnels.

**Ta mission :**

Creer les fonctions suivantes:

```c
// Somme des elements
int array_sum(int arr[], int size);

// Trouver le minimum
int array_min(int arr[], int size);

// Trouver le maximum
int array_max(int arr[], int size);

// Calculer la moyenne (entiere)
int array_average(int arr[], int size);

// Compter les occurrences d'une valeur
int array_count(int arr[], int size, int value);

// Inverser le tableau en place
void array_reverse(int arr[], int size);

// Copier un tableau
void array_copy(int dest[], int src[], int size);

// Remplir avec une valeur
void array_fill(int arr[], int size, int value);
```

**Comportement:**

1. `array_sum({1,2,3,4,5}, 5)` -> 15
2. `array_min({3,1,4,1,5}, 5)` -> 1
3. `array_max({3,1,4,1,5}, 5)` -> 5
4. `array_average({10,20,30}, 3)` -> 20
5. `array_count({1,2,1,3,1}, 5, 1)` -> 3
6. `array_reverse({1,2,3,4}, 4)` -> {4,3,2,1}
7. `array_copy(dest, src, size)` -> copie src dans dest
8. `array_fill(arr, 5, 0)` -> {0,0,0,0,0}

**Exemples:**
```
int data[5] = {1, 2, 3, 4, 5};
array_sum(data, 5)      -> 15

int vals[5] = {3, 1, 4, 1, 5};
array_min(vals, 5)      -> 1
array_max(vals, 5)      -> 5
array_count(vals, 5, 1) -> 2

int nums[4] = {1, 2, 3, 4};
array_reverse(nums, 4);
// nums = {4, 3, 2, 1}

array_average({10, 20, 30, 40}, 4) -> 25
```

### 1.3 Prototype

```c
// array_basics.h
#ifndef ARRAY_BASICS_H
#define ARRAY_BASICS_H

int array_sum(int arr[], int size);
int array_min(int arr[], int size);
int array_max(int arr[], int size);
int array_average(int arr[], int size);
int array_count(int arr[], int size, int value);
void array_reverse(int arr[], int size);
void array_copy(int dest[], int src[], int size);
void array_fill(int arr[], int size, int value);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | array_sum({1,2,3,4,5}, 5) | 15 | 10 |
| T02 | array_sum({}, 0) | 0 | 5 |
| T03 | array_min({3,1,4,1,5}, 5) | 1 | 10 |
| T04 | array_max({3,1,4,1,5}, 5) | 5 | 10 |
| T05 | array_average({10,20,30}, 3) | 20 | 10 |
| T06 | array_count({1,2,1,3,1}, 5, 1) | 3 | 10 |
| T07 | array_reverse({1,2,3,4}, 4) | {4,3,2,1} | 10 |
| T08 | array_copy test | identical arrays | 10 |
| T09 | array_fill({?,?,?}, 3, 7) | {7,7,7} | 10 |
| T10 | Negative values | correct handling | 5 |
| T11 | Compilation | No warnings | 10 |

### 4.3 Solution de reference

```c
#include "array_basics.h"

int array_sum(int arr[], int size)
{
    int sum = 0;
    for (int i = 0; i < size; i++)
    {
        sum += arr[i];
    }
    return sum;
}

int array_min(int arr[], int size)
{
    if (size <= 0)
        return 0;

    int min = arr[0];
    for (int i = 1; i < size; i++)
    {
        if (arr[i] < min)
            min = arr[i];
    }
    return min;
}

int array_max(int arr[], int size)
{
    if (size <= 0)
        return 0;

    int max = arr[0];
    for (int i = 1; i < size; i++)
    {
        if (arr[i] > max)
            max = arr[i];
    }
    return max;
}

int array_average(int arr[], int size)
{
    if (size <= 0)
        return 0;

    int sum = array_sum(arr, size);
    return sum / size;
}

int array_count(int arr[], int size, int value)
{
    int count = 0;
    for (int i = 0; i < size; i++)
    {
        if (arr[i] == value)
            count++;
    }
    return count;
}

void array_reverse(int arr[], int size)
{
    for (int i = 0; i < size / 2; i++)
    {
        int temp = arr[i];
        arr[i] = arr[size - 1 - i];
        arr[size - 1 - i] = temp;
    }
}

void array_copy(int dest[], int src[], int size)
{
    for (int i = 0; i < size; i++)
    {
        dest[i] = src[i];
    }
}

void array_fill(int arr[], int size, int value)
{
    for (int i = 0; i < size; i++)
    {
        arr[i] = value;
    }
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Off-by-one dans la boucle
int array_sum(int arr[], int size)
{
    int sum = 0;
    for (int i = 0; i <= size; i++)  // <= au lieu de <
    {
        sum += arr[i];  // Acces hors limites!
    }
    return sum;
}

// MUTANT 2: Min initialise a 0 au lieu de arr[0]
int array_min(int arr[], int size)
{
    int min = 0;  // Si tous les elements sont positifs, retourne 0
    for (int i = 0; i < size; i++)
    {
        if (arr[i] < min)
            min = arr[i];
    }
    return min;
}

// MUTANT 3: Reverse qui ne va qu'a la moitie
void array_reverse(int arr[], int size)
{
    for (int i = 0; i < size; i++)  // Devrait etre size/2
    {
        int temp = arr[i];
        arr[i] = arr[size - 1 - i];
        arr[size - 1 - i] = temp;
        // Re-inverse ce qui a deja ete inverse!
    }
}

// MUTANT 4: Division par zero potentielle
int array_average(int arr[], int size)
{
    int sum = array_sum(arr, size);
    return sum / size;  // Crash si size == 0
}

// MUTANT 5: Copy dans le mauvais sens
void array_copy(int dest[], int src[], int size)
{
    for (int i = 0; i < size; i++)
    {
        src[i] = dest[i];  // Inverse! Ecrase la source
    }
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **tableaux en C**:
- **Declaration** : `int arr[10];` reserve 10 entiers contigus
- **Acces** : `arr[0]` est le premier element, `arr[9]` le dernier
- **Initialisation** : `int arr[] = {1, 2, 3};` ou `int arr[5] = {0};`
- **Taille fixe** : la taille doit etre connue a la compilation
- **Pas de verification** : C ne verifie pas les depassements

### 5.3 Visualisation ASCII

```
Declaration: int arr[5];

Memoire:
+-------+-------+-------+-------+-------+
| arr[0]| arr[1]| arr[2]| arr[3]| arr[4]|
+-------+-------+-------+-------+-------+
   ^
   |
  arr (adresse du premier element)

Indices:    0       1       2       3       4
Adresses: 0x100   0x104   0x108   0x10C   0x110
          (chaque int = 4 octets)

Initialisation:
int a[5] = {1, 2, 3};
+---+---+---+---+---+
| 1 | 2 | 3 | 0 | 0 |  <- reste initialise a 0
+---+---+---+---+---+

int b[5] = {0};
+---+---+---+---+---+
| 0 | 0 | 0 | 0 | 0 |  <- tout a 0
+---+---+---+---+---+
```

### 5.5 Cours Complet

#### Declaration et initialisation

```c
// Declaration simple
int arr[10];  // 10 entiers, valeurs indeterminees

// Initialisation complete
int arr[5] = {1, 2, 3, 4, 5};

// Initialisation partielle (reste = 0)
int arr[5] = {1, 2};  // {1, 2, 0, 0, 0}

// Taille implicite
int arr[] = {1, 2, 3};  // Taille = 3

// Tout a zero
int arr[100] = {0};
```

#### Attention: pas de bounds checking

```c
int arr[5] = {1, 2, 3, 4, 5};
arr[10] = 42;  // DANGER: ecriture hors limites
               // Compile sans erreur!
               // Comportement indefini
```

---

## SECTION 7 : QCM

### Question 1
Quel est l'index du premier element d'un tableau en C ?

A) 1
B) 0
C) -1
D) Depend de la declaration
E) Indefini

**Reponse correcte: B**

### Question 2
Que contient `arr` apres `int arr[5] = {1, 2};` ?

A) {1, 2, garbage, garbage, garbage}
B) {1, 2, 0, 0, 0}
C) {1, 2}
D) Erreur de compilation
E) {0, 0, 1, 2, 0}

**Reponse correcte: B**

### Question 3
Que se passe-t-il si on accede a `arr[10]` sur un tableau de taille 5 ?

A) Erreur de compilation
B) Exception a l'execution
C) Retourne 0
D) Comportement indefini
E) Retourne -1

**Reponse correcte: D**

### Question 4
Comment obtenir la taille d'un tableau local `int arr[10]` ?

A) arr.length
B) len(arr)
C) sizeof(arr) / sizeof(arr[0])
D) size(arr)
E) arr.size()

**Reponse correcte: C**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.14-a",
  "name": "array_basics",
  "language": "c",
  "language_version": "c17",
  "files": ["array_basics.c", "array_basics.h"],
  "tests": {
    "sum": [[1,2,3,4,5], [], [-1,-2,-3]],
    "min_max": [[3,1,4,1,5], [5], [-5,-1,-10]],
    "reverse": [[1,2,3,4], [1], [1,2]]
  }
}
```
