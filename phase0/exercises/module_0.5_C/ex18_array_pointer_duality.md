# Exercice 0.5.18-a : array_pointer_duality

**Module :**
0.5.18 — Dualite Tableau-Pointeur

**Concept :**
a-d — arr == &arr[0], arr[i] == *(arr+i), Passing arrays, sizeof

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.17 (pointer_arithmetic)

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
- `array_pointer_duality.c`
- `array_pointer_duality.h`

**Fonctions autorisees :**
- Aucune fonction de bibliotheque requise

### 1.2 Consigne

Implementer des fonctions demontrant l'equivalence entre tableaux et pointeurs.

**Ta mission :**

```c
// Demontrer arr[i] == *(arr + i)
int access_bracket(int *arr, int index);
int access_pointer(int *arr, int index);

// Calculer la taille d'un tableau (version macro/inline pour vrai sizeof)
// Note: impossible en fonction car decay, donc:
// On passe la taille en parametre et on la verifie
int verify_size(int *arr, int size, int expected);

// Somme utilisant notation tableau
int sum_bracket(int *arr, int size);

// Somme utilisant notation pointeur
int sum_pointer(int *arr, int size);

// Modifier via notation tableau
void set_bracket(int *arr, int index, int value);

// Modifier via notation pointeur
void set_pointer(int *arr, int index, int value);

// Trouver element avec notation pointeur pure
int *find_ptr_notation(int *arr, int size, int target);

// Comparer deux methodes d'acces (retourne 1 si identiques)
int compare_access_methods(int *arr, int size);

// Passer un tableau et retourner l'adresse du premier element
int *get_first_address(int arr[]);
```

**Comportement:**

1. `access_bracket(arr, 2)` et `access_pointer(arr, 2)` retournent la meme valeur
2. `sum_bracket` et `sum_pointer` donnent le meme resultat
3. `set_bracket` et `set_pointer` ont le meme effet
4. `compare_access_methods` verifie que arr[i] == *(arr+i) pour tout i

**Exemples:**
```
int data[] = {10, 20, 30, 40, 50};

access_bracket(data, 2)         -> 30
access_pointer(data, 2)         -> 30

sum_bracket(data, 5)            -> 150
sum_pointer(data, 5)            -> 150

set_bracket(data, 0, 100);
// data[0] = 100

set_pointer(data, 1, 200);
// data[1] = 200 (via *(data + 1) = 200)

compare_access_methods(data, 5) -> 1 (toujours vrai)

get_first_address(data)         -> &data[0] (== data)
```

### 1.3 Prototype

```c
// array_pointer_duality.h
#ifndef ARRAY_POINTER_DUALITY_H
#define ARRAY_POINTER_DUALITY_H

// Macro pour sizeof sur tableaux locaux
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int access_bracket(int *arr, int index);
int access_pointer(int *arr, int index);
int verify_size(int *arr, int size, int expected);
int sum_bracket(int *arr, int size);
int sum_pointer(int *arr, int size);
void set_bracket(int *arr, int index, int value);
void set_pointer(int *arr, int index, int value);
int *find_ptr_notation(int *arr, int size, int target);
int compare_access_methods(int *arr, int size);
int *get_first_address(int arr[]);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | access_bracket(arr, 2) | arr[2] | 10 |
| T02 | access_pointer(arr, 2) | *(arr+2) | 10 |
| T03 | Both access equal | true | 5 |
| T04 | sum_bracket({1,2,3,4,5}) | 15 | 10 |
| T05 | sum_pointer({1,2,3,4,5}) | 15 | 10 |
| T06 | set_bracket effect | correct | 10 |
| T07 | set_pointer effect | correct | 10 |
| T08 | find_ptr_notation found | correct ptr | 10 |
| T09 | compare_access_methods | 1 | 10 |
| T10 | get_first_address | arr | 5 |
| T11 | Compilation | No warnings | 10 |

### 4.3 Solution de reference

```c
#include "array_pointer_duality.h"
#include <stddef.h>

int access_bracket(int *arr, int index)
{
    return arr[index];
}

int access_pointer(int *arr, int index)
{
    return *(arr + index);
}

int verify_size(int *arr, int size, int expected)
{
    (void)arr;  // arr est "decayed" en pointeur, sizeof inutile
    return (size == expected) ? 1 : 0;
}

int sum_bracket(int *arr, int size)
{
    int sum = 0;
    for (int i = 0; i < size; i++)
    {
        sum += arr[i];  // Notation tableau
    }
    return sum;
}

int sum_pointer(int *arr, int size)
{
    int sum = 0;
    int *p = arr;
    int *end = arr + size;

    while (p < end)
    {
        sum += *p;  // Notation pointeur
        p++;
    }
    return sum;
}

void set_bracket(int *arr, int index, int value)
{
    arr[index] = value;
}

void set_pointer(int *arr, int index, int value)
{
    *(arr + index) = value;
}

int *find_ptr_notation(int *arr, int size, int target)
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

int compare_access_methods(int *arr, int size)
{
    for (int i = 0; i < size; i++)
    {
        if (arr[i] != *(arr + i))
            return 0;  // Ne devrait jamais arriver
    }
    return 1;
}

int *get_first_address(int arr[])
{
    return arr;  // arr "decays" en &arr[0]
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Confusion entre adresse et valeur
int access_pointer(int *arr, int index)
{
    return (int)(arr + index);  // Retourne l'adresse, pas la valeur!
}

// MUTANT 2: sizeof sur pointeur passe en parametre
int bad_size(int arr[], int expected)
{
    // ERREUR COURANTE: sizeof(arr) ici = sizeof(int*)
    int size = sizeof(arr) / sizeof(arr[0]);
    return (size == expected) ? 1 : 0;
}

// MUTANT 3: Oubli de dereferencer pour set
void set_pointer(int *arr, int index, int value)
{
    arr + index = value;  // Erreur de compilation
    // Ou pire:
    // (arr + index) == value;  // Comparaison au lieu d'affectation
}

// MUTANT 4: Retourne adresse locale
int *bad_get_first(int arr[])
{
    int local = arr[0];
    return &local;  // Dangling pointer!
}

// MUTANT 5: Compare adresses au lieu de valeurs
int compare_access_methods(int *arr, int size)
{
    for (int i = 0; i < size; i++)
    {
        if (&arr[i] != (arr + i))  // Compare adresses (toujours egal)
            return 0;
    }
    return 1;  // Fonctionne mais teste mal
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

La **dualite tableau-pointeur** en C:
- **arr == &arr[0]** : le nom du tableau "decay" en pointeur vers le premier element
- **arr[i] == *(arr + i)** : notation crochet = sucre syntaxique
- **Passage aux fonctions** : tableaux passes comme pointeurs
- **sizeof** : fonctionne sur tableau local, pas sur pointeur

### 5.3 Visualisation ASCII

```
int arr[5] = {10, 20, 30, 40, 50};

Equivalences:
+-------+-------+-------+-------+-------+
|  10   |  20   |  30   |  40   |  50   |
+-------+-------+-------+-------+-------+
   ^       ^       ^       ^       ^
   |       |       |       |       |
arr[0]  arr[1]  arr[2]  arr[3]  arr[4]
*(arr) *(arr+1) *(arr+2) *(arr+3) *(arr+4)

Decay en pointeur:
+-------+                      +-------+
|  arr  | ------------------>  | arr[0]|
+-------+  (pointe vers)       +-------+
   ||
   ||  Quand passe a une fonction:
   vv
+-------+
| int * |  (devient un simple pointeur)
+-------+

sizeof comportement:
  int arr[5];
  sizeof(arr)           -> 20 (5 * 4 bytes)
  sizeof(&arr[0])       -> 8  (taille d'un pointeur)

  void foo(int arr[]) {
      sizeof(arr);      -> 8  (arr est devenu un pointeur!)
  }
```

### 5.5 Cours Complet

#### Equivalence fondamentale

```c
int arr[5];

// Ces expressions sont identiques:
arr[3]          // Notation tableau
*(arr + 3)      // Notation pointeur
*(3 + arr)      // Commutativite
3[arr]          // Syntaxe valide mais bizarre!
```

#### Decay (degradation)

```c
int arr[5] = {1, 2, 3, 4, 5};

// arr "decay" en pointeur dans la plupart des contextes
int *p = arr;       // OK: arr devient &arr[0]
arr++;              // ERREUR: arr n'est pas modifiable!

// Exceptions ou arr reste un tableau:
sizeof(arr)         // 20, pas sizeof(int*)
&arr                // Type: int (*)[5], pas int**
```

#### Passage aux fonctions

```c
// Ces declarations sont EQUIVALENTES:
void foo(int arr[]);
void foo(int arr[5]);   // Le 5 est ignore!
void foo(int *arr);

// Dans la fonction, arr est un pointeur:
void foo(int arr[])
{
    sizeof(arr);    // = sizeof(int*), pas la taille du tableau!
}

// Solution: passer la taille explicitement
void foo(int *arr, int size);
```

#### Macro sizeof pour tableaux

```c
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int main(void)
{
    int data[10];
    int size = ARRAY_SIZE(data);  // 10
    // Fonctionne car data est encore un vrai tableau ici
}
```

---

## SECTION 7 : QCM

### Question 1
`arr[i]` est equivalent a:

A) arr + i
B) &arr[i]
C) *(arr + i)
D) *arr + i
E) i[arr]  // attention!

**Reponse correcte: C** (Note: E est aussi valide mais inhabituel)

### Question 2
Dans une fonction `void f(int arr[])`, que vaut sizeof(arr) ?

A) La taille du tableau
B) Le nombre d'elements
C) sizeof(int*)
D) 0
E) Erreur de compilation

**Reponse correcte: C**

### Question 3
Pourquoi `arr == &arr[0]` ?

A) Ce n'est pas vrai
B) Decay: le nom du tableau devient pointeur vers le premier element
C) arr est un alias
D) Le compilateur optimise
E) Seulement pour int

**Reponse correcte: B**

### Question 4
Comment connaitre la taille d'un tableau passe en parametre ?

A) sizeof(arr)
B) len(arr)
C) arr.size()
D) Il faut la passer en parametre supplementaire
E) Impossible

**Reponse correcte: D**

### Question 5
Que signifie "decay" pour un tableau ?

A) Le tableau est detruit
B) Le tableau perd sa taille et devient un simple pointeur
C) Le tableau est copie
D) Le tableau est converti en struct
E) Le tableau est alloue dynamiquement

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.18-a",
  "name": "array_pointer_duality",
  "language": "c",
  "language_version": "c17",
  "files": ["array_pointer_duality.c", "array_pointer_duality.h"],
  "tests": {
    "access": "bracket_vs_pointer_equivalence",
    "sum": [[1,2,3,4,5], [-1,0,1], [42]],
    "set": "modification_equivalence",
    "find": [[42, true], [99, false]],
    "compare": "always_true_test"
  }
}
```
