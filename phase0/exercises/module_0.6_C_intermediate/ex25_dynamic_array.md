# Exercice 0.6.2-a : dynamic_array

**Module :**
0.6.2 — Tableaux Dynamiques avec Realloc

**Concept :**
a-c — realloc(ptr,size), croissance exponentielle, shrinking

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
2 — Integration concepts

**Langage :**
C17

**Prerequis :**
0.6.1 (malloc_basics)

**Domaines :**
Mem, Structures, Algo

**Duree estimee :**
180 min

**XP Base :**
250

**Complexite :**
T1 O(1) amorti x S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `dynamic_array.c`
- `dynamic_array.h`

**Headers autorises :**
- `<stdio.h>`, `<stdlib.h>`, `<string.h>`, `<stdbool.h>`

**Fonctions autorisees :**
- `malloc()`, `calloc()`, `realloc()`, `free()`, `memcpy()`, `memmove()`

### 1.2 Consigne

Implementer un tableau dynamique (vector) en C qui grandit automatiquement.

**Ta mission :**

Creer une structure de tableau dynamique avec redimensionnement automatique utilisant la strategie de croissance exponentielle (doublement de capacite).

**Structure :**
```c
typedef struct {
    int *data;       // Pointeur vers les donnees
    size_t size;     // Nombre d'elements actuels
    size_t capacity; // Capacite totale allouee
} DynArray;
```

**Prototypes :**
```c
// Initialise un tableau dynamique avec capacite initiale
DynArray *dynarray_create(size_t initial_capacity);

// Libere le tableau dynamique
void dynarray_destroy(DynArray *arr);

// Ajoute un element a la fin (redimensionne si necessaire)
bool dynarray_push(DynArray *arr, int value);

// Retire et retourne le dernier element
int dynarray_pop(DynArray *arr, bool *success);

// Acces a un element par index (avec verification)
int dynarray_get(const DynArray *arr, size_t index, bool *success);

// Modifie un element par index
bool dynarray_set(DynArray *arr, size_t index, int value);

// Insere un element a une position donnee
bool dynarray_insert(DynArray *arr, size_t index, int value);

// Supprime l'element a une position donnee
bool dynarray_remove(DynArray *arr, size_t index);

// Reduit la capacite pour correspondre a la taille
bool dynarray_shrink_to_fit(DynArray *arr);

// Retourne la taille actuelle
size_t dynarray_size(const DynArray *arr);

// Retourne la capacite actuelle
size_t dynarray_capacity(const DynArray *arr);
```

**Comportement :**
- `dynarray_create(0)` utilise une capacite initiale par defaut de 4
- `dynarray_push` double la capacite si `size == capacity`
- `dynarray_pop` sur tableau vide retourne 0 avec `*success = false`
- `dynarray_get/set` avec index >= size retourne false
- `dynarray_insert/remove` decale les elements existants
- `dynarray_destroy(NULL)` ne fait rien (safe)

**Exemples :**
```
DynArray *arr = dynarray_create(2);  // capacity=2, size=0
dynarray_push(arr, 10);              // [10], size=1, cap=2
dynarray_push(arr, 20);              // [10,20], size=2, cap=2
dynarray_push(arr, 30);              // [10,20,30], size=3, cap=4 (doubled!)
dynarray_get(arr, 1, &ok);           // returns 20, ok=true
dynarray_insert(arr, 1, 15);         // [10,15,20,30], size=4
dynarray_remove(arr, 0);             // [15,20,30], size=3
dynarray_pop(arr, &ok);              // returns 30, [15,20], size=2
dynarray_shrink_to_fit(arr);         // capacity reduced to 2
dynarray_destroy(arr);               // memory freed
```

**Contraintes :**
- Utiliser `realloc` pour le redimensionnement
- Croissance par facteur 2 (doublement)
- Verifier tous les retours d'allocation
- Gerer le cas ou realloc retourne NULL (garder ancien buffer)

### 1.3 Prototype

```c
// dynamic_array.h
#ifndef DYNAMIC_ARRAY_H
#define DYNAMIC_ARRAY_H

#include <stddef.h>
#include <stdbool.h>

typedef struct {
    int *data;
    size_t size;
    size_t capacity;
} DynArray;

DynArray *dynarray_create(size_t initial_capacity);
void dynarray_destroy(DynArray *arr);
bool dynarray_push(DynArray *arr, int value);
int dynarray_pop(DynArray *arr, bool *success);
int dynarray_get(const DynArray *arr, size_t index, bool *success);
bool dynarray_set(DynArray *arr, size_t index, int value);
bool dynarray_insert(DynArray *arr, size_t index, int value);
bool dynarray_remove(DynArray *arr, size_t index);
bool dynarray_shrink_to_fit(DynArray *arr);
size_t dynarray_size(const DynArray *arr);
size_t dynarray_capacity(const DynArray *arr);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Croissance exponentielle vs lineaire

**Lineaire (ajouter K elements):**
- Push 1: realloc(K)
- Push 2: realloc(2K)
- Push n: realloc(nK)
- Total: O(n^2) copies!

**Exponentielle (doubler):**
- Push 1: realloc(1)
- Push 2: realloc(2)
- Push 3: realloc(4)
- Push 5: realloc(8)
- Total: O(n) copies (amorti O(1) par push)

### 2.2 Le secret de realloc

`realloc` peut:
1. Etendre le bloc existant sur place (rapide)
2. Allouer un nouveau bloc et copier (lent mais necessaire)
3. Retourner NULL si echec (ancien bloc INCHANGE)

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Backend Developer**

Les tableaux dynamiques sont partout:
- `std::vector` en C++
- `ArrayList` en Java
- `Vec` en Rust
- `list` en Python (implementation interne)

**Metier : Game Developer**

Gestion des entites de jeu:
- Liste dynamique d'ennemis
- Particules system
- Inventaires de joueurs

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o test_dyn test_main.c dynamic_array.c
$ ./test_dyn
Creating array with capacity 2...
  Initial: size=0, capacity=2

Pushing 10, 20, 30...
  After push(10): size=1, capacity=2
  After push(20): size=2, capacity=2
  After push(30): size=3, capacity=4 (resized!)

Testing get...
  get(0) = 10
  get(1) = 20
  get(2) = 30

Testing insert at index 1...
  Before: [10, 20, 30]
  After insert(1, 15): [10, 15, 20, 30], size=4

Testing remove at index 0...
  After remove(0): [15, 20, 30], size=3

Testing pop...
  pop() = 30, size=2

Shrinking to fit...
  Before: capacity=4
  After shrink_to_fit: capacity=2

All tests passed!
$ valgrind --leak-check=full ./test_dyn
==12345== All heap blocks were freed -- no leaks are possible
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★☆☆☆☆☆☆ (4/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Rendre le tableau dynamique generique avec des macros et void*.

```c
// Tableau generique
typedef struct {
    void *data;
    size_t size;
    size_t capacity;
    size_t elem_size;  // Taille d'un element
} GenericArray;

// Macros d'acces type-safe
#define GARRAY_GET(arr, index, type) \
    (*(type*)((char*)(arr)->data + (index) * (arr)->elem_size))

#define GARRAY_SET(arr, index, value, type) \
    (GARRAY_GET(arr, index, type) = (value))
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Expected | Points |
|---------|-------------|----------|--------|
| T01 | create with capacity | size=0, cap=given | 10 |
| T02 | create with 0 -> default | cap=4 | 5 |
| T03 | push increases size | size++ | 10 |
| T04 | push triggers resize | cap doubles | 15 |
| T05 | pop returns last | correct value | 10 |
| T06 | pop empty fails | success=false | 5 |
| T07 | get valid index | correct value | 10 |
| T08 | get invalid index | success=false | 5 |
| T09 | insert shifts right | elements shifted | 10 |
| T10 | remove shifts left | elements shifted | 10 |
| T11 | shrink_to_fit | cap=size | 5 |
| T12 | destroy NULL safe | no crash | 5 |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include "dynamic_array.h"

int main(void)
{
    int pass = 0, fail = 0;
    bool ok;

    // T01: create with capacity
    DynArray *arr = dynarray_create(5);
    if (arr != NULL && dynarray_size(arr) == 0 && dynarray_capacity(arr) == 5) {
        printf("T01 PASS\n"); pass++;
    } else {
        printf("T01 FAIL\n"); fail++;
    }
    dynarray_destroy(arr);

    // T02: create with 0 -> default capacity
    arr = dynarray_create(0);
    if (arr != NULL && dynarray_capacity(arr) == 4) {
        printf("T02 PASS\n"); pass++;
    } else {
        printf("T02 FAIL\n"); fail++;
    }

    // T03: push increases size
    if (dynarray_push(arr, 10) && dynarray_size(arr) == 1) {
        printf("T03 PASS\n"); pass++;
    } else {
        printf("T03 FAIL\n"); fail++;
    }

    // T04: push triggers resize
    dynarray_push(arr, 20);
    dynarray_push(arr, 30);
    dynarray_push(arr, 40);
    size_t old_cap = dynarray_capacity(arr);
    dynarray_push(arr, 50);  // Should trigger resize
    if (dynarray_capacity(arr) > old_cap) {
        printf("T04 PASS\n"); pass++;
    } else {
        printf("T04 FAIL\n"); fail++;
    }

    // T05: pop returns last
    int val = dynarray_pop(arr, &ok);
    if (ok && val == 50) {
        printf("T05 PASS\n"); pass++;
    } else {
        printf("T05 FAIL\n"); fail++;
    }
    dynarray_destroy(arr);

    // T06: pop empty fails
    arr = dynarray_create(4);
    val = dynarray_pop(arr, &ok);
    if (!ok) {
        printf("T06 PASS\n"); pass++;
    } else {
        printf("T06 FAIL\n"); fail++;
    }

    // T07: get valid index
    dynarray_push(arr, 100);
    dynarray_push(arr, 200);
    val = dynarray_get(arr, 1, &ok);
    if (ok && val == 200) {
        printf("T07 PASS\n"); pass++;
    } else {
        printf("T07 FAIL\n"); fail++;
    }

    // T08: get invalid index
    val = dynarray_get(arr, 99, &ok);
    if (!ok) {
        printf("T08 PASS\n"); pass++;
    } else {
        printf("T08 FAIL\n"); fail++;
    }

    // T09: insert shifts right
    dynarray_insert(arr, 1, 150);  // [100, 150, 200]
    if (dynarray_get(arr, 0, &ok) == 100 &&
        dynarray_get(arr, 1, &ok) == 150 &&
        dynarray_get(arr, 2, &ok) == 200) {
        printf("T09 PASS\n"); pass++;
    } else {
        printf("T09 FAIL\n"); fail++;
    }

    // T10: remove shifts left
    dynarray_remove(arr, 1);  // [100, 200]
    if (dynarray_size(arr) == 2 &&
        dynarray_get(arr, 0, &ok) == 100 &&
        dynarray_get(arr, 1, &ok) == 200) {
        printf("T10 PASS\n"); pass++;
    } else {
        printf("T10 FAIL\n"); fail++;
    }

    // T11: shrink_to_fit
    dynarray_shrink_to_fit(arr);
    if (dynarray_capacity(arr) == dynarray_size(arr)) {
        printf("T11 PASS\n"); pass++;
    } else {
        printf("T11 FAIL\n"); fail++;
    }
    dynarray_destroy(arr);

    // T12: destroy NULL safe
    dynarray_destroy(NULL);
    printf("T12 PASS\n"); pass++;

    printf("\nResults: %d passed, %d failed\n", pass, fail);
    return fail > 0 ? 1 : 0;
}
```

### 4.3 Solution de reference

```c
/*
 * dynamic_array.c
 * Implementation de tableau dynamique avec realloc
 * Exercice ex25_dynamic_array
 */

#include "dynamic_array.h"
#include <stdlib.h>
#include <string.h>

#define DEFAULT_CAPACITY 4
#define GROWTH_FACTOR 2

DynArray *dynarray_create(size_t initial_capacity)
{
    DynArray *arr = malloc(sizeof(*arr));
    if (arr == NULL)
    {
        return NULL;
    }

    if (initial_capacity == 0)
    {
        initial_capacity = DEFAULT_CAPACITY;
    }

    arr->data = malloc(initial_capacity * sizeof(*arr->data));
    if (arr->data == NULL)
    {
        free(arr);
        return NULL;
    }

    arr->size = 0;
    arr->capacity = initial_capacity;
    return arr;
}

void dynarray_destroy(DynArray *arr)
{
    if (arr == NULL)
    {
        return;
    }
    free(arr->data);
    free(arr);
}

static bool dynarray_grow(DynArray *arr)
{
    size_t new_capacity = arr->capacity * GROWTH_FACTOR;
    int *new_data = realloc(arr->data, new_capacity * sizeof(*new_data));

    if (new_data == NULL)
    {
        return false;  // Garde l'ancien buffer
    }

    arr->data = new_data;
    arr->capacity = new_capacity;
    return true;
}

bool dynarray_push(DynArray *arr, int value)
{
    if (arr == NULL)
    {
        return false;
    }

    if (arr->size == arr->capacity)
    {
        if (!dynarray_grow(arr))
        {
            return false;
        }
    }

    arr->data[arr->size] = value;
    arr->size++;
    return true;
}

int dynarray_pop(DynArray *arr, bool *success)
{
    if (arr == NULL || arr->size == 0)
    {
        if (success) *success = false;
        return 0;
    }

    arr->size--;
    if (success) *success = true;
    return arr->data[arr->size];
}

int dynarray_get(const DynArray *arr, size_t index, bool *success)
{
    if (arr == NULL || index >= arr->size)
    {
        if (success) *success = false;
        return 0;
    }

    if (success) *success = true;
    return arr->data[index];
}

bool dynarray_set(DynArray *arr, size_t index, int value)
{
    if (arr == NULL || index >= arr->size)
    {
        return false;
    }

    arr->data[index] = value;
    return true;
}

bool dynarray_insert(DynArray *arr, size_t index, int value)
{
    if (arr == NULL || index > arr->size)
    {
        return false;
    }

    if (arr->size == arr->capacity)
    {
        if (!dynarray_grow(arr))
        {
            return false;
        }
    }

    // Decaler les elements vers la droite
    memmove(&arr->data[index + 1],
            &arr->data[index],
            (arr->size - index) * sizeof(*arr->data));

    arr->data[index] = value;
    arr->size++;
    return true;
}

bool dynarray_remove(DynArray *arr, size_t index)
{
    if (arr == NULL || index >= arr->size)
    {
        return false;
    }

    // Decaler les elements vers la gauche
    memmove(&arr->data[index],
            &arr->data[index + 1],
            (arr->size - index - 1) * sizeof(*arr->data));

    arr->size--;
    return true;
}

bool dynarray_shrink_to_fit(DynArray *arr)
{
    if (arr == NULL || arr->size == 0)
    {
        return false;
    }

    if (arr->size == arr->capacity)
    {
        return true;  // Deja optimal
    }

    int *new_data = realloc(arr->data, arr->size * sizeof(*new_data));
    if (new_data == NULL)
    {
        return false;
    }

    arr->data = new_data;
    arr->capacity = arr->size;
    return true;
}

size_t dynarray_size(const DynArray *arr)
{
    return arr ? arr->size : 0;
}

size_t dynarray_capacity(const DynArray *arr)
{
    return arr ? arr->capacity : 0;
}
```

### 4.5 Solutions refusees (avec explications)

```c
// REFUSE 1: Pas de verification du retour de realloc
bool dynarray_push(DynArray *arr, int value)
{
    if (arr->size == arr->capacity)
    {
        arr->data = realloc(arr->data, arr->capacity * 2 * sizeof(int));
        // Si realloc echoue, arr->data est maintenant NULL!
        // On perd le pointeur vers l'ancien buffer = MEMORY LEAK
        arr->capacity *= 2;
    }
    arr->data[arr->size++] = value;
    return true;
}
// Raison: Memory leak et crash si realloc echoue

// REFUSE 2: Croissance lineaire au lieu d'exponentielle
static bool dynarray_grow(DynArray *arr)
{
    size_t new_capacity = arr->capacity + 1;  // +1 au lieu de *2
    // ...
}
// Raison: Performance O(n^2) pour n insertions

// REFUSE 3: memcpy au lieu de memmove pour insert
bool dynarray_insert(DynArray *arr, size_t index, int value)
{
    // ...
    memcpy(&arr->data[index + 1],
           &arr->data[index],
           (arr->size - index) * sizeof(int));
    // ...
}
// Raison: memcpy avec zones qui se chevauchent = comportement indefini

// REFUSE 4: Pas de gestion du cas arr == NULL
int dynarray_get(const DynArray *arr, size_t index, bool *success)
{
    if (index >= arr->size)  // Crash si arr == NULL
    {
        *success = false;
        return 0;
    }
    // ...
}
// Raison: Segfault si arr est NULL
```

### 4.9 spec.json

```json
{
  "exercise_id": "0.6.2-a",
  "name": "dynamic_array",
  "version": "1.0.0",
  "language": "c",
  "language_version": "c17",
  "files": {
    "submission": ["dynamic_array.c", "dynamic_array.h"],
    "test": ["test_dynamic_array.c"]
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"],
    "output": "test_dyn"
  },
  "tests": {
    "type": "unit",
    "valgrind": true,
    "categories": ["create", "push", "pop", "access", "resize"]
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
// MUTANT 1 (Memory): Perte du pointeur si realloc echoue
static bool dynarray_grow(DynArray *arr)
{
    size_t new_capacity = arr->capacity * 2;
    arr->data = realloc(arr->data, new_capacity * sizeof(*arr->data));
    // Si echec, arr->data = NULL, on perd l'ancien buffer!
    if (arr->data == NULL) return false;
    arr->capacity = new_capacity;
    return true;
}
// Detection: Test avec allocation limitee + valgrind

// MUTANT 2 (Logic): Off-by-one dans insert
bool dynarray_insert(DynArray *arr, size_t index, int value)
{
    if (arr == NULL || index >= arr->size)  // >= au lieu de >
    {
        return false;  // Ne peut pas inserer a la fin!
    }
    // ...
}
// Detection: insert(arr, size, val) devrait fonctionner

// MUTANT 3 (Logic): Mauvais calcul de deplacement
bool dynarray_remove(DynArray *arr, size_t index)
{
    // ...
    memmove(&arr->data[index],
            &arr->data[index + 1],
            (arr->size - index) * sizeof(*arr->data));  // Manque -1
    // Lit un element de trop!
    arr->size--;
    return true;
}
// Detection: Valgrind invalid read

// MUTANT 4 (Boundary): shrink_to_fit avec size=0
bool dynarray_shrink_to_fit(DynArray *arr)
{
    if (arr == NULL) return false;
    // Manque check arr->size == 0
    int *new_data = realloc(arr->data, arr->size * sizeof(*new_data));
    // realloc(ptr, 0) peut retourner NULL ou free!
    // ...
}
// Detection: shrink_to_fit sur array vide

// MUTANT 5 (Safety): pop ne verifie pas size
int dynarray_pop(DynArray *arr, bool *success)
{
    // Manque verification arr->size == 0
    arr->size--;
    if (success) *success = true;
    return arr->data[arr->size];  // Peut etre negatif!
}
// Detection: pop sur array vide, size underflow
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **concepts cles des tableaux dynamiques**:

1. **realloc(ptr, size)** - Redimensionne un bloc alloue
2. **Croissance exponentielle** - Doublement pour O(1) amorti
3. **Shrinking** - Reduction de capacite pour economiser memoire
4. **Gestion d'erreur realloc** - Ne pas perdre l'ancien pointeur

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION push(tableau, valeur):
DEBUT
    SI taille == capacite ALORS
        nouvelle_capacite <- capacite * 2
        nouveau_buffer <- reallouer(donnees, nouvelle_capacite)

        SI nouveau_buffer est NULL ALORS
            RETOURNER ECHEC (garder ancien buffer)
        FIN SI

        donnees <- nouveau_buffer
        capacite <- nouvelle_capacite
    FIN SI

    donnees[taille] <- valeur
    taille <- taille + 1
    RETOURNER SUCCES
FIN
```

### 5.3 Visualisation ASCII

```
Initial: capacity=4, size=0
+---+---+---+---+
| _ | _ | _ | _ |  data
+---+---+---+---+

After push(10), push(20), push(30), push(40): size=4, cap=4
+----+----+----+----+
| 10 | 20 | 30 | 40 |  data (FULL)
+----+----+----+----+

After push(50): RESIZE! capacity=8, size=5
+----+----+----+----+----+---+---+---+
| 10 | 20 | 30 | 40 | 50 | _ | _ | _ |
+----+----+----+----+----+---+---+---+

realloc peut:
1. Etendre sur place (rapide):
   [data....][new space]
             ^
   Pointeur inchange

2. Copier vers nouveau bloc:
   Old: [data....]  ->  New: [data........]
        ^                     ^
        |                     nouveau pointeur
        ancien (libere)
```

### 5.4 Les pieges en detail

#### Piege 1: Perte du pointeur avec realloc
```c
// FAUX - Si realloc echoue, on perd arr->data
arr->data = realloc(arr->data, new_size);
if (arr->data == NULL) // Trop tard! L'ancien pointeur est perdu

// CORRECT
int *new_data = realloc(arr->data, new_size);
if (new_data == NULL)
{
    return false;  // arr->data est toujours valide
}
arr->data = new_data;
```

#### Piege 2: memcpy avec zones chevauchantes
```c
// FAUX - Comportement indefini si source et dest se chevauchent
memcpy(&arr[1], &arr[0], n * sizeof(int));

// CORRECT - memmove gere le chevauchement
memmove(&arr[1], &arr[0], n * sizeof(int));
```

#### Piege 3: realloc(ptr, 0)
```c
// ATTENTION - Comportement defini par implementation
void *p = realloc(ptr, 0);
// Peut retourner NULL et liberer ptr
// OU retourner un pointeur unique minimal
// C'est dangereux, eviter!
```

### 5.5 Cours Complet

#### 5.5.1 realloc - REALLOCation

```c
void *realloc(void *ptr, size_t size);
```

Cas possibles:
1. `ptr == NULL`: equivalent a `malloc(size)`
2. `size == 0`: comportement defini par implementation (eviter)
3. Succes: retourne nouveau pointeur (peut etre == ou != ptr)
4. Echec: retourne NULL, ptr reste VALIDE

```c
// Pattern securise
int *new_data = realloc(arr->data, new_size);
if (new_data != NULL)
{
    arr->data = new_data;
    arr->capacity = new_capacity;
}
// Si echec, arr->data est toujours utilisable
```

#### 5.5.2 Analyse de complexite amortie

Pour n operations push:

**Croissance lineaire (+1 a chaque fois):**
- Copies totales: 1 + 2 + 3 + ... + n = n(n+1)/2 = O(n^2)
- Par push: O(n) en moyenne

**Croissance exponentielle (*2 a chaque fois):**
- Copies totales: 1 + 2 + 4 + 8 + ... = 2n - 1 = O(n)
- Par push: O(1) amorti

#### 5.5.3 Facteur de croissance

| Facteur | Avantage | Inconvenient |
|---------|----------|--------------|
| 1.5 | Moins de memoire gaspillee | Plus de reallocations |
| 2.0 | Moins de reallocations | ~50% memoire inutilisee |
| 3.0 | Tres peu de reallocations | ~67% memoire inutilisee |

Le facteur 2 est le plus commun (std::vector, ArrayList).

### 5.6 Normes avec explications pedagogiques

| Regle | Explication | Exemple |
|-------|-------------|---------|
| Verifier realloc | Ne pas perdre l'ancien pointeur | `new_p = realloc(p, size)` |
| memmove pas memcpy | Gere le chevauchement | `memmove(dst, src, n)` |
| Croissance *2 | O(1) amorti | `cap = cap * 2` |
| Verifier taille | Eviter underflow | `if (size > 0)` |

### 5.7 Simulation avec trace d'execution

```
dynarray_create(2):
1. malloc(sizeof(DynArray)) -> 0x1000 (structure)
2. malloc(2 * sizeof(int)) -> 0x2000 (donnees)
3. arr->data = 0x2000, size = 0, capacity = 2

push(10):
1. size(0) < capacity(2), pas besoin de resize
2. data[0] = 10, size = 1

push(20):
1. size(1) < capacity(2), pas de resize
2. data[1] = 20, size = 2

push(30):
1. size(2) == capacity(2), RESIZE!
2. realloc(0x2000, 4 * sizeof(int))
3. Scenario A: extension sur place -> toujours 0x2000
   Scenario B: nouveau bloc -> 0x3000, copie, free(0x2000)
4. capacity = 4
5. data[2] = 30, size = 3
```

### 5.8 Mnemotechniques

**"PARC" - Regles de realloc**
- **P**reserver l'ancien pointeur
- **A**ssigner seulement si succes
- **R**eallouer avec nouveau pointeur temporaire
- **C**onserver l'ancien buffer si echec

**"2x" - La regle d'or**
- Toujours doubler la capacite
- O(1) amorti garanti

### 5.9 Applications pratiques

1. **Buffers de lecture**: Fichiers de taille inconnue
2. **Collections dynamiques**: Listes d'objets dans un jeu
3. **Parsers**: Accumulation de tokens
4. **String builders**: Construction de chaines de caracteres

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Perte pointeur realloc | Memory leak | Sauvegarder avant |
| memcpy chevauchement | Corruption | Utiliser memmove |
| Croissance lineaire | Performance O(n^2) | Croissance *2 |
| realloc(ptr, 0) | Comportement indefini | Eviter ce cas |
| Pas de check taille | Underflow size_t | Verifier size > 0 |

---

## SECTION 7 : QCM

### Question 1
Que retourne realloc si l'allocation echoue ?

A) L'ancien pointeur
B) Un pointeur vers un bloc vide
C) NULL, et l'ancien bloc reste valide
D) NULL, et l'ancien bloc est libere
E) Une exception

**Reponse correcte: C**

### Question 2
Pourquoi utiliser memmove au lieu de memcpy dans insert ?

A) memmove est plus rapide
B) memmove gere les zones qui se chevauchent
C) memcpy ne fonctionne pas avec des int
D) memmove utilise moins de memoire
E) Il n'y a pas de difference

**Reponse correcte: B**

### Question 3
Quel est l'avantage de doubler la capacite a chaque resize ?

A) Utilise moins de memoire
B) Operations push en O(1) amorti
C) Evite completement les reallocations
D) Plus simple a implementer
E) Meilleure localite de cache

**Reponse correcte: B**

### Question 4
Que fait realloc(NULL, 100) ?

A) Retourne NULL
B) Crash
C) Equivalent a malloc(100)
D) Comportement indefini
E) Retourne un pointeur vers 0 octets

**Reponse correcte: C**

### Question 5
Comment gerer correctement l'echec de realloc ?

A) Ignorer l'echec et continuer
B) Appeler free() sur l'ancien pointeur
C) Sauvegarder le pointeur temporaire et ne mettre a jour que si non-NULL
D) Appeler realloc a nouveau
E) Terminer le programme

**Reponse correcte: C**

---

## SECTION 8 : RECAPITULATIF

| Fonction | Description | Retour echec |
|----------|-------------|--------------|
| realloc(ptr, size) | Redimensionne bloc | NULL (ancien valide) |
| memmove(dst, src, n) | Copie avec chevauchement | N/A |
| memcpy(dst, src, n) | Copie sans chevauchement | N/A |

| Operation | Complexite | Note |
|-----------|------------|------|
| push | O(1) amorti | Avec croissance *2 |
| pop | O(1) | Pas de shrink auto |
| get/set | O(1) | Acces direct |
| insert/remove | O(n) | Decalage elements |
| shrink_to_fit | O(n) | Copie possible |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise": {
    "id": "0.6.2-a",
    "name": "dynamic_array",
    "module": "0.6.2",
    "phase": 0,
    "difficulty": 3,
    "xp": 250,
    "time_minutes": 180
  },
  "metadata": {
    "concepts": ["realloc", "amortized_complexity", "dynamic_resizing"],
    "prerequisites": ["0.6.1"],
    "language": "c",
    "language_version": "c17"
  },
  "files": {
    "template": "dynamic_array.c",
    "header": "dynamic_array.h",
    "solution": "dynamic_array_solution.c",
    "test": "test_dynamic_array.c"
  },
  "compilation": {
    "compiler": "gcc",
    "flags": ["-Wall", "-Werror", "-std=c17"]
  },
  "grading": {
    "automated": true,
    "valgrind_required": true,
    "complexity_check": true
  }
}
```
