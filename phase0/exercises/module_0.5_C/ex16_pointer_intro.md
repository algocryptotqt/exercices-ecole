# Exercice 0.5.16-a : pointer_intro

**Module :**
0.5.16 — Introduction aux Pointeurs

**Concept :**
a-d — int *p, &x, *p (dereference), NULL

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.15 (matrix_ops)

**Domaines :**
Algo, Systeme

**Duree estimee :**
200 min

**XP Base :**
220

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `pointer_intro.c`
- `pointer_intro.h`

**Fonctions autorisees :**
- Aucune fonction de bibliotheque requise

### 1.2 Consigne

Implementer des fonctions utilisant les concepts de base des pointeurs.

**Ta mission :**

```c
// Echanger deux valeurs via pointeurs
void swap(int *a, int *b);

// Modifier une valeur via pointeur (ajouter n)
void add_to(int *value, int n);

// Retourner l'adresse de la plus grande valeur
int *max_ptr(int *a, int *b);

// Retourner l'adresse de la plus petite valeur
int *min_ptr(int *a, int *b);

// Verifier si un pointeur est NULL
int is_null(void *ptr);

// Initialiser une valeur via pointeur (si non NULL)
int safe_init(int *ptr, int value);

// Copier valeur de src vers dest (si les deux non NULL)
int safe_copy(int *dest, int *src);

// Obtenir la valeur ou defaut si NULL
int get_or_default(int *ptr, int default_val);
```

**Comportement:**

1. `swap(&a, &b)`: Echange les valeurs de a et b
2. `add_to(&x, 5)`: Ajoute 5 a x
3. `max_ptr(&a, &b)`: Retourne pointeur vers le plus grand
4. `is_null(NULL)` -> 1, `is_null(&x)` -> 0
5. `safe_init(ptr, val)`: Retourne 1 si succes, 0 si ptr NULL
6. `safe_copy(dest, src)`: Copie *src dans *dest, retourne 1 si OK
7. `get_or_default(NULL, 42)` -> 42

**Exemples:**
```
int x = 5, y = 10;
swap(&x, &y);
// x = 10, y = 5

int val = 100;
add_to(&val, 25);
// val = 125

int a = 3, b = 7;
int *bigger = max_ptr(&a, &b);
// *bigger = 7, bigger == &b

is_null(NULL)     -> 1
is_null(&x)       -> 0

safe_init(NULL, 5)    -> 0 (echec)
safe_init(&x, 5)      -> 1 (x = 5)

get_or_default(&val, 0)  -> 125
get_or_default(NULL, 42) -> 42
```

### 1.3 Prototype

```c
// pointer_intro.h
#ifndef POINTER_INTRO_H
#define POINTER_INTRO_H

void swap(int *a, int *b);
void add_to(int *value, int n);
int *max_ptr(int *a, int *b);
int *min_ptr(int *a, int *b);
int is_null(void *ptr);
int safe_init(int *ptr, int value);
int safe_copy(int *dest, int *src);
int get_or_default(int *ptr, int default_val);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | swap(5, 10) | 10, 5 | 10 |
| T02 | swap(0, 0) | 0, 0 | 5 |
| T03 | add_to(100, 25) | 125 | 10 |
| T04 | add_to(0, -5) | -5 | 5 |
| T05 | max_ptr(3, 7) | ptr to 7 | 10 |
| T06 | min_ptr(3, 7) | ptr to 3 | 10 |
| T07 | is_null(NULL) | 1 | 10 |
| T08 | is_null(&x) | 0 | 5 |
| T09 | safe_init(NULL, 5) | 0 | 10 |
| T10 | safe_init(&x, 5) | 1, x=5 | 10 |
| T11 | get_or_default(NULL, 42) | 42 | 10 |
| T12 | Compilation | No warnings | 5 |

### 4.3 Solution de reference

```c
#include "pointer_intro.h"
#include <stddef.h>  // Pour NULL

void swap(int *a, int *b)
{
    if (a == NULL || b == NULL)
        return;

    int temp = *a;
    *a = *b;
    *b = temp;
}

void add_to(int *value, int n)
{
    if (value == NULL)
        return;

    *value = *value + n;
}

int *max_ptr(int *a, int *b)
{
    if (a == NULL)
        return b;
    if (b == NULL)
        return a;

    return (*a >= *b) ? a : b;
}

int *min_ptr(int *a, int *b)
{
    if (a == NULL)
        return b;
    if (b == NULL)
        return a;

    return (*a <= *b) ? a : b;
}

int is_null(void *ptr)
{
    return (ptr == NULL) ? 1 : 0;
}

int safe_init(int *ptr, int value)
{
    if (ptr == NULL)
        return 0;

    *ptr = value;
    return 1;
}

int safe_copy(int *dest, int *src)
{
    if (dest == NULL || src == NULL)
        return 0;

    *dest = *src;
    return 1;
}

int get_or_default(int *ptr, int default_val)
{
    if (ptr == NULL)
        return default_val;

    return *ptr;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Swap sans variable temporaire (incorrect)
void swap(int *a, int *b)
{
    *a = *b;  // Perd la valeur originale de *a
    *b = *a;  // Maintenant *b = nouvelle valeur de *a
}

// MUTANT 2: Confusion & et *
void add_to(int *value, int n)
{
    value = value + n;  // Modifie l'ADRESSE, pas la valeur!
}

// MUTANT 3: Retourne valeur au lieu d'adresse
int *max_ptr(int *a, int *b)
{
    if (*a > *b)
        return (int *)*a;  // Cast illegal, retourne valeur comme adresse!
    return (int *)*b;
}

// MUTANT 4: Oubli de dereferencer
int get_or_default(int *ptr, int default_val)
{
    if (ptr == NULL)
        return default_val;
    return (int)ptr;  // Retourne l'adresse, pas la valeur!
}

// MUTANT 5: is_null inverse
int is_null(void *ptr)
{
    return (ptr != NULL);  // Retourne 1 si NON null
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **pointeurs en C**:
- **Declaration** : `int *p;` declare un pointeur vers int
- **Adresse-of** : `&x` obtient l'adresse de x
- **Dereference** : `*p` accede a la valeur pointee
- **NULL** : valeur speciale indiquant "aucune adresse"

### 5.3 Visualisation ASCII

```
Variables et pointeurs:

int x = 42;
int *p = &x;

Memoire:
          +-------+
  x (0x100): | 42    |  <- valeur
          +-------+
               ^
               |
          +-------+
  p (0x200): | 0x100 |  <- adresse de x
          +-------+

Operations:
  x    -> 42       (valeur de x)
  &x   -> 0x100    (adresse de x)
  p    -> 0x100    (valeur de p = adresse)
  *p   -> 42       (valeur a l'adresse p)
  &p   -> 0x200    (adresse de p)

Swap avec pointeurs:
  a=5      b=10
+-----+  +-----+
|  5  |  | 10  |
+-----+  +-----+
   ^        ^
   |        |
 swap(&a, &b)
   |        |
+-----+  +-----+
| 10  |  |  5  |
+-----+  +-----+
```

### 5.5 Cours Complet

#### Declaration et initialisation

```c
int x = 42;
int *p;      // Declare un pointeur (non initialise!)
p = &x;      // p pointe vers x

// Ou en une ligne:
int *p = &x;

// NULL pour pointeur invalide
int *q = NULL;
```

#### Dereferencement

```c
int x = 42;
int *p = &x;

printf("%d\n", *p);  // Affiche 42
*p = 100;            // x vaut maintenant 100
```

#### Pass-by-reference simule

```c
void increment(int *n)
{
    (*n)++;  // Modifie la variable originale
}

int main(void)
{
    int x = 5;
    increment(&x);  // x = 6
}
```

#### Securite avec NULL

```c
void safe_print(int *p)
{
    if (p == NULL)
    {
        printf("Pointeur invalide\n");
        return;
    }
    printf("Valeur: %d\n", *p);
}
```

---

## SECTION 7 : QCM

### Question 1
Que fait l'operateur `&` ?

A) Dereference un pointeur
B) Obtient l'adresse d'une variable
C) Declare un pointeur
D) Compare deux adresses
E) AND binaire

**Reponse correcte: B**

### Question 2
Que fait l'operateur `*` sur un pointeur ?

A) Multiplie
B) Obtient l'adresse
C) Accede a la valeur pointee
D) Declare une variable
E) Libere la memoire

**Reponse correcte: C**

### Question 3
Apres `int x = 5; int *p = &x; *p = 10;`, que vaut x ?

A) 5
B) 10
C) Adresse de p
D) NULL
E) Undefined

**Reponse correcte: B**

### Question 4
Que represente NULL ?

A) La valeur 0
B) Une adresse invalide/aucune adresse
C) Un pointeur vers 0
D) Une erreur de compilation
E) L'adresse 0x00000000 uniquement

**Reponse correcte: B**

### Question 5
Pourquoi verifier `if (ptr == NULL)` avant `*ptr` ?

A) Pour la performance
B) Pour eviter une erreur de compilation
C) Pour eviter un comportement indefini/crash
D) C'est optionnel
E) Pour liberer la memoire

**Reponse correcte: C**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.16-a",
  "name": "pointer_intro",
  "language": "c",
  "language_version": "c17",
  "files": ["pointer_intro.c", "pointer_intro.h"],
  "tests": {
    "swap": [[5,10], [0,0], [-1,1]],
    "add_to": [[100,25], [0,-5], [-10,10]],
    "max_ptr": [[3,7], [10,10], [-5,-1]],
    "null_checks": ["NULL", "valid_ptr"]
  }
}
```
