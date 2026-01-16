# Exercice 0.5.23-a : preprocessor

**Module :**
0.5.23 — Preprocesseur C

**Concept :**
a-f — #define, #include, #ifdef, #ifndef, macros avec parametres, ## concatenation

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.9 (fonctions)

**Domaines :**
Algo, Encodage

**Duree estimee :**
120 min

**XP Base :**
180

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `preprocessor.c`
- `preprocessor.h`

### 1.2 Consigne

Implementer des macros et fonctions utilisant le preprocesseur.

**Ta mission :**

```c
// Constantes
#define PI 3.14159265359
#define MAX_SIZE 100
#define VERSION "1.0.0"

// Macros simples
#define SQUARE(x) ((x) * (x))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define ABS(x) ((x) < 0 ? -(x) : (x))

// Macro avec effets de bord documentes
#define SWAP(a, b, type) do { type tmp = (a); (a) = (b); (b) = tmp; } while(0)

// Macro pour taille de tableau
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// Concatenation
#define CONCAT(a, b) a##b
#define STRINGIFY(x) #x

// Compilation conditionnelle
#ifdef DEBUG
#define DEBUG_PRINT(fmt, ...) printf("DEBUG: " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

// Fonctions utilisant les macros
int use_square(int x);
int use_max(int a, int b);
int use_array_size(void);
```

**Comportement:**

1. `SQUARE(5)` -> 25
2. `MAX(3, 7)` -> 7
3. `MIN(3, 7)` -> 3
4. `ABS(-5)` -> 5
5. `ARRAY_SIZE(int arr[10])` -> 10
6. `STRINGIFY(hello)` -> "hello"

**Exemples:**
```
int x = 4;
SQUARE(x)     -> 16
SQUARE(x+1)   -> 25 (grace aux parentheses)

MAX(3, 7)     -> 7
MIN(-5, 5)    -> -5

int arr[5];
ARRAY_SIZE(arr) -> 5

CONCAT(my, _var)  -> my_var (identifiant)
STRINGIFY(test)   -> "test" (chaine)
```

### 1.3 Prototype

```c
// preprocessor.h
#ifndef PREPROCESSOR_H
#define PREPROCESSOR_H

// Constantes
#define PI 3.14159265359
#define MAX_SIZE 100
#define VERSION "1.0.0"

// Macros arithmetiques
#define SQUARE(x) ((x) * (x))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define ABS(x) ((x) < 0 ? -(x) : (x))

// Macro swap type-safe
#define SWAP(a, b, type) do { type tmp = (a); (a) = (b); (b) = tmp; } while(0)

// Taille de tableau
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// Concatenation et stringification
#define CONCAT(a, b) a##b
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

// Debug conditionnel
#ifdef DEBUG
#include <stdio.h>
#define DEBUG_PRINT(fmt, ...) printf("DEBUG: " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...) ((void)0)
#endif

// Fonctions
int use_square(int x);
int use_max(int a, int b);
int use_array_size(void);
const char *get_version(void);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | SQUARE(5) | 25 | 15 |
| T02 | SQUARE(3+2) | 25 | 10 |
| T03 | MAX(3, 7) | 7 | 15 |
| T04 | MIN(-5, 5) | -5 | 10 |
| T05 | ABS(-42) | 42 | 10 |
| T06 | ARRAY_SIZE | correct | 15 |
| T07 | STRINGIFY | correct | 15 |
| T08 | Header guards | no redefinition | 10 |

### 4.3 Solution de reference

```c
#include "preprocessor.h"

int use_square(int x)
{
    return SQUARE(x);
}

int use_max(int a, int b)
{
    return MAX(a, b);
}

int use_array_size(void)
{
    int arr[10] = {0};
    return ARRAY_SIZE(arr);
}

const char *get_version(void)
{
    return VERSION;
}

// Exemple d'utilisation de SWAP
void example_swap(void)
{
    int a = 5, b = 10;
    SWAP(a, b, int);
    // Maintenant a == 10, b == 5
}

// Exemple de CONCAT
int CONCAT(my, _function)(void)
{
    return 42;
}
// Cree une fonction nommee my_function
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: SQUARE sans parentheses
#define SQUARE(x) x * x
// SQUARE(3+2) -> 3+2*3+2 = 3+6+2 = 11 au lieu de 25

// MUTANT 2: MAX sans parentheses externes
#define MAX(a, b) (a) > (b) ? (a) : (b)
// Probleme de priorite avec operateurs externes

// MUTANT 3: ABS ne gere pas 0
#define ABS(x) ((x) < 0 ? -(x) : (x))
// Correct, mais certains oublient les parentheses

// MUTANT 4: ARRAY_SIZE sur pointeur
// int *ptr = arr;
// ARRAY_SIZE(ptr)  -> sizeof(ptr)/sizeof(*ptr) = 8/4 = 2 (FAUX!)

// MUTANT 5: SWAP sans do-while
#define SWAP(a, b, type) type tmp = (a); (a) = (b); (b) = tmp
// Probleme avec:
// if (cond) SWAP(x, y, int); else foo();
// Se developpe en:
// if (cond) type tmp = x; x = y; y = tmp; else foo();  // ERREUR!
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Le **preprocesseur** C:

1. **#define** - Definir constantes et macros
2. **#include** - Inclure des fichiers
3. **#ifdef/#ifndef** - Compilation conditionnelle
4. **##** - Concatenation de tokens
5. **#** - Stringification (convertir en chaine)

### 5.3 Visualisation ASCII

```
AVANT PREPROCESSEUR:           APRES PREPROCESSEUR:

#define SQUARE(x) ((x)*(x))

int main() {                   int main() {
    int r = SQUARE(5);             int r = ((5)*(5));
    return 0;                      return 0;
}                              }

POURQUOI LES PARENTHESES:

#define BAD(x) x * x
BAD(3+2) -> 3+2 * 3+2 = 3 + 6 + 2 = 11  (FAUX!)

#define GOOD(x) ((x) * (x))
GOOD(3+2) -> ((3+2) * (3+2)) = (5 * 5) = 25  (CORRECT!)
```

### 5.5 Header Guards

```c
// preprocessor.h
#ifndef PREPROCESSOR_H      // Si pas encore defini
#define PREPROCESSOR_H      // Le definir

// Contenu du header...

#endif                      // Fin de la protection

// Evite les inclusions multiples:
// #include "preprocessor.h"
// #include "preprocessor.h"  <- Ne sera pas re-inclus
```

---

## SECTION 7 : QCM

### Question 1
Pourquoi utiliser ((x) * (x)) plutot que x * x dans SQUARE ?

A) Pour la lisibilite
B) Pour eviter les problemes de priorite d'operateurs
C) Pour la performance
D) C'est equivalent
E) Convention de style

**Reponse correcte: B**

### Question 2
A quoi sert #ifndef/#define/#endif autour d'un header ?

A) Optimiser la compilation
B) Eviter les inclusions multiples
C) Definir des macros
D) Commenter le code
E) Rien

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.23-a",
  "name": "preprocessor",
  "language": "c",
  "language_version": "c17",
  "files": ["preprocessor.c", "preprocessor.h"],
  "tests": {
    "macros": "preprocessor_macro_tests",
    "guards": "header_guard_test"
  }
}
```
