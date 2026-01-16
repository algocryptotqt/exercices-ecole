# Exercice 0.5.6-a : modifier_lab

**Module :**
0.5.6 — Modificateurs de Type

**Concept :**
a-h — signed, unsigned, short, long, const, static, volatile, extern

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.5 (stdint_precision)

**Domaines :**
Mem, CPU

**Duree estimee :**
180 min

**XP Base :**
200

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `modifier_lab.c`
- `external_var.c`
- `modifier_lab.h`

**Fonctions autorisees :**
- `printf()`

### 1.2 Consigne

Creer un laboratoire demontrant l'effet de chaque modificateur de type.

**Ta mission :**

Implementer les fonctions suivantes:

```c
void demo_signed_unsigned(void);  // Montre difference signed/unsigned
void demo_short_long(void);       // Montre difference de range
void demo_const(void);            // Montre const (lecture seule)
int  demo_static(void);           // Compteur avec static local
void demo_volatile(int *ptr);     // Lecture sans optimisation
int  get_external_value(void);    // Utilise variable extern
```

**Comportement attendu:**

1. `demo_signed_unsigned()`: Affiche comment -1 est interprete en unsigned
2. `demo_short_long()`: Affiche les ranges des differentes tailles
3. `demo_const()`: Montre une variable const (pas de modification)
4. `demo_static()`: Retourne un compteur incremente a chaque appel (1, 2, 3...)
5. `demo_volatile()`: Lit une valeur volatile
6. `get_external_value()`: Retourne une variable definie dans external_var.c

**Sortie attendue:**
```
=== signed vs unsigned ===
signed int: -1
unsigned int: 4294967295
Same bits, different interpretation

=== short vs long ===
short range: -32768 to 32767
long range: -9223372036854775808 to 9223372036854775807

=== const demo ===
const value: 42
Cannot modify a const variable

=== static counter ===
Call 1: 1
Call 2: 2
Call 3: 3

=== volatile demo ===
Volatile read: 100

=== extern demo ===
External value: 12345
```

### 1.3 Prototype

```c
// modifier_lab.h
#ifndef MODIFIER_LAB_H
#define MODIFIER_LAB_H

void demo_signed_unsigned(void);
void demo_short_long(void);
void demo_const(void);
int  demo_static(void);
void demo_volatile(int *ptr);
int  get_external_value(void);

extern int external_variable;

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

Le modificateur `volatile` est crucial pour:
- Variables partagees entre threads
- Registres hardware (memory-mapped I/O)
- Variables modifiees par interruptions

Sans `volatile`, le compilateur peut optimiser les lectures en cache.

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Embedded Developer**

Les modificateurs sont essentiels pour:
- `volatile` pour les registres peripheriques
- `const` pour les donnees en ROM
- `static` pour les variables persistantes entre appels

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -c modifier_lab.c
$ gcc -Wall -Werror -std=c17 -c external_var.c
$ gcc -o test_modifier modifier_lab.o external_var.o
$ ./test_modifier
=== signed vs unsigned ===
signed int: -1
unsigned int: 4294967295
[...]
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Function | Check | Points |
|---------|----------|-------|--------|
| T01 | demo_signed_unsigned | Output -1 et 4294967295 | 15 |
| T02 | demo_short_long | Ranges corrects | 15 |
| T03 | demo_const | Valeur 42 affichee | 10 |
| T04 | demo_static | Appels successifs 1,2,3 | 20 |
| T05 | demo_volatile | Lecture correcte | 10 |
| T06 | get_external_value | Retourne 12345 | 15 |
| T07 | Compilation | No warnings | 15 |

### 4.3 Solution de reference

**modifier_lab.c:**
```c
#include <stdio.h>
#include <limits.h>
#include "modifier_lab.h"

void demo_signed_unsigned(void)
{
    signed int s = -1;
    unsigned int u = (unsigned int)s;

    printf("=== signed vs unsigned ===\n");
    printf("signed int: %d\n", s);
    printf("unsigned int: %u\n", u);
    printf("Same bits, different interpretation\n\n");
}

void demo_short_long(void)
{
    printf("=== short vs long ===\n");
    printf("short range: %d to %d\n", SHRT_MIN, SHRT_MAX);
    printf("long range: %ld to %ld\n\n", LONG_MIN, LONG_MAX);
}

void demo_const(void)
{
    const int value = 42;

    printf("=== const demo ===\n");
    printf("const value: %d\n", value);
    printf("Cannot modify a const variable\n\n");
}

int demo_static(void)
{
    static int counter = 0;
    counter++;
    return counter;
}

void demo_volatile(int *ptr)
{
    volatile int *vptr = (volatile int *)ptr;
    printf("=== volatile demo ===\n");
    printf("Volatile read: %d\n\n", *vptr);
}

int get_external_value(void)
{
    return external_variable;
}
```

**external_var.c:**
```c
int external_variable = 12345;
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: static oublie dans demo_static
int demo_static(void)
{
    int counter = 0;  // Pas static, reset a chaque appel
    counter++;
    return counter;  // Toujours 1
}

// MUTANT 2: Cast manquant pour unsigned
void demo_signed_unsigned(void)
{
    signed int s = -1;
    unsigned int u = s;  // Warning potentiel
    printf("unsigned int: %d\n", u);  // Mauvais format
}

// MUTANT 3: extern mal declare
// external_variable non declare extern dans le header
int external_variable;  // Cree une nouvelle variable!

// MUTANT 4: volatile non utilise
void demo_volatile(int *ptr)
{
    printf("Volatile read: %d\n", *ptr);  // Peut etre optimise
}

// MUTANT 5: const cast pour modifier (UB)
void demo_const(void)
{
    const int value = 42;
    int *p = (int *)&value;
    *p = 100;  // Undefined behavior!
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **8 modificateurs de type** en C:
- `signed` : entier signe (defaut pour int)
- `unsigned` : entier non signe
- `short` : entier court (au moins 16 bits)
- `long` : entier long (au moins 32 bits)
- `const` : valeur constante (non modifiable)
- `static` : persistance entre appels / liaison interne
- `volatile` : empeche les optimisations de lecture
- `extern` : declaration d'une variable definie ailleurs

### 5.3 Visualisation ASCII

```
Modifier    Effect              Example
--------    ------              -------
signed      Can be negative     signed int x = -5;
unsigned    Always >= 0         unsigned int x = 5;
short       Smaller range       short int x;
long        Larger range        long int x;
const       Read-only           const int x = 42;
static      Persists/internal   static int count;
volatile    No optimization     volatile int *reg;
extern      Defined elsewhere   extern int global;
```

### 5.5 Cours Complet

#### static: Deux usages

1. **Variable locale static**: Conserve sa valeur entre les appels
```c
void counter(void)
{
    static int count = 0;  // Initialise une seule fois
    count++;
    printf("%d\n", count);
}
```

2. **Variable/fonction globale static**: Liaison interne (visible seulement dans ce fichier)
```c
static int internal_var = 42;  // Invisible aux autres fichiers
static void helper(void) { }   // Fonction privee au fichier
```

#### extern: Declaration vs Definition

```c
// header.h
extern int global_var;  // DECLARATION (pas de memoire allouee)

// file.c
int global_var = 42;    // DEFINITION (memoire allouee)

// other.c
#include "header.h"
// Peut utiliser global_var via extern
```

---

## SECTION 7 : QCM

### Question 1
Que fait le modificateur `static` sur une variable locale ?

A) La rend constante
B) La rend visible partout
C) Conserve sa valeur entre les appels de fonction
D) La rend volatile
E) Rien de special

**Reponse correcte: C**

### Question 2
Quelle est la valeur de `(unsigned int)-1` ?

A) -1
B) 0
C) 1
D) UINT_MAX (4294967295 sur 32 bits)
E) Undefined behavior

**Reponse correcte: D**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.6-a",
  "name": "modifier_lab",
  "language": "c",
  "language_version": "c17",
  "files": ["modifier_lab.c", "external_var.c", "modifier_lab.h"],
  "multi_file": true,
  "tests": {
    "static_counter": [1, 2, 3, 4, 5],
    "extern_value": 12345
  }
}
```
