# Exercice 0.5.5-a : stdint_precision

**Module :**
0.5.5 — Types a Taille Fixe

**Concept :**
a-i — int8_t, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t, uint64_t, size_t

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.4 (type_explorer)

**Domaines :**
Mem, CPU, Encodage

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
- `stdint_precision.c`
- `stdint_precision.h`

**Headers autorises :**
- `<stdio.h>`, `<stdint.h>`, `<stdbool.h>`

### 1.2 Consigne

Implementer des fonctions de conversion entre types `stdint.h` avec detection d'overflow.

**Ta mission :**

Creer des fonctions de conversion securisees qui detectent les depassements de capacite.

**Prototypes :**
```c
int8_t   safe_to_int8(int32_t value, bool *overflow);
uint8_t  safe_to_uint8(int32_t value, bool *overflow);
int16_t  safe_to_int16(int32_t value, bool *overflow);
uint16_t safe_to_uint16(int32_t value, bool *overflow);
int32_t  safe_to_int32(int64_t value, bool *overflow);
uint32_t safe_to_uint32(int64_t value, bool *overflow);
size_t   array_total_size(size_t count, size_t element_size, bool *overflow);
```

**Comportement :**
- Si conversion possible sans perte: `*overflow = false`, retourne la valeur convertie
- Si overflow detecte: `*overflow = true`, retourne la valeur saturee (max ou min selon le cas)

**Exemples :**
```
safe_to_int8(100, &ov)    -> 100, overflow=false
safe_to_int8(200, &ov)    -> 127, overflow=true  (INT8_MAX)
safe_to_int8(-200, &ov)   -> -128, overflow=true (INT8_MIN)
safe_to_uint8(-5, &ov)    -> 0, overflow=true    (negatif -> 0)
safe_to_uint8(300, &ov)   -> 255, overflow=true  (UINT8_MAX)
array_total_size(SIZE_MAX, 2, &ov) -> SIZE_MAX, overflow=true
```

**Contraintes :**
- Utiliser uniquement les types de `<stdint.h>`
- Utiliser `<stdbool.h>` pour bool
- Ne pas utiliser de casts implicites dangereux

### 1.3 Prototype

```c
// stdint_precision.h
#ifndef STDINT_PRECISION_H
#define STDINT_PRECISION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

int8_t   safe_to_int8(int32_t value, bool *overflow);
uint8_t  safe_to_uint8(int32_t value, bool *overflow);
int16_t  safe_to_int16(int32_t value, bool *overflow);
uint16_t safe_to_uint16(int32_t value, bool *overflow);
int32_t  safe_to_int32(int64_t value, bool *overflow);
uint32_t safe_to_uint32(int64_t value, bool *overflow);
size_t   array_total_size(size_t count, size_t element_size, bool *overflow);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

Les types de `<stdint.h>` ont ete introduits dans C99 pour resoudre le probleme de portabilite. Avant, un `int` pouvait faire 16, 32 ou 64 bits selon la plateforme.

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Security Engineer**

La detection d'overflow est cruciale pour:
- Prevenir les buffer overflows
- Eviter les integer overflows (CVE frequentes)
- Securiser les calculs de taille de buffer

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o test_stdint test_main.c stdint_precision.c
$ ./test_stdint
safe_to_int8(100): 100, overflow=false
safe_to_int8(200): 127, overflow=true
safe_to_uint8(-5): 0, overflow=true
array_total_size(1000000, 1000000): overflow=true
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | safe_to_int8(0) | 0, false | 10 |
| T02 | safe_to_int8(127) | 127, false | 10 |
| T03 | safe_to_int8(128) | 127, true | 10 |
| T04 | safe_to_int8(-128) | -128, false | 10 |
| T05 | safe_to_int8(-129) | -128, true | 10 |
| T06 | safe_to_uint8(-1) | 0, true | 10 |
| T07 | safe_to_uint8(255) | 255, false | 10 |
| T08 | safe_to_uint8(256) | 255, true | 10 |
| T09 | array_total_size(SIZE_MAX, 2) | SIZE_MAX, true | 10 |
| T10 | array_total_size(100, 10) | 1000, false | 10 |

### 4.3 Solution de reference

```c
#include "stdint_precision.h"
#include <limits.h>

int8_t safe_to_int8(int32_t value, bool *overflow)
{
    if (value > INT8_MAX)
    {
        *overflow = true;
        return INT8_MAX;
    }
    if (value < INT8_MIN)
    {
        *overflow = true;
        return INT8_MIN;
    }
    *overflow = false;
    return (int8_t)value;
}

uint8_t safe_to_uint8(int32_t value, bool *overflow)
{
    if (value < 0)
    {
        *overflow = true;
        return 0;
    }
    if (value > UINT8_MAX)
    {
        *overflow = true;
        return UINT8_MAX;
    }
    *overflow = false;
    return (uint8_t)value;
}

int16_t safe_to_int16(int32_t value, bool *overflow)
{
    if (value > INT16_MAX)
    {
        *overflow = true;
        return INT16_MAX;
    }
    if (value < INT16_MIN)
    {
        *overflow = true;
        return INT16_MIN;
    }
    *overflow = false;
    return (int16_t)value;
}

uint16_t safe_to_uint16(int32_t value, bool *overflow)
{
    if (value < 0)
    {
        *overflow = true;
        return 0;
    }
    if (value > UINT16_MAX)
    {
        *overflow = true;
        return UINT16_MAX;
    }
    *overflow = false;
    return (uint16_t)value;
}

int32_t safe_to_int32(int64_t value, bool *overflow)
{
    if (value > INT32_MAX)
    {
        *overflow = true;
        return INT32_MAX;
    }
    if (value < INT32_MIN)
    {
        *overflow = true;
        return INT32_MIN;
    }
    *overflow = false;
    return (int32_t)value;
}

uint32_t safe_to_uint32(int64_t value, bool *overflow)
{
    if (value < 0)
    {
        *overflow = true;
        return 0;
    }
    if (value > UINT32_MAX)
    {
        *overflow = true;
        return UINT32_MAX;
    }
    *overflow = false;
    return (uint32_t)value;
}

size_t array_total_size(size_t count, size_t element_size, bool *overflow)
{
    if (element_size != 0 && count > SIZE_MAX / element_size)
    {
        *overflow = true;
        return SIZE_MAX;
    }
    *overflow = false;
    return count * element_size;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Pas de verification de negatif pour uint
uint8_t safe_to_uint8(int32_t value, bool *overflow)
{
    if (value > UINT8_MAX)  // Manque check value < 0
    {
        *overflow = true;
        return UINT8_MAX;
    }
    *overflow = false;
    return (uint8_t)value;
}

// MUTANT 2: Retourne 0 au lieu de saturer
int8_t safe_to_int8(int32_t value, bool *overflow)
{
    if (value > INT8_MAX || value < INT8_MIN)
    {
        *overflow = true;
        return 0;  // Devrait etre INT8_MAX ou INT8_MIN
    }
    *overflow = false;
    return (int8_t)value;
}

// MUTANT 3: Mauvaise detection overflow multiplication
size_t array_total_size(size_t count, size_t element_size, bool *overflow)
{
    size_t result = count * element_size;  // Overflow deja produit!
    if (result < count)
    {
        *overflow = true;
        return SIZE_MAX;
    }
    *overflow = false;
    return result;
}

// MUTANT 4: Oubli de setter overflow a false
int8_t safe_to_int8(int32_t value, bool *overflow)
{
    if (value > INT8_MAX)
    {
        *overflow = true;
        return INT8_MAX;
    }
    // *overflow = false; OUBLIE!
    return (int8_t)value;
}

// MUTANT 5: >= au lieu de >
int8_t safe_to_int8(int32_t value, bool *overflow)
{
    if (value >= INT8_MAX)  // >= au lieu de >
    {
        *overflow = true;
        return INT8_MAX;
    }
    // ...
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **types a taille garantie** de `<stdint.h>`:
- `int8_t/uint8_t` : exactement 8 bits
- `int16_t/uint16_t` : exactement 16 bits
- `int32_t/uint32_t` : exactement 32 bits
- `int64_t/uint64_t` : exactement 64 bits
- `size_t` : type pour les tailles (non signe, >= 16 bits)

### 5.3 Visualisation ASCII

```
Type        Bits   Signed Range           Unsigned Range
----        ----   ------------           --------------
int8_t        8    -128 to 127            0 to 255
int16_t      16    -32768 to 32767        0 to 65535
int32_t      32    -2.1B to 2.1B          0 to 4.2B
int64_t      64    -9.2E18 to 9.2E18      0 to 18E18
size_t     >=16    N/A (unsigned)         0 to SIZE_MAX
```

### 5.5 Cours Complet

#### Detection d'overflow pour multiplication

Pour detecter un overflow de multiplication `a * b`:
```c
// CORRECT: verifier AVANT la multiplication
if (b != 0 && a > MAX / b)
{
    // overflow va se produire
}

// INCORRECT: verifier apres (trop tard!)
size_t result = a * b;  // overflow deja produit
if (result < a)  // detection non fiable
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la valeur maximale d'un uint8_t ?

A) 127
B) 128
C) 255
D) 256
E) 65535

**Reponse correcte: C**

### Question 2
Comment detecter un overflow de multiplication de size_t ?

A) Multiplier et verifier si le resultat est negatif
B) Verifier si a > SIZE_MAX / b avant de multiplier
C) Utiliser un try/catch
D) C'est impossible en C
E) Convertir en double et verifier

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.5-a",
  "name": "stdint_precision",
  "language": "c",
  "language_version": "c17",
  "files": ["stdint_precision.c", "stdint_precision.h"],
  "headers_required": ["stdint.h", "stdbool.h"],
  "tests": {
    "type": "unit",
    "edge_cases": ["overflow", "underflow", "boundary"]
  }
}
```
