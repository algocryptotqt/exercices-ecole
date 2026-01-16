# Exercice 0.5.22-a : bitwise_ops

**Module :**
0.5.22 — Operations Bit a Bit

**Concept :**
a-f — AND &, OR |, XOR ^, NOT ~, shifts << >>, bit manipulation

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.4 (types)

**Domaines :**
Algo, CPU, Encodage

**Duree estimee :**
180 min

**XP Base :**
250

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `bitwise_ops.c`
- `bitwise_ops.h`

### 1.2 Consigne

Implementer des fonctions de manipulation de bits.

**Ta mission :**

```c
// Verifier si le bit n est mis a 1
int is_bit_set(unsigned int value, int bit);

// Mettre le bit n a 1
unsigned int set_bit(unsigned int value, int bit);

// Mettre le bit n a 0
unsigned int clear_bit(unsigned int value, int bit);

// Inverser le bit n
unsigned int toggle_bit(unsigned int value, int bit);

// Compter le nombre de bits a 1
int count_ones(unsigned int value);

// Verifier si c'est une puissance de 2
int is_power_of_two(unsigned int value);

// Echanger sans variable temporaire (XOR)
void xor_swap(int *a, int *b);

// Extraire les n bits a partir de la position start
unsigned int extract_bits(unsigned int value, int start, int n);
```

**Comportement:**

1. `is_bit_set(5, 0)` -> 1 (5 = 101, bit 0 = 1)
2. `set_bit(4, 0)` -> 5 (100 | 001 = 101)
3. `clear_bit(5, 0)` -> 4 (101 & 110 = 100)
4. `toggle_bit(5, 1)` -> 7 (101 ^ 010 = 111)
5. `count_ones(7)` -> 3 (111 a trois 1)
6. `is_power_of_two(8)` -> 1 (8 = 1000)

**Exemples:**
```
is_bit_set(0b1010, 1) -> 1  (bit 1 est 1)
is_bit_set(0b1010, 0) -> 0  (bit 0 est 0)

set_bit(0b1000, 1)    -> 0b1010
clear_bit(0b1111, 2)  -> 0b1011

count_ones(0)         -> 0
count_ones(0xFF)      -> 8

is_power_of_two(1)    -> 1
is_power_of_two(6)    -> 0
is_power_of_two(8)    -> 1
```

### 1.3 Prototype

```c
// bitwise_ops.h
#ifndef BITWISE_OPS_H
#define BITWISE_OPS_H

int is_bit_set(unsigned int value, int bit);
unsigned int set_bit(unsigned int value, int bit);
unsigned int clear_bit(unsigned int value, int bit);
unsigned int toggle_bit(unsigned int value, int bit);
int count_ones(unsigned int value);
int is_power_of_two(unsigned int value);
void xor_swap(int *a, int *b);
unsigned int extract_bits(unsigned int value, int start, int n);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | is_bit_set(5, 0) | 1 | 10 |
| T02 | is_bit_set(5, 1) | 0 | 10 |
| T03 | set_bit(4, 0) | 5 | 15 |
| T04 | clear_bit(5, 0) | 4 | 15 |
| T05 | toggle_bit(5, 1) | 7 | 10 |
| T06 | count_ones(7) | 3 | 15 |
| T07 | is_power_of_two | correct | 15 |
| T08 | xor_swap | correct | 10 |

### 4.3 Solution de reference

```c
#include "bitwise_ops.h"

int is_bit_set(unsigned int value, int bit)
{
    return (value >> bit) & 1;
}

unsigned int set_bit(unsigned int value, int bit)
{
    return value | (1U << bit);
}

unsigned int clear_bit(unsigned int value, int bit)
{
    return value & ~(1U << bit);
}

unsigned int toggle_bit(unsigned int value, int bit)
{
    return value ^ (1U << bit);
}

int count_ones(unsigned int value)
{
    int count = 0;
    while (value)
    {
        count += value & 1;
        value >>= 1;
    }
    return count;
}

int is_power_of_two(unsigned int value)
{
    if (value == 0)
        return 0;
    return (value & (value - 1)) == 0;
}

void xor_swap(int *a, int *b)
{
    if (a == b || a == NULL || b == NULL)
        return;
    *a = *a ^ *b;
    *b = *a ^ *b;
    *a = *a ^ *b;
}

unsigned int extract_bits(unsigned int value, int start, int n)
{
    unsigned int mask = (1U << n) - 1;
    return (value >> start) & mask;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: is_bit_set retourne bit decale au lieu de 0/1
int is_bit_set(unsigned int value, int bit)
{
    return value & (1 << bit);  // Retourne 0 ou (1<<bit), pas 0/1
}

// MUTANT 2: set_bit utilise XOR au lieu de OR
unsigned int set_bit(unsigned int value, int bit)
{
    return value ^ (1U << bit);  // XOR au lieu de OR
}

// MUTANT 3: clear_bit oublie le NOT
unsigned int clear_bit(unsigned int value, int bit)
{
    return value & (1U << bit);  // Manque ~
}

// MUTANT 4: count_ones boucle infinie
int count_ones(unsigned int value)
{
    int count = 0;
    while (value)
    {
        count += value & 1;
        // value >>= 1;  // Oublie le shift
    }
    return count;
}

// MUTANT 5: is_power_of_two oublie le cas 0
int is_power_of_two(unsigned int value)
{
    return (value & (value - 1)) == 0;  // 0 serait considere power of 2
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **operations bit a bit**:

1. **AND &** - 1 si les deux bits sont 1
2. **OR |** - 1 si au moins un bit est 1
3. **XOR ^** - 1 si les bits sont differents
4. **NOT ~** - Inverse tous les bits
5. **Shift << >>** - Decale les bits a gauche/droite

### 5.3 Visualisation ASCII

```
OPERATIONS DE BASE (sur 4 bits):

  0101 (5)            0101 (5)            0101 (5)
& 0011 (3)          | 0011 (3)          ^ 0011 (3)
--------            --------            --------
  0001 (1)            0111 (7)            0110 (6)
  AND                 OR                  XOR

~0101 = 1010 (NOT - inverse tous les bits)

SHIFTS:
0101 << 1 = 1010 (decale a gauche, multiplie par 2)
0101 >> 1 = 0010 (decale a droite, divise par 2)

MANIPULATION DE BITS:

Set bit 2:    value | (1 << 2)
              0001 | 0100 = 0101

Clear bit 0:  value & ~(1 << 0)
              0101 & 1110 = 0100

Toggle bit 1: value ^ (1 << 1)
              0101 ^ 0010 = 0111
```

### 5.5 Astuce: is_power_of_two

```
Pourquoi n & (n-1) == 0 pour puissance de 2 ?

8 = 1000
7 = 0111
& -----
    0000

6 = 0110
5 = 0101
& -----
    0100  (pas 0, donc pas puissance de 2)
```

---

## SECTION 7 : QCM

### Question 1
Que fait `x & (1 << n)` ?

A) Met le bit n a 1
B) Met le bit n a 0
C) Teste si le bit n est 1
D) Inverse le bit n
E) Rien

**Reponse correcte: C**

### Question 2
Comment mettre un bit a 0 ?

A) value | (1 << bit)
B) value & ~(1 << bit)
C) value ^ (1 << bit)
D) value >> bit
E) value << bit

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.22-a",
  "name": "bitwise_ops",
  "language": "c",
  "language_version": "c17",
  "files": ["bitwise_ops.c", "bitwise_ops.h"],
  "tests": {
    "bit_manipulation": "bitwise_tests",
    "edge_cases": [0, 1, 0xFFFFFFFF]
  }
}
```
