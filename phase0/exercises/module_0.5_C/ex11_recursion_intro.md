# Exercice 0.5.11-a : recursion_intro

**Module :**
0.5.11 — Introduction a la Recursivite

**Concept :**
a-d — Cas de base, Cas recursif, Pile d'appels, Tail recursion

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.9 (fonctions), 0.5.10 (scope)

**Domaines :**
Algo

**Duree estimee :**
180 min

**XP Base :**
250

**Complexite :**
T2 O(n) x S2 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `recursion_intro.c`
- `recursion_intro.h`

### 1.2 Consigne

Implementer des algorithmes recursifs classiques.

**Ta mission :**

```c
// Factorielle recursive
unsigned long factorial_rec(int n);

// Suite de Fibonacci recursive
int fibonacci_rec(int n);

// Somme des entiers de 1 a n
int sum_to_n(int n);

// Compter les chiffres d'un nombre
int count_digits(int n);

// Puissance recursive (x^n)
long power_rec(int base, int exp);
```

**Comportement:**

1. `factorial_rec(5)` -> 120
2. `fibonacci_rec(10)` -> 55
3. `sum_to_n(100)` -> 5050
4. `count_digits(12345)` -> 5
5. `power_rec(2, 10)` -> 1024

**Exemples:**
```
factorial_rec(0) -> 1
factorial_rec(1) -> 1
factorial_rec(5) -> 120

fibonacci_rec(0) -> 0
fibonacci_rec(1) -> 1
fibonacci_rec(2) -> 1
fibonacci_rec(10) -> 55

sum_to_n(0) -> 0
sum_to_n(1) -> 1
sum_to_n(10) -> 55

count_digits(0) -> 1
count_digits(9) -> 1
count_digits(99) -> 2
count_digits(-123) -> 3

power_rec(2, 0) -> 1
power_rec(3, 3) -> 27
```

### 1.3 Prototype

```c
// recursion_intro.h
#ifndef RECURSION_INTRO_H
#define RECURSION_INTRO_H

unsigned long factorial_rec(int n);
int fibonacci_rec(int n);
int sum_to_n(int n);
int count_digits(int n);
long power_rec(int base, int exp);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | factorial_rec(0) | 1 | 10 |
| T02 | factorial_rec(10) | 3628800 | 15 |
| T03 | fibonacci_rec(0) | 0 | 10 |
| T04 | fibonacci_rec(10) | 55 | 15 |
| T05 | sum_to_n(100) | 5050 | 15 |
| T06 | count_digits(-999) | 3 | 15 |
| T07 | power_rec(2, 10) | 1024 | 20 |

### 4.3 Solution de reference

```c
#include "recursion_intro.h"

unsigned long factorial_rec(int n)
{
    // Cas de base
    if (n <= 1)
        return 1;
    // Cas recursif
    return n * factorial_rec(n - 1);
}

int fibonacci_rec(int n)
{
    // Cas de base
    if (n <= 0)
        return 0;
    if (n == 1)
        return 1;
    // Cas recursif
    return fibonacci_rec(n - 1) + fibonacci_rec(n - 2);
}

int sum_to_n(int n)
{
    if (n <= 0)
        return 0;
    return n + sum_to_n(n - 1);
}

int count_digits(int n)
{
    // Gerer les negatifs
    if (n < 0)
        n = -n;
    // Cas de base
    if (n < 10)
        return 1;
    // Cas recursif
    return 1 + count_digits(n / 10);
}

long power_rec(int base, int exp)
{
    // Cas de base
    if (exp == 0)
        return 1;
    // Cas recursif
    return base * power_rec(base, exp - 1);
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Pas de cas de base (boucle infinie)
unsigned long factorial_rec(int n)
{
    return n * factorial_rec(n - 1);  // Manque cas de base
}

// MUTANT 2: Fibonacci cas de base incorrect
int fibonacci_rec(int n)
{
    if (n == 1)
        return 1;
    return fibonacci_rec(n - 1) + fibonacci_rec(n - 2);
    // Manque cas n==0, crash sur fib(0)
}

// MUTANT 3: sum_to_n oublie d'inclure n
int sum_to_n(int n)
{
    if (n <= 0)
        return 0;
    return sum_to_n(n - 1);  // Oublie + n
}

// MUTANT 4: count_digits ne gere pas negatifs
int count_digits(int n)
{
    if (n < 10)  // -5 < 10 mais a 2 "chiffres" conceptuellement
        return 1;
    return 1 + count_digits(n / 10);
}

// MUTANT 5: power_rec mauvais operateur
long power_rec(int base, int exp)
{
    if (exp == 0)
        return 1;
    return base + power_rec(base, exp - 1);  // + au lieu de *
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

La **recursivite** : une fonction qui s'appelle elle-meme.

**Structure obligatoire:**
1. **Cas de base** - Condition d'arret (OBLIGATOIRE)
2. **Cas recursif** - Appel a soi-meme avec parametre modifie

### 5.3 Visualisation ASCII

```
factorial_rec(4):

PILE D'APPELS:
+-----------------+
| factorial_rec(1)| -> return 1
+-----------------+
| factorial_rec(2)| -> return 2 * 1 = 2
+-----------------+
| factorial_rec(3)| -> return 3 * 2 = 6
+-----------------+
| factorial_rec(4)| -> return 4 * 6 = 24
+-----------------+
|      main()     |
+-----------------+

DEROULEMENT:
f(4) = 4 * f(3)
     = 4 * (3 * f(2))
     = 4 * (3 * (2 * f(1)))
     = 4 * (3 * (2 * 1))
     = 4 * (3 * 2)
     = 4 * 6
     = 24
```

---

## SECTION 7 : QCM

### Question 1
Qu'est-ce qu'un cas de base en recursion ?

A) Le premier appel de la fonction
B) La condition qui arrete la recursion
C) L'appel recursif principal
D) Le dernier appel de la fonction
E) Une optimisation

**Reponse correcte: B**

### Question 2
Que se passe-t-il sans cas de base ?

A) La fonction retourne 0
B) Stack overflow (debordement de pile)
C) Rien de special
D) Le programme compile pas
E) Retourne NULL

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.11-a",
  "name": "recursion_intro",
  "language": "c",
  "language_version": "c17",
  "files": ["recursion_intro.c", "recursion_intro.h"],
  "tests": {
    "factorial": [0, 1, 5, 10, 12],
    "fibonacci": [0, 1, 2, 5, 10],
    "sum_to_n": [0, 1, 10, 100],
    "count_digits": [0, 9, 99, -123],
    "power": [[2,0], [2,10], [3,3]]
  }
}
```
