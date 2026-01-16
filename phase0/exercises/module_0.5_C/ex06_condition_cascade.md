# Exercice 0.5.7-a : condition_cascade

**Module :**
0.5.7 — Structures Conditionnelles

**Concept :**
a-c, h — if, else, else if, operateur ternaire

**Difficulte :**
★★☆☆☆☆☆☆☆☆ (2/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.6 (modifier_lab)

**Domaines :**
Algo

**Duree estimee :**
120 min

**XP Base :**
150

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `condition_cascade.c`
- `condition_cascade.h`

**Fonctions autorisees :**
- Aucune fonction de bibliotheque requise

### 1.2 Consigne

Implementer un classificateur de nombres avec conditions en cascade.

**Ta mission :**

Creer les fonctions suivantes:

```c
const char *classify_number(int n);
int absolute_value(int n);
int max_of_three(int a, int b, int c);
char grade_from_score(int score);
```

**Comportement:**

1. `classify_number(n)`:
   - Retourne "zero" si n == 0
   - Retourne "positive_even" si n > 0 et pair
   - Retourne "positive_odd" si n > 0 et impair
   - Retourne "negative_even" si n < 0 et pair
   - Retourne "negative_odd" si n < 0 et impair

2. `absolute_value(n)`: Utiliser l'operateur ternaire

3. `max_of_three(a, b, c)`: Utiliser des ternaires imbriques

4. `grade_from_score(score)`:
   - 'A' si score >= 90
   - 'B' si score >= 80
   - 'C' si score >= 70
   - 'D' si score >= 60
   - 'F' si score < 60

**Exemples:**
```
classify_number(0)    -> "zero"
classify_number(4)    -> "positive_even"
classify_number(7)    -> "positive_odd"
classify_number(-6)   -> "negative_even"
classify_number(-3)   -> "negative_odd"

absolute_value(-5)    -> 5
absolute_value(5)     -> 5

max_of_three(1, 2, 3) -> 3
max_of_three(3, 1, 2) -> 3

grade_from_score(95)  -> 'A'
grade_from_score(85)  -> 'B'
grade_from_score(55)  -> 'F'
```

### 1.3 Prototype

```c
// condition_cascade.h
#ifndef CONDITION_CASCADE_H
#define CONDITION_CASCADE_H

const char *classify_number(int n);
int absolute_value(int n);
int max_of_three(int a, int b, int c);
char grade_from_score(int score);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

L'operateur ternaire `? :` est le seul operateur ternaire en C. Il existe depuis les origines du langage et permet d'ecrire des conditions simples en une seule ligne.

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Backend Developer**

Les conditions en cascade sont utilisees pour:
- Validation de donnees utilisateur
- Routage de requetes HTTP
- Classification de donnees

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ gcc -Wall -Werror -std=c17 -o test_cond test_main.c condition_cascade.c
$ ./test_cond
classify_number(0) = zero
classify_number(4) = positive_even
classify_number(-3) = negative_odd
absolute_value(-5) = 5
max_of_three(1, 2, 3) = 3
grade_from_score(85) = B
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | classify_number(0) | "zero" | 10 |
| T02 | classify_number(4) | "positive_even" | 10 |
| T03 | classify_number(7) | "positive_odd" | 10 |
| T04 | classify_number(-6) | "negative_even" | 10 |
| T05 | classify_number(-3) | "negative_odd" | 10 |
| T06 | absolute_value(-5) | 5 | 10 |
| T07 | absolute_value(0) | 0 | 5 |
| T08 | max_of_three(1,2,3) | 3 | 10 |
| T09 | max_of_three(3,3,3) | 3 | 5 |
| T10 | grade_from_score(95) | 'A' | 5 |
| T11 | grade_from_score(55) | 'F' | 5 |
| T12 | Compilation | No warnings | 10 |

### 4.3 Solution de reference

```c
#include "condition_cascade.h"

const char *classify_number(int n)
{
    if (n == 0)
    {
        return "zero";
    }
    else if (n > 0)
    {
        if (n % 2 == 0)
            return "positive_even";
        else
            return "positive_odd";
    }
    else
    {
        if (n % 2 == 0)
            return "negative_even";
        else
            return "negative_odd";
    }
}

int absolute_value(int n)
{
    return (n < 0) ? -n : n;
}

int max_of_three(int a, int b, int c)
{
    return (a > b) ? ((a > c) ? a : c) : ((b > c) ? b : c);
}

char grade_from_score(int score)
{
    if (score >= 90)
        return 'A';
    else if (score >= 80)
        return 'B';
    else if (score >= 70)
        return 'C';
    else if (score >= 60)
        return 'D';
    else
        return 'F';
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Mauvaise parite pour negatifs
const char *classify_number(int n)
{
    // En C, -3 % 2 peut donner -1, pas 1
    if (n < 0 && n % 2 == 1)  // Ne matche jamais les impairs negatifs!
        return "negative_odd";
}

// MUTANT 2: Oubli du cas 0
const char *classify_number(int n)
{
    if (n > 0)
        return n % 2 == 0 ? "positive_even" : "positive_odd";
    else  // Traite 0 comme negatif!
        return n % 2 == 0 ? "negative_even" : "negative_odd";
}

// MUTANT 3: Mauvaise priorite ternaire
int max_of_three(int a, int b, int c)
{
    return a > b ? a > c ? a : c : b > c ? b : c;  // Ambigu sans parentheses
}

// MUTANT 4: >= au lieu de > pour les grades
char grade_from_score(int score)
{
    if (score > 90)  // 90 devient B au lieu de A
        return 'A';
    // ...
}

// MUTANT 5: absolute_value avec overflow potentiel
int absolute_value(int n)
{
    return -n;  // Mauvais pour positifs ET INT_MIN overflow
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **structures conditionnelles** en C:
- `if` : execute si condition vraie
- `else` : execute si condition fausse
- `else if` : chainages de conditions
- `? :` : operateur ternaire pour conditions simples

### 5.3 Visualisation ASCII

```
if-else-if cascade:

     +--[condition1]--+
     |  true    false |
     v                v
  [action1]    +--[condition2]--+
               |  true    false |
               v                v
            [action2]    +--[condition3]--+
                         |  true    false |
                         v                v
                      [action3]        [else]


Operateur ternaire:

condition ? value_if_true : value_if_false
    |             |              |
    v             v              v
   bool       returned       returned
             if true        if false
```

### 5.5 Cours Complet

#### L'operateur ternaire

Syntaxe: `condition ? expression1 : expression2`

```c
// Equivalent a:
if (condition)
    result = expression1;
else
    result = expression2;

// En une ligne:
result = condition ? expression1 : expression2;
```

#### Ternaires imbriques

```c
// Trouver le maximum de 3 nombres
int max = (a > b) ? ((a > c) ? a : c) : ((b > c) ? b : c);

// Equivalent:
if (a > b)
{
    if (a > c)
        max = a;
    else
        max = c;
}
else
{
    if (b > c)
        max = b;
    else
        max = c;
}
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la syntaxe de l'operateur ternaire ?

A) condition ?? value1 : value2
B) condition ? value1 : value2
C) condition : value1 ? value2
D) if condition then value1 else value2
E) condition -> value1 | value2

**Reponse correcte: B**

### Question 2
Que retourne `(-5 % 2)` en C ?

A) 1
B) -1
C) 0
D) Undefined behavior
E) Erreur de compilation

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.7-a",
  "name": "condition_cascade",
  "language": "c",
  "language_version": "c17",
  "files": ["condition_cascade.c", "condition_cascade.h"],
  "tests": {
    "classify": ["zero", "positive_even", "positive_odd", "negative_even", "negative_odd"],
    "boundary": [0, -1, 1, "INT_MIN", "INT_MAX"]
  }
}
```
