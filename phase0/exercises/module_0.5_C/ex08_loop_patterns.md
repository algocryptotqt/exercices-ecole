# Exercice 0.5.8-a : loop_patterns

**Module :**
0.5.8 — Boucles

**Concept :**
a-f — for, while, do-while, break, continue, goto

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.7 (conditions)

**Domaines :**
Algo

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
- `loop_patterns.c`
- `loop_patterns.h`

### 1.2 Consigne

Implementer des algorithmes classiques utilisant chaque type de boucle.

**Ta mission :**

```c
// FOR: Calculer factorielle
unsigned long factorial_for(int n);

// WHILE: Plus grand diviseur commun (Euclide)
int gcd_while(int a, int b);

// DO-WHILE: Valider input (premier valide dans range 1-100)
int validate_input_do_while(int *inputs, int count);

// BREAK: Trouver premier element
int find_first(int *arr, int size, int target);

// CONTINUE: Somme des positifs seulement
int sum_positive_only(int *arr, int size);

// GOTO: Machine a etats simple (cleanup pattern)
int state_machine_goto(int initial_state);
```

**Comportement:**

1. `factorial_for(5)` -> 120
2. `gcd_while(48, 18)` -> 6
3. `validate_input_do_while({0, -5, 50, 200}, 4)` -> 50 (premier valide)
4. `find_first({1,2,3,4,5}, 5, 3)` -> 2 (index)
5. `sum_positive_only({-1, 2, -3, 4}, 4)` -> 6
6. `state_machine_goto(0)` -> resultat final apres transitions

**Exemples:**
```
factorial_for(0)  -> 1
factorial_for(5)  -> 120
factorial_for(10) -> 3628800

gcd_while(48, 18) -> 6
gcd_while(17, 13) -> 1

find_first({1,2,3}, 3, 2) -> 1
find_first({1,2,3}, 3, 9) -> -1

sum_positive_only({-1,2,-3,4}, 4) -> 6
```

### 1.3 Prototype

```c
// loop_patterns.h
#ifndef LOOP_PATTERNS_H
#define LOOP_PATTERNS_H

unsigned long factorial_for(int n);
int gcd_while(int a, int b);
int validate_input_do_while(int *inputs, int count);
int find_first(int *arr, int size, int target);
int sum_positive_only(int *arr, int size);
int state_machine_goto(int initial_state);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.3 Solution de reference

```c
#include "loop_patterns.h"

unsigned long factorial_for(int n)
{
    unsigned long result = 1;
    for (int i = 2; i <= n; i++)
    {
        result *= i;
    }
    return result;
}

int gcd_while(int a, int b)
{
    if (a < 0) a = -a;
    if (b < 0) b = -b;

    while (b != 0)
    {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

int validate_input_do_while(int *inputs, int count)
{
    int i = 0;
    int value;

    do {
        if (i >= count)
            return -1;
        value = inputs[i];
        i++;
    } while (value < 1 || value > 100);

    return value;
}

int find_first(int *arr, int size, int target)
{
    for (int i = 0; i < size; i++)
    {
        if (arr[i] == target)
        {
            return i;  // break implicite via return
        }
    }
    return -1;
}

int sum_positive_only(int *arr, int size)
{
    int sum = 0;
    for (int i = 0; i < size; i++)
    {
        if (arr[i] <= 0)
            continue;
        sum += arr[i];
    }
    return sum;
}

int state_machine_goto(int initial_state)
{
    int state = initial_state;
    int result = 0;

state_0:
    if (state != 0) goto state_1;
    result += 10;
    state = 1;
    goto state_1;

state_1:
    if (state != 1) goto state_2;
    result += 20;
    state = 2;
    goto state_2;

state_2:
    if (state != 2) goto cleanup;
    result += 30;
    goto cleanup;

cleanup:
    return result;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Factorial commence a 0 (multiplie par 0)
unsigned long factorial_for(int n)
{
    unsigned long result = 1;
    for (int i = 0; i <= n; i++)  // Commence a 0!
        result *= i;  // 1 * 0 = 0
    return result;
}

// MUTANT 2: GCD sans valeur absolue
int gcd_while(int a, int b)
{
    while (b != 0)
    {
        int temp = b;
        b = a % b;  // Negatif % peut etre negatif
        a = temp;
    }
    return a;  // Peut retourner negatif
}

// MUTANT 3: do-while sans increment
int validate_input_do_while(int *inputs, int count)
{
    int i = 0;
    int value;
    do {
        value = inputs[i];
        // i++ oublie -> boucle infinie
    } while (value < 1 || value > 100);
    return value;
}

// MUTANT 4: continue mal place
int sum_positive_only(int *arr, int size)
{
    int sum = 0;
    for (int i = 0; i < size; i++)
    {
        continue;  // Saute TOUJOURS
        if (arr[i] > 0)
            sum += arr[i];
    }
    return sum;  // Toujours 0
}

// MUTANT 5: find_first retourne element au lieu d'index
int find_first(int *arr, int size, int target)
{
    for (int i = 0; i < size; i++)
        if (arr[i] == target)
            return arr[i];  // Retourne valeur, pas index!
    return -1;
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **3 types de boucles** en C:
- `for` : quand on connait le nombre d'iterations
- `while` : quand on test la condition avant
- `do-while` : quand on veut au moins une execution

Les **mots-cles de controle**:
- `break` : sort de la boucle immediatement
- `continue` : passe a l'iteration suivante
- `goto` : saut inconditionnel (usage limite)

### 5.3 Visualisation ASCII

```
FOR:                    WHILE:                 DO-WHILE:
+--[init]--+            +--[condition]--+      +--[body]--+
|          |            |   true  false |      |          |
v          |            v         |     |      v          |
[condition]|         [body]       |     |   [condition]   |
true  false|            |         |     |   true  false   |
v          |            +---------+     |   |         |   |
[body]     |                      |     |   +---------+   |
|          |                      v     |             |   |
[increment]|                   [end]    |             v   |
|          |                            |          [end]  |
+----------+                            +--------+        |
|                                                |        |
v                                                +--------+
[end]
```

---

## SECTION 7 : QCM

### Question 1
Quelle boucle garantit au moins une execution ?

A) for
B) while
C) do-while
D) foreach
E) Aucune

**Reponse correcte: C**

### Question 2
Que fait `continue` dans une boucle for ?

A) Sort de la boucle
B) Passe a l'iteration suivante (execute l'increment)
C) Recommence depuis le debut
D) Arrete le programme
E) Ne fait rien

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.8-a",
  "name": "loop_patterns",
  "language": "c",
  "language_version": "c17",
  "files": ["loop_patterns.c", "loop_patterns.h"],
  "tests": {
    "factorial": [0, 1, 5, 10, 12],
    "gcd": [[48,18], [17,13], [100,25], [-12,8]],
    "find_first": "array_search_tests"
  }
}
```
