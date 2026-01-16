# Exercice 0.5.9-a : function_basics

**Module :**
0.5.9 — Fonctions

**Concept :**
a-f — Prototype, Definition, return, void return, Parameters, Pass by value

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.8 (loop_patterns)

**Domaines :**
Algo

**Duree estimee :**
150 min

**XP Base :**
180

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `function_basics.c`
- `function_basics.h`

**Fonctions autorisees :**
- Aucune fonction de bibliotheque requise

### 1.2 Consigne

Implementer des fonctions illustrant les differents aspects des fonctions en C.

**Ta mission :**

Creer les fonctions suivantes:

```c
// Fonction avec retour int
int add(int a, int b);

// Fonction avec retour void
void print_value(int val, char *buffer, int buffer_size);

// Fonction sans parametres
int get_magic_number(void);

// Fonction demontrant pass-by-value
int try_modify(int value);

// Fonction avec plusieurs parametres
int compute_polynomial(int x, int a, int b, int c);

// Fonction recursive simple
int factorial(int n);
```

**Comportement:**

1. `add(a, b)`: Retourne a + b
2. `print_value(val, buffer, buffer_size)`: Ecrit val en decimal dans buffer
3. `get_magic_number()`: Retourne toujours 42
4. `try_modify(value)`: Ajoute 10 a value et retourne le resultat (l'original reste inchange chez l'appelant)
5. `compute_polynomial(x, a, b, c)`: Retourne ax^2 + bx + c
6. `factorial(n)`: Retourne n! (0! = 1)

**Exemples:**
```
add(3, 5)                    -> 8
add(-2, 7)                   -> 5

get_magic_number()           -> 42

try_modify(5)                -> 15

compute_polynomial(2, 1, 2, 3)  -> 1*4 + 2*2 + 3 = 11
compute_polynomial(3, 2, -1, 4) -> 2*9 + (-1)*3 + 4 = 19

factorial(0)                 -> 1
factorial(5)                 -> 120
factorial(10)                -> 3628800
```

### 1.3 Prototype

```c
// function_basics.h
#ifndef FUNCTION_BASICS_H
#define FUNCTION_BASICS_H

int add(int a, int b);
void print_value(int val, char *buffer, int buffer_size);
int get_magic_number(void);
int try_modify(int value);
int compute_polynomial(int x, int a, int b, int c);
int factorial(int n);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | add(3, 5) | 8 | 10 |
| T02 | add(-2, 7) | 5 | 10 |
| T03 | add(0, 0) | 0 | 5 |
| T04 | get_magic_number() | 42 | 10 |
| T05 | try_modify(5) | 15 | 10 |
| T06 | compute_polynomial(2, 1, 2, 3) | 11 | 10 |
| T07 | compute_polynomial(0, 5, 3, 2) | 2 | 10 |
| T08 | factorial(0) | 1 | 10 |
| T09 | factorial(5) | 120 | 10 |
| T10 | factorial(10) | 3628800 | 5 |
| T11 | Compilation | No warnings | 10 |

### 4.3 Solution de reference

```c
#include "function_basics.h"

int add(int a, int b)
{
    return a + b;
}

void print_value(int val, char *buffer, int buffer_size)
{
    if (buffer == NULL || buffer_size < 2)
        return;

    int i = 0;
    int negative = 0;
    int temp = val;

    if (val < 0)
    {
        negative = 1;
        temp = -temp;
    }

    char temp_buf[32];
    int j = 0;

    if (temp == 0)
    {
        temp_buf[j++] = '0';
    }
    else
    {
        while (temp > 0 && j < 31)
        {
            temp_buf[j++] = '0' + (temp % 10);
            temp /= 10;
        }
    }

    if (negative && i < buffer_size - 1)
        buffer[i++] = '-';

    while (j > 0 && i < buffer_size - 1)
        buffer[i++] = temp_buf[--j];

    buffer[i] = '\0';
}

int get_magic_number(void)
{
    return 42;
}

int try_modify(int value)
{
    value = value + 10;
    return value;
}

int compute_polynomial(int x, int a, int b, int c)
{
    return a * x * x + b * x + c;
}

int factorial(int n)
{
    if (n <= 1)
        return 1;
    return n * factorial(n - 1);
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Oubli du return
int add(int a, int b)
{
    int result = a + b;
    // return result;  // Oublie! Retourne valeur indeterminee
}

// MUTANT 2: Parametre void mal compris
int get_magic_number()  // Pas de void = accepte n'importe quoi en C ancien
{
    return 42;
}

// MUTANT 3: Confusion pass-by-value
int try_modify(int value)
{
    value += 10;
    // Pense que l'original est modifie
    return value;  // Correct mais mauvaise comprehension
}

// MUTANT 4: Erreur dans polynomial
int compute_polynomial(int x, int a, int b, int c)
{
    return a * x + b * x + c;  // Oublie x^2, fait 2*a*x au lieu de ax^2
}

// MUTANT 5: Factorial sans cas de base correct
int factorial(int n)
{
    return n * factorial(n - 1);  // Recursion infinie si n <= 0
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **composants d'une fonction** en C:
- **Prototype (declaration)** : annonce la fonction avant son utilisation
- **Definition** : contient le corps de la fonction
- **return** : termine la fonction et renvoie une valeur
- **void** : indique qu'une fonction ne retourne rien
- **Parametres** : valeurs passees a la fonction
- **Pass-by-value** : C copie les arguments, l'original n'est pas modifie

### 5.3 Visualisation ASCII

```
Declaration (prototype):
+------------------------------------------+
| type_retour nom_fonction(type param, ...);|
+------------------------------------------+

Definition:
+------------------------------------------+
| type_retour nom_fonction(type param)      |
| {                                         |
|     // Corps de la fonction               |
|     return valeur;                        |
| }                                         |
+------------------------------------------+

Appel:
+------------------+
| int x = 5;       |    x reste 5
|        |         |        ^
|        v (copie) |        |
| try_modify(x);   |    value = 15 (local)
+------------------+
```

### 5.5 Cours Complet

#### Prototype vs Definition

```c
// Prototype (declaration) - dans le .h
int add(int a, int b);

// Definition - dans le .c
int add(int a, int b)
{
    return a + b;
}
```

#### Pass-by-value

En C, tous les arguments sont passes par valeur:

```c
void increment(int x)
{
    x = x + 1;  // Modifie la COPIE locale
}

int main(void)
{
    int n = 5;
    increment(n);
    // n vaut toujours 5!
}
```

#### Fonctions void

```c
void greet(void)
{
    // Pas de return necessaire
    // ou: return;  (sans valeur)
}
```

---

## SECTION 7 : QCM

### Question 1
Que signifie `void` dans `int get_value(void)` ?

A) La fonction retourne void
B) La fonction n'accepte aucun parametre
C) La fonction peut accepter n'importe quoi
D) C'est une erreur de syntaxe
E) La fonction est privee

**Reponse correcte: B**

### Question 2
Apres `int x = 5; try_modify(x);`, que vaut x ?

A) 5
B) 15
C) 10
D) 0
E) Undefined

**Reponse correcte: A**

### Question 3
Quelle est la difference entre declaration et definition ?

A) Aucune difference
B) Declaration a le corps, definition non
C) Declaration annonce, definition contient le code
D) Declaration est dans .c, definition dans .h
E) Les deux termes sont synonymes

**Reponse correcte: C**

### Question 4
Que se passe-t-il si on oublie le return dans une fonction non-void ?

A) Erreur de compilation
B) Le programme crash
C) Retourne 0 automatiquement
D) Comportement indefini
E) Retourne NULL

**Reponse correcte: D**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.9-a",
  "name": "function_basics",
  "language": "c",
  "language_version": "c17",
  "files": ["function_basics.c", "function_basics.h"],
  "tests": {
    "add": [[3,5], [-2,7], [0,0], [-5,-5]],
    "factorial": [0, 1, 5, 10, 12],
    "polynomial": [[2,1,2,3], [0,5,3,2], [1,1,1,1]]
  }
}
```
