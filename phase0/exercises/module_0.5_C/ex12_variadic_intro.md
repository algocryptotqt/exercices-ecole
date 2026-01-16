# Exercice 0.5.12-a : variadic_intro

**Module :**
0.5.12 — Fonctions Variadiques

**Concept :**
a-e — va_list, va_start, va_arg, va_end, va_copy

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.9 (fonctions)

**Domaines :**
Algo

**Duree estimee :**
180 min

**XP Base :**
250

**Complexite :**
T2 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `variadic_intro.c`
- `variadic_intro.h`

### 1.2 Consigne

Implementer des fonctions variadiques (nombre variable d'arguments).

**Ta mission :**

```c
// Somme de n entiers
int sum_ints(int count, ...);

// Moyenne de n doubles
double average_doubles(int count, ...);

// Minimum parmi n entiers
int min_of(int count, ...);

// Maximum parmi n entiers
int max_of(int count, ...);

// Concatenation de n chaines (alloue memoire)
char *concat_strings(int count, ...);
```

**Comportement:**

1. `sum_ints(3, 10, 20, 30)` -> 60
2. `average_doubles(4, 1.0, 2.0, 3.0, 4.0)` -> 2.5
3. `min_of(5, 3, 1, 4, 1, 5)` -> 1
4. `max_of(5, 3, 1, 4, 1, 5)` -> 5
5. `concat_strings(3, "Hello", " ", "World")` -> "Hello World"

**Exemples:**
```
sum_ints(0)              -> 0
sum_ints(1, 42)          -> 42
sum_ints(4, 1, 2, 3, 4)  -> 10

min_of(1, 5)             -> 5
min_of(3, -5, 0, 5)      -> -5

max_of(2, 100, 50)       -> 100
```

### 1.3 Prototype

```c
// variadic_intro.h
#ifndef VARIADIC_INTRO_H
#define VARIADIC_INTRO_H

int sum_ints(int count, ...);
double average_doubles(int count, ...);
int min_of(int count, ...);
int max_of(int count, ...);
char *concat_strings(int count, ...);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | sum_ints(3, 1, 2, 3) | 6 | 15 |
| T02 | sum_ints(0) | 0 | 10 |
| T03 | average_doubles(2, 10.0, 20.0) | 15.0 | 15 |
| T04 | min_of(4, 5, 2, 8, 1) | 1 | 15 |
| T05 | max_of(4, 5, 2, 8, 1) | 8 | 15 |
| T06 | concat_strings(2, "A", "B") | "AB" | 20 |
| T07 | Memory check (no leaks) | Pass | 10 |

### 4.3 Solution de reference

```c
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "variadic_intro.h"

int sum_ints(int count, ...)
{
    va_list args;
    va_start(args, count);

    int sum = 0;
    for (int i = 0; i < count; i++)
    {
        sum += va_arg(args, int);
    }

    va_end(args);
    return sum;
}

double average_doubles(int count, ...)
{
    if (count <= 0)
        return 0.0;

    va_list args;
    va_start(args, count);

    double sum = 0.0;
    for (int i = 0; i < count; i++)
    {
        sum += va_arg(args, double);
    }

    va_end(args);
    return sum / count;
}

int min_of(int count, ...)
{
    if (count <= 0)
        return 0;

    va_list args;
    va_start(args, count);

    int min = va_arg(args, int);
    for (int i = 1; i < count; i++)
    {
        int val = va_arg(args, int);
        if (val < min)
            min = val;
    }

    va_end(args);
    return min;
}

int max_of(int count, ...)
{
    if (count <= 0)
        return 0;

    va_list args;
    va_start(args, count);

    int max = va_arg(args, int);
    for (int i = 1; i < count; i++)
    {
        int val = va_arg(args, int);
        if (val > max)
            max = val;
    }

    va_end(args);
    return max;
}

char *concat_strings(int count, ...)
{
    if (count <= 0)
    {
        char *empty = malloc(1);
        if (empty)
            empty[0] = '\0';
        return empty;
    }

    va_list args;
    va_list args_copy;

    // Premier passage: calculer longueur totale
    va_start(args, count);
    va_copy(args_copy, args);

    size_t total_len = 0;
    for (int i = 0; i < count; i++)
    {
        total_len += strlen(va_arg(args, char *));
    }
    va_end(args);

    // Allouer la memoire
    char *result = malloc(total_len + 1);
    if (!result)
    {
        va_end(args_copy);
        return NULL;
    }

    // Deuxieme passage: copier les chaines
    result[0] = '\0';
    for (int i = 0; i < count; i++)
    {
        strcat(result, va_arg(args_copy, char *));
    }

    va_end(args_copy);
    return result;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Oubli de va_end (fuite de ressources)
int sum_ints(int count, ...)
{
    va_list args;
    va_start(args, count);
    int sum = 0;
    for (int i = 0; i < count; i++)
        sum += va_arg(args, int);
    return sum;  // Manque va_end(args)
}

// MUTANT 2: Mauvais type dans va_arg
double average_doubles(int count, ...)
{
    va_list args;
    va_start(args, count);
    double sum = 0.0;
    for (int i = 0; i < count; i++)
        sum += va_arg(args, int);  // int au lieu de double
    va_end(args);
    return sum / count;
}

// MUTANT 3: min_of commence par 0 au lieu du premier element
int min_of(int count, ...)
{
    va_list args;
    va_start(args, count);
    int min = 0;  // Devrait etre le premier element
    for (int i = 0; i < count; i++)
    {
        int val = va_arg(args, int);
        if (val < min)
            min = val;
    }
    va_end(args);
    return min;
}

// MUTANT 4: concat_strings ne termine pas par '\0'
char *concat_strings(int count, ...)
{
    va_list args;
    va_start(args, count);
    size_t total_len = 0;
    for (int i = 0; i < count; i++)
        total_len += strlen(va_arg(args, char *));
    va_end(args);

    char *result = malloc(total_len);  // Manque +1 pour '\0'
    // ... reste du code
    return result;
}

// MUTANT 5: Division par zero dans average
double average_doubles(int count, ...)
{
    va_list args;
    va_start(args, count);
    double sum = 0.0;
    for (int i = 0; i < count; i++)
        sum += va_arg(args, double);
    va_end(args);
    return sum / count;  // Division par 0 si count == 0
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **fonctions variadiques** en C:

1. **va_list** - Type pour stocker les arguments variables
2. **va_start(ap, last)** - Initialise la liste avec le dernier argument fixe
3. **va_arg(ap, type)** - Recupere l'argument suivant du type specifie
4. **va_end(ap)** - Nettoie la liste (OBLIGATOIRE)
5. **va_copy(dest, src)** - Copie une liste d'arguments

### 5.3 Visualisation ASCII

```
sum_ints(3, 10, 20, 30):

PILE D'APPELS:
+----------------+
| count = 3      | <- dernier argument fixe
+----------------+
| 10             | <- va_arg 1
+----------------+
| 20             | <- va_arg 2
+----------------+
| 30             | <- va_arg 3
+----------------+

va_start(args, count)  -> args pointe apres count
va_arg(args, int)      -> 10, deplace args
va_arg(args, int)      -> 20, deplace args
va_arg(args, int)      -> 30, deplace args
va_end(args)           -> nettoie
```

---

## SECTION 7 : QCM

### Question 1
Quel header faut-il inclure pour les fonctions variadiques ?

A) stdlib.h
B) stdio.h
C) stdarg.h
D) string.h
E) varargs.h

**Reponse correcte: C**

### Question 2
Que se passe-t-il si on oublie va_end() ?

A) Erreur de compilation
B) Fuite de ressources possible
C) Rien
D) Crash immediat
E) Retourne NULL

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.12-a",
  "name": "variadic_intro",
  "language": "c",
  "language_version": "c17",
  "files": ["variadic_intro.c", "variadic_intro.h"],
  "tests": {
    "sum": "variadic_sum_tests",
    "average": "variadic_avg_tests",
    "min_max": "variadic_minmax_tests",
    "concat": "variadic_concat_tests"
  }
}
```
