# Exercice 0.5.13-a : main_args

**Module :**
0.5.13 — Arguments de main

**Concept :**
a-d — argc, argv, argv[0], Parsing d'arguments

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
T2 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `main_args.c`
- `main_args.h`

### 1.2 Consigne

Implementer des fonctions pour manipuler les arguments de ligne de commande.

**Ta mission :**

```c
// Affiche tous les arguments (un par ligne)
void print_args(int argc, char **argv);

// Retourne le nombre d'arguments (sans argv[0])
int count_args(int argc);

// Cherche si un argument existe
int has_arg(int argc, char **argv, const char *target);

// Retourne l'argument a l'index donne (NULL si invalide)
char *get_arg_at(int argc, char **argv, int index);

// Somme tous les arguments numeriques
int sum_numeric_args(int argc, char **argv);
```

**Comportement:**

1. `print_args(3, {"prog", "a", "b"})` -> affiche "prog\na\nb\n"
2. `count_args(3)` -> 2 (exclut argv[0])
3. `has_arg(3, {"prog", "-v", "file"}, "-v")` -> 1
4. `get_arg_at(3, {"prog", "a", "b"}, 1)` -> "a"
5. `sum_numeric_args(4, {"prog", "10", "20", "abc"})` -> 30

**Exemples:**
```
./main_args hello world
-> affiche: ./main_args
            hello
            world
-> count_args(3) = 2

./main_args -v --help file.txt
-> has_arg(..., "-v") = 1
-> has_arg(..., "-x") = 0

./main_args 1 2 3 4 5
-> sum_numeric_args(...) = 15
```

### 1.3 Prototype

```c
// main_args.h
#ifndef MAIN_ARGS_H
#define MAIN_ARGS_H

void print_args(int argc, char **argv);
int count_args(int argc);
int has_arg(int argc, char **argv, const char *target);
char *get_arg_at(int argc, char **argv, int index);
int sum_numeric_args(int argc, char **argv);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | count_args(1) | 0 | 10 |
| T02 | count_args(5) | 4 | 10 |
| T03 | has_arg("-v") present | 1 | 15 |
| T04 | has_arg("-x") absent | 0 | 10 |
| T05 | get_arg_at(0) | argv[0] | 15 |
| T06 | get_arg_at(99) | NULL | 10 |
| T07 | sum_numeric_args("1","2","x") | 3 | 20 |
| T08 | print_args output | Correct | 10 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "main_args.h"

void print_args(int argc, char **argv)
{
    for (int i = 0; i < argc; i++)
    {
        printf("%s\n", argv[i]);
    }
}

int count_args(int argc)
{
    if (argc <= 0)
        return 0;
    return argc - 1;  // Exclut argv[0] (nom du programme)
}

int has_arg(int argc, char **argv, const char *target)
{
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], target) == 0)
            return 1;
    }
    return 0;
}

char *get_arg_at(int argc, char **argv, int index)
{
    if (index < 0 || index >= argc)
        return NULL;
    return argv[index];
}

int sum_numeric_args(int argc, char **argv)
{
    int sum = 0;

    // Commence a 1 pour ignorer argv[0]
    for (int i = 1; i < argc; i++)
    {
        // Tente de convertir en entier
        char *endptr;
        long val = strtol(argv[i], &endptr, 10);

        // Si la conversion est complete (pas de caracteres invalides)
        if (*endptr == '\0')
        {
            sum += (int)val;
        }
    }

    return sum;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: count_args inclut argv[0]
int count_args(int argc)
{
    return argc;  // Devrait etre argc - 1
}

// MUTANT 2: has_arg commence a 1 (rate argv[0])
int has_arg(int argc, char **argv, const char *target)
{
    for (int i = 1; i < argc; i++)  // Devrait commencer a 0
    {
        if (strcmp(argv[i], target) == 0)
            return 1;
    }
    return 0;
}

// MUTANT 3: get_arg_at ne verifie pas les bornes
char *get_arg_at(int argc, char **argv, int index)
{
    (void)argc;
    return argv[index];  // Crash si index >= argc
}

// MUTANT 4: sum_numeric_args utilise atoi (ignore erreurs)
int sum_numeric_args(int argc, char **argv)
{
    int sum = 0;
    for (int i = 1; i < argc; i++)
    {
        sum += atoi(argv[i]);  // atoi("abc") = 0, pas d'erreur
    }
    return sum;  // Compte les non-numeriques comme 0
}

// MUTANT 5: print_args oublie newline
void print_args(int argc, char **argv)
{
    for (int i = 0; i < argc; i++)
    {
        printf("%s", argv[i]);  // Manque \n
    }
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **arguments de main()** en C:

1. **argc** - Nombre d'arguments (argument count)
2. **argv** - Tableau de chaines (argument vector)
3. **argv[0]** - Toujours le nom du programme
4. **argv[argc]** - Toujours NULL (terminateur)

### 5.3 Visualisation ASCII

```
Commande: ./program hello world

argc = 3

argv:
+-------+     +-------------+
| argv  | --> | "./program" | argv[0]
+-------+     +-------------+
              | "hello"     | argv[1]
              +-------------+
              | "world"     | argv[2]
              +-------------+
              | NULL        | argv[3] (terminateur)
              +-------------+

Note: argv est un char** (pointeur vers tableau de char*)
      Chaque argv[i] est un char* (pointeur vers chaine)
```

### 5.5 Signatures de main

```c
// Forme 1: Sans arguments
int main(void)

// Forme 2: Avec arguments
int main(int argc, char **argv)

// Forme 2 alternative (equivalente)
int main(int argc, char *argv[])
```

---

## SECTION 7 : QCM

### Question 1
Que contient argv[0] ?

A) Le premier argument utilisateur
B) Le nom du programme
C) NULL
D) Le nombre d'arguments
E) Rien

**Reponse correcte: B**

### Question 2
Si argc vaut 1, combien d'arguments utilisateur y a-t-il ?

A) 1
B) 0
C) 2
D) Impossible a dire
E) Erreur

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.13-a",
  "name": "main_args",
  "language": "c",
  "language_version": "c17",
  "files": ["main_args.c", "main_args.h"],
  "tests": {
    "arg_parsing": true,
    "cli_tests": [
      {"args": [], "expected_count": 0},
      {"args": ["a", "b"], "expected_count": 2}
    ]
  }
}
```
