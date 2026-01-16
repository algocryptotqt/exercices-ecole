# Exercice 0.5.10-a : scope_lifetime

**Module :**
0.5.10 — Portee et Duree de Vie

**Concept :**
a-e — Local, Global, static local, static global, extern

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.9 (function_basics)

**Domaines :**
Algo, Systeme

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
- `scope_lifetime.c`
- `scope_lifetime.h`
- `scope_extern.c` (pour tester extern)

**Fonctions autorisees :**
- Aucune fonction de bibliotheque requise

### 1.2 Consigne

Implementer des fonctions illustrant les differentes portees et durees de vie des variables.

**Ta mission :**

Creer les fonctions suivantes:

```c
// Demonstre variable locale
int local_demo(int input);

// Demonstre variable statique locale (compteur persistant)
int call_counter(void);

// Reset le compteur statique
void reset_counter(void);

// Utilise variable globale
int get_global_value(void);
void set_global_value(int val);

// Fonction interne (static) - non exportee
// static int internal_helper(int x);

// Acces a variable externe (definie dans scope_extern.c)
int get_external_value(void);
```

**Comportement:**

1. `local_demo(input)`: Cree une variable locale, la modifie, retourne le resultat
2. `call_counter()`: Retourne le nombre de fois qu'elle a ete appelee (1, 2, 3, ...)
3. `reset_counter()`: Remet le compteur a 0
4. `get_global_value()`: Retourne la valeur de la variable globale g_value
5. `set_global_value(val)`: Modifie g_value
6. `get_external_value()`: Retourne la valeur de external_var (definie ailleurs)

**Exemples:**
```
local_demo(5)           -> 15 (5 * 3)
local_demo(5)           -> 15 (pas de persistance)

call_counter()          -> 1
call_counter()          -> 2
call_counter()          -> 3
reset_counter()
call_counter()          -> 1

set_global_value(100)
get_global_value()      -> 100
set_global_value(42)
get_global_value()      -> 42
```

### 1.3 Prototype

```c
// scope_lifetime.h
#ifndef SCOPE_LIFETIME_H
#define SCOPE_LIFETIME_H

int local_demo(int input);
int call_counter(void);
void reset_counter(void);
int get_global_value(void);
void set_global_value(int val);
int get_external_value(void);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | local_demo(5) | 15 | 10 |
| T02 | local_demo(5) twice | 15, 15 | 10 |
| T03 | call_counter() x3 | 1, 2, 3 | 15 |
| T04 | reset_counter() then call | 1 | 10 |
| T05 | set_global_value(100), get | 100 | 10 |
| T06 | set_global_value(42), get | 42 | 10 |
| T07 | get_external_value() | 999 | 10 |
| T08 | Multiple global sets | correct values | 10 |
| T09 | Compilation | No warnings | 15 |

### 4.3 Solution de reference

```c
// scope_lifetime.c
#include "scope_lifetime.h"

// Variable globale - visible dans tout le fichier
static int g_value = 0;

// Variable externe - definie dans scope_extern.c
extern int external_var;

// Variable statique locale - pour le compteur
static int s_counter = 0;

int local_demo(int input)
{
    int local_var = input;  // Variable locale
    local_var = local_var * 3;
    return local_var;
    // local_var est detruite ici
}

int call_counter(void)
{
    static int count = 0;  // Initialisee une seule fois
    count++;
    return count;
}

void reset_counter(void)
{
    // On ne peut pas acceder a count de call_counter
    // Solution: utiliser une variable statique au niveau fichier
    s_counter = 0;
}

int call_counter_v2(void)
{
    s_counter++;
    return s_counter;
}

int get_global_value(void)
{
    return g_value;
}

void set_global_value(int val)
{
    g_value = val;
}

int get_external_value(void)
{
    return external_var;
}

// Fonction statique - interne au fichier
static int internal_helper(int x)
{
    return x * 2;
}
```

```c
// scope_extern.c
int external_var = 999;  // Definition de la variable externe
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: Confusion local vs static
int call_counter(void)
{
    int count = 0;  // Reinitialise a chaque appel!
    count++;
    return count;  // Retourne toujours 1
}

// MUTANT 2: Oubli de static pour variable globale privee
int g_value = 0;  // Sans static, visible partout (collision possible)

void set_global_value(int val)
{
    g_value = val;
}

// MUTANT 3: extern mal utilise
extern int external_var = 999;  // ERREUR: extern + initialisation

// MUTANT 4: Variable locale retournee par adresse (dangling pointer)
int *bad_local_demo(int input)
{
    int local_var = input * 3;
    return &local_var;  // DANGER: adresse de variable locale!
}

// MUTANT 5: Static global au lieu de static local
static int global_count = 0;  // Fonctionne mais pollue l'espace

int call_counter(void)
{
    global_count++;  // Pas encapsule dans la fonction
    return global_count;
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **4 types de portee** en C:
- **Local** : visible uniquement dans le bloc {}
- **Global** : visible dans tout le fichier (et potentiellement ailleurs)
- **static local** : portee locale, duree de vie globale
- **static global** : visible uniquement dans le fichier actuel
- **extern** : declare une variable definie ailleurs

### 5.3 Visualisation ASCII

```
Portee et Duree de vie:

+------------------+-------------------+-------------------+
|                  |  Portee           |  Duree de vie     |
+------------------+-------------------+-------------------+
| local            |  bloc {}          |  bloc execution   |
| static local     |  bloc {}          |  programme entier |
| global           |  fichier (+extern)|  programme entier |
| static global    |  fichier seul     |  programme entier |
+------------------+-------------------+-------------------+

Memoire:

+------------------+
|      STACK       |  <- Variables locales
+------------------+
|       ...        |
+------------------+
|      HEAP        |  <- malloc/free
+------------------+
|       BSS        |  <- Variables globales non initialisees
+------------------+
|      DATA        |  <- Variables globales initialisees
+------------------+
|      TEXT        |  <- Code
+------------------+
```

### 5.5 Cours Complet

#### Variables locales

```c
void foo(void)
{
    int x = 5;  // Creee a l'entree, detruite a la sortie
    {
        int y = 10;  // Portee limitee a ce bloc
    }
    // y n'existe plus ici
}
```

#### Variables static locales

```c
int counter(void)
{
    static int n = 0;  // Initialisee UNE SEULE fois
    n++;
    return n;  // 1, 2, 3, 4...
}
```

#### extern

```c
// fichier1.c
int shared_var = 42;  // Definition

// fichier2.c
extern int shared_var;  // Declaration (pas de memoire allouee)

void use_it(void)
{
    shared_var = 100;  // Utilise la variable de fichier1.c
}
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la duree de vie d'une variable static locale ?

A) Le bloc ou elle est declaree
B) La fonction ou elle est declaree
C) Tout le programme
D) Jusqu'au prochain appel
E) Indefinie

**Reponse correcte: C**

### Question 2
Que fait le mot-cle `extern` ?

A) Exporte une variable
B) Declare une variable definie ailleurs
C) Rend une variable globale
D) Protege une variable
E) Supprime une variable

**Reponse correcte: B**

### Question 3
Une variable `static` au niveau global est:

A) Visible partout
B) Visible seulement dans le fichier actuel
C) Visible seulement dans la fonction
D) Invisible
E) Constante

**Reponse correcte: B**

### Question 4
Ou sont stockees les variables locales ?

A) Dans le segment DATA
B) Dans le segment BSS
C) Sur le tas (heap)
D) Sur la pile (stack)
E) Dans les registres uniquement

**Reponse correcte: D**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.10-a",
  "name": "scope_lifetime",
  "language": "c",
  "language_version": "c17",
  "files": ["scope_lifetime.c", "scope_lifetime.h", "scope_extern.c"],
  "tests": {
    "local": [5, 10, 0, -3],
    "counter": "sequence_test",
    "global": [0, 42, 100, -1],
    "extern": "link_test"
  }
}
```
