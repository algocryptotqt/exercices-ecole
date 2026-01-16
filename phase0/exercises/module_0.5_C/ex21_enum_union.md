# Exercice 0.5.21-a : enum_union

**Module :**
0.5.21 — Enumerations et Unions

**Concept :**
a-d — enum, valeurs enum, union, tagged union

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.20 (structures)

**Domaines :**
Algo, CPU

**Duree estimee :**
120 min

**XP Base :**
180

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `enum_union.c`
- `enum_union.h`

### 1.2 Consigne

Implementer des fonctions utilisant enumerations et unions.

**Ta mission :**

```c
// Enumeration des jours
typedef enum e_day {
    MONDAY = 1,
    TUESDAY,
    WEDNESDAY,
    THURSDAY,
    FRIDAY,
    SATURDAY,
    SUNDAY
} t_day;

// Enumeration des types
typedef enum e_type {
    TYPE_INT,
    TYPE_FLOAT,
    TYPE_STRING
} t_type;

// Union pour stocker differents types
typedef union u_value {
    int i;
    float f;
    char *s;
} t_value;

// Tagged union (variant)
typedef struct s_variant {
    t_type type;
    t_value value;
} t_variant;

// Retourner le nom du jour
const char *day_name(t_day day);

// Verifier si c'est un weekend
int is_weekend(t_day day);

// Creer un variant int
t_variant make_int(int value);

// Creer un variant float
t_variant make_float(float value);

// Creer un variant string
t_variant make_string(char *value);

// Afficher un variant (retourne string descriptif)
const char *variant_describe(t_variant v);
```

**Comportement:**

1. `day_name(MONDAY)` -> "Monday"
2. `is_weekend(SATURDAY)` -> 1
3. `is_weekend(MONDAY)` -> 0
4. `make_int(42)` -> variant de type INT avec valeur 42
5. `make_float(3.14)` -> variant de type FLOAT

**Exemples:**
```
day_name(MONDAY)    -> "Monday"
day_name(FRIDAY)    -> "Friday"
day_name(SUNDAY)    -> "Sunday"

is_weekend(MONDAY)   -> 0
is_weekend(SATURDAY) -> 1
is_weekend(SUNDAY)   -> 1

t_variant v = make_int(42);
v.type   == TYPE_INT
v.value.i == 42
```

### 1.3 Prototype

```c
// enum_union.h
#ifndef ENUM_UNION_H
#define ENUM_UNION_H

typedef enum e_day {
    MONDAY = 1,
    TUESDAY,
    WEDNESDAY,
    THURSDAY,
    FRIDAY,
    SATURDAY,
    SUNDAY
} t_day;

typedef enum e_type {
    TYPE_INT,
    TYPE_FLOAT,
    TYPE_STRING
} t_type;

typedef union u_value {
    int i;
    float f;
    char *s;
} t_value;

typedef struct s_variant {
    t_type type;
    t_value value;
} t_variant;

const char *day_name(t_day day);
int is_weekend(t_day day);
t_variant make_int(int value);
t_variant make_float(float value);
t_variant make_string(char *value);
const char *variant_describe(t_variant v);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | day_name(MONDAY) | "Monday" | 15 |
| T02 | day_name(SUNDAY) | "Sunday" | 10 |
| T03 | is_weekend(SATURDAY) | 1 | 15 |
| T04 | is_weekend(TUESDAY) | 0 | 10 |
| T05 | make_int(42) | correct | 15 |
| T06 | make_float(3.14) | correct | 15 |
| T07 | make_string("hi") | correct | 10 |
| T08 | variant_describe | correct | 10 |

### 4.3 Solution de reference

```c
#include <stdio.h>
#include "enum_union.h"

const char *day_name(t_day day)
{
    static const char *names[] = {
        "Invalid",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
        "Sunday"
    };

    if (day < MONDAY || day > SUNDAY)
        return names[0];
    return names[day];
}

int is_weekend(t_day day)
{
    return (day == SATURDAY || day == SUNDAY) ? 1 : 0;
}

t_variant make_int(int value)
{
    t_variant v;
    v.type = TYPE_INT;
    v.value.i = value;
    return v;
}

t_variant make_float(float value)
{
    t_variant v;
    v.type = TYPE_FLOAT;
    v.value.f = value;
    return v;
}

t_variant make_string(char *value)
{
    t_variant v;
    v.type = TYPE_STRING;
    v.value.s = value;
    return v;
}

const char *variant_describe(t_variant v)
{
    static char buffer[64];

    switch (v.type)
    {
        case TYPE_INT:
            snprintf(buffer, sizeof(buffer), "int: %d", v.value.i);
            break;
        case TYPE_FLOAT:
            snprintf(buffer, sizeof(buffer), "float: %f", v.value.f);
            break;
        case TYPE_STRING:
            snprintf(buffer, sizeof(buffer), "string: %s",
                     v.value.s ? v.value.s : "(null)");
            break;
        default:
            snprintf(buffer, sizeof(buffer), "unknown");
    }
    return buffer;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: day_name index off-by-one
const char *day_name(t_day day)
{
    static const char *names[] = {
        "Monday", "Tuesday", "Wednesday",
        "Thursday", "Friday", "Saturday", "Sunday"
    };
    return names[day];  // MONDAY=1 mais names[0]="Monday"
}

// MUTANT 2: is_weekend oublie SUNDAY
int is_weekend(t_day day)
{
    return day == SATURDAY;  // Oublie SUNDAY
}

// MUTANT 3: make_int n'initialise pas le type
t_variant make_int(int value)
{
    t_variant v;
    // v.type = TYPE_INT;  // Oublie d'initialiser
    v.value.i = value;
    return v;  // type non initialise
}

// MUTANT 4: union utilisee incorrectement
t_variant make_float(float value)
{
    t_variant v;
    v.type = TYPE_FLOAT;
    v.value.i = (int)value;  // Stocke dans mauvais membre
    return v;
}

// MUTANT 5: variant_describe ne gere pas tous les cas
const char *variant_describe(t_variant v)
{
    if (v.type == TYPE_INT)
        return "int";
    return "other";  // Ne gere pas FLOAT ni STRING
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **enums** et **unions** en C:

1. **enum** - Ensemble de constantes nommees
2. **union** - Plusieurs types partageant la meme memoire
3. **Tagged union** - Union + tag indiquant le type actif
4. **sizeof(union)** - Taille du plus grand membre

### 5.3 Visualisation ASCII

```
ENUM:
typedef enum { MONDAY=1, TUESDAY, ... } t_day;

Valeurs: MONDAY=1, TUESDAY=2, WEDNESDAY=3, ...

UNION:
typedef union {
    int i;      // 4 bytes
    float f;    // 4 bytes
    char *s;    // 8 bytes (64-bit)
} t_value;

Memoire (une seule zone de 8 bytes):
+----------------+
| i | f |   s    |  <- Tous au meme endroit!
+----------------+
sizeof(t_value) = 8 (taille du plus grand)

TAGGED UNION:
struct { t_type type; t_value value; }

+------+----------------+
| type |     value      |
+------+----------------+
   4         8          = 12 bytes (+ padding possible)
```

---

## SECTION 7 : QCM

### Question 1
Dans une union, les membres:

A) Sont stockes a des adresses differentes
B) Partagent la meme zone memoire
C) Sont copies
D) Sont en read-only
E) Doivent avoir le meme type

**Reponse correcte: B**

### Question 2
Pourquoi utiliser un tagged union ?

A) Pour economiser de la memoire
B) Pour savoir quel membre est actuellement utilise
C) Pour avoir plusieurs valeurs en meme temps
D) Pour accelerer l'acces
E) C'est deprecated

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.21-a",
  "name": "enum_union",
  "language": "c",
  "language_version": "c17",
  "files": ["enum_union.c", "enum_union.h"],
  "tests": {
    "enum": "day_tests",
    "union": "variant_tests"
  }
}
```
