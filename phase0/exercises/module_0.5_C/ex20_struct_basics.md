# Exercice 0.5.20-a : struct_basics

**Module :**
0.5.20 — Structures en C

**Concept :**
a-e — struct definition, member access (.), pointer access (->), typedef, initialization

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
0.5.16 (pointeurs)

**Domaines :**
Algo, CPU

**Duree estimee :**
150 min

**XP Base :**
200

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `struct_basics.c`
- `struct_basics.h`

### 1.2 Consigne

Implementer des fonctions manipulant des structures.

**Ta mission :**

```c
// Structure Point 2D
typedef struct s_point {
    int x;
    int y;
} t_point;

// Structure Rectangle
typedef struct s_rect {
    t_point origin;
    int width;
    int height;
} t_rect;

// Creer un point
t_point make_point(int x, int y);

// Distance au carre entre deux points
int distance_squared(t_point p1, t_point p2);

// Calculer l'aire d'un rectangle
int rect_area(t_rect rect);

// Deplacer un point (modifier via pointeur)
void move_point(t_point *p, int dx, int dy);

// Verifier si un point est dans un rectangle
int point_in_rect(t_point p, t_rect rect);

// Comparer deux points
int points_equal(t_point p1, t_point p2);
```

**Comportement:**

1. `make_point(3, 4)` -> {x: 3, y: 4}
2. `distance_squared({0,0}, {3,4})` -> 25
3. `rect_area({{0,0}, 10, 5})` -> 50
4. `move_point(&p, 2, 3)` -> p.x += 2, p.y += 3
5. `point_in_rect({5,5}, {{0,0}, 10, 10})` -> 1
6. `points_equal({1,2}, {1,2})` -> 1

**Exemples:**
```
t_point p = make_point(0, 0);
// p.x == 0, p.y == 0

move_point(&p, 5, 3);
// p.x == 5, p.y == 3

distance_squared(make_point(0,0), make_point(3,4)) -> 25
// (3-0)^2 + (4-0)^2 = 9 + 16 = 25

t_rect r = {{0, 0}, 10, 10};
rect_area(r) -> 100
point_in_rect(make_point(5, 5), r) -> 1
point_in_rect(make_point(15, 5), r) -> 0
```

### 1.3 Prototype

```c
// struct_basics.h
#ifndef STRUCT_BASICS_H
#define STRUCT_BASICS_H

typedef struct s_point {
    int x;
    int y;
} t_point;

typedef struct s_rect {
    t_point origin;
    int width;
    int height;
} t_rect;

t_point make_point(int x, int y);
int distance_squared(t_point p1, t_point p2);
int rect_area(t_rect rect);
void move_point(t_point *p, int dx, int dy);
int point_in_rect(t_point p, t_rect rect);
int points_equal(t_point p1, t_point p2);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | make_point(3, 4) | {3, 4} | 15 |
| T02 | distance_squared | 25 | 20 |
| T03 | rect_area | 50 | 15 |
| T04 | move_point | correct | 15 |
| T05 | point_in_rect (in) | 1 | 15 |
| T06 | point_in_rect (out) | 0 | 10 |
| T07 | points_equal | correct | 10 |

### 4.3 Solution de reference

```c
#include "struct_basics.h"

t_point make_point(int x, int y)
{
    t_point p;
    p.x = x;
    p.y = y;
    return p;
}

int distance_squared(t_point p1, t_point p2)
{
    int dx = p2.x - p1.x;
    int dy = p2.y - p1.y;
    return dx * dx + dy * dy;
}

int rect_area(t_rect rect)
{
    return rect.width * rect.height;
}

void move_point(t_point *p, int dx, int dy)
{
    if (p == NULL)
        return;
    p->x += dx;
    p->y += dy;
}

int point_in_rect(t_point p, t_rect rect)
{
    if (p.x < rect.origin.x)
        return 0;
    if (p.y < rect.origin.y)
        return 0;
    if (p.x >= rect.origin.x + rect.width)
        return 0;
    if (p.y >= rect.origin.y + rect.height)
        return 0;
    return 1;
}

int points_equal(t_point p1, t_point p2)
{
    return (p1.x == p2.x && p1.y == p2.y);
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: make_point n'initialise pas correctement
t_point make_point(int x, int y)
{
    t_point p;
    p.x = y;  // Inverse x et y
    p.y = x;
    return p;
}

// MUTANT 2: distance_squared oublie de mettre au carre
int distance_squared(t_point p1, t_point p2)
{
    int dx = p2.x - p1.x;
    int dy = p2.y - p1.y;
    return dx + dy;  // Manque les carres
}

// MUTANT 3: move_point utilise . au lieu de ->
void move_point(t_point *p, int dx, int dy)
{
    (*p).x += dx;  // Fonctionne mais moins idiomatique
    p->y += dy;
}

// MUTANT 4: point_in_rect mauvaises bornes
int point_in_rect(t_point p, t_rect rect)
{
    return (p.x >= rect.origin.x &&
            p.y >= rect.origin.y &&
            p.x < rect.width &&      // Oublie origin.x
            p.y < rect.height);      // Oublie origin.y
}

// MUTANT 5: rect_area additionne au lieu de multiplier
int rect_area(t_rect rect)
{
    return rect.width + rect.height;  // + au lieu de *
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **structures** en C:

1. **struct** - Type compose de plusieurs champs
2. **Acces direct (.)** - `point.x` pour acceder a un membre
3. **Acces indirect (->)** - `ptr->x` equivalent a `(*ptr).x`
4. **typedef** - Creer un alias pour le type struct
5. **Structures imbriquees** - Struct dans struct

### 5.3 Visualisation ASCII

```
t_point p = {3, 4};

Memoire:
+-------+-------+
|   x   |   y   |
|   3   |   4   |
+-------+-------+
    ^
    &p

Acces:
p.x      -> 3 (acces direct)
(&p)->x  -> 3 (acces via pointeur)

t_rect r = {{0, 0}, 10, 5};

Memoire:
+---------------+-------+--------+
|    origin     | width | height |
| +-----+-----+ |       |        |
| |  x  |  y  | |       |        |
| |  0  |  0  | |  10   |   5    |
| +-----+-----+ |       |        |
+---------------+-------+--------+

Acces:
r.origin.x   -> 0
r.width      -> 10
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la difference entre . et -> ?

A) Aucune
B) . pour valeur, -> pour pointeur
C) . pour pointeur, -> pour valeur
D) -> est deprecated
E) . est plus rapide

**Reponse correcte: B**

### Question 2
Que fait `typedef struct s_point t_point` ?

A) Cree une copie de la structure
B) Cree un alias pour `struct s_point`
C) Alloue de la memoire
D) Declare une variable
E) Rien

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.5.20-a",
  "name": "struct_basics",
  "language": "c",
  "language_version": "c17",
  "files": ["struct_basics.c", "struct_basics.h"],
  "tests": {
    "point": "point_tests",
    "rect": "rect_tests",
    "nested": "nested_struct_tests"
  }
}
```
