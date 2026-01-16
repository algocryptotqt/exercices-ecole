# Exercice 0.7.8-a : structs

**Module :**
0.7.8 — Structures

**Concept :**
a-e — struct definition, impl, methods, associated functions, derive

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
0.7.7 (strings)

**Domaines :**
Algo, Structures

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
- `src/lib.rs`

### 1.2 Consigne

Implementer des structures avec methodes et fonctions associees.

**Ta mission :**

```rust
// Structure Point 2D
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    // Constructeur (fonction associee)
    pub fn new(x: f64, y: f64) -> Self;

    // Point a l'origine
    pub fn origin() -> Self;

    // Distance depuis l'origine
    pub fn distance_from_origin(&self) -> f64;

    // Distance vers un autre point
    pub fn distance_to(&self, other: &Point) -> f64;

    // Deplacer le point
    pub fn translate(&mut self, dx: f64, dy: f64);

    // Creer un point translate (immutable)
    pub fn translated(&self, dx: f64, dy: f64) -> Self;
}

// Structure Rectangle
#[derive(Debug, Clone)]
pub struct Rectangle {
    pub top_left: Point,
    pub width: f64,
    pub height: f64,
}

impl Rectangle {
    pub fn new(top_left: Point, width: f64, height: f64) -> Self;
    pub fn area(&self) -> f64;
    pub fn perimeter(&self) -> f64;
    pub fn contains(&self, point: &Point) -> bool;
    pub fn center(&self) -> Point;
}
```

**Comportement:**

1. `Point::new(3.0, 4.0).distance_from_origin()` -> 5.0
2. `Rectangle::new(Point::origin(), 10.0, 5.0).area()` -> 50.0
3. `rect.contains(&Point::new(5.0, 2.0))` -> true (si dans le rectangle)

**Exemples:**
```rust
let mut p = Point::new(3.0, 4.0);
println!("{:?}", p);  // Point { x: 3.0, y: 4.0 }
println!("{}", p.distance_from_origin());  // 5.0

p.translate(1.0, 1.0);
println!("{:?}", p);  // Point { x: 4.0, y: 5.0 }

let rect = Rectangle::new(Point::origin(), 10.0, 5.0);
println!("Area: {}", rect.area());  // 50.0
println!("Contains origin: {}", rect.contains(&Point::origin()));  // true
```

### 1.3 Prototype

```rust
// src/lib.rs

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    pub fn new(x: f64, y: f64) -> Self {
        todo!()
    }

    pub fn origin() -> Self {
        todo!()
    }

    pub fn distance_from_origin(&self) -> f64 {
        todo!()
    }

    pub fn distance_to(&self, other: &Point) -> f64 {
        todo!()
    }

    pub fn translate(&mut self, dx: f64, dy: f64) {
        todo!()
    }

    pub fn translated(&self, dx: f64, dy: f64) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct Rectangle {
    pub top_left: Point,
    pub width: f64,
    pub height: f64,
}

impl Rectangle {
    pub fn new(top_left: Point, width: f64, height: f64) -> Self {
        todo!()
    }

    pub fn area(&self) -> f64 {
        todo!()
    }

    pub fn perimeter(&self) -> f64 {
        todo!()
    }

    pub fn contains(&self, point: &Point) -> bool {
        todo!()
    }

    pub fn center(&self) -> Point {
        todo!()
    }
}
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | Point::new | correct | 10 |
| T02 | distance_from_origin | 5.0 for (3,4) | 15 |
| T03 | distance_to | correct | 10 |
| T04 | translate | mutated | 10 |
| T05 | translated | new point | 10 |
| T06 | Rectangle::area | correct | 15 |
| T07 | Rectangle::contains | correct | 15 |
| T08 | Rectangle::center | correct | 15 |

### 4.3 Solution de reference

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }

    pub fn origin() -> Self {
        Self { x: 0.0, y: 0.0 }
    }

    pub fn distance_from_origin(&self) -> f64 {
        (self.x * self.x + self.y * self.y).sqrt()
    }

    pub fn distance_to(&self, other: &Point) -> f64 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        (dx * dx + dy * dy).sqrt()
    }

    pub fn translate(&mut self, dx: f64, dy: f64) {
        self.x += dx;
        self.y += dy;
    }

    pub fn translated(&self, dx: f64, dy: f64) -> Self {
        Self {
            x: self.x + dx,
            y: self.y + dy,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rectangle {
    pub top_left: Point,
    pub width: f64,
    pub height: f64,
}

impl Rectangle {
    pub fn new(top_left: Point, width: f64, height: f64) -> Self {
        Self {
            top_left,
            width: width.abs(),
            height: height.abs(),
        }
    }

    pub fn area(&self) -> f64 {
        self.width * self.height
    }

    pub fn perimeter(&self) -> f64 {
        2.0 * (self.width + self.height)
    }

    pub fn contains(&self, point: &Point) -> bool {
        point.x >= self.top_left.x
            && point.x <= self.top_left.x + self.width
            && point.y >= self.top_left.y
            && point.y <= self.top_left.y + self.height
    }

    pub fn center(&self) -> Point {
        Point::new(
            self.top_left.x + self.width / 2.0,
            self.top_left.y + self.height / 2.0,
        )
    }
}
```

### 4.10 Solutions Mutantes

```rust
// MUTANT 1: distance_from_origin sans sqrt
impl Point {
    pub fn distance_from_origin(&self) -> f64 {
        self.x * self.x + self.y * self.y  // Manque .sqrt()
    }
}

// MUTANT 2: translate retourne au lieu de muter
impl Point {
    pub fn translate(&mut self, dx: f64, dy: f64) {
        // Ne modifie pas self, retourne nouveau (signature incorrecte)
        let _ = Point::new(self.x + dx, self.y + dy);
    }
}

// MUTANT 3: contains avec bornes strictes
impl Rectangle {
    pub fn contains(&self, point: &Point) -> bool {
        point.x > self.top_left.x  // > au lieu de >=
            && point.x < self.top_left.x + self.width
            && point.y > self.top_left.y
            && point.y < self.top_left.y + self.height
    }
}

// MUTANT 4: perimeter formule incorrecte
impl Rectangle {
    pub fn perimeter(&self) -> f64 {
        self.width + self.height  // Manque le * 2
    }
}

// MUTANT 5: center oublie top_left offset
impl Rectangle {
    pub fn center(&self) -> Point {
        Point::new(self.width / 2.0, self.height / 2.0)
        // Oublie d'ajouter top_left
    }
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **structures** en Rust:

1. **struct** - Definir un type de donnees composite
2. **impl** - Ajouter des methodes et fonctions associees
3. **&self** - Methode qui emprunte la structure
4. **&mut self** - Methode qui modifie la structure
5. **derive** - Generation automatique de traits

### 5.3 Visualisation ASCII

```
STRUCTURE MEMOIRE:

Point { x: 3.0, y: 4.0 }

Stack:
+--------+--------+
|   x    |   y    |
| 3.0    | 4.0    |
+--------+--------+
  8 bytes  8 bytes = 16 bytes total

Rectangle:
+--------+--------+--------+--------+
| top_left.x | top_left.y | width | height |
|    0.0     |    0.0     | 10.0  |  5.0   |
+--------+--------+--------+--------+

METHODES VS FONCTIONS ASSOCIEES:

Point::new(3.0, 4.0)      // Fonction associee (pas de self)
        |                  // Appel avec ::
        v
fn new(x: f64, y: f64) -> Self

point.distance_to(&other)  // Methode (prend &self)
      |                    // Appel avec .
      v
fn distance_to(&self, other: &Point) -> f64

SELF VARIANTS:
&self     -> emprunt immutable (lecture)
&mut self -> emprunt mutable (modification)
self      -> ownership (consomme la structure)
```

### 5.5 Derive Macros

```rust
#[derive(Debug)]        // Permet {:?} formatting
#[derive(Clone)]        // Permet .clone()
#[derive(Copy)]         // Copie implicite (types simples)
#[derive(PartialEq)]    // Permet == et !=
#[derive(Eq)]           // Egalite complete
#[derive(Hash)]         // Permet d'utiliser dans HashMap
#[derive(Default)]      // Valeur par defaut

// Peut combiner plusieurs
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point { ... }
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la difference entre `fn new()` et `fn area(&self)` ?

A) new est public, area est prive
B) new est une fonction associee, area est une methode
C) new retourne Self, area retourne f64
D) Pas de difference
E) new est statique, area est dynamique

**Reponse correcte: B**

### Question 2
Que signifie `&mut self` dans une methode ?

A) self est copie
B) self est detruit
C) self est emprunte en lecture
D) self est emprunte en ecriture
E) self est optionnel

**Reponse correcte: D**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.7.8-a",
  "name": "structs",
  "language": "rust",
  "language_version": "edition2024",
  "files": ["src/lib.rs"],
  "tests": {
    "point": "point_tests",
    "rectangle": "rectangle_tests",
    "methods": "method_tests"
  }
}
```
