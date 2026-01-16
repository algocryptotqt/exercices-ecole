# Exercice 0.7.8 : structs

**Module :**
0.7 — Introduction a Rust

**Concept :**
i — Structures : definition, impl, et methodes

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.7 (strings)
- Comprehension des types

**Domaines :**
Structs, OOP

**Duree estimee :**
50 min

**XP Base :**
95

**Complexite :**
T0 O(1) × S0 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Rust | `src/lib.rs` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Rust | Toutes les fonctions de la bibliotheque standard |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Rust | `unsafe` |

---

### 1.2 Consigne

#### Section Culture : "Struct Your Stuff"

Les structures en Rust permettent de regrouper des donnees liees. Contrairement aux classes dans d'autres langages, les struct Rust n'ont pas d'heritage. On utilise des traits pour le polymorphisme.

Le bloc `impl` permet d'ajouter des methodes a une structure. La premiere methode qui prend `&self` ou `&mut self` est une methode d'instance.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des structures avec methodes :

1. `Point` : structure avec coordonnees x, y et methodes
2. `Rectangle` : structure avec position et dimensions
3. Implementer des fonctions associees (constructeurs) et des methodes

**Entree :**

```rust
// src/lib.rs

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    /// Cree un nouveau point.
    pub fn new(x: f64, y: f64) -> Self {
        // A implementer
    }

    /// Point a l'origine (0, 0).
    pub fn origin() -> Self {
        // A implementer
    }

    /// Distance depuis l'origine.
    pub fn distance_from_origin(&self) -> f64 {
        // A implementer
    }

    /// Distance vers un autre point.
    pub fn distance_to(&self, other: &Point) -> f64 {
        // A implementer
    }

    /// Deplace le point (mutable).
    pub fn translate(&mut self, dx: f64, dy: f64) {
        // A implementer
    }

    /// Retourne un nouveau point translate.
    pub fn translated(&self, dx: f64, dy: f64) -> Self {
        // A implementer
    }
}

#[derive(Debug, Clone)]
pub struct Rectangle {
    pub origin: Point,
    pub width: f64,
    pub height: f64,
}

impl Rectangle {
    /// Cree un nouveau rectangle.
    pub fn new(origin: Point, width: f64, height: f64) -> Self {
        // A implementer
    }

    /// Calcule l'aire.
    pub fn area(&self) -> f64 {
        // A implementer
    }

    /// Calcule le perimetre.
    pub fn perimeter(&self) -> f64 {
        // A implementer
    }

    /// Verifie si un point est dans le rectangle.
    pub fn contains(&self, point: &Point) -> bool {
        // A implementer
    }
}
```

**Sortie attendue :**

```
$ cargo test
running 8 tests
test tests::test_point_new ... ok
test tests::test_point_distance ... ok
test tests::test_point_translate ... ok
test tests::test_rect_area ... ok
test tests::test_rect_contains ... ok
...
test result: ok. 8 passed; 0 failed
```

**Contraintes :**
- Utiliser `Self` pour le type de retour des constructeurs
- `&self` pour les methodes en lecture
- `&mut self` pour les methodes qui modifient

**Exemples :**

| Methode | Input | Output |
|---------|-------|--------|
| `Point::new(3.0, 4.0).distance_from_origin()` | - | `5.0` |
| `Rectangle::new(Point::origin(), 10.0, 5.0).area()` | - | `50.0` |

---

### 1.3 Prototype

```rust
impl Point {
    pub fn new(x: f64, y: f64) -> Self;
    pub fn origin() -> Self;
    pub fn distance_from_origin(&self) -> f64;
    pub fn distance_to(&self, other: &Point) -> f64;
    pub fn translate(&mut self, dx: f64, dy: f64);
    pub fn translated(&self, dx: f64, dy: f64) -> Self;
}

impl Rectangle {
    pub fn new(origin: Point, width: f64, height: f64) -> Self;
    pub fn area(&self) -> f64;
    pub fn perimeter(&self) -> f64;
    pub fn contains(&self, point: &Point) -> bool;
}
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Self vs self :**

- `Self` (majuscule) = le type de la structure
- `self` (minuscule) = l'instance de la structure

**Methode vs Fonction associee :**

- Methode : prend `self`, `&self`, ou `&mut self` en premier parametre
- Fonction associee : pas de `self`, appele avec `Type::fonction()`

**derive :**

```rust
#[derive(Debug, Clone, Copy, PartialEq)]
```
Genere automatiquement des implementations de traits.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Game Dev** | Entites, composants, vecteurs |
| **Web Dev** | DTOs, modeles de donnees |
| **Systems** | Configurations, etats |
| **Data** | Records, schemas |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo new structs --lib
     Created library `structs` package

$ cargo test
running 8 tests
test tests::test_point_new ... ok
test tests::test_point_distance ... ok
...
test result: ok. 8 passed; 0 failed
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | point_new | `(3.0, 4.0)` | Point | 10 | Basic |
| 2 | point_origin | - | `(0.0, 0.0)` | 5 | Basic |
| 3 | distance_origin | `(3.0, 4.0)` | `5.0` | 15 | Math |
| 4 | distance_to | deux points | correct | 15 | Math |
| 5 | translate | mutation | correct | 10 | Mutation |
| 6 | translated | nouveau point | correct | 10 | Immutable |
| 7 | rect_area | `10x5` | `50.0` | 15 | Math |
| 8 | rect_contains | point inside | `true` | 20 | Logic |

**Total : 100 points**

---

### 4.3 Solution de reference (Rust)

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
    pub origin: Point,
    pub width: f64,
    pub height: f64,
}

impl Rectangle {
    pub fn new(origin: Point, width: f64, height: f64) -> Self {
        Self {
            origin,
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
        point.x >= self.origin.x
            && point.x <= self.origin.x + self.width
            && point.y >= self.origin.y
            && point.y <= self.origin.y + self.height
    }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Math) : distance sans sqrt**

```rust
/* Mutant A (Math) : Oubli du sqrt */
pub fn distance_from_origin(&self) -> f64 {
    self.x * self.x + self.y * self.y  // Manque .sqrt()
}
// Pourquoi faux : Retourne le carre de la distance
```

**Mutant B (Logic) : translate ne modifie pas**

```rust
/* Mutant B (Logic) : Pas de mutation */
pub fn translate(&mut self, dx: f64, dy: f64) {
    let _ = Point::new(self.x + dx, self.y + dy);
    // Ne modifie pas self!
}
// Pourquoi faux : self n'est pas modifie
```

**Mutant C (Math) : perimeter incorrecte**

```rust
/* Mutant C (Math) : Formule incorrecte */
pub fn perimeter(&self) -> f64 {
    self.width + self.height  // Manque * 2
}
// Pourquoi faux : Demi-perimetre seulement
```

**Mutant D (Logic) : contains stricte**

```rust
/* Mutant D (Logic) : Bornes strictes */
pub fn contains(&self, point: &Point) -> bool {
    point.x > self.origin.x  // > au lieu de >=
        && point.x < self.origin.x + self.width
        && point.y > self.origin.y
        && point.y < self.origin.y + self.height
}
// Pourquoi faux : Exclut les points sur les bords
```

**Mutant E (Type) : Retourne Point au lieu de Self**

```rust
/* Mutant E (Type) : Hardcode le type */
pub fn new(x: f64, y: f64) -> Point {
    Point { x, y }
}
// Pourquoi faux : Moins flexible, devrait utiliser Self
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| struct | Definition de type composite | Critique |
| impl | Bloc d'implementation | Critique |
| &self | Methode en lecture | Critique |
| &mut self | Methode en ecriture | Critique |
| Self | Alias pour le type courant | Important |

---

### 5.3 Visualisation ASCII

**Structure en memoire :**

```
Point { x: 3.0, y: 4.0 }

Stack:
+--------+--------+
|   x    |   y    |
|  3.0   |  4.0   |
+--------+--------+
  8 bytes  8 bytes = 16 bytes total


Rectangle avec Point:
+--------+--------+--------+--------+
| origin.x | origin.y | width | height |
|   0.0    |   0.0    | 10.0  |  5.0   |
+--------+--------+--------+--------+
```

**Methodes vs Fonctions associees :**

```
Point::new(3.0, 4.0)      // Fonction associee (pas de self)
        |                  // Appel avec ::
        v
fn new(x: f64, y: f64) -> Self

point.distance_to(&other)  // Methode (prend &self)
      |                    // Appel avec .
      v
fn distance_to(&self, other: &Point) -> f64
```

**Types de self :**

```
&self     -> emprunt immutable (lecture seule)
&mut self -> emprunt mutable (modification possible)
self      -> ownership (consomme la structure)
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Oublier pub sur les champs

```rust
pub struct Point {
    x: f64,  // PRIVE! Non accessible hors du module
    y: f64,
}

// Solution
pub struct Point {
    pub x: f64,  // Public
    pub y: f64,
}
```

#### Piege 2 : Confondre Self et self

```rust
impl Point {
    // Self = le type Point
    pub fn new(x: f64, y: f64) -> Self { ... }

    // self = l'instance
    pub fn method(&self) { ... }
}
```

---

### 5.5 Cours Complet

#### 5.5.1 Definition de struct

```rust
// Struct classique
struct Point {
    x: f64,
    y: f64,
}

// Tuple struct
struct Color(u8, u8, u8);

// Unit struct
struct Marker;
```

#### 5.5.2 Bloc impl

```rust
impl Point {
    // Fonction associee (constructeur)
    pub fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }

    // Methode immutable
    pub fn length(&self) -> f64 {
        (self.x * self.x + self.y * self.y).sqrt()
    }

    // Methode mutable
    pub fn scale(&mut self, factor: f64) {
        self.x *= factor;
        self.y *= factor;
    }

    // Methode qui consomme self
    pub fn into_tuple(self) -> (f64, f64) {
        (self.x, self.y)
    }
}
```

#### 5.5.3 derive

```rust
#[derive(Debug)]        // {:?} formatting
#[derive(Clone)]        // .clone()
#[derive(Copy)]         // copie implicite
#[derive(PartialEq)]    // == et !=
#[derive(Default)]      // Point::default()
```

---

### 5.8 Mnemotechniques

**IMPL = Instance Methods Plus Library functions**

Le bloc impl contient les methodes d'instance et les fonctions de la bibliotheque (constructeurs).

**Self = Same type as the implementing struct**

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Champs prives | Inaccessibles | Ajouter `pub` |
| 2 | Self vs self | Confusion type/instance | Self = type |
| 3 | &self vs &mut self | Mutation interdite | Utiliser &mut self |
| 4 | Oubli de .sqrt() | Distance incorrecte | Formule Pythagore |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quelle est la difference entre une methode et une fonction associee ?

- A) Les methodes sont plus rapides
- B) Les methodes prennent self, les fonctions associees non
- C) Les fonctions associees sont privees
- D) Pas de difference

**Reponse : B** — Les methodes ont self, &self, ou &mut self.

---

### Question 2 (4 points)
Que signifie `&mut self` ?

- A) self est copie
- B) self est emprunte en lecture
- C) self est emprunte en ecriture
- D) self est detruit

**Reponse : C** — &mut self permet de modifier la structure.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.8 |
| **Nom** | structs |
| **Difficulte** | 4/10 |
| **Duree** | 50 min |
| **XP Base** | 95 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | struct, impl, &self, &mut self, methods |
| **Prerequis** | strings |
| **Domaines** | Structs, OOP |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.8-structs",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.8",
      "exercise_name": "structs",
      "module": "0.7",
      "concept": "i",
      "concept_name": "Structures",
      "type": "code",
      "tier": 1,
      "difficulty": 4,
      "prerequisites": ["0.7.7"],
      "domains": ["Structs", "OOP"],
      "tags": ["struct", "impl", "methods", "self"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
