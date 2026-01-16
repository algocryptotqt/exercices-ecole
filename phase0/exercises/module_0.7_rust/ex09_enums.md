# Exercice 0.7.9 : enums

**Module :**
0.7 — Introduction a Rust

**Concept :**
j — Enumerations : variants et pattern matching

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.8 (structs)
- Comprehension des types

**Domaines :**
Enums, Pattern Matching

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

#### Section Culture : "To Be or Not To Be... or Something Else"

Les enums en Rust sont beaucoup plus puissantes que dans d'autres langages. Chaque variant peut contenir des donnees differentes, et le pattern matching garantit que tous les cas sont traites.

Les enums Option<T> et Result<T, E> sont au coeur de la gestion des erreurs en Rust.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des enumerations avec pattern matching :

1. `Direction` : enum simple avec methodes
2. `Shape` : enum avec donnees associees
3. Utiliser match pour traiter tous les variants

**Entree :**

```rust
// src/lib.rs
use std::f64::consts::PI;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Direction {
    North,
    South,
    East,
    West,
}

impl Direction {
    /// Retourne la direction opposee.
    pub fn opposite(&self) -> Direction {
        // A implementer
    }

    /// Tourne a droite.
    pub fn turn_right(&self) -> Direction {
        // A implementer
    }

    /// Tourne a gauche.
    pub fn turn_left(&self) -> Direction {
        // A implementer
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Shape {
    Circle { radius: f64 },
    Rectangle { width: f64, height: f64 },
    Triangle { base: f64, height: f64 },
}

impl Shape {
    /// Calcule l'aire de la forme.
    pub fn area(&self) -> f64 {
        // A implementer
    }

    /// Calcule le perimetre de la forme.
    pub fn perimeter(&self) -> f64 {
        // A implementer
    }

    /// Scale la forme par un facteur.
    pub fn scale(&self, factor: f64) -> Shape {
        // A implementer
    }
}
```

**Sortie attendue :**

```
$ cargo test
running 6 tests
test tests::test_direction_opposite ... ok
test tests::test_direction_turn ... ok
test tests::test_shape_area ... ok
test tests::test_shape_perimeter ... ok
test tests::test_shape_scale ... ok
...
test result: ok. 6 passed; 0 failed
```

**Contraintes :**
- Utiliser `match` pour traiter tous les variants
- Le match doit etre exhaustif (tous les cas)
- Circle area = PI * r^2

**Exemples :**

| Methode | Input | Output |
|---------|-------|--------|
| `Direction::North.opposite()` | - | `Direction::South` |
| `Shape::Circle { radius: 5.0 }.area()` | - | `~78.54` |

---

### 1.3 Prototype

```rust
impl Direction {
    pub fn opposite(&self) -> Direction;
    pub fn turn_right(&self) -> Direction;
    pub fn turn_left(&self) -> Direction;
}

impl Shape {
    pub fn area(&self) -> f64;
    pub fn perimeter(&self) -> f64;
    pub fn scale(&self, factor: f64) -> Shape;
}
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Enum vs enum C :**

En C, les enums sont juste des entiers. En Rust, chaque variant peut avoir des types differents.

**Pattern matching exhaustif :**

Le compilateur Rust verifie que tous les cas sont traites. Si tu oublies un variant, erreur de compilation.

**Sum types :**

Les enums Rust sont des "sum types" ou "tagged unions" - ils peuvent etre l'un OU l'autre des variants.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Game Dev** | Etats du jeu, input events |
| **Web Dev** | Reponses HTTP, messages |
| **Systems** | Etats de machine, protocoles |
| **Parsers** | Tokens, AST nodes |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo new enums --lib
     Created library `enums` package

$ cargo test
running 6 tests
test tests::test_direction ... ok
test tests::test_shape ... ok
...
test result: ok. 6 passed; 0 failed
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | opposite | `North` | `South` | 15 | Basic |
| 2 | turn_right | `North` | `East` | 10 | Basic |
| 3 | turn_left | `North` | `West` | 10 | Basic |
| 4 | circle_area | `r=5.0` | `~78.54` | 15 | Math |
| 5 | rect_area | `10x5` | `50.0` | 15 | Math |
| 6 | scale | `factor=2.0` | scaled | 20 | Logic |
| 7 | perimeter | all shapes | correct | 15 | Math |

**Total : 100 points**

---

### 4.3 Solution de reference (Rust)

```rust
use std::f64::consts::PI;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Direction {
    North,
    South,
    East,
    West,
}

impl Direction {
    pub fn opposite(&self) -> Direction {
        match self {
            Direction::North => Direction::South,
            Direction::South => Direction::North,
            Direction::East => Direction::West,
            Direction::West => Direction::East,
        }
    }

    pub fn turn_right(&self) -> Direction {
        match self {
            Direction::North => Direction::East,
            Direction::East => Direction::South,
            Direction::South => Direction::West,
            Direction::West => Direction::North,
        }
    }

    pub fn turn_left(&self) -> Direction {
        match self {
            Direction::North => Direction::West,
            Direction::West => Direction::South,
            Direction::South => Direction::East,
            Direction::East => Direction::North,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Shape {
    Circle { radius: f64 },
    Rectangle { width: f64, height: f64 },
    Triangle { base: f64, height: f64 },
}

impl Shape {
    pub fn area(&self) -> f64 {
        match self {
            Shape::Circle { radius } => PI * radius * radius,
            Shape::Rectangle { width, height } => width * height,
            Shape::Triangle { base, height } => 0.5 * base * height,
        }
    }

    pub fn perimeter(&self) -> f64 {
        match self {
            Shape::Circle { radius } => 2.0 * PI * radius,
            Shape::Rectangle { width, height } => 2.0 * (width + height),
            Shape::Triangle { base, height } => {
                let hypotenuse = (base * base + height * height).sqrt();
                base + height + hypotenuse
            }
        }
    }

    pub fn scale(&self, factor: f64) -> Shape {
        match self {
            Shape::Circle { radius } => Shape::Circle {
                radius: radius * factor,
            },
            Shape::Rectangle { width, height } => Shape::Rectangle {
                width: width * factor,
                height: height * factor,
            },
            Shape::Triangle { base, height } => Shape::Triangle {
                base: base * factor,
                height: height * factor,
            },
        }
    }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Logic) : opposite retourne self**

```rust
/* Mutant A (Logic) : Pas d'inversion */
pub fn opposite(&self) -> Direction {
    *self  // Retourne la meme direction!
}
// Pourquoi faux : North.opposite() devrait etre South
```

**Mutant B (Logic) : turn_right est turn_left**

```rust
/* Mutant B (Logic) : Sens inverse */
pub fn turn_right(&self) -> Direction {
    match self {
        Direction::North => Direction::West,  // West au lieu de East!
        // ...
    }
}
// Pourquoi faux : Tourne a gauche au lieu de droite
```

**Mutant C (Math) : Circle area sans PI**

```rust
/* Mutant C (Math) : Oubli de PI */
pub fn area(&self) -> f64 {
    match self {
        Shape::Circle { radius } => radius * radius,  // Manque PI
        // ...
    }
}
// Pourquoi faux : Formule incorrecte
```

**Mutant D (Logic) : scale ne scale qu'une dimension**

```rust
/* Mutant D (Logic) : Scale partiel */
pub fn scale(&self, factor: f64) -> Shape {
    match self {
        Shape::Rectangle { width, height } => Shape::Rectangle {
            width: width * factor,
            height: *height,  // Oublie de scaler height!
        },
        // ...
    }
}
// Pourquoi faux : Scale non uniforme
```

**Mutant E (Coverage) : Match non exhaustif**

```rust
/* Mutant E (Coverage) : Oubli d'un variant */
pub fn area(&self) -> f64 {
    match self {
        Shape::Circle { radius } => PI * radius * radius,
        Shape::Rectangle { width, height } => width * height,
        // Oublie Triangle!
    }
}
// Pourquoi faux : Erreur de compilation (non exhaustif)
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| enum | Type avec variants | Critique |
| match | Pattern matching | Critique |
| Variants avec data | Circle { radius } | Important |
| Exhaustivite | Tous les cas | Critique |

---

### 5.3 Visualisation ASCII

**Enum simple vs avec donnees :**

```
Direction (simple):
+-----+
| tag |  (1 byte si < 256 variants)
+-----+
  0 = North
  1 = South
  2 = East
  3 = West

Shape (avec donnees):
+-----+--------+--------+
| tag |  data  | padding|
+-----+--------+--------+

Shape::Circle { radius: 5.0 }:
+-----+--------+--------+
|  0  |  5.0   |  ...   |
+-----+--------+--------+

Shape::Rectangle { width: 10.0, height: 5.0 }:
+-----+--------+--------+
|  1  | 10.0   |  5.0   |
+-----+--------+--------+

Taille = max(Circle, Rectangle, Triangle) + tag
```

**Pattern matching :**

```rust
match shape {
    Shape::Circle { radius } => {
        //       ^^^^^^^
        //       extrait radius de la structure
    },
    Shape::Rectangle { width, height } => {
        // width et height disponibles ici
    },
    Shape::Triangle { .. } => {
        // .. ignore les champs
    },
}
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Match non exhaustif

```rust
// ERREUR: non-exhaustive patterns
match direction {
    Direction::North => {},
    Direction::South => {},
    // Oublie East et West!
}
```

#### Piege 2 : Oublier de destructurer

```rust
// ERREUR: shape.radius n'existe pas
fn area(shape: &Shape) -> f64 {
    shape.radius * shape.radius  // Won't compile!
}

// Solution: match et destructure
fn area(shape: &Shape) -> f64 {
    match shape {
        Shape::Circle { radius } => radius * radius * PI,
        // ...
    }
}
```

---

### 5.5 Cours Complet

#### 5.5.1 Definition d'enum

```rust
// Enum simple (comme C)
enum Direction {
    North,
    South,
    East,
    West,
}

// Enum avec donnees
enum Shape {
    Circle { radius: f64 },
    Rectangle { width: f64, height: f64 },
    Point,  // Unit variant
}

// Enum tuple-like
enum Message {
    Quit,
    Move(i32, i32),
    Text(String),
}
```

#### 5.5.2 Pattern matching

```rust
// Match exhaustif
match direction {
    Direction::North => println!("Going north"),
    Direction::South => println!("Going south"),
    Direction::East => println!("Going east"),
    Direction::West => println!("Going west"),
}

// Avec wildcard
match number {
    1 => println!("One"),
    2 => println!("Two"),
    _ => println!("Other"),  // Catch-all
}

// if let (raccourci)
if let Direction::North = direction {
    println!("Heading north!");
}
```

---

### 5.8 Mnemotechniques

**ENUM = Every Number Under Match**

Chaque enum a un numero (tag) et doit etre traite par match.

**match = Must Address Total Cases Holistically**

Match doit traiter TOUS les cas de maniere exhaustive.

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Match non exhaustif | Erreur compilation | Ajouter tous les variants |
| 2 | Acceder aux champs | Impossible sans match | Destructurer |
| 3 | Oublier PI | Aire incorrecte | Formules mathematiques |
| 4 | opposite() = self | Pas d'inversion | Bien mapper les opposites |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Que se passe-t-il si on oublie un variant dans match ?

- A) Warning seulement
- B) Erreur de compilation
- C) Panic au runtime
- D) Comportement indefini

**Reponse : B** — Le match doit etre exhaustif.

---

### Question 2 (4 points)
Quelle est la difference entre enum Rust et enum C ?

- A) Pas de difference
- B) Rust enum peut contenir des donnees par variant
- C) C enum est plus rapide
- D) Rust enum ne supporte pas le pattern matching

**Reponse : B** — Les variants Rust peuvent avoir des types differents.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.9 |
| **Nom** | enums |
| **Difficulte** | 4/10 |
| **Duree** | 50 min |
| **XP Base** | 95 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | enum, variants, match, pattern matching |
| **Prerequis** | structs |
| **Domaines** | Enums, Pattern Matching |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.9-enums",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.9",
      "exercise_name": "enums",
      "module": "0.7",
      "concept": "j",
      "concept_name": "Enumerations",
      "type": "code",
      "tier": 1,
      "difficulty": 4,
      "prerequisites": ["0.7.8"],
      "domains": ["Enums", "Pattern Matching"],
      "tags": ["enum", "variants", "match", "pattern-matching"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
