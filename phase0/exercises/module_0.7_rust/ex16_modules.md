# Exercice 0.7.16-a : modules

**Module :**
0.7.16 — Modules et Visibilite

**Concept :**
a-e — mod, pub, use, crate, super, self

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
0.7.8 (structs)

**Domaines :**
Architecture

**Duree estimee :**
150 min

**XP Base :**
220

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `src/lib.rs`
- `src/math/mod.rs`
- `src/math/geometry.rs`
- `src/math/arithmetic.rs`
- `src/utils/mod.rs`
- `src/utils/string_utils.rs`

### 1.2 Consigne

Organiser du code en modules avec visibilite appropriee.

**Ta mission :**

Structure du projet:
```
src/
  lib.rs           <- Module racine, re-exporte les modules publics
  math/
    mod.rs         <- Declare geometry et arithmetic
    geometry.rs    <- Point, Rectangle, fonctions geometriques
    arithmetic.rs  <- add, subtract, multiply, divide
  utils/
    mod.rs         <- Declare string_utils
    string_utils.rs <- capitalize, reverse
```

**Comportement:**

```rust
// Dans lib.rs, re-exporter pour acces facile
pub use math::geometry::Point;
pub use math::arithmetic::{add, subtract};

// Utilisateurs peuvent faire:
use mylib::Point;
use mylib::add;
// ou
use mylib::math::geometry::Rectangle;
```

**Exemples:**
```rust
// Depuis l'exterieur de la crate
use mylib::Point;
use mylib::math::arithmetic::multiply;

let p = Point::new(3.0, 4.0);
println!("Distance: {}", p.distance_from_origin());

println!("{}", multiply(3, 4));  // 12
```

### 1.3 Prototype

```rust
// src/lib.rs
pub mod math;
pub mod utils;

// Re-exports pour commodite
pub use math::geometry::Point;
pub use math::arithmetic::{add, subtract, multiply, divide};
pub use utils::string_utils::{capitalize, reverse};

// src/math/mod.rs
pub mod geometry;
pub mod arithmetic;

// src/math/geometry.rs
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    pub fn new(x: f64, y: f64) -> Self { todo!() }
    pub fn origin() -> Self { todo!() }
    pub fn distance_from_origin(&self) -> f64 { todo!() }
    pub fn distance_to(&self, other: &Point) -> f64 { todo!() }
}

#[derive(Debug, Clone)]
pub struct Rectangle {
    top_left: Point,  // Private par defaut
    width: f64,
    height: f64,
}

impl Rectangle {
    pub fn new(top_left: Point, width: f64, height: f64) -> Self { todo!() }
    pub fn area(&self) -> f64 { todo!() }
}

// src/math/arithmetic.rs
pub fn add(a: i32, b: i32) -> i32 { todo!() }
pub fn subtract(a: i32, b: i32) -> i32 { todo!() }
pub fn multiply(a: i32, b: i32) -> i32 { todo!() }
pub fn divide(a: i32, b: i32) -> Option<i32> { todo!() }

// Fonction interne (non publique)
fn validate_operands(a: i32, b: i32) -> bool { todo!() }

// src/utils/mod.rs
pub mod string_utils;

// src/utils/string_utils.rs
pub fn capitalize(s: &str) -> String { todo!() }
pub fn reverse(s: &str) -> String { todo!() }
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | Import Point | accessible | 10 |
| T02 | Import math::geometry | accessible | 10 |
| T03 | Re-export | works | 15 |
| T04 | Private field | not accessible | 15 |
| T05 | Public method | accessible | 15 |
| T06 | Private function | not accessible | 15 |
| T07 | Cross-module use | works | 20 |

### 4.3 Solution de reference

```rust
// src/lib.rs
pub mod math;
pub mod utils;

pub use math::geometry::Point;
pub use math::arithmetic::{add, subtract, multiply, divide};
pub use utils::string_utils::{capitalize, reverse};

// src/math/mod.rs
pub mod geometry;
pub mod arithmetic;

// src/math/geometry.rs
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
}

#[derive(Debug, Clone)]
pub struct Rectangle {
    top_left: Point,
    width: f64,
    height: f64,
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
}

// src/math/arithmetic.rs
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

pub fn subtract(a: i32, b: i32) -> i32 {
    a - b
}

pub fn multiply(a: i32, b: i32) -> i32 {
    a * b
}

pub fn divide(a: i32, b: i32) -> Option<i32> {
    if b == 0 {
        None
    } else {
        Some(a / b)
    }
}

fn validate_operands(_a: i32, _b: i32) -> bool {
    true  // Fonction privee, non accessible depuis l'exterieur
}

// src/utils/mod.rs
pub mod string_utils;

// src/utils/string_utils.rs
pub fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().chain(chars).collect(),
    }
}

pub fn reverse(s: &str) -> String {
    s.chars().rev().collect()
}
```

### 4.10 Solutions Mutantes

```rust
// MUTANT 1: Oublie pub sur module
mod math;  // Pas pub, non accessible depuis l'exterieur

// MUTANT 2: Oublie pub sur fonction
fn add(a: i32, b: i32) -> i32 {  // Pas pub, non accessible
    a + b
}

// MUTANT 3: Struct publique mais champs prives sans constructeur
pub struct Point {
    x: f64,  // Prive!
    y: f64,  // Prive!
}
// Impossible de creer Point depuis l'exterieur sans new()

// MUTANT 4: Re-export incorrect
pub use math::geometry;  // Exporte le module, pas le contenu
// Utilisateur doit faire: lib::geometry::Point au lieu de lib::Point

// MUTANT 5: Circular dependency
// Dans a.rs:
use crate::b::func_b;
// Dans b.rs:
use crate::a::func_a;
// Peut causer des problemes de compilation
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

**Modules** en Rust:

1. **Organisation** - Separer le code en fichiers logiques
2. **Encapsulation** - Cacher les details d'implementation
3. **Visibilite** - pub, pub(crate), pub(super), private
4. **Re-exports** - Simplifier l'API publique

### 5.3 Visualisation ASCII

```
STRUCTURE DES FICHIERS:

src/
  lib.rs          <- pub mod math; pub mod utils;
  math/
    mod.rs        <- pub mod geometry; pub mod arithmetic;
    geometry.rs   <- pub struct Point { pub x, pub y }
    arithmetic.rs <- pub fn add(), fn validate() (private)
  utils/
    mod.rs        <- pub mod string_utils;
    string_utils.rs

ARBRE DE VISIBILITE:

crate (lib.rs)
  |
  +-- math (pub)
  |     |
  |     +-- geometry (pub)
  |     |     +-- Point (pub)
  |     |     +-- Rectangle (pub, mais champs prives)
  |     |
  |     +-- arithmetic (pub)
  |           +-- add (pub)
  |           +-- validate (private) <- INVISIBLE
  |
  +-- utils (pub)
        |
        +-- string_utils (pub)
              +-- capitalize (pub)

CHEMINS D'ACCES:

crate::math::geometry::Point
crate::math::arithmetic::add

Avec re-export:
pub use math::geometry::Point;

Devient:
crate::Point  (plus court!)
```

### 5.5 Modificateurs de visibilite

```rust
pub           // Public a tous
pub(crate)    // Public dans la crate seulement
pub(super)    // Public au module parent
pub(in path)  // Public a un chemin specifique
(rien)        // Prive (defaut)

// Exemple
pub struct Config {
    pub name: String,           // Public
    pub(crate) secret: String,  // Visible dans la crate
    password: String,           // Prive
}
```

---

## SECTION 7 : QCM

### Question 1
Un champ de struct sans modificateur est:

A) Public
B) Prive
C) pub(crate)
D) pub(super)
E) Depend de la struct

**Reponse correcte: B**

### Question 2
A quoi sert `pub use`?

A) Rendre un module public
B) Re-exporter un item sous un chemin plus court
C) Importer pour usage interne
D) Creer un alias
E) Rien

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.7.16-a",
  "name": "modules",
  "language": "rust",
  "language_version": "edition2024",
  "files": [
    "src/lib.rs",
    "src/math/mod.rs",
    "src/math/geometry.rs",
    "src/math/arithmetic.rs",
    "src/utils/mod.rs",
    "src/utils/string_utils.rs"
  ],
  "tests": {
    "visibility": "module_visibility_tests",
    "imports": "import_tests"
  }
}
```
