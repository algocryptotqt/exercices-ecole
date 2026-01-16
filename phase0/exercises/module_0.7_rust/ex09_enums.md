# Exercice 0.7.9-a : enums

**Module :**
0.7.9 — Enumerations

**Concept :**
a-e — enum, variants, pattern matching, Option, Result

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

Implementer des enumerations avec pattern matching.

**Ta mission :**

```rust
// Enum simple (comme en C)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Direction {
    North,
    South,
    East,
    West,
}

impl Direction {
    pub fn opposite(&self) -> Direction;
    pub fn turn_right(&self) -> Direction;
    pub fn turn_left(&self) -> Direction;
}

// Enum avec donnees
#[derive(Debug, Clone, PartialEq)]
pub enum Shape {
    Circle { radius: f64 },
    Rectangle { width: f64, height: f64 },
    Triangle { base: f64, height: f64 },
}

impl Shape {
    pub fn area(&self) -> f64;
    pub fn perimeter(&self) -> f64;
    pub fn scale(&self, factor: f64) -> Shape;
}

// Enum pour resultats
#[derive(Debug, Clone, PartialEq)]
pub enum MathResult {
    Value(f64),
    DivisionByZero,
    NegativeRoot,
    Overflow,
}

pub fn safe_divide(a: f64, b: f64) -> MathResult;
pub fn safe_sqrt(x: f64) -> MathResult;
```

**Comportement:**

1. `Direction::North.opposite()` -> Direction::South
2. `Shape::Circle { radius: 5.0 }.area()` -> ~78.54
3. `safe_divide(10.0, 0.0)` -> MathResult::DivisionByZero

**Exemples:**
```rust
let dir = Direction::North;
println!("{:?}", dir.opposite());  // South
println!("{:?}", dir.turn_right());  // East

let circle = Shape::Circle { radius: 5.0 };
println!("Area: {}", circle.area());  // ~78.54

let result = safe_divide(10.0, 2.0);
match result {
    MathResult::Value(v) => println!("Result: {}", v),
    MathResult::DivisionByZero => println!("Error: division by zero"),
    _ => println!("Other error"),
}
```

### 1.3 Prototype

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
    pub fn opposite(&self) -> Direction {
        todo!()
    }

    pub fn turn_right(&self) -> Direction {
        todo!()
    }

    pub fn turn_left(&self) -> Direction {
        todo!()
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
        todo!()
    }

    pub fn perimeter(&self) -> f64 {
        todo!()
    }

    pub fn scale(&self, factor: f64) -> Shape {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MathResult {
    Value(f64),
    DivisionByZero,
    NegativeRoot,
    Overflow,
}

pub fn safe_divide(a: f64, b: f64) -> MathResult {
    todo!()
}

pub fn safe_sqrt(x: f64) -> MathResult {
    todo!()
}
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | opposite | correct | 10 |
| T02 | turn_right/left | correct | 10 |
| T03 | Circle area | PI*r^2 | 15 |
| T04 | Rectangle area | w*h | 10 |
| T05 | scale | scaled shape | 15 |
| T06 | safe_divide OK | Value | 10 |
| T07 | safe_divide zero | DivisionByZero | 15 |
| T08 | safe_sqrt neg | NegativeRoot | 15 |

### 4.3 Solution de reference

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
                // Assume right triangle for simplicity
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

#[derive(Debug, Clone, PartialEq)]
pub enum MathResult {
    Value(f64),
    DivisionByZero,
    NegativeRoot,
    Overflow,
}

pub fn safe_divide(a: f64, b: f64) -> MathResult {
    if b == 0.0 {
        MathResult::DivisionByZero
    } else {
        let result = a / b;
        if result.is_infinite() {
            MathResult::Overflow
        } else {
            MathResult::Value(result)
        }
    }
}

pub fn safe_sqrt(x: f64) -> MathResult {
    if x < 0.0 {
        MathResult::NegativeRoot
    } else {
        MathResult::Value(x.sqrt())
    }
}
```

### 4.10 Solutions Mutantes

```rust
// MUTANT 1: opposite retourne self
impl Direction {
    pub fn opposite(&self) -> Direction {
        *self  // Retourne la meme direction!
    }
}

// MUTANT 2: turn_right est en fait turn_left
impl Direction {
    pub fn turn_right(&self) -> Direction {
        match self {
            Direction::North => Direction::West,  // West au lieu de East
            // ...
        }
    }
}

// MUTANT 3: Circle area sans PI
impl Shape {
    pub fn area(&self) -> f64 {
        match self {
            Shape::Circle { radius } => radius * radius,  // Manque PI
            // ...
        }
    }
}

// MUTANT 4: scale ne scale qu'une dimension
impl Shape {
    pub fn scale(&self, factor: f64) -> Shape {
        match self {
            Shape::Rectangle { width, height } => Shape::Rectangle {
                width: width * factor,
                height: *height,  // Oublie de scaler height
            },
            // ...
        }
    }
}

// MUTANT 5: safe_divide ne check pas infinity
pub fn safe_divide(a: f64, b: f64) -> MathResult {
    if b == 0.0 {
        MathResult::DivisionByZero
    } else {
        MathResult::Value(a / b)  // Peut retourner infinity
    }
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **enumerations** en Rust:

1. **Variants** - Chaque variant est un type possible
2. **Donnees associees** - Les variants peuvent contenir des donnees
3. **Pattern matching** - match exhaustif sur tous les variants
4. **Option/Result** - Enums standard pour absence/erreurs

### 5.3 Visualisation ASCII

```
ENUM SIMPLE:
Direction::North  -> tag = 0
Direction::South  -> tag = 1
Direction::East   -> tag = 2
Direction::West   -> tag = 3

Memoire: juste un entier (discriminant)
+-----+
| tag |  (1 byte si < 256 variants)
+-----+

ENUM AVEC DONNEES:
Shape::Circle { radius: 5.0 }

+-----+--------+--------+
| tag | radius | padding|
|  0  |  5.0   |   ...  |
+-----+--------+--------+

Shape::Rectangle { width: 10.0, height: 5.0 }

+-----+--------+--------+
| tag | width  | height |
|  1  | 10.0   |  5.0   |
+-----+--------+--------+

Taille totale = max(Circle, Rectangle, Triangle) + tag

PATTERN MATCHING:
match shape {
    Shape::Circle { radius } => /* radius disponible */,
    Shape::Rectangle { width, height } => /* les deux disponibles */,
    Shape::Triangle { .. } => /* ignore les champs */,
}
```

### 5.5 Option et Result

```rust
// Option<T> - Presence ou absence
enum Option<T> {
    Some(T),
    None,
}

let x: Option<i32> = Some(5);
let y: Option<i32> = None;

// Result<T, E> - Succes ou erreur
enum Result<T, E> {
    Ok(T),
    Err(E),
}

let ok: Result<i32, &str> = Ok(42);
let err: Result<i32, &str> = Err("something went wrong");

// Pattern matching
match result {
    Ok(value) => println!("Success: {}", value),
    Err(e) => println!("Error: {}", e),
}

// if let (raccourci)
if let Some(x) = option {
    println!("Got value: {}", x);
}
```

---

## SECTION 7 : QCM

### Question 1
Que se passe-t-il si on oublie un variant dans match ?

A) Le code compile avec un warning
B) Erreur de compilation
C) Runtime panic
D) Le variant est ignore
E) Comportement indefini

**Reponse correcte: B**

### Question 2
Quelle est la difference entre enum Rust et enum C ?

A) Pas de difference
B) Rust enum peut contenir des donnees
C) C enum est plus rapide
D) Rust enum est deprecated
E) C enum supporte le pattern matching

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.7.9-a",
  "name": "enums",
  "language": "rust",
  "language_version": "edition2024",
  "files": ["src/lib.rs"],
  "tests": {
    "direction": "direction_tests",
    "shape": "shape_tests",
    "math_result": "math_result_tests"
  }
}
```
