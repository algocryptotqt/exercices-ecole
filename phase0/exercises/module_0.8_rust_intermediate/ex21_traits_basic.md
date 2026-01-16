# Exercice 0.8.21 : traits_basic

**Module :**
0.8 — Rust Intermediate

**Concept :**
a-c — Trait definition, default methods, impl Trait for Type

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
2 — Concept combine

**Langage :**
Rust Edition 2024

**Prerequis :**
0.8.19 (generic_functions), structs, impl blocks

**Domaines :**
Type System, Traits, Polymorphism

**Duree estimee :**
120 min

**XP Base :**
250

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichier a rendre :** `traits_basic.rs`

**Fonctions autorisees :**
- Standard library

**Fonctions interdites :**
- External crates

### 1.2 Consigne

**Le Contrat des Types: Definir les Comportements**

Les traits sont des contrats qui definissent ce qu'un type peut faire. Tu vas creer tes propres traits et les implementer pour differents types.

**Ta mission :**

Definir et implementer les traits suivants:

```rust
// Trait pour les formes geometriques
trait Shape {
    fn area(&self) -> f64;
    fn perimeter(&self) -> f64;

    // Methode par defaut
    fn describe(&self) -> String {
        format!("Area: {:.2}, Perimeter: {:.2}", self.area(), self.perimeter())
    }
}

// Trait pour les objets qui peuvent etre affiches en ASCII
trait AsciiDrawable {
    fn draw(&self) -> String;
}

// Trait pour les objets qui peuvent etre redimensionnes
trait Resizable {
    fn resize(&mut self, factor: f64);
}
```

**Structures a implementer:**

```rust
struct Circle {
    radius: f64,
}

struct Rectangle {
    width: f64,
    height: f64,
}

struct Square {
    side: f64,
}
```

**Implementer ces traits pour chaque structure:**

- `Shape` pour Circle, Rectangle, Square
- `AsciiDrawable` pour Circle, Rectangle
- `Resizable` pour Circle, Rectangle, Square

**Sortie attendue du main:**

```
=== Traits Demo ===
Circle (r=5): Area: 78.54, Perimeter: 31.42
Rectangle (3x4): Area: 12.00, Perimeter: 14.00
Square (5): Area: 25.00, Perimeter: 20.00

ASCII Circle:
  ***
 *   *
*     *
 *   *
  ***

Resizing circle by 2x:
New radius: 10
```

### 1.3 Prototype

```rust
use std::f64::consts::PI;

trait Shape {
    fn area(&self) -> f64;
    fn perimeter(&self) -> f64;
    fn describe(&self) -> String;
}

trait AsciiDrawable {
    fn draw(&self) -> String;
}

trait Resizable {
    fn resize(&mut self, factor: f64);
}

struct Circle { radius: f64 }
struct Rectangle { width: f64, height: f64 }
struct Square { side: f64 }

fn main();
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Traits vs Interfaces

Les traits Rust sont similaires aux interfaces en Java/C# mais avec des differences importantes:
- Les traits peuvent avoir des **implementations par defaut**
- Les traits peuvent etre implementes pour des types externes (blanket implementations)
- Pas d'heritage de classe, seulement composition de traits

### 2.2 Coherence (Orphan Rule)

La regle de coherence ("orphan rule") stipule que vous ne pouvez implementer un trait pour un type que si:
- Le trait est defini dans votre crate, OU
- Le type est defini dans votre crate

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : API Designer**

Les traits definissent les interfaces publiques:
- `Iterator` pour les collections
- `Read`/`Write` pour les I/O
- `Serialize`/`Deserialize` pour la serialisation

**Metier : Game Developer**

Les traits permettent le polymorphisme:
- `Drawable` pour les entites graphiques
- `Updatable` pour la game loop
- `Collidable` pour la physique

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ rustc --edition 2024 traits_basic.rs
$ ./traits_basic
=== Traits Demo ===
Circle (r=5): Area: 78.54, Perimeter: 31.42
Rectangle (3x4): Area: 12.00, Perimeter: 14.00
Square (5): Area: 25.00, Perimeter: 20.00

ASCII Circle:
  ***
 *   *
*     *
 *   *
  ***

Resizing circle by 2x:
New radius: 10
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★☆☆☆☆☆ (5/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Implementer un trait avec types associes:

```rust
trait Container {
    type Item;

    fn add(&mut self, item: Self::Item);
    fn get(&self, index: usize) -> Option<&Self::Item>;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Expected | Points |
|---------|-------------|----------|--------|
| T01 | Compilation sans warning | Success | 10 |
| T02 | Circle::area | PI * r^2 | 15 |
| T03 | Circle::perimeter | 2 * PI * r | 10 |
| T04 | Rectangle::area | w * h | 15 |
| T05 | Rectangle::perimeter | 2*(w+h) | 10 |
| T06 | Shape::describe default | Format correct | 10 |
| T07 | Resizable::resize | Facteur applique | 15 |
| T08 | AsciiDrawable::draw | String non vide | 15 |

### 4.2 Tests unitaires

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circle_area() {
        let c = Circle { radius: 5.0 };
        assert!((c.area() - 78.53981633974483).abs() < 0.0001);
    }

    #[test]
    fn test_circle_perimeter() {
        let c = Circle { radius: 5.0 };
        assert!((c.perimeter() - 31.41592653589793).abs() < 0.0001);
    }

    #[test]
    fn test_rectangle_area() {
        let r = Rectangle { width: 3.0, height: 4.0 };
        assert_eq!(r.area(), 12.0);
    }

    #[test]
    fn test_rectangle_perimeter() {
        let r = Rectangle { width: 3.0, height: 4.0 };
        assert_eq!(r.perimeter(), 14.0);
    }

    #[test]
    fn test_square_area() {
        let s = Square { side: 5.0 };
        assert_eq!(s.area(), 25.0);
    }

    #[test]
    fn test_describe_default() {
        let c = Circle { radius: 1.0 };
        let desc = c.describe();
        assert!(desc.contains("Area:"));
        assert!(desc.contains("Perimeter:"));
    }

    #[test]
    fn test_resize_circle() {
        let mut c = Circle { radius: 5.0 };
        c.resize(2.0);
        assert_eq!(c.radius, 10.0);
    }

    #[test]
    fn test_resize_rectangle() {
        let mut r = Rectangle { width: 3.0, height: 4.0 };
        r.resize(2.0);
        assert_eq!(r.width, 6.0);
        assert_eq!(r.height, 8.0);
    }

    #[test]
    fn test_ascii_drawable() {
        let c = Circle { radius: 3.0 };
        let drawing = c.draw();
        assert!(!drawing.is_empty());
    }
}
```

### 4.3 Solution de reference

```rust
/*
 * traits_basic.rs
 * Traits definition and implementation
 * Exercice ex21_traits_basic
 */

use std::f64::consts::PI;

/// Trait for geometric shapes
trait Shape {
    fn area(&self) -> f64;
    fn perimeter(&self) -> f64;

    /// Default implementation using other trait methods
    fn describe(&self) -> String {
        format!("Area: {:.2}, Perimeter: {:.2}", self.area(), self.perimeter())
    }
}

/// Trait for ASCII art representation
trait AsciiDrawable {
    fn draw(&self) -> String;
}

/// Trait for resizable objects
trait Resizable {
    fn resize(&mut self, factor: f64);
}

// ============ Structures ============

struct Circle {
    radius: f64,
}

struct Rectangle {
    width: f64,
    height: f64,
}

struct Square {
    side: f64,
}

// ============ Shape implementations ============

impl Shape for Circle {
    fn area(&self) -> f64 {
        PI * self.radius * self.radius
    }

    fn perimeter(&self) -> f64 {
        2.0 * PI * self.radius
    }
}

impl Shape for Rectangle {
    fn area(&self) -> f64 {
        self.width * self.height
    }

    fn perimeter(&self) -> f64 {
        2.0 * (self.width + self.height)
    }
}

impl Shape for Square {
    fn area(&self) -> f64 {
        self.side * self.side
    }

    fn perimeter(&self) -> f64 {
        4.0 * self.side
    }
}

// ============ AsciiDrawable implementations ============

impl AsciiDrawable for Circle {
    fn draw(&self) -> String {
        // Simple ASCII circle approximation
        let mut result = String::new();
        let r = self.radius as i32;
        for y in -r..=r {
            for x in -r..=r {
                let dist = ((x * x + y * y) as f64).sqrt();
                if (dist - self.radius).abs() < 0.8 {
                    result.push('*');
                } else if dist < self.radius {
                    result.push(' ');
                } else {
                    result.push(' ');
                }
            }
            result.push('\n');
        }
        result
    }
}

impl AsciiDrawable for Rectangle {
    fn draw(&self) -> String {
        let w = self.width as usize;
        let h = self.height as usize;
        let mut result = String::new();

        for row in 0..h {
            for col in 0..w {
                if row == 0 || row == h - 1 || col == 0 || col == w - 1 {
                    result.push('*');
                } else {
                    result.push(' ');
                }
            }
            result.push('\n');
        }
        result
    }
}

// ============ Resizable implementations ============

impl Resizable for Circle {
    fn resize(&mut self, factor: f64) {
        self.radius *= factor;
    }
}

impl Resizable for Rectangle {
    fn resize(&mut self, factor: f64) {
        self.width *= factor;
        self.height *= factor;
    }
}

impl Resizable for Square {
    fn resize(&mut self, factor: f64) {
        self.side *= factor;
    }
}

fn main() {
    println!("=== Traits Demo ===");

    let circle = Circle { radius: 5.0 };
    let rectangle = Rectangle { width: 3.0, height: 4.0 };
    let square = Square { side: 5.0 };

    println!("Circle (r=5): {}", circle.describe());
    println!("Rectangle (3x4): {}", rectangle.describe());
    println!("Square (5): {}", square.describe());

    println!("\nASCII Circle:");
    let small_circle = Circle { radius: 3.0 };
    println!("{}", small_circle.draw());

    println!("Resizing circle by 2x:");
    let mut resizable_circle = Circle { radius: 5.0 };
    resizable_circle.resize(2.0);
    println!("New radius: {}", resizable_circle.radius);
}
```

### 4.4 Solutions alternatives acceptees

```rust
// Alternative 1: Utiliser une macro pour les implementations similaires
macro_rules! impl_shape_for_square_like {
    ($t:ty, $side:ident) => {
        impl Shape for $t {
            fn area(&self) -> f64 { self.$side * self.$side }
            fn perimeter(&self) -> f64 { 4.0 * self.$side }
        }
    };
}

// Alternative 2: Override de describe
impl Shape for Square {
    fn area(&self) -> f64 { self.side * self.side }
    fn perimeter(&self) -> f64 { 4.0 * self.side }

    fn describe(&self) -> String {
        format!("Square (side={}): Area: {:.2}", self.side, self.area())
    }
}

// Alternative 3: Utiliser const pour PI
const MY_PI: f64 = 3.14159265358979323846;
```

### 4.10 Solutions Mutantes (minimum 5)

```rust
// MUTANT 1 (Math): Formule de l'aire du cercle incorrecte
impl Shape for Circle {
    fn area(&self) -> f64 {
        PI * self.radius  // ERREUR: manque ^2
    }
}
// Detection: area() retourne ~15.7 au lieu de ~78.5 pour r=5

// MUTANT 2 (Math): Perimetre du rectangle incorrect
impl Shape for Rectangle {
    fn perimeter(&self) -> f64 {
        self.width + self.height  // ERREUR: manque 2*
    }
}
// Detection: perimeter() retourne 7 au lieu de 14 pour 3x4

// MUTANT 3 (Logic): resize divise au lieu de multiplier
impl Resizable for Circle {
    fn resize(&mut self, factor: f64) {
        self.radius /= factor;  // ERREUR: devrait etre *=
    }
}
// Detection: resize(2.0) reduit le rayon au lieu de l'agrandir

// MUTANT 4 (Type): describe retourne mauvais format
trait Shape {
    fn describe(&self) -> String {
        format!("{} {}", self.area(), self.perimeter())  // Pas de labels
    }
}
// Detection: Format de sortie incorrect

// MUTANT 5 (Logic): Square utilise formule de rectangle
impl Shape for Square {
    fn area(&self) -> f64 {
        self.side * 2.0  // ERREUR: devrait etre side^2
    }
}
// Detection: area() retourne 10 au lieu de 25 pour side=5
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

1. **Definition de traits** - Declarer des comportements abstraits
2. **Implementation de traits** - `impl Trait for Type`
3. **Methodes par defaut** - Implementations reutilisables
4. **Polymorphisme via traits** - Abstraire sur les types

### 5.2 LDA - Traduction Litterale en Francais

```
TRAIT Shape
    METHODE ABSTRAITE area() -> f64
    METHODE ABSTRAITE perimeter() -> f64

    METHODE PAR DEFAUT describe() -> String
    DEBUT
        RETOURNER format("Area: {}, Perimeter: {}", area(), perimeter())
    FIN
FIN TRAIT

IMPLEMENTATION Shape POUR Circle
    METHODE area() -> f64
    DEBUT
        RETOURNER PI * radius * radius
    FIN

    METHODE perimeter() -> f64
    DEBUT
        RETOURNER 2 * PI * radius
    FIN
FIN IMPLEMENTATION
```

### 5.3 Visualisation ASCII

```
Trait Shape                     Implementations
+------------------+
| trait Shape {    |           Circle
|   fn area()      |---------> impl Shape for Circle {
|   fn perimeter() |              area() = PI * r^2
|   fn describe()  |              perimeter() = 2*PI*r
| }                |           }
+------------------+
                               Rectangle
                    ---------> impl Shape for Rectangle {
                                  area() = w * h
                                  perimeter() = 2*(w+h)
                               }

+------------------+
| Default method   |
| describe() uses  |           describe() appelle
| area() and       |---------> area() et perimeter()
| perimeter()      |           de chaque impl
+------------------+
```

### 5.4 Les pieges en detail

#### Piege 1: Oublier une methode requise

```rust
// ERREUR: perimeter() manquant
impl Shape for Circle {
    fn area(&self) -> f64 {
        PI * self.radius * self.radius
    }
    // Erreur: missing `perimeter`
}
```

#### Piege 2: Signature incorrecte

```rust
// ERREUR: mauvais type de retour
impl Shape for Circle {
    fn area(&self) -> i32 {  // Devrait etre f64!
        (PI * self.radius * self.radius) as i32
    }
}
```

#### Piege 3: Orphan rule

```rust
// ERREUR: ni String ni Display ne sont definis localement
impl std::fmt::Display for String {  // Interdit!
    // ...
}
```

### 5.5 Cours Complet

#### 5.5.1 Syntaxe de definition de trait

```rust
trait NomDuTrait {
    // Methode abstraite (obligatoire)
    fn methode_requise(&self) -> Type;

    // Methode avec implementation par defaut
    fn methode_par_defaut(&self) {
        println!("Implementation par defaut");
    }
}
```

#### 5.5.2 Implementation de trait

```rust
impl NomDuTrait for MonType {
    fn methode_requise(&self) -> Type {
        // Implementation specifique
    }

    // Peut overrider les methodes par defaut
    fn methode_par_defaut(&self) {
        println!("Ma propre implementation");
    }
}
```

#### 5.5.3 Traits comme bounds

```rust
// Function qui accepte n'importe quel Shape
fn print_area<T: Shape>(shape: &T) {
    println!("Area: {}", shape.area());
}

// Syntaxe impl Trait (sucre syntaxique)
fn print_area(shape: &impl Shape) {
    println!("Area: {}", shape.area());
}
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication |
|-------|-------------|
| Trait en CamelCase | Convention Rust |
| Methodes en snake_case | Convention Rust |
| `&self` pour lecture | Ne consomme pas |
| `&mut self` pour mutation | Modifie en place |
| `self` pour consommation | Prend ownership |

### 5.7 Simulation avec trace d'execution

```
Appel: circle.describe()

1. circle est de type Circle
2. Circle implemente Shape
3. describe() est une methode par defaut
4. describe() appelle self.area()
5. Dispatch vers Circle::area() -> 78.54
6. describe() appelle self.perimeter()
7. Dispatch vers Circle::perimeter() -> 31.42
8. Retourne "Area: 78.54, Perimeter: 31.42"
```

### 5.8 Mnemotechniques

**"TRAIT = Contrat de Comportement"**
- Un trait definit ce qu'un type peut FAIRE

**"impl Trait for Type = Ce Type respecte ce Contrat"**
- Implementation concrete des methodes

**"Default = Optionnel mais pratique"**
- Evite la duplication de code

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Methode manquante | Erreur E0046 | Implementer toutes les methodes |
| Signature incorrecte | Erreur E0053 | Verifier types et lifetime |
| Orphan rule | Erreur E0117 | Wrapper type local |
| Self vs &self | Move inattendu | Utiliser reference |

---

## SECTION 7 : QCM

### Question 1
Qu'est-ce qu'un trait en Rust?

A) Une classe abstraite
B) Un contrat definissant des comportements
C) Un type concret
D) Une macro
E) Un module

**Reponse correcte: B**

### Question 2
Que se passe-t-il si vous n'implementez pas une methode par defaut?

A) Erreur de compilation
B) La methode par defaut est utilisee
C) Panic a l'execution
D) La methode retourne None
E) Comportement indefini

**Reponse correcte: B**

### Question 3
Quelle est la syntaxe correcte pour implementer un trait?

A) `impl Circle: Shape`
B) `impl Shape on Circle`
C) `impl Shape for Circle`
D) `Circle implements Shape`
E) `trait Shape for Circle`

**Reponse correcte: C**

### Question 4
Peut-on implementer un trait de la std pour un type de la std?

A) Oui, toujours
B) Non, a cause de la orphan rule
C) Seulement avec unsafe
D) Seulement en nightly
E) Seulement avec une feature gate

**Reponse correcte: B**

### Question 5
Que permet la methode par defaut `describe()` dans Shape?

A) Eviter de l'implementer pour chaque type
B) Forcer une implementation
C) Creer une erreur
D) Desactiver le trait
E) Rien de special

**Reponse correcte: A**

---

## SECTION 8 : RECAPITULATIF

| Concept | Description | Exemple |
|---------|-------------|---------|
| Trait | Contrat de comportement | `trait Shape { }` |
| Methode abstraite | Sans implementation | `fn area(&self) -> f64;` |
| Methode par defaut | Avec implementation | `fn describe() { ... }` |
| impl for | Implementation | `impl Shape for Circle` |
| Trait bound | Contrainte generique | `T: Shape` |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.8.21",
  "name": "traits_basic",
  "version": "1.0.0",
  "language": "rust",
  "language_version": "edition2024",
  "files": {
    "submission": ["traits_basic.rs"],
    "test": ["test_traits_basic.rs"]
  },
  "compilation": {
    "compiler": "rustc",
    "flags": ["--edition", "2024", "-W", "warnings"],
    "output": "traits_basic"
  },
  "tests": {
    "unit_tests": true,
    "output_match": true
  },
  "scoring": {
    "total": 100,
    "compilation": 10,
    "tests": 90
  },
  "concepts": ["traits", "impl_for", "default_methods", "polymorphism"]
}
```
