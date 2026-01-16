# Exercice 0.8.20 : generic_types

**Module :**
0.8 — Rust Intermediate

**Concept :**
a-c — Generic structs, const generics, Matrix<T, ROWS, COLS>

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
2 — Concept combine

**Langage :**
Rust Edition 2024

**Prerequis :**
0.8.19 (generic_functions), structs, impl blocks

**Domaines :**
Type System, Generics, Data Structures

**Duree estimee :**
150 min

**XP Base :**
300

**Complexite :**
T2 O(n*m) x S2 O(n*m)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichier a rendre :** `generic_types.rs`

**Fonctions autorisees :**
- Standard library traits et macros

**Fonctions interdites :**
- External crates

### 1.2 Consigne

**L'Architecte des Structures: Concevoir l'Universel**

Tu es un architecte de donnees. Ta mission: concevoir des structures qui s'adaptent a n'importe quel type, avec des dimensions connues a la compilation.

**Ta mission :**

Implementer les structures generiques suivantes:

```rust
// Paire generique avec deux types differents
struct Pair<T, U> {
    first: T,
    second: U,
}

// Point generique en N dimensions (const generic)
struct Point<T, const N: usize> {
    coords: [T; N],
}

// Matrice generique avec dimensions const
struct Matrix<T, const ROWS: usize, const COLS: usize> {
    data: [[T; COLS]; ROWS],
}

// Option maison (pour comprendre le concept)
enum MyOption<T> {
    Some(T),
    None,
}
```

**Methodes a implementer:**

```rust
impl<T, U> Pair<T, U> {
    fn new(first: T, second: U) -> Self;
    fn first(&self) -> &T;
    fn second(&self) -> &U;
    fn swap(self) -> Pair<U, T>;  // Inverse les types!
}

impl<T: Default + Copy, const N: usize> Point<T, N> {
    fn origin() -> Self;
    fn get(&self, index: usize) -> Option<&T>;
}

impl<T: Default + Copy, const ROWS: usize, const COLS: usize> Matrix<T, ROWS, COLS> {
    fn new() -> Self;
    fn get(&self, row: usize, col: usize) -> Option<&T>;
    fn set(&mut self, row: usize, col: usize, value: T) -> bool;
    fn rows(&self) -> usize;
    fn cols(&self) -> usize;
}

impl<T> MyOption<T> {
    fn is_some(&self) -> bool;
    fn is_none(&self) -> bool;
    fn unwrap(self) -> T;  // Panic si None
}
```

**Sortie attendue du main:**

```
=== Generic Types Demo ===
Pair: (42, "hello")
Swapped: ("hello", 42)
Point2D origin: [0, 0]
Point3D origin: [0.0, 0.0, 0.0]
Matrix 2x3 created
matrix[0][1] = 5
Matrix dimensions: 2 rows x 3 cols
MyOption::Some(42) is_some: true
MyOption::None is_none: true
```

### 1.3 Prototype

```rust
struct Pair<T, U> { first: T, second: U }
struct Point<T, const N: usize> { coords: [T; N] }
struct Matrix<T, const ROWS: usize, const COLS: usize> { data: [[T; COLS]; ROWS] }
enum MyOption<T> { Some(T), None }

fn main();
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Const Generics

Les **const generics** (stabilises dans Rust 1.51) permettent de parametrer les types par des valeurs constantes, pas seulement par des types. Cela permet des tableaux de taille generique!

```rust
// Avant const generics: impossible
// Apres: trivial
fn array_len<T, const N: usize>(arr: &[T; N]) -> usize {
    N
}
```

### 2.2 Turbofish ::<>

Quand Rust ne peut pas inferer le type, utilisez la syntaxe "turbofish":

```rust
let p = Point::<i32, 3>::origin();
//            ^^^^^^^^^ Turbofish!
```

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Game Developer**

Les matrices const-generiques sont parfaites pour:
- Transformations 4x4 en graphisme 3D
- Vecteurs de dimension fixe (Vec3, Vec4)
- Optimisations compile-time

**Metier : Embedded Developer**

Les const generics permettent:
- Buffers de taille fixe sans allocation
- Garanties de taille a la compilation
- Code sans heap pour microcontroleurs

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ rustc --edition 2024 generic_types.rs
$ ./generic_types
=== Generic Types Demo ===
Pair: (42, "hello")
Swapped: ("hello", 42)
Point2D origin: [0, 0]
Point3D origin: [0.0, 0.0, 0.0]
Matrix 2x3 created
matrix[0][1] = 5
Matrix dimensions: 2 rows x 3 cols
MyOption::Some(42) is_some: true
MyOption::None is_none: true
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★☆☆☆☆ (6/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Implementer la multiplication de matrices avec const generics:

```rust
impl<T, const M: usize, const N: usize, const P: usize> Matrix<T, M, N> {
    fn multiply<RHS: AsRef<[[T; P]; N]>>(&self, other: &Matrix<T, N, P>) -> Matrix<T, M, P>
    where
        T: Default + Copy + std::ops::Add<Output = T> + std::ops::Mul<Output = T>;
}
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Expected | Points |
|---------|-------------|----------|--------|
| T01 | Compilation sans warning | Success | 10 |
| T02 | Pair::new et accesseurs | Valeurs correctes | 15 |
| T03 | Pair::swap | Types inverses | 10 |
| T04 | Point::origin | Tableau de zeros | 15 |
| T05 | Matrix::new | Matrice de zeros | 15 |
| T06 | Matrix::get/set | Acces correct | 15 |
| T07 | MyOption::is_some/is_none | true/false correct | 10 |
| T08 | MyOption::unwrap | Valeur ou panic | 10 |

### 4.2 Tests unitaires

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pair() {
        let p = Pair::new(42, "hello");
        assert_eq!(*p.first(), 42);
        assert_eq!(*p.second(), "hello");
    }

    #[test]
    fn test_pair_swap() {
        let p = Pair::new(1, "one");
        let swapped = p.swap();
        assert_eq!(*swapped.first(), "one");
        assert_eq!(*swapped.second(), 1);
    }

    #[test]
    fn test_point_origin() {
        let p2d: Point<i32, 2> = Point::origin();
        assert_eq!(p2d.coords, [0, 0]);

        let p3d: Point<f64, 3> = Point::origin();
        assert_eq!(p3d.coords, [0.0, 0.0, 0.0]);
    }

    #[test]
    fn test_matrix_new() {
        let m: Matrix<i32, 2, 3> = Matrix::new();
        assert_eq!(m.rows(), 2);
        assert_eq!(m.cols(), 3);
        assert_eq!(m.get(0, 0), Some(&0));
    }

    #[test]
    fn test_matrix_set_get() {
        let mut m: Matrix<i32, 2, 2> = Matrix::new();
        assert!(m.set(0, 1, 42));
        assert_eq!(m.get(0, 1), Some(&42));
        assert!(!m.set(5, 5, 100)); // Out of bounds
    }

    #[test]
    fn test_my_option() {
        let some: MyOption<i32> = MyOption::Some(42);
        let none: MyOption<i32> = MyOption::None;

        assert!(some.is_some());
        assert!(!some.is_none());
        assert!(none.is_none());
        assert!(!none.is_some());
    }

    #[test]
    fn test_my_option_unwrap() {
        let some = MyOption::Some(42);
        assert_eq!(some.unwrap(), 42);
    }

    #[test]
    #[should_panic]
    fn test_my_option_unwrap_none() {
        let none: MyOption<i32> = MyOption::None;
        none.unwrap(); // Should panic
    }
}
```

### 4.3 Solution de reference

```rust
/*
 * generic_types.rs
 * Generic structs and const generics demonstration
 * Exercice ex20_generic_types
 */

use std::fmt::Debug;

/// Generic pair with two different types
#[derive(Debug)]
struct Pair<T, U> {
    first: T,
    second: U,
}

impl<T, U> Pair<T, U> {
    fn new(first: T, second: U) -> Self {
        Pair { first, second }
    }

    fn first(&self) -> &T {
        &self.first
    }

    fn second(&self) -> &U {
        &self.second
    }

    fn swap(self) -> Pair<U, T> {
        Pair {
            first: self.second,
            second: self.first,
        }
    }
}

/// Point in N dimensions with const generic
#[derive(Debug)]
struct Point<T, const N: usize> {
    coords: [T; N],
}

impl<T: Default + Copy, const N: usize> Point<T, N> {
    fn origin() -> Self {
        Point {
            coords: [T::default(); N],
        }
    }

    fn get(&self, index: usize) -> Option<&T> {
        self.coords.get(index)
    }
}

/// Matrix with const generic dimensions
#[derive(Debug)]
struct Matrix<T, const ROWS: usize, const COLS: usize> {
    data: [[T; COLS]; ROWS],
}

impl<T: Default + Copy, const ROWS: usize, const COLS: usize> Matrix<T, ROWS, COLS> {
    fn new() -> Self {
        Matrix {
            data: [[T::default(); COLS]; ROWS],
        }
    }

    fn get(&self, row: usize, col: usize) -> Option<&T> {
        if row < ROWS && col < COLS {
            Some(&self.data[row][col])
        } else {
            None
        }
    }

    fn set(&mut self, row: usize, col: usize, value: T) -> bool {
        if row < ROWS && col < COLS {
            self.data[row][col] = value;
            true
        } else {
            false
        }
    }

    fn rows(&self) -> usize {
        ROWS
    }

    fn cols(&self) -> usize {
        COLS
    }
}

/// Custom Option implementation
enum MyOption<T> {
    Some(T),
    None,
}

impl<T> MyOption<T> {
    fn is_some(&self) -> bool {
        matches!(self, MyOption::Some(_))
    }

    fn is_none(&self) -> bool {
        matches!(self, MyOption::None)
    }

    fn unwrap(self) -> T {
        match self {
            MyOption::Some(value) => value,
            MyOption::None => panic!("called `MyOption::unwrap()` on a `None` value"),
        }
    }
}

fn main() {
    println!("=== Generic Types Demo ===");

    // Pair
    let pair = Pair::new(42, "hello");
    println!("Pair: ({}, \"{}\")", pair.first(), pair.second());

    let swapped = pair.swap();
    println!("Swapped: (\"{}\", {})", swapped.first(), swapped.second());

    // Point with const generics
    let p2d: Point<i32, 2> = Point::origin();
    println!("Point2D origin: {:?}", p2d.coords);

    let p3d: Point<f64, 3> = Point::origin();
    println!("Point3D origin: {:?}", p3d.coords);

    // Matrix with const generics
    let mut matrix: Matrix<i32, 2, 3> = Matrix::new();
    println!("Matrix 2x3 created");

    matrix.set(0, 1, 5);
    println!("matrix[0][1] = {}", matrix.get(0, 1).unwrap());
    println!("Matrix dimensions: {} rows x {} cols", matrix.rows(), matrix.cols());

    // MyOption
    let some: MyOption<i32> = MyOption::Some(42);
    let none: MyOption<i32> = MyOption::None;

    println!("MyOption::Some(42) is_some: {}", some.is_some());
    println!("MyOption::None is_none: {}", none.is_none());
}
```

### 4.4 Solutions alternatives acceptees

```rust
// Alternative 1: Point avec Vec au lieu de array (moins optimal)
struct PointVec<T> {
    coords: Vec<T>,
    dimensions: usize,
}

// Alternative 2: Matrix avec Vec<Vec<T>> (dynamique)
struct MatrixDyn<T> {
    data: Vec<Vec<T>>,
    rows: usize,
    cols: usize,
}

// Alternative 3: MyOption avec if let
impl<T> MyOption<T> {
    fn is_some(&self) -> bool {
        if let MyOption::Some(_) = self { true } else { false }
    }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```rust
// MUTANT 1 (Logic): swap ne swap pas vraiment
impl<T, U> Pair<T, U> {
    fn swap(self) -> Pair<U, T> {
        Pair {
            first: self.first,  // ERREUR: types incompatibles
            second: self.second,
        }
    }
}
// Detection: Erreur de compilation (types)

// MUTANT 2 (Boundary): get sans verification bounds
impl<T: Default + Copy, const ROWS: usize, const COLS: usize> Matrix<T, ROWS, COLS> {
    fn get(&self, row: usize, col: usize) -> Option<&T> {
        Some(&self.data[row][col])  // PANIC possible!
    }
}
// Detection: get(100, 100) provoque un panic

// MUTANT 3 (Logic): set retourne toujours true
impl<T: Default + Copy, const ROWS: usize, const COLS: usize> Matrix<T, ROWS, COLS> {
    fn set(&mut self, row: usize, col: usize, value: T) -> bool {
        self.data[row][col] = value;  // PANIC si hors limites
        true
    }
}
// Detection: set avec indices invalides panic au lieu de false

// MUTANT 4 (Logic): is_some et is_none inverses
impl<T> MyOption<T> {
    fn is_some(&self) -> bool {
        matches!(self, MyOption::None)  // ERREUR: inverse
    }
}
// Detection: MyOption::Some(42).is_some() retourne false

// MUTANT 5 (Safety): unwrap retourne default au lieu de panic
impl<T: Default> MyOption<T> {
    fn unwrap(self) -> T {
        match self {
            MyOption::Some(value) => value,
            MyOption::None => T::default(),  // Ne panic pas!
        }
    }
}
// Detection: Comportement different de std::Option
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

1. **Generic structs** - Structures parametrees par des types
2. **Const generics** - Parametres de valeurs constantes (`const N: usize`)
3. **Impl blocks generiques** - Implementation pour types generiques
4. **Type inference** - Quand le compilateur infere les types

### 5.2 LDA - Traduction Litterale en Francais

```
STRUCTURE Pair<T, U>
    first: T
    second: U
FIN STRUCTURE

FONCTION Pair::swap(self) -> Pair<U, T>
DEBUT
    RETOURNER nouvelle Pair avec:
        first = self.second
        second = self.first
FIN

STRUCTURE Matrix<T, ROWS constante, COLS constante>
    data: tableau 2D de T avec ROWS lignes et COLS colonnes
FIN STRUCTURE

FONCTION Matrix::get(row, col) -> Option<&T>
DEBUT
    SI row < ROWS ET col < COLS ALORS
        RETOURNER Some(reference vers data[row][col])
    SINON
        RETOURNER None
    FIN SI
FIN
```

### 5.3 Visualisation ASCII

```
Pair<i32, &str>                    Point<f64, 3>
+-------------+                    +-------------------+
| first: i32  |  42                | coords: [f64; 3]  |
+-------------+                    +-------------------+
| second: &str| "hi"               | [0.0, 0.0, 0.0]   |
+-------------+                    +-------------------+

Matrix<i32, 2, 3>
+---+---+---+
| 0 | 5 | 0 |  <- Row 0
+---+---+---+
| 0 | 0 | 0 |  <- Row 1
+---+---+---+
  ^   ^   ^
  C   C   C
  0   1   2

Const Generics: ROWS=2, COLS=3 connus a la compilation!
```

### 5.4 Les pieges en detail

#### Piege 1: Default + Copy requis pour array initialization

```rust
// ERREUR: T n'implemente pas forcement Default
fn new<T, const N: usize>() -> [T; N] {
    [T::default(); N]  // Erreur!
}

// CORRECT
fn new<T: Default + Copy, const N: usize>() -> [T; N] {
    [T::default(); N]
}
```

#### Piege 2: Const generics et expressions

```rust
// ERREUR (actuellement): expressions complexes
struct Foo<const N: usize> {
    data: [i32; N + 1],  // Non supporte!
}

// CORRECT
struct Foo<const N: usize> {
    data: [i32; N],
}
```

#### Piege 3: Turbofish necessaire

```rust
// ERREUR: Rust ne peut pas inferer N
let p = Point::origin();

// CORRECT
let p: Point<i32, 2> = Point::origin();
// ou
let p = Point::<i32, 2>::origin();
```

### 5.5 Cours Complet

#### 5.5.1 Generic Structs

```rust
// Un type generique
struct Wrapper<T> {
    value: T,
}

// Deux types generiques
struct Pair<T, U> {
    first: T,
    second: U,
}

// Implementation generique
impl<T> Wrapper<T> {
    fn new(value: T) -> Self {
        Wrapper { value }
    }
}
```

#### 5.5.2 Const Generics

```rust
// Const generic pour la taille
struct Buffer<T, const SIZE: usize> {
    data: [T; SIZE],
}

// Utilisation
let small: Buffer<u8, 64> = Buffer { data: [0; 64] };
let large: Buffer<u8, 1024> = Buffer { data: [0; 1024] };
```

#### 5.5.3 Generic Enums

```rust
// L'enum Option standard
enum Option<T> {
    Some(T),
    None,
}

// L'enum Result standard
enum Result<T, E> {
    Ok(T),
    Err(E),
}
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication |
|-------|-------------|
| `T, U, V` pour types | Convention standard |
| `N, M, K` pour const | Convention pour dimensions |
| Bounds sur impl, pas struct | Plus flexible |
| `const N: usize` | Type le plus courant pour tailles |

### 5.7 Simulation avec trace d'execution

```
Creation: Matrix::<i32, 2, 3>::new()

1. ROWS = 2, COLS = 3 (const generics)
2. T = i32, i32::default() = 0
3. Alloue [[0i32; 3]; 2] sur la stack
4. Retourne Matrix { data: [[0,0,0], [0,0,0]] }

Appel: matrix.set(0, 1, 5)

1. row=0, col=1
2. 0 < 2 (ROWS)? OUI
3. 1 < 3 (COLS)? OUI
4. data[0][1] = 5
5. Retourne true
```

### 5.8 Mnemotechniques

**"Const Generics = Taille a la Compilation"**
- Plus de `Vec` pour les tableaux de taille fixe

**"<T, const N: usize> = Type + Taille"**
- T est le type, N est la dimension

**"Turbofish ::<> = Je te dis le type!"**
- Quand Rust ne peut pas deviner

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Pas de Default | Erreur compilation | Ajouter `T: Default` |
| Pas de Copy | Erreur sur array init | Ajouter `T: Copy` |
| Type non inferable | Erreur E0282 | Utiliser turbofish |
| Index hors limites | Panic runtime | Verifier bounds |

---

## SECTION 7 : QCM

### Question 1
Que signifie `const N: usize` dans `struct Foo<const N: usize>`?

A) N est un type
B) N est une valeur constante connue a la compilation
C) N est une variable runtime
D) N est une reference
E) N est optionnel

**Reponse correcte: B**

### Question 2
Pourquoi `Point::origin()` necessite-t-il `T: Default + Copy`?

A) Pour pouvoir afficher le point
B) Pour initialiser l'array avec des valeurs par defaut
C) Pour comparer les points
D) Pour le debugging
E) C'est obligatoire pour tous les generiques

**Reponse correcte: B**

### Question 3
Quelle est la syntaxe turbofish correcte?

A) `Point<i32, 2>::origin()`
B) `Point::<i32, 2>::origin()`
C) `Point::origin::<i32, 2>()`
D) `Point::origin<i32, 2>()`
E) `<i32, 2>Point::origin()`

**Reponse correcte: B**

### Question 4
Que retourne `Matrix::get(100, 100)` sur une matrice 2x3?

A) Panic
B) Some(&0)
C) None
D) Erreur de compilation
E) Comportement indefini

**Reponse correcte: C**

### Question 5
Comment Pair::swap change-t-il les types?

A) Il ne change pas les types
B) `Pair<T, U>` devient `Pair<U, T>`
C) `Pair<T, U>` devient `Pair<T, U>`
D) Il clone les valeurs
E) Il mute en place

**Reponse correcte: B**

---

## SECTION 8 : RECAPITULATIF

| Concept | Description | Exemple |
|---------|-------------|---------|
| Generic struct | Struct avec type param | `struct Foo<T>` |
| Const generic | Valeur const en param | `const N: usize` |
| Array generique | Taille connue compile | `[T; N]` |
| Turbofish | Specification de type | `::<i32, 3>` |
| Impl generique | Methodes pour generics | `impl<T> Foo<T>` |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.8.20",
  "name": "generic_types",
  "version": "1.0.0",
  "language": "rust",
  "language_version": "edition2024",
  "files": {
    "submission": ["generic_types.rs"],
    "test": ["test_generic_types.rs"]
  },
  "compilation": {
    "compiler": "rustc",
    "flags": ["--edition", "2024", "-W", "warnings"],
    "output": "generic_types"
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
  "concepts": ["generic_structs", "const_generics", "impl_blocks", "turbofish"]
}
```
