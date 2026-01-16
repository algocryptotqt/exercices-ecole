# Exercice 0.8.19 : generic_functions

**Module :**
0.8 — Rust Intermediate

**Concept :**
a-c — Generic functions, type parameters, trait bounds

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
2 — Concept combine

**Langage :**
Rust Edition 2024

**Prerequis :**
0.7 (Rust basics), functions, ownership

**Domaines :**
Type System, Generics

**Duree estimee :**
120 min

**XP Base :**
250

**Complexite :**
T1 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichier a rendre :** `generic_functions.rs`

**Fonctions autorisees :**
- Standard library traits (`std::cmp::PartialOrd`, `std::fmt::Display`, etc.)

**Fonctions interdites :**
- Aucune restriction

### 1.2 Consigne

**Alchimie Numerique: L'Art de l'Abstraction**

Dans le monde de la programmation generique, tu es un alchimiste capable de creer des fonctions qui fonctionnent avec n'importe quel type. Le secret: les parametres de type et les trait bounds.

**Ta mission :**

Implementer les fonctions generiques suivantes:

```rust
// Retourne le plus grand des deux elements
fn maximum<T: PartialOrd>(a: T, b: T) -> T;

// Echange deux valeurs via references mutables
fn swap<T>(a: &mut T, b: &mut T);

// Retourne le plus petit element d'un slice
fn find_min<T: PartialOrd + Copy>(slice: &[T]) -> Option<T>;

// Affiche un element qui implemente Display
fn print_labeled<T: std::fmt::Display>(label: &str, value: T);

// Retourne true si deux elements sont egaux (avec trait bound)
fn are_equal<T: PartialEq>(a: &T, b: &T) -> bool;
```

**Comportement attendu:**

1. `maximum(5, 3)` retourne `5`
2. `swap(&mut a, &mut b)` echange les valeurs de `a` et `b`
3. `find_min(&[3, 1, 4, 1, 5])` retourne `Some(1)`
4. `print_labeled("Value", 42)` affiche `Value: 42`
5. `are_equal(&"hello", &"hello")` retourne `true`

**Sortie attendue du main:**

```
=== Generic Functions Demo ===
maximum(10, 20) = 20
maximum(3.14, 2.71) = 3.14
After swap: a = world, b = hello
find_min([5, 2, 8, 1, 9]) = Some(1)
find_min([]) = None
Greeting: Hello, Generics!
are_equal(42, 42) = true
are_equal(1, 2) = false
```

### 1.3 Prototype

```rust
use std::fmt::Display;

fn maximum<T: PartialOrd>(a: T, b: T) -> T;
fn swap<T>(a: &mut T, b: &mut T);
fn find_min<T: PartialOrd + Copy>(slice: &[T]) -> Option<T>;
fn print_labeled<T: Display>(label: &str, value: T);
fn are_equal<T: PartialEq>(a: &T, b: &T) -> bool;

fn main();
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Monomorphisation

Rust utilise la **monomorphisation** pour les generiques: le compilateur genere une version concrete de la fonction pour chaque type utilise. Cela signifie zero cout a l'execution (zero-cost abstractions).

```rust
maximum(5i32, 3i32);    // Genere maximum_i32
maximum(5.0f64, 3.0f64); // Genere maximum_f64
```

### 2.2 Trait Bounds vs Where Clauses

```rust
// Syntaxe inline
fn foo<T: Display + Clone>(x: T) { }

// Syntaxe where (plus lisible pour bounds complexes)
fn bar<T>(x: T)
where
    T: Display + Clone
{ }
```

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Library Developer**

Les developpeurs de bibliotheques utilisent intensivement les generiques pour:
- Creer des containers (Vec, HashMap)
- Implementer des algorithmes reutilisables
- Ecrire du code zero-cost abstraction

**Metier : Systems Programmer**

Les programmeurs systeme utilisent les generiques pour:
- Abstraire sur les types d'entiers (i32, i64, usize)
- Creer des wrappers type-safe
- Ecrire des drivers generiques

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ rustc --edition 2024 generic_functions.rs
$ ./generic_functions
=== Generic Functions Demo ===
maximum(10, 20) = 20
maximum(3.14, 2.71) = 3.14
After swap: a = world, b = hello
find_min([5, 2, 8, 1, 9]) = Some(1)
find_min([]) = None
Greeting: Hello, Generics!
are_equal(42, 42) = true
are_equal(1, 2) = false
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★☆☆☆☆☆ (5/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Implementer une fonction generique avec plusieurs parametres de type:

```rust
// Convertit un type en un autre si Into est implemente
fn convert<T, U>(value: T) -> U
where
    T: Into<U>;

// Applique une fonction a une valeur et retourne le resultat
fn apply<T, U, F>(value: T, f: F) -> U
where
    F: FnOnce(T) -> U;
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Expected | Points |
|---------|-------------|----------|--------|
| T01 | Compilation sans warning | Success | 15 |
| T02 | maximum avec i32 | 20 pour (10, 20) | 15 |
| T03 | maximum avec f64 | 3.14 pour (3.14, 2.71) | 10 |
| T04 | swap fonctionne | Valeurs echangees | 15 |
| T05 | find_min slice non vide | Some(min) | 15 |
| T06 | find_min slice vide | None | 10 |
| T07 | print_labeled affiche correctement | Format correct | 10 |
| T08 | are_equal fonctionne | true/false correct | 10 |

### 4.2 Tests unitaires

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_maximum_integers() {
        assert_eq!(maximum(10, 20), 20);
        assert_eq!(maximum(20, 10), 20);
        assert_eq!(maximum(5, 5), 5);
    }

    #[test]
    fn test_maximum_floats() {
        assert_eq!(maximum(3.14, 2.71), 3.14);
        assert_eq!(maximum(-1.0, -2.0), -1.0);
    }

    #[test]
    fn test_swap() {
        let mut a = 10;
        let mut b = 20;
        swap(&mut a, &mut b);
        assert_eq!(a, 20);
        assert_eq!(b, 10);
    }

    #[test]
    fn test_swap_strings() {
        let mut a = String::from("hello");
        let mut b = String::from("world");
        swap(&mut a, &mut b);
        assert_eq!(a, "world");
        assert_eq!(b, "hello");
    }

    #[test]
    fn test_find_min() {
        assert_eq!(find_min(&[5, 2, 8, 1, 9]), Some(1));
        assert_eq!(find_min(&[42]), Some(42));
        assert_eq!(find_min::<i32>(&[]), None);
    }

    #[test]
    fn test_are_equal() {
        assert!(are_equal(&42, &42));
        assert!(!are_equal(&1, &2));
        assert!(are_equal(&"hello", &"hello"));
    }
}
```

### 4.3 Solution de reference

```rust
/*
 * generic_functions.rs
 * Generic functions demonstration
 * Exercice ex19_generic_functions
 */

use std::fmt::Display;

/// Returns the maximum of two values
fn maximum<T: PartialOrd>(a: T, b: T) -> T {
    if a >= b {
        a
    } else {
        b
    }
}

/// Swaps two values via mutable references
fn swap<T>(a: &mut T, b: &mut T) {
    std::mem::swap(a, b);
}

/// Finds the minimum element in a slice
fn find_min<T: PartialOrd + Copy>(slice: &[T]) -> Option<T> {
    if slice.is_empty() {
        return None;
    }

    let mut min = slice[0];
    for &item in &slice[1..] {
        if item < min {
            min = item;
        }
    }
    Some(min)
}

/// Prints a labeled value
fn print_labeled<T: Display>(label: &str, value: T) {
    println!("{}: {}", label, value);
}

/// Checks if two values are equal
fn are_equal<T: PartialEq>(a: &T, b: &T) -> bool {
    a == b
}

fn main() {
    println!("=== Generic Functions Demo ===");

    // maximum
    println!("maximum(10, 20) = {}", maximum(10, 20));
    println!("maximum(3.14, 2.71) = {}", maximum(3.14, 2.71));

    // swap
    let mut a = String::from("hello");
    let mut b = String::from("world");
    swap(&mut a, &mut b);
    println!("After swap: a = {}, b = {}", a, b);

    // find_min
    println!("find_min([5, 2, 8, 1, 9]) = {:?}", find_min(&[5, 2, 8, 1, 9]));
    println!("find_min([]) = {:?}", find_min::<i32>(&[]));

    // print_labeled
    print_labeled("Greeting", "Hello, Generics!");

    // are_equal
    println!("are_equal(42, 42) = {}", are_equal(&42, &42));
    println!("are_equal(1, 2) = {}", are_equal(&1, &2));
}
```

### 4.4 Solutions alternatives acceptees

```rust
// Alternative 1: swap sans std::mem::swap
fn swap<T>(a: &mut T, b: &mut T) {
    unsafe {
        let temp = std::ptr::read(a);
        std::ptr::copy_nonoverlapping(b, a, 1);
        std::ptr::write(b, temp);
    }
}

// Alternative 2: find_min avec iterateurs
fn find_min<T: PartialOrd + Copy>(slice: &[T]) -> Option<T> {
    slice.iter().copied().reduce(|a, b| if a < b { a } else { b })
}

// Alternative 3: maximum avec if let
fn maximum<T: PartialOrd>(a: T, b: T) -> T {
    if a > b { a } else { b }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```rust
// MUTANT 1 (Logic): Mauvaise comparaison dans maximum
fn maximum<T: PartialOrd>(a: T, b: T) -> T {
    if a <= b {  // ERREUR: devrait etre >=
        a
    } else {
        b
    }
}
// Detection: maximum(10, 20) retourne 10 au lieu de 20

// MUTANT 2 (Boundary): find_min ne gere pas slice vide
fn find_min<T: PartialOrd + Copy>(slice: &[T]) -> Option<T> {
    let mut min = slice[0];  // PANIC si vide!
    for &item in &slice[1..] {
        if item < min {
            min = item;
        }
    }
    Some(min)
}
// Detection: find_min(&[]) provoque un panic

// MUTANT 3 (Logic): swap incomplet
fn swap<T>(a: &mut T, b: &mut T) {
    let temp = std::mem::replace(a, unsafe { std::mem::zeroed() });
    *a = std::mem::replace(b, temp);
    // ERREUR: a n'a pas la bonne valeur
}
// Detection: swap ne fonctionne pas correctement

// MUTANT 4 (Trait): Trait bound manquant
fn find_min<T: Copy>(slice: &[T]) -> Option<T> {  // Manque PartialOrd!
    // Ne compile pas
}
// Detection: Erreur de compilation

// MUTANT 5 (Logic): are_equal inverse
fn are_equal<T: PartialEq>(a: &T, b: &T) -> bool {
    a != b  // ERREUR: devrait etre ==
}
// Detection: are_equal(42, 42) retourne false
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **fonctions generiques** permettent d'ecrire du code qui fonctionne avec plusieurs types:

1. **Type parameters** `<T>` - Placeholders pour les types concrets
2. **Trait bounds** `T: Trait` - Contraintes sur les capacites du type
3. **Monomorphisation** - Generation de code specialise pour chaque type

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION maximum<T>(a: T, b: T) -> T
    OU T implemente PartialOrd
DEBUT
    SI a >= b ALORS
        RETOURNER a
    SINON
        RETOURNER b
    FIN SI
FIN

FONCTION find_min<T>(slice: &[T]) -> Option<T>
    OU T implemente PartialOrd et Copy
DEBUT
    SI slice est vide ALORS
        RETOURNER None
    FIN SI

    min <- slice[0]
    POUR CHAQUE element DANS slice[1..] FAIRE
        SI element < min ALORS
            min <- element
        FIN SI
    FIN POUR
    RETOURNER Some(min)
FIN
```

### 5.3 Visualisation ASCII

```
                    Generic Function
                    +---------------+
                    | fn foo<T>(x:T)|
                    +-------+-------+
                            |
            +---------------+---------------+
            |               |               |
            v               v               v
    +-------+-------+ +-----+-----+ +-------+-------+
    | foo::<i32>    | | foo::<f64>| | foo::<String> |
    | (Specialized) | | (Special.)| | (Specialized) |
    +---------------+ +-----------+ +---------------+

    Monomorphisation: Une version par type utilise
```

### 5.4 Les pieges en detail

#### Piege 1: Oublier le trait bound

```rust
// ERREUR: T n'implemente pas forcement PartialOrd
fn maximum<T>(a: T, b: T) -> T {
    if a > b { a } else { b }  // Erreur de compilation!
}

// CORRECT
fn maximum<T: PartialOrd>(a: T, b: T) -> T {
    if a > b { a } else { b }
}
```

#### Piege 2: Trait bounds multiples

```rust
// Syntaxe avec +
fn foo<T: Display + Clone>(x: T) { }

// Syntaxe where pour plus de clarte
fn bar<T, U>(x: T, y: U)
where
    T: Display + Clone,
    U: Debug + Default,
{ }
```

#### Piege 3: Copy vs Clone dans les generiques

```rust
// Copy: copie bit a bit, implicite
fn double<T: Copy + std::ops::Add<Output = T>>(x: T) -> T {
    x + x  // x est copie, pas deplace
}

// Clone: clone explicite necessaire
fn duplicate<T: Clone>(x: T) -> (T, T) {
    (x.clone(), x)  // Clone explicite
}
```

### 5.5 Cours Complet

#### 5.5.1 Syntaxe des generiques

```rust
// Fonction generique simple
fn identity<T>(x: T) -> T {
    x
}

// Plusieurs parametres de type
fn pair<T, U>(first: T, second: U) -> (T, U) {
    (first, second)
}

// Avec trait bounds
fn print_twice<T: Display>(x: T) {
    println!("{}", x);
    println!("{}", x);
}
```

#### 5.5.2 Trait Bounds courants

| Trait | Utilisation |
|-------|-------------|
| `PartialOrd` | Comparaison (<, >, <=, >=) |
| `Ord` | Comparaison totale |
| `PartialEq` | Egalite (==, !=) |
| `Eq` | Egalite reflexive |
| `Clone` | Duplication explicite |
| `Copy` | Duplication implicite |
| `Display` | Affichage formatte |
| `Debug` | Affichage debug |
| `Default` | Valeur par defaut |

#### 5.5.3 Where Clauses

```rust
// Quand les bounds deviennent complexes
fn complex<T, U, V>(t: T, u: U, v: V) -> i32
where
    T: Display + Clone,
    U: Clone + Debug,
    V: Fn(T) -> U,
{
    // ...
}
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication |
|-------|-------------|
| `T` pour un seul type | Convention de nommage |
| `T, U, V` pour plusieurs | Ordre alphabetique |
| `where` pour bounds complexes | Lisibilite |
| Trait bounds minimaux | Flexibilite maximale |

### 5.7 Simulation avec trace d'execution

```
Appel: maximum(10i32, 20i32)

1. Compilateur detecte T = i32
2. Verifie: i32 implemente PartialOrd? OUI
3. Genere: fn maximum_i32(a: i32, b: i32) -> i32
4. Execute: 10 >= 20 ? NON
5. Retourne: 20

Appel: maximum(3.14f64, 2.71f64)

1. Compilateur detecte T = f64
2. Verifie: f64 implemente PartialOrd? OUI
3. Genere: fn maximum_f64(a: f64, b: f64) -> f64
4. Execute: 3.14 >= 2.71 ? OUI
5. Retourne: 3.14
```

### 5.8 Mnemotechniques

**"TRAIT BOUNDS = Contrat de capacites"**
- Le type DOIT pouvoir faire ce que le bound exige

**"<T> = Type To Be Determined"**
- Le type sera fixe a la compilation

**"Monomorphisation = Many versions, Zero cost"**
- Une version par type, performance native

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Oubli trait bound | Erreur compilation | Ajouter le bound requis |
| Copy vs Clone | Move inattendu | Utiliser le bon trait |
| Slice vide | Panic a l'acces | Verifier `is_empty()` |
| Bounds trop restrictifs | Code non reutilisable | Minimiser les bounds |

---

## SECTION 7 : QCM

### Question 1
Que signifie `<T: PartialOrd>` dans une signature de fonction?

A) T est un type partiel
B) T doit implementer le trait PartialOrd
C) T est optionnel
D) T est ordonne totalement
E) T peut etre null

**Reponse correcte: B**

### Question 2
Qu'est-ce que la monomorphisation?

A) Un pattern de design
B) La generation de code specialise pour chaque type
C) Une optimisation runtime
D) Un type de polymorphisme dynamique
E) Une technique de serialisation

**Reponse correcte: B**

### Question 3
Quelle syntaxe est equivalente a `fn foo<T: Display + Clone>(x: T)`?

A) `fn foo<T>(x: T) where T: Display, T: Clone`
B) `fn foo<T>(x: T) where T: Display + Clone`
C) `fn foo(x: impl Display + Clone)`
D) Toutes les reponses ci-dessus
E) Aucune des reponses ci-dessus

**Reponse correcte: D**

### Question 4
Pourquoi `find_min` requiert-il `T: Copy`?

A) Pour pouvoir comparer les elements
B) Pour pouvoir retourner une copie de l'element minimal
C) Pour eviter les allocations
D) C'est obligatoire pour tous les generiques
E) Pour la performance

**Reponse correcte: B**

### Question 5
Que se passe-t-il si on appelle `find_min` sur un slice vide avec la solution de reference?

A) Panic
B) Retourne Some(0)
C) Retourne None
D) Erreur de compilation
E) Comportement indefini

**Reponse correcte: C**

---

## SECTION 8 : RECAPITULATIF

| Concept | Description | Exemple |
|---------|-------------|---------|
| Type parameter | Placeholder pour type | `<T>` |
| Trait bound | Contrainte sur type | `T: Display` |
| Multiple bounds | Plusieurs contraintes | `T: Clone + Debug` |
| Where clause | Bounds lisibles | `where T: Display` |
| Monomorphisation | Specialisation compile-time | Zero-cost |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.8.19",
  "name": "generic_functions",
  "version": "1.0.0",
  "language": "rust",
  "language_version": "edition2024",
  "files": {
    "submission": ["generic_functions.rs"],
    "test": ["test_generic_functions.rs"]
  },
  "compilation": {
    "compiler": "rustc",
    "flags": ["--edition", "2024", "-W", "warnings"],
    "output": "generic_functions"
  },
  "tests": {
    "unit_tests": true,
    "output_match": true
  },
  "scoring": {
    "total": 100,
    "compilation": 15,
    "tests": 85
  },
  "concepts": ["generics", "type_parameters", "trait_bounds", "monomorphisation"]
}
```
