# Exercice 0.7.15-a : closures

**Module :**
0.7.15 — Closures

**Concept :**
a-e — |x| x+1, Fn/FnMut/FnOnce, move, capturing environment

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
0.7.14 (iterators)

**Domaines :**
Algo, Fonctionnel

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

Implementer des fonctions utilisant des closures.

**Ta mission :**

```rust
// Appliquer une closure a chaque element
pub fn apply_to_all<F>(nums: &[i32], f: F) -> Vec<i32>
where
    F: Fn(i32) -> i32;

// Filtrer avec une closure
pub fn filter_with<F>(nums: &[i32], predicate: F) -> Vec<i32>
where
    F: Fn(&i32) -> bool;

// Creer un compteur (closure avec etat)
pub fn make_counter() -> impl FnMut() -> i32;

// Creer un additionneur
pub fn make_adder(n: i32) -> impl Fn(i32) -> i32;

// Composer deux fonctions
pub fn compose<F, G>(f: F, g: G) -> impl Fn(i32) -> i32
where
    F: Fn(i32) -> i32,
    G: Fn(i32) -> i32;

// Appliquer n fois
pub fn apply_n_times<F>(f: F, x: i32, n: usize) -> i32
where
    F: Fn(i32) -> i32;

// Fold avec closure
pub fn fold_with<F>(nums: &[i32], init: i32, f: F) -> i32
where
    F: Fn(i32, i32) -> i32;
```

**Comportement:**

1. `apply_to_all(&[1,2,3], |x| x * 2)` -> [2, 4, 6]
2. `filter_with(&[1,2,3,4], |&x| x > 2)` -> [3, 4]
3. `let mut counter = make_counter(); counter()` -> 1, puis 2, puis 3
4. `make_adder(5)(10)` -> 15
5. `compose(|x| x + 1, |x| x * 2)(3)` -> 8 ((3+1)*2)

**Exemples:**
```rust
let doubled = apply_to_all(&[1, 2, 3], |x| x * 2);
println!("{:?}", doubled);  // [2, 4, 6]

let adder = make_adder(10);
println!("{}", adder(5));   // 15
println!("{}", adder(100)); // 110

let mut counter = make_counter();
println!("{}", counter());  // 1
println!("{}", counter());  // 2
println!("{}", counter());  // 3

let f = compose(|x| x + 1, |x| x * 2);
println!("{}", f(3));  // 8
```

### 1.3 Prototype

```rust
// src/lib.rs

pub fn apply_to_all<F>(nums: &[i32], f: F) -> Vec<i32>
where
    F: Fn(i32) -> i32,
{
    todo!()
}

pub fn filter_with<F>(nums: &[i32], predicate: F) -> Vec<i32>
where
    F: Fn(&i32) -> bool,
{
    todo!()
}

pub fn make_counter() -> impl FnMut() -> i32 {
    todo!()
}

pub fn make_adder(n: i32) -> impl Fn(i32) -> i32 {
    todo!()
}

pub fn compose<F, G>(f: F, g: G) -> impl Fn(i32) -> i32
where
    F: Fn(i32) -> i32,
    G: Fn(i32) -> i32,
{
    todo!()
}

pub fn apply_n_times<F>(f: F, x: i32, n: usize) -> i32
where
    F: Fn(i32) -> i32,
{
    todo!()
}

pub fn fold_with<F>(nums: &[i32], init: i32, f: F) -> i32
where
    F: Fn(i32, i32) -> i32,
{
    todo!()
}
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | apply_to_all | mapped | 15 |
| T02 | filter_with | filtered | 15 |
| T03 | make_counter | increments | 15 |
| T04 | make_adder | adds | 15 |
| T05 | compose | composed | 15 |
| T06 | apply_n_times | correct | 10 |
| T07 | fold_with | folded | 15 |

### 4.3 Solution de reference

```rust
pub fn apply_to_all<F>(nums: &[i32], f: F) -> Vec<i32>
where
    F: Fn(i32) -> i32,
{
    nums.iter().map(|&n| f(n)).collect()
}

pub fn filter_with<F>(nums: &[i32], predicate: F) -> Vec<i32>
where
    F: Fn(&i32) -> bool,
{
    nums.iter().filter(|n| predicate(n)).copied().collect()
}

pub fn make_counter() -> impl FnMut() -> i32 {
    let mut count = 0;
    move || {
        count += 1;
        count
    }
}

pub fn make_adder(n: i32) -> impl Fn(i32) -> i32 {
    move |x| x + n
}

pub fn compose<F, G>(f: F, g: G) -> impl Fn(i32) -> i32
where
    F: Fn(i32) -> i32,
    G: Fn(i32) -> i32,
{
    move |x| g(f(x))
}

pub fn apply_n_times<F>(f: F, x: i32, n: usize) -> i32
where
    F: Fn(i32) -> i32,
{
    let mut result = x;
    for _ in 0..n {
        result = f(result);
    }
    result
}

pub fn fold_with<F>(nums: &[i32], init: i32, f: F) -> i32
where
    F: Fn(i32, i32) -> i32,
{
    nums.iter().fold(init, |acc, &n| f(acc, n))
}
```

### 4.10 Solutions Mutantes

```rust
// MUTANT 1: make_counter sans move
pub fn make_counter() -> impl FnMut() -> i32 {
    let mut count = 0;
    || {  // Manque move!
        count += 1;
        count
    }
    // Erreur de compilation: count ne survit pas
}

// MUTANT 2: compose dans le mauvais ordre
pub fn compose<F, G>(f: F, g: G) -> impl Fn(i32) -> i32
where
    F: Fn(i32) -> i32,
    G: Fn(i32) -> i32,
{
    move |x| f(g(x))  // g puis f, au lieu de f puis g
}

// MUTANT 3: apply_n_times off-by-one
pub fn apply_n_times<F>(f: F, x: i32, n: usize) -> i32
where
    F: Fn(i32) -> i32,
{
    let mut result = x;
    for _ in 0..=n {  // <= au lieu de <, applique n+1 fois
        result = f(result);
    }
    result
}

// MUTANT 4: filter_with ne copie pas
pub fn filter_with<F>(nums: &[i32], predicate: F) -> Vec<&i32>
where
    F: Fn(&i32) -> bool,
{
    nums.iter().filter(|n| predicate(n)).collect()
    // Retourne Vec<&i32> au lieu de Vec<i32>
}

// MUTANT 5: make_adder capture par reference
pub fn make_adder(n: i32) -> impl Fn(i32) -> i32 + '_ {
    |x| x + n  // Sans move, tente de capturer par reference
    // Probleme de lifetime
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **closures** en Rust:

1. **Syntaxe** - |args| expression ou |args| { body }
2. **Capture** - Peut capturer des variables de l'environnement
3. **Traits** - Fn (read), FnMut (modify), FnOnce (consume)
4. **move** - Force la capture par valeur (ownership)

### 5.3 Visualisation ASCII

```
CLOSURE TRAITS:

FnOnce: Peut etre appelee une fois (consomme les captures)
   |
   +-- FnMut: Peut etre appelee plusieurs fois (modifie captures)
          |
          +-- Fn: Peut etre appelee plusieurs fois (read-only captures)

CAPTURE MODES:

let s = String::from("hello");

// Capture par reference (&s)
let closure1 = || println!("{}", s);
// s peut encore etre utilise apres

// Capture par reference mutable (&mut s)
let mut closure2 = || s.push_str("!");
// s ne peut pas etre utilise pendant closure2 existe

// Capture par valeur (move s)
let closure3 = move || println!("{}", s);
// s est maintenant owned par closure3

EXEMPLE DE COUNTER:

fn make_counter() -> impl FnMut() -> i32 {
    let mut count = 0;  // Variable locale
    move || {           // move: prend ownership de count
        count += 1;     // Modifie count (FnMut)
        count
    }
}

let mut c = make_counter();
// c possede count (= 0)
c();  // count devient 1, retourne 1
c();  // count devient 2, retourne 2
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la difference entre Fn, FnMut et FnOnce ?

A) Pas de difference
B) Fn read-only, FnMut modifie, FnOnce consomme
C) FnOnce est le plus restrictif
D) Fn est deprecated
E) FnMut ne peut etre appele qu'une fois

**Reponse correcte: B**

### Question 2
A quoi sert le mot-cle `move` devant une closure ?

A) Deplacer la closure
B) Forcer la capture par valeur (ownership)
C) Rendre la closure plus rapide
D) Permettre la mutation
E) Rien

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.7.15-a",
  "name": "closures",
  "language": "rust",
  "language_version": "edition2024",
  "files": ["src/lib.rs"],
  "tests": {
    "basic": "closure_basic_tests",
    "capture": "capture_tests",
    "higher_order": "higher_order_tests"
  }
}
```
