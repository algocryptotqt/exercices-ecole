# Exercice 0.7.16 : closures

**Module :**
0.7 — Introduction a Rust

**Concept :**
q — Closures : fonctions anonymes et capture

**Difficulte :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
code

**Tiers :**
2 — Combinaison de concepts

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.15 (iterators)
- Ownership et borrowing

**Domaines :**
Closures, Functional Programming

**Duree estimee :**
55 min

**XP Base :**
110

**Complexite :**
T0 O(1) × S0 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Rust | `src/lib.rs` |

---

### 1.2 Consigne

#### Section Culture : "Closures: Functions That Remember"

Les closures sont des fonctions anonymes qui peuvent capturer leur environnement. Rust infere automatiquement comment capturer (par reference, mutable, ou par valeur).

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des fonctions utilisant les closures :

1. `apply_fn` : appliquer une closure a une valeur
2. `create_adder` : retourner une closure
3. `filter_with` : filtrer avec une closure
4. `compose` : composer deux closures
5. Utiliser les traits Fn, FnMut, FnOnce

**Entree :**

```rust
// src/lib.rs

/// Applique une fonction a une valeur.
pub fn apply_fn<F, T, R>(value: T, f: F) -> R
where
    F: Fn(T) -> R,
{
    // A implementer
}

/// Cree une closure qui ajoute n.
pub fn create_adder(n: i32) -> impl Fn(i32) -> i32 {
    // A implementer
}

/// Cree une closure qui multiplie par n.
pub fn create_multiplier(n: i32) -> impl Fn(i32) -> i32 {
    // A implementer
}

/// Applique une closure et retourne le resultat modifie.
pub fn apply_mut<F>(mut value: i32, mut f: F) -> i32
where
    F: FnMut(&mut i32),
{
    // A implementer
}

/// Filtre un vecteur avec une closure.
pub fn filter_with<F>(numbers: &[i32], predicate: F) -> Vec<i32>
where
    F: Fn(&i32) -> bool,
{
    // A implementer
}

/// Compose deux closures: (f o g)(x) = f(g(x)).
pub fn compose<F, G>(f: F, g: G) -> impl Fn(i32) -> i32
where
    F: Fn(i32) -> i32,
    G: Fn(i32) -> i32,
{
    // A implementer
}

/// Execute une closure une fois (FnOnce).
pub fn call_once<F, T>(f: F) -> T
where
    F: FnOnce() -> T,
{
    // A implementer
}
```

**Sortie attendue :**

```
$ cargo test
running 7 tests
test tests::test_apply_fn ... ok
test tests::test_create_adder ... ok
test tests::test_create_multiplier ... ok
test tests::test_apply_mut ... ok
test tests::test_filter_with ... ok
test tests::test_compose ... ok
test tests::test_call_once ... ok

test result: ok. 7 passed; 0 failed
```

---

### 1.3 Prototype

```rust
pub fn apply_fn<F, T, R>(value: T, f: F) -> R where F: Fn(T) -> R;
pub fn create_adder(n: i32) -> impl Fn(i32) -> i32;
pub fn create_multiplier(n: i32) -> impl Fn(i32) -> i32;
pub fn apply_mut<F>(value: i32, f: F) -> i32 where F: FnMut(&mut i32);
pub fn filter_with<F>(numbers: &[i32], predicate: F) -> Vec<i32> where F: Fn(&i32) -> bool;
pub fn compose<F, G>(f: F, g: G) -> impl Fn(i32) -> i32 where F: Fn(i32) -> i32, G: Fn(i32) -> i32;
pub fn call_once<F, T>(f: F) -> T where F: FnOnce() -> T;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Trois traits Fn :**

```rust
FnOnce  // Peut etre appelee une fois (consomme les captures)
FnMut   // Peut etre appelee plusieurs fois (modifie les captures)
Fn      // Peut etre appelee plusieurs fois (emprunte les captures)

// Hierarchie: Fn : FnMut : FnOnce
// Fn est le plus restrictif
```

**Capture automatique :**

```rust
let x = 5;
let y = String::from("hello");

let f = || println!("{}", x);        // Capture x par ref (&x)
let g = || println!("{}", y);        // Capture y par ref (&y)
let h = move || println!("{}", y);   // Capture y par valeur (move)
```

**move keyword :**

```rust
let x = vec![1, 2, 3];
let f = move || x;  // x est move dans la closure
// x n'est plus utilisable ici
```

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo test
running 7 tests
...
test result: ok. 7 passed; 0 failed
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.3 Solution de reference (Rust)

```rust
pub fn apply_fn<F, T, R>(value: T, f: F) -> R
where
    F: Fn(T) -> R,
{
    f(value)
}

pub fn create_adder(n: i32) -> impl Fn(i32) -> i32 {
    move |x| x + n
}

pub fn create_multiplier(n: i32) -> impl Fn(i32) -> i32 {
    move |x| x * n
}

pub fn apply_mut<F>(mut value: i32, mut f: F) -> i32
where
    F: FnMut(&mut i32),
{
    f(&mut value);
    value
}

pub fn filter_with<F>(numbers: &[i32], predicate: F) -> Vec<i32>
where
    F: Fn(&i32) -> bool,
{
    numbers.iter().filter(|x| predicate(x)).copied().collect()
}

pub fn compose<F, G>(f: F, g: G) -> impl Fn(i32) -> i32
where
    F: Fn(i32) -> i32,
    G: Fn(i32) -> i32,
{
    move |x| f(g(x))
}

pub fn call_once<F, T>(f: F) -> T
where
    F: FnOnce() -> T,
{
    f()
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A : create_adder sans move**

```rust
pub fn create_adder(n: i32) -> impl Fn(i32) -> i32 {
    |x| x + n  // n est Copy, donc ca marche quand meme
}
// Note: Correct car i32 est Copy, mais move est plus explicite
```

**Mutant B : compose dans le mauvais ordre**

```rust
pub fn compose<F, G>(f: F, g: G) -> impl Fn(i32) -> i32
where
    F: Fn(i32) -> i32,
    G: Fn(i32) -> i32,
{
    move |x| g(f(x))  // g(f(x)) au lieu de f(g(x))!
}
// Pourquoi faux : Ordre de composition inverse
```

**Mutant C : apply_mut ne retourne pas**

```rust
pub fn apply_mut<F>(mut value: i32, mut f: F) -> i32
where
    F: FnMut(&mut i32),
{
    f(&mut value);
    0  // Retourne 0 au lieu de value!
}
// Pourquoi faux : Perd la valeur modifiee
```

**Mutant D : filter_with inverse la condition**

```rust
pub fn filter_with<F>(numbers: &[i32], predicate: F) -> Vec<i32>
where
    F: Fn(&i32) -> bool,
{
    numbers.iter().filter(|x| !predicate(x)).copied().collect()
}
// Pourquoi faux : Garde les elements qui ne matchent pas
```

**Mutant E : call_once appele deux fois**

```rust
pub fn call_once<F, T>(f: F) -> T
where
    F: FnOnce() -> T,
{
    let _ = f();  // Premier appel ignore
    f()           // ERREUR: f deja consomme!
}
// Pourquoi faux : FnOnce ne peut etre appele qu'une fois
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Closure | Fonction anonyme | Critique |
| Fn/FnMut/FnOnce | Traits de closure | Critique |
| move | Capture par valeur | Important |
| impl Trait | Type opaque | Important |

---

### 5.3 Visualisation ASCII

**Capture de variables :**

```
let x = 5;
let y = String::from("hi");

// Closure qui capture x et y
let f = || println!("{} {}", x, y);

Stack:
+------+     +------+
| x: 5 |     | f    |
+------+     +------+
| y ---+---->| captures:
| ptr  |     |   &x (ref)
| len  |     |   &y (ref)
| cap  |     +------+
+------+

Avec move:
let f = move || println!("{} {}", x, y);

+------+     +------+
| x: 5 |     | f    |
+------+     +------+
             | x: 5 (copie)
             | y: String (moved)
             +------+
```

**Hierarchie des traits Fn :**

```
         +----------+
         | FnOnce   |  Toutes les closures
         +----+-----+
              |
         +----+-----+
         | FnMut    |  Closures appelables plusieurs fois
         +----+-----+       (peut muter les captures)
              |
         +----+-----+
         |   Fn     |  Closures "pures"
         +----------+       (reference seulement)

Fn <: FnMut <: FnOnce
(Fn implemente FnMut qui implemente FnOnce)
```

---

### 5.5 Cours Complet

```rust
// Syntaxe de closure
let add_one = |x| x + 1;           // Type infere
let add_two = |x: i32| -> i32 { x + 2 };  // Type explicite

// Capture d'environnement
let factor = 2;
let multiply = |x| x * factor;     // Capture factor par ref

// move pour capturer par valeur
let s = String::from("hello");
let f = move || println!("{}", s); // s est move
// s n'est plus utilisable

// Traits Fn
fn takes_fn<F: Fn()>(f: F) { f(); f(); }      // Ref seulement
fn takes_fn_mut<F: FnMut()>(mut f: F) { f(); } // Peut muter
fn takes_fn_once<F: FnOnce()>(f: F) { f(); }   // Consomme

// impl Trait pour retourner des closures
fn make_closure() -> impl Fn(i32) -> i32 {
    |x| x + 1
}

// Box<dyn Fn> pour types dynamiques
fn make_dynamic() -> Box<dyn Fn(i32) -> i32> {
    Box::new(|x| x + 1)
}

// Closures comme arguments
vec.iter().map(|x| x * 2);
vec.iter().filter(|x| **x > 0);
vec.iter().fold(0, |acc, x| acc + x);
```

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Oublier move | Lifetime issues | Ajouter move si necessaire |
| 2 | Fn vs FnOnce | Impossible d'appeler 2x | Utiliser le bon trait |
| 3 | Mut sans FnMut | Ne compile pas | Utiliser FnMut |

---

## SECTION 7 : QCM

### Question 1 (4 points)
Quelle est la difference entre Fn et FnOnce ?

- A) Fn est plus rapide
- B) Fn peut etre appelee plusieurs fois, FnOnce une seule fois
- C) FnOnce capture par reference
- D) Aucune difference

**Reponse : B** — FnOnce consomme ses captures, Fn les emprunte.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.16 |
| **Nom** | closures |
| **Difficulte** | 6/10 |
| **Duree** | 55 min |
| **XP Base** | 110 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | closure, Fn, FnMut, FnOnce, move |
| **Prerequis** | iterators |
| **Domaines** | Closures, Functional Programming |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.16-closures",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.16",
      "exercise_name": "closures",
      "module": "0.7",
      "concept": "q",
      "concept_name": "Closures",
      "prerequisites": ["0.7.15"],
      "tags": ["closure", "fn", "fnmut", "fnonce", "move"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
