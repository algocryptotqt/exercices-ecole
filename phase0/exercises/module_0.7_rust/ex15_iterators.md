# Exercice 0.7.15 : iterators

**Module :**
0.7 — Introduction a Rust

**Concept :**
p — Iterators : iter, map, filter, collect

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.12 (vectors)
- Option et Result

**Domaines :**
Iterators, Functional Programming

**Duree estimee :**
50 min

**XP Base :**
100

**Complexite :**
T1 O(n) × S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Rust | `src/lib.rs` |

---

### 1.2 Consigne

#### Section Culture : "Iterators: Lazy Evaluation Done Right"

Les iterateurs Rust sont lazy - ils ne calculent rien tant qu'on ne consomme pas. Cela permet de chainer les operations sans allocation intermediaire.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des fonctions utilisant les iterateurs :

1. `double_all` : doubler chaque element
2. `filter_positive` : garder les positifs
3. `sum_squares` : somme des carres
4. `find_first_match` : trouver le premier element
5. `flatten_nested` : aplatir des vecteurs imbriques

**Entree :**

```rust
// src/lib.rs

/// Double chaque element.
pub fn double_all(numbers: &[i32]) -> Vec<i32> {
    // A implementer avec map
}

/// Garde uniquement les nombres positifs.
pub fn filter_positive(numbers: &[i32]) -> Vec<i32> {
    // A implementer avec filter
}

/// Calcule la somme des carres.
pub fn sum_squares(numbers: &[i32]) -> i32 {
    // A implementer avec map et sum
}

/// Trouve le premier nombre > seuil.
pub fn find_first_above(numbers: &[i32], threshold: i32) -> Option<i32> {
    // A implementer avec find
}

/// Aplatit un vecteur de vecteurs.
pub fn flatten_nested(nested: Vec<Vec<i32>>) -> Vec<i32> {
    // A implementer avec flatten
}

/// Compte les elements satisfaisant une condition.
pub fn count_matching<F>(numbers: &[i32], predicate: F) -> usize
where
    F: Fn(&i32) -> bool,
{
    // A implementer avec filter et count
}

/// Prend les n premiers elements.
pub fn take_first(numbers: &[i32], n: usize) -> Vec<i32> {
    // A implementer avec take
}

/// Saute les n premiers elements.
pub fn skip_first(numbers: &[i32], n: usize) -> Vec<i32> {
    // A implementer avec skip
}
```

**Sortie attendue :**

```
$ cargo test
running 8 tests
test tests::test_double_all ... ok
test tests::test_filter_positive ... ok
test tests::test_sum_squares ... ok
test tests::test_find_first_above ... ok
test tests::test_flatten_nested ... ok
test tests::test_count_matching ... ok
test tests::test_take_first ... ok
test tests::test_skip_first ... ok

test result: ok. 8 passed; 0 failed
```

---

### 1.3 Prototype

```rust
pub fn double_all(numbers: &[i32]) -> Vec<i32>;
pub fn filter_positive(numbers: &[i32]) -> Vec<i32>;
pub fn sum_squares(numbers: &[i32]) -> i32;
pub fn find_first_above(numbers: &[i32], threshold: i32) -> Option<i32>;
pub fn flatten_nested(nested: Vec<Vec<i32>>) -> Vec<i32>;
pub fn count_matching<F>(numbers: &[i32], predicate: F) -> usize where F: Fn(&i32) -> bool;
pub fn take_first(numbers: &[i32], n: usize) -> Vec<i32>;
pub fn skip_first(numbers: &[i32], n: usize) -> Vec<i32>;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Lazy vs Eager :**

```rust
// Lazy - rien ne se passe
let iter = vec![1, 2, 3].iter().map(|x| {
    println!("Processing {}", x);  // Jamais execute!
    x * 2
});

// Eager - execution au collect
let result: Vec<_> = iter.collect();  // Maintenant ca s'execute
```

**Iterator trait :**

```rust
pub trait Iterator {
    type Item;
    fn next(&mut self) -> Option<Self::Item>;
    // + 70+ methodes par defaut!
}
```

**Chaines efficaces :**

```rust
// Une seule passe sur les donnees
numbers.iter()
    .filter(|x| **x > 0)
    .map(|x| x * 2)
    .sum::<i32>()
```

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo test
running 8 tests
...
test result: ok. 8 passed; 0 failed
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.3 Solution de reference (Rust)

```rust
pub fn double_all(numbers: &[i32]) -> Vec<i32> {
    numbers.iter().map(|x| x * 2).collect()
}

pub fn filter_positive(numbers: &[i32]) -> Vec<i32> {
    numbers.iter().filter(|&&x| x > 0).copied().collect()
}

pub fn sum_squares(numbers: &[i32]) -> i32 {
    numbers.iter().map(|x| x * x).sum()
}

pub fn find_first_above(numbers: &[i32], threshold: i32) -> Option<i32> {
    numbers.iter().find(|&&x| x > threshold).copied()
}

pub fn flatten_nested(nested: Vec<Vec<i32>>) -> Vec<i32> {
    nested.into_iter().flatten().collect()
}

pub fn count_matching<F>(numbers: &[i32], predicate: F) -> usize
where
    F: Fn(&i32) -> bool,
{
    numbers.iter().filter(|x| predicate(x)).count()
}

pub fn take_first(numbers: &[i32], n: usize) -> Vec<i32> {
    numbers.iter().take(n).copied().collect()
}

pub fn skip_first(numbers: &[i32], n: usize) -> Vec<i32> {
    numbers.iter().skip(n).copied().collect()
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A : map sans collect**

```rust
pub fn double_all(numbers: &[i32]) -> Vec<i32> {
    numbers.iter().map(|x| x * 2);  // Retourne Map, pas Vec!
    vec![]
}
// Pourquoi faux : Iterator non consomme, retourne vide
```

**Mutant B : filter >= au lieu de >**

```rust
pub fn filter_positive(numbers: &[i32]) -> Vec<i32> {
    numbers.iter().filter(|&&x| x >= 0).copied().collect()
}
// Pourquoi faux : Inclut zero qui n'est pas positif
```

**Mutant C : sum sans map**

```rust
pub fn sum_squares(numbers: &[i32]) -> i32 {
    numbers.iter().sum()  // Somme simple, pas des carres!
}
// Pourquoi faux : Ne calcule pas les carres
```

**Mutant D : find retourne le dernier**

```rust
pub fn find_first_above(numbers: &[i32], threshold: i32) -> Option<i32> {
    numbers.iter().filter(|&&x| x > threshold).last().copied()
}
// Pourquoi faux : Retourne le dernier, pas le premier
```

**Mutant E : flatten sans into_iter**

```rust
pub fn flatten_nested(nested: Vec<Vec<i32>>) -> Vec<i32> {
    nested.iter().flatten().copied().collect()
    // Fonctionne mais moins efficace
}
// Note: Correct mais avec copies supplementaires
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| iter() | Creer un iterateur | Critique |
| map | Transformer | Critique |
| filter | Filtrer | Critique |
| collect | Consumer | Critique |

---

### 5.3 Visualisation ASCII

**Pipeline d'iterateur :**

```
Source         map(|x| x*2)     filter(|x| x>5)    collect()
   |               |                 |                |
   v               v                 v                v
[1,2,3,4,5]  [2,4,6,8,10]       [6,8,10]          Vec<i32>
   |               |                 |                |
   +----lazy-------+------lazy-------+----eager-------+
                                                      ^
                                          Execution ici!
```

**Types d'iterateurs :**

```rust
vec.iter()       // Iterator<Item = &T>      (emprunte)
vec.iter_mut()   // Iterator<Item = &mut T>  (emprunte mut)
vec.into_iter()  // Iterator<Item = T>       (consomme)
```

**Adaptateurs vs Consommateurs :**

```
Adaptateurs (lazy):        Consommateurs (eager):
  .map()                     .collect()
  .filter()                  .sum()
  .take()                    .count()
  .skip()                    .find()
  .flatten()                 .for_each()
  .enumerate()               .fold()
  .zip()                     .any() / .all()
```

---

### 5.5 Cours Complet

```rust
// Creation d'iterateurs
let iter = vec.iter();           // &T
let iter = vec.iter_mut();       // &mut T
let iter = vec.into_iter();      // T (consomme)
let iter = (0..10);              // Range
let iter = (0..=10);             // RangeInclusive

// Adaptateurs (transforment l'iterateur)
iter.map(|x| x * 2)              // Transforme chaque element
iter.filter(|x| condition)        // Garde si true
iter.take(n)                      // Prend n premiers
iter.skip(n)                      // Saute n premiers
iter.enumerate()                  // (index, value)
iter.zip(other)                   // Combine deux iterateurs
iter.flatten()                    // Aplatit les iterables
iter.chain(other)                 // Concatene
iter.rev()                        // Inverse (si DoubleEnded)

// Consommateurs (executent l'iterateur)
iter.collect::<Vec<_>>()          // Collecte dans une collection
iter.sum::<i32>()                 // Somme
iter.product::<i32>()             // Produit
iter.count()                      // Nombre d'elements
iter.find(|x| condition)          // Premier match -> Option
iter.any(|x| condition)           // Au moins un true?
iter.all(|x| condition)           // Tous true?
iter.fold(init, |acc, x| ...)     // Reduction
iter.for_each(|x| ...)            // Execute pour effet
```

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Oublier collect | Iterator non consomme | Ajouter .collect() |
| 2 | iter() vs into_iter() | Emprunt vs ownership | Choisir selon besoin |
| 3 | Double reference &&x | Confusion | filter(|&&x| ...) |

---

## SECTION 7 : QCM

### Question 1 (4 points)
Pourquoi les iterateurs Rust sont-ils "lazy" ?

- A) Pour etre plus lents
- B) Pour eviter les allocations intermediaires
- C) Pour la compatibilite C
- D) Pour le multithreading

**Reponse : B** — Lazy permet d'eviter d'allouer des vecteurs intermediaires.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.15 |
| **Nom** | iterators |
| **Difficulte** | 5/10 |
| **Duree** | 50 min |
| **XP Base** | 100 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | iter, map, filter, collect, lazy |
| **Prerequis** | vectors |
| **Domaines** | Iterators, Functional Programming |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.15-iterators",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.15",
      "exercise_name": "iterators",
      "module": "0.7",
      "concept": "p",
      "concept_name": "Iterators",
      "prerequisites": ["0.7.12"],
      "tags": ["iter", "map", "filter", "collect", "lazy"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
