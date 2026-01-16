# Exercice 0.7.14-a : iterators

**Module :**
0.7.14 — Iterateurs

**Concept :**
a-e — iter(), map, filter, fold, collect, Iterator trait

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
0.7.13 (hashmaps)

**Domaines :**
Algo, Fonctionnel

**Duree estimee :**
180 min

**XP Base :**
250

**Complexite :**
T2 O(n) x S1 O(1) lazy

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `src/lib.rs`

### 1.2 Consigne

Implementer des fonctions utilisant les iterateurs.

**Ta mission :**

```rust
// Doubler tous les elements
pub fn double_all(nums: &[i32]) -> Vec<i32>;

// Filtrer les pairs et les doubler
pub fn filter_and_double(nums: &[i32]) -> Vec<i32>;

// Somme avec fold
pub fn sum_fold(nums: &[i32]) -> i32;

// Produit avec fold
pub fn product_fold(nums: &[i32]) -> i32;

// Trouver le premier superieur a n
pub fn find_greater_than(nums: &[i32], n: i32) -> Option<i32>;

// Prendre les n premiers
pub fn take_first(nums: &[i32], n: usize) -> Vec<i32>;

// Sauter les n premiers
pub fn skip_first(nums: &[i32], n: usize) -> Vec<i32>;

// Chainer deux slices
pub fn chain_slices(a: &[i32], b: &[i32]) -> Vec<i32>;

// Zip deux slices
pub fn zip_sum(a: &[i32], b: &[i32]) -> Vec<i32>;

// Compter les elements satisfaisant un predicat
pub fn count_positive(nums: &[i32]) -> usize;

// any/all
pub fn has_negative(nums: &[i32]) -> bool;
pub fn all_positive(nums: &[i32]) -> bool;
```

**Comportement:**

1. `double_all(&[1, 2, 3])` -> [2, 4, 6]
2. `filter_and_double(&[1, 2, 3, 4])` -> [4, 8]
3. `sum_fold(&[1, 2, 3])` -> 6
4. `find_greater_than(&[1, 5, 3], 2)` -> Some(5)
5. `zip_sum(&[1, 2], &[3, 4])` -> [4, 6]

**Exemples:**
```rust
let nums = vec![1, 2, 3, 4, 5];

println!("{:?}", double_all(&nums));  // [2, 4, 6, 8, 10]
println!("{:?}", filter_and_double(&nums));  // [4, 8]
println!("{}", sum_fold(&nums));  // 15
println!("{:?}", take_first(&nums, 3));  // [1, 2, 3]
println!("{}", has_negative(&[-1, 2, 3]));  // true
println!("{}", all_positive(&[1, 2, 3]));  // true
```

### 1.3 Prototype

```rust
// src/lib.rs

pub fn double_all(nums: &[i32]) -> Vec<i32> {
    todo!()
}

pub fn filter_and_double(nums: &[i32]) -> Vec<i32> {
    todo!()
}

pub fn sum_fold(nums: &[i32]) -> i32 {
    todo!()
}

pub fn product_fold(nums: &[i32]) -> i32 {
    todo!()
}

pub fn find_greater_than(nums: &[i32], n: i32) -> Option<i32> {
    todo!()
}

pub fn take_first(nums: &[i32], n: usize) -> Vec<i32> {
    todo!()
}

pub fn skip_first(nums: &[i32], n: usize) -> Vec<i32> {
    todo!()
}

pub fn chain_slices(a: &[i32], b: &[i32]) -> Vec<i32> {
    todo!()
}

pub fn zip_sum(a: &[i32], b: &[i32]) -> Vec<i32> {
    todo!()
}

pub fn count_positive(nums: &[i32]) -> usize {
    todo!()
}

pub fn has_negative(nums: &[i32]) -> bool {
    todo!()
}

pub fn all_positive(nums: &[i32]) -> bool {
    todo!()
}
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | double_all | doubled | 10 |
| T02 | filter_and_double | filtered doubled | 10 |
| T03 | sum_fold | sum | 10 |
| T04 | find_greater_than | correct | 10 |
| T05 | take/skip | correct | 10 |
| T06 | chain_slices | combined | 10 |
| T07 | zip_sum | element-wise | 15 |
| T08 | count_positive | count | 10 |
| T09 | any/all | correct | 15 |

### 4.3 Solution de reference

```rust
pub fn double_all(nums: &[i32]) -> Vec<i32> {
    nums.iter().map(|&n| n * 2).collect()
}

pub fn filter_and_double(nums: &[i32]) -> Vec<i32> {
    nums.iter()
        .filter(|&&n| n % 2 == 0)
        .map(|&n| n * 2)
        .collect()
}

pub fn sum_fold(nums: &[i32]) -> i32 {
    nums.iter().fold(0, |acc, &n| acc + n)
    // Equivalent: nums.iter().sum()
}

pub fn product_fold(nums: &[i32]) -> i32 {
    nums.iter().fold(1, |acc, &n| acc * n)
    // Equivalent: nums.iter().product()
}

pub fn find_greater_than(nums: &[i32], n: i32) -> Option<i32> {
    nums.iter().find(|&&x| x > n).copied()
}

pub fn take_first(nums: &[i32], n: usize) -> Vec<i32> {
    nums.iter().take(n).copied().collect()
}

pub fn skip_first(nums: &[i32], n: usize) -> Vec<i32> {
    nums.iter().skip(n).copied().collect()
}

pub fn chain_slices(a: &[i32], b: &[i32]) -> Vec<i32> {
    a.iter().chain(b.iter()).copied().collect()
}

pub fn zip_sum(a: &[i32], b: &[i32]) -> Vec<i32> {
    a.iter().zip(b.iter()).map(|(&x, &y)| x + y).collect()
}

pub fn count_positive(nums: &[i32]) -> usize {
    nums.iter().filter(|&&n| n > 0).count()
}

pub fn has_negative(nums: &[i32]) -> bool {
    nums.iter().any(|&n| n < 0)
}

pub fn all_positive(nums: &[i32]) -> bool {
    nums.iter().all(|&n| n > 0)
}
```

### 4.10 Solutions Mutantes

```rust
// MUTANT 1: filter_and_double filtre apres double
pub fn filter_and_double(nums: &[i32]) -> Vec<i32> {
    nums.iter()
        .map(|&n| n * 2)
        .filter(|&n| n % 2 == 0)  // Filtre apres, tous pairs!
        .collect()
}

// MUTANT 2: product_fold initialise a 0
pub fn product_fold(nums: &[i32]) -> i32 {
    nums.iter().fold(0, |acc, &n| acc * n)  // Toujours 0!
}

// MUTANT 3: find_greater_than ne copie pas
pub fn find_greater_than(nums: &[i32], n: i32) -> Option<&i32> {
    nums.iter().find(|&&x| x > n)
    // Retourne reference, pas valeur
}

// MUTANT 4: zip_sum tronque silencieusement
pub fn zip_sum(a: &[i32], b: &[i32]) -> Vec<i32> {
    // zip s'arrete au plus court, potentiellement unexpected
    a.iter().zip(b.iter()).map(|(&x, &y)| x + y).collect()
}

// MUTANT 5: all_positive avec >= au lieu de >
pub fn all_positive(nums: &[i32]) -> bool {
    nums.iter().all(|&n| n >= 0)  // Accepte 0!
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **iterateurs** Rust:

1. **Lazy evaluation** - Ne calcule que quand necessaire
2. **Zero-cost abstraction** - Aussi rapide que boucles manuelles
3. **Composabilite** - Chainer map, filter, fold
4. **Ownership** - iter() vs into_iter() vs iter_mut()

### 5.3 Visualisation ASCII

```
ITERATOR CHAIN:

[1, 2, 3, 4, 5]
    |
    | .iter()
    v
Iterator<Item=&i32>
    |
    | .filter(|&&n| n % 2 == 0)
    v
Iterator<Item=&i32> (lazy, pas encore filtre)
    |
    | .map(|&n| n * 2)
    v
Iterator<Item=i32> (lazy, pas encore mappe)
    |
    | .collect()
    v
Vec<i32> = [4, 8]  (maintenant tout est evalue)

LAZY EVALUATION:

let iter = vec![1,2,3].iter().map(|n| {
    println!("Processing {}", n);
    n * 2
});
// Rien n'est affiche!

let result: Vec<_> = iter.collect();
// Maintenant: "Processing 1", "Processing 2", "Processing 3"

OWNERSHIP:
vec.iter()       -> Iterator<Item=&T>     (borrow)
vec.iter_mut()   -> Iterator<Item=&mut T> (borrow mut)
vec.into_iter()  -> Iterator<Item=T>      (ownership)
```

---

## SECTION 7 : QCM

### Question 1
Quand les elements sont-ils traites dans un iterateur ?

A) A la creation de l'iterateur
B) A chaque appel de map/filter
C) Quand collect() ou autre consommateur est appele
D) Au premier element
E) Jamais

**Reponse correcte: C**

### Question 2
Quelle est la difference entre iter() et into_iter() ?

A) Pas de difference
B) iter() emprunte, into_iter() prend l'ownership
C) into_iter() est plus rapide
D) iter() est deprecated
E) into_iter() ne fonctionne que sur Vec

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.7.14-a",
  "name": "iterators",
  "language": "rust",
  "language_version": "edition2024",
  "files": ["src/lib.rs"],
  "tests": {
    "basic": "iterator_basic_tests",
    "combinators": "combinator_tests",
    "lazy": "lazy_evaluation_tests"
  }
}
```
