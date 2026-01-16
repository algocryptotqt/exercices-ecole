# Exercice 0.7.12-a : vectors

**Module :**
0.7.12 — Vec<T>

**Concept :**
a-e — push, pop, len, capacity, iter, slice conversion

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
0.7.11 (result)

**Domaines :**
Algo, Structures

**Duree estimee :**
150 min

**XP Base :**
220

**Complexite :**
T2 O(n) x S2 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `src/lib.rs`

### 1.2 Consigne

Implementer des fonctions manipulant les vecteurs.

**Ta mission :**

```rust
// Creer un vecteur avec elements
pub fn create_vec(elements: &[i32]) -> Vec<i32>;

// Ajouter un element et retourner la nouvelle longueur
pub fn push_and_len(vec: &mut Vec<i32>, value: i32) -> usize;

// Retirer le dernier element
pub fn pop_last(vec: &mut Vec<i32>) -> Option<i32>;

// Filtrer les elements pairs
pub fn filter_even(vec: &[i32]) -> Vec<i32>;

// Doubler tous les elements
pub fn double_all(vec: &[i32]) -> Vec<i32>;

// Somme des elements
pub fn sum_vec(vec: &[i32]) -> i32;

// Trouver l'index d'un element
pub fn find_index(vec: &[i32], target: i32) -> Option<usize>;

// Concatener deux vecteurs
pub fn concat_vecs(v1: &[i32], v2: &[i32]) -> Vec<i32>;

// Inverser un vecteur
pub fn reverse_vec(vec: &[i32]) -> Vec<i32>;

// Supprimer les doublons
pub fn remove_duplicates(vec: &[i32]) -> Vec<i32>;
```

**Comportement:**

1. `filter_even(&[1, 2, 3, 4])` -> [2, 4]
2. `double_all(&[1, 2, 3])` -> [2, 4, 6]
3. `find_index(&[10, 20, 30], 20)` -> Some(1)
4. `remove_duplicates(&[1, 2, 2, 3, 1])` -> [1, 2, 3]

**Exemples:**
```rust
let mut vec = create_vec(&[1, 2, 3]);
push_and_len(&mut vec, 4);  // vec = [1, 2, 3, 4], returns 4

let even = filter_even(&vec);
println!("{:?}", even);  // [2, 4]

let doubled = double_all(&vec);
println!("{:?}", doubled);  // [2, 4, 6, 8]

println!("{}", sum_vec(&vec));  // 10
```

### 1.3 Prototype

```rust
// src/lib.rs

pub fn create_vec(elements: &[i32]) -> Vec<i32> {
    todo!()
}

pub fn push_and_len(vec: &mut Vec<i32>, value: i32) -> usize {
    todo!()
}

pub fn pop_last(vec: &mut Vec<i32>) -> Option<i32> {
    todo!()
}

pub fn filter_even(vec: &[i32]) -> Vec<i32> {
    todo!()
}

pub fn double_all(vec: &[i32]) -> Vec<i32> {
    todo!()
}

pub fn sum_vec(vec: &[i32]) -> i32 {
    todo!()
}

pub fn find_index(vec: &[i32], target: i32) -> Option<usize> {
    todo!()
}

pub fn concat_vecs(v1: &[i32], v2: &[i32]) -> Vec<i32> {
    todo!()
}

pub fn reverse_vec(vec: &[i32]) -> Vec<i32> {
    todo!()
}

pub fn remove_duplicates(vec: &[i32]) -> Vec<i32> {
    todo!()
}
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | create_vec | correct | 5 |
| T02 | push_and_len | length | 10 |
| T03 | pop_last | Some/None | 10 |
| T04 | filter_even | evens only | 15 |
| T05 | double_all | doubled | 10 |
| T06 | sum_vec | sum | 10 |
| T07 | find_index | Some/None | 15 |
| T08 | concat_vecs | combined | 10 |
| T09 | remove_duplicates | unique | 15 |

### 4.3 Solution de reference

```rust
pub fn create_vec(elements: &[i32]) -> Vec<i32> {
    elements.to_vec()
}

pub fn push_and_len(vec: &mut Vec<i32>, value: i32) -> usize {
    vec.push(value);
    vec.len()
}

pub fn pop_last(vec: &mut Vec<i32>) -> Option<i32> {
    vec.pop()
}

pub fn filter_even(vec: &[i32]) -> Vec<i32> {
    vec.iter().filter(|&&n| n % 2 == 0).copied().collect()
}

pub fn double_all(vec: &[i32]) -> Vec<i32> {
    vec.iter().map(|&n| n * 2).collect()
}

pub fn sum_vec(vec: &[i32]) -> i32 {
    vec.iter().sum()
}

pub fn find_index(vec: &[i32], target: i32) -> Option<usize> {
    vec.iter().position(|&n| n == target)
}

pub fn concat_vecs(v1: &[i32], v2: &[i32]) -> Vec<i32> {
    let mut result = v1.to_vec();
    result.extend(v2);
    result
}

pub fn reverse_vec(vec: &[i32]) -> Vec<i32> {
    vec.iter().rev().copied().collect()
}

pub fn remove_duplicates(vec: &[i32]) -> Vec<i32> {
    let mut seen = std::collections::HashSet::new();
    vec.iter()
        .filter(|&&n| seen.insert(n))
        .copied()
        .collect()
}
```

### 4.10 Solutions Mutantes

```rust
// MUTANT 1: filter_even avec mauvaise condition
pub fn filter_even(vec: &[i32]) -> Vec<i32> {
    vec.iter().filter(|&&n| n % 2 != 0).copied().collect()
    // Retourne les impairs!
}

// MUTANT 2: double_all modifie en place (ne compile pas)
pub fn double_all(vec: &[i32]) -> Vec<i32> {
    for n in vec.iter_mut() {  // Erreur: vec est &[i32], pas &mut
        *n *= 2;
    }
    vec.to_vec()
}

// MUTANT 3: find_index off-by-one
pub fn find_index(vec: &[i32], target: i32) -> Option<usize> {
    vec.iter().position(|&n| n == target).map(|i| i + 1)
    // Retourne index+1
}

// MUTANT 4: concat_vecs ordre inverse
pub fn concat_vecs(v1: &[i32], v2: &[i32]) -> Vec<i32> {
    let mut result = v2.to_vec();
    result.extend(v1);  // v2 puis v1, ordre inverse
    result
}

// MUTANT 5: remove_duplicates garde le dernier
pub fn remove_duplicates(vec: &[i32]) -> Vec<i32> {
    let mut seen = std::collections::HashSet::new();
    vec.iter()
        .rev()  // Parcourt a l'envers, garde le dernier au lieu du premier
        .filter(|&&n| seen.insert(n))
        .copied()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

**Vec<T>** - Le tableau dynamique de Rust:

1. **Heap-allocated** - Donnees sur le tas
2. **Growable** - Peut grandir automatiquement
3. **Generic** - Vec<T> pour tout type T
4. **Ownership** - Possede ses elements

### 5.3 Visualisation ASCII

```
VEC MEMORY LAYOUT:

let v: Vec<i32> = vec![1, 2, 3];

Stack:              Heap:
+----------+        +---+---+---+---+---+
| ptr      | -----> | 1 | 2 | 3 | ? | ? |
+----------+        +---+---+---+---+---+
| len: 3   |          ^         ^
+----------+          |         |
| cap: 5   |         len=3    cap=5
+----------+

GROWTH (push):
v.push(4);

Stack:              Heap:
+----------+        +---+---+---+---+---+
| ptr      | -----> | 1 | 2 | 3 | 4 | ? |
+----------+        +---+---+---+---+---+
| len: 4   |
| cap: 5   |

v.push(5);
v.push(6);  // Depasse capacity!

Stack:              Heap (new allocation):
+----------+        +---+---+---+---+---+---+---+---+---+---+
| ptr      | -----> | 1 | 2 | 3 | 4 | 5 | 6 | ? | ? | ? | ? |
+----------+        +---+---+---+---+---+---+---+---+---+---+
| len: 6   |
| cap: 10  |        (capacity doubled)
```

### 5.5 Vec vs slice

```rust
// Vec<T>: owned, mutable, heap
let mut vec: Vec<i32> = vec![1, 2, 3];
vec.push(4);  // OK

// &[T]: borrowed slice, immutable view
let slice: &[i32] = &vec[..];
// slice.push(4);  // Erreur!

// &mut [T]: mutable slice, peut modifier elements
let slice_mut: &mut [i32] = &mut vec[..];
slice_mut[0] = 10;  // OK
// slice_mut.push(4);  // Erreur! Ne peut pas changer la taille

// Conversion
let vec: Vec<i32> = slice.to_vec();  // Copie
let slice: &[i32] = &vec;            // Borrow (deref coercion)
```

---

## SECTION 7 : QCM

### Question 1
Que se passe-t-il quand Vec depasse sa capacite ?

A) Erreur de compilation
B) Panic
C) Reallocation avec plus de capacite
D) Les elements sont perdus
E) Rien

**Reponse correcte: C**

### Question 2
Quelle est la difference entre Vec<T> et &[T] ?

A) Pas de difference
B) Vec est owned et growable, &[T] est borrowed
C) &[T] est plus rapide
D) Vec est sur la stack
E) &[T] est mutable

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.7.12-a",
  "name": "vectors",
  "language": "rust",
  "language_version": "edition2024",
  "files": ["src/lib.rs"],
  "tests": {
    "basic": "vec_basic_tests",
    "manipulation": "vec_manipulation_tests",
    "iteration": "vec_iteration_tests"
  }
}
```
