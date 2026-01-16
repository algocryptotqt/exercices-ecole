# Exercice 0.7.6-a : slices

**Module :**
0.7.6 — Slices

**Concept :**
a-d — &[T], &str, slice operations, range syntax

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
0.7.5 (borrowing)

**Domaines :**
Algo, Memoire

**Duree estimee :**
150 min

**XP Base :**
220

**Complexite :**
T2 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `src/lib.rs`

### 1.2 Consigne

Implementer des fonctions manipulant les slices.

**Ta mission :**

```rust
// Obtenir le premier mot d'une chaine
fn first_word(s: &str) -> &str;

// Obtenir une sous-slice
fn middle_elements(arr: &[i32]) -> &[i32];

// Trouver le premier element negatif
fn find_negative(arr: &[i32]) -> Option<&i32>;

// Somme d'une portion
fn sum_range(arr: &[i32], start: usize, end: usize) -> i32;

// Verifier si slice est triee
fn is_sorted(arr: &[i32]) -> bool;

// Trouver le minimum et maximum
fn min_max(arr: &[i32]) -> Option<(&i32, &i32)>;

// Separer une chaine en deux parties
fn split_at_char(s: &str, c: char) -> (&str, &str);
```

**Comportement:**

1. `first_word("hello world")` -> "hello"
2. `middle_elements(&[1,2,3,4,5])` -> &[2,3,4]
3. `is_sorted(&[1,2,3])` -> true
4. `min_max(&[3,1,4,1,5])` -> Some((&1, &5))

**Exemples:**
```rust
let s = "hello beautiful world";
println!("{}", first_word(s));  // "hello"

let arr = [1, 2, 3, 4, 5];
let mid = middle_elements(&arr);  // [2, 3, 4]

let neg = find_negative(&[1, -2, 3]);  // Some(&-2)

let (before, after) = split_at_char("key=value", '=');
// before = "key", after = "value"
```

### 1.3 Prototype

```rust
// src/lib.rs

pub fn first_word(s: &str) -> &str {
    todo!()
}

pub fn middle_elements(arr: &[i32]) -> &[i32] {
    todo!()
}

pub fn find_negative(arr: &[i32]) -> Option<&i32> {
    todo!()
}

pub fn sum_range(arr: &[i32], start: usize, end: usize) -> i32 {
    todo!()
}

pub fn is_sorted(arr: &[i32]) -> bool {
    todo!()
}

pub fn min_max(arr: &[i32]) -> Option<(&i32, &i32)> {
    todo!()
}

pub fn split_at_char(s: &str, c: char) -> (&str, &str) {
    todo!()
}
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | first_word simple | first word | 15 |
| T02 | first_word no space | full string | 10 |
| T03 | middle_elements | correct slice | 15 |
| T04 | find_negative found | Some(&neg) | 10 |
| T05 | find_negative none | None | 10 |
| T06 | is_sorted true | true | 10 |
| T07 | min_max | correct tuple | 15 |
| T08 | split_at_char | correct parts | 15 |

### 4.3 Solution de reference

```rust
pub fn first_word(s: &str) -> &str {
    // Trouver le premier espace
    match s.find(' ') {
        Some(pos) => &s[..pos],
        None => s,  // Pas d'espace, retourner tout
    }
}

pub fn middle_elements(arr: &[i32]) -> &[i32] {
    if arr.len() <= 2 {
        return &[];
    }
    &arr[1..arr.len() - 1]
}

pub fn find_negative(arr: &[i32]) -> Option<&i32> {
    arr.iter().find(|&&x| x < 0)
}

pub fn sum_range(arr: &[i32], start: usize, end: usize) -> i32 {
    if start >= arr.len() || end > arr.len() || start >= end {
        return 0;
    }
    arr[start..end].iter().sum()
}

pub fn is_sorted(arr: &[i32]) -> bool {
    arr.windows(2).all(|w| w[0] <= w[1])
}

pub fn min_max(arr: &[i32]) -> Option<(&i32, &i32)> {
    if arr.is_empty() {
        return None;
    }

    let min = arr.iter().min()?;
    let max = arr.iter().max()?;
    Some((min, max))
}

pub fn split_at_char(s: &str, c: char) -> (&str, &str) {
    match s.find(c) {
        Some(pos) => (&s[..pos], &s[pos + c.len_utf8()..]),
        None => (s, ""),
    }
}
```

### 4.10 Solutions Mutantes

```rust
// MUTANT 1: first_word retourne index au lieu de slice
pub fn first_word(s: &str) -> usize {
    // Retourne la position, pas le slice
    s.find(' ').unwrap_or(s.len())
}

// MUTANT 2: middle_elements off-by-one
pub fn middle_elements(arr: &[i32]) -> &[i32] {
    &arr[1..arr.len()]  // Inclut le dernier element!
}

// MUTANT 3: find_negative retourne copie
pub fn find_negative(arr: &[i32]) -> Option<i32> {
    arr.iter().find(|&&x| x < 0).copied()
    // Retourne valeur, pas reference
}

// MUTANT 4: is_sorted strict
pub fn is_sorted(arr: &[i32]) -> bool {
    arr.windows(2).all(|w| w[0] < w[1])
    // < au lieu de <=, echoue sur [1, 1, 2]
}

// MUTANT 5: split_at_char oublie de skip le separateur
pub fn split_at_char(s: &str, c: char) -> (&str, &str) {
    match s.find(c) {
        Some(pos) => (&s[..pos], &s[pos..]),  // Inclut le separateur!
        None => (s, ""),
    }
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **slices** en Rust:

1. **&[T]** - Reference vers une portion de tableau
2. **&str** - Slice de caracteres UTF-8 (string slice)
3. **Range syntax** - arr[1..4], arr[..3], arr[2..]
4. **Zero-cost** - Pas de copie, juste pointeur + longueur

### 5.3 Visualisation ASCII

```
SLICE STRUCTURE:

let arr = [10, 20, 30, 40, 50];
let slice = &arr[1..4];

arr:   [10, 20, 30, 40, 50]
         ^   ^   ^
         |   |   |
slice:  [ptr     ]  len=3
         |
         +-> 20

STRING SLICE:

let s = String::from("hello world");
let word = &s[0..5];

s: [ptr] -> h e l l o   w o r l d
    |       ^     ^
    |       |     |
word:      [ptr]  len=5
            |
            +-> "hello"

RANGE SYNTAX:
[1..4]   -> indices 1, 2, 3
[..3]    -> indices 0, 1, 2
[2..]    -> indices 2 jusqu'a la fin
[..]     -> tous les indices
[1..=4]  -> indices 1, 2, 3, 4 (inclusif)
```

### 5.5 String vs &str

```rust
// String: owned, mutable, heap-allocated
let mut s = String::from("hello");
s.push_str(" world");  // OK

// &str: borrowed, immutable, peut etre sur stack ou heap
let slice: &str = "hello";  // String literal, static
let slice2: &str = &s[..];  // Borrow de String

// Conversion
let s: String = slice.to_string();
let s: String = String::from(slice);
let slice: &str = &s;  // Deref coercion
```

---

## SECTION 7 : QCM

### Question 1
Que represente &[i32] ?

A) Un pointeur vers un i32
B) Un tableau de taille fixe
C) Une reference vers une portion de tableau
D) Un Vec<i32>
E) Un iterateur

**Reponse correcte: C**

### Question 2
Quelle est la difference entre String et &str ?

A) String est plus rapide
B) String est owned, &str est borrowed
C) &str peut etre modifie
D) Il n'y a pas de difference
E) String est pour ASCII seulement

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.7.6-a",
  "name": "slices",
  "language": "rust",
  "language_version": "edition2024",
  "files": ["src/lib.rs"],
  "tests": {
    "string_slices": "str_slice_tests",
    "array_slices": "array_slice_tests"
  }
}
```
