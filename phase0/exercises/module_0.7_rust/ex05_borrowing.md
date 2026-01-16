# Exercice 0.7.5-a : borrowing

**Module :**
0.7.5 — Emprunt (Borrowing)

**Concept :**
a-d — &T, &mut T, borrow rules, multiple readers OR single writer

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
0.7.4 (ownership)

**Domaines :**
Algo, Memoire

**Duree estimee :**
150 min

**XP Base :**
220

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `src/lib.rs`

### 1.2 Consigne

Implementer des fonctions demonstrant les regles d'emprunt Rust.

**Ta mission :**

```rust
// Emprunt immutable: lecture seule
fn print_length(s: &String) -> usize;

// Emprunt mutable: modification
fn append_exclaim(s: &mut String);

// Plusieurs emprunts immutables simultanes
fn compare_strings(s1: &String, s2: &String) -> bool;

// Calcul sur reference
fn sum_array(arr: &[i32]) -> i32;

// Modification d'un element
fn double_first(arr: &mut [i32]);

// Retourner une reference vers le max
fn find_max(arr: &[i32]) -> Option<&i32>;

// Modifier et retourner reference
fn push_and_get_last(vec: &mut Vec<i32>, val: i32) -> &i32;
```

**Comportement:**

1. `print_length(&s)` -> longueur de s, s reste valide
2. `append_exclaim(&mut s)` -> ajoute "!" a s
3. `sum_array(&[1,2,3])` -> 6
4. `find_max(&[1,5,3])` -> Some(&5)

**Exemples:**
```rust
let s = String::from("hello");
println!("{}", print_length(&s));  // 5
println!("{}", s);  // s toujours valide

let mut s2 = String::from("hi");
append_exclaim(&mut s2);
println!("{}", s2);  // "hi!"

let arr = [1, 2, 3, 4, 5];
println!("{}", sum_array(&arr));  // 15

let mut arr2 = [10, 20, 30];
double_first(&mut arr2);
// arr2 = [20, 20, 30]
```

### 1.3 Prototype

```rust
// src/lib.rs

pub fn print_length(s: &String) -> usize {
    todo!()
}

pub fn append_exclaim(s: &mut String) {
    todo!()
}

pub fn compare_strings(s1: &String, s2: &String) -> bool {
    todo!()
}

pub fn sum_array(arr: &[i32]) -> i32 {
    todo!()
}

pub fn double_first(arr: &mut [i32]) {
    todo!()
}

pub fn find_max(arr: &[i32]) -> Option<&i32> {
    todo!()
}

pub fn push_and_get_last(vec: &mut Vec<i32>, val: i32) -> &i32 {
    todo!()
}
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | print_length | correct len | 10 |
| T02 | append_exclaim | modified | 15 |
| T03 | compare_strings | correct bool | 10 |
| T04 | sum_array | correct sum | 15 |
| T05 | double_first | first doubled | 15 |
| T06 | find_max Some | correct ref | 15 |
| T07 | find_max None | None | 10 |
| T08 | push_and_get_last | correct ref | 10 |

### 4.3 Solution de reference

```rust
pub fn print_length(s: &String) -> usize {
    s.len()  // Emprunte s en lecture
}

pub fn append_exclaim(s: &mut String) {
    s.push('!');  // Emprunte s en ecriture
}

pub fn compare_strings(s1: &String, s2: &String) -> bool {
    // Deux emprunts immutables simultanes OK
    s1 == s2
}

pub fn sum_array(arr: &[i32]) -> i32 {
    // &[i32] est un slice, emprunt immutable
    arr.iter().sum()
}

pub fn double_first(arr: &mut [i32]) {
    if !arr.is_empty() {
        arr[0] *= 2;  // Modification via emprunt mutable
    }
}

pub fn find_max(arr: &[i32]) -> Option<&i32> {
    // Retourne une reference vers l'element max
    arr.iter().max()
}

pub fn push_and_get_last(vec: &mut Vec<i32>, val: i32) -> &i32 {
    vec.push(val);
    // Retourne reference vers le dernier element
    vec.last().unwrap()
}
```

### 4.10 Solutions Mutantes

```rust
// MUTANT 1: Tente de modifier via emprunt immutable
pub fn print_length(s: &String) -> usize {
    s.push('x');  // ERREUR: cannot borrow as mutable
    s.len()
}

// MUTANT 2: Deux emprunts mutables simultanes
pub fn bad_double_swap(arr: &mut [i32]) {
    let first = &mut arr[0];
    let second = &mut arr[1];  // ERREUR: cannot borrow twice
    std::mem::swap(first, second);
}

// MUTANT 3: Retourne reference vers variable locale
pub fn bad_find_max(arr: &[i32]) -> Option<&i32> {
    let max = *arr.iter().max()?;
    Some(&max)  // ERREUR: returns reference to local
}

// MUTANT 4: Use after move
pub fn bad_append(s: &mut String) {
    let s2 = s;  // Move!
    s.push('!');  // ERREUR: borrow of moved value
}

// MUTANT 5: Emprunt mutable puis immutable
pub fn bad_push_and_read(vec: &mut Vec<i32>, val: i32) -> i32 {
    let last_ref = vec.last();  // Immutable borrow
    vec.push(val);  // ERREUR: mutable borrow while immutable exists
    *last_ref.unwrap()
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

L'**emprunt (borrowing)** en Rust:

1. **&T** - Reference immutable (lecture seule)
2. **&mut T** - Reference mutable (lecture/ecriture)
3. **Regle fondamentale** - Plusieurs &T OU un seul &mut T
4. **Lifetime** - Les references ne peuvent pas survivre a leur source

### 5.3 Visualisation ASCII

```
OWNERSHIP VS BORROWING:

Ownership (move):
let s1 = String::from("hi");
let s2 = s1;  // s1 moved to s2
// s1 invalide!

   s1        s2
  [X]  -->  [ptr] --> "hi"
(invalid)

Borrowing (&):
let s1 = String::from("hi");
let s2 = &s1;  // s2 emprunte s1
// s1 et s2 valides

   s1         s2
  [ptr] <--- [&]
    |
    v
   "hi"

REGLES D'EMPRUNT:

OK: Plusieurs lecteurs
let r1 = &data;
let r2 = &data;
let r3 = &data;  // Tous OK

ERREUR: Lecteur + Ecrivain
let r1 = &data;
let r2 = &mut data;  // ERREUR!

ERREUR: Plusieurs ecrivains
let r1 = &mut data;
let r2 = &mut data;  // ERREUR!
```

### 5.5 Analogie du bibliothecaire

```
Emprunt immutable (&T):
- Tu peux consulter le livre a la bibliotheque
- D'autres peuvent aussi le consulter en meme temps
- Personne ne peut l'emporter ou le modifier

Emprunt mutable (&mut T):
- Tu empruntes le livre chez toi
- Tu peux le modifier (prendre des notes)
- Personne d'autre ne peut y acceder pendant ce temps
- Tu dois le rendre avant que d'autres puissent l'utiliser
```

---

## SECTION 7 : QCM

### Question 1
Combien de references mutables peut-on avoir simultanement ?

A) 0
B) 1
C) 2
D) Autant qu'on veut
E) Depend du type

**Reponse correcte: B**

### Question 2
Peut-on avoir &T et &mut T en meme temps ?

A) Oui, toujours
B) Non, jamais
C) Seulement dans unsafe
D) Seulement en lecture
E) Depend de la taille

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.7.5-a",
  "name": "borrowing",
  "language": "rust",
  "language_version": "edition2024",
  "files": ["src/lib.rs"],
  "tests": {
    "immutable": "borrowing_immutable_tests",
    "mutable": "borrowing_mutable_tests",
    "slices": "slice_borrowing_tests"
  }
}
```
