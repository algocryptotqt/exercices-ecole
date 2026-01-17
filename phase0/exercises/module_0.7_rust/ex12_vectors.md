# Exercice 0.7.12 : vectors

**Module :**
0.7 — Introduction a Rust

**Concept :**
m — Vectors : collections dynamiques

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.11 (result)
- Slices et references

**Domaines :**
Collections, Memory

**Duree estimee :**
45 min

**XP Base :**
90

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

#### Section Culture : "Vec: The Swiss Army Knife of Collections"

Vec<T> est le tableau dynamique de Rust. Contrairement aux arrays de taille fixe, un Vec peut grandir et retrecir. Il alloue sur le heap et gere automatiquement sa capacite.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des fonctions manipulant Vec<T> :

1. `create_vec` : creer un vecteur
2. `push_pop` : ajouter et retirer des elements
3. `sum_vec` : calculer la somme
4. `filter_even` : filtrer les nombres pairs
5. `reverse_vec` : inverser un vecteur

**Entree :**

```rust
// src/lib.rs

/// Cree un vecteur avec les elements donnes.
pub fn create_vec(elements: &[i32]) -> Vec<i32> {
    // A implementer
}

/// Ajoute un element a la fin.
pub fn push_element(vec: &mut Vec<i32>, elem: i32) {
    // A implementer
}

/// Retire et retourne le dernier element.
pub fn pop_element(vec: &mut Vec<i32>) -> Option<i32> {
    // A implementer
}

/// Calcule la somme des elements.
pub fn sum_vec(vec: &[i32]) -> i32 {
    // A implementer
}

/// Retourne un nouveau vecteur avec les nombres pairs.
pub fn filter_even(vec: &[i32]) -> Vec<i32> {
    // A implementer
}

/// Inverse le vecteur en place.
pub fn reverse_in_place(vec: &mut Vec<i32>) {
    // A implementer
}

/// Retourne un nouveau vecteur inverse.
pub fn reverse_vec(vec: &[i32]) -> Vec<i32> {
    // A implementer
}

/// Trouve l'element maximum.
pub fn find_max(vec: &[i32]) -> Option<i32> {
    // A implementer
}
```

**Sortie attendue :**

```
$ cargo test
running 8 tests
test tests::test_create_vec ... ok
test tests::test_push_element ... ok
test tests::test_pop_element ... ok
test tests::test_sum_vec ... ok
test tests::test_filter_even ... ok
test tests::test_reverse ... ok
test tests::test_find_max ... ok
...

test result: ok. 8 passed; 0 failed
```

---

### 1.3 Prototype

```rust
pub fn create_vec(elements: &[i32]) -> Vec<i32>;
pub fn push_element(vec: &mut Vec<i32>, elem: i32);
pub fn pop_element(vec: &mut Vec<i32>) -> Option<i32>;
pub fn sum_vec(vec: &[i32]) -> i32;
pub fn filter_even(vec: &[i32]) -> Vec<i32>;
pub fn reverse_in_place(vec: &mut Vec<i32>);
pub fn reverse_vec(vec: &[i32]) -> Vec<i32>;
pub fn find_max(vec: &[i32]) -> Option<i32>;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Vec vs Array :**

```rust
let arr: [i32; 3] = [1, 2, 3];  // Taille fixe, stack
let vec: Vec<i32> = vec![1, 2, 3];  // Taille variable, heap
```

**Capacite vs Longueur :**

```rust
let mut v = Vec::with_capacity(10);
v.push(1);
// v.len() = 1 (elements)
// v.capacity() = 10 (espace alloue)
```

**Macro vec! :**

```rust
let v1 = vec![1, 2, 3];        // Elements
let v2 = vec![0; 10];          // 10 zeros
let v3: Vec<i32> = Vec::new(); // Vide
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
pub fn create_vec(elements: &[i32]) -> Vec<i32> {
    elements.to_vec()
}

pub fn push_element(vec: &mut Vec<i32>, elem: i32) {
    vec.push(elem);
}

pub fn pop_element(vec: &mut Vec<i32>) -> Option<i32> {
    vec.pop()
}

pub fn sum_vec(vec: &[i32]) -> i32 {
    vec.iter().sum()
}

pub fn filter_even(vec: &[i32]) -> Vec<i32> {
    vec.iter().filter(|&&x| x % 2 == 0).copied().collect()
}

pub fn reverse_in_place(vec: &mut Vec<i32>) {
    vec.reverse();
}

pub fn reverse_vec(vec: &[i32]) -> Vec<i32> {
    vec.iter().rev().copied().collect()
}

pub fn find_max(vec: &[i32]) -> Option<i32> {
    vec.iter().copied().max()
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A : pop sans gestion du vide**

```rust
pub fn pop_element(vec: &mut Vec<i32>) -> Option<i32> {
    Some(vec.pop().unwrap())  // Panic si vide!
}
// Pourquoi faux : Panic sur vecteur vide
```

**Mutant B : sum avec overflow**

```rust
pub fn sum_vec(vec: &[i32]) -> i32 {
    let mut sum: i32 = 0;
    for x in vec {
        sum += x;  // Peut overflow en debug!
    }
    sum
}
// Note: Correct mais peut panic en debug mode
```

**Mutant C : filter_even inverse**

```rust
pub fn filter_even(vec: &[i32]) -> Vec<i32> {
    vec.iter().filter(|&&x| x % 2 != 0).copied().collect()
}
// Pourquoi faux : Filtre les impairs au lieu des pairs
```

**Mutant D : reverse_in_place ne modifie pas**

```rust
pub fn reverse_in_place(vec: &mut Vec<i32>) {
    let _ = vec.iter().rev().collect::<Vec<_>>();
    // Ne modifie pas vec!
}
// Pourquoi faux : vec reste inchange
```

**Mutant E : find_max retourne minimum**

```rust
pub fn find_max(vec: &[i32]) -> Option<i32> {
    vec.iter().copied().min()  // min au lieu de max!
}
// Pourquoi faux : Retourne le minimum
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Vec<T> | Collection dynamique | Critique |
| push/pop | Ajout/retrait elements | Critique |
| iter() | Iteration | Critique |
| Capacity | Gestion memoire | Important |

---

### 5.3 Visualisation ASCII

**Vec<i32> en memoire :**

```
Stack:                          Heap:
+------------------+           +---+---+---+---+---+---+
| ptr --------------+--------->| 1 | 2 | 3 |   |   |   |
| len: 3           |           +---+---+---+---+---+---+
| capacity: 6      |             0   1   2   3   4   5
+------------------+                       ^
                                          |
                            len=3 (utilise)
                            capacity=6 (alloue)
```

**Push et reallocation :**

```
Initial: capacity=4, len=3
+---+---+---+---+
| 1 | 2 | 3 |   |
+---+---+---+---+

Apres push(4): capacity=4, len=4
+---+---+---+---+
| 1 | 2 | 3 | 4 |
+---+---+---+---+

Apres push(5): REALLOCATION! capacity=8, len=5
+---+---+---+---+---+---+---+---+
| 1 | 2 | 3 | 4 | 5 |   |   |   |
+---+---+---+---+---+---+---+---+
```

---

### 5.5 Cours Complet

```rust
// Creation
let v1: Vec<i32> = Vec::new();
let v2 = vec![1, 2, 3];
let v3 = vec![0; 10];  // 10 zeros
let v4 = Vec::with_capacity(100);

// Modification
v.push(element);       // Ajoute a la fin
v.pop();               // Retire de la fin -> Option
v.insert(index, elem); // Insere a l'index
v.remove(index);       // Retire a l'index

// Acces
v[0]                   // Acces direct (panic si hors bornes)
v.get(0)               // Option<&T> (safe)
v.first()              // Option<&T>
v.last()               // Option<&T>

// Iteration
for x in &v { }        // Emprunte
for x in &mut v { }    // Emprunte mut
for x in v { }         // Consomme (move)

// Methodes utiles
v.len()                // Nombre d'elements
v.is_empty()           // len == 0
v.capacity()           // Espace alloue
v.clear()              // Vide le vecteur
v.reverse()            // Inverse en place
v.sort()               // Trie en place
```

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | v[i] hors bornes | Panic | Utiliser get(i) |
| 2 | pop() sur vide | Retourne None | Gerer Option |
| 3 | Iteration + modification | Borrow error | Utiliser indices ou drain |

---

## SECTION 7 : QCM

### Question 1 (4 points)
Quelle est la difference entre len() et capacity() ?

- A) Aucune difference
- B) len = elements stockes, capacity = espace alloue
- C) len = espace alloue, capacity = elements stockes
- D) len est deprecated

**Reponse : B** — len compte les elements, capacity l'espace reserve.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.12 |
| **Nom** | vectors |
| **Difficulte** | 4/10 |
| **Duree** | 45 min |
| **XP Base** | 90 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | Vec<T>, push, pop, iter, capacity |
| **Prerequis** | result |
| **Domaines** | Collections, Memory |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.12-vectors",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.12",
      "exercise_name": "vectors",
      "module": "0.7",
      "concept": "m",
      "concept_name": "Vectors",
      "prerequisites": ["0.7.11"],
      "tags": ["vec", "push", "pop", "iter", "collect"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
