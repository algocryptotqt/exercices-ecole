# Exercice 0.7.6 : slices

**Module :**
0.7 — Introduction a Rust

**Concept :**
g — Slices : vues sur les donnees contigues

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.5 (borrowing)
- Comprehension des references

**Domaines :**
Slices, Memory

**Duree estimee :**
40 min

**XP Base :**
85

**Complexite :**
T1 O(n) × S0 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Rust | `src/lib.rs` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Rust | Toutes les fonctions de la bibliotheque standard |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Rust | `unsafe` |

---

### 1.2 Consigne

#### Section Culture : "A Slice of Life"

Les slices sont des "vues" sur des portions de donnees contigues. Elles ne possedent pas les donnees, elles les referencent. C'est comme regarder un morceau d'un tableau sans le copier.

Le type &[T] est un "fat pointer" : il contient un pointeur vers le debut ET une longueur. C'est different de &T qui est juste un pointeur.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des fonctions manipulant des slices :

1. `first_n` : retourne les n premiers elements d'une slice
2. `last_n` : retourne les n derniers elements d'une slice
3. `middle` : retourne les elements du milieu (sans premier ni dernier)
4. `sum_slice` : calcule la somme des elements d'une slice
5. `find_in_slice` : trouve l'index d'un element

**Entree :**

```rust
// src/lib.rs

/// Retourne les n premiers elements d'une slice.
///
/// # Arguments
///
/// * `slice` - La slice source
/// * `n` - Le nombre d'elements a prendre
///
/// # Returns
///
/// Une slice contenant les n premiers elements (ou moins si slice plus courte)
///
/// # Example
///
/// ```
/// let arr = [1, 2, 3, 4, 5];
/// let first = slices::first_n(&arr, 3);
/// assert_eq!(first, &[1, 2, 3]);
/// ```
pub fn first_n<T>(slice: &[T], n: usize) -> &[T] {
    // A implementer
}

/// Retourne les n derniers elements d'une slice.
pub fn last_n<T>(slice: &[T], n: usize) -> &[T] {
    // A implementer
}

/// Retourne les elements du milieu (sans le premier ni le dernier).
pub fn middle<T>(slice: &[T]) -> &[T] {
    // A implementer
}

/// Calcule la somme des elements d'une slice d'entiers.
pub fn sum_slice(slice: &[i32]) -> i32 {
    // A implementer
}

/// Trouve l'index d'un element dans une slice.
pub fn find_in_slice<T: PartialEq>(slice: &[T], target: &T) -> Option<usize> {
    // A implementer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_n() {
        // A implementer
    }
}
```

**Sortie attendue :**

```
$ cargo test
running 5 tests
test tests::test_first_n ... ok
test tests::test_last_n ... ok
test tests::test_middle ... ok
test tests::test_sum_slice ... ok
test tests::test_find_in_slice ... ok

test result: ok. 5 passed; 0 failed
```

**Contraintes :**
- Ne pas panic si n > len (retourner ce qui est disponible)
- middle sur slice de 0, 1 ou 2 elements retourne slice vide
- Utiliser la syntaxe slice [start..end]

**Exemples :**

| Fonction | Input | Output |
|----------|-------|--------|
| `first_n(&[1,2,3,4,5], 3)` | - | `&[1,2,3]` |
| `first_n(&[1,2], 5)` | - | `&[1,2]` |
| `last_n(&[1,2,3,4,5], 2)` | - | `&[4,5]` |
| `middle(&[1,2,3])` | - | `&[2]` |
| `middle(&[1])` | - | `&[]` |
| `sum_slice(&[1,2,3])` | - | `6` |
| `find_in_slice(&[1,2,3], &2)` | - | `Some(1)` |

---

### 1.3 Prototype

```rust
pub fn first_n<T>(slice: &[T], n: usize) -> &[T];
pub fn last_n<T>(slice: &[T], n: usize) -> &[T];
pub fn middle<T>(slice: &[T]) -> &[T];
pub fn sum_slice(slice: &[i32]) -> i32;
pub fn find_in_slice<T: PartialEq>(slice: &[T], target: &T) -> Option<usize>;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Fat Pointer :**

Une slice &[T] est un "fat pointer" de 16 octets (sur 64-bit) :
- 8 octets : pointeur vers les donnees
- 8 octets : longueur

**String slice &str :**

&str est en fait &[u8] avec la garantie d'etre du UTF-8 valide. C'est pour ca qu'on ne peut pas indexer par caractere directement.

**Deref coercion :**

Vec<T> implemente Deref<Target = [T]>, donc &Vec<T> peut etre automatiquement converti en &[T].

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Data Engineer** | Traitement de chunks de donnees |
| **Game Dev** | Rendu de portions de meshes |
| **Crypto** | Manipulation de blocs de bytes |
| **Audio/Video** | Buffers de frames |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo new slices --lib
     Created library `slices` package

$ cd slices

$ cargo test
running 5 tests
test tests::test_first_n ... ok
test tests::test_last_n ... ok
test tests::test_middle ... ok
test tests::test_sum_slice ... ok
test tests::test_find_in_slice ... ok

test result: ok. 5 passed; 0 failed
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | first_n_basic | `[1,2,3,4,5], 3` | `[1,2,3]` | 10 | Basic |
| 2 | first_n_overflow | `[1,2], 5` | `[1,2]` | 10 | Edge |
| 3 | first_n_zero | `[1,2,3], 0` | `[]` | 5 | Edge |
| 4 | last_n_basic | `[1,2,3,4,5], 2` | `[4,5]` | 10 | Basic |
| 5 | last_n_overflow | `[1,2], 5` | `[1,2]` | 10 | Edge |
| 6 | middle_basic | `[1,2,3,4,5]` | `[2,3,4]` | 15 | Basic |
| 7 | middle_small | `[1]` | `[]` | 10 | Edge |
| 8 | sum_basic | `[1,2,3,4,5]` | `15` | 10 | Basic |
| 9 | sum_empty | `[]` | `0` | 5 | Edge |
| 10 | find_found | `[1,2,3], 2` | `Some(1)` | 10 | Basic |
| 11 | find_not | `[1,2,3], 9` | `None` | 5 | Edge |

**Total : 100 points**

---

### 4.2 Tests de la moulinette

```rust
#[cfg(test)]
mod moulinette_tests {
    use super::*;

    #[test]
    fn test_first_n_basic() {
        let arr = [1, 2, 3, 4, 5];
        assert_eq!(first_n(&arr, 3), &[1, 2, 3]);
    }

    #[test]
    fn test_first_n_overflow() {
        let arr = [1, 2];
        assert_eq!(first_n(&arr, 5), &[1, 2]);
    }

    #[test]
    fn test_last_n_basic() {
        let arr = [1, 2, 3, 4, 5];
        assert_eq!(last_n(&arr, 2), &[4, 5]);
    }

    #[test]
    fn test_middle_basic() {
        let arr = [1, 2, 3, 4, 5];
        assert_eq!(middle(&arr), &[2, 3, 4]);
    }

    #[test]
    fn test_middle_small() {
        let arr: [i32; 1] = [1];
        assert_eq!(middle(&arr), &[]);
    }

    #[test]
    fn test_sum_basic() {
        let arr = [1, 2, 3, 4, 5];
        assert_eq!(sum_slice(&arr), 15);
    }

    #[test]
    fn test_find_found() {
        let arr = [10, 20, 30];
        assert_eq!(find_in_slice(&arr, &20), Some(1));
    }

    #[test]
    fn test_find_not() {
        let arr = [10, 20, 30];
        assert_eq!(find_in_slice(&arr, &99), None);
    }
}
```

---

### 4.3 Solution de reference (Rust)

```rust
/// Retourne les n premiers elements.
pub fn first_n<T>(slice: &[T], n: usize) -> &[T] {
    let end = n.min(slice.len());
    &slice[..end]
}

/// Retourne les n derniers elements.
pub fn last_n<T>(slice: &[T], n: usize) -> &[T] {
    let start = slice.len().saturating_sub(n);
    &slice[start..]
}

/// Retourne les elements du milieu.
pub fn middle<T>(slice: &[T]) -> &[T] {
    if slice.len() <= 2 {
        &[]
    } else {
        &slice[1..slice.len() - 1]
    }
}

/// Somme des elements.
pub fn sum_slice(slice: &[i32]) -> i32 {
    slice.iter().sum()
}

/// Trouve l'index d'un element.
pub fn find_in_slice<T: PartialEq>(slice: &[T], target: &T) -> Option<usize> {
    slice.iter().position(|x| x == target)
}
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : Panic sur overflow**

```rust
// REFUSE : Panic si n > len
pub fn first_n<T>(slice: &[T], n: usize) -> &[T] {
    &slice[..n]  // Panic si n > slice.len()
}
```
**Pourquoi refuse :** Doit gerer n > len sans panic.

---

### 4.9 spec.json (ENGINE v22.1)

```json
{
  "name": "slices",
  "language": "rust",
  "language_version": "edition 2024",
  "type": "code",
  "tier": 1,
  "tags": ["module0.7", "slices", "arrays", "phase0"],
  "passing_score": 70
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Safety) : Panic sur overflow**

```rust
/* Mutant A (Safety) : Pas de verification */
pub fn first_n<T>(slice: &[T], n: usize) -> &[T] {
    &slice[..n]  // Panic!
}
// Pourquoi faux : Panic si n > len
```

**Mutant B (Logic) : last_n inverse**

```rust
/* Mutant B (Logic) : Mauvais calcul */
pub fn last_n<T>(slice: &[T], n: usize) -> &[T] {
    &slice[..n]  // Retourne les premiers, pas les derniers!
}
// Pourquoi faux : Retourne le debut au lieu de la fin
```

**Mutant C (Edge) : middle ne gere pas les petites slices**

```rust
/* Mutant C (Edge) : Panic sur petite slice */
pub fn middle<T>(slice: &[T]) -> &[T] {
    &slice[1..slice.len() - 1]  // Panic si len <= 1
}
// Pourquoi faux : Panic sur [1] ou []
```

**Mutant D (Type) : Retourne Vec au lieu de slice**

```rust
/* Mutant D (Type) : Mauvais type retour */
pub fn first_n<T: Clone>(slice: &[T], n: usize) -> Vec<T> {
    slice.iter().take(n).cloned().collect()
}
// Pourquoi faux : La signature demande &[T]
```

**Mutant E (Logic) : find retourne le mauvais index**

```rust
/* Mutant E (Logic) : Off-by-one */
pub fn find_in_slice<T: PartialEq>(slice: &[T], target: &T) -> Option<usize> {
    slice.iter().position(|x| x == target).map(|i| i + 1)
}
// Pourquoi faux : Retourne index + 1 (off-by-one)
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| &[T] | Slice : vue sur donnees contigues | Critique |
| &str | String slice (UTF-8) | Critique |
| Range syntax | [start..end] | Important |
| Fat pointer | ptr + len | Important |

---

### 5.2 LDA — Traduction litterale en MAJUSCULES

```
FONCTION first_n QUI PREND slice ET n
DEBUT FONCTION
    SI n >= LONGUEUR DE slice ALORS
        RETOURNER TOUTE LA SLICE
    SINON
        RETOURNER LES n PREMIERS ELEMENTS
    FIN SI
FIN FONCTION

UNE SLICE EST:
    - UN POINTEUR VERS LE DEBUT DES DONNEES
    - PLUS UNE LONGUEUR
    - ELLE NE POSSEDE PAS LES DONNEES
```

---

### 5.3 Visualisation ASCII

**Structure d'une slice :**

```
Array en memoire:
+-----+-----+-----+-----+-----+
|  1  |  2  |  3  |  4  |  5  |
+-----+-----+-----+-----+-----+
  ^
  |
  +-- Adresse memoire

Slice &arr[1..4]:
+--------------------+
| ptr: --------------+--> pointe vers arr[1]
| len: 3             |
+--------------------+

Vue:          +-----+-----+-----+
              |  2  |  3  |  4  |
              +-----+-----+-----+
```

**Fat pointer vs thin pointer :**

```
Thin pointer (&T):
+------------------+
| ptr: 0x7fff...   |  <- 8 octets
+------------------+

Fat pointer (&[T]):
+------------------+
| ptr: 0x7fff...   |  <- 8 octets
| len: 42          |  <- 8 octets
+------------------+
     Total: 16 octets
```

**Syntaxe des ranges :**

```
arr = [0, 1, 2, 3, 4]
       0  1  2  3  4  <- index

arr[..]     = [0, 1, 2, 3, 4]   // tout
arr[1..]    = [1, 2, 3, 4]      // depuis index 1
arr[..3]    = [0, 1, 2]         // jusqu'a index 3 (exclu)
arr[1..4]   = [1, 2, 3]         // de 1 a 4 (exclu)
arr[1..=3]  = [1, 2, 3]         // de 1 a 3 (inclus)
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Index out of bounds

```rust
let arr = [1, 2, 3];
let slice = &arr[0..10];  // PANIC! index out of bounds
```

#### Piege 2 : Slices de &str sur boundaries UTF-8

```rust
let s = "cafe";        // 'e' = 2 bytes en UTF-8!
let slice = &s[0..4];  // OK: "cafe"
let slice = &s[0..5];  // PANIC! not a char boundary
```

---

### 5.5 Cours Complet

#### 5.5.1 Creer des slices

```rust
// Depuis un array
let arr = [1, 2, 3, 4, 5];
let slice: &[i32] = &arr[1..4];  // [2, 3, 4]

// Depuis un Vec
let vec = vec![1, 2, 3];
let slice: &[i32] = &vec[..];  // slice de tout le vec

// Depuis une String
let s = String::from("hello");
let slice: &str = &s[0..2];  // "he"
```

#### 5.5.2 Methodes utiles sur les slices

```rust
let slice = &[1, 2, 3, 4, 5];

slice.len()           // 5
slice.is_empty()      // false
slice.first()         // Some(&1)
slice.last()          // Some(&5)
slice.get(2)          // Some(&3)
slice.get(10)         // None (safe, pas de panic)
slice.contains(&3)    // true
slice.iter()          // iterateur
slice.split_at(2)     // (&[1, 2], &[3, 4, 5])
```

---

### 5.8 Mnemotechniques

**SLICE = Subset, Length, Index, Contiguous, Efficient**

Une slice est un Subset de donnees Contiguues avec Length et Index, de maniere Efficient (pas de copie).

**[start..end] = "de start a end exclu"**
**[start..=end] = "de start a end inclus"**

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Index > len | Panic | Utiliser get() ou min() |
| 2 | &str boundaries | Panic si pas sur char | Utiliser char_indices() |
| 3 | Confusion &[T] / Vec | Type mismatch | Deref coercion |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quelle est la taille d'une slice &[T] sur un systeme 64-bit ?

- A) 8 octets
- B) 16 octets
- C) Depend de T
- D) Depend de la longueur

**Reponse : B** — Fat pointer = ptr (8) + len (8).

---

### Question 2 (4 points)
Quelle methode pour acceder a un element sans risque de panic ?

- A) `slice[i]`
- B) `slice.get(i)`
- C) `slice.at(i)`
- D) `slice.fetch(i)`

**Reponse : B** — get() retourne Option, pas de panic.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.6 |
| **Nom** | slices |
| **Difficulte** | 4/10 |
| **Duree** | 40 min |
| **XP Base** | 85 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | &[T], &str, range syntax |
| **Prerequis** | borrowing |
| **Domaines** | Slices, Memory |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.6-slices",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.6",
      "exercise_name": "slices",
      "module": "0.7",
      "module_name": "Introduction a Rust",
      "concept": "g",
      "concept_name": "Slices",
      "type": "code",
      "tier": 1,
      "difficulty": 4,
      "prerequisites": ["0.7.5"],
      "domains": ["Slices", "Memory"],
      "tags": ["slices", "arrays", "str", "fat-pointer"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
