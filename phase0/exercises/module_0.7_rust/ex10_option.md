# Exercice 0.7.10 : option

**Module :**
0.7 — Introduction a Rust

**Concept :**
k — Option : gestion de l'absence de valeur

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.9 (enums)
- Pattern matching

**Domaines :**
Option, Error Handling

**Duree estimee :**
45 min

**XP Base :**
90

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

#### Section Culture : "Some or None, There is No Null"

Rust n'a pas de null. A la place, on utilise Option<T> qui est soit Some(value) soit None. Cela force le developpeur a gerer explicitement l'absence de valeur.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des fonctions utilisant Option<T> :

1. `find_first_even` : trouve le premier nombre pair
2. `divide` : division qui peut echouer
3. `get_username` : retourne Some ou None
4. Utiliser map, unwrap_or, and_then

**Entree :**

```rust
// src/lib.rs

/// Trouve le premier nombre pair dans un slice.
pub fn find_first_even(numbers: &[i32]) -> Option<i32> {
    // A implementer
}

/// Division safe (retourne None si diviseur = 0).
pub fn divide(a: f64, b: f64) -> Option<f64> {
    // A implementer
}

/// Retourne le username si l'id existe.
pub fn get_username(id: u32) -> Option<String> {
    // A implementer (simuler une DB)
    // id 1 = "alice", id 2 = "bob", autres = None
}

/// Double la valeur si elle existe.
pub fn double_option(opt: Option<i32>) -> Option<i32> {
    // A implementer avec map
}

/// Retourne la valeur ou une valeur par defaut.
pub fn unwrap_or_default(opt: Option<i32>, default: i32) -> i32 {
    // A implementer
}

/// Chaine deux operations qui peuvent echouer.
pub fn chain_options(x: Option<i32>) -> Option<i32> {
    // A implementer avec and_then
    // Si x existe, le multiplier par 2, puis retourner Some si > 10
}
```

**Sortie attendue :**

```
$ cargo test
running 6 tests
test tests::test_find_first_even ... ok
test tests::test_divide ... ok
test tests::test_get_username ... ok
test tests::test_double_option ... ok
test tests::test_unwrap_or_default ... ok
test tests::test_chain_options ... ok

test result: ok. 6 passed; 0 failed
```

---

### 1.3 Prototype

```rust
pub fn find_first_even(numbers: &[i32]) -> Option<i32>;
pub fn divide(a: f64, b: f64) -> Option<f64>;
pub fn get_username(id: u32) -> Option<String>;
pub fn double_option(opt: Option<i32>) -> Option<i32>;
pub fn unwrap_or_default(opt: Option<i32>, default: i32) -> i32;
pub fn chain_options(x: Option<i32>) -> Option<i32>;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Option vs null :**

- null = "billion dollar mistake" (Tony Hoare)
- Option = force le traitement explicite

**Methodes utiles :**

```rust
opt.is_some()     // true si Some
opt.is_none()     // true si None
opt.unwrap()      // extrait ou panic
opt.unwrap_or(x)  // extrait ou retourne x
opt.map(f)        // applique f si Some
opt.and_then(f)   // chaine si Some
opt.ok_or(e)      // convertit en Result
```

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo test
running 6 tests
...
test result: ok. 6 passed; 0 failed
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.3 Solution de reference (Rust)

```rust
pub fn find_first_even(numbers: &[i32]) -> Option<i32> {
    numbers.iter().find(|&&x| x % 2 == 0).copied()
}

pub fn divide(a: f64, b: f64) -> Option<f64> {
    if b == 0.0 {
        None
    } else {
        Some(a / b)
    }
}

pub fn get_username(id: u32) -> Option<String> {
    match id {
        1 => Some("alice".to_string()),
        2 => Some("bob".to_string()),
        _ => None,
    }
}

pub fn double_option(opt: Option<i32>) -> Option<i32> {
    opt.map(|x| x * 2)
}

pub fn unwrap_or_default(opt: Option<i32>, default: i32) -> i32 {
    opt.unwrap_or(default)
}

pub fn chain_options(x: Option<i32>) -> Option<i32> {
    x.map(|v| v * 2).filter(|&v| v > 10)
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A : Utiliser unwrap() sans verification**

```rust
pub fn find_first_even(numbers: &[i32]) -> Option<i32> {
    Some(numbers.iter().find(|&&x| x % 2 == 0).unwrap())
}
// Pourquoi faux : Panic si aucun pair trouve
```

**Mutant B : Division ne verifie pas zero**

```rust
pub fn divide(a: f64, b: f64) -> Option<f64> {
    Some(a / b)  // Retourne Infinity au lieu de None
}
// Pourquoi faux : Ne gere pas la division par zero
```

**Mutant C : map au lieu de and_then**

```rust
pub fn chain_options(x: Option<i32>) -> Option<i32> {
    x.map(|v| if v * 2 > 10 { Some(v * 2) } else { None })
    // Resultat: Option<Option<i32>>!
}
// Pourquoi faux : Double emballage
```

**Mutant D : Oubli du .copied()**

```rust
pub fn find_first_even(numbers: &[i32]) -> Option<i32> {
    numbers.iter().find(|&&x| x % 2 == 0)
    // Type: Option<&i32>, pas Option<i32>
}
// Pourquoi faux : Type de retour incorrect
```

**Mutant E : unwrap_or modifie l'original**

```rust
pub fn unwrap_or_default(opt: Option<i32>, default: i32) -> i32 {
    match opt {
        Some(v) => v,
        None => default + 1,  // Modifie le default!
    }
}
// Pourquoi faux : Ne retourne pas exactement le default
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Option<T> | Some(T) ou None | Critique |
| unwrap | Extrait ou panic | Important |
| map | Transforme si Some | Critique |
| and_then | Chaine les Options | Important |

---

### 5.3 Visualisation ASCII

**Option en memoire :**

```
Some(42):
+-----+--------+
| tag |  data  |
|  1  |   42   |
+-----+--------+

None:
+-----+--------+
| tag | (vide) |
|  0  |  ...   |
+-----+--------+
```

**Chaines d'operations :**

```
Option<T>
   |
   +--> map(f) -----> Option<U>     (transforme T en U)
   |
   +--> and_then(f) -> Option<U>    (f retourne Option<U>)
   |
   +--> unwrap_or(x) -> T           (extrait ou default)
   |
   +--> ? operator -> T ou return   (early return si None)
```

---

### 5.5 Cours Complet

```rust
// Creation
let some = Some(42);
let none: Option<i32> = None;

// Pattern matching
match option {
    Some(value) => println!("Got {}", value),
    None => println!("Nothing"),
}

// Methodes
option.is_some()           // bool
option.is_none()           // bool
option.unwrap()            // T ou panic
option.unwrap_or(default)  // T ou default
option.unwrap_or_else(|| compute())  // T ou closure

// Transformations
option.map(|x| x * 2)      // Option<U>
option.and_then(|x| Some(x * 2))  // flat map
option.filter(|x| *x > 0)  // Option<T>

// Conversion
option.ok_or("error")      // Result<T, E>
```

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | unwrap() direct | Panic possible | Utiliser unwrap_or ou match |
| 2 | map vs and_then | Double emballage | and_then pour aplatir |
| 3 | Oublier .copied() | Type incorrect | Copier les references |

---

## SECTION 7 : QCM

### Question 1 (4 points)
Que retourne `None.unwrap_or(42)` ?

- A) None
- B) Some(42)
- C) 42
- D) Panic

**Reponse : C** — unwrap_or retourne la valeur, pas Option.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.10 |
| **Nom** | option |
| **Difficulte** | 4/10 |
| **Duree** | 45 min |
| **XP Base** | 90 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | Option<T>, Some, None, unwrap, map |
| **Prerequis** | enums |
| **Domaines** | Option, Error Handling |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.10-option",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.10",
      "exercise_name": "option",
      "module": "0.7",
      "concept": "k",
      "concept_name": "Option",
      "prerequisites": ["0.7.9"],
      "tags": ["option", "some", "none", "unwrap", "map"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
