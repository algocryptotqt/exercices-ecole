# Exercice 0.7.11 : result

**Module :**
0.7 — Introduction a Rust

**Concept :**
l — Result : gestion des erreurs explicite

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.10 (option)
- Pattern matching

**Domaines :**
Result, Error Handling

**Duree estimee :**
50 min

**XP Base :**
100

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

#### Section Culture : "Result: Because Errors Deserve First-Class Treatment"

Rust n'utilise pas d'exceptions. A la place, Result<T, E> represente soit un succes (Ok(T)) soit une erreur (Err(E)). L'operateur ? permet de propager les erreurs elegamment.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des fonctions utilisant Result<T, E> :

1. `parse_number` : parse une chaine en nombre
2. `divide_result` : division qui peut echouer
3. `read_file_size` : simule lecture de fichier
4. Utiliser l'operateur ? pour propager les erreurs

**Entree :**

```rust
// src/lib.rs
use std::num::ParseIntError;

/// Parse une chaine en i32.
pub fn parse_number(s: &str) -> Result<i32, ParseIntError> {
    // A implementer
}

/// Division safe avec Result.
pub fn divide_result(a: i32, b: i32) -> Result<i32, String> {
    // A implementer
}

/// Parse et divise (chaine les operations).
pub fn parse_and_divide(a: &str, b: &str) -> Result<i32, String> {
    // A implementer avec ?
}

/// Simule la lecture d'un fichier (retourne taille ou erreur).
pub fn read_file_size(filename: &str) -> Result<usize, String> {
    // A implementer
    // "valid.txt" = 1024, "empty.txt" = 0, autres = erreur
}

/// Convertit Result en Option.
pub fn result_to_option<T, E>(result: Result<T, E>) -> Option<T> {
    // A implementer
}

/// Retourne la valeur ou une valeur par defaut.
pub fn unwrap_or_result<T: Clone>(result: Result<T, &str>, default: T) -> T {
    // A implementer
}
```

**Sortie attendue :**

```
$ cargo test
running 6 tests
test tests::test_parse_number ... ok
test tests::test_divide_result ... ok
test tests::test_parse_and_divide ... ok
test tests::test_read_file_size ... ok
test tests::test_result_to_option ... ok
test tests::test_unwrap_or_result ... ok

test result: ok. 6 passed; 0 failed
```

---

### 1.3 Prototype

```rust
pub fn parse_number(s: &str) -> Result<i32, ParseIntError>;
pub fn divide_result(a: i32, b: i32) -> Result<i32, String>;
pub fn parse_and_divide(a: &str, b: &str) -> Result<i32, String>;
pub fn read_file_size(filename: &str) -> Result<usize, String>;
pub fn result_to_option<T, E>(result: Result<T, E>) -> Option<T>;
pub fn unwrap_or_result<T: Clone>(result: Result<T, &str>, default: T) -> T;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Result vs Exception :**

- Exceptions = flux de controle invisible, peut etre oublie
- Result = explicite, force le traitement

**L'operateur ? :**

```rust
// Sans ?
let value = match result {
    Ok(v) => v,
    Err(e) => return Err(e.into()),
};

// Avec ?
let value = result?;  // Equivalent!
```

**Methodes utiles :**

```rust
result.is_ok()        // true si Ok
result.is_err()       // true si Err
result.unwrap()       // extrait ou panic
result.unwrap_or(x)   // extrait ou retourne x
result.map(f)         // applique f si Ok
result.map_err(f)     // applique f si Err
result.ok()           // convertit en Option<T>
result.err()          // convertit en Option<E>
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
use std::num::ParseIntError;

pub fn parse_number(s: &str) -> Result<i32, ParseIntError> {
    s.parse()
}

pub fn divide_result(a: i32, b: i32) -> Result<i32, String> {
    if b == 0 {
        Err("Division by zero".to_string())
    } else {
        Ok(a / b)
    }
}

pub fn parse_and_divide(a: &str, b: &str) -> Result<i32, String> {
    let num_a: i32 = a.parse().map_err(|e: ParseIntError| e.to_string())?;
    let num_b: i32 = b.parse().map_err(|e: ParseIntError| e.to_string())?;
    divide_result(num_a, num_b)
}

pub fn read_file_size(filename: &str) -> Result<usize, String> {
    match filename {
        "valid.txt" => Ok(1024),
        "empty.txt" => Ok(0),
        _ => Err(format!("File not found: {}", filename)),
    }
}

pub fn result_to_option<T, E>(result: Result<T, E>) -> Option<T> {
    result.ok()
}

pub fn unwrap_or_result<T: Clone>(result: Result<T, &str>, default: T) -> T {
    result.unwrap_or(default)
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A : Utiliser unwrap() sans verification**

```rust
pub fn parse_number(s: &str) -> Result<i32, ParseIntError> {
    Ok(s.parse().unwrap())  // Panic si erreur!
}
// Pourquoi faux : Ne retourne jamais Err, panic a la place
```

**Mutant B : Division ne verifie pas zero**

```rust
pub fn divide_result(a: i32, b: i32) -> Result<i32, String> {
    Ok(a / b)  // Panic si b = 0!
}
// Pourquoi faux : Ne gere pas la division par zero
```

**Mutant C : Oubli de map_err avec ?**

```rust
pub fn parse_and_divide(a: &str, b: &str) -> Result<i32, String> {
    let num_a: i32 = a.parse()?;  // Type error: ParseIntError != String
    // ...
}
// Pourquoi faux : Les types d'erreur ne correspondent pas
```

**Mutant D : result_to_option retourne toujours None**

```rust
pub fn result_to_option<T, E>(result: Result<T, E>) -> Option<T> {
    None  // Ignore le resultat!
}
// Pourquoi faux : Perd la valeur Ok
```

**Mutant E : unwrap_or modifie le default**

```rust
pub fn unwrap_or_result<T: Clone>(result: Result<T, &str>, default: T) -> T {
    match result {
        Ok(v) => v,
        Err(_) => default.clone(),  // Clone inutile mais correct
    }
}
// Note: Ce mutant est en fait correct, juste inefficace
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Result<T,E> | Ok(T) ou Err(E) | Critique |
| ? operator | Propagation d'erreur | Critique |
| map_err | Transformation d'erreur | Important |
| unwrap | Extraction avec panic | Important |

---

### 5.3 Visualisation ASCII

**Result en memoire :**

```
Ok(42):
+-----+--------+
| tag |  data  |
|  0  |   42   |
+-----+--------+

Err("oops"):
+-----+----------------+
| tag |     data       |
|  1  | ptr -> "oops"  |
+-----+----------------+
```

**Propagation avec ? :**

```
fn outer() -> Result<i32, Error> {
    let x = inner()?;   // Si Err, return immediat
    //              ^
    //              |
    //   equivalent a:
    //   match inner() {
    //       Ok(v) => v,
    //       Err(e) => return Err(e.into()),
    //   }
    Ok(x * 2)
}
```

**Chaines de Result :**

```
Result<T, E>
   |
   +--> map(f) -------> Result<U, E>    (transforme T en U)
   |
   +--> map_err(f) ---> Result<T, F>    (transforme E en F)
   |
   +--> and_then(f) --> Result<U, E>    (f retourne Result<U, E>)
   |
   +--> ok() ---------> Option<T>       (convertit en Option)
   |
   +--> ? ------------> T ou return Err (early return si Err)
```

---

### 5.5 Cours Complet

```rust
// Creation
let ok: Result<i32, String> = Ok(42);
let err: Result<i32, String> = Err("error".to_string());

// Pattern matching
match result {
    Ok(value) => println!("Success: {}", value),
    Err(e) => println!("Error: {}", e),
}

// Methodes
result.is_ok()           // bool
result.is_err()          // bool
result.unwrap()          // T ou panic
result.unwrap_or(default)// T ou default
result.expect("msg")     // T ou panic avec message

// Transformations
result.map(|x| x * 2)    // Result<U, E>
result.map_err(|e| ...)  // Result<T, F>
result.and_then(|x| Ok(x * 2))  // flat map

// Conversions
result.ok()              // Option<T>
result.err()             // Option<E>

// Operateur ?
fn foo() -> Result<i32, Error> {
    let x = may_fail()?;  // Propage l'erreur
    Ok(x)
}
```

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | unwrap() direct | Panic possible | Utiliser ? ou match |
| 2 | Types d'erreur differents | Compilation echoue | map_err pour convertir |
| 3 | Oublier ? | Erreur non propagee | Ajouter ? |

---

## SECTION 7 : QCM

### Question 1 (4 points)
Que fait l'operateur ? sur un Err ?

- A) Ignore l'erreur
- B) Panic
- C) Return l'erreur depuis la fonction
- D) Convertit en Option

**Reponse : C** — ? propage l'erreur avec return Err(e).

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.11 |
| **Nom** | result |
| **Difficulte** | 5/10 |
| **Duree** | 50 min |
| **XP Base** | 100 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | Result<T,E>, Ok, Err, ?, map_err |
| **Prerequis** | option |
| **Domaines** | Result, Error Handling |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.11-result",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.11",
      "exercise_name": "result",
      "module": "0.7",
      "concept": "l",
      "concept_name": "Result",
      "prerequisites": ["0.7.10"],
      "tags": ["result", "ok", "err", "question-mark", "map_err"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
