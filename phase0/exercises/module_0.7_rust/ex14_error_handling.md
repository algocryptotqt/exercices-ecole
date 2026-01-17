# Exercice 0.7.14 : error_handling

**Module :**
0.7 — Introduction a Rust

**Concept :**
o — Error Handling : erreurs personnalisees et From trait

**Difficulte :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
code

**Tiers :**
2 — Combinaison de concepts

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.11 (result)
- Exercice 0.7.9 (enums)

**Domaines :**
Error Handling, Traits

**Duree estimee :**
60 min

**XP Base :**
120

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

#### Section Culture : "Custom Errors: When String Isn't Enough"

Les erreurs personnalisees permettent de creer des types d'erreur specifiques au domaine. Le trait From<T> permet la conversion automatique avec l'operateur ?.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un systeme d'erreurs personnalisees :

1. `AppError` : enum avec differents types d'erreur
2. Implementer Display pour les messages
3. Implementer From pour les conversions
4. Utiliser ? avec conversion automatique

**Entree :**

```rust
// src/lib.rs
use std::fmt;
use std::num::ParseIntError;
use std::io;

/// Enum representant les erreurs de l'application.
#[derive(Debug)]
pub enum AppError {
    ParseError(String),
    IoError(String),
    ValidationError(String),
    NotFound(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // A implementer
    }
}

impl From<ParseIntError> for AppError {
    fn from(err: ParseIntError) -> Self {
        // A implementer
    }
}

impl From<io::Error> for AppError {
    fn from(err: io::Error) -> Self {
        // A implementer
    }
}

/// Parse un nombre et le valide (doit etre positif).
pub fn parse_positive(s: &str) -> Result<i32, AppError> {
    // A implementer
}

/// Simule lecture fichier avec validation.
pub fn read_config(filename: &str) -> Result<String, AppError> {
    // A implementer
    // "config.txt" -> Ok("value=42")
    // "missing.txt" -> Err(NotFound)
    // autres -> Err(IoError)
}

/// Chaine les operations avec ?.
pub fn process_config(filename: &str) -> Result<i32, AppError> {
    // A implementer: lit config, parse le nombre, valide
}
```

**Sortie attendue :**

```
$ cargo test
running 5 tests
test tests::test_display ... ok
test tests::test_from_parse ... ok
test tests::test_parse_positive ... ok
test tests::test_read_config ... ok
test tests::test_process_config ... ok

test result: ok. 5 passed; 0 failed
```

---

### 1.3 Prototype

```rust
pub enum AppError {
    ParseError(String),
    IoError(String),
    ValidationError(String),
    NotFound(String),
}

impl fmt::Display for AppError;
impl From<ParseIntError> for AppError;
impl From<io::Error> for AppError;

pub fn parse_positive(s: &str) -> Result<i32, AppError>;
pub fn read_config(filename: &str) -> Result<String, AppError>;
pub fn process_config(filename: &str) -> Result<i32, AppError>;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Error trait :**

```rust
// std::error::Error
pub trait Error: Debug + Display {
    fn source(&self) -> Option<&(dyn Error + 'static)> { None }
}
```

**thiserror crate :**

```rust
// Avec thiserror (derive macro)
#[derive(thiserror::Error, Debug)]
pub enum MyError {
    #[error("Parse error: {0}")]
    Parse(#[from] ParseIntError),
    
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
}
```

**anyhow crate :**

```rust
// Pour les applications (pas les libs)
fn main() -> anyhow::Result<()> {
    let x: i32 = "42".parse()?;
    Ok(())
}
```

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo test
running 5 tests
...
test result: ok. 5 passed; 0 failed
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.3 Solution de reference (Rust)

```rust
use std::fmt;
use std::num::ParseIntError;
use std::io;

#[derive(Debug)]
pub enum AppError {
    ParseError(String),
    IoError(String),
    ValidationError(String),
    NotFound(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            AppError::IoError(msg) => write!(f, "IO error: {}", msg),
            AppError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not found: {}", msg),
        }
    }
}

impl From<ParseIntError> for AppError {
    fn from(err: ParseIntError) -> Self {
        AppError::ParseError(err.to_string())
    }
}

impl From<io::Error> for AppError {
    fn from(err: io::Error) -> Self {
        AppError::IoError(err.to_string())
    }
}

pub fn parse_positive(s: &str) -> Result<i32, AppError> {
    let num: i32 = s.parse()?;  // Utilise From<ParseIntError>
    if num < 0 {
        Err(AppError::ValidationError("Number must be positive".to_string()))
    } else {
        Ok(num)
    }
}

pub fn read_config(filename: &str) -> Result<String, AppError> {
    match filename {
        "config.txt" => Ok("value=42".to_string()),
        "missing.txt" => Err(AppError::NotFound(filename.to_string())),
        _ => Err(AppError::IoError(format!("Cannot read {}", filename))),
    }
}

pub fn process_config(filename: &str) -> Result<i32, AppError> {
    let content = read_config(filename)?;
    let value_str = content
        .strip_prefix("value=")
        .ok_or_else(|| AppError::ParseError("Invalid format".to_string()))?;
    parse_positive(value_str)
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A : Display sans match exhaustif**

```rust
impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Error occurred")  // Message generique
    }
}
// Pourquoi faux : Perd l'information specifique
```

**Mutant B : From perd le message**

```rust
impl From<ParseIntError> for AppError {
    fn from(_err: ParseIntError) -> Self {
        AppError::ParseError("parse error".to_string())
    }
}
// Pourquoi faux : Perd le message d'origine
```

**Mutant C : parse_positive accepte zero comme negatif**

```rust
pub fn parse_positive(s: &str) -> Result<i32, AppError> {
    let num: i32 = s.parse()?;
    if num <= 0 {  // <= au lieu de <
        Err(AppError::ValidationError("...".to_string()))
    } else {
        Ok(num)
    }
}
// Note: Depend de la spec - zero est-il positif?
```

**Mutant D : process_config ne propage pas**

```rust
pub fn process_config(filename: &str) -> Result<i32, AppError> {
    let content = read_config(filename).unwrap();  // Panic!
    // ...
}
// Pourquoi faux : Panic au lieu de propager l'erreur
```

**Mutant E : Mauvais variant d'erreur**

```rust
impl From<io::Error> for AppError {
    fn from(err: io::Error) -> Self {
        AppError::ParseError(err.to_string())  // ParseError au lieu de IoError!
    }
}
// Pourquoi faux : Mauvaise categorisation de l'erreur
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Custom Error | Enum d'erreur | Critique |
| Display | Message d'erreur | Critique |
| From trait | Conversion auto | Critique |
| ? + From | Propagation elegante | Important |

---

### 5.3 Visualisation ASCII

**Hierarchie d'erreurs :**

```
AppError
    |
    +-- ParseError(String)
    |       |
    |       +-- From<ParseIntError>
    |
    +-- IoError(String)
    |       |
    |       +-- From<io::Error>
    |
    +-- ValidationError(String)
    |
    +-- NotFound(String)
```

**Conversion avec ? :**

```rust
fn foo() -> Result<T, AppError> {
    let x: i32 = s.parse()?;
    //                   ^
    //                   |
    // s.parse() -> Result<i32, ParseIntError>
    //            -> Err(ParseIntError)
    //            -> Err(AppError::from(ParseIntError))
    //            -> return Err(AppError::ParseError(...))
}
```

**Pattern Error :**

```
        +----------+
        |   User   |
        +----+-----+
             |
             v
     +-------+-------+
     |   process()   |
     +-------+-------+
             |
     +-------+-------+
     |  parse()?     |---> Err(AppError::ParseError)
     +-------+-------+
             |
     +-------+-------+
     |  validate()?  |---> Err(AppError::ValidationError)
     +-------+-------+
             |
             v
         Ok(value)
```

---

### 5.5 Cours Complet

```rust
// 1. Definir l'enum d'erreur
#[derive(Debug)]
pub enum MyError {
    Io(io::Error),
    Parse(ParseIntError),
    Custom(String),
}

// 2. Implementer Display
impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MyError::Io(e) => write!(f, "IO error: {}", e),
            MyError::Parse(e) => write!(f, "Parse error: {}", e),
            MyError::Custom(msg) => write!(f, "{}", msg),
        }
    }
}

// 3. Implementer std::error::Error (optionnel mais recommande)
impl std::error::Error for MyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MyError::Io(e) => Some(e),
            MyError::Parse(e) => Some(e),
            MyError::Custom(_) => None,
        }
    }
}

// 4. Implementer From pour conversions automatiques
impl From<io::Error> for MyError {
    fn from(err: io::Error) -> Self {
        MyError::Io(err)
    }
}

impl From<ParseIntError> for MyError {
    fn from(err: ParseIntError) -> Self {
        MyError::Parse(err)
    }
}

// 5. Utiliser avec ?
fn process() -> Result<i32, MyError> {
    let content = std::fs::read_to_string("file.txt")?;  // io::Error -> MyError
    let num: i32 = content.trim().parse()?;              // ParseIntError -> MyError
    Ok(num)
}
```

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Oublier Display | Pas de message lisible | Implementer fmt::Display |
| 2 | From perd info | Debug difficile | Garder le message |
| 3 | Mauvais variant | Confusion | Mapper correctement |

---

## SECTION 7 : QCM

### Question 1 (4 points)
Pourquoi implementer From<T> pour un type d'erreur ?

- A) Pour le Debug
- B) Pour permettre ? avec conversion automatique
- C) Pour la serialisation
- D) Pour le multithreading

**Reponse : B** — From permet a ? de convertir automatiquement les erreurs.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.14 |
| **Nom** | error_handling |
| **Difficulte** | 6/10 |
| **Duree** | 60 min |
| **XP Base** | 120 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | Custom Error, Display, From, ? operator |
| **Prerequis** | result, enums |
| **Domaines** | Error Handling, Traits |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.14-error_handling",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.14",
      "exercise_name": "error_handling",
      "module": "0.7",
      "concept": "o",
      "concept_name": "Error Handling",
      "prerequisites": ["0.7.11", "0.7.9"],
      "tags": ["error", "custom", "from", "display", "result"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
