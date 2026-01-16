# Exercice 0.7.11-a : result

**Module :**
0.7.11 — Result<T, E>

**Concept :**
a-e — Ok, Err, ? operator, error propagation, custom errors

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
0.7.10 (option)

**Domaines :**
Algo, Safety

**Duree estimee :**
180 min

**XP Base :**
250

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `src/lib.rs`

### 1.2 Consigne

Implementer des fonctions utilisant Result pour la gestion d'erreurs.

**Ta mission :**

```rust
// Erreurs personnalisees
#[derive(Debug, Clone, PartialEq)]
pub enum MathError {
    DivisionByZero,
    NegativeSquareRoot,
    Overflow,
}

// Division safe
pub fn divide(a: i32, b: i32) -> Result<i32, MathError>;

// Racine carree safe
pub fn sqrt(x: f64) -> Result<f64, MathError>;

// Parser un entier avec erreur personnalisee
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    Empty,
    InvalidChar(char),
    Overflow,
}

pub fn parse_positive(s: &str) -> Result<u32, ParseError>;

// Chainer des operations (utilise ?)
pub fn calculate(a: i32, b: i32) -> Result<f64, MathError>;

// Convertir Result en Option
pub fn result_to_option<T, E>(result: Result<T, E>) -> Option<T>;

// Map sur Result
pub fn double_result(result: Result<i32, MathError>) -> Result<i32, MathError>;
```

**Comportement:**

1. `divide(10, 2)` -> Ok(5)
2. `divide(10, 0)` -> Err(MathError::DivisionByZero)
3. `sqrt(-1.0)` -> Err(MathError::NegativeSquareRoot)
4. `parse_positive("42")` -> Ok(42)
5. `parse_positive("abc")` -> Err(ParseError::InvalidChar('a'))

**Exemples:**
```rust
let result = divide(10, 2);
match result {
    Ok(n) => println!("Result: {}", n),  // Result: 5
    Err(e) => println!("Error: {:?}", e),
}

let result = parse_positive("123");
println!("{:?}", result);  // Ok(123)

let result = parse_positive("");
println!("{:?}", result);  // Err(ParseError::Empty)
```

### 1.3 Prototype

```rust
// src/lib.rs

#[derive(Debug, Clone, PartialEq)]
pub enum MathError {
    DivisionByZero,
    NegativeSquareRoot,
    Overflow,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    Empty,
    InvalidChar(char),
    Overflow,
}

pub fn divide(a: i32, b: i32) -> Result<i32, MathError> {
    todo!()
}

pub fn sqrt(x: f64) -> Result<f64, MathError> {
    todo!()
}

pub fn parse_positive(s: &str) -> Result<u32, ParseError> {
    todo!()
}

pub fn calculate(a: i32, b: i32) -> Result<f64, MathError> {
    todo!()
}

pub fn result_to_option<T, E>(result: Result<T, E>) -> Option<T> {
    todo!()
}

pub fn double_result(result: Result<i32, MathError>) -> Result<i32, MathError> {
    todo!()
}
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | divide OK | Ok | 10 |
| T02 | divide by zero | Err | 15 |
| T03 | sqrt positive | Ok | 10 |
| T04 | sqrt negative | Err | 15 |
| T05 | parse_positive OK | Ok | 10 |
| T06 | parse_positive empty | Err(Empty) | 10 |
| T07 | parse_positive invalid | Err(InvalidChar) | 15 |
| T08 | calculate chain | correct | 15 |

### 4.3 Solution de reference

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum MathError {
    DivisionByZero,
    NegativeSquareRoot,
    Overflow,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    Empty,
    InvalidChar(char),
    Overflow,
}

pub fn divide(a: i32, b: i32) -> Result<i32, MathError> {
    if b == 0 {
        Err(MathError::DivisionByZero)
    } else {
        Ok(a / b)
    }
}

pub fn sqrt(x: f64) -> Result<f64, MathError> {
    if x < 0.0 {
        Err(MathError::NegativeSquareRoot)
    } else {
        Ok(x.sqrt())
    }
}

pub fn parse_positive(s: &str) -> Result<u32, ParseError> {
    if s.is_empty() {
        return Err(ParseError::Empty);
    }

    let mut result: u32 = 0;

    for c in s.chars() {
        if !c.is_ascii_digit() {
            return Err(ParseError::InvalidChar(c));
        }

        let digit = c.to_digit(10).unwrap();

        result = result
            .checked_mul(10)
            .and_then(|r| r.checked_add(digit))
            .ok_or(ParseError::Overflow)?;
    }

    Ok(result)
}

pub fn calculate(a: i32, b: i32) -> Result<f64, MathError> {
    let quotient = divide(a, b)?;  // Propage l'erreur si division echoue
    let root = sqrt(quotient as f64)?;  // Propage l'erreur si sqrt echoue
    Ok(root)
}

pub fn result_to_option<T, E>(result: Result<T, E>) -> Option<T> {
    result.ok()
}

pub fn double_result(result: Result<i32, MathError>) -> Result<i32, MathError> {
    result.map(|n| n * 2)
}
```

### 4.10 Solutions Mutantes

```rust
// MUTANT 1: divide ne gere pas overflow
pub fn divide(a: i32, b: i32) -> Result<i32, MathError> {
    if b == 0 {
        Err(MathError::DivisionByZero)
    } else {
        Ok(a / b)  // i32::MIN / -1 cause overflow!
    }
}

// MUTANT 2: sqrt avec mauvaise condition
pub fn sqrt(x: f64) -> Result<f64, MathError> {
    if x <= 0.0 {  // <= au lieu de <, rejette 0
        Err(MathError::NegativeSquareRoot)
    } else {
        Ok(x.sqrt())
    }
}

// MUTANT 3: parse_positive ignore caracteres invalides
pub fn parse_positive(s: &str) -> Result<u32, ParseError> {
    let filtered: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if filtered.is_empty() {
        Err(ParseError::Empty)
    } else {
        Ok(filtered.parse().unwrap())  // Ignore caracteres invalides
    }
}

// MUTANT 4: calculate ne propage pas les erreurs
pub fn calculate(a: i32, b: i32) -> Result<f64, MathError> {
    let quotient = divide(a, b).unwrap();  // Panic au lieu de propager!
    let root = sqrt(quotient as f64).unwrap();
    Ok(root)
}

// MUTANT 5: double_result unwrap
pub fn double_result(result: Result<i32, MathError>) -> Result<i32, MathError> {
    Ok(result.unwrap() * 2)  // Panic si Err
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

**Result<T, E>** - Le type pour les operations qui peuvent echouer:

1. **Ok(value)** - Succes avec valeur
2. **Err(error)** - Echec avec information d'erreur
3. **? operator** - Propagation automatique des erreurs
4. **Custom errors** - Enums pour erreurs typees

### 5.3 Visualisation ASCII

```
RESULT FLOW:

Ok(value)
    |
    | .map(|v| transform(v))
    v
Ok(transformed)
    |
    | .and_then(|v| may_fail(v))
    v
Ok(result) or Err(error)

? OPERATOR:

fn process() -> Result<i32, Error> {
    let a = step1()?;  // Si Err, retourne immediatement
    let b = step2(a)?; // Si Err, retourne immediatement
    Ok(b * 2)
}

Equivalent a:
fn process() -> Result<i32, Error> {
    let a = match step1() {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    let b = match step2(a) {
        Ok(v) => v,
        Err(e) => return Err(e),
    };
    Ok(b * 2)
}
```

### 5.5 Option vs Result

```rust
// Option: absence de valeur (pas d'info sur pourquoi)
fn find(id: u32) -> Option<User> {
    // Some(user) ou None
}

// Result: operation qui peut echouer (avec info d'erreur)
fn load_file(path: &str) -> Result<String, io::Error> {
    // Ok(content) ou Err(why)
}

// Conversion
let opt: Option<i32> = result.ok();     // Perd l'erreur
let result: Result<i32, ()> = opt.ok_or(());  // Ajoute erreur vide

// Quand utiliser quoi:
// - Option: "il peut ne pas y avoir de valeur" (find, get)
// - Result: "cette operation peut echouer" (I/O, parsing, network)
```

---

## SECTION 7 : QCM

### Question 1
Que fait l'operateur ? sur un Err ?

A) Panic
B) Retourne None
C) Retourne l'Err depuis la fonction
D) Continue avec valeur par defaut
E) Ignore l'erreur

**Reponse correcte: C**

### Question 2
Quelle methode convertit Result<T, E> en Option<T> ?

A) to_option()
B) ok()
C) some()
D) unwrap()
E) convert()

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.7.11-a",
  "name": "result",
  "language": "rust",
  "language_version": "edition2024",
  "files": ["src/lib.rs"],
  "tests": {
    "basic": "result_basic_tests",
    "propagation": "error_propagation_tests",
    "custom_errors": "custom_error_tests"
  }
}
```
