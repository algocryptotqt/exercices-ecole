# Exercice 0.7.17-a : testing

**Module :**
0.7.17 — Tests en Rust

**Concept :**
a-e — #[test], assert!, assert_eq!, #[cfg(test)], cargo test

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
Testing

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

Implementer des fonctions ET leurs tests unitaires.

**Ta mission :**

```rust
// Fonctions a implementer et tester
pub fn add(a: i32, b: i32) -> i32;
pub fn divide(a: i32, b: i32) -> Result<i32, &'static str>;
pub fn is_palindrome(s: &str) -> bool;
pub fn fizzbuzz(n: u32) -> String;
pub fn fibonacci(n: u32) -> u64;

// Tests a ecrire
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_positive() { ... }

    #[test]
    fn test_add_negative() { ... }

    #[test]
    fn test_divide_ok() { ... }

    #[test]
    fn test_divide_by_zero() { ... }

    #[test]
    fn test_palindrome_true() { ... }

    #[test]
    fn test_palindrome_false() { ... }

    #[test]
    fn test_fizzbuzz() { ... }

    #[test]
    fn test_fibonacci() { ... }

    #[test]
    #[should_panic(expected = "overflow")]
    fn test_overflow() { ... }
}
```

**Comportement:**

1. Tous les tests doivent passer avec `cargo test`
2. Couvrir les cas normaux ET les cas limites
3. Utiliser assert!, assert_eq!, assert_ne!
4. Tester les erreurs attendues

**Exemples:**
```rust
// Test simple
#[test]
fn test_add() {
    assert_eq!(add(2, 3), 5);
}

// Test avec Result
#[test]
fn test_divide_ok() {
    assert_eq!(divide(10, 2), Ok(5));
}

#[test]
fn test_divide_error() {
    assert!(divide(10, 0).is_err());
}

// Test should_panic
#[test]
#[should_panic]
fn test_panic() {
    panic!("This test expects panic");
}
```

### 1.3 Prototype

```rust
// src/lib.rs

pub fn add(a: i32, b: i32) -> i32 {
    todo!()
}

pub fn divide(a: i32, b: i32) -> Result<i32, &'static str> {
    todo!()
}

pub fn is_palindrome(s: &str) -> bool {
    todo!()
}

pub fn fizzbuzz(n: u32) -> String {
    todo!()
}

pub fn fibonacci(n: u32) -> u64 {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_positive() {
        todo!()
    }

    #[test]
    fn test_add_negative() {
        todo!()
    }

    #[test]
    fn test_add_zero() {
        todo!()
    }

    #[test]
    fn test_divide_ok() {
        todo!()
    }

    #[test]
    fn test_divide_by_zero() {
        todo!()
    }

    #[test]
    fn test_palindrome_true() {
        todo!()
    }

    #[test]
    fn test_palindrome_false() {
        todo!()
    }

    #[test]
    fn test_palindrome_empty() {
        todo!()
    }

    #[test]
    fn test_fizzbuzz_fizz() {
        todo!()
    }

    #[test]
    fn test_fizzbuzz_buzz() {
        todo!()
    }

    #[test]
    fn test_fizzbuzz_fizzbuzz() {
        todo!()
    }

    #[test]
    fn test_fizzbuzz_number() {
        todo!()
    }

    #[test]
    fn test_fibonacci_base() {
        todo!()
    }

    #[test]
    fn test_fibonacci_sequence() {
        todo!()
    }
}
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | cargo test | all pass | 30 |
| T02 | add tests | comprehensive | 10 |
| T03 | divide tests | error handling | 15 |
| T04 | palindrome tests | edge cases | 15 |
| T05 | fizzbuzz tests | all cases | 15 |
| T06 | fibonacci tests | sequence | 15 |

### 4.3 Solution de reference

```rust
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

pub fn divide(a: i32, b: i32) -> Result<i32, &'static str> {
    if b == 0 {
        Err("division by zero")
    } else {
        Ok(a / b)
    }
}

pub fn is_palindrome(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();

    for i in 0..n / 2 {
        if chars[i] != chars[n - 1 - i] {
            return false;
        }
    }
    true
}

pub fn fizzbuzz(n: u32) -> String {
    match (n % 3, n % 5) {
        (0, 0) => "FizzBuzz".to_string(),
        (0, _) => "Fizz".to_string(),
        (_, 0) => "Buzz".to_string(),
        _ => n.to_string(),
    }
}

pub fn fibonacci(n: u32) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        _ => {
            let mut a = 0u64;
            let mut b = 1u64;
            for _ in 2..=n {
                let c = a + b;
                a = b;
                b = c;
            }
            b
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests for add
    #[test]
    fn test_add_positive() {
        assert_eq!(add(2, 3), 5);
        assert_eq!(add(100, 200), 300);
    }

    #[test]
    fn test_add_negative() {
        assert_eq!(add(-2, -3), -5);
        assert_eq!(add(-5, 3), -2);
    }

    #[test]
    fn test_add_zero() {
        assert_eq!(add(0, 0), 0);
        assert_eq!(add(5, 0), 5);
        assert_eq!(add(0, 5), 5);
    }

    // Tests for divide
    #[test]
    fn test_divide_ok() {
        assert_eq!(divide(10, 2), Ok(5));
        assert_eq!(divide(9, 3), Ok(3));
        assert_eq!(divide(-10, 2), Ok(-5));
    }

    #[test]
    fn test_divide_by_zero() {
        assert!(divide(10, 0).is_err());
        assert_eq!(divide(10, 0), Err("division by zero"));
    }

    // Tests for is_palindrome
    #[test]
    fn test_palindrome_true() {
        assert!(is_palindrome("radar"));
        assert!(is_palindrome("level"));
        assert!(is_palindrome("a"));
    }

    #[test]
    fn test_palindrome_false() {
        assert!(!is_palindrome("hello"));
        assert!(!is_palindrome("world"));
    }

    #[test]
    fn test_palindrome_empty() {
        assert!(is_palindrome(""));
    }

    // Tests for fizzbuzz
    #[test]
    fn test_fizzbuzz_fizz() {
        assert_eq!(fizzbuzz(3), "Fizz");
        assert_eq!(fizzbuzz(6), "Fizz");
        assert_eq!(fizzbuzz(9), "Fizz");
    }

    #[test]
    fn test_fizzbuzz_buzz() {
        assert_eq!(fizzbuzz(5), "Buzz");
        assert_eq!(fizzbuzz(10), "Buzz");
        assert_eq!(fizzbuzz(20), "Buzz");
    }

    #[test]
    fn test_fizzbuzz_fizzbuzz() {
        assert_eq!(fizzbuzz(15), "FizzBuzz");
        assert_eq!(fizzbuzz(30), "FizzBuzz");
        assert_eq!(fizzbuzz(45), "FizzBuzz");
    }

    #[test]
    fn test_fizzbuzz_number() {
        assert_eq!(fizzbuzz(1), "1");
        assert_eq!(fizzbuzz(2), "2");
        assert_eq!(fizzbuzz(7), "7");
    }

    // Tests for fibonacci
    #[test]
    fn test_fibonacci_base() {
        assert_eq!(fibonacci(0), 0);
        assert_eq!(fibonacci(1), 1);
    }

    #[test]
    fn test_fibonacci_sequence() {
        assert_eq!(fibonacci(2), 1);
        assert_eq!(fibonacci(3), 2);
        assert_eq!(fibonacci(4), 3);
        assert_eq!(fibonacci(5), 5);
        assert_eq!(fibonacci(10), 55);
        assert_eq!(fibonacci(20), 6765);
    }
}
```

### 4.10 Solutions Mutantes

```rust
// MUTANT 1: Test qui passe toujours
#[test]
fn test_add() {
    let _ = add(2, 3);  // Pas d'assertion!
}

// MUTANT 2: Test avec mauvaise valeur attendue
#[test]
fn test_add() {
    assert_eq!(add(2, 3), 6);  // Devrait etre 5
}

// MUTANT 3: is_err() au lieu de is_ok()
#[test]
fn test_divide_ok() {
    assert!(divide(10, 2).is_err());  // Devrait etre is_ok()
}

// MUTANT 4: Ne teste pas les cas limites
#[test]
fn test_fibonacci() {
    assert_eq!(fibonacci(5), 5);
    // Manque: fibonacci(0), fibonacci(1)
}

// MUTANT 5: Test should_panic sans message
#[test]
#[should_panic]
fn test_panic() {
    // Si le code ne panic pas, le test passe quand meme
    divide(10, 2);  // Ne panic pas!
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

**Testing** en Rust:

1. **#[test]** - Marquer une fonction comme test
2. **assert!** - Verifier une condition booleenne
3. **assert_eq!/assert_ne!** - Comparer des valeurs
4. **#[should_panic]** - Test qui doit panic
5. **cargo test** - Executer tous les tests

### 5.3 Visualisation ASCII

```
STRUCTURE DES TESTS:

src/lib.rs
+----------------------------+
| pub fn add(a, b) -> i32    |
| pub fn divide(a, b) -> ... |
+----------------------------+
|                            |
| #[cfg(test)]               | <- Compile seulement pour tests
| mod tests {                |
|   use super::*;            | <- Importe le code a tester
|                            |
|   #[test]                  |
|   fn test_add() {          |
|     assert_eq!(add(2,3),5);|
|   }                        |
| }                          |
+----------------------------+

EXECUTION: cargo test

running 6 tests
test tests::test_add_positive ... ok
test tests::test_add_negative ... ok
test tests::test_divide_ok ... ok
test tests::test_divide_by_zero ... ok
test tests::test_palindrome_true ... ok
test tests::test_palindrome_false ... ok

test result: ok. 6 passed; 0 failed
```

### 5.5 Bonnes pratiques de tests

```rust
// 1. Nommer clairement
#[test]
fn test_divide_returns_error_on_zero() { ... }

// 2. Un test = une assertion principale
#[test]
fn test_add_positive_numbers() {
    assert_eq!(add(2, 3), 5);
}

// 3. Tester les cas limites
#[test]
fn test_fibonacci_zero() {
    assert_eq!(fibonacci(0), 0);
}

// 4. Tester les erreurs
#[test]
fn test_divide_by_zero_returns_error() {
    assert!(divide(10, 0).is_err());
}

// 5. Utiliser should_panic avec expected
#[test]
#[should_panic(expected = "index out of bounds")]
fn test_panic_message() {
    let v = vec![1, 2, 3];
    let _ = v[10];
}
```

---

## SECTION 7 : QCM

### Question 1
Comment executer tous les tests ?

A) rust test
B) cargo test
C) test --all
D) rustc test
E) make test

**Reponse correcte: B**

### Question 2
Que fait #[should_panic] ?

A) Le test doit reussir
B) Le test doit echouer
C) Le test doit panic pour reussir
D) Desactive le test
E) Ignore le panic

**Reponse correcte: C**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.7.17-a",
  "name": "testing",
  "language": "rust",
  "language_version": "edition2024",
  "files": ["src/lib.rs"],
  "tests": {
    "validation": "cargo test"
  }
}
```
