# Exercice 0.7.2 : scalars

**Module :**
0.7 — Introduction a Rust

**Concept :**
c — Types scalaires : entiers, flottants, caracteres et booleens

**Difficulte :**
★★☆☆☆☆☆☆☆☆ (2/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.1 (variables)
- Notion de representation binaire

**Domaines :**
Types, Arithmetique

**Duree estimee :**
30 min

**XP Base :**
60

**Complexite :**
T0 O(1) × S0 O(1)

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
| Rust | Operations arithmetiques, `checked_add`, `saturating_add`, `wrapping_add` |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Rust | Crates externes |

---

### 1.2 Consigne

#### Section Culture : "Size matters"

En Rust, chaque type entier a une taille fixe : `i8`, `i16`, `i32`, `i64`, `i128` pour les signes, et leurs equivalents `u8`, `u16`, `u32`, `u64`, `u128` pour les non-signes. Le suffixe indique le nombre de bits.

Cette precision vient du monde des systemes embarques ou chaque octet compte. Contrairement a Python ou JavaScript ou les nombres sont "magiques", Rust te force a penser a la representation memoire.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des fonctions qui manipulent les types scalaires de Rust :

1. `integer_operations` : Operations arithmetiques de base
2. `float_precision` : Manipulation de flottants
3. `char_to_digit` : Conversion caractere vers chiffre
4. `overflow_safe_add` : Addition avec gestion de l'overflow

**Entree :**

```rust
// src/lib.rs

/// Effectue des operations arithmetiques et retourne le resultat.
/// Calcule : (a + b) * c - d / e
///
/// # Arguments
///
/// * `a`, `b`, `c`, `d`, `e` - Les operandes (e != 0)
///
/// # Example
///
/// ```
/// assert_eq!(scalars::integer_operations(1, 2, 3, 10, 2), 4);
/// // (1 + 2) * 3 - 10 / 2 = 9 - 5 = 4
/// ```
pub fn integer_operations(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {
    // A implementer
}

/// Compare deux flottants avec une tolerance epsilon.
/// Retourne true si |a - b| < epsilon.
///
/// # Example
///
/// ```
/// assert!(scalars::float_approx_equal(0.1 + 0.2, 0.3, 1e-10));
/// ```
pub fn float_approx_equal(a: f64, b: f64, epsilon: f64) -> bool {
    // A implementer
}

/// Convertit un caractere chiffre en sa valeur numerique.
/// Retourne None si le caractere n'est pas un chiffre.
///
/// # Example
///
/// ```
/// assert_eq!(scalars::char_to_digit('5'), Some(5));
/// assert_eq!(scalars::char_to_digit('a'), None);
/// ```
pub fn char_to_digit(c: char) -> Option<u32> {
    // A implementer
}

/// Addition securisee qui retourne None en cas d'overflow.
///
/// # Example
///
/// ```
/// assert_eq!(scalars::overflow_safe_add(100, 50), Some(150));
/// assert_eq!(scalars::overflow_safe_add(u8::MAX, 1), None);
/// ```
pub fn overflow_safe_add(a: u8, b: u8) -> Option<u8> {
    // A implementer
}

/// Addition saturante qui plafonne au maximum.
///
/// # Example
///
/// ```
/// assert_eq!(scalars::saturating_addition(250u8, 10u8), 255);
/// ```
pub fn saturating_addition(a: u8, b: u8) -> u8 {
    // A implementer
}
```

**Sortie attendue :**

```
$ cargo test
running 5 tests
test tests::test_integer_operations ... ok
test tests::test_float_approx_equal ... ok
test tests::test_char_to_digit ... ok
test tests::test_overflow_safe_add ... ok
test tests::test_saturating_addition ... ok

test result: ok. 5 passed; 0 failed
```

**Contraintes :**
- `overflow_safe_add` doit utiliser `checked_add`
- `saturating_addition` doit utiliser `saturating_add`
- Pas de panic sur les operations
- Gestion correcte des cas limites

**Exemples :**

| Fonction | Input | Output |
|----------|-------|--------|
| `integer_operations(1, 2, 3, 10, 2)` | - | 4 |
| `integer_operations(0, 0, 0, 0, 1)` | - | 0 |
| `float_approx_equal(0.1 + 0.2, 0.3, 1e-10)` | - | true |
| `float_approx_equal(1.0, 2.0, 0.5)` | - | false |
| `char_to_digit('0')` | - | Some(0) |
| `char_to_digit('9')` | - | Some(9) |
| `char_to_digit('a')` | - | None |
| `overflow_safe_add(255, 1)` | - | None |
| `overflow_safe_add(100, 100)` | - | Some(200) |
| `saturating_addition(250, 10)` | - | 255 |

---

### 1.3 Prototype

```rust
pub fn integer_operations(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32;
pub fn float_approx_equal(a: f64, b: f64, epsilon: f64) -> bool;
pub fn char_to_digit(c: char) -> Option<u32>;
pub fn overflow_safe_add(a: u8, b: u8) -> Option<u8>;
pub fn saturating_addition(a: u8, b: u8) -> u8;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Le probleme de 0.1 + 0.2**

En IEEE 754, `0.1 + 0.2 != 0.3` car ces nombres n'ont pas de representation binaire exacte. C'est pourquoi on compare les flottants avec une tolerance.

```rust
assert!(0.1 + 0.2 != 0.3);  // C'est vrai !
assert!((0.1 + 0.2 - 0.3).abs() < 1e-10);  // Comparaison correcte
```

**Pourquoi checked_add existe ?**

En mode release, Rust ne verifie pas l'overflow par defaut (pour la performance). `checked_add` fournit une verification explicite.

```rust
// Mode debug : panic sur overflow
// Mode release : wrapping (silencieux)
let x: u8 = 255 + 1;  // Comportement depend du mode !
```

**Unicode et char**

En Rust, `char` est un scalar value Unicode (4 octets), pas un ASCII (1 octet). Un `char` peut representer des emojis !

```rust
let heart: char = '❤';  // Valide !
```

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Finance** | `checked_*` pour eviter les erreurs de calcul |
| **Embedded** | Types de taille fixe pour les registres |
| **Game Dev** | `saturating_*` pour les barres de vie/mana |
| **Cryptographie** | Operations modulaires avec `wrapping_*` |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo new scalars --lib
     Created library `scalars` package

$ cd scalars

$ cargo test
running 5 tests
test tests::test_integer_operations ... ok
test tests::test_float_approx_equal ... ok
test tests::test_char_to_digit ... ok
test tests::test_overflow_safe_add ... ok
test tests::test_saturating_addition ... ok

test result: ok. 5 passed; 0 failed

$ cargo clippy
    Finished dev [unoptimized + debuginfo] target(s)
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | int_ops_basic | `(1, 2, 3, 10, 2)` | 4 | 10 | Basic |
| 2 | int_ops_zero | `(0, 0, 0, 0, 1)` | 0 | 5 | Edge |
| 3 | int_ops_negative | `(-5, 10, 2, 6, 3)` | 8 | 10 | Basic |
| 4 | float_equal_true | `(0.1+0.2, 0.3, 1e-10)` | true | 10 | Basic |
| 5 | float_equal_false | `(1.0, 2.0, 0.5)` | false | 10 | Basic |
| 6 | char_digit_valid | `'5'` | Some(5) | 10 | Basic |
| 7 | char_digit_invalid | `'x'` | None | 10 | Edge |
| 8 | char_digit_zero | `'0'` | Some(0) | 5 | Edge |
| 9 | overflow_safe | `(255, 1)` | None | 15 | Safety |
| 10 | overflow_ok | `(100, 100)` | Some(200) | 5 | Basic |
| 11 | saturate_overflow | `(250, 10)` | 255 | 10 | Safety |

**Total : 100 points**

---

### 4.2 Tests de la moulinette

```rust
#[cfg(test)]
mod moulinette_tests {
    use super::*;

    #[test]
    fn test_integer_operations_basic() {
        assert_eq!(integer_operations(1, 2, 3, 10, 2), 4);
    }

    #[test]
    fn test_integer_operations_zero() {
        assert_eq!(integer_operations(0, 0, 0, 0, 1), 0);
    }

    #[test]
    fn test_integer_operations_negative() {
        assert_eq!(integer_operations(-5, 10, 2, 6, 3), 8);
    }

    #[test]
    fn test_float_approx_equal_true() {
        assert!(float_approx_equal(0.1 + 0.2, 0.3, 1e-10));
    }

    #[test]
    fn test_float_approx_equal_false() {
        assert!(!float_approx_equal(1.0, 2.0, 0.5));
    }

    #[test]
    fn test_float_approx_equal_exact() {
        assert!(float_approx_equal(5.0, 5.0, 0.0));
    }

    #[test]
    fn test_char_to_digit_valid() {
        assert_eq!(char_to_digit('5'), Some(5));
        assert_eq!(char_to_digit('0'), Some(0));
        assert_eq!(char_to_digit('9'), Some(9));
    }

    #[test]
    fn test_char_to_digit_invalid() {
        assert_eq!(char_to_digit('a'), None);
        assert_eq!(char_to_digit(' '), None);
        assert_eq!(char_to_digit('-'), None);
    }

    #[test]
    fn test_overflow_safe_add_overflow() {
        assert_eq!(overflow_safe_add(255, 1), None);
        assert_eq!(overflow_safe_add(200, 100), None);
    }

    #[test]
    fn test_overflow_safe_add_ok() {
        assert_eq!(overflow_safe_add(100, 100), Some(200));
        assert_eq!(overflow_safe_add(0, 0), Some(0));
    }

    #[test]
    fn test_saturating_addition() {
        assert_eq!(saturating_addition(250, 10), 255);
        assert_eq!(saturating_addition(255, 255), 255);
        assert_eq!(saturating_addition(100, 50), 150);
    }
}
```

---

### 4.3 Solution de reference (Rust)

```rust
/// Effectue des operations arithmetiques.
pub fn integer_operations(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {
    (a + b) * c - d / e
}

/// Compare deux flottants avec une tolerance.
pub fn float_approx_equal(a: f64, b: f64, epsilon: f64) -> bool {
    (a - b).abs() < epsilon
}

/// Convertit un caractere chiffre en valeur numerique.
pub fn char_to_digit(c: char) -> Option<u32> {
    c.to_digit(10)
}

/// Addition securisee avec verification d'overflow.
pub fn overflow_safe_add(a: u8, b: u8) -> Option<u8> {
    a.checked_add(b)
}

/// Addition saturante.
pub fn saturating_addition(a: u8, b: u8) -> u8 {
    a.saturating_add(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integer_operations() {
        assert_eq!(integer_operations(1, 2, 3, 10, 2), 4);
    }

    #[test]
    fn test_float_approx_equal() {
        assert!(float_approx_equal(0.1 + 0.2, 0.3, 1e-10));
    }

    #[test]
    fn test_char_to_digit() {
        assert_eq!(char_to_digit('5'), Some(5));
        assert_eq!(char_to_digit('a'), None);
    }

    #[test]
    fn test_overflow_safe_add() {
        assert_eq!(overflow_safe_add(255, 1), None);
        assert_eq!(overflow_safe_add(100, 50), Some(150));
    }

    #[test]
    fn test_saturating_addition() {
        assert_eq!(saturating_addition(250, 10), 255);
    }
}
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : char_to_digit manuel**

```rust
pub fn char_to_digit(c: char) -> Option<u32> {
    if c >= '0' && c <= '9' {
        Some(c as u32 - '0' as u32)
    } else {
        None
    }
}
// Accepte, equivalent a to_digit(10)
```

**Alternative 2 : float_approx_equal avec <= au lieu de <**

```rust
pub fn float_approx_equal(a: f64, b: f64, epsilon: f64) -> bool {
    (a - b).abs() <= epsilon
}
// Accepte, semantiquement equivalent pour epsilon > 0
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : Pas de gestion d'overflow**

```rust
// REFUSE : Peut paniquer en mode debug
pub fn overflow_safe_add(a: u8, b: u8) -> Option<u8> {
    Some(a + b)
}
```
**Pourquoi refuse :** L'addition directe peut overflow/panic.

**Refus 2 : Comparaison directe de flottants**

```rust
// REFUSE : Ne gere pas l'imprecision IEEE 754
pub fn float_approx_equal(a: f64, b: f64, _epsilon: f64) -> bool {
    a == b
}
```
**Pourquoi refuse :** 0.1 + 0.2 == 0.3 retourne false en IEEE 754.

**Refus 3 : Panic sur caractere invalide**

```rust
// REFUSE : Panic au lieu de retourner None
pub fn char_to_digit(c: char) -> Option<u32> {
    Some(c.to_digit(10).unwrap())
}
```
**Pourquoi refuse :** `unwrap()` panic si None, doit propager l'Option.

---

### 4.9 spec.json (ENGINE v22.1)

```json
{
  "name": "scalars",
  "language": "rust",
  "language_version": "edition 2024",
  "type": "code",
  "tier": 1,
  "tier_info": "Concept isole",
  "tags": ["module0.7", "types", "arithmetic", "overflow", "phase0"],
  "passing_score": 70,

  "function": {
    "name": "integer_operations",
    "prototype": "pub fn integer_operations(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32",
    "return_type": "i32",
    "parameters": [
      {"name": "a", "type": "i32"},
      {"name": "b", "type": "i32"},
      {"name": "c", "type": "i32"},
      {"name": "d", "type": "i32"},
      {"name": "e", "type": "i32"}
    ]
  },

  "driver": {
    "edge_cases": [
      {
        "name": "division_by_one",
        "args": [0, 0, 0, 0, 1],
        "expected": 0,
        "is_trap": false
      },
      {
        "name": "overflow_boundary",
        "args": [255, 1],
        "expected": null,
        "is_trap": true,
        "trap_explanation": "u8::MAX + 1 doit retourner None"
      }
    ]
  },

  "norm": {
    "allowed_functions": ["checked_add", "saturating_add", "to_digit", "abs"],
    "forbidden_functions": [],
    "check_security": false,
    "check_memory": false,
    "blocking": false
  }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Mauvaise priorite des operateurs**

```rust
/* Mutant A (Boundary) : Priorite incorrecte */
pub fn integer_operations(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {
    a + b * c - d / e  // Mauvaise priorite : * et / avant + et -
}
// Pourquoi faux : (a + b) * c != a + b * c
// Ce qui etait pense : "Les parentheses ne sont pas necessaires"
```

**Mutant B (Logic) : Comparaison sans valeur absolue**

```rust
/* Mutant B (Logic) : Oubli de abs() */
pub fn float_approx_equal(a: f64, b: f64, epsilon: f64) -> bool {
    a - b < epsilon  // Manque abs(), echoue si a < b
}
// Pourquoi faux : Si a < b, la difference est negative
// Ce qui etait pense : "a est toujours plus grand"
```

**Mutant C (Type) : Mauvaise base pour to_digit**

```rust
/* Mutant C (Type) : Base 16 au lieu de 10 */
pub fn char_to_digit(c: char) -> Option<u32> {
    c.to_digit(16)  // Accepte a-f comme chiffres !
}
// Pourquoi faux : 'a' retourne Some(10), pas None
// Ce qui etait pense : "16 c'est mieux pour les hex"
```

**Mutant D (Safety) : Addition sans checked**

```rust
/* Mutant D (Safety) : Pas de verification */
pub fn overflow_safe_add(a: u8, b: u8) -> Option<u8> {
    Some(a.wrapping_add(b))  // Wrap au lieu de None
}
// Pourquoi faux : 255 + 1 retourne Some(0), pas None
// Ce qui etait pense : "wrapping c'est safe"
```

**Mutant E (Return) : saturating_add oublie**

```rust
/* Mutant E (Return) : Addition normale */
pub fn saturating_addition(a: u8, b: u8) -> u8 {
    a + b  // Peut paniquer ou wrapper
}
// Pourquoi faux : 250 + 10 peut donner 4 (wrap) au lieu de 255
// Ce qui etait pense : "L'addition suffit"
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Types entiers | i8/u8 a i128/u128, isize/usize | Fondamental |
| Types flottants | f32, f64, precision IEEE 754 | Fondamental |
| Type char | Unicode scalar value | Important |
| Overflow handling | checked, saturating, wrapping | Critique |
| Comparaison flottants | Tolerance epsilon | Important |

---

### 5.2 LDA — Traduction litterale en MAJUSCULES

```
FONCTION integer_operations QUI PREND a, b, c, d, e COMME ENTIERS SIGNES 32 BITS
DEBUT FONCTION
    CALCULER somme COMME a PLUS b
    CALCULER produit COMME somme MULTIPLIE PAR c
    CALCULER quotient COMME d DIVISE PAR e
    CALCULER resultat COMME produit MOINS quotient
    RETOURNER resultat
FIN FONCTION

FONCTION char_to_digit QUI PREND c COMME CARACTERE
DEBUT FONCTION
    SI c EST UN CHIFFRE (ENTRE '0' ET '9') ALORS
        RETOURNER Some(VALEUR NUMERIQUE DE c)
    SINON
        RETOURNER None
    FIN SI
FIN FONCTION

FONCTION overflow_safe_add QUI PREND a, b COMME ENTIERS NON SIGNES 8 BITS
DEBUT FONCTION
    SI a PLUS b DEPASSE 255 ALORS
        RETOURNER None
    SINON
        RETOURNER Some(a PLUS b)
    FIN SI
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

**Types entiers en memoire :**

```
u8  (1 octet):   [00000000] - [11111111]     0 a 255
i8  (1 octet):   [10000000] - [01111111]    -128 a 127

u16 (2 octets):  [00000000 00000000] - [11111111 11111111]
                  0 a 65535

i32 (4 octets):  [10000000 00000000 00000000 00000000] - [01111111 ...]
                 -2,147,483,648 a 2,147,483,647
```

**Representation IEEE 754 de f64 :**

```
f64 (8 octets = 64 bits):
┌─────────┬───────────────┬─────────────────────────────────────────────┐
│ 1 bit   │   11 bits     │                52 bits                      │
│ signe   │   exposant    │                mantisse                     │
└─────────┴───────────────┴─────────────────────────────────────────────┘

0.1 en binaire = 0.0001100110011001100110011... (infini periodique !)
                 ^---- C'est pourquoi 0.1 n'est pas exact
```

**Overflow visualise :**

```
u8: 255 + 1

  11111111   (255)
+ 00000001   (1)
──────────
 100000000   <- 9 bits ! Overflow !

checked_add  -> None
wrapping_add -> 00000000 (0)
saturating_add -> 11111111 (255)
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Division entiere

```rust
let x: i32 = 5 / 2;  // x = 2, pas 2.5 !
let y: f64 = 5.0 / 2.0;  // y = 2.5
```

#### Piege 2 : Comparaison de flottants

```rust
// FAUX
if 0.1 + 0.2 == 0.3 {  // false !
    println!("Equal");
}

// CORRECT
if (0.1 + 0.2 - 0.3).abs() < 1e-10 {
    println!("Approximately equal");
}
```

#### Piege 3 : char vs u8

```rust
let c: char = 'A';
let b: u8 = b'A';  // Byte literal

// char = 4 bytes (Unicode)
// u8 = 1 byte (ASCII)
```

#### Piege 4 : Overflow en release

```rust
// Mode debug : panic
// Mode release : wrap silencieusement

let x: u8 = 255;
let y = x + 1;  // Debug: panic! Release: y = 0
```

---

### 5.5 Cours Complet

#### 5.5.1 Types entiers

| Type | Taille | Plage |
|------|--------|-------|
| i8/u8 | 1 octet | -128..127 / 0..255 |
| i16/u16 | 2 octets | -32768..32767 / 0..65535 |
| i32/u32 | 4 octets | -2^31..2^31-1 / 0..2^32-1 |
| i64/u64 | 8 octets | -2^63..2^63-1 / 0..2^64-1 |
| i128/u128 | 16 octets | -2^127..2^127-1 / 0..2^128-1 |
| isize/usize | arch | Depend de l'architecture |

#### 5.5.2 Litteraux numeriques

```rust
let decimal = 98_222;      // Underscore pour lisibilite
let hex = 0xff;            // Hexadecimal
let octal = 0o77;          // Octal
let binary = 0b1111_0000;  // Binaire
let byte = b'A';           // Byte (u8)
```

#### 5.5.3 Methodes d'overflow

```rust
let a: u8 = 250;
let b: u8 = 10;

// checked: retourne Option
a.checked_add(b);  // None

// wrapping: modulo 2^n
a.wrapping_add(b);  // 4

// saturating: plafonne
a.saturating_add(b);  // 255

// overflowing: retourne (result, did_overflow)
a.overflowing_add(b);  // (4, true)
```

#### 5.5.4 Conversion de types

```rust
let x: i32 = 42;
let y: i64 = x as i64;  // Conversion explicite

let f: f64 = 3.14;
let i: i32 = f as i32;  // Tronque : 3

// TryFrom pour conversions fallibles
let big: i64 = 300;
let small: Result<u8, _> = u8::try_from(big);  // Err
```

---

### 5.6 Normes avec explications pedagogiques

```
┌─────────────────────────────────────────────────────────────────┐
│ HORS NORME                                                      │
├─────────────────────────────────────────────────────────────────┤
│ pub fn overflow_safe_add(a: u8, b: u8) -> Option<u8> {          │
│     if a as u16 + b as u16 > 255 { None } else { Some(a+b) } }  │
├─────────────────────────────────────────────────────────────────┤
│ CONFORME                                                        │
├─────────────────────────────────────────────────────────────────┤
│ pub fn overflow_safe_add(a: u8, b: u8) -> Option<u8> {          │
│     a.checked_add(b)                                           │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ POURQUOI ?                                                      │
│ - Utilise les methodes standard de Rust                        │
│ - Plus lisible et idiomatique                                  │
│ - Evite les conversions manuelles                              │
└─────────────────────────────────────────────────────────────────┘
```

---

### 5.7 Simulation avec trace d'execution

```
overflow_safe_add(250, 10):
┌───────┬─────────────────────────────────────────────────────────┐
│ Etape │ Operation                                               │
├───────┼─────────────────────────────────────────────────────────┤
│   1   │ Appel: a = 250, b = 10                                 │
│   2   │ checked_add calcule 250 + 10 = 260                     │
│   3   │ 260 > u8::MAX (255)                                    │
│   4   │ Retourne None                                          │
└───────┴─────────────────────────────────────────────────────────┘

overflow_safe_add(100, 50):
┌───────┬─────────────────────────────────────────────────────────┐
│ Etape │ Operation                                               │
├───────┼─────────────────────────────────────────────────────────┤
│   1   │ Appel: a = 100, b = 50                                 │
│   2   │ checked_add calcule 100 + 50 = 150                     │
│   3   │ 150 <= u8::MAX (255)                                   │
│   4   │ Retourne Some(150)                                     │
└───────┴─────────────────────────────────────────────────────────┘
```

---

### 5.8 Mnemotechniques

**COWS = Checked Overflowing Wrapping Saturating**

Les 4 methodes pour gerer l'overflow :
- **C**hecked : retourne Option
- **O**verflowing : retourne (result, bool)
- **W**rapping : modulo
- **S**aturating : plafonne

**IEEE = Inexact Even Errors Expected**

Les flottants IEEE 754 ne sont pas exacts, toujours comparer avec epsilon.

---

### 5.9 Applications pratiques

| Scenario | Solution |
|----------|----------|
| **Calcul financier** | `checked_*` pour detecter les erreurs |
| **Barre de vie jeu** | `saturating_sub` pour ne pas descendre sous 0 |
| **Cryptographie** | `wrapping_*` pour arithmetique modulaire |
| **Parsing nombres** | `char::to_digit()` pour validation |

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Division entiere | Resultat tronque | Utiliser f64 si besoin |
| 2 | Comparaison flottants | false positif/negatif | Comparer avec epsilon |
| 3 | Overflow silent | Resultat incorrect | Utiliser checked_* |
| 4 | char vs u8 | 4 bytes vs 1 byte | Choisir selon le cas |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quel est le resultat de `5i32 / 2i32` ?

- A) 2.5
- B) 2
- C) 3
- D) Erreur

**Reponse : B** — Division entiere tronque vers zero.

---

### Question 2 (3 points)
Quelle methode utiliser pour une addition qui plafonne au max ?

- A) `checked_add`
- B) `wrapping_add`
- C) `saturating_add`
- D) `overflowing_add`

**Reponse : C** — `saturating_add` plafonne a la valeur maximale.

---

### Question 3 (4 points)
Pourquoi `0.1 + 0.2 != 0.3` en Rust ?

- A) Bug de Rust
- B) Representation IEEE 754 inexacte
- C) Les flottants sont immutables
- D) Erreur de type

**Reponse : B** — 0.1 et 0.2 n'ont pas de representation binaire exacte.

---

### Question 4 (5 points)
Que retourne `'5'.to_digit(10)` ?

- A) 5
- B) Some(5)
- C) "5"
- D) None

**Reponse : B** — `to_digit` retourne `Option<u32>`.

---

### Question 5 (5 points)
Quelle est la taille d'un `char` en Rust ?

- A) 1 octet
- B) 2 octets
- C) 4 octets
- D) Variable

**Reponse : C** — 4 octets pour representer tout scalar Unicode.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.2 |
| **Nom** | scalars |
| **Difficulte** | 2/10 |
| **Duree** | 30 min |
| **XP Base** | 60 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | integers, floats, char, overflow |
| **Prerequis** | variables |
| **Domaines** | Types, Arithmetique |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.2-scalars",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.2",
      "exercise_name": "scalars",
      "module": "0.7",
      "module_name": "Introduction a Rust",
      "concept": "c",
      "concept_name": "Types scalaires",
      "type": "code",
      "tier": 1,
      "difficulty": 2,
      "difficulty_stars": "2/10",
      "languages": ["rust"],
      "duration_minutes": 30,
      "xp_base": 60,
      "prerequisites": ["0.7.1"],
      "domains": ["Types", "Arithmetic"],
      "tags": ["integers", "floats", "char", "overflow", "checked"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
