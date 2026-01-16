# Exercice 0.7.7-a : strings

**Module :**
0.7.7 — Chaines de caracteres

**Concept :**
a-e — String vs &str, from/into, push_str, format!, UTF-8

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
0.7.6 (slices)

**Domaines :**
Algo, Encodage

**Duree estimee :**
150 min

**XP Base :**
220

**Complexite :**
T2 O(n) x S2 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `src/lib.rs`

### 1.2 Consigne

Implementer des fonctions manipulant les chaines de caracteres.

**Ta mission :**

```rust
// Concatener deux chaines
fn concat(s1: &str, s2: &str) -> String;

// Repeter une chaine n fois
fn repeat_string(s: &str, n: usize) -> String;

// Inverser une chaine
fn reverse_string(s: &str) -> String;

// Compter les occurrences d'un caractere
fn count_char(s: &str, c: char) -> usize;

// Remplacer un caractere par un autre
fn replace_char(s: &str, from: char, to: char) -> String;

// Verifier si palindrome
fn is_palindrome(s: &str) -> bool;

// Capitaliser le premier caractere
fn capitalize(s: &str) -> String;

// Formatter un message
fn greet(name: &str, age: u32) -> String;
```

**Comportement:**

1. `concat("hello", " world")` -> "hello world"
2. `repeat_string("ab", 3)` -> "ababab"
3. `reverse_string("hello")` -> "olleh"
4. `count_char("hello", 'l')` -> 2
5. `is_palindrome("radar")` -> true

**Exemples:**
```rust
let s = concat("Hello", " World");
println!("{}", s);  // "Hello World"

let repeated = repeat_string("ab", 3);
println!("{}", repeated);  // "ababab"

let reversed = reverse_string("Rust");
println!("{}", reversed);  // "tsuR"

let cap = capitalize("rust");
println!("{}", cap);  // "Rust"

let msg = greet("Alice", 30);
println!("{}", msg);  // "Hello, Alice! You are 30 years old."
```

### 1.3 Prototype

```rust
// src/lib.rs

pub fn concat(s1: &str, s2: &str) -> String {
    todo!()
}

pub fn repeat_string(s: &str, n: usize) -> String {
    todo!()
}

pub fn reverse_string(s: &str) -> String {
    todo!()
}

pub fn count_char(s: &str, c: char) -> usize {
    todo!()
}

pub fn replace_char(s: &str, from: char, to: char) -> String {
    todo!()
}

pub fn is_palindrome(s: &str) -> bool {
    todo!()
}

pub fn capitalize(s: &str) -> String {
    todo!()
}

pub fn greet(name: &str, age: u32) -> String {
    todo!()
}
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | concat | combined | 10 |
| T02 | repeat_string | repeated | 10 |
| T03 | reverse_string | reversed | 15 |
| T04 | count_char | count | 10 |
| T05 | replace_char | replaced | 15 |
| T06 | is_palindrome true | true | 10 |
| T07 | is_palindrome false | false | 10 |
| T08 | capitalize | capitalized | 10 |
| T09 | greet | formatted | 10 |

### 4.3 Solution de reference

```rust
pub fn concat(s1: &str, s2: &str) -> String {
    format!("{}{}", s1, s2)
    // ou: s1.to_string() + s2
    // ou: [s1, s2].concat()
}

pub fn repeat_string(s: &str, n: usize) -> String {
    s.repeat(n)
}

pub fn reverse_string(s: &str) -> String {
    s.chars().rev().collect()
}

pub fn count_char(s: &str, c: char) -> usize {
    s.chars().filter(|&ch| ch == c).count()
}

pub fn replace_char(s: &str, from: char, to: char) -> String {
    s.chars()
        .map(|c| if c == from { to } else { c })
        .collect()
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

    // Alternative elegant:
    // s.chars().eq(s.chars().rev())
}

pub fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => {
            first.to_uppercase().chain(chars).collect()
        }
    }
}

pub fn greet(name: &str, age: u32) -> String {
    format!("Hello, {}! You are {} years old.", name, age)
}
```

### 4.10 Solutions Mutantes

```rust
// MUTANT 1: reverse_string sur bytes (pas UTF-8 safe)
pub fn reverse_string(s: &str) -> String {
    let bytes: Vec<u8> = s.bytes().rev().collect();
    String::from_utf8(bytes).unwrap()  // PANIC sur UTF-8 multi-byte!
}

// MUTANT 2: count_char sur bytes
pub fn count_char(s: &str, c: char) -> usize {
    s.bytes().filter(|&b| b as char == c).count()
    // Incorrect pour caracteres multi-byte
}

// MUTANT 3: is_palindrome case-sensitive
pub fn is_palindrome(s: &str) -> bool {
    s.chars().eq(s.chars().rev())
    // "Radar" retourne false (devrait ignorer la casse?)
}

// MUTANT 4: capitalize ASCII only
pub fn capitalize(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let first = s.chars().next().unwrap().to_ascii_uppercase();
    format!("{}{}", first, &s[1..])  // &s[1..] peut panic sur UTF-8!
}

// MUTANT 5: greet avec mauvais format
pub fn greet(name: &str, age: u32) -> String {
    format!("Hello {}! You are {} years old.", name, age)
    // Manque la virgule apres "Hello"
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Les **chaines** en Rust:

1. **String** - Owned, mutable, heap-allocated
2. **&str** - Borrowed string slice
3. **UTF-8** - Rust strings sont toujours UTF-8 valide
4. **Chars vs Bytes** - Iterer sur caracteres Unicode, pas bytes

### 5.3 Visualisation ASCII

```
STRING INTERNALS:

let s = String::from("hello");

Stack:              Heap:
+----------+        +---+---+---+---+---+
| ptr      | -----> | h | e | l | l | o |
+----------+        +---+---+---+---+---+
| len: 5   |
+----------+
| cap: 5   |
+----------+

UTF-8 ENCODING:

"hello"  -> 5 bytes, 5 chars
"cafe"   -> 5 bytes, 5 chars (si 'e' ASCII)
"cafe"   -> 6 bytes, 5 chars (si 'e' avec accent)

let s = "cafe";  // e avec accent
s.len()          // 5 (bytes)
s.chars().count() // 4 (caracteres)

METHODS CHAIN:
"hello"
  .chars()      // Iterateur sur caracteres
  .rev()        // Inverse l'iterateur
  .collect()    // Collecte en String
  = "olleh"
```

### 5.5 String vs &str cheatsheet

```rust
// Creation
let s: String = String::from("hello");
let s: String = "hello".to_string();
let s: String = format!("hello {}", name);

let slice: &str = "hello";  // String literal
let slice: &str = &s[..];   // Borrow from String

// Concatenation
let s = s1 + &s2;           // Consomme s1
let s = format!("{}{}", s1, s2);  // Ne consomme pas

// Modification
s.push('!');                // Ajoute un char
s.push_str(" world");       // Ajoute un &str

// Conversion
let s: String = slice.to_string();
let slice: &str = s.as_str();
```

---

## SECTION 7 : QCM

### Question 1
Quelle methode ajoute une chaine a un String ?

A) push()
B) push_str()
C) append()
D) add()
E) concat()

**Reponse correcte: B**

### Question 2
Pourquoi s.len() peut etre different de s.chars().count() ?

A) Bug dans Rust
B) len() compte les bytes, chars() les caracteres Unicode
C) chars() ignore les espaces
D) len() inclut le terminateur null
E) Pas de difference

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.7.7-a",
  "name": "strings",
  "language": "rust",
  "language_version": "edition2024",
  "files": ["src/lib.rs"],
  "tests": {
    "basic": "string_basic_tests",
    "manipulation": "string_manipulation_tests",
    "utf8": "utf8_tests"
  }
}
```
