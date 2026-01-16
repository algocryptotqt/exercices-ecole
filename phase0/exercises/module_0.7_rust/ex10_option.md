# Exercice 0.7.10-a : option

**Module :**
0.7.10 — Option<T>

**Concept :**
a-e — Some, None, unwrap, map, and_then, unwrap_or

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
0.7.9 (enums)

**Domaines :**
Algo, Safety

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

Implementer des fonctions utilisant Option pour gerer l'absence de valeur.

**Ta mission :**

```rust
// Trouver le premier element pair
pub fn find_first_even(numbers: &[i32]) -> Option<i32>;

// Division safe
pub fn safe_divide(a: i32, b: i32) -> Option<i32>;

// Obtenir le caractere a un index
pub fn char_at(s: &str, index: usize) -> Option<char>;

// Chainer des operations
pub fn parse_and_double(s: &str) -> Option<i32>;

// Combiner deux Options
pub fn add_options(a: Option<i32>, b: Option<i32>) -> Option<i32>;

// Fournir une valeur par defaut
pub fn unwrap_or_default(opt: Option<i32>, default: i32) -> i32;

// Transformer le contenu
pub fn double_if_some(opt: Option<i32>) -> Option<i32>;

// Filtrer une Option
pub fn filter_positive(opt: Option<i32>) -> Option<i32>;
```

**Comportement:**

1. `find_first_even(&[1, 3, 4, 5])` -> Some(4)
2. `safe_divide(10, 0)` -> None
3. `parse_and_double("5")` -> Some(10)
4. `add_options(Some(1), Some(2))` -> Some(3)

**Exemples:**
```rust
let numbers = vec![1, 3, 5, 6, 7];
match find_first_even(&numbers) {
    Some(n) => println!("Found: {}", n),  // Found: 6
    None => println!("No even number"),
}

let result = parse_and_double("42");
println!("{:?}", result);  // Some(84)

let result = parse_and_double("not_a_number");
println!("{:?}", result);  // None
```

### 1.3 Prototype

```rust
// src/lib.rs

pub fn find_first_even(numbers: &[i32]) -> Option<i32> {
    todo!()
}

pub fn safe_divide(a: i32, b: i32) -> Option<i32> {
    todo!()
}

pub fn char_at(s: &str, index: usize) -> Option<char> {
    todo!()
}

pub fn parse_and_double(s: &str) -> Option<i32> {
    todo!()
}

pub fn add_options(a: Option<i32>, b: Option<i32>) -> Option<i32> {
    todo!()
}

pub fn unwrap_or_default(opt: Option<i32>, default: i32) -> i32 {
    todo!()
}

pub fn double_if_some(opt: Option<i32>) -> Option<i32> {
    todo!()
}

pub fn filter_positive(opt: Option<i32>) -> Option<i32> {
    todo!()
}
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | find_first_even found | Some | 10 |
| T02 | find_first_even none | None | 10 |
| T03 | safe_divide OK | Some | 10 |
| T04 | safe_divide zero | None | 15 |
| T05 | parse_and_double OK | Some(doubled) | 15 |
| T06 | add_options both Some | Some(sum) | 10 |
| T07 | add_options one None | None | 10 |
| T08 | filter_positive | correct | 10 |
| T09 | unwrap_or_default | correct | 10 |

### 4.3 Solution de reference

```rust
pub fn find_first_even(numbers: &[i32]) -> Option<i32> {
    numbers.iter().find(|&&n| n % 2 == 0).copied()
}

pub fn safe_divide(a: i32, b: i32) -> Option<i32> {
    if b == 0 {
        None
    } else {
        Some(a / b)
    }
}

pub fn char_at(s: &str, index: usize) -> Option<char> {
    s.chars().nth(index)
}

pub fn parse_and_double(s: &str) -> Option<i32> {
    s.parse::<i32>().ok().map(|n| n * 2)
}

pub fn add_options(a: Option<i32>, b: Option<i32>) -> Option<i32> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x + y),
        _ => None,
    }
    // Alternative: a.and_then(|x| b.map(|y| x + y))
    // Alternative: Some(a? + b?)
}

pub fn unwrap_or_default(opt: Option<i32>, default: i32) -> i32 {
    opt.unwrap_or(default)
}

pub fn double_if_some(opt: Option<i32>) -> Option<i32> {
    opt.map(|n| n * 2)
}

pub fn filter_positive(opt: Option<i32>) -> Option<i32> {
    opt.filter(|&n| n > 0)
}
```

### 4.10 Solutions Mutantes

```rust
// MUTANT 1: find_first_even retourne premier element
pub fn find_first_even(numbers: &[i32]) -> Option<i32> {
    numbers.first().copied()  // Premier, pas premier pair
}

// MUTANT 2: safe_divide panic sur zero
pub fn safe_divide(a: i32, b: i32) -> Option<i32> {
    Some(a / b)  // Panic si b == 0!
}

// MUTANT 3: parse_and_double unwrap sans check
pub fn parse_and_double(s: &str) -> Option<i32> {
    Some(s.parse::<i32>().unwrap() * 2)  // Panic si parse echoue
}

// MUTANT 4: add_options retourne Some meme si None
pub fn add_options(a: Option<i32>, b: Option<i32>) -> Option<i32> {
    Some(a.unwrap_or(0) + b.unwrap_or(0))
    // Retourne Some meme si a ou b est None
}

// MUTANT 5: filter_positive garde 0
pub fn filter_positive(opt: Option<i32>) -> Option<i32> {
    opt.filter(|&n| n >= 0)  // >= au lieu de >, garde 0
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

**Option<T>** - Le type pour l'absence potentielle de valeur:

1. **Some(value)** - Contient une valeur
2. **None** - Absence de valeur
3. **Pas de null** - Rust n'a pas de null pointer
4. **Combinators** - map, and_then, unwrap_or pour transformer

### 5.3 Visualisation ASCII

```
OPTION MEMORY:

Option<i32>::Some(42)
+-----+-------+
| tag |  42   |
|  1  |       |
+-----+-------+

Option<i32>::None
+-----+-------+
| tag | undef |
|  0  |       |
+-----+-------+

COMBINATORS CHAIN:

Some(5)
  |
  | .map(|n| n * 2)
  v
Some(10)
  |
  | .filter(|&n| n > 5)
  v
Some(10)
  |
  | .and_then(|n| if n < 100 { Some(n) } else { None })
  v
Some(10)

None
  |
  | .map(|n| n * 2)
  v
None  (map ne fait rien sur None)
```

### 5.5 Pattern matching vs Combinators

```rust
// Pattern matching (verbose mais clair)
let result = match option {
    Some(n) => Some(n * 2),
    None => None,
};

// Combinator (concis)
let result = option.map(|n| n * 2);

// Chaining (elegant)
let result = option
    .map(|n| n * 2)
    .filter(|&n| n > 0)
    .unwrap_or(0);

// ? operator (dans fonctions retournant Option)
fn process(opt: Option<i32>) -> Option<i32> {
    let value = opt?;  // Retourne None si opt est None
    Some(value * 2)
}
```

---

## SECTION 7 : QCM

### Question 1
Que retourne `Some(5).map(|n| n * 2)` ?

A) 10
B) Some(10)
C) None
D) Erreur
E) Some(Some(10))

**Reponse correcte: B**

### Question 2
Quelle methode retourne une valeur par defaut si None ?

A) unwrap()
B) unwrap_or()
C) expect()
D) get()
E) default()

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.7.10-a",
  "name": "option",
  "language": "rust",
  "language_version": "edition2024",
  "files": ["src/lib.rs"],
  "tests": {
    "basic": "option_basic_tests",
    "combinators": "option_combinator_tests"
  }
}
```
