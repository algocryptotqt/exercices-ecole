# Exercice 0.7.1 : variables

**Module :**
0.7 — Introduction a Rust

**Concept :**
b — Variables immutables, mutables, constantes et shadowing

**Difficulte :**
★★☆☆☆☆☆☆☆☆ (2/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.0 (cargo_init)
- Notion de variable en programmation

**Domaines :**
Variables, Mutabilite

**Duree estimee :**
25 min

**XP Base :**
50

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
| Rust | `format!`, `println!`, operations arithmetiques de base |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Rust | Aucune restriction |

---

### 1.2 Consigne

#### Section Culture : "Let it be... mutable?"

En Rust, les variables sont immutables par defaut. Ce n'est pas une contrainte arbitraire mais une decision de design pour encourager la programmation fonctionnelle et eviter les bugs lies aux mutations inattendues.

Ce concept vient de langages fonctionnels comme Haskell ou OCaml, ou l'immutabilite est la norme. Rust adopte une approche pragmatique : immutable par defaut, mais mutable sur demande explicite avec `mut`.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer plusieurs fonctions qui demontrent la maitrise des variables en Rust :

1. `increment_counter` : Utilise une variable mutable
2. `shadow_and_transform` : Utilise le shadowing pour changer de type
3. `get_max_value` : Retourne une constante
4. `format_greeting` : Utilise plusieurs variables avec println!

**Entree :**

```rust
// src/lib.rs

/// Incremente un compteur de 1 a n et retourne la somme.
///
/// # Arguments
///
/// * `n` - Le nombre d'iterations
///
/// # Example
///
/// ```
/// assert_eq!(variables::increment_counter(5), 15); // 1+2+3+4+5
/// ```
pub fn increment_counter(n: u32) -> u32 {
    // A implementer avec une variable mutable
}

/// Transforme une chaine en sa longueur puis en son carre.
/// Utilise le shadowing pour changer le type de la variable.
///
/// # Arguments
///
/// * `input` - La chaine d'entree
///
/// # Example
///
/// ```
/// assert_eq!(variables::shadow_and_transform("hello"), 25); // len=5, 5*5=25
/// ```
pub fn shadow_and_transform(input: &str) -> usize {
    // A implementer avec shadowing
}

/// Retourne la valeur maximale definie comme constante.
pub const MAX_VALUE: u32 = 1000;

pub fn get_max_value() -> u32 {
    // A implementer
}

/// Formate un message avec nom, age et ville.
///
/// # Arguments
///
/// * `name` - Le nom de la personne
/// * `age` - L'age de la personne
/// * `city` - La ville de residence
///
/// # Example
///
/// ```
/// let msg = variables::format_greeting("Alice", 30, "Paris");
/// assert_eq!(msg, "Hello Alice, you are 30 years old and live in Paris.");
/// ```
pub fn format_greeting(name: &str, age: u32, city: &str) -> String {
    // A implementer
}
```

**Sortie attendue :**

```
$ cargo test
running 4 tests
test tests::test_increment_counter ... ok
test tests::test_shadow_and_transform ... ok
test tests::test_get_max_value ... ok
test tests::test_format_greeting ... ok

test result: ok. 4 passed; 0 failed
```

**Contraintes :**
- `increment_counter` DOIT utiliser une variable `mut`
- `shadow_and_transform` DOIT utiliser le shadowing (meme nom, types differents)
- `MAX_VALUE` DOIT etre une constante `const`, pas `static`
- Pas de warnings clippy

**Exemples :**

| Fonction | Input | Output |
|----------|-------|--------|
| `increment_counter(5)` | 5 | 15 |
| `increment_counter(0)` | 0 | 0 |
| `increment_counter(10)` | 10 | 55 |
| `shadow_and_transform("hi")` | "hi" | 4 |
| `shadow_and_transform("")` | "" | 0 |
| `get_max_value()` | - | 1000 |
| `format_greeting("Bob", 25, "Lyon")` | - | "Hello Bob, you are 25 years old and live in Lyon." |

---

### 1.3 Prototype

```rust
pub fn increment_counter(n: u32) -> u32;
pub fn shadow_and_transform(input: &str) -> usize;
pub const MAX_VALUE: u32 = 1000;
pub fn get_max_value() -> u32;
pub fn format_greeting(name: &str, age: u32, city: &str) -> String;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Pourquoi immutable par defaut ?**

Des etudes montrent que 95% des variables dans un programme typique ne sont jamais modifiees apres leur initialisation. Rust rend ce cas par defaut, et force le programmeur a etre explicite pour les 5% restants.

**const vs static**

- `const` : valeur inline a la compilation, pas d'adresse fixe
- `static` : adresse fixe en memoire, peut etre mutable (unsafe)

```rust
const PI: f64 = 3.14159;      // Copie partout ou utilise
static COUNTER: u32 = 0;      // Une seule instance en memoire
```

**Le shadowing n'est pas une reassignation**

Le shadowing cree une NOUVELLE variable avec le meme nom. L'ancienne variable existe toujours mais est "masquee" (shadowed).

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Game Dev** | `mut` pour les etats de jeu (position, score) |
| **Backend** | Constantes pour la configuration (ports, timeouts) |
| **Embedded** | `static mut` pour les registres hardware |
| **Data Science** | Shadowing pour transformer les donnees etape par etape |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo new variables --lib
     Created library `variables` package

$ cd variables

$ cat src/lib.rs
// Implementation...

$ cargo test
running 4 tests
test tests::test_increment_counter ... ok
test tests::test_shadow_and_transform ... ok
test tests::test_get_max_value ... ok
test tests::test_format_greeting ... ok

test result: ok. 4 passed; 0 failed

$ cargo clippy
    Finished dev [unoptimized + debuginfo] target(s)
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | increment_basic | `increment_counter(5)` | 15 | 10 | Basic |
| 2 | increment_zero | `increment_counter(0)` | 0 | 10 | Edge |
| 3 | increment_large | `increment_counter(100)` | 5050 | 10 | Basic |
| 4 | shadow_basic | `shadow_and_transform("hello")` | 25 | 15 | Basic |
| 5 | shadow_empty | `shadow_and_transform("")` | 0 | 10 | Edge |
| 6 | shadow_long | `shadow_and_transform("abcdefghij")` | 100 | 10 | Basic |
| 7 | max_value | `get_max_value()` | 1000 | 10 | Basic |
| 8 | const_check | `MAX_VALUE` | 1000 | 5 | Const |
| 9 | format_basic | `format_greeting(...)` | correct | 15 | Basic |
| 10 | clippy_clean | `cargo clippy` | no warnings | 5 | Lint |

**Total : 100 points**

---

### 4.2 Tests de la moulinette

```rust
#[cfg(test)]
mod moulinette_tests {
    use super::*;

    #[test]
    fn test_increment_counter_basic() {
        assert_eq!(increment_counter(5), 15);
    }

    #[test]
    fn test_increment_counter_zero() {
        assert_eq!(increment_counter(0), 0);
    }

    #[test]
    fn test_increment_counter_one() {
        assert_eq!(increment_counter(1), 1);
    }

    #[test]
    fn test_increment_counter_large() {
        assert_eq!(increment_counter(100), 5050);
    }

    #[test]
    fn test_shadow_and_transform_hello() {
        assert_eq!(shadow_and_transform("hello"), 25);
    }

    #[test]
    fn test_shadow_and_transform_empty() {
        assert_eq!(shadow_and_transform(""), 0);
    }

    #[test]
    fn test_shadow_and_transform_single() {
        assert_eq!(shadow_and_transform("x"), 1);
    }

    #[test]
    fn test_get_max_value() {
        assert_eq!(get_max_value(), 1000);
    }

    #[test]
    fn test_max_value_const() {
        assert_eq!(MAX_VALUE, 1000);
    }

    #[test]
    fn test_format_greeting() {
        assert_eq!(
            format_greeting("Alice", 30, "Paris"),
            "Hello Alice, you are 30 years old and live in Paris."
        );
    }

    #[test]
    fn test_format_greeting_other() {
        assert_eq!(
            format_greeting("Bob", 25, "Lyon"),
            "Hello Bob, you are 25 years old and live in Lyon."
        );
    }
}
```

---

### 4.3 Solution de reference (Rust)

```rust
/// Incremente un compteur de 1 a n et retourne la somme.
pub fn increment_counter(n: u32) -> u32 {
    let mut sum = 0;
    let mut counter = 1;

    while counter <= n {
        sum += counter;
        counter += 1;
    }

    sum
}

/// Transforme une chaine en sa longueur puis en son carre.
pub fn shadow_and_transform(input: &str) -> usize {
    // Premiere variable : la chaine
    let value = input;

    // Shadowing : meme nom, type usize
    let value = value.len();

    // Shadowing : meme nom, calcul du carre
    let value = value * value;

    value
}

/// Constante globale
pub const MAX_VALUE: u32 = 1000;

/// Retourne la valeur maximale.
pub fn get_max_value() -> u32 {
    MAX_VALUE
}

/// Formate un message de bienvenue.
pub fn format_greeting(name: &str, age: u32, city: &str) -> String {
    format!(
        "Hello {}, you are {} years old and live in {}.",
        name, age, city
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increment_counter() {
        assert_eq!(increment_counter(5), 15);
    }

    #[test]
    fn test_shadow_and_transform() {
        assert_eq!(shadow_and_transform("hello"), 25);
    }

    #[test]
    fn test_get_max_value() {
        assert_eq!(get_max_value(), MAX_VALUE);
    }

    #[test]
    fn test_format_greeting() {
        let msg = format_greeting("Alice", 30, "Paris");
        assert_eq!(msg, "Hello Alice, you are 30 years old and live in Paris.");
    }
}
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : increment_counter avec formule directe**

```rust
pub fn increment_counter(n: u32) -> u32 {
    // Formule de Gauss : n * (n + 1) / 2
    n * (n + 1) / 2
}
// Accepte mais ne demontre pas l'utilisation de mut
```

**Alternative 2 : increment_counter avec for loop**

```rust
pub fn increment_counter(n: u32) -> u32 {
    let mut sum = 0;
    for i in 1..=n {
        sum += i;
    }
    sum
}
```

**Alternative 3 : shadow_and_transform avec .pow()**

```rust
pub fn shadow_and_transform(input: &str) -> usize {
    let len = input.len();
    len.pow(2)
}
// Accepte mais ne montre pas le shadowing explicite
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : Pas de variable mutable**

```rust
// REFUSE : N'utilise pas mut
pub fn increment_counter(n: u32) -> u32 {
    (1..=n).sum()
}
```
**Pourquoi refuse :** L'exercice demande explicitement d'utiliser une variable mutable.

**Refus 2 : Pas de shadowing**

```rust
// REFUSE : Utilise des noms differents
pub fn shadow_and_transform(input: &str) -> usize {
    let str_val = input;
    let len_val = str_val.len();
    let squared = len_val * len_val;
    squared
}
```
**Pourquoi refuse :** L'exercice demande d'utiliser le shadowing (meme nom de variable).

**Refus 3 : static au lieu de const**

```rust
// REFUSE : static n'est pas const
pub static MAX_VALUE: u32 = 1000;
```
**Pourquoi refuse :** L'exercice demande une constante `const`, pas `static`.

---

### 4.9 spec.json (ENGINE v22.1)

```json
{
  "name": "variables",
  "language": "rust",
  "language_version": "edition 2024",
  "type": "code",
  "tier": 1,
  "tier_info": "Concept isole",
  "tags": ["module0.7", "variables", "mutability", "shadowing", "phase0"],
  "passing_score": 70,

  "function": {
    "name": "increment_counter",
    "prototype": "pub fn increment_counter(n: u32) -> u32",
    "return_type": "u32",
    "parameters": [
      {"name": "n", "type": "u32"}
    ]
  },

  "driver": {
    "edge_cases": [
      {
        "name": "zero_input",
        "args": [0],
        "expected": 0,
        "is_trap": true,
        "trap_explanation": "n=0 doit retourner 0, pas crash"
      },
      {
        "name": "empty_string",
        "args": [""],
        "expected": 0,
        "is_trap": true,
        "trap_explanation": "Chaine vide a longueur 0, carre = 0"
      }
    ],

    "fuzzing": {
      "enabled": true,
      "iterations": 1000,
      "generators": [
        {
          "type": "uint",
          "param_index": 0,
          "params": {"min": 0, "max": 1000}
        }
      ]
    }
  },

  "norm": {
    "allowed_functions": ["format!"],
    "forbidden_functions": [],
    "check_security": false,
    "check_memory": false,
    "blocking": false
  }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Off-by-one dans la boucle**

```rust
/* Mutant A (Boundary) : Boucle incorrecte */
pub fn increment_counter(n: u32) -> u32 {
    let mut sum = 0;
    let mut counter = 0;  // Commence a 0 au lieu de 1

    while counter <= n {
        sum += counter;
        counter += 1;
    }
    sum  // Retourne n*(n+1)/2 + 0 = correct par accident
}
// Pourquoi faux : La logique est incorrecte meme si le resultat est bon
// Ce qui etait pense : "Commencer a 0 c'est plus naturel"
```

**Mutant B (Logic) : Pas de shadowing**

```rust
/* Mutant B (Logic) : Variables differentes */
pub fn shadow_and_transform(input: &str) -> usize {
    let input_str = input;
    let length = input_str.len();
    let squared = length * length;
    squared
}
// Pourquoi faux : Ne demontre pas le shadowing
// Ce qui etait pense : "C'est plus clair avec des noms differents"
```

**Mutant C (Type) : static au lieu de const**

```rust
/* Mutant C (Type) : Mauvais mot-cle */
pub static MAX_VALUE: u32 = 1000;

pub fn get_max_value() -> u32 {
    MAX_VALUE
}
// Pourquoi faux : static a une adresse fixe, const est inline
// Ce qui etait pense : "C'est pareil"
```

**Mutant D (Return) : Mauvais format du message**

```rust
/* Mutant D (Return) : Format incorrect */
pub fn format_greeting(name: &str, age: u32, city: &str) -> String {
    format!(
        "Hello {}, you are {} years old and live in {}",
        name, age, city
    )  // Manque le point final
}
// Pourquoi faux : Le format exact est specifie
// Ce qui etait pense : "Le point n'est pas important"
```

**Mutant E (Safety) : Overflow potentiel**

```rust
/* Mutant E (Safety) : Pas de protection overflow */
pub fn shadow_and_transform(input: &str) -> usize {
    let value = input.len();
    value * value  // Overflow si len > sqrt(usize::MAX)
}
// Pourquoi faux : Pas de shadowing + overflow potentiel
// Ce qui etait pense : "Les chaines sont toujours petites"
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Immutabilite | Variables immutables par defaut | Fondamental |
| Mutabilite | Mot-cle `mut` pour autoriser | Fondamental |
| Shadowing | Redeclarer une variable | Important |
| Constantes | `const` vs `static` | Important |
| Formatage | macro `format!` | Important |

---

### 5.2 LDA — Traduction litterale en MAJUSCULES

```
FONCTION increment_counter QUI PREND n COMME ENTIER NON SIGNE 32 BITS
DEBUT FONCTION
    DECLARER sum COMME ENTIER MUTABLE INITIALISE A 0
    DECLARER counter COMME ENTIER MUTABLE INITIALISE A 1

    TANT QUE counter EST INFERIEUR OU EGAL A n FAIRE
        AJOUTER counter A sum
        INCREMENTER counter DE 1
    FIN TANT QUE

    RETOURNER sum
FIN FONCTION

FONCTION shadow_and_transform QUI PREND input COMME REFERENCE VERS CHAINE
DEBUT FONCTION
    DECLARER value COMME input (TYPE: &str)
    REDECLARER value COMME LONGUEUR DE value (TYPE: usize) -- SHADOWING
    REDECLARER value COMME value MULTIPLIE PAR value (TYPE: usize) -- SHADOWING
    RETOURNER value
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

**Shadowing vs Mutation :**

```
MUTATION (avec mut):
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  let mut x = 5;                                                │
│                                                                 │
│  Stack:                                                        │
│  ┌─────────┐                                                   │
│  │  x: 5   │  <- Meme adresse memoire                         │
│  └─────────┘                                                   │
│                                                                 │
│  x = 10;                                                       │
│                                                                 │
│  Stack:                                                        │
│  ┌─────────┐                                                   │
│  │  x: 10  │  <- Meme adresse, valeur modifiee                │
│  └─────────┘                                                   │
└─────────────────────────────────────────────────────────────────┘

SHADOWING (sans mut):
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  let x = 5;                                                    │
│                                                                 │
│  Stack:                                                        │
│  ┌─────────┐                                                   │
│  │  x: 5   │  <- Premiere variable                            │
│  └─────────┘                                                   │
│                                                                 │
│  let x = x * 2;                                                │
│                                                                 │
│  Stack:                                                        │
│  ┌─────────┐                                                   │
│  │  x: 5   │  <- Ancienne variable (masquee, mais existe)     │
│  ├─────────┤                                                   │
│  │  x: 10  │  <- Nouvelle variable (visible)                  │
│  └─────────┘                                                   │
└─────────────────────────────────────────────────────────────────┘
```

**const vs static :**

```
const PI: f64 = 3.14159;
┌─────────────────────────────────────────────────────────────────┐
│  Code:                                                         │
│  let area = PI * r * r;                                        │
│                                                                 │
│  Apres compilation (inline):                                   │
│  let area = 3.14159 * r * r;   <- PI remplace directement     │
└─────────────────────────────────────────────────────────────────┘

static COUNTER: u32 = 0;
┌─────────────────────────────────────────────────────────────────┐
│  Segment data (memoire):                                       │
│  Adresse 0x1000: COUNTER = 0                                   │
│                                                                 │
│  Code:                                                         │
│  let val = COUNTER;                                            │
│  // Lit depuis l'adresse 0x1000                                │
└─────────────────────────────────────────────────────────────────┘
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Oublier mut

```rust
// Erreur de compilation
let x = 5;
x = 10;  // error[E0384]: cannot assign twice to immutable variable

// Correct
let mut x = 5;
x = 10;  // OK
```

#### Piege 2 : Confusion shadowing et mutation

```rust
// Shadowing : cree une nouvelle variable
let x = 5;
let x = "hello";  // OK : nouvelle variable de type different

// Mutation : meme variable
let mut x = 5;
x = "hello";  // ERREUR : ne peut pas changer le type
```

#### Piege 3 : const dans une fonction

```rust
// ERREUR : const doit etre global ou dans un impl block
fn foo() {
    const LOCAL: u32 = 42;  // Warning: unused, mais compile
}

// Mieux : au niveau module
const GLOBAL: u32 = 42;
```

---

### 5.5 Cours Complet

#### 5.5.1 Declaration de variables

```rust
// Immutable (par defaut)
let x = 5;

// Mutable
let mut y = 10;
y += 1;

// Avec annotation de type explicite
let z: i32 = -42;

// Destructuration
let (a, b) = (1, 2);
```

#### 5.5.2 Shadowing

```rust
// Meme scope
let x = 5;
let x = x + 1;      // x = 6
let x = x * 2;      // x = 12

// Changement de type
let spaces = "   ";        // &str
let spaces = spaces.len(); // usize

// Dans un bloc
let x = 5;
{
    let x = x * 2;  // x = 10 dans ce bloc
    println!("{}", x);  // Affiche 10
}
println!("{}", x);  // Affiche 5 (shadow termine)
```

#### 5.5.3 Constantes

```rust
// const : valeur connue a la compilation
const MAX_POINTS: u32 = 100_000;
const PI: f64 = 3.14159265359;

// Expressions constantes
const SECONDS_PER_DAY: u32 = 60 * 60 * 24;

// INTERDIT : appels de fonction non-const
// const RANDOM: u32 = rand::random();  // Erreur
```

#### 5.5.4 Formatage avec format! et println!

```rust
// Positional arguments
let s = format!("{} + {} = {}", 1, 2, 3);  // "1 + 2 = 3"

// Named arguments
let name = "Alice";
let s = format!("Hello, {name}!");  // "Hello, Alice!"

// Debug formatting
let v = vec![1, 2, 3];
println!("{:?}", v);  // [1, 2, 3]
println!("{:#?}", v); // Pretty-print

// Padding and alignment
println!("{:>10}", "right");  // "     right"
println!("{:<10}", "left");   // "left      "
println!("{:^10}", "center"); // "  center  "

// Number formatting
println!("{:08}", 42);    // "00000042"
println!("{:.2}", 3.14159); // "3.14"
println!("{:b}", 42);     // "101010" (binary)
println!("{:x}", 255);    // "ff" (hex)
```

---

### 5.6 Normes avec explications pedagogiques

```
┌─────────────────────────────────────────────────────────────────┐
│ HORS NORME                                                      │
├─────────────────────────────────────────────────────────────────┤
│ pub fn increment_counter(n: u32) -> u32 {                       │
│     let mut s = 0; let mut c = 1;                              │
│     while c <= n { s += c; c += 1; } s }                       │
├─────────────────────────────────────────────────────────────────┤
│ CONFORME                                                        │
├─────────────────────────────────────────────────────────────────┤
│ pub fn increment_counter(n: u32) -> u32 {                       │
│     let mut sum = 0;                                           │
│     let mut counter = 1;                                       │
│                                                                 │
│     while counter <= n {                                       │
│         sum += counter;                                        │
│         counter += 1;                                          │
│     }                                                          │
│                                                                 │
│     sum                                                        │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ POURQUOI ?                                                      │
│ - Noms explicites : sum, counter au lieu de s, c               │
│ - Une instruction par ligne                                    │
│ - Espacement coherent                                          │
└─────────────────────────────────────────────────────────────────┘
```

---

### 5.7 Simulation avec trace d'execution

```
increment_counter(5):
┌───────┬─────────┬─────────┬─────────┬──────────────────────────┐
│ Etape │ counter │   sum   │ Action  │ Explication              │
├───────┼─────────┼─────────┼─────────┼──────────────────────────┤
│   0   │    1    │    0    │ Init    │ Variables initialisees   │
│   1   │    1    │    1    │ sum+=1  │ 0 + 1 = 1               │
│   2   │    2    │    3    │ sum+=2  │ 1 + 2 = 3               │
│   3   │    3    │    6    │ sum+=3  │ 3 + 3 = 6               │
│   4   │    4    │   10    │ sum+=4  │ 6 + 4 = 10              │
│   5   │    5    │   15    │ sum+=5  │ 10 + 5 = 15             │
│   6   │    6    │   15    │ Exit    │ counter > n, fin boucle │
└───────┴─────────┴─────────┴─────────┴──────────────────────────┘
Resultat: 15
```

---

### 5.8 Mnemotechniques

**MUT = Modification Under Trust**

Quand tu ajoutes `mut`, tu dis au compilateur : "Fais-moi confiance, je vais modifier cette variable de maniere controlee."

**SHADOW = Same name, Hidden And Different, Over Written**

Le shadowing cache (HIDE) l'ancienne variable avec une nouvelle.

**CONST = Compile-time Optimized Numeric/String Literal**

Les constantes sont resolues a la compilation, pas a l'execution.

---

### 5.9 Applications pratiques

| Scenario | Utilisation |
|----------|-------------|
| **Compteur de boucle** | `let mut i = 0; while i < n { i += 1; }` |
| **Accumulateur** | `let mut sum = 0; for x in data { sum += x; }` |
| **Transformation de donnees** | Shadowing pour changer le type |
| **Configuration** | `const` pour les valeurs fixes |
| **Etat mutable** | `let mut state = State::new();` |

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Oublier `mut` | Erreur compilation | Ajouter `mut` |
| 2 | Confusion shadow/mut | Comportement inattendu | Comprendre la difference |
| 3 | `static` au lieu de `const` | Semantique differente | Utiliser `const` |
| 4 | Noms de variables courts | Code illisible | Noms explicites |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Que fait le shadowing en Rust ?

- A) Modifie la valeur d'une variable
- B) Cree une nouvelle variable avec le meme nom
- C) Supprime la variable precedente
- D) Change la mutabilite

**Reponse : B** — Le shadowing cree une nouvelle variable, l'ancienne existe mais est masquee.

---

### Question 2 (3 points)
Quel est le mot-cle pour rendre une variable modifiable ?

- A) `var`
- B) `mutable`
- C) `mut`
- D) `ref`

**Reponse : C** — `mut` est le mot-cle pour la mutabilite.

---

### Question 3 (4 points)
Quelle est la difference entre `const` et `static` ?

- A) Aucune difference
- B) `const` est inline, `static` a une adresse fixe
- C) `const` peut etre mutable
- D) `static` est plus rapide

**Reponse : B** — `const` est substitue a la compilation, `static` existe en memoire.

---

### Question 4 (5 points)
Ce code compile-t-il ?
```rust
let x = 5;
let x = "hello";
```

- A) Non, erreur de type
- B) Oui, grace au shadowing
- C) Non, variable non mutable
- D) Oui, mais warning

**Reponse : B** — Le shadowing permet de changer le type.

---

### Question 5 (5 points)
Quelle macro utiliser pour formater une String sans l'afficher ?

- A) `println!`
- B) `print!`
- C) `format!`
- D) `write!`

**Reponse : C** — `format!` retourne une String, `println!` affiche.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.1 |
| **Nom** | variables |
| **Difficulte** | 2/10 |
| **Duree** | 25 min |
| **XP Base** | 50 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | mut, shadowing, const, format! |
| **Prerequis** | cargo_init |
| **Domaines** | Variables, Mutabilite |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.1-variables",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.1",
      "exercise_name": "variables",
      "module": "0.7",
      "module_name": "Introduction a Rust",
      "concept": "b",
      "concept_name": "Variables et mutabilite",
      "type": "code",
      "tier": 1,
      "difficulty": 2,
      "difficulty_stars": "2/10",
      "languages": ["rust"],
      "language_versions": {
        "rust": "edition 2024"
      },
      "duration_minutes": 25,
      "xp_base": 50,
      "prerequisites": ["0.7.0"],
      "domains": ["Variables", "Mutability"],
      "tags": ["mut", "shadowing", "const", "format"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
