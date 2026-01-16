# Exercice 0.7.3 : compounds

**Module :**
0.7 — Introduction a Rust

**Concept :**
d — Types composes : tuples, arrays, slices, String et str

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.2 (scalars)
- Notion de collection

**Domaines :**
Types, Collections

**Duree estimee :**
35 min

**XP Base :**
70

**Complexite :**
T1 O(n) × S1 O(n)

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
| Rust | Methodes standard sur tuples, arrays, slices, String |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Rust | Crates externes |

---

### 1.2 Consigne

#### Section Culture : "Compound Interest"

Les types composes sont les briques de base pour construire des structures de donnees. En Rust :
- Les **tuples** groupent des valeurs de types differents
- Les **arrays** stockent des valeurs de meme type avec taille fixe
- Les **slices** sont des vues sur des sequences
- **String** et **&str** sont les deux facettes des chaines

La distinction String vs &str est unique a Rust et vient du systeme d'ownership. String possede ses donnees, &str les emprunte.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des fonctions manipulant les types composes :

1. `swap_tuple` : Inverse les elements d'un tuple
2. `array_sum` : Somme les elements d'un array
3. `first_and_last` : Retourne le premier et dernier element d'un slice
4. `string_stats` : Calcule des statistiques sur une String

**Entree :**

```rust
// src/lib.rs

/// Inverse les elements d'un tuple de deux elements.
///
/// # Example
///
/// ```
/// let (a, b) = compounds::swap_tuple((1, 2));
/// assert_eq!((a, b), (2, 1));
/// ```
pub fn swap_tuple<T, U>(tuple: (T, U)) -> (U, T) {
    // A implementer
}

/// Calcule la somme des elements d'un array de taille fixe.
///
/// # Example
///
/// ```
/// assert_eq!(compounds::array_sum([1, 2, 3, 4, 5]), 15);
/// ```
pub fn array_sum(arr: [i32; 5]) -> i32 {
    // A implementer
}

/// Retourne le premier et le dernier element d'un slice.
/// Retourne None si le slice est vide.
///
/// # Example
///
/// ```
/// assert_eq!(compounds::first_and_last(&[1, 2, 3]), Some((&1, &3)));
/// assert_eq!(compounds::first_and_last::<i32>(&[]), None);
/// ```
pub fn first_and_last<T>(slice: &[T]) -> Option<(&T, &T)> {
    // A implementer
}

/// Structure contenant des statistiques sur une chaine.
#[derive(Debug, PartialEq)]
pub struct StringStats {
    pub char_count: usize,
    pub byte_count: usize,
    pub word_count: usize,
}

/// Calcule des statistiques sur une String.
///
/// # Example
///
/// ```
/// let stats = compounds::string_stats("Hello World");
/// assert_eq!(stats.char_count, 11);
/// assert_eq!(stats.word_count, 2);
/// ```
pub fn string_stats(s: &str) -> StringStats {
    // A implementer
}

/// Convertit un &str en String et ajoute un suffixe.
///
/// # Example
///
/// ```
/// assert_eq!(compounds::str_to_string_with_suffix("hello", "!"), "hello!");
/// ```
pub fn str_to_string_with_suffix(s: &str, suffix: &str) -> String {
    // A implementer
}
```

**Sortie attendue :**

```
$ cargo test
running 5 tests
test tests::test_swap_tuple ... ok
test tests::test_array_sum ... ok
test tests::test_first_and_last ... ok
test tests::test_string_stats ... ok
test tests::test_str_to_string ... ok

test result: ok. 5 passed; 0 failed
```

**Contraintes :**
- `swap_tuple` doit etre generique
- `first_and_last` doit gerer le cas du slice vide
- `string_stats` compte les mots separes par des espaces
- Les caracteres multi-octets (UTF-8) doivent etre correctement comptes

**Exemples :**

| Fonction | Input | Output |
|----------|-------|--------|
| `swap_tuple((1, "hello"))` | - | `("hello", 1)` |
| `array_sum([1, 2, 3, 4, 5])` | - | 15 |
| `array_sum([0, 0, 0, 0, 0])` | - | 0 |
| `first_and_last(&[10, 20, 30])` | - | `Some((&10, &30))` |
| `first_and_last(&[42])` | - | `Some((&42, &42))` |
| `first_and_last::<i32>(&[])` | - | None |
| `string_stats("Hello")` | - | `{char:5, byte:5, word:1}` |
| `string_stats("Bonjour monde")` | - | `{char:13, byte:13, word:2}` |
| `str_to_string_with_suffix("hi", "!")` | - | `"hi!"` |

---

### 1.3 Prototype

```rust
pub fn swap_tuple<T, U>(tuple: (T, U)) -> (U, T);
pub fn array_sum(arr: [i32; 5]) -> i32;
pub fn first_and_last<T>(slice: &[T]) -> Option<(&T, &T)>;
pub fn string_stats(s: &str) -> StringStats;
pub fn str_to_string_with_suffix(s: &str, suffix: &str) -> String;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Tuples vs Structs**

Les tuples sont des structs anonymes. `(i32, String)` est equivalent a :
```rust
struct Anonymous { field_0: i32, field_1: String }
```
Mais sans noms de champs, donc moins lisibles pour plus de 2-3 elements.

**Arrays sont sur la stack**

Les arrays Rust `[T; N]` ont une taille connue a la compilation et vivent sur la stack. Les Vec<T> sont sur le heap avec une taille dynamique.

**String vs &str : owned vs borrowed**

- `String` : donnees sur le heap, peut grandir, possede ses donnees
- `&str` : "string slice", vue sur des donnees existantes, ne possede rien

C'est comme la difference entre posseder un livre (String) et avoir un marque-page (slice).

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Data Engineer** | Tuples pour retourner plusieurs valeurs |
| **Embedded** | Arrays de taille fixe pour buffers |
| **Web Backend** | &str pour les parametres de requete |
| **Game Dev** | Tuples pour les coordonnees (x, y, z) |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo new compounds --lib
     Created library `compounds` package

$ cd compounds

$ cargo test
running 5 tests
test tests::test_swap_tuple ... ok
test tests::test_array_sum ... ok
test tests::test_first_and_last ... ok
test tests::test_string_stats ... ok
test tests::test_str_to_string ... ok

test result: ok. 5 passed; 0 failed
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | swap_int_str | `(1, "a")` | `("a", 1)` | 10 | Basic |
| 2 | swap_same_type | `(1, 2)` | `(2, 1)` | 5 | Basic |
| 3 | array_sum_basic | `[1,2,3,4,5]` | 15 | 10 | Basic |
| 4 | array_sum_zeros | `[0,0,0,0,0]` | 0 | 5 | Edge |
| 5 | array_sum_neg | `[-1,-2,3,4,5]` | 9 | 5 | Basic |
| 6 | first_last_basic | `[1,2,3]` | `Some(1,3)` | 10 | Basic |
| 7 | first_last_single | `[42]` | `Some(42,42)` | 10 | Edge |
| 8 | first_last_empty | `[]` | None | 10 | Edge |
| 9 | stats_simple | `"hello"` | 5,5,1 | 10 | Basic |
| 10 | stats_multi_word | `"a b c"` | 5,5,3 | 10 | Basic |
| 11 | stats_utf8 | `"cafe"` | 4,5,1 | 10 | UTF8 |
| 12 | str_suffix | `"hi","!"` | `"hi!"` | 5 | Basic |

**Total : 100 points**

---

### 4.2 Tests de la moulinette

```rust
#[cfg(test)]
mod moulinette_tests {
    use super::*;

    #[test]
    fn test_swap_tuple_int_str() {
        assert_eq!(swap_tuple((1, "hello")), ("hello", 1));
    }

    #[test]
    fn test_swap_tuple_same_type() {
        assert_eq!(swap_tuple((1, 2)), (2, 1));
    }

    #[test]
    fn test_array_sum_basic() {
        assert_eq!(array_sum([1, 2, 3, 4, 5]), 15);
    }

    #[test]
    fn test_array_sum_zeros() {
        assert_eq!(array_sum([0, 0, 0, 0, 0]), 0);
    }

    #[test]
    fn test_array_sum_negative() {
        assert_eq!(array_sum([-1, -2, 3, 4, 5]), 9);
    }

    #[test]
    fn test_first_and_last_basic() {
        let arr = [1, 2, 3];
        assert_eq!(first_and_last(&arr), Some((&1, &3)));
    }

    #[test]
    fn test_first_and_last_single() {
        let arr = [42];
        assert_eq!(first_and_last(&arr), Some((&42, &42)));
    }

    #[test]
    fn test_first_and_last_empty() {
        let arr: [i32; 0] = [];
        assert_eq!(first_and_last(&arr), None);
    }

    #[test]
    fn test_string_stats_simple() {
        let stats = string_stats("hello");
        assert_eq!(stats.char_count, 5);
        assert_eq!(stats.byte_count, 5);
        assert_eq!(stats.word_count, 1);
    }

    #[test]
    fn test_string_stats_multi_word() {
        let stats = string_stats("hello world");
        assert_eq!(stats.char_count, 11);
        assert_eq!(stats.word_count, 2);
    }

    #[test]
    fn test_string_stats_empty() {
        let stats = string_stats("");
        assert_eq!(stats.char_count, 0);
        assert_eq!(stats.word_count, 0);
    }

    #[test]
    fn test_str_to_string_with_suffix() {
        assert_eq!(str_to_string_with_suffix("hello", "!"), "hello!");
    }
}
```

---

### 4.3 Solution de reference (Rust)

```rust
/// Inverse les elements d'un tuple.
pub fn swap_tuple<T, U>(tuple: (T, U)) -> (U, T) {
    (tuple.1, tuple.0)
}

/// Somme les elements d'un array.
pub fn array_sum(arr: [i32; 5]) -> i32 {
    arr.iter().sum()
}

/// Retourne le premier et dernier element.
pub fn first_and_last<T>(slice: &[T]) -> Option<(&T, &T)> {
    if slice.is_empty() {
        None
    } else {
        Some((slice.first()?, slice.last()?))
    }
}

/// Statistiques sur une chaine.
#[derive(Debug, PartialEq)]
pub struct StringStats {
    pub char_count: usize,
    pub byte_count: usize,
    pub word_count: usize,
}

/// Calcule les statistiques d'une chaine.
pub fn string_stats(s: &str) -> StringStats {
    StringStats {
        char_count: s.chars().count(),
        byte_count: s.len(),
        word_count: s.split_whitespace().count(),
    }
}

/// Convertit et ajoute un suffixe.
pub fn str_to_string_with_suffix(s: &str, suffix: &str) -> String {
    format!("{}{}", s, suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swap_tuple() {
        assert_eq!(swap_tuple((1, 2)), (2, 1));
    }

    #[test]
    fn test_array_sum() {
        assert_eq!(array_sum([1, 2, 3, 4, 5]), 15);
    }

    #[test]
    fn test_first_and_last() {
        assert_eq!(first_and_last(&[1, 2, 3]), Some((&1, &3)));
        assert_eq!(first_and_last::<i32>(&[]), None);
    }

    #[test]
    fn test_string_stats() {
        let stats = string_stats("Hello World");
        assert_eq!(stats.char_count, 11);
        assert_eq!(stats.word_count, 2);
    }

    #[test]
    fn test_str_to_string() {
        assert_eq!(str_to_string_with_suffix("hi", "!"), "hi!");
    }
}
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : first_and_last avec pattern matching**

```rust
pub fn first_and_last<T>(slice: &[T]) -> Option<(&T, &T)> {
    match slice {
        [] => None,
        [single] => Some((single, single)),
        [first, .., last] => Some((first, last)),
    }
}
// Accepte, pattern matching idiomatique
```

**Alternative 2 : array_sum avec boucle for**

```rust
pub fn array_sum(arr: [i32; 5]) -> i32 {
    let mut sum = 0;
    for &x in &arr {
        sum += x;
    }
    sum
}
// Accepte, style imperatif
```

**Alternative 3 : str_to_string avec + operator**

```rust
pub fn str_to_string_with_suffix(s: &str, suffix: &str) -> String {
    s.to_string() + suffix
}
// Accepte, utilise String + &str
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : first_and_last sans gestion du vide**

```rust
// REFUSE : Panic sur slice vide
pub fn first_and_last<T>(slice: &[T]) -> Option<(&T, &T)> {
    Some((&slice[0], &slice[slice.len() - 1]))
}
```
**Pourquoi refuse :** Index out of bounds sur slice vide.

**Refus 2 : string_stats avec len() pour les caracteres**

```rust
// REFUSE : len() compte les octets, pas les caracteres
pub fn string_stats(s: &str) -> StringStats {
    StringStats {
        char_count: s.len(),  // FAUX pour UTF-8 multi-octets
        byte_count: s.len(),
        word_count: s.split(' ').count(),
    }
}
```
**Pourquoi refuse :** Pour "cafe", len()=5 mais chars().count()=4.

**Refus 3 : word_count avec split(' ')**

```rust
// REFUSE : Ne gere pas les espaces multiples
pub fn string_stats(s: &str) -> StringStats {
    StringStats {
        word_count: s.split(' ').count(),  // "a  b" donne 3 mots !
        // ...
    }
}
```
**Pourquoi refuse :** split(' ') cree des chaines vides entre espaces multiples.

---

### 4.9 spec.json (ENGINE v22.1)

```json
{
  "name": "compounds",
  "language": "rust",
  "language_version": "edition 2024",
  "type": "code",
  "tier": 1,
  "tier_info": "Concept isole",
  "tags": ["module0.7", "tuples", "arrays", "slices", "strings", "phase0"],
  "passing_score": 70,

  "function": {
    "name": "first_and_last",
    "prototype": "pub fn first_and_last<T>(slice: &[T]) -> Option<(&T, &T)>",
    "return_type": "Option<(&T, &T)>",
    "parameters": [
      {"name": "slice", "type": "&[T]"}
    ]
  },

  "driver": {
    "edge_cases": [
      {
        "name": "empty_slice",
        "args": [[]],
        "expected": null,
        "is_trap": true,
        "trap_explanation": "Slice vide doit retourner None"
      },
      {
        "name": "single_element",
        "args": [[42]],
        "expected": "(42, 42)",
        "is_trap": true,
        "trap_explanation": "Un seul element = first et last identiques"
      },
      {
        "name": "utf8_chars",
        "args": ["cafe"],
        "expected": {"char_count": 4, "byte_count": 5},
        "is_trap": true,
        "trap_explanation": "UTF-8 multi-octets"
      }
    ]
  },

  "norm": {
    "allowed_functions": ["iter", "sum", "first", "last", "chars", "split_whitespace"],
    "forbidden_functions": [],
    "check_security": false,
    "check_memory": false,
    "blocking": false
  }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Index sans verification**

```rust
/* Mutant A (Boundary) : Pas de check pour slice vide */
pub fn first_and_last<T>(slice: &[T]) -> Option<(&T, &T)> {
    Some((&slice[0], &slice[slice.len() - 1]))  // Panic si vide !
}
// Pourquoi faux : Panic sur slice vide au lieu de None
// Ce qui etait pense : "Un slice a toujours des elements"
```

**Mutant B (Logic) : len() au lieu de chars().count()**

```rust
/* Mutant B (Logic) : Mauvais comptage de caracteres */
pub fn string_stats(s: &str) -> StringStats {
    StringStats {
        char_count: s.len(),  // Compte les octets !
        byte_count: s.len(),
        word_count: s.split_whitespace().count(),
    }
}
// Pourquoi faux : "cafe" a 4 caracteres mais 5 octets
// Ce qui etait pense : "len() donne le nombre de caracteres"
```

**Mutant C (Type) : Retour par valeur au lieu de reference**

```rust
/* Mutant C (Type) : Clone au lieu de reference */
pub fn first_and_last<T: Clone>(slice: &[T]) -> Option<(T, T)> {
    if slice.is_empty() {
        None
    } else {
        Some((slice[0].clone(), slice[slice.len()-1].clone()))
    }
}
// Pourquoi faux : Change la signature, necessite Clone
// Ce qui etait pense : "C'est plus simple sans references"
```

**Mutant D (Logic) : split(' ') au lieu de split_whitespace()**

```rust
/* Mutant D (Logic) : Mauvais decoupage de mots */
pub fn string_stats(s: &str) -> StringStats {
    StringStats {
        char_count: s.chars().count(),
        byte_count: s.len(),
        word_count: s.split(' ').count(),  // "a  b" = 3 mots !
    }
}
// Pourquoi faux : Compte les chaines vides entre espaces
// Ce qui etait pense : "split par espace donne les mots"
```

**Mutant E (Return) : Oubli du suffixe**

```rust
/* Mutant E (Return) : Suffixe ignore */
pub fn str_to_string_with_suffix(s: &str, _suffix: &str) -> String {
    s.to_string()  // Oublie d'ajouter le suffixe
}
// Pourquoi faux : Le suffixe est ignore
// Ce qui etait pense : "to_string suffit"
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Tuples | Groupement de types heterogenes | Important |
| Arrays | Collection homogene de taille fixe | Fondamental |
| Slices | Vue sur une sequence | Fondamental |
| String vs &str | Owned vs borrowed | Critique |
| Generics basiques | `<T, U>` dans les signatures | Important |

---

### 5.2 LDA — Traduction litterale en MAJUSCULES

```
FONCTION swap_tuple QUI PREND tuple DE TYPE (T, U)
DEBUT FONCTION
    RETOURNER (SECOND ELEMENT DE tuple, PREMIER ELEMENT DE tuple)
FIN FONCTION

FONCTION first_and_last QUI PREND slice COMME REFERENCE VERS TABLEAU DE T
DEBUT FONCTION
    SI slice EST VIDE ALORS
        RETOURNER None
    SINON
        RETOURNER Some(REFERENCE VERS PREMIER ELEMENT, REFERENCE VERS DERNIER ELEMENT)
    FIN SI
FIN FONCTION

FONCTION string_stats QUI PREND s COMME REFERENCE VERS CHAINE
DEBUT FONCTION
    CREER STRUCTURE StringStats AVEC:
        char_count = NOMBRE DE CARACTERES UNICODE DANS s
        byte_count = NOMBRE D'OCTETS DANS s
        word_count = NOMBRE DE MOTS SEPARES PAR ESPACES
    RETOURNER CETTE STRUCTURE
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

**Tuple en memoire :**

```
let t: (i32, bool, char) = (42, true, 'A');

Stack:
┌─────────────────────────────────────────┐
│          Tuple (i32, bool, char)        │
├─────────────┬──────────┬────────────────┤
│   42 (4B)   │ true(1B) │    'A' (4B)    │
│   i32       │   bool   │     char       │
└─────────────┴──────────┴────────────────┘
     .0            .1          .2
```

**Array vs Slice :**

```
let arr: [i32; 5] = [1, 2, 3, 4, 5];
let slice: &[i32] = &arr[1..4];

Stack:                           Stack (slice = fat pointer):
┌───────────────────────┐        ┌─────────────────────────┐
│  arr: [1, 2, 3, 4, 5] │        │ ptr ──────────────┐     │
│       ↑               │        │ len: 3            │     │
│       │               │        └────────────────────│────┘
│       │               │                             │
│       │               │                             ↓
│  [1] [2] [3] [4] [5]  │                      [2] [3] [4]
└───────────────────────┘
                                 slice pointe vers arr[1..4]
```

**String vs &str :**

```
let s: String = String::from("Hello");
let slice: &str = &s[0..3];

Heap:                              Stack:
┌────────────────────┐            String:
│ H │ e │ l │ l │ o │            ┌─────────────────────┐
└────────────────────┘            │ ptr ───────────────┼──► Heap
  ↑                               │ len: 5             │
  │                               │ capacity: 5        │
  │                               └─────────────────────┘
  │
  │                               &str:
  └──────────────────────────────┌─────────────────────┐
                                 │ ptr ────────────────┤
                                 │ len: 3              │
                                 └─────────────────────┘
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Index hors limites

```rust
let arr = [1, 2, 3];
let x = arr[10];  // Panic: index out of bounds !

// Utiliser get() pour un acces sur
let x = arr.get(10);  // None
```

#### Piege 2 : len() vs chars().count()

```rust
let s = "cafe";  // e avec accent
s.len();           // 5 (octets)
s.chars().count(); // 4 (caracteres)

// "cafe" = [0x63, 0x61, 0x66, 0xC3, 0xA9]
//           c     a     f     e (2 bytes UTF-8)
```

#### Piege 3 : String vs &str conversions

```rust
let s: String = String::from("hello");
let slice: &str = &s;           // String -> &str (gratuit)
let owned: String = slice.to_string();  // &str -> String (allocation)

// Prefer &str dans les parametres
fn greet(name: &str) { }  // Accepte String et &str
```

---

### 5.5 Cours Complet

#### 5.5.1 Tuples

```rust
// Declaration
let tup: (i32, f64, char) = (42, 6.28, 'z');

// Acces par index
let x = tup.0;  // 42
let y = tup.1;  // 6.28

// Destructuration
let (a, b, c) = tup;

// Tuple unit
let unit: () = ();  // Type de retour par defaut
```

#### 5.5.2 Arrays

```rust
// Declaration avec type et taille
let arr: [i32; 5] = [1, 2, 3, 4, 5];

// Initialisation avec meme valeur
let zeros: [i32; 10] = [0; 10];

// Acces
let first = arr[0];
let last = arr[arr.len() - 1];

// Iteration
for x in &arr {
    println!("{}", x);
}
```

#### 5.5.3 Slices

```rust
let arr = [1, 2, 3, 4, 5];

// Slice complet
let all: &[i32] = &arr[..];

// Sous-slice
let middle: &[i32] = &arr[1..4];  // [2, 3, 4]

// Methodes utiles
middle.first();  // Some(&2)
middle.last();   // Some(&4)
middle.len();    // 3
middle.is_empty();  // false
```

#### 5.5.4 String et &str

```rust
// String : owned, mutable, heap
let mut s = String::from("Hello");
s.push_str(", World!");

// &str : borrowed, immutable, peut pointer vers stack ou heap
let slice: &str = "Hello";  // String literal (statique)

// Methodes communes
s.len();           // Octets
s.chars().count(); // Caracteres
s.is_empty();
s.contains("llo");
s.split_whitespace();
```

---

### 5.6 Normes avec explications pedagogiques

```
┌─────────────────────────────────────────────────────────────────┐
│ HORS NORME                                                      │
├─────────────────────────────────────────────────────────────────┤
│ pub fn first_and_last<T>(s: &[T]) -> Option<(&T, &T)> {         │
│     if s.len() == 0 { None } else { Some((&s[0], &s[s.len()-1])) } } │
├─────────────────────────────────────────────────────────────────┤
│ CONFORME                                                        │
├─────────────────────────────────────────────────────────────────┤
│ pub fn first_and_last<T>(slice: &[T]) -> Option<(&T, &T)> {     │
│     if slice.is_empty() {                                      │
│         None                                                    │
│     } else {                                                    │
│         Some((slice.first()?, slice.last()?))                  │
│     }                                                          │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ POURQUOI ?                                                      │
│ - is_empty() plus idiomatique que len() == 0                   │
│ - first() et last() retournent Option, plus sur               │
│ - Nommage explicite (slice au lieu de s)                       │
└─────────────────────────────────────────────────────────────────┘
```

---

### 5.7 Simulation avec trace d'execution

```
string_stats("Hello World"):
┌───────┬──────────────────────────────────────────────────────────┐
│ Etape │ Operation                                                │
├───────┼──────────────────────────────────────────────────────────┤
│   1   │ s = "Hello World"                                       │
│   2   │ s.chars() = ['H','e','l','l','o',' ','W','o','r','l','d']│
│   3   │ chars().count() = 11                                    │
│   4   │ s.len() = 11 (tous ASCII = 1 octet)                    │
│   5   │ s.split_whitespace() = ["Hello", "World"]              │
│   6   │ split_whitespace().count() = 2                         │
│   7   │ Retourne StringStats { char: 11, byte: 11, word: 2 }   │
└───────┴──────────────────────────────────────────────────────────┘
```

---

### 5.8 Mnemotechniques

**SOS = String Owns, Str Sees**

- **S**tring **O**wns (possede ses donnees)
- **S**tr **S**ees (voit/emprunte les donnees)

**TASK = Tuple Array Slice Kind**

Les 4 types composes de base en Rust.

---

### 5.9 Applications pratiques

| Scenario | Type a utiliser |
|----------|-----------------|
| **Coordonnees 2D** | `(f64, f64)` tuple |
| **Buffer fixe** | `[u8; 1024]` array |
| **Parametres de fonction** | `&[T]` slice |
| **Texte dynamique** | `String` |
| **Texte en parametre** | `&str` |

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Index hors limites | Panic | Utiliser get() |
| 2 | len() pour caracteres | Mauvais compte | chars().count() |
| 3 | String en parametre | Copie inutile | Utiliser &str |
| 4 | split(' ') pour mots | Mots vides | split_whitespace() |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quelle est la difference entre un array et un slice ?

- A) Aucune difference
- B) Array a taille fixe, slice a taille dynamique
- C) Array est sur le heap, slice sur la stack
- D) Slice possede ses donnees

**Reponse : B** — Array `[T; N]` a une taille N fixe, slice `&[T]` est une vue.

---

### Question 2 (3 points)
Comment obtenir le nombre de caracteres Unicode dans une String ?

- A) `s.len()`
- B) `s.size()`
- C) `s.chars().count()`
- D) `s.char_count()`

**Reponse : C** — `chars().count()` compte les caracteres, `len()` les octets.

---

### Question 3 (4 points)
Que retourne `"hello".to_string()` ?

- A) `&str`
- B) `String`
- C) `&String`
- D) `[char]`

**Reponse : B** — `to_string()` cree un `String` (owned) a partir d'un `&str`.

---

### Question 4 (5 points)
Comment acceder au deuxieme element d'un tuple ?

- A) `tuple[1]`
- B) `tuple.1`
- C) `tuple.get(1)`
- D) `tuple.second()`

**Reponse : B** — Les tuples utilisent `.0`, `.1`, `.2`, etc.

---

### Question 5 (5 points)
Que retourne `[1, 2, 3].first()` ?

- A) `1`
- B) `Some(&1)`
- C) `&1`
- D) `Some(1)`

**Reponse : B** — `first()` retourne `Option<&T>`, donc `Some(&1)`.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.3 |
| **Nom** | compounds |
| **Difficulte** | 3/10 |
| **Duree** | 35 min |
| **XP Base** | 70 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | tuples, arrays, slices, String, &str |
| **Prerequis** | scalars |
| **Domaines** | Types, Collections |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.3-compounds",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.3",
      "exercise_name": "compounds",
      "module": "0.7",
      "module_name": "Introduction a Rust",
      "concept": "d",
      "concept_name": "Types composes",
      "type": "code",
      "tier": 1,
      "difficulty": 3,
      "difficulty_stars": "3/10",
      "languages": ["rust"],
      "duration_minutes": 35,
      "xp_base": 70,
      "prerequisites": ["0.7.2"],
      "domains": ["Types", "Collections"],
      "tags": ["tuples", "arrays", "slices", "string", "str"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
