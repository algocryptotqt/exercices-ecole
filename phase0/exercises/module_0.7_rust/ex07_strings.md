# Exercice 0.7.7 : strings

**Module :**
0.7 — Introduction a Rust

**Concept :**
h — Strings : String vs &str et manipulations

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.6 (slices)
- Comprehension de l'UTF-8

**Domaines :**
Strings, Memory

**Duree estimee :**
45 min

**XP Base :**
85

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
| Rust | Toutes les fonctions de la bibliotheque standard |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Rust | `unsafe` |

---

### 1.2 Consigne

#### Section Culture : "Two Strings Walk Into a Bar..."

Rust a deux types de chaines principaux :
- `String` : chaine possedee, modifiable, allouee sur le heap
- `&str` : reference vers une sequence UTF-8, souvent un literal

Cette distinction existe car Rust veut que tu sois conscient de qui possede la memoire et si elle peut etre modifiee.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des fonctions de manipulation de chaines :

1. `to_uppercase_string` : convertit en majuscules
2. `concatenate` : concatene deux chaines
3. `repeat_string` : repete une chaine n fois
4. `word_count` : compte les mots
5. `reverse_string` : inverse une chaine (attention UTF-8!)

**Entree :**

```rust
// src/lib.rs

/// Convertit une chaine en majuscules.
pub fn to_uppercase_string(s: &str) -> String {
    // A implementer
}

/// Concatene deux chaines avec un espace.
pub fn concatenate(s1: &str, s2: &str) -> String {
    // A implementer
}

/// Repete une chaine n fois avec un separateur.
pub fn repeat_string(s: &str, n: usize, sep: &str) -> String {
    // A implementer
}

/// Compte le nombre de mots (separes par des espaces).
pub fn word_count(s: &str) -> usize {
    // A implementer
}

/// Inverse une chaine (en respectant les caracteres UTF-8).
pub fn reverse_string(s: &str) -> String {
    // A implementer
}

/// Cree une String depuis differentes sources.
pub fn from_literal(s: &str) -> String {
    // A implementer
}

pub fn from_number(n: i32) -> String {
    // A implementer
}
```

**Sortie attendue :**

```
$ cargo test
running 5 tests
test tests::test_uppercase ... ok
test tests::test_concatenate ... ok
test tests::test_repeat ... ok
test tests::test_word_count ... ok
test tests::test_reverse ... ok

test result: ok. 5 passed; 0 failed
```

**Contraintes :**
- `reverse_string` doit gerer correctement l'UTF-8 (caracteres multi-octets)
- `repeat_string` avec n=0 retourne une chaine vide
- `word_count` sur chaine vide retourne 0

**Exemples :**

| Fonction | Input | Output |
|----------|-------|--------|
| `to_uppercase_string("hello")` | - | `"HELLO"` |
| `concatenate("a", "b")` | - | `"a b"` |
| `repeat_string("x", 3, ",")` | - | `"x,x,x"` |
| `word_count("a b c")` | - | `3` |
| `reverse_string("abc")` | - | `"cba"` |

---

### 1.3 Prototype

```rust
pub fn to_uppercase_string(s: &str) -> String;
pub fn concatenate(s1: &str, s2: &str) -> String;
pub fn repeat_string(s: &str, n: usize, sep: &str) -> String;
pub fn word_count(s: &str) -> usize;
pub fn reverse_string(s: &str) -> String;
pub fn from_literal(s: &str) -> String;
pub fn from_number(n: i32) -> String;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**String vs &str :**

```rust
// &str : reference vers donnees UTF-8 (peut etre statique)
let s: &str = "hello";  // stocke dans le binaire

// String : chaine possedee sur le heap
let s: String = String::from("hello");  // allouee dynamiquement
```

**Pourquoi pas d'indexation directe ?**

```rust
let s = "hello";
// s[0] ne compile pas!

// Raison: UTF-8 est a longueur variable
let s = "cafe";  // 5 octets (e = 2 octets)
// s[0..1] = "c", s[3..5] = "e" (2 octets!)
```

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Web Dev** | Parsing JSON, generation HTML |
| **CLI Dev** | Arguments, formatage output |
| **Game Dev** | Localisation, dialogues |
| **Data Eng** | Nettoyage de donnees texte |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo new strings --lib
     Created library `strings` package

$ cargo test
running 5 tests
test tests::test_uppercase ... ok
test tests::test_concatenate ... ok
test tests::test_repeat ... ok
test tests::test_word_count ... ok
test tests::test_reverse ... ok

test result: ok. 5 passed; 0 failed
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | upper_basic | `"hello"` | `"HELLO"` | 10 | Basic |
| 2 | concat_basic | `"a", "b"` | `"a b"` | 10 | Basic |
| 3 | repeat_3 | `"x", 3, ","` | `"x,x,x"` | 10 | Basic |
| 4 | repeat_0 | `"x", 0, ","` | `""` | 10 | Edge |
| 5 | words_basic | `"a b c"` | `3` | 10 | Basic |
| 6 | words_empty | `""` | `0` | 10 | Edge |
| 7 | reverse_basic | `"hello"` | `"olleh"` | 15 | Basic |
| 8 | reverse_utf8 | `"cafe"` | `"efac"` | 15 | UTF-8 |

**Total : 100 points**

---

### 4.3 Solution de reference (Rust)

```rust
/// Convertit en majuscules.
pub fn to_uppercase_string(s: &str) -> String {
    s.to_uppercase()
}

/// Concatene avec un espace.
pub fn concatenate(s1: &str, s2: &str) -> String {
    format!("{} {}", s1, s2)
}

/// Repete n fois avec separateur.
pub fn repeat_string(s: &str, n: usize, sep: &str) -> String {
    if n == 0 {
        return String::new();
    }
    let parts: Vec<&str> = (0..n).map(|_| s).collect();
    parts.join(sep)
}

/// Compte les mots.
pub fn word_count(s: &str) -> usize {
    s.split_whitespace().count()
}

/// Inverse la chaine (UTF-8 safe).
pub fn reverse_string(s: &str) -> String {
    s.chars().rev().collect()
}

/// Cree depuis un literal.
pub fn from_literal(s: &str) -> String {
    s.to_string()
}

/// Cree depuis un nombre.
pub fn from_number(n: i32) -> String {
    n.to_string()
}
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : reverse avec bytes au lieu de chars**

```rust
// REFUSE : Casse l'UTF-8
pub fn reverse_string(s: &str) -> String {
    let bytes: Vec<u8> = s.bytes().rev().collect();
    String::from_utf8_lossy(&bytes).to_string()
}
```
**Pourquoi refuse :** Inverse les octets, pas les caracteres. Casse l'UTF-8.

**Refus 2 : word_count avec split(' ')**

```rust
// REFUSE : Ne gere pas les espaces multiples
pub fn word_count(s: &str) -> usize {
    s.split(' ').count()
}
```
**Pourquoi refuse :** `"a  b".split(' ')` donne ["a", "", "b"], compte 3.

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (UTF-8) : Inverse par octets**

```rust
/* Mutant A (UTF-8) : Casse les multi-octets */
pub fn reverse_string(s: &str) -> String {
    let bytes: Vec<u8> = s.bytes().rev().collect();
    String::from_utf8(bytes).unwrap()
}
// Pourquoi faux : "cafe" -> bytes inverses = UTF-8 invalide
```

**Mutant B (Logic) : word_count avec split(' ')**

```rust
/* Mutant B (Logic) : Espaces multiples mal geres */
pub fn word_count(s: &str) -> usize {
    s.split(' ').count()
}
// Pourquoi faux : "a  b" donne 3 (element vide entre espaces)
```

**Mutant C (Return) : concatenate sans espace**

```rust
/* Mutant C (Return) : Oubli de l'espace */
pub fn concatenate(s1: &str, s2: &str) -> String {
    format!("{}{}", s1, s2)
}
// Pourquoi faux : "ab" au lieu de "a b"
```

**Mutant D (Edge) : repeat ne gere pas n=0**

```rust
/* Mutant D (Edge) : Panic pour n=0 */
pub fn repeat_string(s: &str, n: usize, sep: &str) -> String {
    (0..n-1).map(|_| s).collect::<Vec<_>>().join(sep)
}
// Pourquoi faux : Panic sur underflow si n=0
```

**Mutant E (Type) : Retourne &str au lieu de String**

```rust
/* Mutant E (Type) : Mauvais type de retour */
pub fn to_uppercase_string(s: &str) -> &str {
    // Ne compile pas ou ne fonctionne pas
}
// Pourquoi faux : to_uppercase() cree une nouvelle String
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| String | Chaine possedee, heap | Critique |
| &str | String slice, reference | Critique |
| UTF-8 | Encodage, caracteres multi-octets | Important |
| From/Into | Conversions de types | Important |

---

### 5.3 Visualisation ASCII

**String vs &str en memoire :**

```
String (owned):
Stack:                          Heap:
+------------------+           +-------------------------+
| ptr --------------+--------->| h | e | l | l | o |     |
| len: 5           |           +-------------------------+
| capacity: 8      |                (capacite > len)
+------------------+

&str (borrowed):
Stack:
+------------------+           Data segment (ou heap):
| ptr --------------+--------->| h | e | l | l | o |
| len: 5           |
+------------------+           (pas de capacity, lecture seule)
```

**UTF-8 encoding :**

```
"cafe" en UTF-8:

Caractere:    c      a      f      e
Codepoint:    U+0063 U+0061 U+0066 U+00E9
Octets:       63     61     66     C3 A9
              ^      ^      ^      ^^^^^
              1      1      1        2 octets (accent!)

Total: 5 octets, 4 caracteres

s.len() = 5       (octets)
s.chars().count() = 4  (caracteres)
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Indexation directe interdite

```rust
let s = "hello";
let c = s[0];  // ERROR: cannot index into a string

// Solution: chars()
let c = s.chars().nth(0);  // Some('h')
```

#### Piege 2 : UTF-8 et bytes

```rust
let s = "cafe";
let len_bytes = s.len();        // 5
let len_chars = s.chars().count(); // 4
```

---

### 5.5 Cours Complet

#### 5.5.1 Creer des Strings

```rust
// Depuis un literal
let s1 = String::from("hello");
let s2 = "hello".to_string();
let s3: String = "hello".into();

// String vide
let s = String::new();

// Avec capacite pre-allouee
let s = String::with_capacity(10);

// Depuis d'autres types
let s = 42.to_string();  // "42"
let s = format!("{} {}", "hello", "world");
```

#### 5.5.2 Modifier des Strings

```rust
let mut s = String::from("hello");

// Ajouter
s.push('!');           // "hello!"
s.push_str(" world");  // "hello! world"

// Concatenation
let s1 = String::from("hello");
let s2 = String::from(" world");
let s3 = s1 + &s2;  // s1 est move!

// format! (pas de move)
let s = format!("{} {}", s2, s3);
```

---

### 5.8 Mnemotechniques

**String = Growable, Owned, Heap**
**&str = Slice, Static, Borrowed**

**Pour convertir :**
- `&str` -> `String` : `.to_string()` ou `String::from()`
- `String` -> `&str` : `&s` (deref coercion)

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | s[i] direct | Erreur compilation | Utiliser chars().nth(i) |
| 2 | bytes() pour reverse | UTF-8 casse | Utiliser chars() |
| 3 | split(' ') | Espaces multiples mal geres | split_whitespace() |
| 4 | fn(String) | Trop restrictif | fn(&str) |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quelle est la difference entre String et &str ?

- A) Aucune difference
- B) String est owned, &str est borrowed
- C) &str est plus rapide
- D) String ne supporte pas UTF-8

**Reponse : B** — String possede ses donnees, &str les emprunte.

---

### Question 2 (4 points)
Quelle methode pour compter les caracteres ?

- A) `s.len()`
- B) `s.chars().count()`
- C) `s.size()`
- D) `s.length()`

**Reponse : B** — len() compte les octets, chars().count() les caracteres.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.7 |
| **Nom** | strings |
| **Difficulte** | 4/10 |
| **Duree** | 45 min |
| **XP Base** | 85 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | String, &str, UTF-8, From/Into, push_str |
| **Prerequis** | slices |
| **Domaines** | Strings, Memory |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.7-strings",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.7",
      "exercise_name": "strings",
      "module": "0.7",
      "concept": "h",
      "concept_name": "Strings",
      "type": "code",
      "tier": 1,
      "difficulty": 4,
      "prerequisites": ["0.7.6"],
      "domains": ["Strings", "Memory"],
      "tags": ["String", "str", "utf8", "from", "into", "push_str"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
