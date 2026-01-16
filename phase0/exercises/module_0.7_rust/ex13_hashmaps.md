# Exercice 0.7.13-a : hashmaps

**Module :**
0.7.13 — HashMap<K, V>

**Concept :**
a-e — insert, get, remove, entry API, iteration

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
0.7.12 (vectors)

**Domaines :**
Algo, Structures

**Duree estimee :**
150 min

**XP Base :**
220

**Complexite :**
T2 O(1) amortized x S2 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `src/lib.rs`

### 1.2 Consigne

Implementer des fonctions utilisant les HashMaps.

**Ta mission :**

```rust
use std::collections::HashMap;

// Compter les occurrences de chaque caractere
pub fn char_count(s: &str) -> HashMap<char, usize>;

// Compter les mots
pub fn word_count(text: &str) -> HashMap<String, usize>;

// Grouper des elements par cle
pub fn group_by_first_char(words: &[&str]) -> HashMap<char, Vec<String>>;

// Inverser une map (valeurs deviennent cles)
pub fn invert_map(map: &HashMap<i32, i32>) -> HashMap<i32, i32>;

// Fusionner deux maps (somme des valeurs)
pub fn merge_maps(m1: &HashMap<String, i32>, m2: &HashMap<String, i32>) -> HashMap<String, i32>;

// Filtrer une map
pub fn filter_by_value(map: &HashMap<String, i32>, min: i32) -> HashMap<String, i32>;

// Obtenir ou inserer une valeur par defaut
pub fn get_or_default(map: &mut HashMap<String, i32>, key: &str, default: i32) -> i32;
```

**Comportement:**

1. `char_count("hello")` -> {'h': 1, 'e': 1, 'l': 2, 'o': 1}
2. `word_count("the cat and the dog")` -> {"the": 2, "cat": 1, ...}
3. `invert_map({1: 10, 2: 20})` -> {10: 1, 20: 2}
4. `merge_maps({"a": 1}, {"a": 2, "b": 3})` -> {"a": 3, "b": 3}

**Exemples:**
```rust
let counts = char_count("banana");
println!("{:?}", counts);  // {'b': 1, 'a': 3, 'n': 2}

let words = word_count("to be or not to be");
println!("{:?}", words.get("to"));  // Some(&2)

let grouped = group_by_first_char(&["apple", "ant", "banana"]);
println!("{:?}", grouped.get(&'a'));  // Some(["apple", "ant"])
```

### 1.3 Prototype

```rust
// src/lib.rs
use std::collections::HashMap;

pub fn char_count(s: &str) -> HashMap<char, usize> {
    todo!()
}

pub fn word_count(text: &str) -> HashMap<String, usize> {
    todo!()
}

pub fn group_by_first_char(words: &[&str]) -> HashMap<char, Vec<String>> {
    todo!()
}

pub fn invert_map(map: &HashMap<i32, i32>) -> HashMap<i32, i32> {
    todo!()
}

pub fn merge_maps(m1: &HashMap<String, i32>, m2: &HashMap<String, i32>) -> HashMap<String, i32> {
    todo!()
}

pub fn filter_by_value(map: &HashMap<String, i32>, min: i32) -> HashMap<String, i32> {
    todo!()
}

pub fn get_or_default(map: &mut HashMap<String, i32>, key: &str, default: i32) -> i32 {
    todo!()
}
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | char_count | correct counts | 15 |
| T02 | word_count | correct counts | 15 |
| T03 | group_by_first_char | correct groups | 15 |
| T04 | invert_map | inverted | 10 |
| T05 | merge_maps | summed | 15 |
| T06 | filter_by_value | filtered | 15 |
| T07 | get_or_default | correct | 15 |

### 4.3 Solution de reference

```rust
use std::collections::HashMap;

pub fn char_count(s: &str) -> HashMap<char, usize> {
    let mut counts = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    counts
}

pub fn word_count(text: &str) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for word in text.split_whitespace() {
        *counts.entry(word.to_lowercase()).or_insert(0) += 1;
    }
    counts
}

pub fn group_by_first_char(words: &[&str]) -> HashMap<char, Vec<String>> {
    let mut groups = HashMap::new();
    for word in words {
        if let Some(first) = word.chars().next() {
            groups
                .entry(first)
                .or_insert_with(Vec::new)
                .push(word.to_string());
        }
    }
    groups
}

pub fn invert_map(map: &HashMap<i32, i32>) -> HashMap<i32, i32> {
    map.iter().map(|(&k, &v)| (v, k)).collect()
}

pub fn merge_maps(m1: &HashMap<String, i32>, m2: &HashMap<String, i32>) -> HashMap<String, i32> {
    let mut result = m1.clone();
    for (k, v) in m2 {
        *result.entry(k.clone()).or_insert(0) += v;
    }
    result
}

pub fn filter_by_value(map: &HashMap<String, i32>, min: i32) -> HashMap<String, i32> {
    map.iter()
        .filter(|(_, &v)| v >= min)
        .map(|(k, &v)| (k.clone(), v))
        .collect()
}

pub fn get_or_default(map: &mut HashMap<String, i32>, key: &str, default: i32) -> i32 {
    *map.entry(key.to_string()).or_insert(default)
}
```

### 4.10 Solutions Mutantes

```rust
// MUTANT 1: char_count ne compte pas correctement
pub fn char_count(s: &str) -> HashMap<char, usize> {
    let mut counts = HashMap::new();
    for c in s.chars() {
        counts.insert(c, 1);  // Ecrase au lieu d'incrementer
    }
    counts
}

// MUTANT 2: word_count case-sensitive
pub fn word_count(text: &str) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    for word in text.split_whitespace() {
        *counts.entry(word.to_string()).or_insert(0) += 1;
        // "The" et "the" comptes separement
    }
    counts
}

// MUTANT 3: group_by_first_char ignore mots vides
pub fn group_by_first_char(words: &[&str]) -> HashMap<char, Vec<String>> {
    let mut groups = HashMap::new();
    for word in words {
        let first = word.chars().next().unwrap();  // Panic sur ""!
        groups.entry(first).or_insert_with(Vec::new).push(word.to_string());
    }
    groups
}

// MUTANT 4: invert_map perd des donnees si valeurs dupliquees
pub fn invert_map(map: &HashMap<i32, i32>) -> HashMap<i32, i32> {
    // Si deux cles ont la meme valeur, une est perdue
    map.iter().map(|(&k, &v)| (v, k)).collect()
}

// MUTANT 5: merge_maps remplace au lieu de sommer
pub fn merge_maps(m1: &HashMap<String, i32>, m2: &HashMap<String, i32>) -> HashMap<String, i32> {
    let mut result = m1.clone();
    for (k, v) in m2 {
        result.insert(k.clone(), *v);  // Remplace au lieu de sommer
    }
    result
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

**HashMap<K, V>** - Table de hachage:

1. **O(1) amortized** - Acces, insertion, suppression
2. **Entry API** - Pattern pour get-or-insert efficace
3. **Ownership** - Les cles et valeurs sont owned
4. **Hash + Eq** - Cles doivent implementer ces traits

### 5.3 Visualisation ASCII

```
HASHMAP INTERNALS:

HashMap<String, i32>

let mut map = HashMap::new();
map.insert("hello".to_string(), 42);

   hash("hello") = 12345

Buckets:
[0] -> None
[1] -> None
...
[12] -> Some(("hello", 42))
...
[n] -> None

ENTRY API:
map.entry(key)
    |
    +-> Occupied(entry)  // Cle existe
    |       .get() -> &V
    |       .get_mut() -> &mut V
    |       .insert(V) -> V (old)
    |
    +-> Vacant(entry)    // Cle n'existe pas
            .insert(V) -> &mut V
            .or_insert(V) -> &mut V

PATTERN COMMUN:
*map.entry(key).or_insert(0) += 1;

Equivalent a:
if map.contains_key(&key) {
    *map.get_mut(&key).unwrap() += 1;
} else {
    map.insert(key, 1);
}
```

---

## SECTION 7 : QCM

### Question 1
Quelle est la complexite moyenne d'une recherche dans HashMap ?

A) O(1)
B) O(log n)
C) O(n)
D) O(n log n)
E) O(n^2)

**Reponse correcte: A**

### Question 2
Que retourne `map.entry(key).or_insert(default)` ?

A) La valeur
B) Une reference mutable vers la valeur
C) Un Option
D) Un Result
E) Un bool

**Reponse correcte: B**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.7.13-a",
  "name": "hashmaps",
  "language": "rust",
  "language_version": "edition2024",
  "files": ["src/lib.rs"],
  "tests": {
    "counting": "hashmap_counting_tests",
    "grouping": "hashmap_grouping_tests",
    "entry_api": "entry_api_tests"
  }
}
```
