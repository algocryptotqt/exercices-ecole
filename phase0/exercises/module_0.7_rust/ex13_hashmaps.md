# Exercice 0.7.13 : hashmaps

**Module :**
0.7 — Introduction a Rust

**Concept :**
n — HashMaps : collections cle-valeur

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.12 (vectors)
- Option et Result

**Domaines :**
Collections, Hashing

**Duree estimee :**
45 min

**XP Base :**
90

**Complexite :**
T0 O(1) amortized × S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Langage | Fichiers |
|---------|----------|
| Rust | `src/lib.rs` |

---

### 1.2 Consigne

#### Section Culture : "HashMap: O(1) Lookup, Infinite Possibilities"

HashMap<K, V> permet d'associer des cles a des valeurs avec un acces en temps constant (amortized). Les cles doivent implementer Hash et Eq.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des fonctions manipulant HashMap<K, V> :

1. `create_phonebook` : creer un annuaire
2. `insert_entry` : ajouter une entree
3. `get_entry` : recuperer une valeur
4. `word_frequency` : compter les occurrences
5. `merge_maps` : fusionner deux hashmaps

**Entree :**

```rust
// src/lib.rs
use std::collections::HashMap;

/// Cree un annuaire depuis des tuples.
pub fn create_phonebook(entries: &[(&str, &str)]) -> HashMap<String, String> {
    // A implementer
}

/// Ajoute une entree a l'annuaire.
pub fn insert_entry(book: &mut HashMap<String, String>, name: &str, number: &str) {
    // A implementer
}

/// Recupere un numero par nom.
pub fn get_entry(book: &HashMap<String, String>, name: &str) -> Option<String> {
    // A implementer
}

/// Compte la frequence des mots.
pub fn word_frequency(text: &str) -> HashMap<String, usize> {
    // A implementer
}

/// Met a jour ou insere une valeur.
pub fn upsert(map: &mut HashMap<String, i32>, key: &str, value: i32) {
    // A implementer avec entry API
}

/// Fusionne deux hashmaps (la seconde ecrase en cas de conflit).
pub fn merge_maps(
    map1: HashMap<String, i32>,
    map2: HashMap<String, i32>,
) -> HashMap<String, i32> {
    // A implementer
}
```

**Sortie attendue :**

```
$ cargo test
running 6 tests
test tests::test_create_phonebook ... ok
test tests::test_insert_entry ... ok
test tests::test_get_entry ... ok
test tests::test_word_frequency ... ok
test tests::test_upsert ... ok
test tests::test_merge_maps ... ok

test result: ok. 6 passed; 0 failed
```

---

### 1.3 Prototype

```rust
pub fn create_phonebook(entries: &[(&str, &str)]) -> HashMap<String, String>;
pub fn insert_entry(book: &mut HashMap<String, String>, name: &str, number: &str);
pub fn get_entry(book: &HashMap<String, String>, name: &str) -> Option<String>;
pub fn word_frequency(text: &str) -> HashMap<String, usize>;
pub fn upsert(map: &mut HashMap<String, i32>, key: &str, value: i32);
pub fn merge_maps(map1: HashMap<String, i32>, map2: HashMap<String, i32>) -> HashMap<String, i32>;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Entry API :**

```rust
// Au lieu de:
if map.contains_key(&key) {
    *map.get_mut(&key).unwrap() += 1;
} else {
    map.insert(key, 1);
}

// Utiliser:
*map.entry(key).or_insert(0) += 1;
```

**Ownership des cles :**

```rust
let mut map = HashMap::new();
let key = String::from("hello");
map.insert(key, 42);  // key est move!
// println!("{}", key);  // ERREUR: key moved
```

**Iteration :**

```rust
for (key, value) in &map { }
for (key, value) in &mut map { }
for (key, value) in map { }  // Consomme
```

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo test
running 6 tests
...
test result: ok. 6 passed; 0 failed
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.3 Solution de reference (Rust)

```rust
use std::collections::HashMap;

pub fn create_phonebook(entries: &[(&str, &str)]) -> HashMap<String, String> {
    entries
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

pub fn insert_entry(book: &mut HashMap<String, String>, name: &str, number: &str) {
    book.insert(name.to_string(), number.to_string());
}

pub fn get_entry(book: &HashMap<String, String>, name: &str) -> Option<String> {
    book.get(name).cloned()
}

pub fn word_frequency(text: &str) -> HashMap<String, usize> {
    let mut freq = HashMap::new();
    for word in text.split_whitespace() {
        *freq.entry(word.to_string()).or_insert(0) += 1;
    }
    freq
}

pub fn upsert(map: &mut HashMap<String, i32>, key: &str, value: i32) {
    map.entry(key.to_string())
        .and_modify(|v| *v = value)
        .or_insert(value);
}

pub fn merge_maps(
    mut map1: HashMap<String, i32>,
    map2: HashMap<String, i32>,
) -> HashMap<String, i32> {
    for (k, v) in map2 {
        map1.insert(k, v);
    }
    map1
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A : get sans clone**

```rust
pub fn get_entry(book: &HashMap<String, String>, name: &str) -> Option<String> {
    book.get(name).map(|s| s.as_str().to_string())
}
// Note: Correct mais moins idiomatique que .cloned()
```

**Mutant B : word_frequency case-sensitive**

```rust
pub fn word_frequency(text: &str) -> HashMap<String, usize> {
    let mut freq = HashMap::new();
    for word in text.split_whitespace() {
        *freq.entry(word.to_string()).or_insert(0) += 1;
    }
    freq
}
// Note: La spec ne demande pas case-insensitive, donc c'est correct
```

**Mutant C : insert ecrase sans retour**

```rust
pub fn insert_entry(book: &mut HashMap<String, String>, name: &str, number: &str) {
    book.insert(name.to_string(), number.to_string());
    // Ignore le retour Option<String> (ancien valeur)
}
// Note: Correct selon la spec, l'ancien valeur est perdue
```

**Mutant D : merge_maps priorite inversee**

```rust
pub fn merge_maps(
    map1: HashMap<String, i32>,
    mut map2: HashMap<String, i32>,
) -> HashMap<String, i32> {
    for (k, v) in map1 {
        map2.insert(k, v);  // map1 ecrase au lieu de map2!
    }
    map2
}
// Pourquoi faux : Priorite inversee
```

**Mutant E : upsert n'update pas**

```rust
pub fn upsert(map: &mut HashMap<String, i32>, key: &str, value: i32) {
    map.entry(key.to_string()).or_insert(value);
    // Ne met pas a jour si existe deja!
}
// Pourquoi faux : N'ecrase pas la valeur existante
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| HashMap<K,V> | Collection cle-valeur | Critique |
| Entry API | Insert/Update efficace | Critique |
| Hash + Eq | Traits requis pour cles | Important |
| Ownership | Cles possedees | Important |

---

### 5.3 Visualisation ASCII

**HashMap en memoire :**

```
HashMap<String, i32>

Buckets (tableau de hash):
+-----+-----+-----+-----+-----+-----+-----+-----+
|  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |
+-----+-----+-----+-----+-----+-----+-----+-----+
  |           |                       |
  v           v                       v
+-------+   +-------+               +-------+
|"alice"|   |"bob"  |               |"carol"|
|  42   |   |  17   |               |  99   |
+-------+   +-------+               +-------+

hash("alice") % 8 = 0
hash("bob") % 8 = 2
hash("carol") % 8 = 6
```

**Entry API :**

```rust
map.entry(key)
    |
    +--> Occupied(OccupiedEntry)  // Cle existe
    |        |
    |        +--> .get() -> &V
    |        +--> .get_mut() -> &mut V
    |        +--> .into_mut() -> &mut V
    |
    +--> Vacant(VacantEntry)      // Cle n'existe pas
             |
             +--> .insert(value) -> &mut V
             +--> .or_insert(default) -> &mut V
             +--> .or_insert_with(|| ...) -> &mut V
```

---

### 5.5 Cours Complet

```rust
use std::collections::HashMap;

// Creation
let mut map: HashMap<String, i32> = HashMap::new();
let map2 = HashMap::from([("a", 1), ("b", 2)]);

// Insertion
map.insert("key".to_string(), 42);  // Retourne Option<V> (ancienne valeur)

// Acces
map.get("key")          // Option<&V>
map.get_mut("key")      // Option<&mut V>
map["key"]              // V (panic si absent!)
map.contains_key("key") // bool

// Entry API (recommande)
map.entry("key".to_string())
    .or_insert(0);            // Insere si absent
map.entry("key".to_string())
    .or_insert_with(|| expensive_computation());
map.entry("key".to_string())
    .and_modify(|v| *v += 1)
    .or_insert(1);

// Suppression
map.remove("key")       // Option<V>

// Iteration
for (k, v) in &map { }
for k in map.keys() { }
for v in map.values() { }

// Taille
map.len()
map.is_empty()
map.clear()
```

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | map[key] absent | Panic | Utiliser get() |
| 2 | Clone des cles String | Performance | Utiliser &str ou Cow |
| 3 | Modification pendant iteration | Borrow error | Collecter les cles d'abord |

---

## SECTION 7 : QCM

### Question 1 (4 points)
Que retourne map.entry(key).or_insert(0) ?

- A) Option<i32>
- B) &i32
- C) &mut i32
- D) i32

**Reponse : C** — or_insert retourne une reference mutable.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.13 |
| **Nom** | hashmaps |
| **Difficulte** | 4/10 |
| **Duree** | 45 min |
| **XP Base** | 90 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | HashMap, Entry API, Hash, Eq |
| **Prerequis** | vectors |
| **Domaines** | Collections, Hashing |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.13-hashmaps",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.13",
      "exercise_name": "hashmaps",
      "module": "0.7",
      "concept": "n",
      "concept_name": "HashMaps",
      "prerequisites": ["0.7.12"],
      "tags": ["hashmap", "entry", "get", "insert", "hash"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
