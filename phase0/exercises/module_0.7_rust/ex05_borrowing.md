# Exercice 0.7.5 : borrowing

**Module :**
0.7 — Introduction a Rust

**Concept :**
f — Borrowing : references immutables et mutables

**Difficulte :**
★★★★☆☆☆☆☆☆ (4/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.4 (ownership_basics)
- Comprehension du move semantics

**Domaines :**
Borrowing, Memory

**Duree estimee :**
45 min

**XP Base :**
90

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
| Rust | Toutes les fonctions de la bibliotheque standard |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Rust | `unsafe`, raw pointers |

---

### 1.2 Consigne

#### Section Culture : "Neither a Borrower Nor a Lender Be... Actually, Be Both!"

Le borrowing en Rust permet d'acceder a une valeur sans en prendre possession. C'est comme emprunter un livre a la bibliotheque : tu peux le lire, mais tu dois le rendre.

Les regles de borrowing sont au coeur du borrow checker, l'outil qui rend Rust unique. Ces regles sont inspirees du systeme de types lineaires et des "regions" de Cyclone.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des fonctions demontrant les regles du borrowing :

1. `calculate_length` : emprunte une String en lecture
2. `append_world` : emprunte une String en ecriture
3. `first_word` : retourne une reference vers une partie de la String
4. `longest` : compare deux Strings et retourne la plus longue

**Entree :**

```rust
// src/lib.rs

/// Calcule la longueur d'une String sans en prendre possession.
///
/// # Arguments
///
/// * `s` - Reference immutable vers une String
///
/// # Example
///
/// ```
/// let s = String::from("hello");
/// let len = borrowing::calculate_length(&s);
/// assert_eq!(len, 5);
/// // s est toujours utilisable
/// assert_eq!(s, "hello");
/// ```
pub fn calculate_length(s: &String) -> usize {
    // A implementer
}

/// Ajoute " world" a une String en la modifiant.
///
/// # Arguments
///
/// * `s` - Reference mutable vers une String
///
/// # Example
///
/// ```
/// let mut s = String::from("hello");
/// borrowing::append_world(&mut s);
/// assert_eq!(s, "hello world");
/// ```
pub fn append_world(s: &mut String) {
    // A implementer
}

/// Retourne le premier mot d'une chaine (jusqu'au premier espace).
///
/// # Arguments
///
/// * `s` - Reference vers une String
///
/// # Returns
///
/// Reference vers la slice contenant le premier mot
///
/// # Example
///
/// ```
/// let s = String::from("hello world");
/// let word = borrowing::first_word(&s);
/// assert_eq!(word, "hello");
/// ```
pub fn first_word(s: &String) -> &str {
    // A implementer
}

/// Compare deux Strings et retourne la plus longue.
///
/// # Arguments
///
/// * `s1` - Reference vers la premiere String
/// * `s2` - Reference vers la deuxieme String
///
/// # Returns
///
/// Reference vers la String la plus longue
///
/// # Example
///
/// ```
/// let s1 = String::from("short");
/// let s2 = String::from("longer string");
/// let longest = borrowing::longest(&s1, &s2);
/// assert_eq!(longest, "longer string");
/// ```
pub fn longest<'a>(s1: &'a String, s2: &'a String) -> &'a String {
    // A implementer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_length() {
        // A implementer
    }

    #[test]
    fn test_append_world() {
        // A implementer
    }

    #[test]
    fn test_first_word() {
        // A implementer
    }

    #[test]
    fn test_longest() {
        // A implementer
    }
}
```

**Sortie attendue :**

```
$ cargo test
running 4 tests
test tests::test_calculate_length ... ok
test tests::test_append_world ... ok
test tests::test_first_word ... ok
test tests::test_longest ... ok

test result: ok. 4 passed; 0 failed
```

**Contraintes :**
- Utiliser `&T` pour les emprunts immutables
- Utiliser `&mut T` pour les emprunts mutables
- Respecter les regles du borrow checker
- Annoter les lifetimes quand necessaire

**Exemples :**

| Fonction | Input | Output |
|----------|-------|--------|
| `calculate_length(&"hello".to_string())` | - | 5 |
| `append_world(&mut "hi".to_string())` | - | "hi world" |
| `first_word(&"hello world".to_string())` | - | "hello" |
| `longest(&"ab".to_string(), &"abc".to_string())` | - | "abc" |

---

### 1.3 Prototype

```rust
pub fn calculate_length(s: &String) -> usize;
pub fn append_world(s: &mut String);
pub fn first_word(s: &String) -> &str;
pub fn longest<'a>(s1: &'a String, s2: &'a String) -> &'a String;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Les deux regles d'or du borrowing :**

1. Tu peux avoir SOIT plusieurs references immutables (&T)
2. SOIT une seule reference mutable (&mut T)
3. Jamais les deux en meme temps !

**Pourquoi ces regles ?**

Elles empechent les data races a la compilation :
- Plusieurs lecteurs = OK (pas de modification)
- Un seul ecrivain = OK (pas de conflit)
- Lecteurs + Ecrivain = DATA RACE !

**Le borrow checker est ton ami**

Il peut sembler frustrant au debut, mais il te protege de bugs qui sont extremement difficiles a debugger dans d'autres langages.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Systems Programmer** | Acces concurrent safe aux ressources |
| **Game Dev** | References vers les entites du monde |
| **Backend Dev** | Partage de donnees entre handlers |
| **Embedded** | Acces aux peripheriques hardware |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo new borrowing --lib
     Created library `borrowing` package

$ cd borrowing

$ cat > src/lib.rs << 'EOF'
pub fn calculate_length(s: &String) -> usize {
    s.len()
}

pub fn append_world(s: &mut String) {
    s.push_str(" world");
}

pub fn first_word(s: &String) -> &str {
    let bytes = s.as_bytes();
    for (i, &item) in bytes.iter().enumerate() {
        if item == b' ' {
            return &s[..i];
        }
    }
    &s[..]
}

pub fn longest<'a>(s1: &'a String, s2: &'a String) -> &'a String {
    if s1.len() > s2.len() { s1 } else { s2 }
}
EOF

$ cargo test
running 0 tests
test result: ok. 0 passed; 0 failed

$ cargo clippy
    Checking borrowing v0.1.0
    Finished dev [unoptimized + debuginfo] target(s)
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | length_basic | `&"hello"` | 5 | 10 | Basic |
| 2 | length_empty | `&""` | 0 | 10 | Edge |
| 3 | append_basic | `&mut "hi"` | "hi world" | 15 | Basic |
| 4 | append_empty | `&mut ""` | " world" | 10 | Edge |
| 5 | first_word_basic | `&"hello world"` | "hello" | 15 | Basic |
| 6 | first_word_single | `&"hello"` | "hello" | 10 | Edge |
| 7 | longest_first | `&"longer", &"short"` | "longer" | 15 | Basic |
| 8 | longest_equal | `&"abc", &"def"` | "def" | 15 | Edge |

**Total : 100 points**

---

### 4.2 Tests de la moulinette

```rust
#[cfg(test)]
mod moulinette_tests {
    use super::*;

    #[test]
    fn test_calculate_length_basic() {
        let s = String::from("hello");
        assert_eq!(calculate_length(&s), 5);
        assert_eq!(s, "hello"); // s toujours valide
    }

    #[test]
    fn test_calculate_length_empty() {
        let s = String::from("");
        assert_eq!(calculate_length(&s), 0);
    }

    #[test]
    fn test_append_world_basic() {
        let mut s = String::from("hello");
        append_world(&mut s);
        assert_eq!(s, "hello world");
    }

    #[test]
    fn test_append_world_empty() {
        let mut s = String::from("");
        append_world(&mut s);
        assert_eq!(s, " world");
    }

    #[test]
    fn test_first_word_basic() {
        let s = String::from("hello world");
        assert_eq!(first_word(&s), "hello");
    }

    #[test]
    fn test_first_word_single() {
        let s = String::from("hello");
        assert_eq!(first_word(&s), "hello");
    }

    #[test]
    fn test_longest_first() {
        let s1 = String::from("longer");
        let s2 = String::from("short");
        assert_eq!(longest(&s1, &s2), &s1);
    }

    #[test]
    fn test_longest_equal() {
        let s1 = String::from("abc");
        let s2 = String::from("def");
        assert_eq!(longest(&s1, &s2), &s2);
    }
}
```

---

### 4.3 Solution de reference (Rust)

```rust
/// Calcule la longueur sans prendre possession.
pub fn calculate_length(s: &String) -> usize {
    s.len()
}

/// Ajoute " world" via reference mutable.
pub fn append_world(s: &mut String) {
    s.push_str(" world");
}

/// Retourne le premier mot (jusqu'a l'espace).
pub fn first_word(s: &String) -> &str {
    let bytes = s.as_bytes();
    for (i, &item) in bytes.iter().enumerate() {
        if item == b' ' {
            return &s[..i];
        }
    }
    &s[..]
}

/// Retourne la plus longue des deux Strings.
pub fn longest<'a>(s1: &'a String, s2: &'a String) -> &'a String {
    if s1.len() > s2.len() {
        s1
    } else {
        s2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_length() {
        let s = String::from("hello");
        assert_eq!(calculate_length(&s), 5);
    }

    #[test]
    fn test_append_world() {
        let mut s = String::from("hello");
        append_world(&mut s);
        assert_eq!(s, "hello world");
    }

    #[test]
    fn test_first_word() {
        let s = String::from("hello world");
        assert_eq!(first_word(&s), "hello");
    }

    #[test]
    fn test_longest() {
        let s1 = String::from("short");
        let s2 = String::from("longer");
        assert_eq!(longest(&s1, &s2), &s2);
    }
}
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : first_word avec find**

```rust
pub fn first_word(s: &String) -> &str {
    match s.find(' ') {
        Some(idx) => &s[..idx],
        None => &s[..],
    }
}
// Accepte, plus concis
```

**Alternative 2 : first_word avec split**

```rust
pub fn first_word(s: &String) -> &str {
    s.split_whitespace().next().unwrap_or("")
}
// Accepte, mais gere differemment les espaces multiples
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : Prendre possession au lieu d'emprunter**

```rust
// REFUSE : Prend possession au lieu d'emprunter
pub fn calculate_length(s: String) -> usize {
    s.len()
}
```
**Pourquoi refuse :** La signature demande une reference, pas la valeur.

**Refus 2 : Reference mutable quand immutable suffit**

```rust
// REFUSE : Mutable inutile
pub fn calculate_length(s: &mut String) -> usize {
    s.len()
}
```
**Pourquoi refuse :** Demander &mut quand & suffit viole le principe du moindre privilege.

**Refus 3 : Retourner une String au lieu d'une reference**

```rust
// REFUSE : Allocation inutile
pub fn first_word(s: &String) -> String {
    s.split_whitespace().next().unwrap_or("").to_string()
}
```
**Pourquoi refuse :** La signature demande &str, pas String.

---

### 4.9 spec.json (ENGINE v22.1)

```json
{
  "name": "borrowing",
  "language": "rust",
  "language_version": "edition 2024",
  "type": "code",
  "tier": 1,
  "tier_info": "Concept isole",
  "tags": ["module0.7", "borrowing", "references", "lifetimes", "phase0"],
  "passing_score": 70,

  "function": {
    "name": "calculate_length",
    "prototype": "pub fn calculate_length(s: &String) -> usize",
    "return_type": "usize",
    "parameters": [
      {"name": "s", "type": "&String"}
    ]
  },

  "driver": {
    "edge_cases": [
      {
        "name": "empty_string",
        "args": [""],
        "expected": 0,
        "is_trap": false
      },
      {
        "name": "no_space",
        "args": ["hello"],
        "expected": "hello",
        "is_trap": true,
        "trap_explanation": "first_word doit retourner toute la chaine si pas d'espace"
      }
    ]
  },

  "norm": {
    "allowed_functions": ["len", "push_str", "as_bytes", "iter", "enumerate"],
    "forbidden_functions": ["unsafe"],
    "check_security": false,
    "check_memory": false,
    "blocking": false
  }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Type) : Prendre possession au lieu d'emprunter**

```rust
/* Mutant A (Type) : Signature incorrecte */
pub fn calculate_length(s: String) -> usize {
    s.len()
}
// Pourquoi faux : Ne compile pas avec la signature demandee
// Ce qui etait pense : "C'est pareil"
```

**Mutant B (Logic) : Oublier le cas sans espace**

```rust
/* Mutant B (Logic) : Panic si pas d'espace */
pub fn first_word(s: &String) -> &str {
    let idx = s.find(' ').unwrap();  // Panic si pas d'espace !
    &s[..idx]
}
// Pourquoi faux : Panic sur "hello" (sans espace)
// Ce qui etait pense : "Il y aura toujours un espace"
```

**Mutant C (Lifetime) : Mauvaise annotation de lifetime**

```rust
/* Mutant C (Lifetime) : Lifetimes incorrects */
pub fn longest<'a, 'b>(s1: &'a String, s2: &'b String) -> &'a String {
    if s1.len() > s2.len() { s1 } else { s2 }
}
// Pourquoi faux : s2 pourrait avoir un lifetime different
// Ce qui etait pense : "Chacun son lifetime"
```

**Mutant D (Return) : Retourner une copie au lieu d'une reference**

```rust
/* Mutant D (Return) : Type de retour incorrect */
pub fn first_word(s: &String) -> String {
    s.split_whitespace().next().unwrap_or("").to_string()
}
// Pourquoi faux : La signature demande &str
// Ce qui etait pense : "Retourner String c'est plus safe"
```

**Mutant E (Safety) : Reference mutable inutile**

```rust
/* Mutant E (Safety) : Privilege excessif */
pub fn calculate_length(s: &mut String) -> usize {
    s.len()
}
// Pourquoi faux : Demande mut alors que & suffit
// Ce qui etait pense : "&mut donne plus d'acces"
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| &T | Reference immutable | Critique |
| &mut T | Reference mutable | Critique |
| Borrow rules | Une seule &mut OU plusieurs & | Critique |
| Lifetimes | Duree de vie des references | Important |

---

### 5.2 LDA — Traduction litterale en MAJUSCULES

```
FONCTION calculate_length QUI EMPRUNTE s EN LECTURE
DEBUT FONCTION
    RETOURNER LA LONGUEUR DE s
    -- s EST TOUJOURS POSSEDE PAR LE CALLER
FIN FONCTION

FONCTION append_world QUI EMPRUNTE s EN ECRITURE
DEBUT FONCTION
    AJOUTER " world" A LA FIN DE s
    -- s EST MODIFIE MAIS TOUJOURS POSSEDE PAR LE CALLER
FIN FONCTION

REGLES DU BORROW CHECKER:
    REGLE 1: PLUSIEURS &T OU UN SEUL &mut T, JAMAIS LES DEUX
    REGLE 2: LES REFERENCES NE PEUVENT PAS SURVIVRE A LEUR REFERENT
    REGLE 3: PAS DE DANGLING REFERENCES
```

---

### 5.3 Visualisation ASCII

**Immutable borrow (&T) :**

```
let s = String::from("hello");
let r1 = &s;  // emprunt immutable
let r2 = &s;  // emprunt immutable (OK, plusieurs & autorise)

Stack:                     Heap:
+----------------+         +-----------------+
| s              |-------->| h | e | l | l | o |
| (owner)        |         +-----------------+
+----------------+                  ^
+----------------+                  |
| r1 (&s)        |------------------+
+----------------+                  |
+----------------+                  |
| r2 (&s)        |------------------+
+----------------+

Plusieurs lecteurs = OK
```

**Mutable borrow (&mut T) :**

```
let mut s = String::from("hello");
let r = &mut s;  // emprunt mutable (exclusif)

Stack:                     Heap:
+----------------+         +-----------------+
| s              |--X----->| h | e | l | l | o |
| (owner,        |         +-----------------+
|  temporaire-   |                  ^
|  ment bloque)  |                  |
+----------------+                  |
+----------------+                  |
| r (&mut s)     |------------------+
+----------------+

Un seul ecrivain, owner bloque temporairement
```

**Conflit interdit :**

```
let mut s = String::from("hello");
let r1 = &s;      // emprunt immutable
let r2 = &mut s;  // ERROR: ne peut pas emprunter mut pendant &

    +--------------------------------------------+
    |  ERROR: cannot borrow `s` as mutable       |
    |  because it is also borrowed as            |
    |  immutable                                 |
    +--------------------------------------------+
```

**Lifetimes :**

```
fn longest<'a>(s1: &'a str, s2: &'a str) -> &'a str

'a signifie: "la reference retournee vit aussi longtemps
              que la plus courte des deux entrees"

Timeline:
|-------- s1 vit ici -----------|
|---- s2 vit ici ----|
|---- retour valide -|          <- limite par s2
                     |
                     +-- apres ce point, le retour serait dangling
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Mutable et immutable en meme temps

```rust
let mut s = String::from("hello");
let r1 = &s;      // OK
let r2 = &s;      // OK
let r3 = &mut s;  // ERROR: conflit avec r1, r2

// Solution: s'assurer que r1 et r2 ne sont plus utilises
let r1 = &s;
println!("{}", r1);  // derniere utilisation de r1
let r3 = &mut s;     // OK maintenant (NLL: Non-Lexical Lifetimes)
```

#### Piege 2 : Reference qui survit a son owner

```rust
fn dangle() -> &String {
    let s = String::from("hello");
    &s  // ERROR: s sera drop, reference invalide
}
```

#### Piege 3 : Modifier pendant une iteration

```rust
let mut v = vec![1, 2, 3];
for x in &v {
    v.push(*x);  // ERROR: ne peut pas modifier v pendant qu'on itere
}
```

---

### 5.5 Cours Complet

#### 5.5.1 References immutables (&T)

```rust
let s = String::from("hello");
let r = &s;  // emprunte s en lecture

println!("{}", r);  // OK: lecture
// r.push_str("!");  // ERROR: r est immutable

// Plusieurs & OK
let r1 = &s;
let r2 = &s;
let r3 = &s;
```

#### 5.5.2 References mutables (&mut T)

```rust
let mut s = String::from("hello");
let r = &mut s;  // emprunte s en ecriture

r.push_str(" world");  // OK: modification
println!("{}", r);     // "hello world"

// Une seule &mut a la fois
let r1 = &mut s;
// let r2 = &mut s;  // ERROR: deja emprunte mut
```

#### 5.5.3 Regles du borrow checker

```rust
// REGLE 1: Plusieurs &T OU un seul &mut T

// OK: plusieurs lectures
let r1 = &s;
let r2 = &s;

// OK: une ecriture
let r = &mut s;

// ERROR: lecture + ecriture
let r1 = &s;
let r2 = &mut s;  // CONFLIT


// REGLE 2: References ne survivent pas a leur owner

let r;
{
    let s = String::from("hello");
    r = &s;  // ERROR: s sera drop
}
println!("{}", r);  // dangling!
```

#### 5.5.4 Lifetimes

```rust
// Annotations explicites
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() > y.len() { x } else { y }
}

// 'a = intersection des lifetimes de x et y
// Le retour ne peut pas vivre plus longtemps que le plus court des deux
```

---

### 5.6 Normes avec explications pedagogiques

```
+------------------------------------------------------------------+
| HORS NORME                                                       |
+------------------------------------------------------------------+
| pub fn calculate_length(s: &mut String) -> usize { s.len() }     |
+------------------------------------------------------------------+
| CONFORME                                                         |
+------------------------------------------------------------------+
| pub fn calculate_length(s: &String) -> usize { s.len() }         |
+------------------------------------------------------------------+
| POURQUOI ?                                                       |
|                                                                  |
| - Moindre privilege : demander & quand &mut n'est pas necessaire |
| - Flexibilite : le caller peut avoir d'autres references         |
| - Intention claire : cette fonction ne modifie pas               |
+------------------------------------------------------------------+
```

---

### 5.7 Simulation avec trace d'execution

```
calculate_length(&"hello".to_string()):
+-------+----------------------------------------------------------+
| Etape | Operation                                                |
+-------+----------------------------------------------------------+
|   1   | Caller cree String "hello" (owner)                       |
|   2   | Caller cree reference &s vers String                     |
|   3   | Reference passee a calculate_length                      |
|   4   | Fonction lit s.len() via reference                       |
|   5   | Reference termine (emprunt fini)                         |
|   6   | Caller peut reutiliser s                                 |
+-------+----------------------------------------------------------+

first_word(&"hello world".to_string()):
+-------+----------------------------------------------------------+
| Etape | Operation                                                |
+-------+----------------------------------------------------------+
|   1   | s = "hello world"                                        |
|   2   | Cherche l'espace (index 5)                               |
|   3   | Cree slice &s[0..5] = "hello"                            |
|   4   | Retourne reference vers partie de s                      |
+-------+----------------------------------------------------------+
```

---

### 5.8 Mnemotechniques

**BORROW = Briefly Obtain Reference, Return Ownership When done**

Tu obtiens brievement une reference, tu rends l'ownership quand c'est fini.

**& = Amper-share (plusieurs peuvent partager)**
**&mut = Amper-mute-exclusive (un seul peut modifier)**

---

### 5.9 Applications pratiques

| Scenario | Technique |
|----------|-----------|
| **Lire des donnees** | &T (reference immutable) |
| **Modifier des donnees** | &mut T (reference mutable) |
| **Retourner une vue** | Slice &[T] ou &str |
| **Comparer des donnees** | Deux &T (plusieurs lectures OK) |

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | &mut + & en meme temps | Erreur compilation | Separer les usages |
| 2 | Reference qui survit | Dangling reference | Respecter les lifetimes |
| 3 | &mut quand & suffit | Moindre flexibilite | Utiliser & si possible |
| 4 | Oublier 'a | Erreur lifetime | Annoter quand necessaire |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Combien de references immutables peut-on avoir simultanement ?

- A) Une seule
- B) Deux maximum
- C) Autant qu'on veut
- D) Cela depend de la taille

**Reponse : C** — On peut avoir autant de & qu'on veut.

---

### Question 2 (3 points)
Peut-on avoir une &mut et une & en meme temps ?

- A) Oui, toujours
- B) Non, jamais
- C) Seulement dans les closures
- D) Seulement si c'est le meme scope

**Reponse : B** — Les deux sont incompatibles.

---

### Question 3 (4 points)
Que signifie 'a dans `fn foo<'a>(x: &'a str) -> &'a str` ?

- A) Le type du parametre
- B) La duree de vie de la reference
- C) La taille en memoire
- D) Le nom de la variable

**Reponse : B** — 'a est une annotation de lifetime.

---

### Question 4 (5 points)
Pourquoi &String est-il moins idiomatique que &str ?

- A) &String est plus lent
- B) &str est plus general (accepte String et &str)
- C) &String ne compile pas
- D) Ils sont equivalents

**Reponse : B** — &str peut etre cree depuis String, &str, ou literal.

---

### Question 5 (5 points)
Que se passe-t-il si on retourne &T d'une variable locale ?

- A) Ca marche normalement
- B) Erreur de compilation (dangling reference)
- C) Undefined behavior
- D) La variable est clonee

**Reponse : B** — Le compilateur refuse (la variable sera droppee).

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.5 |
| **Nom** | borrowing |
| **Difficulte** | 4/10 |
| **Duree** | 45 min |
| **XP Base** | 90 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | &T, &mut T, borrow rules, lifetimes |
| **Prerequis** | ownership_basics |
| **Domaines** | Borrowing, Memory |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.5-borrowing",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.5",
      "exercise_name": "borrowing",
      "module": "0.7",
      "module_name": "Introduction a Rust",
      "concept": "f",
      "concept_name": "Borrowing",
      "type": "code",
      "tier": 1,
      "difficulty": 4,
      "difficulty_stars": "4/10",
      "languages": ["rust"],
      "duration_minutes": 45,
      "xp_base": 90,
      "prerequisites": ["0.7.4"],
      "domains": ["Borrowing", "Memory"],
      "tags": ["borrowing", "references", "lifetimes", "borrow-checker"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
