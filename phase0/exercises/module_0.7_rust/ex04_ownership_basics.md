# Exercice 0.7.4 : ownership_basics

**Module :**
0.7 — Introduction a Rust

**Concept :**
e — Ownership : move, Clone, Copy et Drop

**Difficulte :**
★★★☆☆☆☆☆☆☆ (3/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Exercice 0.7.3 (compounds)
- Notion de pointeur et memoire

**Domaines :**
Ownership, Memory

**Duree estimee :**
40 min

**XP Base :**
80

**Complexite :**
T0 O(1) × S1 O(n)

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
| Rust | `clone()`, `to_string()`, `drop()` |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Rust | `unsafe`, `Rc`, `Arc` |

---

### 1.2 Consigne

#### Section Culture : "One Owner to Rule Them All"

L'ownership est le concept central de Rust. Chaque valeur a un proprietaire unique. Quand le proprietaire sort du scope, la valeur est detruite (Drop). C'est comme ca que Rust garantit la securite memoire sans garbage collector.

Ce systeme s'inspire des "affine types" en theorie des types, ou une ressource ne peut etre utilisee qu'une seule fois. C'est aussi lie au RAII (Resource Acquisition Is Initialization) de C++.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer des fonctions qui demontrent la comprehension de l'ownership :

1. `take_ownership` : Prend possession d'une String
2. `give_ownership` : Cree et retourne une String
3. `clone_and_modify` : Clone une String et la modifie
4. `copy_value` : Montre que les types Copy sont copies, pas moves

**Entree :**

```rust
// src/lib.rs

/// Prend possession d'une String et retourne sa longueur.
/// La String est detruite a la fin de la fonction.
///
/// # Example
///
/// ```
/// let s = String::from("hello");
/// let len = ownership_basics::take_ownership(s);
/// assert_eq!(len, 5);
/// // s n'est plus utilisable ici (moved)
/// ```
pub fn take_ownership(s: String) -> usize {
    // A implementer
}

/// Cree une nouvelle String et la retourne (transfert de propriete).
///
/// # Example
///
/// ```
/// let s = ownership_basics::give_ownership();
/// assert_eq!(s, "Hello from Rust");
/// ```
pub fn give_ownership() -> String {
    // A implementer
}

/// Clone une String, modifie le clone, et retourne les deux.
///
/// # Example
///
/// ```
/// let original = String::from("hello");
/// let (orig, modified) = ownership_basics::clone_and_modify(original);
/// assert_eq!(orig, "hello");
/// assert_eq!(modified, "hello world");
/// ```
pub fn clone_and_modify(s: String) -> (String, String) {
    // A implementer
}

/// Demontre que les types Copy sont copies automatiquement.
/// Retourne la somme de deux entiers sans move.
///
/// # Example
///
/// ```
/// let a = 5;
/// let b = 10;
/// let sum = ownership_basics::copy_value(a, b);
/// assert_eq!(sum, 15);
/// // a et b sont toujours utilisables
/// ```
pub fn copy_value(a: i32, b: i32) -> i32 {
    // A implementer
}

/// Structure avec implementation Drop pour tracer la destruction.
#[derive(Debug)]
pub struct TrackedResource {
    pub name: String,
    pub id: u32,
}

impl TrackedResource {
    pub fn new(name: &str, id: u32) -> Self {
        println!("[TRACE] Creating resource: {} (id={})", name, id);
        Self {
            name: name.to_string(),
            id,
        }
    }
}

impl Drop for TrackedResource {
    fn drop(&mut self) {
        println!("[TRACE] Dropping resource: {} (id={})", self.name, self.id);
    }
}

/// Cree des ressources tracees pour demontrer l'ordre de Drop.
///
/// # Example
///
/// ```
/// ownership_basics::demonstrate_drop_order();
/// // Output:
/// // [TRACE] Creating resource: first (id=1)
/// // [TRACE] Creating resource: second (id=2)
/// // [TRACE] Dropping resource: second (id=2)
/// // [TRACE] Dropping resource: first (id=1)
/// ```
pub fn demonstrate_drop_order() {
    // A implementer
}
```

**Sortie attendue :**

```
$ cargo test
running 5 tests
test tests::test_take_ownership ... ok
test tests::test_give_ownership ... ok
test tests::test_clone_and_modify ... ok
test tests::test_copy_value ... ok
test tests::test_drop_order ... ok

test result: ok. 5 passed; 0 failed
```

**Contraintes :**
- `take_ownership` doit prendre la String par valeur (move)
- `clone_and_modify` doit utiliser `.clone()` explicitement
- `TrackedResource` doit implementer `Drop`
- L'ordre de Drop est LIFO (dernier cree, premier detruit)

**Exemples :**

| Fonction | Input | Output |
|----------|-------|--------|
| `take_ownership("hello".to_string())` | - | 5 |
| `give_ownership()` | - | `"Hello from Rust"` |
| `clone_and_modify("hi".to_string())` | - | `("hi", "hi world")` |
| `copy_value(10, 20)` | - | 30 |

---

### 1.3 Prototype

```rust
pub fn take_ownership(s: String) -> usize;
pub fn give_ownership() -> String;
pub fn clone_and_modify(s: String) -> (String, String);
pub fn copy_value(a: i32, b: i32) -> i32;
pub fn demonstrate_drop_order();
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Pourquoi "move" et pas "copy" par defaut ?**

Rust suppose que les types sont couteux a copier. Seuls les types triviaux (entiers, booleens, etc.) implementent Copy. Pour les autres, il faut explicitement demander une copie avec `.clone()`.

**RAII : Resource Acquisition Is Initialization**

Le Drop de Rust vient de C++ et du pattern RAII : les ressources (memoire, fichiers, sockets) sont automatiquement liberees quand l'objet est detruit.

**Affine Types**

L'ownership de Rust est inspire des "affine types" de la theorie des types lineaires, ou chaque ressource doit etre utilisee exactement une fois (ou zero fois).

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **Systems Programmer** | Gestion de fichiers, sockets, memoire |
| **Game Dev** | Gestion des assets et ressources GPU |
| **Embedded** | Controle precis de la memoire |
| **Backend** | Connexions DB, handles de fichiers |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo new ownership_basics --lib
     Created library `ownership_basics` package

$ cd ownership_basics

$ cargo test
running 5 tests
test tests::test_take_ownership ... ok
test tests::test_give_ownership ... ok
test tests::test_clone_and_modify ... ok
test tests::test_copy_value ... ok
test tests::test_drop_order ... ok

test result: ok. 5 passed; 0 failed

$ cargo run --example drop_demo
[TRACE] Creating resource: first (id=1)
[TRACE] Creating resource: second (id=2)
[TRACE] Dropping resource: second (id=2)
[TRACE] Dropping resource: first (id=1)
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | take_basic | `"hello"` | 5 | 15 | Basic |
| 2 | take_empty | `""` | 0 | 10 | Edge |
| 3 | give_basic | - | `"Hello from Rust"` | 15 | Basic |
| 4 | clone_basic | `"hi"` | `("hi", "hi world")` | 20 | Clone |
| 5 | clone_empty | `""` | `("", " world")` | 10 | Edge |
| 6 | copy_basic | `(5, 10)` | 15 | 10 | Copy |
| 7 | copy_negative | `(-5, 10)` | 5 | 5 | Copy |
| 8 | drop_order | - | LIFO order | 15 | Drop |

**Total : 100 points**

---

### 4.2 Tests de la moulinette

```rust
#[cfg(test)]
mod moulinette_tests {
    use super::*;

    #[test]
    fn test_take_ownership_basic() {
        let s = String::from("hello");
        assert_eq!(take_ownership(s), 5);
    }

    #[test]
    fn test_take_ownership_empty() {
        let s = String::from("");
        assert_eq!(take_ownership(s), 0);
    }

    #[test]
    fn test_give_ownership() {
        let s = give_ownership();
        assert_eq!(s, "Hello from Rust");
    }

    #[test]
    fn test_clone_and_modify_basic() {
        let s = String::from("hello");
        let (orig, modified) = clone_and_modify(s);
        assert_eq!(orig, "hello");
        assert_eq!(modified, "hello world");
    }

    #[test]
    fn test_clone_and_modify_empty() {
        let s = String::from("");
        let (orig, modified) = clone_and_modify(s);
        assert_eq!(orig, "");
        assert_eq!(modified, " world");
    }

    #[test]
    fn test_copy_value_basic() {
        let a = 5;
        let b = 10;
        let sum = copy_value(a, b);
        assert_eq!(sum, 15);
        // a et b toujours utilisables apres l'appel (Copy)
        assert_eq!(a, 5);
        assert_eq!(b, 10);
    }

    #[test]
    fn test_copy_value_negative() {
        assert_eq!(copy_value(-5, 10), 5);
    }

    #[test]
    fn test_tracked_resource_drop() {
        let _r = TrackedResource::new("test", 42);
        // Drop sera appele automatiquement
    }
}
```

---

### 4.3 Solution de reference (Rust)

```rust
/// Prend possession d'une String et retourne sa longueur.
pub fn take_ownership(s: String) -> usize {
    s.len()
    // s est drop ici automatiquement
}

/// Cree et retourne une String.
pub fn give_ownership() -> String {
    String::from("Hello from Rust")
    // La propriete est transferee au caller
}

/// Clone et modifie.
pub fn clone_and_modify(s: String) -> (String, String) {
    let cloned = s.clone();
    let modified = cloned + " world";
    (s, modified)
}

/// Addition de types Copy.
pub fn copy_value(a: i32, b: i32) -> i32 {
    a + b
    // a et b sont copies, pas moves (i32 impl Copy)
}

/// Structure tracee.
#[derive(Debug)]
pub struct TrackedResource {
    pub name: String,
    pub id: u32,
}

impl TrackedResource {
    pub fn new(name: &str, id: u32) -> Self {
        println!("[TRACE] Creating resource: {} (id={})", name, id);
        Self {
            name: name.to_string(),
            id,
        }
    }
}

impl Drop for TrackedResource {
    fn drop(&mut self) {
        println!("[TRACE] Dropping resource: {} (id={})", self.name, self.id);
    }
}

/// Demontre l'ordre LIFO du Drop.
pub fn demonstrate_drop_order() {
    let _first = TrackedResource::new("first", 1);
    let _second = TrackedResource::new("second", 2);
    // A la fin du scope :
    // second est drop en premier (LIFO)
    // first est drop ensuite
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_take_ownership() {
        assert_eq!(take_ownership(String::from("test")), 4);
    }

    #[test]
    fn test_give_ownership() {
        assert_eq!(give_ownership(), "Hello from Rust");
    }

    #[test]
    fn test_clone_and_modify() {
        let (orig, modified) = clone_and_modify(String::from("hello"));
        assert_eq!(orig, "hello");
        assert_eq!(modified, "hello world");
    }

    #[test]
    fn test_copy_value() {
        assert_eq!(copy_value(5, 10), 15);
    }

    #[test]
    fn test_drop_order() {
        demonstrate_drop_order();
    }
}
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : clone_and_modify avec format!**

```rust
pub fn clone_and_modify(s: String) -> (String, String) {
    let modified = format!("{} world", &s);
    (s, modified)
}
// Accepte, utilise une reference pour creer le format
```

**Alternative 2 : clone_and_modify avec push_str sur clone**

```rust
pub fn clone_and_modify(s: String) -> (String, String) {
    let mut modified = s.clone();
    modified.push_str(" world");
    (s, modified)
}
// Accepte, modification in-place du clone
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : Retourner une reference a une String locale**

```rust
// REFUSE : Dangling reference !
pub fn give_ownership() -> &'static str {
    let s = String::from("Hello");
    &s  // ERROR: s est drop, reference invalide
}
```
**Pourquoi refuse :** La String est detruite a la fin de la fonction, la reference serait invalide.

**Refus 2 : Utiliser s apres le move**

```rust
// REFUSE : Use after move
pub fn take_ownership(s: String) -> usize {
    let len = s.len();
    drop(s);
    s.len()  // ERROR: s a ete moved/dropped
}
```
**Pourquoi refuse :** Une fois moved ou dropped, une valeur ne peut plus etre utilisee.

**Refus 3 : Pas de Clone explicite**

```rust
// REFUSE : Pas de clone, move implicite
pub fn clone_and_modify(s: String) -> (String, String) {
    let modified = s + " world";  // s est move ici !
    (s, modified)  // ERROR: s deja moved
}
```
**Pourquoi refuse :** L'operateur + prend ownership de la String gauche.

---

### 4.9 spec.json (ENGINE v22.1)

```json
{
  "name": "ownership_basics",
  "language": "rust",
  "language_version": "edition 2024",
  "type": "code",
  "tier": 1,
  "tier_info": "Concept isole",
  "tags": ["module0.7", "ownership", "move", "clone", "copy", "drop", "phase0"],
  "passing_score": 70,

  "function": {
    "name": "take_ownership",
    "prototype": "pub fn take_ownership(s: String) -> usize",
    "return_type": "usize",
    "parameters": [
      {"name": "s", "type": "String"}
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
        "name": "clone_required",
        "args": ["test"],
        "expected": "original preserved",
        "is_trap": true,
        "trap_explanation": "Doit cloner pour garder l'original"
      }
    ]
  },

  "norm": {
    "allowed_functions": ["clone", "drop", "len", "to_string"],
    "forbidden_functions": ["unsafe", "Rc", "Arc"],
    "check_security": false,
    "check_memory": false,
    "blocking": false
  }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Logic) : Oubli du clone**

```rust
/* Mutant A (Logic) : Move au lieu de clone */
pub fn clone_and_modify(s: String) -> (String, String) {
    let modified = s + " world";  // s est move !
    (s, modified)  // ERROR: use after move
}
// Pourquoi faux : s est moved par +, ne peut plus etre retourne
// Ce qui etait pense : "+ ne move pas"
```

**Mutant B (Return) : Mauvais message**

```rust
/* Mutant B (Return) : Message incorrect */
pub fn give_ownership() -> String {
    String::from("Hello")  // Manque "from Rust"
}
// Pourquoi faux : Le message attendu est "Hello from Rust"
// Ce qui etait pense : "Hello suffit"
```

**Mutant C (Type) : Reference au lieu de valeur**

```rust
/* Mutant C (Type) : Ne prend pas ownership */
pub fn take_ownership(s: &String) -> usize {
    s.len()  // Emprunte seulement, ne prend pas ownership
}
// Pourquoi faux : La signature demande String, pas &String
// Ce qui etait pense : "Une reference c'est plus efficace"
```

**Mutant D (Safety) : Drop manuel incorrect**

```rust
/* Mutant D (Safety) : Double drop */
pub fn take_ownership(s: String) -> usize {
    let len = s.len();
    drop(s);
    drop(s);  // ERROR: use after move
    len
}
// Pourquoi faux : On ne peut pas drop deux fois
// Ce qui etait pense : "Drop explicite est mieux"
```

**Mutant E (Logic) : Ordre de Drop incorrect**

```rust
/* Mutant E (Logic) : Mauvaise comprehension LIFO */
pub fn demonstrate_drop_order() {
    let _second = TrackedResource::new("second", 2);
    let _first = TrackedResource::new("first", 1);
    // Drop: first puis second (LIFO du mauvais ordre)
}
// Pourquoi faux : L'ordre de creation est inverse
// Ce qui etait pense : "L'ordre n'a pas d'importance"
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Ownership | Chaque valeur a un proprietaire unique | Critique |
| Move | Transfert de propriete | Critique |
| Clone | Copie explicite en profondeur | Important |
| Copy | Copie implicite pour types simples | Important |
| Drop | Liberation automatique des ressources | Critique |

---

### 5.2 LDA — Traduction litterale en MAJUSCULES

```
FONCTION take_ownership QUI PREND s COMME String (OWNERSHIP TRANSFERE)
DEBUT FONCTION
    CALCULER len COMME LONGUEUR DE s
    RETOURNER len
    -- A LA FIN DU SCOPE, s EST AUTOMATIQUEMENT DETRUIT (DROP)
FIN FONCTION

FONCTION clone_and_modify QUI PREND s COMME String (OWNERSHIP TRANSFERE)
DEBUT FONCTION
    CREER cloned COMME COPIE PROFONDE DE s (CLONE)
    CREER modified COMME cloned CONCATENE AVEC " world"
    RETOURNER (s, modified) -- LES DEUX OWNERSHIPS SONT TRANSFERES AU CALLER
FIN FONCTION

REGLE D'OWNERSHIP:
    QUAND UNE VALEUR SORT DU SCOPE:
        APPELER drop() SUR CETTE VALEUR
        LIBERER LA MEMOIRE ASSOCIEE
```

---

### 5.3 Visualisation ASCII

**Move semantics :**

```
let s1 = String::from("hello");

Stack:                Heap:
┌──────────────┐     ┌─────────────────┐
│ s1           │     │ h │ e │ l │ l │ o │
│ ├─ ptr ──────┼────►└─────────────────┘
│ ├─ len: 5    │
│ └─ cap: 5    │
└──────────────┘

let s2 = s1;  // MOVE !

Stack:                Heap:
┌──────────────┐     ┌─────────────────┐
│ s1 (invalid) │  X  │ h │ e │ l │ l │ o │
│ ├─ ptr ──────┼──/  └─────────────────┘
│ ...          │            ▲
└──────────────┘            │
┌──────────────┐            │
│ s2           │            │
│ ├─ ptr ──────┼────────────┘
│ ├─ len: 5    │
│ └─ cap: 5    │
└──────────────┘

s1 n'est plus valide ! Seul s2 possede les donnees.
```

**Clone :**

```
let s1 = String::from("hello");
let s2 = s1.clone();  // CLONE !

Stack:                Heap:
┌──────────────┐     ┌─────────────────┐
│ s1           │     │ h │ e │ l │ l │ o │ (original)
│ ├─ ptr ──────┼────►└─────────────────┘
│ ...          │
└──────────────┘
┌──────────────┐     ┌─────────────────┐
│ s2           │     │ h │ e │ l │ l │ o │ (copie)
│ ├─ ptr ──────┼────►└─────────────────┘
│ ...          │
└──────────────┘

Les deux sont valides et independants !
```

**Copy (types simples) :**

```
let x: i32 = 5;
let y = x;  // COPY, pas move !

Stack:
┌──────────┐
│ x: 5     │  <- Toujours valide
└──────────┘
┌──────────┐
│ y: 5     │  <- Copie independante
└──────────┘

i32 implemente Copy : pas d'allocation heap, copie bit-a-bit.
```

**Drop order (LIFO) :**

```
{
    let a = Resource::new("A");  // Cree en premier
    let b = Resource::new("B");  // Cree en deuxieme

    // A la fin du bloc:
    // 1. b.drop() est appele  (dernier cree = premier drop)
    // 2. a.drop() est appele  (premier cree = dernier drop)
}

Timeline:
CREATE a ──┬── CREATE b ──┬── DROP b ──┬── DROP a
           │              │            │
           │              │            └── LIFO !
           │              │
           └──────────────┘
```

---

### 5.4 Les pieges en detail

#### Piege 1 : Use after move

```rust
let s1 = String::from("hello");
let s2 = s1;  // s1 est moved

println!("{}", s1);  // ERROR: borrow of moved value
```

#### Piege 2 : Move dans une fonction

```rust
fn take(s: String) { }

let s = String::from("hello");
take(s);
println!("{}", s);  // ERROR: s a ete moved dans take()
```

#### Piege 3 : Clone oublie dans une boucle

```rust
let v = vec!["a".to_string(), "b".to_string()];

for s in v {  // v est consume !
    println!("{}", s);
}

println!("{:?}", v);  // ERROR: v a ete moved
```

#### Piege 4 : Copy vs Clone confusion

```rust
// Copy : copie implicite, automatique
let x: i32 = 5;
let y = x;  // Copy

// Clone : copie explicite, manuelle
let s1 = String::from("hello");
let s2 = s1.clone();  // Clone
```

---

### 5.5 Cours Complet

#### 5.5.1 Regles d'ownership

1. Chaque valeur a un **proprietaire** unique
2. Il ne peut y avoir qu'**un seul proprietaire** a la fois
3. Quand le proprietaire sort du scope, la valeur est **droppee**

#### 5.5.2 Move

```rust
// Les types sans Copy sont moved par defaut
let s1 = String::from("hello");
let s2 = s1;  // Move : s1 -> s2

// s1 n'est plus valide
// s2 possede maintenant les donnees
```

#### 5.5.3 Clone

```rust
// Clone cree une copie profonde
let s1 = String::from("hello");
let s2 = s1.clone();  // Clone explicite

// s1 et s2 sont tous deux valides
// Chacun possede ses propres donnees
```

#### 5.5.4 Copy

```rust
// Types implementant Copy :
// - Scalaires : i32, f64, bool, char, etc.
// - Tuples de types Copy : (i32, i32)
// - Arrays de types Copy : [i32; 5]

let x: i32 = 5;
let y = x;  // Copy implicite, x toujours valide

// String n'implemente PAS Copy (allocation heap)
```

#### 5.5.5 Drop

```rust
// Drop est appele automatiquement a la fin du scope
{
    let s = String::from("hello");
    // ... utilisation de s ...
}  // s.drop() appele ici, memoire liberee

// On peut aussi appeler drop manuellement
let s = String::from("hello");
drop(s);  // s est drop maintenant
// s n'est plus utilisable
```

#### 5.5.6 Implementer Drop

```rust
struct MyResource {
    data: String,
}

impl Drop for MyResource {
    fn drop(&mut self) {
        println!("Releasing: {}", self.data);
    }
}

// Utilisation
{
    let r = MyResource { data: "test".to_string() };
}  // "Releasing: test" est affiche
```

---

### 5.6 Normes avec explications pedagogiques

```
┌─────────────────────────────────────────────────────────────────┐
│ HORS NORME                                                      │
├─────────────────────────────────────────────────────────────────┤
│ pub fn clone_and_modify(s: String) -> (String, String) {        │
│     (s.clone(), s + " world") }                                 │
├─────────────────────────────────────────────────────────────────┤
│ CONFORME                                                        │
├─────────────────────────────────────────────────────────────────┤
│ pub fn clone_and_modify(s: String) -> (String, String) {        │
│     let cloned = s.clone();                                    │
│     let modified = cloned + " world";                          │
│     (s, modified)                                              │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ POURQUOI ?                                                      │
│ - Clarte : operations separees sur des lignes distinctes       │
│ - Intention : le clone est explicitement nomme                 │
│ - Debug : points d'arret possibles                             │
└─────────────────────────────────────────────────────────────────┘
```

---

### 5.7 Simulation avec trace d'execution

```
clone_and_modify("hello".to_string()):
┌───────┬──────────────────────────────────────────────────────────┐
│ Etape │ Operation                                                │
├───────┼──────────────────────────────────────────────────────────┤
│   1   │ s = "hello" (ownership transfere a la fonction)         │
│   2   │ cloned = s.clone() (nouvelle String sur le heap)        │
│   3   │ modified = cloned + " world" (cloned est consume)       │
│   4   │ Retourne (s, modified) (ownership transfere au caller)  │
│   5   │ Rien n'est drop (tout est retourne)                     │
└───────┴──────────────────────────────────────────────────────────┘

Memoire a l'etape 2:
Heap: ["hello"] (s)  ["hello"] (cloned)

Memoire a l'etape 3:
Heap: ["hello"] (s)  ["hello world"] (modified)
      cloned a ete consume par +
```

---

### 5.8 Mnemotechniques

**MOVE = Memory Ownership Voluntarily Exits**

Quand tu passes une valeur, la memoire quitte volontairement son proprietaire actuel.

**CLONE = Copy Leaving Original Not Erased**

Clone fait une copie, l'original n'est pas efface.

**DROP = Deallocate Resources On exit from Program scope**

Drop libere les ressources quand on sort du scope.

---

### 5.9 Applications pratiques

| Scenario | Technique |
|----------|-----------|
| **Passer une config** | Move si plus besoin, Clone si reutilisation |
| **Retourner des donnees** | Move (retour transfere l'ownership) |
| **Ressources systeme** | Impl Drop pour liberation automatique |
| **Types simples** | Copy automatique, pas de souci |

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Use after move | Erreur compilation | Clone ou reference |
| 2 | Move dans boucle | Collection consumed | Iterer par reference |
| 3 | Oubli de Clone | Move inattendu | Clone explicite |
| 4 | Confusion Copy/Clone | Comportement different | Comprendre les traits |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Que se passe-t-il quand on assigne une String a une autre variable ?

- A) Les deux variables pointent vers les memes donnees
- B) La String est copiee
- C) L'ownership est transfere (move)
- D) Une erreur de compilation

**Reponse : C** — String n'implemente pas Copy, donc c'est un move.

---

### Question 2 (3 points)
Quels types implementent Copy ?

- A) String
- B) Vec<T>
- C) i32
- D) Box<T>

**Reponse : C** — Seuls les types scalaires et leurs compositions implementent Copy.

---

### Question 3 (4 points)
Quand est appele Drop::drop() ?

- A) Manuellement seulement
- B) A la fin du scope
- C) Quand on appelle free()
- D) Au demarrage du programme

**Reponse : B** — Drop est appele automatiquement quand la variable sort du scope.

---

### Question 4 (5 points)
Pourquoi Clone n'est pas automatique comme Copy ?

- A) Clone est plus lent
- B) Clone peut echouer
- C) Clone necessite une allocation et peut etre couteux
- D) Clone est deprecie

**Reponse : C** — Clone fait une copie profonde, potentiellement couteuse.

---

### Question 5 (5 points)
Dans quel ordre sont droppes deux variables creees dans le meme scope ?

- A) FIFO (premier cree, premier drop)
- B) LIFO (dernier cree, premier drop)
- C) Aleatoire
- D) Alphabetique

**Reponse : B** — LIFO, comme une pile (stack unwinding).

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.4 |
| **Nom** | ownership_basics |
| **Difficulte** | 3/10 |
| **Duree** | 40 min |
| **XP Base** | 80 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | ownership, move, clone, copy, drop |
| **Prerequis** | compounds |
| **Domaines** | Ownership, Memory |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.4-ownership_basics",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.4",
      "exercise_name": "ownership_basics",
      "module": "0.7",
      "module_name": "Introduction a Rust",
      "concept": "e",
      "concept_name": "Ownership",
      "type": "code",
      "tier": 1,
      "difficulty": 3,
      "difficulty_stars": "3/10",
      "languages": ["rust"],
      "duration_minutes": 40,
      "xp_base": 80,
      "prerequisites": ["0.7.3"],
      "domains": ["Ownership", "Memory"],
      "tags": ["ownership", "move", "clone", "copy", "drop"]
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
