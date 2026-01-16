# Exercice 0.8.24 : lifetimes

**Module :**
0.8 — Rust Intermediate

**Concept :**
a-c — Lifetime annotations 'a, struct lifetimes, function lifetimes

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
3 — Concept avance

**Langage :**
Rust Edition 2024

**Prerequis :**
0.8.19-23 (generics, traits), references, borrowing

**Domaines :**
Memory Safety, Borrow Checker, Type System

**Duree estimee :**
180 min

**XP Base :**
350

**Complexite :**
T1 O(1) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichier a rendre :** `lifetimes.rs`

**Fonctions autorisees :**
- Standard library

**Fonctions interdites :**
- unsafe code

### 1.2 Consigne

**Le Gardien de la Memoire: Comprendre les Lifetimes**

Les lifetimes sont le systeme de Rust pour garantir que les references restent valides. Tu vas apprendre a les annoter explicitement.

**Ta mission :**

Implementer les structures et fonctions suivantes avec les annotations de lifetime correctes:

```rust
// Structure contenant une reference
struct TextRef<'a> {
    content: &'a str,
}

// Structure avec plusieurs lifetimes
struct Excerpt<'a, 'b> {
    title: &'a str,
    body: &'b str,
}

// Structure avec reference mutable
struct MutableRef<'a> {
    value: &'a mut i32,
}
```

**Fonctions a implementer:**

```rust
// Retourne la plus longue des deux strings
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str;

// Retourne la premiere partie avant le delimiteur
fn first_word<'a>(s: &'a str) -> &'a str;

// Retourne le premier et le dernier element
fn first_and_last<'a, T>(slice: &'a [T]) -> Option<(&'a T, &'a T)>;

// Methodes sur TextRef
impl<'a> TextRef<'a> {
    fn new(content: &'a str) -> Self;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool;
    fn first_char(&self) -> Option<char>;
}

// Methodes sur Excerpt
impl<'a, 'b> Excerpt<'a, 'b> {
    fn new(title: &'a str, body: &'b str) -> Self;
    fn summary(&self) -> String;
}

// Methodes sur MutableRef
impl<'a> MutableRef<'a> {
    fn new(value: &'a mut i32) -> Self;
    fn increment(&mut self);
    fn get(&self) -> i32;
}
```

**Sortie attendue du main:**

```
=== Lifetimes Demo ===
longest("hello", "world!") = "world!"
first_word("hello world") = "hello"
first_and_last([1,2,3,4,5]) = Some((1, 5))

TextRef:
Content: "Hello, Rust!"
Length: 12
First char: 'H'

Excerpt:
Title: "Rust Programming"
Body: "Rust is a systems programming language..."
Summary: Rust Programming: Rust is a systems p...

MutableRef:
Initial value: 10
After increment: 11
```

### 1.3 Prototype

```rust
struct TextRef<'a> { content: &'a str }
struct Excerpt<'a, 'b> { title: &'a str, body: &'b str }
struct MutableRef<'a> { value: &'a mut i32 }

fn longest<'a>(x: &'a str, y: &'a str) -> &'a str;
fn first_word<'a>(s: &'a str) -> &'a str;
fn first_and_last<'a, T>(slice: &'a [T]) -> Option<(&'a T, &'a T)>;

fn main();
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Pourquoi les Lifetimes?

Rust garantit a la compilation que:
1. Aucune reference ne survit a son referent
2. Aucune reference mutable n'existe pendant qu'une autre reference existe

Les lifetimes sont la facon dont le compilateur suit ces regles.

### 2.2 'static Lifetime

`'static` est une lifetime speciale signifiant "vit pour toute la duree du programme":
```rust
let s: &'static str = "Je suis dans le binaire";
```

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Systems Programmer**

Les lifetimes sont cruciales pour:
- Parsers zero-copy
- Structures self-referentielles (avec des crates speciales)
- APIs de bas niveau sans allocation

**Metier : Library Author**

Les annotations de lifetime permettent:
- APIs expressives et sures
- Documentation des invariants
- Optimisations sans unsafe

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ rustc --edition 2024 lifetimes.rs
$ ./lifetimes
=== Lifetimes Demo ===
longest("hello", "world!") = "world!"
[...]
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★☆☆☆☆ (6/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Implementer une structure `Parser` qui garde une reference au texte source:

```rust
struct Parser<'source> {
    source: &'source str,
    position: usize,
}

impl<'source> Parser<'source> {
    fn new(source: &'source str) -> Self;
    fn peek(&self) -> Option<char>;
    fn advance(&mut self) -> Option<char>;
    fn slice(&self, start: usize, end: usize) -> &'source str;
    fn remaining(&self) -> &'source str;
}
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Expected | Points |
|---------|-------------|----------|--------|
| T01 | Compilation sans warning | Success | 10 |
| T02 | longest fonctionne | Plus longue string | 15 |
| T03 | first_word fonctionne | Premier mot | 15 |
| T04 | first_and_last fonctionne | Tuple correct | 15 |
| T05 | TextRef methodes | Toutes fonctionnent | 15 |
| T06 | Excerpt summary | Format correct | 15 |
| T07 | MutableRef increment | Valeur modifiee | 15 |

### 4.2 Tests unitaires

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_longest() {
        assert_eq!(longest("short", "longer"), "longer");
        assert_eq!(longest("hello", "world"), "hello"); // same length, first returned
    }

    #[test]
    fn test_first_word() {
        assert_eq!(first_word("hello world"), "hello");
        assert_eq!(first_word("single"), "single");
        assert_eq!(first_word(""), "");
    }

    #[test]
    fn test_first_and_last() {
        assert_eq!(first_and_last(&[1, 2, 3, 4, 5]), Some((&1, &5)));
        assert_eq!(first_and_last(&[42]), Some((&42, &42)));
        assert_eq!(first_and_last::<i32>(&[]), None);
    }

    #[test]
    fn test_text_ref() {
        let text = "Hello, Rust!";
        let tr = TextRef::new(text);
        assert_eq!(tr.len(), 12);
        assert!(!tr.is_empty());
        assert_eq!(tr.first_char(), Some('H'));
    }

    #[test]
    fn test_text_ref_empty() {
        let tr = TextRef::new("");
        assert!(tr.is_empty());
        assert_eq!(tr.first_char(), None);
    }

    #[test]
    fn test_excerpt() {
        let title = "Rust Programming";
        let body = "Rust is great";
        let exc = Excerpt::new(title, body);
        let summary = exc.summary();
        assert!(summary.contains("Rust Programming"));
    }

    #[test]
    fn test_mutable_ref() {
        let mut value = 10;
        let mut mr = MutableRef::new(&mut value);
        assert_eq!(mr.get(), 10);
        mr.increment();
        assert_eq!(mr.get(), 11);
    }

    #[test]
    fn test_lifetime_scope() {
        let result;
        {
            let s1 = String::from("long string");
            let s2 = String::from("short");
            result = longest(&s1, &s2);
            assert_eq!(result, "long string");
        }
        // result cannot be used here if s1/s2 were dropped
    }
}
```

### 4.3 Solution de reference

```rust
/*
 * lifetimes.rs
 * Lifetime annotations demonstration
 * Exercice ex24_lifetimes
 */

/// Structure holding a string reference
struct TextRef<'a> {
    content: &'a str,
}

/// Structure with two different lifetimes
struct Excerpt<'a, 'b> {
    title: &'a str,
    body: &'b str,
}

/// Structure with mutable reference
struct MutableRef<'a> {
    value: &'a mut i32,
}

// ============ Free Functions ============

/// Returns the longer of two string slices
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    if x.len() >= y.len() {
        x
    } else {
        y
    }
}

/// Returns the first word in a string
fn first_word<'a>(s: &'a str) -> &'a str {
    let bytes = s.as_bytes();

    for (i, &byte) in bytes.iter().enumerate() {
        if byte == b' ' {
            return &s[0..i];
        }
    }

    s // Whole string is one word
}

/// Returns first and last elements of a slice
fn first_and_last<'a, T>(slice: &'a [T]) -> Option<(&'a T, &'a T)> {
    if slice.is_empty() {
        None
    } else {
        Some((&slice[0], &slice[slice.len() - 1]))
    }
}

// ============ TextRef Implementation ============

impl<'a> TextRef<'a> {
    fn new(content: &'a str) -> Self {
        TextRef { content }
    }

    fn len(&self) -> usize {
        self.content.len()
    }

    fn is_empty(&self) -> bool {
        self.content.is_empty()
    }

    fn first_char(&self) -> Option<char> {
        self.content.chars().next()
    }
}

// ============ Excerpt Implementation ============

impl<'a, 'b> Excerpt<'a, 'b> {
    fn new(title: &'a str, body: &'b str) -> Self {
        Excerpt { title, body }
    }

    fn summary(&self) -> String {
        let body_preview: String = self.body.chars().take(20).collect();
        format!("{}: {}...", self.title, body_preview)
    }
}

// ============ MutableRef Implementation ============

impl<'a> MutableRef<'a> {
    fn new(value: &'a mut i32) -> Self {
        MutableRef { value }
    }

    fn increment(&mut self) {
        *self.value += 1;
    }

    fn get(&self) -> i32 {
        *self.value
    }
}

fn main() {
    println!("=== Lifetimes Demo ===");

    // longest
    let s1 = "hello";
    let s2 = "world!";
    println!("longest(\"{}\", \"{}\") = \"{}\"", s1, s2, longest(s1, s2));

    // first_word
    let sentence = "hello world";
    println!("first_word(\"{}\") = \"{}\"", sentence, first_word(sentence));

    // first_and_last
    let numbers = [1, 2, 3, 4, 5];
    println!(
        "first_and_last({:?}) = {:?}",
        numbers,
        first_and_last(&numbers)
    );

    // TextRef
    println!("\nTextRef:");
    let text = "Hello, Rust!";
    let tr = TextRef::new(text);
    println!("Content: \"{}\"", tr.content);
    println!("Length: {}", tr.len());
    println!("First char: {:?}", tr.first_char());

    // Excerpt
    println!("\nExcerpt:");
    let title = "Rust Programming";
    let body = "Rust is a systems programming language focused on safety and performance.";
    let exc = Excerpt::new(title, body);
    println!("Title: \"{}\"", exc.title);
    println!("Body: \"{}\"", exc.body);
    println!("Summary: {}", exc.summary());

    // MutableRef
    println!("\nMutableRef:");
    let mut value = 10;
    {
        let mut mr = MutableRef::new(&mut value);
        println!("Initial value: {}", mr.get());
        mr.increment();
        println!("After increment: {}", mr.get());
    }
}
```

### 4.4 Solutions alternatives acceptees

```rust
// Alternative 1: first_word avec split
fn first_word<'a>(s: &'a str) -> &'a str {
    s.split_whitespace().next().unwrap_or("")
}

// Alternative 2: longest avec match
fn longest<'a>(x: &'a str, y: &'a str) -> &'a str {
    match x.len().cmp(&y.len()) {
        std::cmp::Ordering::Less => y,
        _ => x,
    }
}

// Alternative 3: first_and_last avec split_first/last
fn first_and_last<'a, T>(slice: &'a [T]) -> Option<(&'a T, &'a T)> {
    let first = slice.first()?;
    let last = slice.last()?;
    Some((first, last))
}
```

### 4.10 Solutions Mutantes (minimum 5)

```rust
// MUTANT 1 (Lifetime): Lifetime manquant sur le retour
fn longest(x: &str, y: &str) -> &str {  // ERREUR: missing lifetime
    if x.len() >= y.len() { x } else { y }
}
// Detection: Erreur de compilation E0106

// MUTANT 2 (Lifetime): Lifetimes differentes mais meme retour
fn longest<'a, 'b>(x: &'a str, y: &'b str) -> &'a str {
    if x.len() >= y.len() { x } else { y }  // ERREUR: y a lifetime 'b
}
// Detection: Erreur de compilation - lifetime mismatch

// MUTANT 3 (Logic): first_word retourne tout
fn first_word<'a>(s: &'a str) -> &'a str {
    s  // Ne cherche pas l'espace!
}
// Detection: first_word("hello world") retourne "hello world"

// MUTANT 4 (Boundary): first_and_last panic sur vide
fn first_and_last<'a, T>(slice: &'a [T]) -> Option<(&'a T, &'a T)> {
    Some((&slice[0], &slice[slice.len() - 1]))  // PANIC si vide!
}
// Detection: first_and_last(&[]) panic

// MUTANT 5 (Logic): MutableRef::increment n'incremente pas
impl<'a> MutableRef<'a> {
    fn increment(&mut self) {
        // Oublie d'incrementer!
    }
}
// Detection: get() retourne la meme valeur apres increment
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

1. **Lifetime annotations** `'a` - Nommer les durees de vie des references
2. **Struct lifetimes** - References dans les structures
3. **Function lifetimes** - Relations entre parametres et retours
4. **Multiple lifetimes** - Quand utiliser `'a, 'b`

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION longest<'a>(x: &'a str, y: &'a str) -> &'a str
    -- x et y vivent au moins aussi longtemps que 'a
    -- Le retour vit aussi longtemps que 'a
DEBUT
    SI longueur(x) >= longueur(y) ALORS
        RETOURNER x
    SINON
        RETOURNER y
    FIN SI
FIN

STRUCTURE TextRef<'a>
    -- Le contenu est emprunte pour la duree 'a
    content: &'a str
FIN STRUCTURE
```

### 5.3 Visualisation ASCII

```
Lifetime 'a:
|---------------------------------------|
                                        |
+----------+                            |
| String s |                            |
+----------+                            |
    |                                   |
    v                                   |
+------------+                          |
| &s (ref)   | valid while s exists     |
+------------+                          |
    |                                   v
    +-----------------------------------> lifetime 'a ends here


Multiple Lifetimes:

'a: |------------------------|
'b:     |--------------------------------|

struct Excerpt<'a, 'b> {
    title: &'a str,    // lives for 'a
    body: &'b str,     // lives for 'b (possibly longer)
}
```

### 5.4 Les pieges en detail

#### Piege 1: Dangling Reference

```rust
// ERREUR: retourne reference a donnee locale
fn bad() -> &str {
    let s = String::from("hello");
    &s  // s est detruit ici!
}

// CORRECT: retourner String ou 'static
fn good() -> &'static str {
    "hello"  // Literal vit toujours
}
```

#### Piege 2: Lifetime Mismatch

```rust
// ERREUR: y pourrait vivre moins longtemps que 'a
fn bad<'a, 'b>(x: &'a str, y: &'b str) -> &'a str {
    if true { x } else { y }  // Erreur!
}

// CORRECT: meme lifetime
fn good<'a>(x: &'a str, y: &'a str) -> &'a str {
    if true { x } else { y }
}
```

#### Piege 3: Struct sans lifetime

```rust
// ERREUR: reference sans lifetime
struct Bad {
    content: &str,  // Erreur: missing lifetime specifier
}

// CORRECT
struct Good<'a> {
    content: &'a str,
}
```

### 5.5 Cours Complet

#### 5.5.1 Syntaxe des Lifetimes

```rust
// Annotation de lifetime
'a  // Une lifetime nommee 'a

// Sur une reference
&'a T      // Reference immutable
&'a mut T  // Reference mutable

// Sur une structure
struct Foo<'a> {
    field: &'a str,
}

// Sur une fonction
fn foo<'a>(x: &'a str) -> &'a str { x }
```

#### 5.5.2 Regles des Lifetimes

1. **Input lifetimes**: Lifetimes sur les parametres
2. **Output lifetimes**: Lifetimes sur le retour
3. **La lifetime du retour doit correspondre a un input**

```rust
// Valide: retour lie a un input
fn valid<'a>(x: &'a str, y: &str) -> &'a str { x }

// Invalide: retour sans lien avec input
fn invalid<'a>(x: &str) -> &'a str {
    let s = String::new();
    &s  // Erreur!
}
```

#### 5.5.3 Lifetimes Multiples

```rust
// Meme lifetime: les deux references vivent aussi longtemps
fn same<'a>(x: &'a str, y: &'a str) -> &'a str

// Lifetimes differentes: independantes
struct Different<'a, 'b> {
    first: &'a str,   // Peut vivre plus longtemps que second
    second: &'b str,
}
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication |
|-------|-------------|
| `'a, 'b, 'c` | Noms conventionnels |
| `'_` | Lifetime anonyme |
| `'static` | Vit tout le programme |
| Lifetime sur impl | `impl<'a> Foo<'a>` |

### 5.7 Simulation avec trace d'execution

```
Code:
let s1 = String::from("long");
let result;
{
    let s2 = String::from("xy");
    result = longest(&s1, &s2);
}
println!("{}", result);  // ERREUR!

Timeline:
1. s1 cree (lifetime 'a commence)
2. result declare (pas initialise)
3. Bloc interne:
   - s2 cree (lifetime 'b commence)
   - longest(&s1, &s2) -> 'a et 'b unifies en min('a, 'b) = 'b
   - result = reference avec lifetime 'b
4. Fin du bloc:
   - s2 detruit ('b termine)
   - result pointe vers memoire invalide!
5. println! utiliserait result -> ERREUR detectee a la compilation
```

### 5.8 Mnemotechniques

**"'a = Annotation de duree de vie"**
- Pas une valeur, une annotation

**"Le retour vit aussi longtemps que le plus court des inputs"**
- Unification des lifetimes

**"Pas de reference sans source"**
- Toute reference doit pointer vers quelque chose de valide

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Missing lifetime | E0106 | Ajouter `<'a>` |
| Dangling reference | E0515 | Retourner owned ou 'static |
| Lifetime mismatch | E0623 | Unifier les lifetimes |
| Reference outlives data | E0597 | Reorganiser le code |

---

## SECTION 7 : QCM

### Question 1
Que signifie `'a` dans `fn foo<'a>(x: &'a str) -> &'a str`?

A) Un type generique
B) Un parametre de lifetime
C) Un alias de type
D) Une variable
E) Une constante

**Reponse correcte: B**

### Question 2
Pourquoi cette fonction ne compile pas?
```rust
fn bad() -> &str {
    let s = String::from("hello");
    &s
}
```

A) Syntaxe incorrecte
B) s est detruit avant que la reference soit retournee
C) String n'implemente pas Deref
D) Il manque un return
E) &str n'est pas un type valide

**Reponse correcte: B**

### Question 3
Quand utiliser plusieurs lifetimes `<'a, 'b>`?

A) Jamais
B) Quand les references sont independantes
C) Pour la performance
D) C'est obligatoire
E) Pour le debugging

**Reponse correcte: B**

### Question 4
Que signifie `'static`?

A) Une variable statique
B) Une reference qui vit pour toute la duree du programme
C) Un type immutable
D) Une constante
E) Un singleton

**Reponse correcte: B**

### Question 5
Dans `struct Foo<'a> { x: &'a str }`, que garantit `'a`?

A) x est immutable
B) x ne sera jamais null
C) x reste valide tant que Foo existe
D) x est copie
E) x est sur le heap

**Reponse correcte: C**

---

## SECTION 8 : RECAPITULATIF

| Concept | Description | Exemple |
|---------|-------------|---------|
| `'a` | Parametre de lifetime | `<'a>` |
| `&'a T` | Reference avec lifetime | `&'a str` |
| `'static` | Vit toujours | `&'static str` |
| Multiple lifetimes | Independence | `<'a, 'b>` |
| Struct lifetime | Reference dans struct | `struct F<'a>` |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.8.24",
  "name": "lifetimes",
  "version": "1.0.0",
  "language": "rust",
  "language_version": "edition2024",
  "files": {
    "submission": ["lifetimes.rs"],
    "test": ["test_lifetimes.rs"]
  },
  "compilation": {
    "compiler": "rustc",
    "flags": ["--edition", "2024", "-W", "warnings"],
    "output": "lifetimes"
  },
  "tests": {
    "unit_tests": true,
    "output_match": true
  },
  "scoring": {
    "total": 100,
    "compilation": 10,
    "tests": 90
  },
  "concepts": ["lifetime_annotations", "struct_lifetimes", "function_lifetimes", "borrow_checker"]
}
```
