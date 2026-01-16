# Exercice 0.7.0 : cargo_init

**Module :**
0.7 — Introduction a Rust

**Concept :**
a — Installation et premier projet Cargo

**Difficulte :**
★★☆☆☆☆☆☆☆☆ (2/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024

**Prerequis :**
- Terminal de commande basique
- Notion de compilation

**Domaines :**
Tooling, Config

**Duree estimee :**
30 min

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
| Rust | `Cargo.toml`, `src/lib.rs` |

**Fonctions autorisees :**

| Langage | Fonctions |
|---------|-----------|
| Rust | Toutes les fonctions de la bibliotheque standard |

**Fonctions interdites :**

| Langage | Fonctions |
|---------|-----------|
| Rust | Aucune restriction |

---

### 1.2 Consigne

#### Section Culture : "Hello, Cargo!"

Le nom "Cargo" vient du fait qu'il "transporte" toutes les dependances de ton projet, comme un cargo maritime transporte des conteneurs. C'est le gestionnaire de paquets et l'outil de build officiel de Rust, inspire de npm (Node.js) et bundler (Ruby).

Rust a ete cree chez Mozilla en 2010 par Graydon Hoare. Le langage tire son nom d'un champignon (la rouille) qui est connu pour sa robustesse et sa capacite a survivre dans des conditions difficiles.

---

#### Section Academique : Enonce Formel

**Ta mission :**

1. Installer Rust via rustup (si pas deja fait)
2. Creer un nouveau projet bibliotheque avec `cargo new`
3. Ecrire une fonction `greet` qui retourne un message de bienvenue
4. Ecrire des tests unitaires
5. Verifier le code avec clippy et rustfmt

**Entree :**

```rust
// src/lib.rs

/// Retourne un message de bienvenue personnalise.
///
/// # Arguments
///
/// * `name` - Le nom de la personne a saluer
///
/// # Returns
///
/// Un String contenant le message de bienvenue
///
/// # Example
///
/// ```
/// let msg = cargo_init::greet("Alice");
/// assert_eq!(msg, "Hello, Alice! Welcome to Rust.");
/// ```
pub fn greet(name: &str) -> String {
    // A implementer
}

/// Retourne le numero de version de la bibliotheque.
pub fn version() -> &'static str {
    // A implementer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_greet_basic() {
        // A implementer
    }

    #[test]
    fn test_greet_empty_name() {
        // A implementer
    }

    #[test]
    fn test_version() {
        // A implementer
    }
}
```

**Sortie attendue :**

```
$ cargo test
running 3 tests
test tests::test_greet_basic ... ok
test tests::test_greet_empty_name ... ok
test tests::test_version ... ok

test result: ok. 3 passed; 0 failed

$ cargo clippy
$ cargo fmt --check
```

**Contraintes :**
- Le projet doit compiler sans warnings (`cargo build`)
- clippy ne doit signaler aucun probleme (`cargo clippy`)
- Le code doit etre formate selon rustfmt (`cargo fmt --check`)
- La documentation doit etre valide (`cargo doc`)

**Exemples :**

| Appel | Resultat |
|-------|----------|
| `greet("World")` | `"Hello, World! Welcome to Rust."` |
| `greet("")` | `"Hello, ! Welcome to Rust."` |
| `greet("42")` | `"Hello, 42! Welcome to Rust."` |
| `version()` | `"0.1.0"` |

---

### 1.3 Prototype

```rust
pub fn greet(name: &str) -> String;
pub fn version() -> &'static str;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Fun Facts

**Pourquoi rustup et pas un installeur classique ?**

rustup permet d'installer plusieurs versions de Rust en parallele (stable, beta, nightly) et de changer facilement entre elles. C'est essentiel car certaines fonctionnalites experimentales ne sont disponibles que sur nightly.

**Cargo.toml vs Cargo.lock**

- `Cargo.toml` : ce que tu veux (dependances declarees)
- `Cargo.lock` : ce que tu as (versions exactes installees)

Pour une bibliotheque, on ne commit pas `Cargo.lock`. Pour une application, on le commit.

**Les editions Rust**

Rust a des "editions" (2015, 2018, 2021, 2024) qui permettent d'introduire des changements incompatibles sans casser l'ancien code. Chaque crate declare son edition dans `Cargo.toml`.

---

### 2.5 DANS LA VRAIE VIE

| Metier | Utilisation du concept |
|--------|----------------------|
| **DevOps** | Configuration de CI/CD avec cargo test, clippy, fmt |
| **Open Source Maintainer** | Publication de crates sur crates.io |
| **Systems Programmer** | Gestion de dependances natives (build.rs) |
| **Backend Developer** | Workspace multi-crates pour microservices |

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ rustup --version
rustup 1.27.0

$ rustc --version
rustc 1.82.0

$ cargo --version
cargo 1.82.0

$ cargo new cargo_init --lib
     Created library `cargo_init` package

$ cd cargo_init
$ ls -la
total 16
drwxr-xr-x  4 user user 4096 Jan 16 10:00 .
drwxr-xr-x 10 user user 4096 Jan 16 10:00 ..
-rw-r--r--  1 user user  178 Jan 16 10:00 Cargo.toml
drwxr-xr-x  2 user user 4096 Jan 16 10:00 src

$ cat Cargo.toml
[package]
name = "cargo_init"
version = "0.1.0"
edition = "2024"

[dependencies]

$ cargo build
   Compiling cargo_init v0.1.0
    Finished dev [unoptimized + debuginfo] target(s)

$ cargo test
running 3 tests
test tests::test_greet_basic ... ok
test tests::test_greet_empty_name ... ok
test tests::test_version ... ok

test result: ok. 3 passed; 0 failed

$ cargo clippy
    Checking cargo_init v0.1.0
    Finished dev [unoptimized + debuginfo] target(s)

$ cargo fmt --check
$ echo $?
0

$ cargo doc --open
   Documenting cargo_init v0.1.0
    Finished dev [unoptimized + debuginfo] target(s)
     Opening docs/cargo_init/index.html
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| # | Test | Input | Expected | Points | Categorie |
|---|------|-------|----------|--------|-----------|
| 1 | cargo_build | `cargo build` | exit 0 | 10 | Build |
| 2 | cargo_test | `cargo test` | all pass | 20 | Tests |
| 3 | greet_basic | `greet("World")` | `"Hello, World! Welcome to Rust."` | 10 | Basic |
| 4 | greet_empty | `greet("")` | `"Hello, ! Welcome to Rust."` | 10 | Edge |
| 5 | greet_special | `greet("@#$")` | `"Hello, @#$! Welcome to Rust."` | 5 | Edge |
| 6 | version_check | `version()` | `"0.1.0"` | 10 | Basic |
| 7 | clippy_clean | `cargo clippy` | no warnings | 15 | Lint |
| 8 | fmt_check | `cargo fmt --check` | exit 0 | 10 | Format |
| 9 | doc_build | `cargo doc` | exit 0 | 10 | Doc |

**Total : 100 points**

---

### 4.2 Tests de la moulinette

```rust
#[cfg(test)]
mod moulinette_tests {
    use super::*;

    #[test]
    fn test_greet_basic() {
        assert_eq!(greet("World"), "Hello, World! Welcome to Rust.");
    }

    #[test]
    fn test_greet_with_name() {
        assert_eq!(greet("Alice"), "Hello, Alice! Welcome to Rust.");
    }

    #[test]
    fn test_greet_empty_name() {
        assert_eq!(greet(""), "Hello, ! Welcome to Rust.");
    }

    #[test]
    fn test_greet_special_chars() {
        assert_eq!(greet("@#$"), "Hello, @#$! Welcome to Rust.");
    }

    #[test]
    fn test_greet_unicode() {
        assert_eq!(greet("monde"), "Hello, monde! Welcome to Rust.");
    }

    #[test]
    fn test_version() {
        assert_eq!(version(), "0.1.0");
    }

    #[test]
    fn test_version_not_empty() {
        assert!(!version().is_empty());
    }
}
```

---

### 4.3 Solution de reference (Rust)

```rust
//! Bibliotheque d'introduction a Rust et Cargo.
//!
//! Cette crate fournit des fonctions basiques pour se familiariser
//! avec l'ecosysteme Rust.

/// Retourne un message de bienvenue personnalise.
///
/// # Arguments
///
/// * `name` - Le nom de la personne a saluer
///
/// # Returns
///
/// Un String contenant le message de bienvenue
///
/// # Example
///
/// ```
/// let msg = cargo_init::greet("Alice");
/// assert_eq!(msg, "Hello, Alice! Welcome to Rust.");
/// ```
pub fn greet(name: &str) -> String {
    format!("Hello, {}! Welcome to Rust.", name)
}

/// Retourne le numero de version de la bibliotheque.
///
/// # Example
///
/// ```
/// let v = cargo_init::version();
/// assert_eq!(v, "0.1.0");
/// ```
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_greet_basic() {
        let result = greet("World");
        assert_eq!(result, "Hello, World! Welcome to Rust.");
    }

    #[test]
    fn test_greet_empty_name() {
        let result = greet("");
        assert_eq!(result, "Hello, ! Welcome to Rust.");
    }

    #[test]
    fn test_version() {
        let v = version();
        assert_eq!(v, "0.1.0");
    }
}
```

**Cargo.toml de reference :**

```toml
[package]
name = "cargo_init"
version = "0.1.0"
edition = "2024"
authors = ["Student <student@school.edu>"]
description = "Introduction to Rust and Cargo"
license = "MIT"

[dependencies]

[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
all = "warn"
pedantic = "warn"
```

---

### 4.4 Solutions alternatives acceptees

**Alternative 1 : Version hardcodee**

```rust
pub fn version() -> &'static str {
    "0.1.0"
}
// Accepte mais moins maintenable que env!("CARGO_PKG_VERSION")
```

**Alternative 2 : Concatenation avec + au lieu de format!**

```rust
pub fn greet(name: &str) -> String {
    "Hello, ".to_string() + name + "! Welcome to Rust."
}
// Accepte mais moins idiomatique
```

---

### 4.5 Solutions refusees (avec explications)

**Refus 1 : Retourner &str au lieu de String**

```rust
// REFUSE : Lifetime issue
pub fn greet(name: &str) -> &str {
    &format!("Hello, {}! Welcome to Rust.", name)
    // format! cree un String temporaire qui est detruit
}
```
**Pourquoi refuse :** Le String cree par format! est temporaire et serait detruit avant le retour.

**Refus 2 : Pas de documentation**

```rust
// REFUSE : Pas de doc comments
pub fn greet(name: &str) -> String {
    format!("Hello, {}! Welcome to Rust.", name)
}
```
**Pourquoi refuse :** La documentation est requise pour cet exercice.

**Refus 3 : Panic sur chaine vide**

```rust
// REFUSE : Comportement inattendu
pub fn greet(name: &str) -> String {
    if name.is_empty() {
        panic!("Name cannot be empty");
    }
    format!("Hello, {}! Welcome to Rust.", name)
}
```
**Pourquoi refuse :** L'exercice demande de gerer les chaines vides, pas de paniquer.

---

### 4.9 spec.json (ENGINE v22.1)

```json
{
  "name": "cargo_init",
  "language": "rust",
  "language_version": "edition 2024",
  "type": "code",
  "tier": 1,
  "tier_info": "Concept isole",
  "tags": ["module0.7", "cargo", "tooling", "phase0"],
  "passing_score": 70,

  "function": {
    "name": "greet",
    "prototype": "pub fn greet(name: &str) -> String",
    "return_type": "String",
    "parameters": [
      {"name": "name", "type": "&str"}
    ]
  },

  "driver": {
    "reference": "pub fn greet(name: &str) -> String { format!(\"Hello, {}! Welcome to Rust.\", name) }",

    "edge_cases": [
      {
        "name": "empty_name",
        "args": [""],
        "expected": "Hello, ! Welcome to Rust.",
        "is_trap": true,
        "trap_explanation": "Chaine vide doit etre geree sans panic"
      },
      {
        "name": "special_chars",
        "args": ["<script>"],
        "expected": "Hello, <script>! Welcome to Rust.",
        "is_trap": false
      }
    ],

    "fuzzing": {
      "enabled": true,
      "iterations": 1000,
      "generators": [
        {
          "type": "string",
          "param_index": 0,
          "params": {"min_len": 0, "max_len": 100}
        }
      ]
    }
  },

  "norm": {
    "allowed_functions": ["format!", "env!"],
    "forbidden_functions": [],
    "check_security": false,
    "check_memory": false,
    "blocking": false
  }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

**Mutant A (Boundary) : Oubli du point final**

```rust
/* Mutant A (Boundary) : Message incomplet */
pub fn greet(name: &str) -> String {
    format!("Hello, {}! Welcome to Rust", name)  // Manque le point
}
// Pourquoi faux : Le format exact attendu inclut le point final
// Ce qui etait pense : "Le message est la"
```

**Mutant B (Logic) : Mauvais ordre des elements**

```rust
/* Mutant B (Logic) : Ordre inverse */
pub fn greet(name: &str) -> String {
    format!("Welcome to Rust. Hello, {}!", name)  // Ordre inverse
}
// Pourquoi faux : Le format attendu commence par "Hello"
// Ce qui etait pense : "Bienvenue d'abord, salutation ensuite"
```

**Mutant C (Type) : Retourne &str au lieu de String**

```rust
/* Mutant C (Type) : Mauvais type de retour */
pub fn greet(name: &str) -> &str {
    "Hello, World! Welcome to Rust."  // Ignore le parametre
}
// Pourquoi faux : Ne compile pas ou ignore le nom
// Ce qui etait pense : "Retourner une reference c'est pareil"
```

**Mutant D (Safety) : Panic sur vide**

```rust
/* Mutant D (Safety) : Panic inattendu */
pub fn greet(name: &str) -> String {
    assert!(!name.is_empty(), "name cannot be empty");
    format!("Hello, {}! Welcome to Rust.", name)
}
// Pourquoi faux : Panic sur chaine vide alors qu'on attend une reponse valide
// Ce qui etait pense : "Il faut valider les entrees"
```

**Mutant E (Return) : Version incorrecte**

```rust
/* Mutant E (Return) : Mauvaise version */
pub fn version() -> &'static str {
    "1.0.0"  // Mauvaise version
}
// Pourquoi faux : Cargo.toml declare 0.1.0, pas 1.0.0
// Ce qui etait pense : "1.0.0 c'est une version standard"
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

| Concept | Description | Importance |
|---------|-------------|------------|
| Cargo | Gestionnaire de paquets et build tool | Fondamental |
| Crate structure | Organisation d'un projet Rust | Fondamental |
| Tests unitaires | #[test] et cargo test | Fondamental |
| Documentation | /// et //! doc comments | Important |
| Linting | clippy pour la qualite du code | Important |
| Formatting | rustfmt pour le style | Important |

---

### 5.2 LDA — Traduction litterale en MAJUSCULES

```
FONCTION greet QUI PREND name COMME REFERENCE VERS CHAINE
DEBUT FONCTION
    CREER UNE NOUVELLE CHAINE EN FORMATANT "Hello, {name}! Welcome to Rust."
    RETOURNER CETTE CHAINE
FIN FONCTION

FONCTION version QUI RETOURNE UNE REFERENCE STATIQUE VERS CHAINE
DEBUT FONCTION
    RETOURNER LA VARIABLE D'ENVIRONNEMENT "CARGO_PKG_VERSION"
FIN FONCTION
```

---

### 5.2.2 Style Academique Francais

```
Algorithme : Salutation personnalisee

Donnees :
    name : chaine de caracteres (reference)

Resultat :
    message : chaine de caracteres (possedee)

Operation GREET(name):
    Precondition : name est une reference valide
    Postcondition : retourne une nouvelle chaine formatee

    Debut
        message <- concatener("Hello, ", name, "! Welcome to Rust.")
        Retourner message
    Fin

Complexite :
    Temps : O(n) ou n = longueur de name
    Espace : O(n) pour la nouvelle chaine
```

---

### 5.3 Visualisation ASCII

**Structure d'un projet Cargo :**

```
cargo_init/
├── Cargo.toml          <- Manifest du projet
├── Cargo.lock          <- Versions exactes (auto-genere)
├── src/
│   └── lib.rs          <- Code source principal
├── target/             <- Artefacts de compilation
│   ├── debug/          <- Build de developpement
│   └── release/        <- Build optimise
└── tests/              <- Tests d'integration (optionnel)
    └── integration.rs
```

**Anatomie de Cargo.toml :**

```
┌─────────────────────────────────────────────────────────────────┐
│ [package]                                                       │
│ name = "cargo_init"      <- Nom du crate                       │
│ version = "0.1.0"        <- Version semantique                 │
│ edition = "2024"         <- Edition Rust                       │
│                                                                 │
│ [dependencies]           <- Dependances externes               │
│ serde = "1.0"            <- Exemple de dependance             │
│                                                                 │
│ [dev-dependencies]       <- Dependances pour tests seulement   │
│ criterion = "0.5"        <- Exemple                            │
│                                                                 │
│ [lints.clippy]           <- Configuration clippy               │
│ all = "warn"                                                    │
└─────────────────────────────────────────────────────────────────┘
```

---

### 5.4 Les pieges en detail

#### Piege 1 : lib.rs vs main.rs

```
// lib.rs = bibliotheque (crate type = "lib")
// Peut etre importee par d'autres crates
pub fn greet(name: &str) -> String { ... }

// main.rs = executable (crate type = "bin")
// Point d'entree fn main()
fn main() {
    println!("{}", cargo_init::greet("World"));
}
```

#### Piege 2 : Oublier pub

```rust
// FAUX : fonction privee par defaut
fn greet(name: &str) -> String { ... }
// Ne peut pas etre appelee depuis l'exterieur du module

// CORRECT : fonction publique
pub fn greet(name: &str) -> String { ... }
```

#### Piege 3 : Edition non specifiee

```toml
# FAUX : utilise l'edition par defaut (2015)
[package]
name = "my_crate"
version = "0.1.0"

# CORRECT : edition explicite
[package]
name = "my_crate"
version = "0.1.0"
edition = "2024"
```

---

### 5.5 Cours Complet

#### 5.5.1 Installation de Rust

```bash
# Unix/macOS/WSL
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verifier l'installation
rustc --version
cargo --version
rustup --version
```

#### 5.5.2 Les commandes Cargo essentielles

| Commande | Description |
|----------|-------------|
| `cargo new <name>` | Creer un nouveau projet |
| `cargo build` | Compiler le projet |
| `cargo run` | Compiler et executer |
| `cargo test` | Executer les tests |
| `cargo doc` | Generer la documentation |
| `cargo clippy` | Linter le code |
| `cargo fmt` | Formater le code |
| `cargo check` | Verifier sans compiler |
| `cargo publish` | Publier sur crates.io |

#### 5.5.3 Les attributs de test

```rust
#[cfg(test)]        // Module compile seulement pour les tests
mod tests {
    use super::*;   // Importe tout du module parent

    #[test]         // Marque une fonction comme test
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    #[test]
    #[should_panic] // Le test reussit si la fonction panic
    fn it_panics() {
        panic!("This should panic");
    }

    #[test]
    #[ignore]       // Ignore ce test par defaut
    fn slow_test() {
        // cargo test -- --ignored pour l'executer
    }
}
```

---

### 5.6 Normes avec explications pedagogiques

```
┌─────────────────────────────────────────────────────────────────┐
│ HORS NORME (compile, mais interdit)                             │
├─────────────────────────────────────────────────────────────────┤
│ pub fn greet(n: &str) -> String { format!("Hello, {}!", n) }    │
├─────────────────────────────────────────────────────────────────┤
│ CONFORME                                                        │
├─────────────────────────────────────────────────────────────────┤
│ /// Retourne un message de bienvenue.                           │
│ ///                                                             │
│ /// # Arguments                                                 │
│ ///                                                             │
│ /// * `name` - Le nom de la personne                           │
│ pub fn greet(name: &str) -> String {                           │
│     format!("Hello, {}! Welcome to Rust.", name)               │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ POURQUOI ?                                                      │
│                                                                 │
│ - Documentation : Les doc comments sont essentiels              │
│ - Nommage : `name` est plus clair que `n`                      │
│ - Format : Respecter le message exact demande                  │
└─────────────────────────────────────────────────────────────────┘
```

---

### 5.7 Simulation avec trace d'execution

```
┌───────┬──────────────────────────────────────┬─────────────────────────────┐
│ Etape │ Commande                             │ Resultat                    │
├───────┼──────────────────────────────────────┼─────────────────────────────┤
│   1   │ cargo new cargo_init --lib           │ Cree le projet              │
│   2   │ cd cargo_init                        │ Entre dans le repertoire    │
│   3   │ code src/lib.rs                      │ Ouvre l'editeur             │
│   4   │ [Ecriture du code]                   │ Implemente les fonctions    │
│   5   │ cargo build                          │ Compile le projet           │
│   6   │ cargo test                           │ Execute les tests           │
│   7   │ cargo clippy                         │ Verifie la qualite          │
│   8   │ cargo fmt                            │ Formate le code             │
│   9   │ cargo doc --open                     │ Genere et ouvre la doc      │
└───────┴──────────────────────────────────────┴─────────────────────────────┘
```

---

### 5.8 Mnemotechniques

**Cargo = Container Ship**

Pense a Cargo comme un navire cargo :
- Les crates sont les conteneurs
- Les dependances sont la cargaison
- Cargo.toml est le manifeste de chargement
- Cargo.lock est l'inventaire exact

**RCFT = Rust Cargo Flow Test**

1. **R**ustup : installer Rust
2. **C**argo new : creer le projet
3. **F**mt/clippy : nettoyer le code
4. **T**est : verifier que ca marche

---

### 5.9 Applications pratiques

| Application | Commandes Cargo utilisees |
|-------------|--------------------------|
| **CI/CD Pipeline** | `cargo test`, `cargo clippy`, `cargo fmt --check` |
| **Publication de crate** | `cargo publish` |
| **Documentation** | `cargo doc`, deploiement sur docs.rs |
| **Benchmarking** | `cargo bench` avec criterion |
| **Cross-compilation** | `cargo build --target wasm32-unknown-unknown` |

---

## SECTION 6 : PIEGES — RECAPITULATIF

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Oublier `pub` | Fonction inaccessible | Toujours `pub` pour API |
| 2 | Pas d'edition | Edition 2015 par defaut | Specifier `edition = "2024"` |
| 3 | lib.rs vs main.rs | Mauvais type de crate | `--lib` pour bibliotheque |
| 4 | Pas de doc | clippy warning | Ajouter `///` comments |
| 5 | Version hardcodee | Desync avec Cargo.toml | Utiliser `env!()` |

---

## SECTION 7 : QCM

### Question 1 (3 points)
Quelle commande cree un nouveau projet bibliotheque ?

- A) `cargo init`
- B) `cargo new mylib`
- C) `cargo new mylib --lib`
- D) `cargo create --library mylib`

**Reponse : C** — `cargo new mylib --lib` cree une bibliotheque (lib.rs).

---

### Question 2 (3 points)
Quel fichier contient les metadonnees du projet ?

- A) `src/lib.rs`
- B) `Cargo.lock`
- C) `Cargo.toml`
- D) `package.json`

**Reponse : C** — `Cargo.toml` est le manifest du projet.

---

### Question 3 (4 points)
Quelle macro recupere la version du package au compile-time ?

- A) `version!()`
- B) `env!("VERSION")`
- C) `env!("CARGO_PKG_VERSION")`
- D) `std::env::var("VERSION")`

**Reponse : C** — `env!("CARGO_PKG_VERSION")` lit la version de Cargo.toml a la compilation.

---

### Question 4 (5 points)
Pourquoi `cargo clippy` est-il important ?

- A) Il formate le code
- B) Il compile plus vite
- C) Il detecte des erreurs et mauvaises pratiques
- D) Il gere les dependances

**Reponse : C** — clippy est un linter qui detecte des patterns problematiques.

---

### Question 5 (5 points)
Que fait `#[cfg(test)]` ?

- A) Active le mode debug
- B) Compile le code seulement pour les tests
- C) Ignore le module
- D) Exporte le module publiquement

**Reponse : B** — Le code sous `#[cfg(test)]` n'est compile que lors de `cargo test`.

---

## SECTION 8 : RECAPITULATIF

| Critere | Valeur |
|---------|--------|
| **ID** | 0.7.0 |
| **Nom** | cargo_init |
| **Difficulte** | 2/10 |
| **Duree** | 30 min |
| **XP Base** | 50 |
| **Langages** | Rust Edition 2024 |
| **Concepts cles** | Cargo, tests, clippy, rustfmt, documentation |
| **Prerequis** | Terminal basique |
| **Domaines** | Tooling, Config |

---

## SECTION 9 : DEPLOYMENT PACK (JSON COMPLET)

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "0.7.0-cargo_init",
    "generated_at": "2026-01-16",

    "metadata": {
      "exercise_id": "0.7.0",
      "exercise_name": "cargo_init",
      "module": "0.7",
      "module_name": "Introduction a Rust",
      "concept": "a",
      "concept_name": "Installation et premier projet",
      "type": "code",
      "tier": 1,
      "difficulty": 2,
      "difficulty_stars": "2/10",
      "languages": ["rust"],
      "language_versions": {
        "rust": "edition 2024"
      },
      "duration_minutes": 30,
      "xp_base": 50,
      "prerequisites": ["terminal"],
      "domains": ["Tooling", "Config"],
      "tags": ["cargo", "rustup", "tests", "clippy", "rustfmt"]
    },

    "files": {
      "spec.json": "/* Section 4.9 */",
      "references/rust/ref_solution.rs": "/* Section 4.3 */",
      "mutants/mutant_a_boundary.rs": "/* Section 4.10 */",
      "mutants/mutant_b_logic.rs": "/* Section 4.10 */",
      "mutants/mutant_c_type.rs": "/* Section 4.10 */",
      "mutants/mutant_d_safety.rs": "/* Section 4.10 */",
      "mutants/mutant_e_return.rs": "/* Section 4.10 */"
    }
  }
}
```

---

*Document genere selon HACKBRAIN v5.5.2*
