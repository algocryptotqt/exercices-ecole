# Exercice 0.8.22 : std_traits

**Module :**
0.8 — Rust Intermediate

**Concept :**
a-j — Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Display, From, Into

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
2 — Concept combine

**Langage :**
Rust Edition 2024

**Prerequis :**
0.8.21 (traits_basic)

**Domaines :**
Type System, Standard Library, Traits

**Duree estimee :**
180 min

**XP Base :**
350

**Complexite :**
T1 O(n) x S1 O(1)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichier a rendre :** `std_traits.rs`

**Fonctions autorisees :**
- Standard library

**Fonctions interdites :**
- derive macros (implementer manuellement!)

### 1.2 Consigne

**Maitriser les Fondations: Les Traits de la Standard Library**

Les traits de la bibliotheque standard sont les briques de base de l'ecosysteme Rust. Tu vas les implementer manuellement pour comprendre leur fonctionnement.

**Ta mission :**

Creer une structure `Temperature` et implementer manuellement tous ces traits:

```rust
struct Temperature {
    celsius: f64,
}
```

**Traits a implementer:**

```rust
// Debug - Affichage pour le debugging
impl std::fmt::Debug for Temperature

// Clone - Duplication explicite
impl Clone for Temperature

// PartialEq - Comparaison d'egalite (==, !=)
impl PartialEq for Temperature

// Eq - Egalite reflexive (marker trait)
impl Eq for Temperature

// PartialOrd - Comparaison partielle (<, >, <=, >=)
impl PartialOrd for Temperature

// Ord - Comparaison totale (pour sort)
impl Ord for Temperature

// Default - Valeur par defaut
impl Default for Temperature

// Display - Affichage formatte
impl std::fmt::Display for Temperature

// From<f64> - Conversion depuis f64
impl From<f64> for Temperature

// From<i32> - Conversion depuis i32
impl From<i32> for Temperature
```

**Methodes supplementaires:**

```rust
impl Temperature {
    fn new(celsius: f64) -> Self;
    fn to_fahrenheit(&self) -> f64;
    fn to_kelvin(&self) -> f64;
    fn is_freezing(&self) -> bool;
    fn is_boiling(&self) -> bool;
}
```

**Sortie attendue du main:**

```
=== Std Traits Demo ===
Debug: Temperature { celsius: 25.0 }
Display: 25.00C (77.00F, 298.15K)
Clone: t1 == t2? true
Default: 0.00C (32.00F, 273.15K)

Comparisons:
20C < 25C? true
25C == 25C? true

Sorted temperatures: [-40, 0, 20, 25, 100]

From conversions:
From f64: 36.60C
From i32: 100.00C
Into f64: 25
```

### 1.3 Prototype

```rust
use std::fmt;
use std::cmp::Ordering;

struct Temperature {
    celsius: f64,
}

impl fmt::Debug for Temperature { ... }
impl fmt::Display for Temperature { ... }
impl Clone for Temperature { ... }
impl PartialEq for Temperature { ... }
impl Eq for Temperature { }
impl PartialOrd for Temperature { ... }
impl Ord for Temperature { ... }
impl Default for Temperature { ... }
impl From<f64> for Temperature { ... }
impl From<i32> for Temperature { ... }

fn main();
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 La Hierarchie des Traits de Comparaison

```
PartialEq (== !=)
    |
    v
   Eq (reflexive: a == a toujours vrai)

PartialOrd (< > <= >=) [requiert PartialEq]
    |
    v
  Ord (comparaison totale) [requiert Eq]
```

### 2.2 Pourquoi Partial?

`PartialEq` et `PartialOrd` existent car certains types n'ont pas d'egalite/ordre total:
- `f64::NAN != f64::NAN` (NaN n'est egal a rien, meme lui-meme)
- Les flotants implementent PartialOrd mais pas Ord

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Library Author**

Les traits standards permettent:
- `Debug` pour le logging et debugging
- `Clone` pour la duplication
- `Ord` pour le tri avec `.sort()`
- `From/Into` pour les conversions idiomatiques

**Metier : Data Engineer**

Les traits de comparaison sont essentiels pour:
- Trier des donnees (`Ord`)
- Deduplication (`Eq`, `Hash`)
- Recherche binaire (`Ord`)

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ rustc --edition 2024 std_traits.rs
$ ./std_traits
=== Std Traits Demo ===
Debug: Temperature { celsius: 25.0 }
Display: 25.00C (77.00F, 298.15K)
Clone: t1 == t2? true
Default: 0.00C (32.00F, 273.15K)

Comparisons:
20C < 25C? true
25C == 25C? true

Sorted temperatures: [-40, 0, 20, 25, 100]

From conversions:
From f64: 36.60C
From i32: 100.00C
Into f64: 25
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★☆☆☆☆ (6/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Implementer `Hash` pour permettre l'utilisation dans `HashMap`:

```rust
use std::hash::{Hash, Hasher};

impl Hash for Temperature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Convertir f64 en representation hashable
    }
}
```

Et implementer `TryFrom` avec gestion d'erreur:

```rust
impl TryFrom<&str> for Temperature {
    type Error = &'static str;
    fn try_from(s: &str) -> Result<Self, Self::Error>;
}
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Expected | Points |
|---------|-------------|----------|--------|
| T01 | Compilation sans warning | Success | 5 |
| T02 | Debug format | "Temperature { celsius: X }" | 10 |
| T03 | Display format | "X.XXC (Y.YYF, Z.ZZK)" | 10 |
| T04 | Clone fonctionne | Copies independantes | 10 |
| T05 | PartialEq/Eq | == et != fonctionnent | 10 |
| T06 | PartialOrd | <, >, <=, >= fonctionnent | 10 |
| T07 | Ord (sort) | Vec triable | 15 |
| T08 | Default | 0.0 celsius | 10 |
| T09 | From<f64> | Conversion correcte | 10 |
| T10 | From<i32> | Conversion correcte | 10 |

### 4.2 Tests unitaires

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug() {
        let t = Temperature::new(25.0);
        assert_eq!(format!("{:?}", t), "Temperature { celsius: 25.0 }");
    }

    #[test]
    fn test_display() {
        let t = Temperature::new(25.0);
        let display = format!("{}", t);
        assert!(display.contains("25.00C"));
        assert!(display.contains("77.00F"));
    }

    #[test]
    fn test_clone() {
        let t1 = Temperature::new(25.0);
        let t2 = t1.clone();
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_partial_eq() {
        let t1 = Temperature::new(25.0);
        let t2 = Temperature::new(25.0);
        let t3 = Temperature::new(30.0);
        assert_eq!(t1, t2);
        assert_ne!(t1, t3);
    }

    #[test]
    fn test_partial_ord() {
        let t1 = Temperature::new(20.0);
        let t2 = Temperature::new(25.0);
        assert!(t1 < t2);
        assert!(t2 > t1);
        assert!(t1 <= t2);
        assert!(t2 >= t1);
    }

    #[test]
    fn test_ord_sort() {
        let mut temps = vec![
            Temperature::new(25.0),
            Temperature::new(0.0),
            Temperature::new(100.0),
            Temperature::new(-40.0),
            Temperature::new(20.0),
        ];
        temps.sort();
        assert_eq!(temps[0].celsius, -40.0);
        assert_eq!(temps[4].celsius, 100.0);
    }

    #[test]
    fn test_default() {
        let t: Temperature = Default::default();
        assert_eq!(t.celsius, 0.0);
    }

    #[test]
    fn test_from_f64() {
        let t: Temperature = Temperature::from(36.6);
        assert!((t.celsius - 36.6).abs() < 0.001);
    }

    #[test]
    fn test_from_i32() {
        let t: Temperature = Temperature::from(100);
        assert_eq!(t.celsius, 100.0);
    }

    #[test]
    fn test_to_fahrenheit() {
        let t = Temperature::new(0.0);
        assert!((t.to_fahrenheit() - 32.0).abs() < 0.001);
    }

    #[test]
    fn test_to_kelvin() {
        let t = Temperature::new(0.0);
        assert!((t.to_kelvin() - 273.15).abs() < 0.001);
    }
}
```

### 4.3 Solution de reference

```rust
/*
 * std_traits.rs
 * Standard library traits implementation
 * Exercice ex22_std_traits
 */

use std::fmt;
use std::cmp::Ordering;

struct Temperature {
    celsius: f64,
}

impl Temperature {
    fn new(celsius: f64) -> Self {
        Temperature { celsius }
    }

    fn to_fahrenheit(&self) -> f64 {
        self.celsius * 9.0 / 5.0 + 32.0
    }

    fn to_kelvin(&self) -> f64 {
        self.celsius + 273.15
    }

    fn is_freezing(&self) -> bool {
        self.celsius <= 0.0
    }

    fn is_boiling(&self) -> bool {
        self.celsius >= 100.0
    }
}

// Debug trait - for debugging output
impl fmt::Debug for Temperature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Temperature")
            .field("celsius", &self.celsius)
            .finish()
    }
}

// Display trait - for user-facing output
impl fmt::Display for Temperature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:.2}C ({:.2}F, {:.2}K)",
            self.celsius,
            self.to_fahrenheit(),
            self.to_kelvin()
        )
    }
}

// Clone trait - explicit duplication
impl Clone for Temperature {
    fn clone(&self) -> Self {
        Temperature {
            celsius: self.celsius,
        }
    }
}

// Copy could be derived but we're implementing manually
impl Copy for Temperature {}

// PartialEq trait - equality comparison
impl PartialEq for Temperature {
    fn eq(&self, other: &Self) -> bool {
        // Use epsilon comparison for floats
        (self.celsius - other.celsius).abs() < f64::EPSILON
    }
}

// Eq trait - reflexive equality (marker trait)
impl Eq for Temperature {}

// PartialOrd trait - partial ordering
impl PartialOrd for Temperature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.celsius.partial_cmp(&other.celsius)
    }
}

// Ord trait - total ordering
impl Ord for Temperature {
    fn cmp(&self, other: &Self) -> Ordering {
        // Since we're treating temperatures as comparable,
        // we use total_cmp which handles NaN
        self.celsius.total_cmp(&other.celsius)
    }
}

// Default trait - default value
impl Default for Temperature {
    fn default() -> Self {
        Temperature { celsius: 0.0 }
    }
}

// From<f64> trait - conversion from f64
impl From<f64> for Temperature {
    fn from(celsius: f64) -> Self {
        Temperature { celsius }
    }
}

// From<i32> trait - conversion from i32
impl From<i32> for Temperature {
    fn from(celsius: i32) -> Self {
        Temperature {
            celsius: celsius as f64,
        }
    }
}

// Into<f64> is automatically implemented when From<Temperature> for f64 exists
// But we can also implement it the other way
impl From<Temperature> for f64 {
    fn from(temp: Temperature) -> f64 {
        temp.celsius
    }
}

fn main() {
    println!("=== Std Traits Demo ===");

    // Debug
    let t = Temperature::new(25.0);
    println!("Debug: {:?}", t);

    // Display
    println!("Display: {}", t);

    // Clone
    let t1 = Temperature::new(25.0);
    let t2 = t1.clone();
    println!("Clone: t1 == t2? {}", t1 == t2);

    // Default
    let default_temp: Temperature = Default::default();
    println!("Default: {}", default_temp);

    // Comparisons
    println!("\nComparisons:");
    let t20 = Temperature::new(20.0);
    let t25 = Temperature::new(25.0);
    println!("20C < 25C? {}", t20 < t25);
    println!("25C == 25C? {}", t25 == Temperature::new(25.0));

    // Ord - sorting
    let mut temps = vec![
        Temperature::new(25.0),
        Temperature::new(0.0),
        Temperature::new(100.0),
        Temperature::new(-40.0),
        Temperature::new(20.0),
    ];
    temps.sort();
    let sorted: Vec<i32> = temps.iter().map(|t| t.celsius as i32).collect();
    println!("\nSorted temperatures: {:?}", sorted);

    // From conversions
    println!("\nFrom conversions:");
    let from_f64: Temperature = Temperature::from(36.6);
    println!("From f64: {:.2}C", from_f64.celsius);

    let from_i32: Temperature = Temperature::from(100);
    println!("From i32: {:.2}C", from_i32.celsius);

    // Into (automatic from From<Temperature> for f64)
    let celsius: f64 = t25.into();
    println!("Into f64: {}", celsius);
}
```

### 4.4 Solutions alternatives acceptees

```rust
// Alternative 1: PartialEq sans epsilon (exact)
impl PartialEq for Temperature {
    fn eq(&self, other: &Self) -> bool {
        self.celsius == other.celsius
    }
}

// Alternative 2: Debug avec format simple
impl fmt::Debug for Temperature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Temperature {{ celsius: {} }}", self.celsius)
    }
}

// Alternative 3: Ord avec panic sur NaN
impl Ord for Temperature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.partial_cmp(other).expect("Temperature should not be NaN")
    }
}
```

### 4.10 Solutions Mutantes (minimum 5)

```rust
// MUTANT 1 (Logic): PartialEq inverse
impl PartialEq for Temperature {
    fn eq(&self, other: &Self) -> bool {
        self.celsius != other.celsius  // ERREUR: != au lieu de ==
    }
}
// Detection: 25C == 25C retourne false

// MUTANT 2 (Math): to_fahrenheit incorrect
impl Temperature {
    fn to_fahrenheit(&self) -> f64 {
        self.celsius + 32.0  // ERREUR: manque * 9/5
    }
}
// Detection: 0C donne 32F mais 100C donne 132F au lieu de 212F

// MUTANT 3 (Logic): Ord inverse
impl Ord for Temperature {
    fn cmp(&self, other: &Self) -> Ordering {
        other.celsius.total_cmp(&self.celsius)  // ERREUR: inverse
    }
}
// Detection: sort() trie en ordre decroissant

// MUTANT 4 (Value): Default non zero
impl Default for Temperature {
    fn default() -> Self {
        Temperature { celsius: 20.0 }  // ERREUR: devrait etre 0.0
    }
}
// Detection: Default::default() != 0C

// MUTANT 5 (Type): From<i32> ne convertit pas
impl From<i32> for Temperature {
    fn from(celsius: i32) -> Self {
        Temperature { celsius: celsius as f64 + 1.0 }  // ERREUR: +1
    }
}
// Detection: Temperature::from(100) donne 101C
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

Les **10 traits fondamentaux** de la standard library:

| Trait | Utilite | Methodes |
|-------|---------|----------|
| Debug | Affichage debug | `fmt()` |
| Display | Affichage user | `fmt()` |
| Clone | Copie explicite | `clone()` |
| Copy | Copie implicite | (marker) |
| PartialEq | Egalite partielle | `eq()` |
| Eq | Egalite totale | (marker) |
| PartialOrd | Ordre partiel | `partial_cmp()` |
| Ord | Ordre total | `cmp()` |
| Default | Valeur defaut | `default()` |
| From/Into | Conversions | `from()` |

### 5.2 LDA - Traduction Litterale en Francais

```
TRAIT Debug
    METHODE fmt(formateur) -> Resultat
    DEBUT
        ECRIRE "Temperature { celsius: " + celsius + " }"
    FIN
FIN TRAIT

TRAIT Ord REQUIERT Eq
    METHODE cmp(autre) -> Ordering
    DEBUT
        SI self.celsius < autre.celsius ALORS
            RETOURNER Less
        SINON SI self.celsius > autre.celsius ALORS
            RETOURNER Greater
        SINON
            RETOURNER Equal
        FIN SI
    FIN
FIN TRAIT
```

### 5.3 Visualisation ASCII

```
Trait Hierarchy:

PartialEq (== !=)                 PartialOrd (< > <= >=)
     |                                    |
     v                                    v
    Eq  <-------------------------->     Ord
(a == a true)                       (total order)

                From<T>
                   |
                   v
                Into<U>  (auto-implemented)


Debug  -----> {:?}
Display ----> {}
```

### 5.4 Les pieges en detail

#### Piege 1: Eq sans PartialEq

```rust
// ERREUR: Eq requiert PartialEq
impl Eq for Temperature {}  // Erreur de compilation!

// CORRECT
impl PartialEq for Temperature { ... }
impl Eq for Temperature {}
```

#### Piege 2: Ord avec f64

```rust
// PROBLEME: f64 n'implemente pas Ord (a cause de NaN)
impl Ord for Temperature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.celsius.cmp(&other.celsius)  // Erreur!
    }
}

// SOLUTION: Utiliser total_cmp
impl Ord for Temperature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.celsius.total_cmp(&other.celsius)
    }
}
```

#### Piege 3: From vs Into

```rust
// Implementer From donne Into gratuitement
impl From<f64> for Temperature { ... }

// Maintenant ceci fonctionne:
let t: Temperature = 25.0.into();
```

### 5.5 Cours Complet

#### 5.5.1 Debug vs Display

```rust
// Debug: pour les developpeurs, format {:?}
impl fmt::Debug for T {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "T {{ field: {:?} }}", self.field)
    }
}

// Display: pour les utilisateurs, format {}
impl fmt::Display for T {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nice format: {}", self.field)
    }
}
```

#### 5.5.2 Clone vs Copy

```rust
// Clone: copie explicite, peut etre couteux
let s1 = String::from("hello");
let s2 = s1.clone();  // Clone explicite

// Copy: copie implicite bit-a-bit, types simples
let x = 5;
let y = x;  // Copy implicite, x toujours valide
```

#### 5.5.3 La famille Eq/Ord

```rust
// PartialEq: peut etre asymetrique (NaN)
// Eq: symmetrique et reflexif

// PartialOrd: peut retourner None
// Ord: retourne toujours un Ordering
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication |
|-------|-------------|
| Debug auto-derivable | `#[derive(Debug)]` |
| Display manuel | Format specifique |
| Clone pour heap | String, Vec |
| Copy pour stack | i32, f64, bool |
| Ord pour sort | `vec.sort()` |

### 5.7 Simulation avec trace d'execution

```
Appel: temps.sort()

1. sort() requiert Ord
2. Pour chaque paire (a, b):
   - Appelle a.cmp(&b)
   - cmp() retourne Ordering::Less/Equal/Greater
3. Algorithme de tri (merge sort stable)
4. Vec reorganise en place
```

### 5.8 Mnemotechniques

**"DCCDE = Debug Clone Copy Default Eq"**
- Les 5 traits derivables les plus courants

**"Partial = Peut retourner None/false pour NaN"**
- PartialEq, PartialOrd

**"From = Je me transforme en, Into = Tu te transformes en"**
- `T::from(u)` vs `t.into()`

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| Ord sans Eq | E0277 | Implementer Eq d'abord |
| f64 et Ord | Pas de cmp | Utiliser total_cmp |
| Clone sans Copy | Move inattendu | Ajouter Clone |
| From sans Into | Compilation ok mais non idiomatique | From donne Into |

---

## SECTION 7 : QCM

### Question 1
Pourquoi f64 n'implemente-t-il pas Ord?

A) C'est un bug
B) f64 est trop grand
C) NaN n'a pas d'ordre total
D) f64 n'est pas comparable
E) Performance

**Reponse correcte: C**

### Question 2
Quelle est la difference entre Debug et Display?

A) Aucune
B) Debug pour dev, Display pour user
C) Debug est plus lent
D) Display supporte les generiques
E) Debug requiert Display

**Reponse correcte: B**

### Question 3
Si j'implemente `From<A> for B`, qu'est-ce que j'obtiens gratuitement?

A) Clone
B) `Into<B> for A`
C) Default
D) Copy
E) Rien

**Reponse correcte: B**

### Question 4
Quel trait est requis pour utiliser `.sort()` sur un Vec?

A) PartialOrd
B) PartialEq
C) Ord
D) Clone
E) Display

**Reponse correcte: C**

### Question 5
Qu'est-ce qu'un "marker trait"?

A) Un trait avec beaucoup de methodes
B) Un trait sans methodes a implementer
C) Un trait deprecie
D) Un trait unsafe
E) Un trait async

**Reponse correcte: B**

---

## SECTION 8 : RECAPITULATIF

| Trait | Methode principale | Format/Operateur |
|-------|-------------------|------------------|
| Debug | `fmt()` | `{:?}` |
| Display | `fmt()` | `{}` |
| Clone | `clone()` | `.clone()` |
| Copy | (marker) | implicite |
| PartialEq | `eq()` | `==` `!=` |
| Eq | (marker) | - |
| PartialOrd | `partial_cmp()` | `<` `>` |
| Ord | `cmp()` | `.sort()` |
| Default | `default()` | `Default::default()` |
| From | `from()` | `T::from(x)` |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.8.22",
  "name": "std_traits",
  "version": "1.0.0",
  "language": "rust",
  "language_version": "edition2024",
  "files": {
    "submission": ["std_traits.rs"],
    "test": ["test_std_traits.rs"]
  },
  "compilation": {
    "compiler": "rustc",
    "flags": ["--edition", "2024", "-W", "warnings"],
    "output": "std_traits"
  },
  "tests": {
    "unit_tests": true,
    "output_match": true
  },
  "scoring": {
    "total": 100,
    "compilation": 5,
    "tests": 95
  },
  "concepts": ["debug", "clone", "partial_eq", "eq", "partial_ord", "ord", "default", "display", "from", "into"]
}
```
