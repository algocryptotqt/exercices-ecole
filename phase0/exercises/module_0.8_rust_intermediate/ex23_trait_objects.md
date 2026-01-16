# Exercice 0.8.23 : trait_objects

**Module :**
0.8 — Rust Intermediate

**Concept :**
a-d — dyn Trait, Box<dyn Trait>, trait objects, dynamic dispatch

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
code

**Tiers :**
2 — Concept combine

**Langage :**
Rust Edition 2024

**Prerequis :**
0.8.21 (traits_basic), 0.8.22 (std_traits), Box, heap allocation

**Domaines :**
Type System, Polymorphism, Runtime Dispatch

**Duree estimee :**
150 min

**XP Base :**
300

**Complexite :**
T1 O(n) x S1 O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichier a rendre :** `trait_objects.rs`

**Fonctions autorisees :**
- Standard library

**Fonctions interdites :**
- External crates

### 1.2 Consigne

**Polymorphisme a l'Execution: L'Art du Dynamic Dispatch**

Parfois, tu ne connais pas le type exact a la compilation. Les trait objects permettent de stocker differents types implementant le meme trait dans une meme collection.

**Ta mission :**

Creer un systeme de notification avec differents types de notificateurs:

```rust
// Trait pour les notificateurs
trait Notifier {
    fn send(&self, message: &str);
    fn name(&self) -> &str;
}

// Differents types de notificateurs
struct EmailNotifier {
    email: String,
}

struct SmsNotifier {
    phone: String,
}

struct SlackNotifier {
    channel: String,
}

struct ConsoleNotifier;
```

**Implementer:**

1. Le trait `Notifier` pour chaque type de notificateur
2. Une fonction qui accepte un trait object:
   ```rust
   fn notify_all(notifiers: &[Box<dyn Notifier>], message: &str);
   ```
3. Une fonction qui retourne un trait object:
   ```rust
   fn create_notifier(notifier_type: &str, target: &str) -> Box<dyn Notifier>;
   ```

**Sortie attendue du main:**

```
=== Trait Objects Demo ===
Creating notifiers...
Email notifier: user@example.com
SMS notifier: +1234567890
Slack notifier: #general
Console notifier: console

Notifying all (dynamic dispatch):
[Email] Sending to user@example.com: Hello, World!
[SMS] Sending to +1234567890: Hello, World!
[Slack] Posting to #general: Hello, World!
[Console] Hello, World!

Dynamic creation:
Created: Email notifier
Created: SMS notifier
Created: Slack notifier
Created: Console notifier

Object safety demo:
Number of notifiers: 4
```

### 1.3 Prototype

```rust
trait Notifier {
    fn send(&self, message: &str);
    fn name(&self) -> &str;
}

struct EmailNotifier { email: String }
struct SmsNotifier { phone: String }
struct SlackNotifier { channel: String }
struct ConsoleNotifier;

fn notify_all(notifiers: &[Box<dyn Notifier>], message: &str);
fn create_notifier(notifier_type: &str, target: &str) -> Box<dyn Notifier>;

fn main();
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Static vs Dynamic Dispatch

**Static dispatch** (monomorphisation):
```rust
fn notify<T: Notifier>(n: &T, msg: &str) {
    n.send(msg);  // Type connu a la compilation
}
```

**Dynamic dispatch** (trait objects):
```rust
fn notify(n: &dyn Notifier, msg: &str) {
    n.send(msg);  // Type resolu a l'execution via vtable
}
```

### 2.2 Object Safety

Un trait est "object-safe" (utilisable comme trait object) si:
- Pas de methodes avec `Self` en retour
- Pas de parametres generiques sur les methodes
- Pas de methodes `where Self: Sized`

### SECTION 2.5 : DANS LA VRAIE VIE

**Metier : Plugin Developer**

Les trait objects permettent:
- Systemes de plugins chargeables dynamiquement
- Handlers de differents types d'evenements
- Middleware chains

**Metier : Game Developer**

Utilisations courantes:
- Collection d'entites heterogenes
- Systeme de composants (ECS simplifie)
- Event handlers polymorphes

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ rustc --edition 2024 trait_objects.rs
$ ./trait_objects
=== Trait Objects Demo ===
Creating notifiers...
[...]
```

### 3.1 BONUS STANDARD (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★☆☆☆☆ (6/10)

**Recompense :**
XP x2

#### 3.1.1 Consigne Bonus

Implementer un systeme avec multiples traits:

```rust
trait Drawable {
    fn draw(&self);
}

trait Updatable {
    fn update(&mut self, delta: f64);
}

// Combiner les traits
trait Entity: Drawable + Updatable {
    fn name(&self) -> &str;
}

// Utiliser avec dyn
fn process_entities(entities: &mut [Box<dyn Entity>], delta: f64);
```

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette

| Test ID | Description | Expected | Points |
|---------|-------------|----------|--------|
| T01 | Compilation sans warning | Success | 10 |
| T02 | EmailNotifier::send | Format correct | 15 |
| T03 | SmsNotifier::send | Format correct | 15 |
| T04 | SlackNotifier::send | Format correct | 15 |
| T05 | notify_all fonctionne | Tous appeles | 15 |
| T06 | create_notifier "email" | EmailNotifier | 10 |
| T07 | create_notifier "sms" | SmsNotifier | 10 |
| T08 | Vec<Box<dyn Notifier>> | Heterogene | 10 |

### 4.2 Tests unitaires

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_email_notifier_name() {
        let n = EmailNotifier { email: "test@test.com".into() };
        assert!(n.name().contains("Email"));
    }

    #[test]
    fn test_sms_notifier_name() {
        let n = SmsNotifier { phone: "+123".into() };
        assert!(n.name().contains("SMS"));
    }

    #[test]
    fn test_trait_object_collection() {
        let notifiers: Vec<Box<dyn Notifier>> = vec![
            Box::new(EmailNotifier { email: "a@b.c".into() }),
            Box::new(SmsNotifier { phone: "+1".into() }),
            Box::new(ConsoleNotifier),
        ];
        assert_eq!(notifiers.len(), 3);
    }

    #[test]
    fn test_create_notifier_email() {
        let n = create_notifier("email", "test@test.com");
        assert!(n.name().contains("Email"));
    }

    #[test]
    fn test_create_notifier_sms() {
        let n = create_notifier("sms", "+123");
        assert!(n.name().contains("SMS"));
    }

    #[test]
    fn test_create_notifier_slack() {
        let n = create_notifier("slack", "#test");
        assert!(n.name().contains("Slack"));
    }

    #[test]
    fn test_create_notifier_default() {
        let n = create_notifier("unknown", "");
        assert!(n.name().contains("Console"));
    }

    #[test]
    fn test_dynamic_dispatch() {
        let notifiers: Vec<Box<dyn Notifier>> = vec![
            Box::new(ConsoleNotifier),
        ];
        // This should compile and run
        notify_all(&notifiers, "test");
    }
}
```

### 4.3 Solution de reference

```rust
/*
 * trait_objects.rs
 * Trait objects and dynamic dispatch
 * Exercice ex23_trait_objects
 */

/// Trait for notification systems
trait Notifier {
    /// Send a notification message
    fn send(&self, message: &str);

    /// Get the notifier's display name
    fn name(&self) -> &str;
}

// ============ Notifier Types ============

struct EmailNotifier {
    email: String,
}

struct SmsNotifier {
    phone: String,
}

struct SlackNotifier {
    channel: String,
}

struct ConsoleNotifier;

// ============ Notifier Implementations ============

impl Notifier for EmailNotifier {
    fn send(&self, message: &str) {
        println!("[Email] Sending to {}: {}", self.email, message);
    }

    fn name(&self) -> &str {
        "Email notifier"
    }
}

impl Notifier for SmsNotifier {
    fn send(&self, message: &str) {
        println!("[SMS] Sending to {}: {}", self.phone, message);
    }

    fn name(&self) -> &str {
        "SMS notifier"
    }
}

impl Notifier for SlackNotifier {
    fn send(&self, message: &str) {
        println!("[Slack] Posting to {}: {}", self.channel, message);
    }

    fn name(&self) -> &str {
        "Slack notifier"
    }
}

impl Notifier for ConsoleNotifier {
    fn send(&self, message: &str) {
        println!("[Console] {}", message);
    }

    fn name(&self) -> &str {
        "Console notifier"
    }
}

// ============ Functions using trait objects ============

/// Notify all notifiers in the slice
fn notify_all(notifiers: &[Box<dyn Notifier>], message: &str) {
    for notifier in notifiers {
        notifier.send(message);
    }
}

/// Factory function that creates a notifier dynamically
fn create_notifier(notifier_type: &str, target: &str) -> Box<dyn Notifier> {
    match notifier_type {
        "email" => Box::new(EmailNotifier {
            email: target.to_string(),
        }),
        "sms" => Box::new(SmsNotifier {
            phone: target.to_string(),
        }),
        "slack" => Box::new(SlackNotifier {
            channel: target.to_string(),
        }),
        _ => Box::new(ConsoleNotifier),
    }
}

fn main() {
    println!("=== Trait Objects Demo ===");

    // Create notifiers manually
    println!("Creating notifiers...");
    let email = EmailNotifier {
        email: "user@example.com".to_string(),
    };
    let sms = SmsNotifier {
        phone: "+1234567890".to_string(),
    };
    let slack = SlackNotifier {
        channel: "#general".to_string(),
    };
    let console = ConsoleNotifier;

    println!("{}: {}", email.name(), email.email);
    println!("{}: {}", sms.name(), sms.phone);
    println!("{}: {}", slack.name(), slack.channel);
    println!("{}: console", console.name());

    // Store different types in a Vec using trait objects
    let notifiers: Vec<Box<dyn Notifier>> = vec![
        Box::new(email),
        Box::new(sms),
        Box::new(slack),
        Box::new(console),
    ];

    // Dynamic dispatch - call methods through trait objects
    println!("\nNotifying all (dynamic dispatch):");
    notify_all(&notifiers, "Hello, World!");

    // Create notifiers dynamically
    println!("\nDynamic creation:");
    let types = ["email", "sms", "slack", "console"];
    let targets = ["dynamic@test.com", "+9876543210", "#random", ""];

    for (t, target) in types.iter().zip(targets.iter()) {
        let n = create_notifier(t, target);
        println!("Created: {}", n.name());
    }

    // Demonstrate object safety
    println!("\nObject safety demo:");
    println!("Number of notifiers: {}", notifiers.len());
}
```

### 4.4 Solutions alternatives acceptees

```rust
// Alternative 1: Utiliser &dyn au lieu de Box<dyn>
fn notify_all_ref(notifiers: &[&dyn Notifier], message: &str) {
    for notifier in notifiers {
        notifier.send(message);
    }
}

// Alternative 2: Trait avec associated type pour le retour
trait NotifierFactory {
    type Output: Notifier;
    fn create(target: &str) -> Self::Output;
}

// Alternative 3: Enum au lieu de trait objects (plus performant)
enum AnyNotifier {
    Email(EmailNotifier),
    Sms(SmsNotifier),
    Slack(SlackNotifier),
    Console(ConsoleNotifier),
}
```

### 4.10 Solutions Mutantes (minimum 5)

```rust
// MUTANT 1 (Type): Oublier Box pour dyn
fn notify_all(notifiers: &[dyn Notifier], message: &str) {
    // ERREUR: dyn Trait n'est pas Sized!
}
// Detection: Erreur de compilation E0277

// MUTANT 2 (Logic): create_notifier retourne toujours Console
fn create_notifier(notifier_type: &str, target: &str) -> Box<dyn Notifier> {
    Box::new(ConsoleNotifier)  // Ignore les parametres!
}
// Detection: create_notifier("email", ...) n'est pas EmailNotifier

// MUTANT 3 (Trait): Trait non object-safe
trait BadNotifier {
    fn send(&self, message: &str);
    fn clone_boxed(&self) -> Self;  // Self en retour = non object-safe
}
// Detection: Erreur de compilation

// MUTANT 4 (Safety): Pas de dyn keyword
fn notify_all(notifiers: &[Box<Notifier>], message: &str) {
    // Erreur: Notifier sans dyn est ambigu
}
// Detection: Warning ou erreur de compilation

// MUTANT 5 (Logic): notify_all n'appelle pas tous les notifiers
fn notify_all(notifiers: &[Box<dyn Notifier>], message: &str) {
    if let Some(first) = notifiers.first() {
        first.send(message);  // N'appelle que le premier!
    }
}
// Detection: Un seul notifier appele
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

1. **Trait Objects** (`dyn Trait`) - Polymorphisme runtime
2. **Box<dyn Trait>** - Allocation heap pour trait objects
3. **Dynamic Dispatch** - Resolution de methodes a l'execution
4. **Object Safety** - Regles pour les traits utilisables comme objects

### 5.2 LDA - Traduction Litterale en Francais

```
FONCTION notify_all(notifiers: liste de Box<dyn Notifier>, message)
DEBUT
    POUR CHAQUE notifier DANS notifiers FAIRE
        notifier.send(message)  -- Dispatch dynamique via vtable
    FIN POUR
FIN

FONCTION create_notifier(type, cible) -> Box<dyn Notifier>
DEBUT
    SELON type FAIRE
        "email": RETOURNER Box(nouveau EmailNotifier(cible))
        "sms": RETOURNER Box(nouveau SmsNotifier(cible))
        "slack": RETOURNER Box(nouveau SlackNotifier(cible))
        autre: RETOURNER Box(nouveau ConsoleNotifier)
    FIN SELON
FIN
```

### 5.3 Visualisation ASCII

```
Static Dispatch (Monomorphisation):
+------------------+
| notify::<Email>  |  Compile-time: une fonction par type
| notify::<SMS>    |
| notify::<Slack>  |
+------------------+

Dynamic Dispatch (Trait Objects):
+-------------------+
| notify(dyn)       |  Une seule fonction
+-------------------+
         |
         v
+-------------------+     +-------------------+
| vtable            |---->| EmailNotifier::send|
| (function ptrs)   |---->| SmsNotifier::send  |
+-------------------+---->| SlackNotifier::send|
                          +-------------------+

Box<dyn Notifier> in memory:
+--------+--------+
| data   | vtable |
| (ptr)  | (ptr)  |
+--------+--------+
    |         |
    v         v
[Notifier   [send_fn,
 data]       name_fn]
```

### 5.4 Les pieges en detail

#### Piege 1: dyn Trait n'est pas Sized

```rust
// ERREUR: taille inconnue a la compilation
fn take_notifier(n: dyn Notifier) { }  // Erreur!

// CORRECT: utiliser une reference ou Box
fn take_notifier(n: &dyn Notifier) { }
fn take_notifier(n: Box<dyn Notifier>) { }
```

#### Piege 2: Object Safety

```rust
// NON object-safe: retourne Self
trait Clone {
    fn clone(&self) -> Self;  // Self = type concret
}

// NON object-safe: methode generique
trait Foo {
    fn bar<T>(&self, x: T);  // Generique
}
```

#### Piege 3: Performance

```rust
// Static dispatch: inline possible, zero overhead
fn notify<T: Notifier>(n: &T) { n.send("msg"); }

// Dynamic dispatch: indirection via vtable
fn notify(n: &dyn Notifier) { n.send("msg"); }  // ~2 pointeurs deref
```

### 5.5 Cours Complet

#### 5.5.1 Syntaxe des Trait Objects

```rust
// Reference a trait object
let n: &dyn Notifier = &email;

// Box (owned) trait object
let n: Box<dyn Notifier> = Box::new(email);

// Slice de Box trait objects
let notifiers: &[Box<dyn Notifier>] = &[...];
```

#### 5.5.2 Quand utiliser Trait Objects

| Situation | Solution |
|-----------|----------|
| Types connus a la compilation | Generiques (static) |
| Types inconnus / collection heterogene | Trait objects (dynamic) |
| Plugin system | Trait objects |
| Maximum performance | Generiques |

#### 5.5.3 Object Safety Rules

Un trait est object-safe si toutes ses methodes:
1. Ne retournent pas `Self`
2. N'ont pas de parametres de type generiques
3. Receiver est `&self`, `&mut self`, ou `self: Box<Self>`

```rust
// Object-safe
trait Safe {
    fn method(&self);
    fn other(&mut self) -> i32;
}

// NOT object-safe
trait Unsafe {
    fn returns_self(&self) -> Self;
    fn generic<T>(&self, x: T);
}
```

### 5.6 Normes avec explications pedagogiques

| Regle | Explication |
|-------|-------------|
| `dyn` obligatoire | Clarte sur le dispatch dynamique |
| `Box<dyn Trait>` pour owned | Taille fixe sur la stack |
| `&dyn Trait` pour borrows | Plus leger si possible |
| Trait objects = 2 pointeurs | Data + vtable |

### 5.7 Simulation avec trace d'execution

```
Appel: notify_all(&notifiers, "Hello")

1. notifiers[0] = Box<dyn Notifier>
2. Contient: (ptr vers EmailNotifier, ptr vers vtable)
3. notifier.send("Hello"):
   a. Lire vtable pointer
   b. Trouver offset de send() dans vtable
   c. Appeler EmailNotifier::send(data_ptr, "Hello")
4. Repeter pour chaque notifier

Vtable pour EmailNotifier:
+------------------+
| send: 0x1234     |  -> EmailNotifier::send
| name: 0x5678     |  -> EmailNotifier::name
+------------------+
```

### 5.8 Mnemotechniques

**"dyn = Dynamic = Runtime Resolution"**
- Le type est resolu a l'execution

**"Box<dyn Trait> = Fat Pointer"**
- Deux pointeurs: data + vtable

**"Object-Safe = Pas de Self, Pas de Generics"**
- Regles simples pour la compatibilite

---

## SECTION 6 : PIEGES - RECAPITULATIF

| Piege | Symptome | Solution |
|-------|----------|----------|
| dyn sans Box/& | E0277 (not Sized) | Ajouter Box ou & |
| Self en retour | E0038 (not object-safe) | Redesigner le trait |
| Generics dans methode | E0038 | Utiliser impl Trait |
| Performance | Lenteur | Considerer static dispatch |

---

## SECTION 7 : QCM

### Question 1
Pourquoi `dyn Trait` doit-il etre derriere un pointeur?

A) Pour des raisons de securite
B) Parce que sa taille n'est pas connue a la compilation
C) Pour permettre la mutation
D) C'est une convention
E) Pour le garbage collection

**Reponse correcte: B**

### Question 2
Qu'est-ce qu'une vtable?

A) Une table de variables
B) Une table de pointeurs vers les methodes du type concret
C) Une table de types
D) Une structure de donnees
E) Un allocateur

**Reponse correcte: B**

### Question 3
Quel trait n'est PAS object-safe?

A) `trait Foo { fn bar(&self); }`
B) `trait Foo { fn bar(&self) -> i32; }`
C) `trait Foo { fn bar(&self) -> Self; }`
D) `trait Foo { fn bar(&mut self); }`
E) `trait Foo { fn bar(self: Box<Self>); }`

**Reponse correcte: C**

### Question 4
Quelle est la taille de `Box<dyn Trait>` sur un systeme 64-bit?

A) 8 bytes
B) 16 bytes (2 pointeurs)
C) Depend du type concret
D) 0 bytes
E) 24 bytes

**Reponse correcte: B**

### Question 5
Quand preferer les trait objects aux generiques?

A) Toujours
B) Jamais
C) Quand les types sont inconnus a la compilation
D) Pour la performance
E) Pour la securite

**Reponse correcte: C**

---

## SECTION 8 : RECAPITULATIF

| Concept | Description | Exemple |
|---------|-------------|---------|
| dyn Trait | Trait object | `dyn Notifier` |
| Box<dyn Trait> | Owned trait object | `Box<dyn Notifier>` |
| &dyn Trait | Borrowed trait object | `&dyn Notifier` |
| vtable | Table de methodes | Pointeurs de fonctions |
| Object safety | Regles de compatibilite | Pas de Self, pas de generics |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "0.8.23",
  "name": "trait_objects",
  "version": "1.0.0",
  "language": "rust",
  "language_version": "edition2024",
  "files": {
    "submission": ["trait_objects.rs"],
    "test": ["test_trait_objects.rs"]
  },
  "compilation": {
    "compiler": "rustc",
    "flags": ["--edition", "2024", "-W", "warnings"],
    "output": "trait_objects"
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
  "concepts": ["dyn_trait", "box_dyn", "dynamic_dispatch", "object_safety", "vtable"]
}
```
