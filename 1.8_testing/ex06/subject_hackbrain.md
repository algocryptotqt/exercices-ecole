# Exercice 1.8.7-a : the_puppet_master

**Module :**
1.8.7 — Mocking, Stubs & Test Doubles

**Concept :**
a — Mocks, Stubs, Fakes, Spies, Dependency Injection, Trait-Based Mocking

**Difficulte :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
complet

**Tiers :**
2 — Combinaison (test doubles + dependency injection + verification comportementale)

**Langage :**
Rust Edition 2024

**Prerequis :**
- Traits et generiques (Module 1.1)
- Tests unitaires (Module 1.8.0)
- Ownership et lifetimes

**Domaines :**
Struct, Algo, MD

**Duree estimee :**
100 min

**XP Base :**
170

**Complexite :**
T3 O(1) mock × S2 O(n) enregistrements

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Categorie | Fichiers |
|-----------|----------|
| Mocking | `src/mock.rs` (framework de mocking) |
| Stubs | `src/stub.rs` (implementations de stubs) |
| DI | `src/di.rs` (dependency injection) |
| Examples | `src/examples.rs` (cas d'usage) |

**Fonctions autorisees :**
- Rust : `std::collections::*`, `std::sync::*`
- Pas de crate mockall (tu implementes ton propre systeme)

---

### 1.2 Consigne

#### Section Culture : "The Puppet Master"

**GHOST IN THE SHELL (1995) — "I am not an AI. My code name is Project 2501. I am a living, thinking entity."**

Le Puppet Master controle les corps des autres. En testing, tu fais pareil : tu controles le comportement des dependances.

**Le probleme du testing :**

```rust
struct PaymentService {
    gateway: RealPaymentGateway,  // Appelle vraiment Stripe!
}

#[test]
fn test_payment() {
    let service = PaymentService::new();
    service.process_payment(100.0);  // PROBLEME: charge vraiment 100 euros!
}
```

**La solution : Test Doubles**

| Type | Description | Utilisation |
|------|-------------|-------------|
| **Stub** | Retourne une valeur fixe | "Toujours retourner Ok" |
| **Mock** | Verifie les appels | "Doit etre appele 2 fois" |
| **Fake** | Implementation simplifiee | "DB en memoire" |
| **Spy** | Enregistre les appels | "Quels args ont ete passes?" |

```rust
trait PaymentGateway {
    fn charge(&self, amount: f64) -> Result<(), Error>;
}

struct MockGateway {
    expected_calls: Vec<f64>,
    call_count: usize,
}

impl PaymentGateway for MockGateway {
    fn charge(&self, amount: f64) -> Result<(), Error> {
        // Verifie que amount correspond a l'attendu
        // Incremente call_count
        Ok(())
    }
}
```

*"Your effort to remain what you are is what limits you."* — S'accrocher au code reel limite tes tests. Utilise des doubles.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un **framework de mocking** comprenant :

**1. Mock Builder**
```rust
pub struct MockBuilder<T> {
    expectations: Vec<Expectation>,
}

impl<T> MockBuilder<T> {
    pub fn expect_call(&mut self, method: &str) -> &mut Expectation;
    pub fn times(&mut self, n: usize) -> &mut Self;
    pub fn returning<R>(&mut self, value: R) -> &mut Self;
    pub fn build(self) -> Mock<T>;
}
```

**2. Verification System**
```rust
pub struct Mock<T> {
    expectations: Vec<Expectation>,
    calls: Vec<Call>,
}

impl<T> Mock<T> {
    pub fn verify(&self) -> Result<(), VerificationError>;
    pub fn was_called(&self, method: &str) -> bool;
    pub fn call_count(&self, method: &str) -> usize;
    pub fn calls_with_args(&self, method: &str) -> Vec<Vec<String>>;
}
```

**3. Spy Pattern**
```rust
pub struct Spy<T> {
    inner: T,
    calls: RefCell<Vec<Call>>,
}

impl<T> Spy<T> {
    pub fn wrap(inner: T) -> Self;
    pub fn get_calls(&self) -> Vec<Call>;
    pub fn clear_calls(&self);
}
```

**4. Dependency Injection Container**
```rust
pub struct Container {
    bindings: HashMap<TypeId, Box<dyn Any>>,
}

impl Container {
    pub fn bind<T: 'static>(&mut self, instance: T);
    pub fn resolve<T: 'static>(&self) -> Option<&T>;
}
```

---

### 1.3 Prototype

```rust
// src/mock.rs
use std::collections::HashMap;
use std::cell::RefCell;

#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub args: Vec<String>,
    pub timestamp: std::time::Instant,
}

#[derive(Debug)]
pub struct Expectation {
    pub method: String,
    pub times: Option<usize>,
    pub return_value: Option<String>,
}

pub struct MockBuilder<T> {
    expectations: Vec<Expectation>,
    _phantom: std::marker::PhantomData<T>,
}

pub struct Mock<T> {
    expectations: Vec<Expectation>,
    calls: RefCell<Vec<Call>>,
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug)]
pub enum VerificationError {
    ExpectedCallNotMade { method: String, expected: usize, actual: usize },
    UnexpectedCall { method: String },
}

impl<T> MockBuilder<T> {
    pub fn new() -> Self;
    pub fn expect_call(&mut self, method: &str) -> &mut Expectation;
    pub fn build(self) -> Mock<T>;
}

impl<T> Mock<T> {
    pub fn record_call(&self, method: &str, args: Vec<String>);
    pub fn verify(&self) -> Result<(), VerificationError>;
    pub fn was_called(&self, method: &str) -> bool;
    pub fn call_count(&self, method: &str) -> usize;
}

// src/stub.rs
pub trait Stubbable {
    type Stub;
    fn stub() -> Self::Stub;
}

// src/spy.rs
pub struct Spy<T> {
    inner: T,
    calls: RefCell<Vec<Call>>,
}

impl<T> Spy<T> {
    pub fn wrap(inner: T) -> Self;
    pub fn inner(&self) -> &T;
    pub fn get_calls(&self) -> Vec<Call>;
}

// src/di.rs
use std::any::{Any, TypeId};

pub struct Container {
    bindings: HashMap<TypeId, Box<dyn Any>>,
}

impl Container {
    pub fn new() -> Self;
    pub fn bind<T: 'static>(&mut self, instance: T);
    pub fn resolve<T: 'static>(&self) -> Option<&T>;
}
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Anecdote

**Le Test Qui A Coute 100 000 Euros**

Une equipe de developpement testait son integration Stripe sans mock. Un test automatise a ete lance en boucle pendant un week-end, effectuant 10 000 transactions reelles de 10 euros chacun.

Lundi matin : facture Stripe de 100 000 euros en frais de transaction.

**Lecon :** Toujours mocker les services externes en test.

### 2.2 Fun Fact

Rust n'a pas de reflection complete comme Java, ce qui rend le mocking plus difficile. La solution idiomatique : **trait-based mocking**.

```rust
// Au lieu de mocker une struct concrete...
trait Database {
    fn query(&self, sql: &str) -> Vec<Row>;
}

// ...on implemente le trait pour le mock
struct MockDatabase {
    responses: HashMap<String, Vec<Row>>,
}

impl Database for MockDatabase {
    fn query(&self, sql: &str) -> Vec<Row> {
        self.responses.get(sql).cloned().unwrap_or_default()
    }
}
```

---

### 2.5 DANS LA VRAIE VIE

#### Backend Engineer chez AWS

**Cas d'usage : Mocking S3 pour tests locaux**

```rust
trait ObjectStorage {
    fn put(&self, key: &str, data: &[u8]) -> Result<(), Error>;
    fn get(&self, key: &str) -> Result<Vec<u8>, Error>;
}

// Production
struct S3Storage { client: aws_sdk_s3::Client }

// Test
struct InMemoryStorage {
    data: RefCell<HashMap<String, Vec<u8>>>,
}

impl ObjectStorage for InMemoryStorage {
    fn put(&self, key: &str, data: &[u8]) -> Result<(), Error> {
        self.data.borrow_mut().insert(key.to_string(), data.to_vec());
        Ok(())
    }
    fn get(&self, key: &str) -> Result<Vec<u8>, Error> {
        self.data.borrow().get(key).cloned().ok_or(Error::NotFound)
    }
}
```

Tests locaux instantanes, sans AWS.

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo test
running 18 tests
test mock::test_expect_call ... ok
test mock::test_verify_success ... ok
test mock::test_verify_failure ... ok
test mock::test_call_count ... ok
test spy::test_wrap_and_record ... ok
test spy::test_get_calls ... ok
test di::test_bind_resolve ... ok
test integration::test_payment_with_mock ... ok

test result: ok. 18 passed; 0 failed
```

---

### 3.1 BONUS AVANCE

**Difficulte Bonus :** ★★★★★★★★☆☆ (8/10)

**Consigne Bonus : "Macro-Based Mocking"**

Creer une macro procedurale qui genere automatiquement les mocks :

```rust
#[automock]
trait PaymentGateway {
    fn charge(&self, amount: f64) -> Result<(), Error>;
    fn refund(&self, transaction_id: &str) -> Result<(), Error>;
}

// Genere automatiquement:
// struct MockPaymentGateway { ... }
// impl PaymentGateway for MockPaymentGateway { ... }
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| ID | Fonction | Input | Expected | Points |
|----|----------|-------|----------|--------|
| T01 | `MockBuilder::expect_call` | "process" | Expectation created | 10 |
| T02 | `Mock::verify` | All expectations met | Ok(()) | 15 |
| T03 | `Mock::verify` | Missing call | Err(ExpectedCallNotMade) | 15 |
| T04 | `Mock::call_count` | 3 calls | 3 | 10 |
| T05 | `Spy::get_calls` | Multiple calls | All recorded | 15 |
| T06 | `Container::resolve` | Bound type | Some(&T) | 10 |
| T07 | `Container::resolve` | Unbound type | None | 10 |

---

### 4.3 Solution de reference

```rust
// src/mock.rs
use std::cell::RefCell;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Call {
    pub method: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct Expectation {
    pub method: String,
    pub times: Option<usize>,
}

impl Expectation {
    pub fn new(method: &str) -> Self {
        Expectation {
            method: method.to_string(),
            times: None,
        }
    }

    pub fn times(&mut self, n: usize) -> &mut Self {
        self.times = Some(n);
        self
    }
}

pub struct MockBuilder<T> {
    expectations: Vec<Expectation>,
    _phantom: std::marker::PhantomData<T>,
}

impl<T> MockBuilder<T> {
    pub fn new() -> Self {
        MockBuilder {
            expectations: Vec::new(),
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn expect_call(&mut self, method: &str) -> &mut Expectation {
        self.expectations.push(Expectation::new(method));
        self.expectations.last_mut().unwrap()
    }

    pub fn build(self) -> Mock<T> {
        Mock {
            expectations: self.expectations,
            calls: RefCell::new(Vec::new()),
            _phantom: std::marker::PhantomData,
        }
    }
}

pub struct Mock<T> {
    expectations: Vec<Expectation>,
    calls: RefCell<Vec<Call>>,
    _phantom: std::marker::PhantomData<T>,
}

#[derive(Debug, PartialEq)]
pub enum VerificationError {
    ExpectedCallNotMade { method: String, expected: usize, actual: usize },
    UnexpectedCall { method: String },
}

impl<T> Mock<T> {
    pub fn record_call(&self, method: &str, args: Vec<String>) {
        self.calls.borrow_mut().push(Call {
            method: method.to_string(),
            args,
        });
    }

    pub fn was_called(&self, method: &str) -> bool {
        self.calls.borrow().iter().any(|c| c.method == method)
    }

    pub fn call_count(&self, method: &str) -> usize {
        self.calls.borrow().iter().filter(|c| c.method == method).count()
    }

    pub fn verify(&self) -> Result<(), VerificationError> {
        for exp in &self.expectations {
            let actual = self.call_count(&exp.method);
            if let Some(expected) = exp.times {
                if actual != expected {
                    return Err(VerificationError::ExpectedCallNotMade {
                        method: exp.method.clone(),
                        expected,
                        actual,
                    });
                }
            } else if actual == 0 {
                return Err(VerificationError::ExpectedCallNotMade {
                    method: exp.method.clone(),
                    expected: 1,
                    actual: 0,
                });
            }
        }
        Ok(())
    }
}

// src/spy.rs
pub struct Spy<T> {
    inner: T,
    calls: RefCell<Vec<Call>>,
}

impl<T> Spy<T> {
    pub fn wrap(inner: T) -> Self {
        Spy {
            inner,
            calls: RefCell::new(Vec::new()),
        }
    }

    pub fn inner(&self) -> &T {
        &self.inner
    }

    pub fn record(&self, method: &str, args: Vec<String>) {
        self.calls.borrow_mut().push(Call {
            method: method.to_string(),
            args,
        });
    }

    pub fn get_calls(&self) -> Vec<Call> {
        self.calls.borrow().clone()
    }

    pub fn clear(&self) {
        self.calls.borrow_mut().clear();
    }
}

// src/di.rs
use std::any::{Any, TypeId};
use std::collections::HashMap;

pub struct Container {
    bindings: HashMap<TypeId, Box<dyn Any>>,
}

impl Container {
    pub fn new() -> Self {
        Container {
            bindings: HashMap::new(),
        }
    }

    pub fn bind<T: 'static>(&mut self, instance: T) {
        self.bindings.insert(TypeId::of::<T>(), Box::new(instance));
    }

    pub fn resolve<T: 'static>(&self) -> Option<&T> {
        self.bindings
            .get(&TypeId::of::<T>())
            .and_then(|b| b.downcast_ref::<T>())
    }
}
```

---

### 4.10 Solutions Mutantes

```rust
// Mutant A: Ne verifie pas le nombre d'appels
pub fn mutant_verify_no_count(&self) -> Result<(), VerificationError> {
    Ok(())  // BUG: accepte tout!
}

// Mutant B: Oublie de clone les calls
pub fn mutant_spy_no_clone(&self) -> &Vec<Call> {
    &*self.calls.borrow()  // BUG: reference invalide apres drop
}

// Mutant C: Container resolve mauvais type
pub fn mutant_resolve_wrong<T: 'static>(&self) -> Option<&T> {
    self.bindings.values().next()
        .and_then(|b| b.downcast_ref::<T>())  // BUG: prend le premier, pas le bon
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Types de Test Doubles

| Type | Comportement | Verification |
|------|--------------|--------------|
| **Dummy** | Ne fait rien | Aucune |
| **Stub** | Retourne valeur fixe | Aucune |
| **Spy** | Enregistre appels | A posteriori |
| **Mock** | Verifie appels | Immediate/fin |
| **Fake** | Implementation simplifiee | Aucune |

### 5.2 LDA

```
FONCTION verify QUI RETOURNE Result
DEBUT
    POUR CHAQUE expectation DANS expectations FAIRE
        DECLARER actual COMME call_count(expectation.method)
        SI expectation.times EST DEFINI ALORS
            SI actual N'EGALE PAS expectation.times ALORS
                RETOURNER Err(ExpectedCallNotMade)
            FIN SI
        SINON SI actual EGALE 0 ALORS
            RETOURNER Err(ExpectedCallNotMade)
        FIN SI
    FIN POUR
    RETOURNER Ok(())
FIN
```

---

## SECTION 6 : PIEGES

| # | Piege | Solution |
|---|-------|----------|
| 1 | Mock trop rigide | Permettre flexibilite |
| 2 | Oublier verify() | Toujours appeler en fin de test |
| 3 | Spy sans clear | Reset entre tests |
| 4 | DI avec lifetimes | Utiliser 'static ou Arc |

---

## SECTION 7 : QCM

**Q1:** Quelle est la difference entre Mock et Stub ?

A) Mock retourne des valeurs, Stub verifie les appels
B) Stub retourne des valeurs, Mock verifie les appels
C) Aucune difference
D) Mock est pour les fonctions, Stub pour les structs

**Reponse:** B

---

## SECTION 8 : RECAPITULATIF

| # | Concept | Maitrise |
|---|---------|----------|
| a | Mocks | [ ] |
| b | Stubs | [ ] |
| c | Spies | [ ] |
| d | Fakes | [ ] |
| e | DI Container | [ ] |
| f | Trait-based mocking | [ ] |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "exercise_slug": "1.8.7-a-the-puppet-master",
    "metadata": {
      "exercise_id": "1.8.7-a",
      "module": "1.8.7",
      "difficulty": 6,
      "xp_base": 170,
      "meme_reference": "GHOST IN THE SHELL - Puppet Master"
    }
  }
}
```

---

**FIN DE L'EXERCICE 1.8.7-a : the_puppet_master**
