# Exercice 1.8.8-a : inception_testing

**Module :**
1.8.8 — Test Design Patterns & Best Practices

**Concept :**
a — AAA Pattern, Test Fixtures, Test Data Builders, Golden Testing, Snapshot Testing, Test Isolation

**Difficulte :**
★★★★★★★☆☆☆ (7/10)

**Type :**
complet

**Tiers :**
3 — Synthese (patterns de test + architecture testable + bonnes pratiques)

**Langage :**
Rust Edition 2024

**Prerequis :**
- Tests unitaires (Module 1.8.0)
- Mocking (Module 1.8.7)
- Property testing (Module 1.8.1)

**Domaines :**
Struct, Algo, MD

**Duree estimee :**
120 min

**XP Base :**
200

**Complexite :**
T4 O(n) test execution × S3 O(n) fixtures

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Categorie | Fichiers |
|-----------|----------|
| Patterns | `src/patterns.rs` (AAA, fixtures, builders) |
| Golden | `src/golden.rs` (golden/snapshot testing) |
| Isolation | `src/isolation.rs` (test isolation) |
| Framework | `src/framework.rs` (test framework utilities) |

---

### 1.2 Consigne

#### Section Culture : "Inception Testing"

**INCEPTION (2010) — "We need to go deeper."**

Dans Inception, Cobb et son equipe descendent dans des reves imbriques. Chaque niveau a ses propres regles, mais tous doivent etre coherents pour que la mission reussisse.

En testing, c'est pareil. Chaque test est un "niveau" avec ses propres regles :

**Niveau 1 : Arrange (Setup)**
- Preparer les donnees
- Configurer les mocks
- Creer l'environnement

**Niveau 2 : Act (Execution)**
- Appeler la fonction testee
- Une seule action par test

**Niveau 3 : Assert (Verification)**
- Verifier le resultat
- Comparer avec l'attendu

**Le probleme ?** Si les niveaux sont mal isoles, les tests deviennent fragiles, lents, et interdependants.

```rust
// MAUVAIS: Tests couples
static mut SHARED_STATE: i32 = 0;

#[test]
fn test_a() {
    unsafe { SHARED_STATE = 1; }  // Modifie l'etat global
    // ...
}

#[test]
fn test_b() {
    // Resultat depend de l'ordre d'execution!
}

// BON: Tests isoles
#[test]
fn test_a() {
    let state = TestFixture::new();  // Etat local
    // ...
}
```

*"You mustn't be afraid to dream a little bigger, darling."* — Tes tests doivent etre ambitieux mais isoles.

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un **framework de patterns de test** comprenant :

**1. AAA Pattern Helper**
```rust
pub struct TestCase<S, R> {
    name: String,
    arrange: Box<dyn Fn() -> S>,
    act: Box<dyn Fn(&S) -> R>,
    assert: Box<dyn Fn(&R) -> bool>,
}

pub fn test_case<S, R>(name: &str) -> TestCaseBuilder<S, R>;
```

**2. Test Data Builder**
```rust
pub trait TestDataBuilder: Sized {
    fn new() -> Self;
    fn build(self) -> Self::Output;
}

pub struct UserBuilder {
    id: Option<u64>,
    name: Option<String>,
    email: Option<String>,
}

impl UserBuilder {
    pub fn with_id(self, id: u64) -> Self;
    pub fn with_name(self, name: &str) -> Self;
    pub fn with_email(self, email: &str) -> Self;
    pub fn build(self) -> User;
}
```

**3. Test Fixture**
```rust
pub trait TestFixture {
    fn setup() -> Self;
    fn teardown(self);
}

pub struct DatabaseFixture {
    connection: Connection,
    created_ids: Vec<u64>,
}

impl TestFixture for DatabaseFixture {
    fn setup() -> Self;
    fn teardown(self);  // Clean up created records
}
```

**4. Golden/Snapshot Testing**
```rust
pub struct GoldenTest {
    name: String,
    golden_path: PathBuf,
}

impl GoldenTest {
    pub fn new(name: &str) -> Self;
    pub fn assert_matches(&self, actual: &str) -> Result<(), GoldenError>;
    pub fn update_golden(&self, content: &str) -> std::io::Result<()>;
}

pub enum GoldenError {
    Mismatch { expected: String, actual: String, diff: String },
    GoldenNotFound { path: PathBuf },
}
```

**5. Test Isolation Manager**
```rust
pub struct IsolationManager {
    temp_dirs: Vec<PathBuf>,
    env_backup: HashMap<String, Option<String>>,
}

impl IsolationManager {
    pub fn new() -> Self;
    pub fn create_temp_dir(&mut self) -> PathBuf;
    pub fn set_env(&mut self, key: &str, value: &str);
    pub fn cleanup(self);  // Restore everything
}
```

---

### 1.3 Prototype

```rust
// src/patterns.rs
pub struct TestCaseBuilder<S, R> {
    name: String,
    arrange: Option<Box<dyn Fn() -> S>>,
    act: Option<Box<dyn Fn(&S) -> R>>,
    assert: Option<Box<dyn Fn(&R) -> bool>>,
}

impl<S, R> TestCaseBuilder<S, R> {
    pub fn arrange<F: Fn() -> S + 'static>(self, f: F) -> Self;
    pub fn act<F: Fn(&S) -> R + 'static>(self, f: F) -> Self;
    pub fn assert<F: Fn(&R) -> bool + 'static>(self, f: F) -> Self;
    pub fn run(self) -> TestResult;
}

// src/builders.rs
pub trait TestDataBuilder: Sized {
    type Output;
    fn new() -> Self;
    fn build(self) -> Self::Output;
}

#[derive(Default)]
pub struct UserBuilder {
    id: Option<u64>,
    name: Option<String>,
    email: Option<String>,
    role: Option<Role>,
}

pub struct User {
    pub id: u64,
    pub name: String,
    pub email: String,
    pub role: Role,
}

// src/fixtures.rs
pub trait TestFixture: Sized {
    type Context;
    fn setup() -> (Self, Self::Context);
    fn teardown(self);
}

// src/golden.rs
use std::path::PathBuf;

pub struct GoldenTest {
    name: String,
    golden_dir: PathBuf,
}

#[derive(Debug)]
pub enum GoldenError {
    Mismatch { expected: String, actual: String },
    NotFound { path: PathBuf },
    IoError(std::io::Error),
}

impl GoldenTest {
    pub fn new(name: &str) -> Self;
    pub fn assert_matches(&self, actual: &str) -> Result<(), GoldenError>;
    pub fn update(&self, content: &str) -> Result<(), GoldenError>;
}

// src/isolation.rs
use std::collections::HashMap;
use std::path::PathBuf;

pub struct IsolationManager {
    temp_dirs: Vec<PathBuf>,
    env_backup: HashMap<String, Option<String>>,
}

impl IsolationManager {
    pub fn new() -> Self;
    pub fn temp_dir(&mut self) -> PathBuf;
    pub fn set_env(&mut self, key: &str, value: &str);
    pub fn unset_env(&mut self, key: &str);
}

impl Drop for IsolationManager {
    fn drop(&mut self);  // Auto-cleanup
}
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Anecdote

**Le Test Qui Echouait Uniquement Le Vendredi**

Une equipe avait un test qui echouait mysterieusement chaque vendredi. Apres investigation : le test dependait de la date du jour, et le vendredi etait le seul jour ou une certaine condition etait vraie.

**Probleme :** Le test n'etait pas isole du temps systeme.

**Solution :** Injecter le temps comme dependance :

```rust
trait Clock {
    fn now(&self) -> DateTime;
}

struct RealClock;
impl Clock for RealClock {
    fn now(&self) -> DateTime { Utc::now() }
}

struct FakeClock { fixed_time: DateTime }
impl Clock for FakeClock {
    fn now(&self) -> DateTime { self.fixed_time }
}
```

### 2.2 Fun Fact

Le pattern AAA (Arrange-Act-Assert) a ete popularise par Bill Wake en 2001. Il est aussi appele "Given-When-Then" dans le BDD (Behavior-Driven Development).

---

### 2.5 DANS LA VRAIE VIE

#### Staff Engineer chez Figma

**Cas d'usage : Golden testing pour UI**

Figma utilise le golden testing pour verifier que les rendus graphiques n'ont pas change :

```rust
#[test]
fn test_button_render() {
    let button = Button::new("Click me");
    let rendered = render_to_svg(&button);

    GoldenTest::new("button_default")
        .assert_matches(&rendered)
        .expect("Button render changed");
}
```

Quand le rendu change intentionnellement :
```bash
UPDATE_GOLDENS=1 cargo test
```

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo test
running 20 tests
test patterns::test_aaa_basic ... ok
test patterns::test_builder_user ... ok
test patterns::test_fixture_setup_teardown ... ok
test golden::test_match_existing ... ok
test golden::test_mismatch_detected ... ok
test isolation::test_temp_dir_cleaned ... ok
test isolation::test_env_restored ... ok
test integration::test_full_workflow ... ok

test result: ok. 20 passed; 0 failed

$ UPDATE_GOLDENS=1 cargo test
Golden files updated:
  - tests/golden/user_json.golden
  - tests/golden/report_html.golden
```

---

### 3.1 BONUS AVANCE

**Difficulte Bonus :** ★★★★★★★★★☆ (9/10)

**Consigne Bonus : "Parameterized Test Generator"**

Creer une macro qui genere des tests parametres :

```rust
#[parameterized_test]
#[case(1, 1, 2)]
#[case(0, 0, 0)]
#[case(-1, 1, 0)]
fn test_add(a: i32, b: i32, expected: i32) {
    assert_eq!(add(a, b), expected);
}

// Genere:
// #[test] fn test_add_case_0() { assert_eq!(add(1, 1), 2); }
// #[test] fn test_add_case_1() { assert_eq!(add(0, 0), 0); }
// #[test] fn test_add_case_2() { assert_eq!(add(-1, 1), 0); }
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| ID | Fonction | Input | Expected | Points |
|----|----------|-------|----------|--------|
| T01 | `TestCaseBuilder::run` | Valid AAA | TestResult::Pass | 10 |
| T02 | `UserBuilder::build` | Defaults | Valid User | 10 |
| T03 | `UserBuilder::build` | Custom values | Custom User | 10 |
| T04 | `TestFixture::teardown` | DB fixture | Records cleaned | 15 |
| T05 | `GoldenTest::assert_matches` | Match | Ok(()) | 15 |
| T06 | `GoldenTest::assert_matches` | Mismatch | Err(Mismatch) | 10 |
| T07 | `IsolationManager::drop` | Temp dirs | All deleted | 15 |
| T08 | `IsolationManager::drop` | Env vars | All restored | 15 |

---

### 4.3 Solution de reference

```rust
// src/patterns.rs
pub enum TestResult {
    Pass,
    Fail(String),
}

pub struct TestCaseBuilder<S, R> {
    name: String,
    arrange: Option<Box<dyn Fn() -> S>>,
    act: Option<Box<dyn Fn(&S) -> R>>,
    assert_fn: Option<Box<dyn Fn(&R) -> bool>>,
}

impl<S, R> TestCaseBuilder<S, R> {
    pub fn new(name: &str) -> Self {
        TestCaseBuilder {
            name: name.to_string(),
            arrange: None,
            act: None,
            assert_fn: None,
        }
    }

    pub fn arrange<F: Fn() -> S + 'static>(mut self, f: F) -> Self {
        self.arrange = Some(Box::new(f));
        self
    }

    pub fn act<F: Fn(&S) -> R + 'static>(mut self, f: F) -> Self {
        self.act = Some(Box::new(f));
        self
    }

    pub fn assert<F: Fn(&R) -> bool + 'static>(mut self, f: F) -> Self {
        self.assert_fn = Some(Box::new(f));
        self
    }

    pub fn run(self) -> TestResult {
        let arrange = self.arrange.expect("arrange not set");
        let act = self.act.expect("act not set");
        let assert_fn = self.assert_fn.expect("assert not set");

        let state = arrange();
        let result = act(&state);

        if assert_fn(&result) {
            TestResult::Pass
        } else {
            TestResult::Fail(format!("Test '{}' failed", self.name))
        }
    }
}

// src/builders.rs
#[derive(Default)]
pub struct UserBuilder {
    id: Option<u64>,
    name: Option<String>,
    email: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub id: u64,
    pub name: String,
    pub email: String,
}

impl UserBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_id(mut self, id: u64) -> Self {
        self.id = Some(id);
        self
    }

    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    pub fn with_email(mut self, email: &str) -> Self {
        self.email = Some(email.to_string());
        self
    }

    pub fn build(self) -> User {
        User {
            id: self.id.unwrap_or(1),
            name: self.name.unwrap_or_else(|| "Test User".to_string()),
            email: self.email.unwrap_or_else(|| "test@example.com".to_string()),
        }
    }
}

// src/golden.rs
use std::fs;
use std::path::PathBuf;

pub struct GoldenTest {
    name: String,
    golden_dir: PathBuf,
}

#[derive(Debug)]
pub enum GoldenError {
    Mismatch { expected: String, actual: String },
    NotFound { path: PathBuf },
    IoError(std::io::Error),
}

impl GoldenTest {
    pub fn new(name: &str) -> Self {
        GoldenTest {
            name: name.to_string(),
            golden_dir: PathBuf::from("tests/golden"),
        }
    }

    fn golden_path(&self) -> PathBuf {
        self.golden_dir.join(format!("{}.golden", self.name))
    }

    pub fn assert_matches(&self, actual: &str) -> Result<(), GoldenError> {
        let path = self.golden_path();

        if std::env::var("UPDATE_GOLDENS").is_ok() {
            return self.update(actual);
        }

        let expected = fs::read_to_string(&path)
            .map_err(|_| GoldenError::NotFound { path: path.clone() })?;

        if expected.trim() == actual.trim() {
            Ok(())
        } else {
            Err(GoldenError::Mismatch {
                expected,
                actual: actual.to_string(),
            })
        }
    }

    pub fn update(&self, content: &str) -> Result<(), GoldenError> {
        let path = self.golden_path();
        fs::create_dir_all(&self.golden_dir).map_err(GoldenError::IoError)?;
        fs::write(path, content).map_err(GoldenError::IoError)?;
        Ok(())
    }
}

// src/isolation.rs
use std::collections::HashMap;
use std::path::PathBuf;
use std::fs;

pub struct IsolationManager {
    temp_dirs: Vec<PathBuf>,
    env_backup: HashMap<String, Option<String>>,
}

impl IsolationManager {
    pub fn new() -> Self {
        IsolationManager {
            temp_dirs: Vec::new(),
            env_backup: HashMap::new(),
        }
    }

    pub fn temp_dir(&mut self) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("Failed to create temp dir");
        self.temp_dirs.push(dir.clone());
        dir
    }

    pub fn set_env(&mut self, key: &str, value: &str) {
        if !self.env_backup.contains_key(key) {
            self.env_backup.insert(key.to_string(), std::env::var(key).ok());
        }
        std::env::set_var(key, value);
    }

    pub fn unset_env(&mut self, key: &str) {
        if !self.env_backup.contains_key(key) {
            self.env_backup.insert(key.to_string(), std::env::var(key).ok());
        }
        std::env::remove_var(key);
    }

    fn cleanup(&mut self) {
        // Restore env vars
        for (key, value) in &self.env_backup {
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }

        // Remove temp dirs
        for dir in &self.temp_dirs {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

impl Drop for IsolationManager {
    fn drop(&mut self) {
        self.cleanup();
    }
}
```

---

### 4.10 Solutions Mutantes

```rust
// Mutant A: Builder n'utilise pas les valeurs custom
pub fn mutant_builder_ignores_custom(self) -> User {
    User {
        id: 1,  // BUG: ignore self.id
        name: "Default".to_string(),
        email: "default@test.com".to_string(),
    }
}

// Mutant B: Golden ne compare pas correctement
pub fn mutant_golden_always_pass(&self, _actual: &str) -> Result<(), GoldenError> {
    Ok(())  // BUG: ne compare jamais!
}

// Mutant C: Isolation ne restore pas les env vars
impl Drop for MutantIsolation {
    fn drop(&mut self) {
        // BUG: ne restore pas self.env_backup!
        for dir in &self.temp_dirs {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

// Mutant D: AAA execute dans le mauvais ordre
pub fn mutant_aaa_wrong_order(self) -> TestResult {
    let assert_fn = self.assert_fn.unwrap();
    let act = self.act.unwrap();
    let arrange = self.arrange.unwrap();

    let result = act(&arrange());  // BUG: assert avant act!
    if assert_fn(&result) {
        TestResult::Pass
    } else {
        TestResult::Fail("Failed".to_string())
    }
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Patterns de Test

| Pattern | Description | Quand l'utiliser |
|---------|-------------|------------------|
| **AAA** | Arrange-Act-Assert | Tout test |
| **Builder** | Construction flexible | Objets complexes |
| **Fixture** | Setup/teardown partage | Tests DB, fichiers |
| **Golden** | Comparaison avec reference | Outputs stables |
| **Snapshot** | Golden automatique | UI, serialization |

### 5.2 LDA

```
STRUCTURE TestCaseBuilder
    METHODE run QUI RETOURNE TestResult
    DEBUT
        DECLARER state COMME RESULTAT DE arrange()
        DECLARER result COMME RESULTAT DE act(state)
        SI assert(result) EST VRAI ALORS
            RETOURNER Pass
        SINON
            RETOURNER Fail
        FIN SI
    FIN
```

### 5.3 Visualisation

```
AAA Pattern Flow
================

    ┌─────────────┐
    │   ARRANGE   │  Setup: Create test data
    │             │  - Build objects
    │  Setup      │  - Configure mocks
    │  Context    │  - Prepare environment
    └──────┬──────┘
           │
           v
    ┌─────────────┐
    │     ACT     │  Execute: Call the function
    │             │  - ONE action only
    │  Execute    │  - Capture result
    │  Function   │
    └──────┬──────┘
           │
           v
    ┌─────────────┐
    │   ASSERT    │  Verify: Check expectations
    │             │  - Compare result
    │  Verify     │  - Validate side effects
    │  Result     │  - Clean up (optional)
    └─────────────┘
```

---

## SECTION 6 : PIEGES

| # | Piege | Solution |
|---|-------|----------|
| 1 | Tests couples | Isoler avec fixtures |
| 2 | Golden outdated | CI avec UPDATE_GOLDENS |
| 3 | Builder trop permissif | Valider dans build() |
| 4 | Fixture leak | Utiliser Drop |
| 5 | Multiple acts par test | Un act = un test |

---

## SECTION 7 : QCM

**Q1:** Que signifie AAA ?

A) Assert-Act-Arrange
B) Arrange-Act-Assert
C) Act-Assert-Arrange
D) Arrange-Assert-Act

**Reponse:** B

**Q2:** Quand utiliser le golden testing ?

A) Pour tester la performance
B) Pour comparer avec une sortie de reference stable
C) Pour generer des donnees de test
D) Pour isoler les tests

**Reponse:** B

---

## SECTION 8 : RECAPITULATIF

| # | Concept | Maitrise |
|---|---------|----------|
| a | AAA Pattern | [ ] |
| b | Test Data Builder | [ ] |
| c | Test Fixture | [ ] |
| d | Golden Testing | [ ] |
| e | Snapshot Testing | [ ] |
| f | Test Isolation | [ ] |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "exercise_slug": "1.8.8-a-inception-testing",
    "metadata": {
      "exercise_id": "1.8.8-a",
      "module": "1.8.8",
      "difficulty": 7,
      "xp_base": 200,
      "meme_reference": "INCEPTION - We need to go deeper"
    }
  }
}
```

---

**FIN DE L'EXERCICE 1.8.8-a : inception_testing**
