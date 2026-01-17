# Exercice 1.8.6-a : the_coverage_matrix

**Module :**
1.8.6 — Code Coverage & Quality Metrics

**Concept :**
a — Line Coverage, Branch Coverage, Path Coverage, Mutation Score, Coverage-Driven Testing

**Difficulte :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
complet

**Tiers :**
2 — Combinaison (metriques de couverture + analyse de qualite + generation de tests)

**Langage :**
Rust Edition 2024

**Prerequis :**
- Tests unitaires (Module 1.8.0)
- Property-based testing (Module 1.8.1)
- Comprehension du control flow (branches, loops)

**Domaines :**
Algo, Struct, MD

**Duree estimee :**
90 min

**XP Base :**
160

**Complexite :**
T3 O(n) analyse × S2 O(n) stockage AST

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Categorie | Fichiers |
|-----------|----------|
| Coverage | `src/coverage.rs` (analyse de couverture) |
| Metrics | `src/metrics.rs` (calcul des metriques) |
| Reporter | `src/reporter.rs` (generation de rapports) |
| Library | `src/lib.rs` (module principal) |

**Fonctions autorisees :**
- Rust : `std::collections::*`, manipulation de strings
- Pas de dependances externes pour la logique de couverture

**Fonctions interdites :**
- `llvm-cov` directement (tu implementes ta propre logique)

---

### 1.2 Consigne

#### Section Culture : "The Coverage Matrix"

**THE MATRIX (1999) — "I know kung fu." — "Show me."**

Neo telecharge instantanement des competences. Mais comment **prouver** qu'il les maitrise ? En les testant.

En programmation, tu peux dire "mon code est teste". Mais comment le **prouver** ?

La reponse : **la couverture de code**.

- **Line coverage** — Combien de lignes ont ete executees ?
- **Branch coverage** — Combien de branches (if/else) ont ete testees ?
- **Path coverage** — Combien de chemins d'execution possibles ont ete explores ?

**Le piege ?** 100% de line coverage ne garantit RIEN.

```rust
fn dangerous(x: i32) -> i32 {
    if x > 0 { return x * 2; }  // Teste avec x=5
    if x < 0 { return x / 2; }  // Teste avec x=-4
    x  // Jamais teste! (x=0)
}
// Line coverage: 100%
// Branch coverage: 66%
// Bug pour x=0? Peut-etre.
```

**La verite ?** La couverture est un **indicateur**, pas une **garantie**. Un code avec 80% de couverture et des tests pertinents est meilleur qu'un code avec 100% et des tests triviaux.

*"Unfortunately, no one can be told what coverage quality is. You have to see it for yourself."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer un **analyseur de couverture** qui :

**1. Parse le code source et identifie les elements couverts**
```rust
pub struct CodeElement {
    pub element_type: ElementType,
    pub line_start: usize,
    pub line_end: usize,
    pub covered: bool,
}

pub enum ElementType {
    Function,
    Branch,
    Line,
    Expression,
}
```

**2. Calcule les metriques de couverture**
```rust
pub struct CoverageReport {
    pub line_coverage: f64,        // % de lignes couvertes
    pub branch_coverage: f64,      // % de branches couvertes
    pub function_coverage: f64,    // % de fonctions appelees
    pub uncovered_lines: Vec<usize>,
    pub uncovered_branches: Vec<Branch>,
}

pub fn calculate_coverage(elements: &[CodeElement]) -> CoverageReport;
```

**3. Genere des rapports**
```rust
pub fn generate_html_report(report: &CoverageReport, source: &str) -> String;
pub fn generate_summary(report: &CoverageReport) -> String;
pub fn identify_gaps(report: &CoverageReport) -> Vec<TestSuggestion>;
```

**4. Simule l'execution de tests**
```rust
pub struct TestExecution {
    pub test_name: String,
    pub lines_hit: Vec<usize>,
    pub branches_taken: Vec<(usize, bool)>,  // (branch_id, taken_true)
}

pub fn merge_executions(executions: &[TestExecution]) -> CoverageData;
```

**Sortie attendue :**
- Analyse de couverture fonctionnelle
- Rapport textuel et HTML
- Suggestions de tests pour combler les lacunes

---

### 1.3 Prototype

```rust
// src/lib.rs
pub mod coverage;
pub mod metrics;
pub mod reporter;

// src/coverage.rs
#[derive(Debug, Clone)]
pub enum ElementType {
    Function,
    Branch,
    Line,
    Expression,
}

#[derive(Debug, Clone)]
pub struct CodeElement {
    pub element_type: ElementType,
    pub line_start: usize,
    pub line_end: usize,
    pub id: usize,
    pub covered: bool,
    pub hit_count: usize,
}

#[derive(Debug, Clone)]
pub struct Branch {
    pub line: usize,
    pub condition: String,
    pub true_taken: bool,
    pub false_taken: bool,
}

#[derive(Debug)]
pub struct TestExecution {
    pub test_name: String,
    pub lines_hit: Vec<usize>,
    pub branches_taken: Vec<(usize, bool)>,
}

pub fn parse_source(source: &str) -> Vec<CodeElement>;
pub fn merge_executions(executions: &[TestExecution]) -> CoverageData;

// src/metrics.rs
#[derive(Debug)]
pub struct CoverageReport {
    pub line_coverage: f64,
    pub branch_coverage: f64,
    pub function_coverage: f64,
    pub total_lines: usize,
    pub covered_lines: usize,
    pub total_branches: usize,
    pub covered_branches: usize,
    pub total_functions: usize,
    pub covered_functions: usize,
    pub uncovered_lines: Vec<usize>,
    pub uncovered_branches: Vec<Branch>,
}

pub fn calculate_coverage(elements: &[CodeElement], branches: &[Branch]) -> CoverageReport;

// src/reporter.rs
pub struct TestSuggestion {
    pub target: String,
    pub reason: String,
    pub priority: Priority,
}

pub enum Priority { High, Medium, Low }

pub fn generate_summary(report: &CoverageReport) -> String;
pub fn generate_html_report(report: &CoverageReport, source: &str) -> String;
pub fn identify_gaps(report: &CoverageReport) -> Vec<TestSuggestion>;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Anecdote Historique

**Le Bug de Therac-25 (1985-1987) — Quand la couverture ne suffit pas**

Le Therac-25 etait une machine de radiotherapie qui a tue 6 patients et en a blesse d'autres a cause de bugs logiciels.

**Le probleme ?** Le logiciel avait ete "teste" mais :
- Les race conditions n'etaient pas couvertes par les tests
- Certains chemins d'execution etaient impossibles a atteindre en test normal
- La couverture de code etait elevee, mais les tests ne simulaient pas les conditions reelles

**Lecon :** 100% de couverture ne detecte pas :
- Race conditions
- Problemes de timing
- Combinaisons d'inputs extremes
- Etats systeme anormaux

La couverture est necessaire mais pas suffisante.

---

### 2.2 Fun Fact

**Pourquoi Google vise 80% de couverture, pas 100% ?**

Chez Google, l'objectif est 80% de couverture, pas 100%. Pourquoi ?

Les 20% restants sont souvent :
- Code d'erreur rarement atteint (network failures, disk full)
- Branches defensives (qui ne devraient jamais etre atteintes)
- Code genere automatiquement

Atteindre 100% couterait plus cher en maintenance de tests que la valeur apportee.

**La regle Google :** "Teste ce qui est critique, pas ce qui est trivial."

---

### 2.5 DANS LA VRAIE VIE

#### Quality Engineer chez Stripe

**Cas d'usage : Coverage gates dans CI/CD**

Stripe traite des milliards de dollars. Chaque bug peut couter cher.

```yaml
# .github/workflows/coverage.yml
- name: Run tests with coverage
  run: cargo tarpaulin --out Xml

- name: Check coverage threshold
  run: |
    COVERAGE=$(grep -oP 'line-rate="\K[^"]+' coverage.xml)
    if (( $(echo "$COVERAGE < 0.80" | bc -l) )); then
      echo "Coverage $COVERAGE < 80%. Failing."
      exit 1
    fi
```

**Resultat :** Aucun code avec moins de 80% de couverture n'atteint la production.

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo test
running 15 tests
test coverage::test_parse_source ... ok
test coverage::test_identify_branches ... ok
test metrics::test_line_coverage ... ok
test metrics::test_branch_coverage ... ok
test metrics::test_function_coverage ... ok
test reporter::test_generate_summary ... ok
test reporter::test_identify_gaps ... ok
test integration::test_full_pipeline ... ok

test result: ok. 15 passed; 0 failed

$ cargo run --example analyze_coverage -- src/example.rs

Coverage Analysis for src/example.rs
====================================

Summary:
  Line Coverage:     85.7% (24/28 lines)
  Branch Coverage:   66.7% (4/6 branches)
  Function Coverage: 100.0% (3/3 functions)

Uncovered Lines:
  - Line 15: else branch of input validation
  - Line 22: error handling path
  - Line 25: panic recovery
  - Line 26: panic recovery

Uncovered Branches:
  - Line 10: condition `x < 0` (false branch not taken)
  - Line 18: condition `result.is_err()` (true branch not taken)

Test Suggestions:
  [HIGH] Add test for negative input (line 10)
  [HIGH] Add test for error case (line 18)
  [MEDIUM] Add test for empty input (line 15)
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★★★☆☆ (8/10)

**Recompense :**
XP x3

#### 3.1.1 Consigne Bonus

**BONUS : "Mutation Coverage Analyzer"**

Implementer un analyseur de **mutation coverage** :

```rust
pub struct Mutant {
    pub id: usize,
    pub location: (usize, usize),  // (line, column)
    pub original: String,
    pub mutated: String,
    pub mutation_type: MutationType,
    pub killed: bool,
}

pub enum MutationType {
    ArithmeticOperator,  // + -> -
    RelationalOperator,  // < -> <=
    LogicalOperator,     // && -> ||
    ConstantMutation,    // 0 -> 1
    ReturnMutation,      // return x -> return 0
}

pub fn generate_mutants(source: &str) -> Vec<Mutant>;
pub fn run_tests_against_mutant(mutant: &Mutant, tests: &[Test]) -> bool;  // killed?
pub fn calculate_mutation_score(mutants: &[Mutant]) -> f64;
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| ID | Fonction | Input | Expected | Points |
|----|----------|-------|----------|--------|
| T01 | `parse_source` | Simple function | Correct elements | 10 |
| T02 | `parse_source` | With branches | Branches identified | 10 |
| T03 | `calculate_coverage` | All covered | 100% | 10 |
| T04 | `calculate_coverage` | Half covered | 50% | 10 |
| T05 | `calculate_coverage` | With branches | Correct branch % | 15 |
| T06 | `generate_summary` | Mixed coverage | Correct format | 10 |
| T07 | `identify_gaps` | Low coverage | Suggestions generated | 15 |
| T08 | `merge_executions` | Multiple tests | Correct merge | 10 |
| T09 | `generate_html_report` | Full report | Valid HTML | 10 |

---

### 4.3 Solution de reference (Rust)

```rust
// src/coverage.rs
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq)]
pub enum ElementType {
    Function,
    Branch,
    Line,
    Expression,
}

#[derive(Debug, Clone)]
pub struct CodeElement {
    pub element_type: ElementType,
    pub line_start: usize,
    pub line_end: usize,
    pub id: usize,
    pub covered: bool,
    pub hit_count: usize,
}

#[derive(Debug, Clone)]
pub struct Branch {
    pub id: usize,
    pub line: usize,
    pub condition: String,
    pub true_taken: bool,
    pub false_taken: bool,
}

#[derive(Debug, Default)]
pub struct CoverageData {
    pub lines_hit: HashSet<usize>,
    pub branches_taken: Vec<(usize, bool)>,
    pub functions_called: HashSet<String>,
}

pub fn parse_source(source: &str) -> (Vec<CodeElement>, Vec<Branch>) {
    let mut elements = Vec::new();
    let mut branches = Vec::new();
    let mut element_id = 0;
    let mut branch_id = 0;

    for (line_num, line) in source.lines().enumerate() {
        let line_num = line_num + 1;  // 1-indexed
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }

        // Detect functions
        if trimmed.starts_with("fn ") || trimmed.starts_with("pub fn ") {
            elements.push(CodeElement {
                element_type: ElementType::Function,
                line_start: line_num,
                line_end: line_num,
                id: element_id,
                covered: false,
                hit_count: 0,
            });
            element_id += 1;
        }

        // Detect branches (if, else if, match arms)
        if trimmed.starts_with("if ") || trimmed.contains("} else if ") {
            let condition = extract_condition(trimmed);
            branches.push(Branch {
                id: branch_id,
                line: line_num,
                condition,
                true_taken: false,
                false_taken: false,
            });
            branch_id += 1;
        }

        // Every non-empty line is a line element
        elements.push(CodeElement {
            element_type: ElementType::Line,
            line_start: line_num,
            line_end: line_num,
            id: element_id,
            covered: false,
            hit_count: 0,
        });
        element_id += 1;
    }

    (elements, branches)
}

fn extract_condition(line: &str) -> String {
    if let Some(start) = line.find("if ") {
        let rest = &line[start + 3..];
        if let Some(end) = rest.find('{') {
            return rest[..end].trim().to_string();
        }
    }
    "unknown".to_string()
}

pub fn merge_executions(executions: &[TestExecution]) -> CoverageData {
    let mut data = CoverageData::default();

    for exec in executions {
        data.lines_hit.extend(&exec.lines_hit);
        data.branches_taken.extend(&exec.branches_taken);
    }

    data
}
```

```rust
// src/metrics.rs
use crate::coverage::{CodeElement, Branch, ElementType, CoverageData};

#[derive(Debug)]
pub struct CoverageReport {
    pub line_coverage: f64,
    pub branch_coverage: f64,
    pub function_coverage: f64,
    pub total_lines: usize,
    pub covered_lines: usize,
    pub total_branches: usize,
    pub covered_branches: usize,
    pub total_functions: usize,
    pub covered_functions: usize,
    pub uncovered_lines: Vec<usize>,
    pub uncovered_branches: Vec<Branch>,
}

pub fn calculate_coverage(
    elements: &[CodeElement],
    branches: &[Branch],
    data: &CoverageData,
) -> CoverageReport {
    // Line coverage
    let line_elements: Vec<_> = elements.iter()
        .filter(|e| e.element_type == ElementType::Line)
        .collect();
    let total_lines = line_elements.len();
    let covered_lines = line_elements.iter()
        .filter(|e| data.lines_hit.contains(&e.line_start))
        .count();

    // Function coverage
    let function_elements: Vec<_> = elements.iter()
        .filter(|e| e.element_type == ElementType::Function)
        .collect();
    let total_functions = function_elements.len();
    let covered_functions = function_elements.iter()
        .filter(|e| data.lines_hit.contains(&e.line_start))
        .count();

    // Branch coverage (both true and false must be taken)
    let total_branches = branches.len() * 2;  // Each branch has true/false
    let mut covered_branch_count = 0;
    for branch in branches {
        let true_taken = data.branches_taken.iter()
            .any(|(id, taken)| *id == branch.id && *taken);
        let false_taken = data.branches_taken.iter()
            .any(|(id, taken)| *id == branch.id && !*taken);
        if true_taken { covered_branch_count += 1; }
        if false_taken { covered_branch_count += 1; }
    }

    // Uncovered lines
    let uncovered_lines: Vec<usize> = line_elements.iter()
        .filter(|e| !data.lines_hit.contains(&e.line_start))
        .map(|e| e.line_start)
        .collect();

    // Uncovered branches
    let uncovered_branches: Vec<Branch> = branches.iter()
        .filter(|b| {
            let true_taken = data.branches_taken.iter()
                .any(|(id, taken)| *id == b.id && *taken);
            let false_taken = data.branches_taken.iter()
                .any(|(id, taken)| *id == b.id && !*taken);
            !true_taken || !false_taken
        })
        .cloned()
        .collect();

    CoverageReport {
        line_coverage: if total_lines > 0 {
            covered_lines as f64 / total_lines as f64 * 100.0
        } else { 100.0 },
        branch_coverage: if total_branches > 0 {
            covered_branch_count as f64 / total_branches as f64 * 100.0
        } else { 100.0 },
        function_coverage: if total_functions > 0 {
            covered_functions as f64 / total_functions as f64 * 100.0
        } else { 100.0 },
        total_lines,
        covered_lines,
        total_branches,
        covered_branches: covered_branch_count,
        total_functions,
        covered_functions,
        uncovered_lines,
        uncovered_branches,
    }
}
```

```rust
// src/reporter.rs
use crate::metrics::CoverageReport;
use crate::coverage::Branch;

#[derive(Debug)]
pub struct TestSuggestion {
    pub target: String,
    pub reason: String,
    pub priority: Priority,
}

#[derive(Debug)]
pub enum Priority { High, Medium, Low }

pub fn generate_summary(report: &CoverageReport) -> String {
    format!(
        "Coverage Summary\n\
         ================\n\
         Line Coverage:     {:.1}% ({}/{})\n\
         Branch Coverage:   {:.1}% ({}/{})\n\
         Function Coverage: {:.1}% ({}/{})\n",
        report.line_coverage, report.covered_lines, report.total_lines,
        report.branch_coverage, report.covered_branches, report.total_branches,
        report.function_coverage, report.covered_functions, report.total_functions,
    )
}

pub fn identify_gaps(report: &CoverageReport) -> Vec<TestSuggestion> {
    let mut suggestions = Vec::new();

    // High priority: uncovered branches
    for branch in &report.uncovered_branches {
        suggestions.push(TestSuggestion {
            target: format!("Line {}: {}", branch.line, branch.condition),
            reason: if !branch.true_taken {
                "True branch not tested".to_string()
            } else {
                "False branch not tested".to_string()
            },
            priority: Priority::High,
        });
    }

    // Medium priority: uncovered lines
    for &line in &report.uncovered_lines {
        suggestions.push(TestSuggestion {
            target: format!("Line {}", line),
            reason: "Line not executed".to_string(),
            priority: Priority::Medium,
        });
    }

    suggestions
}

pub fn generate_html_report(report: &CoverageReport, source: &str) -> String {
    let mut html = String::from(r#"<!DOCTYPE html>
<html><head><style>
.covered { background-color: #90EE90; }
.uncovered { background-color: #FFB6C1; }
pre { line-height: 1.5; }
</style></head><body>
<h1>Coverage Report</h1>
"#);

    html.push_str(&format!("<p>Line Coverage: {:.1}%</p>", report.line_coverage));
    html.push_str(&format!("<p>Branch Coverage: {:.1}%</p>", report.branch_coverage));

    html.push_str("<pre>");
    for (i, line) in source.lines().enumerate() {
        let line_num = i + 1;
        let class = if report.uncovered_lines.contains(&line_num) {
            "uncovered"
        } else {
            "covered"
        };
        html.push_str(&format!(
            "<span class=\"{}\">{:4} | {}</span>\n",
            class, line_num, html_escape(line)
        ));
    }
    html.push_str("</pre></body></html>");

    html
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
}
```

---

### 4.10 Solutions Mutantes

```rust
// Mutant A: Division par zero sur coverage vide
pub fn mutant_div_zero(total: usize, covered: usize) -> f64 {
    covered as f64 / total as f64 * 100.0  // CRASH si total = 0
}

// Mutant B: Off-by-one dans le comptage de lignes
pub fn mutant_line_count(source: &str) -> usize {
    source.lines().count() + 1  // BUG: +1 de trop
}

// Mutant C: Oublie une branche dans le calcul
pub fn mutant_branch_coverage(branches: &[Branch]) -> f64 {
    let covered = branches.iter()
        .filter(|b| b.true_taken)  // BUG: oublie false_taken!
        .count();
    covered as f64 / branches.len() as f64
}

// Mutant D: Mauvaise priorite des suggestions
pub fn mutant_wrong_priority() -> Priority {
    Priority::Low  // BUG: devrait etre High pour branches
}

// Mutant E: HTML non escape
pub fn mutant_no_escape(line: &str) -> String {
    line.to_string()  // BUG: <script> serait execute!
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Types de couverture

| Type | Description | Force | Faiblesse |
|------|-------------|-------|-----------|
| **Line** | % lignes executees | Simple | Ignore branches |
| **Branch** | % branches (if/else) | Teste decisions | Ignore combinaisons |
| **Path** | % chemins d'execution | Exhaustif | Explosion combinatoire |
| **Condition** | Chaque condition booleenne | Precis | Complexe |
| **MC/DC** | Modified Condition/Decision | Aviation/Medical | Tres couteux |

### 5.2 LDA

```
FONCTION calculate_coverage QUI RETOURNE CoverageReport
DEBUT
    DECLARER total_lines COMME COMPTE DES ELEMENTS DE TYPE LINE
    DECLARER covered_lines COMME COMPTE DES LINES DANS lines_hit

    DECLARER line_coverage COMME covered_lines DIVISE PAR total_lines FOIS 100

    POUR CHAQUE branch DANS branches FAIRE
        SI branch.id EST DANS branches_taken AVEC true ALORS
            INCREMENTER covered_branches
        FIN SI
        SI branch.id EST DANS branches_taken AVEC false ALORS
            INCREMENTER covered_branches
        FIN SI
    FIN POUR

    RETOURNER CoverageReport
FIN FONCTION
```

### 5.3 Visualisation

```
Source Code Coverage Map
========================

    fn calculate(x: i32, y: i32) -> i32 {
 1  [====] if x > 0 {                    // Branch 1
 2  [====]     if y > 0 {                // Branch 2 (nested)
 3  [====]         return x + y;
 4  [    ]     } else {                  // NOT COVERED
 5  [    ]         return x - y;         // NOT COVERED
 6  [====]     }
 7  [    ] } else {                      // NOT COVERED
 8  [    ]     return 0;                 // NOT COVERED
 9  [====] }
    }

Coverage:
  [====] = Covered
  [    ] = Not Covered

Analysis:
  Line Coverage: 55% (5/9)
  Branch Coverage: 33% (2/6 branches: B1-true, B2-true only)

Missing Tests:
  - Test with x > 0, y <= 0 (B2-false)
  - Test with x <= 0 (B1-false)
```

---

## SECTION 6 : PIEGES

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Viser 100% coverage | Tests inutiles, maintenance elevee | Viser 80% sur code critique |
| 2 | Ignorer branch coverage | Bugs dans les else | Toujours mesurer branches |
| 3 | Coverage sans assertions | Code execute mais pas verifie | Chaque test doit assert |
| 4 | Tests triviaux pour gonfler % | Fausse securite | Code review des tests |
| 5 | Oublier les erreurs | Happy path teste seulement | Tester les echecs |

---

## SECTION 7 : QCM

**Q1:** Un code a 100% de line coverage. Est-il sans bugs ?

A) Oui
B) Non
C) Seulement si les tests sont bons
D) Seulement en Rust

**Reponse:** B — La couverture ne garantit pas la qualite des assertions.

**Q2:** Quelle couverture est la plus forte ?

A) Line coverage
B) Branch coverage
C) Path coverage
D) Function coverage

**Reponse:** C — Path coverage teste toutes les combinaisons possibles.

---

## SECTION 8 : RECAPITULATIF

| # | Concept | Maitrise |
|---|---------|----------|
| a | Line coverage | [ ] |
| b | Branch coverage | [ ] |
| c | Function coverage | [ ] |
| d | Path coverage | [ ] |
| e | Mutation score | [ ] |
| f | Gap identification | [ ] |
| g | Report generation | [ ] |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "exercise_slug": "1.8.6-a-the-coverage-matrix",
    "metadata": {
      "exercise_id": "1.8.6-a",
      "module": "1.8.6",
      "difficulty": 6,
      "xp_base": 160,
      "meme_reference": "THE MATRIX - I know kung fu"
    }
  }
}
```

---

**FIN DE L'EXERCICE 1.8.6-a : the_coverage_matrix**
