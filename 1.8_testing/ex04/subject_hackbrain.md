# Exercice 1.8.5-a : the_need_for_speed

**Module :**
1.8.5 — Benchmarking & Performance Testing

**Concept :**
a — Criterion Benchmarks, Memory Profiling, Flamegraphs, Performance Regression Detection, Statistical Analysis

**Difficulte :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
complet

**Tiers :**
2 — Combinaison (techniques de benchmarking + analyse statistique + detection de regressions)

**Langage :**
Rust Edition 2024

**Prerequis :**
- Tests unitaires de base (Module 1.8.0)
- Comprehension de la complexite algorithmique (Module 1.1)
- Bases de statistiques (moyenne, ecart-type, percentiles)

**Domaines :**
Algo, Sys, MD

**Duree estimee :**
120 min

**XP Base :**
180

**Complexite :**
T4 O(n log n) × S2 O(1) auxiliaire

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Categorie | Fichiers |
|-----------|----------|
| Benchmarks | `benches/sorting_bench.rs` (benchmarks Criterion) |
| Library | `src/lib.rs` (algorithmes a benchmarker) |
| Analysis | `src/analysis.rs` (analyse statistique) |
| Regression | `src/regression.rs` (detection de regressions) |
| Config | `Cargo.toml` (dependances Criterion) |

**Fonctions autorisees :**
- Rust : `criterion`, `std::time`, `std::hint::black_box`
- Statistiques : calculs manuels ou `statrs` crate

**Fonctions interdites :**
- Benchmarks naifs avec `Instant::now()` seul (trop imprecis)
- `std::thread::sleep` dans les benchmarks

---

### 1.2 Consigne

#### Section Culture : "The Need for Speed"

**TOP GUN (1986) — "I feel the need... the need for speed!"**

Maverick et Goose le savaient : en competition, chaque milliseconde compte. En programmation, c'est pareil.

Tu as ecrit un algorithme. Il fonctionne. Les tests passent. Mais est-il **rapide** ?

"Ca tourne" n'est pas suffisant. "Ca tourne en 50ms au lieu de 500ms" change tout :
- Un serveur qui repond en 50ms au lieu de 500ms supporte **10x plus de requetes**
- Un jeu qui tourne a 60 FPS au lieu de 6 FPS est **jouable**
- Un algorithme O(n log n) au lieu de O(n2) passe de 10 heures a 10 secondes sur n=10^7

**Le probleme ?** Mesurer la performance est **difficile**.

- Le CPU a des caches qui faussent les mesures
- L'OS interrompt ton programme pour d'autres taches
- Le compilateur optimise differemment selon le contexte
- La variance entre executions peut etre enorme

**La solution ?** Des outils statistiques rigoureux. Criterion. Flamegraphs. Analyse de regression.

*"Talk to me, Goose."*
*"The benchmark says we're 15% faster than the previous version, Mav."*
*"Then let's push it."*

---

#### Section Academique : Enonce Formel

**Ta mission :**

Implementer une **suite de benchmarks complete** comprenant :

**1. Benchmarks Criterion (4 fonctions)**
```rust
// Dans benches/sorting_bench.rs
fn benchmark_sorting(c: &mut Criterion);
fn benchmark_searching(c: &mut Criterion);
fn benchmark_parameterized(c: &mut Criterion);
fn benchmark_comparison(c: &mut Criterion);
```

**2. Analyse Statistique (3 fonctions)**
```rust
pub fn compute_statistics(samples: &[f64]) -> BenchStats;
pub fn detect_outliers(samples: &[f64], threshold: f64) -> Vec<usize>;
pub fn confidence_interval(samples: &[f64], confidence: f64) -> (f64, f64);
```

**3. Detection de Regression (3 fonctions)**
```rust
pub fn compare_runs(baseline: &BenchStats, current: &BenchStats) -> Comparison;
pub fn detect_regression(comparison: &Comparison, threshold: f64) -> bool;
pub fn generate_report(comparisons: &[Comparison]) -> Report;
```

**Structures de donnees :**
```rust
pub struct BenchStats {
    pub mean: f64,
    pub std_dev: f64,
    pub median: f64,
    pub min: f64,
    pub max: f64,
    pub p95: f64,
    pub p99: f64,
    pub sample_count: usize,
}

pub struct Comparison {
    pub name: String,
    pub baseline: BenchStats,
    pub current: BenchStats,
    pub change_percent: f64,
    pub is_significant: bool,
}

pub struct Report {
    pub comparisons: Vec<Comparison>,
    pub regressions: Vec<String>,
    pub improvements: Vec<String>,
    pub unchanged: Vec<String>,
}
```

**Sortie attendue :**
- Benchmarks executables via `cargo bench`
- Rapport de comparaison textuel
- Detection automatique des regressions > 5%

**Contraintes :**
- Minimum 100 echantillons par benchmark
- Warm-up obligatoire avant mesures
- Utiliser `black_box()` pour empecher les optimisations
- Gerer les outliers (> 3 ecarts-types)

---

### 1.3 Prototype

```rust
// src/lib.rs
pub mod sorting;
pub mod searching;
pub mod analysis;
pub mod regression;

// src/analysis.rs
#[derive(Debug, Clone)]
pub struct BenchStats {
    pub mean: f64,
    pub std_dev: f64,
    pub median: f64,
    pub min: f64,
    pub max: f64,
    pub p95: f64,
    pub p99: f64,
    pub sample_count: usize,
}

pub fn compute_statistics(samples: &[f64]) -> BenchStats;
pub fn detect_outliers(samples: &[f64], threshold: f64) -> Vec<usize>;
pub fn confidence_interval(samples: &[f64], confidence: f64) -> (f64, f64);

// src/regression.rs
#[derive(Debug)]
pub struct Comparison {
    pub name: String,
    pub baseline: BenchStats,
    pub current: BenchStats,
    pub change_percent: f64,
    pub is_significant: bool,
}

#[derive(Debug)]
pub struct Report {
    pub comparisons: Vec<Comparison>,
    pub regressions: Vec<String>,
    pub improvements: Vec<String>,
    pub unchanged: Vec<String>,
}

pub fn compare_runs(baseline: &BenchStats, current: &BenchStats) -> Comparison;
pub fn detect_regression(comparison: &Comparison, threshold: f64) -> bool;
pub fn generate_report(comparisons: &[Comparison]) -> Report;

// benches/sorting_bench.rs
use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};

fn benchmark_sorting(c: &mut Criterion);
fn benchmark_searching(c: &mut Criterion);
fn benchmark_parameterized(c: &mut Criterion);
fn benchmark_comparison(c: &mut Criterion);

criterion_group!(benches, benchmark_sorting, benchmark_searching);
criterion_main!(benches);
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Anecdote Historique

**Le Bug de Performance de Knight Capital (2012) — 440 Millions en 45 Minutes**

Le 1er aout 2012, Knight Capital a deploye une mise a jour de son systeme de trading. Un bug de performance a cause l'envoi de millions d'ordres errones en 45 minutes.

**Cout :** 440 millions de dollars de pertes.

**Cause technique :** Un ancien code de test n'avait pas ete supprime. Ce code, concu pour simuler des ordres lents, s'est active en production. Aucun benchmark n'avait detecte que le systeme pouvait generer 10x plus d'ordres que prevu.

**Lecon :** Les benchmarks ne sont pas optionnels. Un changement "mineur" peut avoir des consequences catastrophiques sur la performance. Knight Capital a fait faillite peu apres.

---

### 2.2 Fun Fact

**Pourquoi Criterion utilise des statistiques bayesiennes ?**

Criterion, le framework de benchmarking Rust, utilise une approche statistique sophistiquee :

1. **Bootstrap resampling** — Estime la distribution des temps sans supposer une loi normale
2. **Intervalles de confiance** — Donne une plage, pas juste une moyenne
3. **Detection de changement** — Compare statistiquement deux runs

**Pourquoi ?** Parce que les temps d'execution ne suivent PAS une distribution normale :
- Interruptions OS (spikes)
- Cache misses (variance elevee)
- Garbage collection (pauses)

Moyenne seule = **mensonge statistique**. Criterion montre median, ecart-type, et percentiles.

---

### 2.5 DANS LA VRAIE VIE

#### Performance Engineer chez Discord

**Cas d'usage : Detection de regression sur chaque PR**

Discord traite des milliards de messages par jour. Une regression de 5% sur une fonction critique = des milliers de serveurs en plus.

```yaml
# .github/workflows/benchmark.yml
name: Performance Regression Check

on: [pull_request]

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run benchmarks
        run: cargo bench -- --save-baseline pr-${{ github.event.number }}
      - name: Compare with main
        run: |
          cargo bench -- --baseline main --save-baseline pr-${{ github.event.number }}
          # Fail if regression > 5%
```

**Resultat :** Aucune regression de performance n'atteint la production. Chaque PR est validee automatiquement.

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo bench
   Compiling the_need_for_speed v0.1.0
    Finished bench [optimized] target(s) in 2.34s
     Running benches/sorting_bench.rs

sorting/merge_sort/1000 time:   [45.234 us 45.891 us 46.612 us]
                        change: [-1.2% +0.5% +2.1%] (p = 0.42 > 0.05)
                        No change in performance detected.

sorting/quick_sort/1000 time:   [32.156 us 32.789 us 33.401 us]
                        change: [-0.8% +0.1% +1.0%] (p = 0.78 > 0.05)
                        No change in performance detected.

sorting/insertion_sort/1000
                        time:   [234.12 us 238.45 us 242.89 us]
                        change: [+12.3% +15.1% +18.2%] (p = 0.00 < 0.05)
                        Performance has REGRESSED.

searching/binary_search/1000
                        time:   [89.23 ns 91.45 ns 93.78 ns]

Benchmarking sorting/comparison: Collecting 100 samples in estimated 5.0s
sorting/comparison      time:   [comparative analysis...]

$ cargo test --lib
running 12 tests
test analysis::test_compute_statistics ... ok
test analysis::test_detect_outliers ... ok
test analysis::test_confidence_interval ... ok
test regression::test_compare_runs ... ok
test regression::test_detect_regression_positive ... ok
test regression::test_detect_regression_negative ... ok
test regression::test_generate_report ... ok
test integration::test_full_pipeline ... ok

test result: ok. 12 passed; 0 failed
```

---

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★★★☆☆ (8/10)

**Recompense :**
XP x3

**Domaines Bonus :**
`Sys, Infra, MD`

#### 3.1.1 Consigne Bonus

**BONUS : "Flamegraph Profiler"**

Implementer un **profileur avec flamegraphs** :

1. **Instrumentation automatique** — Wrapper qui mesure chaque fonction
2. **Generation de flamegraph** — Sortie SVG interactive
3. **Analyse de hotspots** — Identifier les fonctions les plus couteuses

```rust
pub struct Profiler {
    samples: Vec<StackSample>,
}

pub struct StackSample {
    stack: Vec<String>,  // Noms des fonctions
    duration: Duration,
}

impl Profiler {
    pub fn start_function(&mut self, name: &str);
    pub fn end_function(&mut self);
    pub fn generate_flamegraph(&self) -> String;  // SVG
    pub fn top_hotspots(&self, n: usize) -> Vec<(String, f64)>;  // (name, % time)
}
```

#### 3.1.2 Prototype Bonus

```rust
pub struct Profiler { /* ... */ }
pub struct StackSample { /* ... */ }

impl Profiler {
    pub fn new() -> Self;
    pub fn start_function(&mut self, name: &str);
    pub fn end_function(&mut self);
    pub fn generate_flamegraph(&self) -> String;
    pub fn top_hotspots(&self, n: usize) -> Vec<(String, f64)>;
}

// Macro pour instrumentation automatique
#[macro_export]
macro_rules! profile {
    ($profiler:expr, $name:expr, $body:block) => {{
        $profiler.start_function($name);
        let result = $body;
        $profiler.end_function();
        result
    }};
}
```

#### 3.1.3 Ce qui change par rapport a l'exercice de base

| Aspect | Base | Bonus |
|--------|------|-------|
| Mesure | Temps total | Stack traces complets |
| Sortie | Texte | SVG interactif |
| Analyse | Statistiques | Hotspots hierarchiques |
| Complexite | O(n) samples | O(n * depth) |

---

## SECTION 4 : ZONE CORRECTION (POUR LE TESTEUR)

### 4.1 Moulinette — Tableau des tests

| ID | Fonction | Input | Expected | Points |
|----|----------|-------|----------|--------|
| T01 | `compute_statistics` | `[1.0, 2.0, 3.0, 4.0, 5.0]` | `mean=3.0, median=3.0` | 10 |
| T02 | `compute_statistics` | `[1.0, 1.0, 1.0, 100.0]` | `std_dev > 40` | 10 |
| T03 | `detect_outliers` | `[1,2,3,4,5,100]`, `threshold=2.0` | `[5]` (index of 100) | 10 |
| T04 | `confidence_interval` | 100 samples, 95% | Width < mean * 0.1 | 15 |
| T05 | `compare_runs` | baseline vs 10% slower | `change_percent ~ 10` | 15 |
| T06 | `detect_regression` | 10% slower, threshold 5% | `true` | 10 |
| T07 | `generate_report` | Mixed comparisons | Correct categorization | 15 |
| T08 | Benchmark execution | `cargo bench` | Completes without panic | 15 |

---

### 4.2 Tests unitaires (Rust)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_statistics_basic() {
        let samples = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let stats = compute_statistics(&samples);

        assert!((stats.mean - 3.0).abs() < 0.001);
        assert!((stats.median - 3.0).abs() < 0.001);
        assert!((stats.min - 1.0).abs() < 0.001);
        assert!((stats.max - 5.0).abs() < 0.001);
        assert_eq!(stats.sample_count, 5);
    }

    #[test]
    fn test_compute_statistics_std_dev() {
        let samples = vec![2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0];
        let stats = compute_statistics(&samples);

        // Mean = 5.0, Std Dev = 2.0
        assert!((stats.mean - 5.0).abs() < 0.001);
        assert!((stats.std_dev - 2.0).abs() < 0.1);
    }

    #[test]
    fn test_detect_outliers() {
        let samples = vec![1.0, 2.0, 3.0, 4.0, 5.0, 100.0];
        let outliers = detect_outliers(&samples, 2.0);

        assert_eq!(outliers, vec![5]);  // Index of 100.0
    }

    #[test]
    fn test_confidence_interval_95() {
        // Generate 1000 samples from known distribution
        let samples: Vec<f64> = (0..1000).map(|i| 100.0 + (i % 10) as f64).collect();
        let (lower, upper) = confidence_interval(&samples, 0.95);

        let stats = compute_statistics(&samples);
        assert!(lower < stats.mean);
        assert!(upper > stats.mean);
        assert!(upper - lower < stats.mean * 0.1);  // Reasonably tight
    }

    #[test]
    fn test_compare_runs_regression() {
        let baseline = BenchStats {
            mean: 100.0,
            std_dev: 5.0,
            median: 100.0,
            min: 90.0,
            max: 110.0,
            p95: 108.0,
            p99: 109.0,
            sample_count: 100,
        };

        let current = BenchStats {
            mean: 115.0,  // 15% slower
            std_dev: 5.0,
            median: 115.0,
            min: 105.0,
            max: 125.0,
            p95: 123.0,
            p99: 124.0,
            sample_count: 100,
        };

        let comparison = compare_runs(&baseline, &current);

        assert!((comparison.change_percent - 15.0).abs() < 0.1);
        assert!(detect_regression(&comparison, 5.0));
    }

    #[test]
    fn test_generate_report() {
        let comparisons = vec![
            Comparison {
                name: "fast_func".to_string(),
                baseline: BenchStats { mean: 100.0, ..Default::default() },
                current: BenchStats { mean: 85.0, ..Default::default() },
                change_percent: -15.0,
                is_significant: true,
            },
            Comparison {
                name: "slow_func".to_string(),
                baseline: BenchStats { mean: 100.0, ..Default::default() },
                current: BenchStats { mean: 120.0, ..Default::default() },
                change_percent: 20.0,
                is_significant: true,
            },
        ];

        let report = generate_report(&comparisons);

        assert!(report.improvements.contains(&"fast_func".to_string()));
        assert!(report.regressions.contains(&"slow_func".to_string()));
    }
}
```

---

### 4.3 Solution de reference (Rust)

```rust
// src/analysis.rs
use std::cmp::Ordering;

#[derive(Debug, Clone, Default)]
pub struct BenchStats {
    pub mean: f64,
    pub std_dev: f64,
    pub median: f64,
    pub min: f64,
    pub max: f64,
    pub p95: f64,
    pub p99: f64,
    pub sample_count: usize,
}

pub fn compute_statistics(samples: &[f64]) -> BenchStats {
    if samples.is_empty() {
        return BenchStats::default();
    }

    let n = samples.len();

    // Mean
    let mean = samples.iter().sum::<f64>() / n as f64;

    // Standard deviation
    let variance = samples.iter()
        .map(|x| (x - mean).powi(2))
        .sum::<f64>() / n as f64;
    let std_dev = variance.sqrt();

    // Sort for percentiles
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));

    let median = if n % 2 == 0 {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    };

    let percentile = |p: f64| -> f64 {
        let idx = ((n - 1) as f64 * p).round() as usize;
        sorted[idx.min(n - 1)]
    };

    BenchStats {
        mean,
        std_dev,
        median,
        min: sorted[0],
        max: sorted[n - 1],
        p95: percentile(0.95),
        p99: percentile(0.99),
        sample_count: n,
    }
}

pub fn detect_outliers(samples: &[f64], threshold: f64) -> Vec<usize> {
    let stats = compute_statistics(samples);

    samples.iter()
        .enumerate()
        .filter(|(_, &x)| (x - stats.mean).abs() > threshold * stats.std_dev)
        .map(|(i, _)| i)
        .collect()
}

pub fn confidence_interval(samples: &[f64], confidence: f64) -> (f64, f64) {
    let stats = compute_statistics(samples);
    let n = samples.len() as f64;

    // Z-score for confidence level (approximation)
    let z = match confidence {
        c if (c - 0.90).abs() < 0.01 => 1.645,
        c if (c - 0.95).abs() < 0.01 => 1.96,
        c if (c - 0.99).abs() < 0.01 => 2.576,
        _ => 1.96,  // Default to 95%
    };

    let margin = z * stats.std_dev / n.sqrt();

    (stats.mean - margin, stats.mean + margin)
}
```

```rust
// src/regression.rs
use crate::analysis::BenchStats;

#[derive(Debug)]
pub struct Comparison {
    pub name: String,
    pub baseline: BenchStats,
    pub current: BenchStats,
    pub change_percent: f64,
    pub is_significant: bool,
}

#[derive(Debug)]
pub struct Report {
    pub comparisons: Vec<Comparison>,
    pub regressions: Vec<String>,
    pub improvements: Vec<String>,
    pub unchanged: Vec<String>,
}

pub fn compare_runs(baseline: &BenchStats, current: &BenchStats) -> Comparison {
    let change_percent = ((current.mean - baseline.mean) / baseline.mean) * 100.0;

    // Simple significance test: is change > 2 std devs?
    let pooled_std = ((baseline.std_dev.powi(2) + current.std_dev.powi(2)) / 2.0).sqrt();
    let is_significant = (current.mean - baseline.mean).abs() > 2.0 * pooled_std;

    Comparison {
        name: String::new(),
        baseline: baseline.clone(),
        current: current.clone(),
        change_percent,
        is_significant,
    }
}

pub fn detect_regression(comparison: &Comparison, threshold: f64) -> bool {
    comparison.change_percent > threshold && comparison.is_significant
}

pub fn generate_report(comparisons: &[Comparison]) -> Report {
    let mut regressions = Vec::new();
    let mut improvements = Vec::new();
    let mut unchanged = Vec::new();

    for comp in comparisons {
        if comp.change_percent > 5.0 && comp.is_significant {
            regressions.push(comp.name.clone());
        } else if comp.change_percent < -5.0 && comp.is_significant {
            improvements.push(comp.name.clone());
        } else {
            unchanged.push(comp.name.clone());
        }
    }

    Report {
        comparisons: comparisons.to_vec(),
        regressions,
        improvements,
        unchanged,
    }
}
```

---

### 4.4 Solutions alternatives acceptees

```rust
// Alternative 1: Using welford's online algorithm for statistics
pub fn compute_statistics_welford(samples: &[f64]) -> BenchStats {
    let mut mean = 0.0;
    let mut m2 = 0.0;
    let mut count = 0.0;

    for &x in samples {
        count += 1.0;
        let delta = x - mean;
        mean += delta / count;
        let delta2 = x - mean;
        m2 += delta * delta2;
    }

    let variance = m2 / count;
    // ... rest same
}

// Alternative 2: Bootstrap confidence interval
pub fn confidence_interval_bootstrap(samples: &[f64], confidence: f64, iterations: usize) -> (f64, f64) {
    use rand::seq::SliceRandom;
    let mut rng = rand::thread_rng();

    let mut means: Vec<f64> = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let bootstrap: Vec<f64> = (0..samples.len())
            .map(|_| *samples.choose(&mut rng).unwrap())
            .collect();
        means.push(bootstrap.iter().sum::<f64>() / bootstrap.len() as f64);
    }

    means.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let alpha = (1.0 - confidence) / 2.0;
    let lower_idx = (iterations as f64 * alpha) as usize;
    let upper_idx = (iterations as f64 * (1.0 - alpha)) as usize;

    (means[lower_idx], means[upper_idx])
}
```

---

### 4.5 Solutions refusees (avec explications)

```rust
// REFUSE 1: Benchmark naif sans warm-up
fn bad_benchmark() -> Duration {
    let start = Instant::now();
    do_work();  // Premier appel = cache froid!
    start.elapsed()
}
// Pourquoi refuse: Le premier appel est toujours plus lent (cache miss, JIT, etc.)

// REFUSE 2: Moyenne sans gestion des outliers
fn bad_statistics(samples: &[f64]) -> f64 {
    samples.iter().sum::<f64>() / samples.len() as f64
}
// Pourquoi refuse: Un seul outlier (GC pause, interruption OS) fausse tout

// REFUSE 3: Comparaison sans test de significativite
fn bad_compare(old: f64, new: f64) -> bool {
    new > old  // "Plus lent donc regression"
}
// Pourquoi refuse: La variance peut expliquer la difference, pas un vrai changement

// REFUSE 4: Benchmark sans black_box
fn bad_bench_no_blackbox() {
    let result = pure_function(input);
    // Resultat non utilise = compilateur peut eliminer l'appel!
}
// Pourquoi refuse: Le compilateur peut optimiser le code mesure

// REFUSE 5: Echantillon trop petit
fn bad_sample_size(samples: &[f64]) -> BenchStats {
    assert!(samples.len() >= 3);  // 3 echantillons suffisent ?
    // Non! Minimum 30 pour le theoreme central limite, 100+ recommande
}
```

---

### 4.6 Solution bonus de reference (Rust)

```rust
// Profiler avec flamegraph
use std::time::{Duration, Instant};
use std::collections::HashMap;

pub struct Profiler {
    stack: Vec<(String, Instant)>,
    samples: Vec<StackSample>,
}

pub struct StackSample {
    pub stack: Vec<String>,
    pub duration: Duration,
}

impl Profiler {
    pub fn new() -> Self {
        Profiler {
            stack: Vec::new(),
            samples: Vec::new(),
        }
    }

    pub fn start_function(&mut self, name: &str) {
        self.stack.push((name.to_string(), Instant::now()));
    }

    pub fn end_function(&mut self) {
        if let Some((name, start)) = self.stack.pop() {
            let duration = start.elapsed();
            let stack: Vec<String> = self.stack.iter()
                .map(|(n, _)| n.clone())
                .chain(std::iter::once(name))
                .collect();

            self.samples.push(StackSample { stack, duration });
        }
    }

    pub fn generate_flamegraph(&self) -> String {
        // Aggregate by stack
        let mut stacks: HashMap<String, u64> = HashMap::new();

        for sample in &self.samples {
            let key = sample.stack.join(";");
            let micros = sample.duration.as_micros() as u64;
            *stacks.entry(key).or_insert(0) += micros;
        }

        // Generate folded stacks format (for flamegraph.pl)
        let mut output = String::new();
        for (stack, count) in stacks {
            output.push_str(&format!("{} {}\n", stack, count));
        }
        output
    }

    pub fn top_hotspots(&self, n: usize) -> Vec<(String, f64)> {
        let mut function_times: HashMap<String, u64> = HashMap::new();
        let mut total_time: u64 = 0;

        for sample in &self.samples {
            if let Some(func) = sample.stack.last() {
                let micros = sample.duration.as_micros() as u64;
                *function_times.entry(func.clone()).or_insert(0) += micros;
                total_time += micros;
            }
        }

        let mut sorted: Vec<_> = function_times.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));

        sorted.into_iter()
            .take(n)
            .map(|(name, time)| (name, time as f64 / total_time as f64 * 100.0))
            .collect()
    }
}

#[macro_export]
macro_rules! profile {
    ($profiler:expr, $name:expr, $body:block) => {{
        $profiler.start_function($name);
        let result = $body;
        $profiler.end_function();
        result
    }};
}
```

---

### 4.9 spec.json (ENGINE v22.1)

```json
{
  "exercise_id": "1.8.5-a",
  "title": "the_need_for_speed",
  "module": "1.8.5",
  "difficulty": 6,
  "languages": ["rust"],
  "time_limit_seconds": 300,
  "memory_limit_mb": 256,
  "test_cases": [
    {
      "id": "T01",
      "function": "compute_statistics",
      "input": {"samples": [1.0, 2.0, 3.0, 4.0, 5.0]},
      "expected": {"mean": 3.0, "median": 3.0, "min": 1.0, "max": 5.0},
      "points": 10
    },
    {
      "id": "T02",
      "function": "detect_outliers",
      "input": {"samples": [1.0, 2.0, 3.0, 4.0, 5.0, 100.0], "threshold": 2.0},
      "expected": [5],
      "points": 10
    },
    {
      "id": "T05",
      "function": "compare_runs",
      "input": {
        "baseline": {"mean": 100.0, "std_dev": 5.0},
        "current": {"mean": 115.0, "std_dev": 5.0}
      },
      "expected": {"change_percent_approx": 15.0},
      "points": 15
    }
  ],
  "grading": {
    "correctness": 70,
    "performance": 15,
    "style": 15
  }
}
```

---

### 4.10 Solutions Mutantes (minimum 5)

```rust
// Mutant A (Boundary): Off-by-one dans le calcul du median
pub fn mutant_median_boundary(samples: &[f64]) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = sorted.len();

    sorted[n / 2]  // BUG: Pour n pair, devrait etre moyenne de [n/2-1] et [n/2]
}

// Mutant B (Logic): Ecart-type avec n au lieu de n-1 (biais)
pub fn mutant_std_dev_biased(samples: &[f64]) -> f64 {
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let variance = samples.iter()
        .map(|x| (x - mean).powi(2))
        .sum::<f64>() / samples.len() as f64;  // Devrait etre n-1 pour echantillon
    variance.sqrt()
}

// Mutant C (Safety): Division par zero non geree
pub fn mutant_div_zero(samples: &[f64]) -> BenchStats {
    let n = samples.len() as f64;
    BenchStats {
        mean: samples.iter().sum::<f64>() / n,  // CRASH si samples vide!
        ..Default::default()
    }
}

// Mutant D (Regression): Seuil inverse (amelioration detectee comme regression)
pub fn mutant_threshold_inverted(comparison: &Comparison, threshold: f64) -> bool {
    comparison.change_percent < -threshold  // BUG: < au lieu de >
}

// Mutant E (Statistical): Pas de test de significativite
pub fn mutant_no_significance(baseline: &BenchStats, current: &BenchStats) -> Comparison {
    let change_percent = ((current.mean - baseline.mean) / baseline.mean) * 100.0;
    Comparison {
        name: String::new(),
        baseline: baseline.clone(),
        current: current.clone(),
        change_percent,
        is_significant: true,  // BUG: Toujours significatif!
    }
}

// Mutant F (Percentile): Mauvais calcul du percentile
pub fn mutant_percentile_wrong(samples: &[f64], p: f64) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let idx = (sorted.len() as f64 * p) as usize;  // BUG: devrait etre (n-1) * p
    sorted[idx]
}
```

---

## SECTION 5 : COMPRENDRE (DOCUMENT DE COURS COMPLET)

### 5.1 Ce que cet exercice enseigne

**Concepts fondamentaux :**

| # | Concept | Description |
|---|---------|-------------|
| 1 | Benchmarking statistique | Mesure rigoureuse avec intervalles de confiance |
| 2 | Criterion framework | Outil standard pour Rust |
| 3 | black_box | Empecher les optimisations du compilateur |
| 4 | Warm-up | Preparer les caches avant mesure |
| 5 | Detection de regression | Comparer statistiquement deux versions |
| 6 | Outlier detection | Identifier et gerer les mesures aberrantes |
| 7 | Percentiles | p50, p95, p99 pour caracteriser la distribution |
| 8 | Confidence intervals | Quantifier l'incertitude de la mesure |

---

### 5.2 LDA — Traduction litterale en MAJUSCULES

```
FONCTION compute_statistics QUI RETOURNE BenchStats ET PREND PARAMETRE samples COMME TABLEAU DE FLOTTANTS
DEBUT FONCTION
    SI samples EST VIDE ALORS
        RETOURNER BenchStats PAR DEFAUT
    FIN SI

    DECLARER n COMME LONGUEUR DE samples

    DECLARER mean COMME SOMME DE samples DIVISEE PAR n

    DECLARER variance COMME SOMME DE (x MOINS mean) AU CARRE POUR CHAQUE x DANS samples DIVISEE PAR n
    DECLARER std_dev COMME RACINE CARREE DE variance

    DECLARER sorted COMME COPIE TRIEE DE samples

    SI n EST PAIR ALORS
        DECLARER median COMME MOYENNE DE sorted[n/2-1] ET sorted[n/2]
    SINON
        DECLARER median COMME sorted[n/2]
    FIN SI

    RETOURNER BenchStats AVEC mean, std_dev, median, sorted[0], sorted[n-1], percentile(0.95), percentile(0.99), n
FIN FONCTION

FONCTION detect_regression QUI RETOURNE BOOLEEN ET PREND comparison ET threshold
DEBUT FONCTION
    SI comparison.change_percent EST SUPERIEUR A threshold ET comparison.is_significant ALORS
        RETOURNER VRAI
    SINON
        RETOURNER FAUX
    FIN SI
FIN FONCTION
```

---

### 5.3 Visualisation ASCII

```
Distribution des temps de benchmark (1000 echantillons)
======================================================

                         median
                           v
    |          ****       |***        |
    |        ********     |*****      |
    |      ***********    |*******    |
    |    **************   |*********  |
    |  *****************  |********** |
    +----+----+----+----+----+----+----+
        45   50   55   60   65   70   75  (microseconds)
         ^              ^         ^
        p5           mean       p95

    Outliers: 2 echantillons > 100us (GC pauses)

    Stats:
    - Mean:   58.3 us
    - Median: 56.1 us  (median < mean = distribution skewed right)
    - Std:    8.2 us
    - p95:    71.5 us
    - p99:    78.2 us
```

```
Flamegraph (simplifie)
======================

100% |====================================================|
     |           main                                      |
     |====================================================|
 85% |     |============================================|  |
     |     |          sort_function                     |  |
     |     |============================================|  |
 60% |     |   |================================|       |  |
     |     |   |       partition                |       |  |
     |     |   |================================|       |  |
 25% |     |   |     |==============|           |       |  |
     |     |   |     |   compare    |           |       |  |
     +-----+---+-----+--------------+-----------+-------+--+

     Hotspot: partition() consomme 60% du temps
     Action: Optimiser la fonction de comparaison
```

---

### 5.4 Diagramme de flux

```
Workflow de benchmarking CI/CD
==============================

    [Git Push]
        |
        v
    [CI Pipeline]
        |
        v
    +-------------------+
    | 1. Build optimise |
    |    (--release)    |
    +-------------------+
        |
        v
    +-------------------+
    | 2. Warm-up        |
    |    (10 iterations)|
    +-------------------+
        |
        v
    +-------------------+
    | 3. Collect samples|
    |    (100+ runs)    |
    +-------------------+
        |
        v
    +-------------------+
    | 4. Compute stats  |
    |    mean, p95, etc |
    +-------------------+
        |
        v
    +-------------------+
    | 5. Load baseline  |
    |    (from cache)   |
    +-------------------+
        |
        v
    +-------------------+
    | 6. Compare        |
    |    statistical    |
    +-------------------+
        |
        v
    +-------------+     +----------------+
    | Regression? |---->| FAIL: Block PR |
    | (> 5%)      | Yes +----------------+
    +-------------+
        | No
        v
    +----------------+
    | PASS: Save     |
    | as new baseline|
    +----------------+
```

---

### 5.5 Criterion cheatsheet

```rust
// Cargo.toml
[dev-dependencies]
criterion = "0.5"

[[bench]]
name = "my_benchmark"
harness = false

// benches/my_benchmark.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};

// Benchmark simple
fn bench_simple(c: &mut Criterion) {
    c.bench_function("fibonacci_20", |b| {
        b.iter(|| fibonacci(black_box(20)))
    });
}

// Benchmark parametre
fn bench_with_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("sorting");

    for size in [100, 1000, 10000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            |b, &size| {
                let mut data: Vec<i32> = (0..size).rev().collect();
                b.iter(|| sort(black_box(&mut data)))
            }
        );
    }

    group.finish();
}

// Comparaison d'algorithmes
fn bench_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("sort_comparison");
    let data: Vec<i32> = (0..10000).rev().collect();

    group.bench_function("merge_sort", |b| {
        b.iter(|| merge_sort(black_box(&data.clone())))
    });

    group.bench_function("quick_sort", |b| {
        b.iter(|| quick_sort(black_box(&data.clone())))
    });

    group.finish();
}

criterion_group!(benches, bench_simple, bench_with_sizes, bench_comparison);
criterion_main!(benches);
```

---

### 5.6 Formules mathematiques

```
Statistiques de base
====================

Moyenne (mean):
    x̄ = (1/n) * Σ(xi)

Ecart-type (standard deviation):
    σ = √[(1/n) * Σ(xi - x̄)²]

Ecart-type echantillon (sample std dev, sans biais):
    s = √[(1/(n-1)) * Σ(xi - x̄)²]

Intervalle de confiance 95%:
    IC = x̄ ± 1.96 * (σ / √n)

Percentile p:
    index = floor((n-1) * p)
    Pp = sorted[index]

Detection d'outlier (z-score):
    z = (x - x̄) / σ
    Outlier si |z| > 3

Comparaison (changement %):
    change = ((new - old) / old) * 100%

Test de significativite (t-test simplifie):
    t = (x̄₁ - x̄₂) / √(s₁²/n₁ + s₂²/n₂)
    Significatif si |t| > 2 (approximation)
```

---

### 5.8 Mnemoniques

#### SPEED — Les 5 etapes du benchmark

- **S**ample suffisamment (100+ mesures)
- **P**repare le cache (warm-up)
- **E**limine les outliers (> 3σ)
- **E**value statistiquement (median, p95)
- **D**etecte les regressions (> 5%)

#### BLACK_BOX — Pourquoi l'utiliser

```
B - Bloque les optimisations
L - Le compilateur ne peut pas eliminer
A - Assure que le code est execute
C - Cache les resultats pour le compilateur
K - Keep it real (mesure reelle)

B - Bench sans black_box = mensonge
O - Optimiseur voit tout
X - Xecute rien si resultat non utilise
```

---

## SECTION 6 : PIEGES

| # | Piege | Consequence | Solution |
|---|-------|-------------|----------|
| 1 | Pas de warm-up | Premier run 10x plus lent | Minimum 10 iterations de warm-up |
| 2 | Pas de black_box | Compilateur elimine le code | `black_box(result)` |
| 3 | Echantillon trop petit | Variance enorme | Minimum 100 echantillons |
| 4 | Ignorer les outliers | Moyenne faussee | Utiliser median ou filtrer > 3σ |
| 5 | Build en debug | 10-100x plus lent | Toujours `--release` |
| 6 | Comparer moyennes seules | Ignore la variance | Utiliser test statistique |
| 7 | Mesurer avec Instant::now() seul | Imprecision | Utiliser Criterion |
| 8 | Turbo boost CPU variable | Resultats non reproductibles | Desactiver ou moyenner |

---

## SECTION 7 : QCM

**Question 1:** Pourquoi utiliser `black_box()` dans un benchmark ?

A) Pour cacher le code aux autres developpeurs
B) Pour empecher le compilateur d'optimiser le code mesure
C) Pour accelerer l'execution du benchmark
D) Pour mesurer la memoire au lieu du temps

**Reponse:** B — Sans black_box, le compilateur peut eliminer du code dont le resultat n'est pas utilise.

---

**Question 2:** Combien d'echantillons minimum pour un benchmark fiable ?

A) 3
B) 10
C) 30
D) 100+

**Reponse:** D — 100+ echantillons permettent une bonne estimation statistique. Criterion utilise 100 par defaut.

---

**Question 3:** Quelle metrique utiliser si la distribution a des outliers ?

A) Moyenne (mean)
B) Maximum
C) Median
D) Minimum

**Reponse:** C — Le median est robuste aux outliers, contrairement a la moyenne.

---

**Question 4:** Un benchmark montre +3% de temps. Est-ce une regression ?

A) Oui, toujours
B) Non, jamais
C) Depend du test de significativite
D) Depend du jour de la semaine

**Reponse:** C — 3% peut etre dans la variance normale. Il faut un test statistique pour conclure.

---

**Question 5:** Pourquoi faire un warm-up avant les mesures ?

A) Pour chauffer le CPU physiquement
B) Pour remplir les caches et stabiliser les mesures
C) Pour fatiguer le CPU
D) Pour detecter les bugs

**Reponse:** B — Le premier run a des cache misses, le warm-up met le systeme dans un etat stable.

---

## SECTION 8 : RECAPITULATIF

**Concepts maitrises (8) :**

| # | Concept | Description | Maitrise |
|---|---------|-------------|----------|
| a | Criterion | Framework de benchmarking Rust | [ ] |
| b | black_box | Empecher optimisations | [ ] |
| c | Warm-up | Stabiliser les caches | [ ] |
| d | Statistiques | mean, median, std_dev, p95 | [ ] |
| e | Outliers | Detection et filtrage | [ ] |
| f | Confidence intervals | Quantifier l'incertitude | [ ] |
| g | Regression detection | Comparer deux versions | [ ] |
| h | CI integration | Automatiser les benchmarks | [ ] |

**Commandes essentielles :**

```bash
# Lancer les benchmarks
cargo bench

# Sauvegarder une baseline
cargo bench -- --save-baseline main

# Comparer avec une baseline
cargo bench -- --baseline main

# Benchmark specifique
cargo bench -- sorting

# Profiling avec flamegraph
cargo flamegraph --bench my_benchmark
```

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "exercise_slug": "1.8.5-a-the-need-for-speed",
    "metadata": {
      "exercise_id": "1.8.5-a",
      "module": "1.8.5",
      "concept": "a",
      "difficulty": 6,
      "xp_base": 180,
      "xp_bonus_multiplier": 3,
      "estimated_time_minutes": 120,
      "tier": 2,
      "domains": ["Algo", "Sys", "MD"],
      "prerequisites": ["1.8.0", "1.1"],
      "bonus_icon": "flame",
      "meme_reference": "TOP GUN - I feel the need for speed"
    },
    "files": {
      "template": ["src/lib.rs", "src/analysis.rs", "src/regression.rs", "benches/sorting_bench.rs", "Cargo.toml"],
      "solution": ["solutions/analysis.rs", "solutions/regression.rs"],
      "tests": ["tests/analysis_tests.rs", "tests/regression_tests.rs"]
    },
    "grading": {
      "automated_tests": 70,
      "benchmark_execution": 15,
      "code_style": 15
    },
    "ci": {
      "timeout_seconds": 300,
      "memory_limit_mb": 256,
      "required_commands": ["cargo test", "cargo bench"]
    }
  }
}
```

---

**FIN DE L'EXERCICE 1.8.5-a : the_need_for_speed**
