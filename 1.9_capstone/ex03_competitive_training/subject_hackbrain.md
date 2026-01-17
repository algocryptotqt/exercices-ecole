# Exercice 1.9.3-synth : the_competitive_edge

**Module :**
1.9.3 — Competitive Programming Training

**Concept :**
synth — Speed Coding, Template Optimization, Time Management, Platform-Specific Techniques (Codeforces, LeetCode, AtCoder)

**Difficulte :**
★★★★★★★☆☆☆ (7/10)

**Type :**
complet

**Tiers :**
3 — Synthese (application pratique competitive programming)

**Langage :**
Rust Edition 2024

**Prerequis :**
- Tous les modules 1.1-1.7 (algorithmes et structures)
- Competition vs Production (1.9.0)
- Data Structures Review (1.9.1)
- Algorithms Review (1.9.2)

**Domaines :**
Algo, Struct, MD

**Duree estimee :**
180 min (3h simulated contest)

**XP Base :**
250

**Complexite :**
Variable selon problemes (T1-T6 × S1-S4)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**

| Categorie | Fichiers |
|-----------|----------|
| Template | `src/template.rs` (template de competition) |
| Fast I/O | `src/fast_io.rs` (I/O optimise) |
| Debug | `src/debug_macro.rs` (macro de debug) |
| Solutions | `src/problems/*.rs` (10 problemes resolus) |
| Stress | `src/stress_test.rs` (generateur de tests) |

---

### 1.2 Consigne

#### Section Culture : "The Competitive Edge"

**THE SOCIAL NETWORK (2010) — "You don't get to 500 million users without making a few enemies."**

Mark Zuckerberg a code Facebook en quelques semaines. Pourquoi ? Parce qu'il avait une **competitive edge** — une longueur d'avance.

En competitive programming, ta competitive edge c'est :
- Un **template** prepare a l'avance
- Une **bibliotheque** d'algorithmes prets a copier
- Une **discipline** de temps (ne pas bloquer sur un probleme)

**La realite des contests :**

| Plateforme | Duree | Problemes | Strategie |
|------------|-------|-----------|-----------|
| **Codeforces** | 2h | 5-6 | A,B rapide, C,D methodique |
| **LeetCode** | 1.5h | 4 | Easy 5min, Medium 15min, Hard 30min |
| **AtCoder** | 100min | 6 | A-C speedrun, D-F reflexion |

**Le secret ?** Tu ne "resous" pas les problemes pendant le contest. Tu **reconnais des patterns** et appliques des solutions connues.

*"We lived on farms, then we lived in cities, and now we're going to live on the internet."* — Tu vas vivre dans les contests.

---

#### Section Academique : Enonce Formel

**Ta mission :**

**1. Creer un Template de Competition Optimal**

```rust
// template.rs - Copie-colle pour chaque probleme
#![allow(unused_imports)]
use std::io::{self, BufRead, Write, BufWriter};
use std::collections::*;

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    // Fast input
    let mut input = stdin.lock().lines();
    macro_rules! read {
        ($t:ty) => { input.next().unwrap().unwrap().parse::<$t>().unwrap() };
        ($($t:ty),+) => { ($(read!($t)),+) };
    }

    // Solution here
}
```

**2. Implementer Fast I/O**

```rust
pub struct FastScanner<R: BufRead> {
    reader: R,
    buf: Vec<u8>,
    pos: usize,
}

impl<R: BufRead> FastScanner<R> {
    pub fn new(reader: R) -> Self;
    pub fn next<T: std::str::FromStr>(&mut self) -> T;
    pub fn next_line(&mut self) -> String;
}
```

**3. Resoudre 10 Problemes Classes**

| # | Categorie | Probleme | Difficulte |
|---|-----------|----------|------------|
| 1 | Greedy | Activity Selection | 800 |
| 2 | Binary Search | First Bad Version | 1000 |
| 3 | Two Pointers | Container With Most Water | 1200 |
| 4 | DP | Longest Increasing Subsequence | 1400 |
| 5 | Graph BFS | Shortest Path in Grid | 1200 |
| 6 | Graph DFS | Number of Islands | 1100 |
| 7 | Union-Find | Redundant Connection | 1300 |
| 8 | Segment Tree | Range Sum Query | 1500 |
| 9 | Math | Modular Exponentiation | 1400 |
| 10 | String | KMP Pattern Matching | 1600 |

**4. Implementer Stress Testing**

```rust
pub fn stress_test<F, G, T>(
    solution: F,
    brute: G,
    generator: impl Fn() -> T,
    iterations: usize,
) -> Option<T>
where
    F: Fn(&T) -> String,
    G: Fn(&T) -> String;
```

---

### 1.3 Prototype

```rust
// src/template.rs
pub const TEMPLATE: &str = r#"
#![allow(unused_imports, dead_code)]
use std::io::{self, BufRead, Write, BufWriter};
use std::collections::*;
use std::cmp::{min, max, Ordering};

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    let mut scanner = FastScanner::new(stdin.lock());

    // Solution
    solve(&mut scanner, &mut out);
}

fn solve<R: BufRead, W: Write>(scanner: &mut FastScanner<R>, out: &mut W) {
    // Your code here
}
"#;

// src/fast_io.rs
use std::io::BufRead;

pub struct FastScanner<R: BufRead> {
    reader: R,
    buffer: Vec<String>,
    pos: usize,
}

impl<R: BufRead> FastScanner<R> {
    pub fn new(reader: R) -> Self;
    pub fn next<T: std::str::FromStr>(&mut self) -> T where T::Err: std::fmt::Debug;
    pub fn next_vec<T: std::str::FromStr>(&mut self, n: usize) -> Vec<T> where T::Err: std::fmt::Debug;
}

// src/debug_macro.rs
#[macro_export]
macro_rules! dbg {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        eprintln!($($arg)*);
    };
}

// src/stress_test.rs
use rand::Rng;

pub fn stress_test<I, O, F, G, Gen>(
    solution: F,
    brute_force: G,
    generator: Gen,
    max_iterations: usize,
) -> Result<(), (I, O, O)>
where
    F: Fn(&I) -> O,
    G: Fn(&I) -> O,
    Gen: Fn() -> I,
    O: PartialEq + std::fmt::Debug,
    I: Clone + std::fmt::Debug;
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 Anecdote

**Gennady Korotkevich (tourist) — Le Plus Grand Competitive Programmer**

Gennady "tourist" Korotkevich est considere comme le meilleur competitive programmer de l'histoire. Ses stats :
- 7x champion du monde de l'ICPC (equipe)
- 2x champion Google Code Jam
- Rating Codeforces > 3900 (legendary grandmaster)

**Son secret ?** Il connait ~500 algorithmes par coeur et les applique en < 5 minutes chacun. Il ne "reflechit" pas pendant les contests — il reconnait des patterns.

### 2.2 Fun Fact

**Pourquoi les Russes dominent le CP ?**

La Russie et les pays de l'ex-URSS dominent le competitive programming. Raisons :
1. **Tradition mathematique** — Olympiades depuis les annees 1930
2. **Codeforces** — Cree par un Russe (Mike Mirzayanov)
3. **Culture** — CP est enseigne dans les ecoles

Le mot "Codeforces" vient de "Code" + "Forces" (puissance en russe).

---

### 2.5 DANS LA VRAIE VIE

#### Software Engineer chez Jane Street

**Cas d'usage : Recrutement base sur CP**

Jane Street (trading firm) recrute principalement via des puzzles algorithmiques. Leur processus :
1. Online assessment (problems style Codeforces)
2. Phone screen (live coding)
3. Onsite (5h de problemes)

Salaire d'entree : $400k+ (new grad)

Les meilleurs performers en CP ont un avantage significatif.

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ cargo test
running 15 tests
test template::test_compiles ... ok
test fast_io::test_parse_int ... ok
test fast_io::test_parse_vec ... ok
test problems::test_activity_selection ... ok
test problems::test_binary_search ... ok
test problems::test_two_pointers ... ok
test problems::test_lis ... ok
test problems::test_bfs_grid ... ok
test problems::test_dfs_islands ... ok
test problems::test_union_find ... ok
test problems::test_segment_tree ... ok
test problems::test_mod_exp ... ok
test problems::test_kmp ... ok
test stress::test_stress_sort ... ok

test result: ok. 15 passed; 0 failed

$ cargo run --release --bin stress -- 1000
Stress testing with 1000 iterations...
All tests passed!
```

---

### 3.1 BONUS AVANCE

**Difficulte Bonus :** ★★★★★★★★★☆ (9/10)

**Consigne Bonus : "Virtual Contest Simulator"**

Creer un simulateur de contest qui :
1. Presente des problemes avec timer
2. Verifie les solutions
3. Calcule le score selon les regles Codeforces

```rust
pub struct VirtualContest {
    problems: Vec<Problem>,
    time_limit: Duration,
    penalties: HashMap<usize, Vec<Duration>>,
}

impl VirtualContest {
    pub fn start(&mut self);
    pub fn submit(&mut self, problem_id: usize, solution: &str) -> Verdict;
    pub fn score(&self) -> ContestScore;
}
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| ID | Probleme | Input | Expected | Points |
|----|----------|-------|----------|--------|
| T01 | Activity Selection | Intervals | Max activities | 10 |
| T02 | Binary Search | Sorted array | Correct index | 10 |
| T03 | Two Pointers | Heights | Max water | 10 |
| T04 | LIS | Sequence | Length | 10 |
| T05 | BFS Grid | Grid | Shortest path | 10 |
| T06 | DFS Islands | Grid | Count | 10 |
| T07 | Union-Find | Edges | Redundant | 10 |
| T08 | Segment Tree | Queries | Sums | 10 |
| T09 | Mod Exp | Large n | Result | 10 |
| T10 | KMP | Pattern | Matches | 10 |

---

### 4.3 Solutions de reference (extraits)

```rust
// Activity Selection
pub fn activity_selection(activities: &[(i32, i32)]) -> Vec<usize> {
    let mut sorted: Vec<_> = activities.iter().enumerate().collect();
    sorted.sort_by_key(|(_, (_, end))| end);

    let mut result = vec![sorted[0].0];
    let mut last_end = sorted[0].1.1;

    for &(idx, (start, end)) in sorted.iter().skip(1) {
        if *start >= last_end {
            result.push(idx);
            last_end = *end;
        }
    }
    result
}

// LIS O(n log n)
pub fn lis(nums: &[i32]) -> usize {
    let mut tails = Vec::new();
    for &num in nums {
        let pos = tails.binary_search(&num).unwrap_or_else(|x| x);
        if pos == tails.len() {
            tails.push(num);
        } else {
            tails[pos] = num;
        }
    }
    tails.len()
}

// Number of Islands
pub fn num_islands(grid: &[Vec<char>]) -> i32 {
    let mut grid = grid.to_vec();
    let (m, n) = (grid.len(), grid[0].len());
    let mut count = 0;

    fn dfs(grid: &mut [Vec<char>], i: usize, j: usize) {
        if grid[i][j] != '1' { return; }
        grid[i][j] = '0';
        if i > 0 { dfs(grid, i - 1, j); }
        if i + 1 < grid.len() { dfs(grid, i + 1, j); }
        if j > 0 { dfs(grid, i, j - 1); }
        if j + 1 < grid[0].len() { dfs(grid, i, j + 1); }
    }

    for i in 0..m {
        for j in 0..n {
            if grid[i][j] == '1' {
                count += 1;
                dfs(&mut grid, i, j);
            }
        }
    }
    count
}

// Fast I/O
impl<R: BufRead> FastScanner<R> {
    pub fn new(reader: R) -> Self {
        FastScanner {
            reader,
            buffer: Vec::new(),
            pos: 0,
        }
    }

    pub fn next<T: std::str::FromStr>(&mut self) -> T
    where T::Err: std::fmt::Debug
    {
        loop {
            if self.pos < self.buffer.len() {
                let token = self.buffer[self.pos].clone();
                self.pos += 1;
                return token.parse().unwrap();
            }
            let mut line = String::new();
            self.reader.read_line(&mut line).unwrap();
            self.buffer = line.split_whitespace().map(String::from).collect();
            self.pos = 0;
        }
    }
}
```

---

### 4.10 Solutions Mutantes

```rust
// Mutant A: Activity selection sans tri
pub fn mutant_no_sort(activities: &[(i32, i32)]) -> Vec<usize> {
    // BUG: prend les activites dans l'ordre sans trier par end time
    let mut result = vec![0];
    let mut last_end = activities[0].1;
    for (idx, (start, _end)) in activities.iter().enumerate().skip(1) {
        if *start >= last_end { result.push(idx); }
    }
    result
}

// Mutant B: LIS avec mauvais binary_search
pub fn mutant_lis_wrong_search(nums: &[i32]) -> usize {
    let mut tails = Vec::new();
    for &num in nums {
        // BUG: utilise upper_bound au lieu de lower_bound
        let pos = tails.partition_point(|&x| x <= num);
        if pos == tails.len() { tails.push(num); }
        else { tails[pos] = num; }
    }
    tails.len()
}

// Mutant C: Islands ne marque pas visited
pub fn mutant_islands_infinite(grid: &[Vec<char>]) -> i32 {
    fn dfs(grid: &[Vec<char>], i: usize, j: usize) {
        // BUG: ne modifie pas grid -> boucle infinie
        if grid[i][j] != '1' { return; }
        // ...
    }
    // ...
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Patterns de Competition

| Pattern | Reconnaissance | Complexite |
|---------|---------------|------------|
| Greedy | "Maximum/minimum sous contrainte" | O(n log n) |
| DP | "Compter chemins/combiner sous-problemes" | O(n²) ou O(n×m) |
| Binary Search | "Trouver minimum X tel que..." | O(log n) |
| Two Pointers | "Paire dans array trie" | O(n) |
| BFS | "Plus court chemin non-pondere" | O(V+E) |
| DFS | "Composantes/cycle/exploration" | O(V+E) |
| Union-Find | "Groupes/composantes dynamiques" | O(α(n)) |

### 5.2 Time Management

```
Contest de 2h (Codeforces Div.2)
================================

0:00 - 0:05   Lire tous les problemes (A-E)
0:05 - 0:10   Resoudre A (trivial)
0:10 - 0:25   Resoudre B (implementation)
0:25 - 0:50   Resoudre C (algorithme standard)
0:50 - 1:30   Resoudre D (combinaison de techniques)
1:30 - 2:00   Tenter E ou debug

REGLE D'OR: Si bloque > 10min, passe au suivant!
```

---

## SECTION 6 : PIEGES

| # | Piege | Solution |
|---|-------|----------|
| 1 | Time Limit | O(n log n) au lieu de O(n²) |
| 2 | Memory Limit | Vec vs HashMap |
| 3 | Integer Overflow | Utiliser i64/u64 |
| 4 | Edge cases | Tester n=0, n=1 |
| 5 | Off-by-one | Verifier indices |

---

## SECTION 7 : QCM

**Q1:** Quelle complexite pour trier 10^6 elements en < 1s ?

A) O(n²)
B) O(n log n)
C) O(n)
D) O(2^n)

**Reponse:** B ou C — O(n²) = 10^12 operations = trop lent

**Q2:** Comment reconnaitre un probleme de DP ?

A) Il demande un chemin
B) Il a des sous-problemes qui se recoupent
C) Il demande de trier
D) Il a un graphe

**Reponse:** B

---

## SECTION 8 : RECAPITULATIF

| # | Competence | Maitrise |
|---|------------|----------|
| a | Template optimise | [ ] |
| b | Fast I/O | [ ] |
| c | Greedy problems | [ ] |
| d | DP problems | [ ] |
| e | Graph problems | [ ] |
| f | Binary search | [ ] |
| g | Stress testing | [ ] |
| h | Time management | [ ] |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "exercise_slug": "1.9.3-synth-the-competitive-edge",
    "metadata": {
      "exercise_id": "1.9.3-synth",
      "module": "1.9.3",
      "difficulty": 7,
      "xp_base": 250,
      "meme_reference": "THE SOCIAL NETWORK - Competitive Edge"
    }
  }
}
```

---

**FIN DE L'EXERCICE 1.9.3-synth : the_competitive_edge**
