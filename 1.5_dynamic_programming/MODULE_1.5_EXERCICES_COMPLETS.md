# MODULE 1.5 - DYNAMIC PROGRAMMING
## 150 Concepts - 16 Exercices Progressifs

---

# BLOC A: Fondamentaux DP (Exercices 01-04)

## Exercice 01: DP Foundations
**Concepts couverts**: 1.5.1.a-i (9 concepts)
**Difficulté**: ⭐⭐

### Objectif
Maîtriser les concepts fondamentaux de la programmation dynamique.

```rust
pub trait DPProblem {
    type State;
    type Answer;

    fn optimal_substructure(&self) -> bool;                   // 1.5.1.a
    fn has_overlapping_subproblems(&self) -> bool;            // 1.5.1.b
}

pub struct DPSolver<T: DPProblem> {
    memo: HashMap<T::State, T::Answer>,                       // 1.5.1.c (memoization)
    table: Vec<T::Answer>,                                    // 1.5.1.d (tabulation)
}

impl<T: DPProblem> DPSolver<T> {
    fn define_state(&self) -> String;                         // 1.5.1.e
    fn define_transition(&self) -> String;                    // 1.5.1.f
    fn base_cases(&self) -> Vec<(T::State, T::Answer)>;       // 1.5.1.g
    fn extract_answer(&self) -> T::Answer;                    // 1.5.1.h
    fn reconstruct_solution(&self) -> Vec<T::State>;          // 1.5.1.i
}

// Exemples classiques pour démontrer
pub fn fibonacci_memo(n: usize) -> u64;       // Top-down
pub fn fibonacci_table(n: usize) -> u64;      // Bottom-up
pub fn fibonacci_optimized(n: usize) -> u64;  // O(1) space
```

---

## Exercice 02: 1D DP Classics
**Concepts couverts**: 1.5.2.a-i (9 concepts)
**Difficulté**: ⭐⭐

### Objectif
Problèmes DP à une dimension.

```rust
// Climbing Stairs
pub fn climb_stairs(n: usize) -> u64;                         // 1.5.2.a
pub fn climb_stairs_k_steps(n: usize, k: usize) -> u64;       // 1.5.2.b

// Coin Change
pub fn coin_change_min(coins: &[u32], amount: u32) -> Option<u32>; // 1.5.2.c
pub fn coin_change_ways(coins: &[u32], amount: u32) -> u64;   // 1.5.2.d

// House Robber
pub fn rob_houses(houses: &[i64]) -> i64;                     // 1.5.2.e
pub fn rob_houses_circular(houses: &[i64]) -> i64;            // 1.5.2.f

// Decode Ways
pub fn decode_ways(s: &str) -> u64;                           // 1.5.2.g

// Jump Game
pub fn can_jump(nums: &[u32]) -> bool;                        // 1.5.2.h
pub fn min_jumps(nums: &[u32]) -> Option<u32>;                // 1.5.2.i
```

---

## Exercice 03: 2D DP Basics
**Concepts couverts**: 1.5.3.a-i (9 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Problèmes DP à deux dimensions.

```rust
// Grid problems
pub fn unique_paths(m: usize, n: usize) -> u64;               // 1.5.3.a
pub fn unique_paths_obstacles(grid: &[Vec<bool>]) -> u64;     // 1.5.3.b
pub fn min_path_sum(grid: &[Vec<i32>]) -> i64;                // 1.5.3.c

// Matrix problems
pub fn maximal_square(matrix: &[Vec<bool>]) -> usize;         // 1.5.3.d
pub fn maximal_rectangle(matrix: &[Vec<bool>]) -> usize;      // 1.5.3.e

// Triangle
pub fn min_triangle_path(triangle: &[Vec<i32>]) -> i32;       // 1.5.3.f

// Dungeon Game
pub fn min_hp_dungeon(dungeon: &[Vec<i32>]) -> i32;           // 1.5.3.g

// Cherry Pickup
pub fn cherry_pickup(grid: &[Vec<i32>]) -> i32;               // 1.5.3.h

// Paint House
pub fn min_cost_paint(costs: &[Vec<i32>]) -> i32;             // 1.5.3.i
```

---

## Exercice 04: LCS & LIS
**Concepts couverts**: 1.5.4.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Longest Common Subsequence et Longest Increasing Subsequence.

```rust
// LCS
pub fn lcs_length(s1: &str, s2: &str) -> usize;               // 1.5.4.a
pub fn lcs_string(s1: &str, s2: &str) -> String;              // 1.5.4.b
pub fn lcs_space_optimized(s1: &str, s2: &str) -> usize;      // 1.5.4.c

// Edit Distance
pub fn edit_distance(s1: &str, s2: &str) -> usize;            // 1.5.4.d
pub fn edit_distance_ops(s1: &str, s2: &str) -> Vec<EditOp>;  // 1.5.4.e

// LIS
pub fn lis_length(nums: &[i32]) -> usize;                     // 1.5.4.f (O(n²))
pub fn lis_binary_search(nums: &[i32]) -> usize;              // 1.5.4.g (O(n log n))
pub fn lis_sequence(nums: &[i32]) -> Vec<i32>;                // 1.5.4.h

// Variations
pub fn longest_bitonic_subsequence(nums: &[i32]) -> usize;    // 1.5.4.i
pub fn number_of_lis(nums: &[i32]) -> usize;                  // 1.5.4.j
```

---

# BLOC B: DP Intermédiaire (Exercices 05-08)

## Exercice 05: Knapsack Problems
**Concepts couverts**: 1.5.5.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Variantes du problème du sac à dos.

```rust
// 0/1 Knapsack
pub fn knapsack_01(weights: &[u32], values: &[u32], capacity: u32) -> u32; // 1.5.5.a
pub fn knapsack_01_items(weights: &[u32], values: &[u32], capacity: u32) -> Vec<usize>; // 1.5.5.b

// Unbounded Knapsack
pub fn knapsack_unbounded(weights: &[u32], values: &[u32], capacity: u32) -> u32; // 1.5.5.c

// Bounded Knapsack
pub fn knapsack_bounded(items: &[(u32, u32, u32)], capacity: u32) -> u32; // 1.5.5.d
// (weight, value, quantity)

// Subset Sum
pub fn subset_sum_exists(nums: &[u32], target: u32) -> bool;  // 1.5.5.e
pub fn subset_sum_count(nums: &[u32], target: u32) -> u64;    // 1.5.5.f

// Partition
pub fn can_partition(nums: &[u32]) -> bool;                   // 1.5.5.g
pub fn min_partition_diff(nums: &[u32]) -> u32;               // 1.5.5.h

// Coin Row
pub fn coin_row(coins: &[u32]) -> u32;                        // 1.5.5.i

// Rod Cutting
pub fn rod_cutting(prices: &[u32], length: usize) -> u32;     // 1.5.5.j
```

---

## Exercice 06: Interval DP
**Concepts couverts**: 1.5.6.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
DP sur intervalles.

```rust
// Matrix Chain Multiplication
pub fn matrix_chain_order(dims: &[usize]) -> u64;             // 1.5.6.a
pub fn matrix_chain_parenthesization(dims: &[usize]) -> String; // 1.5.6.b

// Optimal BST
pub fn optimal_bst_cost(keys: &[u32], freqs: &[u32]) -> u64;  // 1.5.6.c

// Palindrome Partitioning
pub fn min_palindrome_cuts(s: &str) -> usize;                 // 1.5.6.d
pub fn is_palindrome_dp(s: &str) -> Vec<Vec<bool>>;           // 1.5.6.e

// Burst Balloons
pub fn max_coins_balloons(nums: &[i32]) -> i64;               // 1.5.6.f

// Stone Game
pub fn stone_game(piles: &[i32]) -> bool;                     // 1.5.6.g

// Strange Printer
pub fn strange_printer(s: &str) -> i32;                       // 1.5.6.h
```

---

## Exercice 07: String DP
**Concepts couverts**: 1.5.7.a-i (9 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
DP sur chaînes de caractères.

```rust
// Wildcard Matching
pub fn wildcard_match(s: &str, p: &str) -> bool;              // 1.5.7.a

// Regular Expression Matching
pub fn regex_match(s: &str, p: &str) -> bool;                 // 1.5.7.b

// Distinct Subsequences
pub fn num_distinct(s: &str, t: &str) -> u64;                 // 1.5.7.c

// Interleaving String
pub fn is_interleave(s1: &str, s2: &str, s3: &str) -> bool;   // 1.5.7.d

// Longest Palindromic Subsequence
pub fn longest_palindrome_subseq(s: &str) -> usize;           // 1.5.7.e

// Longest Palindromic Substring
pub fn longest_palindrome_substring(s: &str) -> String;       // 1.5.7.f
pub fn longest_palindrome_manacher(s: &str) -> String;        // 1.5.7.g

// Shortest Common Supersequence
pub fn shortest_common_superseq(s1: &str, s2: &str) -> String; // 1.5.7.h

// Word Break
pub fn word_break(s: &str, dict: &HashSet<String>) -> bool;   // 1.5.7.i
```

---

## Exercice 08: Digit DP
**Concepts couverts**: 1.5.8.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
DP sur les chiffres.

```rust
// Count numbers with property in range [0, n]
pub struct DigitDP {
    memo: Vec<Vec<Vec<Option<u64>>>>,
}

impl DigitDP {
    pub fn new() -> Self;

    // Count numbers with digit sum = k
    pub fn count_digit_sum(&self, n: u64, k: u32) -> u64;     // 1.5.8.a

    // Count numbers with no consecutive same digits
    pub fn count_no_consecutive(&self, n: u64) -> u64;        // 1.5.8.b

    // Count numbers with at most k distinct digits
    pub fn count_k_distinct(&self, n: u64, k: u32) -> u64;    // 1.5.8.c

    // Count numbers without digit d
    pub fn count_without_digit(&self, n: u64, d: u8) -> u64;  // 1.5.8.d

    // Count numbers divisible by k with digit sum divisible by m
    pub fn count_div_with_sum(&self, n: u64, k: u32, m: u32) -> u64; // 1.5.8.e

    // Framework for custom constraint
    fn solve<F>(&mut self, digits: &[u8], pos: usize, tight: bool, state: usize, f: F) -> u64
    where F: Fn(u8, usize) -> usize;                          // 1.5.8.f

    // Range version: count in [l, r]
    pub fn count_in_range<F>(&self, l: u64, r: u64, f: F) -> u64
    where F: Fn(u64) -> bool;                                 // 1.5.8.g
}

// Applications
pub fn count_special_numbers(n: u64) -> u64;                  // 1.5.8.h
```

---

# BLOC C: DP Avancé (Exercices 09-13)

## Exercice 09: Tree DP
**Concepts couverts**: 1.5.10.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
DP sur arbres.

```rust
pub struct Tree {
    adj: Vec<Vec<usize>>,
    values: Vec<i64>,
}

impl Tree {
    // Pattern général Tree DP                                 // 1.5.10.a
    fn dfs_dp(&self, u: usize, parent: Option<usize>, dp: &mut [Vec<i64>]);

    // État: dp[u][0/1] = ...                                  // 1.5.10.b

    // Subtree problems                                         // 1.5.10.c
    pub fn subtree_sum(&self) -> Vec<i64>;

    // Tree Diameter
    pub fn diameter(&self) -> usize;                          // 1.5.10.d

    // Binary Tree Max Path Sum
    pub fn max_path_sum(&self) -> i64;                        // 1.5.10.e

    // House Robber III
    pub fn rob_tree(&self) -> i64;                            // 1.5.10.f

    // Tree Coloring (min colors)
    pub fn min_coloring(&self) -> Vec<usize>;                 // 1.5.10.g

    // Maximum Matching
    pub fn max_matching(&self) -> usize;                      // 1.5.10.h

    // Maximum Independent Set
    pub fn max_independent_set(&self) -> usize;               // 1.5.10.i

    // Rerooting DP
    pub fn rerooting<T: Clone, F, G>(&self, combine: F, base: T, apply: G) -> Vec<T>
    where F: Fn(T, T) -> T, G: Fn(T, usize, usize) -> T;      // 1.5.10.j
}
```

---

## Exercice 10: Bitmask DP
**Concepts couverts**: 1.5.11.a-k (11 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
DP avec masques de bits.

```rust
// Concepts
pub fn explain_bitmask_dp() -> String;                        // 1.5.11.a
pub fn subset_representation(n: usize) -> String;             // 1.5.11.b
pub fn bit_operations() -> String;                            // 1.5.11.c

// TSP
pub fn tsp(dist: &[Vec<i64>]) -> i64;                         // 1.5.11.d
pub fn tsp_path(dist: &[Vec<i64>]) -> Vec<usize>;             // 1.5.11.e

// Assignment Problem
pub fn min_cost_assignment(cost: &[Vec<i64>]) -> i64;         // 1.5.11.f

// Hamiltonian Path
pub fn hamiltonian_path_count(adj: &[Vec<bool>]) -> u64;      // 1.5.11.g

// Subset enumeration
pub fn count_valid_subsets<F>(n: usize, valid: F) -> u64
where F: Fn(u32) -> bool;                                     // 1.5.11.h

// Subset Sum over Subsets (SOS DP)
pub fn sos_dp(a: &[i64]) -> Vec<i64>;                         // 1.5.11.i

// Profile DP (broken profile)
pub fn tiling_dominos(n: usize, m: usize) -> u64;             // 1.5.11.j

// Steiner Tree (bitmask)
pub fn steiner_tree(graph: &[Vec<(usize, i64)>], terminals: &[usize]) -> i64; // 1.5.11.k
```

---

## Exercice 11: Game DP
**Concepts couverts**: 1.5.9.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
DP pour jeux combinatoires.

```rust
// Nim Game
pub fn nim_winner(piles: &[u32]) -> bool;                     // 1.5.9.a (XOR)

// Sprague-Grundy theorem
pub fn grundy_number<F>(state: u32, moves: F) -> u32
where F: Fn(u32) -> Vec<u32>;                                 // 1.5.9.b

// Composite Games
pub fn composite_game_winner(games: &[u32]) -> bool;          // 1.5.9.c

// Stone Game variations
pub fn stone_game_optimal(piles: &[i32]) -> i32;              // 1.5.9.d
pub fn predict_winner(nums: &[i32]) -> bool;                  // 1.5.9.e

// Flip Game
pub fn can_win_flip(s: &str) -> bool;                         // 1.5.9.f

// Cat and Mouse
pub fn cat_mouse_winner(graph: &[Vec<usize>]) -> i32;         // 1.5.9.g

// Minimax with Alpha-Beta
pub fn minimax_alpha_beta<S, M, F>(state: S, depth: u32, alpha: i32, beta: i32,
                                   maximizing: bool, eval: F) -> i32
where F: Fn(&S) -> i32;                                       // 1.5.9.h
```

---

## Exercice 12: DP Optimizations
**Concepts couverts**: 1.5.12.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐⭐⭐

### Objectif
Techniques d'optimisation DP.

```rust
// Space Optimization
pub fn lcs_space_O_n(s1: &str, s2: &str) -> usize;            // 1.5.12.a

// Divide and Conquer Optimization
// Pour dp[i][j] = min(dp[i-1][k] + C[k][j]) où opt[i][j] ≤ opt[i][j+1]
pub fn dc_optimize(n: usize, m: usize, cost: &dyn Fn(usize, usize) -> i64) -> Vec<Vec<i64>>; // 1.5.12.b

// Knuth Optimization
// Quand C[i][j] satisfait quadrangle inequality
pub fn knuth_optimize(n: usize, cost: &dyn Fn(usize, usize) -> i64) -> Vec<Vec<i64>>; // 1.5.12.c

// Convex Hull Trick
pub struct ConvexHullTrick {
    lines: VecDeque<(i64, i64)>,
}

impl ConvexHullTrick {
    pub fn add_line(&mut self, m: i64, b: i64);               // 1.5.12.d
    pub fn query(&self, x: i64) -> i64;                       // 1.5.12.e
}

// Li Chao Tree
pub struct LiChaoTree {
    tree: Vec<(i64, i64)>,
}

impl LiChaoTree {
    pub fn add_line(&mut self, m: i64, b: i64);               // 1.5.12.f
    pub fn query(&self, x: i64) -> i64;                       // 1.5.12.g
}

// Monotonic Deque Optimization
pub fn sliding_window_dp<F>(n: usize, k: usize, f: F) -> Vec<i64>
where F: Fn(usize) -> i64;                                    // 1.5.12.h

// Meet in the Middle
pub fn subset_sum_meet_middle(nums: &[i64], target: i64) -> bool; // 1.5.12.i

// Aliens Trick (WQS Binary Search)
pub fn aliens_trick<F>(n: usize, k: usize, cost: F) -> i64
where F: Fn(usize, i64) -> (i64, usize);                      // 1.5.12.j
```

---

## Exercice 13: Sequence Alignment
**Concepts couverts**: 1.5.13.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
Algorithmes d'alignement de séquences (bioinformatique).

```rust
pub struct AlignmentParams {
    match_score: i32,
    mismatch_penalty: i32,
    gap_penalty: i32,
}

// Needleman-Wunsch (global alignment)
pub fn needleman_wunsch(s1: &str, s2: &str, params: &AlignmentParams) -> (i32, String, String); // 1.5.13.a

// Smith-Waterman (local alignment)
pub fn smith_waterman(s1: &str, s2: &str, params: &AlignmentParams) -> (i32, String, String); // 1.5.13.b

// Affine gap penalties
pub struct AffineGapParams {
    match_score: i32,
    mismatch_penalty: i32,
    gap_open: i32,
    gap_extend: i32,
}

pub fn gotoh_alignment(s1: &str, s2: &str, params: &AffineGapParams) -> (i32, String, String); // 1.5.13.c

// Hirschberg (linear space)
pub fn hirschberg(s1: &str, s2: &str, params: &AlignmentParams) -> (String, String); // 1.5.13.d

// Multiple Sequence Alignment (heuristic)
pub fn center_star_alignment(seqs: &[String], params: &AlignmentParams) -> Vec<String>; // 1.5.13.e

// BLOSUM62 matrix
pub fn blosum62_score(a: char, b: char) -> i32;               // 1.5.13.f

// DNA alignment with specific scoring
pub fn dna_alignment(s1: &str, s2: &str) -> (i32, String, String); // 1.5.13.g

// Protein alignment
pub fn protein_alignment(s1: &str, s2: &str) -> (i32, String, String); // 1.5.13.h
```

---

# BLOC D: Projet Final (Exercices 14-16)

## Exercice 14: DP Visualizer
**Concepts couverts**: 1.5.b (+ interface)
**Difficulté**: ⭐⭐⭐

### Objectif
Visualisation des tables DP.

```rust
pub struct DPVisualizer {
    tables: Vec<Vec<Vec<i64>>>,
    transitions: Vec<Transition>,
}

pub struct Transition {
    from: (usize, usize),
    to: (usize, usize),
    value: i64,
}

impl DPVisualizer {
    pub fn new() -> Self;

    // Capture table state
    pub fn snapshot(&mut self, table: &[Vec<i64>]);

    // Record transition
    pub fn record_transition(&mut self, from: (usize, usize), to: (usize, usize), val: i64);

    // Export formats
    pub fn to_ascii(&self) -> String;
    pub fn to_html(&self) -> String;
    pub fn to_dot(&self) -> String;

    // Animation (step by step)
    pub fn steps(&self) -> Vec<String>;
}

// Integrate with DP solvers
pub fn visualize_lcs(s1: &str, s2: &str) -> DPVisualizer;
pub fn visualize_knapsack(w: &[u32], v: &[u32], cap: u32) -> DPVisualizer;
```

---

## Exercice 15: DP Problem Library
**Concepts couverts**: 1.5.a,c,d,e (fonctions globales)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
Bibliothèque de 20+ algorithmes DP.

```rust
pub mod dp_library {
    // 1D DP
    pub mod linear {
        pub fn fibonacci(n: usize) -> u64;
        pub fn climbing_stairs(n: usize) -> u64;
        pub fn house_robber(houses: &[i64]) -> i64;
        pub fn decode_ways(s: &str) -> u64;
        pub fn coin_change(coins: &[u32], amount: u32) -> Option<u32>;
    }

    // 2D DP
    pub mod grid {
        pub fn unique_paths(m: usize, n: usize) -> u64;
        pub fn min_path_sum(grid: &[Vec<i32>]) -> i64;
        pub fn maximal_square(matrix: &[Vec<bool>]) -> usize;
        pub fn edit_distance(s1: &str, s2: &str) -> usize;
        pub fn lcs(s1: &str, s2: &str) -> String;
    }

    // Sequence DP
    pub mod sequence {
        pub fn lis(nums: &[i32]) -> Vec<i32>;
        pub fn longest_palindrome_subseq(s: &str) -> usize;
        pub fn word_break(s: &str, dict: &HashSet<String>) -> bool;
    }

    // Knapsack variants
    pub mod knapsack {
        pub fn knapsack_01(w: &[u32], v: &[u32], cap: u32) -> u32;
        pub fn knapsack_unbounded(w: &[u32], v: &[u32], cap: u32) -> u32;
        pub fn subset_sum(nums: &[u32], target: u32) -> bool;
        pub fn partition(nums: &[u32]) -> bool;
    }

    // Tree DP
    pub mod tree {
        pub fn tree_diameter(adj: &[Vec<usize>]) -> usize;
        pub fn max_independent_set(adj: &[Vec<usize>]) -> usize;
    }

    // Bitmask DP
    pub mod bitmask {
        pub fn tsp(dist: &[Vec<i64>]) -> i64;
        pub fn assignment(cost: &[Vec<i64>]) -> i64;
    }

    // Each function includes:
    // - Time complexity                                       // 1.5.d
    // - Space complexity
    // - Space-optimized version when possible                 // 1.5.e
    // - Solution reconstruction                               // 1.5.c
}
```

---

## Exercice 16: DP Problem Solver (Projet Final)
**Concepts couverts**: 1.5.a-n (14 concepts du projet)
**Difficulté**: ⭐⭐⭐⭐⭐

### Objectif
Système complet de résolution et visualisation DP.

```rust
pub struct DPSolver {
    problems: HashMap<String, Box<dyn DPProblem>>,
}

impl DPSolver {
    pub fn new() -> Self;                                     // 1.5.a (20+ algorithms)

    // Visualization
    pub fn visualize(&self, problem: &str, input: &str) -> String; // 1.5.b

    // Solution reconstruction
    pub fn reconstruct(&self, problem: &str, input: &str) -> Vec<String>; // 1.5.c

    // Complexity analysis
    pub fn analyze_complexity(&self, problem: &str) -> ComplexityReport; // 1.5.d

    // Space optimization
    pub fn optimize_space(&self, problem: &str) -> OptimizationReport; // 1.5.e

    // Specialized algorithms
    pub fn sequence_alignment(&self, s1: &str, s2: &str) -> AlignmentResult; // 1.5.f
    pub fn knapsack(&self, variant: KnapsackVariant, input: &str) -> u64; // 1.5.g
    pub fn tree_dp(&self, tree: &Tree, problem: TreeDPProblem) -> i64; // 1.5.h
    pub fn bitmask_dp(&self, problem: BitmaskProblem, input: &str) -> i64; // 1.5.i
    pub fn meet_in_middle(&self, nums: &[i64], target: i64) -> bool; // 1.5.j

    // CLI
    pub fn cli_handler(args: &[String]) -> Result<String, Error>; // 1.5.k

    // Benchmarks
    pub fn benchmark(&self, problem: &str, sizes: &[usize]) -> Vec<Duration>; // 1.5.l

    // Bonus: DP optimizations (CHT, D&C, Knuth)
    pub fn apply_optimization(&self, problem: &str, opt: DPOptimization) -> i64; // 1.5.m

    // Bonus: Digit DP framework
    pub fn digit_dp<F>(&self, n: u64, constraint: F) -> u64
    where F: Fn(&[u8]) -> bool;                               // 1.5.n
}

// CLI Interface
// dp_solver solve lcs "ABCD" "AEBD"
// dp_solver visualize knapsack "weights=1,2,3 values=6,10,12 capacity=5"
// dp_solver benchmark tsp 10,15,20
// dp_solver optimize knapsack_01
```

---

# RÉCAPITULATIF

| Bloc | Exercices | Concepts | Description |
|------|-----------|----------|-------------|
| A | 01-04 | 37 | Fondamentaux DP |
| B | 05-08 | 35 | DP Intermédiaire |
| C | 09-13 | 47 | DP Avancé |
| D | 14-16 | 31 | Projet + Library |
| **TOTAL** | **16** | **150** | **Module 1.5 complet** |

---
