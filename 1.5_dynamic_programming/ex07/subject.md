# Exercise 07: Digit DP & State Compression

## Concepts Covered
- **1.5.14.d-l** Digit DP, counting numbers with properties
- **1.5.15.d-k** Profile DP, broken profile, tiling problems

## Objective

Master digit-by-digit dynamic programming and state compression techniques.

## Requirements

### Rust Implementation

```rust
pub mod digit_dp {
    /// Count numbers from 0 to n with no repeated digits
    pub fn count_no_repeat(n: u64) -> u64;

    /// Count numbers from 0 to n with digit sum = k
    pub fn count_digit_sum(n: u64, k: u32) -> u64;

    /// Count numbers from 0 to n divisible by d
    pub fn count_divisible(n: u64, d: u64) -> u64;

    /// Count numbers from 0 to n with all digits different
    pub fn count_all_diff(n: u64) -> u64;

    /// Count numbers where digits are non-decreasing
    pub fn count_non_decreasing(n: u64) -> u64;

    /// Count numbers where digits are strictly increasing
    pub fn count_strictly_increasing(n: u64) -> u64;

    /// Count stepping numbers (adjacent digits differ by 1)
    pub fn count_stepping(n: u64) -> u64;

    /// Count numbers with at most k distinct digits
    pub fn count_k_distinct(n: u64, k: usize) -> u64;

    /// Count numbers with exactly k occurrences of digit d
    pub fn count_digit_occurrences(n: u64, digit: u8, k: usize) -> u64;

    /// Count numbers in range [lo, hi] with given properties
    pub fn count_range<F>(lo: u64, hi: u64, predicate: F) -> u64
    where
        F: Fn(u64) -> bool;

    /// Generic digit DP framework
    pub struct DigitDP {
        digits: Vec<u8>,
        memo: Vec<Vec<Vec<Option<u64>>>>,  // [pos][state][tight]
    }

    impl DigitDP {
        pub fn new(n: u64) -> Self;

        /// Run digit DP with custom state transition
        pub fn solve<F>(&mut self, f: F) -> u64
        where
            F: Fn(usize, usize, bool, u8) -> (usize, bool);
    }
}

pub mod profile_dp {
    /// Domino tiling of m×n grid
    pub fn domino_tiling(m: usize, n: usize) -> u64;

    /// Tiling with 1×2 and 2×1 tiles
    pub fn tiling_2xn(n: usize) -> u64;

    /// Tiling with 1×k tiles
    pub fn tiling_1xk(n: usize, k: usize) -> u64;

    /// Broken profile DP for m×n grid (use smaller dimension as profile)
    pub fn domino_tiling_broken(m: usize, n: usize) -> u64;

    /// Count ways to tile with L-shaped triominoes + 1×1
    pub fn l_tiling(n: usize) -> u64;

    /// Hamiltonian path count on grid
    pub fn hamiltonian_paths_grid(m: usize, n: usize) -> u64;

    /// Plug DP / connectivity profile
    pub struct PlugDP {
        m: usize,
        n: usize,
    }

    impl PlugDP {
        pub fn new(m: usize, n: usize) -> Self;
        pub fn count_hamiltonian_cycles(&self) -> u64;
    }
}

pub mod state_compression {
    /// Count valid board configurations (no two adjacent)
    pub fn count_valid_boards(m: usize, n: usize) -> u64;

    /// Maximum independent set on grid
    pub fn max_independent_set_grid(grid: &[Vec<i32>]) -> i32;

    /// Corn fields problem (plant on compatible cells)
    pub fn corn_fields(grid: &[Vec<bool>]) -> u64;

    /// Little bishops (non-attacking on m×n)
    pub fn little_bishops(m: usize, n: usize, k: usize) -> u64;

    /// Soldiers placement (non-attacking)
    pub fn place_soldiers(m: usize, n: usize, k: usize) -> u64;
}

pub mod steiner_dp {
    /// Steiner tree: connect subset of vertices with minimum edges
    pub fn steiner_tree(adj: &[Vec<(usize, i64)>], terminals: &[usize]) -> i64;

    /// Count connected components after taking subset
    pub fn connected_subsets(adj: &[Vec<usize>]) -> u64;

    /// Minimum cost to connect all terminals
    pub fn min_connection_cost(
        adj: &[Vec<(usize, i64)>],
        terminals: &[usize],
    ) -> i64;
}

pub mod game_dp {
    /// Nim game: can first player win?
    pub fn nim(piles: &[u32]) -> bool;

    /// Sprague-Grundy values
    pub fn sg_value(state: u64, moves: &[u64]) -> u32;

    /// Game on DAG
    pub fn dag_game(adj: &[Vec<usize>], start: usize) -> bool;

    /// Stone game variants
    pub fn stone_game(piles: &[i32]) -> i32;

    /// Can partition array for game
    pub fn can_first_win(nums: &[i32]) -> bool;
}
```

### Python Implementation

```python
from typing import List, Callable

def count_no_repeat(n: int) -> int: ...
def count_digit_sum(n: int, k: int) -> int: ...
def count_stepping(n: int) -> int: ...
def count_non_decreasing(n: int) -> int: ...

def domino_tiling(m: int, n: int) -> int: ...
def tiling_2xn(n: int) -> int: ...
def l_tiling(n: int) -> int: ...

def count_valid_boards(m: int, n: int) -> int: ...
def max_independent_set_grid(grid: List[List[int]]) -> int: ...
def corn_fields(grid: List[List[bool]]) -> int: ...

def steiner_tree(adj: List[List[tuple]], terminals: List[int]) -> int: ...

def nim(piles: List[int]) -> bool: ...
def stone_game(piles: List[int]) -> int: ...
```

## Test Cases

```rust
#[test]
fn test_count_no_repeat() {
    assert_eq!(count_no_repeat(20), 19);   // 0-20 except 11
    assert_eq!(count_no_repeat(100), 91);  // 0-100, exclude 11,22,33,...,99
    assert_eq!(count_no_repeat(1000), 738);
}

#[test]
fn test_count_digit_sum() {
    // Count numbers 0-99 with digit sum 10
    assert_eq!(count_digit_sum(99, 10), 9);  // 19,28,37,46,55,64,73,82,91
}

#[test]
fn test_stepping_numbers() {
    // 0-100: 0,1,2,3,4,5,6,7,8,9,10,12,21,23,32,34,43,45,54,56,65,67,76,78,87,89,98
    let count = count_stepping(100);
    assert_eq!(count, 27);
}

#[test]
fn test_non_decreasing() {
    // 0-20: 0,1,2,3,4,5,6,7,8,9,11,12,13,14,15,16,17,18,19
    assert_eq!(count_non_decreasing(20), 29);  // Includes numbers like 11-19
}

#[test]
fn test_domino_tiling() {
    assert_eq!(domino_tiling(2, 3), 3);   // Standard result
    assert_eq!(domino_tiling(2, 4), 5);
    assert_eq!(domino_tiling(3, 4), 11);
    assert_eq!(domino_tiling(4, 4), 36);
}

#[test]
fn test_tiling_2xn() {
    assert_eq!(tiling_2xn(1), 1);
    assert_eq!(tiling_2xn(2), 2);
    assert_eq!(tiling_2xn(3), 3);
    assert_eq!(tiling_2xn(4), 5);  // Fibonacci!
}

#[test]
fn test_l_tiling() {
    // 2×n with L-shaped and 2×1 tiles
    assert_eq!(l_tiling(2), 2);
}

#[test]
fn test_valid_boards() {
    // Count configurations where no two 1s are adjacent
    assert_eq!(count_valid_boards(2, 2), 7);   // All 4 empty configs + ...
    assert_eq!(count_valid_boards(2, 3), 13);
}

#[test]
fn test_corn_fields() {
    let grid = vec![
        vec![true, true, true],
        vec![true, false, true],
    ];
    // Count ways to place crops on fertile land (no adjacent)
    let ways = corn_fields(&grid);
    assert!(ways > 0);
}

#[test]
fn test_steiner_tree() {
    //     1
    //    /|\
    //   0 2 3
    let adj = vec![
        vec![(1, 1)],
        vec![(0, 1), (2, 1), (3, 1)],
        vec![(1, 1)],
        vec![(1, 1)],
    ];
    let terminals = vec![0, 2, 3];
    // Minimum: connect through node 1, cost = 3
    assert_eq!(steiner_tree(&adj, &terminals), 3);
}

#[test]
fn test_nim() {
    assert!(nim(&[1, 2, 3]));      // XOR = 0, second player wins? No, 1^2^3 = 0
    assert!(!nim(&[1, 2, 3]));     // XOR = 0, losing position
    assert!(nim(&[1, 2, 4]));      // XOR != 0, winning position
}

#[test]
fn test_stone_game() {
    // Alice and Bob pick from ends, Alice first
    assert!(stone_game(&[5, 3, 4, 5]) > 0);  // Alice wins
}

#[test]
fn test_max_independent_set_grid() {
    let grid = vec![
        vec![1, 2, 3],
        vec![4, 5, 6],
        vec![7, 8, 9],
    ];
    let max = max_independent_set_grid(&grid);
    // No two adjacent: pick corners and center? 1+3+5+7+9 = 25
    assert_eq!(max, 25);
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Digit DP basics | 20 |
| Complex digit constraints | 15 |
| Domino tiling | 15 |
| Profile/Broken Profile DP | 20 |
| Steiner Tree DP | 15 |
| Game DP | 10 |
| Edge cases | 5 |
| **Total** | **100** |
