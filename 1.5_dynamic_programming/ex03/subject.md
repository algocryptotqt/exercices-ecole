# Exercise 03: Grid & Matrix DP

## Concepts Covered
- **1.5.7.d-l** Grid DP, unique paths, obstacles, minimum path sum
- **1.5.8.d-k** Matrix chain multiplication, optimal BST

## Objective

Master dynamic programming on grids and matrix-based problems.

## Requirements

### Rust Implementation

```rust
pub mod grid_dp {
    /// Unique paths from top-left to bottom-right
    pub fn unique_paths(m: usize, n: usize) -> i64;

    /// Unique paths with obstacles
    pub fn unique_paths_obstacles(grid: &[Vec<i32>]) -> i64;

    /// Minimum path sum (top-left to bottom-right)
    pub fn min_path_sum(grid: &[Vec<i32>]) -> i32;

    /// Maximum path sum
    pub fn max_path_sum(grid: &[Vec<i32>]) -> i32;

    /// Minimum path sum with path reconstruction
    pub fn min_path_sum_path(grid: &[Vec<i32>]) -> (i32, Vec<(usize, usize)>);

    /// Dungeon game (minimum initial health)
    pub fn min_initial_health(dungeon: &[Vec<i32>]) -> i32;

    /// Cherry pickup (two paths, maximize cherries)
    pub fn cherry_pickup(grid: &[Vec<i32>]) -> i32;

    /// Maximum gold in mine (start from first column)
    pub fn gold_mine(grid: &[Vec<i32>]) -> i32;

    /// Falling path sum (any start in first row)
    pub fn falling_path_sum(matrix: &[Vec<i32>]) -> i32;

    /// Maximum square of 1s
    pub fn max_square(matrix: &[Vec<char>]) -> i32;

    /// Maximal rectangle of 1s
    pub fn maximal_rectangle(matrix: &[Vec<char>]) -> i32;

    /// Count square submatrices with all 1s
    pub fn count_squares(matrix: &[Vec<i32>]) -> i32;
}

pub mod matrix_dp {
    /// Matrix Chain Multiplication - minimum scalar multiplications
    pub fn matrix_chain_order(dims: &[usize]) -> i64;

    /// MCM with parenthesization
    pub fn matrix_chain_parenthesis(dims: &[usize]) -> (i64, String);

    /// Optimal Binary Search Tree
    pub fn optimal_bst(keys: &[i32], freq: &[i64]) -> i64;

    /// Optimal BST with structure
    pub fn optimal_bst_structure(keys: &[i32], freq: &[i64]) -> (i64, Vec<i32>);

    /// Burst Balloons
    pub fn burst_balloons(nums: &[i32]) -> i32;

    /// Boolean Parenthesization
    pub fn boolean_parenthesis(symbols: &str, operators: &str) -> i64;

    /// Scramble String
    pub fn is_scramble(s1: &str, s2: &str) -> bool;

    /// Minimum score triangulation of polygon
    pub fn min_score_triangulation(values: &[i32]) -> i32;
}

pub mod interval_dp {
    /// Minimum cost to merge stones
    pub fn merge_stones(stones: &[i32], k: usize) -> i32;

    /// Palindrome removal (minimum rounds)
    pub fn min_palindrome_removal(arr: &[i32]) -> i32;

    /// Strange printer (minimum turns)
    pub fn strange_printer(s: &str) -> i32;

    /// Minimum insertions to form palindrome
    pub fn min_insertions(s: &str) -> i32;

    /// Longest palindromic subsequence
    pub fn lps(s: &str) -> i32;

    /// Remove boxes (maximum points)
    pub fn remove_boxes(boxes: &[i32]) -> i32;
}

pub mod multidim_grid {
    /// 3D grid DP: minimum cost path
    pub fn min_path_3d(grid: &[Vec<Vec<i32>>]) -> i32;

    /// Paths with exactly k coins
    pub fn paths_with_coins(grid: &[Vec<i32>], k: i32) -> i64;

    /// Two robots collecting cherries
    pub fn two_robots_cherries(grid: &[Vec<i32>]) -> i32;
}
```

### Python Implementation

```python
from typing import List, Tuple

def unique_paths(m: int, n: int) -> int: ...
def unique_paths_obstacles(grid: List[List[int]]) -> int: ...
def min_path_sum(grid: List[List[int]]) -> int: ...
def min_initial_health(dungeon: List[List[int]]) -> int: ...
def cherry_pickup(grid: List[List[int]]) -> int: ...

def max_square(matrix: List[List[str]]) -> int: ...
def maximal_rectangle(matrix: List[List[str]]) -> int: ...

def matrix_chain_order(dims: List[int]) -> int: ...
def optimal_bst(keys: List[int], freq: List[int]) -> int: ...
def burst_balloons(nums: List[int]) -> int: ...

def merge_stones(stones: List[int], k: int) -> int: ...
def min_insertions(s: str) -> int: ...
```

## Test Cases

```rust
#[test]
fn test_unique_paths() {
    assert_eq!(unique_paths(3, 7), 28);
    assert_eq!(unique_paths(3, 3), 6);
}

#[test]
fn test_unique_paths_obstacles() {
    let grid = vec![
        vec![0, 0, 0],
        vec![0, 1, 0],
        vec![0, 0, 0],
    ];
    assert_eq!(unique_paths_obstacles(&grid), 2);
}

#[test]
fn test_min_path_sum() {
    let grid = vec![
        vec![1, 3, 1],
        vec![1, 5, 1],
        vec![4, 2, 1],
    ];
    assert_eq!(min_path_sum(&grid), 7);  // 1→3→1→1→1
}

#[test]
fn test_dungeon() {
    let dungeon = vec![
        vec![-2, -3, 3],
        vec![-5, -10, 1],
        vec![10, 30, -5],
    ];
    assert_eq!(min_initial_health(&dungeon), 7);
}

#[test]
fn test_cherry_pickup() {
    let grid = vec![
        vec![0, 1, -1],
        vec![1, 0, -1],
        vec![1, 1, 1],
    ];
    assert_eq!(cherry_pickup(&grid), 5);
}

#[test]
fn test_max_square() {
    let matrix = vec![
        vec!['1', '0', '1', '0', '0'],
        vec!['1', '0', '1', '1', '1'],
        vec!['1', '1', '1', '1', '1'],
        vec!['1', '0', '0', '1', '0'],
    ];
    assert_eq!(max_square(&matrix), 4);  // 2×2 square
}

#[test]
fn test_maximal_rectangle() {
    let matrix = vec![
        vec!['1', '0', '1', '0', '0'],
        vec!['1', '0', '1', '1', '1'],
        vec!['1', '1', '1', '1', '1'],
        vec!['1', '0', '0', '1', '0'],
    ];
    assert_eq!(maximal_rectangle(&matrix), 6);
}

#[test]
fn test_matrix_chain() {
    // Matrices: A1(10×30), A2(30×5), A3(5×60)
    let dims = vec![10, 30, 5, 60];
    assert_eq!(matrix_chain_order(&dims), 4500);
    // ((A1×A2)×A3): 10×30×5 + 10×5×60 = 1500 + 3000 = 4500
}

#[test]
fn test_optimal_bst() {
    let keys = vec![10, 12, 20];
    let freq = vec![34, 8, 50];
    // Optimal: 12 as root with 10 left, 20 right
    let cost = optimal_bst(&keys, &freq);
    assert_eq!(cost, 142);
}

#[test]
fn test_burst_balloons() {
    assert_eq!(burst_balloons(&[3, 1, 5, 8]), 167);
    // Burst 1: 3×1×5 = 15, Burst 5: 3×5×8 = 120, Burst 3: 1×3×8 = 24, Burst 8: 1×8×1 = 8
    // Total: 167
}

#[test]
fn test_boolean_parenthesis() {
    // T|F&T^F
    let symbols = "TFFT";
    let operators = "|&^";
    // Count ways to parenthesize to get True
    let count = boolean_parenthesis(symbols, operators);
    assert_eq!(count, 4);
}

#[test]
fn test_merge_stones() {
    assert_eq!(merge_stones(&[3, 2, 4, 1], 2), 20);
    assert_eq!(merge_stones(&[3, 2, 4, 1], 3), -1);  // Impossible
    assert_eq!(merge_stones(&[3, 5, 1, 2, 6], 3), 25);
}

#[test]
fn test_falling_path() {
    let matrix = vec![
        vec![2, 1, 3],
        vec![6, 5, 4],
        vec![7, 8, 9],
    ];
    assert_eq!(falling_path_sum(&matrix), 13);  // 1→5→7
}

#[test]
fn test_min_score_triangulation() {
    assert_eq!(min_score_triangulation(&[1, 2, 3]), 6);
    assert_eq!(min_score_triangulation(&[3, 7, 4, 5]), 144);
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Basic grid DP | 15 |
| Path reconstruction | 10 |
| Cherry pickup / two paths | 15 |
| Max square / rectangle | 15 |
| Matrix chain multiplication | 15 |
| Optimal BST | 10 |
| Interval DP | 15 |
| Edge cases | 5 |
| **Total** | **100** |
