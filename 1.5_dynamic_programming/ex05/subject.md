# Exercise 05: DP Optimizations

## Concepts Covered
- **1.5.12.d-l** Convex Hull Trick, divide and conquer optimization
- **1.5.13.d-k** Knuth optimization, aliens trick

## Objective

Master advanced DP optimization techniques for reducing time complexity.

## Requirements

### Rust Implementation

```rust
pub mod convex_hull_trick {
    /// Line y = mx + b
    #[derive(Clone, Copy, Debug)]
    pub struct Line {
        pub m: i64,  // slope
        pub b: i64,  // intercept
    }

    impl Line {
        pub fn eval(&self, x: i64) -> i64;
    }

    /// Convex Hull Trick for minimum queries (decreasing slopes)
    pub struct CHT {
        lines: Vec<Line>,
    }

    impl CHT {
        pub fn new() -> Self;

        /// Add line y = mx + b (slopes must be decreasing)
        pub fn add(&mut self, m: i64, b: i64);

        /// Query minimum y at given x (x must be increasing)
        pub fn query(&self, x: i64) -> i64;

        /// Query minimum y at any x
        pub fn query_any(&self, x: i64) -> i64;
    }

    /// Li Chao Tree for arbitrary queries
    pub struct LiChaoTree {
        tree: Vec<Option<Line>>,
        lo: i64,
        hi: i64,
    }

    impl LiChaoTree {
        pub fn new(lo: i64, hi: i64) -> Self;
        pub fn add(&mut self, line: Line);
        pub fn query(&self, x: i64) -> i64;
    }

    /// DP with CHT optimization
    /// dp[i] = min(dp[j] + cost(j, i)) where cost has form a[j]*b[i] + c[j]
    pub fn dp_with_cht(a: &[i64], b: &[i64], c: &[i64]) -> Vec<i64>;
}

pub mod divide_conquer_dp {
    /// Divide and Conquer DP optimization
    /// For recurrences: dp[i][j] = min(dp[i-1][k] + cost(k, j)) for k < j
    /// where cost satisfies quadrangle inequality
    pub fn dc_dp_1d<F>(n: usize, cost: F) -> Vec<i64>
    where
        F: Fn(usize, usize) -> i64;

    /// 2D version
    pub fn dc_dp_2d<F>(rows: usize, cols: usize, cost: F) -> Vec<Vec<i64>>
    where
        F: Fn(usize, usize) -> i64;

    /// Optimal binary search tree using DC optimization
    pub fn optimal_bst_fast(freq: &[i64]) -> i64;
}

pub mod knuth_optimization {
    /// Knuth's optimization for dp[i][j] = min(dp[i][k] + dp[k][j]) + w[i][j]
    /// When opt[i][j-1] <= opt[i][j] <= opt[i+1][j]
    pub fn knuth_dp<F>(n: usize, w: F) -> Vec<Vec<i64>>
    where
        F: Fn(usize, usize) -> i64;

    /// Matrix chain with Knuth optimization
    pub fn matrix_chain_knuth(dims: &[usize]) -> i64;

    /// Optimal BST with Knuth optimization - O(n²)
    pub fn optimal_bst_knuth(freq: &[i64]) -> i64;
}

pub mod aliens_trick {
    /// Aliens / WQS Binary Search / Lagrangian Relaxation
    /// For: minimize f(k) subject to exactly k items selected
    /// If f is convex, use binary search on penalty

    /// Find minimum cost to select exactly k elements
    pub fn aliens_dp<F>(n: usize, k: usize, cost_with_penalty: F) -> i64
    where
        F: Fn(i64) -> (i64, usize);  // returns (min_cost, count)

    /// Example: minimum cost to split array into exactly k parts
    pub fn min_split_cost_k_parts(arr: &[i64], k: usize) -> i64;

    /// Example: select exactly k segments with minimum total cost
    pub fn select_k_segments(n: usize, k: usize, cost: &[Vec<i64>]) -> i64;
}

pub mod slope_trick {
    /// Slope trick for piecewise linear convex functions
    pub struct SlopeTrick {
        min_val: i64,
        left: std::collections::BinaryHeap<i64>,      // max-heap: left breakpoints
        right: std::collections::BinaryHeap<std::cmp::Reverse<i64>>,  // min-heap: right
    }

    impl SlopeTrick {
        pub fn new() -> Self;

        /// Add |x - a|
        pub fn add_abs(&mut self, a: i64);

        /// Get minimum value of function
        pub fn get_min(&self) -> i64;

        /// Get argmin (range where minimum is achieved)
        pub fn get_argmin(&self) -> (i64, i64);

        /// Shift function right by delta
        pub fn shift(&mut self, delta: i64);

        /// Apply min over prefix: g(x) = min_{y <= x} f(y)
        pub fn prefix_min(&mut self);

        /// Apply min over suffix: g(x) = min_{y >= x} f(y)
        pub fn suffix_min(&mut self);
    }

    /// Make array non-decreasing with minimum cost
    pub fn min_cost_non_decreasing(arr: &[i64]) -> i64;

    /// Make array equal with minimum moves
    pub fn min_moves_to_equal(arr: &[i64]) -> i64;
}

pub mod monotonic_dp {
    /// Deque optimization for sliding window DP
    pub fn sliding_window_dp(arr: &[i64], k: usize) -> Vec<i64>;

    /// Monotonic stack/deque DP
    pub fn largest_rectangle_histogram(heights: &[i64]) -> i64;

    /// Jump game with sliding window
    pub fn min_jumps_sliding(arr: &[i64], k: usize) -> i64;
}
```

### Python Implementation

```python
from typing import List, Tuple, Callable
import heapq

class Line:
    def __init__(self, m: int, b: int):
        self.m = m
        self.b = b

    def eval(self, x: int) -> int:
        return self.m * x + self.b

class CHT:
    def __init__(self):
        self.lines: List[Line] = []

    def add(self, m: int, b: int) -> None: ...
    def query(self, x: int) -> int: ...

class LiChaoTree:
    def __init__(self, lo: int, hi: int): ...
    def add(self, line: Line) -> None: ...
    def query(self, x: int) -> int: ...

def dc_dp(n: int, cost: Callable[[int, int], int]) -> List[int]: ...
def knuth_dp(n: int, w: Callable[[int, int], int]) -> List[List[int]]: ...
def aliens_dp(n: int, k: int, cost_with_penalty: Callable[[int], Tuple[int, int]]) -> int: ...

class SlopeTrick:
    def __init__(self): ...
    def add_abs(self, a: int) -> None: ...
    def get_min(self) -> int: ...
    def prefix_min(self) -> None: ...
    def suffix_min(self) -> None: ...

def min_cost_non_decreasing(arr: List[int]) -> int: ...
def largest_rectangle_histogram(heights: List[int]) -> int: ...
```

## Test Cases

```rust
#[test]
fn test_cht_basic() {
    let mut cht = CHT::new();
    cht.add(-1, 0);   // y = -x
    cht.add(-2, 1);   // y = -2x + 1
    cht.add(-3, 3);   // y = -3x + 3

    // At x=0: min(-0, 1, 3) = 0
    assert_eq!(cht.query(0), 0);
    // At x=2: min(-2, -3, -3) = -3
    assert_eq!(cht.query(2), -3);
}

#[test]
fn test_li_chao() {
    let mut tree = LiChaoTree::new(-100, 100);
    tree.add(Line { m: 1, b: 0 });   // y = x
    tree.add(Line { m: -1, b: 2 });  // y = -x + 2
    tree.add(Line { m: 0, b: 1 });   // y = 1

    assert_eq!(tree.query(0), 0);   // min(0, 2, 1) = 0
    assert_eq!(tree.query(1), 1);   // min(1, 1, 1) = 1
    assert_eq!(tree.query(-2), -2); // min(-2, 4, 1) = -2
}

#[test]
fn test_dc_optimization() {
    // Example: minimum cost to partition array
    let arr = vec![1, 3, 5, 7, 9];
    let cost = |i: usize, j: usize| {
        // Quadratic cost
        let sum: i64 = arr[i..=j].iter().sum();
        sum * sum
    };

    let result = dc_dp_1d(arr.len(), cost);
    // Verify result is correct
}

#[test]
fn test_knuth_optimization() {
    // Matrix chain multiplication
    let dims = vec![10, 20, 30, 40];
    let result = matrix_chain_knuth(&dims);
    assert_eq!(result, 18000);  // Verify with naive MCM
}

#[test]
fn test_aliens_trick() {
    // Split array into exactly k=2 parts minimizing sum of squares
    let arr = vec![1, 2, 3, 4, 5];
    let result = min_split_cost_k_parts(&arr, 2);
    // (1+2+3)² + (4+5)² = 36 + 81 = 117
    // or (1+2)² + (3+4+5)² = 9 + 144 = 153
    // etc.
}

#[test]
fn test_slope_trick() {
    // Make array [1, 5, 3, 4, 2] non-decreasing with min cost
    let arr = vec![1, 5, 3, 4, 2];
    let cost = min_cost_non_decreasing(&arr);
    // One solution: [1, 3, 3, 4, 4] costs |5-3| + |3-3| + |4-4| + |2-4| = 2+0+0+2 = 4?
    // Actually [1, 3, 3, 3, 3] costs 2+0+1+1 = 4
    assert!(cost <= 4);
}

#[test]
fn test_min_moves_equal() {
    let arr = vec![1, 2, 3];
    assert_eq!(min_moves_to_equal(&arr), 2);  // Move to 2: |1-2| + |3-2| = 2
}

#[test]
fn test_largest_rectangle() {
    let heights = vec![2, 1, 5, 6, 2, 3];
    assert_eq!(largest_rectangle_histogram(&heights), 10);  // 5*2
}

#[test]
fn test_sliding_window_dp() {
    // Minimum cost to reach end with jumps of size <= k
    let arr = vec![1, 100, 1, 1, 1, 100, 1, 1, 100, 1];
    let result = min_jumps_sliding(&arr, 3);
    // Can skip over 100s
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Convex Hull Trick | 20 |
| Li Chao Tree | 15 |
| Divide & Conquer DP | 20 |
| Knuth Optimization | 15 |
| Aliens Trick | 15 |
| Slope Trick | 10 |
| Edge cases | 5 |
| **Total** | **100** |
