# Exercise 02: Knapsack Problems

## Concepts Covered
- **1.5.5.d-o** 0/1 Knapsack, unbounded, bounded, multidimensional
- **1.5.6.d-l** Subset sum, coin change, partition problems

## Objective

Implement all major variants of the knapsack problem.

## Requirements

### Rust Implementation

```rust
pub mod knapsack {
    /// 0/1 Knapsack - O(nW)
    pub fn knapsack_01(weights: &[usize], values: &[i64], capacity: usize) -> i64;

    /// 0/1 Knapsack with item selection
    pub fn knapsack_01_items(
        weights: &[usize],
        values: &[i64],
        capacity: usize,
    ) -> (i64, Vec<usize>);

    /// 0/1 Knapsack - space optimized O(W)
    pub fn knapsack_01_optimized(weights: &[usize], values: &[i64], capacity: usize) -> i64;

    /// Unbounded Knapsack (items can be taken multiple times)
    pub fn knapsack_unbounded(weights: &[usize], values: &[i64], capacity: usize) -> i64;

    /// Bounded Knapsack (each item has a count limit)
    pub fn knapsack_bounded(
        weights: &[usize],
        values: &[i64],
        counts: &[usize],
        capacity: usize,
    ) -> i64;

    /// Fractional Knapsack (greedy, not DP)
    pub fn knapsack_fractional(
        weights: &[f64],
        values: &[f64],
        capacity: f64,
    ) -> f64;

    /// Multidimensional Knapsack (multiple constraints)
    pub fn knapsack_multidim(
        weights: &[Vec<usize>],  // weights[i][j] = weight of item i in dimension j
        values: &[i64],
        capacities: &[usize],
    ) -> i64;

    /// Meet in the Middle for large n, small W
    pub fn knapsack_meet_middle(
        weights: &[usize],
        values: &[i64],
        capacity: usize,
    ) -> i64;
}

pub mod subset_sum {
    /// Subset sum: can we achieve target?
    pub fn subset_sum(arr: &[i64], target: i64) -> bool;

    /// Count subsets with given sum
    pub fn count_subset_sum(arr: &[i64], target: i64) -> i64;

    /// Subset with sum closest to target
    pub fn closest_subset_sum(arr: &[i64], target: i64) -> i64;

    /// Partition into two subsets with minimum difference
    pub fn min_subset_diff(arr: &[i64]) -> i64;

    /// Count partitions with given difference
    pub fn count_partitions_diff(arr: &[i64], diff: i64) -> i64;

    /// Target sum with +/- signs
    pub fn target_sum_ways(arr: &[i64], target: i64) -> i64;
}

pub mod coin_change {
    /// Minimum coins to make amount
    pub fn min_coins(coins: &[usize], amount: usize) -> Option<usize>;

    /// Minimum coins with coin selection
    pub fn min_coins_selection(coins: &[usize], amount: usize) -> Option<Vec<usize>>;

    /// Number of ways to make amount (order doesn't matter)
    pub fn coin_combinations(coins: &[usize], amount: usize) -> i64;

    /// Number of ways to make amount (order matters)
    pub fn coin_permutations(coins: &[usize], amount: usize) -> i64;

    /// Minimum coins with limited supply
    pub fn min_coins_limited(coins: &[usize], counts: &[usize], amount: usize) -> Option<usize>;

    /// Perfect squares sum
    pub fn min_perfect_squares(n: usize) -> usize;

    /// Integer break (maximize product)
    pub fn integer_break(n: usize) -> i64;
}

pub mod rod_cutting {
    /// Maximum value from rod cutting
    pub fn rod_cutting(prices: &[i64], length: usize) -> i64;

    /// Rod cutting with cuts
    pub fn rod_cutting_cuts(prices: &[i64], length: usize) -> (i64, Vec<usize>);

    /// Minimum cost to cut rod at given positions
    pub fn min_cut_cost(length: usize, cuts: &[usize]) -> i64;
}

pub mod advanced_knapsack {
    /// Knapsack with dependencies (item j requires item i)
    pub fn knapsack_dependencies(
        weights: &[usize],
        values: &[i64],
        deps: &[Option<usize>],
        capacity: usize,
    ) -> i64;

    /// Group Knapsack (pick at most one from each group)
    pub fn knapsack_groups(
        groups: &[Vec<(usize, i64)>],  // groups[g] = [(weight, value)]
        capacity: usize,
    ) -> i64;

    /// Knapsack with conflict pairs
    pub fn knapsack_conflicts(
        weights: &[usize],
        values: &[i64],
        conflicts: &[(usize, usize)],
        capacity: usize,
    ) -> i64;
}
```

### Python Implementation

```python
from typing import List, Optional, Tuple

def knapsack_01(weights: List[int], values: List[int], capacity: int) -> int: ...
def knapsack_01_items(weights: List[int], values: List[int], capacity: int) -> Tuple[int, List[int]]: ...
def knapsack_unbounded(weights: List[int], values: List[int], capacity: int) -> int: ...
def knapsack_bounded(weights: List[int], values: List[int], counts: List[int], capacity: int) -> int: ...

def subset_sum(arr: List[int], target: int) -> bool: ...
def count_subset_sum(arr: List[int], target: int) -> int: ...
def min_subset_diff(arr: List[int]) -> int: ...
def target_sum_ways(arr: List[int], target: int) -> int: ...

def min_coins(coins: List[int], amount: int) -> Optional[int]: ...
def coin_combinations(coins: List[int], amount: int) -> int: ...
def coin_permutations(coins: List[int], amount: int) -> int: ...

def rod_cutting(prices: List[int], length: int) -> int: ...
```

## Test Cases

```rust
#[test]
fn test_knapsack_01() {
    let weights = vec![1, 2, 3];
    let values = vec![6, 10, 12];
    assert_eq!(knapsack_01(&weights, &values, 5), 22);  // Items 1 and 2

    let (val, items) = knapsack_01_items(&weights, &values, 5);
    assert_eq!(val, 22);
    assert!(items.contains(&1) && items.contains(&2));
}

#[test]
fn test_knapsack_unbounded() {
    let weights = vec![1, 3, 4, 5];
    let values = vec![1, 4, 5, 7];
    // Can take item 0 seven times for value 7, or item 3 + 2×item 0 for 9
    assert_eq!(knapsack_unbounded(&weights, &values, 7), 9);
}

#[test]
fn test_knapsack_bounded() {
    let weights = vec![1, 2, 3];
    let values = vec![6, 10, 12];
    let counts = vec![2, 1, 1];  // Item 0 up to 2 times
    assert_eq!(knapsack_bounded(&weights, &values, &counts, 5), 22);
}

#[test]
fn test_subset_sum() {
    assert!(subset_sum(&[3, 34, 4, 12, 5, 2], 9));
    assert!(!subset_sum(&[3, 34, 4, 12, 5, 2], 30));

    assert_eq!(count_subset_sum(&[1, 2, 3, 3], 6), 3);  // {3,3}, {1,2,3}, {1,2,3}
}

#[test]
fn test_min_subset_diff() {
    assert_eq!(min_subset_diff(&[1, 6, 11, 5]), 1);  // {1,5,6} vs {11}
    assert_eq!(min_subset_diff(&[1, 2, 3, 4, 5]), 1);  // {1,2,4,5}=12 vs {3}=3... wait
}

#[test]
fn test_target_sum_ways() {
    assert_eq!(target_sum_ways(&[1, 1, 1, 1, 1], 3), 5);
    // +1+1+1+1-1=3, +1+1+1-1+1=3, etc.
}

#[test]
fn test_min_coins() {
    assert_eq!(min_coins(&[1, 2, 5], 11), Some(3));  // 5+5+1
    assert_eq!(min_coins(&[2], 3), None);
    assert_eq!(min_coins(&[1], 0), Some(0));
}

#[test]
fn test_coin_combinations() {
    assert_eq!(coin_combinations(&[1, 2, 5], 5), 4);
    // 5, 2+2+1, 2+1+1+1, 1+1+1+1+1
}

#[test]
fn test_coin_permutations() {
    assert_eq!(coin_permutations(&[1, 2, 3], 4), 7);
    // 1+1+1+1, 1+1+2, 1+2+1, 2+1+1, 2+2, 1+3, 3+1
}

#[test]
fn test_perfect_squares() {
    assert_eq!(min_perfect_squares(12), 3);  // 4+4+4
    assert_eq!(min_perfect_squares(13), 2);  // 9+4
}

#[test]
fn test_rod_cutting() {
    let prices = vec![1, 5, 8, 9, 10, 17, 17, 20];
    assert_eq!(rod_cutting(&prices, 8), 22);  // Cut into 2+6
}

#[test]
fn test_min_cut_cost() {
    // Rod of length 7, cut at positions [1, 3, 4, 5]
    // Cost = length of piece being cut
    assert_eq!(min_cut_cost(7, &[1, 3, 4, 5]), 16);
}

#[test]
fn test_integer_break() {
    assert_eq!(integer_break(2), 1);   // 1×1
    assert_eq!(integer_break(10), 36); // 3×3×4
}

#[test]
fn test_knapsack_groups() {
    let groups = vec![
        vec![(2, 3), (3, 4)],   // Group 0
        vec![(1, 2), (2, 3)],   // Group 1
    ];
    let result = knapsack_groups(&groups, 4);
    assert_eq!(result, 6);  // Pick (2,3) from group 0, (2,3) from group 1
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| 0/1 Knapsack | 15 |
| Unbounded Knapsack | 10 |
| Bounded Knapsack | 10 |
| Subset sum variants | 15 |
| Coin change variants | 20 |
| Rod cutting | 10 |
| Advanced variants | 15 |
| Edge cases | 5 |
| **Total** | **100** |
