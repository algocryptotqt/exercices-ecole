# Exercise 06: Bitmask DP

## Concepts Covered
- **1.5.11.e-k** TSP, assignment, Hamiltonian, subset enumeration, SOS DP

## Objective

Master bitmask DP for subset and permutation problems.

## Requirements

### Rust Implementation

```rust
pub mod bitmask_dp {
    /// Traveling Salesman Problem - O(n² * 2ⁿ)
    pub fn tsp(dist: &[Vec<i64>]) -> i64;

    /// TSP with path reconstruction
    pub fn tsp_path(dist: &[Vec<i64>]) -> (i64, Vec<usize>);

    /// Assignment Problem (Hungarian can be faster, but bitmask works)
    pub fn assignment(cost: &[Vec<i64>]) -> i64;

    /// Hamiltonian Path existence
    pub fn has_hamiltonian_path(adj: &[Vec<usize>]) -> bool;

    /// Count Hamiltonian Paths
    pub fn count_hamiltonian_paths(adj: &[Vec<usize>]) -> i64;

    /// Maximum weight independent set on path graph
    pub fn max_independent_set(weights: &[i64]) -> i64;

    /// Subset enumeration: iterate all subsets of a mask
    pub fn subsets(mask: usize) -> Vec<usize>;

    /// SOS DP: Sum over Subsets
    /// For each mask, compute sum of f[submask] for all submasks
    pub fn sos_dp(f: &[i64]) -> Vec<i64>;

    /// Count pairs with AND = 0
    pub fn count_and_zero_pairs(nums: &[i32]) -> i64;

    /// Partition into K equal sum subsets
    pub fn can_partition_k_subsets(nums: &[i32], k: usize) -> bool;

    /// Shortest superstring (combine strings with overlap)
    pub fn shortest_superstring(words: &[&str]) -> String;

    /// Maximum students on seats (no cheating)
    pub fn max_students(seats: &[Vec<char>]) -> i32;
}
```

## Key Techniques

### Subset Iteration
```rust
// Iterate all subsets of mask
let mut sub = mask;
loop {
    // process sub
    if sub == 0 { break; }
    sub = (sub - 1) & mask;
}
```

### SOS DP
```rust
fn sos_dp(f: &[i64]) -> Vec<i64> {
    let n = f.len().trailing_zeros() as usize;
    let mut dp = f.to_vec();

    for i in 0..n {
        for mask in 0..(1 << n) {
            if mask & (1 << i) != 0 {
                dp[mask] += dp[mask ^ (1 << i)];
            }
        }
    }
    dp
}
```

## Test Cases

```rust
#[test]
fn test_tsp() {
    let dist = vec![
        vec![0, 10, 15, 20],
        vec![10, 0, 35, 25],
        vec![15, 35, 0, 30],
        vec![20, 25, 30, 0],
    ];
    assert_eq!(tsp(&dist), 80);
}

#[test]
fn test_sos_dp() {
    let f = vec![1, 2, 3, 4, 5, 6, 7, 8];  // 2^3 elements
    let sos = sos_dp(&f);
    // sos[7] = f[0] + f[1] + ... + f[7] = 36
    assert_eq!(sos[7], 36);
    // sos[5] = f[0] + f[1] + f[4] + f[5] = 1+2+5+6 = 14
    assert_eq!(sos[5], 14);
}

#[test]
fn test_partition_k() {
    assert!(can_partition_k_subsets(&[4, 3, 2, 3, 5, 2, 1], 4));
    assert!(!can_partition_k_subsets(&[1, 2, 3, 4], 3));
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| TSP | 25 |
| Hamiltonian path | 15 |
| SOS DP | 20 |
| Subset enumeration | 10 |
| K-partition | 15 |
| Shortest superstring | 15 |
| **Total** | **100** |
