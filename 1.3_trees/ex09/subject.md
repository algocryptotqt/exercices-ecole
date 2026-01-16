# Exercise 09: LCA & Tree Decomposition

## Concepts Covered
- **1.3.23** Sparse Tables for RMQ
- **1.3.24** LCA with Binary Lifting
- **1.3.25** LCA with Euler Tour + RMQ
- **1.3.26** Heavy-Light Decomposition
- **1.3.27** Centroid Decomposition

## Objective

Implement advanced tree algorithms for path queries and decomposition.

## Requirements

### Rust Implementation

```rust
pub mod tree_algorithms {
    /// Sparse Table for Range Minimum Query
    pub struct SparseTable {
        table: Vec<Vec<usize>>,
        log: Vec<usize>,
    }

    impl SparseTable {
        pub fn new(arr: &[usize]) -> Self;
        pub fn query(&self, l: usize, r: usize) -> usize;
    }

    /// LCA using Binary Lifting - O(n log n) preprocessing, O(log n) query
    pub struct LcaBinaryLifting {
        up: Vec<Vec<usize>>,
        depth: Vec<usize>,
        log: usize,
    }

    impl LcaBinaryLifting {
        pub fn new(adj: &[Vec<usize>], root: usize) -> Self;
        pub fn lca(&self, u: usize, v: usize) -> usize;
        pub fn distance(&self, u: usize, v: usize) -> usize;
        pub fn kth_ancestor(&self, u: usize, k: usize) -> Option<usize>;
    }

    /// LCA using Euler Tour + RMQ - O(n) preprocessing, O(1) query
    pub struct LcaEulerTour {
        euler: Vec<usize>,
        first: Vec<usize>,
        depth: Vec<usize>,
        sparse: SparseTable,
    }

    impl LcaEulerTour {
        pub fn new(adj: &[Vec<usize>], root: usize) -> Self;
        pub fn lca(&self, u: usize, v: usize) -> usize;
    }

    /// Heavy-Light Decomposition
    pub struct HLD {
        parent: Vec<usize>,
        depth: Vec<usize>,
        heavy: Vec<Option<usize>>,
        head: Vec<usize>,
        pos: Vec<usize>,
        n: usize,
    }

    impl HLD {
        pub fn new(adj: &[Vec<usize>], root: usize) -> Self;
        pub fn lca(&self, u: usize, v: usize) -> usize;

        /// Decompose path u-v into O(log n) chains
        pub fn path_decomposition(&self, u: usize, v: usize) -> Vec<(usize, usize)>;

        /// Path query with segment tree
        pub fn path_query<T, F>(&self, u: usize, v: usize, seg: &impl Fn(usize, usize) -> T, combine: F) -> T
        where F: Fn(T, T) -> T;
    }

    /// Centroid Decomposition
    pub struct CentroidDecomp {
        centroid_parent: Vec<Option<usize>>,
        removed: Vec<bool>,
    }

    impl CentroidDecomp {
        pub fn new(adj: &[Vec<usize>]) -> Self;
        pub fn find_centroid(&self, adj: &[Vec<usize>], root: usize) -> usize;

        /// Answer distance queries using centroid tree
        pub fn distance_query(&self, u: usize, v: usize) -> usize;
    }
}
```

## Test Cases

```rust
#[test]
fn test_lca_binary_lifting() {
    //       0
    //      /|\
    //     1 2 3
    //    /|   |
    //   4 5   6
    let adj = vec![
        vec![1, 2, 3], vec![0, 4, 5], vec![0], vec![0, 6],
        vec![1], vec![1], vec![3]
    ];
    let lca = LcaBinaryLifting::new(&adj, 0);

    assert_eq!(lca.lca(4, 5), 1);
    assert_eq!(lca.lca(4, 6), 0);
    assert_eq!(lca.lca(4, 2), 0);
    assert_eq!(lca.distance(4, 6), 4);
}

#[test]
fn test_hld_path_query() {
    let adj = vec![vec![1, 2], vec![0, 3, 4], vec![0], vec![1], vec![1]];
    let hld = HLD::new(&adj, 0);

    let chains = hld.path_decomposition(3, 2);
    // Should decompose into O(log n) chains
    assert!(chains.len() <= 3);
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Sparse Table RMQ | 15 |
| LCA Binary Lifting | 20 |
| LCA Euler Tour | 15 |
| Heavy-Light Decomposition | 25 |
| Centroid Decomposition | 20 |
| Edge cases | 5 |
| **Total** | **100** |
