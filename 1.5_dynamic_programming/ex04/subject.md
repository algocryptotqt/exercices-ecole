# Exercise 04: Tree DP

## Concepts Covered
- **1.5.9.d-m** Tree DP, rerooting technique, tree diameter
- **1.5.10.d-k** Tree path queries, subtree aggregation

## Objective

Master dynamic programming on tree structures.

## Requirements

### Rust Implementation

```rust
pub mod tree_dp {
    /// Maximum independent set on tree
    pub fn max_independent_set(adj: &[Vec<usize>], weights: &[i64]) -> i64;

    /// Maximum matching on tree
    pub fn max_matching(adj: &[Vec<usize>]) -> usize;

    /// Tree diameter
    pub fn tree_diameter(adj: &[Vec<(usize, i64)>]) -> i64;

    /// Tree diameter with endpoints
    pub fn tree_diameter_path(adj: &[Vec<(usize, i64)>]) -> (i64, Vec<usize>);

    /// Tree center(s)
    pub fn tree_center(adj: &[Vec<usize>]) -> Vec<usize>;

    /// Minimum vertex cover
    pub fn min_vertex_cover(adj: &[Vec<usize>]) -> usize;

    /// Minimum dominating set
    pub fn min_dominating_set(adj: &[Vec<usize>]) -> usize;

    /// Count paths of length k
    pub fn count_paths_length_k(adj: &[Vec<usize>], k: usize) -> i64;

    /// Tree coloring with k colors (count valid colorings)
    pub fn tree_colorings(adj: &[Vec<usize>], k: usize) -> i64;

    /// Maximum path sum in tree
    pub fn max_path_sum(adj: &[Vec<usize>], values: &[i64]) -> i64;
}

pub mod rerooting {
    /// Distance sum from each node to all other nodes
    pub fn distance_sum_all(adj: &[Vec<(usize, i64)>]) -> Vec<i64>;

    /// Subtree sum for each node as root
    pub fn subtree_sums_rerooted(adj: &[Vec<usize>], values: &[i64]) -> Vec<i64>;

    /// Maximum distance to any node (eccentricity)
    pub fn eccentricity(adj: &[Vec<(usize, i64)>]) -> Vec<i64>;

    /// Count nodes in subtree for each possible root
    pub fn subtree_sizes_rerooted(adj: &[Vec<usize>]) -> Vec<Vec<usize>>;

    /// Minimum cost to reach all nodes from each starting node
    pub fn min_cost_from_each(adj: &[Vec<(usize, i64)>]) -> Vec<i64>;

    /// Maximum product of subtree sizes
    pub fn max_product_split(adj: &[Vec<usize>]) -> i64;
}

pub mod tree_queries {
    /// Precompute for path sum queries
    pub struct TreePathQuery {
        adj: Vec<Vec<(usize, i64)>>,
        parent: Vec<usize>,
        depth: Vec<usize>,
        dist_to_root: Vec<i64>,
        // LCA preprocessing...
    }

    impl TreePathQuery {
        pub fn new(adj: &[Vec<(usize, i64)>], root: usize) -> Self;

        /// Sum of edge weights on path u-v
        pub fn path_sum(&self, u: usize, v: usize) -> i64;

        /// Maximum edge weight on path u-v
        pub fn path_max(&self, u: usize, v: usize) -> i64;

        /// Minimum edge weight on path u-v
        pub fn path_min(&self, u: usize, v: usize) -> i64;

        /// Length (number of edges) of path u-v
        pub fn path_length(&self, u: usize, v: usize) -> usize;
    }

    /// Subtree queries with updates
    pub struct SubtreeQuery {
        adj: Vec<Vec<usize>>,
        values: Vec<i64>,
        euler_in: Vec<usize>,
        euler_out: Vec<usize>,
        // BIT or segment tree for range queries
    }

    impl SubtreeQuery {
        pub fn new(adj: &[Vec<usize>], values: &[i64], root: usize) -> Self;

        /// Sum of values in subtree of u
        pub fn subtree_sum(&self, u: usize) -> i64;

        /// Update value at node u
        pub fn update(&mut self, u: usize, new_val: i64);

        /// Add delta to all nodes in subtree
        pub fn add_to_subtree(&mut self, u: usize, delta: i64);
    }
}

pub mod tree_dp_advanced {
    /// Binary tree maximum path sum (any path)
    pub fn binary_tree_max_path(root: &TreeNode) -> i64;

    /// House robber on tree
    pub fn house_robber_tree(adj: &[Vec<usize>], values: &[i64]) -> i64;

    /// Longest path with same values
    pub fn longest_same_value_path(adj: &[Vec<usize>], values: &[i32]) -> usize;

    /// Count good nodes (node value >= all ancestors)
    pub fn count_good_nodes(adj: &[Vec<usize>], values: &[i32], root: usize) -> usize;

    /// Distribute coins in tree
    pub fn distribute_coins(adj: &[Vec<usize>], coins: &[i32]) -> i32;

    /// Sum of distances in tree (rerooting)
    pub fn sum_of_distances(adj: &[Vec<usize>]) -> Vec<i64>;

    /// Minimum height trees (find centroids)
    pub fn find_min_height_roots(adj: &[Vec<usize>]) -> Vec<usize>;
}

#[derive(Debug)]
pub struct TreeNode {
    pub val: i64,
    pub left: Option<Box<TreeNode>>,
    pub right: Option<Box<TreeNode>>,
}
```

### Python Implementation

```python
from typing import List, Tuple, Optional
from dataclasses import dataclass

def max_independent_set(adj: List[List[int]], weights: List[int]) -> int: ...
def max_matching(adj: List[List[int]]) -> int: ...
def tree_diameter(adj: List[List[Tuple[int, int]]]) -> int: ...
def tree_center(adj: List[List[int]]) -> List[int]: ...
def min_vertex_cover(adj: List[List[int]]) -> int: ...

def distance_sum_all(adj: List[List[Tuple[int, int]]]) -> List[int]: ...
def eccentricity(adj: List[List[Tuple[int, int]]]) -> List[int]: ...
def sum_of_distances(adj: List[List[int]]) -> List[int]: ...

@dataclass
class TreeNode:
    val: int
    left: Optional['TreeNode'] = None
    right: Optional['TreeNode'] = None

def binary_tree_max_path(root: TreeNode) -> int: ...
def house_robber_tree(adj: List[List[int]], values: List[int]) -> int: ...
def find_min_height_roots(adj: List[List[int]]) -> List[int]: ...
```

## Test Cases

```rust
#[test]
fn test_max_independent_set() {
    //     0(3)
    //    / \
    //   1(2) 2(1)
    //   |
    //   3(4)
    let adj = vec![vec![1, 2], vec![0, 3], vec![0], vec![1]];
    let weights = vec![3, 2, 1, 4];

    // Best: {0, 3} = 7 or {1, 2} = 3... actually {0, 3} = 3+4 = 7
    let result = max_independent_set(&adj, &weights);
    assert_eq!(result, 8);  // {3, 0, 2} = 4 + 3 + 1 = 8
}

#[test]
fn test_tree_diameter() {
    //     0
    //    /|\
    //   1 2 3
    //   |
    //   4
    let adj = vec![
        vec![(1, 1), (2, 1), (3, 1)],
        vec![(0, 1), (4, 1)],
        vec![(0, 1)],
        vec![(0, 1)],
        vec![(1, 1)],
    ];
    assert_eq!(tree_diameter(&adj), 4);  // Path 4-1-0-2 or 4-1-0-3
}

#[test]
fn test_tree_center() {
    //   0-1-2-3-4
    let adj = vec![vec![1], vec![0, 2], vec![1, 3], vec![2, 4], vec![3]];
    assert_eq!(tree_center(&adj), vec![2]);

    //   0-1-2-3
    let adj2 = vec![vec![1], vec![0, 2], vec![1, 3], vec![2]];
    let center = tree_center(&adj2);
    assert!(center == vec![1, 2] || center == vec![1] || center == vec![2]);
}

#[test]
fn test_distance_sum_all() {
    //   0-1-2
    let adj = vec![
        vec![(1, 1)],
        vec![(0, 1), (2, 1)],
        vec![(1, 1)],
    ];
    let sums = distance_sum_all(&adj);
    assert_eq!(sums, vec![3, 2, 3]);  // 0: 1+2=3, 1: 1+1=2, 2: 2+1=3
}

#[test]
fn test_eccentricity() {
    //   0-1-2-3
    let adj = vec![
        vec![(1, 1)],
        vec![(0, 1), (2, 1)],
        vec![(1, 1), (3, 1)],
        vec![(2, 1)],
    ];
    let ecc = eccentricity(&adj);
    assert_eq!(ecc, vec![3, 2, 2, 3]);
}

#[test]
fn test_binary_tree_max_path() {
    // Tree:    -10
    //         /   \
    //        9     20
    //             /  \
    //            15   7
    let tree = TreeNode {
        val: -10,
        left: Some(Box::new(TreeNode { val: 9, left: None, right: None })),
        right: Some(Box::new(TreeNode {
            val: 20,
            left: Some(Box::new(TreeNode { val: 15, left: None, right: None })),
            right: Some(Box::new(TreeNode { val: 7, left: None, right: None })),
        })),
    };

    assert_eq!(binary_tree_max_path(&tree), 42);  // 15 + 20 + 7
}

#[test]
fn test_house_robber_tree() {
    //     3
    //    / \
    //   2   3
    //    \   \
    //     3   1
    let adj = vec![
        vec![1, 2],  // 0
        vec![0, 3],  // 1
        vec![0, 4],  // 2
        vec![1],     // 3
        vec![2],     // 4
    ];
    let values = vec![3, 2, 3, 3, 1];
    assert_eq!(house_robber_tree(&adj, &values), 7);  // 3 + 3 + 1
}

#[test]
fn test_sum_of_distances() {
    let adj = vec![
        vec![1, 2],
        vec![0, 3, 4],
        vec![0],
        vec![1],
        vec![1],
    ];
    let result = sum_of_distances(&adj);
    // Node 0: dist to 1=1, 2=1, 3=2, 4=2 → 6
    // Node 1: dist to 0=1, 2=2, 3=1, 4=1 → 5
    assert_eq!(result[0], 6);
    assert_eq!(result[1], 5);
}

#[test]
fn test_min_height_roots() {
    // Find roots that minimize tree height
    let adj = vec![
        vec![1],
        vec![0, 2, 3],
        vec![1],
        vec![1, 4],
        vec![3],
    ];
    let roots = find_min_height_roots(&adj);
    assert!(roots.contains(&1) || roots.contains(&3));
}

#[test]
fn test_max_matching() {
    //   0-1-2-3-4
    let adj = vec![vec![1], vec![0, 2], vec![1, 3], vec![2, 4], vec![3]];
    assert_eq!(max_matching(&adj), 2);  // (0-1), (2-3) or (1-2), (3-4)
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Max independent set | 15 |
| Tree diameter & center | 15 |
| Rerooting technique | 20 |
| Tree path queries | 15 |
| Subtree queries | 15 |
| Binary tree DP | 15 |
| Edge cases | 5 |
| **Total** | **100** |
