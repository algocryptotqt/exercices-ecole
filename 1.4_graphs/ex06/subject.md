# Exercise 06: Minimum Spanning Trees

## Concepts Covered
- **1.4.13.d-l** Kruskal's algorithm, Union-Find optimization
- **1.4.14.d-k** Prim's algorithm, Fibonacci heap optimization
- **1.4.15.d-h** Borůvka's algorithm, parallel MST

## Objective

Implement all major MST algorithms with their optimizations.

## Requirements

### Rust Implementation

```rust
pub mod mst {
    /// Edge representation
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct Edge {
        pub u: usize,
        pub v: usize,
        pub weight: i64,
    }

    impl Ord for Edge {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.weight.cmp(&other.weight)
        }
    }

    impl PartialOrd for Edge {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }

    /// Kruskal's algorithm - O(E log E)
    pub fn kruskal(n: usize, edges: &[Edge]) -> (i64, Vec<Edge>);

    /// Kruskal with path compression + union by rank
    pub fn kruskal_optimized(n: usize, edges: &mut [Edge]) -> (i64, Vec<Edge>);

    /// Prim's algorithm - O(E log V) with binary heap
    pub fn prim(adj: &[Vec<(usize, i64)>]) -> (i64, Vec<(usize, usize)>);

    /// Prim's algorithm starting from specific vertex
    pub fn prim_from(adj: &[Vec<(usize, i64)>], start: usize) -> (i64, Vec<(usize, usize)>);

    /// Prim with Fibonacci heap - O(E + V log V)
    pub fn prim_fibonacci(adj: &[Vec<(usize, i64)>]) -> (i64, Vec<(usize, usize)>);

    /// Borůvka's algorithm - O(E log V)
    pub fn boruvka(n: usize, edges: &[Edge]) -> (i64, Vec<Edge>);

    /// Check if MST is unique
    pub fn is_mst_unique(n: usize, edges: &[Edge]) -> bool;

    /// Second-best MST
    pub fn second_best_mst(n: usize, edges: &[Edge]) -> Option<(i64, Vec<Edge>)>;

    /// MST of complete graph (special case)
    pub fn mst_complete_graph(weights: &[Vec<i64>]) -> (i64, Vec<(usize, usize)>);
}

pub mod mst_variants {
    use super::mst::Edge;

    /// Minimum Spanning Forest (for disconnected graphs)
    pub fn msf(n: usize, edges: &[Edge]) -> Vec<(i64, Vec<Edge>)>;

    /// Maximum Spanning Tree
    pub fn max_spanning_tree(n: usize, edges: &[Edge]) -> (i64, Vec<Edge>);

    /// Minimum Bottleneck Spanning Tree
    /// (MST minimizes the maximum edge weight)
    pub fn min_bottleneck_path(mst: &[(usize, usize, i64)], u: usize, v: usize) -> i64;

    /// Steiner Tree (MST connecting subset of vertices)
    /// NP-hard, use approximation
    pub fn steiner_tree_approx(
        adj: &[Vec<(usize, i64)>],
        terminals: &[usize],
    ) -> (i64, Vec<(usize, usize)>);

    /// Minimum Diameter Spanning Tree (NP-hard, approximation)
    pub fn min_diameter_st_approx(adj: &[Vec<(usize, i64)>]) -> Vec<(usize, usize)>;

    /// Directed MST (Minimum Spanning Arborescence) - Edmonds' algorithm
    pub fn min_arborescence(
        n: usize,
        edges: &[(usize, usize, i64)],
        root: usize,
    ) -> Option<(i64, Vec<(usize, usize)>)>;
}

pub mod mst_applications {
    /// Clustering using MST (remove k-1 heaviest edges for k clusters)
    pub fn mst_clustering(n: usize, edges: &[(usize, usize, i64)], k: usize) -> Vec<Vec<usize>>;

    /// Approximate TSP using MST (2-approximation)
    pub fn tsp_mst_approx(adj: &[Vec<i64>]) -> (i64, Vec<usize>);

    /// Network design: minimum cost to connect all cities
    pub fn min_network_cost(cities: &[(f64, f64)]) -> f64;

    /// Critical edges in MST (edges that if removed increase MST weight)
    pub fn critical_edges(n: usize, edges: &[(usize, usize, i64)]) -> Vec<(usize, usize)>;

    /// Pseudo-critical edges (edges that can appear in some MST)
    pub fn pseudo_critical_edges(n: usize, edges: &[(usize, usize, i64)]) -> Vec<(usize, usize)>;
}

pub mod dynamic_mst {
    /// Dynamic MST supporting edge insertions
    pub struct DynamicMST {
        n: usize,
        mst_edges: Vec<(usize, usize, i64)>,
        non_mst_edges: Vec<(usize, usize, i64)>,
    }

    impl DynamicMST {
        pub fn new(n: usize) -> Self;

        /// Add edge, update MST if necessary
        pub fn add_edge(&mut self, u: usize, v: usize, w: i64);

        /// Current MST weight
        pub fn mst_weight(&self) -> i64;

        /// Current MST edges
        pub fn mst_edges(&self) -> &[(usize, usize, i64)];
    }
}
```

### Python Implementation

```python
from typing import List, Tuple, Optional
from dataclasses import dataclass

@dataclass
class Edge:
    u: int
    v: int
    weight: int

    def __lt__(self, other):
        return self.weight < other.weight

def kruskal(n: int, edges: List[Edge]) -> Tuple[int, List[Edge]]: ...
def prim(adj: List[List[Tuple[int, int]]]) -> Tuple[int, List[Tuple[int, int]]]: ...
def boruvka(n: int, edges: List[Edge]) -> Tuple[int, List[Edge]]: ...

def is_mst_unique(n: int, edges: List[Edge]) -> bool: ...
def second_best_mst(n: int, edges: List[Edge]) -> Optional[Tuple[int, List[Edge]]]: ...
def max_spanning_tree(n: int, edges: List[Edge]) -> Tuple[int, List[Edge]]: ...

def mst_clustering(n: int, edges: List[Tuple[int, int, int]], k: int) -> List[List[int]]: ...
def tsp_mst_approx(adj: List[List[int]]) -> Tuple[int, List[int]]: ...
```

## Test Cases

```rust
#[test]
fn test_kruskal() {
    let edges = vec![
        Edge { u: 0, v: 1, weight: 10 },
        Edge { u: 0, v: 2, weight: 6 },
        Edge { u: 0, v: 3, weight: 5 },
        Edge { u: 1, v: 3, weight: 15 },
        Edge { u: 2, v: 3, weight: 4 },
    ];

    let (weight, mst) = kruskal(4, &edges);
    assert_eq!(weight, 19);  // 4 + 5 + 10
    assert_eq!(mst.len(), 3);
}

#[test]
fn test_prim() {
    let adj = vec![
        vec![(1, 10), (2, 6), (3, 5)],
        vec![(0, 10), (3, 15)],
        vec![(0, 6), (3, 4)],
        vec![(0, 5), (1, 15), (2, 4)],
    ];

    let (weight, mst) = prim(&adj);
    assert_eq!(weight, 19);
    assert_eq!(mst.len(), 3);
}

#[test]
fn test_boruvka() {
    let edges = vec![
        Edge { u: 0, v: 1, weight: 1 },
        Edge { u: 0, v: 2, weight: 2 },
        Edge { u: 1, v: 2, weight: 3 },
        Edge { u: 1, v: 3, weight: 4 },
        Edge { u: 2, v: 3, weight: 5 },
    ];

    let (weight, mst) = boruvka(4, &edges);
    assert_eq!(weight, 7);  // 1 + 2 + 4
}

#[test]
fn test_algorithms_same_result() {
    let n = 5;
    let edges = vec![
        Edge { u: 0, v: 1, weight: 2 },
        Edge { u: 0, v: 3, weight: 6 },
        Edge { u: 1, v: 2, weight: 3 },
        Edge { u: 1, v: 3, weight: 8 },
        Edge { u: 1, v: 4, weight: 5 },
        Edge { u: 2, v: 4, weight: 7 },
        Edge { u: 3, v: 4, weight: 9 },
    ];

    let adj = edges_to_adj(n, &edges);

    let (w1, _) = kruskal(n, &edges);
    let (w2, _) = prim(&adj);
    let (w3, _) = boruvka(n, &edges);

    assert_eq!(w1, w2);
    assert_eq!(w2, w3);
}

#[test]
fn test_mst_unique() {
    // MST is unique when all edge weights are distinct
    let edges = vec![
        Edge { u: 0, v: 1, weight: 1 },
        Edge { u: 0, v: 2, weight: 2 },
        Edge { u: 1, v: 2, weight: 3 },
    ];
    assert!(is_mst_unique(3, &edges));

    // MST may not be unique with equal weights
    let edges2 = vec![
        Edge { u: 0, v: 1, weight: 1 },
        Edge { u: 0, v: 2, weight: 1 },
        Edge { u: 1, v: 2, weight: 1 },
    ];
    assert!(!is_mst_unique(3, &edges2));
}

#[test]
fn test_second_best_mst() {
    let edges = vec![
        Edge { u: 0, v: 1, weight: 1 },
        Edge { u: 0, v: 2, weight: 2 },
        Edge { u: 1, v: 2, weight: 3 },
        Edge { u: 1, v: 3, weight: 4 },
        Edge { u: 2, v: 3, weight: 5 },
    ];

    let (best, _) = kruskal(4, &edges);
    let second = second_best_mst(4, &edges);

    assert!(second.is_some());
    let (second_weight, _) = second.unwrap();
    assert!(second_weight >= best);
}

#[test]
fn test_max_spanning_tree() {
    let edges = vec![
        Edge { u: 0, v: 1, weight: 1 },
        Edge { u: 0, v: 2, weight: 2 },
        Edge { u: 1, v: 2, weight: 3 },
    ];

    let (weight, mst) = max_spanning_tree(3, &edges);
    assert_eq!(weight, 5);  // 3 + 2
}

#[test]
fn test_mst_clustering() {
    let edges = vec![
        (0, 1, 1),
        (1, 2, 2),
        (2, 3, 10),  // Large gap
        (3, 4, 1),
        (4, 5, 2),
    ];

    let clusters = mst_clustering(6, &edges, 2);
    assert_eq!(clusters.len(), 2);
    // Should split at edge (2,3)
}

#[test]
fn test_min_arborescence() {
    let edges = vec![
        (0, 1, 1),
        (0, 2, 2),
        (1, 2, 1),
        (2, 3, 1),
    ];

    let result = min_arborescence(4, &edges, 0);
    assert!(result.is_some());
    let (weight, _) = result.unwrap();
    assert_eq!(weight, 4);  // 1 + 2 + 1 or 1 + 1 + 1 = 3? Check edges
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Kruskal's algorithm | 20 |
| Prim's algorithm | 20 |
| Borůvka's algorithm | 15 |
| MST uniqueness / second-best | 15 |
| Min arborescence | 15 |
| Applications | 10 |
| Edge cases | 5 |
| **Total** | **100** |
