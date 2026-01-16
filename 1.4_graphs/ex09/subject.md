# Exercise 09: Bipartite Matching & Graph Coloring

## Concepts Covered
- **1.4.20.d-l** Maximum bipartite matching, Hungarian algorithm
- **1.4.21.d-k** Graph coloring, chromatic number, greedy coloring

## Objective

Implement matching algorithms and graph coloring techniques.

## Requirements

### Rust Implementation

```rust
pub mod bipartite_matching {
    /// Maximum bipartite matching using augmenting paths
    /// Returns (matching_size, matching) where matching[u] = v means u matched to v
    pub fn max_matching_augmenting(
        left_size: usize,
        right_size: usize,
        edges: &[(usize, usize)],
    ) -> (usize, Vec<Option<usize>>);

    /// Hopcroft-Karp algorithm - O(E√V)
    pub fn hopcroft_karp(
        left_size: usize,
        right_size: usize,
        adj: &[Vec<usize>],
    ) -> (usize, Vec<Option<usize>>);

    /// Hungarian algorithm for weighted bipartite matching - O(V³)
    /// Finds maximum weight perfect matching
    pub fn hungarian(cost: &[Vec<i64>]) -> (i64, Vec<usize>);

    /// Minimum cost perfect matching
    pub fn min_cost_matching(cost: &[Vec<i64>]) -> (i64, Vec<usize>);

    /// Check if perfect matching exists
    pub fn has_perfect_matching(
        left_size: usize,
        right_size: usize,
        adj: &[Vec<usize>],
    ) -> bool;

    /// König's theorem: minimum vertex cover = maximum matching
    pub fn min_vertex_cover(
        left_size: usize,
        right_size: usize,
        adj: &[Vec<usize>],
    ) -> Vec<(bool, usize)>;  // (is_left, vertex)

    /// Maximum independent set in bipartite graph
    pub fn max_independent_set(
        left_size: usize,
        right_size: usize,
        adj: &[Vec<usize>],
    ) -> Vec<(bool, usize)>;

    /// Stable matching (Gale-Shapley algorithm)
    pub fn stable_matching(
        men_prefs: &[Vec<usize>],
        women_prefs: &[Vec<usize>],
    ) -> Vec<usize>;  // men_match[m] = w
}

pub mod general_matching {
    /// Maximum matching in general graph (Blossom algorithm concept)
    /// Full implementation is complex; this is simplified
    pub fn max_matching_general(adj: &[Vec<usize>]) -> Vec<(usize, usize)>;

    /// Check if graph has perfect matching
    pub fn has_perfect_matching(adj: &[Vec<usize>]) -> bool;

    /// Tutte's theorem check
    pub fn tutte_condition(adj: &[Vec<usize>]) -> bool;
}

pub mod graph_coloring {
    /// Greedy coloring - O(V + E)
    pub fn greedy_coloring(adj: &[Vec<usize>]) -> Vec<usize>;

    /// Greedy with specific vertex ordering
    pub fn greedy_coloring_order(adj: &[Vec<usize>], order: &[usize]) -> Vec<usize>;

    /// Welsh-Powell algorithm (order by degree)
    pub fn welsh_powell(adj: &[Vec<usize>]) -> Vec<usize>;

    /// DSatur algorithm (order by saturation degree)
    pub fn dsatur(adj: &[Vec<usize>]) -> Vec<usize>;

    /// Check if k-colorable
    pub fn is_k_colorable(adj: &[Vec<usize>], k: usize) -> bool;

    /// Find k-coloring if exists
    pub fn find_k_coloring(adj: &[Vec<usize>], k: usize) -> Option<Vec<usize>>;

    /// Chromatic number (exact, exponential)
    pub fn chromatic_number(adj: &[Vec<usize>]) -> usize;

    /// Chromatic number bounds
    pub fn chromatic_bounds(adj: &[Vec<usize>]) -> (usize, usize);  // (lower, upper)

    /// Chromatic polynomial (number of k-colorings)
    pub fn chromatic_polynomial(adj: &[Vec<usize>], k: usize) -> i64;

    /// Edge coloring (Vizing's theorem: Δ or Δ+1 colors)
    pub fn edge_coloring(adj: &[Vec<usize>]) -> Vec<Vec<usize>>;  // edge_color[u][i] for u's i-th edge
}

pub mod interval_coloring {
    /// Interval graph coloring (minimum colors = max clique size)
    pub fn interval_coloring(intervals: &[(i64, i64)]) -> Vec<usize>;

    /// Interval scheduling with multiple resources
    pub fn schedule_intervals(
        intervals: &[(i64, i64)],
        num_resources: usize,
    ) -> Option<Vec<usize>>;  // assignment[i] = resource for interval i

    /// Minimum resources needed
    pub fn min_resources(intervals: &[(i64, i64)]) -> usize;
}
```

### Python Implementation

```python
from typing import List, Optional, Tuple

def max_matching_augmenting(
    left_size: int,
    right_size: int,
    edges: List[Tuple[int, int]]
) -> Tuple[int, List[Optional[int]]]: ...

def hopcroft_karp(
    left_size: int,
    right_size: int,
    adj: List[List[int]]
) -> Tuple[int, List[Optional[int]]]: ...

def hungarian(cost: List[List[int]]) -> Tuple[int, List[int]]: ...

def stable_matching(
    men_prefs: List[List[int]],
    women_prefs: List[List[int]]
) -> List[int]: ...

def greedy_coloring(adj: List[List[int]]) -> List[int]: ...
def welsh_powell(adj: List[List[int]]) -> List[int]: ...
def dsatur(adj: List[List[int]]) -> List[int]: ...
def is_k_colorable(adj: List[List[int]], k: int) -> bool: ...
def chromatic_number(adj: List[List[int]]) -> int: ...

def interval_coloring(intervals: List[Tuple[int, int]]) -> List[int]: ...
```

## Test Cases

```rust
#[test]
fn test_bipartite_matching() {
    // 3 left vertices, 3 right vertices
    let adj = vec![
        vec![0, 1],     // left 0 connects to right 0, 1
        vec![0],        // left 1 connects to right 0
        vec![1, 2],     // left 2 connects to right 1, 2
    ];

    let (size, matching) = hopcroft_karp(3, 3, &adj);
    assert_eq!(size, 3);  // Perfect matching exists
}

#[test]
fn test_hungarian() {
    let cost = vec![
        vec![10, 5, 13],
        vec![3, 15, 8],
        vec![11, 9, 7],
    ];

    let (total_cost, assignment) = hungarian(&cost);
    // Optimal: 0->1 (5), 1->0 (3), 2->2 (7) = 15
    assert_eq!(total_cost, 15);
}

#[test]
fn test_min_cost_matching() {
    let cost = vec![
        vec![90, 80, 75],
        vec![35, 85, 55],
        vec![125, 95, 90],
    ];

    let (total, assignment) = min_cost_matching(&cost);
    // Minimum assignment cost
    assert_eq!(assignment.len(), 3);
}

#[test]
fn test_stable_matching() {
    // Men's preferences (most preferred first)
    let men_prefs = vec![
        vec![0, 1, 2],
        vec![1, 0, 2],
        vec![0, 1, 2],
    ];

    // Women's preferences
    let women_prefs = vec![
        vec![1, 0, 2],
        vec![0, 1, 2],
        vec![0, 1, 2],
    ];

    let matching = stable_matching(&men_prefs, &women_prefs);

    // Verify stability: no blocking pair
    for m in 0..3 {
        let w = matching[m];
        let m_rank_w = men_prefs[m].iter().position(|&x| x == w).unwrap();

        for &w2 in &men_prefs[m][..m_rank_w] {
            // m prefers w2 to w
            let m2 = matching.iter().position(|&x| x == w2).unwrap();
            let w2_rank_m = women_prefs[w2].iter().position(|&x| x == m).unwrap();
            let w2_rank_m2 = women_prefs[w2].iter().position(|&x| x == m2).unwrap();
            // w2 should prefer m2 to m (no blocking pair)
            assert!(w2_rank_m2 < w2_rank_m);
        }
    }
}

#[test]
fn test_greedy_coloring() {
    // Cycle of 5 (odd cycle needs 3 colors)
    let adj = vec![
        vec![1, 4],
        vec![0, 2],
        vec![1, 3],
        vec![2, 4],
        vec![3, 0],
    ];

    let colors = greedy_coloring(&adj);
    let num_colors = *colors.iter().max().unwrap() + 1;

    // Verify valid coloring
    for (u, neighbors) in adj.iter().enumerate() {
        for &v in neighbors {
            assert_ne!(colors[u], colors[v]);
        }
    }

    // Odd cycle needs exactly 3 colors
    assert_eq!(num_colors, 3);
}

#[test]
fn test_k_colorable() {
    // Complete graph K4 needs 4 colors
    let adj = vec![
        vec![1, 2, 3],
        vec![0, 2, 3],
        vec![0, 1, 3],
        vec![0, 1, 2],
    ];

    assert!(!is_k_colorable(&adj, 3));
    assert!(is_k_colorable(&adj, 4));
}

#[test]
fn test_chromatic_number() {
    // Petersen graph has chromatic number 3
    let petersen = vec![
        vec![1, 4, 5],
        vec![0, 2, 6],
        vec![1, 3, 7],
        vec![2, 4, 8],
        vec![3, 0, 9],
        vec![0, 7, 8],
        vec![1, 8, 9],
        vec![2, 9, 5],
        vec![3, 5, 6],
        vec![4, 6, 7],
    ];

    let chi = chromatic_number(&petersen);
    assert_eq!(chi, 3);
}

#[test]
fn test_interval_coloring() {
    let intervals = vec![
        (1, 4),
        (2, 5),
        (3, 6),
        (5, 8),
        (7, 9),
    ];

    let colors = interval_coloring(&intervals);
    let num_colors = *colors.iter().max().unwrap() + 1;

    // Maximum overlap is 3 (at time 3-4)
    assert_eq!(num_colors, 3);

    // Verify no overlapping intervals have same color
    for i in 0..intervals.len() {
        for j in i + 1..intervals.len() {
            let (s1, e1) = intervals[i];
            let (s2, e2) = intervals[j];
            if s1 < e2 && s2 < e1 {  // Overlapping
                assert_ne!(colors[i], colors[j]);
            }
        }
    }
}

#[test]
fn test_vertex_cover() {
    let adj = vec![
        vec![0, 1],
        vec![1],
        vec![0, 2],
    ];

    let cover = min_vertex_cover(3, 3, &adj);

    // Verify cover: every edge has at least one endpoint in cover
    // This is a König's theorem application
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Augmenting path matching | 15 |
| Hopcroft-Karp | 15 |
| Hungarian algorithm | 20 |
| Stable matching | 10 |
| Greedy coloring | 10 |
| Chromatic number | 15 |
| Interval coloring | 10 |
| Edge cases | 5 |
| **Total** | **100** |
