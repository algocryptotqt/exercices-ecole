# Exercise 04: Shortest Paths

## Concepts Covered
- **1.4.8.e-m** Dijkstra with priority queue, proofs, bidirectional
- **1.4.9.e-j** Bellman-Ford, negative cycles, SPFA
- **1.4.10.d-j** Floyd-Warshall optimizations, transitive closure

## Objective

Implement all major shortest path algorithms with optimizations.

## Requirements

### Rust Implementation

```rust
pub mod shortest_paths {
    use std::collections::BinaryHeap;

    /// Dijkstra's algorithm - O((V+E) log V)
    pub fn dijkstra(adj: &[Vec<(usize, i64)>], source: usize) -> (Vec<i64>, Vec<Option<usize>>);

    /// Dijkstra with target (early termination)
    pub fn dijkstra_target(adj: &[Vec<(usize, i64)>], source: usize, target: usize) -> Option<(i64, Vec<usize>)>;

    /// Bidirectional Dijkstra
    pub fn bidirectional_dijkstra(adj: &[Vec<(usize, i64)>], rev_adj: &[Vec<(usize, i64)>], source: usize, target: usize) -> Option<i64>;

    /// Bellman-Ford - O(VE)
    pub fn bellman_ford(n: usize, edges: &[(usize, usize, i64)], source: usize) -> Result<Vec<i64>, Vec<usize>>;

    /// SPFA (Shortest Path Faster Algorithm)
    pub fn spfa(adj: &[Vec<(usize, i64)>], source: usize) -> Result<Vec<i64>, ()>;

    /// Floyd-Warshall - O(V³)
    pub fn floyd_warshall(adj: &[Vec<(usize, i64)>]) -> Vec<Vec<i64>>;

    /// Floyd-Warshall with path reconstruction
    pub fn floyd_warshall_paths(adj: &[Vec<(usize, i64)>]) -> (Vec<Vec<i64>>, Vec<Vec<Option<usize>>>);

    /// Reconstruct path from Floyd-Warshall
    pub fn reconstruct_path(next: &[Vec<Option<usize>>], u: usize, v: usize) -> Vec<usize>;

    /// Transitive closure
    pub fn transitive_closure(adj: &[Vec<usize>]) -> Vec<Vec<bool>>;

    /// Detect negative cycle
    pub fn has_negative_cycle(n: usize, edges: &[(usize, usize, i64)]) -> bool;

    /// Find negative cycle
    pub fn find_negative_cycle(n: usize, edges: &[(usize, usize, i64)]) -> Option<Vec<usize>>;
}
```

## Test Cases

```rust
#[test]
fn test_dijkstra() {
    let adj = vec![
        vec![(1, 4), (2, 1)],
        vec![(3, 1)],
        vec![(1, 2), (3, 5)],
        vec![],
    ];
    let (dist, _) = dijkstra(&adj, 0);
    assert_eq!(dist, vec![0, 3, 1, 4]);
}

#[test]
fn test_bellman_ford_negative() {
    let edges = vec![(0, 1, 4), (0, 2, 5), (1, 2, -3), (2, 3, 4)];
    let result = bellman_ford(4, &edges, 0);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![0, 4, 1, 5]);
}

#[test]
fn test_negative_cycle() {
    let edges = vec![(0, 1, 1), (1, 2, -1), (2, 0, -1)];
    assert!(has_negative_cycle(3, &edges));
}

#[test]
fn test_floyd_warshall() {
    let adj = vec![
        vec![(1, 3), (2, 8)],
        vec![(2, 1)],
        vec![],
    ];
    let dist = floyd_warshall(&adj);
    assert_eq!(dist[0][2], 4);  // 0->1->2
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Dijkstra | 20 |
| Bidirectional Dijkstra | 10 |
| Bellman-Ford | 20 |
| SPFA | 10 |
| Floyd-Warshall | 20 |
| Negative cycle detection | 15 |
| Edge cases | 5 |
| **Total** | **100** |
