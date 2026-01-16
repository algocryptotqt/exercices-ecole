# Exercise 07: Network Flow

## Concepts Covered
- **1.4.14.c-i** Flow concepts, residual graph, augmenting path, max-flow min-cut
- **1.4.15.c-g** Ford-Fulkerson method
- **1.4.16.c-f** Edmonds-Karp algorithm
- **1.4.17.c-h** Dinic's algorithm
- **1.4.18.c-h** Max-flow min-cut theorem
- **1.4.19.c-i** Flow applications

## Objective

Implement network flow algorithms and apply them to solve real problems.

## Requirements

### Rust Implementation

```rust
pub mod network_flow {
    use std::collections::VecDeque;

    /// Flow network representation
    pub struct FlowNetwork {
        adj: Vec<Vec<usize>>,      // Adjacency list (edge indices)
        edges: Vec<Edge>,          // All edges
        n: usize,
    }

    #[derive(Clone)]
    struct Edge {
        from: usize,
        to: usize,
        capacity: i64,
        flow: i64,
    }

    impl FlowNetwork {
        pub fn new(n: usize) -> Self;

        /// Add edge with capacity (also adds reverse edge with 0 capacity)
        pub fn add_edge(&mut self, from: usize, to: usize, capacity: i64);

        /// Get current flow on edge
        pub fn get_flow(&self, edge_idx: usize) -> i64;

        /// Get residual capacity
        pub fn residual(&self, edge_idx: usize) -> i64;
    }

    /// Ford-Fulkerson with DFS (exponential worst case)
    pub fn ford_fulkerson(network: &mut FlowNetwork, source: usize, sink: usize) -> i64;

    /// Edmonds-Karp (BFS-based Ford-Fulkerson) - O(VE^2)
    pub fn edmonds_karp(network: &mut FlowNetwork, source: usize, sink: usize) -> i64;

    /// Dinic's algorithm - O(V^2 * E)
    pub struct Dinic {
        network: FlowNetwork,
        level: Vec<i32>,
        iter: Vec<usize>,
    }

    impl Dinic {
        pub fn new(n: usize) -> Self;
        pub fn add_edge(&mut self, from: usize, to: usize, capacity: i64);
        pub fn max_flow(&mut self, source: usize, sink: usize) -> i64;
    }

    /// Push-Relabel algorithm - O(V^2 * E) or O(V^3) with FIFO
    pub fn push_relabel(network: &mut FlowNetwork, source: usize, sink: usize) -> i64;

    /// Find minimum cut after max flow
    /// Returns vertices reachable from source in residual graph
    pub fn min_cut(network: &FlowNetwork, source: usize) -> Vec<usize>;

    // Flow Applications

    /// Maximum bipartite matching
    /// Returns matching as pairs (left_node, right_node)
    pub fn bipartite_matching(
        left_size: usize,
        right_size: usize,
        edges: &[(usize, usize)],
    ) -> Vec<(usize, usize)>;

    /// Edge-disjoint paths between s and t
    pub fn edge_disjoint_paths(
        n: usize,
        edges: &[(usize, usize)],
        source: usize,
        sink: usize,
    ) -> Vec<Vec<usize>>;

    /// Vertex-disjoint paths (split each vertex)
    pub fn vertex_disjoint_paths(
        n: usize,
        edges: &[(usize, usize)],
        source: usize,
        sink: usize,
    ) -> usize;

    /// Minimum vertex cover in bipartite graph
    pub fn min_vertex_cover(
        left_size: usize,
        right_size: usize,
        edges: &[(usize, usize)],
    ) -> (Vec<usize>, Vec<usize>);  // (left_cover, right_cover)

    /// Maximum independent set in bipartite graph
    pub fn max_independent_set(
        left_size: usize,
        right_size: usize,
        edges: &[(usize, usize)],
    ) -> (Vec<usize>, Vec<usize>);

    /// Assignment problem (minimum cost perfect matching)
    pub fn hungarian_algorithm(cost: &[Vec<i64>]) -> (i64, Vec<usize>);

    /// Project selection problem
    /// Returns (max profit, selected projects)
    pub fn project_selection(
        profits: &[i64],           // Profit for selecting each project
        requirements: &[(usize, usize)],  // (i, j) means i requires j
    ) -> (i64, Vec<usize>);
}
```

### Python Implementation

```python
from dataclasses import dataclass
from typing import Optional

class FlowNetwork:
    def __init__(self, n: int) -> None: ...
    def add_edge(self, from_: int, to: int, capacity: int) -> None: ...
    def get_flow(self, edge_idx: int) -> int: ...
    def residual(self, edge_idx: int) -> int: ...

def ford_fulkerson(network: FlowNetwork, source: int, sink: int) -> int: ...
def edmonds_karp(network: FlowNetwork, source: int, sink: int) -> int: ...

class Dinic:
    def __init__(self, n: int) -> None: ...
    def add_edge(self, from_: int, to: int, capacity: int) -> None: ...
    def max_flow(self, source: int, sink: int) -> int: ...

def min_cut(network: FlowNetwork, source: int) -> list[int]: ...
def bipartite_matching(left_size: int, right_size: int, edges: list[tuple[int, int]]) -> list[tuple[int, int]]: ...
def edge_disjoint_paths(n: int, edges: list[tuple[int, int]], source: int, sink: int) -> list[list[int]]: ...
def min_vertex_cover(left_size: int, right_size: int, edges: list[tuple[int, int]]) -> tuple[list[int], list[int]]: ...
def hungarian_algorithm(cost: list[list[int]]) -> tuple[int, list[int]]: ...
```

## Algorithm Details

### Dinic's Algorithm
```rust
fn max_flow(&mut self, s: usize, t: usize) -> i64 {
    let mut flow = 0;
    while self.bfs(s, t) {  // Build level graph
        self.iter.fill(0);
        loop {
            let f = self.dfs(s, t, i64::MAX);
            if f == 0 { break; }
            flow += f;
        }
    }
    flow
}

fn bfs(&mut self, s: usize, t: usize) -> bool {
    self.level.fill(-1);
    self.level[s] = 0;
    let mut queue = VecDeque::new();
    queue.push_back(s);

    while let Some(v) = queue.pop_front() {
        for &e in &self.network.adj[v] {
            let edge = &self.network.edges[e];
            if edge.capacity > edge.flow && self.level[edge.to] < 0 {
                self.level[edge.to] = self.level[v] + 1;
                queue.push_back(edge.to);
            }
        }
    }
    self.level[t] >= 0
}

fn dfs(&mut self, v: usize, t: usize, f: i64) -> i64 {
    if v == t { return f; }
    while self.iter[v] < self.network.adj[v].len() {
        let e = self.network.adj[v][self.iter[v]];
        let edge = &self.network.edges[e];
        if edge.capacity > edge.flow && self.level[v] < self.level[edge.to] {
            let d = self.dfs(edge.to, t, f.min(edge.capacity - edge.flow));
            if d > 0 {
                self.network.edges[e].flow += d;
                self.network.edges[e ^ 1].flow -= d;
                return d;
            }
        }
        self.iter[v] += 1;
    }
    0
}
```

### Max-Flow Min-Cut Theorem
- Value of max flow = capacity of min cut
- Min cut: partition (S, T) where s ∈ S, t ∈ T
- After max flow, S = vertices reachable from s in residual graph

## Test Cases

```rust
#[test]
fn test_simple_flow() {
    // Simple graph: 0 -> 1 -> 3
    //                \-> 2 -/
    let mut dinic = Dinic::new(4);
    dinic.add_edge(0, 1, 10);
    dinic.add_edge(0, 2, 10);
    dinic.add_edge(1, 3, 10);
    dinic.add_edge(2, 3, 10);

    assert_eq!(dinic.max_flow(0, 3), 20);
}

#[test]
fn test_bottleneck() {
    // Bottleneck in the middle
    let mut dinic = Dinic::new(4);
    dinic.add_edge(0, 1, 100);
    dinic.add_edge(0, 2, 100);
    dinic.add_edge(1, 3, 1);  // Bottleneck
    dinic.add_edge(2, 3, 100);

    assert_eq!(dinic.max_flow(0, 3), 101);
}

#[test]
fn test_bipartite_matching() {
    // 3 left nodes, 3 right nodes
    let edges = vec![(0, 0), (0, 1), (1, 1), (1, 2), (2, 2)];
    let matching = bipartite_matching(3, 3, &edges);

    assert_eq!(matching.len(), 3);  // Perfect matching exists
}

#[test]
fn test_min_cut() {
    let mut network = FlowNetwork::new(4);
    network.add_edge(0, 1, 2);
    network.add_edge(0, 2, 3);
    network.add_edge(1, 3, 3);
    network.add_edge(2, 3, 2);

    edmonds_karp(&mut network, 0, 3);
    let cut = min_cut(&network, 0);

    // Min cut separates {0, 1} from {2, 3} or similar
    assert!(cut.contains(&0));
    assert!(!cut.contains(&3));
}

#[test]
fn test_edge_disjoint() {
    // Two edge-disjoint paths from 0 to 3
    let edges = vec![(0, 1), (0, 2), (1, 3), (2, 3)];
    let paths = edge_disjoint_paths(4, &edges, 0, 3);

    assert_eq!(paths.len(), 2);
}

#[test]
fn test_hungarian() {
    let cost = vec![
        vec![3, 2, 7],
        vec![5, 1, 3],
        vec![2, 7, 2],
    ];

    let (min_cost, assignment) = hungarian_algorithm(&cost);
    assert_eq!(min_cost, 5);  // 2 + 1 + 2
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Flow network representation | 10 |
| Edmonds-Karp implementation | 15 |
| Dinic's algorithm | 20 |
| Min cut finding | 10 |
| Bipartite matching | 15 |
| Edge/vertex disjoint paths | 10 |
| Min vertex cover | 10 |
| Hungarian algorithm | 10 |
| **Total** | **100** |

## Files to Submit

### Rust
- `src/lib.rs`
- `Cargo.toml`

### Python
- `network_flow.py`
