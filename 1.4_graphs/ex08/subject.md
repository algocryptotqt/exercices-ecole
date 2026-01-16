# Exercise 08: Eulerian & Hamiltonian Paths

## Concepts Covered
- **1.4.18.d-l** Eulerian path/circuit, Hierholzer's algorithm
- **1.4.19.d-k** Hamiltonian path, backtracking, held-karp

## Objective

Implement algorithms for finding special paths and circuits in graphs.

## Requirements

### Rust Implementation

```rust
pub mod eulerian {
    /// Check if undirected graph has Eulerian circuit
    pub fn has_euler_circuit_undirected(adj: &[Vec<usize>]) -> bool;

    /// Check if undirected graph has Eulerian path
    pub fn has_euler_path_undirected(adj: &[Vec<usize>]) -> bool;

    /// Check if directed graph has Eulerian circuit
    pub fn has_euler_circuit_directed(adj: &[Vec<usize>]) -> bool;

    /// Check if directed graph has Eulerian path
    pub fn has_euler_path_directed(adj: &[Vec<usize>]) -> bool;

    /// Find Eulerian path in undirected graph (Hierholzer's algorithm)
    pub fn euler_path_undirected(adj: &[Vec<usize>]) -> Option<Vec<usize>>;

    /// Find Eulerian circuit in undirected graph
    pub fn euler_circuit_undirected(adj: &[Vec<usize>]) -> Option<Vec<usize>>;

    /// Find Eulerian path in directed graph
    pub fn euler_path_directed(adj: &[Vec<usize>]) -> Option<Vec<usize>>;

    /// Find Eulerian circuit in directed graph
    pub fn euler_circuit_directed(adj: &[Vec<usize>]) -> Option<Vec<usize>>;

    /// Make graph Eulerian by adding minimum edges
    pub fn make_eulerian(adj: &mut Vec<Vec<usize>>) -> Vec<(usize, usize)>;

    /// Chinese Postman Problem (minimum walk covering all edges)
    pub fn chinese_postman(adj: &[Vec<(usize, i64)>]) -> (i64, Vec<usize>);
}

pub mod hamiltonian {
    /// Check if Hamiltonian path exists (backtracking)
    pub fn has_hamiltonian_path(adj: &[Vec<usize>]) -> bool;

    /// Check if Hamiltonian circuit exists
    pub fn has_hamiltonian_circuit(adj: &[Vec<usize>]) -> bool;

    /// Find Hamiltonian path
    pub fn find_hamiltonian_path(adj: &[Vec<usize>]) -> Option<Vec<usize>>;

    /// Find Hamiltonian circuit
    pub fn find_hamiltonian_circuit(adj: &[Vec<usize>]) -> Option<Vec<usize>>;

    /// Count Hamiltonian paths (bitmask DP)
    pub fn count_hamiltonian_paths(adj: &[Vec<usize>]) -> i64;

    /// Shortest Hamiltonian path (Held-Karp algorithm) - O(n² * 2^n)
    pub fn shortest_hamiltonian_path(dist: &[Vec<i64>]) -> (i64, Vec<usize>);

    /// Traveling Salesman Problem (shortest Hamiltonian circuit)
    pub fn tsp(dist: &[Vec<i64>]) -> (i64, Vec<usize>);

    /// TSP with specific start/end vertices
    pub fn tsp_fixed_endpoints(
        dist: &[Vec<i64>],
        start: usize,
        end: usize,
    ) -> (i64, Vec<usize>);

    /// Ore's theorem: sufficient condition for Hamiltonian circuit
    pub fn ore_condition(adj: &[Vec<usize>]) -> bool;

    /// Dirac's theorem: sufficient condition
    pub fn dirac_condition(adj: &[Vec<usize>]) -> bool;
}

pub mod de_bruijn {
    /// Generate de Bruijn sequence for alphabet size k and string length n
    /// Uses Eulerian path on de Bruijn graph
    pub fn de_bruijn_sequence(k: usize, n: usize) -> Vec<usize>;

    /// Build de Bruijn graph
    pub fn de_bruijn_graph(k: usize, n: usize) -> Vec<Vec<usize>>;

    /// Shortest superstring containing all k^n strings of length n
    pub fn shortest_superstring_debruijn(k: usize, n: usize) -> String;
}

pub mod knight_tour {
    /// Knight's tour on n×n chessboard
    pub fn knights_tour(n: usize) -> Option<Vec<(usize, usize)>>;

    /// Knight's tour starting from specific position
    pub fn knights_tour_from(
        n: usize,
        start: (usize, usize),
    ) -> Option<Vec<(usize, usize)>>;

    /// Closed knight's tour (returns to start)
    pub fn closed_knights_tour(n: usize) -> Option<Vec<(usize, usize)>>;

    /// Count knight's tours (expensive!)
    pub fn count_knights_tours(n: usize) -> i64;

    /// Warnsdorff's heuristic for finding knight's tour
    pub fn knights_tour_warnsdorff(n: usize) -> Option<Vec<(usize, usize)>>;
}
```

### Python Implementation

```python
from typing import List, Optional, Tuple

def has_euler_circuit_undirected(adj: List[List[int]]) -> bool: ...
def has_euler_path_undirected(adj: List[List[int]]) -> bool: ...
def euler_path_undirected(adj: List[List[int]]) -> Optional[List[int]]: ...
def euler_circuit_directed(adj: List[List[int]]) -> Optional[List[int]]: ...

def has_hamiltonian_path(adj: List[List[int]]) -> bool: ...
def find_hamiltonian_path(adj: List[List[int]]) -> Optional[List[int]]: ...
def count_hamiltonian_paths(adj: List[List[int]]) -> int: ...
def tsp(dist: List[List[int]]) -> Tuple[int, List[int]]: ...

def de_bruijn_sequence(k: int, n: int) -> List[int]: ...
def knights_tour(n: int) -> Optional[List[Tuple[int, int]]]: ...
```

## Test Cases

```rust
#[test]
fn test_euler_circuit_undirected() {
    // Complete graph K4 has Euler circuit (all vertices even degree)
    let adj = vec![
        vec![1, 2, 3],
        vec![0, 2, 3],
        vec![0, 1, 3],
        vec![0, 1, 2],
    ];

    assert!(has_euler_circuit_undirected(&adj));

    let circuit = euler_circuit_undirected(&adj);
    assert!(circuit.is_some());
    let path = circuit.unwrap();
    assert_eq!(path.first(), path.last());
    assert_eq!(path.len(), 7);  // 6 edges + return to start
}

#[test]
fn test_euler_path_undirected() {
    // Path graph has Euler path but not circuit
    let adj = vec![
        vec![1],
        vec![0, 2],
        vec![1, 3],
        vec![2],
    ];

    assert!(has_euler_path_undirected(&adj));
    assert!(!has_euler_circuit_undirected(&adj));

    let path = euler_path_undirected(&adj);
    assert!(path.is_some());
}

#[test]
fn test_euler_directed() {
    // Directed cycle
    let adj = vec![
        vec![1],
        vec![2],
        vec![0],
    ];

    assert!(has_euler_circuit_directed(&adj));
    let circuit = euler_circuit_directed(&adj);
    assert!(circuit.is_some());
}

#[test]
fn test_hamiltonian_path() {
    // Complete graph always has Hamiltonian path
    let adj = vec![
        vec![1, 2, 3],
        vec![0, 2, 3],
        vec![0, 1, 3],
        vec![0, 1, 2],
    ];

    assert!(has_hamiltonian_path(&adj));
    assert!(has_hamiltonian_circuit(&adj));

    let path = find_hamiltonian_path(&adj);
    assert!(path.is_some());
    assert_eq!(path.unwrap().len(), 4);
}

#[test]
fn test_no_hamiltonian() {
    // Star graph: only center connects to all
    let adj = vec![
        vec![1, 2, 3, 4],
        vec![0],
        vec![0],
        vec![0],
        vec![0],
    ];

    // Has Hamiltonian path but not circuit
    assert!(has_hamiltonian_path(&adj));
    assert!(!has_hamiltonian_circuit(&adj));
}

#[test]
fn test_tsp() {
    let dist = vec![
        vec![0, 10, 15, 20],
        vec![10, 0, 35, 25],
        vec![15, 35, 0, 30],
        vec![20, 25, 30, 0],
    ];

    let (cost, tour) = tsp(&dist);
    assert_eq!(cost, 80);  // Optimal tour
    assert_eq!(tour.len(), 5);  // 4 cities + return
    assert_eq!(tour[0], tour[4]);
}

#[test]
fn test_held_karp() {
    let dist = vec![
        vec![0, 2, 9, 10],
        vec![1, 0, 6, 4],
        vec![15, 7, 0, 8],
        vec![6, 3, 12, 0],
    ];

    let (cost, path) = shortest_hamiltonian_path(&dist);
    assert_eq!(path.len(), 4);

    // Verify path visits all vertices
    let mut visited = vec![false; 4];
    for &v in &path {
        visited[v] = true;
    }
    assert!(visited.iter().all(|&v| v));
}

#[test]
fn test_de_bruijn() {
    // de Bruijn sequence for binary (k=2) strings of length 3
    let seq = de_bruijn_sequence(2, 3);
    // Should contain all 8 binary strings of length 3
    assert_eq!(seq.len(), 8);  // k^n = 2^3 = 8
}

#[test]
fn test_knights_tour() {
    // Knight's tour exists for n >= 5
    let tour = knights_tour(5);
    assert!(tour.is_some());
    let path = tour.unwrap();
    assert_eq!(path.len(), 25);  // 5x5 = 25 squares

    // Verify each move is valid knight move
    for i in 1..path.len() {
        let (r1, c1) = path[i - 1];
        let (r2, c2) = path[i];
        let dr = (r1 as i32 - r2 as i32).abs();
        let dc = (c1 as i32 - c2 as i32).abs();
        assert!((dr == 1 && dc == 2) || (dr == 2 && dc == 1));
    }
}

#[test]
fn test_chinese_postman() {
    // Graph where all edges must be traversed
    let adj = vec![
        vec![(1, 1), (2, 2)],
        vec![(0, 1), (2, 3)],
        vec![(0, 2), (1, 3)],
    ];

    let (cost, walk) = chinese_postman(&adj);
    // Total edge weight = 1 + 2 + 3 = 6
    // May need to repeat some edges if not Eulerian
    assert!(cost >= 6);
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Eulerian path/circuit detection | 15 |
| Hierholzer's algorithm | 15 |
| Hamiltonian path detection | 15 |
| TSP / Held-Karp | 20 |
| de Bruijn sequence | 10 |
| Knight's tour | 15 |
| Chinese Postman | 5 |
| Edge cases | 5 |
| **Total** | **100** |
