# MODULE 1.4 - GRAPHS
## 264 Concepts - 24 Exercices Progressifs

---

# BLOC A: Représentations & Parcours (Exercices 01-06)

## Exercice 01: Graph Forge
**Concepts couverts**: 1.4.1.a-o (15 concepts)
**Difficulté**: ⭐⭐

### Objectif
Implémenter les 3 représentations de graphes avec conversions.

```rust
pub trait Graph {
    fn add_edge(&mut self, u: usize, v: usize, weight: i64);
    fn has_edge(&self, u: usize, v: usize) -> bool;
    fn neighbors(&self, u: usize) -> Vec<(usize, i64)>;
    fn edge_count(&self) -> usize;
    fn vertex_count(&self) -> usize;
}

// Matrice d'adjacence
pub struct AdjMatrix {
    matrix: Vec<Vec<Option<i64>>>,                      // 1.4.1.d
    n: usize,
}
// Space: O(V²)                                         // 1.4.1.e
// Edge check: O(1)                                     // 1.4.1.f
// Iterate neighbors: O(V)                              // 1.4.1.g

// Liste d'adjacence
pub struct AdjList {
    adj: Vec<Vec<(usize, i64)>>,                        // 1.4.1.h
    n: usize,
}
// Space: O(V + E)                                      // 1.4.1.i
// Edge check: O(degree)                                // 1.4.1.j
// Iterate neighbors: O(degree)                         // 1.4.1.k

// Liste d'arêtes
pub struct EdgeList {
    edges: Vec<(usize, usize, i64)>,                    // 1.4.1.l
    n: usize,
}
// Space: O(E)                                          // 1.4.1.m

// Conversions
impl From<&AdjMatrix> for AdjList { ... }               // 1.4.1.n
impl From<&AdjList> for AdjMatrix { ... }

// Graphes implicites (grille, etc.)
pub struct GridGraph { rows: usize, cols: usize }       // 1.4.1.o
```

### Définitions
- Graphe orienté/non-orienté (1.4.1.a)
- Pondéré/non-pondéré (1.4.1.b)
- Dense vs Sparse (1.4.1.c)

---

## Exercice 02: DFS Explorer
**Concepts couverts**: 1.4.2.a-j (10 concepts)
**Difficulté**: ⭐⭐

### Objectif
Maîtriser le parcours en profondeur.

```rust
impl AdjList {
    // DFS récursif
    pub fn dfs_recursive(&self, start: usize, visited: &mut [bool]) -> Vec<usize>; // 1.4.2.a

    // DFS itératif avec pile
    pub fn dfs_iterative(&self, start: usize) -> Vec<usize>;  // 1.4.2.b

    // Classification des arêtes
    pub fn classify_edges(&self) -> EdgeClassification;        // 1.4.2.c
    // Tree edges, Back edges, Forward edges, Cross edges

    // Timestamps
    pub fn dfs_with_times(&self, start: usize) -> Vec<(usize, usize, usize)>; // 1.4.2.d
    // (node, discovery_time, finish_time)

    // Applications
    pub fn find_cycle(&self) -> Option<Vec<usize>>;           // 1.4.2.e
    pub fn is_acyclic(&self) -> bool;                         // 1.4.2.f
    pub fn path_exists(&self, u: usize, v: usize) -> bool;    // 1.4.2.g

    // Complexity
    pub fn time_complexity(&self) -> String;                  // 1.4.2.h O(V + E)
    pub fn space_complexity(&self) -> String;                 // 1.4.2.i O(V)
}

pub struct EdgeClassification {
    tree: Vec<(usize, usize)>,                                // 1.4.2.j
    back: Vec<(usize, usize)>,
    forward: Vec<(usize, usize)>,
    cross: Vec<(usize, usize)>,
}
```

---

## Exercice 03: BFS Navigator
**Concepts couverts**: 1.4.3.a-i (9 concepts)
**Difficulté**: ⭐⭐

### Objectif
Maîtriser le parcours en largeur.

```rust
use std::collections::VecDeque;

impl AdjList {
    pub fn bfs(&self, start: usize) -> Vec<usize>;            // 1.4.3.a

    // Distances depuis source
    pub fn bfs_distances(&self, start: usize) -> Vec<Option<usize>>; // 1.4.3.b

    // Plus court chemin (non pondéré)
    pub fn shortest_path(&self, start: usize, end: usize) -> Option<Vec<usize>>; // 1.4.3.c

    // BFS bidirectionnel
    pub fn bidirectional_bfs(&self, start: usize, end: usize) -> Option<usize>; // 1.4.3.d

    // Niveaux
    pub fn bfs_levels(&self, start: usize) -> Vec<Vec<usize>>; // 1.4.3.e

    // Applications
    pub fn is_bipartite(&self) -> bool;                       // 1.4.3.f
    pub fn bipartite_coloring(&self) -> Option<Vec<u8>>;      // 1.4.3.g

    // Complexity
    pub fn time_complexity(&self) -> String;                  // 1.4.3.h O(V + E)
    pub fn space_complexity(&self) -> String;                 // 1.4.3.i O(V)
}
```

---

## Exercice 04: Union-Find
**Concepts couverts**: 1.4.4.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Implémenter Union-Find avec optimisations.

```rust
pub struct UnionFind {
    parent: Vec<usize>,                                       // 1.4.4.a
    rank: Vec<usize>,                                         // 1.4.4.b (ou size)
    count: usize,                                             // nombre de composantes
}

impl UnionFind {
    pub fn new(n: usize) -> Self;                             // 1.4.4.c

    // Find avec path compression
    pub fn find(&mut self, x: usize) -> usize;                // 1.4.4.d

    // Union by rank
    pub fn union(&mut self, x: usize, y: usize) -> bool;      // 1.4.4.e

    pub fn connected(&mut self, x: usize, y: usize) -> bool;  // 1.4.4.f
    pub fn component_count(&self) -> usize;                   // 1.4.4.g

    // Complexité amortie
    pub fn time_complexity(&self) -> String;                  // 1.4.4.h O(α(n)) ≈ O(1)

    // Applications
    pub fn is_connected(&mut self) -> bool;                   // 1.4.4.i
    pub fn component_size(&mut self, x: usize) -> usize;      // 1.4.4.j
}
```

---

## Exercice 05: Connected Components
**Concepts couverts**: 1.4.5.a-i (9 concepts)
**Difficulté**: ⭐⭐

### Objectif
Trouver les composantes connexes.

```rust
impl AdjList {
    // DFS-based
    pub fn connected_components_dfs(&self) -> Vec<Vec<usize>>; // 1.4.5.a

    // BFS-based
    pub fn connected_components_bfs(&self) -> Vec<Vec<usize>>; // 1.4.5.b

    // Union-Find based
    pub fn connected_components_uf(&self) -> Vec<Vec<usize>>; // 1.4.5.c

    // Labeling
    pub fn component_labels(&self) -> Vec<usize>;             // 1.4.5.d

    // Largest component
    pub fn largest_component(&self) -> Vec<usize>;            // 1.4.5.e

    // Nombre de composantes
    pub fn num_components(&self) -> usize;                    // 1.4.5.f

    // Articulation points
    pub fn articulation_points(&self) -> Vec<usize>;          // 1.4.5.g

    // Bridges
    pub fn bridges(&self) -> Vec<(usize, usize)>;             // 1.4.5.h

    // Biconnected components
    pub fn biconnected_components(&self) -> Vec<Vec<usize>>;  // 1.4.5.i
}
```

---

## Exercice 06: Topological Sort
**Concepts couverts**: 1.4.6.a-i (9 concepts)
**Difficulté**: ⭐⭐

### Objectif
Tri topologique de DAG.

```rust
impl AdjList {
    // Kahn's algorithm (BFS-based)
    pub fn topological_sort_kahn(&self) -> Option<Vec<usize>>; // 1.4.6.a

    // DFS-based
    pub fn topological_sort_dfs(&self) -> Option<Vec<usize>>; // 1.4.6.b

    // Vérifier si DAG
    pub fn is_dag(&self) -> bool;                             // 1.4.6.c

    // Toutes les ordonnances topologiques
    pub fn all_topological_orders(&self) -> Vec<Vec<usize>>;  // 1.4.6.d

    // Nombre d'ordonnances
    pub fn count_topological_orders(&self) -> usize;          // 1.4.6.e

    // Plus long chemin dans DAG
    pub fn longest_path_dag(&self) -> Vec<usize>;             // 1.4.6.f

    // Shortest path in DAG (O(V+E))
    pub fn shortest_path_dag(&self, start: usize) -> Vec<i64>; // 1.4.6.g

    // Critical path
    pub fn critical_path(&self) -> (i64, Vec<usize>);         // 1.4.6.h

    // Applications: scheduling
    pub fn task_scheduling(&self, durations: &[i64]) -> Vec<(usize, i64)>; // 1.4.6.i
}
```

---

# BLOC B: Composantes Fortement Connexes (Exercices 07-08)

## Exercice 07: SCC Algorithms
**Concepts couverts**: 1.4.7.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Trouver les SCC d'un graphe orienté.

```rust
impl AdjList {
    // Kosaraju's Algorithm
    pub fn scc_kosaraju(&self) -> Vec<Vec<usize>>;            // 1.4.7.a
    fn reverse_graph(&self) -> AdjList;                       // 1.4.7.b
    fn dfs_order(&self) -> Vec<usize>;                        // 1.4.7.c

    // Tarjan's Algorithm
    pub fn scc_tarjan(&self) -> Vec<Vec<usize>>;              // 1.4.7.d
    // low-link values                                        // 1.4.7.e
    // on-stack tracking                                      // 1.4.7.f

    // Condensation graph (DAG of SCCs)
    pub fn condensation(&self) -> (AdjList, Vec<usize>);      // 1.4.7.g

    // Reachability in condensation
    pub fn scc_reachability(&self) -> Vec<Vec<bool>>;         // 1.4.7.h

    // Complexity
    pub fn time_complexity(&self) -> String;                  // 1.4.7.i O(V + E)

    // Applications
    pub fn is_strongly_connected(&self) -> bool;              // 1.4.7.j
}
```

---

## Exercice 08: 2-SAT Solver
**Concepts couverts**: 1.4.8.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
Résoudre 2-SAT via implication graph.

```rust
pub struct TwoSat {
    n: usize,
    graph: AdjList,                                           // 1.4.8.a (implication graph)
}

impl TwoSat {
    pub fn new(n: usize) -> Self;                             // 1.4.8.b

    // Ajouter clause (a ∨ b)
    pub fn add_clause(&mut self, a: i32, b: i32);             // 1.4.8.c
    // a = var si positif, ¬var si négatif

    // Implication: ¬a → b et ¬b → a
    fn add_implication(&mut self, a: i32, b: i32);            // 1.4.8.d

    // Résoudre
    pub fn solve(&self) -> Option<Vec<bool>>;                 // 1.4.8.e

    // Utilise SCC
    fn check_satisfiability(&self) -> bool;                   // 1.4.8.f
    fn assign_values(&self) -> Vec<bool>;                     // 1.4.8.g

    // Applications
    pub fn solve_with_implications(&self, fixed: &[(usize, bool)]) -> Option<Vec<bool>>; // 1.4.8.h
}
```

---

# BLOC C: Shortest Paths (Exercices 09-13)

## Exercice 09: Dijkstra
**Concepts couverts**: 1.4.9.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Implémenter Dijkstra avec différentes structures.

```rust
use std::collections::BinaryHeap;
use std::cmp::Reverse;

impl AdjList {
    // Dijkstra avec priority queue
    pub fn dijkstra(&self, start: usize) -> Vec<i64>;         // 1.4.9.a

    // Avec reconstruction du chemin
    pub fn dijkstra_path(&self, start: usize, end: usize) -> Option<(i64, Vec<usize>)>; // 1.4.9.b

    // Dijkstra bidirectionnel
    pub fn dijkstra_bidirectional(&self, start: usize, end: usize) -> Option<i64>; // 1.4.9.c

    // Variantes de priority queue
    pub fn dijkstra_binary_heap(&self, start: usize) -> Vec<i64>;  // 1.4.9.d O((V+E) log V)
    pub fn dijkstra_fibonacci_heap(&self, start: usize) -> Vec<i64>; // 1.4.9.e O(V log V + E)

    // Optimisations
    fn early_termination(&self, start: usize, end: usize) -> i64;   // 1.4.9.f

    // Limitation: poids négatifs
    pub fn has_negative_weights(&self) -> bool;                     // 1.4.9.g

    // Multiple sources
    pub fn dijkstra_multi_source(&self, sources: &[usize]) -> Vec<i64>; // 1.4.9.h

    // K shortest paths
    pub fn k_shortest_paths(&self, start: usize, end: usize, k: usize) -> Vec<(i64, Vec<usize>)>; // 1.4.9.i

    // Dial's algorithm (bounded weights)
    pub fn dial(&self, start: usize, max_weight: usize) -> Vec<i64>; // 1.4.9.j
}
```

---

## Exercice 10: Bellman-Ford
**Concepts couverts**: 1.4.10.a-j (10 concepts) [Note: Floyd-Warshall dans curriculum]
**Difficulté**: ⭐⭐⭐

### Objectif
Plus courts chemins avec poids négatifs.

```rust
impl AdjList {
    // Bellman-Ford standard
    pub fn bellman_ford(&self, start: usize) -> Result<Vec<i64>, Vec<usize>>; // 1.4.10.a
    // Ok(distances) ou Err(negative_cycle)

    // Détection cycle négatif
    pub fn has_negative_cycle(&self) -> bool;                 // 1.4.10.b

    // Trouver le cycle négatif
    pub fn find_negative_cycle(&self) -> Option<Vec<usize>>;  // 1.4.10.c

    // SPFA (Shortest Path Faster Algorithm)
    pub fn spfa(&self, start: usize) -> Result<Vec<i64>, Vec<usize>>; // 1.4.10.d

    // Complexité
    pub fn time_complexity(&self) -> String;                  // 1.4.10.e O(VE)

    // Applications
    pub fn arbitrage_detection(&self) -> Option<Vec<usize>>;  // 1.4.10.f
}
```

---

## Exercice 11: Floyd-Warshall
**Concepts couverts**: 1.4.10.a-j (repris)
**Difficulté**: ⭐⭐⭐

### Objectif
All-pairs shortest paths.

```rust
pub struct AllPairsShortestPaths {
    dist: Vec<Vec<i64>>,                                      // 1.4.10.a
    next: Vec<Vec<Option<usize>>>,                            // pour reconstruction
}

impl AllPairsShortestPaths {
    // Floyd-Warshall
    pub fn floyd_warshall(graph: &AdjMatrix) -> Self;         // 1.4.10.b

    // DP: dist[i][j] = min(dist[i][j], dist[i][k] + dist[k][j])  // 1.4.10.c

    // Space optimization (in-place)
    pub fn floyd_warshall_inplace(dist: &mut Vec<Vec<i64>>);  // 1.4.10.d

    // Initialization
    fn initialize(graph: &AdjMatrix) -> Vec<Vec<i64>>;        // 1.4.10.e

    // Complexity O(V³)                                        // 1.4.10.f

    // Détection cycle négatif
    pub fn has_negative_cycle(&self) -> bool;                 // 1.4.10.g

    // Reconstruction chemin
    pub fn path(&self, u: usize, v: usize) -> Option<Vec<usize>>; // 1.4.10.h

    // Transitive closure
    pub fn transitive_closure(&self) -> Vec<Vec<bool>>;       // 1.4.10.i

    // When to use
    pub fn when_to_use() -> String;                           // 1.4.10.j
}
```

---

## Exercice 12: A* Algorithm
**Concepts couverts**: 1.4.11.a-m (13 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
Implémenter A* avec différentes heuristiques.

```rust
pub trait Heuristic {
    fn h(&self, node: usize, goal: usize) -> i64;
}

pub struct AStar<H: Heuristic> {
    graph: AdjList,
    heuristic: H,
}

impl<H: Heuristic> AStar<H> {
    pub fn search(&self, start: usize, goal: usize) -> Option<(i64, Vec<usize>)>;  // 1.4.11.a

    // f(n) = g(n) + h(n)                                     // 1.4.11.b
    // g(n): cost from start                                  // 1.4.11.c
    // h(n): heuristic estimate to goal                       // 1.4.11.d

    fn is_admissible(&self) -> bool;                          // 1.4.11.e (h ≤ actual)
    fn is_consistent(&self) -> bool;                          // 1.4.11.f (h(n) ≤ c(n,n') + h(n'))
}

// Heuristiques communes
pub struct ManhattanDistance { ... }                          // 1.4.11.g
pub struct EuclideanDistance { ... }                          // 1.4.11.h
pub struct ChebyshevDistance { ... }                          // 1.4.11.i

// IDA* (Iterative Deepening A*)
pub struct IDAStar<H: Heuristic> { ... }                      // 1.4.11.j

// Optimisations
impl<H: Heuristic> AStar<H> {
    pub fn search_with_limit(&self, start: usize, goal: usize, limit: usize) -> Option<...>; // 1.4.11.k
    pub fn nodes_expanded(&self) -> usize;                    // 1.4.11.l
    pub fn compare_with_dijkstra(&self) -> ComparisonResult;  // 1.4.11.m
}
```

---

## Exercice 13: Johnson's Algorithm
**Concepts couverts**: 1.4.12.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
All-pairs shortest paths pour graphes sparse.

```rust
impl AdjList {
    // Johnson's Algorithm
    pub fn johnson(&self) -> Option<Vec<Vec<i64>>>;           // 1.4.12.a

    // Étapes
    fn add_dummy_vertex(&self) -> AdjList;                    // 1.4.12.b
    fn bellman_ford_reweighting(&self) -> Option<Vec<i64>>;   // 1.4.12.c
    fn reweight_edges(&self, h: &[i64]) -> AdjList;           // 1.4.12.d
    fn run_dijkstra_all(&self) -> Vec<Vec<i64>>;              // 1.4.12.e
    fn restore_weights(&self, dist: &mut Vec<Vec<i64>>, h: &[i64]); // 1.4.12.f

    // Complexity O(VE + V² log V)                             // 1.4.12.g

    // Quand utiliser vs Floyd-Warshall
    pub fn when_to_use() -> String;                           // 1.4.12.h
}
```

---

# BLOC D: Minimum Spanning Trees (Exercices 14-15)

## Exercice 14: MST Algorithms
**Concepts couverts**: 1.4.13.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Implémenter Kruskal et Prim.

```rust
pub struct MstResult {
    edges: Vec<(usize, usize, i64)>,
    total_weight: i64,
}

impl AdjList {
    // Kruskal avec Union-Find
    pub fn kruskal(&self) -> MstResult;                       // 1.4.13.a
    // Complexité O(E log E)                                  // 1.4.13.b

    // Prim avec priority queue
    pub fn prim(&self, start: usize) -> MstResult;            // 1.4.13.c
    // Complexité O(E log V)                                  // 1.4.13.d

    // Prim avec Fibonacci heap
    pub fn prim_fibonacci(&self, start: usize) -> MstResult;  // 1.4.13.e

    // Vérification MST
    pub fn verify_mst(&self, mst: &MstResult) -> bool;        // 1.4.13.f

    // MST unique?
    pub fn is_mst_unique(&self) -> bool;                      // 1.4.13.g

    // Second-best MST
    pub fn second_best_mst(&self) -> Option<MstResult>;       // 1.4.13.h

    // Minimum spanning forest
    pub fn minimum_spanning_forest(&self) -> Vec<MstResult>;  // 1.4.13.i

    // Bottleneck MST
    pub fn bottleneck_path(&self, mst: &MstResult, u: usize, v: usize) -> i64; // 1.4.13.j
}
```

---

## Exercice 15: MST Variations
**Concepts couverts**: 1.4.14.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
Variations et applications de MST.

```rust
impl AdjList {
    // Minimum bottleneck spanning tree
    pub fn mbst(&self) -> MstResult;                          // 1.4.14.a

    // Maximum spanning tree
    pub fn maximum_spanning_tree(&self) -> MstResult;         // 1.4.14.b

    // Steiner tree (NP-hard, approximation)
    pub fn steiner_tree_approx(&self, terminals: &[usize]) -> MstResult; // 1.4.14.c

    // Degree-constrained MST
    pub fn degree_constrained_mst(&self, max_degree: usize) -> Option<MstResult>; // 1.4.14.d

    // Online MST
    pub fn online_mst_insert(&mut self, mst: &mut MstResult, edge: (usize, usize, i64)); // 1.4.14.e
    pub fn online_mst_delete(&mut self, mst: &mut MstResult, edge: (usize, usize, i64)); // 1.4.14.f

    // Boruvka's algorithm
    pub fn boruvka(&self) -> MstResult;                       // 1.4.14.g

    // Distributed MST (GHS algorithm concepts)
    pub fn ghs_concepts() -> String;                          // 1.4.14.h
}
```

---

# BLOC E: Network Flow (Exercices 16-19)

## Exercice 16: Max Flow Basics
**Concepts couverts**: 1.4.15.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
Implémenter Ford-Fulkerson et Edmonds-Karp.

```rust
pub struct FlowNetwork {
    capacity: Vec<Vec<i64>>,                                  // 1.4.15.a
    flow: Vec<Vec<i64>>,                                      // 1.4.15.b
    n: usize,
}

impl FlowNetwork {
    pub fn new(n: usize) -> Self;
    pub fn add_edge(&mut self, u: usize, v: usize, cap: i64);

    // Ford-Fulkerson (DFS)
    pub fn ford_fulkerson(&mut self, s: usize, t: usize) -> i64; // 1.4.15.c
    fn find_augmenting_path_dfs(&self, s: usize, t: usize) -> Option<Vec<usize>>; // 1.4.15.d

    // Edmonds-Karp (BFS)
    pub fn edmonds_karp(&mut self, s: usize, t: usize) -> i64; // 1.4.15.e
    fn find_augmenting_path_bfs(&self, s: usize, t: usize) -> Option<Vec<usize>>; // 1.4.15.f

    // Residual graph
    fn residual_capacity(&self, u: usize, v: usize) -> i64;   // 1.4.15.g

    // Min cut
    pub fn min_cut(&self, s: usize) -> Vec<(usize, usize)>;   // 1.4.15.h

    // Max-flow min-cut theorem
    pub fn verify_max_flow_min_cut(&self, s: usize, t: usize) -> bool; // 1.4.15.i

    // Complexity
    pub fn edmonds_karp_complexity() -> String;               // 1.4.15.j O(VE²)
}
```

---

## Exercice 17: Advanced Max Flow
**Concepts couverts**: 1.4.16.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐⭐

### Objectif
Algorithmes de flot avancés.

```rust
impl FlowNetwork {
    // Dinic's Algorithm
    pub fn dinic(&mut self, s: usize, t: usize) -> i64;       // 1.4.16.a
    fn build_level_graph(&self, s: usize) -> Option<Vec<i32>>; // 1.4.16.b
    fn blocking_flow(&mut self, s: usize, t: usize, levels: &[i32]) -> i64; // 1.4.16.c
    // Complexity O(V²E)                                       // 1.4.16.d

    // Push-Relabel
    pub fn push_relabel(&mut self, s: usize, t: usize) -> i64; // 1.4.16.e
    fn push(&mut self, u: usize, v: usize);                   // 1.4.16.f
    fn relabel(&mut self, u: usize);                          // 1.4.16.g
    // Complexity O(V²E) or O(V³) with FIFO                   // 1.4.16.h
}
```

---

## Exercice 18: Min Cost Max Flow
**Concepts couverts**: 1.4.17.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐⭐

### Objectif
Flot de coût minimum.

```rust
pub struct MinCostFlowNetwork {
    capacity: Vec<Vec<i64>>,
    cost: Vec<Vec<i64>>,                                      // 1.4.17.a
    flow: Vec<Vec<i64>>,
    n: usize,
}

impl MinCostFlowNetwork {
    pub fn add_edge(&mut self, u: usize, v: usize, cap: i64, cost: i64);

    // Successive Shortest Paths
    pub fn min_cost_max_flow(&mut self, s: usize, t: usize) -> (i64, i64); // 1.4.17.b
    // Returns (flow, cost)

    fn shortest_path_bellman_ford(&self, s: usize, t: usize) -> Option<(Vec<usize>, i64)>; // 1.4.17.c

    // Cycle-canceling
    pub fn cycle_canceling(&mut self, s: usize, t: usize) -> (i64, i64); // 1.4.17.d
    fn find_negative_cycle(&self) -> Option<Vec<usize>>;      // 1.4.17.e

    // SPFA for min cost
    pub fn spfa_min_cost(&mut self, s: usize, t: usize) -> (i64, i64); // 1.4.17.f

    // Applications
    pub fn assignment_problem(&self) -> Vec<(usize, usize)>;  // 1.4.17.g
    pub fn transportation_problem(&self) -> Vec<Vec<i64>>;    // 1.4.17.h
}
```

---

## Exercice 19: Bipartite Matching
**Concepts couverts**: 1.4.18.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
Maximum bipartite matching.

```rust
pub struct BipartiteGraph {
    left: usize,                                              // 1.4.18.a
    right: usize,
    adj: Vec<Vec<usize>>,
}

impl BipartiteGraph {
    // Hungarian algorithm (Kuhn's)
    pub fn max_matching(&self) -> Vec<(usize, usize)>;        // 1.4.18.b
    fn augment(&self, u: usize, match_: &mut [Option<usize>], visited: &mut [bool]) -> bool; // 1.4.18.c

    // Hopcroft-Karp O(E√V)
    pub fn hopcroft_karp(&self) -> Vec<(usize, usize)>;       // 1.4.18.d

    // König's theorem
    pub fn minimum_vertex_cover(&self) -> Vec<usize>;         // 1.4.18.e

    // Maximum independent set
    pub fn maximum_independent_set(&self) -> Vec<usize>;      // 1.4.18.f

    // Hall's theorem check
    pub fn has_perfect_matching(&self) -> bool;               // 1.4.18.g

    // Weighted matching (Hungarian)
    pub fn min_cost_matching(&self, weights: &[Vec<i64>]) -> (i64, Vec<(usize, usize)>); // 1.4.18.h

    // Applications
    pub fn job_assignment(&self, costs: &[Vec<i64>]) -> Vec<(usize, usize)>; // 1.4.18.i
    pub fn stable_matching_gale_shapley(&self, prefs_left: &[Vec<usize>], prefs_right: &[Vec<usize>]) -> Vec<(usize, usize)>; // 1.4.18.j
}
```

---

# BLOC F: Advanced Graph Algorithms (Exercices 20-23)

## Exercice 20: Eulerian & Hamiltonian
**Concepts couverts**: 1.4.19.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Chemins et circuits eulériens/hamiltoniens.

```rust
impl AdjList {
    // Eulerian
    pub fn is_eulerian(&self) -> bool;                        // 1.4.19.a
    pub fn has_euler_path(&self) -> bool;                     // 1.4.19.b
    pub fn euler_circuit(&self) -> Option<Vec<usize>>;        // 1.4.19.c (Hierholzer)
    pub fn euler_path(&self) -> Option<Vec<usize>>;           // 1.4.19.d

    // Hamiltonian (NP-complete)
    pub fn hamiltonian_path_backtrack(&self) -> Option<Vec<usize>>; // 1.4.19.e
    pub fn hamiltonian_cycle_dp(&self) -> Option<Vec<usize>>; // 1.4.19.f O(n² * 2^n)

    // TSP approximation
    pub fn tsp_nearest_neighbor(&self) -> (i64, Vec<usize>);  // 1.4.19.g
    pub fn tsp_christofides(&self) -> (i64, Vec<usize>);      // 1.4.19.h (1.5-approx)
}
```

---

## Exercice 21: Graph Coloring
**Concepts couverts**: 1.4.20.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Algorithmes de coloration.

```rust
impl AdjList {
    // Greedy coloring
    pub fn greedy_coloring(&self) -> Vec<usize>;              // 1.4.20.a

    // Welsh-Powell
    pub fn welsh_powell(&self) -> Vec<usize>;                 // 1.4.20.b

    // DSatur
    pub fn dsatur(&self) -> Vec<usize>;                       // 1.4.20.c

    // Chromatic number (exact, exponential)
    pub fn chromatic_number_exact(&self) -> usize;            // 1.4.20.d

    // k-colorable check
    pub fn is_k_colorable(&self, k: usize) -> bool;           // 1.4.20.e

    // Edge coloring
    pub fn edge_coloring(&self) -> Vec<usize>;                // 1.4.20.f

    // Interval graph coloring
    pub fn interval_graph_coloring(&self) -> usize;           // 1.4.20.g

    // Applications
    pub fn register_allocation(&self) -> Vec<usize>;          // 1.4.20.h
}
```

---

## Exercice 22: Planar Graphs
**Concepts couverts**: 1.4.21.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
Tester et exploiter la planarité.

```rust
impl AdjList {
    // Euler's formula: V - E + F = 2                         // 1.4.21.a

    // Planarity test (Kuratowski)
    pub fn is_planar(&self) -> bool;                          // 1.4.21.b

    // Boyer-Myrvold algorithm
    pub fn boyer_myrvold(&self) -> bool;                      // 1.4.21.c

    // Find Kuratowski subgraph
    pub fn find_kuratowski(&self) -> Option<AdjList>;         // 1.4.21.d

    // Planar embedding
    pub fn planar_embedding(&self) -> Option<PlanarEmbedding>; // 1.4.21.e

    // Faces of planar graph
    pub fn find_faces(&self, embedding: &PlanarEmbedding) -> Vec<Vec<usize>>; // 1.4.21.f

    // 4-coloring (planar graphs)
    pub fn four_coloring(&self) -> Option<Vec<usize>>;        // 1.4.21.g

    // Outerplanar check
    pub fn is_outerplanar(&self) -> bool;                     // 1.4.21.h
}
```

---

## Exercice 23: Special Graphs
**Concepts couverts**: 1.4.22.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Algorithmes pour graphes spéciaux.

```rust
// Graphe d'intervalles
pub struct IntervalGraph {
    intervals: Vec<(i64, i64)>,
}

impl IntervalGraph {
    pub fn build(&self) -> AdjList;                           // 1.4.22.a
    pub fn max_clique(&self) -> Vec<usize>;                   // 1.4.22.b (polynomial)
    pub fn chromatic_number(&self) -> usize;                  // 1.4.22.c
}

// Graphe de comparabilité
impl AdjList {
    pub fn is_comparability(&self) -> bool;                   // 1.4.22.d
    pub fn transitive_orientation(&self) -> Option<AdjList>;  // 1.4.22.e
}

// Cographs
impl AdjList {
    pub fn is_cograph(&self) -> bool;                         // 1.4.22.f
    pub fn cotree(&self) -> Option<CoTree>;                   // 1.4.22.g
}

// Chordal graphs
impl AdjList {
    pub fn is_chordal(&self) -> bool;                         // 1.4.22.h
    pub fn perfect_elimination_order(&self) -> Option<Vec<usize>>;
}
```

---

# BLOC G: Projet Final (Exercice 24)

## Exercice 24: Network Analysis Tool
**Concepts couverts**: 1.4.a-p (16 concepts du projet)
**Difficulté**: ⭐⭐⭐⭐⭐

### Objectif
Outil d'analyse de réseaux complet.

```rust
pub struct NetworkAnalyzer {
    graph: AdjList,                                           // 1.4.a
    uf: UnionFind,                                            // 1.4.b
}

impl NetworkAnalyzer {
    // Traversals
    pub fn bfs_dfs_analysis(&self, start: usize) -> TraversalResult; // 1.4.c

    // Connectivity
    pub fn connected_components(&self) -> Vec<Vec<usize>>;    // 1.4.d

    // Ordering
    pub fn topological_sort(&self) -> Option<Vec<usize>>;     // 1.4.e

    // Strong connectivity
    pub fn strongly_connected_components(&self) -> Vec<Vec<usize>>; // 1.4.f

    // Shortest paths
    pub fn shortest_paths(&self, algo: ShortestPathAlgo) -> PathResult; // 1.4.g

    // MST
    pub fn minimum_spanning_tree(&self) -> MstResult;         // 1.4.h

    // Flow
    pub fn max_flow(&self, s: usize, t: usize) -> i64;        // 1.4.i

    // Matching
    pub fn bipartite_matching(&self) -> Vec<(usize, usize)>;  // 1.4.j

    // Visualization (DOT format)
    pub fn to_dot(&self) -> String;                           // 1.4.k

    // CLI
    pub fn cli_handler(args: &[String]) -> Result<String, Error>; // 1.4.l

    // File format
    pub fn load_from_file(path: &Path) -> io::Result<Self>;   // 1.4.m
    pub fn save_to_file(&self, path: &Path) -> io::Result<()>;

    // Benchmarks
    pub fn benchmark(&self, n: usize) -> BenchmarkResults;    // 1.4.n

    // Bonus: A*
    pub fn astar(&self, start: usize, goal: usize) -> Option<(i64, Vec<usize>)>; // 1.4.o

    // Bonus: 2-SAT
    pub fn solve_2sat(&self, clauses: &[(i32, i32)]) -> Option<Vec<bool>>; // 1.4.p
}
```

### CLI Interface
```bash
network_tool load graph.txt
network_tool components
network_tool shortest-path dijkstra 0 5
network_tool mst kruskal
network_tool max-flow 0 10
network_tool visualize output.dot
network_tool benchmark 10000
```

---

# RÉCAPITULATIF

| Bloc | Exercices | Concepts | Description |
|------|-----------|----------|-------------|
| A | 01-06 | 62 | Représentations & Parcours |
| B | 07-08 | 18 | SCC & 2-SAT |
| C | 09-13 | 49 | Shortest Paths |
| D | 14-15 | 18 | MST |
| E | 16-19 | 36 | Network Flow |
| F | 20-23 | 32 | Advanced Algorithms |
| G | 24 | 16 | Projet Network Tool |
| **TOTAL** | **24** | **264** | **Module 1.4 complet** |

---
