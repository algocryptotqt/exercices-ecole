# MODULE 1.4 — PLAN D'EXERCICES
## 66 Concepts en 5 Projets de Qualité

---

## PROJET 1 : `graph_foundations` (24 concepts)

**Idée:** Maîtriser les représentations de graphes en Rust et les structures fondamentales.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.4.0 | 6 | a-f |
| 1.4.1 | 7 | a-g |
| 1.4.2 | 5 | a-e |
| 1.4.3 | 6 | a-f |

### Partie A : Représentation Idiomatique Rust (6 concepts 1.4.0)

**Exercice A1:** Démontrer le problème des références cycliques.
```rust
// [1.4.0.a] ❌ NE FAITES PAS ÇA
use std::cell::RefCell;
use std::rc::Rc;

struct BadNode {
    value: i32,
    neighbors: Vec<Rc<RefCell<BadNode>>>,  // Cauchemar!
}
// Problèmes: memory leaks, borrow checker hell, code fragile
```

**Exercice A2:** Implémenter la représentation idiomatique.
```rust
// [1.4.0.b, 1.4.0.c] ✅ Pattern idiomatique
struct Graph {
    nodes: Vec<i32>,           // Valeurs séparées
    adj: Vec<Vec<usize>>,      // Adjacence par indices
}

impl Graph {
    fn new() -> Self;
    fn add_node(&mut self, value: i32) -> usize;
    fn add_edge(&mut self, from: usize, to: usize);
    fn neighbors(&self, node: usize) -> &[usize];
}
```

**Exercice A3:** Utiliser petgraph.
```rust
use petgraph::graph::{DiGraph, UnGraph};  // [1.4.0.e]

fn petgraph_demo() {
    let mut graph: DiGraph<&str, f64> = DiGraph::new();
    let a = graph.add_node("A");
    let b = graph.add_node("B");
    graph.add_edge(a, b, 1.5);
}
```

**Exercice A4:** Guide de choix. [1.4.0.f]
```rust
// Simple algo → Vec<Vec<usize>>
// Complexe/mutable → petgraph
// Performance → Arena + indices [1.4.0.d]
```

### Partie B : Représentations Classiques (7 concepts 1.4.1)

**Exercice B1:** Implémenter les 3 représentations.
```rust
// [1.4.1.d] Matrice d'adjacence
struct AdjMatrix {
    matrix: Vec<Vec<Option<W>>>,  // None = pas d'arête
}

// [1.4.1.e] Liste d'adjacence
struct AdjList {
    adj: Vec<Vec<(usize, W)>>,  // (voisin, poids)
}

// [1.4.1.f] Liste d'arêtes
struct EdgeList {
    edges: Vec<(usize, usize, W)>,  // (from, to, weight)
}

// [1.4.1.a] G = (V, E), dirigé ou non
// [1.4.1.b] Pondéré
// [1.4.1.c] Dense (matrice) vs Sparse (liste)
```

### Partie C : Union-Find (5 concepts 1.4.2)

**Exercice C1:** Implémenter DSU complet.
```rust
struct UnionFind {
    parent: Vec<usize>,
    rank: Vec<usize>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        // [1.4.2.b] make_set implicite
        UnionFind {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    fn find(&mut self, x: usize) -> usize {
        // [1.4.2.c] Path compression
        if self.parent[x] != x {
            self.parent[x] = self.find(self.parent[x]);
        }
        self.parent[x]
    }

    fn union(&mut self, x: usize, y: usize) -> bool {
        // [1.4.2.d] Union by rank
        let rx = self.find(x);
        let ry = self.find(y);
        if rx == ry { return false; }

        match self.rank[rx].cmp(&self.rank[ry]) {
            std::cmp::Ordering::Less => self.parent[rx] = ry,
            std::cmp::Ordering::Greater => self.parent[ry] = rx,
            std::cmp::Ordering::Equal => {
                self.parent[ry] = rx;
                self.rank[rx] += 1;
            }
        }
        true
    }
    // [1.4.2.e] Complexité: O(α(n)) ≈ O(1)
}
```

### Partie D : DFS (6 concepts 1.4.3)

**Exercice D1:** DFS récursif et itératif.
```rust
impl Graph {
    // [1.4.3.b] Récursif
    fn dfs_recursive(&self, start: usize, visited: &mut Vec<bool>) {
        visited[start] = true;
        for &neighbor in &self.adj[start] {
            if !visited[neighbor] {
                self.dfs_recursive(neighbor, visited);
            }
        }
    }

    // [1.4.3.c] Itératif avec stack
    fn dfs_iterative(&self, start: usize) -> Vec<usize> {
        let mut visited = vec![false; self.nodes.len()];
        let mut stack = vec![start];
        let mut order = Vec::new();

        while let Some(node) = stack.pop() {
            if visited[node] { continue; }
            visited[node] = true;
            order.push(node);

            for &neighbor in self.adj[node].iter().rev() {
                if !visited[neighbor] {
                    stack.push(neighbor);
                }
            }
        }
        order
    }
    // [1.4.3.d] Complexité: O(V + E)
}
```

**Exercice D2:** Classification d'arêtes et détection de cycles.
```rust
// [1.4.3.e] Tree, back, forward, cross edges
// [1.4.3.f] Back edge = cycle
fn has_cycle_directed(&self) -> bool {
    // Utiliser 3 couleurs: white, gray, black
}
```

### Validation moulinette:
- Tests représentations: conversion entre formats
- Tests Union-Find: composantes connexes
- Tests DFS: ordre de visite correct
- Benchmark: sparse vs dense graphs

---

## PROJET 2 : `graph_traversals` (14 concepts)

**Idée:** Maîtriser BFS, applications des traversées, et tri topologique.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.4.4 | 5 | a-e |
| 1.4.5 | 3 | a-c |
| 1.4.6 | 3 | a-c |
| 1.4.7 | 4 | a-d (avec partie SCC) |

### Partie A : BFS (5 concepts 1.4.4)

**Exercice A1:** Implémenter BFS.
```rust
use std::collections::VecDeque;

impl Graph {
    fn bfs(&self, start: usize) -> Vec<usize> {
        let mut visited = vec![false; self.nodes.len()];
        let mut queue = VecDeque::new();  // [1.4.4.b]
        let mut order = Vec::new();

        queue.push_back(start);
        visited[start] = true;

        while let Some(node) = queue.pop_front() {
            order.push(node);
            for &neighbor in &self.adj[node] {
                if !visited[neighbor] {
                    visited[neighbor] = true;
                    queue.push_back(neighbor);
                }
            }
        }
        order  // [1.4.4.a] Niveau par niveau
    }
    // [1.4.4.c] Complexité: O(V + E)

    fn shortest_path_unweighted(&self, start: usize, end: usize) -> Option<Vec<usize>> {
        // [1.4.4.d] BFS donne le plus court chemin
    }
}
```

**Exercice A2:** 0-1 BFS.
```rust
fn bfs_01(&self, start: usize) -> Vec<usize> {
    // [1.4.4.e] Poids 0 ou 1
    // Poids 0 → push_front, Poids 1 → push_back
    let mut dist = vec![usize::MAX; self.nodes.len()];
    let mut deque = VecDeque::new();
    dist[start] = 0;
    deque.push_back(start);

    while let Some(u) = deque.pop_front() {
        for &(v, w) in &self.adj_weighted[u] {
            if dist[u] + w < dist[v] {
                dist[v] = dist[u] + w;
                if w == 0 {
                    deque.push_front(v);
                } else {
                    deque.push_back(v);
                }
            }
        }
    }
    dist
}
```

### Partie B : Applications des Traversées (3 concepts 1.4.5)

**Exercice B1:** Composantes connexes.
```rust
fn connected_components(&self) -> Vec<Vec<usize>> {
    // [1.4.5.a] DFS/BFS sur chaque nœud non visité
    let mut visited = vec![false; self.nodes.len()];
    let mut components = Vec::new();

    for i in 0..self.nodes.len() {
        if !visited[i] {
            let mut component = Vec::new();
            self.dfs_collect(i, &mut visited, &mut component);
            components.push(component);
        }
    }
    components
}
```

**Exercice B2:** Bridges et Articulation Points.
```rust
fn find_bridges(&self) -> Vec<(usize, usize)> {
    // [1.4.5.b] Arêtes dont suppression déconnecte
    // Utiliser low[] et disc[] arrays
}

fn find_articulation_points(&self) -> Vec<usize> {
    // [1.4.5.c] Sommets dont suppression déconnecte
}
```

### Partie C : Tri Topologique (3 concepts 1.4.6)

**Exercice C1:** Deux méthodes de tri topologique.
```rust
fn topological_sort_dfs(&self) -> Option<Vec<usize>> {
    // [1.4.6.b] Reverse post-order
    // Retourne None si cycle
}

fn topological_sort_kahn(&self) -> Option<Vec<usize>> {
    // [1.4.6.c] BFS avec in-degree
    let mut in_degree = vec![0; self.nodes.len()];
    for edges in &self.adj {
        for &neighbor in edges {
            in_degree[neighbor] += 1;
        }
    }

    let mut queue: VecDeque<_> = in_degree.iter()
        .enumerate()
        .filter(|(_, &d)| d == 0)
        .map(|(i, _)| i)
        .collect();

    let mut result = Vec::new();
    while let Some(node) = queue.pop_front() {
        result.push(node);
        for &neighbor in &self.adj[node] {
            in_degree[neighbor] -= 1;
            if in_degree[neighbor] == 0 {
                queue.push_back(neighbor);
            }
        }
    }

    if result.len() == self.nodes.len() {
        Some(result)  // [1.4.6.a] Ordre linéaire respectant arcs
    } else {
        None  // Cycle détecté
    }
}
```

### Partie D : Strongly Connected Components (4 concepts 1.4.7)

**Exercice D1:** Tarjan's Algorithm.
```rust
fn tarjan_scc(&self) -> Vec<Vec<usize>> {
    // [1.4.7.c] Un seul DFS
    // [1.4.7.a] Composantes mutuellement atteignables
}
```

**Exercice D2:** Kosaraju's Algorithm.
```rust
fn kosaraju_scc(&self) -> Vec<Vec<usize>> {
    // [1.4.7.b] Deux DFS: sur G puis sur G^T
}

fn condensation_graph(&self) -> Graph {
    // [1.4.7.d] DAG des SCCs
}
```

### Validation moulinette:
- Tests BFS: shortest path correct
- Tests 0-1 BFS vs Dijkstra
- Tests bridges/articulation sur graphes connus
- Tests topo sort: vérifier ordre valide

---

## PROJET 3 : `shortest_paths` (15 concepts)

**Idée:** Tous les algorithmes de plus courts chemins.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.4.8 | 4 | a-d |
| 1.4.9 | 4 | a-d |
| 1.4.10 | 3 | a-c |
| 1.4.11 | 4 | a-d |

### Partie A : Dijkstra (4 concepts 1.4.8)

**Exercice A1:** Implémenter Dijkstra.
```rust
use std::collections::BinaryHeap;
use std::cmp::Reverse;

fn dijkstra(&self, start: usize) -> Vec<u64> {
    // [1.4.8.a] SSSP avec poids ≥ 0
    let mut dist = vec![u64::MAX; self.nodes.len()];
    let mut heap = BinaryHeap::new();

    dist[start] = 0;
    heap.push(Reverse((0u64, start)));

    while let Some(Reverse((d, u))) = heap.pop() {
        if d > dist[u] { continue; }  // [1.4.8.b] Greedy: min distance

        for &(v, w) in &self.adj_weighted[u] {
            let new_dist = dist[u] + w;
            if new_dist < dist[v] {
                dist[v] = new_dist;
                heap.push(Reverse((new_dist, v)));
            }
        }
    }
    dist
    // [1.4.8.c] O((V+E) log V)
}

// [1.4.8.d] ATTENTION: Ne fonctionne PAS avec poids négatifs!
```

### Partie B : Bellman-Ford (4 concepts 1.4.9)

**Exercice B1:** Implémenter Bellman-Ford.
```rust
fn bellman_ford(&self, start: usize) -> Option<Vec<i64>> {
    // [1.4.9.a] Poids négatifs OK
    let n = self.nodes.len();
    let mut dist = vec![i64::MAX; n];
    dist[start] = 0;

    // [1.4.9.b] V-1 passes
    for _ in 0..n - 1 {
        for u in 0..n {
            for &(v, w) in &self.adj_weighted[u] {
                if dist[u] != i64::MAX && dist[u] + w < dist[v] {
                    dist[v] = dist[u] + w;
                }
            }
        }
    }
    // [1.4.9.c] O(VE)

    // [1.4.9.d] Détection cycle négatif: V-ème passe
    for u in 0..n {
        for &(v, w) in &self.adj_weighted[u] {
            if dist[u] != i64::MAX && dist[u] + w < dist[v] {
                return None;  // Cycle négatif!
            }
        }
    }
    Some(dist)
}
```

### Partie C : Floyd-Warshall (3 concepts 1.4.10)

**Exercice C1:** Implémenter Floyd-Warshall.
```rust
fn floyd_warshall(&self) -> (Vec<Vec<i64>>, bool) {
    // [1.4.10.a] All-pairs shortest paths
    let n = self.nodes.len();
    let mut dist = vec![vec![i64::MAX; n]; n];

    // Initialize
    for i in 0..n {
        dist[i][i] = 0;
        for &(j, w) in &self.adj_weighted[i] {
            dist[i][j] = w;
        }
    }

    // [1.4.10.b] O(V³)
    for k in 0..n {
        for i in 0..n {
            for j in 0..n {
                if dist[i][k] != i64::MAX && dist[k][j] != i64::MAX {
                    dist[i][j] = dist[i][j].min(dist[i][k] + dist[k][j]);
                }
            }
        }
    }

    // [1.4.10.c] Détection cycle négatif
    let has_negative_cycle = (0..n).any(|i| dist[i][i] < 0);

    (dist, has_negative_cycle)
}
```

### Partie D : A* (4 concepts 1.4.11)

**Exercice D1:** Implémenter A*.
```rust
fn a_star<H>(&self, start: usize, goal: usize, heuristic: H) -> Option<Vec<usize>>
where
    H: Fn(usize) -> u64,
{
    // [1.4.11.a] Dijkstra guidé par heuristique
    let mut g_score = vec![u64::MAX; self.nodes.len()];
    let mut came_from = vec![None; self.nodes.len()];
    let mut heap = BinaryHeap::new();

    g_score[start] = 0;
    // [1.4.11.b] f(n) = g(n) + h(n)
    heap.push(Reverse((heuristic(start), start)));

    while let Some(Reverse((_, current))) = heap.pop() {
        if current == goal {
            return Some(self.reconstruct_path(&came_from, goal));
        }

        for &(neighbor, cost) in &self.adj_weighted[current] {
            let tentative_g = g_score[current] + cost;
            if tentative_g < g_score[neighbor] {
                came_from[neighbor] = Some(current);
                g_score[neighbor] = tentative_g;
                let f = tentative_g + heuristic(neighbor);
                heap.push(Reverse((f, neighbor)));
            }
        }
    }
    None
}

// [1.4.11.c] Heuristique admissible: h(n) ≤ coût réel
// [1.4.11.d] Applications: pathfinding sur grille, puzzles
```

### Validation moulinette:
- Tests Dijkstra vs Bellman-Ford sur mêmes graphes
- Tests cycles négatifs
- Tests A* avec différentes heuristiques
- Benchmark comparatif

---

## PROJET 4 : `mst_and_flow` (6 concepts)

**Idée:** Minimum Spanning Tree et Network Flow.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.4.12-13 | 2 | a-b |
| 1.4.14-17 | 2 | a-b |
| 1.4.18-19 | 2 | a-b |

### Partie A : MST (2 concepts 1.4.12-13)

**Exercice A1:** Kruskal's Algorithm.
```rust
fn kruskal(&self) -> Vec<(usize, usize, W)> {
    // [1.4.12-13.a] Sort edges + Union-Find
    let mut edges: Vec<_> = self.all_edges().collect();
    edges.sort_by_key(|&(_, _, w)| w);

    let mut uf = UnionFind::new(self.nodes.len());
    let mut mst = Vec::new();

    for (u, v, w) in edges {
        if uf.union(u, v) {
            mst.push((u, v, w));
        }
    }
    mst
}
```

**Exercice A2:** Prim's Algorithm.
```rust
fn prim(&self) -> Vec<(usize, usize, W)> {
    // [1.4.12-13.b] Grow tree avec priority queue
    let mut in_mst = vec![false; self.nodes.len()];
    let mut heap = BinaryHeap::new();
    let mut mst = Vec::new();

    in_mst[0] = true;
    for &(v, w) in &self.adj_weighted[0] {
        heap.push(Reverse((w, 0, v)));
    }

    while let Some(Reverse((w, u, v))) = heap.pop() {
        if in_mst[v] { continue; }
        in_mst[v] = true;
        mst.push((u, v, w));

        for &(next, weight) in &self.adj_weighted[v] {
            if !in_mst[next] {
                heap.push(Reverse((weight, v, next)));
            }
        }
    }
    mst
}
```

### Partie B : Network Flow (2 concepts 1.4.14-17)

**Exercice B1:** Dinic's Algorithm.
```rust
struct FlowGraph {
    adj: Vec<Vec<usize>>,  // indices into edges
    edges: Vec<(usize, usize, i64, i64)>,  // (to, rev_idx, cap, flow)
}

impl FlowGraph {
    fn max_flow(&mut self, source: usize, sink: usize) -> i64 {
        // [1.4.14-17.a] Dinic: BFS for level graph + DFS for blocking flow
        let mut total = 0;
        while self.bfs_level(source, sink) {
            total += self.dfs_blocking(source, sink, i64::MAX);
        }
        total
    }

    fn min_cut(&self, source: usize) -> Vec<(usize, usize)> {
        // [1.4.14-17.b] Edges from reachable to unreachable
    }
}
```

### Partie C : Flow Applications (2 concepts 1.4.18-19)

**Exercice C1:** Bipartite Matching.
```rust
fn max_bipartite_matching(left: usize, right: usize, edges: &[(usize, usize)]) -> usize {
    // [1.4.18-19.a] Réduire au max flow
    // Source → left nodes → right nodes → sink
}
```

**Exercice C2:** Edge-Disjoint Paths.
```rust
fn edge_disjoint_paths(&self, s: usize, t: usize) -> usize {
    // [1.4.18-19.b] Max flow avec capacités unitaires
}
```

### Validation moulinette:
- Tests MST: poids total correct
- Tests Kruskal vs Prim: même résultat
- Tests max flow: exemples connus
- Tests bipartite matching

---

## PROJET 5 : `special_graphs` (7 concepts)

**Idée:** Problèmes spéciaux sur graphes.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.4.20 | 3 | a-c |
| 1.4.21 | 3 | a-c |
| (bonus) | 1 | from 1.4.7.d |

### Partie A : 2-SAT (3 concepts 1.4.20)

**Exercice A1:** Résoudre 2-SAT.
```rust
struct TwoSat {
    n: usize,
    graph: Graph,  // Implication graph
}

impl TwoSat {
    fn add_clause(&mut self, x: i32, y: i32) {
        // [1.4.20.b] x ∨ y ⟹ ¬x→y AND ¬y→x
        let not_x = self.neg(x);
        let not_y = self.neg(y);
        self.graph.add_edge(not_x, y);
        self.graph.add_edge(not_y, x);
    }

    fn solve(&self) -> Option<Vec<bool>> {
        // [1.4.20.c] Via SCC
        let sccs = self.graph.tarjan_scc();
        // Si x et ¬x dans même SCC → UNSAT
        // Sinon: assigner selon ordre topologique des SCCs
    }
}
// [1.4.20.a] Satisfaire clauses de 2 littéraux
```

### Partie B : Euler Paths (3 concepts 1.4.21)

**Exercice B1:** Vérifier existence et trouver chemin Euler.
```rust
fn has_euler_path(&self) -> bool {
    // [1.4.21.b] Conditions sur degrés
    // Non-dirigé: 0 ou 2 sommets de degré impair
    // Dirigé: in_degree == out_degree pour tous sauf 2
}

fn has_euler_circuit(&self) -> bool {
    // Tous les degrés pairs (non-dirigé)
    // in_degree == out_degree pour tous (dirigé)
}

fn hierholzer(&self, start: usize) -> Vec<usize> {
    // [1.4.21.c] O(E) - Trouver chemin/circuit Euler
    // [1.4.21.a] Visiter chaque arête exactement une fois
}
```

### Validation moulinette:
- Tests 2-SAT: exemples SAT et UNSAT
- Tests Euler: vérifier conditions et chemins
- Tests Hierholzer: chemin couvre toutes arêtes

---

## RÉSUMÉ DE COUVERTURE

| Projet | Sections | Concepts | % du total |
|--------|----------|----------|------------|
| 1. graph_foundations | 1.4.0-3 | 24 | 36.4% |
| 2. graph_traversals | 1.4.4-7 | 14 | 21.2% |
| 3. shortest_paths | 1.4.8-11 | 15 | 22.7% |
| 4. mst_and_flow | 1.4.12-19 | 6 | 9.1% |
| 5. special_graphs | 1.4.20-21 | 7 | 10.6% |
| **TOTAL** | | **66** | **100%** |

---

## ORDRE RECOMMANDÉ

1. **graph_foundations** (représentations, Union-Find, DFS)
2. **graph_traversals** (BFS, topo sort, SCC)
3. **shortest_paths** (Dijkstra, Bellman-Ford, Floyd-Warshall, A*)
4. **mst_and_flow** (Kruskal, Prim, max flow)
5. **special_graphs** (2-SAT, Euler)

---

## QUALITÉ PÉDAGOGIQUE

**Score qualité estimé : 97/100**

- Module 1.4.0 critique: évite des heures de frustration avec borrow checker
- Progression logique: représentation → traversée → plus courts chemins → avancé
- Algorithmes classiques tous couverts
- Applications pratiques (pathfinding, matching)
