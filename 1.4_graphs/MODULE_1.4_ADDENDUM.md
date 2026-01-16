# MODULE 1.4 - ADDENDUM
## Exercices supplémentaires pour couverture complète

Ces exercices complètent MODULE_1.4_EXERCICES_COMPLETS.md pour atteindre 100% de couverture.

---

## Exercice ADD-1: `rust_graph_idioms`
**Couvre: 1.4.0.a-f (6 concepts)**

### Concepts
- [1.4.0.a] Le problème `Rc<RefCell<Node>>` — Références cycliques
- [1.4.0.b] Solution idiomatique: `Vec<Vec<usize>>` — Liste d'adjacence par indices
- [1.4.0.c] Nodes et Edges séparés — Stockage par Vec
- [1.4.0.d] Arena pattern — Allocation stable
- [1.4.0.e] `petgraph` crate — Bibliothèque standard
- [1.4.0.f] Guide: quelle représentation choisir

### Rust
```rust
use std::cell::RefCell;
use std::rc::Rc;
use petgraph::graph::{DiGraph, UnGraph, NodeIndex};
use petgraph::algo::{dijkstra, is_cyclic_directed};

// ============================================================
// 1.4.0.a - Le problème Rc<RefCell<Node>> - À ÉVITER
// ============================================================

// Cette approche "naïve" cause des problèmes en Rust
struct BadNode {
    value: i32,
    neighbors: Vec<Rc<RefCell<BadNode>>>,  // PROBLÈME!
}

// Problèmes:
// 1. Références cycliques = memory leaks (Rc ne libère jamais)
// 2. RefCell = runtime borrow checking = panics possibles
// 3. Code verbeux: node.borrow().neighbors[0].borrow().value
// 4. Impossible à paralléliser (RefCell n'est pas Sync)

// ============================================================
// 1.4.0.b - Solution idiomatique: Vec<Vec<usize>>
// ============================================================

/// Graph par liste d'adjacence avec INDICES
pub struct IndexGraph {
    nodes: Vec<i32>,              // Valeurs des noeuds
    adj: Vec<Vec<usize>>,         // adj[i] = voisins du noeud i
}

impl IndexGraph {
    pub fn new() -> Self {
        Self { nodes: Vec::new(), adj: Vec::new() }
    }

    pub fn add_node(&mut self, value: i32) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(value);
        self.adj.push(Vec::new());
        idx
    }

    pub fn add_edge(&mut self, from: usize, to: usize) {
        self.adj[from].push(to);
    }

    pub fn neighbors(&self, node: usize) -> &[usize] {
        &self.adj[node]
    }

    pub fn value(&self, node: usize) -> i32 {
        self.nodes[node]
    }
}

// ============================================================
// 1.4.0.c - Nodes et Edges séparés
// ============================================================

/// Représentation avec edges explicites
pub struct SeparatedGraph<N, E> {
    nodes: Vec<N>,
    edges: Vec<(usize, usize, E)>,  // (from, to, weight)
}

impl<N, E> SeparatedGraph<N, E> {
    pub fn new() -> Self {
        Self { nodes: Vec::new(), edges: Vec::new() }
    }

    pub fn add_node(&mut self, data: N) -> usize {
        let idx = self.nodes.len();
        self.nodes.push(data);
        idx
    }

    pub fn add_edge(&mut self, from: usize, to: usize, weight: E) {
        self.edges.push((from, to, weight));
    }

    pub fn edges_from(&self, node: usize) -> impl Iterator<Item = &(usize, usize, E)> {
        self.edges.iter().filter(move |(from, _, _)| *from == node)
    }
}

// ============================================================
// 1.4.0.d - Arena pattern
// ============================================================

/// Arena pour allocation stable
pub struct Arena<T> {
    chunks: Vec<Vec<T>>,
    chunk_size: usize,
}

impl<T> Arena<T> {
    pub fn new(chunk_size: usize) -> Self {
        Self { chunks: vec![Vec::with_capacity(chunk_size)], chunk_size }
    }

    pub fn alloc(&mut self, value: T) -> usize {
        let last = self.chunks.last_mut().unwrap();
        if last.len() >= self.chunk_size {
            self.chunks.push(Vec::with_capacity(self.chunk_size));
        }
        let chunk_idx = self.chunks.len() - 1;
        let inner_idx = self.chunks[chunk_idx].len();
        self.chunks[chunk_idx].push(value);
        chunk_idx * self.chunk_size + inner_idx
    }

    pub fn get(&self, idx: usize) -> Option<&T> {
        let chunk_idx = idx / self.chunk_size;
        let inner_idx = idx % self.chunk_size;
        self.chunks.get(chunk_idx)?.get(inner_idx)
    }
}

// ============================================================
// 1.4.0.e - petgraph crate
// ============================================================

pub fn demonstrate_petgraph() {
    // Graph dirigé
    let mut graph: DiGraph<&str, i32> = DiGraph::new();
    let a = graph.add_node("A");
    let b = graph.add_node("B");
    let c = graph.add_node("C");

    graph.add_edge(a, b, 1);
    graph.add_edge(b, c, 2);
    graph.add_edge(a, c, 5);

    // Dijkstra
    let distances = dijkstra(&graph, a, None, |e| *e.weight());
    println!("Distance A->C: {:?}", distances.get(&c));

    // Détection de cycles
    let has_cycle = is_cyclic_directed(&graph);

    // Graph non-dirigé
    let mut undirected: UnGraph<&str, ()> = UnGraph::new_undirected();
    let n1 = undirected.add_node("N1");
    let n2 = undirected.add_node("N2");
    undirected.add_edge(n1, n2, ());
}

// ============================================================
// 1.4.0.f - Guide: quelle représentation choisir
// ============================================================

/// Guide de sélection de représentation
///
/// | Cas d'usage                    | Représentation recommandée      |
/// |--------------------------------|---------------------------------|
/// | Algorithmes classiques (DFS)   | Vec<Vec<usize>>                 |
/// | Graphes pondérés               | Vec<Vec<(usize, W)>>            |
/// | Modifications fréquentes       | petgraph::Graph                 |
/// | Graphes denses                 | Matrice d'adjacence             |
/// | Graphes statiques optimisés    | CSR (Compressed Sparse Row)     |
/// | Données riches sur noeuds      | SeparatedGraph<N, E>            |
/// | Besoin de références stables   | Arena + indices                 |

pub fn choose_representation(
    dense: bool,
    weighted: bool,
    mutable: bool,
    rich_data: bool,
) -> &'static str {
    match (dense, weighted, mutable, rich_data) {
        (true, _, _, _) => "Matrice d'adjacence: Vec<Vec<bool>> ou Vec<Vec<Option<W>>>",
        (_, _, true, _) => "petgraph::Graph - API complète pour modifications",
        (_, true, false, false) => "Vec<Vec<(usize, W)>> - simple et efficace",
        (_, _, _, true) => "SeparatedGraph<N, E> - données riches séparées",
        _ => "Vec<Vec<usize>> - le défaut pour graphes simples",
    }
}

// ============================================================
// Démonstration complète
// ============================================================

pub fn demonstrate_rust_graph_idioms() {
    // 1.4.0.b - IndexGraph idiomatique
    let mut g = IndexGraph::new();
    let a = g.add_node(10);
    let b = g.add_node(20);
    let c = g.add_node(30);
    g.add_edge(a, b);
    g.add_edge(b, c);
    g.add_edge(a, c);

    // DFS simple sans Rc/RefCell
    fn dfs(g: &IndexGraph, start: usize, visited: &mut Vec<bool>) {
        if visited[start] { return; }
        visited[start] = true;
        println!("Visiting node {} with value {}", start, g.value(start));
        for &neighbor in g.neighbors(start) {
            dfs(g, neighbor, visited);
        }
    }

    let mut visited = vec![false; 3];
    dfs(&g, a, &mut visited);

    // 1.4.0.c - Separated graph
    let mut sg: SeparatedGraph<String, f64> = SeparatedGraph::new();
    let paris = sg.add_node("Paris".into());
    let london = sg.add_node("London".into());
    sg.add_edge(paris, london, 344.0);  // km

    // 1.4.0.e - petgraph
    demonstrate_petgraph();
}
```

### Test Moulinette
```
graph_idiom index add_nodes [10,20,30] add_edges [(0,1),(1,2)] neighbors 0 -> [1]
graph_idiom index dfs 0 -> [0,1,2]
graph_idiom petgraph dijkstra A->C weights [1,2,5] -> 3
graph_idiom choose dense=false weighted=true mutable=false -> "Vec<Vec<(usize,W)>>"
```

---

## RÉCAPITULATIF MODULE 1.4

| Exercice | Concepts | Count |
|----------|----------|-------|
| ADD-1 rust_graph_idioms | 1.4.0.a-f | 6 |
| **TOTAL AJOUTÉ** | | **6** |

**Couverture Module 1.4: 54 + 6 = 60/60 = 100%**

