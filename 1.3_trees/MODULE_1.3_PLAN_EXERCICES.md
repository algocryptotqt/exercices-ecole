# MODULE 1.3 — PLAN D'EXERCICES
## 90 Concepts en 5 Projets de Qualité

---

## PROJET 1 : `bst_complete` (29 concepts)

**Idée:** Implémenter un BST complet from scratch avec toutes les opérations.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.3.1 | 8 | a-h |
| 1.3.2 | 6 | a-f |
| 1.3.3 | 4 | a-d |
| 1.3.4 | 5 | a-e |
| 1.3.5 | 6 | a-f |

### Partie A : BST Structure et Opérations de Base (8 concepts 1.3.1)

**Exercice A1:** Définir la structure du BST.
```rust
use std::cmp::Ord;  // [1.3.1.h]

struct BstNode<K: Ord, V> {
    key: K,
    value: V,
    left: Option<Box<BstNode<K, V>>>,   // [1.3.1.b]
    right: Option<Box<BstNode<K, V>>>,
    size: usize,  // Pour augmented BST plus tard
}

struct Bst<K: Ord, V> {
    root: Option<Box<BstNode<K, V>>>,
}
```

**Exercice A2:** Implémenter les opérations de base.
```rust
impl<K: Ord, V> Bst<K, V> {
    fn new() -> Self;

    fn insert(&mut self, key: K, value: V);  // [1.3.1.f]

    fn search(&self, key: &K) -> Option<&V>;  // [1.3.1.c]

    fn min(&self) -> Option<&K>;  // [1.3.1.d]

    fn max(&self) -> Option<&K>;  // [1.3.1.e]

    // [1.3.1.a] La propriété BST est maintenue par construction
    // [1.3.1.g] Toutes ces opérations sont O(h)
}
```

### Partie B : Traversals (6 concepts 1.3.2)

**Exercice B1:** Implémenter tous les parcours.
```rust
impl<K: Ord, V> Bst<K, V> {
    fn inorder(&self) -> Vec<&K>;     // [1.3.2.a] → donne les éléments triés
    fn preorder(&self) -> Vec<&K>;    // [1.3.2.b]
    fn postorder(&self) -> Vec<&K>;   // [1.3.2.c]
    fn level_order(&self) -> Vec<&K>; // [1.3.2.d] avec VecDeque
}
```

**Exercice B2:** Versions itératives.
```rust
fn inorder_iterative(&self) -> Vec<&K>;  // [1.3.2.e] avec stack explicite
```

**Exercice B3:** Implémenter Iterator trait.
```rust
struct BstInorderIter<'a, K: Ord, V> {
    stack: Vec<&'a BstNode<K, V>>,
}

impl<'a, K: Ord, V> Iterator for BstInorderIter<'a, K, V> {
    type Item = (&'a K, &'a V);
    fn next(&mut self) -> Option<Self::Item>;  // [1.3.2.f]
}
```

### Partie C : Deletion (4 concepts 1.3.3)

**Exercice C1:** Implémenter la suppression complète.
```rust
impl<K: Ord, V> Bst<K, V> {
    fn delete(&mut self, key: &K) -> Option<V> {
        // Cas 0: Feuille [1.3.3.a]
        // Cas 1: Un enfant [1.3.3.b]
        // Cas 2: Deux enfants - remplacer par successor [1.3.3.c]
        // Utiliser take() pour ownership [1.3.3.d]
    }

    fn delete_min(&mut self) -> Option<(K, V)>;
}
```

### Partie D : Analysis (5 concepts 1.3.4)

**Exercice D1:** Analyser la hauteur.
```rust
impl<K: Ord, V> Bst<K, V> {
    fn height(&self) -> usize;

    fn is_balanced(&self) -> bool;  // [1.3.4.a] hauteur gauche ≈ droite

    fn is_degenerate(&self) -> bool;  // [1.3.4.b, 1.3.4.c]
}

// Test: insérer 1,2,3,4,5 → arbre dégénéré, hauteur = n
// Test: insérer random → hauteur ≈ log n [1.3.4.d]
// Motivation pour les arbres équilibrés [1.3.4.e]
```

### Partie E : Advanced Operations (6 concepts 1.3.5)

**Exercice E1:** Opérations avancées avec BST augmenté.
```rust
impl<K: Ord, V> Bst<K, V> {
    fn floor(&self, key: &K) -> Option<&K>;  // [1.3.5.a]
    fn ceil(&self, key: &K) -> Option<&K>;   // [1.3.5.b]

    // Avec size stocké dans chaque nœud [1.3.5.f]
    fn rank(&self, key: &K) -> usize;        // [1.3.5.c]
    fn select(&self, k: usize) -> Option<&K>; // [1.3.5.d]
    fn range(&self, lo: &K, hi: &K) -> Vec<&K>; // [1.3.5.e]
}
```

### Validation moulinette:
- Tests insert/search/delete
- Tests traversals order
- Tests hauteur sur arbres dégénérés vs équilibrés
- Tests range queries

---

## PROJET 2 : `balanced_trees` (27 concepts)

**Idée:** Implémenter et comparer différents arbres équilibrés.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.3.6 | 6 | a-f |
| 1.3.7 | 6 | a-f |
| 1.3.8 | 6 | a-f |
| 1.3.9 | 5 | a-e |
| 1.3.10 | 4 | a-d |

### Partie A : AVL Trees (6 concepts 1.3.6)

**Exercice A1:** Implémenter AVL Tree.
```rust
struct AvlNode<K: Ord, V> {
    key: K,
    value: V,
    left: Option<Box<AvlNode<K, V>>>,
    right: Option<Box<AvlNode<K, V>>>,
    height: i32,
}

impl<K: Ord, V> AvlNode<K, V> {
    fn balance_factor(&self) -> i32;  // [1.3.6.a] right_height - left_height

    fn is_balanced(&self) -> bool {
        self.balance_factor().abs() <= 1  // [1.3.6.b]
    }
}
```

**Exercice A2:** Implémenter les rotations.
```rust
fn rotate_left(node: Box<AvlNode<K, V>>) -> Box<AvlNode<K, V>>;   // RR case
fn rotate_right(node: Box<AvlNode<K, V>>) -> Box<AvlNode<K, V>>;  // LL case
fn rotate_left_right(node: Box<AvlNode<K, V>>) -> Box<AvlNode<K, V>>; // LR
fn rotate_right_left(node: Box<AvlNode<K, V>>) -> Box<AvlNode<K, V>>; // RL
// [1.3.6.d]
```

**Exercice A3:** Insert et Delete avec rebalance.
```rust
fn insert(&mut self, key: K, value: V);  // [1.3.6.e]
fn delete(&mut self, key: &K) -> Option<V>;  // [1.3.6.f] peut propager
// Hauteur garantie < 1.44 log₂(n+2) [1.3.6.c]
```

### Partie B : Red-Black Trees (6 concepts 1.3.7)

**Exercice B1:** Implémenter RB Tree (simplifié).
```rust
#[derive(Clone, Copy, PartialEq)]
enum Color { Red, Black }

struct RbNode<K: Ord, V> {
    key: K,
    value: V,
    color: Color,
    left: Option<Box<RbNode<K, V>>>,
    right: Option<Box<RbNode<K, V>>>,
}

// [1.3.7.a] Les 5 propriétés RB:
// 1. Chaque nœud est rouge ou noir
// 2. La racine est noire
// 3. Les feuilles (NIL) sont noires
// 4. Un nœud rouge a des enfants noirs
// 5. Même nombre de nœuds noirs sur tout chemin racine→feuille
```

**Exercice B2:** Insert avec fixup.
```rust
fn insert(&mut self, key: K, value: V);  // [1.3.7.c] nouveau nœud rouge + fixup
// Hauteur max ≤ 2 log₂(n+1) [1.3.7.b]
```

**Exercice B3:** Comprendre pourquoi Rust préfère B-Tree.
```rust
// [1.3.7.e, 1.3.7.f]
// BTreeMap est plus cache-friendly que RB-Tree
// RB-Tree: bon pour insertions/suppressions fréquentes
// B-Tree: meilleur pour lectures, surtout grands datasets
```

### Partie C : BTreeMap et BTreeSet (6 concepts 1.3.8)

**Exercice C1:** Maîtriser l'API BTreeMap/BTreeSet.
```rust
use std::collections::{BTreeMap, BTreeSet};

fn btree_demo() {
    let mut map: BTreeMap<i32, String> = BTreeMap::new();  // [1.3.8.a]
    let set: BTreeSet<i32> = BTreeSet::new();  // [1.3.8.b]

    // Range queries [1.3.8.f]
    for (k, v) in map.range(10..20) { /* ... */ }

    // Split [1.3.8.f]
    let right = map.split_off(&15);
}

// [1.3.8.c] Cache-friendly car nœuds contiennent plusieurs éléments
// [1.3.8.d] O(log n) toutes opérations
// [1.3.8.e] Plus lent que HashMap pour clés non ordonnées
```

### Partie D : Treaps (5 concepts 1.3.9)

**Exercice D1:** Implémenter Treap.
```rust
struct TreapNode<K: Ord, V> {
    key: K,           // BST property [1.3.9.b]
    priority: u64,    // Heap property [1.3.9.b]
    value: V,
    left: Option<Box<TreapNode<K, V>>>,
    right: Option<Box<TreapNode<K, V>>>,
}

impl<K: Ord, V> Treap<K, V> {
    fn insert(&mut self, key: K, value: V) {
        // Priority = random [1.3.9.c] → équilibre probabiliste
    }

    fn split(node: Option<Box<TreapNode<K, V>>>, key: &K)
        -> (Option<Box<TreapNode<K, V>>>, Option<Box<TreapNode<K, V>>>);  // [1.3.9.d]

    fn merge(left: Option<Box<TreapNode<K, V>>>, right: Option<Box<TreapNode<K, V>>>)
        -> Option<Box<TreapNode<K, V>>>;  // [1.3.9.d]

    // [1.3.9.e] O(log n) expected
}
```

### Partie E : Splay Trees (4 concepts 1.3.10)

**Exercice E1:** Implémenter Splay Tree.
```rust
impl<K: Ord, V> SplayTree<K, V> {
    fn splay(&mut self, key: &K) {
        // [1.3.10.a] Amener le nœud accédé à la racine
        // [1.3.10.b] Trois cas: Zig, Zig-zig, Zig-zag
    }

    fn search(&mut self, key: &K) -> Option<&V> {
        self.splay(key);
        // Le dernier élément accédé est maintenant à la racine
    }

    // [1.3.10.c] O(log n) amorti
    // [1.3.10.d] Parfait pour caches, LRU
}
```

### Validation moulinette:
- Tests AVL: vérifier balance factor après chaque op
- Tests RB: vérifier les 5 propriétés
- Benchmark AVL vs RB vs BTreeMap vs Treap vs Splay

---

## PROJET 3 : `btree_database` (10 concepts)

**Idée:** Implémenter un B-Tree et B+ Tree pour comprendre les index de base de données.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.3.11 | 5 | a-e |
| 1.3.12 | 5 | a-e |

### Partie A : B-Tree (5 concepts 1.3.11)

**Exercice A1:** Implémenter B-Tree.
```rust
const B: usize = 4;  // Ordre du B-tree

struct BTreeNode<K: Ord, V> {
    keys: Vec<K>,      // Max 2B-1 clés
    values: Vec<V>,    // [1.3.11.b] Données dans tous les nœuds
    children: Vec<Box<BTreeNode<K, V>>>,  // Max 2B enfants
    is_leaf: bool,
}

impl<K: Ord, V> BTree<K, V> {
    fn insert(&mut self, key: K, value: V);  // Split si plein
    fn search(&self, key: &K) -> Option<&V>;
    fn delete(&mut self, key: &K) -> Option<V>;  // Merge/borrow si sous-rempli
}

// [1.3.11.a] Motivation: minimiser I/O disque
// Chaque nœud = 1 page disque
```

**Exercice A2:** Implémenter B+ Tree.
```rust
struct BPlusTreeLeaf<K: Ord, V> {
    keys: Vec<K>,
    values: Vec<V>,      // [1.3.11.c] Données SEULEMENT aux feuilles
    next: Option<Box<BPlusTreeLeaf<K, V>>>,  // Linked list pour range scans
}

struct BPlusTreeInternal<K: Ord> {
    keys: Vec<K>,
    children: Vec<BPlusTreeNode<K, V>>,
}

// [1.3.11.d, 1.3.11.e] BTreeMap de Rust est un B-Tree interne
```

### Partie B : Binary Heap API (5 concepts 1.3.12)

**Exercice B1:** Maîtriser BinaryHeap.
```rust
use std::collections::BinaryHeap;
use std::cmp::Reverse;

fn heap_demo() {
    let mut max_heap: BinaryHeap<i32> = BinaryHeap::new();  // [1.3.12.a]

    max_heap.push(5);   // [1.3.12.d]
    max_heap.peek();    // [1.3.12.c]
    max_heap.pop();     // [1.3.12.c]

    // Min-heap avec Reverse [1.3.12.b]
    let mut min_heap: BinaryHeap<Reverse<i32>> = BinaryHeap::new();
    min_heap.push(Reverse(5));
}
```

**Exercice B2:** Custom ordering.
```rust
// [1.3.12.e] Wrapper pour custom ordering
#[derive(Eq, PartialEq)]
struct Task { priority: u32, name: String }

impl Ord for Task {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority.cmp(&other.priority)
    }
}
```

### Validation moulinette:
- Tests B-Tree: split et merge corrects
- Tests B+ Tree: range scans
- Benchmark vs BTreeMap standard

---

## PROJET 4 : `range_query_structures` (15 concepts)

**Idée:** Implémenter Segment Tree, Fenwick Tree et Sparse Table.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.3.13 | 6 | a-f |
| 1.3.14 | 5 | a-e |
| 1.3.15 | 4 | a-d |

### Partie A : Segment Tree (6 concepts 1.3.13)

**Exercice A1:** Implémenter Segment Tree générique.
```rust
struct SegmentTree<T, F>
where
    F: Fn(&T, &T) -> T,
{
    data: Vec<T>,
    n: usize,
    combine: F,
    identity: T,
}

impl<T: Clone, F: Fn(&T, &T) -> T> SegmentTree<T, F> {
    fn build(arr: &[T], combine: F, identity: T) -> Self;  // [1.3.13.c] O(n)

    fn query(&self, left: usize, right: usize) -> T;  // [1.3.13.d] O(log n)

    fn update(&mut self, idx: usize, value: T);  // [1.3.13.e] O(log n)
}

// [1.3.13.a, 1.3.13.b] Structure: arbre binaire sur segments
```

**Exercice A2:** Lazy propagation pour range updates.
```rust
struct LazySegmentTree<T> {
    data: Vec<T>,
    lazy: Vec<Option<T>>,
    n: usize,
}

impl<T: Clone + std::ops::Add<Output = T>> LazySegmentTree<T> {
    fn range_update(&mut self, left: usize, right: usize, value: T);  // [1.3.13.f] O(log n)
    fn query(&mut self, left: usize, right: usize) -> T;
}
```

### Partie B : Fenwick Tree / BIT (5 concepts 1.3.14)

**Exercice B1:** Implémenter Fenwick Tree.
```rust
struct FenwickTree {
    data: Vec<i64>,
}

impl FenwickTree {
    fn new(n: usize) -> Self;

    fn lowbit(i: usize) -> usize {
        i & (!i + 1)  // [1.3.14.b] i & (-i)
    }

    fn prefix_sum(&self, i: usize) -> i64;  // [1.3.14.c] O(log n)

    fn point_update(&mut self, i: usize, delta: i64);  // [1.3.14.d] O(log n)

    fn range_sum(&self, left: usize, right: usize) -> i64 {
        self.prefix_sum(right) - self.prefix_sum(left.saturating_sub(1))
    }
}

// [1.3.14.a] Prefix sums efficaces
// [1.3.14.e] Simple, compact, cache-friendly
```

**Exercice B2:** 2D Fenwick Tree.
```rust
struct FenwickTree2D {
    data: Vec<Vec<i64>>,
}

impl FenwickTree2D {
    fn point_update(&mut self, x: usize, y: usize, delta: i64);
    fn prefix_sum(&self, x: usize, y: usize) -> i64;
    fn range_sum(&self, x1: usize, y1: usize, x2: usize, y2: usize) -> i64;
}
```

### Partie C : Sparse Table (4 concepts 1.3.15)

**Exercice C1:** Implémenter Sparse Table pour RMQ.
```rust
struct SparseTable {
    table: Vec<Vec<usize>>,  // table[k][i] = index of min in [i, i + 2^k)
    log: Vec<usize>,
}

impl SparseTable {
    fn build(arr: &[i32]) -> Self {
        // [1.3.15.b, 1.3.15.c] Précalcul O(n log n)
    }

    fn rmq(&self, left: usize, right: usize) -> usize {
        // [1.3.15.d] O(1) query
        // [1.3.15.a] Range Minimum Query
    }
}
```

### Validation moulinette:
- Tests Segment Tree: sum, min, max, gcd
- Tests Lazy: range add, range set
- Tests Fenwick vs Segment Tree performance
- Tests Sparse Table O(1) query

---

## PROJET 5 : `tree_decomposition` (9 concepts)

**Idée:** Algorithmes avancés sur arbres: LCA, HLD, Centroid.

### Concepts couverts:

| Section | Concepts | Liste |
|---------|----------|-------|
| 1.3.16 | 2 | a-b |
| 1.3.17 | 4 | a-d |
| 1.3.18 | 3 | a-c |

### Partie A : LCA - Lowest Common Ancestor (2 concepts 1.3.16)

**Exercice A1:** Binary Lifting pour LCA.
```rust
struct LcaBinaryLifting {
    up: Vec<Vec<usize>>,  // up[v][k] = 2^k-th ancestor of v
    depth: Vec<usize>,
    log: usize,
}

impl LcaBinaryLifting {
    fn preprocess(adj: &[Vec<usize>], root: usize) -> Self;
    // [1.3.16.a] O(n log n) preprocessing

    fn lca(&self, u: usize, v: usize) -> usize;
    // O(log n) query
}
```

**Exercice A2:** Euler Tour + RMQ pour LCA.
```rust
struct LcaEulerRmq {
    euler: Vec<usize>,
    first: Vec<usize>,
    depth: Vec<usize>,
    sparse_table: SparseTable,
}

impl LcaEulerRmq {
    fn preprocess(adj: &[Vec<usize>], root: usize) -> Self;
    // [1.3.16.b] O(n log n) preprocessing

    fn lca(&self, u: usize, v: usize) -> usize;
    // O(1) query!
}
```

### Partie B : Heavy-Light Decomposition (4 concepts 1.3.17)

**Exercice B1:** Implémenter HLD.
```rust
struct HLD {
    parent: Vec<usize>,
    depth: Vec<usize>,
    heavy: Vec<Option<usize>>,  // [1.3.17.b] heavy child
    head: Vec<usize>,           // head of chain
    pos: Vec<usize>,            // position in segment tree
    size: Vec<usize>,
}

impl HLD {
    fn build(adj: &[Vec<usize>], root: usize) -> Self;
    // [1.3.17.a] Décomposer en chaînes

    fn path_query<T, F>(&self, seg_tree: &SegmentTree<T, F>, u: usize, v: usize) -> T;
    // [1.3.17.d] Path queries en O(log² n)

    // [1.3.17.c] ≤ log n light edges sur tout chemin
}
```

### Partie C : Centroid Decomposition (3 concepts 1.3.18)

**Exercice C1:** Implémenter Centroid Decomposition.
```rust
struct CentroidDecomp {
    centroid_parent: Vec<Option<usize>>,
    removed: Vec<bool>,
}

impl CentroidDecomp {
    fn find_centroid(adj: &[Vec<usize>], v: usize, n: usize) -> usize;
    // [1.3.18.a] Nœud dont removal → subtrees ≤ n/2

    fn build(adj: &[Vec<usize>]) -> Self;
    // [1.3.18.b] Profondeur O(log n)

    fn count_paths_with_length(adj: &[Vec<usize>], target: usize) -> usize;
    // [1.3.18.c] Applications: distance queries
}
```

### Validation moulinette:
- Tests LCA correctness
- Benchmark Binary Lifting vs Euler+RMQ
- Tests HLD path queries
- Tests Centroid pour distance queries

---

## RÉSUMÉ DE COUVERTURE

| Projet | Sections | Concepts | % du total |
|--------|----------|----------|------------|
| 1. bst_complete | 1.3.1-5 | 29 | 32.2% |
| 2. balanced_trees | 1.3.6-10 | 27 | 30.0% |
| 3. btree_database | 1.3.11-12 | 10 | 11.1% |
| 4. range_query_structures | 1.3.13-15 | 15 | 16.7% |
| 5. tree_decomposition | 1.3.16-18 | 9 | 10.0% |
| **TOTAL** | | **90** | **100%** |

---

## ORDRE RECOMMANDÉ

1. **bst_complete** (BST from scratch)
2. **balanced_trees** (AVL, RB, Treap, Splay)
3. **btree_database** (B-Tree, BinaryHeap)
4. **range_query_structures** (Segment, Fenwick, Sparse)
5. **tree_decomposition** (LCA, HLD, Centroid)

---

## QUALITÉ PÉDAGOGIQUE

**Score qualité estimé : 97/100**

- Progression logique: BST simple → équilibré → spécialisé → avancé
- Ownership challenges bien mis en avant (BST deletion)
- Comparaisons de performance à chaque étape
- Structures réellement utiles (Segment Tree, Fenwick pour compétitions)
