# MODULE 1.3 - TREES & ADVANCED STRUCTURES
## 279 Concepts - 25 Exercices Progressifs

---

# BLOC A: Binary Search Trees (Exercices 01-05)

## Exercice 01: BST Forge
**Concepts couverts**: 1.3.1.a-i (9 concepts)
**Difficulté**: ⭐⭐

### Objectif
Implémenter un BST complet avec toutes les opérations fondamentales.

### Structure Rust
```rust
pub struct BstNode<K: Ord, V> {
    key: K,
    value: V,
    left: Option<Box<BstNode<K, V>>>,
    right: Option<Box<BstNode<K, V>>>,
}

pub struct Bst<K: Ord, V> {
    root: Option<Box<BstNode<K, V>>>,
    size: usize,
}

impl<K: Ord, V> Bst<K, V> {
    pub fn new() -> Self;
    pub fn insert(&mut self, key: K, value: V) -> Option<V>;      // 1.3.1.h
    pub fn search(&self, key: &K) -> Option<&V>;                   // 1.3.1.c
    pub fn min(&self) -> Option<(&K, &V)>;                         // 1.3.1.d
    pub fn max(&self) -> Option<(&K, &V)>;                         // 1.3.1.e
    pub fn successor(&self, key: &K) -> Option<(&K, &V)>;          // 1.3.1.f
    pub fn predecessor(&self, key: &K) -> Option<(&K, &V)>;        // 1.3.1.g
    pub fn is_valid_bst(&self) -> bool;                            // 1.3.1.a, 1.3.1.b
}
```

### Tests Moulinette
```
bst_forge [insert|search|min|max|succ|pred|validate] <args>
```
- `insert 5,3,7,1,9` → `size: 5`
- `search 5,3,7,1,9 7` → `found`
- `min 5,3,7,1,9` → `1`
- `succ 5,3,7,1,9 5` → `7`

---

## Exercice 02: BST Surgery
**Concepts couverts**: 1.3.2.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Maîtriser les opérations de suppression BST.

```rust
impl<K: Ord, V> Bst<K, V> {
    pub fn delete(&mut self, key: &K) -> Option<V>;                // 1.3.2.a
    pub fn delete_min(&mut self) -> Option<(K, V)>;                // 1.3.2.b
    pub fn delete_max(&mut self) -> Option<(K, V)>;                // 1.3.2.c

    // Les 3 cas de suppression:
    // - Feuille (1.3.2.d)
    // - Un enfant (1.3.2.e)
    // - Deux enfants avec successeur (1.3.2.f, 1.3.2.g)

    pub fn verify_bst_after_delete(&self) -> bool;                 // 1.3.2.h
}
```

### Scénarios de Test
1. Suppression feuille: `delete_leaf`
2. Suppression avec 1 enfant: `delete_one_child`
3. Suppression avec 2 enfants: `delete_two_children`
4. Suppression racine: `delete_root`

---

## Exercice 03: Traversal Symphony
**Concepts couverts**: 1.3.3.a-i (9 concepts)
**Difficulté**: ⭐⭐

### Objectif
Implémenter tous les parcours d'arbre récursifs et itératifs.

```rust
impl<K: Ord + Clone, V: Clone> Bst<K, V> {
    // Récursif
    pub fn inorder(&self) -> Vec<(K, V)>;              // 1.3.3.a
    pub fn preorder(&self) -> Vec<(K, V)>;             // 1.3.3.b
    pub fn postorder(&self) -> Vec<(K, V)>;            // 1.3.3.c
    pub fn level_order(&self) -> Vec<(K, V)>;          // 1.3.3.d (BFS)

    // Itératif avec pile explicite
    pub fn inorder_iterative(&self) -> Vec<(K, V)>;    // 1.3.3.e
    pub fn preorder_iterative(&self) -> Vec<(K, V)>;   // 1.3.3.f
    pub fn postorder_iterative(&self) -> Vec<(K, V)>;  // 1.3.3.g

    // Morris Traversal (O(1) space)
    pub fn morris_inorder(&self) -> Vec<(K, V)>;       // 1.3.3.h
    pub fn morris_preorder(&self) -> Vec<(K, V)>;      // 1.3.3.i
}
```

---

## Exercice 04: Tree Metrics
**Concepts couverts**: 1.3.4.a-h (8 concepts)
**Difficulté**: ⭐⭐

### Objectif
Calculer les métriques essentielles d'un arbre.

```rust
impl<K: Ord, V> Bst<K, V> {
    pub fn height(&self) -> usize;                     // 1.3.4.a
    pub fn size(&self) -> usize;                       // 1.3.4.b
    pub fn depth(&self, key: &K) -> Option<usize>;     // 1.3.4.c
    pub fn is_balanced(&self) -> bool;                 // 1.3.4.d
    pub fn diameter(&self) -> usize;                   // 1.3.4.e
    pub fn count_leaves(&self) -> usize;               // 1.3.4.f
    pub fn count_internals(&self) -> usize;            // 1.3.4.g
    pub fn is_complete(&self) -> bool;                 // 1.3.4.h
}
```

---

## Exercice 05: Tree Surgeon
**Concepts couverts**: 1.3.5.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Sérialisation et reconstruction d'arbres.

```rust
impl<K: Ord + ToString + FromStr, V: ToString + FromStr> Bst<K, V> {
    pub fn serialize_preorder(&self) -> String;        // 1.3.5.a
    pub fn serialize_inorder(&self) -> String;         // 1.3.5.b
    pub fn deserialize(pre: &str, in_: &str) -> Self;  // 1.3.5.c
    pub fn serialize_level(&self) -> String;           // 1.3.5.d
    pub fn deserialize_level(s: &str) -> Self;         // 1.3.5.e
    pub fn clone_tree(&self) -> Self;                  // 1.3.5.f
    pub fn mirror(&mut self);                          // 1.3.5.g
    pub fn is_symmetric(&self) -> bool;                // 1.3.5.h
}
```

---

# BLOC B: Self-Balancing Trees (Exercices 06-12)

## Exercice 06: AVL Foundation
**Concepts couverts**: 1.3.6.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Comprendre les propriétés AVL et le facteur d'équilibre.

```rust
pub struct AvlNode<K: Ord, V> {
    key: K,
    value: V,
    height: i32,                                       // 1.3.6.d
    left: Option<Box<AvlNode<K, V>>>,
    right: Option<Box<AvlNode<K, V>>>,
}

impl<K: Ord, V> AvlNode<K, V> {
    pub fn balance_factor(&self) -> i32;               // 1.3.6.a
    pub fn update_height(&mut self);                   // 1.3.6.b
    pub fn is_balanced(&self) -> bool;                 // 1.3.6.c (|bf| <= 1)
}

pub struct Avl<K: Ord, V> {
    root: Option<Box<AvlNode<K, V>>>,
}

impl<K: Ord, V> Avl<K, V> {
    pub fn max_height_for_n(n: usize) -> usize;        // 1.3.6.e (1.44 log n)
    pub fn min_nodes_for_h(h: usize) -> usize;         // 1.3.6.f (Fibonacci)
    pub fn verify_avl_property(&self) -> bool;         // 1.3.6.g
    pub fn visualize(&self) -> String;                 // 1.3.6.h
}
```

---

## Exercice 07: AVL Rotations
**Concepts couverts**: 1.3.7.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Implémenter les 4 types de rotations AVL.

```rust
impl<K: Ord, V> Avl<K, V> {
    fn rotate_left(&mut self, node: &mut Box<AvlNode<K, V>>);   // 1.3.7.a
    fn rotate_right(&mut self, node: &mut Box<AvlNode<K, V>>);  // 1.3.7.b
    fn rotate_left_right(&mut self, node: &mut Box<AvlNode<K, V>>); // 1.3.7.c
    fn rotate_right_left(&mut self, node: &mut Box<AvlNode<K, V>>); // 1.3.7.d

    // Détection automatique du cas
    fn detect_case(&self, node: &AvlNode<K, V>) -> RotationCase;  // 1.3.7.e
    fn rebalance(&mut self, node: &mut Box<AvlNode<K, V>>);       // 1.3.7.f

    pub fn visualize_rotation(&self, before: &str, after: &str);  // 1.3.7.g
    pub fn rotation_count(&self) -> usize;                         // 1.3.7.h
}

pub enum RotationCase { LL, RR, LR, RL, None }
```

---

## Exercice 08: AVL Complete
**Concepts couverts**: 1.3.8.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
AVL complet avec insert et delete.

```rust
impl<K: Ord, V> Avl<K, V> {
    pub fn insert(&mut self, key: K, value: V) -> Option<V>;      // 1.3.8.a
    pub fn delete(&mut self, key: &K) -> Option<V>;               // 1.3.8.b
    pub fn bulk_insert(&mut self, items: Vec<(K, V)>);            // 1.3.8.c
    pub fn bulk_delete(&mut self, keys: &[K]);                    // 1.3.8.d

    // Opérations ensemblistes
    pub fn merge(self, other: Self) -> Self;                      // 1.3.8.e
    pub fn split(self, key: &K) -> (Self, Option<V>, Self);       // 1.3.8.f

    pub fn rank(&self, key: &K) -> usize;                         // 1.3.8.g
    pub fn select(&self, rank: usize) -> Option<(&K, &V)>;        // 1.3.8.h
}
```

---

## Exercice 09: BST Iterator
**Concepts couverts**: 1.3.9.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Itérateur efficace pour BST/AVL.

```rust
pub struct BstIterator<'a, K: Ord, V> {
    stack: Vec<&'a BstNode<K, V>>,                     // 1.3.9.a
    current: Option<&'a BstNode<K, V>>,                // 1.3.9.b
}

impl<'a, K: Ord, V> Iterator for BstIterator<'a, K, V> {
    type Item = (&'a K, &'a V);
    fn next(&mut self) -> Option<Self::Item>;          // 1.3.9.c
}

impl<'a, K: Ord, V> BstIterator<'a, K, V> {
    pub fn has_next(&self) -> bool;                    // 1.3.9.d
    pub fn peek(&self) -> Option<(&K, &V)>;            // 1.3.9.e
}

// Range iterator
pub struct RangeIterator<'a, K: Ord, V> {...}          // 1.3.9.f

impl<K: Ord, V> Bst<K, V> {
    pub fn iter(&self) -> BstIterator<K, V>;           // 1.3.9.g
    pub fn range(&self, lo: &K, hi: &K) -> RangeIterator<K, V>; // 1.3.9.h
}
```

---

## Exercice 10: Red-Black Foundation
**Concepts couverts**: 1.3.10.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Comprendre les 5 propriétés Red-Black.

```rust
#[derive(Clone, Copy, PartialEq)]
pub enum Color { Red, Black }

pub struct RbNode<K: Ord, V> {
    key: K,
    value: V,
    color: Color,
    left: Option<Box<RbNode<K, V>>>,
    right: Option<Box<RbNode<K, V>>>,
}

impl<K: Ord, V> RbNode<K, V> {
    // Vérification des 5 propriétés
    pub fn is_red_or_black(&self) -> bool;             // 1.3.10.a - Prop 1
    pub fn root_is_black(root: &Self) -> bool;         // 1.3.10.b - Prop 2
    pub fn leaves_are_black(&self) -> bool;            // 1.3.10.c - Prop 3
    pub fn red_children_black(&self) -> bool;          // 1.3.10.d - Prop 4
    pub fn black_height_consistent(&self) -> bool;     // 1.3.10.e - Prop 5

    pub fn black_height(&self) -> usize;               // 1.3.10.f
    pub fn max_height(&self) -> usize;                 // 1.3.10.g (2 * log(n+1))
}

pub fn verify_all_properties<K: Ord, V>(root: &RbNode<K, V>) -> bool; // 1.3.10.h
```

---

## Exercice 11: Red-Black Insert
**Concepts couverts**: 1.3.11.a-i (9 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
Insertion Red-Black avec tous les cas de rééquilibrage.

```rust
impl<K: Ord, V> RedBlackTree<K, V> {
    pub fn insert(&mut self, key: K, value: V) -> Option<V>;  // 1.3.11.a

    // Cas de fix-up
    fn fix_case0(&mut self, node: &mut Box<RbNode<K, V>>);    // 1.3.11.b (root)
    fn fix_case1(&mut self, node: &mut Box<RbNode<K, V>>);    // 1.3.11.c (parent black)
    fn fix_case2(&mut self, node: &mut Box<RbNode<K, V>>);    // 1.3.11.d (uncle red)
    fn fix_case3(&mut self, node: &mut Box<RbNode<K, V>>);    // 1.3.11.e (triangle)
    fn fix_case4(&mut self, node: &mut Box<RbNode<K, V>>);    // 1.3.11.f (line)

    fn propagate_fix(&mut self, node: &mut Box<RbNode<K, V>>); // 1.3.11.g

    pub fn max_rotations_insert() -> usize;                    // 1.3.11.h (max 2)
}

// Test visuel
pub fn trace_insert_steps(keys: &[K]) -> Vec<String>;          // 1.3.11.i
```

---

## Exercice 12: Red-Black Delete
**Concepts couverts**: 1.3.12.a-i (9 concepts)
**Difficulté**: ⭐⭐⭐⭐⭐

### Objectif
Suppression Red-Black avec tous les cas.

```rust
impl<K: Ord, V> RedBlackTree<K, V> {
    pub fn delete(&mut self, key: &K) -> Option<V>;            // 1.3.12.a

    fn handle_double_black(&mut self, node: &mut Box<RbNode<K, V>>); // 1.3.12.b
    fn fix_delete_case1(&mut self, ...);                       // 1.3.12.c (sibling red)
    fn fix_delete_case2(&mut self, ...);                       // 1.3.12.d (sibling black, nephews black)
    fn fix_delete_case3(&mut self, ...);                       // 1.3.12.e (close nephew red)
    fn fix_delete_case4(&mut self, ...);                       // 1.3.12.f (far nephew red)

    fn propagate_delete_fix(&mut self, ...);                   // 1.3.12.g
    pub fn max_rotations_delete() -> usize;                    // 1.3.12.h (max 3)
}

pub fn trace_delete_steps(tree: &RedBlackTree<i32, ()>, key: i32) -> Vec<String>; // 1.3.12.i
```

---

## Exercice 13: AVL vs RB Benchmark
**Concepts couverts**: 1.3.13.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Comparer empiriquement AVL et Red-Black.

```rust
pub struct TreeBenchmark {
    avl_results: BenchmarkResults,
    rb_results: BenchmarkResults,
}

pub struct BenchmarkResults {
    insert_time: Duration,
    search_time: Duration,
    delete_time: Duration,
    rotation_count: usize,
    max_height: usize,
}

impl TreeBenchmark {
    pub fn compare_balance(&self) -> String;           // 1.3.13.a
    pub fn compare_height(&self) -> String;            // 1.3.13.b
    pub fn compare_search(&self) -> String;            // 1.3.13.c
    pub fn compare_insert_rotations(&self) -> String;  // 1.3.13.d
    pub fn compare_delete_rotations(&self) -> String;  // 1.3.13.e
    pub fn recommend_use_case(&self) -> String;        // 1.3.13.f
    pub fn real_world_examples(&self) -> Vec<String>;  // 1.3.13.g
    pub fn code_complexity_analysis(&self) -> String;  // 1.3.13.h

    pub fn run(n: usize, ops: usize) -> Self;
    pub fn report(&self) -> String;
}
```

---

# BLOC C: Randomized & Specialized Trees (Exercices 14-17)

## Exercice 14: Treap
**Concepts couverts**: 1.3.14.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Implémenter un Treap (Tree + Heap).

```rust
pub struct TreapNode<K: Ord, V> {
    key: K,
    value: V,
    priority: u64,  // Heap property                   // 1.3.14.a
    left: Option<Box<TreapNode<K, V>>>,
    right: Option<Box<TreapNode<K, V>>>,
}

pub struct Treap<K: Ord, V> {
    root: Option<Box<TreapNode<K, V>>>,
    rng: StdRng,
}

impl<K: Ord, V> Treap<K, V> {
    pub fn new() -> Self;                              // 1.3.14.b
    pub fn insert(&mut self, key: K, value: V);        // 1.3.14.c
    pub fn delete(&mut self, key: &K) -> Option<V>;    // 1.3.14.d
    pub fn search(&self, key: &K) -> Option<&V>;       // 1.3.14.e

    fn split(&mut self, key: &K) -> (Option<Box<TreapNode<K, V>>>, Option<Box<TreapNode<K, V>>>); // 1.3.14.f
    fn merge(left: Option<Box<TreapNode<K, V>>>, right: Option<Box<TreapNode<K, V>>>) -> Option<Box<TreapNode<K, V>>>; // 1.3.14.g

    pub fn kth(&self, k: usize) -> Option<(&K, &V)>;   // 1.3.14.h
    pub fn count_less(&self, key: &K) -> usize;        // 1.3.14.i
    pub fn expected_height(&self) -> f64;              // 1.3.14.j (O(log n))
}
```

---

## Exercice 15: Skip List
**Concepts couverts**: 1.3.15.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Implémenter une Skip List probabiliste.

```rust
pub struct SkipNode<K: Ord, V> {
    key: K,
    value: V,
    forward: Vec<Option<Rc<RefCell<SkipNode<K, V>>>>>,  // 1.3.15.a
}

pub struct SkipList<K: Ord, V> {
    head: Rc<RefCell<SkipNode<K, V>>>,
    level: usize,                                       // 1.3.15.b
    p: f64,                                             // 1.3.15.c (typiquement 0.5)
}

impl<K: Ord, V> SkipList<K, V> {
    pub fn new(p: f64) -> Self;
    fn random_level(&self) -> usize;                    // 1.3.15.d
    pub fn search(&self, key: &K) -> Option<&V>;        // 1.3.15.e
    pub fn insert(&mut self, key: K, value: V);         // 1.3.15.f
    pub fn delete(&mut self, key: &K) -> Option<V>;     // 1.3.15.g

    pub fn expected_space(&self) -> f64;                // 1.3.15.h (O(n))
    pub fn expected_time(&self) -> f64;                 // 1.3.15.i (O(log n))
    pub fn visualize(&self) -> String;                  // 1.3.15.j
}
```

---

## Exercice 16: Splay Tree
**Concepts couverts**: 1.3.16.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
Implémenter un Splay Tree avec analyse amortie.

```rust
pub struct SplayTree<K: Ord, V> {
    root: Option<Box<SplayNode<K, V>>>,
}

impl<K: Ord, V> SplayTree<K, V> {
    fn splay(&mut self, key: &K);                       // 1.3.16.a
    fn zig(&mut self, node: &mut Box<SplayNode<K, V>>); // 1.3.16.b
    fn zag(&mut self, node: &mut Box<SplayNode<K, V>>); // 1.3.16.c
    fn zig_zig(&mut self, ...);                         // 1.3.16.d
    fn zag_zag(&mut self, ...);                         // 1.3.16.e
    fn zig_zag(&mut self, ...);                         // 1.3.16.f
    fn zag_zig(&mut self, ...);                         // 1.3.16.g

    pub fn search(&mut self, key: &K) -> Option<&V>;    // 1.3.16.h (splays to root)
    pub fn insert(&mut self, key: K, value: V);         // 1.3.16.i
    pub fn delete(&mut self, key: &K) -> Option<V>;     // 1.3.16.j
}
```

---

## Exercice 17: B-Tree Foundation
**Concepts couverts**: 1.3.17.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
Implémenter les bases d'un B-Tree.

```rust
pub struct BTreeNode<K: Ord, V> {
    keys: Vec<K>,                                       // 1.3.17.a
    values: Vec<V>,
    children: Vec<Box<BTreeNode<K, V>>>,                // 1.3.17.b
    is_leaf: bool,                                      // 1.3.17.c
}

pub struct BTree<K: Ord, V> {
    root: Option<Box<BTreeNode<K, V>>>,
    t: usize,  // Minimum degree                        // 1.3.17.d
}

impl<K: Ord, V> BTree<K, V> {
    pub fn new(t: usize) -> Self;
    pub fn search(&self, key: &K) -> Option<&V>;        // 1.3.17.e
    pub fn insert(&mut self, key: K, value: V);         // 1.3.17.f
    fn split_child(&mut self, parent: &mut BTreeNode<K, V>, i: usize); // 1.3.17.g

    pub fn min_keys(&self) -> usize;                    // 1.3.17.h (t-1)
    pub fn max_keys(&self) -> usize;                    // 1.3.17.i (2t-1)
    pub fn max_children(&self) -> usize;                // 1.3.17.j (2t)
}
```

---

# BLOC D: Segment Trees & Range Queries (Exercices 18-21)

## Exercice 18: Segment Tree Basic
**Concepts couverts**: 1.3.18.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Segment Tree pour range queries.

```rust
pub struct SegmentTree<T: Clone + Default> {
    tree: Vec<T>,                                       // 1.3.18.a
    n: usize,
    op: fn(T, T) -> T,                                  // 1.3.18.b (combine function)
}

impl<T: Clone + Default> SegmentTree<T> {
    pub fn new(arr: &[T], op: fn(T, T) -> T) -> Self;   // 1.3.18.c
    pub fn build(&mut self, arr: &[T]);                 // 1.3.18.d (O(n))
    pub fn query(&self, l: usize, r: usize) -> T;       // 1.3.18.e (O(log n))
    pub fn update(&mut self, i: usize, val: T);         // 1.3.18.f (O(log n))

    fn left_child(i: usize) -> usize;                   // 1.3.18.g (2*i + 1)
    fn right_child(i: usize) -> usize;                  // 1.3.18.h (2*i + 2)
    fn parent(i: usize) -> usize;                       // 1.3.18.i ((i-1) / 2)

    pub fn space_complexity(&self) -> usize;            // 1.3.18.j (4n)
}
```

---

## Exercice 19: Lazy Propagation
**Concepts couverts**: 1.3.19.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
Segment Tree avec lazy propagation pour range updates.

```rust
pub struct LazySegmentTree<T: Clone + Default> {
    tree: Vec<T>,
    lazy: Vec<Option<T>>,                               // 1.3.19.a
    n: usize,
}

impl<T: Clone + Default + std::ops::Add<Output = T>> LazySegmentTree<T> {
    pub fn new(arr: &[T]) -> Self;

    fn push_down(&mut self, node: usize);               // 1.3.19.b
    fn apply_lazy(&mut self, node: usize, val: T);      // 1.3.19.c

    pub fn range_update(&mut self, l: usize, r: usize, val: T); // 1.3.19.d (O(log n))
    pub fn range_query(&self, l: usize, r: usize) -> T; // 1.3.19.e (O(log n))

    pub fn point_query(&self, i: usize) -> T;           // 1.3.19.f

    // Applications
    pub fn range_add(&mut self, l: usize, r: usize, val: T);    // 1.3.19.g
    pub fn range_set(&mut self, l: usize, r: usize, val: T);    // 1.3.19.h
}
```

---

## Exercice 20: Fenwick Tree (BIT)
**Concepts couverts**: 1.3.20.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Binary Indexed Tree pour prefix sums efficaces.

```rust
pub struct FenwickTree {
    tree: Vec<i64>,                                     // 1.3.20.a
    n: usize,
}

impl FenwickTree {
    pub fn new(n: usize) -> Self;                       // 1.3.20.b
    pub fn from_array(arr: &[i64]) -> Self;             // 1.3.20.c (O(n))

    fn lowbit(x: usize) -> usize;                       // 1.3.20.d (x & (-x))

    pub fn update(&mut self, i: usize, delta: i64);     // 1.3.20.e (O(log n))
    pub fn prefix_sum(&self, i: usize) -> i64;          // 1.3.20.f (O(log n))
    pub fn range_sum(&self, l: usize, r: usize) -> i64; // 1.3.20.g

    pub fn lower_bound(&self, sum: i64) -> usize;       // 1.3.20.h (find first >= sum)
}
```

---

## Exercice 21: 2D Fenwick Tree
**Concepts couverts**: 1.3.21.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
Fenwick Tree 2D pour matrices.

```rust
pub struct FenwickTree2D {
    tree: Vec<Vec<i64>>,                                // 1.3.21.a
    n: usize,
    m: usize,
}

impl FenwickTree2D {
    pub fn new(n: usize, m: usize) -> Self;             // 1.3.21.b
    pub fn from_matrix(matrix: &[Vec<i64>]) -> Self;    // 1.3.21.c

    pub fn update(&mut self, x: usize, y: usize, delta: i64); // 1.3.21.d
    pub fn prefix_sum(&self, x: usize, y: usize) -> i64;      // 1.3.21.e
    pub fn range_sum(&self, x1: usize, y1: usize, x2: usize, y2: usize) -> i64; // 1.3.21.f

    pub fn time_complexity(&self) -> String;            // 1.3.21.g (O(log n * log m))
    pub fn space_complexity(&self) -> String;           // 1.3.21.h (O(n * m))
}
```

---

# BLOC E: Special Trees & LCA (Exercices 22-24)

## Exercice 22: LCA Algorithms
**Concepts couverts**: 1.3.22.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐

### Objectif
Lowest Common Ancestor avec plusieurs méthodes.

```rust
pub struct LcaTree {
    parent: Vec<usize>,
    depth: Vec<usize>,
    up: Vec<Vec<usize>>,  // Binary lifting             // 1.3.22.a
}

impl LcaTree {
    pub fn from_edges(n: usize, edges: &[(usize, usize)], root: usize) -> Self;

    // Méthode naïve O(n)
    pub fn lca_naive(&self, u: usize, v: usize) -> usize;  // 1.3.22.b

    // Binary Lifting O(log n)
    fn preprocess_binary_lifting(&mut self);            // 1.3.22.c
    pub fn lca_binary_lifting(&self, u: usize, v: usize) -> usize; // 1.3.22.d

    // Euler Tour + RMQ
    fn euler_tour(&self) -> (Vec<usize>, Vec<usize>);   // 1.3.22.e
    pub fn lca_euler_rmq(&self, u: usize, v: usize) -> usize; // 1.3.22.f

    // Applications
    pub fn distance(&self, u: usize, v: usize) -> usize; // 1.3.22.g
    pub fn is_ancestor(&self, u: usize, v: usize) -> bool; // 1.3.22.h
}
```

---

## Exercice 23: Heavy-Light Decomposition
**Concepts couverts**: 1.3.23.a-h (8 concepts)
**Difficulté**: ⭐⭐⭐⭐⭐

### Objectif
HLD pour path queries sur arbres.

```rust
pub struct HLD {
    parent: Vec<usize>,
    depth: Vec<usize>,
    heavy: Vec<Option<usize>>,                          // 1.3.23.a
    head: Vec<usize>,                                   // 1.3.23.b
    pos: Vec<usize>,                                    // 1.3.23.c (position in segment tree)
    subtree_size: Vec<usize>,
}

impl HLD {
    pub fn new(n: usize, edges: &[(usize, usize)], root: usize) -> Self;

    fn dfs_size(&mut self, u: usize, p: usize);         // 1.3.23.d
    fn decompose(&mut self, u: usize, h: usize);        // 1.3.23.e

    pub fn path_query(&self, u: usize, v: usize) -> Vec<(usize, usize)>; // 1.3.23.f
    pub fn subtree_range(&self, u: usize) -> (usize, usize); // 1.3.23.g

    // Avec segment tree
    pub fn path_max(&self, st: &SegmentTree<i64>, u: usize, v: usize) -> i64; // 1.3.23.h
}
```

---

## Exercice 24: Trie (Prefix Tree)
**Concepts couverts**: 1.3.24.a-j (10 concepts)
**Difficulté**: ⭐⭐⭐

### Objectif
Implémenter un Trie complet.

```rust
pub struct TrieNode {
    children: [Option<Box<TrieNode>>; 26],              // 1.3.24.a
    is_end: bool,                                       // 1.3.24.b
    count: usize,                                       // 1.3.24.c (words passing through)
}

pub struct Trie {
    root: TrieNode,
}

impl Trie {
    pub fn new() -> Self;                               // 1.3.24.d
    pub fn insert(&mut self, word: &str);               // 1.3.24.e
    pub fn search(&self, word: &str) -> bool;           // 1.3.24.f
    pub fn starts_with(&self, prefix: &str) -> bool;    // 1.3.24.g
    pub fn delete(&mut self, word: &str) -> bool;       // 1.3.24.h

    pub fn autocomplete(&self, prefix: &str) -> Vec<String>; // 1.3.24.i
    pub fn count_prefix(&self, prefix: &str) -> usize;  // 1.3.24.j
}
```

---

# BLOC F: Mini-Projet Final (Exercice 25)

## Exercice 25: Database Index Engine
**Concepts couverts**: 1.3.a-p (16 concepts du projet)
**Difficulté**: ⭐⭐⭐⭐⭐

### Objectif
Moteur d'index de base de données complet utilisant B+ Tree.

```rust
pub struct BPlusTree<K: Ord + Clone, V: Clone> {
    root: Node<K, V>,
    order: usize,
}

pub enum Node<K: Ord + Clone, V: Clone> {
    Internal { keys: Vec<K>, children: Vec<Box<Node<K, V>>> },
    Leaf { keys: Vec<K>, values: Vec<V>, next: Option<Box<Node<K, V>>> },
}

impl<K: Ord + Clone, V: Clone> BPlusTree<K, V> {
    // Core B+ Tree operations
    pub fn new(order: usize) -> Self;                   // 1.3.a
    pub fn insert(&mut self, key: K, value: V);         // 1.3.b (with split)
    pub fn delete(&mut self, key: &K) -> Option<V>;     // 1.3.c (with merge/borrow)
    pub fn get(&self, key: &K) -> Option<&V>;           // 1.3.d (point query)
    pub fn range(&self, lo: &K, hi: &K) -> Vec<(&K, &V)>; // 1.3.e (range query)
    pub fn iter(&self) -> BPlusTreeIterator<K, V>;      // 1.3.f

    // Persistence
    pub fn save(&self, path: &Path) -> io::Result<()>;  // 1.3.g
    pub fn load(path: &Path) -> io::Result<Self>;

    // Bulk operations
    pub fn bulk_load(items: Vec<(K, V)>) -> Self;       // 1.3.h

    // Secondary index support
    pub fn create_secondary_index<F>(&self, f: F) -> SecondaryIndex<K, V>
    where F: Fn(&V) -> K;                               // 1.3.i

    // Statistics
    pub fn stats(&self) -> IndexStats;                  // 1.3.j
}

// Segment Tree for aggregations
pub struct AggregationIndex { ... }                     // 1.3.k

// Fenwick Tree for counts
pub struct CountIndex { ... }                           // 1.3.l

// Full test suite
#[cfg(test)]
mod tests { ... }                                       // 1.3.m

// Benchmarks
pub fn benchmark_operations(n: usize) -> BenchmarkResults; // 1.3.n

// Bonus: LCA for tree queries
pub struct TreeQueryEngine { ... }                      // 1.3.o

// Bonus: HLD for path queries
pub struct PathQueryEngine { ... }                      // 1.3.p
```

### Livrables
1. `lib.rs` - Module principal avec B+ Tree
2. `segment_tree.rs` - Segment Tree library
3. `fenwick_tree.rs` - Fenwick Tree library
4. `lca.rs` - LCA algorithms (Bonus)
5. `hld.rs` - Heavy-Light Decomposition (Bonus)
6. `tests/` - Suite de tests complète
7. `benches/` - Benchmarks Criterion

### Tests Moulinette
```bash
# Operations de base
index_engine insert 1,Alice 2,Bob 3,Charlie
index_engine get 2                    # -> Bob
index_engine range 1 3                # -> [(1,Alice),(2,Bob),(3,Charlie)]

# Bulk load et persistence
index_engine bulk_load data.csv
index_engine save db.idx
index_engine load db.idx && index_engine get 42

# Benchmarks
index_engine bench 100000             # 100k operations
```

---

# RÉCAPITULATIF DES CONCEPTS

| Bloc | Exercices | Concepts | Description |
|------|-----------|----------|-------------|
| A | 01-05 | 44 | BST fondamentaux |
| B | 06-13 | 67 | Arbres équilibrés (AVL, RB) |
| C | 14-17 | 40 | Arbres randomisés/spécialisés |
| D | 18-21 | 34 | Segment Trees & Range Queries |
| E | 22-24 | 26 | LCA, HLD, Trie |
| F | 25 | 16 | Projet Database Index |
| **TOTAL** | **25** | **279** | **Module 1.3 complet** |

---

# CRITÈRES DE QUALITÉ (95/100 minimum)

1. **Couverture** (40 pts): Chaque concept lettre doit être explicitement testé
2. **Complexité algorithmique** (20 pts): Vérification des bornes O(...)
3. **Tests edge cases** (15 pts): Arbres vides, un élément, dégénérés
4. **Qualité du code** (15 pts): Rust idiomatique, ownership correct
5. **Documentation** (10 pts): Chaque fonction documentée

---
