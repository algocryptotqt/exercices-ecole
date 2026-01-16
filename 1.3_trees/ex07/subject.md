# Exercise 07: Segment Trees

## Concepts Covered
- **1.3.21.a-n** Complete Segment Tree implementation
  - Point and range queries
  - Point and range updates
  - Lazy propagation
  - 2D segment tree
  - Persistent segment tree

## Objective

Implement a comprehensive Segment Tree library supporting various operations and optimizations.

## Requirements

### Rust Implementation

```rust
pub mod segment_tree {
    /// Basic segment tree for range sum queries
    pub struct SegmentTree<T> {
        tree: Vec<T>,
        n: usize,
    }

    impl<T: Clone + Default + std::ops::Add<Output = T>> SegmentTree<T> {
        /// Build from array - O(n)
        pub fn new(arr: &[T]) -> Self;

        /// Point update: arr[index] = value - O(log n)
        pub fn update(&mut self, index: usize, value: T);

        /// Range query: sum of arr[left..=right] - O(log n)
        pub fn query(&self, left: usize, right: usize) -> T;

        /// Point query: arr[index] - O(log n)
        pub fn get(&self, index: usize) -> T;
    }

    /// Segment tree with lazy propagation for range updates
    pub struct LazySegmentTree<T, U> {
        tree: Vec<T>,
        lazy: Vec<Option<U>>,
        n: usize,
    }

    impl LazySegmentTree<i64, i64> {
        /// Build from array
        pub fn new(arr: &[i64]) -> Self;

        /// Range update: add value to arr[left..=right] - O(log n)
        pub fn range_add(&mut self, left: usize, right: usize, value: i64);

        /// Range update: set arr[left..=right] = value - O(log n)
        pub fn range_set(&mut self, left: usize, right: usize, value: i64);

        /// Range query: sum of arr[left..=right] - O(log n)
        pub fn query(&mut self, left: usize, right: usize) -> i64;

        /// Range query: min of arr[left..=right]
        pub fn query_min(&mut self, left: usize, right: usize) -> i64;

        /// Range query: max of arr[left..=right]
        pub fn query_max(&mut self, left: usize, right: usize) -> i64;
    }

    /// Generic segment tree with custom merge operation
    pub struct GenericSegmentTree<T, F>
    where
        F: Fn(&T, &T) -> T,
    {
        tree: Vec<T>,
        n: usize,
        merge: F,
        identity: T,
    }

    impl<T: Clone, F: Fn(&T, &T) -> T> GenericSegmentTree<T, F> {
        pub fn new(arr: &[T], merge: F, identity: T) -> Self;
        pub fn update(&mut self, index: usize, value: T);
        pub fn query(&self, left: usize, right: usize) -> T;
    }

    /// 2D Segment Tree for matrix queries
    pub struct SegmentTree2D {
        tree: Vec<Vec<i64>>,
        n: usize,
        m: usize,
    }

    impl SegmentTree2D {
        /// Build from matrix
        pub fn new(matrix: &[Vec<i64>]) -> Self;

        /// Point update: matrix[row][col] = value
        pub fn update(&mut self, row: usize, col: usize, value: i64);

        /// Submatrix sum query
        pub fn query(&self, r1: usize, c1: usize, r2: usize, c2: usize) -> i64;
    }

    /// Persistent Segment Tree (functional updates)
    pub struct PersistentSegmentTree {
        nodes: Vec<Node>,
        roots: Vec<usize>,
    }

    struct Node {
        sum: i64,
        left: Option<usize>,
        right: Option<usize>,
    }

    impl PersistentSegmentTree {
        /// Build initial version from array
        pub fn new(arr: &[i64]) -> Self;

        /// Update and create new version
        pub fn update(&mut self, version: usize, index: usize, value: i64) -> usize;

        /// Query on specific version
        pub fn query(&self, version: usize, left: usize, right: usize) -> i64;

        /// Number of versions
        pub fn version_count(&self) -> usize;
    }

    // Segment Tree Applications

    /// Range Maximum Query with position
    pub fn rmq_with_pos(st: &SegmentTree<(i64, usize)>, left: usize, right: usize) -> (i64, usize);

    /// Count elements in range less than k
    pub fn count_less_than(arr: &[i64], queries: &[(usize, usize, i64)]) -> Vec<usize>;

    /// Kth smallest in range using persistent segment tree
    pub fn kth_smallest_in_range(arr: &[i64], queries: &[(usize, usize, usize)]) -> Vec<i64>;
}
```

### Python Implementation

```python
from typing import TypeVar, Callable, Generic

T = TypeVar("T")

class SegmentTree(Generic[T]):
    def __init__(self, arr: list[T], merge: Callable[[T, T], T], identity: T) -> None: ...
    def update(self, index: int, value: T) -> None: ...
    def query(self, left: int, right: int) -> T: ...
    def get(self, index: int) -> T: ...

class LazySegmentTree:
    def __init__(self, arr: list[int]) -> None: ...
    def range_add(self, left: int, right: int, value: int) -> None: ...
    def range_set(self, left: int, right: int, value: int) -> None: ...
    def query_sum(self, left: int, right: int) -> int: ...
    def query_min(self, left: int, right: int) -> int: ...
    def query_max(self, left: int, right: int) -> int: ...

class SegmentTree2D:
    def __init__(self, matrix: list[list[int]]) -> None: ...
    def update(self, row: int, col: int, value: int) -> None: ...
    def query(self, r1: int, c1: int, r2: int, c2: int) -> int: ...

class PersistentSegmentTree:
    def __init__(self, arr: list[int]) -> None: ...
    def update(self, version: int, index: int, value: int) -> int: ...
    def query(self, version: int, left: int, right: int) -> int: ...
    def version_count(self) -> int: ...
```

## Implementation Details

### Array Representation
For 1-indexed tree:
- Root at index 1
- Left child of i at 2*i
- Right child of i at 2*i + 1
- Parent of i at i/2

### Build O(n)
```rust
fn build(arr: &[i64], tree: &mut Vec<i64>, node: usize, start: usize, end: usize) {
    if start == end {
        tree[node] = arr[start];
        return;
    }
    let mid = (start + end) / 2;
    build(arr, tree, 2*node, start, mid);
    build(arr, tree, 2*node+1, mid+1, end);
    tree[node] = tree[2*node] + tree[2*node+1];
}
```

### Lazy Propagation
```rust
fn push_down(&mut self, node: usize, start: usize, end: usize) {
    if let Some(lazy_val) = self.lazy[node].take() {
        let mid = (start + end) / 2;
        self.apply(2*node, start, mid, lazy_val);
        self.apply(2*node+1, mid+1, end, lazy_val);
    }
}
```

## Test Cases

```rust
#[test]
fn test_basic_segment_tree() {
    let arr = vec![1, 3, 5, 7, 9, 11];
    let st = SegmentTree::new(&arr);

    assert_eq!(st.query(0, 5), 36);  // Sum all
    assert_eq!(st.query(1, 3), 15);  // 3 + 5 + 7
    assert_eq!(st.get(2), 5);
}

#[test]
fn test_point_update() {
    let arr = vec![1, 3, 5, 7, 9, 11];
    let mut st = SegmentTree::new(&arr);

    st.update(2, 10);  // 5 -> 10
    assert_eq!(st.query(0, 5), 41);  // 36 - 5 + 10
    assert_eq!(st.get(2), 10);
}

#[test]
fn test_lazy_range_add() {
    let arr = vec![1, 2, 3, 4, 5];
    let mut lst = LazySegmentTree::new(&arr);

    lst.range_add(1, 3, 10);  // Add 10 to indices 1-3
    assert_eq!(lst.query(0, 4), 45);  // 1 + 12 + 13 + 14 + 5
    assert_eq!(lst.query(1, 3), 39);  // 12 + 13 + 14
}

#[test]
fn test_lazy_range_set() {
    let arr = vec![1, 2, 3, 4, 5];
    let mut lst = LazySegmentTree::new(&arr);

    lst.range_set(1, 3, 0);  // Set indices 1-3 to 0
    assert_eq!(lst.query(0, 4), 6);  // 1 + 0 + 0 + 0 + 5
}

#[test]
fn test_min_max_queries() {
    let arr = vec![5, 2, 8, 1, 9, 3];
    let mut lst = LazySegmentTree::new(&arr);

    assert_eq!(lst.query_min(0, 5), 1);
    assert_eq!(lst.query_max(0, 5), 9);
    assert_eq!(lst.query_min(2, 4), 1);
    assert_eq!(lst.query_max(0, 2), 8);
}

#[test]
fn test_2d_segment_tree() {
    let matrix = vec![
        vec![1, 2, 3],
        vec![4, 5, 6],
        vec![7, 8, 9],
    ];
    let mut st2d = SegmentTree2D::new(&matrix);

    assert_eq!(st2d.query(0, 0, 2, 2), 45);  // All
    assert_eq!(st2d.query(0, 0, 1, 1), 12);  // Top-left 2x2

    st2d.update(1, 1, 10);  // 5 -> 10
    assert_eq!(st2d.query(0, 0, 2, 2), 50);
}

#[test]
fn test_persistent_segment_tree() {
    let arr = vec![1, 2, 3, 4, 5];
    let mut pst = PersistentSegmentTree::new(&arr);

    assert_eq!(pst.query(0, 0, 4), 15);  // Version 0

    let v1 = pst.update(0, 2, 10);  // Version 1: change 3 to 10
    assert_eq!(pst.query(v1, 0, 4), 22);
    assert_eq!(pst.query(0, 0, 4), 15);  // Version 0 unchanged

    let v2 = pst.update(v1, 0, 100);  // Version 2: change 1 to 100
    assert_eq!(pst.query(v2, 0, 4), 121);
    assert_eq!(pst.query(v1, 0, 4), 22);  // Version 1 unchanged
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Basic segment tree (sum) | 15 |
| Point update | 10 |
| Lazy propagation (range add) | 20 |
| Range set with lazy | 10 |
| Min/Max queries | 10 |
| 2D segment tree | 15 |
| Persistent segment tree | 20 |
| **Total** | **100** |

## Files to Submit

### Rust
- `src/lib.rs`
- `Cargo.toml`

### Python
- `segment_tree.py`
