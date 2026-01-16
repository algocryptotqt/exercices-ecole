# Exercise 08: Fenwick Trees (Binary Indexed Trees)

## Concepts Covered
- **1.3.22.a-k** Complete Fenwick Tree implementation

## Objective

Implement Fenwick Trees for efficient prefix sum queries and point updates.

## Requirements

### Rust Implementation

```rust
pub mod fenwick {
    /// Fenwick Tree (Binary Indexed Tree)
    pub struct FenwickTree {
        tree: Vec<i64>,
        n: usize,
    }

    impl FenwickTree {
        /// Create empty Fenwick tree of size n
        pub fn new(n: usize) -> Self;

        /// Build from array in O(n)
        pub fn from_array(arr: &[i64]) -> Self;

        /// Point update: arr[i] += delta - O(log n)
        pub fn add(&mut self, i: usize, delta: i64);

        /// Prefix sum: sum of arr[0..=i] - O(log n)
        pub fn prefix_sum(&self, i: usize) -> i64;

        /// Range sum: sum of arr[l..=r] - O(log n)
        pub fn range_sum(&self, l: usize, r: usize) -> i64;

        /// Point query: get arr[i] - O(log n)
        pub fn get(&self, i: usize) -> i64;

        /// Find smallest i such that prefix_sum(i) >= value - O(log n)
        pub fn lower_bound(&self, value: i64) -> usize;

        /// Update: set arr[i] = value
        pub fn set(&mut self, i: usize, value: i64);
    }

    /// Fenwick Tree with range updates
    pub struct FenwickRangeUpdate {
        tree1: Vec<i64>,
        tree2: Vec<i64>,
        n: usize,
    }

    impl FenwickRangeUpdate {
        pub fn new(n: usize) -> Self;

        /// Range update: add delta to arr[l..=r] - O(log n)
        pub fn range_add(&mut self, l: usize, r: usize, delta: i64);

        /// Point query: get arr[i] - O(log n)
        pub fn get(&self, i: usize) -> i64;
    }

    /// 2D Fenwick Tree
    pub struct FenwickTree2D {
        tree: Vec<Vec<i64>>,
        n: usize,
        m: usize,
    }

    impl FenwickTree2D {
        pub fn new(n: usize, m: usize) -> Self;

        /// Update: matrix[x][y] += delta
        pub fn add(&mut self, x: usize, y: usize, delta: i64);

        /// Prefix sum: sum of matrix[0..=x][0..=y]
        pub fn prefix_sum(&self, x: usize, y: usize) -> i64;

        /// Submatrix sum
        pub fn range_sum(&self, x1: usize, y1: usize, x2: usize, y2: usize) -> i64;
    }

    // Applications

    /// Count inversions in array
    pub fn count_inversions(arr: &[i32]) -> i64;

    /// Count elements smaller than arr[i] to its left
    pub fn smaller_to_left(arr: &[i32]) -> Vec<i32>;

    /// Dynamic order statistics
    pub struct OrderStatistics {
        tree: FenwickTree,
        max_val: usize,
    }

    impl OrderStatistics {
        pub fn new(max_val: usize) -> Self;
        pub fn insert(&mut self, value: usize);
        pub fn remove(&mut self, value: usize);
        pub fn kth_smallest(&self, k: usize) -> usize;
        pub fn count_less_than(&self, value: usize) -> usize;
    }
}
```

### Python Implementation

```python
class FenwickTree:
    def __init__(self, n: int) -> None: ...
    @classmethod
    def from_array(cls, arr: list[int]) -> "FenwickTree": ...
    def add(self, i: int, delta: int) -> None: ...
    def prefix_sum(self, i: int) -> int: ...
    def range_sum(self, l: int, r: int) -> int: ...
    def get(self, i: int) -> int: ...
    def lower_bound(self, value: int) -> int: ...

class FenwickRangeUpdate:
    def __init__(self, n: int) -> None: ...
    def range_add(self, l: int, r: int, delta: int) -> None: ...
    def get(self, i: int) -> int: ...

class FenwickTree2D:
    def __init__(self, n: int, m: int) -> None: ...
    def add(self, x: int, y: int, delta: int) -> None: ...
    def prefix_sum(self, x: int, y: int) -> int: ...
    def range_sum(self, x1: int, y1: int, x2: int, y2: int) -> int: ...

def count_inversions(arr: list[int]) -> int: ...
```

## Key Operations

### lowbit (Lowest Set Bit)
```rust
fn lowbit(x: usize) -> usize {
    x & x.wrapping_neg()
}
```

### Update (Add delta to position i)
```rust
fn add(&mut self, mut i: usize, delta: i64) {
    i += 1;  // 1-indexed
    while i <= self.n {
        self.tree[i] += delta;
        i += lowbit(i);
    }
}
```

### Query (Prefix sum up to i)
```rust
fn prefix_sum(&self, mut i: usize) -> i64 {
    i += 1;  // 1-indexed
    let mut sum = 0;
    while i > 0 {
        sum += self.tree[i];
        i -= lowbit(i);
    }
    sum
}
```

## Test Cases

```rust
#[test]
fn test_basic_fenwick() {
    let arr = vec![1, 7, 3, 0, 5, 8, 3, 2, 6, 4];
    let ft = FenwickTree::from_array(&arr);

    assert_eq!(ft.prefix_sum(0), 1);
    assert_eq!(ft.prefix_sum(4), 16);  // 1+7+3+0+5
    assert_eq!(ft.range_sum(2, 5), 16);  // 3+0+5+8
}

#[test]
fn test_update() {
    let mut ft = FenwickTree::from_array(&[1, 2, 3, 4, 5]);

    ft.add(2, 10);  // arr[2] += 10
    assert_eq!(ft.range_sum(0, 4), 25);  // 1+2+13+4+5
    assert_eq!(ft.get(2), 13);
}

#[test]
fn test_range_update() {
    let mut ft = FenwickRangeUpdate::new(5);

    ft.range_add(1, 3, 10);  // Add 10 to indices 1-3
    assert_eq!(ft.get(0), 0);
    assert_eq!(ft.get(1), 10);
    assert_eq!(ft.get(2), 10);
    assert_eq!(ft.get(3), 10);
    assert_eq!(ft.get(4), 0);
}

#[test]
fn test_2d_fenwick() {
    let mut ft = FenwickTree2D::new(3, 3);

    ft.add(0, 0, 1);
    ft.add(1, 1, 2);
    ft.add(2, 2, 3);

    assert_eq!(ft.prefix_sum(2, 2), 6);
    assert_eq!(ft.range_sum(1, 1, 2, 2), 5);  // 2+3
}

#[test]
fn test_inversions() {
    assert_eq!(count_inversions(&[2, 4, 1, 3, 5]), 3);  // (2,1), (4,1), (4,3)
    assert_eq!(count_inversions(&[5, 4, 3, 2, 1]), 10);  // All pairs
    assert_eq!(count_inversions(&[1, 2, 3, 4, 5]), 0);
}

#[test]
fn test_lower_bound() {
    let ft = FenwickTree::from_array(&[3, 1, 4, 1, 5]);

    // Find first i where prefix_sum(i) >= 8
    assert_eq!(ft.lower_bound(8), 3);  // 3+1+4 = 8
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Basic Fenwick (prefix sum, update) | 20 |
| Range sum | 10 |
| Point query (get) | 10 |
| Lower bound search | 10 |
| Range update Fenwick | 15 |
| 2D Fenwick Tree | 20 |
| Count inversions | 15 |
| **Total** | **100** |

## Files to Submit

### Rust
- `src/lib.rs`
- `Cargo.toml`

### Python
- `fenwick.py`
