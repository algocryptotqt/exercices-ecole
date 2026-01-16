# Exercise 06: Interval & Range Trees

## Concepts Covered
- **1.3.28-30** Interval trees, overlapping queries
- **1.3.31-33** Range trees, fractional cascading, 2D queries

## Objective

Implement specialized trees for geometric and interval queries.

## Requirements

### Rust Implementation

```rust
pub mod interval_tree {
    #[derive(Clone, Debug)]
    pub struct Interval {
        pub lo: i64,
        pub hi: i64,
    }

    impl Interval {
        pub fn new(lo: i64, hi: i64) -> Self;
        pub fn overlaps(&self, other: &Interval) -> bool;
        pub fn contains_point(&self, point: i64) -> bool;
    }

    struct ITNode {
        interval: Interval,
        max_end: i64,  // Maximum end point in subtree
        left: Option<Box<ITNode>>,
        right: Option<Box<ITNode>>,
    }

    pub struct IntervalTree {
        root: Option<Box<ITNode>>,
    }

    impl IntervalTree {
        pub fn new() -> Self;

        /// Insert interval
        pub fn insert(&mut self, interval: Interval);

        /// Delete interval
        pub fn delete(&mut self, interval: &Interval) -> bool;

        /// Find any interval that overlaps with query
        pub fn find_overlap(&self, query: &Interval) -> Option<&Interval>;

        /// Find all intervals overlapping with query
        pub fn find_all_overlaps(&self, query: &Interval) -> Vec<&Interval>;

        /// Find all intervals containing a point
        pub fn stab(&self, point: i64) -> Vec<&Interval>;

        /// Merge overlapping intervals
        pub fn merge_overlapping(&mut self);
    }

    /// Augmented interval tree supporting additional queries
    pub struct AugmentedIT {
        root: Option<Box<AugNode>>,
    }

    impl AugmentedIT {
        /// Count intervals overlapping with query
        pub fn count_overlaps(&self, query: &Interval) -> usize;

        /// Find interval with minimum start that overlaps
        pub fn min_overlap(&self, query: &Interval) -> Option<&Interval>;
    }
}

pub mod segment_tree_2d {
    /// 2D Segment Tree for rectangle queries
    pub struct SegTree2D<T: Clone + Default> {
        tree: Vec<Vec<T>>,
        rows: usize,
        cols: usize,
    }

    impl<T: Clone + Default + std::ops::Add<Output = T>> SegTree2D<T> {
        pub fn new(rows: usize, cols: usize) -> Self;
        pub fn build(matrix: &[Vec<T>]) -> Self;

        /// Point update
        pub fn update(&mut self, r: usize, c: usize, val: T);

        /// Rectangle sum query [r1, c1] to [r2, c2]
        pub fn query(&self, r1: usize, c1: usize, r2: usize, c2: usize) -> T;
    }
}

pub mod range_tree {
    /// 1D Range Tree (essentially a balanced BST with subtree counts)
    pub struct RangeTree1D {
        root: Option<Box<RT1DNode>>,
    }

    impl RangeTree1D {
        pub fn new() -> Self;
        pub fn build(points: &[i64]) -> Self;

        /// Count points in range [lo, hi]
        pub fn count_range(&self, lo: i64, hi: i64) -> usize;

        /// Report all points in range [lo, hi]
        pub fn report_range(&self, lo: i64, hi: i64) -> Vec<i64>;
    }

    /// 2D Range Tree
    #[derive(Clone)]
    pub struct Point2D {
        pub x: i64,
        pub y: i64,
    }

    pub struct RangeTree2D {
        root: Option<Box<RT2DNode>>,
    }

    struct RT2DNode {
        point: Point2D,
        y_tree: RangeTree1D,  // Associated structure for y-coordinates
        left: Option<Box<RT2DNode>>,
        right: Option<Box<RT2DNode>>,
    }

    impl RangeTree2D {
        pub fn new() -> Self;
        pub fn build(points: &[Point2D]) -> Self;

        /// Count points in rectangle [x1, x2] × [y1, y2]
        pub fn count_rect(&self, x1: i64, x2: i64, y1: i64, y2: i64) -> usize;

        /// Report points in rectangle
        pub fn report_rect(&self, x1: i64, x2: i64, y1: i64, y2: i64) -> Vec<&Point2D>;
    }

    /// Fractional Cascading optimization
    pub struct RangeTree2DFC {
        // 2D range tree with fractional cascading
        // Reduces query time from O(log²n) to O(log n + k)
    }

    impl RangeTree2DFC {
        pub fn build(points: &[Point2D]) -> Self;
        pub fn report_rect(&self, x1: i64, x2: i64, y1: i64, y2: i64) -> Vec<&Point2D>;
    }
}

pub mod kd_tree {
    #[derive(Clone, Debug)]
    pub struct Point<const D: usize> {
        pub coords: [f64; D],
    }

    struct KDNode<const D: usize> {
        point: Point<D>,
        split_dim: usize,
        left: Option<Box<KDNode<D>>>,
        right: Option<Box<KDNode<D>>>,
    }

    pub struct KDTree<const D: usize> {
        root: Option<Box<KDNode<D>>>,
    }

    impl<const D: usize> KDTree<D> {
        pub fn new() -> Self;
        pub fn build(points: Vec<Point<D>>) -> Self;

        /// Insert point
        pub fn insert(&mut self, point: Point<D>);

        /// Nearest neighbor query
        pub fn nearest(&self, query: &Point<D>) -> Option<&Point<D>>;

        /// K nearest neighbors
        pub fn k_nearest(&self, query: &Point<D>, k: usize) -> Vec<&Point<D>>;

        /// Range search: points within distance r
        pub fn range_search(&self, center: &Point<D>, radius: f64) -> Vec<&Point<D>>;

        /// Orthogonal range query
        pub fn rect_query(&self, lo: &Point<D>, hi: &Point<D>) -> Vec<&Point<D>>;
    }
}
```

### Python Implementation

```python
from typing import List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class Interval:
    lo: int
    hi: int

    def overlaps(self, other: 'Interval') -> bool: ...
    def contains_point(self, point: int) -> bool: ...

class IntervalTree:
    def __init__(self):
        self.root = None

    def insert(self, interval: Interval) -> None: ...
    def find_overlap(self, query: Interval) -> Optional[Interval]: ...
    def find_all_overlaps(self, query: Interval) -> List[Interval]: ...
    def stab(self, point: int) -> List[Interval]: ...

@dataclass
class Point2D:
    x: int
    y: int

class RangeTree2D:
    def __init__(self):
        self.root = None

    def build(self, points: List[Point2D]) -> None: ...
    def count_rect(self, x1: int, x2: int, y1: int, y2: int) -> int: ...
    def report_rect(self, x1: int, x2: int, y1: int, y2: int) -> List[Point2D]: ...

class KDTree:
    def __init__(self, dim: int = 2):
        self.root = None
        self.dim = dim

    def build(self, points: List[List[float]]) -> None: ...
    def nearest(self, query: List[float]) -> Optional[List[float]]: ...
    def k_nearest(self, query: List[float], k: int) -> List[List[float]]: ...
```

## Test Cases

```rust
#[test]
fn test_interval_overlap() {
    let mut tree = IntervalTree::new();
    tree.insert(Interval::new(15, 20));
    tree.insert(Interval::new(10, 30));
    tree.insert(Interval::new(5, 12));
    tree.insert(Interval::new(17, 19));

    let query = Interval::new(14, 16);
    let overlaps = tree.find_all_overlaps(&query);
    assert_eq!(overlaps.len(), 2);  // [15,20] and [10,30]
}

#[test]
fn test_interval_stab() {
    let mut tree = IntervalTree::new();
    tree.insert(Interval::new(1, 10));
    tree.insert(Interval::new(5, 15));
    tree.insert(Interval::new(12, 20));

    let stabbed = tree.stab(7);
    assert_eq!(stabbed.len(), 2);  // [1,10] and [5,15]
}

#[test]
fn test_range_tree_2d() {
    let points = vec![
        Point2D { x: 1, y: 1 },
        Point2D { x: 2, y: 3 },
        Point2D { x: 3, y: 2 },
        Point2D { x: 5, y: 5 },
        Point2D { x: 4, y: 1 },
    ];

    let tree = RangeTree2D::build(&points);

    // Query rectangle [1,4] × [1,3]
    let count = tree.count_rect(1, 4, 1, 3);
    assert_eq!(count, 3);  // (1,1), (2,3), (3,2)
}

#[test]
fn test_kd_tree_nearest() {
    let points = vec![
        Point { coords: [2.0, 3.0] },
        Point { coords: [5.0, 4.0] },
        Point { coords: [9.0, 6.0] },
        Point { coords: [4.0, 7.0] },
        Point { coords: [8.0, 1.0] },
        Point { coords: [7.0, 2.0] },
    ];

    let tree = KDTree::build(points);
    let query = Point { coords: [6.0, 3.0] };

    let nearest = tree.nearest(&query).unwrap();
    // Should be (5, 4) or (7, 2) - closest to (6, 3)
}

#[test]
fn test_kd_tree_range() {
    let points = vec![
        Point { coords: [1.0, 1.0] },
        Point { coords: [2.0, 2.0] },
        Point { coords: [3.0, 3.0] },
        Point { coords: [5.0, 5.0] },
    ];

    let tree = KDTree::build(points);
    let center = Point { coords: [2.0, 2.0] };

    let in_range = tree.range_search(&center, 1.5);
    assert_eq!(in_range.len(), 2);  // (1,1) and (2,2)
}

#[test]
fn test_2d_segment_tree() {
    let matrix = vec![
        vec![1, 2, 3],
        vec![4, 5, 6],
        vec![7, 8, 9],
    ];

    let seg = SegTree2D::build(&matrix);

    // Sum of entire matrix
    assert_eq!(seg.query(0, 0, 2, 2), 45);

    // Sum of submatrix [0,0] to [1,1]
    assert_eq!(seg.query(0, 0, 1, 1), 12);  // 1+2+4+5
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| Interval tree operations | 20 |
| Overlap queries | 15 |
| Range tree 1D/2D | 20 |
| KD-tree construction | 15 |
| Nearest neighbor | 15 |
| 2D segment tree | 10 |
| Edge cases | 5 |
| **Total** | **100** |
