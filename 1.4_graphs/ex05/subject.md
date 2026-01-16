# Exercise 05: A* and Heuristic Search

## Concepts Covered
- **1.4.11.d-l** A* algorithm, admissible heuristics, optimality proofs
- **1.4.12.d-j** IDA*, Jump Point Search, bidirectional A*

## Objective

Implement heuristic-guided search algorithms for pathfinding.

## Requirements

### Rust Implementation

```rust
pub mod astar {
    use std::collections::{BinaryHeap, HashMap, HashSet};
    use std::cmp::Ordering;

    #[derive(Clone, Eq, PartialEq)]
    pub struct State<T> {
        pub node: T,
        pub g: i64,  // Cost from start
        pub f: i64,  // g + h (estimated total cost)
    }

    impl<T: Eq> Ord for State<T> {
        fn cmp(&self, other: &Self) -> Ordering {
            other.f.cmp(&self.f)  // Min-heap by f
        }
    }

    impl<T: Eq> PartialOrd for State<T> {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    /// A* search with generic state and heuristic
    pub fn astar<T, H, N, G>(
        start: T,
        goal: T,
        heuristic: H,
        neighbors: N,
        is_goal: G,
    ) -> Option<(i64, Vec<T>)>
    where
        T: Clone + Eq + std::hash::Hash,
        H: Fn(&T) -> i64,
        N: Fn(&T) -> Vec<(T, i64)>,
        G: Fn(&T) -> bool;

    /// A* on weighted graph
    pub fn astar_graph(
        adj: &[Vec<(usize, i64)>],
        source: usize,
        target: usize,
        heuristic: &[i64],
    ) -> Option<(i64, Vec<usize>)>;

    /// Bidirectional A*
    pub fn bidirectional_astar(
        adj: &[Vec<(usize, i64)>],
        rev_adj: &[Vec<(usize, i64)>],
        source: usize,
        target: usize,
        heuristic_forward: &[i64],
        heuristic_backward: &[i64],
    ) -> Option<(i64, Vec<usize>)>;

    /// IDA* (Iterative Deepening A*)
    pub fn ida_star<T, H, N, G>(
        start: T,
        heuristic: H,
        neighbors: N,
        is_goal: G,
    ) -> Option<(i64, Vec<T>)>
    where
        T: Clone + Eq,
        H: Fn(&T) -> i64,
        N: Fn(&T) -> Vec<(T, i64)>,
        G: Fn(&T) -> bool;
}

pub mod grid_search {
    /// Common heuristics for grid

    /// Manhattan distance (4-directional movement)
    pub fn manhattan(p1: (i32, i32), p2: (i32, i32)) -> i64;

    /// Euclidean distance
    pub fn euclidean(p1: (i32, i32), p2: (i32, i32)) -> f64;

    /// Chebyshev distance (8-directional movement)
    pub fn chebyshev(p1: (i32, i32), p2: (i32, i32)) -> i64;

    /// Octile distance (8-directional with diagonal cost √2)
    pub fn octile(p1: (i32, i32), p2: (i32, i32)) -> f64;

    /// A* on grid
    pub fn astar_grid(
        grid: &[Vec<char>],
        start: (usize, usize),
        goal: (usize, usize),
        diagonal: bool,
    ) -> Option<(i64, Vec<(usize, usize)>)>;

    /// A* with weighted cells
    pub fn astar_weighted_grid(
        grid: &[Vec<i32>],  // -1 = blocked, else cost to enter
        start: (usize, usize),
        goal: (usize, usize),
    ) -> Option<(i64, Vec<(usize, usize)>)>;

    /// Jump Point Search (JPS) - optimized A* for uniform grids
    pub fn jump_point_search(
        grid: &[Vec<bool>],  // true = walkable
        start: (usize, usize),
        goal: (usize, usize),
    ) -> Option<(i64, Vec<(usize, usize)>)>;

    /// Theta* (any-angle pathfinding)
    pub fn theta_star(
        grid: &[Vec<bool>],
        start: (usize, usize),
        goal: (usize, usize),
    ) -> Option<(f64, Vec<(usize, usize)>)>;
}

pub mod puzzle_search {
    /// 8-puzzle / 15-puzzle state
    #[derive(Clone, Eq, PartialEq, Hash)]
    pub struct PuzzleState {
        tiles: Vec<u8>,
        size: usize,
        blank: usize,
    }

    impl PuzzleState {
        pub fn new(tiles: Vec<u8>) -> Self;
        pub fn neighbors(&self) -> Vec<(PuzzleState, i64)>;
        pub fn is_solved(&self) -> bool;

        /// Manhattan distance heuristic
        pub fn manhattan_heuristic(&self) -> i64;

        /// Linear conflict heuristic (more informed)
        pub fn linear_conflict_heuristic(&self) -> i64;

        /// Check if puzzle is solvable
        pub fn is_solvable(&self) -> bool;
    }

    /// Solve sliding puzzle using IDA*
    pub fn solve_puzzle(initial: PuzzleState) -> Option<Vec<PuzzleState>>;

    /// Rubik's cube (2x2x2 for simplicity)
    #[derive(Clone, Eq, PartialEq, Hash)]
    pub struct CubeState {
        // 6 faces, each with 4 colors
        faces: [[u8; 4]; 6],
    }

    impl CubeState {
        pub fn new() -> Self;  // Solved state
        pub fn scramble(&mut self, moves: usize);
        pub fn apply_move(&mut self, m: Move);
        pub fn neighbors(&self) -> Vec<(CubeState, i64)>;
        pub fn is_solved(&self) -> bool;
        pub fn heuristic(&self) -> i64;
    }

    pub fn solve_cube(initial: CubeState) -> Option<Vec<Move>>;
}

pub mod constraint_search {
    /// N-Queens using backtracking with constraint propagation
    pub fn n_queens(n: usize) -> Option<Vec<usize>>;

    /// All N-Queens solutions
    pub fn all_n_queens(n: usize) -> Vec<Vec<usize>>;

    /// Sudoku solver using constraint propagation + backtracking
    pub fn solve_sudoku(grid: &mut [[u8; 9]; 9]) -> bool;

    /// Graph coloring
    pub fn graph_coloring(adj: &[Vec<usize>], k: usize) -> Option<Vec<usize>>;
}
```

### Python Implementation

```python
from typing import List, Optional, Tuple, Callable, TypeVar, Set
import heapq

T = TypeVar('T')

def astar(
    start: T,
    goal: T,
    heuristic: Callable[[T], int],
    neighbors: Callable[[T], List[Tuple[T, int]]],
    is_goal: Callable[[T], bool]
) -> Optional[Tuple[int, List[T]]]: ...

def astar_grid(
    grid: List[List[str]],
    start: Tuple[int, int],
    goal: Tuple[int, int],
    diagonal: bool = False
) -> Optional[Tuple[int, List[Tuple[int, int]]]]: ...

def manhattan(p1: Tuple[int, int], p2: Tuple[int, int]) -> int: ...
def chebyshev(p1: Tuple[int, int], p2: Tuple[int, int]) -> int: ...

class PuzzleState:
    def __init__(self, tiles: List[int]):
        self.tiles = tiles
        self.size = int(len(tiles) ** 0.5)
        self.blank = tiles.index(0)

    def neighbors(self) -> List[Tuple['PuzzleState', int]]: ...
    def is_solved(self) -> bool: ...
    def manhattan_heuristic(self) -> int: ...
    def is_solvable(self) -> bool: ...

def solve_puzzle(initial: PuzzleState) -> Optional[List[PuzzleState]]: ...

def n_queens(n: int) -> Optional[List[int]]: ...
def all_n_queens(n: int) -> List[List[int]]: ...
def solve_sudoku(grid: List[List[int]]) -> bool: ...
```

## Test Cases

```rust
#[test]
fn test_astar_graph() {
    // Graph with coordinates for heuristic
    let adj = vec![
        vec![(1, 1), (2, 4)],  // 0
        vec![(2, 2), (3, 5)],  // 1
        vec![(3, 1)],          // 2
        vec![],                // 3
    ];
    // Positions: 0=(0,0), 1=(1,0), 2=(1,1), 3=(2,1)
    let heuristic = vec![3, 2, 1, 0];  // Manhattan to node 3

    let result = astar_graph(&adj, 0, 3, &heuristic);
    assert!(result.is_some());
    let (cost, path) = result.unwrap();
    assert_eq!(cost, 4);  // 0 -> 1 -> 2 -> 3: 1 + 2 + 1 = 4
}

#[test]
fn test_astar_grid() {
    let grid = vec![
        vec!['.', '.', '.', '#', '.'],
        vec!['.', '#', '.', '#', '.'],
        vec!['.', '#', '.', '.', '.'],
        vec!['.', '.', '.', '#', '.'],
    ];

    let result = astar_grid(&grid, (0, 0), (3, 4), false);
    assert!(result.is_some());
    let (cost, path) = result.unwrap();
    assert!(!path.is_empty());
}

#[test]
fn test_manhattan_heuristic() {
    assert_eq!(manhattan((0, 0), (3, 4)), 7);
    assert_eq!(chebyshev((0, 0), (3, 4)), 4);
}

#[test]
fn test_8_puzzle() {
    // Solvable 8-puzzle
    let initial = PuzzleState::new(vec![1, 2, 3, 4, 0, 5, 6, 7, 8]);
    assert!(initial.is_solvable());

    let solution = solve_puzzle(initial);
    assert!(solution.is_some());
    assert!(solution.unwrap().last().unwrap().is_solved());
}

#[test]
fn test_unsolvable_puzzle() {
    // Unsolvable configuration (one swap from solved)
    let initial = PuzzleState::new(vec![1, 2, 3, 4, 5, 6, 8, 7, 0]);
    assert!(!initial.is_solvable());
}

#[test]
fn test_n_queens() {
    // 4-queens should have solution
    let solution = n_queens(4);
    assert!(solution.is_some());

    let queens = solution.unwrap();
    // Verify no two queens attack each other
    for i in 0..4 {
        for j in i+1..4 {
            assert_ne!(queens[i], queens[j]);  // Same row
            let diff = (j - i) as i32;
            assert_ne!((queens[j] as i32 - queens[i] as i32).abs(), diff);  // Diagonal
        }
    }
}

#[test]
fn test_all_n_queens() {
    let solutions = all_n_queens(8);
    assert_eq!(solutions.len(), 92);  // 8-queens has 92 solutions
}

#[test]
fn test_sudoku() {
    let mut grid = [
        [5, 3, 0, 0, 7, 0, 0, 0, 0],
        [6, 0, 0, 1, 9, 5, 0, 0, 0],
        [0, 9, 8, 0, 0, 0, 0, 6, 0],
        [8, 0, 0, 0, 6, 0, 0, 0, 3],
        [4, 0, 0, 8, 0, 3, 0, 0, 1],
        [7, 0, 0, 0, 2, 0, 0, 0, 6],
        [0, 6, 0, 0, 0, 0, 2, 8, 0],
        [0, 0, 0, 4, 1, 9, 0, 0, 5],
        [0, 0, 0, 0, 8, 0, 0, 7, 9],
    ];

    assert!(solve_sudoku(&mut grid));

    // Verify solution
    for i in 0..9 {
        let mut row = vec![false; 9];
        let mut col = vec![false; 9];
        for j in 0..9 {
            assert!(grid[i][j] >= 1 && grid[i][j] <= 9);
            row[(grid[i][j] - 1) as usize] = true;
            col[(grid[j][i] - 1) as usize] = true;
        }
        assert!(row.iter().all(|&x| x));
        assert!(col.iter().all(|&x| x));
    }
}
```

## Grading

| Criterion | Points |
|-----------|--------|
| A* algorithm | 20 |
| Heuristic functions | 10 |
| Grid pathfinding | 15 |
| IDA* | 15 |
| Sliding puzzle | 15 |
| N-Queens / Sudoku | 15 |
| Jump Point Search | 5 |
| Edge cases | 5 |
| **Total** | **100** |
