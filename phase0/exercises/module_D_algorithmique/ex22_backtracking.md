# Exercice D.0.22-a : backtracking

**Module :**
D.0.22 — Algorithmes de Backtracking

**Concept :**
a-e — N-Queens, Sudoku solver, Subset sum, Permutations/Combinations, Maze solving

**Difficulte :**
★★★★★★☆☆☆☆ (6/10)

**Type :**
code

**Tiers :**
1 — Concept isole

**Langage :**
C17

**Prerequis :**
D.0.21 (recursion)

**Domaines :**
Algo

**Duree estimee :**
240 min

**XP Base :**
200

**Complexite :**
T[N] O(n!) x S[N] O(n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `backtracking.c`
- `backtracking.h`

### 1.2 Consigne

Implementer des algorithmes de backtracking classiques.

**Ta mission :**

```c
// N-Queens: place N queens on NxN board without conflicts
// Returns number of solutions found
int n_queens(int n, int solutions[][100], int max_solutions);

// Sudoku solver: solve a 9x9 sudoku grid
// Returns 1 if solution found, 0 otherwise
int solve_sudoku(int grid[9][9]);

// Subset sum: find subset of arr that sums to target
// Returns 1 if found, fills result array
int subset_sum(int *arr, int n, int target, int *result, int *result_size);

// Generate all permutations of array
void permutations(int *arr, int n, void (*callback)(int *, int));

// Generate all combinations of k elements from n
void combinations(int *arr, int n, int k, void (*callback)(int *, int));

// Maze solver: find path from start to end
// Maze: 0 = path, 1 = wall
// Returns 1 if path found, fills path array
int solve_maze(int **maze, int rows, int cols,
               int start_row, int start_col,
               int end_row, int end_col,
               int path[][2], int *path_length);
```

**Comportement:**

1. `n_queens(4)` -> 2 solutions
2. `solve_sudoku(grid)` -> fills grid with valid solution
3. `subset_sum([3,34,4,12,5,2], 9)` -> [4,5] or [3,4,2]
4. `permutations([1,2,3])` -> 6 permutations
5. `combinations([1,2,3,4], 2)` -> 6 combinations

**Exemples:**
```
N-Queens (N=4):
Solution 1:        Solution 2:
. Q . .            . . Q .
. . . Q            Q . . .
Q . . .            . . . Q
. . Q .            . Q . .

Sudoku (partial):
5 3 . | . 7 . | . . .      5 3 4 | 6 7 8 | 9 1 2
6 . . | 1 9 5 | . . .  ->  6 7 2 | 1 9 5 | 3 4 8
. 9 8 | . . . | . 6 .      1 9 8 | 3 4 2 | 5 6 7
------+-------+------      ------+-------+------
...                        ...

Maze (5x5):
S 0 1 0 0     Path found:
0 0 1 0 0     S * 1 0 0
1 0 0 0 1     0 * 1 0 0
1 1 1 0 0     1 * * * 1
0 0 0 0 E     1 1 1 * *
              0 0 0 * E
```

### 1.3 Prototype

```c
// backtracking.h
#ifndef BACKTRACKING_H
#define BACKTRACKING_H

int n_queens(int n, int solutions[][100], int max_solutions);
int solve_sudoku(int grid[9][9]);
int subset_sum(int *arr, int n, int target, int *result, int *result_size);
void permutations(int *arr, int n, void (*callback)(int *, int));
void combinations(int *arr, int n, int k, void (*callback)(int *, int));
int solve_maze(int **maze, int rows, int cols,
               int start_row, int start_col,
               int end_row, int end_col,
               int path[][2], int *path_length);

#endif
```

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test ID | Input | Expected | Points |
|---------|-------|----------|--------|
| T01 | n_queens(4) | 2 solutions | 15 |
| T02 | n_queens(8) | 92 solutions | 15 |
| T03 | solve_sudoku(easy) | valid solution | 15 |
| T04 | subset_sum([3,4,5,2], 9) | found | 10 |
| T05 | permutations(3 elements) | 6 calls | 10 |
| T06 | combinations(4, 2) | 6 calls | 10 |
| T07 | solve_maze(solvable) | path found | 15 |
| T08 | solve_maze(unsolvable) | return 0 | 10 |

### 4.3 Solution de reference

```c
#include <stdlib.h>
#include <string.h>
#include "backtracking.h"

// ============ N-QUEENS ============

static int is_safe_queen(int *board, int row, int col, int n)
{
    // Check column
    for (int i = 0; i < row; i++)
    {
        if (board[i] == col)
            return 0;
    }

    // Check upper-left diagonal
    for (int i = row - 1, j = col - 1; i >= 0 && j >= 0; i--, j--)
    {
        if (board[i] == j)
            return 0;
    }

    // Check upper-right diagonal
    for (int i = row - 1, j = col + 1; i >= 0 && j < n; i--, j++)
    {
        if (board[i] == j)
            return 0;
    }

    return 1;
}

static int solve_queens(int *board, int row, int n,
                        int solutions[][100], int *sol_count, int max_solutions)
{
    if (row == n)
    {
        if (*sol_count < max_solutions)
        {
            for (int i = 0; i < n; i++)
                solutions[*sol_count][i] = board[i];
            (*sol_count)++;
        }
        return 1;
    }

    int found = 0;
    for (int col = 0; col < n; col++)
    {
        if (is_safe_queen(board, row, col, n))
        {
            board[row] = col;
            found += solve_queens(board, row + 1, n, solutions, sol_count, max_solutions);
            board[row] = -1;  // Backtrack
        }
    }
    return found;
}

int n_queens(int n, int solutions[][100], int max_solutions)
{
    if (n <= 0 || n > 100)
        return 0;

    int *board = malloc(n * sizeof(int));
    for (int i = 0; i < n; i++)
        board[i] = -1;

    int sol_count = 0;
    solve_queens(board, 0, n, solutions, &sol_count, max_solutions);

    free(board);
    return sol_count;
}

// ============ SUDOKU ============

static int is_valid_sudoku(int grid[9][9], int row, int col, int num)
{
    // Check row
    for (int x = 0; x < 9; x++)
    {
        if (grid[row][x] == num)
            return 0;
    }

    // Check column
    for (int x = 0; x < 9; x++)
    {
        if (grid[x][col] == num)
            return 0;
    }

    // Check 3x3 box
    int start_row = row - row % 3;
    int start_col = col - col % 3;
    for (int i = 0; i < 3; i++)
    {
        for (int j = 0; j < 3; j++)
        {
            if (grid[i + start_row][j + start_col] == num)
                return 0;
        }
    }

    return 1;
}

static int sudoku_backtrack(int grid[9][9], int row, int col)
{
    // Reached end
    if (row == 9)
        return 1;

    // Move to next row
    if (col == 9)
        return sudoku_backtrack(grid, row + 1, 0);

    // Skip filled cells
    if (grid[row][col] != 0)
        return sudoku_backtrack(grid, row, col + 1);

    // Try numbers 1-9
    for (int num = 1; num <= 9; num++)
    {
        if (is_valid_sudoku(grid, row, col, num))
        {
            grid[row][col] = num;

            if (sudoku_backtrack(grid, row, col + 1))
                return 1;

            grid[row][col] = 0;  // Backtrack
        }
    }

    return 0;
}

int solve_sudoku(int grid[9][9])
{
    return sudoku_backtrack(grid, 0, 0);
}

// ============ SUBSET SUM ============

static int subset_sum_helper(int *arr, int n, int target, int *result,
                             int *result_size, int index, int current_sum)
{
    if (current_sum == target)
        return 1;

    if (index >= n || current_sum > target)
        return 0;

    // Include current element
    result[*result_size] = arr[index];
    (*result_size)++;

    if (subset_sum_helper(arr, n, target, result, result_size, index + 1,
                          current_sum + arr[index]))
        return 1;

    // Backtrack: exclude current element
    (*result_size)--;

    return subset_sum_helper(arr, n, target, result, result_size, index + 1,
                             current_sum);
}

int subset_sum(int *arr, int n, int target, int *result, int *result_size)
{
    *result_size = 0;

    if (target == 0)
        return 1;

    if (n <= 0 || target < 0)
        return 0;

    return subset_sum_helper(arr, n, target, result, result_size, 0, 0);
}

// ============ PERMUTATIONS ============

static void swap_int(int *a, int *b)
{
    int temp = *a;
    *a = *b;
    *b = temp;
}

static void perm_helper(int *arr, int n, int index, void (*callback)(int *, int))
{
    if (index == n)
    {
        callback(arr, n);
        return;
    }

    for (int i = index; i < n; i++)
    {
        swap_int(&arr[index], &arr[i]);
        perm_helper(arr, n, index + 1, callback);
        swap_int(&arr[index], &arr[i]);  // Backtrack
    }
}

void permutations(int *arr, int n, void (*callback)(int *, int))
{
    if (n <= 0 || arr == NULL || callback == NULL)
        return;

    int *temp = malloc(n * sizeof(int));
    memcpy(temp, arr, n * sizeof(int));

    perm_helper(temp, n, 0, callback);

    free(temp);
}

// ============ COMBINATIONS ============

static void comb_helper(int *arr, int n, int k, int index, int *current,
                        int curr_size, void (*callback)(int *, int))
{
    if (curr_size == k)
    {
        callback(current, k);
        return;
    }

    if (index >= n)
        return;

    // Include current element
    current[curr_size] = arr[index];
    comb_helper(arr, n, k, index + 1, current, curr_size + 1, callback);

    // Exclude current element (backtrack)
    comb_helper(arr, n, k, index + 1, current, curr_size, callback);
}

void combinations(int *arr, int n, int k, void (*callback)(int *, int))
{
    if (k > n || k <= 0 || n <= 0 || arr == NULL || callback == NULL)
        return;

    int *current = malloc(k * sizeof(int));

    comb_helper(arr, n, k, 0, current, 0, callback);

    free(current);
}

// ============ MAZE SOLVER ============

static int maze_helper(int **maze, int rows, int cols,
                       int row, int col, int end_row, int end_col,
                       int **visited, int path[][2], int *path_length)
{
    // Check bounds
    if (row < 0 || row >= rows || col < 0 || col >= cols)
        return 0;

    // Check if wall or already visited
    if (maze[row][col] == 1 || visited[row][col])
        return 0;

    // Add to path
    path[*path_length][0] = row;
    path[*path_length][1] = col;
    (*path_length)++;

    // Mark as visited
    visited[row][col] = 1;

    // Check if reached destination
    if (row == end_row && col == end_col)
        return 1;

    // Try all 4 directions: down, right, up, left
    int dr[] = {1, 0, -1, 0};
    int dc[] = {0, 1, 0, -1};

    for (int i = 0; i < 4; i++)
    {
        if (maze_helper(maze, rows, cols, row + dr[i], col + dc[i],
                        end_row, end_col, visited, path, path_length))
            return 1;
    }

    // Backtrack
    (*path_length)--;
    visited[row][col] = 0;

    return 0;
}

int solve_maze(int **maze, int rows, int cols,
               int start_row, int start_col,
               int end_row, int end_col,
               int path[][2], int *path_length)
{
    if (maze == NULL || rows <= 0 || cols <= 0)
        return 0;

    if (start_row < 0 || start_row >= rows || start_col < 0 || start_col >= cols)
        return 0;

    if (end_row < 0 || end_row >= rows || end_col < 0 || end_col >= cols)
        return 0;

    // Allocate visited array
    int **visited = malloc(rows * sizeof(int *));
    for (int i = 0; i < rows; i++)
    {
        visited[i] = calloc(cols, sizeof(int));
    }

    *path_length = 0;

    int result = maze_helper(maze, rows, cols, start_row, start_col,
                             end_row, end_col, visited, path, path_length);

    // Free visited array
    for (int i = 0; i < rows; i++)
        free(visited[i]);
    free(visited);

    return result;
}
```

### 4.10 Solutions Mutantes

```c
// MUTANT 1: N-Queens sans backtrack
static int solve_queens_m1(int *board, int row, int n)
{
    if (row == n)
        return 1;

    for (int col = 0; col < n; col++)
    {
        if (is_safe_queen(board, row, col, n))
        {
            board[row] = col;
            solve_queens_m1(board, row + 1, n);
            // ERREUR: pas de board[row] = -1
            // Les iterations suivantes voient un etat corrompu
        }
    }
    return 0;
}

// MUTANT 2: Sudoku modifie l'original meme en echec
static int sudoku_m2(int grid[9][9], int row, int col)
{
    if (row == 9)
        return 1;
    if (col == 9)
        return sudoku_m2(grid, row + 1, 0);
    if (grid[row][col] != 0)
        return sudoku_m2(grid, row, col + 1);

    for (int num = 1; num <= 9; num++)
    {
        grid[row][col] = num;  // ERREUR: pas de verification is_valid
        if (sudoku_m2(grid, row, col + 1))
            return 1;
        // ERREUR: pas de grid[row][col] = 0 en backtrack
    }
    return 0;
}

// MUTANT 3: Subset sum ne restaure pas result_size
static int subset_sum_m3(int *arr, int n, int target, int *result,
                         int *result_size, int index, int sum)
{
    if (sum == target)
        return 1;
    if (index >= n)
        return 0;

    result[*result_size] = arr[index];
    (*result_size)++;

    if (subset_sum_m3(arr, n, target, result, result_size, index + 1, sum + arr[index]))
        return 1;

    // ERREUR: (*result_size)-- manquant
    // Le resultat contient des elements parasites

    return subset_sum_m3(arr, n, target, result, result_size, index + 1, sum);
}

// MUTANT 4: Maze ne demarque pas les cellules visitees
static int maze_m4(int **maze, int rows, int cols, int row, int col,
                   int end_row, int end_col, int **visited, int path[][2], int *len)
{
    if (row < 0 || row >= rows || col < 0 || col >= cols)
        return 0;
    if (maze[row][col] == 1 || visited[row][col])
        return 0;

    path[*len][0] = row;
    path[*len][1] = col;
    (*len)++;
    visited[row][col] = 1;

    if (row == end_row && col == end_col)
        return 1;

    int dr[] = {1, 0, -1, 0};
    int dc[] = {0, 1, 0, -1};

    for (int i = 0; i < 4; i++)
    {
        if (maze_m4(maze, rows, cols, row + dr[i], col + dc[i],
                    end_row, end_col, visited, path, len))
            return 1;
    }

    (*len)--;
    // ERREUR: visited[row][col] = 0 manquant
    // Certains chemins valides ne seront jamais explores

    return 0;
}

// MUTANT 5: Combinations compte mal l'index
static void comb_m5(int *arr, int n, int k, int index, int *current,
                    int curr_size, void (*callback)(int *, int))
{
    if (curr_size == k)
    {
        callback(current, k);
        return;
    }
    if (index >= n)
        return;

    current[curr_size] = arr[index];
    comb_m5(arr, n, k, index + 1, current, curr_size + 1, callback);

    // ERREUR: devrait etre index + 1, pas index
    // Cause une recursion infinie
    comb_m5(arr, n, k, index, current, curr_size, callback);
}
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

Le **backtracking** est une technique algorithmique:

1. **Exploration systematique** - Essayer toutes les possibilites
2. **Pruning** - Abandonner les branches impossibles tot
3. **Etat/Restauration** - Sauvegarder et restaurer l'etat
4. **Recursion** - Structure naturellement recursive

### 5.3 Visualisation ASCII

```
BACKTRACKING PATTERN:

    solve(state)
        |
        v
    [Base case?] --YES--> Return solution
        |
        NO
        v
    For each choice:
        |
        +---> [Valid?] --NO--> Skip
        |        |
        |       YES
        |        v
        |   Make choice (modify state)
        |        |
        |        v
        |   solve(new_state)
        |        |
        |        v
        |   [Found?] --YES--> Return
        |        |
        |       NO
        |        v
        +<-- Undo choice (restore state)  <-- BACKTRACK!


N-QUEENS (N=4) Decision Tree:

                        []
           /      |       |      \
         Q0=0   Q0=1    Q0=2    Q0=3
          |       |       |       |
     [try Q1] [try Q1] [try Q1] [try Q1]
          |       |       |       |
        Q1=2    Q1=3    Q1=0    Q1=1
          |       |       |       |
        FAIL   Q2=0?   Q2=3?   FAIL
          |     FAIL    FAIL     |
          X       |       |      X
                 ...     ...

Final solutions:
Col:  0 1 2 3       0 1 2 3
Row 0: . Q . .      . . Q .
Row 1: . . . Q      Q . . .
Row 2: Q . . .      . . . Q
Row 3: . . Q .      . Q . .


SUDOKU Backtracking:

Grid state at cell (0,2):
5 3 _ | . 7 . | . . .    Try 1: invalid (column)
6 . . | 1 9 5 | . . .    Try 2: invalid (box)
. 9 8 | . . . | . 6 .    Try 3: invalid (row)
                         Try 4: VALID! Place 4
                              |
                              v
5 3 4 | . 7 . | . . .    Continue to (0,3)
6 . . | 1 9 5 | . . .    If stuck later, backtrack
. 9 8 | . . . | . 6 .    here and try 5, 6, 7...


MAZE Backtracking:

Step 1:     Step 2:     Step 3:     Step 4 (stuck):
S . 1 .     S . 1 .     S . 1 .     S . 1 .
. . 1 .     * . 1 .     * . 1 .     * . 1 .
1 . . .     1 . . .     1 * . .     1 * . .
. . . E     . . . E     . . . E     . 1 . E
                                    (wall!)

Step 5 (backtrack):   Step 6:       Step 7:
S . 1 .               S . 1 .       S . 1 .
* . 1 .               * * 1 .       * * 1 .
1 . . .               1 . . .       1 * . .
. . . E               . . . E       . * * E  FOUND!


COMPLEXITY Analysis:

N-Queens:
- Worst case: O(N!)
- Each row: N choices, N rows
- Pruning reduces actual branches

Sudoku:
- Worst case: O(9^81) = O(9^N) where N = empty cells
- With constraints: much faster in practice

Subset Sum:
- O(2^n) - each element included or not

Permutations:
- O(n!) - exactly n! outputs

Combinations C(n,k):
- O(C(n,k)) = O(n! / (k!(n-k)!))

Maze:
- O(4^(rows*cols)) worst case
- With visited tracking: O(rows * cols)
```

---

## SECTION 7 : QCM

### Question 1
Quelle est l'operation essentielle du backtracking?

A) Toujours avancer sans revenir
B) Restaurer l'etat precedent apres un echec
C) Utiliser une boucle infinie
D) Memoriser tous les etats possibles
E) Trier les donnees avant traitement

**Reponse correcte: B**

### Question 2
Pour le probleme N-Queens, quelle est la complexite temporelle dans le pire cas?

A) O(n)
B) O(n^2)
C) O(n log n)
D) O(2^n)
E) O(n!)

**Reponse correcte: E**

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "exercise_id": "D.0.22-a",
  "name": "backtracking",
  "language": "c",
  "language_version": "c17",
  "files": ["backtracking.c", "backtracking.h"],
  "difficulty": 6,
  "xp": 200,
  "complexity": {
    "time": "O(n!)",
    "space": "O(n)"
  },
  "tests": {
    "n_queens": "queens_tests",
    "sudoku": "sudoku_tests",
    "subset_sum": "subset_tests",
    "permutations": "perm_tests",
    "combinations": "comb_tests",
    "maze": "maze_tests"
  },
  "prerequisites": ["D.0.21"],
  "topics": ["backtracking", "recursion", "constraint-satisfaction", "combinatorics"]
}
```
