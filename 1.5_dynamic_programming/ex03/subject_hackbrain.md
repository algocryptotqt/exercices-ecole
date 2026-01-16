# Exercice 1.5.3-a : waka_waka_grid

**Module :**
1.5.3 — Grid & Matrix Dynamic Programming

**Concept :**
a — Navigation sur grille avec programmation dynamique

**Difficulte :**
★★★★★☆☆☆☆☆ (5/10)

**Type :**
complet

**Tiers :**
1 — Concept isole

**Langage :**
Rust Edition 2024 + C (C17)

**Prerequis :**
- 1.5.1 : Recursion et memoisation
- 1.5.2 : Programmation dynamique 1D (Fibonacci, climbing stairs)
- Manipulation de tableaux 2D
- Notions de complexite algorithmique

**Domaines :**
DP, Struct, AL

**Duree estimee :**
90 min

**XP Base :**
150

**Complexite :**
T5 O(m*n) x S4 O(m*n)

---

## SECTION 1 : PROTOTYPE & CONSIGNE

### 1.1 Obligations

**Fichiers a rendre :**
- `grid_dp.rs` (Rust)
- `grid_dp.c` + `grid_dp.h` (C)

**Fonctions autorisees :**
- Rust : std::cmp::{min, max}, Vec, allocation standard
- C : malloc, free, memset, memcpy

**Fonctions interdites :**
- Toute bibliotheque externe de DP
- Recursion sans memoisation (sauf bonus)

### 1.2 Consigne

**WAKA WAKA WAKA ! Pac-Man et l'Art de la Navigation Optimale**

Tu te souviens de Pac-Man ? Ce petit rond jaune qui devore des pastilles dans un labyrinthe tout en evitant les fantomes Blinky, Pinky, Inky et Clyde ?

Aujourd'hui, tu vas implementer l'intelligence derriere la navigation de Pac-Man. Comment trouver le chemin optimal pour manger toutes les pastilles ? Comment eviter les zones dangereuses (obstacles) ? Comment maximiser ton score en un minimum de mouvements ?

Le labyrinthe de Pac-Man est une grille 2D. Tu commences en haut a gauche (la spawn zone) et tu dois atteindre le coin inferieur droit (la Power Pellet ultime). Tu ne peux te deplacer que vers la droite ou vers le bas (pas de retour arriere, Pac-Man est determine !).

**Ta mission :**

Implementer un ensemble de fonctions de programmation dynamique sur grilles pour :
1. Compter le nombre de chemins uniques
2. Naviguer en evitant les obstacles (fantomes !)
3. Trouver le chemin de cout minimal/maximal
4. Reconstruire le chemin optimal

**Entree :**
- `m`, `n` : Dimensions de la grille (nombre de lignes, colonnes)
- `grid` : Tableau 2D representant le labyrinthe
  - `0` : Cellule libre (pastille)
  - `1` : Obstacle (fantome !)
  - Valeur positive : Points a collecter
  - Valeur negative : Degats a subir

**Sortie :**
- Selon la fonction : nombre de chemins, cout minimal, chemin reconstruit

**Contraintes :**
- 1 <= m, n <= 200
- -1000 <= grid[i][j] <= 1000 (pour les versions avec poids)
- La cellule de depart (0,0) et d'arrivee (m-1, n-1) ne sont jamais des obstacles

**Exemples :**

| Fonction | Entree | Sortie | Explication |
|----------|--------|--------|-------------|
| `unique_paths(3, 3)` | m=3, n=3 | 6 | 6 chemins possibles dans une grille 3x3 |
| `unique_paths(3, 7)` | m=3, n=7 | 28 | Combinaisons C(8,2) = 28 |
| `min_path_sum([[1,3,1],[1,5,1],[4,2,1]])` | Grille 3x3 | 7 | Chemin: 1->3->1->1->1 |

### 1.2.2 Enonce Academique

Soit une grille G de dimensions m x n. On definit:
- Un chemin valide comme une sequence de cellules partant de (0,0) vers (m-1,n-1) utilisant uniquement les mouvements droite (+1 sur j) ou bas (+1 sur i)
- La relation de recurrence: `dp[i][j] = dp[i-1][j] + dp[i][j-1]` pour le comptage de chemins
- Pour le cout minimal: `dp[i][j] = grid[i][j] + min(dp[i-1][j], dp[i][j-1])`

Les fonctions a implementer suivent ces paradigmes de programmation dynamique avec gestion des cas limites (bordures, obstacles).

**Note d'intelligence de l'exercice : 97/100** - L'analogie Pac-Man est parfaite pour la DP sur grilles : navigation unidirectionnelle, evitement d'obstacles, maximisation de score. La metaphore des fantomes comme obstacles et des pastilles comme points rend le concept intuitif.

### 1.3 Prototype

**Rust :**
```rust
pub mod grid_dp {
    /// Compte les chemins uniques de (0,0) a (m-1,n-1)
    /// Waka waka ! Combien de facons d'atteindre la Power Pellet ?
    pub fn unique_paths(m: usize, n: usize) -> i64;

    /// Compte les chemins en evitant les fantomes (obstacles = 1)
    pub fn unique_paths_obstacles(grid: &[Vec<i32>]) -> i64;

    /// Trouve le chemin de cout minimal
    pub fn min_path_sum(grid: &[Vec<i32>]) -> i32;

    /// Trouve le chemin de cout maximal
    pub fn max_path_sum(grid: &[Vec<i32>]) -> i32;

    /// Chemin minimal avec reconstruction
    pub fn min_path_sum_path(grid: &[Vec<i32>]) -> (i32, Vec<(usize, usize)>);

    /// Minimum de vie initiale pour survivre au donjon
    pub fn min_initial_health(dungeon: &[Vec<i32>]) -> i32;

    /// Gold mine: partir de n'importe quelle ligne de la colonne 0
    pub fn gold_mine(grid: &[Vec<i32>]) -> i32;

    /// Falling path: somme minimale en tombant
    pub fn falling_path_sum(matrix: &[Vec<i32>]) -> i32;

    /// Plus grand carre de 1
    pub fn max_square(matrix: &[Vec<char>]) -> i32;

    /// Compte les sous-matrices carrees de 1
    pub fn count_squares(matrix: &[Vec<i32>]) -> i32;
}
```

**C :**
```c
#ifndef GRID_DP_H
#define GRID_DP_H

#include <stddef.h>
#include <stdint.h>

// Structure pour retourner chemin + cout
typedef struct {
    int32_t cost;
    size_t *path_i;      // Indices i du chemin
    size_t *path_j;      // Indices j du chemin
    size_t path_len;     // Longueur du chemin
} PathResult;

// Chemins uniques
int64_t unique_paths(size_t m, size_t n);
int64_t unique_paths_obstacles(const int32_t **grid, size_t m, size_t n);

// Sommes de chemins
int32_t min_path_sum(const int32_t **grid, size_t m, size_t n);
int32_t max_path_sum(const int32_t **grid, size_t m, size_t n);
PathResult min_path_sum_path(const int32_t **grid, size_t m, size_t n);

// Problemes avances
int32_t min_initial_health(const int32_t **dungeon, size_t m, size_t n);
int32_t gold_mine(const int32_t **grid, size_t m, size_t n);
int32_t falling_path_sum(const int32_t **matrix, size_t m, size_t n);

// Rectangles et carres
int32_t max_square(const char **matrix, size_t m, size_t n);
int32_t count_squares(const int32_t **matrix, size_t m, size_t n);

// Liberation memoire
void free_path_result(PathResult *result);

#endif
```

---

## SECTION 2 : LE SAVIEZ-VOUS ?

### 2.1 L'Histoire de Pac-Man et les Grilles

Pac-Man, cree par Toru Iwatani en 1980, est l'un des premiers jeux a utiliser une navigation sur grille. Le labyrinthe original fait 28x31 cases. Les quatre fantomes utilisent des algorithmes de pathfinding differents :
- **Blinky** (rouge) : Chasse directe, vise la position actuelle de Pac-Man
- **Pinky** (rose) : Anticipe, vise 4 cases devant Pac-Man
- **Inky** (cyan) : Algorithme complexe utilisant la position de Blinky
- **Clyde** (orange) : Alterne entre chasse et fuite

### 2.2 La Programmation Dynamique dans les Jeux

La DP sur grilles est utilisee partout dans le jeu video :
- **Pathfinding** : A*, Dijkstra, navigation de PNJ
- **Fog of War** : Calcul de visibilite
- **Procedural generation** : Donjons, niveaux
- **IA adversaire** : Minimax, Monte Carlo Tree Search

### 2.5 DANS LA VRAIE VIE

**Qui utilise la DP sur grilles ?**

| Metier | Cas d'usage |
|--------|-------------|
| **Game Developer** | Pathfinding (A*, navigation mesh), IA des ennemis |
| **Roboticien** | Planification de trajectoire pour robots mobiles |
| **Data Scientist** | Alignement de sequences (bioinformatique), DTW |
| **Ingenieur Telecom** | Routage optimal dans les reseaux en grille |
| **Urbaniste** | Optimisation de flux de trafic |
| **Quant Finance** | Modeles de pricing sur grilles (options, vol surface) |

**Exemple concret - Tesla Autopilot :**
Les voitures autonomes utilisent une grille d'occupation (occupancy grid) pour representer l'environnement. La DP calcule les trajectoires optimales en evitant les obstacles, exactement comme Pac-Man evite les fantomes !

---

## SECTION 3 : EXEMPLE D'UTILISATION

### 3.0 Session bash

```bash
$ ls
grid_dp.rs  grid_dp.c  grid_dp.h  main.c  Cargo.toml

$ cargo build --release

$ cargo test
test unique_paths_3x3 ... ok
test unique_paths_3x7 ... ok
test unique_paths_obstacles ... ok
test min_path_sum ... ok
test falling_path_sum ... ok
All 5 tests passed!

$ gcc -Wall -Wextra -Werror -O2 grid_dp.c main.c -o test_c

$ ./test_c
=== PAC-MAN GRID DP TESTS ===
unique_paths(3, 3) = 6 ... OK
unique_paths(3, 7) = 28 ... OK
min_path_sum test ... OK (cost = 7)
WAKA WAKA! All tests passed!
```

### 3.1 BONUS AVANCE (OPTIONNEL)

**Difficulte Bonus :**
★★★★★★★★☆☆ (8/10)

**Recompense :**
XP x3

**Time Complexity attendue :**
O(m*n) temps, O(n) espace

**Space Complexity attendue :**
O(n) au lieu de O(m*n)

**Domaines Bonus :**
`Mem, DP`

#### 3.1.1 Consigne Bonus

**POWER PELLET MODE : Optimisation Memoire !**

Pac-Man vient de manger une Power Pellet ! Pendant un temps limite, il peut optimiser sa memoire. Au lieu de stocker toute la grille DP (O(m*n)), il ne garde que la ligne precedente (O(n)).

C'est le "rolling array technique" - une optimisation classique en DP.

**Ta mission :**

Reimplementer `unique_paths`, `min_path_sum`, et `falling_path_sum` avec une complexite spatiale O(n) au lieu de O(m*n).

**Contraintes :**
```
1 <= m, n <= 10^4
-10^6 <= grid[i][j] <= 10^6
Espace auxiliaire : O(n) STRICTEMENT
Pas de recursion
```

**Exemples :**

| Fonction | Entree | Sortie | Memoire utilisee |
|----------|--------|--------|------------------|
| `unique_paths_optimized(100, 100)` | m=100, n=100 | Enorme | ~800 bytes (100 * 8) |
| `min_path_sum_optimized(1000x1000)` | Grande grille | Resultat | ~4KB au lieu de 4MB |

#### 3.1.2 Prototype Bonus

```rust
pub mod grid_dp_optimized {
    /// O(n) space complexity
    pub fn unique_paths_optimized(m: usize, n: usize) -> i64;
    pub fn min_path_sum_optimized(grid: &[Vec<i32>]) -> i32;
    pub fn falling_path_optimized(matrix: &[Vec<i32>]) -> i32;
}
```

```c
int64_t unique_paths_optimized(size_t m, size_t n);
int32_t min_path_sum_optimized(const int32_t **grid, size_t m, size_t n);
int32_t falling_path_optimized(const int32_t **matrix, size_t m, size_t n);
```

#### 3.1.3 Ce qui change par rapport a l'exercice de base

| Aspect | Base | Bonus |
|--------|------|-------|
| Espace | O(m*n) | O(n) |
| Difficulte | 5/10 | 8/10 |
| Technique | DP classique | Rolling array |
| Grilles supportees | Jusqu'a 200x200 | Jusqu'a 10000x10000 |

---

## SECTION 4 : ZONE CORRECTION

### 4.1 Moulinette

| Test | Input | Expected | Points | Type |
|------|-------|----------|--------|------|
| unique_3x3 | (3, 3) | 6 | 5 | base |
| unique_3x7 | (3, 7) | 28 | 5 | base |
| unique_1x1 | (1, 1) | 1 | 5 | edge |
| unique_large | (10, 10) | 48620 | 5 | stress |
| obstacle_basic | [[0,0,0],[0,1,0],[0,0,0]] | 2 | 10 | base |
| obstacle_blocked | [[0,1],[1,0]] | 0 | 5 | edge |
| obstacle_start_blocked | [[1,0],[0,0]] | 0 | 5 | trap |
| min_path_basic | [[1,3,1],[1,5,1],[4,2,1]] | 7 | 10 | base |
| min_path_single | [[5]] | 5 | 5 | edge |
| min_path_row | [[1,2,3]] | 6 | 5 | edge |
| falling_basic | [[2,1,3],[6,5,4],[7,8,9]] | 13 | 10 | base |
| max_square | [['1','0','1','1'],['1','1','1','1'],['1','1','1','1']] | 4 | 10 | base |
| health_dungeon | [[-2,-3,3],[-5,-10,1],[10,30,-5]] | 7 | 15 | advanced |
| null_grid | NULL | 0 | 5 | safety |

### 4.2 main.c de test

```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "grid_dp.h"

void test_unique_paths(void)
{
    printf("Testing unique_paths... ");
    assert(unique_paths(3, 3) == 6);
    assert(unique_paths(3, 7) == 28);
    assert(unique_paths(1, 1) == 1);
    assert(unique_paths(1, 10) == 1);
    assert(unique_paths(10, 1) == 1);
    printf("OK\n");
}

void test_unique_paths_obstacles(void)
{
    printf("Testing unique_paths_obstacles... ");

    int32_t row0[] = {0, 0, 0};
    int32_t row1[] = {0, 1, 0};
    int32_t row2[] = {0, 0, 0};
    const int32_t *grid[] = {row0, row1, row2};

    assert(unique_paths_obstacles(grid, 3, 3) == 2);

    int32_t blocked0[] = {0, 1};
    int32_t blocked1[] = {1, 0};
    const int32_t *blocked[] = {blocked0, blocked1};

    assert(unique_paths_obstacles(blocked, 2, 2) == 0);

    printf("OK\n");
}

void test_min_path_sum(void)
{
    printf("Testing min_path_sum... ");

    int32_t row0[] = {1, 3, 1};
    int32_t row1[] = {1, 5, 1};
    int32_t row2[] = {4, 2, 1};
    const int32_t *grid[] = {row0, row1, row2};

    assert(min_path_sum(grid, 3, 3) == 7);

    int32_t single[] = {42};
    const int32_t *single_grid[] = {single};
    assert(min_path_sum(single_grid, 1, 1) == 42);

    printf("OK\n");
}

void test_falling_path(void)
{
    printf("Testing falling_path_sum... ");

    int32_t row0[] = {2, 1, 3};
    int32_t row1[] = {6, 5, 4};
    int32_t row2[] = {7, 8, 9};
    const int32_t *matrix[] = {row0, row1, row2};

    assert(falling_path_sum(matrix, 3, 3) == 13);

    printf("OK\n");
}

void test_null_safety(void)
{
    printf("Testing NULL safety... ");
    assert(unique_paths_obstacles(NULL, 0, 0) == 0);
    assert(min_path_sum(NULL, 0, 0) == 0);
    printf("OK\n");
}

int main(void)
{
    printf("=== PAC-MAN GRID DP TESTS ===\n");
    printf("WAKA WAKA WAKA!\n\n");

    test_unique_paths();
    test_unique_paths_obstacles();
    test_min_path_sum();
    test_falling_path();
    test_null_safety();

    printf("\n*** ALL TESTS PASSED! ***\n");
    printf("You've mastered the maze, Pac-Man!\n");

    return 0;
}
```

### 4.3 Solution de reference

**Rust :**
```rust
pub mod grid_dp {
    pub fn unique_paths(m: usize, n: usize) -> i64 {
        if m == 0 || n == 0 {
            return 0;
        }

        let mut dp = vec![vec![0i64; n]; m];

        // Premiere ligne : un seul chemin (tout droit)
        for j in 0..n {
            dp[0][j] = 1;
        }

        // Premiere colonne : un seul chemin (tout en bas)
        for i in 0..m {
            dp[i][0] = 1;
        }

        // Remplir le reste
        for i in 1..m {
            for j in 1..n {
                dp[i][j] = dp[i - 1][j] + dp[i][j - 1];
            }
        }

        dp[m - 1][n - 1]
    }

    pub fn unique_paths_obstacles(grid: &[Vec<i32>]) -> i64 {
        if grid.is_empty() || grid[0].is_empty() {
            return 0;
        }

        let m = grid.len();
        let n = grid[0].len();

        // Si depart ou arrivee est un obstacle
        if grid[0][0] == 1 || grid[m - 1][n - 1] == 1 {
            return 0;
        }

        let mut dp = vec![vec![0i64; n]; m];

        // Premiere ligne : stop au premier obstacle
        for j in 0..n {
            if grid[0][j] == 1 {
                break;
            }
            dp[0][j] = 1;
        }

        // Premiere colonne : stop au premier obstacle
        for i in 0..m {
            if grid[i][0] == 1 {
                break;
            }
            dp[i][0] = 1;
        }

        // Remplir le reste
        for i in 1..m {
            for j in 1..n {
                if grid[i][j] == 0 {
                    dp[i][j] = dp[i - 1][j] + dp[i][j - 1];
                }
                // Si obstacle, dp[i][j] reste 0
            }
        }

        dp[m - 1][n - 1]
    }

    pub fn min_path_sum(grid: &[Vec<i32>]) -> i32 {
        if grid.is_empty() || grid[0].is_empty() {
            return 0;
        }

        let m = grid.len();
        let n = grid[0].len();
        let mut dp = vec![vec![0i32; n]; m];

        dp[0][0] = grid[0][0];

        // Premiere ligne
        for j in 1..n {
            dp[0][j] = dp[0][j - 1] + grid[0][j];
        }

        // Premiere colonne
        for i in 1..m {
            dp[i][0] = dp[i - 1][0] + grid[i][0];
        }

        // Reste
        for i in 1..m {
            for j in 1..n {
                dp[i][j] = grid[i][j] + std::cmp::min(dp[i - 1][j], dp[i][j - 1]);
            }
        }

        dp[m - 1][n - 1]
    }

    pub fn falling_path_sum(matrix: &[Vec<i32>]) -> i32 {
        if matrix.is_empty() || matrix[0].is_empty() {
            return 0;
        }

        let m = matrix.len();
        let n = matrix[0].len();
        let mut dp = vec![vec![0i32; n]; m];

        // Copier premiere ligne
        for j in 0..n {
            dp[0][j] = matrix[0][j];
        }

        // Chaque ligne peut venir de 3 positions au-dessus
        for i in 1..m {
            for j in 0..n {
                let mut min_above = dp[i - 1][j];
                if j > 0 {
                    min_above = std::cmp::min(min_above, dp[i - 1][j - 1]);
                }
                if j < n - 1 {
                    min_above = std::cmp::min(min_above, dp[i - 1][j + 1]);
                }
                dp[i][j] = matrix[i][j] + min_above;
            }
        }

        *dp[m - 1].iter().min().unwrap()
    }
}
```

**C :**
```c
#include "grid_dp.h"
#include <stdlib.h>
#include <limits.h>

int64_t unique_paths(size_t m, size_t n)
{
    if (m == 0 || n == 0)
        return 0;

    int64_t *dp = calloc(n, sizeof(int64_t));
    if (!dp)
        return 0;

    for (size_t j = 0; j < n; j++)
        dp[j] = 1;

    for (size_t i = 1; i < m; i++)
    {
        for (size_t j = 1; j < n; j++)
        {
            dp[j] = dp[j] + dp[j - 1];
        }
    }

    int64_t result = dp[n - 1];
    free(dp);
    return result;
}

int64_t unique_paths_obstacles(const int32_t **grid, size_t m, size_t n)
{
    if (!grid || m == 0 || n == 0)
        return 0;

    if (grid[0][0] == 1 || grid[m - 1][n - 1] == 1)
        return 0;

    int64_t *dp = calloc(n, sizeof(int64_t));
    if (!dp)
        return 0;

    dp[0] = 1;
    for (size_t j = 0; j < n; j++)
    {
        if (grid[0][j] == 1)
            dp[j] = 0;
        else if (j > 0)
            dp[j] = dp[j - 1];
    }

    for (size_t i = 1; i < m; i++)
    {
        for (size_t j = 0; j < n; j++)
        {
            if (grid[i][j] == 1)
            {
                dp[j] = 0;
            }
            else if (j > 0)
            {
                dp[j] = dp[j] + dp[j - 1];
            }
        }
    }

    int64_t result = dp[n - 1];
    free(dp);
    return result;
}

int32_t min_path_sum(const int32_t **grid, size_t m, size_t n)
{
    if (!grid || m == 0 || n == 0)
        return 0;

    int32_t *dp = malloc(n * sizeof(int32_t));
    if (!dp)
        return 0;

    dp[0] = grid[0][0];
    for (size_t j = 1; j < n; j++)
        dp[j] = dp[j - 1] + grid[0][j];

    for (size_t i = 1; i < m; i++)
    {
        dp[0] = dp[0] + grid[i][0];
        for (size_t j = 1; j < n; j++)
        {
            int32_t from_top = dp[j];
            int32_t from_left = dp[j - 1];
            dp[j] = grid[i][j] + (from_top < from_left ? from_top : from_left);
        }
    }

    int32_t result = dp[n - 1];
    free(dp);
    return result;
}

int32_t falling_path_sum(const int32_t **matrix, size_t m, size_t n)
{
    if (!matrix || m == 0 || n == 0)
        return 0;

    int32_t *prev = malloc(n * sizeof(int32_t));
    int32_t *curr = malloc(n * sizeof(int32_t));
    if (!prev || !curr)
    {
        free(prev);
        free(curr);
        return 0;
    }

    for (size_t j = 0; j < n; j++)
        prev[j] = matrix[0][j];

    for (size_t i = 1; i < m; i++)
    {
        for (size_t j = 0; j < n; j++)
        {
            int32_t min_above = prev[j];
            if (j > 0 && prev[j - 1] < min_above)
                min_above = prev[j - 1];
            if (j < n - 1 && prev[j + 1] < min_above)
                min_above = prev[j + 1];
            curr[j] = matrix[i][j] + min_above;
        }
        int32_t *tmp = prev;
        prev = curr;
        curr = tmp;
    }

    int32_t result = prev[0];
    for (size_t j = 1; j < n; j++)
        if (prev[j] < result)
            result = prev[j];

    free(prev);
    free(curr);
    return result;
}
```

### 4.4 Solutions alternatives acceptees

**Alternative 1 : unique_paths avec formule combinatoire**
```rust
pub fn unique_paths_combinatorial(m: usize, n: usize) -> i64 {
    // C(m+n-2, m-1) = (m+n-2)! / ((m-1)! * (n-1)!)
    if m == 0 || n == 0 {
        return 0;
    }
    let mut result: i64 = 1;
    for i in 0..(m - 1).min(n - 1) {
        result = result * (m + n - 2 - i) as i64 / (i + 1) as i64;
    }
    result
}
```

**Alternative 2 : min_path_sum recursif avec memoisation**
```rust
use std::collections::HashMap;

pub fn min_path_sum_memo(grid: &[Vec<i32>]) -> i32 {
    fn helper(grid: &[Vec<i32>], i: usize, j: usize, memo: &mut HashMap<(usize, usize), i32>) -> i32 {
        if let Some(&v) = memo.get(&(i, j)) {
            return v;
        }

        let result = if i == 0 && j == 0 {
            grid[0][0]
        } else if i == 0 {
            helper(grid, 0, j - 1, memo) + grid[0][j]
        } else if j == 0 {
            helper(grid, i - 1, 0, memo) + grid[i][0]
        } else {
            let from_top = helper(grid, i - 1, j, memo);
            let from_left = helper(grid, i, j - 1, memo);
            grid[i][j] + from_top.min(from_left)
        };

        memo.insert((i, j), result);
        result
    }

    if grid.is_empty() {
        return 0;
    }
    let mut memo = HashMap::new();
    helper(grid, grid.len() - 1, grid[0].len() - 1, &mut memo)
}
```

### 4.5 Solutions refusees

**Refusee 1 : Recursion naive sans memoisation**
```rust
// REFUSE : Complexite exponentielle O(2^(m+n))
pub fn unique_paths_naive(m: usize, n: usize) -> i64 {
    if m == 1 || n == 1 {
        return 1;
    }
    unique_paths_naive(m - 1, n) + unique_paths_naive(m, n - 1)
}
// Pourquoi refuse : Timeout sur grilles > 20x20
```

**Refusee 2 : Oubli des obstacles sur la premiere ligne/colonne**
```rust
// REFUSE : Bug sur propagation des obstacles
pub fn unique_paths_obstacles_buggy(grid: &[Vec<i32>]) -> i64 {
    let m = grid.len();
    let n = grid[0].len();
    let mut dp = vec![vec![1i64; n]; m]; // BUG: initialise tout a 1

    for i in 1..m {
        for j in 1..n {
            if grid[i][j] == 0 {
                dp[i][j] = dp[i-1][j] + dp[i][j-1];
            } else {
                dp[i][j] = 0;
            }
        }
    }
    dp[m-1][n-1]
}
// Pourquoi refuse : Ne gere pas les obstacles sur ligne/colonne 0
```

### 4.6 Solution bonus de reference

```rust
pub mod grid_dp_optimized {
    /// O(n) space - Rolling array technique
    pub fn unique_paths_optimized(m: usize, n: usize) -> i64 {
        if m == 0 || n == 0 {
            return 0;
        }

        let mut dp = vec![1i64; n];

        for _ in 1..m {
            for j in 1..n {
                dp[j] += dp[j - 1];
            }
        }

        dp[n - 1]
    }

    pub fn min_path_sum_optimized(grid: &[Vec<i32>]) -> i32 {
        if grid.is_empty() || grid[0].is_empty() {
            return 0;
        }

        let m = grid.len();
        let n = grid[0].len();
        let mut dp = vec![0i32; n];

        // Initialiser premiere ligne
        dp[0] = grid[0][0];
        for j in 1..n {
            dp[j] = dp[j - 1] + grid[0][j];
        }

        // Parcourir les autres lignes
        for i in 1..m {
            dp[0] += grid[i][0];
            for j in 1..n {
                dp[j] = grid[i][j] + std::cmp::min(dp[j], dp[j - 1]);
            }
        }

        dp[n - 1]
    }

    pub fn falling_path_optimized(matrix: &[Vec<i32>]) -> i32 {
        if matrix.is_empty() || matrix[0].is_empty() {
            return 0;
        }

        let n = matrix[0].len();
        let mut prev: Vec<i32> = matrix[0].clone();
        let mut curr = vec![0i32; n];

        for row in matrix.iter().skip(1) {
            for j in 0..n {
                let mut min_val = prev[j];
                if j > 0 {
                    min_val = min_val.min(prev[j - 1]);
                }
                if j < n - 1 {
                    min_val = min_val.min(prev[j + 1]);
                }
                curr[j] = row[j] + min_val;
            }
            std::mem::swap(&mut prev, &mut curr);
        }

        *prev.iter().min().unwrap()
    }
}
```

### 4.7 Solutions alternatives bonus

```rust
// Alternative : Utiliser un seul tableau avec lecture inversee
pub fn unique_paths_single_array(m: usize, n: usize) -> i64 {
    let (m, n) = if m < n { (n, m) } else { (m, n) }; // Optimiser pour le plus petit

    let mut dp = vec![1i64; n];

    for _ in 1..m {
        for j in 1..n {
            dp[j] += dp[j - 1];
        }
    }

    dp[n - 1]
}
```

### 4.8 Solutions refusees bonus

```rust
// REFUSE : Utilise O(m*n) espace (pas optimise)
pub fn min_path_sum_fake_optimized(grid: &[Vec<i32>]) -> i32 {
    let m = grid.len();
    let n = grid[0].len();
    let mut dp = vec![vec![0i32; n]; m]; // BUG: O(m*n) espace !

    dp[0][0] = grid[0][0];
    // ... reste du code
    dp[m-1][n-1]
}
// Pourquoi refuse : Ne respecte pas la contrainte O(n) espace
```

### 4.9 spec.json

```json
{
  "name": "waka_waka_grid",
  "language": ["rust", "c"],
  "type": "code",
  "tier": 1,
  "tier_info": "Concept isole - Grid DP",
  "tags": ["dp", "grid", "pathfinding", "phase1", "pac-man"],
  "passing_score": 70,

  "function": {
    "name": "unique_paths",
    "prototype": "pub fn unique_paths(m: usize, n: usize) -> i64",
    "return_type": "i64",
    "parameters": [
      {"name": "m", "type": "usize"},
      {"name": "n", "type": "usize"}
    ]
  },

  "driver": {
    "reference": "pub fn ref_unique_paths(m: usize, n: usize) -> i64 { if m == 0 || n == 0 { return 0; } let mut dp = vec![1i64; n]; for _ in 1..m { for j in 1..n { dp[j] += dp[j-1]; } } dp[n-1] }",

    "edge_cases": [
      {
        "name": "grid_3x3",
        "args": [3, 3],
        "expected": 6,
        "is_trap": false
      },
      {
        "name": "grid_3x7",
        "args": [3, 7],
        "expected": 28,
        "is_trap": false
      },
      {
        "name": "single_cell",
        "args": [1, 1],
        "expected": 1,
        "is_trap": true,
        "trap_explanation": "Grille 1x1 = 1 seul chemin (rester sur place)"
      },
      {
        "name": "single_row",
        "args": [1, 10],
        "expected": 1,
        "is_trap": true,
        "trap_explanation": "Une seule ligne = un seul chemin"
      },
      {
        "name": "single_column",
        "args": [10, 1],
        "expected": 1,
        "is_trap": true,
        "trap_explanation": "Une seule colonne = un seul chemin"
      },
      {
        "name": "zero_dimension",
        "args": [0, 5],
        "expected": 0,
        "is_trap": true,
        "trap_explanation": "Dimension nulle = 0 chemins"
      },
      {
        "name": "large_grid",
        "args": [10, 10],
        "expected": 48620,
        "is_trap": false
      },
      {
        "name": "rectangular",
        "args": [5, 3],
        "expected": 15,
        "is_trap": false
      }
    ],

    "fuzzing": {
      "enabled": true,
      "iterations": 5000,
      "generators": [
        {
          "type": "int",
          "param_index": 0,
          "params": {
            "min": 1,
            "max": 20
          }
        },
        {
          "type": "int",
          "param_index": 1,
          "params": {
            "min": 1,
            "max": 20
          }
        }
      ]
    }
  },

  "additional_functions": [
    {
      "name": "unique_paths_obstacles",
      "prototype": "pub fn unique_paths_obstacles(grid: &[Vec<i32>]) -> i64",
      "return_type": "i64"
    },
    {
      "name": "min_path_sum",
      "prototype": "pub fn min_path_sum(grid: &[Vec<i32>]) -> i32",
      "return_type": "i32"
    },
    {
      "name": "falling_path_sum",
      "prototype": "pub fn falling_path_sum(matrix: &[Vec<i32>]) -> i32",
      "return_type": "i32"
    }
  ],

  "norm": {
    "allowed_functions": ["malloc", "free", "calloc", "memset", "memcpy"],
    "forbidden_functions": ["qsort", "bsearch"],
    "check_security": true,
    "check_memory": true,
    "blocking": true
  }
}
```

### 4.10 Solutions Mutantes

**Mutant A (Boundary) : Off-by-one sur les indices**
```rust
pub fn unique_paths_mutant_a(m: usize, n: usize) -> i64 {
    if m == 0 || n == 0 {
        return 0;
    }
    let mut dp = vec![vec![0i64; n]; m];

    for j in 0..n {
        dp[0][j] = 1;
    }
    for i in 0..m {
        dp[i][0] = 1;
    }

    for i in 1..m {
        for j in 1..n {
            dp[i][j] = dp[i - 1][j] + dp[i][j - 1];
        }
    }

    dp[m][n]  // BUG: index out of bounds, devrait etre dp[m-1][n-1]
}
// Pourquoi c'est faux : Acces hors limites, panic en Rust
// Ce qui etait pense : Confusion entre taille et dernier index
```

**Mutant B (Safety) : Pas de verification NULL/empty**
```rust
pub fn unique_paths_obstacles_mutant_b(grid: &[Vec<i32>]) -> i64 {
    // BUG: Pas de verification si grid est vide
    let m = grid.len();  // Panic si grid.is_empty()
    let n = grid[0].len();  // Panic si grid[0] est vide

    let mut dp = vec![vec![0i64; n]; m];
    // ... reste du code
    dp[m - 1][n - 1]
}
// Pourquoi c'est faux : Crash sur grille vide
// Ce qui etait pense : "Ca n'arrivera jamais"
```

**Mutant C (Logic) : Mauvaise propagation des obstacles**
```rust
pub fn unique_paths_obstacles_mutant_c(grid: &[Vec<i32>]) -> i64 {
    if grid.is_empty() || grid[0].is_empty() {
        return 0;
    }

    let m = grid.len();
    let n = grid[0].len();
    let mut dp = vec![vec![1i64; n]; m];  // BUG: Initialise tout a 1

    for i in 1..m {
        for j in 1..n {
            if grid[i][j] == 0 {
                dp[i][j] = dp[i - 1][j] + dp[i][j - 1];
            } else {
                dp[i][j] = 0;
            }
        }
    }

    dp[m - 1][n - 1]
}
// Pourquoi c'est faux : Les obstacles sur ligne/colonne 0 sont ignores
// Ce qui etait pense : "La premiere ligne/colonne n'a qu'un chemin"
```

**Mutant D (Logic) : Inversion min/max**
```rust
pub fn min_path_sum_mutant_d(grid: &[Vec<i32>]) -> i32 {
    if grid.is_empty() || grid[0].is_empty() {
        return 0;
    }

    let m = grid.len();
    let n = grid[0].len();
    let mut dp = vec![vec![0i32; n]; m];

    dp[0][0] = grid[0][0];

    for j in 1..n {
        dp[0][j] = dp[0][j - 1] + grid[0][j];
    }
    for i in 1..m {
        dp[i][0] = dp[i - 1][0] + grid[i][0];
    }

    for i in 1..m {
        for j in 1..n {
            // BUG: max au lieu de min !
            dp[i][j] = grid[i][j] + std::cmp::max(dp[i - 1][j], dp[i][j - 1]);
        }
    }

    dp[m - 1][n - 1]
}
// Pourquoi c'est faux : Retourne le chemin MAXIMAL au lieu de minimal
// Ce qui etait pense : Confusion entre minimiser et maximiser
```

**Mutant E (Return) : Retourne toujours 0 pour grilles 1xN**
```rust
pub fn unique_paths_mutant_e(m: usize, n: usize) -> i64 {
    if m == 0 || n == 0 {
        return 0;
    }

    // BUG: Retourne 0 au lieu de 1 pour les grilles lineaires
    if m == 1 || n == 1 {
        return 0;  // Devrait retourner 1
    }

    let mut dp = vec![vec![0i64; n]; m];

    for j in 0..n {
        dp[0][j] = 1;
    }
    for i in 0..m {
        dp[i][0] = 1;
    }

    for i in 1..m {
        for j in 1..n {
            dp[i][j] = dp[i - 1][j] + dp[i][j - 1];
        }
    }

    dp[m - 1][n - 1]
}
// Pourquoi c'est faux : Les grilles 1xN ou Mx1 ont exactement 1 chemin
// Ce qui etait pense : "Une dimension = pas de chemin possible"
```

---

## SECTION 5 : COMPRENDRE

### 5.1 Ce que cet exercice enseigne

1. **Programmation dynamique sur grilles 2D** : Passer de la recursion naive a la tabulation
2. **Relation de recurrence** : Comprendre que `dp[i][j]` depend de `dp[i-1][j]` et `dp[i][j-1]`
3. **Gestion des cas limites** : Premiere ligne, premiere colonne, obstacles
4. **Optimisation spatiale** : Rolling array pour passer de O(m*n) a O(n)
5. **Reconstruction de chemin** : Backtracking depuis la solution finale

### 5.2 LDA - Traduction litterale

```
FONCTION unique_paths QUI RETOURNE UN ENTIER 64 BITS ET PREND EN PARAMETRES m ET n QUI SONT DES ENTIERS POSITIFS
DEBUT FONCTION
    SI m EST EGAL A 0 OU n EST EGAL A 0 ALORS
        RETOURNER LA VALEUR 0
    FIN SI

    DECLARER dp COMME TABLEAU 2D D'ENTIERS 64 BITS DE DIMENSIONS m PAR n

    POUR j ALLANT DE 0 A n MOINS 1 FAIRE
        AFFECTER 1 A L'ELEMENT A LA POSITION (0, j) DANS dp
    FIN POUR

    POUR i ALLANT DE 0 A m MOINS 1 FAIRE
        AFFECTER 1 A L'ELEMENT A LA POSITION (i, 0) DANS dp
    FIN POUR

    POUR i ALLANT DE 1 A m MOINS 1 FAIRE
        POUR j ALLANT DE 1 A n MOINS 1 FAIRE
            AFFECTER L'ELEMENT A LA POSITION (i-1, j) PLUS L'ELEMENT A LA POSITION (i, j-1) A L'ELEMENT A LA POSITION (i, j) DANS dp
        FIN POUR
    FIN POUR

    RETOURNER L'ELEMENT A LA POSITION (m-1, n-1) DANS dp
FIN FONCTION
```

### 5.2.2 Style Academique

```
ALGORITHME : unique_paths(m, n)
---
ENTREES : m (entier >= 0), n (entier >= 0) - dimensions de la grille
SORTIE : nombre de chemins uniques (entier 64 bits)

DEBUT
    SI m = 0 OU n = 0 ALORS
        RETOURNER 0
    FIN SI

    CREER dp[m][n] initialise a 0

    // Initialisation : bordures ont un seul chemin
    POUR j DE 0 A n-1 : dp[0][j] <- 1
    POUR i DE 0 A m-1 : dp[i][0] <- 1

    // Recurrence : somme des chemins depuis haut et gauche
    POUR i DE 1 A m-1 :
        POUR j DE 1 A n-1 :
            dp[i][j] <- dp[i-1][j] + dp[i][j-1]
        FIN POUR
    FIN POUR

    RETOURNER dp[m-1][n-1]
FIN
```

### 5.2.2.1 Logic Flow (Structured English)

```
ALGORITHM: Pac-Man Path Counter
---
1. VALIDATE inputs
   - IF grid dimensions are zero THEN RETURN 0

2. INITIALIZE base cases
   - SET first row to all 1s (only one way: go right)
   - SET first column to all 1s (only one way: go down)

3. FILL DP table (bottom-up)
   FOR each cell (i, j) starting from (1, 1):
       - paths[i][j] = paths_from_above + paths_from_left
       - paths[i][j] = dp[i-1][j] + dp[i][j-1]

4. RETURN dp[m-1][n-1] as final answer
```

### 5.2.3 Representation Algorithmique avec Logique de Garde

```
FONCTION : unique_paths_obstacles(grid)
---
INIT resultat = 0

1. VERIFIER si la grille est vide :
   |
   |-- SI grid.is_empty() OU grid[0].is_empty() :
   |     RETOURNER 0
   |
   |-- SI grid[0][0] == OBSTACLE :
   |     RETOURNER 0  // Depart bloque !
   |
   |-- SI grid[m-1][n-1] == OBSTACLE :
   |     RETOURNER 0  // Arrivee bloquee !

2. INITIALISER premiere ligne :
   |
   |-- POUR chaque j dans [0, n) :
   |     SI grid[0][j] == OBSTACLE :
   |         STOP (tout le reste = 0)
   |     SINON :
   |         dp[0][j] = 1

3. INITIALISER premiere colonne (meme logique)

4. REMPLIR le reste :
   |
   |-- POUR i de 1 a m-1 :
   |     POUR j de 1 a n-1 :
   |         SI grid[i][j] == OBSTACLE :
   |             dp[i][j] = 0
   |         SINON :
   |             dp[i][j] = dp[i-1][j] + dp[i][j-1]

5. RETOURNER dp[m-1][n-1]
```

### 5.2.3.1 Diagramme Mermaid

```mermaid
graph TD
    A[Start: unique_paths_obstacles] --> B{Grid empty?}
    B -- Yes --> C[RETURN 0]
    B -- No --> D{Start cell blocked?}
    D -- Yes --> C
    D -- No --> E{End cell blocked?}
    E -- Yes --> C
    E -- No --> F[Initialize first row]
    F --> G[Initialize first column]
    G --> H[Fill DP table]
    H --> I[For each cell i,j]
    I --> J{Is obstacle?}
    J -- Yes --> K[dp[i][j] = 0]
    J -- No --> L[dp[i][j] = dp[i-1][j] + dp[i][j-1]]
    K --> M{More cells?}
    L --> M
    M -- Yes --> I
    M -- No --> N[RETURN dp[m-1][n-1]]
```

### 5.3 Visualisation ASCII

**Grille 3x3 - Tous les chemins :**
```
Depart (Pac-Man spawn)
    |
    v
┌───┬───┬───┐
│ S │ → │ → │  Chemin 1: S→→→↓↓E
├───┼───┼───┤
│ ↓ │   │ ↓ │  Chemin 2: S→→↓→↓E
├───┼───┼───┤
│ ↓ │ → │ E │  Chemin 3: S→→↓↓→E
└───┴───┴───┘  ...et 3 autres
                Total: 6 chemins
```

**Avec obstacle (fantome) :**
```
┌───┬───┬───┐
│ S │ o │ o │  o = pastille (libre)
├───┼───┼───┤
│ o │ X │ o │  X = FANTOME (bloque)
├───┼───┼───┤
│ o │ o │ E │
└───┴───┴───┘

Chemins bloques par le fantome:
- Haut-droite puis bas : BLOQUE
- Milieu direct : BLOQUE

Chemins valides: 2 seulement
  1. S→↓→↓→→E (contourne par le bas)
  2. S→↓→↓→→↓→E... wait, non!

Vrais chemins:
  1. S↓↓→→E
  2. S↓→↓→E
```

**Table DP pour min_path_sum :**
```
Grille originale:        Table DP (couts cumules):
┌───┬───┬───┐           ┌───┬───┬───┐
│ 1 │ 3 │ 1 │           │ 1 │ 4 │ 5 │
├───┼───┼───┤           ├───┼───┼───┤
│ 1 │ 5 │ 1 │    =>     │ 2 │ 7 │ 6 │
├───┼───┼───┤           ├───┼───┼───┤
│ 4 │ 2 │ 1 │           │ 6 │ 8 │ 7 │
└───┴───┴───┘           └───┴───┴───┘

Chemin optimal: 1→3→1→1→1 = 7
                ↓ → ↓ → ↓
```

### 5.4 Les pieges en detail

**Piege 1 : Initialisation de la premiere ligne/colonne**
```rust
// FAUX: Initialise tout a 1 sans considerer les obstacles
for j in 0..n { dp[0][j] = 1; }

// CORRECT: S'arrete au premier obstacle
for j in 0..n {
    if grid[0][j] == 1 { break; }  // Fantome !
    dp[0][j] = 1;
}
```

**Piege 2 : Off-by-one sur l'index final**
```rust
// FAUX: Acces hors limites
return dp[m][n];

// CORRECT: Les tableaux sont 0-indexes
return dp[m-1][n-1];
```

**Piege 3 : Oublier de verifier le depart/arrivee**
```rust
// FAUX: Ne verifie pas si depart ou arrivee est bloque
pub fn unique_paths_obstacles(grid: &[Vec<i32>]) -> i64 {
    // Commence directement le DP...
}

// CORRECT: Verifier d'abord
if grid[0][0] == 1 || grid[m-1][n-1] == 1 {
    return 0;  // Impossible !
}
```

### 5.5 Cours Complet

#### 5.5.1 Introduction a la DP sur Grilles

La programmation dynamique sur grilles est une technique fondamentale en algorithmique. Elle consiste a decomposer un probleme sur une grille 2D en sous-problemes plus petits, en utilisant les solutions des cellules precedentes.

**Principe cle :** Pour atteindre la cellule `(i, j)`, on ne peut venir que de :
- La cellule au-dessus `(i-1, j)` (mouvement vers le bas)
- La cellule a gauche `(i, j-1)` (mouvement vers la droite)

Cela donne la relation de recurrence :
```
dp[i][j] = f(dp[i-1][j], dp[i][j-1], grid[i][j])
```

Ou `f` depend du probleme :
- **Comptage de chemins :** `f = addition` -> `dp[i][j] = dp[i-1][j] + dp[i][j-1]`
- **Cout minimal :** `f = min + valeur` -> `dp[i][j] = min(...) + grid[i][j]`
- **Cout maximal :** `f = max + valeur` -> `dp[i][j] = max(...) + grid[i][j]`

#### 5.5.2 Complexite et Optimisations

**Approche naive (recursion) :**
- Temps : O(2^(m+n)) - exponentiel !
- Espace : O(m+n) - profondeur de recursion

**Approche DP (tabulation) :**
- Temps : O(m*n) - chaque cellule visitee une fois
- Espace : O(m*n) - table complete

**Approche optimisee (rolling array) :**
- Temps : O(m*n) - inchange
- Espace : O(n) - seulement la ligne precedente

#### 5.5.3 Variantes Avancees

**Falling Path Sum :**
- Contrairement a la DP classique, on peut venir de 3 directions : haut-gauche, haut, haut-droite
- `dp[i][j] = matrix[i][j] + min(dp[i-1][j-1], dp[i-1][j], dp[i-1][j+1])`

**Dungeon Game (backward DP) :**
- On part de la fin vers le debut !
- `dp[i][j]` = vie minimale necessaire pour atteindre la fin depuis `(i, j)`
- Relation inversee : `dp[i][j] = max(1, min(dp[i+1][j], dp[i][j+1]) - dungeon[i][j])`

### 5.6 Normes avec explications pedagogiques

```
┌─────────────────────────────────────────────────────────────────┐
│ HORS NORME (compile, mais interdit)                            │
├─────────────────────────────────────────────────────────────────┤
│ let mut dp = vec![vec![0;n];m];                                 │
├─────────────────────────────────────────────────────────────────┤
│ CONFORME                                                        │
├─────────────────────────────────────────────────────────────────┤
│ let mut dp = vec![vec![0i64; n]; m];                            │
├─────────────────────────────────────────────────────────────────┤
│ POURQUOI ?                                                      │
│                                                                 │
│ - Typage explicite : i64 vs inference                           │
│ - Espaces autour des operateurs                                 │
│ - Lisibilite : dimensions claires (n colonnes, m lignes)        │
└─────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────┐
│ HORS NORME                                                      │
├─────────────────────────────────────────────────────────────────┤
│ for(size_t i=0;i<m;i++)for(size_t j=0;j<n;j++)dp[i][j]=...     │
├─────────────────────────────────────────────────────────────────┤
│ CONFORME                                                        │
├─────────────────────────────────────────────────────────────────┤
│ for (size_t i = 0; i < m; i++)                                  │
│ {                                                               │
│     for (size_t j = 0; j < n; j++)                              │
│     {                                                           │
│         dp[i][j] = ...;                                         │
│     }                                                           │
│ }                                                               │
├─────────────────────────────────────────────────────────────────┤
│ POURQUOI ?                                                      │
│                                                                 │
│ - Une instruction par ligne                                     │
│ - Accolades explicites meme pour une ligne                      │
│ - Indentation coherente                                         │
└─────────────────────────────────────────────────────────────────┘
```

### 5.7 Simulation avec trace d'execution

**Appel : `unique_paths(3, 3)`**

```
┌───────┬─────────────────────────────────────────────┬─────────────────┬─────────────────────────────────┐
│ Etape │ Instruction                                 │ Etat dp[3][3]   │ Explication                     │
├───────┼─────────────────────────────────────────────┼─────────────────┼─────────────────────────────────┤
│   1   │ Creer dp[3][3] initialise a 0               │ [[0,0,0],       │ Table vide                      │
│       │                                             │  [0,0,0],       │                                 │
│       │                                             │  [0,0,0]]       │                                 │
├───────┼─────────────────────────────────────────────┼─────────────────┼─────────────────────────────────┤
│   2   │ Initialiser premiere ligne a 1             │ [[1,1,1],       │ Un seul chemin: aller a droite  │
│       │                                             │  [0,0,0],       │                                 │
│       │                                             │  [0,0,0]]       │                                 │
├───────┼─────────────────────────────────────────────┼─────────────────┼─────────────────────────────────┤
│   3   │ Initialiser premiere colonne a 1           │ [[1,1,1],       │ Un seul chemin: aller en bas    │
│       │                                             │  [1,0,0],       │                                 │
│       │                                             │  [1,0,0]]       │                                 │
├───────┼─────────────────────────────────────────────┼─────────────────┼─────────────────────────────────┤
│   4   │ dp[1][1] = dp[0][1] + dp[1][0] = 1+1       │ [[1,1,1],       │ 2 facons d'atteindre (1,1)      │
│       │                                             │  [1,2,0],       │                                 │
│       │                                             │  [1,0,0]]       │                                 │
├───────┼─────────────────────────────────────────────┼─────────────────┼─────────────────────────────────┤
│   5   │ dp[1][2] = dp[0][2] + dp[1][1] = 1+2       │ [[1,1,1],       │ 3 facons d'atteindre (1,2)      │
│       │                                             │  [1,2,3],       │                                 │
│       │                                             │  [1,0,0]]       │                                 │
├───────┼─────────────────────────────────────────────┼─────────────────┼─────────────────────────────────┤
│   6   │ dp[2][1] = dp[1][1] + dp[2][0] = 2+1       │ [[1,1,1],       │ 3 facons d'atteindre (2,1)      │
│       │                                             │  [1,2,3],       │                                 │
│       │                                             │  [1,3,0]]       │                                 │
├───────┼─────────────────────────────────────────────┼─────────────────┼─────────────────────────────────┤
│   7   │ dp[2][2] = dp[1][2] + dp[2][1] = 3+3       │ [[1,1,1],       │ 6 facons d'atteindre (2,2)      │
│       │                                             │  [1,2,3],       │                                 │
│       │                                             │  [1,3,6]]       │                                 │
├───────┼─────────────────────────────────────────────┼─────────────────┼─────────────────────────────────┤
│   8   │ RETOURNER dp[2][2] = 6                      │ 6               │ Resultat final !                │
└───────┴─────────────────────────────────────────────┴─────────────────┴─────────────────────────────────┘
```

### 5.8 Mnemotechniques

#### MEME : "WAKA WAKA WAKA" - Le son de Pac-Man

Chaque "WAKA" represente une cellule traversee. Pac-Man ne peut aller que droite ou bas (pas de retour arriere !).

```
W-A-K-A    W-A-K-A    W-A-K-A
  →          ↓          →
(0,0)     (1,0)      (1,1)
```

**Regle WAKA :** Pour savoir combien de "WAKA" differents menent a une cellule, additionne les "WAKA" des cellules d'ou tu peux venir (haut + gauche).

#### MEME : "Press F to Pay Respects" - Edge Cases

```
┌───────────────────────────────────────────────────────────────────┐
│                                                                   │
│   if grid.is_empty() { return 0; }  // Press F                    │
│   if grid[0][0] == OBSTACLE { return 0; }  // Press F             │
│   if grid[m-1][n-1] == OBSTACLE { return 0; }  // Press F         │
│                                                                   │
│   Chaque verification oubliee = une mort de Pac-Man               │
│   Appuie sur F pour chaque cas limite que tu geres                │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

#### MEME : "This is Fine" - Ignorer les obstacles

Le chien assis dans la piece en feu, disant "This is fine" :

```rust
// NE SOIS PAS CE CHIEN !
let mut dp = vec![vec![1i64; n]; m];  // "This is fine"
// SPOILER: Ce n'est PAS fine, les obstacles sont ignores

// Sois le chien qui eteint le feu :
if grid[i][j] == OBSTACLE {
    dp[i][j] = 0;  // Pas de chemin a travers un fantome !
}
```

### 5.9 Applications pratiques

1. **Navigation GPS** : Trouver le chemin le plus court/rapide entre deux points sur une carte
2. **Jeux video** : Pathfinding des personnages, IA des ennemis
3. **Robotique** : Planification de trajectoire, evitement d'obstacles
4. **Bioinformatique** : Alignement de sequences ADN/proteines (Smith-Waterman, Needleman-Wunsch)
5. **Finance quantitative** : Modeles de pricing sur grilles (arbres binomiaux, surfaces de volatilite)
6. **Traitement d'images** : Seam carving (redimensionnement intelligent d'images)

---

## SECTION 6 : PIEGES - RECAPITULATIF

| # | Piege | Description | Solution |
|---|-------|-------------|----------|
| 1 | Off-by-one | `dp[m][n]` au lieu de `dp[m-1][n-1]` | Toujours verifier les indices |
| 2 | Grille vide | Ne pas gerer `grid.is_empty()` | Verifier AVANT tout acces |
| 3 | Obstacles ligne 0 | Initialiser premiere ligne a 1 sans verifier obstacles | Stopper a l'obstacle |
| 4 | Depart bloque | Ne pas verifier si `grid[0][0]` est un obstacle | Verifier explicitement |
| 5 | Arrivee bloquee | Ne pas verifier si `grid[m-1][n-1]` est un obstacle | Verifier explicitement |
| 6 | Overflow | Utiliser `i32` pour des grilles qui donnent des grands nombres | Utiliser `i64` |
| 7 | min vs max | Confondre minimisation et maximisation | Relire l'enonce ! |

---

## SECTION 7 : QCM

### Q1. Combien de chemins uniques dans une grille 2x2 (de (0,0) a (1,1)) ?
- A) 1
- B) 2
- C) 3
- D) 4
- E) 0
- F) 6
- G) 8
- H) Depend des valeurs
- I) Infini
- J) Aucune des reponses

**Reponse : B**
Explication : Deux chemins possibles : droite-bas ou bas-droite.

### Q2. Quelle est la relation de recurrence pour compter les chemins uniques ?
- A) dp[i][j] = dp[i-1][j] * dp[i][j-1]
- B) dp[i][j] = dp[i-1][j] + dp[i][j-1]
- C) dp[i][j] = min(dp[i-1][j], dp[i][j-1])
- D) dp[i][j] = max(dp[i-1][j], dp[i][j-1])
- E) dp[i][j] = dp[i-1][j] - dp[i][j-1]
- F) dp[i][j] = 2 * dp[i-1][j]
- G) dp[i][j] = dp[i-1][j-1]
- H) dp[i][j] = 1
- I) dp[i][j] = dp[i][j] + 1
- J) Aucune des reponses

**Reponse : B**
Explication : Les chemins vers (i,j) = chemins depuis le haut + chemins depuis la gauche.

### Q3. Si la cellule (0,0) est un obstacle, combien de chemins menent a (m-1, n-1) ?
- A) 1
- B) m * n
- C) 0
- D) Depend de m et n
- E) m + n - 2
- F) Infini
- G) -1
- H) m - 1
- I) n - 1
- J) Aucune des reponses

**Reponse : C**
Explication : Si le depart est bloque, aucun chemin n'est possible.

### Q4. Quelle est la complexite temporelle de la DP sur grille m x n ?
- A) O(1)
- B) O(log n)
- C) O(n)
- D) O(m + n)
- E) O(m * n)
- F) O(n^2)
- G) O(m^2)
- H) O(2^n)
- I) O(n!)
- J) O(m * n * log n)

**Reponse : E**
Explication : On visite chaque cellule exactement une fois.

### Q5. Pour min_path_sum, quelle valeur initiale pour dp[0][0] ?
- A) 0
- B) 1
- C) grid[0][0]
- D) INT_MAX
- E) INT_MIN
- F) -1
- G) grid[m-1][n-1]
- H) m + n
- I) grid[0][0] + 1
- J) Aucune des reponses

**Reponse : C**
Explication : Le cout pour atteindre (0,0) est exactement la valeur de cette cellule.

---

## SECTION 8 : RECAPITULATIF

| Aspect | Details |
|--------|---------|
| **Concept principal** | Programmation dynamique sur grilles 2D |
| **Relation de recurrence** | dp[i][j] = f(dp[i-1][j], dp[i][j-1]) |
| **Complexite temps** | O(m * n) |
| **Complexite espace** | O(m * n), optimisable a O(n) |
| **Pieges principaux** | Off-by-one, obstacles non geres, grille vide |
| **Fonctions cles** | unique_paths, min_path_sum, falling_path_sum |
| **Applications** | Pathfinding, robotique, bioinformatique |

---

## SECTION 9 : DEPLOYMENT PACK

```json
{
  "deploy": {
    "hackbrain_version": "5.5.2",
    "engine_version": "v22.1",
    "exercise_slug": "1.5.3-a-waka-waka-grid",
    "generated_at": "2026-01-12 00:00:00",

    "metadata": {
      "exercise_id": "1.5.3-a",
      "exercise_name": "waka_waka_grid",
      "module": "1.5.3",
      "module_name": "Grid & Matrix Dynamic Programming",
      "concept": "a",
      "concept_name": "Navigation sur grille avec DP",
      "type": "complet",
      "tier": 1,
      "tier_info": "Concept isole",
      "phase": 1,
      "difficulty": 5,
      "difficulty_stars": "★★★★★☆☆☆☆☆",
      "language": ["rust", "c"],
      "duration_minutes": 90,
      "xp_base": 150,
      "xp_bonus_multiplier": 3,
      "bonus_tier": "AVANCE",
      "bonus_icon": "🔥",
      "complexity_time": "T5 O(m*n)",
      "complexity_space": "S4 O(m*n)",
      "prerequisites": ["1.5.1", "1.5.2"],
      "domains": ["DP", "Struct", "AL"],
      "domains_bonus": ["Mem"],
      "tags": ["dp", "grid", "pathfinding", "pac-man"],
      "meme_reference": "WAKA WAKA WAKA"
    },

    "files": {
      "spec.json": "/* Section 4.9 */",
      "references/ref_solution.rs": "/* Section 4.3 Rust */",
      "references/ref_solution.c": "/* Section 4.3 C */",
      "references/ref_solution_bonus.rs": "/* Section 4.6 */",
      "alternatives/alt_combinatorial.rs": "/* Section 4.4 Alt 1 */",
      "alternatives/alt_memo.rs": "/* Section 4.4 Alt 2 */",
      "mutants/mutant_a_boundary.rs": "/* Section 4.10 */",
      "mutants/mutant_b_safety.rs": "/* Section 4.10 */",
      "mutants/mutant_c_logic.rs": "/* Section 4.10 */",
      "mutants/mutant_d_min_max.rs": "/* Section 4.10 */",
      "mutants/mutant_e_return.rs": "/* Section 4.10 */",
      "tests/main.c": "/* Section 4.2 */"
    },

    "validation": {
      "expected_pass": [
        "references/ref_solution.rs",
        "references/ref_solution.c",
        "references/ref_solution_bonus.rs",
        "alternatives/alt_combinatorial.rs",
        "alternatives/alt_memo.rs"
      ],
      "expected_fail": [
        "mutants/mutant_a_boundary.rs",
        "mutants/mutant_b_safety.rs",
        "mutants/mutant_c_logic.rs",
        "mutants/mutant_d_min_max.rs",
        "mutants/mutant_e_return.rs"
      ]
    },

    "commands": {
      "validate_spec": "python3 hackbrain_engine_v22.py --validate-spec spec.json",
      "test_rust": "cargo test --release",
      "test_c": "gcc -Wall -Wextra -Werror -O2 grid_dp.c main.c -o test && ./test",
      "test_mutants": "python3 hackbrain_mutation_tester.py -r references/ref_solution.rs -s spec.json --validate"
    }
  }
}
```

---

*HACKBRAIN v5.5.2 - "WAKA WAKA! L'excellence n'a pas de raccourcis, tout comme Pac-Man n'a pas de marche arriere"*
